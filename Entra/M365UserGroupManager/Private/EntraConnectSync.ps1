<#
    Microsoft Entra Connect Sync -- force a delta sync from an admin workstation.

    For a hybrid create (user made in on-prem AD), the cloud only sees it after the next Entra Connect
    delta cycle (default 30 min). This layer optionally forces that cycle now and lets the caller poll
    until the object appears in Entra.

    Design (verified against Microsoft Learn):
      * The Connect SERVER NAME is best-effort auto-detected FROM THE CLOUD via the Graph beta
        onPremisesSynchronization resource (configuration.currentExportData.clientMachineName) -- the
        machine that ran the last export, which is inherently the active (non-staging) server. Plain
        Graph v1.0 / the organization resource do NOT expose it; MSOnline's DirSyncClientMachineName has
        no v1.0 successor. Reading the beta resource needs OnPremDirectorySynchronization.Read.All.
      * There is NO cloud trigger for a sync cycle. Forcing is Start-ADSyncSyncCycle -PolicyType Delta,
        from the on-prem ADSync module, which lives ONLY on the Connect server -- so we run it there over
        WinRM (Invoke-Command), using the operator's Windows identity (no stored creds; single hop).
      * Guards: skip a staging server (never exports), a disabled scheduler, and a busy cycle (the change
        rides the in-flight/next cycle). Entra CLOUD SYNC is a different agent (no ADSync module) -- the
        remote import fails and we report that, rather than forcing the wrong thing.

    Live WinRM/Start-ADSyncSyncCycle is unverifiable on this RSAT-less box; the decision logic is pure +
    unit-tested, and the I/O matches current Microsoft Learn cmdlet usage.
#>

function Get-EntraConnectSyncInfo {
    <#
        Best-effort cloud lookup of the Entra Connect server + pending-export counts, via Graph beta
        /directory/onPremisesSynchronization. Returns @{ ServerName; PendingAdds; PendingUpdates;
        PendingDeletes; ClientVersion } or $null (not synced / no permission / not exposed). Read-only;
        never throws -- a missing OnPremDirectorySynchronization.Read.All consent just yields $null so
        the caller falls back to a configured/prompted server name.
    #>
    try {
        $r = Invoke-MgGraphRequest -Method GET -OutputType PSObject -ErrorAction Stop `
            -Uri 'https://graph.microsoft.com/beta/directory/onPremisesSynchronization'
        $cfg = @($r.value)[0].configuration   # List form returns a value[] wrapper (one entry per tenant)
        if (-not $cfg) { return $null }
        # currentExportData is a single object in practice; wrap in @() so this is robust either way, and
        # take the entry that names the export client (the active, non-staging server that last exported).
        $ced = @($cfg.currentExportData) | Where-Object { $_ -and $_.clientMachineName } | Select-Object -First 1
        if (-not $ced) { return $null }
        return @{
            ServerName     = [string]$ced.clientMachineName
            PendingAdds    = [int]$ced.pendingObjectsAddition
            PendingUpdates = [int]$ced.pendingObjectsUpdate
            PendingDeletes = [int]$ced.pendingObjectsDeletion
            ClientVersion  = [string]$cfg.synchronizationClientVersion
        }
    } catch { return $null }
}

function Resolve-ServerFqdn {
    <# Best-effort short-name -> FQDN for WinRM (the cloud reports a NetBIOS-ish hostname). Falls back to
       the name as-is (WinRM/Kerberos usually resolves a short name via the DNS suffix search list). #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name -like '*.*') { return $Name }
    try {
        $h = [System.Net.Dns]::GetHostEntry($Name)
        if ($h.HostName -like '*.*') { return [string]$h.HostName }
    } catch { }
    return $Name
}

function New-AdSyncSessionOption {
    <# WinRM session options with a BOUNDED open timeout. Without this, an unreachable-but-resolvable
       Connect server makes Invoke-Command wait on the default WinRM connect timeout (tens of seconds to
       minutes) -- on the UI thread, that is the "app hangs with no indication" the operator hit. 8s is
       long enough for a healthy on-VPN/in-office connect, short enough to fail fast and report. #>
    $open = 8000
    try { if ($script:Config -and $script:Config.WinRmTimeoutMs) { $open = [int]$script:Config.WinRmTimeoutMs } } catch { }
    New-PSSessionOption -OpenTimeout $open -OperationTimeout 60000 -CancelTimeout 2000
}

function Test-ConnectServerReachable {
    <# WinRM reachability probe (no longer on the hot path -- the bounded Invoke-Command below surfaces
       unreachability directly; kept for callers/tests). Proves the transport is up, NOT that you're
       authorized or that ADSync is present. #>
    param([Parameter(Mandatory)][string]$Server)
    try { [void](Test-WSMan -ComputerName $Server -ErrorAction Stop); return $true } catch { return $false }
}

function Test-AdSyncForceAllowed {
    <#
        PURE: given a Get-ADSyncScheduler result + whether a cycle is currently running, decide whether
        forcing a delta is appropriate. Returns @{ Allowed=[bool]; Reason }.
          - no scheduler  -> not a reachable Connect server (or access denied)
          - staging mode  -> never exports to Entra; forcing here wouldn't push the change (poll would hang)
          - cycle disabled-> a manual force wouldn't run
          - already busy  -> benign; the change rides the in-flight/next cycle (no need to force again)
    #>
    param($Scheduler, [bool]$Busy)
    if (-not $Scheduler) { return @{ Allowed = $false; Reason = "Couldn't read the sync scheduler -- this may not be a Microsoft Entra Connect server, or access was denied." } }
    if ($Scheduler.StagingModeEnabled) { return @{ Allowed = $false; Reason = 'This server is in staging mode -- it never exports to Entra, so forcing a sync here would not push the change up.' } }
    if (-not $Scheduler.SyncCycleEnabled) { return @{ Allowed = $false; Reason = 'The sync scheduler is disabled on this server, so a forced cycle would not run.' } }
    if ($Busy) { return @{ Allowed = $false; Reason = 'A sync cycle is already running; the pending change will be picked up by the current or next cycle.' } }
    return @{ Allowed = $true; Reason = '' }
}

function Get-RemoteAdSyncState {
    <# Remotely read the Connect server's scheduler + busy state over WinRM (one round-trip). Returns
       @{ Scheduler; Busy } on success, or @{ Error } if remoting / the ADSync module / rights fail. #>
    param([Parameter(Mandatory)][string]$Server)
    try {
        $r = Invoke-Command -ComputerName $Server -SessionOption (New-AdSyncSessionOption) -ErrorAction Stop -ScriptBlock {
            Import-Module ADSync -ErrorAction Stop   # absent on a non-Connect / Cloud Sync host -> throws
            [pscustomobject]@{ Scheduler = (Get-ADSyncScheduler); Busy = [bool](Get-ADSyncConnectorRunStatus) }
        }
        return @{ Scheduler = $r.Scheduler; Busy = [bool]$r.Busy }
    } catch { return @{ Error = $_.Exception.Message } }
}

function Invoke-RemoteAdSyncDelta {
    <# Remotely run Start-ADSyncSyncCycle -PolicyType Delta on the Connect server. Returns @{ Started }
       or @{ Error }. The caller gates this with Test-AdSyncForceAllowed first; if a cycle started in the
       meantime, Start-ADSyncSyncCycle reports AlreadyRunning, which is benign. #>
    param([Parameter(Mandatory)][string]$Server)
    try {
        Invoke-Command -ComputerName $Server -SessionOption (New-AdSyncSessionOption) -ErrorAction Stop -ScriptBlock {
            Import-Module ADSync -ErrorAction Stop
            Start-ADSyncSyncCycle -PolicyType Delta | Out-Null
        }
        return @{ Started = $true }
    } catch { return @{ Error = $_.Exception.Message } }
}
