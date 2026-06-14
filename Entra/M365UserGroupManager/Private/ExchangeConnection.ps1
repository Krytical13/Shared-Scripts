<#
    Exchange Online connection -- isolated in a dedicated background runspace.

    Why a runspace: (1) Connect-ExchangeOnline blocks its thread during interactive sign-in; running
    it on the WinForms UI thread freezes the app (and EXO 3.7.1 has no -Device/-DisableWAM escape).
    (2) Loading the EXO assemblies into the same runspace as the Microsoft.Graph SDK can hit
    .NET dependency conflicts. So we open ONE STA runspace, import EXO there, and run every
    Exchange cmdlet inside it. The connect runs async while the UI pumps messages (stays responsive);
    the session lives in the runspace for all subsequent calls. Objects come back as live .NET
    objects (same-process runspace -- no serialization), so callers read properties normally.
#>

$script:ExoRunspace = $null

function Test-ExoModuleInstalled { [bool](Get-Module -ListAvailable -Name ExchangeOnlineManagement) }

function Install-ExoModuleIfMissing {
    if (Test-ExoModuleInstalled) { return }
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "The Exchange Online management module (ExchangeOnlineManagement) is not installed.`n`nInstall it now for the current user?",
        'Install Exchange Online module', 'YesNo', 'Question')
    if ($ans -ne 'Yes') { throw 'The ExchangeOnlineManagement module is required to manage Exchange recipients.' }
    Set-Progress 'Installing Exchange Online module (this can take a minute)...'
    Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}

function Test-ExoRunspaceOpen {
    [bool]($script:ExoRunspace -and $script:ExoRunspace.RunspaceStateInfo.State -eq 'Opened')
}

function Initialize-ExoRunspace {
    if (Test-ExoRunspaceOpen) { return }
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()
    $script:ExoRunspace = $rs
}

function Invoke-ExoCommand {
    <#
        Run a scriptblock inside the EXO runspace. -Async pumps the WinForms message loop while it
        runs (used for the long-blocking connect) so the UI stays responsive. Returns the output;
        re-throws the first error from the runspace.
    #>
    param([Parameter(Mandatory)][scriptblock]$Script, [hashtable]$Parameters = @{}, [switch]$Async)
    if (-not (Test-ExoRunspaceOpen)) { throw 'Not connected to Exchange Online.' }
    # The runspace runs one pipeline at a time. While the async connect pumps the UI, a stray
    # click could re-enter; refuse rather than corrupt the runspace state.
    if ($script:ExoBusy) { throw 'Exchange Online is busy; please wait for the current operation to finish.' }
    $script:ExoBusy = $true

    $ps = [powershell]::Create()
    $ps.Runspace = $script:ExoRunspace
    [void]$ps.AddScript($Script)
    foreach ($k in $Parameters.Keys) { [void]$ps.AddParameter($k, $Parameters[$k]) }
    try {
        if ($Async) {
            $handle = $ps.BeginInvoke()
            while (-not $handle.IsCompleted) {
                [System.Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 75
            }
            $out = $ps.EndInvoke($handle)
        } else {
            $out = $ps.Invoke()
        }
        if ($ps.HadErrors -and $ps.Streams.Error.Count -gt 0) { throw $ps.Streams.Error[0] }
        return $out
    } finally {
        $ps.Dispose()
        $script:ExoBusy = $false
    }
}

function Get-ExoConnectionInfo {
    <# Active EXO connection (or $null) -- queried inside the runspace. #>
    if (-not (Test-ExoRunspaceOpen)) { return $null }
    try {
        $info = Invoke-ExoCommand -Script { Get-ConnectionInformation }
        return ($info | Select-Object -First 1)
    } catch {
        return $null
    }
}

function Test-ExoConnected { [bool](Get-ExoConnectionInfo) }

function Connect-Exo {
    <#
        Ensure the module is installed, open the runspace, then import EXO + Connect-ExchangeOnline
        INSIDE the runspace, async, while the UI pumps. Targets the Graph-connected admin's UPN so
        Exchange lands in the same tenant. Returns the connection info, or throws.
    #>
    Install-ExoModuleIfMissing
    Initialize-ExoRunspace

    $upn = ''
    $ctx = Get-GraphContextSafe
    if ($ctx -and $ctx.Account) { $upn = [string]$ctx.Account }

    Set-Progress 'Connecting to Exchange Online -- a browser sign-in will open. This can take a moment...'
    Invoke-ExoCommand -Async -Parameters @{ Upn = $upn } -Script {
        param($Upn)
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $p = @{ ShowBanner = $false; ShowProgress = $false; ErrorAction = 'Stop' }
        if ($Upn) { $p.UserPrincipalName = $Upn }
        Connect-ExchangeOnline @p
    } | Out-Null

    return Get-ExoConnectionInfo
}

function Disconnect-ExoSafe {
    try {
        if (Test-ExoRunspaceOpen) {
            Invoke-ExoCommand -Script { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } | Out-Null
        }
    } catch { }
    finally {
        if ($script:ExoRunspace) {
            try { $script:ExoRunspace.Close(); $script:ExoRunspace.Dispose() } catch { }
            $script:ExoRunspace = $null
        }
    }
}

function Get-ExoTenantHint {
    <# Friendly label for the active EXO connection. #>
    param($Info)
    if (-not $Info) { return '' }
    foreach ($p in 'DelegatedOrganization', 'Organization', 'UserPrincipalName', 'TenantId') {
        $v = $Info.PSObject.Properties[$p]
        if ($v -and $v.Value) { return [string]$v.Value }
    }
    return ''
}
