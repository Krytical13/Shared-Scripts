<#
    SCCM / Microsoft Configuration Manager device operations -- console-less, generic (server from the
    per-tenant config, never hardcoded).

    DISCOVERY uses the ConfigMgr AdminService REST API (HTTPS to the SMS Provider, integrated Windows
    auth, the caller's ConfigMgr RBAC) -- no console install needed on the tech's machine.

    DELETE: the AdminService has no documented HTTP DELETE for a device, so the actual removal runs
    Remove-CMDevice from the ConfigurationManager PowerShell module over WinRM, ON the site/provider
    server (which has the module + a connection to the site) -- the same remote-Invoke-Command pattern as
    the Entra Connect force-sync. The site code drives the temporary CM PSDrive on that server.
#>

function Find-SccmDevice {
    <# Per-store lookup of the ConfigMgr device by name via the AdminService. Returns a normalized
       @{ Found; Id (ResourceID); Count; Detail; Reason; NotConfigured; Error }. Never throws. #>
    param([Parameter(Mandatory)][string]$Name, [string]$Server, [int]$TimeoutSec = 15)
    if (-not $Server) { return @{ Found = $false; NotConfigured = $true; Reason = 'No SCCM server set for this tenant (open Settings).' } }
    try {
        $filter = [uri]::EscapeDataString("Name eq '$($Name.Replace("'", "''"))'")
        $uri = "https://$Server/AdminService/wmi/SMS_R_System?`$filter=$filter&`$select=ResourceId,Name,SMSUniqueIdentifier,Client"
        $r = Invoke-RestMethod -Uri $uri -UseDefaultCredentials -TimeoutSec $TimeoutSec -ErrorAction Stop
        $vals = @($r.value)
        if ($vals.Count -eq 0) { return @{ Found = $false; Reason = 'Not found in Configuration Manager.' } }
        $d = $vals[0]
        return @{ Found = $true; Id = [string]$d.ResourceId; Count = $vals.Count; Detail = "ResourceID $([string]$d.ResourceId)" }
    } catch {
        return @{ Found = $false; Error = $true; Reason = "ConfigMgr AdminService lookup failed: $($_.Exception.Message)" }
    }
}

function Remove-SccmDeviceRemote {
    <# Delete a ConfigMgr device by ResourceID, by running Remove-CMDevice on the site/provider server over
       WinRM (the ConfigurationManager module + site drive live there, not on the tech's box). Bounded
       open-timeout via the shared session option. Returns @{ Removed } or @{ Error }. #>
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$SiteCode,
        [Parameter(Mandatory)][int]$ResourceId
    )
    try {
        Invoke-Command -ComputerName $Server -SessionOption (New-AdSyncSessionOption) -ErrorAction Stop `
            -ArgumentList $SiteCode, $ResourceId -ScriptBlock {
                param($Site, $Rid)
                Import-Module (Join-Path $env:SMS_ADMIN_UI_PATH '..\ConfigurationManager.psd1') -ErrorAction Stop
                $drive = "$Site`:"
                if (-not (Get-PSDrive -Name $Site -ErrorAction SilentlyContinue)) {
                    [void](New-PSDrive -Name $Site -PSProvider CMSite -Root $env:COMPUTERNAME -ErrorAction Stop)
                }
                Push-Location $drive
                try { Remove-CMDevice -ResourceId $Rid -Force -ErrorAction Stop }
                finally { Pop-Location }
            }
        return @{ Removed = $true }
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}
