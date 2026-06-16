<#
.SYNOPSIS
    Launches the M365 User/Group Manager GUI.

.DESCRIPTION
    The file to run. It:
      1. Ensures a single-threaded apartment (WinForms requires STA), relaunching once if not.
      2. Makes sure the required Microsoft Graph SDK sub-modules are installed (offers to
         install them for the current user if missing).
      3. Imports the M365UserGroupManager module and opens the window.

    Run it with no arguments:  .\Start-M365UserGroupManager.ps1
    (or right-click the file > Run with PowerShell).

.NOTES
    Requirements:
      * Windows. Runs on Windows PowerShell 5.1 or PowerShell 7+ (re-launches itself in STA
        if the host is not already single-threaded).
      * Microsoft Graph SDK sub-modules (auto-offered for install to CurrentUser if missing) --
        see M365UserGroupManager.psd1 -> PrivateData.RequiredGraphModules.

    License: MIT (see repository LICENSE).
#>
[CmdletBinding()]
param(
    # Internal: set when the script has already relaunched itself in STA mode.
    [switch]$Relaunched
)

#region ------------------------------------------------------------------- STA relaunch shim
# WinForms requires STA. The Windows PowerShell 5.1 console and pwsh 7 on Windows are STA by
# default, but some hosts (custom runspaces, pwsh -MTA, certain add-ins) are not -- relaunch once.
if (-not $Relaunched -and $PSCommandPath) {
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
        $hostExe = (Get-Process -Id $PID).Path
        if (-not $hostExe) { $hostExe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' } }
        Start-Process -FilePath $hostExe -ArgumentList @(
            '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Relaunched'
        ) | Out-Null
        return
    }
}
#endregion

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $PSScriptRoot 'M365UserGroupManager.psd1'

# NOTE: the Microsoft Graph SDK modules are intentionally NOT installed/imported here. They share the
# Microsoft.Graph.Authentication assembly, and a mismatched-version install causes the dreaded
# "assembly with same name is already loaded" failure. Initialize-GraphModule (run on Connect) owns
# that: it resolves a single coherent version, offers to install/align any laggards, and imports them
# all pinned to that one version -- so a stale "any version present" check here can't poison the set.
# This also keeps launch making zero Graph calls (the Connect button stays the sole gate).

# Import fresh (so edits during development are always picked up) and open the window.
Import-Module $manifestPath -Force
Show-M365UserGroupManager
