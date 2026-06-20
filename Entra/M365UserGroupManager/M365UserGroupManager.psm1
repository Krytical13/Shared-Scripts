<#
    M365UserGroupManager - root module.

    Loads the declarative attribute catalog, dot-sources every Private/ then Public/ function
    file, and exports the public entry point. All functions share module-scoped state via the
    $script:* variables initialised below (UI handles, loaded config, license SKU cache).

    Design: logic is split by concern (GraphConnection / GraphUsers / GraphGroups /
    GraphLicensing / Configuration / Ui*). Nothing here talks to Graph at import time, so the
    module imports cleanly even when the Graph SDK is not installed -- the window can open and
    then offer to install/connect.
#>

$ErrorActionPreference = 'Stop'

# --- Module-scoped shared state ------------------------------------------------------------
$script:ModuleRoot = $PSScriptRoot
$script:UI         = @{}                     # WinForms control handles, populated by UiMainForm
$script:Config     = $null                   # app config (tenants + per-tab enabled attrs), loaded on Show
$script:SkuMap     = @{}                     # SkuId -> SkuPartNumber cache for license names
$script:SkuDetailCache = $null               # rich SKU list (counts) for the license picker, built once/connect
$script:OrgCache   = $null                   # tenant organization object, fetched once per connection
$script:VerifiedDomains = @()                # tenant verified domains for the UPN domain dropdown
$script:AppReady   = $false                  # gate: $true only after the window is shown, so NO
                                             # Graph call happens at startup (Connect is the gate)
$script:UiClosing  = $false                  # set on FormClosing so pump loops unwind without touching
                                             # controls that are about to be disposed
$script:State      = @{                      # transient runtime state
    SelectedUser  = $null                    # the user object currently loaded in Edit mode (or $null)
    SelectedGroup = $null                    # the group object currently loaded in Edit mode (or $null)
}

# --- Load the declarative attribute catalog (pure data) ------------------------------------
$script:Catalog = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'Data/AttributeCatalog.psd1')

# --- Dot-source Private then Public --------------------------------------------------------
foreach ($folder in 'Private', 'Public') {
    $dir = Join-Path $PSScriptRoot $folder
    if (Test-Path -LiteralPath $dir) {
        Get-ChildItem -LiteralPath $dir -Filter '*.ps1' -File | Sort-Object Name | ForEach-Object {
            . $_.FullName
        }
    }
}

# --- Export the public surface -------------------------------------------------------------
$publicNames = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File |
    ForEach-Object { $_.BaseName }
Export-ModuleMember -Function $publicNames
