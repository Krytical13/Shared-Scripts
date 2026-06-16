<#
    Configuration + catalog selection.

    App config persists to %APPDATA%\M365UserGroupManager\config.json:
      {
        "Tenants": [ { "Name": "Contoso", "TenantId": "...|domain" }, ... ],
        "LastTenantId": "...",
        "Users":  { "Enabled": [ "displayName", ... ] },
        "Groups": { "Enabled": [ "displayName", ... ] }
      }

    On Windows PowerShell 5.1, ConvertFrom-Json returns a PSCustomObject (no -AsHashtable),
    so the loader maps the parsed object into a plain hashtable by hand and merges with
    defaults -- that way a config written by an older version (missing a key, or missing a
    newly-added attribute) still loads, and brand-new attributes simply default to their
    DefaultShow state.
#>

function Get-ConfigPath {
    Join-Path $env:APPDATA 'M365UserGroupManager\config.json'
}

# --- Catalog accessors (the catalog is loaded into $script:Catalog by the .psm1) -----------

function Get-CatalogTab {
    param([ValidateSet('User', 'Group')][string]$Tab)
    return $script:Catalog[$Tab]
}

function Get-CatalogAttributeList {
    <# Flatten a tab's catalog to a single ordered list of attribute hashtables. #>
    param([ValidateSet('User', 'Group')][string]$Tab)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($group in (Get-CatalogTab -Tab $Tab)) {
        foreach ($attr in $group.Attributes) { [void]$list.Add($attr) }
    }
    return $list
}

function Get-CatalogAttribute {
    <# Find a single attribute hashtable by its Name within a tab. #>
    param([ValidateSet('User', 'Group')][string]$Tab, [string]$Name)
    foreach ($attr in (Get-CatalogAttributeList -Tab $Tab)) {
        if ($attr.Name -eq $Name) { return $attr }
    }
    return $null
}

function Get-DefaultEnabledNames {
    <# Attribute Names that should be enabled by default for a tab (DefaultShow = $true). #>
    param([ValidateSet('User', 'Group')][string]$Tab)
    return @(Get-CatalogAttributeList -Tab $Tab | Where-Object { $_.DefaultShow } | ForEach-Object { $_.Name })
}

# --- Config load / save --------------------------------------------------------------------

function New-DefaultConfig {
    # Plain hashtable for easy in-memory mutation; serialised to JSON by Save-AppConfig.
    # Accounts: saved sign-ins for quick switching -> @{ Name; TenantId; Upn }.
    @{
        Accounts       = @()
        Users          = @{ Enabled = (Get-DefaultEnabledNames -Tab 'User') }
        Groups         = @{ Enabled = (Get-DefaultEnabledNames -Tab 'Group') }
        LastOnPremOuDn = ''   # last OU chosen for an on-prem AD user create (preselected next time)
        ConnectServer  = ''   # Entra Connect server override/fallback when cloud autofill can't name it
    }
}

function Get-AppConfig {
    <# Load config from disk, merging onto defaults; falls back to defaults on any error. #>
    $cfg  = New-DefaultConfig
    $path = Get-ConfigPath
    if (-not (Test-Path -LiteralPath $path)) { return $cfg }

    try {
        $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $cfg   # corrupt file -> defaults
    }

    # Accounts -> array of plain hashtables (migrating the old 'Tenants' schema if present).
    $accSrc = if ($raw.PSObject.Properties['Accounts'] -and $raw.Accounts) { $raw.Accounts }
    elseif ($raw.PSObject.Properties['Tenants'] -and $raw.Tenants) { $raw.Tenants }
    else { $null }
    if ($accSrc) {
        $cfg.Accounts = @(
            $accSrc | ForEach-Object {
                @{ Name = [string]$_.Name; TenantId = [string]$_.TenantId; Upn = [string]$_.Upn }
            } | Where-Object { $_.TenantId }
        )
    }

    # Enabled attribute sets: keep only Names that still exist in the catalog.
    foreach ($tab in 'Users', 'Groups') {
        $catTab = if ($tab -eq 'Users') { 'User' } else { 'Group' }
        $valid  = @(Get-CatalogAttributeList -Tab $catTab | ForEach-Object { $_.Name })
        if ($raw.PSObject.Properties[$tab] -and $raw.$tab -and $raw.$tab.PSObject.Properties['Enabled'] -and $null -ne $raw.$tab.Enabled) {
            $cfg[$tab].Enabled = @($raw.$tab.Enabled | Where-Object { $valid -contains $_ })
        }
    }
    return $cfg
}

function Save-AppConfig {
    param([hashtable]$Config)
    $path = Get-ConfigPath
    $dir  = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    ($Config | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $path -Encoding UTF8
}

function Get-EnabledAttributeObjects {
    <#
        The catalog attribute hashtables that are currently enabled for a tab, in catalog order.
        $Tab is the catalog key ('User' | 'Group').
    #>
    param([ValidateSet('User', 'Group')][string]$Tab)
    $key     = if ($Tab -eq 'User') { 'Users' } else { 'Groups' }
    $enabled = @($script:Config[$key].Enabled)
    return @(Get-CatalogAttributeList -Tab $Tab | Where-Object { $enabled -contains $_.Name })
}
