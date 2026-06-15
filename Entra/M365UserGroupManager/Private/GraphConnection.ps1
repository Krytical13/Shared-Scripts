<#
    Graph connection + multi-tenant switching.

    Interactive (delegated) sign-in. We request the full scope set on EVERY connect (re-connect
    is additive at the consent level, but the session token isn't guaranteed to carry the union
    of previously-granted scopes -- e.g. Conditional Access can withhold one -- so we always ask
    for everything we need). Sign-in uses -ContextScope CurrentUser so the MSAL token cache PERSISTS
    -- that is what lets the account switcher re-connect a recently-used tenant silently (no prompt).
    Switching tenants therefore does NOT Disconnect-MgGraph first (that would clear the cache and
    force a fresh prompt); it just calls Connect-MgGraph -TenantId <other>. Only the explicit
    Disconnect button clears the cache.
#>

# Delegated scopes for create/modify of users and groups (+ license assignment). Directory.*
# is intentionally NOT requested -- these granular scopes cover everything the tool does.
$script:GraphScopes = @(
    'User.ReadWrite.All'
    'Group.ReadWrite.All'
    'GroupMember.ReadWrite.All'
    'Organization.Read.All'
    'LicenseAssignment.ReadWrite.All'
)

function Initialize-GraphModule {
    <# Ensure the required Graph SDK sub-modules are installed (offer to install) and imported. #>
    $need = (Import-PowerShellDataFile -Path (Join-Path $script:ModuleRoot 'M365UserGroupManager.psd1')).PrivateData.RequiredGraphModules
    $missing = @($need | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
    if ($missing.Count -gt 0) {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            ("These required Microsoft Graph modules are not installed:`n`n  {0}`n`nInstall them now for the current user?" -f ($missing -join "`n  ")),
            'Install Microsoft Graph modules', 'YesNo', 'Question')
        if ($ans -ne 'Yes') { throw "Required Microsoft Graph modules are missing: $($missing -join ', ')." }
        Set-Progress 'Installing modules (this can take a minute)...'
        Install-Module -Name $missing -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module -Name $need -ErrorAction Stop
}

function Get-GraphContextSafe {
    <# Get-MgContext, or $null if not connected / SDK not loaded. #>
    try { Get-MgContext } catch { $null }
}

function Test-GraphConnected {
    [bool](Get-GraphContextSafe)
}

function Disconnect-GraphSafe {
    try { Disconnect-MgGraph -ErrorAction Stop | Out-Null } catch { }
}

function Connect-Tenant {
    <#
        Connect interactively, optionally to a specific tenant (GUID or verified domain).
        If already connected to a DIFFERENT tenant, disconnect first (clean switch).
        Returns the resulting Get-MgContext (or throws on failure).
    #>
    param(
        [string]$TenantId,
        [switch]$DeviceCode
    )
    Initialize-GraphModule

    # NOTE: we do NOT Disconnect-MgGraph before switching tenants. Disconnect clears MSAL's token
    # cache, which would force a fresh prompt every switch. Connecting to a different -TenantId
    # re-targets the context and reuses the cached token for that tenant when present (silent),
    # which is what makes hopping between subsidiary tenants smooth. ContextScope=CurrentUser
    # persists those tokens across switches and app restarts.
    $connectParams = @{
        Scopes       = $script:GraphScopes
        NoWelcome    = $true
        ContextScope = 'CurrentUser'
        ErrorAction  = 'Stop'
    }
    if ($TenantId)   { $connectParams.TenantId = $TenantId }
    if ($DeviceCode) { $connectParams.UseDeviceCode = $true }

    Set-Progress 'Opening sign-in...'
    Connect-MgGraph @connectParams | Out-Null

    # A fresh tenant means the cached license-SKU map is stale.
    $script:SkuMap = @{}
    return Get-GraphContextSafe
}

function Switch-Tenant {
    <# Re-target the Graph context to another tenant WITHOUT disconnecting (keeps the token cache
       so a previously-used tenant connects silently). #>
    param([Parameter(Mandatory)][string]$TenantId, [switch]$DeviceCode)
    $script:SkuMap = @{}
    return (Connect-Tenant -TenantId $TenantId -DeviceCode:$DeviceCode)
}

function Get-MissingScopes {
    <# Which of $script:GraphScopes the current session did NOT actually receive. #>
    $ctx = Get-GraphContextSafe
    if (-not $ctx) { return @($script:GraphScopes) }
    $granted = @($ctx.Scopes)
    return @($script:GraphScopes | Where-Object { $granted -notcontains $_ })
}

function Get-TenantDomainHint {
    <#
        Best-effort friendly tenant name for the connection label: the signed-in account's
        domain, falling back to the organisation displayName, then the tenant GUID.
    #>
    param($Context)
    if (-not $Context) { return '' }
    if ($Context.Account -and $Context.Account.Contains('@')) {
        return $Context.Account.Split('@')[-1]
    }
    return [string]$Context.TenantId
}

function Initialize-VerifiedDomains {
    <# Fetch the tenant's verified domains for the UPN domain dropdown (covered by Organization.Read.All).
       Falls back to the signed-in account's domain so the dropdown is never blank. Best-effort;
       refreshed on each connect/switch. #>
    $list = New-Object System.Collections.Generic.List[object]
    try {
        # NB: fetch the FULL organization object -- selecting just 'verifiedDomains' via -Property has
        # been seen to return it null on some SDK versions (which left the dropdown blank).
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $vd = $org.VerifiedDomains                                   # typed collection
        if (-not $vd) { $vd = Get-GraphVal $org 'verifiedDomains' }  # shape-agnostic fallback
        foreach ($d in $vd) {
            if (-not $d) { continue }
            $name = [string](Get-GraphVal $d 'name')
            if ($name) { [void]$list.Add(@{ Name = $name; IsDefault = [bool](Get-GraphVal $d 'isDefault') }) }
        }
    } catch { }
    if ($list.Count -eq 0) {
        # Fallback: at least offer the signed-in account's own domain.
        $ctx = Get-GraphContextSafe
        if ($ctx -and $ctx.Account -and $ctx.Account.Contains('@')) {
            [void]$list.Add(@{ Name = $ctx.Account.Split('@')[-1]; IsDefault = $true })
        }
    }
    $script:VerifiedDomains = $list.ToArray()
}

function Get-VerifiedDomainList {
    <# Verified domain names, default domain first, for the UPN domain dropdown. #>
    $def  = @($script:VerifiedDomains | Where-Object { $_.IsDefault } | ForEach-Object { $_.Name })
    $rest = @($script:VerifiedDomains | Where-Object { -not $_.IsDefault } | ForEach-Object { $_.Name } | Sort-Object)
    return @($def + $rest)
}

function Get-DefaultVerifiedDomain {
    <# The tenant's default verified domain (or the first, or '' if none fetched yet). #>
    $d = @($script:VerifiedDomains | Where-Object { $_.IsDefault }) | Select-Object -First 1
    if ($d) { return $d.Name }
    $f = @($script:VerifiedDomains) | Select-Object -First 1
    if ($f) { return $f.Name }
    return ''
}
