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
    'User.Invite.All'                  # send B2B guest invitations (New-MgInvitation)
)

function ConvertTo-ThreePartVersion {
    <# Normalize a [version] to Major.Minor.Build. Loaded ASSEMBLY versions are 4-part (2.37.0.0)
       while module-folder/manifest versions are 3-part (2.37.0); compare on 3 parts or every check
       falsely reports a mismatch. Build/Revision of -1 (unset) collapses to 0. #>
    param([Parameter(Mandatory, Position = 0)][version]$Version)
    $build = if ($Version.Build -lt 0) { 0 } else { $Version.Build }
    return [version]::new($Version.Major, $Version.Minor, $build)
}

function Get-LoadedGraphAuthVersion {
    <# The 3-part version of Microsoft.Graph.Authentication loaded in THIS process, or $null. #>
    $asm = [System.AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GetName().Name -eq 'Microsoft.Graph.Authentication' } |
        Select-Object -First 1
    if (-not $asm) { return $null }
    return (ConvertTo-ThreePartVersion $asm.GetName().Version)
}

function Resolve-GraphTargetVersion {
    <#
        Pure: pick ONE coherent version for the required Graph modules and list which modules are not
        yet installed at it. The sub-modules all share the Microsoft.Graph.Authentication assembly, and
        a process can hold only one version of it -- mismatched sub-module versions are exactly what
        throws "assembly with same name is already loaded". Prefer the highest version COMMON to every
        required module (zero install, least disruption); if the install is split (no common version),
        fall back to the highest version present for ANY required module and flag the laggards to install.
        Returns @{ Target=[version] (or $null if nothing installed); Missing=[string[]] }.
        $Installed = hashtable name -> [version[]] (3-part, may be empty).
    #>
    param([Parameter(Mandatory)][hashtable]$Installed, [Parameter(Mandatory)][string[]]$Required)

    $anyVers = [version[]]@($Required | ForEach-Object { $Installed[$_] } | Where-Object { $_ })
    if ($anyVers.Count -eq 0) { return @{ Target = $null; Missing = [string[]]@($Required) } }

    # Versions installed for EVERY required module (the common floor).
    $common = [version[]]@(
        $anyVers | Sort-Object -Unique | Where-Object {
            $v = $_
            @($Required | Where-Object { $Installed[$_] -notcontains $v }).Count -eq 0
        }
    )
    if ($common.Count -gt 0) {
        return @{ Target = @($common | Sort-Object -Descending)[0]; Missing = [string[]]@() }
    }

    # Split install -> heal UP to the highest version anything has.
    $target = @($anyVers | Sort-Object -Descending)[0]
    return @{ Target = $target; Missing = [string[]]@($Required | Where-Object { $Installed[$_] -notcontains $target }) }
}

function Get-InstalledGraphVersionMap {
    <# name -> sorted-unique [version[]] (3-part) of every installed version, for the required set. #>
    param([Parameter(Mandatory)][string[]]$Required)
    $avail = @(Get-Module -ListAvailable -Name $Required)
    $map = @{}
    foreach ($name in $Required) {
        $map[$name] = [version[]]@(
            @($avail | Where-Object { $_.Name -eq $name } |
                ForEach-Object { ConvertTo-ThreePartVersion ([version]$_.Version) }) | Sort-Object -Unique)
    }
    return $map
}

function Initialize-GraphModule {
    <#
        Load the required Graph SDK sub-modules at a SINGLE coherent version, permanently avoiding the
        "Could not load file or assembly 'Microsoft.Graph.Authentication ...' -- assembly with same name
        is already loaded" conflict that a split install (e.g. some sub-modules 2.36.1, others 2.37.0)
        causes. Strategy: resolve one target version -> if a different version is already loaded in this
        process, fail NOW with an actionable restart message (a loaded assembly can't be swapped live) ->
        install any module not at the target (pinned) -> import Authentication first then every sub-module
        pinned to the target so PowerShell's auto-resolution can never drag in a mismatched sibling.

        Host-agnostic: -OnMissingModule is invoked (with @{TargetVersion;Missing}) to authorize installs;
        it returns $true/$false. With no callback the function throws a clear, actionable error instead.
    #>
    param([scriptblock]$OnMissingModule)

    $manifest = Join-Path $script:ModuleRoot 'M365UserGroupManager.psd1'
    $required = [string[]]@((Import-PowerShellDataFile -Path $manifest).PrivateData.RequiredGraphModules |
        Where-Object { $_ } | Select-Object -Unique)
    if ($required.Count -eq 0) { throw 'The module manifest does not define PrivateData.RequiredGraphModules.' }
    $authName = 'Microsoft.Graph.Authentication'
    if ($required -notcontains $authName) { $required = [string[]]@($authName) + $required }

    $installed = Get-InstalledGraphVersionMap -Required $required
    $plan = Resolve-GraphTargetVersion -Installed $installed -Required $required

    # A wrong version already loaded in-process can't be replaced -> surface a restart message up front
    # (on connect) rather than letting the cryptic loader error ambush a later account switch. Check the
    # Authentication assembly AND every already-loaded required sub-module (a stale sibling also conflicts).
    if ($plan.Target) {
        $loadedBad = New-Object System.Collections.Generic.List[string]
        $la = Get-LoadedGraphAuthVersion
        if ($null -ne $la -and $la -ne $plan.Target) { [void]$loadedBad.Add("$authName $la") }
        foreach ($m in (Get-Module -Name $required)) {
            $lv = ConvertTo-ThreePartVersion ([version]$m.Version)
            if ($lv -ne $plan.Target) { [void]$loadedBad.Add("$($m.Name) $lv") }
        }
        if ($loadedBad.Count -gt 0) {
            throw ("A different version of the Microsoft Graph modules is already loaded in this session " +
                   "($(@($loadedBad | Select-Object -Unique) -join ', ')), but this tool needs $($plan.Target). " +
                   "A loaded assembly can't be replaced while the app is running.`n`n" +
                   "Please fully close and reopen the application, then try again.")
        }
    }

    # Heal: install anything not at the target (pinned). Re-inventory + re-resolve afterwards.
    if ($plan.Missing -and $plan.Missing.Count -gt 0) {
        $authorized = $true
        if ($OnMissingModule) {
            $authorized = [bool](& $OnMissingModule ([pscustomobject]@{ TargetVersion = $plan.Target; Missing = $plan.Missing }))
        }
        if (-not $authorized) { throw "Required Microsoft Graph modules were not installed (declined). Can't continue." }

        Set-Progress 'Aligning Microsoft Graph modules (this can take a minute)...'
        $failed = New-Object System.Collections.Generic.List[string]
        foreach ($name in $plan.Missing) {
            try {
                $p = @{ Name = $name; Scope = 'CurrentUser'; Force = $true; AllowClobber = $true; ErrorAction = 'Stop' }
                if ($plan.Target) { $p.RequiredVersion = $plan.Target.ToString() }   # null target (cold machine) -> latest
                Install-Module @p
            } catch { [void]$failed.Add("$name : $($_.Exception.Message)") }
        }
        if ($failed.Count -gt 0) {
            throw ("Could not install the required Microsoft Graph module(s):`n  " + ($failed -join "`n  ") +
                   "`n`nThis is usually no access to the PowerShell Gallery, an untrusted gallery, or a missing " +
                   "NuGet provider. From an internet-connected session run:`n" +
                   "  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force`n" +
                   "(accepting the NuGet provider / gallery-trust prompts), then reopen the app.")
        }
        $installed = Get-InstalledGraphVersionMap -Required $required
        $plan = Resolve-GraphTargetVersion -Installed $installed -Required $required
    }

    if (-not $plan.Target -or ($plan.Missing -and $plan.Missing.Count -gt 0)) {
        throw ("Could not bring the Microsoft Graph modules to a single coherent version. Align them manually, e.g.:`n" +
               "  '$($required -join "','")' | ForEach-Object { Install-Module `$_ -RequiredVersion <version> -Scope CurrentUser -Force -AllowClobber }`n" +
               "then reopen the app.")
    }

    # Import pinned, Authentication FIRST. Pinning every import to the one target is what actually
    # prevents the conflict (auto-resolution can no longer pick a mismatched sibling); loading
    # Authentication first is belt-and-suspenders. Skip a module only if already loaded AT the target.
    $tv = $plan.Target.ToString()
    $authAtTarget = @(Get-Module -Name $authName | Where-Object { (ConvertTo-ThreePartVersion ([version]$_.Version)) -eq $plan.Target })
    if ($authAtTarget.Count -eq 0) { Import-Module -Name $authName -RequiredVersion $tv -ErrorAction Stop }
    foreach ($name in $required) {
        if ($name -eq $authName) { continue }
        $atTarget = @(Get-Module -Name $name | Where-Object { (ConvertTo-ThreePartVersion ([version]$_.Version)) -eq $plan.Target })
        if ($atTarget.Count -gt 0) { continue }
        Import-Module -Name $name -RequiredVersion $tv -ErrorAction Stop
    }
    return $plan.Target
}

function Get-GraphContextSafe {
    <# Get-MgContext, or $null if not connected / SDK not loaded. IMPORTANT: only query when
       Microsoft.Graph.Authentication is ALREADY imported. Calling Get-MgContext cold would auto-load
       the SDK at the highest installed version, before Initialize-GraphModule pins a coherent one --
       which both defeats the "zero Graph calls at startup" rule and could pin Authentication to a
       version the resolver then disagrees with (triggering a spurious "restart" loop). Pre-connect the
       module isn't loaded, so returning $null ("not connected") is correct. #>
    if (-not (Get-Module -Name 'Microsoft.Graph.Authentication')) { return $null }
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
    # Plain scriptblock (no GetNewClosure) invoked synchronously inside Initialize-GraphModule, so it
    # keeps module affinity and may call WinForms (loaded by the GUI). Returns $true to authorize installs.
    Initialize-GraphModule -OnMissingModule {
        param($info)
        $verTxt = if ($info.TargetVersion) { " to version $($info.TargetVersion)" } else { '' }
        ([System.Windows.Forms.MessageBox]::Show(
            ("These Microsoft Graph modules need to be installed/updated$verTxt so they all share one version " +
             "(a version split causes the `"assembly already loaded`" error):`n`n  {0}`n`nInstall them now for the current user?" -f ($info.Missing -join "`n  ")),
            'Microsoft Graph modules', 'YesNo', 'Question')) -eq 'Yes'
    }

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
