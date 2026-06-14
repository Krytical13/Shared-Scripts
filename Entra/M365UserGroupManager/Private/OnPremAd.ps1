<#
    On-premises Active Directory edit path (P1 of hybrid support).

    For a directory-synced object, identity attributes are mastered in on-prem AD and are read-only
    in Graph -- so the tool edits them in AD and lets Microsoft Entra Connect Sync carry the change
    up. This file is the AD layer:
      * capability detection (RSAT ActiveDirectory module + a reachable WRITABLE domain controller),
      * cloud -> on-prem object mapping (by sAMAccountName / distinguishedName, NOT a blind
        immutableId decode -- the source anchor is version/config dependent),
      * a pure cloud-attribute -> AD LDAP-attribute translation (unit-tested), and
      * thin write wrappers over Set-ADUser / Enable-/Disable-ADAccount / Set-ADAccountPassword /
        Add-/Remove-ADGroupMember.

    The module loads cleanly WITHOUT RSAT installed: every ActiveDirectory cmdlet is invoked lazily
    inside a function, never at file scope. Authentication uses the caller's current Windows identity
    (integrated auth); there is no credential store. Targets a single discovered writable DC.

    NOTE: the live AD writes here cannot be exercised on a non-domain-joined / RSAT-less box -- the
    pure logic is unit-tested; the I/O matches current Microsoft Learn cmdlet usage.
#>

# Cached AD-write capability for this session (cleared on disconnect / tenant switch via Reset-HybridState).
$script:AdState = @{ Checked = $false; Available = $false; Reason = ''; Dc = $null }

function Reset-AdState {
    $script:AdState.Checked = $false; $script:AdState.Available = $false; $script:AdState.Reason = ''; $script:AdState.Dc = $null
}

# --- Capability / connection ---------------------------------------------------------------

function Import-AdModule {
    <# Lazily import the RSAT ActiveDirectory module. $true on success. Never throws. #>
    if (Get-Module -Name ActiveDirectory) { return $true }
    try { Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue; return $true }
    catch { return $false }
}

function Get-AdRsatCapabilityName {
    <# The Feature-on-Demand capability id for the RSAT AD tools (client OS). Stable since Win10 1809. #>
    'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
}

function Install-AdModule {
    <# Install the RSAT AD module (client FoD). Requires elevation; returns $true on success. #>
    try {
        $cap = Get-WindowsCapability -Online -Name (Get-AdRsatCapabilityName) -ErrorAction Stop
        if ($cap.State -eq 'Installed') { return $true }
        Add-WindowsCapability -Online -Name (Get-AdRsatCapabilityName) -ErrorAction Stop | Out-Null
        return $true
    } catch { return $false }
}

function Resolve-WritableDc {
    <# FQDN of a reachable WRITABLE domain controller, or $null. RSAT first, then a .NET fallback. #>
    try {
        $dc = Get-ADDomainController -Discover -Writable -ErrorAction Stop
        if ($dc -and $dc.HostName) { return [string]($dc.HostName | Select-Object -First 1) }
    } catch { }
    try {
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        if ($dom.PdcRoleOwner -and $dom.PdcRoleOwner.Name) { return [string]$dom.PdcRoleOwner.Name }
    } catch { }
    return $null
}

function Get-AdWriteCapability {
    <#
        Can the tool write to on-prem AD right now? Returns the cached $script:AdState
        @{ Available; Reason; Dc }. Requires: hybrid tenant + RSAT module + a writable DC.
    #>
    param([switch]$Force)
    if ($script:AdState.Checked -and -not $Force) { return $script:AdState }
    $script:AdState.Checked = $true
    $script:AdState.Available = $false; $script:AdState.Reason = ''; $script:AdState.Dc = $null

    if (-not (Get-TenantHybridState)) { $script:AdState.Reason = 'Tenant is not directory-synced.'; return $script:AdState }
    if (-not (Import-AdModule))       { $script:AdState.Reason = 'The ActiveDirectory (RSAT) module is not installed on this workstation.'; return $script:AdState }
    $dc = Resolve-WritableDc
    if (-not $dc)                     { $script:AdState.Reason = 'No writable domain controller is reachable from this workstation.'; return $script:AdState }

    $script:AdState.Dc = $dc
    $script:AdState.Available = $true
    return $script:AdState
}

# --- Cloud -> on-prem object mapping -------------------------------------------------------

function Get-AdUserForCloudObject {
    <# Find the on-prem AD user for a synced cloud user: sAMAccountName first, then DN. $null if not found. #>
    param($Object, [string]$Dc)
    $sam = Get-GraphVal $Object 'onPremisesSamAccountName'
    if ($sam) {
        $u = Get-ADUser -Filter "sAMAccountName -eq '$sam'" -Server $Dc -ErrorAction SilentlyContinue
        if ($u) { return $u }
    }
    $dn = Get-GraphVal $Object 'onPremisesDistinguishedName'
    if ($dn) { try { return Get-ADUser -Identity $dn -Server $Dc -ErrorAction Stop } catch { } }
    return $null
}

function Get-AdGroupForCloudObject {
    <# Find the on-prem AD group for a synced cloud group. $null if not found. #>
    param($Object, [string]$Dc)
    $sam = Get-GraphVal $Object 'onPremisesSamAccountName'
    if ($sam) {
        $g = Get-ADGroup -Filter "sAMAccountName -eq '$sam'" -Server $Dc -ErrorAction SilentlyContinue
        if ($g) { return $g }
    }
    $sid = Get-GraphVal $Object 'onPremisesSecurityIdentifier'
    if ($sid) { try { return Get-ADGroup -Identity $sid -Server $Dc -ErrorAction Stop } catch { } }
    return $null
}

function Resolve-AdUserFromPerson {
    <# Resolve a picked directory person (@{Id;DisplayName;Detail}) to an AD user via its UPN. $null if not found. #>
    param($Person, [string]$Dc)
    $upn = [string]$Person.Detail
    if ($upn -and $upn -match '^[^@\s]+@[^@\s]+$') {
        $u = Get-ADUser -Filter "userPrincipalName -eq '$upn'" -Server $Dc -ErrorAction SilentlyContinue
        if ($u) { return $u }
    }
    return $null
}

# --- Cloud-attribute -> AD LDAP-attribute translation (PURE, unit-tested) ------------------

function Get-CloudToAdAttributeMap {
    <#
        Graph (camelCase) -> AD LDAP attribute name, for SCALAR on-prem-mastered fields written via
        Set-ADUser -Replace/-Clear. accountEnabled / passwordProfile / manager are handled by
        dedicated wrappers (not here); licenses / usageLocation / userType are cloud-authoritative.
    #>
    $map = @{
        displayName       = 'displayName'
        givenName         = 'givenName'
        surname           = 'sn'
        userPrincipalName = 'userPrincipalName'
        mailNickname      = 'mailNickname'
        jobTitle          = 'title'
        department        = 'department'
        companyName       = 'company'
        employeeId        = 'employeeID'
        employeeType      = 'employeeType'
        officeLocation    = 'physicalDeliveryOfficeName'
        mobilePhone       = 'mobile'
        businessPhones    = 'telephoneNumber'
        streetAddress     = 'streetAddress'
        city              = 'l'
        state             = 'st'
        postalCode        = 'postalCode'
        country           = 'co'
        preferredLanguage = 'preferredLanguage'
    }
    foreach ($i in 1..15) { $map["extensionAttribute$i"] = "extensionAttribute$i" }
    return $map
}

function Get-CloudToAdGroupAttributeMap {
    <# Graph -> AD LDAP for synced-GROUP scalar fields written via Set-ADGroup. Membership is handled
       separately (Sync-AdGroupMembership); owners have no clean AD multi-owner equivalent and stay
       read-only for synced groups. #>
    @{
        displayName  = 'displayName'
        description  = 'description'
        mailNickname = 'mailNickname'
    }
}

function ConvertTo-AdAttributeWrites {
    <#
        Translate a set of changed scalar fields to AD Set-ADUser arguments.
        Input: @( @{ Name = <graphName>; Value = <string|string[]|$null> }, ... ).
        Output: @{ Replace = @{ ldap = value }; Clear = @(ldap...); Unsupported = @(graphName...) }.
        - empty / null value  -> Clear that attribute on-prem
        - multi value         -> AD attrs here are single-valued; take the first non-empty entry
        - unmapped name       -> Unsupported (caller warns; it cannot be written on-prem by this tool)
    #>
    param([object[]]$Changes, [hashtable]$Map)
    $map = if ($Map) { $Map } else { Get-CloudToAdAttributeMap }
    $replace = @{}
    $clear = New-Object System.Collections.Generic.List[string]
    $unsupported = New-Object System.Collections.Generic.List[string]

    foreach ($c in $Changes) {
        if (-not $c -or -not $c.Name) { continue }
        $ldap = $map[$c.Name]
        if (-not $ldap) { [void]$unsupported.Add([string]$c.Name); continue }

        $v = $c.Value
        if ($v -is [System.Array]) {
            # single-valued AD attribute: first non-blank entry (strings are safe under the 5.1 @() binder)
            $first = @($v | Where-Object { "$_".Trim() }) | Select-Object -First 1
            $v = $first
        }
        if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { [void]$clear.Add($ldap) }
        else { $replace[$ldap] = [string]$v }
    }
    return @{ Replace = $replace; Clear = $clear.ToArray(); Unsupported = $unsupported.ToArray() }
}

# --- Write wrappers (LIVE -- require RSAT + a reachable writable DC) ------------------------

function Set-AdUserScalarAttributes {
    <# Apply -Replace / -Clear to an AD user. No-op if both empty. #>
    param($AdUser, [string]$Dc, [hashtable]$Replace, [string[]]$Clear)
    $p = @{ Identity = $AdUser; Server = $Dc; ErrorAction = 'Stop' }
    $any = $false
    if ($Replace -and $Replace.Count) { $p.Replace = $Replace; $any = $true }
    if ($Clear -and $Clear.Count)     { $p.Clear = $Clear;     $any = $true }
    if ($any) { Set-ADUser @p }
}

function Set-AdGroupScalarAttributes {
    <# Apply -Replace / -Clear to an AD group. No-op if both empty. #>
    param($AdGroup, [string]$Dc, [hashtable]$Replace, [string[]]$Clear)
    $p = @{ Identity = $AdGroup; Server = $Dc; ErrorAction = 'Stop' }
    $any = $false
    if ($Replace -and $Replace.Count) { $p.Replace = $Replace; $any = $true }
    if ($Clear -and $Clear.Count)     { $p.Clear = $Clear;     $any = $true }
    if ($any) { Set-ADGroup @p }
}

function Set-AdAccountEnabledState {
    param($AdUser, [string]$Dc, [bool]$Enabled)
    if ($Enabled) { Enable-ADAccount -Identity $AdUser -Server $Dc -ErrorAction Stop }
    else          { Disable-ADAccount -Identity $AdUser -Server $Dc -ErrorAction Stop }
}

function Reset-AdUserPasswordValue {
    param($AdUser, [string]$Dc, [string]$Password, [bool]$ForceChange)
    $sec = ConvertTo-SecureString -String $Password -AsPlainText -Force
    Set-ADAccountPassword -Identity $AdUser -Server $Dc -Reset -NewPassword $sec -ErrorAction Stop
    if ($ForceChange) { Set-ADUser -Identity $AdUser -Server $Dc -ChangePasswordAtLogon $true -ErrorAction Stop }
}

function Set-AdUserManagerFromPerson {
    <# Set (or clear) a synced user's manager in AD from a picked person. Returns $true if applied. #>
    param($AdUser, [string]$Dc, $Person)
    if (-not $Person) { Set-ADUser -Identity $AdUser -Server $Dc -Manager $null -ErrorAction Stop; return $true }
    $mgr = Resolve-AdUserFromPerson -Person $Person -Dc $Dc
    if (-not $mgr) { return $false }   # caller warns: manager not found on-prem
    Set-ADUser -Identity $AdUser -Server $Dc -Manager $mgr.DistinguishedName -ErrorAction Stop
    return $true
}

function Sync-AdGroupMembership {
    <#
        Apply an add/remove membership diff to a synced AD group. $Now / $Original are picked person
        lists (@{Id;Detail}); members are resolved to AD users by UPN. Returns @{ Unresolved = @(...) }.
    #>
    param($AdGroup, [string]$Dc, [object[]]$Now, [object[]]$Original)
    $nowIds  = @($Now      | ForEach-Object { $_.Id })
    $origIds = @($Original | ForEach-Object { $_.Id })
    $unresolved = New-Object System.Collections.Generic.List[string]

    foreach ($p in $Now)      { if ($origIds -notcontains $p.Id) {
        $ad = Resolve-AdUserFromPerson -Person $p -Dc $Dc
        if ($ad) { Add-ADGroupMember -Identity $AdGroup -Members $ad -Server $Dc -Confirm:$false -ErrorAction Stop }
        else { [void]$unresolved.Add([string]$p.DisplayName) }
    } }
    foreach ($p in $Original) { if ($nowIds -notcontains $p.Id) {
        $ad = Resolve-AdUserFromPerson -Person $p -Dc $Dc
        if ($ad) { Remove-ADGroupMember -Identity $AdGroup -Members $ad -Server $Dc -Confirm:$false -ErrorAction Stop }
        else { [void]$unresolved.Add([string]$p.DisplayName) }
    } }
    return @{ Unresolved = $unresolved.ToArray() }
}
