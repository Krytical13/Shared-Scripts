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
# DcDomain = the DNS root the discovered DC actually belongs to; ExpectedDomain = the connected tenant's
# on-prem domain we verified against. The pair is what prevents a wrong-forest write when the workstation
# can reach a DIFFERENT tenant's DC than the one we're signed into (the multi-network hazard).
$script:AdState = @{ Checked = $false; Available = $false; Reason = ''; Dc = $null; DcDomain = $null; ExpectedDomain = $null }

function Reset-AdState {
    $script:AdState.Checked = $false; $script:AdState.Available = $false; $script:AdState.Reason = ''
    $script:AdState.Dc = $null; $script:AdState.DcDomain = $null; $script:AdState.ExpectedDomain = $null
}

# --- Pure pairing / identity guards (exercised offline) ------------------------------------

function Test-OnPremDomainMatch {
    <#
        PURE: does an EXPECTED on-prem domain (a cloud object's onPremisesDomainName, or the tenant's
        stored profile domain) refer to the same AD domain as the ACTUAL domain a reachable DC reports
        (Get-ADDomain DNSRoot)? Case-insensitive; tolerant of NetBIOS-vs-FQDN ONLY when one side is a
        single label (so 'hybrid1' matches 'hybrid1.local' but 'corp.a.dom' never matches
        'corp.b.dom'). Empty expected -> $true (cold start: nothing to verify against; caller confirms).
    #>
    param([string]$Expected, [string]$Actual)
    if ([string]::IsNullOrWhiteSpace($Expected)) { return $true }
    if ([string]::IsNullOrWhiteSpace($Actual))   { return $false }
    $e = $Expected.Trim().ToLowerInvariant().TrimEnd('.')
    $a = $Actual.Trim().ToLowerInvariant().TrimEnd('.')
    if ($e -eq $a) { return $true }
    if (($e -notmatch '\.') -or ($a -notmatch '\.')) { return (($e -split '\.')[0] -eq ($a -split '\.')[0]) }
    return $false
}

function Test-AdIdentityMatch {
    <#
        PURE: confirm a located AD object IS the cloud object's on-prem identity by comparing its
        objectSid to the cloud object's onPremisesSecurityIdentifier. When the cloud object carries a SID
        (it should, for a synced object), the match is REQUIRED -- a mismatch means we found a different
        principal (e.g. a same-named account in the wrong forest), so refuse. When the cloud object has NO
        SID, we can't positively verify here and defer to the domain-pairing guard (which already scoped
        the DC to the right forest), so allow.
    #>
    param($AdObject, [string]$ExpectedSid)
    if (-not $AdObject) { return $false }
    if ([string]::IsNullOrWhiteSpace($ExpectedSid)) { return $true }   # no SID to verify -> rely on domain guard
    $actual = ''
    try { $actual = [string]$AdObject.SID } catch { }
    if (-not $actual) { try { $actual = [string]$AdObject.objectSid } catch { } }
    return ($actual -eq $ExpectedSid)
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
    <#
        FQDN of a reachable WRITABLE domain controller, or $null. When -DomainName is given, discovery is
        SCOPED to that domain -- so it returns a DC for the connected tenant's forest, or $null when that
        forest isn't reachable from here (e.g. the VPN to the other office is down). This scoping is the
        core multi-network guard: it can't accidentally hand back the workstation's own (wrong) domain.
        Only the UNSCOPED call uses the .NET GetComputerDomain fallback (it can only see the joined domain).
    #>
    param([string]$DomainName)
    try {
        $p = @{ Discover = $true; Writable = $true; ErrorAction = 'Stop' }
        if ($DomainName) { $p.DomainName = $DomainName }
        $dc = Get-ADDomainController @p
        if ($dc -and $dc.HostName) { return [string]($dc.HostName | Select-Object -First 1) }
    } catch { }
    if (-not $DomainName) {
        try {
            $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
            if ($dom.PdcRoleOwner -and $dom.PdcRoleOwner.Name) { return [string]$dom.PdcRoleOwner.Name }
        } catch { }
    }
    return $null
}

function Get-AdServerDomain {
    <# The DNS root domain a given DC belongs to (Get-ADDomain DNSRoot), or '' if it can't be read.
       Used to verify a discovered DC really belongs to the tenant's expected on-prem domain. #>
    param([Parameter(Mandatory)][string]$Dc)
    try { return [string]((Get-ADDomain -Server $Dc -ErrorAction Stop).DNSRoot) } catch { return '' }
}

function Get-AdWriteCapability {
    <#
        Can the tool write to on-prem AD for THIS tenant right now? Returns the cached $script:AdState
        @{ Available; Reason; Dc; DcDomain; ExpectedDomain }. Requires: hybrid tenant + RSAT module + a
        writable DC that BELONGS TO the tenant's expected on-prem domain.

        -ExpectedDomain is the connected tenant's on-prem domain (a synced object's onPremisesDomainName,
        or the tenant profile). It is the safety pivot: discovery is scoped to it, so on the wrong network
        we get "not reachable" instead of silently targeting the workstation's own forest; and the
        discovered DC's real domain is verified against it. Recomputes when the expected domain changes
        (different tenant/object) so a cached capability for forest A is never reused for forest B.
    #>
    param([string]$ExpectedDomain, [switch]$Force)
    $expected = [string]$ExpectedDomain
    $sameDomain = ([string]$script:AdState.ExpectedDomain -eq $expected)
    if ($script:AdState.Checked -and -not $Force -and $sameDomain) { return $script:AdState }

    $script:AdState.Checked = $true
    $script:AdState.Available = $false; $script:AdState.Reason = ''; $script:AdState.Dc = $null; $script:AdState.DcDomain = $null
    $script:AdState.ExpectedDomain = $expected

    if (-not (Get-TenantHybridState)) { $script:AdState.Reason = 'Tenant is not directory-synced.'; return $script:AdState }
    if (-not (Import-AdModule))       { $script:AdState.Reason = 'The ActiveDirectory (RSAT) module is not installed on this workstation.'; return $script:AdState }

    $dc = Resolve-WritableDc -DomainName $expected
    if (-not $dc) {
        $script:AdState.Reason = if ($expected) {
            "No writable domain controller for '$expected' is reachable from here. Connect to that network (VPN / RDP) first."
        } else { 'No writable domain controller is reachable from this workstation.' }
        return $script:AdState
    }
    $dcDomain = Get-AdServerDomain -Dc $dc
    $script:AdState.Dc = $dc
    $script:AdState.DcDomain = $dcDomain

    # Forest-pairing guard: the reachable DC MUST be in the tenant's expected on-prem domain. This refuses
    # the wrong-forest case (signed into tenant B, but only tenant A's DC reachable -- e.g. on the local
    # LAN with the other VPN down). With scoped discovery this should already hold; verify belt-and-braces.
    if (-not (Test-OnPremDomainMatch -Expected $expected -Actual $dcDomain)) {
        $script:AdState.Reason = "The reachable domain controller is in '$dcDomain', but this tenant syncs from '$expected'. Connect to '$expected' (VPN / RDP) before editing its on-premises objects."
        return $script:AdState
    }
    $script:AdState.Available = $true
    return $script:AdState
}

function Get-AdState { $script:AdState }

function Test-OnPremReadyForObject {
    <# Is on-prem AD currently CONNECTED + verified for THIS object's domain? Reads the cached capability
       ONLY (never probes -- the operator connects on-prem explicitly via the sidebar). True means: a
       connect was made AND it succeeded AND the connected DC's domain matches this object's
       onPremisesDomainName. Used to decide read-only gating and whether a save routes to AD. #>
    param($Object)
    $st = $script:AdState
    if (-not ($st.Checked -and $st.Available)) { return $false }
    return (Test-OnPremDomainMatch -Expected ([string](Get-GraphVal $Object 'onPremisesDomainName')) -Actual $st.DcDomain)
}

# --- Cloud -> on-prem object mapping -------------------------------------------------------

function Protect-AdFilterValue {
    <# Escape a data value for safe use inside an AD -Filter single-quoted token. The AD filter
       parser auto-escapes the LDAP metacharacters * ( ) / \ inside quotes, but a literal single
       quote is NOT auto-escaped and must be doubled -- otherwise a value like o'brien@contoso.com
       breaks the filter and the lookup silently returns nothing. #>
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return ($Value -replace "'", "''")
}

function Get-AdUserForCloudObject {
    <# Find the on-prem AD user for a synced cloud user (sAMAccountName first, then DN) and VERIFY it is the
       same principal -- objectSid == onPremisesSecurityIdentifier -- before returning. That rejects a
       same-named account in the wrong forest instead of editing it. $null if not found / not confirmed. #>
    param($Object, [string]$Dc)
    $sid = [string](Get-GraphVal $Object 'onPremisesSecurityIdentifier')
    $sam = Get-GraphVal $Object 'onPremisesSamAccountName'
    if ($sam) {
        $u = Get-ADUser -Filter "sAMAccountName -eq '$(Protect-AdFilterValue $sam)'" -Server $Dc -ErrorAction SilentlyContinue
        if ($u -and (Test-AdIdentityMatch -AdObject $u -ExpectedSid $sid)) { return $u }
    }
    $dn = Get-GraphVal $Object 'onPremisesDistinguishedName'
    if ($dn) { try { $u = Get-ADUser -Identity $dn -Server $Dc -ErrorAction Stop; if (Test-AdIdentityMatch -AdObject $u -ExpectedSid $sid) { return $u } } catch { } }
    return $null
}

function Get-AdGroupForCloudObject {
    <# Find the on-prem AD group for a synced cloud group and VERIFY objectSid == onPremisesSecurityIdentifier
       before returning. $null if not found / not confirmed. #>
    param($Object, [string]$Dc)
    $sid = [string](Get-GraphVal $Object 'onPremisesSecurityIdentifier')
    $sam = Get-GraphVal $Object 'onPremisesSamAccountName'
    if ($sam) {
        $g = Get-ADGroup -Filter "sAMAccountName -eq '$(Protect-AdFilterValue $sam)'" -Server $Dc -ErrorAction SilentlyContinue
        if ($g -and (Test-AdIdentityMatch -AdObject $g -ExpectedSid $sid)) { return $g }
    }
    if ($sid) { try { $g = Get-ADGroup -Identity $sid -Server $Dc -ErrorAction Stop; if (Test-AdIdentityMatch -AdObject $g -ExpectedSid $sid) { return $g } } catch { } }
    return $null
}

function Resolve-AdUserFromPerson {
    <# Resolve a picked/loaded directory person to an AD user via its UPN. Person objects come in TWO
       shapes: the person picker uses the 'Detail' key, while Get-UserManagerInfo uses 'Upn' -- accept
       either (otherwise a loaded manager never resolves on-prem). $null if not found. #>
    param($Person, [string]$Dc)
    $upn = [string]$Person.Detail
    if (-not $upn) { $upn = [string]$Person.Upn }
    if ($upn -and $upn -match '^[^@\s]+@[^@\s]+$') {
        $u = Get-ADUser -Filter "userPrincipalName -eq '$(Protect-AdFilterValue $upn)'" -Server $Dc -ErrorAction SilentlyContinue
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

# --- On-prem user CREATE (hybrid: create in AD, let Entra Connect sync it up) --------------

function Get-AdSamAccountName {
    <# PURE: derive a legal sAMAccountName from an alias -- lowercase, strip everything outside a safe
       subset (letters/digits/./-/_), cap at the legacy 20-char limit. May still need a uniqueness check
       by the caller (two long aliases can truncate to the same SAM). #>
    param([string]$Alias)
    $s = (([string]$Alias).ToLower() -replace '[^a-z0-9.\-_]', '').Trim('.')
    if ($s.Length -gt 20) { $s = $s.Substring(0, 20) }
    return $s
}

function Test-AdSamAccountNameValid {
    <# PURE: $true if $Sam is a usable sAMAccountName -- 1..20 chars and none of the characters AD
       forbids: " / \ [ ] : ; | = , + * ? < > #>
    param([string]$Sam)
    if ([string]::IsNullOrEmpty($Sam) -or $Sam.Length -gt 20) { return $false }
    return ($Sam -notmatch '["/\\\[\]:;|=,+*?<>]')
}

function Get-NewAdUserParamMap {
    <# Graph (camelCase) -> New-ADUser NATIVE parameter name, for the attributes that have a dedicated
       cmdlet parameter. Attributes NOT here go through -OtherAttributes (keyed by LDAP name). An attr
       must NEVER be passed both ways, so this split is what avoids the "cannot be specified in
       OtherAttributes" conflict. userPrincipalName/sAMAccountName are first-class create params handled
       by the wrapper; password/manager/enabled have their own wrappers. #>
    @{
        displayName    = 'DisplayName'
        givenName      = 'GivenName'
        surname        = 'Surname'
        jobTitle       = 'Title'
        department     = 'Department'
        companyName    = 'Company'
        employeeId     = 'EmployeeID'
        officeLocation = 'Office'
        mobilePhone    = 'MobilePhone'
        businessPhones = 'OfficePhone'
        streetAddress  = 'StreetAddress'
        city           = 'City'
        state          = 'State'
        postalCode     = 'PostalCode'
    }
}

function ConvertTo-NewAdUserParams {
    <#
        PURE: split a set of non-empty cloud scalar changes into New-ADUser native parameters and a
        residual -OtherAttributes hashtable (keyed by LDAP name). Input: @( @{ Name; Value }, ... ).
        Output: @{ NativeParams = @{DisplayName=...}; OtherAttributes = @{ldap=...} }.
        Skips empties, and skips userPrincipalName + mailNickname (UPN is a first-class create param;
        mailNickname is intentionally NOT stamped on-prem -- let Exchange own the mail alias/proxies).
    #>
    param([object[]]$Changes)
    $paramMap = Get-NewAdUserParamMap
    $ldapMap = Get-CloudToAdAttributeMap
    $native = @{}; $other = @{}
    foreach ($c in $Changes) {
        if (-not $c -or -not $c.Name) { continue }
        if ($c.Name -in 'userPrincipalName', 'mailNickname') { continue }
        $v = $c.Value
        if ($v -is [System.Array]) { $v = @($v | Where-Object { "$_".Trim() }) | Select-Object -First 1 }
        if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { continue }
        if ($paramMap.ContainsKey($c.Name))    { $native[$paramMap[$c.Name]] = [string]$v }
        elseif ($ldapMap.ContainsKey($c.Name)) { $other[$ldapMap[$c.Name]] = [string]$v }
    }
    return @{ NativeParams = $native; OtherAttributes = $other }
}

function Get-AdOrganizationalUnitList {
    <# OUs (Name/DistinguishedName) for the target-OU picker. Capped + paged so a large forest can't
       hang the UI; returns @() on any failure so the caller falls back to the default container. #>
    param([Parameter(Mandatory)][string]$Dc, [int]$Max = 500)
    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Server $Dc -ResultSetSize $Max -ResultPageSize 256 -ErrorAction Stop |
            Select-Object -Property Name, DistinguishedName | Sort-Object DistinguishedName
        return @($ous | ForEach-Object { @{ Name = [string]$_.Name; DistinguishedName = [string]$_.DistinguishedName } })
    } catch { return @() }
}

function Get-AdDefaultUserPath {
    <# The domain's default Users CONTAINER DN (CN=Users,...) as a fallback OU. Note: it is a container,
       not an OU, so it won't appear in Get-AdOrganizationalUnitList -- the caller adds it explicitly. #>
    param([Parameter(Mandatory)][string]$Dc)
    try { return [string]((Get-ADDomain -Server $Dc -ErrorAction Stop).UsersContainer) } catch { return '' }
}

function New-AdUserAccount {
    <#
        Create an on-prem AD user in $Path on $Dc, then set its password + enable it. New-ADUser makes a
        DISABLED, password-less account, so order matters: create -> set password -> enable. Native
        attributes come via $NativeParams (built by ConvertTo-NewAdUserParams); residual attrs via
        $OtherAttributes. Password is MANDATORY (it's a create). If the password is rejected by domain
        policy the account exists but stays DISABLED -- we surface that distinctly so the caller can tell
        the operator to fix it in AD rather than showing a raw exception. Returns the created AD user.
    #>
    param(
        [Parameter(Mandatory)][string]$Dc,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$SamAccountName,
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$Password,
        [hashtable]$NativeParams = @{},
        [hashtable]$OtherAttributes = @{},
        [bool]$ForceChangeAtLogon = $true,
        [bool]$Enabled = $true
    )
    $p = @{ Server = $Dc; Path = $Path; Name = $Name; SamAccountName = $SamAccountName; UserPrincipalName = $UserPrincipalName; ErrorAction = 'Stop' }
    foreach ($k in $NativeParams.Keys) { $p[$k] = $NativeParams[$k] }
    if ($OtherAttributes -and $OtherAttributes.Count) { $p.OtherAttributes = $OtherAttributes }
    $created = New-ADUser @p -PassThru

    try {
        Reset-AdUserPasswordValue -AdUser $created -Dc $Dc -Password $Password -ForceChange $ForceChangeAtLogon
    } catch {
        throw ("The account '$SamAccountName' was created in Active Directory but is DISABLED -- its password " +
               "was rejected by the domain password policy ($($_.Exception.Message)). Set a compliant password " +
               "on it in Active Directory Users and Computers, or delete it and retry with a stronger password.")
    }
    if ($Enabled) { Set-AdAccountEnabledState -AdUser $created -Dc $Dc -Enabled $true }
    return $created
}

function Test-AdSamInUse {
    <# Is $Sam already taken in the domain? $true = in use (block), $false = free, $null = the check
       couldn't run (AD blip) so the caller should proceed and let New-ADUser be the final arbiter. #>
    param([Parameter(Mandatory)][string]$Sam, [Parameter(Mandatory)][string]$Dc)
    try { return [bool](Get-ADUser -Filter "sAMAccountName -eq '$(Protect-AdFilterValue $Sam)'" -Server $Dc -ErrorAction Stop) }
    catch { return $null }
}

function Sync-AdGroupMembership {
    <#
        Apply an add/remove membership diff to a synced AD group. $Now / $Original are picked person
        lists (@{Id;Detail}); members are resolved to AD users by UPN. Returns @{ Unresolved = @(...) }.
    #>
    param($AdGroup, [string]$Dc, [object[]]$Now, [object[]]$Original)
    $nowIds  = @($Now      | ForEach-Object { $_.Id })
    $origIds = @($Original | ForEach-Object { $_.Id })
    # Collect-and-continue: a single failed add/remove must NOT abort the rest (and lose the warnings
    # gathered so far) -- it would leave the group half-updated with no report.
    $warnings = New-Object System.Collections.Generic.List[string]

    foreach ($p in $Now)      { if ($origIds -notcontains $p.Id) {
        $ad = Resolve-AdUserFromPerson -Person $p -Dc $Dc
        if (-not $ad) { [void]$warnings.Add("Member '$($p.DisplayName)' wasn't found in AD by UPN; not added."); continue }
        try { Add-ADGroupMember -Identity $AdGroup -Members $ad -Server $Dc -Confirm:$false -ErrorAction Stop }
        catch { [void]$warnings.Add("Add of '$($p.DisplayName)' failed: $($_.Exception.Message)") }
    } }
    foreach ($p in $Original) { if ($nowIds -notcontains $p.Id) {
        $ad = Resolve-AdUserFromPerson -Person $p -Dc $Dc
        if (-not $ad) { [void]$warnings.Add("Member '$($p.DisplayName)' wasn't found in AD by UPN; not removed."); continue }
        try { Remove-ADGroupMember -Identity $AdGroup -Members $ad -Server $Dc -Confirm:$false -ErrorAction Stop }
        catch { [void]$warnings.Add("Remove of '$($p.DisplayName)' failed: $($_.Exception.Message)") }
    } }
    return @{ Warnings = $warnings.ToArray() }
}
