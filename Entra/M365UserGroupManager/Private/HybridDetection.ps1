<#
    Hybrid (on-prem AD + Entra cloud) detection and Source-of-Authority (SOA) routing.

    Pure helpers (no Graph/AD calls) decide, for a loaded object, whether each catalog field is
    editable in the cloud or is mastered on-premises -- so the form can render synced objects
    correctly and (later phases) route those edits to Active Directory. The live helpers detect
    whether the tenant is hybrid and whether this workstation can reach AD; they only run once
    connected and are gated behind a Graph connection.

    SOA model (verified against Microsoft Learn, 2026):
      onPremisesSyncEnabled  true  = synced from on-prem AD; identity attributes are mastered
                                       on-prem and READ-ONLY via Graph        -> Authority 'OnPrem'
                             false = was synced, now orphaned                 -> treat as cloud
                             null  = cloud-only / never synced (incl. an      -> treat as cloud
                                       object whose SOA was transferred to cloud)
      A small set of attributes stays cloud-authoritative even for a synced user (licenses,
      usageLocation, userType, password with SSPR writeback) -> Authority 'Cloud'.

    Nothing here writes to AD -- that is P1 (Private/OnPremAd.ps1). See docs/HYBRID-SUPPORT-PLAN.md.
#>

# Cached hybrid / capability facts for the current connection + machine.
# Tenant facts clear on disconnect / tenant switch (Reset-HybridState); machine facts persist.
$script:HybridState = @{
    TenantChecked = $false
    TenantHybrid  = $false
    RsatChecked   = $false
    RsatPresent   = $false
}

function Reset-HybridState {
    <# Clear cached per-tenant hybrid facts (+ the AD-write capability + the cached org object). Call on
       disconnect / switch. #>
    $script:HybridState.TenantChecked = $false
    $script:HybridState.TenantHybrid  = $false
    if (Get-Command Clear-OrganizationCache -ErrorAction SilentlyContinue) { Clear-OrganizationCache }
    if (Get-Command Reset-AdState -ErrorAction SilentlyContinue) { Reset-AdState }
}

# --- Pure SOA / authority logic (exercised offline) ----------------------------------------

function Resolve-FieldAuthority {
    <# Where a catalog field is mastered when its object is synced: 'Cloud' | 'OnPrem' | 'ReadOnly'. #>
    param($Attr)
    if ($Attr.Authority) { return [string]$Attr.Authority }
    if ($Attr.Input -eq 'ReadOnly') { return 'ReadOnly' }
    return 'OnPrem'
}

function Test-ObjectSynced {
    <# $true if the object is directory-synced from on-prem AD right now (onPremisesSyncEnabled = true). #>
    param($Object)
    if ($null -eq $Object) { return $false }
    return ((Get-GraphVal $Object 'onPremisesSyncEnabled') -eq $true)
}

function Get-ObjectSourceLabel {
    <# Short ASCII label for the object's source-of-authority badge (no Unicode -- mojibake guard). #>
    param($Object)
    if ($null -eq $Object) { return 'New' }
    if (Test-ObjectSynced $Object) {
        $dom = Get-GraphVal $Object 'onPremisesDomainName'
        if ($dom) { return "Synced from AD ($dom)" }
        return 'Synced from AD'
    }
    return 'Cloud'
}

function Test-FieldCloudEditable {
    <#
        Can this catalog field be edited via Graph for the given LOADED object?
          - New mode ($Object = $null): yes if the field is writable (existing behaviour).
          - Cloud-only object: yes if writable (existing behaviour; Authority is irrelevant).
          - Synced object: only fields whose Authority is 'Cloud'.
    #>
    param($Attr, $Object)
    if (-not $Attr.Writable) { return $false }
    if ($Attr.Input -eq 'ReadOnly') { return $false }
    if (-not (Test-ObjectSynced $Object)) { return $true }
    return ((Resolve-FieldAuthority $Attr) -eq 'Cloud')
}

function Get-FieldHybridState {
    <#
        UI helper: how the form should treat one field for a loaded object.
        Returns @{ Synced; Authority; CloudEditable; OnPremMastered; Hint }.
        OnPremMastered = the field is synced + on-prem-authored, so a real edit must go to AD.
    #>
    param($Attr, $Object)
    $synced = Test-ObjectSynced $Object
    $auth   = Resolve-FieldAuthority $Attr
    $cloud  = Test-FieldCloudEditable -Attr $Attr -Object $Object
    $onprem = ($synced -and $auth -eq 'OnPrem')
    $hint   = if ($onprem) { 'Managed in Active Directory (synced) - edit on-premises' } else { '' }
    return @{ Synced = $synced; Authority = $auth; CloudEditable = $cloud; OnPremMastered = $onprem; Hint = $hint }
}

# --- Live detection (requires a Graph connection; not exercised offline) -------------------

function Get-TenantHybridState {
    <# $true if the tenant has directory sync configured. Cached for the connection. Reads the shared
       cached organization object so the connect path makes ONE Get-MgOrganization call (shared with the
       verified-domain dropdown), not a second dedicated one. #>
    if ($script:HybridState.TenantChecked) { return $script:HybridState.TenantHybrid }
    $hybrid = $false
    try {
        $org = Get-OrganizationCached
        $hybrid = ((Get-GraphVal $org 'onPremisesSyncEnabled') -eq $true)
    } catch {
        $hybrid = $false   # best-effort; treat as non-hybrid if the read fails
    }
    $script:HybridState.TenantChecked = $true
    $script:HybridState.TenantHybrid  = $hybrid
    return $hybrid
}

function Get-CachedTenantHybridState {
    <# The cached hybrid answer WITHOUT triggering any Graph call -- for hot UI paths (the connection
       label, which refreshes on every connect/switch/disconnect and used to fire a Get-MgOrganization
       each time just to decide the Force-sync button). Returns $false until Get-TenantHybridState has
       run once for the connection (which the connect flow does, up front). #>
    if ($script:HybridState.TenantChecked) { return $script:HybridState.TenantHybrid }
    return $false
}

# --- On-prem capability detection (best-effort; full DC reachability lands in P1) ----------

function Test-RsatAdModule {
    <# $true if the ActiveDirectory (RSAT) PowerShell module is available on this machine. Cached. #>
    if ($script:HybridState.RsatChecked) { return $script:HybridState.RsatPresent }
    $present = $false
    try { $present = [bool](Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) } catch { $present = $false }
    $script:HybridState.RsatChecked = $true
    $script:HybridState.RsatPresent = $present
    return $present
}

function Test-MachineDomainJoined {
    <# $true if this workstation is joined to an AD domain (a prerequisite for on-prem edits). #>
    try { return [bool]([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()) }
    catch { return $false }
}
