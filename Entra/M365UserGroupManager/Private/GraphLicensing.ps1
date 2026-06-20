<#
    License operations.

    Set-MgUserLicense lives in Microsoft.Graph.Users.Actions. usageLocation must be set on the
    user before assigning a license (legal availability check) -- the orchestration layer
    ensures that first. Both -AddLicenses and -RemoveLicenses are always supplied (with @() for
    the unused side), matching Microsoft's documented examples.
#>

function Reset-SkuCache {
    <# Drop the per-tenant license caches (the SkuId->name map AND the rich detail list the picker uses).
       Call on connect / switch / disconnect -- a fresh tenant has different SKUs. #>
    $script:SkuMap = @{}
    $script:SkuDetailCache = $null
}

function ConvertTo-SkuDetailList {
    <# PURE: a subscribedSkus collection (typed Get-MgSubscribedSku objects OR raw JSON hashtables from a
       $batch response body) -> @{ Map = SkuId->PartNumber; Details = @(@{SkuId;PartNumber;Consumed;
       Enabled;Available}) sorted }. Get-GraphVal reads either shape, so the cmdlet path and the connect
       $batch path share ONE parser (and one tested shape). #>
    param($SkuValues)
    $map = @{}
    $details = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($SkuValues)) {
        if (-not $s) { continue }
        $id       = [string](Get-GraphVal $s 'skuId')
        $pn       = [string](Get-GraphVal $s 'skuPartNumber')
        $enabled  = [int](Get-GraphVal (Get-GraphVal $s 'prepaidUnits') 'enabled')
        $consumed = [int](Get-GraphVal $s 'consumedUnits')
        if ($id) { $map[$id] = $pn }
        [void]$details.Add([pscustomobject]@{
            SkuId = $id; PartNumber = $pn; Consumed = $consumed; Enabled = $enabled; Available = ($enabled - $consumed)
        })
    }
    return @{ Map = $map; Details = @($details | Sort-Object PartNumber) }
}

function Set-SkuCacheFromValues {
    <# Seed BOTH license caches from a subscribedSkus collection (a Get-MgSubscribedSku result, or the
       body.value of the connect $batch). One seeder keeps the two fetch paths identical. #>
    param($SkuValues)
    $r = ConvertTo-SkuDetailList -SkuValues $SkuValues
    $script:SkuMap = $r.Map
    $script:SkuDetailCache = $r.Details
}

function Initialize-SkuMap {
    <#
        Populate (and cache) BOTH license caches for the current tenant in a SINGLE Get-MgSubscribedSku
        pass: the SkuId -> SkuPartNumber name map, and the rich @{SkuId;PartNumber;Consumed;Enabled;
        Available} detail list the license picker renders. Previously the map and EACH license-field
        build re-paged all SKUs separately (3+ identical enumerations per connect); now it's one --
        and the connect $batch usually seeds it first, so this no-ops entirely unless -Force.
    #>
    param([switch]$Force)
    if (-not $Force -and $script:SkuMap.Count -gt 0 -and $null -ne $script:SkuDetailCache) { return }
    try {
        Set-SkuCacheFromValues -SkuValues (Get-MgSubscribedSku -All -ErrorAction Stop)
    } catch {
        Set-Progress "Note: could not read subscribed SKUs ($($_.Exception.Message))."
    }
}

function Get-AvailableSku {
    <# Tenant SKUs as @{ SkuId; PartNumber; Consumed; Enabled; Available } for the license picker. Served
       from the per-connection cache (built once by Initialize-SkuMap); only hits Graph if the cache is
       empty. Returns @() if the SKUs still can't be read. #>
    if ($null -ne $script:SkuDetailCache) { return $script:SkuDetailCache }
    Initialize-SkuMap -Force
    if ($null -ne $script:SkuDetailCache) { return $script:SkuDetailCache }
    return @()
}

function Get-SkuFriendlyName {
    param([string]$SkuId)
    if ($script:SkuMap.ContainsKey($SkuId)) { return $script:SkuMap[$SkuId] }
    return $SkuId
}

function Get-UserAssignedSkuId {
    <# The SkuIds currently assigned to a user (from a hydrated user object's assignedLicenses). #>
    param($User)
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($lic in @(Get-GraphVal $User 'assignedLicenses')) {
        if ($null -eq $lic) { continue }
        $sku = [string](Get-GraphVal $lic 'skuId')
        if ($sku) { [void]$ids.Add($sku) }
    }
    return @($ids)
}

function Set-UserLicenseAssignment {
    <#
        Apply a license diff to a user. AddSkuIds get assigned (no disabled plans); RemoveSkuIds
        get removed. The user must already have a usageLocation. Both sides always supplied.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [string[]]$AddSkuIds = @(),
        [string[]]$RemoveSkuIds = @()
    )
    $add = @($AddSkuIds | Where-Object { $_ } | ForEach-Object { @{ SkuId = $_ } })
    $remove = @($RemoveSkuIds | Where-Object { $_ })
    Set-MgUserLicense -UserId $Id -AddLicenses $add -RemoveLicenses $remove -ErrorAction Stop
}
