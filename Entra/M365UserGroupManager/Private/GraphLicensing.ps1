<#
    License operations.

    Set-MgUserLicense lives in Microsoft.Graph.Users.Actions. usageLocation must be set on the
    user before assigning a license (legal availability check) -- the orchestration layer
    ensures that first. Both -AddLicenses and -RemoveLicenses are always supplied (with @() for
    the unused side), matching Microsoft's documented examples.
#>

function Initialize-SkuMap {
    <# Populate (and cache) the SkuId -> SkuPartNumber map for the current tenant. #>
    param([switch]$Force)
    if (-not $Force -and $script:SkuMap.Count -gt 0) { return }
    $script:SkuMap = @{}
    try {
        Get-MgSubscribedSku -All -Property 'SkuId', 'SkuPartNumber' -ErrorAction Stop | ForEach-Object {
            $script:SkuMap[[string]$_.SkuId] = [string]$_.SkuPartNumber
        }
    } catch {
        Set-Progress "Note: could not read subscribed SKUs ($($_.Exception.Message))."
    }
}

function Get-AvailableSku {
    <# Tenant SKUs as @{ SkuId; PartNumber; Consumed; Enabled; Available } for the license picker. #>
    $list = New-Object System.Collections.Generic.List[object]
    try {
        Get-MgSubscribedSku -All -ErrorAction Stop | ForEach-Object {
            $enabled  = [int]$_.PrepaidUnits.Enabled
            $consumed = [int]$_.ConsumedUnits
            [void]$list.Add([pscustomobject]@{
                SkuId     = [string]$_.SkuId
                PartNumber = [string]$_.SkuPartNumber
                Consumed  = $consumed
                Enabled   = $enabled
                Available = ($enabled - $consumed)
            })
            $script:SkuMap[[string]$_.SkuId] = [string]$_.SkuPartNumber
        }
    } catch {
        Set-Progress "Could not read subscribed SKUs: $($_.Exception.Message)"
    }
    return ($list | Sort-Object PartNumber)
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
