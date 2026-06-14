<#
    Group operations + membership / ownership.

    Thin wrappers over Microsoft.Graph.Groups. Group type is decided by the
    securityEnabled / mailEnabled / groupTypes combination and is IMMUTABLE after creation, so
    the orchestration layer locks those fields in Edit mode. Membership is incremental: edits
    apply as add ($ref) / remove ($ref) operations -- there is no wholesale members replace.

    Cmdlet choices (verified against Microsoft Learn):
      * Add member/owner via the *ByRef -OdataId form (documented and version-stable).
      * Remove member via Remove-MgGroupMemberDirectoryObjectByRef (maintainer-recommended;
        the plain Remove-MgGroupMemberByRef lost -DirectoryObjectId in SDK 2.17.x).
      * The last owner of a group cannot be removed (Graph enforces; surfaced as an error).
#>

function Get-GroupSelectProperties {
    @(
        'id', 'displayName', 'mailNickname', 'description', 'mail',
        'visibility', 'groupTypes', 'securityEnabled', 'mailEnabled',
        'membershipRule', 'membershipRuleProcessingState', 'createdDateTime',
        # Source-of-authority detection (hybrid) + on-prem correlation keys.
        'onPremisesSyncEnabled', 'onPremisesSamAccountName', 'onPremisesDomainName',
        'onPremisesSecurityIdentifier', 'onPremisesLastSyncDateTime'
    )
}

function Search-DirectoryGroup {
    param([string]$Query, [int]$Top = 100)
    if ([string]::IsNullOrWhiteSpace($Query)) {
        # Empty query = browse: list the first N groups.
        return Get-MgGroup -Top $Top -Property 'id', 'displayName', 'mail', 'groupTypes', 'securityEnabled', 'mailEnabled' -ErrorAction Stop | Sort-Object DisplayName
    }
    $q = $Query.Replace("'", "''")
    Get-MgGroup -Filter "startsWith(displayName,'$q') or startsWith(mail,'$q') or startsWith(mailNickname,'$q')" `
        -ConsistencyLevel eventual -CountVariable searchCount -Top $Top `
        -Property 'id', 'displayName', 'mail', 'groupTypes', 'securityEnabled', 'mailEnabled' -ErrorAction Stop |
        Sort-Object DisplayName
}

function Get-GroupById {
    param([Parameter(Mandatory)][string]$Id)
    Get-MgGroup -GroupId $Id -Property (Get-GroupSelectProperties) -ErrorAction Stop
}

function Get-GroupTypeLabel {
    <# Human label for a group object's type, based on its property combination. #>
    param($Group)
    $types = @(Get-GraphVal $Group 'groupTypes')
    if ($types -contains 'Unified') { return 'Microsoft 365' }
    $sec  = [bool](Get-GraphVal $Group 'securityEnabled')
    $mail = [bool](Get-GraphVal $Group 'mailEnabled')
    if ($sec -and $mail)  { return 'Mail-enabled security (read-only via Graph)' }
    if ($mail)            { return 'Distribution list (read-only via Graph)' }
    if ($sec)             { return 'Security' }
    return 'Unknown'
}

function ConvertTo-DirectoryObjectInfo {
    <# Normalise a member/owner directoryObject into @{ Id; DisplayName; Detail; Type }. #>
    param($Object)
    $type = [string](Get-GraphVal $Object '@odata.type')
    $kind = switch -Wildcard ($type) {
        '*user'             { 'User' }
        '*group'            { 'Group' }
        '*servicePrincipal' { 'ServicePrincipal' }
        '*device'           { 'Device' }
        default             { 'Object' }
    }
    @{
        Id          = [string](Get-GraphVal $Object 'id')
        DisplayName = [string](Get-GraphVal $Object 'displayName')
        Detail      = [string]((Get-GraphVal $Object 'userPrincipalName'), (Get-GraphVal $Object 'mail') | Where-Object { $_ } | Select-Object -First 1)
        Type        = $kind
    }
}

function Get-GroupMemberInfo {
    param([Parameter(Mandatory)][string]$Id)
    Get-MgGroupMember -GroupId $Id -All -ErrorAction Stop | ForEach-Object { ConvertTo-DirectoryObjectInfo $_ }
}

function Get-GroupOwnerInfo {
    param([Parameter(Mandatory)][string]$Id)
    Get-MgGroupOwner -GroupId $Id -All -ErrorAction Stop | ForEach-Object { ConvertTo-DirectoryObjectInfo $_ }
}

function New-DirectoryGroup {
    param([Parameter(Mandatory)][hashtable]$Body)
    New-MgGroup -BodyParameter $Body -ErrorAction Stop
}

function Update-DirectoryGroup {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][hashtable]$Body)
    Update-MgGroup -GroupId $Id -BodyParameter $Body -ErrorAction Stop
}

function Add-GroupMember {
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$ObjectId)
    New-MgGroupMemberByRef -GroupId $GroupId -OdataId "$script:GraphBaseUri/directoryObjects/$ObjectId" -ErrorAction Stop
}

function Remove-GroupMember {
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$ObjectId)
    Remove-MgGroupMemberDirectoryObjectByRef -GroupId $GroupId -DirectoryObjectId $ObjectId -ErrorAction Stop
}

function Add-GroupOwner {
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$ObjectId)
    New-MgGroupOwnerByRef -GroupId $GroupId -OdataId "$script:GraphBaseUri/directoryObjects/$ObjectId" -ErrorAction Stop
}

function Remove-GroupOwner {
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$ObjectId)
    Remove-MgGroupOwnerByRef -GroupId $GroupId -DirectoryObjectId $ObjectId -ErrorAction Stop
}

function Remove-DirectoryGroup {
    <# Microsoft 365 groups are soft-deleted (recoverable ~30 days); security groups are
       removed permanently. #>
    param([Parameter(Mandatory)][string]$Id)
    Remove-MgGroup -GroupId $Id -ErrorAction Stop
}
