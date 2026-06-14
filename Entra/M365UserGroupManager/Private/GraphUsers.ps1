<#
    User operations.

    Thin wrappers over the Microsoft.Graph.Users cmdlets, each using -ErrorAction Stop so the
    UI layer can try/catch and surface a clean message. Payload assembly (which fields to send,
    dirty-diffing on edit, nesting extension attributes) lives in the orchestration layer
    (UiMainForm) -- these functions just talk to Graph.

    Graph facts baked in here (verified against Microsoft Learn):
      * Create requires accountEnabled, displayName, mailNickname, userPrincipalName, passwordProfile.
      * manager is a relationship -> Set-MgUserManagerByRef (@odata.id), not a plain property.
      * proxyAddresses is read-only via Graph; extensionAttribute1-15 are writable only for
        cloud-only users (handled by the caller via Test-UserExtAttrWritable).
      * Remove-MgUser is a soft delete (recoverable ~30 days).
#>

$script:GraphBaseUri = 'https://graph.microsoft.com/v1.0'

function Get-UserSelectProperties {
    <# The $select list to hydrate a user for editing: every readable catalog property plus
       the extras the form/logic needs (sync state, extension-attribute container, licenses). #>
    $props = New-Object System.Collections.Generic.List[string]
    foreach ($a in (Get-CatalogAttributeList -Tab 'User')) {
        switch ($a.Input) {
            'ExtAttr'  { }   # not individually selectable; comes via onPremisesExtensionAttributes
            'Person'   { }   # manager is a navigation property, fetched separately
            'Password' { }   # write-only
            default    { [void]$props.Add($a.Name) }
        }
    }
    foreach ($extra in 'id', 'displayName', 'userPrincipalName', 'usageLocation',
                       'onPremisesSyncEnabled', 'onPremisesExtensionAttributes', 'assignedLicenses',
                       # On-prem correlation keys for hybrid edit routing (P1: cloud -> AD object mapping).
                       'onPremisesSamAccountName', 'onPremisesDomainName', 'onPremisesDistinguishedName') {
        [void]$props.Add($extra)
    }
    return @($props | Select-Object -Unique)
}

function Search-DirectoryUser {
    param([string]$Query, [int]$Top = 100)
    if ([string]::IsNullOrWhiteSpace($Query)) {
        # Empty query = browse: list the first N users.
        return Get-MgUser -Top $Top -Property 'id', 'displayName', 'userPrincipalName', 'mail' -ErrorAction Stop | Sort-Object DisplayName
    }
    $q = $Query.Replace("'", "''")
    Get-MgUser -Filter "startsWith(displayName,'$q') or startsWith(userPrincipalName,'$q') or startsWith(mail,'$q') or startsWith(surname,'$q')" `
        -ConsistencyLevel eventual -CountVariable searchCount -Top $Top `
        -Property 'id', 'displayName', 'userPrincipalName', 'mail' -ErrorAction Stop |
        Sort-Object DisplayName
}

function Get-UserById {
    param([Parameter(Mandatory)][string]$Id)
    Get-MgUser -UserId $Id -Property (Get-UserSelectProperties) -ErrorAction Stop
}

function Get-UserManagerInfo {
    <# Returns @{ Id; DisplayName; Upn } for the user's manager, or $null if none. #>
    param([Parameter(Mandatory)][string]$Id)
    try {
        $m = Get-MgUserManager -UserId $Id -ErrorAction Stop
        if (-not $m) { return $null }
        return @{
            Id          = [string](Get-GraphVal $m 'id')
            DisplayName = [string](Get-GraphVal $m 'displayName')
            Upn         = [string](Get-GraphVal $m 'userPrincipalName')
        }
    } catch {
        return $null   # 404 = no manager assigned
    }
}

function New-DirectoryUser {
    <# Create a user from a fully-formed Graph body hashtable. Returns the new user. #>
    param([Parameter(Mandatory)][hashtable]$Body)
    New-MgUser -BodyParameter $Body -ErrorAction Stop
}

function Update-DirectoryUser {
    <# PATCH an existing user with a partial body hashtable (only the changed fields). #>
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][hashtable]$Body)
    Update-MgUser -UserId $Id -BodyParameter $Body -ErrorAction Stop
}

function Set-UserManager {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$ManagerId)
    Set-MgUserManagerByRef -UserId $Id -OdataId "$script:GraphBaseUri/users/$ManagerId" -ErrorAction Stop
}

function Remove-UserManager {
    param([Parameter(Mandatory)][string]$Id)
    Remove-MgUserManagerByRef -UserId $Id -ErrorAction Stop
}

function Set-UserAccountEnabled {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][bool]$Enabled)
    # -AccountEnabled is a SwitchParameter; drive it from a variable with the :$bool syntax.
    Update-MgUser -UserId $Id -AccountEnabled:$Enabled -ErrorAction Stop
}

function Reset-UserPassword {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Password,
        [bool]$ForceChangeNextSignIn = $true
    )
    Update-MgUser -UserId $Id -PasswordProfile @{
        Password                      = $Password
        ForceChangePasswordNextSignIn = $ForceChangeNextSignIn
    } -ErrorAction Stop
}

function Remove-DirectoryUser {
    <# Soft delete (recoverable ~30 days via deletedItems). #>
    param([Parameter(Mandatory)][string]$Id)
    Remove-MgUser -UserId $Id -ErrorAction Stop
}

function Test-UserExtAttrWritable {
    <#
        Extension attributes are writable via Graph only for cloud-only users. This returns
        $false for directory-synced users. Note: a cloud-only user PREVIOUSLY synced from
        on-prem also can't be written via Graph, and that state can't be detected from
        onPremisesSyncEnabled alone -- so a write may still fail; the caller surfaces that.
    #>
    param($User)
    $synced = Get-GraphVal $User 'onPremisesSyncEnabled'
    return (-not [bool]$synced)
}
