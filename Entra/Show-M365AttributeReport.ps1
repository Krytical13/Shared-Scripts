<#
.SYNOPSIS
    GUI tool to generate Microsoft 365 / Entra ID user-attribute reports for selected
    users and/or groups, resolving nested group membership. Single, standalone script.

.DESCRIPTION
    Run it (no arguments). A window opens with three sections:

        1. Attributes - grouped, labeled checkboxes for ~70 user properties.
        2. Targets    - search-and-pick users and/or groups, or paste UPNs / group names.
                        Group membership is resolved transitively (nested groups included)
                        and de-duplicated across all selected targets.
        3. Output     - choose any of CSV / Excel (.xlsx) / HTML / JSON and a save folder.

    Authentication is interactive (delegated) - the report runs as the signed-in admin,
    with that admin's own permissions. Delegated scopes requested:

        User.Read.All         - read all user profiles, manager, memberships, direct reports
        GroupMember.Read.All  - list groups and read (transitive) group members
        Organization.Read.All - resolve license SKU GUIDs to friendly names (subscribedSkus)

.EXAMPLE
    .\Show-M365AttributeReport.ps1
    Launches the GUI. (Or right-click the file > Run with PowerShell.)

.NOTES
    Requirements:
      * Windows. Runs on Windows PowerShell 5.1 OR PowerShell 7+ (the script re-launches
        itself in a single-threaded apartment when needed; pwsh defaults to MTA).
      * Microsoft Graph modules: Microsoft.Graph.Authentication, .Users, .Groups
        (auto-offered for install to CurrentUser if missing).
      * Optional: the ImportExcel module, only needed for the .xlsx format.

    Self-contained: the attribute catalog is inlined below (the $Catalog variable) - add or
    relabel columns there. Scalar/Raw kinds need no other change; Complex/Nav kinds are
    handled in ConvertTo-FlatRow.

    Sign-in activity (lastSignInDateTime, etc.) is intentionally NOT included: it needs the
    AuditLog.Read.All scope and an Entra ID P1/P2 license. To enable it: add an entry to
    $Catalog (Kind='Complex'), add 'AuditLog.Read.All' to $GraphScopes, and add a flatten
    branch in ConvertTo-FlatRow.

    Test without launching the GUI:
        $env:M365AR_NOLAUNCH=1 ; . .\Show-M365AttributeReport.ps1

    License: MIT (see repository LICENSE).
#>
[CmdletBinding()]
param(
    # Internal: set when the script has already re-launched itself in STA mode.
    [switch]$Relaunched
)

#region ----------------------------------------------------------------- STA relaunch shim
# WinForms requires a single-threaded apartment. Windows PowerShell 5.1 is STA by default;
# PowerShell 7 (pwsh) is MTA, so re-launch once in STA.
if (-not $Relaunched -and $PSCommandPath) {
    $apartment = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($apartment -ne [System.Threading.ApartmentState]::STA) {
        $hostExe = (Get-Process -Id $PID).Path
        if (-not $hostExe) { $hostExe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' } }
        $arguments = @('-NoProfile','-STA','-ExecutionPolicy','Bypass','-File', "`"$PSCommandPath`"", '-Relaunched')
        Start-Process -FilePath $hostExe -ArgumentList $arguments | Out-Null
        return
    }
}
#endregion

#region ----------------------------------------------------------------- Setup & assemblies
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try { [System.Windows.Forms.Application]::SetHighDpiMode([System.Windows.Forms.HighDpiMode]::SystemAware) | Out-Null } catch { }
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

# Graph scopes for interactive sign-in (delegated).
$script:GraphScopes = @('User.Read.All', 'GroupMember.Read.All', 'Organization.Read.All')

# Attribute catalog (inlined so this script is fully standalone -- no companion files).
#   Name    = exact Microsoft Graph property (camelCase, used verbatim for $select)
#   Label   = checkbox text + report column header
#   Kind    = Scalar | Complex | Nav | Raw   (Complex/Nav are special-cased in ConvertTo-FlatRow)
#   Default = $true to pre-check the box.   Add or relabel columns here.
$script:Catalog = @{
    Groups = @(

        @{ Name = 'Identity & IDs'; Attributes = @(
            @{ Name = 'id';                 Label = 'Object ID';               Kind = 'Scalar'; Default = $true  }
            @{ Name = 'userPrincipalName';  Label = 'User Principal Name';     Kind = 'Scalar'; Default = $true  }
            @{ Name = 'mail';               Label = 'Primary Email';           Kind = 'Scalar'; Default = $true  }
            @{ Name = 'mailNickname';       Label = 'Mail Nickname (alias)';   Kind = 'Scalar'; Default = $false }
            @{ Name = 'otherMails';         Label = 'Other Emails';            Kind = 'Scalar'; Default = $false }
            @{ Name = 'proxyAddresses';     Label = 'Proxy Addresses';         Kind = 'Scalar'; Default = $false }
            @{ Name = 'imAddresses';        Label = 'IM Addresses (SIP)';      Kind = 'Scalar'; Default = $false }
            @{ Name = 'securityIdentifier'; Label = 'Security Identifier (SID)';Kind = 'Scalar'; Default = $false }
        )}

        @{ Name = 'Name'; Attributes = @(
            @{ Name = 'displayName'; Label = 'Display Name'; Kind = 'Scalar'; Default = $true }
            @{ Name = 'givenName';   Label = 'First Name';   Kind = 'Scalar'; Default = $true }
            @{ Name = 'surname';     Label = 'Last Name';    Kind = 'Scalar'; Default = $true }
        )}

        @{ Name = 'Job & Organization'; Attributes = @(
            @{ Name = 'jobTitle';         Label = 'Job Title';                 Kind = 'Scalar';  Default = $true  }
            @{ Name = 'department';       Label = 'Department';                Kind = 'Scalar';  Default = $true  }
            @{ Name = 'companyName';      Label = 'Company Name';              Kind = 'Scalar';  Default = $false }
            @{ Name = 'manager';          Label = 'Manager';                   Kind = 'Nav';     Default = $true  }
            @{ Name = 'employeeId';       Label = 'Employee ID';               Kind = 'Scalar';  Default = $false }
            @{ Name = 'employeeType';     Label = 'Employee Type';             Kind = 'Scalar';  Default = $false }
            @{ Name = 'employeeHireDate'; Label = 'Hire Date';                 Kind = 'Scalar';  Default = $false }
            @{ Name = 'employeeOrgData';  Label = 'Org Data (Division/Cost Center)'; Kind = 'Complex'; Default = $false }
            @{ Name = 'officeLocation';   Label = 'Office Location';           Kind = 'Scalar';  Default = $false }
        )}

        @{ Name = 'Contact'; Attributes = @(
            @{ Name = 'mobilePhone';    Label = 'Mobile Phone';    Kind = 'Scalar'; Default = $false }
            @{ Name = 'businessPhones'; Label = 'Business Phones'; Kind = 'Scalar'; Default = $false }
            @{ Name = 'faxNumber';      Label = 'Fax Number';      Kind = 'Scalar'; Default = $false }
        )}

        @{ Name = 'Address & Location'; Attributes = @(
            @{ Name = 'streetAddress';         Label = 'Street Address';     Kind = 'Scalar'; Default = $false }
            @{ Name = 'city';                  Label = 'City';               Kind = 'Scalar'; Default = $false }
            @{ Name = 'state';                 Label = 'State / Province';   Kind = 'Scalar'; Default = $false }
            @{ Name = 'postalCode';            Label = 'Postal Code';        Kind = 'Scalar'; Default = $false }
            @{ Name = 'country';               Label = 'Country';            Kind = 'Scalar'; Default = $false }
            @{ Name = 'usageLocation';         Label = 'Usage Location';     Kind = 'Scalar'; Default = $false }
            @{ Name = 'preferredLanguage';     Label = 'Preferred Language'; Kind = 'Scalar'; Default = $false }
            @{ Name = 'preferredDataLocation'; Label = 'Preferred Data Location'; Kind = 'Scalar'; Default = $false }
        )}

        @{ Name = 'Account Status & Type'; Attributes = @(
            @{ Name = 'accountEnabled';                  Label = 'Account Enabled';        Kind = 'Scalar'; Default = $true  }
            @{ Name = 'userType';                        Label = 'User Type (Member/Guest)'; Kind = 'Scalar'; Default = $true }
            @{ Name = 'createdDateTime';                 Label = 'Created Date';           Kind = 'Scalar'; Default = $false }
            @{ Name = 'creationType';                    Label = 'Creation Type';          Kind = 'Scalar'; Default = $false }
            @{ Name = 'externalUserState';               Label = 'Guest Invite State';     Kind = 'Scalar'; Default = $false }
            @{ Name = 'externalUserStateChangeDateTime'; Label = 'Guest Invite Changed';   Kind = 'Scalar'; Default = $false }
            @{ Name = 'ageGroup';                        Label = 'Age Group';              Kind = 'Scalar'; Default = $false }
            @{ Name = 'consentProvidedForMinor';         Label = 'Minor Consent';          Kind = 'Scalar'; Default = $false }
            @{ Name = 'legalAgeGroupClassification';     Label = 'Legal Age Group';        Kind = 'Scalar'; Default = $false }
            @{ Name = 'isManagementRestricted';          Label = 'Mgmt Restricted';        Kind = 'Scalar'; Default = $false }
        )}

        @{ Name = 'Security & Password'; Attributes = @(
            @{ Name = 'lastPasswordChangeDateTime';      Label = 'Last Password Change';      Kind = 'Scalar'; Default = $false }
            @{ Name = 'passwordPolicies';                Label = 'Password Policies';         Kind = 'Scalar'; Default = $false }
            @{ Name = 'refreshTokensValidFromDateTime';  Label = 'Refresh Tokens Valid From'; Kind = 'Scalar'; Default = $false }
            @{ Name = 'signInSessionsValidFromDateTime'; Label = 'Sign-in Sessions Valid From'; Kind = 'Scalar'; Default = $false }
        )}

        @{ Name = 'On-premises / Sync'; Attributes = @(
            @{ Name = 'onPremisesSyncEnabled';          Label = 'Directory Synced';        Kind = 'Scalar';  Default = $true  }
            @{ Name = 'onPremisesSamAccountName';       Label = 'On-prem SamAccountName';  Kind = 'Scalar';  Default = $false }
            @{ Name = 'onPremisesUserPrincipalName';    Label = 'On-prem UPN';             Kind = 'Scalar';  Default = $false }
            @{ Name = 'onPremisesDistinguishedName';    Label = 'On-prem DN';              Kind = 'Scalar';  Default = $false }
            @{ Name = 'onPremisesDomainName';           Label = 'On-prem Domain';          Kind = 'Scalar';  Default = $false }
            @{ Name = 'onPremisesImmutableId';          Label = 'Immutable ID';            Kind = 'Scalar';  Default = $false }
            @{ Name = 'onPremisesLastSyncDateTime';     Label = 'Last Directory Sync';     Kind = 'Scalar';  Default = $false }
            @{ Name = 'onPremisesSecurityIdentifier';   Label = 'On-prem SID';             Kind = 'Scalar';  Default = $false }
            @{ Name = 'onPremisesExtensionAttributes';  Label = 'Exchange Custom Attributes 1-15'; Kind = 'Complex'; Default = $false }
        )}

        @{ Name = 'Licensing'; Attributes = @(
            @{ Name = 'assignedLicenses';        Label = 'Assigned Licenses (names)';  Kind = 'Complex'; Default = $true  }
            @{ Name = 'licenseAssignmentStates'; Label = 'License Assignment States';  Kind = 'Complex'; Default = $false }
        )}

        @{ Name = 'Membership'; Attributes = @(
            @{ Name = 'groupMemberships'; Label = 'Group Memberships (transitive)'; Kind = 'Nav'; Default = $false }
            @{ Name = 'directReports';    Label = 'Direct Reports';                 Kind = 'Nav'; Default = $false }
        )}

        @{ Name = 'Profile & Misc'; Attributes = @(
            @{ Name = 'aboutMe';          Label = 'About Me';         Kind = 'Scalar'; Default = $false }
            @{ Name = 'birthday';         Label = 'Birthday';         Kind = 'Scalar'; Default = $false }
            @{ Name = 'interests';        Label = 'Interests';        Kind = 'Scalar'; Default = $false }
            @{ Name = 'pastProjects';     Label = 'Past Projects';    Kind = 'Scalar'; Default = $false }
            @{ Name = 'responsibilities'; Label = 'Responsibilities'; Kind = 'Scalar'; Default = $false }
            @{ Name = 'schools';          Label = 'Schools';          Kind = 'Scalar'; Default = $false }
            @{ Name = 'skills';           Label = 'Skills';           Kind = 'Scalar'; Default = $false }
            @{ Name = 'mySite';           Label = 'My Site URL';      Kind = 'Scalar'; Default = $false }
        )}

        @{ Name = 'Advanced (raw JSON)'; Attributes = @(
            @{ Name = 'assignedPlans';               Label = 'Assigned Plans';            Kind = 'Raw'; Default = $false }
            @{ Name = 'provisionedPlans';            Label = 'Provisioned Plans';         Kind = 'Raw'; Default = $false }
            @{ Name = 'identities';                  Label = 'Identities';                Kind = 'Raw'; Default = $false }
            @{ Name = 'onPremisesProvisioningErrors';Label = 'On-prem Provisioning Errors'; Kind = 'Raw'; Default = $false }
            @{ Name = 'serviceProvisioningErrors';   Label = 'Service Provisioning Errors'; Kind = 'Raw'; Default = $false }
        )}
    )
}

# Shared UI / state handles.
$script:UI       = @{}
$script:Targets  = New-Object System.Collections.Generic.List[object]   # @{ Type; Id; Display; Detail }
#endregion

#region ----------------------------------------------------------------- Graph value helpers
function Get-GraphVal {
    <# Robustly read a Graph property by its camelCase name from a typed SDK object,
       a hashtable/dictionary, or an object's AdditionalProperties bag. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }

    # Hashtable and generic Dictionary[string,object] both expose ContainsKey()
    # (the non-generic IDictionary.Contains() can't be bound by PowerShell on generics).
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.ContainsKey($Name)) { return $Object[$Name] }
        $pd = $Name.Substring(0,1).ToUpper() + $Name.Substring(1)
        if ($Object.ContainsKey($pd)) { return $Object[$pd] }
        return $null
    }

    $pascal = $Name.Substring(0,1).ToUpper() + $Name.Substring(1)
    $p = $Object.PSObject.Properties[$pascal]
    if ($p) { return $p.Value }
    $p2 = $Object.PSObject.Properties[$Name]
    if ($p2) { return $p2.Value }

    $ap = $Object.PSObject.Properties['AdditionalProperties']
    if ($ap -and $ap.Value -and ($ap.Value -is [System.Collections.IDictionary])) {
        if ($ap.Value.ContainsKey($Name)) { return $ap.Value[$Name] }
    }
    return $null
}

function Format-Cell {
    <# Turn any Graph value into a flat string for CSV/Excel/HTML cells. #>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime])        { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($Value -is [System.DateTimeOffset]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($Value -is [bool])            { return $Value.ToString() }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return (@($Value) | ForEach-Object { "$_" }) -join '; '
    }
    return "$Value"
}

function Set-Progress {
    param([string]$Text, [int]$Value = -1, [int]$Max = -1)
    if ($script:UI.Status) {
        $script:UI.Status.Text = $Text
        if ($Max -gt 0)    { $script:UI.Progress.Maximum = $Max }
        if ($Value -ge 0)  { $script:UI.Progress.Value = [Math]::Min($Value, $script:UI.Progress.Maximum) }
        [System.Windows.Forms.Application]::DoEvents()
    }
}
#endregion

#region ----------------------------------------------------------------- Graph data functions
function Get-SkuFriendlyMap {
    <# SkuId (GUID) -> SkuPartNumber, for resolving assignedLicenses to readable names. #>
    $map = @{}
    try {
        Get-MgSubscribedSku -All -Property 'SkuId','SkuPartNumber' -ErrorAction Stop | ForEach-Object {
            $map[[string]$_.SkuId] = $_.SkuPartNumber
        }
    } catch {
        Set-Progress "Note: could not read subscribedSkus ($($_.Exception.Message)); showing license GUIDs."
    }
    return $map
}

function Search-DirectoryUser {
    param([string]$Query)
    $q = $Query.Replace("'", "''")
    Get-MgUser -Filter "startsWith(displayName,'$q') or startsWith(userPrincipalName,'$q') or startsWith(mail,'$q') or startsWith(surname,'$q')" `
        -ConsistencyLevel eventual -CountVariable cv -Top 50 `
        -Property 'id','displayName','userPrincipalName','mail' -ErrorAction Stop |
        Sort-Object DisplayName
}

function Search-DirectoryGroup {
    param([string]$Query)
    $q = $Query.Replace("'", "''")
    Get-MgGroup -Filter "startsWith(displayName,'$q') or startsWith(mail,'$q')" `
        -ConsistencyLevel eventual -CountVariable cv -Top 50 `
        -Property 'id','displayName','mail','groupTypes','securityEnabled' -ErrorAction Stop |
        Sort-Object DisplayName
}

function Resolve-CandidateUser {
    <# Expand all targets into a unique id -> user map (scalar/complex/raw props populated),
       plus id -> set of source labels (group display name or '(direct)'). #>
    param([string[]]$SelectProps, [bool]$Transitive)

    $select  = @('id','displayName','userPrincipalName') + $SelectProps | Select-Object -Unique
    $users   = [ordered]@{}
    $sources = @{}

    function Add-User($obj, $sourceLabel) {
        $id = [string]$obj.Id
        if (-not $id) { return }
        if (-not $users.Contains($id)) { $users[$id] = $obj }
        if (-not $sources.ContainsKey($id)) {
            $sources[$id] = New-Object 'System.Collections.Generic.HashSet[string]'
        }
        [void]$sources[$id].Add($sourceLabel)
    }

    foreach ($t in $script:Targets) {
        if ($t.Type -eq 'Group') {
            Set-Progress "Reading members of group '$($t.Display)'..."
            try {
                $members = if ($Transitive) {
                    Get-MgGroupTransitiveMemberAsUser -GroupId $t.Id -All -Property $select -ErrorAction Stop
                } else {
                    Get-MgGroupMemberAsUser -GroupId $t.Id -All -Property $select -ErrorAction Stop
                }
                foreach ($m in $members) { Add-User $m $t.Display }
            } catch {
                Set-Progress "  ! group '$($t.Display)': $($_.Exception.Message)"
            }
        }
        else {
            Set-Progress "Reading user '$($t.Display)'..."
            try {
                $u = Get-MgUser -UserId $t.Id -Property $select -ErrorAction Stop
                Add-User $u '(direct)'
            } catch {
                Set-Progress "  ! user '$($t.Display)': $($_.Exception.Message)"
            }
        }
    }
    return [pscustomobject]@{ Users = $users; Sources = $sources }
}

function Get-NavEnrichment {
    <# Per-user fetch of navigation properties (manager / transitive group memberships /
       direct reports) only for the ones actually selected. #>
    param($Users, [bool]$NeedManager, [bool]$NeedMemberships, [bool]$NeedDirectReports)

    $nav = @{}
    $total = $Users.Count
    $i = 0
    foreach ($id in $Users.Keys) {
        $i++
        $disp = (Get-GraphVal $Users[$id] 'displayName')
        Set-Progress "Enriching membership data ($i of $total): $disp" $i $total
        $e = @{ ManagerName=''; ManagerUpn=''; Groups=''; GroupCount=0; Reports=''; ReportCount=0 }

        if ($NeedManager) {
            try {
                $m = Get-MgUserManager -UserId $id -ErrorAction Stop
                $e.ManagerName = [string](Get-GraphVal $m 'displayName')
                $e.ManagerUpn  = [string](Get-GraphVal $m 'userPrincipalName')
            } catch { }
        }
        if ($NeedMemberships) {
            try {
                $g = Get-MgUserTransitiveMemberOf -UserId $id -All -ErrorAction Stop |
                     Where-Object { ([string](Get-GraphVal $_ '@odata.type')) -like '*group' }
                $names = @($g | ForEach-Object { Get-GraphVal $_ 'displayName' } | Where-Object { $_ })
                $e.Groups = ($names -join '; '); $e.GroupCount = $names.Count
            } catch { }
        }
        if ($NeedDirectReports) {
            try {
                $dr = Get-MgUserDirectReport -UserId $id -All -ErrorAction Stop
                $names = @($dr | ForEach-Object { Get-GraphVal $_ 'displayName' } | Where-Object { $_ })
                $e.Reports = ($names -join '; '); $e.ReportCount = $names.Count
            } catch { }
        }
        $nav[$id] = $e
    }
    return $nav
}

function ConvertTo-FlatRow {
    <# Build one flat [pscustomobject] for a user, in catalog order, handling each Kind. #>
    param($User, [array]$SelectedAttrs, $SkuMap, $NavData, [string]$Source, [bool]$IncludeSource)

    $row = [ordered]@{}
    if ($IncludeSource) { $row['MemberSource'] = $Source }

    foreach ($a in $SelectedAttrs) {
        switch ($a.Kind) {

            'Nav' {
                switch ($a.Name) {
                    'manager' {
                        $row['Manager']    = $NavData.ManagerName
                        $row['ManagerUPN'] = $NavData.ManagerUpn
                    }
                    'groupMemberships' {
                        $row['GroupMemberships']     = $NavData.Groups
                        $row['GroupMembershipCount'] = $NavData.GroupCount
                    }
                    'directReports' {
                        $row['DirectReports']     = $NavData.Reports
                        $row['DirectReportCount'] = $NavData.ReportCount
                    }
                }
            }

            'Complex' {
                switch ($a.Name) {
                    'employeeOrgData' {
                        $o = Get-GraphVal $User 'employeeOrgData'
                        $row['Division']   = [string](Get-GraphVal $o 'division')
                        $row['CostCenter'] = [string](Get-GraphVal $o 'costCenter')
                    }
                    'onPremisesExtensionAttributes' {
                        $o = Get-GraphVal $User 'onPremisesExtensionAttributes'
                        for ($k = 1; $k -le 15; $k++) {
                            $row["ExtensionAttribute$k"] = [string](Get-GraphVal $o "extensionAttribute$k")
                        }
                    }
                    'assignedLicenses' {
                        $names = @()
                        foreach ($l in @(Get-GraphVal $User 'assignedLicenses')) {
                            if ($null -eq $l) { continue }
                            $sku = [string](Get-GraphVal $l 'skuId')
                            $names += $(if ($SkuMap.ContainsKey($sku)) { $SkuMap[$sku] } else { $sku })
                        }
                        $row['AssignedLicenses'] = ($names -join '; ')
                    }
                    'licenseAssignmentStates' {
                        $parts = @()
                        foreach ($s in @(Get-GraphVal $User 'licenseAssignmentStates')) {
                            if ($null -eq $s) { continue }
                            $sku   = [string](Get-GraphVal $s 'skuId')
                            $state = [string](Get-GraphVal $s 'state')
                            $nm    = $(if ($SkuMap.ContainsKey($sku)) { $SkuMap[$sku] } else { $sku })
                            $parts += "$nm=$state"
                        }
                        $row['LicenseAssignmentStates'] = ($parts -join '; ')
                    }
                    default { $row[$a.Label] = Format-Cell (Get-GraphVal $User $a.Name) }
                }
            }

            'Raw' {
                $v = Get-GraphVal $User $a.Name
                $row[$a.Label] = $(if ($null -ne $v) { $v | ConvertTo-Json -Compress -Depth 4 } else { '' })
            }

            default {  # Scalar
                $row[$a.Label] = Format-Cell (Get-GraphVal $User $a.Name)
            }
        }
    }
    return [pscustomobject]$row
}
#endregion

#region ----------------------------------------------------------------- Export
function Build-HtmlReport {
    param([array]$Rows)
    $css = @"
<style>
 body { font-family:'Segoe UI',Arial,sans-serif; margin:20px; color:#222; }
 h1 { font-size:18px; margin:0 0 4px 0; }
 .meta { color:#555; margin-bottom:14px; font-size:12px; }
 table { border-collapse:collapse; width:100%; font-size:12px; }
 th { position:sticky; top:0; background:#2b579a; color:#fff; text-align:left; padding:6px 8px; }
 td { border-bottom:1px solid #e2e2e2; padding:4px 8px; vertical-align:top; }
 tr:nth-child(even){ background:#f5f7fb; }
</style>
"@
    $pre = "<h1>Microsoft 365 Attribute Report</h1><div class='meta'>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; $($Rows.Count) user(s)</div>"
    $Rows | ConvertTo-Html -Head $css -PreContent $pre | Out-String
}

function Export-Report {
    param([array]$Rows, [string]$Folder, [string]$Base, [string[]]$Formats)

    $written  = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    if ($Formats -contains 'CSV') {
        $p = Join-Path $Folder "$Base.csv"
        $Rows | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8
        $written.Add($p)
    }
    if ($Formats -contains 'JSON') {
        $p = Join-Path $Folder "$Base.json"
        ($Rows | ConvertTo-Json -Depth 6) | Out-File -FilePath $p -Encoding UTF8
        $written.Add($p)
    }
    if ($Formats -contains 'HTML') {
        $p = Join-Path $Folder "$Base.html"
        (Build-HtmlReport -Rows $Rows) | Out-File -FilePath $p -Encoding UTF8
        $written.Add($p)
    }
    if ($Formats -contains 'XLSX') {
        $p = Join-Path $Folder "$Base.xlsx"
        try {
            Import-Module ImportExcel -ErrorAction Stop
            $Rows | Export-Excel -Path $p -WorksheetName 'M365 Attributes' `
                -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow -TableStyle 'Medium2' -ClearSheet
            $written.Add($p)
        } catch {
            $warnings.Add("Excel export failed: $($_.Exception.Message)")
        }
    }
    return [pscustomobject]@{ Written = $written; Warnings = $warnings }
}
#endregion

#region ----------------------------------------------------------------- Module bootstrap & connect
function Initialize-GraphModule {
    $need = 'Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Groups'
    $missing = $need | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
    if ($missing) {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "These required modules are not installed:`n  $($missing -join "`n  ")`n`nInstall them now for the current user (Install-Module -Scope CurrentUser)?",
            'Install Microsoft Graph modules', 'YesNo', 'Question')
        if ($ans -ne 'Yes') { throw "Required Microsoft Graph modules are missing." }
        Set-Progress "Installing modules (this can take a minute)..."
        Install-Module $missing -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module $need -ErrorAction Stop
}

function Get-ConnectionContext { try { Get-MgContext } catch { $null } }

function Update-ConnectionLabel {
    $ctx = Get-ConnectionContext
    if ($ctx) {
        $script:UI.ConnLabel.Text      = "Connected: $($ctx.Account)"
        $script:UI.ConnLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 90)
        $script:UI.ConnLabel.BackColor = [System.Drawing.Color]::FromArgb(223, 246, 238)
        $script:UI.ConnectBtn.Text     = '&Reconnect'
    } else {
        $script:UI.ConnLabel.Text      = 'Not connected'
        $script:UI.ConnLabel.ForeColor = [System.Drawing.Color]::FromArgb(168, 0, 0)
        $script:UI.ConnLabel.BackColor = [System.Drawing.SystemColors]::Control
        $script:UI.ConnectBtn.Text     = '&Connect to Graph'
    }
    if ($script:UI.SearchBtn) { $script:UI.SearchBtn.Enabled = [bool]$ctx }
}

function Invoke-GraphConnect {
    try {
        Initialize-GraphModule
        Set-Progress "Opening sign-in..."
        Connect-MgGraph -Scopes $script:GraphScopes -NoWelcome -ErrorAction Stop | Out-Null
        Update-ConnectionLabel
        Set-Progress "Connected."
    } catch {
        Set-Progress "Connection failed."
        [System.Windows.Forms.MessageBox]::Show("Could not connect to Microsoft Graph:`n$($_.Exception.Message)",
            'Connection error', 'OK', 'Error') | Out-Null
    }
}
#endregion

#region ----------------------------------------------------------------- GUI construction
function New-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text          = 'M365 Attribute Reporter'
    $form.Size          = New-Object System.Drawing.Size(1040, 760)
    $form.MinimumSize   = New-Object System.Drawing.Size(900, 620)
    $form.StartPosition = 'CenterScreen'
    $form.Font          = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.AutoScaleMode = 'Font'
    try { $form.Icon = [System.Drawing.SystemIcons]::Information } catch { }

    # --- Shared theme constants (used throughout this form) --------------------------
    $accentBlue = [System.Drawing.Color]::FromArgb(37, 99, 183)
    $btnFace    = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $btnText    = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $fontMedium = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
    $fontLarge  = New-Object System.Drawing.Font('Segoe UI', 11,  [System.Drawing.FontStyle]::Bold)
    # Flat treatment for secondary buttons; the primary Generate button keeps its accent fill.
    $styleSecondaryBtn = {
        param($b)
        $b.FlatStyle = 'Flat'
        $b.FlatAppearance.BorderColor = $accentBlue
        $b.FlatAppearance.BorderSize  = 1
        $b.BackColor = $btnFace
        $b.ForeColor = $btnText
    }

    $root = New-Object System.Windows.Forms.TableLayoutPanel
    $root.Dock = 'Fill'; $root.ColumnCount = 1; $root.RowCount = 3
    [void]$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', 56)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', 96)))
    $form.Controls.Add($root)

    # --- Top strip: connect + status -------------------------------------------------
    $top = New-Object System.Windows.Forms.Panel
    $top.Dock = 'Fill'
    $connectBtn = New-Object System.Windows.Forms.Button
    $connectBtn.Text = '&Connect to Graph'; $connectBtn.Location = New-Object System.Drawing.Point(10, 12)
    $connectBtn.Size = New-Object System.Drawing.Size(150, 30)
    & $styleSecondaryBtn $connectBtn
    $connLabel = New-Object System.Windows.Forms.Label
    $connLabel.AutoSize = $true; $connLabel.Location = New-Object System.Drawing.Point(172, 18)
    $connLabel.Text = 'Not connected'
    $connLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $connLabel.ForeColor = [System.Drawing.Color]::FromArgb(168, 0, 0)
    $top.Controls.AddRange(@($connectBtn, $connLabel))
    $root.Controls.Add($top, 0, 0)

    # --- Middle: left attributes | right (targets / output) --------------------------
    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'; $split.Orientation = 'Vertical'; $split.SplitterWidth = 6
    $root.Controls.Add($split, 0, 1)
    $form.Add_Shown({ try { $split.SplitterDistance = [int]($split.Width * 0.5) } catch {} })

    # ---- LEFT: attribute checkboxes -------------------------------------------------
    $leftHost = New-Object System.Windows.Forms.TableLayoutPanel
    $leftHost.Dock = 'Fill'; $leftHost.ColumnCount = 1; $leftHost.RowCount = 2
    [void]$leftHost.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', 78)))
    [void]$leftHost.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
    $split.Panel1.Controls.Add($leftHost)

    $attrHeader = New-Object System.Windows.Forms.Panel; $attrHeader.Dock = 'Fill'
    $attrTitle = New-Object System.Windows.Forms.Label
    $attrTitle.Text = '1. Attributes to include'; $attrTitle.Font = $fontLarge
    $attrTitle.AutoSize = $true; $attrTitle.Location = New-Object System.Drawing.Point(6, 8)
    $btnAll = New-Object System.Windows.Forms.Button; $btnAll.Text = '&All'; $btnAll.Size = New-Object System.Drawing.Size(50,26); $btnAll.Location = New-Object System.Drawing.Point(8,44); $btnAll.Font = $fontMedium
    $btnNone = New-Object System.Windows.Forms.Button; $btnNone.Text = '&None'; $btnNone.Size = New-Object System.Drawing.Size(50,26); $btnNone.Location = New-Object System.Drawing.Point(62,44); $btnNone.Font = $fontMedium
    $btnDef = New-Object System.Windows.Forms.Button; $btnDef.Text = '&Defaults'; $btnDef.Size = New-Object System.Drawing.Size(66,26); $btnDef.Location = New-Object System.Drawing.Point(116,44); $btnDef.Font = $fontMedium
    $filterBox = New-Object System.Windows.Forms.TextBox; $filterBox.Location = New-Object System.Drawing.Point(192,42); $filterBox.Size = New-Object System.Drawing.Size(158,24)
    $filterLbl = New-Object System.Windows.Forms.Label; $filterLbl.Text='Filter:'; $filterLbl.AutoSize=$true; $filterLbl.Location=New-Object System.Drawing.Point(192,22); $filterLbl.Font=$fontMedium
    $attrHeader.Controls.AddRange(@($attrTitle, $btnAll, $btnNone, $btnDef, $filterLbl, $filterBox))
    $leftHost.Controls.Add($attrHeader, 0, 0)

    $attrScroll = New-Object System.Windows.Forms.Panel
    $attrScroll.Dock = 'Fill'; $attrScroll.AutoScroll = $true
    $attrFlow = New-Object System.Windows.Forms.FlowLayoutPanel
    $attrFlow.FlowDirection = 'LeftToRight'; $attrFlow.WrapContents = $true
    $attrFlow.AutoSize = $true; $attrFlow.AutoSizeMode = 'GrowAndShrink'; $attrFlow.Dock = 'Top'
    $attrScroll.Controls.Add($attrFlow)
    $emptyLbl = New-Object System.Windows.Forms.Label
    $emptyLbl.Dock = 'Top'; $emptyLbl.Height = 48; $emptyLbl.TextAlign = 'MiddleCenter'
    $emptyLbl.Text = 'No attributes match the filter. Clear the box to reset.'
    $emptyLbl.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Italic)
    $emptyLbl.ForeColor = [System.Drawing.Color]::Gray; $emptyLbl.Visible = $false
    $attrScroll.Controls.Add($emptyLbl)
    $leftHost.Controls.Add($attrScroll, 0, 1)

    # Build group boxes + checkboxes from the catalog.
    $attrChecks = New-Object System.Collections.Generic.List[object]
    foreach ($g in $script:Catalog.Groups) {
        $gb = New-Object System.Windows.Forms.GroupBox
        $gb.Text = $g.Name; $gb.Width = 300; $gb.AutoSize = $true; $gb.AutoSizeMode = 'GrowAndShrink'
        $gb.Margin = New-Object System.Windows.Forms.Padding(6)
        $gf = New-Object System.Windows.Forms.FlowLayoutPanel
        $gf.FlowDirection = 'TopDown'; $gf.WrapContents = $false; $gf.AutoSize = $true
        $gf.AutoSizeMode = 'GrowAndShrink'; $gf.Dock = 'Fill'; $gf.Margin = New-Object System.Windows.Forms.Padding(3,16,3,3)

        $hdr = New-Object System.Windows.Forms.CheckBox
        $hdr.Text = 'Select all in group'; $hdr.AutoSize = $true
        $hdr.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $hdr.ForeColor = [System.Drawing.SystemColors]::ControlText
        $hdr.AccessibleName = 'Select all ' + $g.Name + ' attributes'
        $groupChildren = New-Object System.Collections.Generic.List[object]
        $hdr.Add_CheckedChanged({
            param($s,$e)
            foreach ($c in $s.Tag) { $c.Checked = $s.Checked }
        }.GetNewClosure())
        [void]$gf.Controls.Add($hdr)

        foreach ($attr in $g.Attributes) {
            $cb = New-Object System.Windows.Forms.CheckBox
            $cb.Text = $attr.Label; $cb.AutoSize = $true; $cb.Checked = [bool]$attr.Default
            $cb.Tag = $attr
            $cb.Add_CheckedChanged({ Set-GenerateButtonState })
            [void]$gf.Controls.Add($cb)
            [void]$groupChildren.Add($cb)
            [void]$attrChecks.Add([pscustomobject]@{ Check = $cb; Attr = $attr; Group = $g.Name })
        }
        $hdr.Tag = $groupChildren
        $gb.Controls.Add($gf)
        [void]$attrFlow.Controls.Add($gb)
    }

    $btnAll.Add_Click({  foreach ($x in $script:UI.AttrChecks) { if ($x.Check.Visible) { $x.Check.Checked = $true } } })
    $btnNone.Add_Click({ foreach ($x in $script:UI.AttrChecks) { if ($x.Check.Visible) { $x.Check.Checked = $false } } })
    $btnDef.Add_Click({  foreach ($x in $script:UI.AttrChecks) { $x.Check.Checked = [bool]$x.Attr.Default } })
    $filterBox.Add_TextChanged({
        $term = $script:UI.FilterBox.Text.Trim()
        foreach ($x in $script:UI.AttrChecks) {
            $x.Check.Visible = ($term -eq '') -or ($x.Check.Text -like "*$term*") -or ($x.Attr.Name -like "*$term*")
        }
        $anyGroup = $false
        foreach ($gb in $script:UI.AttrFlow.Controls) {
            $anyVisible = $false
            foreach ($child in $gb.Controls[0].Controls) {
                if ($child -is [System.Windows.Forms.CheckBox] -and ($child.Tag -is [System.Collections.Hashtable]) -and $child.Visible) { $anyVisible = $true; break }
            }
            $gb.Visible = $anyVisible
            if ($anyVisible) { $anyGroup = $true }
        }
        if ($script:UI.EmptyLbl) {
            $script:UI.EmptyLbl.Visible = -not $anyGroup
            if (-not $anyGroup) { $script:UI.EmptyLbl.BringToFront() }
        }
    })

    # ---- RIGHT: targets (top) / output (bottom) -------------------------------------
    $rightSplit = New-Object System.Windows.Forms.SplitContainer
    $rightSplit.Dock = 'Fill'; $rightSplit.Orientation = 'Horizontal'; $rightSplit.SplitterWidth = 6
    $split.Panel2.Controls.Add($rightSplit)
    $form.Add_Shown({ try { $rightSplit.SplitterDistance = [int]($rightSplit.Height * 0.58) } catch {} })

    # ----- TARGETS -------------------------------------------------------------------
    $tgtBox = New-Object System.Windows.Forms.GroupBox
    $tgtBox.Text = '2. Users and groups to report on'; $tgtBox.Dock = 'Fill'
    $rightSplit.Panel1.Controls.Add($tgtBox)

    $radUser  = New-Object System.Windows.Forms.RadioButton; $radUser.Text='&Users';  $radUser.Checked=$true; $radUser.AutoSize=$true; $radUser.Location=New-Object System.Drawing.Point(12,23)
    $radGroup = New-Object System.Windows.Forms.RadioButton; $radGroup.Text='&Groups'; $radGroup.AutoSize=$true; $radGroup.Location=New-Object System.Drawing.Point(88,23)
    $searchBox = New-Object System.Windows.Forms.TextBox; $searchBox.Location=New-Object System.Drawing.Point(152,22); $searchBox.Size=New-Object System.Drawing.Size(198,24)
    $searchBtn = New-Object System.Windows.Forms.Button; $searchBtn.Text='&Search'; $searchBtn.Location=New-Object System.Drawing.Point(356,22); $searchBtn.Size=New-Object System.Drawing.Size(70,26); $searchBtn.Enabled=$false

    $resultList = New-Object System.Windows.Forms.ListView
    $resultList.Location = New-Object System.Drawing.Point(12,54); $resultList.Size=New-Object System.Drawing.Size(414,150)
    $resultList.View='Details'; $resultList.CheckBoxes=$true; $resultList.FullRowSelect=$true; $resultList.Anchor='Top,Left,Right'
    $resultList.GridLines = $true
    $resultList.AccessibleName = 'Search results with user/group details'
    $resultList.AccessibleDescription = 'Checkable list of matching users or groups. Use Add checked to include them.'
    $c1=New-Object System.Windows.Forms.ColumnHeader; $c1.Text='Name';       $c1.Width=190
    $c2=New-Object System.Windows.Forms.ColumnHeader; $c2.Text='UPN / Mail'; $c2.Width=150
    $c3=New-Object System.Windows.Forms.ColumnHeader; $c3.Text='Type';       $c3.Width=60
    [void]$resultList.Columns.AddRange([System.Windows.Forms.ColumnHeader[]]@($c1,$c2,$c3))

    $addBtn = New-Object System.Windows.Forms.Button; $addBtn.Text='Add &checked'; $addBtn.Location=New-Object System.Drawing.Point(12,210); $addBtn.Size=New-Object System.Drawing.Size(100,26); $addBtn.Anchor='Top,Left'

    $pasteLbl = New-Object System.Windows.Forms.Label; $pasteLbl.Text='…or paste UPNs / group names (one per line):'; $pasteLbl.AutoSize=$true; $pasteLbl.Location=New-Object System.Drawing.Point(120,214); $pasteLbl.Font=$fontMedium
    $pasteBox = New-Object System.Windows.Forms.TextBox; $pasteBox.Multiline=$true; $pasteBox.ScrollBars='Vertical'; $pasteBox.Location=New-Object System.Drawing.Point(120,236); $pasteBox.Size=New-Object System.Drawing.Size(230,60); $pasteBox.Anchor='Top,Left,Right'
    $pasteBox.BackColor=[System.Drawing.Color]::FromArgb(250,250,250); $pasteBox.BorderStyle='FixedSingle'
    $pasteBtn = New-Object System.Windows.Forms.Button; $pasteBtn.Text='Add &pasted'; $pasteBtn.Location=New-Object System.Drawing.Point(356,270); $pasteBtn.Size=New-Object System.Drawing.Size(70,26); $pasteBtn.Anchor='Top,Right'

    $selLbl = New-Object System.Windows.Forms.Label; $selLbl.Text='Selected targets:'; $selLbl.AutoSize=$false; $selLbl.Size=New-Object System.Drawing.Size(414,20); $selLbl.Location=New-Object System.Drawing.Point(12,302); $selLbl.Font=$fontMedium; $selLbl.Anchor='Top,Left,Right'
    $selList = New-Object System.Windows.Forms.ListBox; $selList.Location=New-Object System.Drawing.Point(12,322); $selList.Size=New-Object System.Drawing.Size(414,96); $selList.Anchor='Top,Left,Right,Bottom'; $selList.SelectionMode='MultiExtended'
    $removeBtn = New-Object System.Windows.Forms.Button; $removeBtn.Text='&Remove'; $removeBtn.Location=New-Object System.Drawing.Point(12,422); $removeBtn.Size=New-Object System.Drawing.Size(70,26); $removeBtn.Anchor='Left,Bottom'
    $clearBtn  = New-Object System.Windows.Forms.Button; $clearBtn.Text='C&lear';  $clearBtn.Location=New-Object System.Drawing.Point(86,422);  $clearBtn.Size=New-Object System.Drawing.Size(70,26); $clearBtn.Anchor='Left,Bottom'

    $chkNested = New-Object System.Windows.Forms.CheckBox; $chkNested.Text='Resolve nested group members (transitive)'; $chkNested.Checked=$true; $chkNested.AutoSize=$true; $chkNested.Location=New-Object System.Drawing.Point(168,422); $chkNested.Anchor='Left,Bottom'
    $chkSource = New-Object System.Windows.Forms.CheckBox; $chkSource.Text="Add 'MemberSource' column"; $chkSource.Checked=$true; $chkSource.AutoSize=$true; $chkSource.Location=New-Object System.Drawing.Point(168,442); $chkSource.Anchor='Left,Bottom'

    $tgtBox.Controls.AddRange(@($radUser,$radGroup,$searchBox,$searchBtn,$resultList,$addBtn,$pasteLbl,$pasteBox,$pasteBtn,$selLbl,$selList,$removeBtn,$clearBtn,$chkNested,$chkSource))

    # ----- OUTPUT --------------------------------------------------------------------
    $outBox = New-Object System.Windows.Forms.GroupBox
    $outBox.Text = '3. Output'; $outBox.Dock = 'Fill'
    $rightSplit.Panel2.Controls.Add($outBox)

    $fmtLbl = New-Object System.Windows.Forms.Label; $fmtLbl.Text='Formats:'; $fmtLbl.AutoSize=$true; $fmtLbl.Location=New-Object System.Drawing.Point(12,25); $fmtLbl.Font=$fontMedium
    $cCsv  = New-Object System.Windows.Forms.CheckBox; $cCsv.Text='CSV';        $cCsv.Checked=$true;  $cCsv.AutoSize=$true; $cCsv.Location=New-Object System.Drawing.Point(74,24)
    $cXlsx = New-Object System.Windows.Forms.CheckBox; $cXlsx.Text='Excel (.xlsx)'; $cXlsx.Checked=$true; $cXlsx.AutoSize=$true; $cXlsx.Location=New-Object System.Drawing.Point(140,24)
    $cHtml = New-Object System.Windows.Forms.CheckBox; $cHtml.Text='HTML';       $cHtml.Checked=$true; $cHtml.AutoSize=$true; $cHtml.Location=New-Object System.Drawing.Point(245,24)
    $cJson = New-Object System.Windows.Forms.CheckBox; $cJson.Text='JSON';       $cJson.Checked=$true; $cJson.AutoSize=$true; $cJson.Location=New-Object System.Drawing.Point(320,24)

    $folderLbl = New-Object System.Windows.Forms.Label; $folderLbl.Text='Save to folder:'; $folderLbl.AutoSize=$true; $folderLbl.Location=New-Object System.Drawing.Point(12,60); $folderLbl.Font=$fontMedium
    $folderBox = New-Object System.Windows.Forms.TextBox; $folderBox.Location=New-Object System.Drawing.Point(100,57); $folderBox.Size=New-Object System.Drawing.Size(250,24); $folderBox.Anchor='Top,Left,Right'
    $folderBox.Text = [Environment]::GetFolderPath('Desktop')
    $browseBtn = New-Object System.Windows.Forms.Button; $browseBtn.Text='&Browse…'; $browseBtn.Location=New-Object System.Drawing.Point(356,56); $browseBtn.Size=New-Object System.Drawing.Size(70,26); $browseBtn.Anchor='Top,Right'

    $nameLbl = New-Object System.Windows.Forms.Label; $nameLbl.Text='Base file name:'; $nameLbl.AutoSize=$true; $nameLbl.Location=New-Object System.Drawing.Point(12,92); $nameLbl.Font=$fontMedium
    $nameBox = New-Object System.Windows.Forms.TextBox; $nameBox.Location=New-Object System.Drawing.Point(100,89); $nameBox.Size=New-Object System.Drawing.Size(326,24); $nameBox.Anchor='Top,Left,Right'
    $nameBox.Text = "M365-AttributeReport_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    $chkOpen = New-Object System.Windows.Forms.CheckBox; $chkOpen.Text='Open the folder when finished'; $chkOpen.Checked=$true; $chkOpen.AutoSize=$true; $chkOpen.Location=New-Object System.Drawing.Point(100,120)
    $outBox.Controls.AddRange(@($fmtLbl,$cCsv,$cXlsx,$cHtml,$cJson,$folderLbl,$folderBox,$browseBtn,$nameLbl,$nameBox,$chkOpen))

    # --- Bottom strip: progress + status (left) | buttons (right) ---------------------
    # Built with nested layout panels (no absolute coords) so the Generate button is
    # always docked at the bottom-right regardless of window size.
    $bottom = New-Object System.Windows.Forms.TableLayoutPanel
    $bottom.Dock = 'Fill'; $bottom.ColumnCount = 2; $bottom.RowCount = 1
    [void]$bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    [void]$bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', 300)))

    $statusHost = New-Object System.Windows.Forms.TableLayoutPanel
    $statusHost.Dock = 'Fill'; $statusHost.ColumnCount = 1; $statusHost.RowCount = 2
    [void]$statusHost.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    [void]$statusHost.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Absolute', 24)))
    [void]$statusHost.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Dock = 'Fill'; $progress.Margin = New-Object System.Windows.Forms.Padding(12,6,12,6)
    $progress.Style = 'Continuous'; $progress.ForeColor = $accentBlue; $progress.BackColor = [System.Drawing.Color]::FromArgb(229,232,237)
    $status = New-Object System.Windows.Forms.Label
    $status.Dock = 'Fill'; $status.Text = 'Ready. Connect to Graph to begin.'; $status.AutoEllipsis = $true
    $status.TextAlign = 'MiddleLeft'; $status.Margin = New-Object System.Windows.Forms.Padding(12,4,12,6)
    $status.ForeColor = [System.Drawing.Color]::FromArgb(60,64,67)
    $statusHost.Controls.Add($progress, 0, 0)
    $statusHost.Controls.Add($status, 0, 1)

    $btnHost = New-Object System.Windows.Forms.FlowLayoutPanel
    $btnHost.Dock = 'Fill'; $btnHost.FlowDirection = 'RightToLeft'; $btnHost.WrapContents = $false
    $btnHost.Padding = New-Object System.Windows.Forms.Padding(0,10,12,10)
    $genBtn = New-Object System.Windows.Forms.Button
    $genBtn.Text = '&Generate Report'; $genBtn.Size = New-Object System.Drawing.Size(168,48)
    $genBtn.Font = $fontLarge
    $genBtn.FlatStyle = 'Flat'; $genBtn.BackColor = $accentBlue; $genBtn.ForeColor = [System.Drawing.Color]::White
    $genBtn.FlatAppearance.BorderColor = $accentBlue
    $closeBtn = New-Object System.Windows.Forms.Button
    $closeBtn.Text = 'C&lose'; $closeBtn.Size = New-Object System.Drawing.Size(84,48)
    $btnHost.Controls.Add($genBtn)    # RightToLeft flow: first added sits furthest right
    $btnHost.Controls.Add($closeBtn)

    $bottom.Controls.Add($statusHost, 0, 0)
    $bottom.Controls.Add($btnHost, 1, 0)
    $root.Controls.Add($bottom, 0, 2)

    # --- Stash handles ---------------------------------------------------------------
    $tt = New-Object System.Windows.Forms.ToolTip
    $script:UI = @{
        Form=$form; ConnectBtn=$connectBtn; ConnLabel=$connLabel
        AttrChecks=$attrChecks; AttrFlow=$attrFlow; FilterBox=$filterBox; EmptyLbl=$emptyLbl
        RadUser=$radUser; RadGroup=$radGroup; SearchBox=$searchBox; SearchBtn=$searchBtn; ResultList=$resultList
        SelList=$selList; SelLbl=$selLbl; ChkNested=$chkNested; ChkSource=$chkSource; PasteBox=$pasteBox
        CsvChk=$cCsv; XlsxChk=$cXlsx; HtmlChk=$cHtml; JsonChk=$cJson
        FolderBox=$folderBox; NameBox=$nameBox; ChkOpen=$chkOpen
        Progress=$progress; Status=$status; GenBtn=$genBtn; Tooltip=$tt
    }

    # Flat styling for every secondary button (primary $genBtn keeps its accent fill).
    foreach ($b in @($btnAll,$btnNone,$btnDef,$searchBtn,$addBtn,$pasteBtn,$removeBtn,$clearBtn,$browseBtn,$closeBtn)) { & $styleSecondaryBtn $b }

    # Tooltips: distinguish local Filter from directory Search; hint the paste box.
    $tt.SetToolTip($filterBox, 'Filter the attribute list locally (no Graph call).')
    $tt.SetToolTip($searchBox, 'Search the Microsoft Graph directory for users / groups.')
    $tt.SetToolTip($pasteBox,  'Paste one UPN or group name per line, then Add pasted.')

    # Re-validate the Generate button whenever a format checkbox changes.
    foreach ($fc in @($cCsv,$cXlsx,$cHtml,$cJson)) { $fc.Add_CheckedChanged({ Set-GenerateButtonState }) }

    # --- Wire events -----------------------------------------------------------------
    $connectBtn.Add_Click({ Invoke-GraphConnect })
    $closeBtn.Add_Click({ $script:UI.Form.Close() })
    $searchBtn.Add_Click({ Invoke-TargetSearch })
    $searchBox.Add_KeyDown({ param($s,$e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress=$true; Invoke-TargetSearch } })
    $addBtn.Add_Click({ Add-CheckedResults })
    $pasteBtn.Add_Click({ Add-PastedTargets })
    $removeBtn.Add_Click({
        $idx = @($script:UI.SelList.SelectedIndices) | Sort-Object -Descending
        foreach ($i in $idx) { $script:Targets.RemoveAt($i) }
        Update-SelectedList
    })
    $clearBtn.Add_Click({ $script:Targets.Clear(); Update-SelectedList })
    $browseBtn.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        if (Test-Path $script:UI.FolderBox.Text) { $dlg.SelectedPath = $script:UI.FolderBox.Text }
        if ($dlg.ShowDialog() -eq 'OK') { $script:UI.FolderBox.Text = $dlg.SelectedPath }
    })
    $genBtn.Add_Click({ Invoke-GenerateReport })

    return $form
}

function Invoke-TargetSearch {
    $q = $script:UI.SearchBox.Text.Trim()
    if ($q.Length -lt 1) { return }
    if (-not (Get-ConnectionContext)) { Set-Progress 'Connect to Graph first.'; return }
    $script:UI.ResultList.Items.Clear()
    try {
        Set-Progress "Searching..."
        if ($script:UI.RadUser.Checked) {
            foreach ($u in (Search-DirectoryUser $q)) {
                $it = New-Object System.Windows.Forms.ListViewItem([string]$u.DisplayName)
                [void]$it.SubItems.Add([string]($u.UserPrincipalName)); [void]$it.SubItems.Add('User')
                $it.Tag = [pscustomobject]@{ Type='User'; Id=[string]$u.Id; Display=[string]$u.DisplayName; Detail=[string]$u.UserPrincipalName }
                [void]$script:UI.ResultList.Items.Add($it)
            }
        } else {
            foreach ($g in (Search-DirectoryGroup $q)) {
                $it = New-Object System.Windows.Forms.ListViewItem([string]$g.DisplayName)
                [void]$it.SubItems.Add([string]($g.Mail)); [void]$it.SubItems.Add('Group')
                $it.Tag = [pscustomobject]@{ Type='Group'; Id=[string]$g.Id; Display=[string]$g.DisplayName; Detail=[string]$g.Mail }
                [void]$script:UI.ResultList.Items.Add($it)
            }
        }
        $n = $script:UI.ResultList.Items.Count
        Set-Progress ("Found $n result(s)." + $(if ($n -ge 50) { ' (showing up to 50)' } else { '' }))
    } catch {
        Set-Progress "Search failed: $($_.Exception.Message)"
    }
}

function Add-Target {
    param($Obj)
    foreach ($t in $script:Targets) { if ($t.Type -eq $Obj.Type -and $t.Id -eq $Obj.Id) { return } }
    [void]$script:Targets.Add($Obj)
}

function Add-CheckedResults {
    foreach ($it in $script:UI.ResultList.CheckedItems) { Add-Target $it.Tag }
    Update-SelectedList
}

function Add-PastedTargets {
    if (-not (Get-ConnectionContext)) { Set-Progress 'Connect to Graph first.'; return }
    $text = $script:UI.PasteBox.Text
    $notFound = @()
    foreach ($line in ($text -split "`r?`n")) {
        $name = $line.Trim(); if (-not $name) { continue }
        try {
            if ($name -match '@') {
                $u = Get-MgUser -UserId $name -Property 'id','displayName','userPrincipalName' -ErrorAction Stop
                Add-Target ([pscustomobject]@{ Type='User'; Id=[string]$u.Id; Display=[string]$u.DisplayName; Detail=[string]$u.UserPrincipalName })
            } else {
                $esc = $name.Replace("'","''")
                $g = Get-MgGroup -Filter "displayName eq '$esc'" -ConsistencyLevel eventual -CountVariable cv -Property 'id','displayName','mail' -ErrorAction Stop | Select-Object -First 1
                if ($g) { Add-Target ([pscustomobject]@{ Type='Group'; Id=[string]$g.Id; Display=[string]$g.DisplayName; Detail=[string]$g.Mail }) }
                else { $notFound += $name }
            }
        } catch { $notFound += $name }
    }
    Update-SelectedList
    $script:UI.PasteBox.Clear()
    if ($notFound) { Set-Progress "Not found: $($notFound -join ', ')" } else { Set-Progress 'Pasted targets added.' }
}

function Update-SelectedList {
    $script:UI.SelList.BeginUpdate()
    $script:UI.SelList.Items.Clear()
    foreach ($t in $script:Targets) {
        $tag = if ($t.Type -eq 'User') { 'U' } else { 'G' }
        $detail = if ($t.Detail) { " <$($t.Detail)>" } else { '' }
        [void]$script:UI.SelList.Items.Add("[$tag] $($t.Display)$detail")
    }
    $script:UI.SelList.EndUpdate()
    $u = @($script:Targets | Where-Object { $_.Type -eq 'User'  }).Count
    $g = @($script:Targets | Where-Object { $_.Type -eq 'Group' }).Count
    $script:UI.SelLbl.Text = "Selected targets: $($script:Targets.Count) ($u user$(if($u -ne 1){'s'}), $g group$(if($g -ne 1){'s'}))"
    Set-Progress "$($script:Targets.Count) target(s) selected."
    Set-GenerateButtonState
}
#endregion

#region ----------------------------------------------------------------- Generate orchestration
function Get-SelectedAttrs {
    # Returns selected catalog attrs in catalog order.
    $script:UI.AttrChecks | Where-Object { $_.Check.Checked } | ForEach-Object { $_.Attr }
}

function Set-UiBusy { param([bool]$Busy)
    $script:UI.ConnectBtn.Enabled = -not $Busy
    if ($Busy) { $script:UI.GenBtn.Enabled = $false } else { Set-GenerateButtonState }
}

function Set-GenerateButtonState {
    # Enable Generate only when there's >=1 attribute, >=1 target, and >=1 format;
    # otherwise disable it and explain what's missing via tooltip.
    if (-not $script:UI -or -not $script:UI.GenBtn) { return }
    $hasAttr   = @($script:UI.AttrChecks | Where-Object { $_.Check.Checked }).Count -gt 0
    $hasTarget = $script:Targets.Count -gt 0
    $hasFmt    = $script:UI.CsvChk.Checked -or $script:UI.XlsxChk.Checked -or $script:UI.HtmlChk.Checked -or $script:UI.JsonChk.Checked
    $ok = $hasAttr -and $hasTarget -and $hasFmt
    $script:UI.GenBtn.Enabled = $ok
    if ($ok) {
        $script:UI.Tooltip.SetToolTip($script:UI.GenBtn, 'Run the report with the current selections.')
    } else {
        $reasons = @()
        if (-not $hasAttr)   { $reasons += 'select at least one attribute' }
        if (-not $hasTarget) { $reasons += 'add at least one target' }
        if (-not $hasFmt)    { $reasons += 'pick at least one format' }
        $script:UI.Tooltip.SetToolTip($script:UI.GenBtn, 'To generate: ' + ($reasons -join ', ') + '.')
    }
}

function Invoke-GenerateReport {
    if (-not (Get-ConnectionContext)) {
        Set-Progress 'Not connected.'
        $ans = [System.Windows.Forms.MessageBox]::Show('You are not connected to Microsoft Graph. Connect now?','Not connected','YesNo','Question')
        if ($ans -eq 'Yes') { Invoke-GraphConnect }
        if (-not (Get-ConnectionContext)) { return }
    }

    $selected = @(Get-SelectedAttrs)
    if ($selected.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Pick at least one attribute.','Nothing selected','OK','Warning')|Out-Null; return }
    if ($script:Targets.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Add at least one user or group target.','No targets','OK','Warning')|Out-Null; return }

    $formats = @()
    if ($script:UI.CsvChk.Checked)  { $formats += 'CSV' }
    if ($script:UI.XlsxChk.Checked) { $formats += 'XLSX' }
    if ($script:UI.HtmlChk.Checked) { $formats += 'HTML' }
    if ($script:UI.JsonChk.Checked) { $formats += 'JSON' }
    if ($formats.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Pick at least one output format.','No format','OK','Warning')|Out-Null; return }

    $folder = $script:UI.FolderBox.Text.Trim()
    if (-not (Test-Path -LiteralPath $folder)) {
        try { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        catch { [System.Windows.Forms.MessageBox]::Show("Output folder is not valid:`n$folder",'Bad folder','OK','Error')|Out-Null; return }
    }
    $base = $script:UI.NameBox.Text.Trim()
    if (-not $base) { $base = "M365-AttributeReport_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }

    # ImportExcel preflight.
    if ($formats -contains 'XLSX' -and -not (Get-Module -ListAvailable -Name ImportExcel)) {
        $ans = [System.Windows.Forms.MessageBox]::Show("The Excel (.xlsx) format needs the 'ImportExcel' module, which isn't installed.`n`nInstall it now for the current user?",'ImportExcel required','YesNoCancel','Question')
        if ($ans -eq 'Yes') {
            try { Set-Progress 'Installing ImportExcel...'; Install-Module ImportExcel -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop }
            catch { $formats = $formats | Where-Object { $_ -ne 'XLSX' }; Set-Progress "ImportExcel install failed; skipping Excel." }
        } elseif ($ans -eq 'No') { $formats = $formats | Where-Object { $_ -ne 'XLSX' } }
        else { return }
    }

    Set-UiBusy $true
    $script:UI.Progress.Value = 0
    try {
        # Which extra work is needed?
        $navNames    = $selected | Where-Object { $_.Kind -eq 'Nav' } | ForEach-Object { $_.Name }
        $needMgr     = $navNames -contains 'manager'
        $needGroups  = $navNames -contains 'groupMemberships'
        $needReports = $navNames -contains 'directReports'
        $selectProps = @($selected | Where-Object { $_.Kind -ne 'Nav' } | ForEach-Object { $_.Name })
        $needSku     = ($selected | Where-Object { $_.Name -in @('assignedLicenses','licenseAssignmentStates') }).Count -gt 0

        $skuMap = @{}
        if ($needSku) { Set-Progress 'Reading license SKUs...'; $skuMap = Get-SkuFriendlyMap }

        Set-Progress 'Resolving members...'
        $resolved = Resolve-CandidateUser -SelectProps $selectProps -Transitive:$script:UI.ChkNested.Checked
        $users   = $resolved.Users
        $sources = $resolved.Sources
        if ($users.Count -eq 0) { Set-Progress 'No users resolved from the selected targets.'; [System.Windows.Forms.MessageBox]::Show('The selected targets contained no users.','Nothing to report','OK','Information')|Out-Null; Set-UiBusy $false; return }

        $nav = @{}
        if ($needMgr -or $needGroups -or $needReports) {
            $nav = Get-NavEnrichment -Users $users -NeedManager:$needMgr -NeedMemberships:$needGroups -NeedDirectReports:$needReports
        }

        Set-Progress 'Building report rows...'
        $includeSource = $script:UI.ChkSource.Checked
        $rows = New-Object System.Collections.Generic.List[object]
        $i = 0; $tot = $users.Count
        foreach ($id in $users.Keys) {
            $i++
            if ($i % 25 -eq 0) { Set-Progress "Building rows ($i of $tot)..." $i $tot }
            $src = if ($sources.ContainsKey($id)) { ($sources[$id] | Sort-Object) -join '; ' } else { '' }
            $navData = if ($nav.ContainsKey($id)) { $nav[$id] } else { @{ManagerName='';ManagerUpn='';Groups='';GroupCount=0;Reports='';ReportCount=0} }
            [void]$rows.Add( (ConvertTo-FlatRow -User $users[$id] -SelectedAttrs $selected -SkuMap $skuMap -NavData $navData -Source $src -IncludeSource $includeSource) )
        }

        Set-Progress "Writing $($formats.Count) file(s)..."
        $result = Export-Report -Rows $rows -Folder $folder -Base $base -Formats $formats

        $msg = "Report complete: $($rows.Count) user(s).`n`nWritten:`n" + (($result.Written | ForEach-Object { "  $_" }) -join "`n")
        if ($result.Warnings.Count) { $msg += "`n`nWarnings:`n" + (($result.Warnings | ForEach-Object { "  $_" }) -join "`n") }
        Set-Progress "Done. $($rows.Count) user(s), $($result.Written.Count) file(s)."
        [System.Windows.Forms.MessageBox]::Show($msg,'Report complete','OK','Information')|Out-Null

        if ($script:UI.ChkOpen.Checked -and $result.Written.Count) {
            try { Start-Process explorer.exe "/select,`"$($result.Written[0])`"" } catch { try { Invoke-Item $folder } catch {} }
        }
    }
    catch {
        Set-Progress "Error: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Report failed:`n$($_.Exception.Message)",'Error','OK','Error')|Out-Null
    }
    finally {
        Set-UiBusy $false
    }
}
#endregion

#region ----------------------------------------------------------------- Main
# When dot-sourced (e.g. for testing the helper functions), InvocationName is '.'.
# Setting $env:M365AR_NOLAUNCH also suppresses launch. Either way, define everything
# but do not build/show the window.
if ($MyInvocation.InvocationName -ne '.' -and -not $env:M365AR_NOLAUNCH) {
    $form = New-MainForm

    # Reflect any existing Graph session in the connection label.
    try { if (Get-ConnectionContext) { Update-ConnectionLabel } } catch {}
    Set-GenerateButtonState

    [void]$form.ShowDialog()
    $form.Dispose()
}
#endregion
