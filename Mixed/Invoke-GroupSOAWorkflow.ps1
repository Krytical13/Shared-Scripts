#Requires -Version 5.1

<#
.SYNOPSIS
    Unified menu-driven workflow for Microsoft Entra Group Source-of-Authority
    (SOA) operations: discovery, convert, revert, and post-conversion owner
    cleanup.

.DESCRIPTION
    Single entry point for the recurring Group SOA workflow. On launch it
    asks whether to run a fresh full discovery or use the latest cached
    readiness CSV, then drops into an action menu that loops until you exit.

    Actions available from the menu:

      1. Convert synced groups to cloud-managed (SOA forward).
         Uses readiness data to drive an Out-GridView picker. PATCHes
         /groups/{id}/onPremisesSyncBehavior with isCloudManaged=true.

      2. Revert cloud-managed groups back to on-prem-synced (SOA reverse).
         Loads the most recent conversion audit log as the candidate list.
         Verifies each group is currently cloud-managed AND still linked to
         an on-prem object before reverting; skips otherwise. Manual entry
         path is also offered if you want to revert a specific group not in
         the audit log.

      3. Fix legacy ManagedBy on cloud-managed Exchange groups.
         Two sub-modes:
           a. Reset: only acts on groups whose ManagedBy is empty or contains
              only known-problematic entries (Organization Management,
              Exchange Recipient Administrators, etc.). Groups with a
              legitimate-looking owner are left alone.
           b. Append: ensures a target owner is present on every
              cloud-managed group, without duplicating where it's already
              there. Existing owners are preserved.
         Targets groups by ExternalDirectoryObjectId to avoid display-name
         collisions with M365 Groups.

      4. Re-run discovery (refresh in-memory readiness data).

      5. Exit.

    The script is modular: each step is a function, so adapting any single
    behavior (scoring weights, eligibility rules, picker columns) is a
    one-place change.

    Modules required:
      - Microsoft.Graph.Authentication, Microsoft.Graph.Groups,
        Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns (Graph side).
      - ExchangeOnlineManagement (only loaded when an Exchange action runs).
    The script offers to install missing modules for the current user before
    proceeding.

    Default output folders:
      Discovery CSVs -> $env:USERPROFILE\Documents\HybridRecon
      Action audits  -> $env:USERPROFILE\Documents\SOAConversion

.PARAMETER DiscoveryLogPath
    Folder for readiness CSV output. Default:
    $env:USERPROFILE\Documents\HybridRecon

.PARAMETER ActionLogPath
    Folder for action audit logs (convert, revert, owner-fix). Default:
    $env:USERPROFILE\Documents\SOAConversion

.EXAMPLE
    .\Invoke-GroupSOAWorkflow.ps1

    Default run. Asks for discovery mode, then loops through the action
    menu until you exit.

.EXAMPLE
    .\Invoke-GroupSOAWorkflow.ps1 -ActionLogPath D:\SOAAudit

    Custom audit log folder.

.INPUTS
    None.

.OUTPUTS
    Writes timestamped CSVs to the discovery and action log folders. Console
    shows progress, OK/FAIL/Skipped per item, and a summary per action.

.NOTES
    Version:    1.0
    Author:     Brandon
    Released:   2026-05-02
    Tested on:  Windows PowerShell 5.1 and PowerShell 7.x with
                Microsoft.Graph 2.x and ExchangeOnlineManagement 3.x.

    PERMISSIONS:
      Graph scopes (consented at first connection):
        - Directory.Read.All
        - Group.Read.All
        - Group-OnPremisesSyncBehavior.ReadWrite.All
        - Policy.Read.All  (for CA policy scan during discovery)
      Entra role:
        - Hybrid Administrator (least-privileged for the SOA PATCH).
      Exchange role:
        - Anything that grants Set-DistributionGroup on recipient write
          scope (Exchange Administrator / Organization Management).

    WRITE OPERATIONS:
      Convert / Revert PATCH /onPremisesSyncBehavior on Entra groups.
      Owner Fix MODIFIES Exchange ManagedBy on selected groups. Each action
      shows a confirmation prompt with the impacted list before executing.

    PAIRS WITH (single-purpose siblings, same conventions):
      - Get-GroupSOAReadiness.ps1
      - Convert-GroupSOA.ps1
      - Set-ConvertedGroupOwners.ps1

    LICENSE (MIT):
      Permission is hereby granted, free of charge, to any person obtaining
      a copy of this software and associated documentation files (the
      "Software"), to deal in the Software without restriction, including
      without limitation the rights to use, copy, modify, merge, publish,
      distribute, sublicense, and/or sell copies of the Software, and to
      permit persons to whom the Software is furnished to do so, subject to
      the following conditions:

      The above copyright notice and this permission notice shall be
      included in all copies or substantial portions of the Software.

      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
      EXPRESS OR IMPLIED. See https://opensource.org/licenses/MIT for
      full text.

    DISCLAIMER:
      Not affiliated with or endorsed by Microsoft. SOA conversion affects
      Exchange Online, licensing, Conditional Access, and other downstream
      systems. Validate in a non-production tenant first and review each
      action's selection list before confirming.

    AI ASSISTANCE:
      Portions of this script were drafted with AI assistance, then
      reviewed and tested by the author. You are responsible for
      understanding and testing any code before running it in your
      environment.

    TROUBLESHOOTING:
      - "Could not load file or assembly" on Graph cmdlets: mixed
        Microsoft.Graph module versions are installed. Uninstall all
        Microsoft.Graph* modules and reinstall a single matched set.

      - TypeLoadException on GetTokenAsync / UserProvidedTokenCredential:
        known SDK bug in hosted runtimes (notably the VSCode PowerShell
        extension on Windows PowerShell 5.1). See
        https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3479
        Fix: run in PowerShell 7, or in a standalone Windows PowerShell
        window rather than the VSCode integrated console.

      - Out-GridView missing on PowerShell 7 non-Windows: install
        Microsoft.PowerShell.GraphicalTools -Scope CurrentUser.

      - "The current operation is not supported on GroupMailbox" during
        owner fix: a MESG/DL and a Microsoft 365 Group share a display
        name. The script targets by ExternalDirectoryObjectId to avoid
        this; if it still happens, run Get-Recipient -Identity '<name>'
        to identify the duplicate and resolve manually.
#>

[CmdletBinding()]
param(
    [string]$DiscoveryLogPath = "$env:USERPROFILE\Documents\HybridRecon",
    [string]$ActionLogPath    = "$env:USERPROFILE\Documents\SOAConversion"
)

# =============================================================================
# Script-wide state
# =============================================================================

$script:DiscoveryData   = $null   # rows from Get-GroupSOAReadiness style scan
$script:DiscoveryFolder = $DiscoveryLogPath
$script:ActionFolder    = $ActionLogPath
$script:ExoConnected    = $false

# Default ManagedBy patterns we treat as 'invalid / safe to overwrite'
$script:DefaultInvalidOwnerHints = @(
    '*Organization Management*',
    '*Exchange Recipient Administrators*',
    '*Exchange Organization Administrators*',
    '*Exchange Trusted Subsystem*'
)

# Recipient types Exchange permits as ManagedBy
$script:ValidOwnerRecipientTypes = @(
    'UserMailbox', 'LegacyMailbox', 'SharedMailbox', 'TeamMailbox',
    'MailUser', 'LinkedMailbox', 'RemoteUserMailbox', 'RemoteSharedMailbox',
    'RemoteTeamMailbox', 'MailContact', 'User', 'UniversalSecurityGroup',
    'MailUniversalSecurityGroup', 'RoomMailbox'
)

# =============================================================================
# Module / connection helpers
# =============================================================================

function Install-RequiredModulesInteractive {
    # Prompt to install any modules that aren't already on the system.
    param([Parameter(Mandatory)][string[]]$Modules)

    $missing = @($Modules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
    if ($missing.Count -eq 0) { return $true }

    Write-Host ""
    Write-Host "The following required module(s) are not installed:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ""
    $answer = Read-Host "Install them now for the current user? [Y/n]"
    if ($answer -match '^[Nn]') {
        Write-Error "Required module(s) missing. Cannot continue."
        return $false
    }

    foreach ($mod in $missing) {
        Write-Host "Installing $mod ..." -ForegroundColor Cyan
        try {
            Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host "  Installed $mod." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install '$mod': $($_.Exception.Message)"
            return $false
        }
    }
    return $true
}

function Connect-GraphForScopes {
    # Connect to Graph with the union of currently-held scopes and the requested ones.
    param([Parameter(Mandatory)][string[]]$Scopes)

    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        $missingScopes = @($Scopes | Where-Object { $_ -notin $context.Scopes })
        if (-not $context -or $missingScopes.Count -gt 0) {
            Write-Host "Connecting to Microsoft Graph ($($Scopes -join ', '))..." -ForegroundColor Cyan
            Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
        }
        return $true
    }
    catch {
        Write-Error "Failed to connect to Graph: $($_.Exception.Message)"
        return $false
    }
}

function Connect-ExoIfNeeded {
    # Connect to Exchange Online if no live connection is present.
    if ($script:ExoConnected) { return $true }

    $ok = Install-RequiredModulesInteractive -Modules @('ExchangeOnlineManagement')
    if (-not $ok) { return $false }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $existing = Get-ConnectionInformation -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Connected' -and $_.TokenStatus -eq 'Active' } |
        Select-Object -First 1

    if ($existing) {
        Write-Host "Using existing Exchange Online connection ($($existing.UserPrincipalName))." -ForegroundColor Green
        $script:ExoConnected = $true
        return $true
    }

    Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        $script:ExoConnected = $true
        return $true
    }
    catch {
        Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
        return $false
    }
}

# =============================================================================
# Common picker / confirm / log helpers
# =============================================================================

function Test-OutGridViewAvailable {
    if (-not (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
        Write-Error "Out-GridView not available. On PowerShell 7, install: Install-Module Microsoft.PowerShell.GraphicalTools -Scope CurrentUser"
        return $false
    }
    return $true
}

function Show-GroupPicker {
    # Out-GridView wrapper. Returns selected rows or $null if cancelled / empty.
    param(
        [Parameter(Mandatory)]$Rows,
        [Parameter(Mandatory)][string]$Title
    )
    if (-not (Test-OutGridViewAvailable)) { return $null }
    if (-not $Rows -or @($Rows).Count -eq 0) {
        Write-Warning "No rows to show in picker."
        return $null
    }
    $selected = $Rows | Out-GridView -Title $Title -PassThru
    if (-not $selected -or @($selected).Count -eq 0) { return $null }
    return @($selected)
}

function Confirm-WithUser {
    param([Parameter(Mandatory)][string]$Question, [string]$Default = 'N')
    $hint = if ($Default -match '^[Yy]') { '[Y/n]' } else { '[y/N]' }
    $answer = Read-Host "$Question $hint"
    if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
    return ($answer -match '^[Yy]')
}

function Write-AuditLog {
    # Writes a list of audit rows to a timestamped CSV in $script:ActionFolder.
    param(
        [Parameter(Mandatory)]$Rows,
        [Parameter(Mandatory)][string]$Prefix
    )
    $clean = @($Rows | Where-Object { $_ })
    if ($clean.Count -eq 0) {
        Write-Host "No rows to log." -ForegroundColor Yellow
        return $null
    }
    if (-not (Test-Path $script:ActionFolder)) {
        New-Item -ItemType Directory -Path $script:ActionFolder -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path  = Join-Path $script:ActionFolder "$Prefix-$stamp.csv"
    $clean | Export-Csv -Path $path -NoTypeInformation
    Write-Host "Audit log written to: $path" -ForegroundColor Green
    return $path
}

# =============================================================================
# Discovery
# =============================================================================

function Get-CaPolicyGroupReferenceSet {
    # Returns a HashSet[string] of group IDs referenced by any Conditional Access policy.
    $set = [System.Collections.Generic.HashSet[string]]::new()
    try {
        Write-Host "Pulling Conditional Access policies..." -ForegroundColor Cyan
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        foreach ($p in $policies) {
            foreach ($gid in @($p.Conditions.Users.IncludeGroups) + @($p.Conditions.Users.ExcludeGroups)) {
                if ($gid) { [void]$set.Add($gid) }
            }
        }
        Write-Host "  $($policies.Count) policies scanned, $($set.Count) unique group references." -ForegroundColor Green
    }
    catch {
        Write-Warning "CA policy scan failed: $($_.Exception.Message). Continuing without CA flag."
    }
    return $set
}

function Get-SyncedUserIdSet {
    # Returns a HashSet[string] of user IDs whose onPremisesSyncEnabled is true.
    # Get-MgGroupMember default projection omits onPremisesSyncEnabled, so we test
    # cloud-only membership by checking each member's Id against this set.
    $set = [System.Collections.Generic.HashSet[string]]::new()
    try {
        Write-Host "Building synced-user ID index..." -ForegroundColor Cyan
        Get-MgUser -Filter "onPremisesSyncEnabled eq true" -All -Property id `
            -ConsistencyLevel eventual -CountVariable userCountVar -ErrorAction Stop |
            ForEach-Object { [void]$set.Add($_.Id) }
        Write-Host "  $($set.Count) synced users indexed." -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not build synced-user index: $($_.Exception.Message). CloudOnly counts will be unreliable."
    }
    return $set
}

function Invoke-FreshDiscovery {
    # Full readiness scan. Returns rows AND writes a CSV to $script:DiscoveryFolder.
    Write-Host "`n=== Fresh Readiness Discovery ===" -ForegroundColor Cyan

    $caGroupIds   = Get-CaPolicyGroupReferenceSet
    $syncedUserIds = Get-SyncedUserIdSet

    Write-Host "Querying synced groups..." -ForegroundColor Cyan
    $groupProps = @(
        'id', 'displayName', 'mail', 'mailEnabled', 'securityEnabled', 'groupTypes',
        'onPremisesSyncEnabled', 'onPremisesSecurityIdentifier', 'onPremisesSamAccountName',
        'assignedLicenses', 'isAssignableToRole', 'description'
    )
    try {
        $syncedGroups = Get-MgGroup -Filter "onPremisesSyncEnabled eq true" -All `
            -Property $groupProps -ConsistencyLevel eventual -CountVariable groupCountVar -ErrorAction Stop |
            Select-Object $groupProps
    }
    catch {
        Write-Error "Synced group query failed: $($_.Exception.Message)"
        return $null
    }
    Write-Host "  $($syncedGroups.Count) synced groups returned." -ForegroundColor Green

    # Filter to convertible types (security groups, MESGs, DLs)
    $candidates = foreach ($g in $syncedGroups) {
        $isDynamic = $g.GroupTypes -contains 'DynamicMembership'
        $isM365    = $g.GroupTypes -contains 'Unified'

        $type = if ($isM365) { 'M365Group' }
            elseif ($isDynamic) { 'Dynamic' }
            elseif ($g.MailEnabled -and $g.SecurityEnabled) { 'MESG' }
            elseif ($g.MailEnabled -and -not $g.SecurityEnabled) { 'DistributionList' }
            elseif (-not $g.MailEnabled -and $g.SecurityEnabled) { 'SecurityGroup' }
            else { 'Unknown' }

        if ($type -in @('SecurityGroup', 'MESG', 'DistributionList')) {
            $g | Add-Member -NotePropertyName _Type -NotePropertyValue $type -PassThru -Force
        }
    }
    Write-Host "  $($candidates.Count) candidates after type filter." -ForegroundColor Green

    Write-Host "Counting members and checking nesting (this is the slow part)..." -ForegroundColor Cyan
    $rows = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($g in $candidates) {
        $i++
        Write-Progress -Activity "Analyzing groups" -Status "$($g.DisplayName) ($i/$($candidates.Count))" `
            -PercentComplete (($i / [Math]::Max(1, $candidates.Count)) * 100)

        $row = Get-GroupReadinessRow -Group $g -SyncedUserIds $syncedUserIds -CaGroupIds $caGroupIds
        if ($row) { [void]$rows.Add($row) }
    }
    Write-Progress -Activity "Analyzing groups" -Completed

    $sorted = $rows | Sort-Object SafetyRank, DisplayName

    if (-not (Test-Path $script:DiscoveryFolder)) {
        New-Item -ItemType Directory -Path $script:DiscoveryFolder -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csvPath = Join-Path $script:DiscoveryFolder "GroupSOAReadiness-$stamp.csv"
    $sorted | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`nReadiness CSV written to: $csvPath" -ForegroundColor Green

    Show-DiscoverySummary -Rows $sorted
    return @($sorted)
}

function Get-GroupReadinessRow {
    # Builds one readiness row for a single Entra group.
    param(
        [Parameter(Mandatory)]$Group,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$SyncedUserIds,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$CaGroupIds
    )

    $members = @()
    $memberError = $null
    try { $members = Get-MgGroupMember -GroupId $Group.Id -All -ErrorAction Stop }
    catch { $memberError = $_.Exception.Message }

    $totalMembers   = $members.Count
    $nestedChildren = @($members | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' })
    $userMembers    = @($members | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.user' })
    $contactMembers = @($members | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.orgContact' })
    $deviceMembers  = @($members | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.device' })
    $otherMembers   = @($members | Where-Object {
        $t = $_.AdditionalProperties['@odata.type']
        $t -and $t -notin @('#microsoft.graph.group', '#microsoft.graph.user', '#microsoft.graph.orgContact', '#microsoft.graph.device')
    })
    $hasNestedChildren = $nestedChildren.Count -gt 0

    $cloudOnlyMemberCount = 0
    foreach ($u in $userMembers) {
        if (-not $SyncedUserIds.Contains($u.Id)) { $cloudOnlyMemberCount++ }
    }

    $nestedAsChild = $false
    try {
        $parents = Get-MgGroupMemberOf -GroupId $Group.Id -All -ErrorAction Stop
        $nestedAsChild = ($parents | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' }).Count -gt 0
    }
    catch { Write-Debug "MemberOf failed for $($Group.DisplayName): $($_.Exception.Message)" }

    $usedForLicensing = ($Group.AssignedLicenses | Measure-Object).Count -gt 0
    $inCA             = $CaGroupIds.Contains($Group.Id)
    $roleAssignable   = [bool]$Group.IsAssignableToRole

    # Lower SafetyRank = safer to convert first.
    $score = $totalMembers `
        + (5  * $cloudOnlyMemberCount) `
        + (10 * [int]$nestedAsChild) `
        + (10 * [int]$hasNestedChildren) `
        + (20 * [int]$usedForLicensing) `
        + (20 * [int]$inCA) `
        + (30 * [int]$roleAssignable)

    $specials = @()
    if ($cloudOnlyMemberCount -gt 0) { $specials += "CloudOnlyMembers($cloudOnlyMemberCount)" }
    if ($contactMembers.Count -gt 0) { $specials += "Contacts($($contactMembers.Count))" }
    if ($deviceMembers.Count -gt 0)  { $specials += "Devices($($deviceMembers.Count))" }
    if ($otherMembers.Count -gt 0)   { $specials += "OtherMemberTypes($($otherMembers.Count))" }
    if ($nestedAsChild)              { $specials += 'NestedAsChild' }
    if ($hasNestedChildren)          { $specials += 'HasNestedChildren' }
    if ($usedForLicensing)           { $specials += 'GroupBasedLicensing' }
    if ($inCA)                       { $specials += 'InConditionalAccess' }
    if ($roleAssignable)             { $specials += 'RoleAssignable' }
    if ($memberError)                { $specials += 'MemberQueryError' }

    return [PSCustomObject]@{
        SafetyRank                = $score
        DisplayName               = $Group.DisplayName
        Type                      = $Group._Type
        Mail                      = $Group.Mail
        TotalMembers              = $totalMembers
        UserMembers               = $userMembers.Count
        CloudOnlyUserMembers      = $cloudOnlyMemberCount
        ContactMembers            = $contactMembers.Count
        DeviceMembers             = $deviceMembers.Count
        OtherMembers              = $otherMembers.Count
        NestedGroupChildren       = $nestedChildren.Count
        NestedAsChildOfOtherGroup = $nestedAsChild
        UsedForLicensing          = $usedForLicensing
        InConditionalAccess       = $inCA
        IsRoleAssignable          = $roleAssignable
        SpecialCases              = ($specials -join '; ')
        EntraObjectId             = $Group.Id
        OnPremSID                 = $Group.OnPremisesSecurityIdentifier
        OnPremSam                 = $Group.OnPremisesSamAccountName
        Description               = $Group.Description
        MemberQueryError          = $memberError
    }
}

function Show-DiscoverySummary {
    param([Parameter(Mandatory)]$Rows)
    if (-not $Rows -or @($Rows).Count -eq 0) {
        Write-Warning "No discovery rows to summarize."
        return
    }
    $tier0 = $Rows | Where-Object { $_.SafetyRank -eq 0 }
    $tier1 = $Rows | Where-Object { $_.SafetyRank -gt 0  -and $_.SafetyRank -le 5 }
    $tier2 = $Rows | Where-Object { $_.SafetyRank -gt 5  -and $_.SafetyRank -le 20 }
    $tier3 = $Rows | Where-Object { $_.SafetyRank -gt 20 }

    Write-Host "`n=== Safety Tiers ===" -ForegroundColor Cyan
    Write-Host ("  Tier 0 (empty, no flags) : {0}" -f $tier0.Count) -ForegroundColor Green
    Write-Host ("  Tier 1 (1-5, no flags)   : {0}" -f $tier1.Count) -ForegroundColor Green
    Write-Host ("  Tier 2 (small or 1 flag) : {0}" -f $tier2.Count) -ForegroundColor Yellow
    Write-Host ("  Tier 3 (larger / flagged): {0}" -f $tier3.Count) -ForegroundColor Yellow
}

function Find-LatestReadinessCsv {
    if (-not (Test-Path $script:DiscoveryFolder)) { return $null }
    return Get-ChildItem -Path $script:DiscoveryFolder -Filter 'GroupSOAReadiness-*.csv' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Read-ReadinessCsv {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) {
        Write-Error "Readiness CSV not found: $Path"
        return $null
    }
    $rows = Import-Csv -Path $Path
    $invalid = @($rows | Where-Object { -not $_.EntraObjectId -or -not $_.DisplayName })
    if ($invalid.Count -gt 0) {
        Write-Warning "$($invalid.Count) row(s) missing EntraObjectId or DisplayName - ignoring."
        $rows = @($rows | Where-Object { $_.EntraObjectId -and $_.DisplayName })
    }
    return @($rows)
}

function Resolve-DiscoveryData {
    # Interactive: fresh / cached / skip. Stores result in $script:DiscoveryData.
    Write-Host "`n=== Discovery ===" -ForegroundColor Cyan
    $latest = Find-LatestReadinessCsv

    if ($latest) {
        $age = (Get-Date) - $latest.LastWriteTime
        $ageStr = if ($age.TotalDays -ge 1) { "{0:N1} days old" -f $age.TotalDays } else { "{0:N1} hours old" -f $age.TotalHours }
        Write-Host "Latest readiness CSV: $($latest.Name) ($ageStr)" -ForegroundColor Green
    }
    else {
        Write-Host "No prior readiness CSV found in $($script:DiscoveryFolder)." -ForegroundColor Yellow
    }

    Write-Host "`nChoose discovery mode:"
    Write-Host "  [1] Fresh full discovery (slow, accurate)"
    if ($latest) { Write-Host "  [2] Use cached CSV ($($latest.Name))" }
    Write-Host "  [3] Skip (only do post-conversion owner cleanup)"

    $choice = Read-Host "`nEnter choice"
    switch ($choice) {
        '1' {
            $script:DiscoveryData = Invoke-FreshDiscovery
        }
        '2' {
            if (-not $latest) {
                Write-Warning "No cached CSV available; falling back to fresh discovery."
                $script:DiscoveryData = Invoke-FreshDiscovery
            }
            else {
                $rows = Read-ReadinessCsv -Path $latest.FullName
                if ($rows) {
                    Write-Host "Loaded $($rows.Count) row(s) from $($latest.Name)." -ForegroundColor Green
                    $script:DiscoveryData = $rows
                }
            }
        }
        '3' {
            Write-Host "Discovery skipped. Convert/Revert actions will require fresh discovery to use." -ForegroundColor Yellow
            $script:DiscoveryData = $null
        }
        default {
            Write-Warning "Invalid choice; defaulting to skip."
            $script:DiscoveryData = $null
        }
    }
}

# =============================================================================
# Convert action
# =============================================================================

function Invoke-ConvertAction {
    if (-not $script:DiscoveryData -or @($script:DiscoveryData).Count -eq 0) {
        Write-Warning "Convert needs discovery data. Choose 'Re-run discovery' from the menu first."
        return
    }

    $picker = $script:DiscoveryData | Sort-Object SafetyRank, DisplayName
    $selected = Show-GroupPicker -Rows $picker -Title "Select groups to CONVERT to cloud-managed (Ctrl/Shift for multi-select)"
    if (-not $selected) { Write-Host "No groups selected. Returning to menu." -ForegroundColor Yellow; return }

    Write-Host "`n=== Convert: Confirmation ===" -ForegroundColor Cyan
    Write-Host "The following $($selected.Count) group(s) will be PATCHed isCloudManaged=true:`n"
    $selected | Format-Table SafetyRank, DisplayName, Type, TotalMembers, SpecialCases -AutoSize
    if (-not (Confirm-WithUser -Question "Proceed?")) {
        Write-Host "Aborted by user. No changes made." -ForegroundColor Yellow
        return
    }

    Write-Host "`nExecuting conversions..." -ForegroundColor Cyan
    $rows = foreach ($g in $selected) {
        $status = 'Unknown'; $err = $null
        try {
            $uri = "https://graph.microsoft.com/v1.0/groups/$($g.EntraObjectId)/onPremisesSyncBehavior"
            $body = @{ isCloudManaged = $true } | ConvertTo-Json
            $null = Invoke-MgGraphRequest -Uri $uri -Method PATCH -Body $body -ContentType 'application/json' -ErrorAction Stop
            $status = 'Converted'
            Write-Host "  [OK]   $($g.DisplayName)" -ForegroundColor Green
        }
        catch {
            $status = 'Failed'; $err = $_.Exception.Message
            Write-Host "  [FAIL] $($g.DisplayName): $err" -ForegroundColor Red
        }
        [PSCustomObject]@{
            Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Action        = 'Convert'
            DisplayName   = $g.DisplayName
            Mail          = $g.Mail
            Type          = $g.Type
            EntraObjectId = $g.EntraObjectId
            OnPremSID     = $g.OnPremSID
            Status        = $status
            Error         = $err
        }
    }

    Write-AuditLog -Rows $rows -Prefix 'SOAConversion' | Out-Null

    $ok = ($rows | Where-Object Status -eq 'Converted').Count
    $bad = ($rows | Where-Object Status -eq 'Failed').Count
    Write-Host "`nConvert summary: $ok converted, $bad failed." -ForegroundColor Cyan
    if ($ok -gt 0) {
        Write-Host "Reminder: run 'Start-ADSyncSyncCycle -PolicyType Delta' on the Entra Connect server" -ForegroundColor Cyan
        Write-Host "to stop syncing the converted group(s) from on-prem AD." -ForegroundColor Cyan
    }
}

# =============================================================================
# Revert action
# =============================================================================

function Find-LatestConversionLog {
    if (-not (Test-Path $script:ActionFolder)) { return $null }
    return Get-ChildItem -Path $script:ActionFolder -Filter 'SOAConversion-*.csv' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

function Get-RevertCandidatesFromAuditLog {
    # Loads recent conversion audit log and returns rows where Status='Converted'.
    $log = Find-LatestConversionLog
    if (-not $log) {
        Write-Host "No prior conversion audit log found." -ForegroundColor Yellow
        return @()
    }
    Write-Host "Most recent conversion log: $($log.Name)" -ForegroundColor Green
    $rows = Import-Csv -Path $log.FullName
    return @($rows | Where-Object { $_.Status -eq 'Converted' -and $_.EntraObjectId })
}

function Resolve-GroupForRevert {
    # Manual entry path: user supplies an identifier; we resolve it to an Entra group.
    $id = Read-Host "Enter group display name, mail, UPN-ish identifier, or object GUID"
    if (-not $id) { return $null }
    try {
        # Try direct GUID lookup first
        if ($id -match '^[0-9a-fA-F\-]{36}$') {
            $g = Get-MgGroup -GroupId $id -ErrorAction Stop -Property id, displayName, mail, onPremisesSyncEnabled, onPremisesSecurityIdentifier
        }
        else {
            $g = Get-MgGroup -Filter "displayName eq '$id' or mail eq '$id'" -ErrorAction Stop `
                -Property id, displayName, mail, onPremisesSyncEnabled, onPremisesSecurityIdentifier |
                Select-Object -First 1
        }
        if (-not $g) { Write-Warning "No group resolved for '$id'."; return $null }
        return [PSCustomObject]@{
            DisplayName   = $g.DisplayName
            Mail          = $g.Mail
            EntraObjectId = $g.Id
            OnPremSID     = $g.OnPremisesSecurityIdentifier
        }
    }
    catch {
        Write-Warning "Lookup failed: $($_.Exception.Message)"
        return $null
    }
}

function Test-IsCurrentlyCloudManaged {
    # GETs onPremisesSyncBehavior and returns $true if isCloudManaged is true.
    param([Parameter(Mandatory)][string]$EntraObjectId)
    try {
        $uri = "https://graph.microsoft.com/v1.0/groups/$EntraObjectId/onPremisesSyncBehavior"
        $r = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
        return [bool]$r.isCloudManaged
    }
    catch {
        Write-Debug "isCloudManaged check failed for $EntraObjectId : $($_.Exception.Message)"
        return $false
    }
}

function Invoke-RevertAction {
    Write-Host "`n=== Revert ===" -ForegroundColor Cyan
    Write-Host "Choose source for revert candidates:"
    Write-Host "  [1] Recent conversion audit log (recommended for 'oops, undo that batch')"
    Write-Host "  [2] Manual entry (one group at a time)"
    $choice = Read-Host "`nEnter choice"

    $candidates = @()
    switch ($choice) {
        '1' { $candidates = Get-RevertCandidatesFromAuditLog }
        '2' {
            $g = Resolve-GroupForRevert
            if ($g) { $candidates = @($g) }
        }
        default { Write-Warning "Invalid choice."; return }
    }

    if (-not $candidates -or $candidates.Count -eq 0) {
        Write-Warning "No revert candidates."
        return
    }

    if ($candidates.Count -gt 1) {
        $selected = Show-GroupPicker -Rows $candidates -Title "Select groups to REVERT (back to on-prem-synced)"
        if (-not $selected) { Write-Host "No groups selected. Returning to menu." -ForegroundColor Yellow; return }
    }
    else {
        $selected = $candidates
    }

    Write-Host "`nVerifying current state for $($selected.Count) group(s)..." -ForegroundColor Cyan
    $eligible = @()
    foreach ($g in $selected) {
        if (Test-IsCurrentlyCloudManaged -EntraObjectId $g.EntraObjectId) {
            $eligible += $g
            Write-Host "  [OK]   $($g.DisplayName) is currently cloud-managed - eligible to revert." -ForegroundColor Green
        }
        else {
            Write-Host "  [SKIP] $($g.DisplayName) is NOT currently cloud-managed - skipping." -ForegroundColor Yellow
        }
    }
    if ($eligible.Count -eq 0) { Write-Warning "Nothing to revert."; return }

    Write-Host "`n=== Revert: Confirmation ===" -ForegroundColor Cyan
    $eligible | Format-Table DisplayName, Mail, EntraObjectId -AutoSize
    if (-not (Confirm-WithUser -Question "Revert $($eligible.Count) group(s) to on-prem-synced?")) {
        Write-Host "Aborted by user." -ForegroundColor Yellow
        return
    }

    Write-Host "`nExecuting reverts..." -ForegroundColor Cyan
    $rows = foreach ($g in $eligible) {
        $status = 'Unknown'; $err = $null
        try {
            $uri = "https://graph.microsoft.com/v1.0/groups/$($g.EntraObjectId)/onPremisesSyncBehavior"
            $body = @{ isCloudManaged = $false } | ConvertTo-Json
            $null = Invoke-MgGraphRequest -Uri $uri -Method PATCH -Body $body -ContentType 'application/json' -ErrorAction Stop
            $status = 'Reverted'
            Write-Host "  [OK]   $($g.DisplayName)" -ForegroundColor Green
        }
        catch {
            $status = 'Failed'; $err = $_.Exception.Message
            Write-Host "  [FAIL] $($g.DisplayName): $err" -ForegroundColor Red
        }
        [PSCustomObject]@{
            Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Action        = 'Revert'
            DisplayName   = $g.DisplayName
            Mail          = $g.Mail
            EntraObjectId = $g.EntraObjectId
            OnPremSID     = $g.OnPremSID
            Status        = $status
            Error         = $err
        }
    }
    Write-AuditLog -Rows $rows -Prefix 'SOARevert' | Out-Null
}

# =============================================================================
# Owner-fix action
# =============================================================================

function Test-IsInvalidOwnerEntry {
    param([string]$Entry, [string[]]$Hints)
    foreach ($h in $Hints) { if ($Entry -like $h) { return $true } }
    return $false
}

function Test-GroupEligibleForOwnerReset {
    # Eligible only if ManagedBy is empty OR every entry matches an invalid pattern.
    param($ManagedBy, [string[]]$Hints)
    if (-not $ManagedBy -or @($ManagedBy).Count -eq 0) { return $true }
    foreach ($e in $ManagedBy) {
        if (-not (Test-IsInvalidOwnerEntry -Entry "$e" -Hints $Hints)) { return $false }
    }
    return $true
}

function Resolve-NewOwnerRecipient {
    # Validates the proposed owner identity resolves and is a permitted ManagedBy type.
    param([Parameter(Mandatory)][string]$Identity)
    try {
        $r = Get-Recipient -Identity $Identity -ErrorAction Stop
    }
    catch {
        Write-Error "Cannot resolve '$Identity' as a recipient: $($_.Exception.Message)"
        return $null
    }
    if ($r.RecipientTypeDetails -notin $script:ValidOwnerRecipientTypes) {
        Write-Error "Owner type '$($r.RecipientTypeDetails)' is not permitted by Exchange as ManagedBy."
        return $null
    }
    Write-Host "  Resolves to: $($r.DisplayName) [$($r.RecipientTypeDetails)] $($r.PrimarySmtpAddress)" -ForegroundColor Green
    return $r
}

function Get-CloudManagedExchangeGroups {
    # Returns all cloud-managed (IsDirSynced=False) DLs/MESGs from EXO.
    Write-Host "Enumerating cloud-managed distribution / mail-enabled security groups..." -ForegroundColor Cyan
    try {
        $all = Get-DistributionGroup -ResultSize Unlimited -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to enumerate distribution groups: $($_.Exception.Message)"
        return @()
    }
    $cloud = @($all | Where-Object { -not $_.IsDirSynced })
    Write-Host "  $($cloud.Count) cloud-managed group(s) found." -ForegroundColor Green
    return $cloud
}

function Invoke-OwnerFixResetAction {
    # Reset broken ManagedBy: only acts on empty / all-invalid groups.
    Write-Host "`n=== Owner Fix: Reset Broken ManagedBy ===" -ForegroundColor Cyan
    $newOwner = Read-Host "New owner identity (UPN, primary SMTP, or display name)"
    if (-not $newOwner) { Write-Warning "No owner provided."; return }

    $ownerRecipient = Resolve-NewOwnerRecipient -Identity $newOwner
    if (-not $ownerRecipient) { return }

    $cloud = Get-CloudManagedExchangeGroups
    if ($cloud.Count -eq 0) { return }

    $rows = foreach ($g in $cloud) {
        $current = @($g.ManagedBy)
        $eligible = Test-GroupEligibleForOwnerReset -ManagedBy $current -Hints $script:DefaultInvalidOwnerHints
        [PSCustomObject]@{
            DisplayName               = $g.DisplayName
            PrimarySmtpAddress        = $g.PrimarySmtpAddress
            Type                      = $g.RecipientTypeDetails
            OwnerCount                = $current.Count
            Eligible                  = $eligible
            CurrentManagedBy          = $current -join '; '
            ExternalDirectoryObjectId = $g.ExternalDirectoryObjectId
        }
    }

    $eligibleRows = @($rows | Where-Object Eligible)
    Write-Host "  Eligible for reset: $($eligibleRows.Count) ; ineligible (already has valid owner): $(($rows | Where-Object {-not $_.Eligible}).Count)" -ForegroundColor Green
    if ($eligibleRows.Count -eq 0) { Write-Warning "No eligible groups."; return }

    $selected = Show-GroupPicker -Rows ($eligibleRows | Sort-Object DisplayName) -Title "Select eligible groups to RESET ManagedBy -> $newOwner"
    if (-not $selected) { Write-Host "No groups selected." -ForegroundColor Yellow; return }

    Write-Host "`n=== Confirmation ===" -ForegroundColor Cyan
    Write-Host "  New owner:   $newOwner ($($ownerRecipient.DisplayName))"
    Write-Host "  Group count: $($selected.Count)`n"
    $selected | Format-Table DisplayName, Type, OwnerCount, CurrentManagedBy -AutoSize
    if (-not (Confirm-WithUser -Question "Proceed with reset?")) { Write-Host "Aborted." -ForegroundColor Yellow; return }

    Write-Host "`nApplying changes..." -ForegroundColor Cyan
    $audit = foreach ($row in $selected) {
        $status = 'Unknown'; $err = $null
        $targetId = if ($row.ExternalDirectoryObjectId) { $row.ExternalDirectoryObjectId } else { $row.DisplayName }
        try {
            $live = Get-DistributionGroup -Identity $targetId -ErrorAction Stop
            $liveManagedBy = @($live.ManagedBy)
            if (-not (Test-GroupEligibleForOwnerReset -ManagedBy $liveManagedBy -Hints $script:DefaultInvalidOwnerHints)) {
                $status = 'Skipped'; $err = 'No longer eligible at apply time.'
                Write-Host "  [SKIP] $($row.DisplayName): $err" -ForegroundColor Yellow
            }
            else {
                Set-DistributionGroup -Identity $targetId -ManagedBy $newOwner -BypassSecurityGroupManagerCheck -ErrorAction Stop
                $status = 'Updated'
                Write-Host "  [OK]   $($row.DisplayName)" -ForegroundColor Green
            }
        }
        catch {
            $status = 'Failed'; $err = $_.Exception.Message
            Write-Host "  [FAIL] $($row.DisplayName): $err" -ForegroundColor Red
        }
        [PSCustomObject]@{
            Timestamp                 = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Action                    = 'OwnerFix-Reset'
            DisplayName               = $row.DisplayName
            PrimarySmtpAddress        = $row.PrimarySmtpAddress
            Type                      = $row.Type
            ExternalDirectoryObjectId = $row.ExternalDirectoryObjectId
            OldManagedBy              = $row.CurrentManagedBy
            NewManagedBy              = if ($status -eq 'Updated') { $newOwner } else { $null }
            Status                    = $status
            Error                     = $err
        }
    }
    Write-AuditLog -Rows $audit -Prefix 'SetConvertedGroupOwners' | Out-Null
}

function Invoke-OwnerFixAppendAction {
    # Append new owner where missing, never duplicate, never strip existing entries.
    Write-Host "`n=== Owner Fix: Append Owner Where Missing ===" -ForegroundColor Cyan
    $newOwner = Read-Host "Owner identity to ensure is present (UPN, primary SMTP, or display name)"
    if (-not $newOwner) { Write-Warning "No owner provided."; return }

    $ownerRecipient = Resolve-NewOwnerRecipient -Identity $newOwner
    if (-not $ownerRecipient) { return }
    $targetEdoId = $ownerRecipient.ExternalDirectoryObjectId

    $cloud = Get-CloudManagedExchangeGroups
    if ($cloud.Count -eq 0) { return }

    Write-Host "Resolving existing ManagedBy entries (cached per identity)..." -ForegroundColor Cyan
    $resolveCache = @{}
    function Resolve-Entry {
        param([string]$Entry)
        if ($resolveCache.ContainsKey($Entry)) { return $resolveCache[$Entry] }
        $id = $null
        try { $id = (Get-Recipient -Identity $Entry -ErrorAction Stop).ExternalDirectoryObjectId } catch {}
        $resolveCache[$Entry] = $id
        return $id
    }

    $rows = foreach ($g in $cloud) {
        $current = @($g.ManagedBy)
        $alreadyPresent = $false
        foreach ($entry in $current) {
            if ((Resolve-Entry $entry) -eq $targetEdoId) { $alreadyPresent = $true; break }
        }
        [PSCustomObject]@{
            DisplayName               = $g.DisplayName
            PrimarySmtpAddress        = $g.PrimarySmtpAddress
            Type                      = $g.RecipientTypeDetails
            OwnerCount                = $current.Count
            AlreadyPresent            = $alreadyPresent
            CurrentManagedBy          = $current -join '; '
            ExternalDirectoryObjectId = $g.ExternalDirectoryObjectId
        }
    }

    $missingRows = @($rows | Where-Object { -not $_.AlreadyPresent })
    Write-Host "  Already has the owner: $(($rows | Where-Object AlreadyPresent).Count)" -ForegroundColor Green
    Write-Host "  Will need to add it:    $($missingRows.Count)" -ForegroundColor Green
    if ($missingRows.Count -eq 0) { Write-Warning "Nothing to append."; return }

    $selected = Show-GroupPicker -Rows ($missingRows | Sort-Object DisplayName) -Title "Select groups to APPEND $newOwner to ManagedBy"
    if (-not $selected) { Write-Host "No groups selected." -ForegroundColor Yellow; return }

    Write-Host "`n=== Confirmation ===" -ForegroundColor Cyan
    Write-Host "  Owner to add:   $newOwner ($($ownerRecipient.DisplayName))"
    Write-Host "  Group count:    $($selected.Count)`n"
    $selected | Format-Table DisplayName, Type, OwnerCount, CurrentManagedBy -AutoSize
    if (-not (Confirm-WithUser -Question "Proceed with append?")) { Write-Host "Aborted." -ForegroundColor Yellow; return }

    Write-Host "`nApplying changes..." -ForegroundColor Cyan
    $audit = foreach ($row in $selected) {
        $status = 'Unknown'; $err = $null; $newList = $null
        $targetId = if ($row.ExternalDirectoryObjectId) { $row.ExternalDirectoryObjectId } else { $row.DisplayName }
        try {
            $live = Get-DistributionGroup -Identity $targetId -ErrorAction Stop
            $liveManagedBy = @($live.ManagedBy)
            # Re-check at apply time
            $stillMissing = $true
            foreach ($entry in $liveManagedBy) {
                if ((Resolve-Entry $entry) -eq $targetEdoId) { $stillMissing = $false; break }
            }
            if (-not $stillMissing) {
                $status = 'Skipped'; $err = 'Owner already present at apply time.'
                Write-Host "  [SKIP] $($row.DisplayName): $err" -ForegroundColor Yellow
            }
            else {
                $newList = @($liveManagedBy) + $newOwner
                Set-DistributionGroup -Identity $targetId -ManagedBy $newList -BypassSecurityGroupManagerCheck -ErrorAction Stop
                $status = 'Appended'
                Write-Host "  [OK]   $($row.DisplayName)" -ForegroundColor Green
            }
        }
        catch {
            $status = 'Failed'; $err = $_.Exception.Message
            Write-Host "  [FAIL] $($row.DisplayName): $err" -ForegroundColor Red
        }
        [PSCustomObject]@{
            Timestamp                 = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Action                    = 'OwnerFix-Append'
            DisplayName               = $row.DisplayName
            PrimarySmtpAddress        = $row.PrimarySmtpAddress
            Type                      = $row.Type
            ExternalDirectoryObjectId = $row.ExternalDirectoryObjectId
            OldManagedBy              = $row.CurrentManagedBy
            NewManagedBy              = if ($status -eq 'Appended') { ($newList -join '; ') } else { $null }
            Status                    = $status
            Error                     = $err
        }
    }
    Write-AuditLog -Rows $audit -Prefix 'AppendGroupOwners' | Out-Null
}

function Invoke-OwnerFixAction {
    if (-not (Connect-ExoIfNeeded)) { return }
    Write-Host "`n=== Owner Fix ===" -ForegroundColor Cyan
    Write-Host "  [1] Reset broken ManagedBy (only on empty / all-invalid groups)"
    Write-Host "  [2] Append owner where missing (additive, preserves existing owners)"
    $sub = Read-Host "`nEnter choice"
    switch ($sub) {
        '1' { Invoke-OwnerFixResetAction }
        '2' { Invoke-OwnerFixAppendAction }
        default { Write-Warning "Invalid choice." }
    }
}

# =============================================================================
# Main flow
# =============================================================================

function Show-Banner {
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "  Group SOA Workflow - Discovery, Convert, Revert, Owner Fix" -ForegroundColor Cyan
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "  Discovery output: $($script:DiscoveryFolder)"
    Write-Host "  Action audits:    $($script:ActionFolder)"
    Write-Host ""
}

function Show-MainMenu {
    Write-Host "`n=== Main Menu ===" -ForegroundColor Cyan
    $hasData = $null -ne $script:DiscoveryData -and @($script:DiscoveryData).Count -gt 0
    $dataSummary = if ($hasData) { "$(@($script:DiscoveryData).Count) candidate group(s) loaded" } else { 'no discovery data loaded' }
    Write-Host "  Discovery: $dataSummary"
    Write-Host ""
    Write-Host "  [1] Convert synced groups to cloud-managed"
    Write-Host "  [2] Revert cloud-managed groups to on-prem-synced"
    Write-Host "  [3] Fix legacy ManagedBy on cloud-managed Exchange groups"
    Write-Host "  [4] Re-run discovery"
    Write-Host "  [5] Exit"
    return (Read-Host "`nEnter choice")
}

function Start-Workflow {
    Show-Banner

    # Modules + Graph connection up front.
    $graphMods = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Identity.SignIns'
    )
    if (-not (Install-RequiredModulesInteractive -Modules $graphMods)) { return }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Groups         -ErrorAction Stop
    Import-Module Microsoft.Graph.Users          -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

    if (-not (Test-OutGridViewAvailable)) { return }

    $graphScopes = @(
        'Directory.Read.All',
        'Group.Read.All',
        'Group-OnPremisesSyncBehavior.ReadWrite.All',
        'Policy.Read.All'
    )
    if (-not (Connect-GraphForScopes -Scopes $graphScopes)) { return }

    # Discovery first, then action loop.
    Resolve-DiscoveryData

    while ($true) {
        $choice = Show-MainMenu
        switch ($choice) {
            '1' { Invoke-ConvertAction }
            '2' { Invoke-RevertAction }
            '3' { Invoke-OwnerFixAction }
            '4' { Resolve-DiscoveryData }
            '5' { Write-Host "Goodbye." -ForegroundColor Cyan; return }
            default { Write-Warning "Invalid choice." }
        }
    }
}

# =============================================================================
# Bootstrap
# =============================================================================

Start-Workflow
