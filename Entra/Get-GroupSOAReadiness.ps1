#Requires -Version 5.1

<#
.SYNOPSIS
    Ranks on-prem synced groups by how safe they are to SOA-convert, safest first.

.DESCRIPTION
    Read-only reconnaissance script for Microsoft Entra Group Source-of-Authority (SOA)
    conversion planning. Pulls synced Security / MESG / DL groups, counts members by
    type (users, contacts, devices, nested groups, other), and flags the things that
    actually affect conversion blast radius: cloud-only members, nesting, group-based
    licensing, Conditional Access references, and role-assignable groups.

    Output is a single CSV sorted by a simple safety rank. Lowest rank equals safest
    to convert first. Use this to build a conversion backlog, then feed the safe ones
    into a companion converter script.

    Ranking weights (edit in the script if they don't match your risk model):
      +1  per total member
      +5  per cloud-only member   (won't revert cleanly if you roll back SOA)
      +10 nested as a child in another group
      +10 contains nested child groups
      +20 used for group-based licensing
      +20 referenced by a Conditional Access policy
      +30 role-assignable group (isAssignableToRole = true)

    Runtime expectation: about 2 Graph calls per synced group (members + memberOf).
    Plan on several minutes on a tenant with hundreds of synced groups. The output CSV
    is your cache -- re-run weekly, not every session.

    Required modules: Microsoft.Graph.Authentication, Microsoft.Graph.Groups,
    Microsoft.Graph.Users, and (unless -SkipConditionalAccessCheck is used)
    Microsoft.Graph.Identity.SignIns. If any are missing the script will prompt to
    install them for the current user before continuing.

.PARAMETER LogPath
    Folder to write the CSV. Default: $env:USERPROFILE\Documents\HybridRecon

.PARAMETER IncludeTypes
    Which group types to include. Default: SecurityGroup, MESG, DistributionList.
    M365Group and Dynamic are always excluded (not in scope for SOA).

.PARAMETER SkipConditionalAccessCheck
    Skip the CA policy scan. Saves one API call and avoids needing Policy.Read.All
    scope, at the cost of losing the InConditionalAccess flag on the output.

.EXAMPLE
    .\Get-GroupSOAReadiness.ps1

    Runs with defaults: all three supported group types, CA scan on, output to
    $env:USERPROFILE\Documents\HybridRecon. Prompts interactively for Graph sign-in
    if not already connected.

.EXAMPLE
    .\Get-GroupSOAReadiness.ps1 -IncludeTypes SecurityGroup

    Scope to security groups only.

.EXAMPLE
    .\Get-GroupSOAReadiness.ps1 -SkipConditionalAccessCheck -LogPath C:\Reports

    Skip CA policy scan, write to a custom folder.

.INPUTS
    None.

.OUTPUTS
    Writes a timestamped CSV to $LogPath. Prints safety-tier counts and a top-15
    safest-candidates table to the console.

.NOTES
    Version:     1.2
    Author:      Brandon Inabinet
    Released:    2026-04-18
    Tested on:   Windows PowerShell 5.1 and PowerShell 7.x with Microsoft.Graph 2.x.

    LICENSE (MIT):
        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in
        all copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED. See https://opensource.org/licenses/MIT for full text.

    DISCLAIMER:
        Not affiliated with or endorsed by Microsoft. This script is read-only and
        does NOT perform SOA conversions, it only reports on the landscape. SOA
        conversion itself affects Exchange Online, licensing, Conditional Access, and
        other downstream systems; validate in a non-production tenant and understand
        the Microsoft guidance before acting on this script's output.

    AI ASSISTANCE:
        Portions of this script were drafted with AI assistance, then reviewed and
        tested by the author. You are responsible for understanding and testing any
        code before running it in your environment.

    NOT DETECTED BY THIS SCRIPT:
      - Access package / entitlement management references
      - Exchange mail-flow rules or DL usage patterns
      - Service principals / enterprise apps assigned the group as an owner
      - Intune / SCCM / GPO-driven membership automation
      Review those separately for groups that end up high in the conversion backlog.

    TROUBLESHOOTING:
      If Graph cmdlets fail with "Could not load file or assembly", your
      Microsoft.Graph modules likely have mixed 1.x/2.x versions installed. Uninstall
      all Microsoft.Graph* modules and reinstall the ones this script uses.
#>

[CmdletBinding()]
param(
    [string]$LogPath = "$env:USERPROFILE\Documents\HybridRecon",

    [ValidateSet('SecurityGroup','MESG','DistributionList')]
    [string[]]$IncludeTypes = @('SecurityGroup','MESG','DistributionList'),

    [switch]$SkipConditionalAccessCheck
)

# ----- Module check: prompt to install anything missing -----
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Users'
)
if (-not $SkipConditionalAccessCheck) {
    $requiredModules += 'Microsoft.Graph.Identity.SignIns'
}

$missingModules = @($requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })

if ($missingModules.Count -gt 0) {
    Write-Host ""
    Write-Host "The following required module(s) are not installed:" -ForegroundColor Yellow
    $missingModules | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ""
    $answer = Read-Host "Install them now for the current user? [Y/n]"
    if ($answer -match '^[Nn]') {
        Write-Error "Required module(s) missing. Exiting."
        return
    }

    foreach ($mod in $missingModules) {
        Write-Host "Installing $mod ..." -ForegroundColor Cyan
        try {
            Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host "  Installed $mod." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install '$mod': $($_.Exception.Message)"
            return
        }
    }
}

# Import what we need (auto-loading handles most of this, but being explicit is harmless)
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Groups -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop
if (-not $SkipConditionalAccessCheck) {
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
}

# ----- Output path -----
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csvPath = Join-Path $LogPath "GroupSOAReadiness-$timestamp.csv"

# ----- Connect to Graph -----
$neededScopes = @('Directory.Read.All')
if (-not $SkipConditionalAccessCheck) { $neededScopes += 'Policy.Read.All' }

try {
    $context = Get-MgContext
    $missingScopes = $neededScopes | Where-Object { $_ -notin $context.Scopes }
    if (-not $context -or $missingScopes) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes $neededScopes -NoWelcome
    }
}
catch {
    Write-Error "Failed to connect to Graph: $_"
    return
}

# ----- Pull CA policy group references up front (one call, cache the IDs) -----
$caGroupIds = [System.Collections.Generic.HashSet[string]]::new()
if (-not $SkipConditionalAccessCheck) {
    Write-Host "Pulling Conditional Access policies..." -ForegroundColor Cyan
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
        foreach ($p in $caPolicies) {
            foreach ($gid in @($p.Conditions.Users.IncludeGroups) + @($p.Conditions.Users.ExcludeGroups)) {
                if ($gid) { [void]$caGroupIds.Add($gid) }
            }
        }
        Write-Host "  $($caPolicies.Count) policies scanned, $($caGroupIds.Count) unique group references." -ForegroundColor Green
    }
    catch {
        Write-Warning "CA policy scan failed: $($_.Exception.Message). Continuing without CA flag."
    }
}

# ----- Pull synced groups -----
Write-Host "Querying synced groups..." -ForegroundColor Cyan
$groupProps = @(
    'id', 'displayName', 'mail', 'mailEnabled', 'securityEnabled', 'groupTypes',
    'onPremisesSyncEnabled', 'onPremisesSecurityIdentifier', 'onPremisesSamAccountName',
    'assignedLicenses', 'isAssignableToRole', 'description'
)
try {
    $syncedGroups = Get-MgGroup -Filter "onPremisesSyncEnabled eq true" -All `
        -Property $groupProps `
        -ConsistencyLevel eventual -CountVariable groupCount |
        Select-Object $groupProps
}
catch {
    Write-Error "Group query failed: $_"
    return
}
Write-Host "  $($syncedGroups.Count) synced groups found." -ForegroundColor Green

# ----- Classify + filter by type -----
$candidates = foreach ($g in $syncedGroups) {
    $isDynamic = $g.GroupTypes -contains 'DynamicMembership'
    $isM365    = $g.GroupTypes -contains 'Unified'

    $type = if ($isM365) { 'M365Group' }
        elseif ($isDynamic) { 'Dynamic' }
        elseif ($g.MailEnabled -and $g.SecurityEnabled) { 'MESG' }
        elseif ($g.MailEnabled -and -not $g.SecurityEnabled) { 'DistributionList' }
        elseif (-not $g.MailEnabled -and $g.SecurityEnabled) { 'SecurityGroup' }
        else { 'Unknown' }

    if ($type -notin $IncludeTypes) { continue }

    $g | Add-Member -NotePropertyName _Type -NotePropertyValue $type -PassThru -Force
}
Write-Host "  $($candidates.Count) candidates after type filter ($($IncludeTypes -join ', '))." -ForegroundColor Green

# ----- Build synced-user ID set for correct cloud-only detection -----
# Get-MgGroupMember returns DirectoryObjects without onPremisesSyncEnabled by default, so
# per-member checks can't see that property. Instead, pull all synced user IDs once and
# test membership against the set. O(1) lookup, correct result.
Write-Host "Building synced-user ID index for cloud-only member detection..." -ForegroundColor Cyan
$syncedUserIds = [System.Collections.Generic.HashSet[string]]::new()
try {
    Get-MgUser -Filter "onPremisesSyncEnabled eq true" -All -Property id `
        -ConsistencyLevel eventual -CountVariable syncedUserCount |
        ForEach-Object { [void]$syncedUserIds.Add($_.Id) }
    Write-Host "  $($syncedUserIds.Count) synced users indexed." -ForegroundColor Green
}
catch {
    Write-Warning "Could not build synced-user index: $($_.Exception.Message). CloudOnlyUserMembers counts will be unreliable."
}

# ----- Enrich each candidate (members + nesting) -----
Write-Host "Counting members and checking nesting (this is the slow part)..." -ForegroundColor Cyan

# List[object] avoids the O(n^2) reallocation pattern that `$rows += ...` causes.
$rows = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($g in $candidates) {
    $i++
    Write-Progress -Activity "Analyzing groups" -Status "$($g.DisplayName) ($i/$($candidates.Count))" `
        -PercentComplete (($i / [Math]::Max(1, $candidates.Count)) * 100)

    $members = @()
    $memberError = $null
    try {
        $members = Get-MgGroupMember -GroupId $g.Id -All
    }
    catch {
        $memberError = $_.Exception.Message
    }

    $totalMembers = $members.Count
    $nestedChildren  = @($members | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' })
    $userMembers     = @($members | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.user' })
    $contactMembers  = @($members | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.orgContact' })
    $deviceMembers   = @($members | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.device' })
    # "Other" = service principals or any other member type not categorized above
    $otherMembers    = @($members | Where-Object {
        $t = $_.AdditionalProperties['@odata.type']
        $t -and $t -notin @('#microsoft.graph.group', '#microsoft.graph.user', '#microsoft.graph.orgContact', '#microsoft.graph.device')
    })
    $hasNestedChildren = $nestedChildren.Count -gt 0

    # Count cloud-only members: users whose Id is NOT in the synced-user index.
    # (Reading onPremisesSyncEnabled off $um.AdditionalProperties doesn't work; the
    # Get-MgGroupMember default projection omits that property.)
    $cloudOnlyMemberCount = 0
    foreach ($um in $userMembers) {
        if (-not $syncedUserIds.Contains($um.Id)) { $cloudOnlyMemberCount++ }
    }

    # Is this group nested as a child in another group?
    $nestedAsChild = $false
    try {
        $parents = Get-MgGroupMemberOf -GroupId $g.Id -All -ErrorAction Stop
        $nestedAsChild = ($parents | Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' }).Count -gt 0
    }
    catch {
        Write-Debug "Get-MgGroupMemberOf failed for '$($g.DisplayName)' ($($g.Id)): $($_.Exception.Message)"
    }

    $usedForLicensing = ($g.AssignedLicenses | Measure-Object).Count -gt 0
    $inCA             = $caGroupIds.Contains($g.Id)
    $roleAssignable   = [bool]$g.IsAssignableToRole

    # Score: lower = safer
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

    [void]$rows.Add([PSCustomObject]@{
        SafetyRank                = $score
        DisplayName               = $g.DisplayName
        Type                      = $g._Type
        Mail                      = $g.Mail
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
        EntraObjectId             = $g.Id
        OnPremSID                 = $g.OnPremisesSecurityIdentifier
        OnPremSam                 = $g.OnPremisesSamAccountName
        Description               = $g.Description
        MemberQueryError          = $memberError
    })
}
Write-Progress -Activity "Analyzing groups" -Completed

# ----- Sort, write, summarize -----
$sorted = $rows | Sort-Object SafetyRank, DisplayName
$sorted | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`nCSV written to: $csvPath" -ForegroundColor Green

# Safety tiers for a quick console view
$tier0 = $sorted | Where-Object { $_.SafetyRank -eq 0 }
$tier1 = $sorted | Where-Object { $_.SafetyRank -gt 0  -and $_.SafetyRank -le 5 }
$tier2 = $sorted | Where-Object { $_.SafetyRank -gt 5  -and $_.SafetyRank -le 20 }
$tier3 = $sorted | Where-Object { $_.SafetyRank -gt 20 }

Write-Host "`n=== Safety Tiers ===" -ForegroundColor Cyan
Write-Host ("  Tier 0 (empty, no flags) : {0}" -f $tier0.Count) -ForegroundColor Green
Write-Host ("  Tier 1 (1-5, no flags)   : {0}" -f $tier1.Count) -ForegroundColor Green
Write-Host ("  Tier 2 (small or 1 flag) : {0}" -f $tier2.Count) -ForegroundColor Yellow
Write-Host ("  Tier 3 (larger / flagged): {0}" -f $tier3.Count) -ForegroundColor Yellow

Write-Host "`n=== Top 15 Safest Candidates ===" -ForegroundColor Cyan
$sorted | Select-Object -First 15 |
    Format-Table SafetyRank, DisplayName, Type, TotalMembers, SpecialCases -AutoSize

Write-Host "`n=== Type Breakdown ===" -ForegroundColor Cyan
$sorted | Group-Object Type | Sort-Object Count -Descending |
    ForEach-Object { "  {0,-18} {1,6}" -f $_.Name, $_.Count } |
    ForEach-Object { Write-Host $_ }
