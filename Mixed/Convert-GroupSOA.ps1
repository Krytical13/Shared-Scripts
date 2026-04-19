#Requires -Version 5.1

<#
.SYNOPSIS
    Interactively converts on-prem AD-synced groups to cloud-managed SOA
    (Source of Authority) in Microsoft Entra ID.

.DESCRIPTION
    Companion to Get-GroupSOAReadiness.ps1. Pick groups from an enriched picker,
    confirm, and the script PATCHes each one's onPremisesSyncBehavior to
    isCloudManaged=true. Writes a timestamped CSV audit log of what it did.

    Data source options (decided interactively at startup):

      1. Readiness CSV (recommended): if the most recent
         Get-GroupSOAReadiness CSV is found in
         $env:USERPROFILE\Documents\HybridRecon, you are prompted to use it.
         The picker then shows the enriched view: SafetyRank, member breakdown
         (Users/Contacts/Devices/Other), nesting flags, licensing/CA references.
         Full context at the moment of selection.

      2. Live Graph query (fallback): if you decline or no CSV is found, the
         script queries Entra live, classifies groups by type, cross-references
         AD for scope/DN, and shows a simpler picker.

    Compatibility rules (applied in live mode; the readiness CSV has already
    filtered these out):
      - Dynamic-membership groups: not supported for SOA conversion.
      - M365 (Unified) groups: not in scope for this tool.
      - AD object must resolve by OnPremisesSecurityIdentifier (sync linkage
        sanity check).

    AD group scope (Universal/Global/DomainLocal) does NOT gate the conversion.
    That requirement only applies if you later provision the group back to AD
    DS via Cloud Sync.

.PARAMETER LogPath
    Folder to write the CSV audit log. Default:
    $env:USERPROFILE\Documents\SOAConversion

.PARAMETER ReadinessCsvPath
    Optional / advanced. Explicit path to a Get-GroupSOAReadiness CSV. Normally
    not needed - the script auto-detects the most recent one in the default
    folder. Pass this to override auto-detection (archived CSV, custom folder,
    etc.).

.EXAMPLE
    .\Convert-GroupSOA.ps1

    Default run. Auto-detects recent readiness CSV and prompts to use it; falls
    back to live Graph query if declined or not found. Output to
    $env:USERPROFILE\Documents\SOAConversion.

.EXAMPLE
    .\Convert-GroupSOA.ps1 -ReadinessCsvPath C:\Reports\GroupSOAReadiness-archive.csv

    Skip auto-detection, use a specific readiness CSV.

.EXAMPLE
    .\Convert-GroupSOA.ps1 -LogPath D:\SOAAudit

    Custom audit log folder.

.INPUTS
    None.

.OUTPUTS
    Writes a timestamped CSV audit log to $LogPath. Emits OK / FAIL / Skipped
    lines to the console as it runs, plus a final summary.

.NOTES
    Version:     1.1
    Author:      Brandon
    Released:    2026-04-19
    Tested on:   Windows PowerShell 5.1 and PowerShell 7.x with
                 Microsoft.Graph 2.x and RSAT ActiveDirectory module.

    WRITE OPERATIONS:
        Unlike Get-GroupSOAReadiness.ps1 (read-only), this script MODIFIES
        tenant state. Each converted group becomes cloud-managed and Entra
        Connect stops syncing it from on-prem AD. The change is reversible
        via the rollback API (PATCH isCloudManaged=false) but has real
        downstream effects. Always confirm the selection list before pressing Y.

    REQUIRED PERMISSIONS:
        - Graph scopes: Group.Read.All, Group-OnPremisesSyncBehavior.ReadWrite.All
        - Role: Hybrid Administrator (least-privileged role for the SOA PATCH).
        - Local: read access to AD (any domain user is usually enough for
          Get-ADGroup lookups in live mode).

    API VERSION NOTE:
        The onPremisesSyncBehavior resource is documented in the Microsoft
        Graph reference under /beta only
        (https://learn.microsoft.com/graph/api/resources/onpremisessyncbehavior).
        The Entra Hybrid Identity "Configure Group SOA" guide uses /v1.0/ URLs
        and the endpoint currently responds on v1.0 - which is what this
        script uses. If Microsoft changes that, switch the URI to
        https://graph.microsoft.com/beta/... or use the
        Update-MgBetaGroupOnPremiseSyncBehavior cmdlet.

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

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        OR IMPLIED. See https://opensource.org/licenses/MIT for full text.

    DISCLAIMER:
        Not affiliated with or endorsed by Microsoft. SOA conversion affects
        Exchange Online, licensing, Conditional Access, and other downstream
        systems. Validate in a non-production tenant first and understand the
        Microsoft guidance before running against production. Review the
        selection list carefully before confirming each batch.

    AI ASSISTANCE:
        Portions of this script were drafted with AI assistance, then reviewed
        and tested by the author. You are responsible for understanding and
        testing any code before running it in your environment.

    PAIRS WITH:
        Get-GroupSOAReadiness.ps1 - read-only recon that produces the CSV
        this script consumes. Run readiness first to plan waves, then this
        script to execute.

    TROUBLESHOOTING:
      - "Could not load file or assembly" on Graph cmdlets: your
        Microsoft.Graph modules likely have mixed versions installed.
        Uninstall all Microsoft.Graph* modules and reinstall only the ones
        this script uses.

      - TypeLoadException on 'GetTokenAsync' / 'UserProvidedTokenCredential':
        known Microsoft.Graph SDK bug that surfaces in hosted runtimes
        (notably the VSCode PowerShell extension on Windows PowerShell 5.1).
        See https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3479
        Fix: run the script in PowerShell 7 (its per-module
        AssemblyLoadContext avoids the conflict), or run from a standalone
        Windows PowerShell window rather than VSCode's integrated console.

      - Out-GridView missing on PowerShell 7: install the cross-platform
        port via  Install-Module Microsoft.PowerShell.GraphicalTools
        -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [string]$LogPath = "$env:USERPROFILE\Documents\SOAConversion",
    [string]$ReadinessCsvPath
)

# ----- Module check: prompt to install missing Graph modules -----
$requiredGraphModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Groups'
)

$missingGraphModules = @($requiredGraphModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })

if ($missingGraphModules.Count -gt 0) {
    Write-Host ""
    Write-Host "The following required Graph module(s) are not installed:" -ForegroundColor Yellow
    $missingGraphModules | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ""
    $answer = Read-Host "Install them now for the current user? [Y/n]"
    if ($answer -match '^[Nn]') {
        Write-Error "Required module(s) missing. Exiting."
        return
    }

    foreach ($mod in $missingGraphModules) {
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

# ActiveDirectory module is an RSAT feature, not a PSGallery module, so we can't
# offer to Install-Module it. Guide the user to enable it instead.
if (-not (Get-Module -ListAvailable -Name 'ActiveDirectory')) {
    Write-Host ""
    Write-Error "The ActiveDirectory module is required but not installed. It ships as part of RSAT."
    Write-Host "To install on Windows 10/11 (elevated PowerShell):" -ForegroundColor Yellow
    Write-Host "  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Yellow
    Write-Host "On Windows Server:" -ForegroundColor Yellow
    Write-Host "  Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Yellow
    return
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Groups -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

# Out-GridView guard (PS 7 on non-Windows doesn't ship it by default)
if (-not (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
    Write-Error "Out-GridView not available. On PowerShell 7, install: Install-Module Microsoft.PowerShell.GraphicalTools -Scope CurrentUser"
    return
}

# ----- Setup log output -----
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Join-Path $LogPath "SOAConversion-$timestamp.csv"

Write-Host "`n=== Group SOA Conversion Tool ===" -ForegroundColor Cyan

# ----- Connect to Graph (needed in both modes for the PATCH call) -----
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    $context = Get-MgContext
    $neededScopes = @('Group.Read.All', 'Group-OnPremisesSyncBehavior.ReadWrite.All')
    $missingScopes = $neededScopes | Where-Object { $_ -notin $context.Scopes }

    if (-not $context -or $missingScopes) {
        Connect-MgGraph -Scopes $neededScopes -NoWelcome
    }
}
catch {
    Write-Error "Failed to connect to Graph: $_"
    return
}

# ----- Decide data source: readiness CSV or live query -----
# No switch required - the script auto-detects recent readiness CSVs and prompts.
$useReadinessCsv = $false

if (-not $ReadinessCsvPath) {
    $defaultReadinessFolder = "$env:USERPROFILE\Documents\HybridRecon"
    if (Test-Path $defaultReadinessFolder) {
        $latestCsv = Get-ChildItem -Path $defaultReadinessFolder -Filter 'GroupSOAReadiness-*.csv' `
            -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latestCsv) {
            $csvAge = (Get-Date) - $latestCsv.LastWriteTime
            $ageStr = if ($csvAge.TotalDays -ge 1) { "{0:N1} days old" -f $csvAge.TotalDays }
                      else { "{0:N1} hours old" -f $csvAge.TotalHours }

            Write-Host "`nFound readiness data:" -ForegroundColor Cyan
            Write-Host "  File: $($latestCsv.Name)"
            Write-Host "  Age:  $ageStr"
            if ($csvAge.TotalDays -gt 3) {
                Write-Host "  (older than 3 days - member counts and flags may be stale)" -ForegroundColor Yellow
            }

            $answer = Read-Host "`nUse this readiness data for the picker? [Y/n]"
            if ($answer -notmatch '^[Nn]') {
                $ReadinessCsvPath = $latestCsv.FullName
                $useReadinessCsv = $true
            }
        }
    }
}
else {
    $useReadinessCsv = $true
}

if ($useReadinessCsv) {
    # --- READINESS CSV MODE ---
    if (-not (Test-Path $ReadinessCsvPath)) {
        Write-Error "Readiness CSV not found: $ReadinessCsvPath"
        return
    }

    Write-Host "Loading readiness data from: $ReadinessCsvPath" -ForegroundColor Cyan
    $results = Import-Csv -Path $ReadinessCsvPath

    # Sanity check: must have EntraObjectId and DisplayName
    $invalid = @($results | Where-Object { -not $_.EntraObjectId -or -not $_.DisplayName })
    if ($invalid.Count -gt 0) {
        Write-Warning "$($invalid.Count) CSV row(s) missing EntraObjectId or DisplayName - will be ignored."
        $results = @($results | Where-Object { $_.EntraObjectId -and $_.DisplayName })
    }

    # Normalize columns the conversion/audit pipeline expects. The readiness CSV
    # uses 'Type' for the group type; map it to GroupType. Also backfill columns
    # that live-mode produces (ADScope, ADDistinguishedName, Compatible, Issues)
    # with safe defaults so downstream code doesn't need to special-case modes.
    foreach ($row in $results) {
        if (-not $row.PSObject.Properties['GroupType']) {
            $row | Add-Member -NotePropertyName GroupType -NotePropertyValue $row.Type -Force
        }
        if (-not $row.PSObject.Properties['ADScope']) {
            $row | Add-Member -NotePropertyName ADScope -NotePropertyValue 'n/a (CSV)' -Force
        }
        if (-not $row.PSObject.Properties['ADDistinguishedName']) {
            $row | Add-Member -NotePropertyName ADDistinguishedName -NotePropertyValue $null -Force
        }
        # Readiness CSV rows are pre-filtered to convertible types, so treat as compatible.
        if (-not $row.PSObject.Properties['Compatible']) {
            $row | Add-Member -NotePropertyName Compatible -NotePropertyValue $true -Force
        }
        if (-not $row.PSObject.Properties['Issues']) {
            $row | Add-Member -NotePropertyName Issues -NotePropertyValue '' -Force
        }
    }

    Write-Host "Loaded $($results.Count) candidate group(s) from readiness CSV." -ForegroundColor Green
}
else {
    # --- LIVE QUERY MODE ---
    Write-Host "Select which group types to include in the search:`n"

    $typeOptions = @(
        [PSCustomObject]@{Key='1'; Label='Security Groups (non-mail-enabled) - simplest, safest'}
        [PSCustomObject]@{Key='2'; Label='Mail-Enabled Security Groups (MESGs)'}
        [PSCustomObject]@{Key='3'; Label='Distribution Lists (DLs) - email-only groups'}
        [PSCustomObject]@{Key='4'; Label='All of the above'}
    )
    $typeOptions | ForEach-Object { Write-Host "  [$($_.Key)] $($_.Label)" }

    $typeChoice = Read-Host "`nEnter choice (1-4)"
    $includeTypes = switch ($typeChoice) {
        '1' { @('SecurityGroup') }
        '2' { @('MESG') }
        '3' { @('DistributionList') }
        '4' { @('SecurityGroup', 'MESG', 'DistributionList') }
        default {
            Write-Error "Invalid choice."
            return
        }
    }
    Write-Host "Including: $($includeTypes -join ', ')`n" -ForegroundColor Green

    Write-Host "Querying Entra ID for on-prem synced groups..." -ForegroundColor Cyan
    $filter = "onPremisesSyncEnabled eq true"
    $properties = @(
        'id', 'displayName', 'mail', 'mailEnabled', 'securityEnabled', 'groupTypes',
        'onPremisesSyncEnabled', 'onPremisesSamAccountName', 'onPremisesSecurityIdentifier',
        'onPremisesDomainName', 'description'
    )

    try {
        $syncedGroups = Get-MgGroup -Filter $filter -All `
            -Property $properties `
            -ConsistencyLevel eventual -CountVariable syncedCount |
            Select-Object $properties
    }
    catch {
        Write-Error "Failed to query Entra ID groups: $_"
        return
    }

    Write-Host "Found $($syncedGroups.Count) on-prem synced groups total." -ForegroundColor Green
    Write-Host "Classifying groups and cross-referencing AD..." -ForegroundColor Cyan

    $results = foreach ($g in $syncedGroups) {
        $isDynamic = $g.GroupTypes -contains 'DynamicMembership'
        $isM365    = $g.GroupTypes -contains 'Unified'

        $groupType = if ($isM365) { 'M365Group' }
            elseif ($isDynamic) { 'Dynamic' }
            elseif ($g.MailEnabled -and $g.SecurityEnabled) { 'MESG' }
            elseif ($g.MailEnabled -and -not $g.SecurityEnabled) { 'DistributionList' }
            elseif (-not $g.MailEnabled -and $g.SecurityEnabled) { 'SecurityGroup' }
            else { 'Unknown' }

        if ($groupType -notin $includeTypes) { continue }

        # AD lookup for scope and status (informational)
        $adScope = 'Unknown'
        $adExists = $false
        $adDN = $null
        $adError = $null

        if ($g.OnPremisesSecurityIdentifier) {
            try {
                $adGroup = Get-ADGroup -Identity $g.OnPremisesSecurityIdentifier `
                    -Properties GroupScope, DistinguishedName -ErrorAction Stop
                $adScope = $adGroup.GroupScope.ToString()
                $adExists = $true
                $adDN = $adGroup.DistinguishedName
            }
            catch {
                $adError = $_.Exception.Message
            }
        }

        $compatible = $true
        $reasons = @()

        if ($groupType -eq 'Dynamic')   { $compatible = $false; $reasons += 'Dynamic membership not supported' }
        if ($groupType -eq 'M365Group') { $compatible = $false; $reasons += 'M365 Groups not in scope for this tool' }
        if (-not $adExists)             { $compatible = $false; $reasons += "AD object not found ($adError)" }

        [PSCustomObject]@{
            DisplayName        = $g.DisplayName
            Mail               = $g.Mail
            GroupType          = $groupType
            ADScope            = $adScope
            ADDistinguishedName= $adDN
            Compatible         = $compatible
            Issues             = ($reasons -join '; ')
            EntraObjectId      = $g.Id
            OnPremSamAccount   = $g.OnPremisesSamAccountName
            OnPremSID          = $g.OnPremisesSecurityIdentifier
            Description        = $g.Description
        }
    }

    $compatibleCount   = ($results | Where-Object Compatible).Count
    $incompatibleCount = ($results | Where-Object { -not $_.Compatible }).Count

    Write-Host "`nResults:" -ForegroundColor Green
    Write-Host "  Compatible:   $compatibleCount"
    Write-Host "  Incompatible: $incompatibleCount"
    Write-Host "  Total:        $($results.Count)"

    if ($compatibleCount -eq 0) {
        Write-Warning "No compatible groups found. Exiting."
        return
    }
}

# ----- Show in Out-GridView for selection -----
Write-Host "`nLaunching selection UI - pick groups to convert, then click OK (or Cancel to abort)." -ForegroundColor Cyan
Write-Host "Only 'Compatible = True' groups will actually be converted; others will be skipped with a warning."

$selected = $results |
    Sort-Object Compatible -Descending |
    Out-GridView -Title "Select groups to convert SOA to cloud (Ctrl/Shift for multi-select)" -PassThru

if (-not $selected -or $selected.Count -eq 0) {
    Write-Host "No groups selected. Exiting." -ForegroundColor Yellow
    return
}

# Split selected into convertible vs not
$toConvert = @($selected | Where-Object Compatible)
$toSkip    = @($selected | Where-Object { -not $_.Compatible })

if ($toSkip.Count -gt 0) {
    Write-Warning "$($toSkip.Count) selected group(s) are not compatible and will be skipped:"
    $toSkip | ForEach-Object { Write-Host "  - $($_.DisplayName): $($_.Issues)" -ForegroundColor Yellow }
}

# Build skip audit rows up front so they're always logged, even if we exit early.
$skipAuditRows = foreach ($group in $toSkip) {
    [PSCustomObject]@{
        Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        DisplayName   = $group.DisplayName
        Mail          = $group.Mail
        GroupType     = $group.GroupType
        ADScope       = $group.ADScope
        EntraObjectId = $group.EntraObjectId
        OnPremSID     = $group.OnPremSID
        ADDN          = $group.ADDistinguishedName
        Status        = 'Skipped'
        Error         = $group.Issues
    }
}

if ($toConvert.Count -eq 0) {
    Write-Host "`nNo compatible groups remaining after filter. Writing skip log and exiting." -ForegroundColor Yellow
    if ($skipAuditRows) {
        $skipAuditRows | Export-Csv -Path $logFile -NoTypeInformation
        Write-Host "Audit log written to: $logFile" -ForegroundColor Green
    }
    return
}

# ----- Confirmation prompt -----
Write-Host "`n=== Ready to Convert ===" -ForegroundColor Cyan
Write-Host "The following $($toConvert.Count) group(s) will be converted to cloud-managed:`n"
$toConvert | Format-Table DisplayName, GroupType, ADScope, Mail -AutoSize

$confirm = Read-Host "Convert $($toConvert.Count) group(s)? [y/N]"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "Aborted by user. No changes made." -ForegroundColor Yellow
    if ($skipAuditRows) {
        $skipAuditRows | Export-Csv -Path $logFile -NoTypeInformation
        Write-Host "Skip-only audit log written to: $logFile" -ForegroundColor Green
    }
    return
}

# ----- Execute conversions -----
Write-Host "`nExecuting conversions..." -ForegroundColor Cyan
$convertAuditRows = foreach ($group in $toConvert) {
    $status = 'Unknown'
    $errorMsg = $null

    try {
        $uri = "https://graph.microsoft.com/v1.0/groups/$($group.EntraObjectId)/onPremisesSyncBehavior"
        $body = @{ isCloudManaged = $true } | ConvertTo-Json
        Invoke-MgGraphRequest -Uri $uri -Method PATCH -Body $body -ContentType "application/json" -ErrorAction Stop
        $status = 'Converted'
        Write-Host "  [OK]   $($group.DisplayName)" -ForegroundColor Green
    }
    catch {
        $status = 'Failed'
        $errorMsg = $_.Exception.Message
        Write-Host "  [FAIL] $($group.DisplayName): $errorMsg" -ForegroundColor Red
    }

    [PSCustomObject]@{
        Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        DisplayName   = $group.DisplayName
        Mail          = $group.Mail
        GroupType     = $group.GroupType
        ADScope       = $group.ADScope
        EntraObjectId = $group.EntraObjectId
        OnPremSID     = $group.OnPremSID
        ADDN          = $group.ADDistinguishedName
        Status        = $status
        Error         = $errorMsg
    }
}

# ----- Write log (converted + skipped) -----
# Guard against null rows: an empty foreach assigns $null, and in PS 7 @($null)
# produces a 1-element array containing null rather than an empty array, which
# makes Export-Csv complain mid-pipeline. Build the list defensively instead.
$auditResults = @()
if ($convertAuditRows) { $auditResults = @($convertAuditRows) }
if ($skipAuditRows)    { $auditResults += @($skipAuditRows) }

if ($auditResults.Count -gt 0) {
    $auditResults | Export-Csv -Path $logFile -NoTypeInformation
    Write-Host "`nAudit log written to: $logFile" -ForegroundColor Green
}
else {
    Write-Host "`nNo rows to log." -ForegroundColor Yellow
}

# ----- Summary -----
$successCount = ($auditResults | Where-Object Status -eq 'Converted').Count
$failCount    = ($auditResults | Where-Object Status -eq 'Failed').Count
$skipCount    = ($auditResults | Where-Object Status -eq 'Skipped').Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "  Converted: $successCount" -ForegroundColor Green
if ($failCount -gt 0) { Write-Host "  Failed:    $failCount" -ForegroundColor Red }
if ($skipCount -gt 0) { Write-Host "  Skipped:   $skipCount" -ForegroundColor Yellow }

if ($successCount -gt 0) {
    Write-Host "`nReminder: Run 'Start-ADSyncSyncCycle -PolicyType Delta' on the Entra Connect server" -ForegroundColor Cyan
    Write-Host "when convenient so Entra Connect stops syncing the converted group(s) from AD." -ForegroundColor Cyan
}
