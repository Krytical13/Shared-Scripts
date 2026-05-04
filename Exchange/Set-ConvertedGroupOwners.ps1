#Requires -Version 5.1

<#
.SYNOPSIS
    Bulk-set the ManagedBy (owners) on cloud-managed distribution and
    mail-enabled security groups in Exchange Online - but ONLY on groups
    whose current owners are empty or all problematic. Groups with any
    valid owner are left alone.

.DESCRIPTION
    After you SOA-convert an on-prem-synced mail-enabled group, its legacy
    ManagedBy attribute often contains values that Exchange Online can't
    resolve as recipients - most commonly "Organization Management" or
    orphaned user references from AD. That leftover blocks normal admins
    from editing membership through EAC and PowerShell, because Exchange's
    manager check refuses to let anyone but a current (valid) manager
    modify the group.

    This script:
      1. Connects to Exchange Online.
      2. Validates that your proposed new owner resolves to a real
         recipient (user, MESG, mailbox, contact, etc.).
      3. Enumerates distribution groups and mail-enabled security groups
         where IsDirSynced = False (cloud-managed) - includes SOA-converted
         and born-in-cloud groups.
      4. Computes eligibility per group: a group is eligible for an owner
         reset only if its current ManagedBy is empty OR contains ONLY
         known-problematic entries (e.g., "Organization Management"). If
         any current owner looks legitimate, the group is ineligible and
         will not be touched.
      5. Shows an Out-GridView picker with an Eligible column. You pick
         which eligible groups to update.
      6. Confirms, then calls Set-DistributionGroup with
         -BypassSecurityGroupManagerCheck to set ManagedBy to the new
         owner.
      7. Writes a timestamped CSV audit log.

    Design intent: this script is for cleaning up groups whose ownership
    is broken or absent post-conversion. It deliberately will not
    overwrite a ManagedBy that has any legitimate-looking entry, to avoid
    accidentally wiping intentional owners. If you need to change
    ownership on a group that already has a valid owner, do that manually
    with Set-DistributionGroup; the manager check will pass because the
    current owner is valid.

    This script is pure Exchange Online PowerShell. It does not touch
    Microsoft Graph or on-prem AD.

.PARAMETER NewOwner
    Identity of the new owner to set: a UPN, primary SMTP address, display
    name, or other recipient identifier that Get-Recipient can resolve.
    Must be one of the recipient types Exchange allows for ManagedBy:
    UserMailbox, MailUser, MailContact, User, UniversalSecurityGroup,
    MailUniversalSecurityGroup, or similar (see Set-DistributionGroup docs).

.PARAMETER LogPath
    Folder to write the CSV audit log. Default:
    $env:USERPROFILE\Documents\SOAConversion

.EXAMPLE
    .\Set-ConvertedGroupOwners.ps1 -NewOwner 'GroupOwners@contoso.com'

    Connect to EXO, show a picker of cloud-managed DLs/MESGs with
    eligibility computed per group, and set ManagedBy on selected
    eligible groups to the GroupOwners distribution group.

.EXAMPLE
    .\Set-ConvertedGroupOwners.ps1 -NewOwner 'admins@contoso.com' -LogPath D:\Audit

    Custom log folder.

.INPUTS
    None.

.OUTPUTS
    Writes a timestamped CSV audit log to $LogPath. Console shows per-group
    OK / FAIL / Skipped as it runs, plus a final summary.

.NOTES
    Version:     2.1
    Author:      Brandon
    Released:    2026-04-24
    Tested on:   Windows PowerShell 5.1 and PowerShell 7.x with
                 ExchangeOnlineManagement 3.x.

    WRITE OPERATIONS:
        This script MODIFIES the ManagedBy attribute on Exchange
        distribution groups that pass the eligibility check. Groups
        that already have a valid owner are skipped unconditionally
        to prevent accidental wipes.

    REQUIRED PERMISSIONS:
        Exchange role that allows Set-DistributionGroup on recipient write
        scope for the target groups. Exchange Administrator (Entra role)
        or Organization Management (Exchange role group) covers this.
        The script uses -BypassSecurityGroupManagerCheck, which lets you
        modify a group even when its current ManagedBy doesn't list you -
        but you still need the base RBAC permission to run the cmdlet.

    ELIGIBILITY RULES:
        A group is ELIGIBLE for owner reset if:
          - Its ManagedBy is empty, OR
          - Every entry in its ManagedBy matches a known-problematic
            pattern (Organization Management, Exchange Recipient
            Administrators, Exchange Organization Administrators,
            Exchange Trusted Subsystem, etc.).
        Any group with at least one unrecognized (presumed legitimate)
        owner is INELIGIBLE and will be skipped.

    KNOWN PROBLEMATIC OWNER PATTERNS:
        The script treats these ManagedBy values as invalid, based on
        real post-SOA-conversion experience:
          - Organization Management
          - Exchange Recipient Administrators
          - Exchange Organization Administrators
          - Exchange Trusted Subsystem
        If your environment has other legacy patterns that need to be
        considered problematic, edit the $invalidOwnerHints array inline.

    PAIRS WITH:
        Convert-GroupSOA.ps1 - the tool that converted the groups in the
        first place. Run this script after each conversion wave to clean
        up broken or legacy-only ManagedBy so your IT team can manage the
        groups in EAC without bypass flags.

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
        Not affiliated with or endorsed by Microsoft. The eligibility
        heuristic treats any unfamiliar ManagedBy value as legitimate.
        If you have legitimate owners that happen to match a problematic
        pattern (unlikely but possible), edit $invalidOwnerHints before
        running.

    AI ASSISTANCE:
        Portions of this script were drafted with AI assistance, then
        reviewed and tested by the author. You are responsible for
        understanding and testing any code before running it in your
        environment.

    TROUBLESHOOTING:
      - "Couldn't find object" on Set-DistributionGroup: usually means the
        new owner identity doesn't resolve. Try a primary SMTP address or
        UPN instead of a display name.

      - Group you expected to update shows Eligible = False: it has a
        ManagedBy entry the script considers legitimate. If that entry is
        actually bad, add its pattern to $invalidOwnerHints. Otherwise,
        the group has a real owner already and doesn't need this script.

      - Out-GridView missing on PowerShell 7: install the cross-platform
        port via Install-Module Microsoft.PowerShell.GraphicalTools
        -Scope CurrentUser

      - "The current operation is not supported on GroupMailbox" on a
        Set/Get-DistributionGroup call: you have two objects sharing a
        display name - a MESG/DL and a separate Microsoft 365 Group
        (GroupMailbox). The script now targets groups by
        ExternalDirectoryObjectId to avoid this collision. If you see it
        again, run:
          Get-Recipient -Identity '<name>' |
            Select DisplayName, RecipientTypeDetails, ExternalDirectoryObjectId, PrimarySmtpAddress
        to confirm the duplicate, then operate on the correct GUID directly.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$NewOwner,

    [string]$LogPath = "$env:USERPROFILE\Documents\SOAConversion"
)

# Known-problematic ManagedBy patterns. If every ManagedBy entry matches one
# of these, the group is eligible for owner reset. If any entry does NOT
# match any of these, the group is left alone.
$invalidOwnerHints = @(
    '*Organization Management*',
    '*Exchange Recipient Administrators*',
    '*Exchange Organization Administrators*',
    '*Exchange Trusted Subsystem*'
)

function Test-IsInvalidOwnerEntry {
    param([string]$Entry, [string[]]$Hints)
    foreach ($hint in $Hints) {
        if ($Entry -like $hint) { return $true }
    }
    return $false
}

function Test-GroupEligibleForOwnerReset {
    param($ManagedBy, [string[]]$Hints)
    # Empty or null ManagedBy: eligible (nothing to protect)
    if (-not $ManagedBy -or @($ManagedBy).Count -eq 0) { return $true }
    # If ANY entry is not in the invalid list, treat as legitimate owner -> ineligible
    foreach ($entry in $ManagedBy) {
        if (-not (Test-IsInvalidOwnerEntry -Entry "$entry" -Hints $Hints)) {
            return $false
        }
    }
    # All entries matched invalid patterns: eligible
    return $true
}

# ----- Module check: prompt to install if missing -----
if (-not (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement')) {
    Write-Host ""
    Write-Host "ExchangeOnlineManagement module is not installed." -ForegroundColor Yellow
    $answer = Read-Host "Install it now for the current user? [Y/n]"
    if ($answer -match '^[Nn]') {
        Write-Error "Required module missing. Exiting."
        return
    }
    try {
        Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "Installed ExchangeOnlineManagement." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install ExchangeOnlineManagement: $($_.Exception.Message)"
        return
    }
}

Import-Module ExchangeOnlineManagement -ErrorAction Stop

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
$logFile = Join-Path $LogPath "SetConvertedGroupOwners-$timestamp.csv"

Write-Host "`n=== Bulk Set Converted Group Owners ===" -ForegroundColor Cyan

# ----- Connect to Exchange Online -----
$existing = Get-ConnectionInformation -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq 'Connected' -and $_.TokenStatus -eq 'Active' } |
    Select-Object -First 1

if (-not $existing) {
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to connect to Exchange Online: $_"
        return
    }
}
else {
    Write-Host "Using existing Exchange Online connection ($($existing.UserPrincipalName))." -ForegroundColor Green
}

# ----- Validate the proposed new owner resolves to a real recipient -----
Write-Host "Validating new owner: $NewOwner" -ForegroundColor Cyan
try {
    $ownerRecipient = Get-Recipient -Identity $NewOwner -ErrorAction Stop
    Write-Host "  Resolves to: $($ownerRecipient.DisplayName) [$($ownerRecipient.RecipientTypeDetails)]" -ForegroundColor Green
    Write-Host "  Primary SMTP: $($ownerRecipient.PrimarySmtpAddress)" -ForegroundColor Gray
}
catch {
    Write-Error "Cannot resolve '$NewOwner' as a recipient: $($_.Exception.Message)"
    Write-Host "Hint: try the primary SMTP address or UPN rather than a display name." -ForegroundColor Yellow
    return
}

$validOwnerTypes = @(
    'UserMailbox', 'LegacyMailbox', 'SharedMailbox', 'TeamMailbox',
    'MailUser', 'LinkedMailbox', 'RemoteUserMailbox', 'RemoteSharedMailbox',
    'RemoteTeamMailbox', 'MailContact', 'User', 'UniversalSecurityGroup',
    'MailUniversalSecurityGroup', 'RoomMailbox'
)
if ($ownerRecipient.RecipientTypeDetails -notin $validOwnerTypes) {
    Write-Error "The specified owner type '$($ownerRecipient.RecipientTypeDetails)' is not permitted by Exchange as a ManagedBy target."
    Write-Host "Allowed types: $($validOwnerTypes -join ', ')" -ForegroundColor Yellow
    return
}

# ----- Enumerate cloud-managed distribution / mail-enabled security groups -----
Write-Host "`nEnumerating cloud-managed distribution groups (this can take a minute on large tenants)..." -ForegroundColor Cyan
try {
    $allGroups = Get-DistributionGroup -ResultSize Unlimited -ErrorAction Stop
}
catch {
    Write-Error "Failed to enumerate distribution groups: $_"
    return
}

$cloudManaged = @($allGroups | Where-Object { -not $_.IsDirSynced })
Write-Host "  $($cloudManaged.Count) cloud-managed group(s) found (IsDirSynced = False)." -ForegroundColor Green

if ($cloudManaged.Count -eq 0) {
    Write-Warning "No cloud-managed distribution groups found. Exiting."
    return
}

# ----- Build rows with eligibility -----
$rows = foreach ($g in $cloudManaged) {
    $currentManagedBy = @($g.ManagedBy)
    $eligible = Test-GroupEligibleForOwnerReset -ManagedBy $currentManagedBy -Hints $invalidOwnerHints

    [PSCustomObject]@{
        DisplayName               = $g.DisplayName
        PrimarySmtpAddress        = $g.PrimarySmtpAddress
        Type                      = $g.RecipientTypeDetails
        OwnerCount                = $currentManagedBy.Count
        Eligible                  = $eligible
        CurrentManagedBy          = $currentManagedBy -join '; '
        Identity                  = $g.Identity
        ExternalDirectoryObjectId = $g.ExternalDirectoryObjectId
    }
}

$eligibleCount   = @($rows | Where-Object Eligible).Count
$ineligibleCount = @($rows | Where-Object { -not $_.Eligible }).Count

Write-Host "  Eligible for owner reset:   $eligibleCount" -ForegroundColor Green
Write-Host "  Ineligible (has valid owner): $ineligibleCount"

if ($eligibleCount -eq 0) {
    Write-Warning "No eligible groups found. Every cloud-managed group already has a legitimate-looking owner. Exiting."
    return
}

# ----- Show eligible groups in Out-GridView for selection -----
Write-Host "`nLaunching selection UI with only eligible groups (empty or all-invalid ManagedBy)." -ForegroundColor Cyan
Write-Host "Select the groups you want to update, then click OK (Cancel to abort)."

$selectable = $rows | Where-Object Eligible | Sort-Object DisplayName
$selected = $selectable | Out-GridView -Title "Select eligible groups to set ManagedBy -> $NewOwner (Ctrl/Shift for multi-select)" -PassThru

if (-not $selected -or $selected.Count -eq 0) {
    Write-Host "No groups selected. Exiting." -ForegroundColor Yellow
    return
}

# ----- Confirmation prompt -----
Write-Host "`n=== Ready to Update ===" -ForegroundColor Cyan
Write-Host "  New owner:   $NewOwner ($($ownerRecipient.DisplayName))"
Write-Host "  Group count: $($selected.Count)"
Write-Host ""
$selected | Format-Table DisplayName, Type, OwnerCount, CurrentManagedBy -AutoSize

$confirm = Read-Host "Proceed with ManagedBy update on $($selected.Count) group(s)? [y/N]"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "Aborted by user. No changes made." -ForegroundColor Yellow
    return
}

# ----- Apply updates (re-check eligibility as a safety net) -----
Write-Host "`nApplying changes..." -ForegroundColor Cyan
$auditRows = foreach ($row in $selected) {
    $status   = 'Unknown'
    $errorMsg = $null

    # Prefer the Entra object GUID for targeting. It's globally unique and
    # avoids display-name collisions where the same name exists on both a
    # MESG/DL and a separate Microsoft 365 Group (which EXO reports as
    # GroupMailbox and which breaks Get/Set-DistributionGroup).
    $targetId = if ($row.ExternalDirectoryObjectId) { $row.ExternalDirectoryObjectId } else { $row.Identity }

    try {
        # Re-fetch and re-check eligibility at apply time. If something changed
        # between the picker and now, skip rather than overwrite a valid owner.
        $live = Get-DistributionGroup -Identity $targetId -ErrorAction Stop
        $liveManagedBy = @($live.ManagedBy)

        if (-not (Test-GroupEligibleForOwnerReset -ManagedBy $liveManagedBy -Hints $invalidOwnerHints)) {
            $status = 'Skipped'
            $errorMsg = 'No longer eligible at apply time (current ManagedBy contains a non-problematic entry).'
            Write-Host "  [SKIP] $($row.DisplayName): $errorMsg" -ForegroundColor Yellow
        }
        else {
            Set-DistributionGroup -Identity $targetId -ManagedBy $NewOwner -BypassSecurityGroupManagerCheck -ErrorAction Stop
            $status = 'Updated'
            Write-Host "  [OK]   $($row.DisplayName)" -ForegroundColor Green
        }
    }
    catch {
        $status = 'Failed'
        $errorMsg = $_.Exception.Message
        Write-Host "  [FAIL] $($row.DisplayName): $errorMsg" -ForegroundColor Red
    }

    [PSCustomObject]@{
        Timestamp          = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        DisplayName        = $row.DisplayName
        PrimarySmtpAddress = $row.PrimarySmtpAddress
        Type               = $row.Type
        OldManagedBy       = $row.CurrentManagedBy
        NewManagedBy       = if ($status -eq 'Updated') { $NewOwner } else { $null }
        Status             = $status
        Error              = $errorMsg
    }
}

# ----- Write log -----
$cleanAudit = @($auditRows | Where-Object { $_ })
if ($cleanAudit.Count -gt 0) {
    $cleanAudit | Export-Csv -Path $logFile -NoTypeInformation
    Write-Host "`nAudit log written to: $logFile" -ForegroundColor Green
}

# ----- Summary -----
$successCount = ($cleanAudit | Where-Object Status -eq 'Updated').Count
$failCount    = ($cleanAudit | Where-Object Status -eq 'Failed').Count
$skipCount    = ($cleanAudit | Where-Object Status -eq 'Skipped').Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "  Updated: $successCount" -ForegroundColor Green
if ($skipCount -gt 0) { Write-Host "  Skipped: $skipCount" -ForegroundColor Yellow }
if ($failCount -gt 0) {
    Write-Host "  Failed:  $failCount" -ForegroundColor Red
    Write-Host "`nFailures above usually mean the new owner isn't a valid recipient type," -ForegroundColor Yellow
    Write-Host "or EXO rejected the update for another reason. Review the audit log." -ForegroundColor Yellow
}
