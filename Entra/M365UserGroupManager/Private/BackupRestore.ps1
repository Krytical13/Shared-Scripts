<#
    Backup / restore (configuration snapshots).

    Backup writes the SELECTED object's configuration -- attributes + relationships
    (manager, members, owners, delegates, licenses) -- to a JSON file. This is a CONFIG snapshot,
    NOT a data backup: it does not capture mailbox contents (email/calendar/files), and passwords
    are write-only in Graph so they are never captured.

    Restore reads a snapshot and LOADS it into the form (it never writes on its own): in New mode it
    recreates / clones the object (you click Create); in Edit mode on a loaded object it reverts that
    object's config to the snapshot (you click Save). Restore overlays values WITHOUT resetting the
    dirty baseline, so Save sends only the real differences.
#>

$script:SnapshotSchemaVersion = 1

function Get-SnapshotStamp { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Get-SafeFileName {
    param([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [regex]::Escape($invalid)
    ($Name -replace $re, '_').Trim()
}

# ----------------------------------------------------------------- export (build snapshot)

function New-Snapshot {
    param([string]$Tab, [string]$ObjectType, [string]$DisplayName, [hashtable]$Fields, [hashtable]$People, [string[]]$Licenses)
    $tenant = ''
    $ctx = Get-GraphContextSafe; if ($ctx) { $tenant = [string]$ctx.TenantId }
    @{
        Tool          = 'M365UserGroupManager'
        SchemaVersion = $script:SnapshotSchemaVersion
        Tab           = $Tab
        ObjectType    = $ObjectType
        Tenant        = $tenant
        Timestamp     = (Get-SnapshotStamp)
        DisplayName   = $DisplayName
        Fields        = $Fields
        People        = $People
        Licenses      = @($Licenses)
    }
}

function Export-UserSnapshot {
    $u = $script:State.SelectedUser
    if (-not $u) { return $null }
    $id = [string](Get-GraphVal $u 'id')
    $ext = Get-GraphVal $u 'onPremisesExtensionAttributes'
    $fields = @{}; $people = @{}; $licenses = @()
    foreach ($a in (Get-CatalogAttributeList -Tab 'User')) {
        if (-not $a.Writable) { continue }
        switch ($a.Input) {
            'Person'   { $m = Get-UserManagerInfo -Id $id; if ($m) { $people[$a.Name] = $m } }
            'License'  { $licenses = @(Get-UserAssignedSkuId -User $u) }
            'Password' { }   # never captured
            'ExtAttr'  { $fields[$a.Name] = [string](Get-GraphVal $ext $a.Name) }
            'Bool'     { $fields[$a.Name] = [bool](Get-GraphVal $u $a.Name) }
            'Multi'    { $fields[$a.Name] = @(ConvertTo-StringList (Get-GraphVal $u $a.Name)) }
            'Date'     { $v = Get-GraphVal $u $a.Name; if ($v) { $fields[$a.Name] = ([datetime]$v).ToString('yyyy-MM-dd') } }
            default    { $fields[$a.Name] = [string](Get-GraphVal $u $a.Name) }
        }
    }
    New-Snapshot -Tab 'User' -ObjectType 'User' -DisplayName ([string](Get-GraphVal $u 'displayName')) -Fields $fields -People $people -Licenses $licenses
}

function Export-GroupSnapshot {
    $g = $script:State.SelectedGroup
    if (-not $g) { return $null }
    $id = [string](Get-GraphVal $g 'id')
    $type = if ((@(Get-GraphVal $g 'groupTypes')) -contains 'Unified') { 'Microsoft365' } else { 'Security' }
    $fields = @{}; $people = @{}
    foreach ($a in (Get-CatalogAttributeList -Tab 'Group')) {
        if (-not $a.Writable) { continue }
        switch ($a.Input) {
            'GroupType' { }   # captured as ObjectType
            'Person'    {
                $ppl = if ($a.Name -eq 'owners') { Get-GroupOwnerInfo -Id $id } else { Get-GroupMemberInfo -Id $id }
                $people[$a.Name] = $ppl
            }
            'Multi'     { $fields[$a.Name] = @(ConvertTo-StringList (Get-GraphVal $g $a.Name)) }
            'Bool'      { $fields[$a.Name] = [bool](Get-GraphVal $g $a.Name) }
            default     { $fields[$a.Name] = [string](Get-GraphVal $g $a.Name) }
        }
    }
    New-Snapshot -Tab 'Group' -ObjectType $type -DisplayName ([string](Get-GraphVal $g 'displayName')) -Fields $fields -People $people
}

function Export-ExchangeSnapshot {
    $o = $script:UI.Exchange.SelectedObject
    if (-not $o) { return $null }
    $type = (Get-ExoTypeDescriptor).Key
    $id = [string]$o.Identity
    $fields = @{}; $people = @{}
    foreach ($grp in $script:Catalog.Exchange.Groups) {
        foreach ($a in ($grp.Attributes | Where-Object { $_.Types -contains $type })) {
            if (-not $a.Writable) { continue }
            switch ($a.Name) {
                'members'      { $people['members']    = Get-ExoDistributionGroupMemberInfo -Id $id }
                'managedBy'    { $people['managedBy']  = Get-ExoDistributionGroupOwnerInfo  -Id $id }
                'fullAccess'   { $people['fullAccess'] = Get-ExoFullAccessInfo -Id $id }
                'sendAs'       { $people['sendAs']     = Get-ExoSendAsInfo -Id $id }
                'sendOnBehalf' { $people['sendOnBehalf'] = Resolve-ExoRecipientInfo -Identities $o.GrantSendOnBehalfTo }
                default        {
                    if ($a.Input -eq 'Bool') { $fields[$a.Name] = [bool](Get-GraphVal $o $a.Name) }
                    else { $fields[$a.Name] = [string](Get-GraphVal $o $a.Name) }
                }
            }
        }
    }
    New-Snapshot -Tab 'Exchange' -ObjectType $type -DisplayName ([string]$o.DisplayName) -Fields $fields -People $people
}

function Export-ObjectSnapshot {
    param([ValidateSet('User', 'Group', 'Exchange')][string]$Tab)
    switch ($Tab) {
        'User'     { Export-UserSnapshot }
        'Group'    { Export-GroupSnapshot }
        'Exchange' { Export-ExchangeSnapshot }
    }
}

# ----------------------------------------------------------------- file I/O

function Save-SnapshotFile {
    param([hashtable]$Snapshot)
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'M365 config backup (*.json)|*.json|All files (*.*)|*.*'
    $dlg.Title = 'Save configuration backup'
    $stamp = ([DateTime]::UtcNow).ToString('yyyyMMdd-HHmmss')
    $dlg.FileName = Get-SafeFileName "$($Snapshot.Tab)-$($Snapshot.DisplayName)-$stamp.json"
    if ($dlg.ShowDialog() -ne 'OK') { return $false }
    ($Snapshot | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $dlg.FileName -Encoding UTF8
    Set-Progress "Backup saved: $($dlg.FileName)"
    return $true
}

function Read-SnapshotFile {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'M365 config backup (*.json)|*.json|All files (*.*)|*.*'
    $dlg.Title = 'Open configuration backup'
    if ($dlg.ShowDialog() -ne 'OK') { return $null }
    try {
        return (Get-Content -LiteralPath $dlg.FileName -Raw | ConvertFrom-Json)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Could not read the backup file:`n$($_.Exception.Message)", 'Restore error', 'OK', 'Error') | Out-Null
        return $null
    }
}

# ----------------------------------------------------------------- restore (load into form)

function Get-SnapshotFieldNames {
    param($Snapshot)
    $names = @()
    if ($Snapshot.Fields)   { $names += @($Snapshot.Fields.PSObject.Properties.Name) }
    if ($Snapshot.People)   { $names += @($Snapshot.People.PSObject.Properties.Name) }
    if ($Snapshot.Licenses -and @($Snapshot.Licenses).Count -gt 0) { $names += 'assignedLicenses' }
    return @($names | Select-Object -Unique)
}

function Set-FieldFromSnapshot {
    <# Overlay snapshot values onto an already-built field map. Does NOT touch baselines. #>
    param([hashtable]$Fields, $Snapshot)
    if ($Snapshot.Fields) {
        foreach ($p in $Snapshot.Fields.PSObject.Properties) {
            $f = $Fields[$p.Name]
            if ($f -and $f.Kind -notin 'Person', 'License', 'GroupType', 'Password') { Set-FieldValue -Field $f -Value $p.Value }
        }
    }
    if ($Snapshot.People) {
        foreach ($p in $Snapshot.People.PSObject.Properties) {
            $f = $Fields[$p.Name]
            if ($f -and $f.Kind -eq 'Person') {
                $ppl = @($p.Value | ForEach-Object { @{ Id = [string]$_.Id; DisplayName = [string]$_.DisplayName; Detail = [string]$_.Detail } })
                Set-PersonFieldValue -Field $f -People $ppl
            }
        }
    }
    if ($Snapshot.Licenses -and $Fields['assignedLicenses'] -and (Test-GraphConnected)) {
        Set-LicenseFieldItems -Field $Fields['assignedLicenses'] -Skus (Get-AvailableSku) -AssignedSkuIds @($Snapshot.Licenses)
    }
}

function Restore-UserSnapshot {
    param($Snapshot)
    $ctx = $script:UI.User
    # Auto-enable the snapshot's fields (in-memory only) so they render and prefill.
    $script:Config.Users.Enabled = @(@($script:Config.Users.Enabled) + (Get-SnapshotFieldNames $Snapshot) | Select-Object -Unique)
    Build-TabForm -Tab 'User'
    if ($ctx.Mode -eq 'Edit' -and $script:State.SelectedUser) { Import-UserIntoForm -User $script:State.SelectedUser }
    Set-FieldFromSnapshot -Fields $ctx.Fields -Snapshot $Snapshot
}

function Restore-GroupSnapshot {
    param($Snapshot)
    $ctx = $script:UI.Group
    $script:Config.Groups.Enabled = @(@($script:Config.Groups.Enabled) + (Get-SnapshotFieldNames $Snapshot) | Select-Object -Unique)
    Build-TabForm -Tab 'Group'
    if ($ctx.Mode -eq 'Edit' -and $script:State.SelectedGroup) {
        Import-GroupIntoForm -Group $script:State.SelectedGroup
    } elseif ($ctx.Fields['__groupType']) {
        # New-mode clone: select the snapshot's kind and apply its reactive view explicitly (don't rely
        # on CheckedChanged firing -- it won't if the kind already matches the default radio).
        $kind = if ($Snapshot.ObjectType -in 'Microsoft365', 'Unified') { 'Microsoft365' } else { 'Security' }
        Set-GroupTypeField -Field $ctx.Fields['__groupType'] -Type $kind
        Set-GroupKindView -Kind $kind
    }
    Set-FieldFromSnapshot -Fields $ctx.Fields -Snapshot $Snapshot
}

function Restore-ExchangeSnapshot {
    param($Snapshot)
    if (-not (Test-ExoConnected)) {
        [System.Windows.Forms.MessageBox]::Show('Activate Exchange Online before restoring an Exchange backup.', 'Not connected', 'OK', 'Information') | Out-Null
        return
    }
    $ex = $script:UI.Exchange
    if ($ex.Mode -eq 'Edit' -and $ex.SelectedObject) {
        # Revert: object type is fixed; just overlay onto the loaded form.
        Set-FieldFromSnapshot -Fields $ex.Fields -Snapshot $Snapshot
    } else {
        # Recreate: select the snapshot's object type, rebuild, then overlay.
        $ex.ModeNew.Checked = $true
        for ($i = 0; $i -lt $ex.TypeCombo.Items.Count; $i++) {
            if ($ex.TypeCombo.Items[$i].Key -eq $Snapshot.ObjectType) { $ex.TypeCombo.SelectedIndex = $i; break }
        }
        Build-ExchangeForm
        Set-FieldFromSnapshot -Fields $ex.Fields -Snapshot $Snapshot
    }
}

function Import-SnapshotIntoForm {
    param($Snapshot)
    switch ($Snapshot.Tab) {
        'User'     { $script:UI.Tabs.SelectedTab = $script:UI.User.Page;  Restore-UserSnapshot $Snapshot }
        'Group'    { $script:UI.Tabs.SelectedTab = $script:UI.Group.Page; Restore-GroupSnapshot $Snapshot }
        'Exchange' { $script:UI.Tabs.SelectedTab = $script:UI.Exchange.Page; Restore-ExchangeSnapshot $Snapshot }
        default    { [System.Windows.Forms.MessageBox]::Show("Unknown backup tab: $($Snapshot.Tab)", 'Restore error', 'OK', 'Warning') | Out-Null }
    }
}

# ----------------------------------------------------------------- button handlers

function Invoke-Backup {
    param([ValidateSet('User', 'Group', 'Exchange')][string]$Tab)
    Set-UiBusy $true
    try {
        Set-Progress 'Building backup...'
        $snap = Export-ObjectSnapshot -Tab $Tab
        if (-not $snap) { [System.Windows.Forms.MessageBox]::Show('Select an existing object first (Edit mode).', 'Nothing to back up', 'OK', 'Information') | Out-Null; return }
        if (Save-SnapshotFile -Snapshot $snap) {
            [System.Windows.Forms.MessageBox]::Show("Saved a configuration backup of:`n$($snap.DisplayName)", 'Backup saved', 'OK', 'Information') | Out-Null
        }
    } catch {
        Set-Progress 'Backup failed.'
        [System.Windows.Forms.MessageBox]::Show("Backup failed:`n$($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

function Invoke-Restore {
    $snap = Read-SnapshotFile
    if (-not $snap) { return }
    if ($snap.Tool -ne 'M365UserGroupManager' -or -not $snap.Tab) {
        [System.Windows.Forms.MessageBox]::Show('This file is not a M365 User/Group Manager backup.', 'Restore error', 'OK', 'Warning') | Out-Null
        return
    }
    Set-UiBusy $true
    try {
        Import-SnapshotIntoForm -Snapshot $snap
        $mode = switch ($snap.Tab) { 'User' { $script:UI.User.Mode } 'Group' { $script:UI.Group.Mode } 'Exchange' { $script:UI.Exchange.Mode } }
        $verb = if ($mode -eq 'Edit') { 'revert (then Save)' } else { 'recreate (then Create)' }
        Set-Progress "Backup loaded into the $($snap.Tab) form. Review, then $verb."
    } catch {
        Set-Progress 'Restore failed.'
        [System.Windows.Forms.MessageBox]::Show("Restore failed:`n$($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}
