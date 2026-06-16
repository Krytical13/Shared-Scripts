<#
    Exchange tab (gated behind an Exchange Online sign-in).

    Until Exchange is activated, the tab shows a calm empty-state call-to-action instead of a
    surprise login. Once activated it reveals an object-type selector (distribution list /
    mail-enabled security group / shared / room / equipment mailbox) and the same New/Edit
    dynamic form used elsewhere, with members/owners (DL/MESG) or Full Access / Send As /
    Send on Behalf delegates (mailboxes).

    State: $script:UI.Exchange. Person pickers here search Exchange recipients (PickerSource on
    the catalog attributes), so the tab works without a Graph connection.
#>

#region ---------------------------------------------------------------------- Construction

function New-ExchangeTab {
    $t = Get-Theme

    # Content page hosted in the main form's page area (was a TabPage; now a Dock=Fill Panel).
    $page = New-Object System.Windows.Forms.Panel
    $page.Dock = 'Fill'; $page.BackColor = $t.Surface; $page.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)

    # --- Activation (empty state) panel ----------------------------------------------------
    $act = New-Object System.Windows.Forms.TableLayoutPanel
    $act.Dock = 'Fill'; $act.ColumnCount = 1; $act.RowCount = 3
    [void]$act.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 38)))
    [void]$act.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$act.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 62)))

    $content = New-Object System.Windows.Forms.FlowLayoutPanel
    $content.FlowDirection = 'TopDown'; $content.WrapContents = $false; $content.AutoSize = $true
    $content.AutoSizeMode = 'GrowAndShrink'; $content.Anchor = 'None'
    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'Exchange Online'; $title.Font = $t.FontLarge; $title.ForeColor = $t.Header; $title.AutoSize = $true
    $title.Margin = New-Object System.Windows.Forms.Padding(3, 3, 3, 6)
    $explain = New-Object System.Windows.Forms.Label
    $explain.Text = "Distribution lists, mail-enabled security groups, and shared, room, and equipment mailboxes are managed through Exchange Online -- a separate sign-in from Microsoft Graph."
    $explain.AutoSize = $true; $explain.MaximumSize = New-Object System.Drawing.Size(440, 0); $explain.ForeColor = $t.Muted
    $explain.Margin = New-Object System.Windows.Forms.Padding(3, 0, 3, 14)
    $connectExo = New-Object System.Windows.Forms.Button
    $connectExo.Text = 'Connect to Exchange Online'; $connectExo.Width = 240; $connectExo.Height = 38; $connectExo.Font = $t.FontMedium
    Set-PrimaryButtonStyle $connectExo
    $content.Controls.AddRange(@($title, $explain, $connectExo))
    $act.Controls.Add($content, 0, 1)
    $page.Controls.Add($act)

    # --- Management panel ------------------------------------------------------------------
    $manage = New-Object System.Windows.Forms.TableLayoutPanel
    $manage.Dock = 'Fill'; $manage.ColumnCount = 1; $manage.RowCount = 4; $manage.Visible = $false
    [void]$manage.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))   # exo status
    [void]$manage.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 44)))   # header
    [void]$manage.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))   # form
    [void]$manage.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 50)))   # actions

    # Row 0: Exchange connection status + disconnect.
    $statusBar = New-Object System.Windows.Forms.FlowLayoutPanel
    $statusBar.Dock = 'Fill'; $statusBar.FlowDirection = 'LeftToRight'; $statusBar.WrapContents = $false
    $exoLabel = New-Object System.Windows.Forms.Label
    $exoLabel.AutoSize = $true; $exoLabel.Font = $t.FontMedium; $exoLabel.ForeColor = $t.OkText; $exoLabel.BackColor = $t.OkBack
    $exoLabel.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4); $exoLabel.TextAlign = 'MiddleLeft'
    $exoLabel.Margin = New-Object System.Windows.Forms.Padding(3, 3, 8, 3)
    $exoDisconnect = New-Object System.Windows.Forms.Button
    $exoDisconnect.Text = 'Disconnect Exchange'; $exoDisconnect.Width = 150; $exoDisconnect.Height = 26; $exoDisconnect.Margin = New-Object System.Windows.Forms.Padding(3, 3, 3, 3)
    Set-SecondaryButtonStyle $exoDisconnect
    $statusBar.Controls.AddRange(@($exoLabel, $exoDisconnect))
    $manage.Controls.Add($statusBar, 0, 0)

    # Row 1: type selector + mode + select-existing + target label.
    $header = New-Object System.Windows.Forms.FlowLayoutPanel
    $header.Dock = 'Fill'; $header.FlowDirection = 'LeftToRight'; $header.WrapContents = $false
    $typeLbl = New-Object System.Windows.Forms.Label; $typeLbl.Text = 'Type:'; $typeLbl.AutoSize = $true; $typeLbl.Font = $t.FontMedium; $typeLbl.Margin = New-Object System.Windows.Forms.Padding(3, 10, 4, 3)
    $typeCombo = New-Object System.Windows.Forms.ComboBox; $typeCombo.DropDownStyle = 'DropDownList'; $typeCombo.Width = 210; $typeCombo.Margin = New-Object System.Windows.Forms.Padding(3, 6, 14, 3)
    foreach ($ty in $script:Catalog.Exchange.Types) { [void]$typeCombo.Items.Add([pscustomobject]@{ Label = $ty.Label; Key = $ty.Key }) }
    $typeCombo.DisplayMember = 'Label'; $typeCombo.SelectedIndex = 0
    $modeNew = New-Object System.Windows.Forms.RadioButton; $modeNew.Text = '&New'; $modeNew.AutoSize = $true; $modeNew.Checked = $true; $modeNew.Margin = New-Object System.Windows.Forms.Padding(3, 10, 8, 3)
    $modeEdit = New-Object System.Windows.Forms.RadioButton; $modeEdit.Text = '&Edit existing'; $modeEdit.AutoSize = $true; $modeEdit.Margin = New-Object System.Windows.Forms.Padding(3, 10, 10, 3)
    $selectBtn = New-Object System.Windows.Forms.Button; $selectBtn.Text = '&Select...'; $selectBtn.Width = 90; $selectBtn.Height = 26; $selectBtn.Visible = $false; $selectBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 3)
    Set-SecondaryButtonStyle $selectBtn
    $targetLabel = New-Object System.Windows.Forms.Label; $targetLabel.AutoSize = $true; $targetLabel.ForeColor = $t.Muted; $targetLabel.Margin = New-Object System.Windows.Forms.Padding(3, 11, 3, 3); $targetLabel.Visible = $false
    $header.Controls.AddRange(@($typeLbl, $typeCombo, $modeNew, $modeEdit, $selectBtn, $targetLabel))
    $manage.Controls.Add($header, 0, 1)

    # Row 2: scrollable form host.
    $scroll = New-Object System.Windows.Forms.Panel; $scroll.Dock = 'Fill'; $scroll.AutoScroll = $true
    $formTlp = New-Object System.Windows.Forms.TableLayoutPanel
    $formTlp.ColumnCount = 2; $formTlp.AutoSize = $true; $formTlp.AutoSizeMode = 'GrowAndShrink'; $formTlp.Dock = 'Top'; $formTlp.GrowStyle = 'AddRows'
    $formTlp.Padding = New-Object System.Windows.Forms.Padding(4, 6, 18, 6)
    [void]$formTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$formTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $scroll.Controls.Add($formTlp)
    $manage.Controls.Add($scroll, 0, 2)

    # Row 3: actions.
    $actions = New-Object System.Windows.Forms.TableLayoutPanel
    $actions.Dock = 'Fill'; $actions.ColumnCount = 2; $actions.RowCount = 1
    [void]$actions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$actions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $leftActions = New-Object System.Windows.Forms.FlowLayoutPanel; $leftActions.Dock = 'Fill'; $leftActions.FlowDirection = 'LeftToRight'; $leftActions.WrapContents = $false
    $saveBtn = New-Object System.Windows.Forms.Button; $saveBtn.Text = '&Create'; $saveBtn.Width = 150; $saveBtn.Height = 34; $saveBtn.Font = $t.FontMedium; $saveBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 6)
    Set-PrimaryButtonStyle $saveBtn
    $resetBtn = New-Object System.Windows.Forms.Button; $resetBtn.Text = '&Reset'; $resetBtn.Width = 84; $resetBtn.Height = 34; $resetBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 6)
    Set-SecondaryButtonStyle $resetBtn
    $backupBtn = New-Object System.Windows.Forms.Button; $backupBtn.Text = '&Backup...'; $backupBtn.Width = 90; $backupBtn.Height = 34; $backupBtn.Margin = New-Object System.Windows.Forms.Padding(16, 6, 3, 6); $backupBtn.Enabled = $false
    $restoreBtn = New-Object System.Windows.Forms.Button; $restoreBtn.Text = 'Res&tore...'; $restoreBtn.Width = 90; $restoreBtn.Height = 34; $restoreBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 6)
    Set-SecondaryButtonStyle $backupBtn; Set-SecondaryButtonStyle $restoreBtn
    $leftActions.Controls.AddRange(@($saveBtn, $resetBtn, $backupBtn, $restoreBtn))
    $rightActions = New-Object System.Windows.Forms.FlowLayoutPanel; $rightActions.Dock = 'Fill'; $rightActions.FlowDirection = 'RightToLeft'; $rightActions.WrapContents = $false
    $deleteBtn = New-Object System.Windows.Forms.Button; $deleteBtn.Text = '&Delete'; $deleteBtn.Width = 130; $deleteBtn.Height = 34; $deleteBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 6); $deleteBtn.Visible = $false
    Set-SecondaryButtonStyle $deleteBtn; $deleteBtn.ForeColor = $t.ErrText
    $rightActions.Controls.Add($deleteBtn)
    $actions.Controls.Add($leftActions, 0, 0); $actions.Controls.Add($rightActions, 1, 0)
    $manage.Controls.Add($actions, 0, 3)

    $page.Controls.Add($manage)

    $script:UI.Exchange = @{
        Page = $page; ActivationPanel = $act; ManagePanel = $manage
        ConnectBtn = $connectExo; DisconnectBtn = $exoDisconnect; StatusLabel = $exoLabel
        TypeCombo = $typeCombo; ModeNew = $modeNew; ModeEdit = $modeEdit; SelectBtn = $selectBtn; TargetLabel = $targetLabel
        ScrollHost = $scroll; FormTlp = $formTlp
        Fields = @{}; Order = (New-Object System.Collections.Generic.List[object])
        SaveBtn = $saveBtn; ResetBtn = $resetBtn; DeleteBtn = $deleteBtn
        BackupBtn = $backupBtn; RestoreBtn = $restoreBtn
        Mode = 'New'; SelectedObject = $null
    }

    # --- Events ----------------------------------------------------------------------------
    $connectExo.Add_Click({ Invoke-ExoConnect })
    $exoDisconnect.Add_Click({ Invoke-ExoDisconnect })
    $typeCombo.Add_SelectedIndexChanged({ if ($script:AppReady) { $script:UI.Exchange.ModeNew.Checked = $true; Set-ExchangeMode -Mode 'New' } })
    $modeNew.Add_CheckedChanged({ param($s, $e) if ($s.Checked) { Set-ExchangeMode -Mode 'New' } })
    $modeEdit.Add_CheckedChanged({ param($s, $e) if ($s.Checked) { Set-ExchangeMode -Mode 'Edit' } })
    $selectBtn.Add_Click({ Invoke-ExoSelectExisting })
    $saveBtn.Add_Click({ Invoke-ExoSave })
    $resetBtn.Add_Click({ Set-ExchangeMode -Mode $script:UI.Exchange.Mode })
    $deleteBtn.Add_Click({ Invoke-ExoDelete })
    $backupBtn.Add_Click({ Invoke-Backup -Tab 'Exchange' })
    $restoreBtn.Add_Click({ Invoke-Restore })

    return $page
}

#endregion

#region ---------------------------------------------------------------------- Activation

function Update-ExchangeActivation {
    <# Show the management panel iff Exchange is connected, else the activation empty-state. #>
    if (-not $script:UI.Exchange) { return }
    $ex = $script:UI.Exchange
    $connected = Test-ExoConnected
    $ex.ManagePanel.Visible = $connected
    $ex.ActivationPanel.Visible = -not $connected
    if ($connected) {
        $ex.ManagePanel.BringToFront()
        $info = Get-ExoConnectionInfo
        $ex.StatusLabel.Text = "Exchange Online: $(Get-ExoTenantHint -Info $info)"
    } else {
        $ex.ActivationPanel.BringToFront()
    }
}

function Invoke-ExoConnect {
    Set-UiBusy $true
    try {
        Connect-Exo | Out-Null
        Update-ExchangeActivation
        if (Test-ExoConnected) {
            Build-ExchangeForm
            Set-Progress 'Exchange Online connected.'
        }
    } catch {
        Set-Progress 'Exchange connection failed.'
        [System.Windows.Forms.MessageBox]::Show("Could not connect to Exchange Online:`n$($_.Exception.Message)", 'Exchange connection error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

function Invoke-ExoDisconnect {
    Disconnect-ExoSafe
    $script:UI.Exchange.SelectedObject = $null
    Update-ExchangeActivation
    Set-Progress 'Exchange Online disconnected.'
}

#endregion

#region ---------------------------------------------------------------------- Form

function Get-ExoTypeDescriptor {
    <# The full catalog Type descriptor for the selected combo item. #>
    $sel = $script:UI.Exchange.TypeCombo.SelectedItem
    if (-not $sel) { return $script:Catalog.Exchange.Types[0] }
    foreach ($ty in $script:Catalog.Exchange.Types) { if ($ty.Key -eq $sel.Key) { return $ty } }
    return $script:Catalog.Exchange.Types[0]
}

function Get-ExoRecipientTypeDetail {
    <# RecipientTypeDetails string used to filter the picker / validate a selection, per type. #>
    param([string]$Key)
    switch ($Key) {
        'Distribution' { 'MailUniversalDistributionGroup' }
        'MailSecurity' { 'MailUniversalSecurityGroup' }
        'Shared'       { 'SharedMailbox' }
        'Room'         { 'RoomMailbox' }
        'Equipment'    { 'EquipmentMailbox' }
        default        { '' }
    }
}

function Build-ExchangeForm {
    <# Build the dynamic fields for the selected object type, grouped under section headers. #>
    $ex = $script:UI.Exchange
    $tlp = $ex.FormTlp
    $t = Get-Theme
    $typeKey = (Get-ExoTypeDescriptor).Key

    $tlp.SuspendLayout()
    try {
    $tlp.Controls.Clear()
    $tlp.RowStyles.Clear()
    $ex.Fields = @{}
    $ex.Order = New-Object System.Collections.Generic.List[object]

    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($group in $script:Catalog.Exchange.Groups) {
        # Show every applicable attribute (incl. ReadOnly) so what you select is what you see.
        $attrs = @($group.Attributes | Where-Object { $_.Types -contains $typeKey })
        if ($attrs.Count -eq 0) { continue }
        [void]$plan.Add(@{ Header = $group.Name })
        foreach ($a in $attrs) { [void]$plan.Add(@{ Attr = $a }) }
    }

    $tlp.RowCount = [Math]::Max($plan.Count, 1)
    for ($i = 0; $i -lt $plan.Count; $i++) {
        [void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    }

    $row = 0; $firstHeader = $true
    foreach ($item in $plan) {
        if ($item.Header) {
            $hdr = New-Object System.Windows.Forms.Label
            $hdr.Text = $item.Header; $hdr.UseMnemonic = $false; $hdr.AutoSize = $true
            $hdr.Font = $t.FontSection; $hdr.ForeColor = $t.Header
            $hdr.Margin = New-Object System.Windows.Forms.Padding(3, $(if ($firstHeader) { 2 } else { 16 }), 3, 4)
            $tlp.Controls.Add($hdr, 0, $row); $tlp.SetColumnSpan($hdr, 2); $firstHeader = $false
        } else {
            $field = New-FieldRow -Attr $item.Attr -Mode $ex.Mode -Tooltip $script:UI.Tooltip
            $tlp.Controls.Add($field.Label, 0, $row)
            $tlp.Controls.Add($field.Cell, 1, $row)
            $ex.Fields[$item.Attr.Name] = $field
            [void]$ex.Order.Add($field)
        }
        $row++
    }

    # New-mode default: groups reject external senders unless told otherwise.
    if ($ex.Mode -eq 'New' -and $ex.Fields.ContainsKey('requireSenderAuthenticationEnabled')) {
        $ex.Fields['requireSenderAuthenticationEnabled'].Main.Checked = $true
    }

    } finally {
        $tlp.ResumeLayout()
    }
    Set-ControlTheme -Root $tlp   # dark-theme the freshly (re)built Exchange field controls
    $ex.SaveBtn.Text = if ($ex.Mode -eq 'New') { '&Create' } else { '&Save changes' }
    Set-ExchangeActionState
}

function Set-ExchangeMode {
    param([ValidateSet('New', 'Edit')][string]$Mode)
    $ex = $script:UI.Exchange
    $ex.Mode = $Mode
    $ex.SelectBtn.Visible = ($Mode -eq 'Edit')
    $ex.TargetLabel.Visible = ($Mode -eq 'Edit')
    $ex.DeleteBtn.Visible = ($Mode -eq 'Edit')
    $ex.TargetLabel.Text = ''
    $ex.SelectedObject = $null
    $script:UI.ErrorProvider.Clear()
    Build-ExchangeForm
}

function Set-ExchangeActionState {
    $ex = $script:UI.Exchange
    $loaded = [bool]$ex.SelectedObject
    $ex.SaveBtn.Enabled = (Test-ExoConnected) -and ($ex.Mode -eq 'New' -or $loaded)
    $ex.DeleteBtn.Enabled = (Test-ExoConnected) -and $loaded
    if ($ex.BackupBtn) { $ex.BackupBtn.Enabled = $loaded }
}

#endregion

#region ---------------------------------------------------------------------- Edit: load existing

function Invoke-ExoSelectExisting {
    if (-not (Test-ExoConnected)) { return }
    $type = Get-ExoTypeDescriptor
    $picked = Show-PersonPicker -Source 'Exchange'
    if (-not $picked) { return }
    $id = $picked[0].Id

    Set-UiBusy $true
    try {
        Set-Progress 'Loading...'
        if ($type.Backend -eq 'DistributionGroup') {
            $obj = Get-ExoDistributionGroup -Id $id
        } else {
            $obj = Get-ExoMailbox -Id $id
        }
        Build-ExchangeForm
        Import-ExoIntoForm -Object $obj -Type $type
    } catch {
        Set-Progress 'Load failed.'
        [System.Windows.Forms.MessageBox]::Show("Could not load the selected object:`n$($_.Exception.Message)", 'Load error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

function Import-ExoIntoForm {
    param($Object, $Type)
    $ex = $script:UI.Exchange
    $ex.SelectedObject = $Object
    $id = [string]$Object.Identity
    if (-not $id) { $id = [string]$Object.PrimarySmtpAddress }
    if (-not $id) {
        [System.Windows.Forms.MessageBox]::Show('Could not determine the object identity.', 'Load error', 'OK', 'Error') | Out-Null
        return
    }

    foreach ($field in $ex.Order) {
        switch ($field.Attr.Name) {
            'members'    { $people = Get-ExoDistributionGroupMemberInfo -Id $id; Set-PersonFieldValue -Field $field -People $people; $field.OriginalIds = @($field.People | ForEach-Object { $_.Id }) }
            'managedBy'  { $people = Get-ExoDistributionGroupOwnerInfo  -Id $id; Set-PersonFieldValue -Field $field -People $people; $field.OriginalIds = @($field.People | ForEach-Object { $_.Id }) }
            'fullAccess' { $people = Get-ExoFullAccessInfo -Id $id; Set-PersonFieldValue -Field $field -People $people; $field.OriginalIds = @($field.People | ForEach-Object { $_.Id }) }
            'sendAs'     { $people = Get-ExoSendAsInfo -Id $id; Set-PersonFieldValue -Field $field -People $people; $field.OriginalIds = @($field.People | ForEach-Object { $_.Id }) }
            'sendOnBehalf' {
                $people = Resolve-ExoRecipientInfo -Identities $Object.GrantSendOnBehalfTo
                Set-PersonFieldValue -Field $field -People $people; $field.OriginalIds = @($field.People | ForEach-Object { $_.Id })
            }
            default { Set-FieldValue -Field $field -Value (Get-GraphVal $Object $field.Attr.Name) }
        }
        Set-FieldBaseline -Field $field
    }

    $ex.TargetLabel.Text = "Editing: $([string]$Object.DisplayName)  <$([string]$Object.PrimarySmtpAddress)>"
    Set-ExchangeActionState
    Set-Progress "Loaded $([string]$Object.DisplayName)."
}

#endregion

#region ---------------------------------------------------------------------- Save / delete

function Test-ExchangeFormValid {
    $ex = $script:UI.Exchange
    $ep = $script:UI.ErrorProvider
    $ep.Clear()
    $firstBad = $null
    foreach ($field in $ex.Order) {
        $msg = Get-FieldValidationError -Field $field
        if ($msg) { $ep.SetError($field.Main, $msg); if (-not $firstBad) { $firstBad = $field } }
    }
    if ($firstBad) {
        Set-Progress (Get-FieldValidationError -Field $firstBad)
        try { $firstBad.Main.Focus() } catch { }
        return $false
    }
    return $true
}

function Get-ExoField { param([string]$Name) $script:UI.Exchange.Fields[$Name] }

function Read-ExoField {
    <# Read a field's value, returning $null if the field isn't present for the current type
       (so callers never pass $null into Read-FieldValue). #>
    param([string]$Name)
    $f = Get-ExoField $Name
    if ($f) { Read-FieldValue $f } else { $null }
}

function Sync-ExoPeopleField {
    <# Apply add/remove diff for a Person field using OriginalIds + scriptblock actions. #>
    param($Field, [scriptblock]$Add, [scriptblock]$Remove)
    if (-not $Field) { return }
    # Loop variable is deliberately NOT named $id so it can't shadow the object-id free variable
    # the Add/Remove blocks resolve from the caller's scope. Those blocks are PLAIN scriptblocks,
    # NOT .GetNewClosure(): a closure loses module affinity on PS 5.1 and can't find the
    # Add-Exo*/Remove-Exo* functions, whereas a plain block keeps affinity and still sees $id via
    # dynamic scope (Sync-ExoPeopleField is called synchronously from the save function).
    $now = @($Field.People | ForEach-Object { $_.Id })
    $orig = @($Field.OriginalIds)
    foreach ($personId in @($now | Where-Object { $orig -notcontains $_ })) { try { & $Add $personId } catch { Set-Progress "Add failed ($personId): $($_.Exception.Message)" } }
    foreach ($personId in @($orig | Where-Object { $now -notcontains $_ })) { try { & $Remove $personId } catch { Set-Progress "Remove failed ($personId): $($_.Exception.Message)" } }
}

function Invoke-ExoSave {
    if (-not (Test-ExoConnected)) { [System.Windows.Forms.MessageBox]::Show('Connect to Exchange Online first.', 'Not connected', 'OK', 'Information') | Out-Null; return }
    if (-not (Test-ExchangeFormValid)) { return }
    Set-UiBusy $true
    try {
        $type = Get-ExoTypeDescriptor
        if ($type.Backend -eq 'DistributionGroup') { Invoke-ExoSaveDistribution -Type $type } else { Invoke-ExoSaveMailbox -Type $type }
    } catch {
        Set-Progress 'Save failed.'
        [System.Windows.Forms.MessageBox]::Show("Save failed:`n$($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

function Invoke-ExoSaveDistribution {
    param($Type)
    $ex = $script:UI.Exchange
    $disp  = Read-ExoField 'displayName'
    $alias = Read-ExoField 'alias'
    $smtp  = Read-ExoField 'primarySmtpAddress'
    $reqAuthF = Get-ExoField 'requireSenderAuthenticationEnabled'
    $hiddenF  = Get-ExoField 'hiddenFromAddressListsEnabled'
    $memF = Get-ExoField 'members'; $ownF = Get-ExoField 'managedBy'

    if ($ex.Mode -eq 'New') {
        # Use the (space-free, validated) alias as the underlying Name when present, so DN-invalid
        # characters in the display name can't fail the create; DisplayName keeps the friendly text.
        $params = @{ Name = $(if ($alias) { $alias } else { $disp }); DisplayName = $disp; Type = $Type.DlType }
        if ($alias) { $params.Alias = $alias }
        if ($smtp)  { $params.PrimarySmtpAddress = $smtp }
        if ($reqAuthF) { $params.RequireSenderAuthenticationEnabled = [bool](Read-FieldValue $reqAuthF) }
        $mem = @($memF.People | ForEach-Object { $_.Id }); if ($mem.Count) { $params.Members = $mem }
        $own = @($ownF.People | ForEach-Object { $_.Id }); if ($own.Count) { $params.ManagedBy = $own }
        Set-Progress 'Creating distribution group...'
        $created = New-ExoDistributionGroup -Params $params
        $id = [string]$created.Identity
        if ($hiddenF -and (Read-FieldValue $hiddenF)) { Set-ExoDistributionGroup -Id $id -Params @{ HiddenFromAddressListsEnabled = $true } | Out-Null }
        Set-Progress "Created $disp."
        [System.Windows.Forms.MessageBox]::Show("Created: $disp", 'Created', 'OK', 'Information') | Out-Null
        $ex.ModeEdit.Checked = $true
        Import-ExoIntoForm -Object (Get-ExoDistributionGroup -Id $id) -Type $Type
        return
    }

    # Edit
    $obj = $ex.SelectedObject
    $id = [string]$obj.Identity
    $changed = $false
    $set = @{}
    foreach ($pair in @(@{F = 'displayName'; P = 'DisplayName' }, @{F = 'alias'; P = 'Alias' }, @{F = 'primarySmtpAddress'; P = 'PrimarySmtpAddress' }, @{F = 'requireSenderAuthenticationEnabled'; P = 'RequireSenderAuthenticationEnabled' }, @{F = 'hiddenFromAddressListsEnabled'; P = 'HiddenFromAddressListsEnabled' })) {
        $f = Get-ExoField $pair.F
        if ($f -and (Test-FieldDirty $f)) { $set[$pair.P] = Read-FieldValue $f; $changed = $true }
    }
    if ($set.Count) { Set-Progress 'Updating group...'; Set-ExoDistributionGroup -Id $id -Params $set | Out-Null }
    if ($memF -and (Test-FieldDirty $memF)) {
        Sync-ExoPeopleField -Field $memF -Add { param($m) Add-ExoDistributionGroupMember -Id $id -Member $m } -Remove { param($m) Remove-ExoDistributionGroupMember -Id $id -Member $m }
        $changed = $true
    }
    if ($ownF -and (Test-FieldDirty $ownF)) {
        $own = @($ownF.People | ForEach-Object { $_.Id })
        if ($own.Count) { Set-ExoDistributionGroupOwners -Id $id -Owners $own | Out-Null; $changed = $true }
    }
    if (-not $changed) { Set-Progress 'No changes to save.'; return }
    Import-ExoIntoForm -Object (Get-ExoDistributionGroup -Id $id) -Type $Type
    Set-Progress 'Saved.'
    [System.Windows.Forms.MessageBox]::Show('Changes saved.', 'Saved', 'OK', 'Information') | Out-Null
}

function Invoke-ExoSaveMailbox {
    param($Type)
    $ex = $script:UI.Exchange
    $disp  = Read-ExoField 'displayName'
    $alias = Read-ExoField 'alias'
    $smtp  = Read-ExoField 'primarySmtpAddress'
    $hiddenF = Get-ExoField 'hiddenFromAddressListsEnabled'
    $faF = Get-ExoField 'fullAccess'; $saF = Get-ExoField 'sendAs'; $sobF = Get-ExoField 'sendOnBehalf'

    if ($ex.Mode -eq 'New') {
        $params = @{ Name = $(if ($alias) { $alias } else { $disp }); DisplayName = $disp; $Type.MailboxSwitch = $true }
        if ($alias) { $params.Alias = $alias }
        if ($smtp)  { $params.PrimarySmtpAddress = $smtp }
        Set-Progress 'Creating mailbox...'
        $created = New-ExoMailbox -Params $params
        $id = [string]$created.Identity
        if ($hiddenF -and (Read-FieldValue $hiddenF)) { Set-ExoMailbox -Id $id -Params @{ HiddenFromAddressListsEnabled = $true } | Out-Null }
        $sob = @($sobF.People | ForEach-Object { $_.Id }); if ($sob.Count) { Set-ExoMailbox -Id $id -Params @{ GrantSendOnBehalfTo = $sob } | Out-Null }
        foreach ($p in $faF.People) { try { Add-ExoFullAccess -Id $id -User $p.Id } catch { Set-Progress "Full Access add failed: $($_.Exception.Message)" } }
        foreach ($p in $saF.People) { try { Add-ExoSendAs -Id $id -Trustee $p.Id } catch { Set-Progress "Send As add failed: $($_.Exception.Message)" } }
        Set-Progress "Created $disp."
        [System.Windows.Forms.MessageBox]::Show("Created mailbox: $disp", 'Created', 'OK', 'Information') | Out-Null
        $ex.ModeEdit.Checked = $true
        Import-ExoIntoForm -Object (Get-ExoMailbox -Id $id) -Type $Type
        return
    }

    # Edit
    $obj = $ex.SelectedObject
    $id = [string]$obj.Identity
    $changed = $false
    $set = @{}
    foreach ($pair in @(@{F = 'displayName'; P = 'DisplayName' }, @{F = 'alias'; P = 'Alias' }, @{F = 'primarySmtpAddress'; P = 'PrimarySmtpAddress' }, @{F = 'hiddenFromAddressListsEnabled'; P = 'HiddenFromAddressListsEnabled' })) {
        $f = Get-ExoField $pair.F
        if ($f -and (Test-FieldDirty $f)) { $set[$pair.P] = Read-FieldValue $f; $changed = $true }
    }
    if ($sobF -and (Test-FieldDirty $sobF)) { $set['GrantSendOnBehalfTo'] = @($sobF.People | ForEach-Object { $_.Id }); $changed = $true }
    if ($set.Count) { Set-Progress 'Updating mailbox...'; Set-ExoMailbox -Id $id -Params $set | Out-Null }
    if ($faF -and (Test-FieldDirty $faF)) {
        Sync-ExoPeopleField -Field $faF -Add { param($u) Add-ExoFullAccess -Id $id -User $u } -Remove { param($u) Remove-ExoFullAccess -Id $id -User $u }
        $changed = $true
    }
    if ($saF -and (Test-FieldDirty $saF)) {
        Sync-ExoPeopleField -Field $saF -Add { param($u) Add-ExoSendAs -Id $id -Trustee $u } -Remove { param($u) Remove-ExoSendAs -Id $id -Trustee $u }
        $changed = $true
    }
    if (-not $changed) { Set-Progress 'No changes to save.'; return }
    Import-ExoIntoForm -Object (Get-ExoMailbox -Id $id) -Type $Type
    Set-Progress 'Saved.'
    [System.Windows.Forms.MessageBox]::Show('Changes saved.', 'Saved', 'OK', 'Information') | Out-Null
}

function Invoke-ExoDelete {
    $ex = $script:UI.Exchange
    $obj = $ex.SelectedObject
    if (-not $obj) { return }
    $type = Get-ExoTypeDescriptor
    $name = [string]$obj.DisplayName
    $note = if ($type.Backend -eq 'Mailbox') { 'The mailbox is soft-deleted (recoverable ~30 days).' } else { 'The group is permanently deleted.' }
    if (-not (Show-TypedConfirm -Prompt "Delete '$name'?`n`n$note`n`nType the name below to confirm:" -Expected $name)) { return }

    Set-UiBusy $true
    try {
        $id = [string]$obj.Identity
        if ($type.Backend -eq 'Mailbox') { Remove-ExoMailbox -Id $id } else { Remove-ExoDistributionGroup -Id $id }
        Set-Progress "Deleted '$name'."
        [System.Windows.Forms.MessageBox]::Show("Deleted '$name'.", 'Deleted', 'OK', 'Information') | Out-Null
        Set-ExchangeMode -Mode 'Edit'
    } catch {
        Set-Progress 'Delete failed.'
        [System.Windows.Forms.MessageBox]::Show("Delete failed:`n$($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

#endregion
