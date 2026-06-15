<#
    Main window + orchestration.

    Builds the chrome (connect/tenant bar, Users/Groups tabs, status bar), then wires the
    create/modify flow:  build a tab's form from the enabled catalog attributes (New or Edit
    mode) -> load an existing object and snapshot baselines -> on Save, assemble a payload
    (full for New, dirty-only for Edit) and apply it, handling the relationships that need
    their own calls (manager, licenses, members, owners).

    Per-tab state lives in $script:UI.User / $script:UI.Group.
#>

#region ---------------------------------------------------------------------- Form construction

function New-MainForm {
    $t = Get-Theme

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'M365 User / Group Manager'
    $form.Size = New-Object System.Drawing.Size(900, 780)
    $form.MinimumSize = New-Object System.Drawing.Size(760, 600)
    $form.StartPosition = 'CenterScreen'
    $form.Font = $t.FontBase
    $form.AutoScaleMode = 'Font'
    try { $form.Icon = [System.Drawing.SystemIcons]::Application } catch { }

    $tooltip = New-Object System.Windows.Forms.ToolTip
    $errorProvider = New-Object System.Windows.Forms.ErrorProvider
    $errorProvider.BlinkStyle = 'NeverBlink'

    $root = New-Object System.Windows.Forms.TableLayoutPanel
    $root.Dock = 'Fill'; $root.ColumnCount = 1; $root.RowCount = 3
    [void]$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 54)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 62)))
    $form.Controls.Add($root)

    # --- Top: connect + tenant bar ---------------------------------------------------------
    $top = New-Object System.Windows.Forms.Panel; $top.Dock = 'Fill'
    $connectBtn = New-Object System.Windows.Forms.Button
    $connectBtn.Text = '&Connect'; $connectBtn.Location = New-Object System.Drawing.Point(10, 12); $connectBtn.Size = New-Object System.Drawing.Size(140, 30)
    $disconnectBtn = New-Object System.Windows.Forms.Button
    $disconnectBtn.Text = 'Dis&connect'; $disconnectBtn.Location = New-Object System.Drawing.Point(156, 12); $disconnectBtn.Size = New-Object System.Drawing.Size(96, 30); $disconnectBtn.Enabled = $false

    $connLabel = New-Object System.Windows.Forms.Label
    $connLabel.AutoSize = $true; $connLabel.Location = New-Object System.Drawing.Point(264, 13); $connLabel.Text = 'Not connected'
    $connLabel.Font = $t.FontMedium; $connLabel.ForeColor = $t.ErrText; $connLabel.BackColor = $t.ErrBack
    $connLabel.Padding = New-Object System.Windows.Forms.Padding(9, 5, 9, 5); $connLabel.TextAlign = 'MiddleLeft'
    $top.Controls.AddRange(@($connectBtn, $disconnectBtn, $connLabel))
    $root.Controls.Add($top, 0, 0)

    # --- Middle: Users / Groups tabs -------------------------------------------------------
    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'; $tabs.Padding = New-Object System.Drawing.Point(14, 6)
    $root.Controls.Add($tabs, 0, 1)

    # --- Bottom: status + progress ---------------------------------------------------------
    $bottom = New-Object System.Windows.Forms.TableLayoutPanel
    $bottom.Dock = 'Fill'; $bottom.ColumnCount = 1; $bottom.RowCount = 2
    [void]$bottom.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 22)))
    [void]$bottom.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Dock = 'Fill'; $progress.Style = 'Continuous'; $progress.Margin = New-Object System.Windows.Forms.Padding(12, 6, 12, 4); $progress.BackColor = $t.ProgBack
    $status = New-Object System.Windows.Forms.Label
    $status.Dock = 'Fill'; $status.Text = 'Ready. Connect to Microsoft 365 to begin.'; $status.AutoEllipsis = $true
    $status.TextAlign = 'MiddleLeft'; $status.Margin = New-Object System.Windows.Forms.Padding(12, 0, 12, 4); $status.ForeColor = $t.Muted
    $bottom.Controls.Add($progress, 0, 0); $bottom.Controls.Add($status, 0, 1)
    $root.Controls.Add($bottom, 0, 2)

    # --- Stash core handles, then build the two tabs ---------------------------------------
    $script:UI = @{
        Form = $form; Tabs = $tabs; Tooltip = $tooltip; ErrorProvider = $errorProvider
        ConnectBtn = $connectBtn; DisconnectBtn = $disconnectBtn
        ConnLabel = $connLabel; Status = $status; Progress = $progress
        User = $null; Group = $null; Exchange = $null
    }

    [void]$tabs.TabPages.Add((New-EntityTab -Tab 'User' -Title 'Users'))
    [void]$tabs.TabPages.Add((New-EntityTab -Tab 'Group' -Title 'Groups'))
    [void]$tabs.TabPages.Add((New-ExchangeTab))
    Update-ExchangeActivation   # show the gated empty-state until Exchange is activated

    foreach ($b in @($connectBtn, $disconnectBtn)) { Set-SecondaryButtonStyle $b }

    # --- Wire connection events ------------------------------------------------------------
    # One button drives the whole account flow: connect, switch between saved accounts, or add a
    # new one. Its label flips to "Switch account" once connected (see Update-ConnectionLabel).
    $connectBtn.Add_Click({ Invoke-Account })
    $disconnectBtn.Add_Click({ Invoke-Disconnect })

    # On open, let the user choose which saved account to connect to (when more than one) instead of
    # silently adopting the last/persisted session. Plain scriptblock keeps module affinity.
    $form.Add_Shown({ Invoke-StartupConnect })

    return $form
}

function New-EntityTab {
    param([ValidateSet('User', 'Group')][string]$Tab, [string]$Title)
    $t = Get-Theme
    $entityWord = if ($Tab -eq 'User') { 'user' } else { 'group' }

    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Title; $page.UseVisualStyleBackColor = $true; $page.Padding = New-Object System.Windows.Forms.Padding(8)

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'; $layout.ColumnCount = 1; $layout.RowCount = 3
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 44)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 50)))
    $page.Controls.Add($layout)

    # --- Header: New / Edit mode + select existing + Settings ------------------------------
    $header = New-Object System.Windows.Forms.TableLayoutPanel
    $header.Dock = 'Fill'; $header.ColumnCount = 2; $header.RowCount = 1
    [void]$header.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$header.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))

    $left = New-Object System.Windows.Forms.FlowLayoutPanel
    $left.Dock = 'Fill'; $left.FlowDirection = 'LeftToRight'; $left.WrapContents = $false
    $modeNew = New-Object System.Windows.Forms.RadioButton; $modeNew.Text = "&New $entityWord"; $modeNew.AutoSize = $true; $modeNew.Checked = $true; $modeNew.Margin = New-Object System.Windows.Forms.Padding(3, 10, 8, 3)
    $modeEdit = New-Object System.Windows.Forms.RadioButton; $modeEdit.Text = '&Edit existing'; $modeEdit.AutoSize = $true; $modeEdit.Margin = New-Object System.Windows.Forms.Padding(3, 10, 12, 3)
    $selectBtn = New-Object System.Windows.Forms.Button; $selectBtn.Text = "&Select $entityWord..."; $selectBtn.Width = 130; $selectBtn.Height = 26; $selectBtn.Visible = $false; $selectBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 3)
    Set-SecondaryButtonStyle $selectBtn
    $targetLabel = New-Object System.Windows.Forms.Label; $targetLabel.AutoSize = $true; $targetLabel.Margin = New-Object System.Windows.Forms.Padding(3, 11, 3, 3); $targetLabel.ForeColor = $t.Muted; $targetLabel.Visible = $false
    $left.Controls.AddRange(@($modeNew, $modeEdit, $selectBtn, $targetLabel))

    $settingsBtn = New-Object System.Windows.Forms.Button; $settingsBtn.Text = '&Fields...'; $settingsBtn.Width = 96; $settingsBtn.Height = 28; $settingsBtn.Margin = New-Object System.Windows.Forms.Padding(3, 7, 3, 3)
    Set-SecondaryButtonStyle $settingsBtn
    $header.Controls.Add($left, 0, 0); $header.Controls.Add($settingsBtn, 1, 0)
    $layout.Controls.Add($header, 0, 0)

    # --- Form host: scrollable 2-column field grid -----------------------------------------
    $scroll = New-Object System.Windows.Forms.Panel; $scroll.Dock = 'Fill'; $scroll.AutoScroll = $true
    $formTlp = New-Object System.Windows.Forms.TableLayoutPanel
    $formTlp.ColumnCount = 2; $formTlp.AutoSize = $true; $formTlp.AutoSizeMode = 'GrowAndShrink'; $formTlp.Dock = 'Top'
    $formTlp.GrowStyle = 'AddRows'; $formTlp.Padding = New-Object System.Windows.Forms.Padding(4, 6, 18, 6)
    [void]$formTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$formTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $scroll.Controls.Add($formTlp)
    $layout.Controls.Add($scroll, 0, 1)

    # --- Actions: Save / Reset (left), Delete (right) --------------------------------------
    $actions = New-Object System.Windows.Forms.TableLayoutPanel
    $actions.Dock = 'Fill'; $actions.ColumnCount = 2; $actions.RowCount = 1
    [void]$actions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$actions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $leftActions = New-Object System.Windows.Forms.FlowLayoutPanel; $leftActions.Dock = 'Fill'; $leftActions.FlowDirection = 'LeftToRight'; $leftActions.WrapContents = $false
    $saveBtn = New-Object System.Windows.Forms.Button; $saveBtn.Text = "&Create $entityWord"; $saveBtn.Width = 150; $saveBtn.Height = 34; $saveBtn.Font = $t.FontMedium; $saveBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 6)
    Set-PrimaryButtonStyle $saveBtn
    $resetBtn = New-Object System.Windows.Forms.Button; $resetBtn.Text = '&Reset'; $resetBtn.Width = 84; $resetBtn.Height = 34; $resetBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 6)
    Set-SecondaryButtonStyle $resetBtn
    $backupBtn = New-Object System.Windows.Forms.Button; $backupBtn.Text = '&Backup...'; $backupBtn.Width = 90; $backupBtn.Height = 34; $backupBtn.Margin = New-Object System.Windows.Forms.Padding(16, 6, 3, 6); $backupBtn.Enabled = $false
    $restoreBtn = New-Object System.Windows.Forms.Button; $restoreBtn.Text = 'Res&tore...'; $restoreBtn.Width = 90; $restoreBtn.Height = 34; $restoreBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 6)
    Set-SecondaryButtonStyle $backupBtn; Set-SecondaryButtonStyle $restoreBtn
    $leftActions.Controls.AddRange(@($saveBtn, $resetBtn, $backupBtn, $restoreBtn))
    $rightActions = New-Object System.Windows.Forms.FlowLayoutPanel; $rightActions.Dock = 'Fill'; $rightActions.FlowDirection = 'RightToLeft'; $rightActions.WrapContents = $false
    $deleteBtn = New-Object System.Windows.Forms.Button; $deleteBtn.Text = "&Delete $entityWord"; $deleteBtn.Width = 130; $deleteBtn.Height = 34; $deleteBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 6); $deleteBtn.Visible = $false
    Set-SecondaryButtonStyle $deleteBtn
    $deleteBtn.ForeColor = $t.ErrText
    $rightActions.Controls.Add($deleteBtn)
    $actions.Controls.Add($leftActions, 0, 0); $actions.Controls.Add($rightActions, 1, 0)
    $layout.Controls.Add($actions, 0, 2)

    # --- Stash tab state -------------------------------------------------------------------
    $script:UI[$Tab] = @{
        Page = $page; Mode = 'New'
        ModeNew = $modeNew; ModeEdit = $modeEdit; SelectBtn = $selectBtn; TargetLabel = $targetLabel
        ScrollHost = $scroll; FormTlp = $formTlp
        Fields = @{}; Order = (New-Object System.Collections.Generic.List[object])
        SaveBtn = $saveBtn; ResetBtn = $resetBtn; DeleteBtn = $deleteBtn; SettingsBtn = $settingsBtn
        BackupBtn = $backupBtn; RestoreBtn = $restoreBtn
    }

    # --- Wire tab events -------------------------------------------------------------------
    $modeNew.Tag = $Tab; $modeEdit.Tag = $Tab; $selectBtn.Tag = $Tab
    $saveBtn.Tag = $Tab; $resetBtn.Tag = $Tab; $deleteBtn.Tag = $Tab; $settingsBtn.Tag = $Tab
    $backupBtn.Tag = $Tab
    $backupBtn.Add_Click({ param($s, $e) Invoke-Backup -Tab $s.Tag })
    $restoreBtn.Add_Click({ Invoke-Restore })
    $modeNew.Add_CheckedChanged({ param($s, $e) if ($s.Checked) { Set-TabMode -Tab $s.Tag -Mode 'New' } })
    $modeEdit.Add_CheckedChanged({ param($s, $e) if ($s.Checked) { Set-TabMode -Tab $s.Tag -Mode 'Edit' } })
    $selectBtn.Add_Click({ param($s, $e) Invoke-SelectExisting -Tab $s.Tag })
    $settingsBtn.Add_Click({
        param($s, $e)
        if (-not (Show-SettingsDialog -Tab $s.Tag)) { return }
        $tab = $s.Tag
        Build-TabForm -Tab $tab
        # If an object is loaded in Edit mode, re-populate the rebuilt form (and re-capture
        # baselines / OriginalIds) so changing which fields are shown doesn't blank it out.
        if ($script:UI[$tab].Mode -eq 'Edit') {
            if ($tab -eq 'User' -and $script:State.SelectedUser) { Import-UserIntoForm -User $script:State.SelectedUser }
            elseif ($tab -eq 'Group' -and $script:State.SelectedGroup) { Import-GroupIntoForm -Group $script:State.SelectedGroup }
        }
    })
    $saveBtn.Add_Click({ param($s, $e) Invoke-Save -Tab $s.Tag })
    $resetBtn.Add_Click({ param($s, $e) Set-TabMode -Tab $s.Tag -Mode $script:UI[$s.Tag].Mode })
    $deleteBtn.Add_Click({ param($s, $e) Invoke-Delete -Tab $s.Tag })

    Build-TabForm -Tab $Tab
    return $page
}

#endregion

#region ---------------------------------------------------------------------- Tab form building

function Build-TabForm {
    <# (Re)build a tab's fields from the enabled catalog attributes + current mode, laid out under
       the catalog's section headers (sections with no enabled fields are skipped). #>
    param([ValidateSet('User', 'Group')][string]$Tab)
    $ctx = $script:UI[$Tab]
    $tlp = $ctx.FormTlp
    $t   = Get-Theme
    $enabled = @($script:Config[$(if ($Tab -eq 'User') { 'Users' } else { 'Groups' })].Enabled)

    $tlp.SuspendLayout()
    $tlp.Controls.Clear()
    $tlp.RowStyles.Clear()
    $ctx.Fields = @{}
    $ctx.Order = New-Object System.Collections.Generic.List[object]

    # Plan the rows first (a section header, then its enabled fields) so RowCount is known up front
    # and explicit cell placement is reliable (auto-placement misbehaves with column-spanning rows).
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($group in (Get-CatalogTab -Tab $Tab)) {
        # Show every enabled attribute (incl. ReadOnly) so the Settings checkboxes are truthful --
        # checked = shown. ReadOnly fields render empty/greyed on a New object (value appears once
        # it exists); they are simply not editable.
        # Fields required to create (marked * or auto-generated) are ALWAYS shown when creating, even
        # if unchecked in Settings -- the object can't be created without them.
        $attrs = @($group.Attributes | Where-Object { ($enabled -contains $_.Name) -or ($ctx.Mode -eq 'New' -and ($_.Required -or $_.RequiredForCreate)) })
        if ($attrs.Count -eq 0) { continue }
        [void]$plan.Add(@{ Header = $group.Name })
        foreach ($a in $attrs) { [void]$plan.Add(@{ Attr = $a }) }
    }

    $tlp.RowCount = [Math]::Max($plan.Count, 1)
    for ($i = 0; $i -lt $plan.Count; $i++) {
        [void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    }

    $row = 0
    $firstHeader = $true
    foreach ($item in $plan) {
        if ($item.Header) {
            $hdr = New-Object System.Windows.Forms.Label
            $hdr.Text = $item.Header
            $hdr.UseMnemonic = $false   # render literal '&' in names like "Identity & Sign-in"
            $hdr.AutoSize = $true
            $hdr.Font = $t.FontMedium
            $hdr.ForeColor = $t.Accent
            $hdr.Margin = New-Object System.Windows.Forms.Padding(3, $(if ($firstHeader) { 2 } else { 16 }), 3, 4)
            $tlp.Controls.Add($hdr, 0, $row)
            $tlp.SetColumnSpan($hdr, 2)
            $firstHeader = $false
        } else {
            $field = New-FieldRow -Attr $item.Attr -Mode $ctx.Mode -Tooltip $script:UI.Tooltip
            $tlp.Controls.Add($field.Label, 0, $row)
            $tlp.Controls.Add($field.Cell, 1, $row)
            $ctx.Fields[$item.Attr.Name] = $field
            [void]$ctx.Order.Add($field)
        }
        $row++
    }

    # New-mode defaults.
    if ($ctx.Mode -eq 'New' -and $ctx.Fields.ContainsKey('accountEnabled')) {
        $ctx.Fields['accountEnabled'].Main.Checked = $true
    }

    # New user: typing First/Last auto-fills displayName, alias, and the UPN local part.
    if ($Tab -eq 'User' -and $ctx.Mode -eq 'New') {
        foreach ($n in 'givenName', 'surname') {
            $nf = $ctx.Fields[$n]
            if ($nf -and $nf.Main) { $nf.Main.Add_TextChanged({ Update-NewUserGeneratedFields }) }
        }
    }

    # License pickers need the tenant SKUs. Only fetch them once the app is ready (i.e. AFTER the
    # user has connected) -- never during initial construction -- so launching the tool makes no
    # Graph call and can't trigger a sign-in prompt before Connect is clicked.
    if ($script:AppReady -and (Test-GraphConnected)) {
        foreach ($f in $ctx.Order) {
            if ($f.Kind -eq 'License') { Set-LicenseFieldItems -Field $f -Skus (Get-AvailableSku) }
        }
    }

    $tlp.ResumeLayout()
    $ctx.SaveBtn.Text = if ($ctx.Mode -eq 'New') { "&Create $(if ($Tab -eq 'User') { 'user' } else { 'group' })" } else { '&Save changes' }
    Set-TabActionState -Tab $Tab
}

function Set-AutoField {
    <# Set a field's value only while the user hasn't manually changed it (current == last auto value,
       or empty), so name-driven auto-fill stops once they override it. Works for Text and the UPN
       local part (both use $Field.Main.Text). #>
    param($Field, [string]$Value)
    if (-not $Field -or -not $Field.Main) { return }
    $cur = [string]$Field.Main.Text
    if ($cur -eq '' -or $cur -eq [string]$Field.AutoLast) {
        $Field.Main.Text = $Value
        $Field.AutoLast = $Value
    }
}

function Get-GeneratedUserNames {
    <# Pure: derive the Display Name ("First Last") and alias (first.last, lowercased, ASCII-only) from
       a first + last name. Alias is also the UPN local part. #>
    param([string]$First, [string]$Last)
    $display = ("$First $Last").Trim()
    $alias   = ((("$First.$Last") -replace '[^A-Za-z0-9.]', '').ToLower()).Trim('.')
    return @{ Display = $display; Alias = $alias }
}

function Update-NewUserGeneratedFields {
    <# New-user convenience: derive Display Name, alias and the UPN local part from the First/Last
       name fields. Each target auto-fills only until the operator edits it. #>
    $ctx = $script:UI.User
    if (-not $ctx -or $ctx.Mode -ne 'New') { return }
    $g = $ctx.Fields
    $first = if ($g.ContainsKey('givenName') -and $g['givenName']) { [string](Read-FieldValue $g['givenName']) } else { '' }
    $last  = if ($g.ContainsKey('surname')   -and $g['surname'])   { [string](Read-FieldValue $g['surname']) }   else { '' }
    $gen = Get-GeneratedUserNames -First $first -Last $last
    if ($g.ContainsKey('displayName'))       { Set-AutoField -Field $g['displayName']       -Value $gen.Display }
    if ($g.ContainsKey('mailNickname'))      { Set-AutoField -Field $g['mailNickname']      -Value $gen.Alias }
    if ($g.ContainsKey('userPrincipalName')) { Set-AutoField -Field $g['userPrincipalName'] -Value $gen.Alias }
}

function Set-TabMode {
    param([ValidateSet('User', 'Group')][string]$Tab, [ValidateSet('New', 'Edit')][string]$Mode)
    $ctx = $script:UI[$Tab]
    $ctx.Mode = $Mode
    $ctx.SelectBtn.Visible = ($Mode -eq 'Edit')
    $ctx.TargetLabel.Visible = ($Mode -eq 'Edit')
    $ctx.DeleteBtn.Visible = ($Mode -eq 'Edit')
    $ctx.TargetLabel.Text = ''
    if ($Tab -eq 'User') { $script:State.SelectedUser = $null } else { $script:State.SelectedGroup = $null }
    $script:UI.ErrorProvider.Clear()
    Build-TabForm -Tab $Tab
}

function Set-TabActionState {
    <# Enable Save only when connected (and, in Edit mode, an object is loaded). #>
    param([ValidateSet('User', 'Group')][string]$Tab)
    $ctx = $script:UI[$Tab]
    $connected = Test-GraphConnected
    $loaded = if ($Tab -eq 'User') { [bool]$script:State.SelectedUser } else { [bool]$script:State.SelectedGroup }
    $ctx.SaveBtn.Enabled = $connected -and ($ctx.Mode -eq 'New' -or $loaded)
    $ctx.DeleteBtn.Enabled = $connected -and $loaded
    $ctx.SelectBtn.Enabled = $connected
    if ($ctx.BackupBtn) { $ctx.BackupBtn.Enabled = $loaded }   # backup needs a loaded object
}

#endregion

#region ---------------------------------------------------------------------- Connection

function Update-ConnectionLabel {
    $ctx = Get-GraphContextSafe
    $t = Get-Theme
    if ($ctx) {
        $domain = Get-TenantDomainHint -Context $ctx
        $script:UI.ConnLabel.Text = "Connected: $($ctx.Account)  [$domain]"
        $script:UI.ConnLabel.ForeColor = $t.OkText
        $script:UI.ConnLabel.BackColor = $t.OkBack
        $script:UI.ConnectBtn.Text = '&Switch account...'
        $script:UI.DisconnectBtn.Enabled = $true
    } else {
        $script:UI.ConnLabel.Text = 'Not connected'
        $script:UI.ConnLabel.ForeColor = $t.ErrText
        $script:UI.ConnLabel.BackColor = $t.ErrBack
        $script:UI.ConnectBtn.Text = '&Connect'
        $script:UI.DisconnectBtn.Enabled = $false
    }
    Set-TabActionState -Tab 'User'
    Set-TabActionState -Tab 'Group'
}

function Save-CurrentAccount {
    <# Remember the currently-connected account (keyed by tenant id) for one-click switching. #>
    $ctx = Get-GraphContextSafe
    if (-not $ctx -or -not $ctx.TenantId) { return }
    $tid = [string]$ctx.TenantId
    $upn = [string]$ctx.Account
    $name = if ($upn -and $upn.Contains('@')) { $upn.Split('@')[-1] } else { $tid }
    $existing = @($script:Config.Accounts | Where-Object { $_.TenantId -eq $tid })
    if ($existing.Count -gt 0) {
        $existing[0].Upn = $upn
        if (-not $existing[0].Name) { $existing[0].Name = $name }
    } else {
        $script:Config.Accounts = @(@($script:Config.Accounts) + @{ Name = $name; TenantId = $tid; Upn = $upn })
    }
    try { Save-AppConfig -Config $script:Config } catch { }
}

function Complete-Connection {
    <# Shared post-connect refresh after any successful connect / switch. #>
    param($Context)
    Reset-HybridState            # recompute hybrid + AD-write capability for the (new) tenant
    Save-CurrentAccount
    Update-ConnectionLabel
    Update-ExchangeActivation
    Initialize-SkuMap -Force
    Initialize-VerifiedDomains          # for the UPN domain dropdown (must precede Build-TabForm)
    foreach ($tab in 'User', 'Group') { Build-TabForm -Tab $tab }
    $missing = Get-MissingScopes
    if ($missing.Count -gt 0) {
        Set-Progress "Connected, but missing scopes: $($missing -join ', '). Some actions may fail."
        [System.Windows.Forms.MessageBox]::Show(
            "Connected, but these requested permissions were not granted:`n`n  $($missing -join "`n  ")`n`nAn administrator may need to consent. Some operations will fail until then.",
            'Some permissions not granted', 'OK', 'Warning') | Out-Null
    } else {
        Set-Progress "Connected: $($Context.Account)"
    }
}

function Connect-NewAccount {
    <# Interactive sign-in to a new account (MSAL shows its own account picker / browser). On
       success the account is remembered for later one-click switching. #>
    Set-UiBusy $true
    try {
        Disconnect-ExoSafe   # any Exchange session belonged to the previous account
        # "Sign in new" must show an account chooser. If we're already connected, a valid cached
        # token makes Connect-MgGraph silently reuse the CURRENT account (so the dialog appeared to do
        # nothing). Disconnect first to clear the context and force a fresh interactive sign-in where
        # the user can pick/add a different account.
        if (Test-GraphConnected) { Disconnect-GraphSafe }
        Set-Progress 'Opening sign-in...'
        $ctx = Connect-Tenant
        if ($ctx) { Complete-Connection -Context $ctx }
    } catch {
        Set-Progress 'Connection failed.'
        [System.Windows.Forms.MessageBox]::Show("Could not connect:`n$($_.Exception.Message)", 'Connection error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

function Invoke-StartupConnect {
    <#
        Runs once when the window first shows. If MORE THAN ONE account is saved, present the picker
        so the user chooses which to connect to (rather than silently adopting the last/persisted
        session). With 0 or 1 saved account we do nothing: the label already reflects any persisted
        session and NO network call is made until the user acts -- so launching off-VPN/off-network
        is safe, and a lone remembered account is simply reused.
    #>
    if (-not $script:AppReady) { return }
    if (@($script:Config.Accounts).Count -ge 2) { Invoke-Account }
}

function Invoke-Account {
    <# Connect / Switch-account button. No saved accounts + not connected -> sign in directly;
       otherwise show the account picker. #>
    $accounts = @($script:Config.Accounts)
    if ($accounts.Count -eq 0 -and -not (Test-GraphConnected)) { Connect-NewAccount; return }

    $choice = Show-AccountDialog
    if (-not $choice) { return }
    if ($choice -eq 'NEW') { Connect-NewAccount; return }

    $current = Get-GraphContextSafe
    if ($current -and $current.TenantId -eq $choice.TenantId) { Set-Progress "Already connected to $($choice.Name)."; return }
    Set-UiBusy $true
    try {
        Disconnect-ExoSafe
        Set-Progress "Switching to $($choice.Name)..."
        $ctx = Switch-Tenant -TenantId $choice.TenantId      # silent if the token is still cached
        if ($ctx) { Complete-Connection -Context $ctx }
    } catch {
        Set-Progress 'Switch failed.'
        [System.Windows.Forms.MessageBox]::Show("Could not switch account:`n$($_.Exception.Message)", 'Switch error', 'OK', 'Error') | Out-Null
        Update-ConnectionLabel
    } finally {
        Set-UiBusy $false
    }
}

function Invoke-Disconnect {
    Disconnect-GraphSafe
    Disconnect-ExoSafe                 # the EXO session belonged to this Graph tenant
    Reset-HybridState                  # clear cached hybrid + AD-write capability
    $script:SkuMap = @{}
    $script:State.SelectedUser = $null; $script:State.SelectedGroup = $null
    Update-ConnectionLabel
    Update-ExchangeActivation          # re-gate the Exchange tab
    Set-Progress 'Disconnected.'
}

function Show-AccountDialog {
    <# Pick a saved account to connect to. Returns the account hashtable, the string 'NEW' to sign
       in a different account, or $null on cancel. #>
    $t = Get-Theme
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Accounts'; $dlg.Size = New-Object System.Drawing.Size(470, 348); $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'; $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false; $dlg.Font = $t.FontBase; $dlg.ShowInTaskbar = $false

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = 'Pick an account to connect to, or sign in another:'; $lbl.Location = New-Object System.Drawing.Point(14, 12); $lbl.AutoSize = $true
    $list = New-Object System.Windows.Forms.ListBox
    $list.Location = New-Object System.Drawing.Point(14, 38); $list.Size = New-Object System.Drawing.Size(316, 252); $list.IntegralHeight = $false
    foreach ($a in @($script:Config.Accounts)) {
        $disp = if ($a.Upn) { "$($a.Name)  -  $($a.Upn)" } else { [string]$a.Name }
        [void]$list.Items.Add([pscustomobject]@{ Display = $disp; Account = $a })
    }
    $list.DisplayMember = 'Display'
    if ($list.Items.Count -gt 0) { $list.SelectedIndex = 0 }

    $connectBtn = New-Object System.Windows.Forms.Button; $connectBtn.Text = '&Connect'; $connectBtn.Location = New-Object System.Drawing.Point(340, 38); $connectBtn.Size = New-Object System.Drawing.Size(108, 30)
    $newBtn = New-Object System.Windows.Forms.Button; $newBtn.Text = 'Sign in &new...'; $newBtn.Location = New-Object System.Drawing.Point(340, 74); $newBtn.Size = New-Object System.Drawing.Size(108, 30)
    $removeBtn = New-Object System.Windows.Forms.Button; $removeBtn.Text = '&Remove'; $removeBtn.Location = New-Object System.Drawing.Point(340, 110); $removeBtn.Size = New-Object System.Drawing.Size(108, 28)
    $cancelBtn = New-Object System.Windows.Forms.Button; $cancelBtn.Text = 'Cancel'; $cancelBtn.Location = New-Object System.Drawing.Point(340, 260); $cancelBtn.Size = New-Object System.Drawing.Size(108, 30); $cancelBtn.DialogResult = 'Cancel'
    Set-PrimaryButtonStyle $connectBtn; foreach ($b in @($newBtn, $removeBtn, $cancelBtn)) { Set-SecondaryButtonStyle $b }
    if ($list.Items.Count -eq 0) { $connectBtn.Enabled = $false; $removeBtn.Enabled = $false }

    # These are PLAIN scriptblocks (no .GetNewClosure()): the dialog is modal, so $list/$dlg are
    # still on the stack when events fire, and a plain block keeps module affinity -- which is what
    # lets the handler write the real $script:AccountDialogResult (read at the bottom of this
    # function) and call Save-AppConfig. A closure would write a phantom script var and lose the
    # module functions on PS 5.1.
    $script:AccountDialogResult = $null
    $connectBtn.Add_Click({ if ($list.SelectedItem) { $script:AccountDialogResult = $list.SelectedItem.Account; $dlg.Close() } })
    $list.Add_DoubleClick({ if ($list.SelectedItem) { $script:AccountDialogResult = $list.SelectedItem.Account; $dlg.Close() } })
    $newBtn.Add_Click({ $script:AccountDialogResult = 'NEW'; $dlg.Close() })
    $removeBtn.Add_Click({
            if ($list.SelectedItem) {
                $acc = $list.SelectedItem.Account
                $script:Config.Accounts = @(@($script:Config.Accounts) | Where-Object { $_.TenantId -ne $acc.TenantId })
                try { Save-AppConfig -Config $script:Config } catch { }
                $list.Items.Remove($list.SelectedItem)
                if ($list.Items.Count -gt 0) { $list.SelectedIndex = 0 } else { $connectBtn.Enabled = $false; $removeBtn.Enabled = $false }
            }
        })

    $dlg.Controls.AddRange(@($lbl, $list, $connectBtn, $newBtn, $removeBtn, $cancelBtn))
    $dlg.CancelButton = $cancelBtn
    [void]$dlg.ShowDialog()
    $dlg.Dispose()
    return $script:AccountDialogResult
}

#endregion

#region ---------------------------------------------------------------------- Edit: load existing

function Invoke-SelectExisting {
    param([ValidateSet('User', 'Group')][string]$Tab)
    if (-not (Test-GraphConnected)) { [System.Windows.Forms.MessageBox]::Show('Connect first.', 'Not connected', 'OK', 'Information') | Out-Null; return }
    $target = if ($Tab -eq 'User') { 'User' } else { 'Group' }
    $picked = Show-PersonPicker -TargetType $target
    if (-not $picked) { return }
    $id = $picked[0].Id

    Set-UiBusy $true
    try {
        if ($Tab -eq 'User') {
            Set-Progress 'Loading user...'
            $obj = Get-UserById -Id $id
            Build-TabForm -Tab 'User'
            Import-UserIntoForm -User $obj
        } else {
            Set-Progress 'Loading group...'
            $obj = Get-GroupById -Id $id
            $label = Get-GroupTypeLabel -Group $obj
            if ($label -like '*read-only*') {
                [System.Windows.Forms.MessageBox]::Show("This is a $label group and can't be modified through Graph (manage it in Exchange).", 'Read-only group type', 'OK', 'Warning') | Out-Null
                return
            }
            Build-TabForm -Tab 'Group'
            Import-GroupIntoForm -Group $obj
        }
    } catch {
        Set-Progress 'Load failed.'
        [System.Windows.Forms.MessageBox]::Show("Could not load the ${Tab}:`n$($_.Exception.Message)", 'Load error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

function Set-TabHybridGating {
    <#
        After an object loads in Edit mode, render its on-prem-mastered fields read-only (with an
        explanatory tooltip) when the object is directory-synced, and colour the target label to
        show the source. No-op for cloud-only objects, so the cloud experience is unchanged.
        P0: shows where edits belong; the actual on-prem write path arrives in P1.
    #>
    param([ValidateSet('User', 'Group')][string]$Tab, $Object)
    $ctx = $script:UI[$Tab]
    $synced = Test-ObjectSynced $Object
    $cap = if ($synced) { Get-AdWriteCapability } else { $null }
    $adAvailable = [bool]($cap -and $cap.Available)
    # On-prem-mastered fields that still can't be routed to AD even when on-prem editing works.
    $adUneditable = @('owners')   # AD groups have no clean multi-owner equivalent (managedBy is single)
    # Scalar fields with no cloud->AD attribute mapping can't be written on-prem either -- keep them
    # read-only rather than letting a synced-object edit be silently discarded on save.
    $adMap = if ($Tab -eq 'User') { Get-CloudToAdAttributeMap } else { Get-CloudToAdGroupAttributeMap }

    foreach ($field in $ctx.Order) {
        $state = Get-FieldHybridState -Attr $field.Attr -Object $Object
        if (-not $state.OnPremMastered) { continue }
        $canAdEdit = $adAvailable -and ($adUneditable -notcontains $field.Attr.Name)
        if ($canAdEdit -and ($field.Attr.Input -in 'Text', 'Multi', 'Choice', 'ExtAttr', 'Date') -and (-not $adMap.ContainsKey($field.Attr.Name))) {
            $canAdEdit = $false   # unmapped scalar (e.g. otherMails) -> not on-prem-writable
        }
        if ($canAdEdit) {
            # Leave the field editable; the save routes this change to on-prem AD.
            if ($field.Main -and $script:UI.Tooltip) {
                $script:UI.Tooltip.SetToolTip($field.Main, 'Synced from AD: this change is written to on-premises Active Directory and syncs up to the cloud.')
            }
        } else {
            Set-FieldReadOnlyForSync -Field $field
            $hint = if ($cap -and $cap.Reason) { "Managed in Active Directory (synced). On-prem editing unavailable: $($cap.Reason)" } else { $state.Hint }
            if ($field.Main -and $script:UI.Tooltip) { $script:UI.Tooltip.SetToolTip($field.Main, $hint) }
        }
    }
    if ($synced) {
        $ctx.TargetLabel.ForeColor = [System.Drawing.Color]::FromArgb(176, 96, 0)   # amber: on-prem-mastered object
    } else {
        $ctx.TargetLabel.ForeColor = (Get-Theme).Muted
    }
}

function Import-UserIntoForm {
    param($User)
    $ctx = $script:UI.User
    $script:State.SelectedUser = $User
    $extContainer = Get-GraphVal $User 'onPremisesExtensionAttributes'

    foreach ($field in $ctx.Order) {
        switch ($field.Kind) {
            'Person' {
                $mgr = Get-UserManagerInfo -Id (Get-GraphVal $User 'id')
                Set-PersonFieldValue -Field $field -People @($mgr | Where-Object { $_ })
                $field.OriginalIds = @($field.People | ForEach-Object { $_.Id })
            }
            'License' {
                $assigned = Get-UserAssignedSkuId -User $User
                Set-LicenseFieldItems -Field $field -Skus (Get-AvailableSku) -AssignedSkuIds $assigned
                $field.OriginalSkuIds = @($assigned)
            }
            'ExtAttr' {
                # Value only; read-only gating for synced users is applied uniformly by
                # Set-TabHybridGating below (extension attributes default to Authority 'OnPrem').
                Set-FieldValue -Field $field -Value (Get-GraphVal $extContainer $field.Attr.Name)
            }
            'Password' { }  # Edit-mode password is a reset button; nothing to prefill.
            default    { Set-FieldValue -Field $field -Value (Get-GraphVal $User $field.Attr.Name) }
        }
        Set-FieldBaseline -Field $field
    }

    Set-TabHybridGating -Tab 'User' -Object $User
    $ctx.TargetLabel.Text = "Editing: $(Get-GraphVal $User 'displayName')  <$(Get-GraphVal $User 'userPrincipalName')>   [$(Get-ObjectSourceLabel $User)]"
    Set-TabActionState -Tab 'User'
    Set-Progress "Loaded user $(Get-GraphVal $User 'userPrincipalName')."
}

function Import-GroupIntoForm {
    param($Group)
    $ctx = $script:UI.Group
    $script:State.SelectedGroup = $Group
    $gid = Get-GraphVal $Group 'id'
    $isUnified = (@(Get-GraphVal $Group 'groupTypes') -contains 'Unified')

    foreach ($field in $ctx.Order) {
        switch ($field.Kind) {
            'GroupType' {
                Set-GroupTypeField -Field $field -Type $(if ($isUnified) { 'Microsoft365' } else { 'Security' }) -Lock
            }
            'Person' {
                $people = if ($field.Attr.Name -eq 'owners') { Get-GroupOwnerInfo -Id $gid } else { Get-GroupMemberInfo -Id $gid }
                Set-PersonFieldValue -Field $field -People $people
                $field.OriginalIds = @($field.People | ForEach-Object { $_.Id })
                $field.OriginalPeople = $field.People.ToArray()   # snapshot for AD membership diff
            }
            default { Set-FieldValue -Field $field -Value (Get-GraphVal $Group $field.Attr.Name) }
        }
        Set-FieldBaseline -Field $field
    }

    Set-TabHybridGating -Tab 'Group' -Object $Group
    $ctx.TargetLabel.Text = "Editing: $(Get-GraphVal $Group 'displayName')  ($(Get-GroupTypeLabel -Group $Group))   [$(Get-ObjectSourceLabel $Group)]"
    Set-TabActionState -Tab 'Group'
    Set-Progress "Loaded group $(Get-GraphVal $Group 'displayName')."
}

#endregion

#region ---------------------------------------------------------------------- Validation + payloads

function Test-FormValid {
    <# Validate all fields via the ErrorProvider; return $true if all pass. #>
    param([ValidateSet('User', 'Group')][string]$Tab)
    $ctx = $script:UI[$Tab]
    $ep = $script:UI.ErrorProvider
    $ep.Clear()
    $firstBad = $null
    foreach ($field in $ctx.Order) {
        $msg = Get-FieldValidationError -Field $field
        if ($msg) {
            $ep.SetError($field.Main, $msg)
            if (-not $firstBad) { $firstBad = $field }
        }
    }
    if ($firstBad) {
        Set-Progress (Get-FieldValidationError -Field $firstBad)
        try { $firstBad.Main.Focus() } catch { }
        return $false
    }
    return $true
}

function ConvertTo-PayloadValue {
    <# Convert a field's current value into the shape the Graph body expects (or $null to clear). #>
    param($Field)
    $v = Read-FieldValue $Field
    switch ($Field.Kind) {
        'Bool'   { return [bool]$v }
        'Multi'  { if (@($v).Count -eq 0) { return $null } else { return @($v) } }
        'Date'   { if ($v) { return ([datetime]$v).ToString('yyyy-MM-ddT00:00:00Z') } else { return $null } }
        'Choice' { if ([string]::IsNullOrEmpty([string]$v)) { return $null } else { return [string]$v } }
        default  { if ([string]::IsNullOrEmpty([string]$v)) { return $null } else { return [string]$v } }
    }
}

function Build-UserPayload {
    <# Body hashtable for create (full) or update (dirty-only). Excludes manager/license/password-reset.
       -ExcludeOnPrem drops on-prem-mastered fields (they are routed to AD for a synced user). #>
    param([ValidateSet('New', 'Edit')][string]$Mode, [switch]$ExcludeOnPrem)
    $ctx = $script:UI.User
    $body = @{}
    $extAttrs = @{}

    foreach ($field in $ctx.Order) {
        $a = $field.Attr
        if (-not $a.Writable) { continue }
        if ($a.Input -in 'Person', 'License') { continue }
        if ($ExcludeOnPrem -and (Resolve-FieldAuthority $a) -eq 'OnPrem') { continue }   # routed to on-prem AD
        if ($a.Input -eq 'Password') {
            if ($Mode -eq 'New') {
                $pw = Read-FieldValue $field
                $body['passwordProfile'] = @{ Password = $pw.Password; ForceChangePasswordNextSignIn = $pw.Force }
            }
            continue
        }

        if ($Mode -eq 'Edit' -and -not (Test-FieldDirty $field)) { continue }

        $val = ConvertTo-PayloadValue $field
        if ($Mode -eq 'New' -and ($null -eq $val -or ($val -is [array] -and $val.Count -eq 0))) { continue }

        if ($a.Input -eq 'ExtAttr') {
            $extAttrs[$a.Name] = $val
        } else {
            $body[$a.Name] = $val
        }
    }

    if ($extAttrs.Count -gt 0) { $body['onPremisesExtensionAttributes'] = $extAttrs }
    return $body
}

function Build-GroupPayload {
    param([ValidateSet('New', 'Edit')][string]$Mode)
    $ctx = $script:UI.Group
    $body = @{}

    # Decide group type once (New: from the radio; Edit: from the loaded object) so the
    # visibility guard below works in BOTH modes -- visibility is a Microsoft 365 concept and
    # must never be sent for a Security group.
    if ($Mode -eq 'New') {
        $typeField = $ctx.Fields['__groupType']
        $type = if ($typeField) { Read-FieldValue $typeField } else { 'Security' }
        if ($type -eq 'Microsoft365') {
            $body['groupTypes'] = @('Unified'); $body['mailEnabled'] = $true; $body['securityEnabled'] = $false
            $isUnified = $true
        } else {
            $body['mailEnabled'] = $false; $body['securityEnabled'] = $true
            $isUnified = $false
        }
    } else {
        $isUnified = (@(Get-GraphVal $script:State.SelectedGroup 'groupTypes') -contains 'Unified')
    }

    foreach ($field in $ctx.Order) {
        $a = $field.Attr
        if (-not $a.Writable) { continue }
        if ($a.Input -in 'Person', 'GroupType') { continue }
        if ($a.Name -eq 'visibility' -and -not $isUnified) { continue }   # M365 groups only
        if ($Mode -eq 'Edit' -and -not (Test-FieldDirty $field)) { continue }
        $val = ConvertTo-PayloadValue $field
        if ($Mode -eq 'New' -and ($null -eq $val -or ($val -is [array] -and $val.Count -eq 0))) { continue }
        $body[$a.Name] = $val
    }
    return $body
}

#endregion

#region ---------------------------------------------------------------------- Save

function Invoke-Save {
    param([ValidateSet('User', 'Group')][string]$Tab)
    if (-not (Test-GraphConnected)) { [System.Windows.Forms.MessageBox]::Show('Connect first.', 'Not connected', 'OK', 'Information') | Out-Null; return }
    if (-not (Test-FormValid -Tab $Tab)) { return }
    Set-UiBusy $true
    try {
        if ($Tab -eq 'User') { Invoke-SaveUser } else { Invoke-SaveGroup }
    } catch {
        Set-Progress 'Save failed.'
        [System.Windows.Forms.MessageBox]::Show("Save failed:`n$($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

function Save-SyncedUserToAd {
    <#
        Write a synced user's dirty on-prem-mastered fields to Active Directory (scalar attributes,
        enable/disable, manager). Returns @{ Changed; Warnings }. Throws if the AD account isn't found.
    #>
    param($Ctx, $User, $Cap)
    $dc = $Cap.Dc
    $adUser = Get-AdUserForCloudObject -Object $User -Dc $dc
    if (-not $adUser) { throw "Couldn't find this user's on-premises AD account (matched by sAMAccountName / distinguishedName). It may live in a different domain than the discovered DC." }
    $changed = $false
    $warnings = New-Object System.Collections.Generic.List[string]

    # Scalar attributes (Text / Multi / ExtAttr / Choice that are on-prem-mastered).
    $changes = New-Object System.Collections.Generic.List[object]
    foreach ($field in $Ctx.Order) {
        $a = $field.Attr
        if (-not $a.Writable) { continue }
        if ($a.Input -in 'Person', 'License', 'Password', 'Bool', 'GroupType') { continue }  # handled below / cloud
        if ((Resolve-FieldAuthority $a) -ne 'OnPrem') { continue }
        if (-not (Test-FieldDirty $field)) { continue }
        [void]$changes.Add(@{ Name = $a.Name; Value = (Read-FieldValue $field) })
    }
    if ($changes.Count -gt 0) {
        $writes = ConvertTo-AdAttributeWrites -Changes $changes.ToArray()
        Set-AdUserScalarAttributes -AdUser $adUser -Dc $dc -Replace $writes.Replace -Clear $writes.Clear
        if (($writes.Replace.Count + $writes.Clear.Count) -gt 0) { $changed = $true }
        foreach ($u in $writes.Unsupported) { [void]$warnings.Add("'$u' has no on-prem mapping and was not written to AD.") }
    }

    # Account enabled -> Enable/Disable-ADAccount.
    $aeField = $Ctx.Fields['accountEnabled']
    if ($aeField -and (Test-FieldDirty $aeField)) {
        Set-AdAccountEnabledState -AdUser $adUser -Dc $dc -Enabled ([bool](Read-FieldValue $aeField)); $changed = $true
    }

    # Manager -> Set-ADUser -Manager (resolved from the picked person's UPN).
    $mgrField = $Ctx.Fields['manager']
    if ($mgrField -and (Test-FieldDirty $mgrField)) {
        $person = $mgrField.People | Select-Object -First 1
        $ok = Set-AdUserManagerFromPerson -AdUser $adUser -Dc $dc -Person $person
        if ($ok) { $changed = $true }
        elseif ($person) { [void]$warnings.Add("Manager '$($person.DisplayName)' wasn't found in AD by UPN; manager not changed on-prem.") }
    }
    return @{ Changed = $changed; Warnings = $warnings.ToArray() }
}

function Save-SyncedGroupToAd {
    <#
        Write a synced group's dirty on-prem-mastered fields to AD (scalar attributes + membership).
        Owners are not routed (no AD multi-owner concept). Returns @{ Changed; Warnings }.
    #>
    param($Ctx, $Group, $Cap)
    $dc = $Cap.Dc
    $adGroup = Get-AdGroupForCloudObject -Object $Group -Dc $dc
    if (-not $adGroup) { throw "Couldn't find this group's on-premises AD object (matched by sAMAccountName / SID)." }
    $changed = $false
    $warnings = New-Object System.Collections.Generic.List[string]

    $gmap = Get-CloudToAdGroupAttributeMap
    $changes = New-Object System.Collections.Generic.List[object]
    foreach ($field in $Ctx.Order) {
        $a = $field.Attr
        if ($a.Input -in 'Person', 'GroupType') { continue }
        if (-not $gmap.ContainsKey($a.Name)) { continue }
        if (-not (Test-FieldDirty $field)) { continue }
        [void]$changes.Add(@{ Name = $a.Name; Value = (Read-FieldValue $field) })
    }
    if ($changes.Count -gt 0) {
        $writes = ConvertTo-AdAttributeWrites -Changes $changes.ToArray() -Map $gmap
        Set-AdGroupScalarAttributes -AdGroup $adGroup -Dc $dc -Replace $writes.Replace -Clear $writes.Clear
        if (($writes.Replace.Count + $writes.Clear.Count) -gt 0) { $changed = $true }
    }

    # Membership -> Add/Remove-ADGroupMember (members only; resolved by UPN).
    $memField = $Ctx.Fields['members']
    if ($memField -and (Test-FieldDirty $memField)) {
        $res = Sync-AdGroupMembership -AdGroup $adGroup -Dc $dc -Now $memField.People -Original $memField.OriginalPeople
        $changed = $true
        foreach ($w in $res.Warnings) { [void]$warnings.Add($w) }
    }
    return @{ Changed = $changed; Warnings = $warnings.ToArray() }
}

function Invoke-SaveUser {
    $ctx = $script:UI.User
    $mode = $ctx.Mode
    $mgrField = $ctx.Fields['manager']
    $licField = $ctx.Fields['assignedLicenses']

    # Guard: assigning a license requires usageLocation.
    if ($licField) {
        $selectedSkus = @(Read-FieldValue $licField)
        $usageField = $ctx.Fields['usageLocation']
        $usage = if ($usageField) { Read-FieldValue $usageField } else { '' }
        $needLicense = if ($mode -eq 'New') { $selectedSkus.Count -gt 0 } else { (Test-FieldDirty $licField) -and $selectedSkus.Count -gt 0 }
        if ($needLicense -and -not $usage) {
            [System.Windows.Forms.MessageBox]::Show('Set a Usage Location before assigning a license.', 'Usage location required', 'OK', 'Warning') | Out-Null
            return
        }
    }

    if ($mode -eq 'New') {
        $body = Build-UserPayload -Mode 'New'
        Set-Progress 'Creating user...'
        $created = New-DirectoryUser -Body $body
        $newId = Get-GraphVal $created 'id'

        if ($mgrField -and (Read-FieldValue $mgrField)) {
            Set-Progress 'Assigning manager...'
            Set-UserManager -Id $newId -ManagerId (Read-FieldValue $mgrField)
        }
        if ($licField) {
            $add = @(Read-FieldValue $licField)
            if ($add.Count -gt 0) { Set-Progress 'Assigning licenses...'; Set-UserLicenseAssignment -Id $newId -AddSkuIds $add }
        }
        Set-Progress "Created user $(Get-GraphVal $created 'userPrincipalName')."
        [System.Windows.Forms.MessageBox]::Show("User created:`n$(Get-GraphVal $created 'userPrincipalName')", 'User created', 'OK', 'Information') | Out-Null

        # Switch to Edit on the new object so further tweaks are dirty-tracked.
        $ctx.ModeEdit.Checked = $true
        Import-UserIntoForm -User (Get-UserById -Id $newId)
        return
    }

    # --- Edit ---
    $user = $script:State.SelectedUser
    $id = Get-GraphVal $user 'id'
    $synced = Test-ObjectSynced $user
    $cap = if ($synced) { Get-AdWriteCapability } else { $null }
    $routeToAd = [bool]($synced -and $cap -and $cap.Available)
    $changed = $false
    $warnings = @()

    if ($routeToAd) {
        # On-prem-mastered fields (name/job/address/ext-attrs/enable/manager) go to Active Directory;
        # cloud-authoritative fields (usageLocation/userType) still go to Graph.
        Set-Progress 'Updating user in Active Directory...'
        $ad = Save-SyncedUserToAd -Ctx $ctx -User $user -Cap $cap
        if ($ad.Changed) { $changed = $true }
        $warnings += $ad.Warnings
        $body = Build-UserPayload -Mode 'Edit' -ExcludeOnPrem
        if ($body.Count -gt 0) { Set-Progress 'Updating cloud attributes...'; Update-DirectoryUser -Id $id -Body $body | Out-Null; $changed = $true }
    } else {
        # Cloud-only user (or synced user with no on-prem access -> on-prem fields are read-only, so
        # nothing on-prem is dirty and only cloud-writable fields reach Graph).
        $body = Build-UserPayload -Mode 'Edit'
        if ($body.Count -gt 0) { Set-Progress 'Updating user...'; Update-DirectoryUser -Id $id -Body $body | Out-Null; $changed = $true }
        if ($mgrField -and (Test-FieldDirty $mgrField)) {
            $newMgr = Read-FieldValue $mgrField
            if ($newMgr) { Set-UserManager -Id $id -ManagerId $newMgr } else { Remove-UserManager -Id $id }
            $changed = $true
        }
    }

    # Licenses are always a cloud operation (valid even for a synced user).
    if ($licField -and (Test-FieldDirty $licField)) {
        $now = @(Read-FieldValue $licField)
        $orig = @($licField.OriginalSkuIds)
        $add = @($now | Where-Object { $orig -notcontains $_ })
        $remove = @($orig | Where-Object { $now -notcontains $_ })
        if ($add.Count -or $remove.Count) { Set-Progress 'Updating licenses...'; Set-UserLicenseAssignment -Id $id -AddSkuIds $add -RemoveSkuIds $remove; $changed = $true }
    }

    if (-not $changed) { Set-Progress 'No changes to save.'; return }
    Set-Progress 'Reloading...'
    Import-UserIntoForm -User (Get-UserById -Id $id)
    $msg = if ($routeToAd) { 'Saved. On-premises changes appear in the cloud after the next directory sync.' } else { 'Changes saved.' }
    if ($warnings.Count) { $msg += "`n`nNotes:`n  " + ($warnings -join "`n  ") }
    Set-Progress "Saved changes to $(Get-GraphVal $user 'userPrincipalName')."
    [System.Windows.Forms.MessageBox]::Show($msg, 'Saved', 'OK', 'Information') | Out-Null
}

function Invoke-SaveGroup {
    $ctx = $script:UI.Group
    $mode = $ctx.Mode
    $memField = $ctx.Fields['members']
    $ownField = $ctx.Fields['owners']

    if ($mode -eq 'New') {
        $body = Build-GroupPayload -Mode 'New'
        Set-Progress 'Creating group...'
        $created = New-DirectoryGroup -Body $body
        $gid = Get-GraphVal $created 'id'

        $failures = @()
        $failures += Add-PeopleToGroup -GroupId $gid -Field $ownField -AsOwner
        $failures += Add-PeopleToGroup -GroupId $gid -Field $memField

        Set-Progress "Created group $(Get-GraphVal $created 'displayName')."
        $cmsg = "Group created:`n$(Get-GraphVal $created 'displayName')"
        if ($failures.Count) { $cmsg += "`n`nBut some members/owners were not added:`n  " + ($failures -join "`n  ") }
        [System.Windows.Forms.MessageBox]::Show($cmsg, $(if ($failures.Count) { 'Group created with warnings' } else { 'Group created' }), 'OK', $(if ($failures.Count) { 'Warning' } else { 'Information' })) | Out-Null
        $ctx.ModeEdit.Checked = $true
        Import-GroupIntoForm -Group (Get-GroupById -Id $gid)
        return
    }

    # --- Edit ---
    $group = $script:State.SelectedGroup
    $gid = Get-GraphVal $group 'id'
    $synced = Test-ObjectSynced $group
    $cap = if ($synced) { Get-AdWriteCapability } else { $null }
    $routeToAd = [bool]($synced -and $cap -and $cap.Available)
    $changed = $false
    $warnings = @()

    if ($routeToAd) {
        # Synced group: scalar attributes + membership go to Active Directory (owners stay read-only).
        Set-Progress 'Updating group in Active Directory...'
        $ad = Save-SyncedGroupToAd -Ctx $ctx -Group $group -Cap $cap
        if ($ad.Changed) { $changed = $true }
        $warnings += $ad.Warnings
    } else {
        # Cloud-only group (or synced group with no on-prem access -> fields read-only, nothing dirty).
        $body = Build-GroupPayload -Mode 'Edit'
        if ($body.Count -gt 0) { Set-Progress 'Updating group...'; Update-DirectoryGroup -Id $gid -Body $body | Out-Null; $changed = $true }
        if ($memField -and (Test-FieldDirty $memField)) { $warnings += Sync-GroupRelationship -GroupId $gid -Field $memField; $changed = $true }
        if ($ownField -and (Test-FieldDirty $ownField)) { $warnings += Sync-GroupRelationship -GroupId $gid -Field $ownField -AsOwner; $changed = $true }
    }

    if (-not $changed) { Set-Progress 'No changes to save.'; return }
    Set-Progress 'Reloading...'
    Import-GroupIntoForm -Group (Get-GroupById -Id $gid)
    $msg = if ($routeToAd) { 'Saved. On-premises changes appear in the cloud after the next directory sync.' } else { 'Changes saved.' }
    if ($warnings.Count) { $msg += "`n`nNotes:`n  " + ($warnings -join "`n  ") }
    Set-Progress "Saved changes to $(Get-GraphVal $group 'displayName')."
    [System.Windows.Forms.MessageBox]::Show($msg, 'Saved', 'OK', 'Information') | Out-Null
}

function Add-PeopleToGroup {
    <# Add all currently-selected people in a Person field to a freshly-created group. Returns any
       per-member failure messages so the caller can surface a partial result (not silently 'saved'). #>
    param([string]$GroupId, $Field, [switch]$AsOwner)
    $failures = New-Object System.Collections.Generic.List[string]
    if (-not $Field) { return $failures.ToArray() }
    # Iterate the List directly -- NEVER @($Field.People): @() over a List of hashtables throws
    # "Argument types do not match" on BOTH Windows PowerShell 5.1 and PowerShell 7.
    foreach ($p in $Field.People) {
        try {
            if ($AsOwner) { Add-GroupOwner -GroupId $GroupId -ObjectId $p.Id } else { Add-GroupMember -GroupId $GroupId -ObjectId $p.Id }
        } catch {
            [void]$failures.Add("Could not add $($p.DisplayName): $($_.Exception.Message)")
        }
    }
    return $failures.ToArray()
}

function Sync-GroupRelationship {
    <# Apply the add/remove diff between a Person field's current and original ids. Returns any
       per-member failure messages so the caller can report a partial result. #>
    param([string]$GroupId, $Field, [switch]$AsOwner)
    $failures = New-Object System.Collections.Generic.List[string]
    $now = @($Field.People | ForEach-Object { $_.Id })
    $orig = @($Field.OriginalIds)
    $add = @($now | Where-Object { $orig -notcontains $_ })
    $remove = @($orig | Where-Object { $now -notcontains $_ })
    foreach ($id in $add) {
        try { if ($AsOwner) { Add-GroupOwner -GroupId $GroupId -ObjectId $id } else { Add-GroupMember -GroupId $GroupId -ObjectId $id } }
        catch { [void]$failures.Add("Add failed: $($_.Exception.Message)") }
    }
    foreach ($id in $remove) {
        try { if ($AsOwner) { Remove-GroupOwner -GroupId $GroupId -ObjectId $id } else { Remove-GroupMember -GroupId $GroupId -ObjectId $id } }
        catch { [void]$failures.Add("Remove failed: $($_.Exception.Message)") }
    }
    return $failures.ToArray()
}

#endregion

#region ---------------------------------------------------------------------- Delete + password reset

function Invoke-Delete {
    param([ValidateSet('User', 'Group')][string]$Tab)
    if ($Tab -eq 'User') {
        $obj = $script:State.SelectedUser
        if (-not $obj) { return }
        $name = [string](Get-GraphVal $obj 'userPrincipalName')
        $what = 'user'
        $note = "The user will be soft-deleted (recoverable for ~30 days)."
    } else {
        $obj = $script:State.SelectedGroup
        if (-not $obj) { return }
        $name = [string](Get-GraphVal $obj 'displayName')
        $what = 'group'
        $note = "Microsoft 365 groups are recoverable for ~30 days; security groups are deleted permanently."
    }

    if (-not (Show-TypedConfirm -Prompt "Delete this $what`?`n`n$note`n`nType the name below to confirm:" -Expected $name)) { return }

    Set-UiBusy $true
    try {
        if ($Tab -eq 'User') { Remove-DirectoryUser -Id (Get-GraphVal $obj 'id') } else { Remove-DirectoryGroup -Id (Get-GraphVal $obj 'id') }
        Set-Progress "Deleted $what '$name'."
        [System.Windows.Forms.MessageBox]::Show("Deleted $what '$name'.", 'Deleted', 'OK', 'Information') | Out-Null
        Set-TabMode -Tab $Tab -Mode 'Edit'   # clears the loaded object
    } catch {
        Set-Progress 'Delete failed.'
        [System.Windows.Forms.MessageBox]::Show("Delete failed:`n$($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

function Invoke-UserPasswordReset {
    <# Called from the Edit-mode Password field's "Reset password..." button. #>
    if (-not $script:State.SelectedUser) { return }
    $user = $script:State.SelectedUser
    $res = Show-PasswordResetDialog -DisplayName (Get-GraphVal $user 'displayName')
    if (-not $res) { return }
    $synced = Test-ObjectSynced $user
    $cap = if ($synced) { Get-AdWriteCapability } else { $null }
    $routeToAd = [bool]($synced -and $cap -and $cap.Available)
    Set-UiBusy $true
    try {
        if ($routeToAd) {
            $adUser = Get-AdUserForCloudObject -Object $user -Dc $cap.Dc
            if (-not $adUser) { throw "Couldn't find this user's on-premises AD account." }
            Reset-AdUserPasswordValue -AdUser $adUser -Dc $cap.Dc -Password $res.Password -ForceChange $res.Force
            Set-Progress "Password reset in AD for $(Get-GraphVal $user 'userPrincipalName')."
            [System.Windows.Forms.MessageBox]::Show('Password reset in Active Directory. It syncs to the cloud at the next directory sync.', 'Done', 'OK', 'Information') | Out-Null
        } else {
            Reset-UserPassword -Id (Get-GraphVal $user 'id') -Password $res.Password -ForceChangeNextSignIn $res.Force
            Set-Progress "Password reset for $(Get-GraphVal $user 'userPrincipalName')."
            [System.Windows.Forms.MessageBox]::Show('Password reset.', 'Done', 'OK', 'Information') | Out-Null
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Password reset failed:`n$($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

#endregion

#region ---------------------------------------------------------------------- Small dialogs

function Show-PasswordResetDialog {
    param([string]$DisplayName)
    $t = Get-Theme
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Reset password"; $dlg.Size = New-Object System.Drawing.Size(430, 210); $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'; $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false; $dlg.Font = $t.FontBase; $dlg.ShowInTaskbar = $false

    $info = New-Object System.Windows.Forms.Label; $info.Text = "New password for $DisplayName"; $info.Location = New-Object System.Drawing.Point(14, 14); $info.AutoSize = $true; $info.Font = $t.FontMedium
    $pwd = New-Object System.Windows.Forms.TextBox; $pwd.Location = New-Object System.Drawing.Point(14, 44); $pwd.Size = New-Object System.Drawing.Size(290, 24); $pwd.UseSystemPasswordChar = $true
    $gen = New-Object System.Windows.Forms.Button; $gen.Text = 'Generate'; $gen.Location = New-Object System.Drawing.Point(312, 43); $gen.Size = New-Object System.Drawing.Size(80, 26)
    Set-SecondaryButtonStyle $gen
    # Plain scriptblock so the handler keeps module affinity and can call New-RandomPassword
    # ($pwd stays in scope because the dialog is modal). A closure would fail on PS 5.1.
    $gen.Add_Click({ $pwd.UseSystemPasswordChar = $false; $pwd.Text = (New-RandomPassword) })
    $force = New-Object System.Windows.Forms.CheckBox; $force.Text = 'Force change at next sign-in'; $force.Checked = $true; $force.AutoSize = $true; $force.Location = New-Object System.Drawing.Point(14, 80)

    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'Reset'; $ok.DialogResult = 'OK'; $ok.Location = New-Object System.Drawing.Point(224, 128); $ok.Size = New-Object System.Drawing.Size(80, 28)
    $cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(312, 128); $cancel.Size = New-Object System.Drawing.Size(80, 28)
    Set-PrimaryButtonStyle $ok; Set-SecondaryButtonStyle $cancel
    $dlg.Controls.AddRange(@($info, $pwd, $gen, $force, $ok, $cancel))
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel

    if ($dlg.ShowDialog() -ne 'OK') { $dlg.Dispose(); return $null }
    $p = $pwd.Text; $f = [bool]$force.Checked
    $dlg.Dispose()
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    return @{ Password = $p; Force = $f }
}

function Show-TypedConfirm {
    <# Destructive-action guard: user must type $Expected exactly to enable OK. Returns bool. #>
    param([string]$Prompt, [string]$Expected)
    $t = Get-Theme
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Confirm'; $dlg.Size = New-Object System.Drawing.Size(460, 230); $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'; $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false; $dlg.Font = $t.FontBase; $dlg.ShowInTaskbar = $false

    $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = $Prompt; $lbl.Location = New-Object System.Drawing.Point(14, 14); $lbl.Size = New-Object System.Drawing.Size(420, 90)
    $box = New-Object System.Windows.Forms.TextBox; $box.Location = New-Object System.Drawing.Point(14, 110); $box.Size = New-Object System.Drawing.Size(420, 24)
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'Delete'; $ok.DialogResult = 'OK'; $ok.Location = New-Object System.Drawing.Point(264, 150); $ok.Size = New-Object System.Drawing.Size(84, 28); $ok.Enabled = $false
    $ok.ForeColor = $t.ErrText
    $cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(352, 150); $cancel.Size = New-Object System.Drawing.Size(84, 28)
    Set-SecondaryButtonStyle $ok; Set-SecondaryButtonStyle $cancel
    $box.Add_TextChanged({ $ok.Enabled = ($box.Text -ceq $Expected) }.GetNewClosure())
    $dlg.Controls.AddRange(@($lbl, $box, $ok, $cancel))
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel

    $result = $dlg.ShowDialog()
    $dlg.Dispose()
    return ($result -eq 'OK')
}

#endregion
