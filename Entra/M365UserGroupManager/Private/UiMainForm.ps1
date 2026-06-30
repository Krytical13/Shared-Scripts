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
    $form.BackColor = $t.AppBg
    $form.ForeColor = $t.Text     # ambient: plain labels inherit light text on the dark theme
    try { $form.Icon = [System.Drawing.SystemIcons]::Application } catch { }

    $tooltip = New-Object System.Windows.Forms.ToolTip
    $errorProvider = New-Object System.Windows.Forms.ErrorProvider
    $errorProvider.BlinkStyle = 'NeverBlink'

    $form.Size = New-Object System.Drawing.Size(1000, 800)
    $form.MinimumSize = New-Object System.Drawing.Size(880, 640)

    # ===== Root: [ left sidebar | content ] =================================================
    $root = New-Object System.Windows.Forms.TableLayoutPanel
    $root.Dock = 'Fill'; $root.ColumnCount = 2; $root.RowCount = 1
    [void]$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, $t.NavW)))
    [void]$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $form.Controls.Add($root)

    # ----- Left sidebar: brand / nav / connection ------------------------------------------
    $nav = New-Object System.Windows.Forms.TableLayoutPanel
    $nav.Dock = 'Fill'; $nav.BackColor = $t.NavBg; $nav.ColumnCount = 1; $nav.RowCount = 9
    $nav.Margin = New-Object System.Windows.Forms.Padding(0)
    [void]$nav.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    foreach ($h in 66, 24, 44, 44, 44, 44, 44) { [void]$nav.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, $h))) }
    [void]$nav.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))   # spacer
    [void]$nav.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))       # connection

    $brand = New-Object System.Windows.Forms.Label
    $brand.Text = 'M365 Manager'; $brand.Dock = 'Fill'; $brand.TextAlign = 'MiddleLeft'; $brand.ForeColor = $t.Brand
    $brand.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 14); $brand.Padding = New-Object System.Windows.Forms.Padding(16, 0, 8, 0)
    $cap = New-Object System.Windows.Forms.Label
    $cap.Text = 'MAIN'; $cap.Dock = 'Fill'; $cap.TextAlign = 'BottomLeft'; $cap.ForeColor = $t.Muted; $cap.Font = $t.FontNavHdr
    $cap.Padding = New-Object System.Windows.Forms.Padding(18, 0, 8, 4)

    $navUser   = New-NavItem -Key 'User'     -Text 'Users'    -Glyph ([char]0xE77B)   # Contact
    $navGroup  = New-NavItem -Key 'Group'    -Text 'Groups'   -Glyph ([char]0xE716)   # People
    $navExch   = New-NavItem -Key 'Exchange' -Text 'Exchange' -Glyph ([char]0xE715)   # Mail
    $navDevice = New-NavItem -Key 'Device'   -Text 'Devices'  -Glyph ([char]0xE977)   # Devices
    $navApprov = New-NavItem -Key 'Approval' -Text 'Approvals' -Glyph ([char]0xE73E)  # CheckMark

    # Connection block, pinned to the sidebar bottom. A "CONNECTION" caption frames it (mirrors MAIN); the
    # on-prem trio is indented to read as sitting UNDER the cloud sign-in; and Settings is detached at the
    # very bottom by a thin separator because it's app config, not a connection action.
    $connPanel = New-Object System.Windows.Forms.TableLayoutPanel
    $connPanel.Dock = 'Fill'; $connPanel.AutoSize = $true; $connPanel.AutoSizeMode = 'GrowAndShrink'
    $connPanel.ColumnCount = 1; $connPanel.RowCount = 9; $connPanel.BackColor = $t.NavBg
    $connPanel.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 14)
    [void]$connPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $connCap = New-Object System.Windows.Forms.Label
    $connCap.Text = 'CONNECTION'; $connCap.AutoSize = $true; $connCap.ForeColor = $t.Muted; $connCap.Font = $t.FontNavHdr
    $connCap.Margin = New-Object System.Windows.Forms.Padding(3, 0, 3, 4)
    $connLabel = New-Object System.Windows.Forms.Label
    $connLabel.Text = "$([char]0x25CB) Not connected"; $connLabel.AutoSize = $true; $connLabel.MaximumSize = New-Object System.Drawing.Size(($t.NavW - 28), 0)
    $connLabel.Font = $t.FontBase; $connLabel.ForeColor = $t.ErrText; $connLabel.Margin = New-Object System.Windows.Forms.Padding(3, 3, 3, 8)
    $connectBtn = New-Object System.Windows.Forms.Button
    $connectBtn.Text = '&Connect'; $connectBtn.Dock = 'Fill'; $connectBtn.Height = $t.BtnHPrimary; $connectBtn.Margin = New-Object System.Windows.Forms.Padding(3, 2, 3, 6)
    $disconnectBtn = New-Object System.Windows.Forms.Button
    $disconnectBtn.Text = 'Dis&connect'; $disconnectBtn.Dock = 'Fill'; $disconnectBtn.Height = $t.BtnH; $disconnectBtn.Enabled = $false; $disconnectBtn.Margin = New-Object System.Windows.Forms.Padding(3, 0, 3, 0)
    # On-prem AD connection -- a SEPARATE connect from the cloud sign-in (the on-prem network is reached by
    # VPN / LAN / RDP, independent of which tenant you're signed into). The label is the second line of the
    # connection banner; both row + button are hidden until the tenant is known hybrid (Update-OnPremUi).
    # Indented left ($t.GapLg) so the trio reads as nested under the cloud sign-in above.
    $onpremLabel = New-Object System.Windows.Forms.Label
    $onpremLabel.Text = ''; $onpremLabel.AutoSize = $true; $onpremLabel.MaximumSize = New-Object System.Drawing.Size(($t.NavW - 28), 0)
    $onpremLabel.Font = $t.FontBase; $onpremLabel.ForeColor = $t.Muted; $onpremLabel.Margin = New-Object System.Windows.Forms.Padding($t.GapLg, 10, 3, 6); $onpremLabel.Visible = $false
    $onpremBtn = New-Object System.Windows.Forms.Button
    $onpremBtn.Text = 'Connect on-&prem AD'; $onpremBtn.Dock = 'Fill'; $onpremBtn.Height = $t.BtnH; $onpremBtn.Visible = $false; $onpremBtn.Margin = New-Object System.Windows.Forms.Padding($t.GapLg, 0, 3, 0)
    # Force a directory sync (hybrid tenants only) -- shown by Update-SyncButtonState when synced.
    $syncBtn = New-Object System.Windows.Forms.Button
    $syncBtn.Text = 'Force AD &sync'; $syncBtn.Dock = 'Fill'; $syncBtn.Height = $t.BtnH; $syncBtn.Visible = $false; $syncBtn.Margin = New-Object System.Windows.Forms.Padding($t.GapLg, 8, 3, 0)
    # Thin separator detaches Settings from the connection actions above it.
    $configSep = New-Object System.Windows.Forms.Panel
    $configSep.Height = 1; $configSep.Dock = 'Fill'; $configSep.BackColor = $t.Border; $configSep.Margin = New-Object System.Windows.Forms.Padding(3, 12, 3, 0)
    # Settings / config (server locations etc.) -- a gear that opens the per-tenant + global config dialog.
    $configBtn = New-Object System.Windows.Forms.Button
    $configBtn.Text = "$([char]0x2699) &Settings"; $configBtn.Dock = 'Fill'; $configBtn.Height = $t.BtnH; $configBtn.Margin = New-Object System.Windows.Forms.Padding(3, 8, 3, 0)
    $connPanel.Controls.Add($connCap, 0, 0)
    $connPanel.Controls.Add($connLabel, 0, 1); $connPanel.Controls.Add($connectBtn, 0, 2); $connPanel.Controls.Add($disconnectBtn, 0, 3)
    $connPanel.Controls.Add($onpremLabel, 0, 4); $connPanel.Controls.Add($onpremBtn, 0, 5); $connPanel.Controls.Add($syncBtn, 0, 6)
    $connPanel.Controls.Add($configSep, 0, 7); $connPanel.Controls.Add($configBtn, 0, 8)

    $nav.Controls.Add($brand, 0, 0); $nav.Controls.Add($cap, 0, 1)
    $nav.Controls.Add($navUser.Row, 0, 2); $nav.Controls.Add($navGroup.Row, 0, 3); $nav.Controls.Add($navExch.Row, 0, 4)
    $nav.Controls.Add($navDevice.Row, 0, 5); $nav.Controls.Add($navApprov.Row, 0, 6)
    $nav.Controls.Add($connPanel, 0, 8)
    $root.Controls.Add($nav, 0, 0)

    # ----- Content: header / page host / status bar ----------------------------------------
    $content = New-Object System.Windows.Forms.TableLayoutPanel
    $content.Dock = 'Fill'; $content.BackColor = $t.AppBg; $content.ColumnCount = 1; $content.RowCount = 3
    [void]$content.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$content.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 58)))
    [void]$content.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$content.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 56)))

    $header = New-Object System.Windows.Forms.Panel; $header.Dock = 'Fill'; $header.BackColor = $t.Surface
    $hdrAccent = New-Object System.Windows.Forms.Panel; $hdrAccent.Dock = 'Bottom'; $hdrAccent.Height = 2; $hdrAccent.BackColor = $t.Brand
    $hdrTitle = New-Object System.Windows.Forms.Label
    $hdrTitle.Text = 'Users'; $hdrTitle.Dock = 'Fill'; $hdrTitle.TextAlign = 'MiddleLeft'; $hdrTitle.Font = $t.FontTitle; $hdrTitle.ForeColor = $t.Text
    $hdrTitle.Padding = New-Object System.Windows.Forms.Padding(20, 0, 12, 0)
    $header.Controls.Add($hdrTitle); $header.Controls.Add($hdrAccent)
    $content.Controls.Add($header, 0, 0)

    $pageHost = New-Object System.Windows.Forms.Panel; $pageHost.Dock = 'Fill'; $pageHost.BackColor = $t.AppBg
    $content.Controls.Add($pageHost, 0, 1)

    $bottom = New-Object System.Windows.Forms.TableLayoutPanel
    $bottom.Dock = 'Fill'; $bottom.ColumnCount = 1; $bottom.RowCount = 2; $bottom.BackColor = $t.SurfaceAlt
    [void]$bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$bottom.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 20)))
    [void]$bottom.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Dock = 'Fill'; $progress.Style = 'Continuous'; $progress.Margin = New-Object System.Windows.Forms.Padding(14, 5, 14, 3); $progress.BackColor = $t.ProgBack
    $status = New-Object System.Windows.Forms.Label
    $status.Dock = 'Fill'; $status.Text = 'Ready. Connect to Microsoft 365 to begin.'; $status.AutoEllipsis = $true
    $status.TextAlign = 'MiddleLeft'; $status.Margin = New-Object System.Windows.Forms.Padding(14, 0, 14, 3); $status.ForeColor = $t.Muted
    $bottom.Controls.Add($progress, 0, 0); $bottom.Controls.Add($status, 0, 1)
    $content.Controls.Add($bottom, 0, 2)
    $root.Controls.Add($content, 1, 0)

    # --- Stash core handles, then build the pages ------------------------------------------
    $script:UI = @{
        Form = $form; Tooltip = $tooltip; ErrorProvider = $errorProvider
        ConnectBtn = $connectBtn; DisconnectBtn = $disconnectBtn; SyncBtn = $syncBtn
        OnPremBtn = $onpremBtn; OnPremLabel = $onpremLabel; ConfigBtn = $configBtn
        ConnLabel = $connLabel; Status = $status; Progress = $progress
        NavPanel = $nav; PageHost = $pageHost; HeaderTitle = $hdrTitle; CurrentPage = 'User'
        NavButtons = @{ User = $navUser.Button; Group = $navGroup.Button; Exchange = $navExch.Button; Device = $navDevice.Button; Approval = $navApprov.Button }
        NavStrips  = @{ User = $navUser.Strip;  Group = $navGroup.Strip;  Exchange = $navExch.Strip;  Device = $navDevice.Strip;  Approval = $navApprov.Strip }
        NavIcons   = @{ User = $navUser.Icon;   Group = $navGroup.Icon;   Exchange = $navExch.Icon;   Device = $navDevice.Icon;   Approval = $navApprov.Icon }
        User = $null; Group = $null; Exchange = $null; Device = $null; Approval = $null
    }

    # Build the pages (Panels now, not TabPages) and stack them in the content host; one shows at a time
    # (Select-NavPage toggles visibility -- only the visible Dock=Fill page claims the space).
    foreach ($p in @((New-EntityTab -Tab 'User' -Title 'Users'), (New-EntityTab -Tab 'Group' -Title 'Groups'), (New-ExchangeTab), (New-DeviceTab), (New-ApprovalsTab))) {
        $p.Dock = 'Fill'; $p.Visible = $false
        $pageHost.Controls.Add($p)
    }
    Update-ExchangeActivation   # show the gated empty-state until Exchange is activated
    Update-DeviceActivation     # show the gated empty-state until connected
    Update-ApprovalsActivation

    # --- Wire nav + connection events ------------------------------------------------------
    foreach ($item in @($navUser, $navGroup, $navExch, $navDevice, $navApprov)) {
        $item.Button.Add_Click({ param($s, $e) Invoke-NavSwitch -Page $s.Tag })
    }
    Set-PrimaryButtonStyle $connectBtn        # the main call-to-action in the sidebar
    Set-SecondaryButtonStyle $disconnectBtn
    Set-SecondaryButtonStyle $onpremBtn
    Set-SecondaryButtonStyle $syncBtn
    Set-SecondaryButtonStyle $configBtn
    $configBtn.Add_Click({ if (Show-ConfigDialog) { Update-SyncButtonState; Update-OnPremUi } })
    $script:UI.Tooltip.SetToolTip($syncBtn, 'Force a Microsoft Entra Connect delta sync and let recent on-prem changes appear in Entra now')
    $connectBtn.Add_Click({ Invoke-Account })
    $disconnectBtn.Add_Click({ Invoke-Disconnect })
    $onpremBtn.Add_Click({ Invoke-ConnectOnPrem })
    $syncBtn.Add_Click({
        Set-UiBusy $true
        try {
            $r = Invoke-ForceDirectorySync
            if ($r.Forced) { [System.Windows.Forms.MessageBox]::Show("A delta sync was started on $($r.Server). Recent changes will appear in Entra shortly.", 'Sync started', 'OK', 'Information') | Out-Null }
        } catch {
            Set-Progress 'Sync failed.'
            [System.Windows.Forms.MessageBox]::Show("Couldn't force a sync:`n$($_.Exception.Message)", 'Sync error', 'OK', 'Error') | Out-Null
        } finally { Set-UiBusy $false }
    })

    Select-NavPage -Page 'User'   # show first page, select its nav item, set header + AcceptButton

    # On open, let the user choose which saved account to connect to (when more than one) instead of
    # silently adopting the last/persisted session. Plain scriptblock keeps module affinity.
    $form.Add_Shown({ Invoke-StartupConnect })

    # If the window is closed mid-operation, flag it so any message-pump loop (the connect setup dialog,
    # the post-create sync poll) unwinds cleanly instead of touching controls that are about to be
    # disposed, and tear down the working dialog when the form is gone.
    $script:UiClosing = $false
    $form.Add_FormClosing({ param($s, $e) $script:UiClosing = $true })
    $form.Add_FormClosed({ param($s, $e) Close-ProgressDialog })

    Set-ControlTheme -Root $form   # dark-theme the input controls (text/combo/list) that don't inherit it
    return $form
}

function New-NavItem {
    <# A left-sidebar nav row: a 3px accent strip + an optional Fluent icon + a full-width flat button.
       Returns @{ Row; Button; Strip; Icon } so Select-NavPage can toggle the selected look. Tag = page key.
       $Glyph is a Segoe MDL2 Assets codepoint; the icon is omitted (text-only) if that font isn't installed. #>
    param([string]$Key, [string]$Text, [string]$Glyph)
    $t = Get-Theme
    $row = New-Object System.Windows.Forms.Panel; $row.Dock = 'Fill'; $row.BackColor = $t.NavBg; $row.Margin = New-Object System.Windows.Forms.Padding(0)
    $strip = New-Object System.Windows.Forms.Panel; $strip.Dock = 'Left'; $strip.Width = 3; $strip.BackColor = $t.NavBg
    $btn = New-Object System.Windows.Forms.Button
    $btn.Dock = 'Fill'; $btn.Text = $Text; $btn.Tag = $Key; $btn.FlatStyle = 'Flat'; $btn.TextAlign = 'MiddleLeft'
    $btn.Font = $t.FontNav; $btn.ForeColor = $t.Muted; $btn.BackColor = $t.NavBg
    $btn.FlatAppearance.BorderSize = 0; $btn.FlatAppearance.MouseOverBackColor = $t.NavSelBg
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $icon = $null
    if ($t.FontIcon -and $Glyph) {
        $icon = New-Object System.Windows.Forms.Label
        $icon.Dock = 'Left'; $icon.Width = 30; $icon.TextAlign = 'MiddleCenter'; $icon.Font = $t.FontIcon
        $icon.Text = $Glyph; $icon.ForeColor = $t.Muted; $icon.BackColor = $t.NavBg
        $btn.Padding = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
        $row.Controls.Add($btn); $row.Controls.Add($icon); $row.Controls.Add($strip)
    } else {
        $btn.Padding = New-Object System.Windows.Forms.Padding(16, 0, 0, 0)
        $row.Controls.Add($btn); $row.Controls.Add($strip)
    }
    return @{ Row = $row; Button = $btn; Strip = $strip; Icon = $icon }
}

function Set-NavItemSelected {
    <# Apply the selected / unselected look to a sidebar nav row (fill + accent strip + icon + text weight). #>
    param([string]$Key, [bool]$Selected)
    $t = Get-Theme
    $btn = $script:UI.NavButtons[$Key]; $strip = $script:UI.NavStrips[$Key]; $icon = $script:UI.NavIcons[$Key]
    if (-not $btn) { return }
    if ($Selected) {
        $btn.BackColor = $t.NavSelBg; $btn.ForeColor = $t.Text; $btn.Font = $t.FontMedium
        $strip.BackColor = $t.Brand
        if ($icon) { $icon.BackColor = $t.NavSelBg; $icon.ForeColor = $t.Brand }
    } else {
        $btn.BackColor = $t.NavBg; $btn.ForeColor = $t.Muted; $btn.Font = $t.FontNav
        $strip.BackColor = $t.NavBg
        if ($icon) { $icon.BackColor = $t.NavBg; $icon.ForeColor = $t.Muted }
    }
}

function Select-NavPage {
    <# Show one content page (User / Group / Exchange), select its nav item, set the header title, and
       re-point the Enter/AcceptButton. Replaces the old TabControl selection. #>
    param([ValidateSet('User', 'Group', 'Exchange', 'Device', 'Approval')][string]$Page)
    if (-not $script:UI) { return }
    $script:UI.CurrentPage = $Page
    foreach ($k in 'User', 'Group', 'Exchange', 'Device', 'Approval') {
        $ctx = $script:UI[$k]
        $pg = if ($ctx) { $ctx.Page } else { $null }
        $sel = ($k -eq $Page)
        if ($pg) { $pg.Visible = $sel; if ($sel) { $pg.BringToFront() } }
        Set-NavItemSelected -Key $k -Selected $sel
    }
    $script:UI.HeaderTitle.Text = switch ($Page) { 'User' { 'Users' } 'Group' { 'Groups' } 'Exchange' { 'Exchange' } 'Device' { 'Devices' } 'Approval' { 'Approvals' } }
    Set-FormAcceptButton
}

function Test-TabDirty {
    <# True if the User/Group tab has unsaved field edits (any enabled field changed vs its loaded /
       initial value). Each tab saves independently -- saving one never saves another, and a nav switch
       saves neither -- so this lets us warn before the tech moves on and forgets pending edits. Only
       meaningful while connected with an interactive form. #>
    param([ValidateSet('User', 'Group')][string]$Tab)
    $ctx = $script:UI[$Tab]
    if (-not $ctx -or -not $ctx.Order) { return $false }
    if (-not (Test-GraphConnected)) { return $false }
    foreach ($field in $ctx.Order) { if (Test-FieldDirty $field) { return $true } }
    return $false
}

function Confirm-LeaveUnsavedChanges {
    <# If the CURRENT User/Group tab has unsaved edits, confirm an action that leaves them. Returns $true
       to proceed, $false to stay. $Consequence tells the operator what happens to the edits. #>
    param([string]$ActionLabel = 'Continue', [string]$Consequence = "Your changes stay in the form but aren't saved.")
    $cur = $script:UI.CurrentPage
    if ($cur -notin 'User', 'Group') { return $true }
    if (-not (Test-TabDirty -Tab $cur)) { return $true }
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "You have unsaved changes on $cur. Saving another tab won't save them, and this won't either. $Consequence`n`n$ActionLabel anyway?",
        'Unsaved changes', 'YesNo', 'Warning')
    return ($ans -eq 'Yes')
}

function Invoke-NavSwitch {
    <# Nav-button click with an unsaved-changes guard. The edits are NOT lost on a tab switch -- they stay
       in the form -- but the operator should know they're unsaved (and that saving the other tab won't
       save them) before moving on. #>
    param([ValidateSet('User', 'Group', 'Exchange', 'Device', 'Approval')][string]$Page)
    if ($script:UI.CurrentPage -eq $Page) { return }
    if (-not (Confirm-LeaveUnsavedChanges -ActionLabel "Switch to $Page")) { return }
    Select-NavPage -Page $Page
}

function New-EntityTab {
    param([ValidateSet('User', 'Group')][string]$Tab, [string]$Title)
    $t = Get-Theme
    $entityWord = if ($Tab -eq 'User') { 'user' } else { 'group' }

    # A content page hosted in the main form's page area (was a TabPage; now a Dock=Fill Panel that the
    # sidebar shows/hides). $Title drives the header text via Select-NavPage, not a tab caption.
    $page = New-Object System.Windows.Forms.Panel
    $page.Dock = 'Fill'; $page.BackColor = $t.Surface; $page.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)

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
    # WrapContents so this busy row reflows onto a second line on a narrow window instead of clipping the
    # trailing controls (e.g. the target label) -- the header host gives it the height it needs.
    $left.Dock = 'Fill'; $left.FlowDirection = 'LeftToRight'; $left.WrapContents = $true
    $modeNew = New-Object System.Windows.Forms.RadioButton; $modeNew.Text = "&New $entityWord"; $modeNew.AutoSize = $true; $modeNew.Checked = $true; $modeNew.Margin = New-Object System.Windows.Forms.Padding(3, 10, 8, 3)
    $modeEdit = New-Object System.Windows.Forms.RadioButton; $modeEdit.Text = '&Edit existing'; $modeEdit.AutoSize = $true; $modeEdit.Margin = New-Object System.Windows.Forms.Padding(3, 10, 12, 3)
    # Surface the progressive-disclosure model at the point of choice (recognition over recall).
    $script:UI.Tooltip.SetToolTip($modeNew, "Create a new $entityWord -- shows just the essentials. Complete the rest in Edit after it's created.")
    $script:UI.Tooltip.SetToolTip($modeEdit, "Modify an existing $entityWord -- shows all the fields you've enabled via Choose fields.")
    # Account type (User tab only): create a Member, or invite an external Guest. These radios MUST
    # live in their own container -- WinForms groups radio buttons by their immediate parent, so
    # putting them in the same panel as New/Edit would make all four one mutually-exclusive group.
    $typePanel = $null; $typeMember = $null; $typeGuest = $null
    if ($Tab -eq 'User') {
        $typePanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $typePanel.AutoSize = $true; $typePanel.AutoSizeMode = 'GrowAndShrink'; $typePanel.FlowDirection = 'LeftToRight'; $typePanel.WrapContents = $false; $typePanel.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 4)
        # Faint tinted card so Member/Guest read as one group distinct from New/Edit (Gestalt > a hairline glyph).
        $typePanel.BackColor = $t.SurfaceAlt; $typePanel.Padding = New-Object System.Windows.Forms.Padding(4, 0, 6, 0)
        # Visible divider (Muted = 5.4:1, not the near-invisible Border at 1.35:1) so the account-type
        # radios read as a separate group from New/Edit -- a perceivable Gestalt boundary (SC 1.4.11).
        $typeSep = New-Object System.Windows.Forms.Label; $typeSep.Text = '|'; $typeSep.AutoSize = $true; $typeSep.ForeColor = $t.Muted; $typeSep.Margin = New-Object System.Windows.Forms.Padding(2, 10, 6, 3)
        $typeMember = New-Object System.Windows.Forms.RadioButton; $typeMember.Text = '&Member'; $typeMember.AutoSize = $true; $typeMember.Checked = $true; $typeMember.Margin = New-Object System.Windows.Forms.Padding(3, 10, 6, 3)
        $typeGuest = New-Object System.Windows.Forms.RadioButton; $typeGuest.Text = '&Guest (invite)'; $typeGuest.AutoSize = $true; $typeGuest.Margin = New-Object System.Windows.Forms.Padding(3, 10, 12, 3)
        $typePanel.Controls.AddRange(@($typeSep, $typeMember, $typeGuest))
    }
    # Create destination (User tab only): a cloud user (Entra, New-MgUser) or an on-prem AD user that
    # syncs up via Entra Connect. Lives as a row at the TOP OF THE FORM (not the header, which has no
    # room) -- shown only for Member + New + when a writable DC is reachable. Own container (radios
    # group by parent). Built here; placed in the form host below.
    $destPanel = $null; $destCloud = $null; $destOnPrem = $null
    if ($Tab -eq 'User') {
        $destPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $destPanel.AutoSize = $true; $destPanel.AutoSizeMode = 'GrowAndShrink'; $destPanel.FlowDirection = 'LeftToRight'; $destPanel.WrapContents = $false
        $destPanel.Margin = New-Object System.Windows.Forms.Padding(4, 6, 18, 2); $destPanel.Padding = New-Object System.Windows.Forms.Padding(4, 2, 4, 2)
        $destLbl = New-Object System.Windows.Forms.Label; $destLbl.Text = 'Create in:'; $destLbl.AutoSize = $true; $destLbl.Font = $t.FontBold; $destLbl.Margin = New-Object System.Windows.Forms.Padding(2, 6, 10, 3)
        $destCloud = New-Object System.Windows.Forms.RadioButton; $destCloud.Text = 'Entra &cloud'; $destCloud.AutoSize = $true; $destCloud.Checked = $true; $destCloud.Margin = New-Object System.Windows.Forms.Padding(3, 5, 10, 3)
        $destOnPrem = New-Object System.Windows.Forms.RadioButton; $destOnPrem.Text = 'On-&premises AD'; $destOnPrem.AutoSize = $true; $destOnPrem.Margin = New-Object System.Windows.Forms.Padding(3, 5, 8, 3)
        $destPanel.Controls.AddRange(@($destLbl, $destCloud, $destOnPrem))
    }
    $selectBtn = New-Object System.Windows.Forms.Button; $selectBtn.Text = "&Select $entityWord..."; $selectBtn.Width = 130; $selectBtn.Height = $t.BtnH; $selectBtn.Visible = $false; $selectBtn.Margin = New-Object System.Windows.Forms.Padding(3, 7, 8, 3)
    Set-SecondaryButtonStyle $selectBtn
    $targetLabel = New-Object System.Windows.Forms.Label; $targetLabel.AutoSize = $true; $targetLabel.Margin = New-Object System.Windows.Forms.Padding(3, 10, 3, 3); $targetLabel.ForeColor = $t.Muted; $targetLabel.Visible = $false
    if ($Tab -eq 'User') {
        $left.Controls.AddRange(@($modeNew, $modeEdit, $typePanel, $selectBtn, $targetLabel))
    } else {
        $left.Controls.AddRange(@($modeNew, $modeEdit, $selectBtn, $targetLabel))
    }

    # Verb-led, outcome-describing label (not the opaque "Fields...") + a tooltip spelling out what it does.
    $settingsBtn = New-Object System.Windows.Forms.Button; $settingsBtn.Text = 'Choose &fields...'; $settingsBtn.Width = 120; $settingsBtn.Height = $t.BtnH; $settingsBtn.Margin = New-Object System.Windows.Forms.Padding(3, 7, 3, 3)
    Set-SecondaryButtonStyle $settingsBtn
    $script:UI.Tooltip.SetToolTip($settingsBtn, 'Choose which attributes appear on the Edit form')
    $header.Controls.Add($left, 0, 0); $header.Controls.Add($settingsBtn, 1, 0)
    $layout.Controls.Add($header, 0, 0)

    # --- Form host: optional OU picker (on-prem create) above the scrollable field grid ----
    $scroll = New-Object System.Windows.Forms.Panel; $scroll.Dock = 'Fill'; $scroll.AutoScroll = $true
    $formHost = New-Object System.Windows.Forms.TableLayoutPanel
    $formHost.Dock = 'Top'; $formHost.AutoSize = $true; $formHost.AutoSizeMode = 'GrowAndShrink'; $formHost.ColumnCount = 1; $formHost.RowCount = 3
    [void]$formHost.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$formHost.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))   # destination toggle
    [void]$formHost.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))   # OU picker
    [void]$formHost.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))   # field grid
    if ($destPanel) { $formHost.Controls.Add($destPanel, 0, 0) }   # visible by default (New + Member); hidden for Guest/Edit

    # OU picker (User tab only) -- shown only for an on-prem create; populated from the writable DC.
    $ouPanel = $null; $ouCombo = $null
    if ($Tab -eq 'User') {
        $ouPanel = New-Object System.Windows.Forms.TableLayoutPanel
        $ouPanel.Dock = 'Fill'; $ouPanel.AutoSize = $true; $ouPanel.AutoSizeMode = 'GrowAndShrink'; $ouPanel.ColumnCount = 2; $ouPanel.RowCount = 2; $ouPanel.Visible = $false
        $ouPanel.BackColor = $t.SurfaceAlt; $ouPanel.Margin = New-Object System.Windows.Forms.Padding(4, 6, 18, 2); $ouPanel.Padding = New-Object System.Windows.Forms.Padding(10, 6, 10, 8)
        [void]$ouPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        [void]$ouPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $ouLbl = New-Object System.Windows.Forms.Label; $ouLbl.Text = 'Target OU *:'; $ouLbl.AutoSize = $true; $ouLbl.Font = $t.FontBold; $ouLbl.Anchor = 'Left'; $ouLbl.Margin = New-Object System.Windows.Forms.Padding(3, 8, 10, 3)
        $ouCombo = New-Object System.Windows.Forms.ComboBox; $ouCombo.DropDownStyle = 'DropDownList'; $ouCombo.Anchor = 'Left,Right'; $ouCombo.Width = 440; $ouCombo.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
        $ouNote = New-Object System.Windows.Forms.Label; $ouNote.Text = "The new user appears in Microsoft 365 only if this OU is within Entra Connect's sync scope. Licenses and usage location are set in the cloud after it syncs."
        $ouNote.AutoSize = $true; $ouNote.MaximumSize = New-Object System.Drawing.Size(640, 0); $ouNote.ForeColor = $t.Muted; $ouNote.Margin = New-Object System.Windows.Forms.Padding(3, 2, 3, 2)
        $ouPanel.Controls.Add($ouLbl, 0, 0); $ouPanel.Controls.Add($ouCombo, 1, 0)
        $ouPanel.Controls.Add($ouNote, 0, 1); $ouPanel.SetColumnSpan($ouNote, 2)
        $formHost.Controls.Add($ouPanel, 0, 1)
    }

    $formTlp = New-Object System.Windows.Forms.TableLayoutPanel
    $formTlp.ColumnCount = 2; $formTlp.AutoSize = $true; $formTlp.AutoSizeMode = 'GrowAndShrink'; $formTlp.Dock = 'Top'
    $formTlp.GrowStyle = 'AddRows'; $formTlp.Padding = New-Object System.Windows.Forms.Padding(4, 6, 18, 6)
    [void]$formTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$formTlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $formHost.Controls.Add($formTlp, 0, 2)
    $scroll.Controls.Add($formHost)
    $layout.Controls.Add($scroll, 0, 1)

    # --- Guest-invite panel (User tab only): a distinct bordered, tinted box shown when "Guest" is
    #     chosen. It shares the form row with the scroll host; the account-type toggle swaps them. ---
    $guestBox = $null; $gEmail = $null; $gName = $null; $gSend = $null; $gUrl = $null
    if ($Tab -eq 'User') {
        $guestBox = New-Object System.Windows.Forms.GroupBox
        $guestBox.Text = ' Guest invitation '; $guestBox.Dock = 'Fill'; $guestBox.Visible = $false
        $guestBox.BackColor = $t.SurfaceAlt; $guestBox.ForeColor = $t.Header
        $guestBox.Margin = New-Object System.Windows.Forms.Padding(4, 6, 18, 6); $guestBox.Padding = New-Object System.Windows.Forms.Padding(14, 8, 14, 12)
        $gtlp = New-Object System.Windows.Forms.TableLayoutPanel
        $gtlp.Dock = 'Top'; $gtlp.ColumnCount = 2; $gtlp.AutoSize = $true; $gtlp.AutoSizeMode = 'GrowAndShrink'
        [void]$gtlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        [void]$gtlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $gIntro = New-Object System.Windows.Forms.Label; $gIntro.Text = 'Invite an external person as a B2B guest. They get a redemption link to access your tenant -- this is not a normal account.'
        $gIntro.AutoSize = $true; $gIntro.MaximumSize = New-Object System.Drawing.Size(620, 0); $gIntro.ForeColor = $t.Text; $gIntro.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 10)
        $gEmailLbl = New-Object System.Windows.Forms.Label; $gEmailLbl.Text = 'Email address *:'; $gEmailLbl.AutoSize = $true; $gEmailLbl.Font = $t.FontBold; $gEmailLbl.ForeColor = $t.Text; $gEmailLbl.Anchor = 'Left'; $gEmailLbl.Margin = New-Object System.Windows.Forms.Padding(3, 8, 10, 3)
        $gEmail = New-Object System.Windows.Forms.TextBox; $gEmail.Anchor = 'Left,Right'; $gEmail.Width = 320; $gEmail.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
        $gNameLbl = New-Object System.Windows.Forms.Label; $gNameLbl.Text = 'Display Name:'; $gNameLbl.AutoSize = $true; $gNameLbl.ForeColor = $t.Text; $gNameLbl.Anchor = 'Left'; $gNameLbl.Margin = New-Object System.Windows.Forms.Padding(3, 8, 10, 3)
        $gName = New-Object System.Windows.Forms.TextBox; $gName.Anchor = 'Left,Right'; $gName.Width = 320; $gName.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
        $gSend = New-Object System.Windows.Forms.CheckBox; $gSend.Text = 'Send the invitation email now'; $gSend.Checked = $true; $gSend.AutoSize = $true; $gSend.ForeColor = $t.Text; $gSend.Margin = New-Object System.Windows.Forms.Padding(3, 8, 3, 4)
        $gUrlLbl = New-Object System.Windows.Forms.Label; $gUrlLbl.Text = 'Redirect URL:'; $gUrlLbl.AutoSize = $true; $gUrlLbl.ForeColor = $t.Text; $gUrlLbl.Anchor = 'Left'; $gUrlLbl.Margin = New-Object System.Windows.Forms.Padding(3, 8, 10, 3)
        $gUrl = New-Object System.Windows.Forms.TextBox; $gUrl.Anchor = 'Left,Right'; $gUrl.Width = 320; $gUrl.Text = 'https://myapplications.microsoft.com'; $gUrl.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
        $gtlp.Controls.Add($gIntro, 0, 0); $gtlp.SetColumnSpan($gIntro, 2)
        $gtlp.Controls.Add($gEmailLbl, 0, 1); $gtlp.Controls.Add($gEmail, 1, 1)
        $gtlp.Controls.Add($gNameLbl, 0, 2); $gtlp.Controls.Add($gName, 1, 2)
        $gtlp.Controls.Add($gSend, 0, 3); $gtlp.SetColumnSpan($gSend, 2)
        $gtlp.Controls.Add($gUrlLbl, 0, 4); $gtlp.Controls.Add($gUrl, 1, 4)
        $guestBox.Controls.Add($gtlp)
        $layout.Controls.Add($guestBox, 0, 1)
    }

    # --- Actions: Save / Reset (left), Delete (right) --------------------------------------
    $actions = New-Object System.Windows.Forms.TableLayoutPanel
    $actions.Dock = 'Fill'; $actions.ColumnCount = 2; $actions.RowCount = 1
    [void]$actions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$actions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $leftActions = New-Object System.Windows.Forms.FlowLayoutPanel; $leftActions.Dock = 'Fill'; $leftActions.FlowDirection = 'LeftToRight'; $leftActions.WrapContents = $false
    # The single primary action is the dominant control: accent fill + widest + a heavier font (so its
    # prominence survives grayscale / colour-blindness, not fill-colour alone). Secondaries share the
    # row height token; the primary stands out on the other three channels.
    $saveBtn = New-Object System.Windows.Forms.Button; $saveBtn.Text = "&Create $entityWord"; $saveBtn.Width = 150; $saveBtn.Height = $t.BtnHPrimary; $saveBtn.Font = $t.FontLarge; $saveBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 6)
    Set-PrimaryButtonStyle $saveBtn
    $resetBtn = New-Object System.Windows.Forms.Button; $resetBtn.Text = '&Reset'; $resetBtn.Width = 84; $resetBtn.Height = $t.BtnHPrimary; $resetBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 6)
    Set-SecondaryButtonStyle $resetBtn
    $backupBtn = New-Object System.Windows.Forms.Button; $backupBtn.Text = '&Backup...'; $backupBtn.Width = 90; $backupBtn.Height = $t.BtnHPrimary; $backupBtn.Margin = New-Object System.Windows.Forms.Padding($t.GapLg, 6, 3, 6); $backupBtn.Enabled = $false
    $restoreBtn = New-Object System.Windows.Forms.Button; $restoreBtn.Text = 'Res&tore...'; $restoreBtn.Width = 90; $restoreBtn.Height = $t.BtnHPrimary; $restoreBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 6)
    Set-SecondaryButtonStyle $backupBtn; Set-SecondaryButtonStyle $restoreBtn
    $leftActions.Controls.AddRange(@($saveBtn, $resetBtn, $backupBtn, $restoreBtn))
    $rightActions = New-Object System.Windows.Forms.FlowLayoutPanel; $rightActions.Dock = 'Fill'; $rightActions.FlowDirection = 'RightToLeft'; $rightActions.WrapContents = $false
    $deleteBtn = New-Object System.Windows.Forms.Button; $deleteBtn.Text = "&Delete $entityWord"; $deleteBtn.Width = 130; $deleteBtn.Height = $t.BtnHPrimary; $deleteBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 6); $deleteBtn.Visible = $false
    Set-DangerButtonStyle $deleteBtn   # red border (affordance survives grayscale), not red text alone
    $rightActions.Controls.Add($deleteBtn)
    $actions.Controls.Add($leftActions, 0, 0); $actions.Controls.Add($rightActions, 1, 0)
    $layout.Controls.Add($actions, 0, 2)

    # --- Disconnected empty-state -----------------------------------------------------------
    # Until connected, cover the form with a centered call-to-action (mirroring the Exchange tab) so
    # the user isn't presented with an editable-but-dead form and a greyed-out Create button with no
    # in-context reason. This panel is also the tab's on-canvas H1 (the top tier of the type scale).
    $overlay = New-Object System.Windows.Forms.TableLayoutPanel
    $overlay.Dock = 'Fill'; $overlay.BackColor = $t.Surface; $overlay.ColumnCount = 1; $overlay.RowCount = 3
    [void]$overlay.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 38)))
    [void]$overlay.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$overlay.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 62)))
    $ovContent = New-Object System.Windows.Forms.FlowLayoutPanel
    $ovContent.FlowDirection = 'TopDown'; $ovContent.WrapContents = $false; $ovContent.AutoSize = $true
    $ovContent.AutoSizeMode = 'GrowAndShrink'; $ovContent.Anchor = 'None'
    $ovTitle = New-Object System.Windows.Forms.Label
    $ovTitle.Text = "Manage $($Title.ToLower())"; $ovTitle.Font = $t.FontLarge; $ovTitle.ForeColor = $t.Header; $ovTitle.AutoSize = $true
    $ovTitle.Margin = New-Object System.Windows.Forms.Padding(3, 3, 3, 6)
    $ovExplain = New-Object System.Windows.Forms.Label
    $ovExplain.Text = "Create a new $entityWord or edit an existing one. Connect to Microsoft 365 to begin."
    $ovExplain.AutoSize = $true; $ovExplain.MaximumSize = New-Object System.Drawing.Size(440, 0); $ovExplain.ForeColor = $t.Muted
    $ovExplain.Margin = New-Object System.Windows.Forms.Padding(3, 0, 3, 14)
    $ovBtn = New-Object System.Windows.Forms.Button
    $ovBtn.Text = 'Connect to Microsoft 365'; $ovBtn.Width = 240; $ovBtn.Height = 38; $ovBtn.Font = $t.FontMedium
    Set-PrimaryButtonStyle $ovBtn
    $ovBtn.Add_Click({ Invoke-Account })
    $ovContent.Controls.AddRange(@($ovTitle, $ovExplain, $ovBtn))
    $overlay.Controls.Add($ovContent, 0, 1)
    $page.Controls.Add($overlay)
    $overlay.BringToFront()

    # --- Stash tab state -------------------------------------------------------------------
    $script:UI[$Tab] = @{
        Page = $page; Mode = 'New'; Overlay = $overlay; ContentLayout = $layout
        ModeNew = $modeNew; ModeEdit = $modeEdit; SelectBtn = $selectBtn; TargetLabel = $targetLabel
        ScrollHost = $scroll; FormTlp = $formTlp
        Fields = @{}; Order = (New-Object System.Collections.Generic.List[object])
        SaveBtn = $saveBtn; ResetBtn = $resetBtn; DeleteBtn = $deleteBtn; SettingsBtn = $settingsBtn
        BackupBtn = $backupBtn; RestoreBtn = $restoreBtn
        TypePanel = $typePanel; TypeMember = $typeMember; TypeGuest = $typeGuest
        GuestBox = $guestBox; GuestEmail = $gEmail; GuestName = $gName; GuestSend = $gSend; GuestUrl = $gUrl
        DestPanel = $destPanel; DestCloud = $destCloud; DestOnPrem = $destOnPrem
        OuPanel = $ouPanel; OuCombo = $ouCombo
        CurrentKind = 'Security'   # Group tab: which kind's view is showing (driven by the GroupType radio / loaded group)
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
    if ($Tab -eq 'User') {
        $typeMember.Add_CheckedChanged({ param($s, $e) if ($s.Checked) { Set-UserAccountType -Type 'Member' } })
        $typeGuest.Add_CheckedChanged({ param($s, $e) if ($s.Checked) { Set-UserAccountType -Type 'Guest' } })
        $destCloud.Add_CheckedChanged({ param($s, $e) if ($s.Checked) { Set-UserCreateDestination -Destination 'Cloud' } })
        $destOnPrem.Add_CheckedChanged({ param($s, $e) if ($s.Checked) { Set-UserCreateDestination -Destination 'OnPrem' } })
    }

    Build-TabForm -Tab $Tab
    # Initialize the create-destination view (User): On-prem disabled until connected; cloud fields shown.
    if ($Tab -eq 'User') { Set-UserCreateDestination -Destination 'Cloud' }
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
        # New (create) mode shows a CURATED set -- the ShowOnNew fields plus everything required to
        # create -- so the new-hire form stays focused. Edit mode shows the Settings-enabled set
        # (you complete the rest after the auto-switch to Edit on create).
        $attrs = @($group.Attributes | Where-Object {
                if ($ctx.Mode -eq 'New') { $_.ShowOnNew -or $_.Required -or $_.RequiredForCreate }
                else { $enabled -contains $_.Name }
            })
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
            $hdr.Font = $t.FontSection   # a clear step above the 9pt field labels (was 9.5, nearly identical)
            $hdr.ForeColor = $t.Header
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

    # New group: typing the Display Name auto-fills the M365 email alias (mailNickname); the alias box
    # gets a read-only "@<default domain>" suffix (the domain is not selectable via Graph -- it derives
    # from the tenant default accepted domain). Then apply the reactive kind view for the default radio.
    if ($Tab -eq 'Group' -and $ctx.Mode -eq 'New') {
        $dn = $ctx.Fields['displayName']
        if ($dn -and $dn.Main) {
            $dn.Main.Add_TextChanged({ Update-NewGroupGeneratedFields })
        }
        $aliasF = $ctx.Fields['mailNickname']
        if ($aliasF -and $aliasF.Cell -and -not $aliasF.Aux) {
            # Wrap the plain alias TextBox in a 2-col cell so we can append the read-only domain suffix,
            # without introducing a new Input type. The TextBox stays $field.Main (Read/Set unchanged).
            # NB: for a Text field $field.Cell IS the textbox, so capture its grid position BEFORE
            # reparenting it (Controls.Add reparents, which would make GetCellPosition return (-1,-1)
            # and the composite cell land at the wrong spot -- the layout bug this replaces).
            $tb = $aliasF.Main
            $pos = $tlp.GetCellPosition($tb)
            $colSpan = $tlp.GetColumnSpan($tb)
            $tlp.Controls.Remove($tb)
            $cell = New-CellTable -Cols 2 -Rows 1 -Height 30
            Add-ColumnStyle $cell 'Percent' 100; Add-ColumnStyle $cell 'AutoSize'
            Add-RowStyle $cell 'Percent' 100
            $cell.Margin = New-Object System.Windows.Forms.Padding(0)
            $tb.Dock = 'Fill'; $tb.Anchor = 'Left,Right'
            $suffix = New-Object System.Windows.Forms.Label
            $suffix.AutoSize = $true; $suffix.Anchor = 'Left'; $suffix.ForeColor = $t.Muted
            $suffix.Margin = New-Object System.Windows.Forms.Padding(4, 8, 3, 3)
            $cell.Controls.Add($tb, 0, 0); $cell.Controls.Add($suffix, 1, 0)
            $tlp.Controls.Add($cell, $pos.Column, $pos.Row)
            if ($colSpan -gt 1) { $tlp.SetColumnSpan($cell, $colSpan) }
            $aliasF.Cell = $cell
            $aliasF.Aux = $suffix
            $tb.Add_TextChanged({ Update-NewGroupGeneratedFields })
        }
        # Apply the initial kind view (Security is the default radio): hides alias + visibility.
        $typeF = $ctx.Fields['__groupType']
        $initialKind = if ($typeF) { Read-FieldValue $typeF } else { 'Security' }
        Set-GroupKindView -Kind $initialKind
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
    Set-ControlTheme -Root $tlp     # dark-theme the freshly (re)built field controls
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

function Update-NewGroupGeneratedFields {
    <# New-group convenience: derive the M365 email alias (mailNickname) from the Display Name, and keep
       the read-only "@<default domain>" preview in sync. Auto-fill stops once the operator edits the
       alias (Set-AutoField). For a Security group the alias box is hidden; the value is regenerated at
       save time by Build-GroupPayload, so nothing here is wasted. #>
    $ctx = $script:UI.Group
    if (-not $ctx -or $ctx.Mode -ne 'New') { return }
    $g = $ctx.Fields
    $display = if ($g.ContainsKey('displayName') -and $g['displayName']) { [string](Read-FieldValue $g['displayName']) } else { '' }
    $alias = Get-GeneratedGroupAlias -DisplayName $display
    if ($g.ContainsKey('mailNickname')) { Set-AutoField -Field $g['mailNickname'] -Value $alias }
    Set-GroupAliasDomainPreview
}

function Set-UserAccountType {
    <# Toggle the User-New view between Member (the create form) and Guest (the invitation box). #>
    param([ValidateSet('Member', 'Guest')][string]$Type)
    $ctx = $script:UI.User
    if (-not $ctx -or -not $ctx.GuestBox) { return }
    $isGuest = ($Type -eq 'Guest')
    $ctx.ScrollHost.Visible = -not $isGuest
    $ctx.GuestBox.Visible = $isGuest
    # Backup/Restore apply to the member-create form, not to a guest invite.
    $ctx.BackupBtn.Visible = -not $isGuest
    $ctx.RestoreBtn.Visible = -not $isGuest
    # "Create in: cloud / on-prem" applies to a NEW Member only -- Guest is a cloud B2B invite, and EDIT
    # has no create destination (showing it there is wrong; Set-TabMode hides it but used to call us right
    # after, which re-showed it). Gate on New mode so Edit never displays the destination row.
    $showDest = (-not $isGuest) -and ($ctx.Mode -eq 'New')
    if ($ctx.DestPanel) { $ctx.DestPanel.Visible = $showDest }
    if (-not $showDest -and $ctx.OuPanel) { $ctx.OuPanel.Visible = $false }
    if ($isGuest) {
        $ctx.SaveBtn.Text = '&Send invite'
    } elseif ($showDest) {
        # Re-apply the destination view (Save text + OU picker + cloud-field gating). Drives off the radio
        # so a previously-chosen On-prem persists across toggles.
        Set-UserCreateDestination -Destination $(if ($ctx.DestOnPrem -and $ctx.DestOnPrem.Checked) { 'OnPrem' } else { 'Cloud' })
    }
    # Edit + Member: leave the Save button text to Build-TabForm ('&Save changes').
}

function Initialize-OuPicker {
    <# Populate the on-prem OU dropdown from the writable DC: the default Users container first, then the
       enumerated OUs; preselect the persisted last-used OU if it still exists. If nothing comes back
       (DC dropped / no OUs), disable on-prem and fall back to Cloud rather than offering an empty list. #>
    $ctx = $script:UI.User
    if (-not $ctx -or -not $ctx.OuCombo) { return }
    $cap = Get-AdWriteCapability -ExpectedDomain (Get-ConnectedTenantOnPremDomain)
    if (-not ($cap -and $cap.Available)) { return }
    Set-Progress 'Loading organizational units from Active Directory...'
    $items = New-Object System.Collections.Generic.List[object]
    $def = Get-AdDefaultUserPath -Dc $cap.Dc
    if ($def) { [void]$items.Add([pscustomobject]@{ Display = "Users (default container) -- $def"; Dn = $def }) }
    foreach ($ou in (Get-AdOrganizationalUnitList -Dc $cap.Dc)) { [void]$items.Add([pscustomobject]@{ Display = $ou.DistinguishedName; Dn = $ou.DistinguishedName }) }
    if ($items.Count -eq 0) {
        $ctx.DestOnPrem.Enabled = $false; $ctx.DestCloud.Checked = $true
        [System.Windows.Forms.MessageBox]::Show('No organizational units could be read from Active Directory, so an on-prem create is not available right now.', 'On-premises AD', 'OK', 'Warning') | Out-Null
        return
    }
    $ctx.OuCombo.Items.Clear()
    foreach ($i in $items) { [void]$ctx.OuCombo.Items.Add($i) }
    $ctx.OuCombo.DisplayMember = 'Display'; $ctx.OuCombo.ValueMember = 'Dn'
    $last = Get-TenantProfileValue -Field 'LastOnPremOuDn'
    $idx = 0
    if ($last) { for ($n = 0; $n -lt $items.Count; $n++) { if ($items[$n].Dn -eq $last) { $idx = $n; break } } }
    $ctx.OuCombo.SelectedIndex = $idx
}

function Set-CreateDestinationFields {
    <# Show/hide the cloud-only fields (license / usage location -- can't be set until the account exists
       in Entra) for the chosen create destination, and label the create button. DestHidden records the
       decision so Get-FieldValidationError skips hidden fields and the offline harness can assert it. #>
    param([bool]$OnPrem)
    $ctx = $script:UI.User
    foreach ($field in $ctx.Order) {
        if ((Resolve-FieldAuthority $field.Attr) -ne 'Cloud') { continue }
        if ($field.Label) { $field.Label.Visible = -not $OnPrem }
        if ($field.Cell)  { $field.Cell.Visible = -not $OnPrem }
        $field.DestHidden = $OnPrem
    }
    $ctx.SaveBtn.Text = if ($OnPrem) { '&Create in AD' } else { '&Create user' }
}

function Set-UserCreateDestination {
    <#
        New-user Member: route the create to Entra cloud (New-MgUser) or on-premises AD (New-AdUserAccount,
        which Entra Connect then syncs up). On-prem reveals the OU picker and HIDES the cloud-only fields.

        PERF: the On-prem availability check (RSAT module import + writable-DC discovery) is DEFERRED until
        the operator actually selects On-prem. It previously ran on every Cloud default and every mode
        switch, freezing the UI thread on a hybrid box for work most sessions never need. The Cloud path
        below makes no AD call; the probe runs only on explicit intent, behind the working dialog.
    #>
    param([ValidateSet('Cloud', 'OnPrem')][string]$Destination)
    $ctx = $script:UI.User
    if (-not $ctx -or -not $ctx.DestPanel) { return }

    if ($Destination -eq 'Cloud') {
        $connected = [bool](Test-GraphConnected)
        $ctx.DestOnPrem.Enabled = $connected     # clickable when connected; the AD check runs on selection
        $script:UI.Tooltip.SetToolTip($ctx.DestOnPrem,
            $(if ($connected) { 'Create the user in on-premises AD instead -- availability is checked when you select this.' }
              else { 'Connect first to create an on-premises user.' }))
        $ctx.CurrentDest = 'Cloud'
        if ($ctx.OuPanel) { $ctx.OuPanel.Visible = $false }
        Set-CreateDestinationFields -OnPrem $false
        return
    }

    # On-prem selected -> probe AD now (deliberate intent), behind the working dialog so the RSAT import
    # + DC discovery isn't a silent freeze. Result is cached in $script:AdState, so re-selecting is instant.
    $cap = Invoke-WithProgress -Title 'On-premises Active Directory' -Work {
        Set-Progress 'Checking on-premises Active Directory availability...'
        Get-AdWriteCapability -ExpectedDomain (Get-ConnectedTenantOnPremDomain)
    }
    Update-OnPremUi   # reflect the probe result in the sidebar on-prem row
    if (-not ($cap -and $cap.Available)) {
        $ctx.DestCloud.Checked = $true           # CheckedChanged re-enters as Cloud (the cheap path)
        [System.Windows.Forms.MessageBox]::Show(
            ("On-premises Active Directory isn't available from this workstation right now:`n`n" +
             "$(if ($cap) { $cap.Reason } else { 'Unknown error.' })`n`nThe user will be created in the cloud instead."),
            'On-premises AD', 'OK', 'Information') | Out-Null
        return
    }
    $ctx.CurrentDest = 'OnPrem'
    if ($ctx.OuPanel) {
        $ctx.OuPanel.Visible = $true
        if ($ctx.OuCombo.Items.Count -eq 0) {
            Invoke-WithProgress -Title 'On-premises Active Directory' -Work { Initialize-OuPicker }
        }
    }
    Set-CreateDestinationFields -OnPrem $true
}

function Get-GeneratedGroupAlias {
    <# Pure: derive a Graph-legal mailNickname from a display name -- lowercase, ASCII letters/digits
       and . - _ only (everything else stripped), trimmed of leading/trailing dots, capped at 64.
       Mirrors Get-GeneratedUserNames' alias rule. Graph requires mailNickname for EVERY group, so
       for a Security group (where the portal hides the alias) the payload builder fills it from here. #>
    param([string]$DisplayName)
    $a = ((([string]$DisplayName) -replace '[^A-Za-z0-9.\-_]', '').ToLower()).Trim('.')
    if ($a.Length -gt 64) { $a = $a.Substring(0, 64) }
    return $a
}

function Set-GroupAliasDomainPreview {
    <# Show the resulting SMTP preview ("alias@<default verified domain>") next to the M365 email-alias
       box, READ-ONLY. Per the create-group docs the domain is NOT selectable via Graph -- it derives
       from the tenant's default accepted domain (so we deliberately show a preview, not a misleading
       editable domain dropdown like the user UPN control). Best-effort: blank if no domain is known yet. #>
    $ctx = $script:UI.Group
    $f = $ctx.Fields['mailNickname']
    if (-not $f -or -not $f.Aux) { return }
    $alias = [string](Read-FieldValue $f)
    $dom = Get-DefaultVerifiedDomain
    $f.Aux.Text = if ($alias -and $dom) { "@$dom" } elseif ($dom) { "@$dom" } else { '' }
}

function Set-GroupKindView {
    <#
        Reactively show/hide + (de)require the kind-specific Group fields for the given kind.
        - Microsoft365: show mailNickname (editable alias + domain preview) and visibility.
        - Security:     hide both; mailNickname is auto-generated by Build-GroupPayload, visibility
                        is an M365-only concept and is never sent.
        Toggling Visible on each field's Label + Cell is enough: a hidden field's RequiredForCreate is
        skipped by Test-FormValid via Get-FieldValidationError, which we also gate on AppliesToGroupKind.
        Used in New mode (driven by the radio) AND in Edit mode (driven by the loaded group's kind).
    #>
    param([ValidateSet('Security', 'Microsoft365')][string]$Kind)
    $ctx = $script:UI.Group
    if (-not $ctx) { return }
    $ctx.CurrentKind = $Kind
    foreach ($field in $ctx.Order) {
        $applies = $field.Attr.AppliesToGroupKind
        if (-not $applies) { continue }                 # field applies to both kinds -- leave it
        $show = ($applies -eq $Kind)
        if ($field.Label) { $field.Label.Visible = $show }
        if ($field.Cell)  { $field.Cell.Visible = $show }
        # Record the requested visibility on the descriptor. Control.Visible reports EFFECTIVE
        # visibility (always false on a not-yet-shown / overlay-covered form), so the offline harness
        # asserts this flag instead -- it reflects what the kind view actually decided.
        $field.KindShown = $show
    }
    # Keep displayName driving the alias preview while we're showing the M365 alias.
    if ($Kind -eq 'Microsoft365') { Set-GroupAliasDomainPreview }
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
    # Member/Guest + Create-in (cloud/on-prem) only apply to creating a User; show them in New mode, and
    # always return to Member + Cloud on a mode switch (create-destination is a create-time concept).
    if ($Tab -eq 'User' -and $ctx.TypePanel) {
        $ctx.TypePanel.Visible = ($Mode -eq 'New')
        if ($ctx.DestPanel) {
            $ctx.DestPanel.Visible = ($Mode -eq 'New')
            if ($ctx.DestCloud) { $ctx.DestCloud.Checked = $true }
            if ($ctx.OuPanel) { $ctx.OuPanel.Visible = $false }
        }
        $ctx.TypeMember.Checked = $true
        Set-UserAccountType -Type 'Member'
    }
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
    # Show the connect call-to-action until connected; reveal the form once connected. Toggle BOTH
    # (not just the overlay): two simultaneously-visible Dock=Fill siblings starve each other for
    # space, so exactly one is shown at a time -- the same pattern the Exchange tab uses.
    if ($ctx.Overlay -and $ctx.ContentLayout) {
        $ctx.Overlay.Visible = -not $connected
        $ctx.ContentLayout.Visible = $connected
        if (-not $connected) { $ctx.Overlay.BringToFront() }
    }
}

function Set-FormAcceptButton {
    <# Make Enter commit the active page's primary action -- matching every dialog in the app (Nielsen #4
       Consistency + the Windows convention). A disabled primary (e.g. before connect) does nothing on
       Enter; multiline fields keep Enter (AcceptsReturn = true) so they aren't hijacked. #>
    if (-not $script:UI -or -not $script:UI.Form) { return }
    $btn = switch ($script:UI.CurrentPage) {
        'User'     { $script:UI.User.SaveBtn }
        'Group'    { $script:UI.Group.SaveBtn }
        'Exchange' { if ($script:UI.Exchange) { $script:UI.Exchange.SaveBtn } else { $null } }
        'Device'   { $null }   # an action page (destructive) -- Enter must never trigger a delete
        'Approval' { $null }   # action page -- Enter must not trigger approve/reject
        default    { $null }
    }
    $script:UI.Form.AcceptButton = $btn
}

#endregion

#region ---------------------------------------------------------------------- Connection

function Update-ConnectionLabel {
    $ctx = Get-GraphContextSafe
    $t = Get-Theme
    if ($ctx) {
        $domain = Get-TenantDomainHint -Context $ctx
        # Glyph (filled vs hollow) carries the state in a non-colour channel (SC 1.4.1 Use of Colour).
        $script:UI.ConnLabel.Text = "$([char]0x25CF) Connected: $($ctx.Account)  [$domain]"
        $script:UI.ConnLabel.ForeColor = $t.OkText
        $script:UI.ConnLabel.BackColor = $t.OkBack
        $script:UI.ConnectBtn.Text = '&Switch account...'
        $script:UI.DisconnectBtn.Enabled = $true
    } else {
        $script:UI.ConnLabel.Text = "$([char]0x25CB) Not connected"
        $script:UI.ConnLabel.ForeColor = $t.ErrText
        $script:UI.ConnLabel.BackColor = $t.ErrBack
        $script:UI.ConnectBtn.Text = '&Connect'
        $script:UI.DisconnectBtn.Enabled = $false
    }
    Update-OnPremUi          # second banner line: on-prem AD state (hybrid only); reads cached state, no probe
    Update-SyncButtonState   # force-sync visibility/label keyed to hybrid + the per-tenant Connect server
    Set-TabActionState -Tab 'User'
    Set-TabActionState -Tab 'Group'
}

function Get-OnPremUiState {
    <#
        On-prem AD connection status for the CONNECTED tenant, derived from the CACHED capability (never
        probes). Drives the sidebar on-prem row + the field gating. States:
          CloudOnly    - not connected, or the tenant isn't hybrid (no on-prem row)
          NotConnected - hybrid, but the operator hasn't connected on-prem yet
          Connected    - connected + verified to the tenant's on-prem domain
          WrongNetwork - a DC answered, but in a DIFFERENT forest than this tenant (e.g. local LAN, other VPN down)
          Unreachable  - no DC for the expected domain answered (VPN/RDP not up)
          NoRsat       - the RSAT ActiveDirectory module isn't installed here
    #>
    if (-not (Test-GraphConnected) -or -not (Get-CachedTenantHybridState)) { return @{ State = 'CloudOnly' } }
    $st = Get-AdState
    $expected = Get-ConnectedTenantOnPremDomain
    if (-not $st.Checked) { return @{ State = 'NotConnected'; Expected = $expected } }
    if ($st.Available)    { return @{ State = 'Connected'; Domain = $st.DcDomain; Dc = $st.Dc; Expected = $expected } }
    if ($st.Reason -match 'RSAT') { return @{ State = 'NoRsat'; Reason = $st.Reason; Expected = $expected } }
    if ($st.DcDomain)     { return @{ State = 'WrongNetwork'; Domain = $st.DcDomain; Expected = $expected; Reason = $st.Reason } }
    return @{ State = 'Unreachable'; Expected = $expected; Reason = $st.Reason }
}

function Update-OnPremUi {
    <# Paint the sidebar on-prem row from the current (cached) state -- the second line of the connection
       banner. No probe; the explicit Connect button is what probes. Hidden for cloud-only tenants. #>
    if (-not $script:UI -or -not $script:UI.OnPremLabel) { return }
    $t = Get-Theme
    $s = Get-OnPremUiState
    $hybrid = ($s.State -ne 'CloudOnly')
    $script:UI.OnPremLabel.Visible = $hybrid
    $script:UI.OnPremBtn.Visible = $hybrid
    if (-not $hybrid) { return }
    $dot = [char]0x25CF; $hollow = [char]0x25CB
    $expectedTxt = if ($s.Expected) { $s.Expected } else { 'this tenant' }
    switch ($s.State) {
        'Connected'    { $script:UI.OnPremLabel.Text = "$dot On-prem AD: $($s.Domain)"; $script:UI.OnPremLabel.ForeColor = $t.OkText;   $script:UI.OnPremBtn.Text = 'Recon&nect on-prem'; $tip = "Connected to $($s.Domain) via $($s.Dc). On-prem edits for this tenant's synced objects are enabled." }
        'NotConnected' { $script:UI.OnPremLabel.Text = "$hollow On-prem AD: not connected"; $script:UI.OnPremLabel.ForeColor = $t.Muted;  $script:UI.OnPremBtn.Text = 'Connect on-&prem AD'; $tip = "Connect to $expectedTxt's on-premises Active Directory to edit synced objects (you may need VPN/RDP to that network)." }
        'WrongNetwork' { $script:UI.OnPremLabel.Text = "$hollow On-prem AD: wrong network"; $script:UI.OnPremLabel.ForeColor = $t.WarnText; $script:UI.OnPremBtn.Text = 'Retr&y on-prem'; $tip = $s.Reason }
        'Unreachable'  { $script:UI.OnPremLabel.Text = "$hollow On-prem AD: not reachable"; $script:UI.OnPremLabel.ForeColor = $t.WarnText; $script:UI.OnPremBtn.Text = 'Connect on-&prem AD'; $tip = $s.Reason }
        'NoRsat'       { $script:UI.OnPremLabel.Text = "$hollow On-prem AD: RSAT not installed"; $script:UI.OnPremLabel.ForeColor = $t.WarnText; $script:UI.OnPremBtn.Text = 'Connect on-&prem AD'; $tip = $s.Reason }
    }
    if ($script:UI.Tooltip) { $script:UI.Tooltip.SetToolTip($script:UI.OnPremLabel, $tip); $script:UI.Tooltip.SetToolTip($script:UI.OnPremBtn, $tip) }
}

function Update-SyncButtonState {
    <# Force-sync button: visible for a hybrid tenant, labelled with the per-tenant Connect server so the
       operator can see WHICH server/tenant it targets (the server name comes from the cloud or the saved
       per-tenant value; WinRM reachability is enforced at click time with a bounded timeout). #>
    if (-not $script:UI -or -not $script:UI.SyncBtn) { return }
    $hybrid = [bool](Test-GraphConnected) -and [bool](Get-CachedTenantHybridState)
    $script:UI.SyncBtn.Visible = $hybrid
    if (-not $hybrid) { return }
    $server = Get-TenantProfileValue -Field 'ConnectServer'
    $script:UI.SyncBtn.Text = if ($server) { "Force AD &sync ($server)" } else { 'Force AD &sync' }
}

function Invoke-ConnectOnPrem {
    <# Explicit "Connect on-prem AD" action: probe the connected tenant's on-prem AD (scoped to its
       expected domain), update the sidebar + re-gate the loaded object, and -- on a cold start where the
       domain isn't known yet -- confirm the discovered domain before trusting it. #>
    if ($script:UI.Busy) { return }
    Set-UiBusy $true
    try {
        $expected = Get-ConnectedTenantOnPremDomain
        $cap = Invoke-WithProgress -Title 'Connect on-premises AD' -Work {
            Set-Progress 'Connecting to on-premises Active Directory...'
            Get-AdWriteCapability -ExpectedDomain $expected -Force
        }
        if ($script:UiClosing) { return }   # window closed mid-connect -> don't touch UI
        if ($cap.Available -and -not $expected) {
            # Cold start: discovery was unscoped (possibly the workstation's own forest) -> require the
            # operator to TYPE the domain before trusting it as this tenant's AD.
            if (Confirm-OnPremDomain -Domain $cap.DcDomain) {
                if ($cap.DcDomain) { Set-TenantProfileValue -Field 'ExpectedOnPremDomain' -Value $cap.DcDomain }
            } else {
                Reset-AdState   # declined -> un-trust the unscoped result
            }
        }
        Update-OnPremUi
        $st = Get-AdState
        # Re-IMPORT the loaded object (not just re-gate) so its fields are rebuilt and the on-prem-mastered
        # ones flip from read-only to editable now that we're connected (re-gating alone wouldn't un-lock them).
        if ($script:UI.User.Mode  -eq 'Edit' -and $script:State.SelectedUser)  { Import-UserIntoForm  -User  $script:State.SelectedUser }
        if ($script:UI.Group.Mode -eq 'Edit' -and $script:State.SelectedGroup) { Import-GroupIntoForm -Group $script:State.SelectedGroup }
        if ($st.Available) {
            Set-Progress "On-premises AD connected: $($st.DcDomain)."
        } else {
            Set-Progress 'On-premises AD not connected.'
            if ($st.Reason) { [System.Windows.Forms.MessageBox]::Show($st.Reason, 'On-premises AD', 'OK', 'Information') | Out-Null }  # empty reason = cold-start cancel -> no dialog
        }
    } catch {
        if (-not $script:UiClosing) { [System.Windows.Forms.MessageBox]::Show("Couldn't connect on-premises AD:`n$($_.Exception.Message)", 'On-premises AD', 'OK', 'Error') | Out-Null }
    } finally { Set-UiBusy $false }
}

function Sync-ConnectionUi {
    <# Refresh all connection-dependent UI to the ACTUAL current Graph state. Safe after any
       connect/switch/disconnect attempt -- success OR failure. When the attempt left us disconnected
       (e.g. a cancelled sign-in, since "sign in new" must disconnect first to show the chooser), it
       also clears the loaded object + hybrid/SKU caches so a stale selection can't linger behind a
       label that wrongly says "Connected". #>
    if (-not (Test-GraphConnected)) {
        $script:State.SelectedUser = $null
        $script:State.SelectedGroup = $null
        Reset-HybridState
        Reset-SkuCache
    }
    Update-ConnectionLabel        # also re-runs Set-TabActionState for both tabs (re-shows the connect overlay if disconnected)
    Update-ExchangeActivation
    Update-DeviceActivation
    Update-ApprovalsActivation
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
    <# Shared post-connect refresh after any successful connect / switch. The Graph reads here all run
       on the UI thread (the SDK session is bound to it); we narrate each step in the working dialog so
       the post-sign-in setup isn't a silent freeze. #>
    param($Context)
    $null = Invoke-WithProgress -Title "Setting up $($Context.Account)" -Work {
        Reset-HybridState            # recompute hybrid + AD-write capability for the (new) tenant
        # A new tenant means any object loaded from the PREVIOUS tenant is stale -- clear it so it can't be
        # re-imported / re-acted-on under the new tenant (e.g. via Invoke-ConnectOnPrem, or a device cleanup
        # that would otherwise delete tenant-A's cached IDs against tenant B). The tabs/pages rebuild below.
        $script:State.SelectedUser = $null; $script:State.SelectedGroup = $null; $script:State.SelectedDevice = $null
        Save-CurrentAccount
        # ONE Graph $batch fetches the org + subscribed SKUs and seeds the caches the next steps read,
        # so the whole connect bootstrap is a single round trip (falls back to per-call reads if /$batch
        # is unavailable).
        Set-Progress 'Loading tenant info...'
        Initialize-ConnectionData
        # Determine hybrid ONCE, up front, so (a) the connection label + Force-sync button read a warm
        # cache (no Graph call from the label), and (b) the sync button is correct on the first paint.
        Set-Progress 'Checking directory sync status...'
        $hybrid = [bool](Get-TenantHybridState)   # reads the cached org seeded above (no extra call)
        if ($script:UI.SyncBtn) { $script:UI.SyncBtn.Visible = $hybrid }
        Update-ConnectionLabel
        Update-ExchangeActivation
        Update-DeviceActivation
        Update-ApprovalsActivation
        Set-Progress 'Loading license SKUs...'
        Initialize-SkuMap                   # cache seeded by the batch -> no-op (per-call fetch only if not)
        Set-Progress 'Loading verified domains...'
        Initialize-VerifiedDomains          # reads the cached org (no extra call); precedes Build-TabForm
        Set-Progress 'Building forms...'
        foreach ($tab in 'User', 'Group') { Build-TabForm -Tab $tab }
        # Now connected: let the On-prem create option be selected (the slow AD availability check still
        # defers until it's actually picked, so connecting stays fast for the cloud-only common case).
        if ($script:UI.User -and $script:UI.User.DestOnPrem) {
            $script:UI.User.DestOnPrem.Enabled = $true
            $script:UI.Tooltip.SetToolTip($script:UI.User.DestOnPrem, 'Create the user in on-premises AD instead -- availability is checked when you select this.')
        }
    }
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
        if ($script:UiClosing) { return }   # window is closing mid-connect -> don't touch UI / pop dialogs
        # We disconnected first to force the account chooser, so a cancel/failure leaves us signed out.
        # Refresh the UI to that truth (the label must not keep saying "Connected"), then explain.
        Sync-ConnectionUi
        if ($_.Exception.Message -match 'cancel') {
            Set-Progress 'Sign-in cancelled -- not connected.'
            [System.Windows.Forms.MessageBox]::Show("Sign-in was cancelled, so you're now signed out. Click Connect to sign in.", 'Sign-in cancelled', 'OK', 'Information') | Out-Null
        } else {
            Set-Progress 'Connection failed.'
            [System.Windows.Forms.MessageBox]::Show("Could not connect:`n$($_.Exception.Message)", 'Connection error', 'OK', 'Error') | Out-Null
        }
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
    if ($script:UI.Busy) { return }   # a connect/switch is already running; ignore a double-click
    # Switching account rebuilds the forms for the new tenant -> unsaved edits would be lost. Warn first.
    if (-not (Confirm-LeaveUnsavedChanges -ActionLabel 'Switch account' -Consequence 'They will be discarded when the session changes.')) { return }
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
        if ($script:UiClosing) { return }   # window is closing mid-switch -> don't touch UI / pop dialogs
        Sync-ConnectionUi   # reflect the real post-attempt state (don't leave a stale "Connected" label)
        if ($_.Exception.Message -match 'cancel') {
            Set-Progress 'Switch cancelled.'
            [System.Windows.Forms.MessageBox]::Show("Account switch was cancelled. $(if (Test-GraphConnected) { 'You are still on the previous account.' } else { 'You are now signed out -- click Connect to sign in.' })", 'Switch cancelled', 'OK', 'Information') | Out-Null
        } else {
            Set-Progress 'Switch failed.'
            [System.Windows.Forms.MessageBox]::Show("Could not switch account:`n$($_.Exception.Message)", 'Switch error', 'OK', 'Error') | Out-Null
        }
    } finally {
        Set-UiBusy $false
    }
}

function Invoke-Disconnect {
    if ($script:UI.Busy) { return }   # don't disconnect underneath an in-flight connect/switch
    if (-not (Confirm-LeaveUnsavedChanges -ActionLabel 'Disconnect' -Consequence 'They will be discarded.')) { return }
    Disconnect-GraphSafe
    Disconnect-ExoSafe                 # the EXO session belonged to this Graph tenant
    Reset-HybridState                  # clear cached hybrid + AD-write capability
    Reset-SkuCache
    $script:State.SelectedUser = $null; $script:State.SelectedGroup = $null
    Update-ConnectionLabel
    Update-ExchangeActivation          # re-gate the Exchange tab
    Update-DeviceActivation            # re-gate the Devices page
    Update-ApprovalsActivation         # re-gate the Approvals page
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
    Set-DialogTheme -Form $dlg; Set-PrimaryButtonStyle $connectBtn   # dark theme + primary CTA
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

function Set-ConnectedTenantOnPremDomain {
    <# Learn (once) the connected tenant's on-prem AD domain from a synced object's onPremisesDomainName
       and persist it to the tenant profile, so CREATE + the on-prem connect can scope DC discovery to the
       right forest even before an object is loaded. Capture-if-empty: never overwrites an existing value. #>
    param($Object)
    $od = [string](Get-GraphVal $Object 'onPremisesDomainName')
    if ($od -and -not (Get-ConnectedTenantOnPremDomain)) { Set-TenantProfileValue -Field 'ExpectedOnPremDomain' -Value $od }
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
    if ($synced) { Set-ConnectedTenantOnPremDomain $Object }   # learn this tenant's on-prem domain (once)
    # Use the CACHED on-prem connection (NO probe on load) -- the operator connects on-prem explicitly via
    # the sidebar. adAvailable = connected + verified for THIS object's on-prem domain.
    $adAvailable = [bool]($synced -and (Test-OnPremReadyForObject $Object))
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
            $hint = if ($synced -and -not $adAvailable) { 'Synced from AD. Use "Connect on-prem AD" in the sidebar (you may need VPN/RDP to this tenant''s network) to edit this field.' } else { $state.Hint }
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
    # Keep this concise so it doesn't run under the "Choose fields..." button -- the UPN/email is already
    # shown in the form (UPN + Primary Email), so the header just needs the name + source tag.
    $ctx.TargetLabel.Text = "Editing: $(Get-GraphVal $User 'displayName')   [$(Get-ObjectSourceLabel $User)]"
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

    # Drive the kind-specific view from the loaded group's ACTUAL kind (not a radio -- the type is
    # locked in Edit): a Security group hides the M365-only email-alias + visibility rows; an M365
    # group shows them. On an M365 group the email alias stays editable and IS dirty-tracked -- Graph
    # permits PATCHing mailNickname -- so an edited alias is re-sent normally via the dirty diff.
    Set-GroupKindView -Kind $(if ($isUnified) { 'Microsoft365' } else { 'Security' })

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
        # Kind-specific fields (mailNickname, visibility) are only sent for the kind they apply to.
        # visibility: M365-only (security groups effectively default to Private; HiddenMembership is
        # M365-only). mailNickname: still required by Graph for a security group, but the operator
        # never sees/types it -- it's auto-generated from the display name in the safety net below.
        if ($a.AppliesToGroupKind -and (($a.AppliesToGroupKind -eq 'Microsoft365') -ne $isUnified)) { continue }
        if ($Mode -eq 'Edit' -and -not (Test-FieldDirty $field)) { continue }
        $val = ConvertTo-PayloadValue $field
        if ($Mode -eq 'New' -and ($null -eq $val -or ($val -is [array] -and $val.Count -eq 0))) { continue }
        $body[$a.Name] = $val
    }

    # mailNickname is REQUIRED by Graph for EVERY group kind (verified: the create-group required-property
    # table lists it unconditionally), but the form only collects it for Microsoft 365. On New, guarantee
    # a NON-EMPTY, Graph-legal alias: for a security group (alias hidden) derive it from the display name;
    # also backfill a blank M365 alias. A display name that's entirely non-ASCII/symbols sanitizes to ''
    # -- so fall back to a unique 'group-<id>' stub rather than POSTing an empty (illegal) mailNickname.
    if ($Mode -eq 'New' -and [string]::IsNullOrWhiteSpace([string]$body['mailNickname'])) {
        $dn = if ($ctx.Fields.ContainsKey('displayName')) { [string](Read-FieldValue $ctx.Fields['displayName']) } else { '' }
        $alias = Get-GeneratedGroupAlias -DisplayName $dn
        if ([string]::IsNullOrWhiteSpace($alias)) { $alias = 'group-' + ([guid]::NewGuid().ToString('N').Substring(0, 12)) }
        $body['mailNickname'] = $alias
    }
    return $body
}

#endregion

#region ---------------------------------------------------------------------- Save

function Invoke-Save {
    param([ValidateSet('User', 'Group')][string]$Tab)
    if (-not (Test-GraphConnected)) { [System.Windows.Forms.MessageBox]::Show('Connect first.', 'Not connected', 'OK', 'Information') | Out-Null; return }
    $ctx = $script:UI[$Tab]
    $guestMode = ($Tab -eq 'User' -and $ctx.Mode -eq 'New' -and $ctx.TypeGuest -and $ctx.TypeGuest.Checked)
    if (-not $guestMode -and -not (Test-FormValid -Tab $Tab)) { return }
    Set-UiBusy $true
    try {
        if ($guestMode) { Invoke-SendGuestInvite }
        elseif ($Tab -eq 'User') { Invoke-SaveUser }
        else { Invoke-SaveGroup }
    } catch {
        Set-Progress 'Save failed.'
        [System.Windows.Forms.MessageBox]::Show("Save failed:`n$($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
    } finally {
        Set-UiBusy $false
    }
}

function Invoke-SendGuestInvite {
    <# Validate + send a B2B guest invitation from the User-New "Guest" panel. #>
    $ctx = $script:UI.User
    $email = ([string]$ctx.GuestEmail.Text).Trim()
    $name  = ([string]$ctx.GuestName.Text).Trim()
    $url   = ([string]$ctx.GuestUrl.Text).Trim()
    $send  = [bool]$ctx.GuestSend.Checked
    if (-not $email -or ($email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$')) {
        [System.Windows.Forms.MessageBox]::Show('Enter a valid email address for the guest.', 'Email required', 'OK', 'Warning') | Out-Null
        return
    }
    if (-not $url) { $url = 'https://myapplications.microsoft.com' }
    Set-Progress 'Sending guest invitation...'
    $inv = Send-GuestInvitation -Email $email -DisplayName $name -RedirectUrl $url -SendEmail $send
    $redeem = [string](Get-GraphVal $inv 'inviteRedeemUrl')
    $msg = if ($send) { "Guest invited: $email`n`nAn invitation email with the redemption link was sent." }
           else       { "Guest invited: $email`n`nNo email was sent. Redemption link:`n$redeem" }
    Set-Progress "Guest invitation sent to $email."
    [System.Windows.Forms.MessageBox]::Show($msg, 'Guest invited', 'OK', 'Information') | Out-Null
    $ctx.GuestEmail.Text = ''; $ctx.GuestName.Text = ''
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

    # On-prem create routes to AD BEFORE the cloud license/usageLocation guard below -- those fields are
    # hidden (and irrelevant) for an on-prem create, and the guard reads them visibility-independently.
    if ($mode -eq 'New' -and $ctx.DestOnPrem -and $ctx.DestOnPrem.Checked) {
        Invoke-CreateUserInAd
        return
    }

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
        $newUpn = Get-GraphVal $created 'userPrincipalName'
        # Explain the handoff: the view is about to switch from New to Edit underneath the user.
        [System.Windows.Forms.MessageBox]::Show(
            "User created:`n$newUpn`n`nNow switching to Edit mode so you can complete the remaining details (job, department, manager, licenses) or pick another user.",
            'User created', 'OK', 'Information') | Out-Null

        # Switch to Edit on the new object so further tweaks are dirty-tracked.
        $ctx.ModeEdit.Checked = $true
        Import-UserIntoForm -User (Get-UserById -Id $newId)
        Set-Progress "Created $newUpn -- now editing. Complete the remaining details, or choose another user."
        return
    }

    # --- Edit ---
    $user = $script:State.SelectedUser
    $id = Get-GraphVal $user 'id'
    $synced = Test-ObjectSynced $user
    # Route to AD only when the operator has explicitly CONNECTED on-prem (cached) AND it's verified for
    # THIS user's on-prem domain -- never probe at save time, never target the wrong forest.
    $routeToAd = [bool]($synced -and (Test-OnPremReadyForObject $user))
    $cap = if ($routeToAd) { Get-AdState } else { $null }
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
    Set-Progress "Saved changes to $(Get-GraphVal $user 'userPrincipalName')."
    Show-SavedWithSyncOffer -RouteToAd $routeToAd -Warnings $warnings
}

function Invoke-CreateUserInAd {
    <#
        Create the new user in on-premises AD (it syncs to Entra via Entra Connect). Runs inside
        Invoke-Save's Set-UiBusy + try/catch, so exceptions (incl. the New-AdUserAccount "created but
        disabled -- password rejected" message) surface through that. Licenses / usage location are NOT
        set here -- they are cloud properties set in Edit after the account syncs.
    #>
    $ctx = $script:UI.User
    $expectedDomain = Get-ConnectedTenantOnPremDomain
    $cap = Get-AdWriteCapability -ExpectedDomain $expectedDomain
    if (-not ($cap -and $cap.Available)) {
        [System.Windows.Forms.MessageBox]::Show("On-premises Active Directory isn't available: $(if ($cap) { $cap.Reason } else { 'not connected' }).", 'On-premises AD', 'OK', 'Warning') | Out-Null
        return
    }
    # Cold-start guard: if we haven't yet learned this tenant's on-prem domain (no synced object loaded),
    # discovery was UNSCOPED and may have fallen back to the WORKSTATION's own forest. Require the operator
    # to TYPE the discovered domain before creating a user in it -- a weak one-click OK would let a tenant-#2
    # user land in the local Hybrid1 forest. On confirm we remember it, so later work is domain-scoped.
    if (-not $expectedDomain) {
        if (-not (Confirm-OnPremDomain -Domain $cap.DcDomain)) { return }
        if ($cap.DcDomain) { Set-TenantProfileValue -Field 'ExpectedOnPremDomain' -Value $cap.DcDomain }
    }
    $dc = $cap.Dc

    $display = [string](Read-FieldValue $ctx.Fields['displayName'])
    $upn     = [string](Read-FieldValue $ctx.Fields['userPrincipalName'])
    $alias   = [string](Read-FieldValue $ctx.Fields['mailNickname'])
    if (-not $display -or -not $upn) {
        [System.Windows.Forms.MessageBox]::Show('First and last name (display name) and the User Principal Name are required.', 'Missing details', 'OK', 'Warning') | Out-Null
        return
    }

    # sAMAccountName: derive from the alias, validate (<=20 chars, legal), and check uniqueness on the DC.
    $sam = Get-AdSamAccountName -Alias $alias
    if (-not (Test-AdSamAccountNameValid -Sam $sam)) {
        [System.Windows.Forms.MessageBox]::Show("Can't derive a valid account name (sAMAccountName: <=20 characters, no \ / [ ] : ; | = , + * ? < > `") from the alias '$alias'. Edit the Mail Nickname (alias) and try again.", 'Invalid account name', 'OK', 'Warning') | Out-Null
        return
    }
    $inUse = Test-AdSamInUse -Sam $sam -Dc $dc
    if ($inUse -eq $true) {
        [System.Windows.Forms.MessageBox]::Show("An account named '$sam' already exists in Active Directory. Choose a different Mail Nickname (alias).", 'Account name in use', 'OK', 'Warning') | Out-Null
        return
    }
    # ($inUse -eq $null) => the uniqueness check couldn't run (AD blip); proceed and let New-ADUser decide.

    $ouDn = if ($ctx.OuCombo -and $ctx.OuCombo.SelectedItem) { [string]$ctx.OuCombo.SelectedItem.Dn } else { '' }
    if (-not $ouDn) {
        [System.Windows.Forms.MessageBox]::Show('Choose a target OU for the new user.', 'OU required', 'OK', 'Warning') | Out-Null
        return
    }

    # Gather the on-prem-mastered scalar fields (non-empty) -> New-ADUser native params + OtherAttributes.
    $changes = New-Object System.Collections.Generic.List[object]
    foreach ($field in $ctx.Order) {
        $a = $field.Attr
        if ($a.Input -in 'Person', 'License', 'Password', 'Bool', 'ReadOnly', 'GroupType', 'Date') { continue }
        if ((Resolve-FieldAuthority $a) -ne 'OnPrem') { continue }
        $v = Read-FieldValue $field
        if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { continue }
        [void]$changes.Add(@{ Name = $a.Name; Value = $v })
    }
    $split = ConvertTo-NewAdUserParams -Changes $changes.ToArray()

    $pw = Read-FieldValue $ctx.Fields['passwordProfile']
    $aeField = $ctx.Fields['accountEnabled']
    $enabled = if ($aeField) { [bool](Read-FieldValue $aeField) } else { $true }

    Set-Progress "Creating $upn in Active Directory..."
    $created = New-AdUserAccount -Dc $dc -Path $ouDn -Name $display -SamAccountName $sam -UserPrincipalName $upn `
        -Password $pw.Password -ForceChangeAtLogon ([bool]$pw.Force) -Enabled $enabled `
        -NativeParams $split.NativeParams -OtherAttributes $split.OtherAttributes

    # Manager: resolve from the PICKED PERSON by UPN -- not Read-FieldValue (which returns a cloud Id).
    $warnings = New-Object System.Collections.Generic.List[string]
    $mgrField = $ctx.Fields['manager']
    if ($mgrField) {
        $person = $mgrField.People | Select-Object -First 1
        if ($person) {
            $ok = Set-AdUserManagerFromPerson -AdUser $created -Dc $dc -Person $person
            if (-not $ok) { [void]$warnings.Add("Manager '$($person.DisplayName)' wasn't found in AD by UPN; manager not set.") }
        }
    }

    # Remember the chosen OU for next time -- per-tenant, so it never bleeds to the other hybrid tenant.
    Set-TenantProfileValue -Field 'LastOnPremOuDn' -Value $ouDn

    $msg = "User created in Active Directory:`n$upn`nin $ouDn`n`nIt will appear in Microsoft 365 after the next Microsoft Entra Connect sync (typically within ~30 minutes). Licenses and Usage Location are cloud properties -- set them on this user in Edit mode once it has synced."
    if ($warnings.Count) { $msg += "`n`nNotes:`n  " + ($warnings -join "`n  ") }
    Set-Progress "Created $upn in Active Directory."

    # Offer to force a directory sync now and wait for the user to land in Entra, instead of waiting ~30 min.
    $offer = [System.Windows.Forms.MessageBox]::Show("$msg`n`nForce a directory sync now and wait for it to appear in Entra?", 'User created in AD', 'YesNo', 'Question')
    if ($offer -eq 'Yes') {
        $r = Invoke-ForceDirectorySync -NoConfirm
        if ($r.Forced) {
            if (Wait-ForSyncedUser -Upn $upn -TimeoutSec 300) {
                [System.Windows.Forms.MessageBox]::Show("$upn has synced to Entra. You can now switch to Edit to set licenses / usage location.", 'Synced', 'OK', 'Information') | Out-Null
            } else {
                [System.Windows.Forms.MessageBox]::Show("Sync was forced on $($r.Server), but $upn hasn't appeared in Entra yet. It should arrive shortly -- check Edit > Select user in a minute.", 'Sync pending', 'OK', 'Information') | Out-Null
            }
        }
    }

    # The object doesn't exist in Entra yet (or just arrived), so reset to a fresh New form rather than
    # auto-switching to Edit on it.
    Set-TabMode -Tab 'User' -Mode 'New'
}

function Show-TextInput {
    <# Minimal themed text-input dialog. Returns the entered string, or $null on cancel. #>
    param([string]$Title, [string]$Prompt, [string]$Default = '')
    $t = Get-Theme
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title; $dlg.Size = New-Object System.Drawing.Size(460, 200); $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'; $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false; $dlg.Font = $t.FontBase; $dlg.ShowInTaskbar = $false
    $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = $Prompt; $lbl.Location = New-Object System.Drawing.Point(14, 14); $lbl.Size = New-Object System.Drawing.Size(420, 70)
    $box = New-Object System.Windows.Forms.TextBox; $box.Text = $Default; $box.Location = New-Object System.Drawing.Point(14, 92); $box.Size = New-Object System.Drawing.Size(420, 24)
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; $ok.DialogResult = 'OK'; $ok.Location = New-Object System.Drawing.Point(264, 126); $ok.Size = New-Object System.Drawing.Size(84, 28)
    $cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(352, 126); $cancel.Size = New-Object System.Drawing.Size(84, 28)
    $dlg.Controls.AddRange(@($lbl, $box, $ok, $cancel)); $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    Set-DialogTheme -Form $dlg; Set-PrimaryButtonStyle $ok
    $res = $dlg.ShowDialog(); $val = $box.Text; $dlg.Dispose()
    if ($res -eq 'OK' -and -not [string]::IsNullOrWhiteSpace($val)) { return $val.Trim() }
    return $null
}

function Invoke-ForceDirectorySync {
    <#
        Detect the Entra Connect server (cloud autofill -> persisted -> prompt), confirm reachability +
        that it's the active exporter, then force a delta sync. Returns @{ Forced; Server; Reason }.
        -NoConfirm skips the confirm dialog (the post-create path already asked). Best-effort throughout;
        every failure mode reports a clear message and returns Forced=$false.
    #>
    param([switch]$NoConfirm)
    if (-not (Test-GraphConnected)) { [System.Windows.Forms.MessageBox]::Show('Connect first.', 'Not connected', 'OK', 'Information') | Out-Null; return @{ Forced = $false } }

    Set-Progress 'Locating the Entra Connect server...'
    $info = Get-EntraConnectSyncInfo
    $savedServer = Get-TenantProfileValue -Field 'ConnectServer'
    $name = if ($info -and $info.ServerName) { $info.ServerName } elseif ($savedServer) { $savedServer } else { $null }
    if (-not $name) {
        $name = Show-TextInput -Title 'Entra Connect server' -Prompt "Couldn't auto-detect the Microsoft Entra Connect server from the cloud. Enter its name or FQDN:" -Default ''
        if (-not $name) { return @{ Forced = $false; Reason = 'No server specified.' } }
    }
    $fqdn = Resolve-ServerFqdn -Name $name
    Set-TenantProfileValue -Field 'ConnectServer' -Value $name   # per-tenant Connect server (no cross-tenant clobber)

    if (-not $NoConfirm) {
        $pending = if ($info) { "`n($($info.PendingAdds) add / $($info.PendingUpdates) update pending export.)" } else { '' }
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Force a Microsoft Entra Connect delta sync on:`n$fqdn$pending`n`nThis runs Start-ADSyncSyncCycle on that server over WinRM (your Windows account needs admin rights there). Continue?",
            'Force directory sync', 'YesNo', 'Question')
        if ($confirm -ne 'Yes') { return @{ Forced = $false; Reason = 'Cancelled.' } }
    }

    # Query the server's scheduler over WinRM. The bounded session option (New-AdSyncSessionOption) caps
    # the connect at ~8s, so an unreachable host fails fast with a message instead of hanging the UI --
    # which also makes the separate Test-WSMan reachability probe redundant, so it's gone.
    $state = Invoke-WithProgress -Title 'Force directory sync' -Work {
        Set-Progress "Contacting $fqdn over WinRM..."
        Get-RemoteAdSyncState -Server $fqdn
    }
    if ($state.Error) {
        [System.Windows.Forms.MessageBox]::Show("Couldn't reach or query the sync server $fqdn`:`n$($state.Error)`n`n(Check VPN/connectivity and that WinRM is enabled, that you have admin rights on it, and that it's a Microsoft Entra Connect server -- not Cloud Sync.)", 'Sync server', 'OK', 'Warning') | Out-Null
        return @{ Forced = $false; Server = $fqdn; Reason = $state.Error }
    }
    $allowed = Test-AdSyncForceAllowed -Scheduler $state.Scheduler -Busy $state.Busy
    if (-not $allowed.Allowed) {
        [System.Windows.Forms.MessageBox]::Show($allowed.Reason, 'Sync not forced', 'OK', 'Information') | Out-Null
        return @{ Forced = $false; Server = $fqdn; Reason = $allowed.Reason }
    }
    $r = Invoke-WithProgress -Title 'Force directory sync' -Work {
        Set-Progress "Forcing a delta sync on $fqdn..."
        Invoke-RemoteAdSyncDelta -Server $fqdn
    }
    if ($r.Error) {
        [System.Windows.Forms.MessageBox]::Show("Couldn't start the sync on $fqdn`:`n$($r.Error)", 'Sync error', 'OK', 'Error') | Out-Null
        return @{ Forced = $false; Server = $fqdn; Reason = $r.Error }
    }
    Set-Progress "Delta sync started on $fqdn."
    return @{ Forced = $true; Server = $fqdn }
}

function Show-SavedWithSyncOffer {
    <#
        Confirm a save and -- when it went to on-premises AD -- offer to force a directory sync NOW, so
        the change appears in the cloud without waiting for the next cycle (closing the loop in one pane
        instead of a portal trip). Runs inside the save's existing busy/try-catch; Invoke-ForceDirectorySync
        brings its own progress dialog + result messages, and -NoConfirm skips its own prompt since we asked.
    #>
    param([bool]$RouteToAd, [string[]]$Warnings)
    $notes = if ($Warnings -and $Warnings.Count) { "`n`nNotes:`n  " + ($Warnings -join "`n  ") } else { '' }
    if (-not $RouteToAd) {
        [System.Windows.Forms.MessageBox]::Show("Changes saved.$notes", 'Saved', 'OK', 'Information') | Out-Null
        return
    }
    $ans = [System.Windows.Forms.MessageBox]::Show(
        ("Saved to on-premises Active Directory.$notes`n`nOn-prem changes appear in the cloud after the next " +
         "Microsoft Entra Connect sync. Force a sync now?"),
        'Saved to AD', 'YesNo', 'Information')
    if ($ans -ne 'Yes') { return }
    try {
        $r = Invoke-ForceDirectorySync -NoConfirm
        if ($r.Forced) {
            [System.Windows.Forms.MessageBox]::Show("A delta sync was started on $($r.Server). The change will appear in Entra shortly (typically a few minutes).", 'Sync started', 'OK', 'Information') | Out-Null
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Couldn't force a sync:`n$($_.Exception.Message)", 'Sync error', 'OK', 'Error') | Out-Null
    }
}

function Wait-ForSyncedUser {
    <# Poll Entra (Get-MgUser by UPN) until the just-created on-prem user appears, or timeout. Pumps the
       UI so the window stays responsive. Returns $true if it appeared. #>
    param([Parameter(Mandatory)][string]$Upn, [int]$TimeoutSec = 300)
    $q = $Upn.Replace("'", "''")
    $deadline = [datetime]::Now.AddSeconds($TimeoutSec)
    while ([datetime]::Now -lt $deadline -and -not $script:UiClosing) {
        Set-Progress "Waiting for $Upn to sync to Entra..."
        try { if (Get-MgUser -Filter "userPrincipalName eq '$q'" -Top 1 -ErrorAction Stop) { return $true } } catch { }
        for ($i = 0; $i -lt 20 -and -not $script:UiClosing; $i++) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 250 }  # ~5s, responsive
    }
    return $false
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

        $gName = Get-GraphVal $created 'displayName'
        $cmsg = "Group created:`n$gName"
        if ($failures.Count) { $cmsg += "`n`nBut some members/owners were not added:`n  " + ($failures -join "`n  ") }
        $cmsg += "`n`nNow switching to Edit mode so you can adjust details, members, and owners."
        [System.Windows.Forms.MessageBox]::Show($cmsg, $(if ($failures.Count) { 'Group created with warnings' } else { 'Group created' }), 'OK', $(if ($failures.Count) { 'Warning' } else { 'Information' })) | Out-Null
        $ctx.ModeEdit.Checked = $true
        Import-GroupIntoForm -Group (Get-GroupById -Id $gid)
        Set-Progress "Created $gName -- now editing. Adjust details, members, and owners, or choose another group."
        return
    }

    # --- Edit ---
    $group = $script:State.SelectedGroup
    $gid = Get-GraphVal $group 'id'
    $synced = Test-ObjectSynced $group
    $routeToAd = [bool]($synced -and (Test-OnPremReadyForObject $group))
    $cap = if ($routeToAd) { Get-AdState } else { $null }
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
    Set-Progress "Saved changes to $(Get-GraphVal $group 'displayName')."
    Show-SavedWithSyncOffer -RouteToAd $routeToAd -Warnings $warnings
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
    # Route to AD only when the operator has explicitly CONNECTED on-prem (cached) AND it's verified for
    # THIS user's on-prem domain -- never probe at save time, never target the wrong forest.
    $routeToAd = [bool]($synced -and (Test-OnPremReadyForObject $user))
    $cap = if ($routeToAd) { Get-AdState } else { $null }
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
    # Plain scriptblock so the handler keeps module affinity and can call New-Passphrase
    # ($pwd stays in scope because the dialog is modal). A closure would fail on PS 5.1.
    $gen.Add_Click({ $pwd.UseSystemPasswordChar = $false; $pwd.Text = (New-Passphrase) })
    $force = New-Object System.Windows.Forms.CheckBox; $force.Text = 'Force change at next sign-in'; $force.Checked = $true; $force.AutoSize = $true; $force.Location = New-Object System.Drawing.Point(14, 80)

    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'Reset'; $ok.DialogResult = 'OK'; $ok.Location = New-Object System.Drawing.Point(224, 128); $ok.Size = New-Object System.Drawing.Size(80, 28)
    $cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(312, 128); $cancel.Size = New-Object System.Drawing.Size(80, 28)
    Set-PrimaryButtonStyle $ok; Set-SecondaryButtonStyle $cancel
    $dlg.Controls.AddRange(@($info, $pwd, $gen, $force, $ok, $cancel))
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel

    Set-DialogTheme -Form $dlg; Set-PrimaryButtonStyle $ok   # dark theme + keep Reset as the primary
    if ($dlg.ShowDialog() -ne 'OK') { $dlg.Dispose(); return $null }
    $p = $pwd.Text; $f = [bool]$force.Checked
    $dlg.Dispose()
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    return @{ Password = $p; Force = $f }
}

function Show-TypedConfirm {
    <# Type-to-confirm guard: the user must type $Expected exactly to enable the OK button. Returns bool.
       Default is the DESTRUCTIVE styling (red 'Delete'); -NotDanger + -OkText reuse it for a high-stakes
       but non-destructive confirmation (e.g. trusting an on-prem domain for a tenant). #>
    param([string]$Prompt, [string]$Expected, [string]$OkText = 'Delete', [switch]$NotDanger)
    $t = Get-Theme
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Confirm'; $dlg.Size = New-Object System.Drawing.Size(460, 230); $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'; $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false; $dlg.Font = $t.FontBase; $dlg.ShowInTaskbar = $false

    $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = $Prompt; $lbl.Location = New-Object System.Drawing.Point(14, 14); $lbl.Size = New-Object System.Drawing.Size(420, 90)
    $box = New-Object System.Windows.Forms.TextBox; $box.Location = New-Object System.Drawing.Point(14, 110); $box.Size = New-Object System.Drawing.Size(420, 24)
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = $OkText; $ok.DialogResult = 'OK'; $ok.Location = New-Object System.Drawing.Point(264, 150); $ok.Size = New-Object System.Drawing.Size(84, 28); $ok.Enabled = $false
    if (-not $NotDanger) { $ok.ForeColor = $t.ErrText }
    $cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(352, 150); $cancel.Size = New-Object System.Drawing.Size(84, 28)
    Set-SecondaryButtonStyle $ok; Set-SecondaryButtonStyle $cancel
    $box.Add_TextChanged({ $ok.Enabled = ($box.Text -ceq $Expected) }.GetNewClosure())
    $dlg.Controls.AddRange(@($lbl, $box, $ok, $cancel))
    # Safety: Enter and Escape both CANCEL -- confirming requires an explicit click on the OK button, which
    # only enables after the exact value is typed. Enter must never trigger the action.
    $dlg.AcceptButton = $cancel; $dlg.CancelButton = $cancel

    Set-DialogTheme -Form $dlg
    if ($NotDanger) { Set-PrimaryButtonStyle $ok } else { Set-DangerButtonStyle $ok }
    $result = $dlg.ShowDialog()
    $dlg.Dispose()
    return ($result -eq 'OK')
}

function Confirm-OnPremDomain {
    <# Strong confirmation before TRUSTING a cold-start, machine-discovered on-prem domain as a tenant's
       Active Directory: the operator must TYPE the domain. This is what stops a one-click acceptance of the
       LOCAL forest (Hybrid1) for a REMOTE tenant when discovery fell back to the workstation's own
       domain. Returns $true only on an exact typed match. #>
    param([Parameter(Mandatory)][string]$Domain)
    Show-TypedConfirm -NotDanger -OkText 'Confirm' -Expected $Domain -Prompt (
        "On-premises Active Directory domain detected:`n`n    $Domain`n`n" +
        "This will be used as the on-prem directory for the tenant you're signed into. If you meant a " +
        "DIFFERENT tenant's directory, Cancel and connect to that network (VPN/RDP) first.`n`n" +
        "To confirm this is correct, type the domain name exactly:")
}

#endregion
