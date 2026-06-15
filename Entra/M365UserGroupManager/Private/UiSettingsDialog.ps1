<#
    Settings dialog.

    A modal window listing every attribute in the catalog (grouped) as a checkbox, for the given
    tab. Checked attributes are the ones the dynamic form renders. On OK the enabled set is saved
    to config and the caller rebuilds the tab. The full catalog is always shown, so newly-added
    attributes appear here automatically even if not yet enabled.

    Returns $true if the user accepted changes (caller should rebuild), else $false.
#>

function Show-SettingsDialog {
    param([ValidateSet('User', 'Group')][string]$Tab)

    $t = Get-Theme
    $key = if ($Tab -eq 'User') { 'Users' } else { 'Groups' }
    $enabled = @($script:Config[$key].Enabled)

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "$Tab fields - choose which to show"
    $dlg.Size = New-Object System.Drawing.Size(560, 620)
    $dlg.MinimumSize = New-Object System.Drawing.Size(460, 420)
    $dlg.StartPosition = 'CenterParent'
    $dlg.Font = $t.FontBase
    $dlg.ShowInTaskbar = $false

    $root = New-Object System.Windows.Forms.TableLayoutPanel
    $root.Dock = 'Fill'; $root.ColumnCount = 1; $root.RowCount = 3
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 40)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 48)))
    $dlg.Controls.Add($root)

    # --- Top: All / None / Defaults --------------------------------------------------------
    $topBar = New-Object System.Windows.Forms.FlowLayoutPanel
    $topBar.Dock = 'Fill'; $topBar.FlowDirection = 'LeftToRight'; $topBar.WrapContents = $false; $topBar.Padding = New-Object System.Windows.Forms.Padding(6, 6, 6, 0)
    $btnAll = New-Object System.Windows.Forms.Button; $btnAll.Text = '&All'; $btnAll.Width = 64; $btnAll.Height = 26
    $btnNone = New-Object System.Windows.Forms.Button; $btnNone.Text = '&None'; $btnNone.Width = 64; $btnNone.Height = 26
    $btnDef = New-Object System.Windows.Forms.Button; $btnDef.Text = '&Defaults'; $btnDef.Width = 80; $btnDef.Height = 26
    Set-SecondaryButtonStyle $btnAll; Set-SecondaryButtonStyle $btnNone; Set-SecondaryButtonStyle $btnDef
    $topBar.Controls.AddRange(@($btnAll, $btnNone, $btnDef))
    $root.Controls.Add($topBar, 0, 0)

    # --- Middle: grouped checkboxes (scrollable) -------------------------------------------
    $scroll = New-Object System.Windows.Forms.Panel
    $scroll.Dock = 'Fill'; $scroll.AutoScroll = $true
    $flow = New-Object System.Windows.Forms.FlowLayoutPanel
    $flow.FlowDirection = 'TopDown'; $flow.WrapContents = $false; $flow.AutoSize = $true
    $flow.AutoSizeMode = 'GrowAndShrink'; $flow.Dock = 'Top'
    $scroll.Controls.Add($flow)
    $root.Controls.Add($scroll, 0, 1)

    $checks = New-Object System.Collections.Generic.List[object]
    foreach ($group in (Get-CatalogTab -Tab $Tab)) {
        $gb = New-Object System.Windows.Forms.GroupBox
        $gb.Text = $group.Name; $gb.AutoSize = $true; $gb.AutoSizeMode = 'GrowAndShrink'
        $gb.Margin = New-Object System.Windows.Forms.Padding(6, 6, 6, 2); $gb.Width = 500
        $inner = New-Object System.Windows.Forms.FlowLayoutPanel
        $inner.FlowDirection = 'TopDown'; $inner.WrapContents = $false; $inner.AutoSize = $true
        $inner.AutoSizeMode = 'GrowAndShrink'; $inner.Dock = 'Fill'
        $inner.Margin = New-Object System.Windows.Forms.Padding(3, 16, 3, 3)
        foreach ($attr in $group.Attributes) {
            $cb = New-Object System.Windows.Forms.CheckBox
            $cb.AutoSize = $true; $cb.Tag = $attr
            if ($attr.Required) {
                # Required-to-create fields are always shown (and marked *) -- lock them on here so
                # the Settings list reflects that and they can't be unchecked.
                $cb.Text = $attr.Label + '  (required)'; $cb.Checked = $true; $cb.Enabled = $false
            } else {
                $cb.Text = $attr.Label; $cb.Checked = ($enabled -contains $attr.Name)
            }
            [void]$inner.Controls.Add($cb)
            [void]$checks.Add($cb)
        }
        $gb.Controls.Add($inner)
        [void]$flow.Controls.Add($gb)
    }

    # Skip disabled (required) checkboxes -- they stay locked on.
    $btnAll.Add_Click({ foreach ($c in $checks) { if ($c.Enabled) { $c.Checked = $true } } }.GetNewClosure())
    $btnNone.Add_Click({ foreach ($c in $checks) { if ($c.Enabled) { $c.Checked = $false } } }.GetNewClosure())
    # Compute the defaults OUTSIDE the handler and capture the RESULT: a .GetNewClosure() block
    # loses module affinity on Windows PowerShell 5.1 and can't call module-private functions
    # (Get-DefaultEnabledNames would throw "not recognized" at click time).
    $defaultNames = Get-DefaultEnabledNames -Tab $Tab
    $btnDef.Add_Click({
        foreach ($c in $checks) { if ($c.Enabled) { $c.Checked = ($defaultNames -contains $c.Tag.Name) } }
    }.GetNewClosure())

    # --- Bottom: OK / Cancel ---------------------------------------------------------------
    $btnBar = New-Object System.Windows.Forms.FlowLayoutPanel
    $btnBar.Dock = 'Fill'; $btnBar.FlowDirection = 'RightToLeft'; $btnBar.WrapContents = $false; $btnBar.Padding = New-Object System.Windows.Forms.Padding(0, 8, 12, 8)
    $okBtn = New-Object System.Windows.Forms.Button; $okBtn.Text = 'OK'; $okBtn.Width = 90; $okBtn.Height = 30; $okBtn.DialogResult = 'OK'
    $cancelBtn = New-Object System.Windows.Forms.Button; $cancelBtn.Text = 'Cancel'; $cancelBtn.Width = 90; $cancelBtn.Height = 30; $cancelBtn.DialogResult = 'Cancel'
    Set-PrimaryButtonStyle $okBtn; Set-SecondaryButtonStyle $cancelBtn
    $btnBar.Controls.Add($okBtn); $btnBar.Controls.Add($cancelBtn)
    $root.Controls.Add($btnBar, 0, 2)
    $dlg.AcceptButton = $okBtn; $dlg.CancelButton = $cancelBtn

    $result = $dlg.ShowDialog()
    if ($result -ne 'OK') { $dlg.Dispose(); return $false }

    $script:Config[$key].Enabled = @($checks | Where-Object { $_.Checked } | ForEach-Object { $_.Tag.Name })
    try { Save-AppConfig -Config $script:Config } catch { Set-Progress "Could not save settings: $($_.Exception.Message)" }
    $dlg.Dispose()
    return $true
}
