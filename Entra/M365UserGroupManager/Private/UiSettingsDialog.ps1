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
    $dlg.Text = "$Tab fields to show on the form"
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
    $note = New-Object System.Windows.Forms.Label
    $note.Text = '  Shown when editing; create-settable ones also appear when creating (read-only/license/manager: edit only)'; $note.AutoSize = $true
    $note.ForeColor = $t.Muted; $note.Margin = New-Object System.Windows.Forms.Padding(12, 9, 3, 0)
    $topBar.Controls.AddRange(@($btnAll, $btnNone, $btnDef, $note))
    $root.Controls.Add($topBar, 0, 0)

    # --- Middle: grouped checkboxes (scrollable) -------------------------------------------
    $scroll = New-Object System.Windows.Forms.Panel
    $scroll.Dock = 'Fill'; $scroll.AutoScroll = $true
    $flow = New-Object System.Windows.Forms.FlowLayoutPanel
    $flow.FlowDirection = 'TopDown'; $flow.WrapContents = $false; $flow.AutoSize = $true
    $flow.AutoSizeMode = 'GrowAndShrink'; $flow.Dock = 'Top'
    $scroll.Controls.Add($flow)
    $root.Controls.Add($scroll, 0, 1)

    # Render each catalog group as a cyan section header (matching the main form's FontSection style)
    # with its checkboxes indented beneath -- NOT a WinForms GroupBox, whose light etched border and
    # title don't dark-theme cleanly.
    $checks = New-Object System.Collections.Generic.List[object]
    $firstGroup = $true
    foreach ($group in (Get-CatalogTab -Tab $Tab)) {
        $hdr = New-Object System.Windows.Forms.Label
        $hdr.Text = $group.Name; $hdr.AutoSize = $true; $hdr.UseMnemonic = $false
        $hdr.Font = $t.FontSection; $hdr.ForeColor = $t.Header
        $hdr.Margin = New-Object System.Windows.Forms.Padding(6, $(if ($firstGroup) { 4 } else { 16 }), 6, 4)
        [void]$flow.Controls.Add($hdr); $firstGroup = $false
        foreach ($attr in $group.Attributes) {
            $cb = New-Object System.Windows.Forms.CheckBox
            $cb.AutoSize = $true; $cb.Tag = $attr; $cb.Margin = New-Object System.Windows.Forms.Padding(20, 1, 6, 1)
            if ($attr.Required -or $attr.RequiredForCreate) {
                # Required-to-create fields (marked * or auto-generated) are always shown when creating.
                # Lock them ON, but keep them ENABLED + Muted (readable) rather than disabled (which renders
                # near-illegible grey on dark); a CheckedChanged guard re-checks them if clicked.
                $cb.Text = $attr.Label + '  (required)'; $cb.Checked = $true; $cb.ForeColor = $t.Muted
                $cb.Add_CheckedChanged({ if (-not $args[0].Checked) { $args[0].Checked = $true } })
            } else {
                $cb.Text = $attr.Label; $cb.Checked = ($enabled -contains $attr.Name)
            }
            [void]$flow.Controls.Add($cb)
            [void]$checks.Add($cb)
        }
    }

    # All/None/Defaults skip the locked "required" checkboxes (identified by their attr Tag).
    $btnAll.Add_Click({ foreach ($c in $checks) { if (-not ($c.Tag.Required -or $c.Tag.RequiredForCreate)) { $c.Checked = $true } } }.GetNewClosure())
    $btnNone.Add_Click({ foreach ($c in $checks) { if (-not ($c.Tag.Required -or $c.Tag.RequiredForCreate)) { $c.Checked = $false } } }.GetNewClosure())
    # Compute the defaults OUTSIDE the handler and capture the RESULT: a .GetNewClosure() block
    # loses module affinity on Windows PowerShell 5.1 and can't call module-private functions
    # (Get-DefaultEnabledNames would throw "not recognized" at click time).
    $defaultNames = Get-DefaultEnabledNames -Tab $Tab
    $btnDef.Add_Click({
        foreach ($c in $checks) { if (-not ($c.Tag.Required -or $c.Tag.RequiredForCreate)) { $c.Checked = ($defaultNames -contains $c.Tag.Name) } }
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

    Set-DialogTheme -Form $dlg; Set-PrimaryButtonStyle $okBtn   # dark theme + primary CTA
    $result = $dlg.ShowDialog()
    if ($result -ne 'OK') { $dlg.Dispose(); return $false }

    $script:Config[$key].Enabled = @($checks | Where-Object { $_.Checked } | ForEach-Object { $_.Tag.Name })
    try { Save-AppConfig -Config $script:Config } catch { Set-Progress "Could not save settings: $($_.Exception.Message)" }
    $dlg.Dispose()
    return $true
}
