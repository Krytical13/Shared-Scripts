<#
    UI theme + status helpers.

    A single cached palette/font set keeps the look consistent, plus helpers to style the two
    button tiers (flat secondary / accent-filled primary) and to push status + progress to the
    bottom bar. Set-Progress is a no-op until the main form has populated $script:UI.
#>

function Get-Theme {
    if (-not $script:Theme) {
        # DARK palette (bright cyan on dark slate). Contrasts are WCAG-AA verified:
        #   Text  #E6EDF3 on Surface #161B22  = ~13:1   Muted #8B949E on Surface = ~5.2:1
        #   Header/Brand cyan #00AEEF on Surface = ~7.1:1 (bright headers read on dark)
        #   White on Accent fill #0277A8 = 4.99:1       CtrlBorder #6E7681 on Surface = ~3.6:1 (SC 1.4.11)
        # Two cyans by role: bright Brand #00AEEF for headers / selection / focus / accents (text-on-dark);
        # deeper Accent #0277A8 for the one primary FILL per row (so white button text stays >=4.5:1).
        # All System.Drawing.Color -> identical on Windows PowerShell 5.1 and 7.
        $script:Theme = @{
            Mode        = 'Dark'
            Brand       = [System.Drawing.Color]::FromArgb(0, 174, 239)    # #00AEEF -- bright cyan: selection, focus, top rule, icons
            Header      = [System.Drawing.Color]::FromArgb(0, 174, 239)    # #00AEEF -- section headers (bright on dark, 7.1:1)
            Accent      = [System.Drawing.Color]::FromArgb(2, 119, 168)    # #0277A8 -- primary button fill (white text 4.99:1)
            AccentHover = [System.Drawing.Color]::FromArgb(1, 80, 118)     # #015076 -- DARKER hover so white button text stays >=4.5:1 (8.7:1)
            AppBg       = [System.Drawing.Color]::FromArgb(13, 17, 23)     # #0D1117 -- window base (behind cards)
            Surface     = [System.Drawing.Color]::FromArgb(22, 27, 34)     # #161B22 -- cards / page content
            SurfaceAlt  = [System.Drawing.Color]::FromArgb(28, 33, 40)     # #1C2128 -- header bar / secondary panels
            NavBg       = [System.Drawing.Color]::FromArgb(16, 20, 27)     # #10141B -- left sidebar
            NavSelBg    = [System.Drawing.Color]::FromArgb(28, 35, 45)     # #1C232D -- selected nav item fill
            Text        = [System.Drawing.Color]::FromArgb(230, 237, 243)  # #E6EDF3 -- primary text
            Muted       = [System.Drawing.Color]::FromArgb(139, 148, 158)  # #8B949E -- secondary text (5.2:1 on Surface)
            Border      = [System.Drawing.Color]::FromArgb(48, 54, 61)     # #30363D -- subtle card borders (decorative)
            CtrlBorder  = [System.Drawing.Color]::FromArgb(110, 118, 129)  # #6E7681 -- control/button boundaries (3.6:1, SC 1.4.11)
            InputBg     = [System.Drawing.Color]::FromArgb(13, 17, 23)     # #0D1117 -- textbox/combo/list background (recessed)
            OkText      = [System.Drawing.Color]::FromArgb(63, 185, 80)    # #3FB950
            OkBack      = [System.Drawing.Color]::FromArgb(18, 38, 26)     # #12261A -- dark green tint
            ErrText     = [System.Drawing.Color]::FromArgb(248, 81, 73)    # #F85149
            ErrBack     = [System.Drawing.Color]::FromArgb(45, 21, 23)     # #2D1517 -- dark red tint
            WarnText    = [System.Drawing.Color]::FromArgb(210, 153, 34)   # #D29922 -- "synced from AD" badge
            BtnFace     = [System.Drawing.Color]::FromArgb(33, 38, 45)     # #21262D -- secondary button fill
            BtnHover    = [System.Drawing.Color]::FromArgb(45, 51, 59)     # #2D333B -- secondary button hover (brightens)
            BtnText     = [System.Drawing.Color]::FromArgb(230, 237, 243)  # #E6EDF3
            ReadOnlyBg  = [System.Drawing.Color]::FromArgb(28, 33, 40)     # #1C2128 -- read-only field bg
            ProgBack    = [System.Drawing.Color]::FromArgb(28, 33, 40)
            # --- spacing scale (4px base) + shared control heights: one token, no ad-hoc literals ---
            GapSm       = 4
            Gap         = 8
            GapLg       = 16
            BtnH        = 28                                               # secondary / inline buttons
            BtnHPrimary = 34                                               # the one primary action per row
            NavW        = 220                                              # left sidebar width
            FontBase    = New-Object System.Drawing.Font('Segoe UI', 9)
            FontBold    = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
            FontMedium  = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
            FontSection = New-Object System.Drawing.Font('Segoe UI', 10.5, [System.Drawing.FontStyle]::Bold)  # section headers, a clear step above 9pt labels
            FontLarge   = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
            FontTitle   = New-Object System.Drawing.Font('Segoe UI Semibold', 16)  # page H1 in the content header
            FontNav     = New-Object System.Drawing.Font('Segoe UI', 10)           # sidebar nav items
            FontNavHdr  = New-Object System.Drawing.Font('Segoe UI', 7.5, [System.Drawing.FontStyle]::Bold) # sidebar section captions
        }
        # Icon font for sidebar glyphs -- Segoe MDL2 Assets (Win10+) / Fluent Icons. Only set it if the
        # font is actually installed, so on a host without it we degrade to text-only nav (no tofu boxes).
        $script:Theme.FontIcon = $null
        try {
            if ([System.Drawing.FontFamily]::Families.Name -contains 'Segoe MDL2 Assets') {
                $script:Theme.FontIcon = New-Object System.Drawing.Font('Segoe MDL2 Assets', 11)
            }
        } catch { }
    }
    return $script:Theme
}

function Set-SecondaryButtonStyle {
    param([System.Windows.Forms.Button]$Button)
    $t = Get-Theme
    $Button.FlatStyle = 'Flat'
    $Button.FlatAppearance.BorderColor = $t.CtrlBorder      # #6E7681 = ~3.6:1 on Surface (SC 1.4.11 control boundary)
    $Button.FlatAppearance.BorderSize = 1
    $Button.FlatAppearance.MouseOverBackColor = $t.BtnHover # dark theme: secondary buttons brighten on hover
    $Button.BackColor = $t.BtnFace
    $Button.ForeColor = $t.BtnText
    $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
    # WCAG 2.4.7 Focus Visible: FlatStyle suppresses the native focus rectangle, so draw our own by
    # thickening the (already-contrasting) border to 2px while the control holds keyboard focus.
    # Handlers read only $args[0] (the sender) -- no captured vars -> safe on 5.1 (no GetNewClosure).
    $Button.Add_GotFocus({ $args[0].FlatAppearance.BorderSize = 2 })
    $Button.Add_LostFocus({ $args[0].FlatAppearance.BorderSize = 1 })
}

function Set-PrimaryButtonStyle {
    param([System.Windows.Forms.Button]$Button)
    $t = Get-Theme
    $Button.FlatStyle = 'Flat'
    $Button.BackColor = $t.Accent
    $Button.ForeColor = [System.Drawing.Color]::White
    $Button.FlatAppearance.BorderColor = $t.Accent
    $Button.FlatAppearance.BorderSize = 1
    $Button.FlatAppearance.MouseOverBackColor = $t.AccentHover
    $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
    # Focus ring: a white 2px inner border reads clearly against the accent fill (6.37:1). On blur,
    # restore the border to match the fill (read from the control, so no captured palette var needed).
    $Button.Add_GotFocus({ $b = $args[0]; $b.FlatAppearance.BorderColor = [System.Drawing.Color]::White; $b.FlatAppearance.BorderSize = 2 })
    $Button.Add_LostFocus({ $b = $args[0]; $b.FlatAppearance.BorderColor = $b.BackColor; $b.FlatAppearance.BorderSize = 1 })
}

function Set-DangerButtonStyle {
    <# Destructive action (Delete). Distinct from constructive secondary buttons: the danger color is
       on the *border* (an affordance that survives grayscale / color-blindness), not just the glyph,
       per Nielsen #5 Error Prevention. Built on the secondary style so it keeps the focus ring. #>
    param([System.Windows.Forms.Button]$Button)
    $t = Get-Theme
    Set-SecondaryButtonStyle $Button
    $Button.FlatAppearance.BorderColor = $t.ErrText
    $Button.ForeColor = $t.ErrText
}

function Set-ControlTheme {
    <#
        Dark-theme the input controls under $Root that DON'T inherit ambient colors. WinForms TextBox /
        ComboBox / ListBox / CheckedListBox / ListView render white regardless of their parent, so we
        set them explicitly. Labels, Panels, GroupBoxes inherit ForeColor/BackColor from the form, so
        we leave them alone -- preserving intentional header (Brand), muted, and error colors. Buttons
        keep their style helpers. Idempotent + recursive; call after building a form/dialog and after
        any rebuild that creates fresh field controls (Build-TabForm / Build-ExchangeForm).
    #>
    param([System.Windows.Forms.Control]$Root)
    if (-not $Root) { return }
    $t = Get-Theme
    foreach ($c in $Root.Controls) {
        switch ($c.GetType().Name) {
            'TextBox' {
                $c.BorderStyle = 'FixedSingle'
                $c.BackColor = if ($c.ReadOnly) { $t.ReadOnlyBg } else { $t.InputBg }
                $c.ForeColor = $t.Text
            }
            'ComboBox'       { $c.FlatStyle = 'Flat'; $c.BackColor = $t.InputBg; $c.ForeColor = $t.Text }
            'ListBox'        { $c.BorderStyle = 'FixedSingle'; $c.BackColor = $t.InputBg; $c.ForeColor = $t.Text }
            'CheckedListBox' { $c.BorderStyle = 'FixedSingle'; $c.BackColor = $t.InputBg; $c.ForeColor = $t.Text }
            'ListView'       { $c.BackColor = $t.InputBg; $c.ForeColor = $t.Text }
            'DateTimePicker' { $c.CalendarMonthBackground = $t.InputBg; $c.CalendarForeColor = $t.Text }
            'NumericUpDown'  { $c.BackColor = $t.InputBg; $c.ForeColor = $t.Text }
        }
        if ($c.HasChildren) { Set-ControlTheme -Root $c }
    }
}

function Set-DialogTheme {
    <# Dark-theme a modal dialog Form to match the main window: dark surface + light text, themed
       inputs, and flat-styled buttons (otherwise dialogs render as light popups on the dark app).
       Call right before ShowDialog. Native OS file dialogs (Open/Save) can't be themed -- skip those. #>
    param([System.Windows.Forms.Form]$Form)
    if (-not $Form) { return }
    $t = Get-Theme
    $Form.BackColor = $t.Surface
    $Form.ForeColor = $t.Text
    Set-ControlTheme -Root $Form
    Set-DialogButtonStyle -Root $Form
}

function Set-DialogButtonStyle {
    <# Recursively give every Button under $Root the flat secondary style (dialogs build plain default
       buttons, which look light on the dark theme). Primary CTAs can be re-styled by the caller after. #>
    param([System.Windows.Forms.Control]$Root)
    foreach ($c in $Root.Controls) {
        if ($c -is [System.Windows.Forms.Button]) { Set-SecondaryButtonStyle $c }
        if ($c.HasChildren) { Set-DialogButtonStyle -Root $c }
    }
}

function Set-Progress {
    param([string]$Text, [int]$Value = -1, [int]$Max = -1)
    # Narrate the working dialog too (when it's open), so the existing 'doing X...' call sites show the
    # current step on top of the window instead of only in the easily-missed bottom status bar.
    if ($script:ProgressDlg -and -not $script:ProgressDlg.Form.IsDisposed -and $script:ProgressDlg.Form.Visible) {
        $script:ProgressDlg.Status.Text = $Text
    }
    if ($script:UI -and $script:UI.Status) {
        $script:UI.Status.Text = $Text
        if ($script:UI.Progress) {
            if ($Max -gt 0)   { $script:UI.Progress.Maximum = $Max }
            if ($Value -ge 0) { $script:UI.Progress.Value = [Math]::Min($Value, $script:UI.Progress.Maximum) }
        }
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Set-UiBusy {
    param([bool]$Busy)
    if (-not $script:UI -or -not $script:UI.Form) { return }
    $script:UI.Busy = $Busy
    $script:UI.Form.Cursor = if ($Busy) { [System.Windows.Forms.Cursors]::WaitCursor } else { [System.Windows.Forms.Cursors]::Default }
    # Block re-entrant input while a long Graph/AD/EXO call runs: Set-Progress pumps DoEvents(), so
    # without this a second click would re-enter Save/Delete/Connect mid-operation. Disable the page
    # content + the sidebar nav + the Connect/Switch button (all unconditionally enabled when idle, so
    # restoring them on completion is always correct -- unlike DisconnectBtn, whose state is conn-driven).
    foreach ($c in @($script:UI.PageHost, $script:UI.NavPanel, $script:UI.ConnectBtn)) {
        if ($c) { $c.Enabled = -not $Busy }
    }
    [System.Windows.Forms.Application]::DoEvents()
}
