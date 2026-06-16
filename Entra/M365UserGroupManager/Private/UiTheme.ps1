<#
    UI theme + status helpers.

    A single cached palette/font set keeps the look consistent, plus helpers to style the two
    button tiers (flat secondary / accent-filled primary) and to push status + progress to the
    bottom bar. Set-Progress is a no-op until the main form has populated $script:UI.
#>

function Get-Theme {
    if (-not $script:Theme) {
        # Palette: brand cyan (#00AEEF) stays as the bright *decorative* accent (top
        # rule, selection) where WCAG non-text-contrast rules are relaxed; a deeper cyan (#016595)
        # carries every *functional* element -- section headers, primary fill, secondary borders --
        # because it clears WCAG AA: white-on-#016595 = 6.37:1 and #016595-on-white = 6.37:1, where
        # the old #0277A8 sat on the 4.99:1 knife-edge and Brand cyan on white is only 2.53:1 (below
        # the 3:1 SC 1.4.11 floor for a control boundary). AccentHover goes *darker* (#015076, white
        # text 8.7:1) so hover never drops contrast. All System.Drawing.Color -> identical on PS 5.1/7.
        $script:Theme = @{
            Brand       = [System.Drawing.Color]::FromArgb(0, 174, 239)    # #00AEEF -- decorative accent / selection only
            Accent      = [System.Drawing.Color]::FromArgb(1, 101, 149)    # #016595 -- headers + primary fill + control borders (6.37:1)
            AccentHover = [System.Drawing.Color]::FromArgb(1, 80, 118)     # #015076 -- darker hover, white text 8.7:1
            Surface     = [System.Drawing.Color]::White                    # form / field background
            SurfaceAlt  = [System.Drawing.Color]::FromArgb(240, 249, 253)  # very light cyan tint (bars / panels)
            Text        = [System.Drawing.Color]::FromArgb(26, 43, 51)     # main text (dark slate)
            Muted       = [System.Drawing.Color]::FromArgb(91, 103, 112)   # secondary text (5.4:1 on white / SurfaceAlt)
            Border      = [System.Drawing.Color]::FromArgb(203, 217, 224)  # subtle borders (decorative only)
            OkText      = [System.Drawing.Color]::FromArgb(0, 120, 90)
            OkBack      = [System.Drawing.Color]::FromArgb(223, 246, 238)
            ErrText     = [System.Drawing.Color]::FromArgb(178, 34, 34)
            ErrBack     = [System.Drawing.Color]::FromArgb(251, 233, 233)
            WarnText    = [System.Drawing.Color]::FromArgb(176, 96, 0)      # "synced from AD" badge
            BtnFace     = [System.Drawing.Color]::White                    # secondary button bg
            BtnText     = [System.Drawing.Color]::FromArgb(26, 43, 51)
            ReadOnlyBg  = [System.Drawing.Color]::FromArgb(240, 244, 246)
            ProgBack    = [System.Drawing.Color]::FromArgb(227, 238, 243)
            # --- spacing scale (4px base) + shared control heights: one token, no ad-hoc literals ---
            GapSm       = 4
            Gap         = 8
            GapLg       = 16
            BtnH        = 28                                               # secondary / inline buttons
            BtnHPrimary = 34                                               # the one primary action per row
            FontBase    = New-Object System.Drawing.Font('Segoe UI', 9)
            FontBold    = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
            FontMedium  = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
            FontSection = New-Object System.Drawing.Font('Segoe UI', 10.5, [System.Drawing.FontStyle]::Bold)  # section headers, a clear step above 9pt labels
            FontLarge   = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
            FontTitle   = New-Object System.Drawing.Font('Segoe UI Semibold', 13)  # on-canvas H1
        }
    }
    return $script:Theme
}

function Set-SecondaryButtonStyle {
    param([System.Windows.Forms.Button]$Button)
    $t = Get-Theme
    $Button.FlatStyle = 'Flat'
    $Button.FlatAppearance.BorderColor = $t.Accent          # #016595 = 6.37:1 on white (was Brand 2.53:1, failed SC 1.4.11)
    $Button.FlatAppearance.BorderSize = 1
    $Button.FlatAppearance.MouseOverBackColor = $t.SurfaceAlt
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

function Set-Progress {
    param([string]$Text, [int]$Value = -1, [int]$Max = -1)
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
    # without this a second click would re-enter Save/Delete/Connect mid-operation. Disable only the
    # tab area + the Connect/Switch button (both are unconditionally enabled when idle, so restoring
    # them on completion is always correct -- unlike DisconnectBtn, whose state is connection-driven).
    foreach ($c in @($script:UI.Tabs, $script:UI.ConnectBtn)) {
        if ($c) { $c.Enabled = -not $Busy }
    }
    [System.Windows.Forms.Application]::DoEvents()
}
