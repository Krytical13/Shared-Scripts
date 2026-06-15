<#
    UI theme + status helpers.

    A single cached palette/font set keeps the look consistent, plus helpers to style the two
    button tiers (flat secondary / accent-filled primary) and to push status + progress to the
    bottom bar. Set-Progress is a no-op until the main form has populated $script:UI.
#>

function Get-Theme {
    if (-not $script:Theme) {
        # Palette: brand cyan (#00AEEF) as the bright accent, a deeper cyan (#0277A8)
        # for headers + primary buttons (white text stays readable), on clean white surfaces. All
        # System.Drawing.Color so it works identically on Windows PowerShell 5.1 and 7.
        $script:Theme = @{
            Brand       = [System.Drawing.Color]::FromArgb(0, 174, 239)    # #00AEEF -- accents, rules, selection
            Accent      = [System.Drawing.Color]::FromArgb(2, 119, 168)    # #0277A8 -- section headers + primary fill
            AccentHover = [System.Drawing.Color]::FromArgb(2, 137, 191)    # button hover
            Surface     = [System.Drawing.Color]::White                    # form / field background
            SurfaceAlt  = [System.Drawing.Color]::FromArgb(240, 249, 253)  # very light cyan tint (bars / panels)
            Text        = [System.Drawing.Color]::FromArgb(26, 43, 51)     # main text (dark slate)
            Muted       = [System.Drawing.Color]::FromArgb(91, 103, 112)   # secondary text
            Border      = [System.Drawing.Color]::FromArgb(203, 217, 224)  # subtle borders
            OkText      = [System.Drawing.Color]::FromArgb(0, 120, 90)
            OkBack      = [System.Drawing.Color]::FromArgb(223, 246, 238)
            ErrText     = [System.Drawing.Color]::FromArgb(178, 34, 34)
            ErrBack     = [System.Drawing.Color]::FromArgb(251, 233, 233)
            WarnText    = [System.Drawing.Color]::FromArgb(176, 96, 0)      # "synced from AD" badge
            BtnFace     = [System.Drawing.Color]::White                    # secondary button bg
            BtnText     = [System.Drawing.Color]::FromArgb(26, 43, 51)
            ReadOnlyBg  = [System.Drawing.Color]::FromArgb(240, 244, 246)
            ProgBack    = [System.Drawing.Color]::FromArgb(227, 238, 243)
            FontBase    = New-Object System.Drawing.Font('Segoe UI', 9)
            FontBold    = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
            FontMedium  = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
            FontLarge   = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
            FontTitle   = New-Object System.Drawing.Font('Segoe UI Semibold', 12)
        }
    }
    return $script:Theme
}

function Set-SecondaryButtonStyle {
    param([System.Windows.Forms.Button]$Button)
    $t = Get-Theme
    $Button.FlatStyle = 'Flat'
    $Button.FlatAppearance.BorderColor = $t.Brand
    $Button.FlatAppearance.BorderSize = 1
    $Button.FlatAppearance.MouseOverBackColor = $t.SurfaceAlt
    $Button.BackColor = $t.BtnFace
    $Button.ForeColor = $t.BtnText
    $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
}

function Set-PrimaryButtonStyle {
    param([System.Windows.Forms.Button]$Button)
    $t = Get-Theme
    $Button.FlatStyle = 'Flat'
    $Button.BackColor = $t.Accent
    $Button.ForeColor = [System.Drawing.Color]::White
    $Button.FlatAppearance.BorderColor = $t.Accent
    $Button.FlatAppearance.MouseOverBackColor = $t.AccentHover
    $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
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
