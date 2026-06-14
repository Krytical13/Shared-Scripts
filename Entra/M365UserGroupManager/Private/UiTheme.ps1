<#
    UI theme + status helpers.

    A single cached palette/font set keeps the look consistent, plus helpers to style the two
    button tiers (flat secondary / accent-filled primary) and to push status + progress to the
    bottom bar. Set-Progress is a no-op until the main form has populated $script:UI.
#>

function Get-Theme {
    if (-not $script:Theme) {
        $script:Theme = @{
            Accent     = [System.Drawing.Color]::FromArgb(37, 99, 183)
            OkText     = [System.Drawing.Color]::FromArgb(0, 120, 90)
            OkBack     = [System.Drawing.Color]::FromArgb(223, 246, 238)
            ErrText    = [System.Drawing.Color]::FromArgb(168, 0, 0)
            ErrBack    = [System.Drawing.Color]::FromArgb(251, 233, 233)
            BtnFace    = [System.Drawing.Color]::FromArgb(240, 240, 240)
            BtnText    = [System.Drawing.Color]::FromArgb(32, 32, 32)
            Muted      = [System.Drawing.Color]::FromArgb(60, 64, 67)
            ReadOnlyBg = [System.Drawing.Color]::FromArgb(244, 245, 247)
            ProgBack   = [System.Drawing.Color]::FromArgb(229, 232, 237)
            FontBase   = New-Object System.Drawing.Font('Segoe UI', 9)
            FontBold   = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
            FontMedium = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
            FontLarge  = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
        }
    }
    return $script:Theme
}

function Set-SecondaryButtonStyle {
    param([System.Windows.Forms.Button]$Button)
    $t = Get-Theme
    $Button.FlatStyle = 'Flat'
    $Button.FlatAppearance.BorderColor = $t.Accent
    $Button.FlatAppearance.BorderSize = 1
    $Button.BackColor = $t.BtnFace
    $Button.ForeColor = $t.BtnText
}

function Set-PrimaryButtonStyle {
    param([System.Windows.Forms.Button]$Button)
    $t = Get-Theme
    $Button.FlatStyle = 'Flat'
    $Button.BackColor = $t.Accent
    $Button.ForeColor = [System.Drawing.Color]::White
    $Button.FlatAppearance.BorderColor = $t.Accent
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
    $script:UI.Form.Cursor = if ($Busy) { [System.Windows.Forms.Cursors]::WaitCursor } else { [System.Windows.Forms.Cursors]::Default }
    [System.Windows.Forms.Application]::DoEvents()
}
