<#
    A small themed "working..." dialog so long operations show WHAT is happening instead of a dead,
    silent window.

    Why this exists: most of the slow work in this app (the Microsoft Graph module import, the
    interactive Connect-MgGraph sign-in, the per-connect Graph reads, an RSAT import + DC discovery)
    is bound to the Microsoft Graph SDK session, which lives in the runspace that called
    Connect-MgGraph -- the WinForms UI thread. It therefore CANNOT be moved to a background runspace
    without migrating the whole Graph layer (a separate, larger change). So we do the honest thing:
    show a labelled dialog with the current step BEFORE each blocking call. Between steps the label
    updates and the message loop is pumped (Set-Progress -> DoEvents), so the window never goes a
    dead grey rectangle; during a single multi-second Graph call the marquee will briefly stop (the
    UI thread is busy), but the operator can always see what the app is doing.

    Set-Progress (UiTheme.ps1) dual-writes to this dialog's status line when it's open, so the ~15
    existing Set-Progress 'doing X...' call sites narrate the dialog for free.

    Headless/offline (M365UGM_NOLAUNCH) -> Show-ProgressDialog is a no-op, so the form-build tests
    stay windowless.
#>

$script:ProgressDlg = $null   # singleton handle: @{ Form; Title; Status; Bar } -- reused across operations

function New-ProgressDialogForm {
    <# Build the reusable working dialog (once). Borderless, no control box, centered on the owner. #>
    $t = Get-Theme
    $f = New-Object System.Windows.Forms.Form
    $f.FormBorderStyle = 'FixedDialog'
    $f.ControlBox      = $false          # no close X -- the operation controls its lifetime
    $f.MinimizeBox     = $false; $f.MaximizeBox = $false
    $f.ShowInTaskbar   = $false
    $f.StartPosition   = 'CenterParent'
    $f.Text            = ''
    $f.ClientSize      = New-Object System.Drawing.Size(440, 150)
    $f.BackColor       = $t.Surface
    $f.ForeColor       = $t.Text

    $title = New-Object System.Windows.Forms.Label
    $title.Font = $t.FontSection; $title.ForeColor = $t.Header
    $title.AutoSize = $false
    $title.Location = New-Object System.Drawing.Point(20, 18)
    $title.Size = New-Object System.Drawing.Size(400, 24)
    $title.Text = 'Working...'

    $status = New-Object System.Windows.Forms.Label
    $status.Font = $t.FontBase; $status.ForeColor = $t.Text; $status.AutoEllipsis = $true
    $status.Location = New-Object System.Drawing.Point(20, 48)
    $status.Size = New-Object System.Drawing.Size(400, 42)
    $status.Text = 'Please wait...'

    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Style = 'Marquee'; $bar.MarqueeAnimationSpeed = 30
    $bar.Location = New-Object System.Drawing.Point(20, 96)
    $bar.Size = New-Object System.Drawing.Size(400, 16)

    $f.Controls.Add($title); $f.Controls.Add($status); $f.Controls.Add($bar)
    return @{ Form = $f; Title = $title; Status = $status; Bar = $bar }
}

function Show-ProgressDialog {
    <# Show (or re-use) the working dialog over the main window with a fresh title. No-op when there's
       no main form yet or we're in headless/offline mode. #>
    param([string]$Title = 'Working...')
    if ($env:M365UGM_NOLAUNCH) { return }
    if (-not $script:UI -or -not $script:UI.Form -or $script:UI.Form.IsDisposed) { return }
    if (-not $script:ProgressDlg -or $script:ProgressDlg.Form.IsDisposed) { $script:ProgressDlg = New-ProgressDialogForm }
    $dlg = $script:ProgressDlg
    $dlg.Title.Text  = $Title
    $dlg.Status.Text = 'Please wait...'
    try {
        $dlg.Form.Owner = $script:UI.Form          # owned -> always paints above the main window, auto-closes with it
        if (-not $dlg.Form.Visible) { $dlg.Form.Show($script:UI.Form) }
        $dlg.Form.BringToFront()
        [System.Windows.Forms.Application]::DoEvents()
    } catch { }
}

function Hide-ProgressDialog {
    <# Hide the working dialog (kept alive for re-use). Safe if it was never shown or is disposed. #>
    if ($script:ProgressDlg -and -not $script:ProgressDlg.Form.IsDisposed -and $script:ProgressDlg.Form.Visible) {
        try { $script:ProgressDlg.Form.Hide(); [System.Windows.Forms.Application]::DoEvents() } catch { }
    }
}

function Close-ProgressDialog {
    <# Dispose the working dialog (on app close). #>
    if ($script:ProgressDlg) {
        try { if (-not $script:ProgressDlg.Form.IsDisposed) { $script:ProgressDlg.Form.Dispose() } } catch { }
        $script:ProgressDlg = $null
    }
}

function Invoke-WithProgress {
    <#
        Run $Work on the UI thread with the working dialog shown and input locked. Returns whatever
        $Work returns. Re-entrant-safe: if a busy state is already in effect (e.g. the connect flow
        already called Set-UiBusy), this does NOT toggle busy off underneath the caller -- it only
        manages the state it itself created. Input is locked BEFORE the dialog's first pump so a
        queued click can't re-enter through the pump window.
    #>
    param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][scriptblock]$Work)
    $ownBusy = -not ($script:UI -and $script:UI.Busy)
    if ($ownBusy) { Set-UiBusy $true }
    Show-ProgressDialog -Title $Title
    try {
        return (& $Work)
    } finally {
        Hide-ProgressDialog
        if ($ownBusy) { Set-UiBusy $false }
    }
}
