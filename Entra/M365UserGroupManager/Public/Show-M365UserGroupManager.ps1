function Show-M365UserGroupManager {
    <#
    .SYNOPSIS
        Opens the M365 User / Group Manager window.

    .DESCRIPTION
        Loads WinForms, reads saved configuration (tenants + which attributes to show), builds
        the main window, reflects any existing Microsoft Graph session, and shows the form modally.

        Normally launched via Start-M365UserGroupManager.ps1 (which guarantees STA and installs
        the Graph SDK). You can also call this directly after Import-Module if those prerequisites
        are already met.

    .EXAMPLE
        Show-M365UserGroupManager

    .NOTES
        Set $env:M365UGM_NOLAUNCH = '1' to build and return the form WITHOUT showing it
        (used by the offline verification tests).
    #>
    [CmdletBinding()]
    param()

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    try { [System.Windows.Forms.Application]::SetHighDpiMode([System.Windows.Forms.HighDpiMode]::SystemAware) | Out-Null } catch { }
    try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }
    try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

    # Resilience: route any unhandled WinForms exception to a clean dialog instead of the raw
    # .NET crash dialog, and keep the window alive. Must be set before any window is created.
    try {
        [System.Windows.Forms.Application]::SetUnhandledExceptionMode([System.Windows.Forms.UnhandledExceptionMode]::CatchException)
        [System.Windows.Forms.Application]::add_ThreadException([System.Threading.ThreadExceptionEventHandler] {
                param($evtSender, $evtArgs)
                try {
                    if ($script:UI -and $script:UI.Status) { $script:UI.Status.Text = "Error: $($evtArgs.Exception.Message)" }
                    [System.Windows.Forms.MessageBox]::Show("An unexpected error occurred:`n`n$($evtArgs.Exception.Message)", 'Unexpected error', 'OK', 'Error') | Out-Null
                } catch { }
            })
    } catch { }

    # Load persisted config (tenants + per-tab enabled attributes).
    $script:Config = Get-AppConfig

    $form = New-MainForm

    # Reflect any pre-existing Graph session in the LABEL only. Get-MgContext is local and never
    # prompts; we deliberately make NO Graph calls at startup (no SKU load, no connect). The
    # window opens idle and the Connect button is the only thing that talks to Microsoft 365.
    Update-ConnectionLabel

    if ($env:M365UGM_NOLAUNCH) {
        return $form   # offline/test mode: hand back the form without showing it
    }

    # The window is about to show; from here on, user-initiated actions may reach Graph.
    $script:AppReady = $true
    [void]$form.ShowDialog()
    $form.Dispose()
}
