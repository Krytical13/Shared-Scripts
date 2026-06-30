<#
    Approvals page -- review + approve/reject pending Multi-Admin-Approval (MAA) requests.

    When the tenant gates Intune operations (device delete/wipe, app/script/policy changes, role
    assignments, ...) behind MAA, each change becomes a pending operationApprovalRequest that a DIFFERENT
    admin must approve. This page lists those pending requests and lets a tech approve/reject them in the
    tool instead of the portal. Delegated/interactive sign-in is allowed to approve (app auth is not), and
    the service enforces that you can't approve your OWN request.

    All calls are raw beta Invoke-MgGraphRequest (no Microsoft.Graph.Beta.* module). Gated behind a Graph
    sign-in. State: $script:UI.Approval.
#>

function New-ApprovalsTab {
    $t = Get-Theme
    $page = New-Object System.Windows.Forms.Panel
    $page.Dock = 'Fill'; $page.BackColor = $t.Surface; $page.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)

    # --- Disconnected overlay --------------------------------------------------------------
    $overlay = New-Object System.Windows.Forms.TableLayoutPanel
    $overlay.Dock = 'Fill'; $overlay.BackColor = $t.Surface; $overlay.ColumnCount = 1; $overlay.RowCount = 3
    [void]$overlay.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 38)))
    [void]$overlay.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$overlay.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 62)))
    $ov = New-Object System.Windows.Forms.FlowLayoutPanel
    $ov.FlowDirection = 'TopDown'; $ov.WrapContents = $false; $ov.AutoSize = $true; $ov.AutoSizeMode = 'GrowAndShrink'; $ov.Anchor = 'None'
    $ovTitle = New-Object System.Windows.Forms.Label; $ovTitle.Text = 'Approvals'; $ovTitle.Font = $t.FontLarge; $ovTitle.ForeColor = $t.Header; $ovTitle.AutoSize = $true; $ovTitle.Margin = New-Object System.Windows.Forms.Padding(3, 3, 3, 6)
    $ovText = New-Object System.Windows.Forms.Label; $ovText.Text = 'Review and approve pending Multi-Admin-Approval requests. Connect to Microsoft 365 to begin.'
    $ovText.AutoSize = $true; $ovText.MaximumSize = New-Object System.Drawing.Size(440, 0); $ovText.ForeColor = $t.Muted; $ovText.Margin = New-Object System.Windows.Forms.Padding(3, 0, 3, 14)
    $ovBtn = New-Object System.Windows.Forms.Button; $ovBtn.Text = 'Connect to Microsoft 365'; $ovBtn.Width = 240; $ovBtn.Height = 38; $ovBtn.Font = $t.FontMedium
    Set-PrimaryButtonStyle $ovBtn; $ovBtn.Add_Click({ Invoke-Account })
    $ov.Controls.AddRange(@($ovTitle, $ovText, $ovBtn)); $overlay.Controls.Add($ov, 0, 1)
    $page.Controls.Add($overlay)

    # --- Content (shown when connected) ----------------------------------------------------
    $content = New-Object System.Windows.Forms.TableLayoutPanel
    $content.Dock = 'Fill'; $content.ColumnCount = 1; $content.RowCount = 4; $content.Visible = $false
    [void]$content.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))   # header/refresh
    [void]$content.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))   # note
    [void]$content.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))   # list
    [void]$content.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 50)))   # actions

    $headerRow = New-Object System.Windows.Forms.FlowLayoutPanel; $headerRow.FlowDirection = 'LeftToRight'; $headerRow.WrapContents = $false; $headerRow.AutoSize = $true; $headerRow.Margin = New-Object System.Windows.Forms.Padding(4, 4, 4, 4)
    $title = New-Object System.Windows.Forms.Label; $title.Text = 'Pending Multi-Admin-Approval requests'; $title.AutoSize = $true; $title.Font = $t.FontMedium; $title.ForeColor = $t.Header; $title.Margin = New-Object System.Windows.Forms.Padding(3, 8, 16, 3)
    $refreshBtn = New-Object System.Windows.Forms.Button; $refreshBtn.Text = '&Refresh'; $refreshBtn.Width = 100; $refreshBtn.Height = $t.BtnH; $refreshBtn.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 3)
    Set-SecondaryButtonStyle $refreshBtn
    $headerRow.Controls.AddRange(@($title, $refreshBtn)); $content.Controls.Add($headerRow, 0, 0)

    $note = New-Object System.Windows.Forms.Label
    $note.Text = "You can't approve your own request -- a different admin must. Approving here completes the change in the cloud (Intune still requires the original requestor to finalize device deletes)."
    $note.AutoSize = $true; $note.MaximumSize = New-Object System.Drawing.Size(700, 0); $note.ForeColor = $t.Muted; $note.Margin = New-Object System.Windows.Forms.Padding(4, 0, 4, 6)
    $content.Controls.Add($note, 0, 1)

    $list = New-Object System.Windows.Forms.ListView
    $list.Dock = 'Fill'; $list.View = 'Details'; $list.FullRowSelect = $true; $list.GridLines = $true; $list.MultiSelect = $false; $list.HideSelection = $false
    [void]$list.Columns.Add('Requested', 140); [void]$list.Columns.Add('Requestor', 200); [void]$list.Columns.Add('Justification', 320); [void]$list.Columns.Add('Expires', 140)
    $content.Controls.Add($list, 0, 2)

    $actions = New-Object System.Windows.Forms.FlowLayoutPanel; $actions.Dock = 'Fill'; $actions.FlowDirection = 'LeftToRight'; $actions.WrapContents = $false
    $approveBtn = New-Object System.Windows.Forms.Button; $approveBtn.Text = '&Approve'; $approveBtn.Width = 130; $approveBtn.Height = $t.BtnHPrimary; $approveBtn.Font = $t.FontMedium; $approveBtn.Enabled = $false; $approveBtn.Margin = New-Object System.Windows.Forms.Padding(4, 7, 8, 7)
    Set-PrimaryButtonStyle $approveBtn
    $rejectBtn = New-Object System.Windows.Forms.Button; $rejectBtn.Text = '&Reject'; $rejectBtn.Width = 130; $rejectBtn.Height = $t.BtnHPrimary; $rejectBtn.Enabled = $false; $rejectBtn.Margin = New-Object System.Windows.Forms.Padding(3, 7, 3, 7)
    Set-DangerButtonStyle $rejectBtn
    $actions.Controls.AddRange(@($approveBtn, $rejectBtn)); $content.Controls.Add($actions, 0, 3)
    $page.Controls.Add($content)

    $script:UI.Approval = @{
        Page = $page; Overlay = $overlay; Content = $content
        List = $list; RefreshBtn = $refreshBtn; ApproveBtn = $approveBtn; RejectBtn = $rejectBtn
    }

    $refreshBtn.Add_Click({ Invoke-ApprovalsRefresh })
    $list.Add_SelectedIndexChanged({
        $on = ($script:UI.Approval.List.SelectedItems.Count -gt 0)
        $script:UI.Approval.ApproveBtn.Enabled = $on; $script:UI.Approval.RejectBtn.Enabled = $on
    })
    $approveBtn.Add_Click({ Invoke-ApprovalDecision -Decision 'approve' })
    $rejectBtn.Add_Click({ Invoke-ApprovalDecision -Decision 'reject' })

    Set-ControlTheme -Root $page
    return $page
}

function Update-ApprovalsActivation {
    <# Gate the page behind a Graph session; auto-load the pending list on (re)connect. #>
    if (-not $script:UI -or -not $script:UI.Approval) { return }
    $connected = Test-GraphConnected
    $a = $script:UI.Approval
    $a.Overlay.Visible = -not $connected
    $a.Content.Visible = $connected
    if (-not $connected) {
        $a.Overlay.BringToFront(); $a.List.Items.Clear(); $a.ApproveBtn.Enabled = $false; $a.RejectBtn.Enabled = $false
    } else { $a.Content.BringToFront() }
}

function Invoke-ApprovalsRefresh {
    <# Load pending MAA requests into the list. Graceful: a tenant without MAA / Intune just shows empty. #>
    if (-not (Test-GraphConnected)) { return }
    $a = $script:UI.Approval
    Set-UiBusy $true
    try {
        $reqs = @()
        $err = $null
        Invoke-WithProgress -Title 'Loading approvals' -Work {
            Set-Progress 'Reading pending Multi-Admin-Approval requests...'
            try { $script:UI.Approval.LoadedRequests = @(Get-PendingApprovalRequests) }
            catch { $script:UI.Approval.LoadError = "$($_.Exception.Message)" }
        } | Out-Null
        if ($script:UiClosing) { return }
        $reqs = @($a.LoadedRequests); $err = $a.LoadError; $a.LoadedRequests = $null; $a.LoadError = $null

        $a.List.Items.Clear(); $a.ApproveBtn.Enabled = $false; $a.RejectBtn.Enabled = $false
        if ($err) { Set-Progress "Could not read approvals: $err"; return }
        foreach ($r in $reqs) {
            $requestor = Get-GraphVal $r 'requestor'
            $upn = if ($requestor) { [string](Get-GraphVal $requestor 'userPrincipalName') } else { '' }
            $item = New-Object System.Windows.Forms.ListViewItem([string](Get-GraphVal $r 'requestDateTime'))
            [void]$item.SubItems.Add($upn)
            [void]$item.SubItems.Add([string](Get-GraphVal $r 'justification'))
            [void]$item.SubItems.Add([string](Get-GraphVal $r 'expirationDateTime'))
            $item.Tag = @{ Id = [string](Get-GraphVal $r 'id'); Upn = $upn }
            [void]$a.List.Items.Add($item)
        }
        Set-Progress "$($reqs.Count) pending approval request(s)."
    } finally { Set-UiBusy $false }
}

function Invoke-ApprovalDecision {
    <# Approve or reject the selected request (with an optional note). Refreshes after. #>
    param([ValidateSet('approve', 'reject')][string]$Decision)
    if (-not (Test-GraphConnected)) { return }
    $a = $script:UI.Approval
    if ($a.List.SelectedItems.Count -eq 0) { return }
    $tag = $a.List.SelectedItems[0].Tag
    $verb = if ($Decision -eq 'approve') { 'Approve' } else { 'Reject' }
    $note = Show-TextInput -Title "$verb request" -Prompt "$verb the request from $($tag.Upn).`n`nOptional note (recorded with the decision):" -Default ''
    if ($null -eq $note) { return }   # cancelled
    Set-UiBusy $true
    try {
        $ok = $true; $msg = ''
        Invoke-WithProgress -Title "$verb request" -Work {
            try { Submit-OperationApprovalDecision -Id $tag.Id -Decision $Decision -Justification $note }
            catch { $script:UI.Approval.DecisionError = "$($_.Exception.Message)" }
        } | Out-Null
        if ($script:UiClosing) { return }
        $msg = $a.DecisionError; $a.DecisionError = $null
        if ($msg) {
            [System.Windows.Forms.MessageBox]::Show("Couldn't $Decision the request:`n$msg`n`n(You can't approve your own request, and only an authorized admin can.)", "$verb failed", 'OK', 'Warning') | Out-Null
        } else {
            Set-Progress "Request ${Decision}d."
        }
    } finally { Set-UiBusy $false }
    Invoke-ApprovalsRefresh
}
