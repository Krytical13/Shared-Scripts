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

    # --- Disconnected overlay: shared locked-overlay helper --------------------------------
    $apprOv = New-LockedOverlay -Title 'Approvals' `
        -Body 'Review and approve pending Multi-Admin-Approval requests. Connect to Microsoft 365 to begin.' `
        -ButtonText 'Connect to Microsoft 365' -OnClick { Invoke-Account }
    $overlay = $apprOv.Panel
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
    $note.Text = "You can't approve your own request -- a different admin must. Approving here completes the change in the cloud (Intune still requires the original requestor to finalize device deletes). Double-click a row for full details."
    $note.AutoSize = $true; $note.MaximumSize = New-Object System.Drawing.Size(700, 0); $note.ForeColor = $t.Muted; $note.Margin = New-Object System.Windows.Forms.Padding(4, 0, 4, 6)
    $content.Controls.Add($note, 0, 1)

    $list = New-Object System.Windows.Forms.ListView
    $list.Dock = 'Fill'; $list.View = 'Details'; $list.FullRowSelect = $true; $list.GridLines = $true; $list.MultiSelect = $false; $list.HideSelection = $false
    [void]$list.Columns.Add('Requested', 125); [void]$list.Columns.Add('Requestor', 165); [void]$list.Columns.Add('Operation', 150); [void]$list.Columns.Add('Justification', 280); [void]$list.Columns.Add('Expires', 125)
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
    $list.Add_DoubleClick({
        $sel = $script:UI.Approval.List.SelectedItems
        if ($sel.Count -gt 0 -and $sel[0].Tag -and $sel[0].Tag.Raw) {
            Show-DetailDialog -Title 'Approval request details' -Text (Format-ApprovalDetail $sel[0].Tag.Raw)
        }
    })

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

function Get-ApprovalRequestorName {
    <# The operationApprovalRequest 'requestor' is an identitySet (application/device/USER), NOT a user
       object -- there is no userPrincipalName. Return the first identity's displayName (user preferred),
       falling back to its id. #>
    param($Request)
    $requestor = Get-GraphVal $Request 'requestor'
    if (-not $requestor) { return '' }
    foreach ($kind in 'user', 'application', 'device') {
        $ident = Get-GraphVal $requestor $kind
        if (-not $ident) { continue }
        $dn = [string](Get-GraphVal $ident 'displayName')
        if ($dn) { return $dn }
        $idv = [string](Get-GraphVal $ident 'id')
        if ($idv) { return $idv }
    }
    return ''
}

function Get-ApprovalOperationText {
    <# requiredOperationApprovalPolicyTypes is a string collection (e.g. deviceDelete, app, role) -- what
       the request is asking to do. Join for the grid. #>
    param($Request)
    $ops = @(Get-GraphVal $Request 'requiredOperationApprovalPolicyTypes')
    return (($ops | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ', ')
}

function Format-ApprovalDetail {
    <# A labelled, copy/paste-friendly dump of every meaningful field on a request (for the details dialog). #>
    param($Request)
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add("Request ID:     $([string](Get-GraphVal $Request 'id'))")
    [void]$lines.Add("Status:         $([string](Get-GraphVal $Request 'status'))")
    [void]$lines.Add("Requested:      $([string](Get-GraphVal $Request 'requestDateTime'))")
    [void]$lines.Add("Expires:        $([string](Get-GraphVal $Request 'expirationDateTime'))")
    [void]$lines.Add("Last modified:  $([string](Get-GraphVal $Request 'lastModifiedDateTime'))")
    [void]$lines.Add("Requestor:      $(Get-ApprovalRequestorName $Request)")
    [void]$lines.Add("Operation(s):   $(Get-ApprovalOperationText $Request)")
    [void]$lines.Add("Justification:  $([string](Get-GraphVal $Request 'requestJustification'))")
    $approver = Get-ApprovalRequestorName ([pscustomobject]@{ requestor = (Get-GraphVal $Request 'approver') })
    if ($approver) { [void]$lines.Add("Approver:       $approver") }
    $aj = [string](Get-GraphVal $Request 'approvalJustification')
    if ($aj) { [void]$lines.Add("Approval note:  $aj") }
    return ($lines -join "`r`n")
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
            catch { $script:UI.Approval.LoadError = (Get-VerboseErrorText $_) }
        } | Out-Null
        if ($script:UiClosing) { return }
        $reqs = @($a.LoadedRequests); $err = $a.LoadError; $a.LoadedRequests = $null; $a.LoadError = $null

        $a.List.Items.Clear(); $a.ApproveBtn.Enabled = $false; $a.RejectBtn.Enabled = $false
        if ($err) {
            Set-Progress 'Could not read approvals.'
            Show-DetailDialog -Title 'Could not read approvals' -Danger -Text "Reading pending Multi-Admin-Approval requests failed.`r`n`r`n(This tenant may not have Intune / MAA enabled, or the account may lack the DeviceManagementRBAC.Read.All scope.)`r`n`r`n--- Error detail ---`r`n$err"
            return
        }
        foreach ($r in $reqs) {
            $who = Get-ApprovalRequestorName $r
            $item = New-Object System.Windows.Forms.ListViewItem([string](Get-GraphVal $r 'requestDateTime'))
            [void]$item.SubItems.Add($who)
            [void]$item.SubItems.Add((Get-ApprovalOperationText $r))
            [void]$item.SubItems.Add([string](Get-GraphVal $r 'requestJustification'))
            [void]$item.SubItems.Add([string](Get-GraphVal $r 'expirationDateTime'))
            $item.Tag = @{ Id = [string](Get-GraphVal $r 'id'); Upn = $who; Raw = $r }
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
    $note = Show-TextInput -Title "$verb request" -Prompt "$verb the request from $($tag.Upn).`n`nReason / justification (REQUIRED -- recorded with the decision):" -Default ''
    if ($null -eq $note) { return }   # cancelled
    if ([string]::IsNullOrWhiteSpace($note)) {
        [System.Windows.Forms.MessageBox]::Show('A justification is required to approve or reject a request.', "$verb request", 'OK', 'Warning') | Out-Null
        return
    }
    Set-UiBusy $true
    try {
        $ok = $true; $msg = ''
        Invoke-WithProgress -Title "$verb request" -Work {
            try { Submit-OperationApprovalDecision -Id $tag.Id -Decision $Decision -Justification $note }
            catch { $script:UI.Approval.DecisionError = (Get-VerboseErrorText $_) }
        } | Out-Null
        if ($script:UiClosing) { return }
        $msg = $a.DecisionError; $a.DecisionError = $null
        if ($msg) {
            Show-DetailDialog -Title "$verb failed" -Danger -Text "Couldn't $Decision the request.`r`n`r`nCommon causes: you can't approve your OWN request (a different admin must), and only an authorized approver can act. The full error is below -- use Copy to share it with an admin.`r`n`r`n--- Error detail ---`r`n$msg"
        } else {
            Set-Progress "Request ${Decision}d."
        }
    } finally { Set-UiBusy $false }
    Invoke-ApprovalsRefresh
}
