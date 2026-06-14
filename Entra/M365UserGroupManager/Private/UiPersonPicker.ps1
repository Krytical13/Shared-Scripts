<#
    Person / object picker dialog.

    A modal search-and-pick window used for manager (single) and group members / owners (many).
    Searches the directory live and returns the chosen objects as normalised hashtables
    @{ Id; DisplayName; Detail; Type }, or $null if cancelled / nothing chosen.

    Requires an active Graph connection (the caller is expected to be connected, but this guards
    anyway). The lookup runs on the UI thread with a wait cursor -- result sets are capped at 50,
    which keeps a single search responsive.
#>

function Show-PersonPicker {
    param(
        [switch]$Multi,
        [ValidateSet('User', 'Group', 'Any')][string]$TargetType = 'User',
        [ValidateSet('Graph', 'Exchange')][string]$Source = 'Graph'
    )

    if ($Source -eq 'Exchange') {
        if (-not (Test-ExoConnected)) {
            [System.Windows.Forms.MessageBox]::Show('Activate Exchange Online first.', 'Not connected', 'OK', 'Information') | Out-Null
            return $null
        }
    } elseif (-not (Test-GraphConnected)) {
        [System.Windows.Forms.MessageBox]::Show('Connect to Microsoft 365 first.', 'Not connected', 'OK', 'Information') | Out-Null
        return $null
    }

    $t = Get-Theme
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = if ($Multi) { 'Select people / objects' } else { 'Select a person' }
    $dlg.Size = New-Object System.Drawing.Size(560, 460)
    $dlg.MinimumSize = New-Object System.Drawing.Size(460, 360)
    $dlg.StartPosition = 'CenterParent'
    $dlg.Font = $t.FontBase
    $dlg.FormBorderStyle = 'Sizable'
    $dlg.ShowInTaskbar = $false

    # --- Search row -------------------------------------------------------------------------
    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Location = New-Object System.Drawing.Point(12, 14)
    $searchBox.Size = New-Object System.Drawing.Size(330, 24)
    $searchBox.Anchor = 'Top,Left,Right'

    $searchBtn = New-Object System.Windows.Forms.Button
    $searchBtn.Text = '&Search'
    $searchBtn.Location = New-Object System.Drawing.Point(348, 13)
    $searchBtn.Size = New-Object System.Drawing.Size(80, 26)
    $searchBtn.Anchor = 'Top,Right'
    Set-SecondaryButtonStyle $searchBtn

    # Optional User/Group toggle for 'Any' targets (Graph only; Exchange ANR returns all types).
    $radUser = $null; $radGroup = $null
    $listTop = 46
    if ($TargetType -eq 'Any' -and $Source -eq 'Graph') {
        $radUser = New-Object System.Windows.Forms.RadioButton
        $radUser.Text = '&Users'; $radUser.Checked = $true; $radUser.AutoSize = $true
        $radUser.Location = New-Object System.Drawing.Point(12, 46)
        $radGroup = New-Object System.Windows.Forms.RadioButton
        $radGroup.Text = '&Groups'; $radGroup.AutoSize = $true
        $radGroup.Location = New-Object System.Drawing.Point(86, 46)
        $listTop = 74
    }

    # --- Results list -----------------------------------------------------------------------
    $list = New-Object System.Windows.Forms.ListView
    $list.Location = New-Object System.Drawing.Point(12, $listTop)
    $list.Size = New-Object System.Drawing.Size(416, ($dlg.ClientSize.Height - $listTop - 56))
    $list.View = 'Details'
    $list.FullRowSelect = $true
    $list.MultiSelect = [bool]$Multi
    $list.CheckBoxes = [bool]$Multi
    $list.GridLines = $true
    $list.HideSelection = $false
    $list.Anchor = 'Top,Bottom,Left,Right'
    [void]$list.Columns.Add('Name', 200)
    [void]$list.Columns.Add('UPN / Mail', 150)
    [void]$list.Columns.Add('Type', 50)

    # --- OK / Cancel ------------------------------------------------------------------------
    $okBtn = New-Object System.Windows.Forms.Button
    $okBtn.Text = 'OK'; $okBtn.Size = New-Object System.Drawing.Size(80, 28)
    $okBtn.Anchor = 'Bottom,Right'; $okBtn.DialogResult = 'OK'
    Set-PrimaryButtonStyle $okBtn
    $cancelBtn = New-Object System.Windows.Forms.Button
    $cancelBtn.Text = 'Cancel'; $cancelBtn.Size = New-Object System.Drawing.Size(80, 28)
    $cancelBtn.Anchor = 'Bottom,Right'; $cancelBtn.DialogResult = 'Cancel'
    Set-SecondaryButtonStyle $cancelBtn
    # Position from the bottom-right; re-anchored on resize.
    $okBtn.Location = New-Object System.Drawing.Point(($dlg.ClientSize.Width - 176), ($dlg.ClientSize.Height - 40))
    $cancelBtn.Location = New-Object System.Drawing.Point(($dlg.ClientSize.Width - 90), ($dlg.ClientSize.Height - 40))

    $dlg.Controls.AddRange(@($searchBox, $searchBtn, $list, $okBtn, $cancelBtn))
    if ($radUser) { $dlg.Controls.AddRange(@($radUser, $radGroup)) }
    $dlg.AcceptButton = $searchBtn
    $dlg.CancelButton = $cancelBtn

    # --- Search action ----------------------------------------------------------------------
    $doSearch = {
        $q = $searchBox.Text.Trim()   # blank = browse: the Search functions list the first 100
        $list.Items.Clear()
        $dlg.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        try {
            if ($Source -eq 'Exchange') {
                foreach ($r in (Search-ExoRecipient -Query $q)) {
                    $it = New-Object System.Windows.Forms.ListViewItem([string]$r.DisplayName)
                    [void]$it.SubItems.Add([string]$r.PrimarySmtpAddress)
                    [void]$it.SubItems.Add([string]$r.RecipientTypeDetails)
                    $it.Tag = ConvertTo-ExoPersonInfo $r
                    [void]$list.Items.Add($it)
                }
                return
            }
            $searchGroups = ($TargetType -eq 'Group') -or ($radGroup -and $radGroup.Checked)
            if ($searchGroups) {
                foreach ($g in (Search-DirectoryGroup -Query $q)) {
                    $it = New-Object System.Windows.Forms.ListViewItem([string]$g.DisplayName)
                    [void]$it.SubItems.Add([string]$g.Mail)
                    [void]$it.SubItems.Add('Group')
                    $it.Tag = @{ Id = [string]$g.Id; DisplayName = [string]$g.DisplayName; Detail = [string]$g.Mail; Type = 'Group' }
                    [void]$list.Items.Add($it)
                }
            } else {
                foreach ($u in (Search-DirectoryUser -Query $q)) {
                    $it = New-Object System.Windows.Forms.ListViewItem([string]$u.DisplayName)
                    [void]$it.SubItems.Add([string]$u.UserPrincipalName)
                    [void]$it.SubItems.Add('User')
                    $it.Tag = @{ Id = [string]$u.Id; DisplayName = [string]$u.DisplayName; Detail = [string]$u.UserPrincipalName; Type = 'User' }
                    [void]$list.Items.Add($it)
                }
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Search failed:`n$($_.Exception.Message)", 'Search error', 'OK', 'Warning') | Out-Null
        } finally {
            $dlg.Cursor = [System.Windows.Forms.Cursors]::Default
        }
    }
    $searchBtn.Add_Click($doSearch)
    # Enter in the search box triggers search rather than closing the dialog.
    $searchBox.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; & $doSearch } }.GetNewClosure())
    # Double-click a row in single-select mode = pick it.
    if (-not $Multi) {
        $list.Add_DoubleClick({ if ($list.SelectedItems.Count -gt 0) { $dlg.DialogResult = 'OK'; $dlg.Close() } })
    }
    # Auto-list the first 100 on open so the dialog is a browser, not just a search box.
    $dlg.Add_Shown({ & $doSearch }.GetNewClosure())

    if ($dlg.ShowDialog() -ne 'OK') { $dlg.Dispose(); return $null }

    $chosen = New-Object System.Collections.Generic.List[object]
    if ($Multi) {
        foreach ($it in $list.CheckedItems) { [void]$chosen.Add($it.Tag) }
    } else {
        foreach ($it in $list.SelectedItems) { [void]$chosen.Add($it.Tag) }
    }
    $dlg.Dispose()
    if ($chosen.Count -eq 0) { return $null }
    # .ToArray() (not @($chosen)): @() over a List of hashtables throws on Windows PowerShell 5.1.
    # Leading comma preserves a single-element array through the function return.
    return , $chosen.ToArray()
}
