<#
    Devices page -- re-image cleanup across the four stores a device lives in:
      * on-prem AD computer object   (on-prem; reuses the explicit Connect-on-prem + forest guard)
      * SCCM / ConfigMgr device       (on-prem; AdminService discovery + Remove-CMDevice over WinRM)
      * Intune managed device         (cloud; delete is Multi-Admin-Approval aware -> may go PENDING)
      * Entra ID device object        (cloud)

    Find a device by hostname -> see its presence/status in each store -> tick which to remove -> a typed
    confirmation -> per-store result line. Gated behind a Graph sign-in (Intune is the always-present leg);
    the two on-prem legs show their own reachability. Server locations come from the per-tenant config
    (Settings), never hardcoded.

    State: $script:UI.Device; transient $script:State.SelectedDevice.
#>

$script:DeviceStoreDefs = @(
    @{ Key = 'AdComputer';  Label = 'On-prem AD computer' }
    @{ Key = 'Sccm';        Label = 'SCCM / ConfigMgr' }
    @{ Key = 'Intune';      Label = 'Intune managed device' }
    @{ Key = 'EntraDevice'; Label = 'Entra ID device' }
)

function New-DeviceTab {
    $t = Get-Theme
    $page = New-Object System.Windows.Forms.Panel
    $page.Dock = 'Fill'; $page.BackColor = $t.Surface; $page.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)

    # --- Disconnected overlay (mirrors the User/Group empty-state) --------------------------
    $overlay = New-Object System.Windows.Forms.TableLayoutPanel
    $overlay.Dock = 'Fill'; $overlay.BackColor = $t.Surface; $overlay.ColumnCount = 1; $overlay.RowCount = 3
    [void]$overlay.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 38)))
    [void]$overlay.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$overlay.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 62)))
    $ov = New-Object System.Windows.Forms.FlowLayoutPanel
    $ov.FlowDirection = 'TopDown'; $ov.WrapContents = $false; $ov.AutoSize = $true; $ov.AutoSizeMode = 'GrowAndShrink'; $ov.Anchor = 'None'
    $ovTitle = New-Object System.Windows.Forms.Label; $ovTitle.Text = 'Devices'; $ovTitle.Font = $t.FontLarge; $ovTitle.ForeColor = $t.Header; $ovTitle.AutoSize = $true; $ovTitle.Margin = New-Object System.Windows.Forms.Padding(3, 3, 3, 6)
    $ovText = New-Object System.Windows.Forms.Label; $ovText.Text = 'Find a device and clean it up across AD, SCCM, Intune and Entra after a re-image. Connect to Microsoft 365 to begin.'
    $ovText.AutoSize = $true; $ovText.MaximumSize = New-Object System.Drawing.Size(440, 0); $ovText.ForeColor = $t.Muted; $ovText.Margin = New-Object System.Windows.Forms.Padding(3, 0, 3, 14)
    $ovBtn = New-Object System.Windows.Forms.Button; $ovBtn.Text = 'Connect to Microsoft 365'; $ovBtn.Width = 240; $ovBtn.Height = 38; $ovBtn.Font = $t.FontMedium
    Set-PrimaryButtonStyle $ovBtn; $ovBtn.Add_Click({ Invoke-Account })
    $ov.Controls.AddRange(@($ovTitle, $ovText, $ovBtn)); $overlay.Controls.Add($ov, 0, 1)
    $page.Controls.Add($overlay)

    # --- Management content (shown when connected) -----------------------------------------
    $content = New-Object System.Windows.Forms.TableLayoutPanel
    $content.Dock = 'Fill'; $content.ColumnCount = 1; $content.RowCount = 2; $content.Visible = $false
    [void]$content.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$content.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 50)))

    $scroll = New-Object System.Windows.Forms.Panel; $scroll.Dock = 'Fill'; $scroll.AutoScroll = $true
    $stack = New-Object System.Windows.Forms.FlowLayoutPanel; $stack.FlowDirection = 'TopDown'; $stack.WrapContents = $false; $stack.AutoSize = $true; $stack.AutoSizeMode = 'GrowAndShrink'; $stack.Dock = 'Top'
    $scroll.Controls.Add($stack); $content.Controls.Add($scroll, 0, 0)

    $intro = New-Object System.Windows.Forms.Label; $intro.Text = 'Re-image cleanup: find a device by name, then remove it from the stores you select.'
    $intro.AutoSize = $true; $intro.ForeColor = $t.Muted; $intro.Margin = New-Object System.Windows.Forms.Padding(4, 6, 4, 8)
    [void]$stack.Controls.Add($intro)

    $searchRow = New-Object System.Windows.Forms.FlowLayoutPanel; $searchRow.FlowDirection = 'LeftToRight'; $searchRow.WrapContents = $false; $searchRow.AutoSize = $true; $searchRow.Margin = New-Object System.Windows.Forms.Padding(4, 0, 4, 8)
    $nameLbl = New-Object System.Windows.Forms.Label; $nameLbl.Text = 'Device name:'; $nameLbl.AutoSize = $true; $nameLbl.Font = $t.FontMedium; $nameLbl.Margin = New-Object System.Windows.Forms.Padding(3, 9, 8, 3)
    $nameBox = New-Object System.Windows.Forms.TextBox; $nameBox.Width = 260; $nameBox.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 3)
    $findBtn = New-Object System.Windows.Forms.Button; $findBtn.Text = '&Find'; $findBtn.Width = 90; $findBtn.Height = $t.BtnH; $findBtn.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
    Set-SecondaryButtonStyle $findBtn
    $searchRow.Controls.AddRange(@($nameLbl, $nameBox, $findBtn)); [void]$stack.Controls.Add($searchRow)

    # Per-store status grid: store name | status | include checkbox.
    $grid = New-Object System.Windows.Forms.TableLayoutPanel; $grid.AutoSize = $true; $grid.AutoSizeMode = 'GrowAndShrink'; $grid.ColumnCount = 3; $grid.RowCount = $script:DeviceStoreDefs.Count; $grid.Margin = New-Object System.Windows.Forms.Padding(4, 2, 4, 8)
    [void]$grid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 190)))
    [void]$grid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 440)))
    [void]$grid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $defaults = @($script:Config.DeviceCleanupTargets)
    $stores = @{}
    $r = 0
    foreach ($s in $script:DeviceStoreDefs) {
        $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = $s.Label; $lbl.AutoSize = $true; $lbl.Font = $t.FontBold; $lbl.Anchor = 'Left'; $lbl.Margin = New-Object System.Windows.Forms.Padding(3, 7, 8, 5)
        $stat = New-Object System.Windows.Forms.Label; $stat.Text = "$([char]0x2014)"; $stat.AutoSize = $true; $stat.ForeColor = $t.Muted; $stat.Anchor = 'Left'; $stat.MaximumSize = New-Object System.Drawing.Size(440, 0); $stat.Margin = New-Object System.Windows.Forms.Padding(3, 7, 8, 5)
        $chk = New-Object System.Windows.Forms.CheckBox; $chk.Text = 'remove'; $chk.AutoSize = $true; $chk.Enabled = $false; $chk.Checked = ($defaults -contains $s.Key); $chk.Anchor = 'Left'; $chk.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 5)
        $grid.Controls.Add($lbl, 0, $r); $grid.Controls.Add($stat, 1, $r); $grid.Controls.Add($chk, 2, $r)
        $stores[$s.Key] = @{ StatusLbl = $stat; Check = $chk; Result = $null; Label = $s.Label }
        $r++
    }
    [void]$stack.Controls.Add($grid)

    $note = New-Object System.Windows.Forms.Label
    $note.Text = "Intune deletes may require Multi-Admin Approval -- if so, the request is submitted and another admin must approve it (see the Approvals area). On-prem stores (AD / SCCM) need an on-prem connection to the device's network."
    $note.AutoSize = $true; $note.MaximumSize = New-Object System.Drawing.Size(640, 0); $note.ForeColor = $t.Muted; $note.Margin = New-Object System.Windows.Forms.Padding(4, 0, 4, 4)
    [void]$stack.Controls.Add($note)

    # Actions bar: Clean up (danger) + result line.
    $actions = New-Object System.Windows.Forms.TableLayoutPanel; $actions.Dock = 'Fill'; $actions.ColumnCount = 2; $actions.RowCount = 1
    [void]$actions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$actions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $cleanupBtn = New-Object System.Windows.Forms.Button; $cleanupBtn.Text = 'Clean up (re-image)'; $cleanupBtn.Width = 180; $cleanupBtn.Height = $t.BtnHPrimary; $cleanupBtn.Font = $t.FontMedium; $cleanupBtn.Enabled = $false; $cleanupBtn.Margin = New-Object System.Windows.Forms.Padding(4, 7, 8, 7)
    Set-DangerButtonStyle $cleanupBtn
    $resultLbl = New-Object System.Windows.Forms.Label; $resultLbl.AutoSize = $true; $resultLbl.ForeColor = $t.Text; $resultLbl.Anchor = 'Left'; $resultLbl.MaximumSize = New-Object System.Drawing.Size(700, 0); $resultLbl.Margin = New-Object System.Windows.Forms.Padding(8, 12, 8, 3)
    $actions.Controls.Add($cleanupBtn, 0, 0); $actions.Controls.Add($resultLbl, 1, 0)
    $content.Controls.Add($actions, 0, 1)
    $page.Controls.Add($content)

    $script:UI.Device = @{
        Page = $page; Overlay = $overlay; Content = $content
        NameBox = $nameBox; FindBtn = $findBtn; CleanupBtn = $cleanupBtn; ResultLbl = $resultLbl
        Stores = $stores
    }

    $findBtn.Add_Click({ Invoke-DeviceLookup })
    $nameBox.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Invoke-DeviceLookup } })
    $cleanupBtn.Add_Click({ Invoke-DeviceCleanup })

    Set-ControlTheme -Root $page
    return $page
}

function Update-DeviceActivation {
    <# Show the connect overlay until a Graph session exists; reveal the device tools once connected. #>
    if (-not $script:UI -or -not $script:UI.Device) { return }
    $connected = Test-GraphConnected
    $d = $script:UI.Device
    $d.Overlay.Visible = -not $connected
    $d.Content.Visible = $connected
    if (-not $connected) {
        $d.Overlay.BringToFront()
        # Reset transient state on disconnect so a stale lookup can't linger.
        foreach ($k in $d.Stores.Keys) { $d.Stores[$k].Result = $null; $d.Stores[$k].StatusLbl.Text = "$([char]0x2014)"; $d.Stores[$k].Check.Enabled = $false }
        $d.CleanupBtn.Enabled = $false; $d.ResultLbl.Text = ''
        $script:State.SelectedDevice = $null
    } else { $d.Content.BringToFront() }
}

function Invoke-DeviceLookup {
    <# Find the named device across all four stores and populate the status grid (read-only; GET is never
       MAA-gated). Cloud stores always; on-prem stores only when on-prem is connected / configured. #>
    if (-not (Test-GraphConnected)) { return }
    $d = $script:UI.Device
    $name = $d.NameBox.Text.Trim()
    if (-not $name) { Set-Progress 'Enter a device name to find.'; return }

    $t = Get-Theme
    $adState = Get-AdState
    $onPremReady = [bool]($adState.Checked -and $adState.Available)
    $sccmServer  = Get-TenantProfileValue -Field 'SccmServer'

    Set-UiBusy $true
    try {
        $results = @{}
        Invoke-WithProgress -Title "Finding $name" -Work {
            Set-Progress 'Checking Intune...';      $results.Intune      = Find-IntuneDevice -Name $name
            Set-Progress 'Checking Entra ID...';    $results.EntraDevice = Find-EntraDevice  -Name $name
            Set-Progress 'Checking Active Directory...'
            $results.AdComputer = if ($onPremReady) { Find-AdComputer -Name $name -Dc $adState.Dc }
                                  else { @{ Found = $false; Reason = 'Connect on-prem AD (sidebar) to check.'; NotReady = $true } }
            Set-Progress 'Checking Configuration Manager...'
            $results.Sccm = Find-SccmDevice -Name $name -Server $sccmServer -TimeoutSec ([Math]::Ceiling(([int]$script:Config.WinRmTimeoutMs) / 1000))
        } | Out-Null

        $any = $false
        foreach ($s in $script:DeviceStoreDefs) {
            $res = $results[$s.Key]; $store = $d.Stores[$s.Key]; $store.Result = $res
            if ($res.Found) {
                $extra = if ($res.Count -gt 1) { " (+$([int]$res.Count - 1) more match)" } else { '' }
                $store.StatusLbl.Text = "Found$extra -- $($res.Detail)"; $store.StatusLbl.ForeColor = $t.OkText
                $store.Check.Enabled = $true; $any = $true
            } else {
                $store.StatusLbl.Text = $res.Reason
                $store.StatusLbl.ForeColor = if ($res.Error) { $t.ErrText } elseif ($res.NotConfigured -or $res.NotReady) { $t.WarnText } else { $t.Muted }
                $store.Check.Enabled = $false
            }
        }
        $script:State.SelectedDevice = @{ Name = $name; Results = $results }
        $d.CleanupBtn.Enabled = $any
        Set-Progress $(if ($any) { "Found $name in one or more stores." } else { "No record of $name found." })
    } finally { Set-UiBusy $false }
}

function Invoke-DeviceCleanup {
    <# Remove the device from the ticked stores. Typed-hostname confirmation; collect-and-continue per
       store; Intune is last and Multi-Admin-Approval aware (may report PENDING, not deleted). #>
    if (-not (Test-GraphConnected) -or -not $script:State.SelectedDevice) { return }
    $d = $script:UI.Device
    $name = [string]$script:State.SelectedDevice.Name

    # Which ticked stores actually have a found object.
    $selected = New-Object System.Collections.Generic.List[string]
    foreach ($s in $script:DeviceStoreDefs) {
        $store = $d.Stores[$s.Key]
        if ($store.Check.Enabled -and $store.Check.Checked -and $store.Result -and $store.Result.Found) { [void]$selected.Add($s.Key) }
    }
    if ($selected.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Nothing selected to remove (tick a store that found the device).', 'Device cleanup', 'OK', 'Information') | Out-Null; return }

    $labels = ($selected | ForEach-Object { ($script:DeviceStoreDefs | Where-Object Key -eq $_).Label }) -join ', '
    if (-not (Show-TypedConfirm -Expected $name -Prompt (
        "Permanently remove '$name' from:`n`n    $labels`n`nThis is destructive and cannot be undone. To confirm, type the device name exactly:"))) { return }

    $adState = Get-AdState
    $sccmServer = Get-TenantProfileValue -Field 'SccmServer'
    $sccmSite   = Get-TenantProfileValue -Field 'SccmSiteCode'
    $justification = "Re-image device cleanup of '$name' via M365 User/Group Manager."
    $summary = New-Object System.Collections.Generic.List[string]

    Set-UiBusy $true
    try {
        Invoke-WithProgress -Title "Cleaning up $name" -Work {
            foreach ($key in $selected) {
                $res = $d.Stores[$key].Result
                $label = $d.Stores[$key].Label
                Set-Progress "Removing from $label..."
                $outcome = switch ($key) {
                    'AdComputer'  { Remove-DeviceFromAd -Result $res -Dc $adState.Dc -DeviceName $name }
                    'Sccm'        { Remove-DeviceFromSccm -Result $res -Server $sccmServer -SiteCode $sccmSite }
                    'EntraDevice' { Remove-DeviceFromEntra -Result $res }
                    'Intune'      { Remove-DeviceFromIntune -Result $res -Justification $justification }
                }
                [void]$summary.Add("$label`: $outcome")
            }
        } | Out-Null
    } finally { Set-UiBusy $false }

    $d.ResultLbl.Text = ($summary -join '   |   ')
    [System.Windows.Forms.MessageBox]::Show("Cleanup of '$name':`n`n  " + ($summary -join "`n  "), 'Device cleanup', 'OK', 'Information') | Out-Null
    Invoke-DeviceLookup   # refresh status (deleted stores now show "not found"; pending Intune still shows)
}

# --- Per-store delete helpers (return a short status string for the summary; never throw) ----------

function Remove-DeviceFromAd {
    param($Result, [string]$Dc, [string]$DeviceName)
    if (-not $Dc) { return 'skipped (on-prem not connected)' }
    try {
        if ($Result.Protected) {
            $ok = [System.Windows.Forms.MessageBox]::Show(
                "'$DeviceName' is protected from accidental deletion in AD. Remove that protection and delete it?",
                'Protected object', 'YesNo', 'Warning')
            if ($ok -ne 'Yes') { return 'skipped (protected)' }
            Remove-AdComputerObject -Dn $Result.Id -Dc $Dc -ClearProtection
        } else {
            Remove-AdComputerObject -Dn $Result.Id -Dc $Dc
        }
        return 'deleted'
    } catch { return "error: $($_.Exception.Message)" }
}

function Remove-DeviceFromSccm {
    param($Result, [string]$Server, [string]$SiteCode)
    if (-not $Server -or -not $SiteCode) { return 'skipped (SCCM server/site not configured)' }
    $r = Remove-SccmDeviceRemote -Server $Server -SiteCode $SiteCode -ResourceId ([int]$Result.Id)
    if ($r.Removed) { return 'deleted' }
    return "error: $($r.Error)"
}

function Remove-DeviceFromEntra {
    param($Result)
    try { Remove-EntraDeviceObject -Id $Result.Id; return 'deleted' }
    catch { return "error: $($_.Exception.Message)" }
}

function Remove-DeviceFromIntune {
    <# Multi-Admin-Approval aware: 204 -> deleted; the expected 403 ApprovalRequired -> pending (submitted,
       another admin must approve); anything else -> error. #>
    param($Result, [string]$Justification)
    try {
        $hdr = @{ 'x-msft-approval-justification' = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Justification)) }
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($Result.Id)" -Headers $hdr -ErrorAction Stop | Out-Null
        return 'deleted'
    } catch {
        if (Test-IntuneApprovalRequiredResponse $_) { return 'PENDING approval (submitted -- another admin must approve in Intune)' }
        return "error: $($_.Exception.Message)"
    }
}
