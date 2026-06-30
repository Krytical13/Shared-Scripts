<#
    Config / Settings dialog.

    Generic, environment-specific server locations + app preferences -- nothing hardcoded. Most settings
    are PER-TENANT (each hybrid tenant has its own ConfigMgr/SCCM server + domain controllers; the
    cloud-only tenant has neither), stored on the connected tenant's Accounts[] profile. A few are global.

    Scope for now: edit the CONNECTED tenant's servers (you connect to a tenant to work on it, then
    configure its servers) + the global device-cleanup defaults. A multi-tenant selector can be layered
    on later. Returns $true if the user accepted changes (caller refreshes the affected UI).

    Sections (no TabControl -- its tabs don't dark-theme; cyan section headers like the fields dialog):
      * Microsoft Configuration Manager (SCCM)  -- per-tenant: SMS Provider FQDN + site code + a Test button
      * Active Directory domain controllers     -- per-tenant: optional preferred DC list (blank = auto-discover)
      * Device cleanup defaults                 -- global: which stores are ticked by default; WinRM timeout
#>

function Show-ConfigDialog {
    $t = Get-Theme
    $tid = Get-ConnectedTenantId
    $connected = [bool]$tid
    $tenantName = if ($connected) {
        $acct = Get-TenantProfile -TenantId $tid
        if ($acct -and $acct.Name) { [string]$acct.Name } else { $tid }
    } else { '' }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Settings'
    $dlg.Size = New-Object System.Drawing.Size(620, 640)
    $dlg.MinimumSize = New-Object System.Drawing.Size(520, 480)
    $dlg.StartPosition = 'CenterParent'
    $dlg.Font = $t.FontBase
    $dlg.ShowInTaskbar = $false

    $root = New-Object System.Windows.Forms.TableLayoutPanel
    $root.Dock = 'Fill'; $root.ColumnCount = 1; $root.RowCount = 3
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 48)))
    $dlg.Controls.Add($root)

    # --- Top: which tenant these per-tenant settings apply to -------------------------------
    $hdr = New-Object System.Windows.Forms.Label
    $hdr.Dock = 'Fill'; $hdr.TextAlign = 'MiddleLeft'; $hdr.Padding = New-Object System.Windows.Forms.Padding(8, 0, 8, 0)
    if ($connected) { $hdr.Text = "Server settings for: $tenantName"; $hdr.ForeColor = $t.Text }
    else { $hdr.Text = 'Not connected -- connect to a tenant to set its servers (global defaults below are still editable).'; $hdr.ForeColor = $t.WarnText }
    $root.Controls.Add($hdr, 0, 0)

    # --- Middle: scrollable sections -------------------------------------------------------
    $scroll = New-Object System.Windows.Forms.Panel; $scroll.Dock = 'Fill'; $scroll.AutoScroll = $true
    $body = New-Object System.Windows.Forms.TableLayoutPanel
    $body.Dock = 'Top'; $body.AutoSize = $true; $body.AutoSizeMode = 'GrowAndShrink'; $body.ColumnCount = 1
    [void]$body.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $scroll.Controls.Add($body)
    $root.Controls.Add($scroll, 0, 1)

    $section = {
        param($Text)
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $Text; $l.AutoSize = $true; $l.Font = $t.FontSection; $l.ForeColor = $t.Header
        $l.Margin = New-Object System.Windows.Forms.Padding(8, 14, 8, 4)
        $body.Controls.Add($l)
    }
    $fieldRow = {
        param($LabelText, $Control, $HelpText)
        $row = New-Object System.Windows.Forms.TableLayoutPanel
        $row.AutoSize = $true; $row.AutoSizeMode = 'GrowAndShrink'; $row.ColumnCount = 2; $row.Dock = 'Top'; $row.Margin = New-Object System.Windows.Forms.Padding(20, 2, 8, 2)
        [void]$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
        [void]$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = $LabelText; $lbl.AutoSize = $true; $lbl.Anchor = 'Left'; $lbl.Margin = New-Object System.Windows.Forms.Padding(3, 7, 8, 3)
        $row.Controls.Add($lbl, 0, 0); $row.Controls.Add($Control, 1, 0)
        $body.Controls.Add($row)
        if ($HelpText) {
            $h = New-Object System.Windows.Forms.Label; $h.Text = $HelpText; $h.AutoSize = $true; $h.MaximumSize = New-Object System.Drawing.Size(520, 0)
            $h.ForeColor = $t.Muted; $h.Margin = New-Object System.Windows.Forms.Padding(173, 0, 8, 4)
            $body.Controls.Add($h)
        }
    }

    # ===== SCCM (per-tenant) ================================================================
    & $section 'Microsoft Configuration Manager (SCCM)'
    $sccmServerBox = New-Object System.Windows.Forms.TextBox; $sccmServerBox.Width = 320; $sccmServerBox.Anchor = 'Left'
    $sccmServerBox.Text = if ($connected) { Get-TenantProfileValue -Field 'SccmServer' } else { '' }
    $sccmServerBox.Enabled = $connected
    & $fieldRow 'SMS Provider FQDN:' $sccmServerBox 'The ConfigMgr SMS Provider / site server (AdminService discovery + the host that runs the delete over WinRM).'
    $sccmSiteBox = New-Object System.Windows.Forms.TextBox; $sccmSiteBox.Width = 80; $sccmSiteBox.Anchor = 'Left'; $sccmSiteBox.MaxLength = 3
    $sccmSiteBox.Text = if ($connected) { Get-TenantProfileValue -Field 'SccmSiteCode' } else { '' }
    $sccmSiteBox.Enabled = $connected
    & $fieldRow 'Site code:' $sccmSiteBox '3-character ConfigMgr site code (e.g. P01).'
    $sccmTestPanel = New-Object System.Windows.Forms.FlowLayoutPanel; $sccmTestPanel.AutoSize = $true; $sccmTestPanel.WrapContents = $false; $sccmTestPanel.Margin = New-Object System.Windows.Forms.Padding(173, 2, 8, 6)
    $sccmTestBtn = New-Object System.Windows.Forms.Button; $sccmTestBtn.Text = 'Test connection'; $sccmTestBtn.Width = 120; $sccmTestBtn.Height = $t.BtnH; $sccmTestBtn.Enabled = $connected
    Set-SecondaryButtonStyle $sccmTestBtn
    $sccmTestLbl = New-Object System.Windows.Forms.Label; $sccmTestLbl.AutoSize = $true; $sccmTestLbl.ForeColor = $t.Muted; $sccmTestLbl.Margin = New-Object System.Windows.Forms.Padding(10, 8, 3, 3); $sccmTestLbl.MaximumSize = New-Object System.Drawing.Size(360, 0)
    $sccmTestPanel.Controls.AddRange(@($sccmTestBtn, $sccmTestLbl))
    $body.Controls.Add($sccmTestPanel)
    # Built-in cmdlets only inside the closure (GetNewClosure loses module affinity on 5.1) -- capture the
    # controls + the theme. Hits the AdminService $metadata, integrated Windows auth, bounded timeout.
    $sccmTestBtn.Add_Click({
        $srv = $sccmServerBox.Text.Trim()
        if (-not $srv) { $sccmTestLbl.Text = 'Enter the SMS Provider FQDN first.'; $sccmTestLbl.ForeColor = $t.WarnText; return }
        $sccmTestLbl.Text = 'Testing...'; $sccmTestLbl.ForeColor = $t.Muted
        [System.Windows.Forms.Application]::DoEvents()
        try {
            $uri = "https://$srv/AdminService/v1.0/`$metadata"
            [void](Invoke-RestMethod -Uri $uri -UseDefaultCredentials -TimeoutSec 8 -ErrorAction Stop)
            $sccmTestLbl.Text = 'Reachable -- AdminService responded.'; $sccmTestLbl.ForeColor = $t.OkText
        } catch {
            $sccmTestLbl.Text = "Failed: $($_.Exception.Message)"; $sccmTestLbl.ForeColor = $t.ErrText
        }
    }.GetNewClosure())

    # ===== Active Directory DCs (per-tenant, optional) ======================================
    & $section 'Active Directory -- domain controllers (optional)'
    $adNote = New-Object System.Windows.Forms.Label
    $adNote.Text = "Optional preferred DC FQDNs/IPs for this tenant's forest. Blank = auto-discover a writable DC. Each one is still verified to belong to the tenant's expected domain before any write."
    $adNote.AutoSize = $true; $adNote.MaximumSize = New-Object System.Drawing.Size(540, 0); $adNote.ForeColor = $t.Muted; $adNote.Margin = New-Object System.Windows.Forms.Padding(20, 0, 8, 4)
    $body.Controls.Add($adNote)
    $adRow = New-Object System.Windows.Forms.TableLayoutPanel; $adRow.AutoSize = $true; $adRow.AutoSizeMode = 'GrowAndShrink'; $adRow.ColumnCount = 2; $adRow.Dock = 'Top'; $adRow.Margin = New-Object System.Windows.Forms.Padding(20, 2, 8, 6)
    [void]$adRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$adRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $adList = New-Object System.Windows.Forms.ListBox; $adList.Height = 80; $adList.Dock = 'Fill'; $adList.Enabled = $connected
    if ($connected) { foreach ($s in (Get-TenantProfileList -Field 'AdServers')) { [void]$adList.Items.Add([string]$s) } }
    $adBtns = New-Object System.Windows.Forms.FlowLayoutPanel; $adBtns.FlowDirection = 'TopDown'; $adBtns.WrapContents = $false; $adBtns.AutoSize = $true; $adBtns.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
    $adAddBox = New-Object System.Windows.Forms.TextBox; $adAddBox.Width = 150; $adAddBox.Enabled = $connected
    $adAddBtn = New-Object System.Windows.Forms.Button; $adAddBtn.Text = 'Add'; $adAddBtn.Width = 70; $adAddBtn.Height = $t.BtnH; $adAddBtn.Enabled = $connected
    $adRemBtn = New-Object System.Windows.Forms.Button; $adRemBtn.Text = 'Remove'; $adRemBtn.Width = 70; $adRemBtn.Height = $t.BtnH; $adRemBtn.Enabled = $connected
    Set-SecondaryButtonStyle $adAddBtn; Set-SecondaryButtonStyle $adRemBtn
    $adBtns.Controls.AddRange(@($adAddBox, $adAddBtn, $adRemBtn))
    $adRow.Controls.Add($adList, 0, 0); $adRow.Controls.Add($adBtns, 1, 0)
    $body.Controls.Add($adRow)
    $adAddBtn.Add_Click({
        $v = $adAddBox.Text.Trim()
        if ($v -and (-not $adList.Items.Contains($v))) { [void]$adList.Items.Add($v); $adAddBox.Clear() }
    }.GetNewClosure())
    $adRemBtn.Add_Click({ if ($adList.SelectedIndex -ge 0) { $adList.Items.RemoveAt($adList.SelectedIndex) } }.GetNewClosure())

    # ===== Device cleanup defaults (global) =================================================
    & $section 'Device cleanup defaults'
    $targets = @($script:Config.DeviceCleanupTargets)
    $cbAd     = New-Object System.Windows.Forms.CheckBox; $cbAd.Text = 'On-prem AD computer object'; $cbAd.AutoSize = $true; $cbAd.Checked = ($targets -contains 'AdComputer'); $cbAd.Margin = New-Object System.Windows.Forms.Padding(20, 2, 8, 1)
    $cbSccm   = New-Object System.Windows.Forms.CheckBox; $cbSccm.Text = 'SCCM / Configuration Manager device'; $cbSccm.AutoSize = $true; $cbSccm.Checked = ($targets -contains 'Sccm'); $cbSccm.Margin = New-Object System.Windows.Forms.Padding(20, 1, 8, 1)
    $cbIntune = New-Object System.Windows.Forms.CheckBox; $cbIntune.Text = 'Intune managed device'; $cbIntune.AutoSize = $true; $cbIntune.Checked = ($targets -contains 'Intune'); $cbIntune.Margin = New-Object System.Windows.Forms.Padding(20, 1, 8, 1)
    $cbEntra  = New-Object System.Windows.Forms.CheckBox; $cbEntra.Text = 'Entra ID device object'; $cbEntra.AutoSize = $true; $cbEntra.Checked = ($targets -contains 'EntraDevice'); $cbEntra.Margin = New-Object System.Windows.Forms.Padding(20, 1, 8, 4)
    $body.Controls.AddRange(@($cbAd, $cbSccm, $cbIntune, $cbEntra))
    $winrmBox = New-Object System.Windows.Forms.NumericUpDown; $winrmBox.Minimum = 2000; $winrmBox.Maximum = 120000; $winrmBox.Increment = 1000; $winrmBox.Width = 100; $winrmBox.Anchor = 'Left'
    $winrmBox.Value = [Math]::Min([Math]::Max([int]$script:Config.WinRmTimeoutMs, 2000), 120000)
    & $fieldRow 'Remote (WinRM) timeout ms:' $winrmBox 'How long to wait when contacting a remote server (SCCM delete, force-sync) before failing.'

    # --- Bottom: OK / Cancel ---------------------------------------------------------------
    $btnBar = New-Object System.Windows.Forms.FlowLayoutPanel
    $btnBar.Dock = 'Fill'; $btnBar.FlowDirection = 'RightToLeft'; $btnBar.WrapContents = $false; $btnBar.Padding = New-Object System.Windows.Forms.Padding(0, 8, 12, 8)
    $okBtn = New-Object System.Windows.Forms.Button; $okBtn.Text = 'OK'; $okBtn.Width = 90; $okBtn.Height = 30; $okBtn.DialogResult = 'OK'
    $cancelBtn = New-Object System.Windows.Forms.Button; $cancelBtn.Text = 'Cancel'; $cancelBtn.Width = 90; $cancelBtn.Height = 30; $cancelBtn.DialogResult = 'Cancel'
    Set-SecondaryButtonStyle $cancelBtn
    $btnBar.Controls.Add($okBtn); $btnBar.Controls.Add($cancelBtn)
    $root.Controls.Add($btnBar, 0, 2)
    $dlg.AcceptButton = $okBtn; $dlg.CancelButton = $cancelBtn

    Set-DialogTheme -Form $dlg; Set-PrimaryButtonStyle $okBtn
    $result = $dlg.ShowDialog()
    if ($result -ne 'OK') { $dlg.Dispose(); return $false }

    # Persist: per-tenant fields to the connected tenant (Set-TenantProfileValue saves); globals via Save-AppConfig.
    if ($connected) {
        Set-TenantProfileValue -Field 'SccmServer'   -Value ($sccmServerBox.Text.Trim())
        Set-TenantProfileValue -Field 'SccmSiteCode' -Value ($sccmSiteBox.Text.Trim().ToUpper())
        Set-TenantProfileValue -Field 'AdServers'    -Value (@($adList.Items | ForEach-Object { [string]$_ }))
    }
    $newTargets = New-Object System.Collections.Generic.List[string]
    if ($cbAd.Checked)     { [void]$newTargets.Add('AdComputer') }
    if ($cbSccm.Checked)   { [void]$newTargets.Add('Sccm') }
    if ($cbIntune.Checked) { [void]$newTargets.Add('Intune') }
    if ($cbEntra.Checked)  { [void]$newTargets.Add('EntraDevice') }
    $script:Config.DeviceCleanupTargets = $newTargets.ToArray()
    $script:Config.WinRmTimeoutMs = [int]$winrmBox.Value
    try { Save-AppConfig -Config $script:Config } catch { Set-Progress "Could not save settings: $($_.Exception.Message)" }
    $dlg.Dispose()
    return $true
}
