<#
    Dynamic field-control factory.

    The form is built entirely from the attribute catalog: for each enabled attribute,
    New-FieldRow creates a label + the control implied by its Input type and returns a "field"
    descriptor (a hashtable) holding the control handles and selection state. The rest of the
    functions read the current value, prefill from a Graph object, snapshot a baseline, and
    answer "is this field dirty?" / "is it valid?".

    A field descriptor:
        @{ Attr; Mode; Kind; Main; Aux; Cell; People(list); Baseline }
      Main   = the primary control (TextBox/CheckBox/ComboBox/DateTimePicker/ListBox/...)
      Aux    = secondary control (force-change checkbox, the Microsoft-365 radio, ...)
      Cell   = the control actually placed in the form's column 1 (Main, or a container)
      People = selected directory objects for Person fields
      Baseline = canonical string captured after prefill, for dirty detection
#>

function Get-IsoCountryCode {
    @(
        'AD','AE','AF','AG','AI','AL','AM','AO','AQ','AR','AS','AT','AU','AW','AX','AZ',
        'BA','BB','BD','BE','BF','BG','BH','BI','BJ','BL','BM','BN','BO','BQ','BR','BS','BT','BV','BW','BY','BZ',
        'CA','CC','CD','CF','CG','CH','CI','CK','CL','CM','CN','CO','CR','CU','CV','CW','CX','CY','CZ',
        'DE','DJ','DK','DM','DO','DZ',
        'EC','EE','EG','EH','ER','ES','ET',
        'FI','FJ','FK','FM','FO','FR',
        'GA','GB','GD','GE','GF','GG','GH','GI','GL','GM','GN','GP','GQ','GR','GS','GT','GU','GW','GY',
        'HK','HM','HN','HR','HT','HU',
        'ID','IE','IL','IM','IN','IO','IQ','IR','IS','IT',
        'JE','JM','JO','JP',
        'KE','KG','KH','KI','KM','KN','KP','KR','KW','KY','KZ',
        'LA','LB','LC','LI','LK','LR','LS','LT','LU','LV','LY',
        'MA','MC','MD','ME','MF','MG','MH','MK','ML','MM','MN','MO','MP','MQ','MR','MS','MT','MU','MV','MW','MX','MY','MZ',
        'NA','NC','NE','NF','NG','NI','NL','NO','NP','NR','NU','NZ',
        'OM',
        'PA','PE','PF','PG','PH','PK','PL','PM','PN','PR','PS','PT','PW','PY',
        'QA',
        'RE','RO','RS','RU','RW',
        'SA','SB','SC','SD','SE','SG','SH','SI','SJ','SK','SL','SM','SN','SO','SR','SS','ST','SV','SX','SY','SZ',
        'TC','TD','TF','TG','TH','TJ','TK','TL','TM','TN','TO','TR','TT','TV','TW','TZ',
        'UA','UG','UM','US','UY','UZ',
        'VA','VC','VE','VG','VI','VN','VU',
        'WF','WS',
        'YE','YT',
        'ZA','ZM','ZW'
    )
}

function Get-IsoCountry {
    <#
        ISO 3166-1 alpha-2 codes paired with their English country name (via .NET RegionInfo, so no
        249-row hardcoded table to maintain). Used to show full names in the Usage Location dropdown
        while still storing/sending the 2-letter code. Codes with no RegionInfo (e.g. AQ) fall back
        to the code as the name.
    #>
    foreach ($code in (Get-IsoCountryCode)) {
        $name = $code
        try { $name = ([System.Globalization.RegionInfo]$code).EnglishName } catch { }
        [pscustomobject]@{ Code = $code; Name = $name }
    }
}

function Get-RandomIndex {
    <# Crypto-random integer 0..Count-1. Uses the RNG byte path so it works on BOTH Windows
       PowerShell 5.1 (.NET Framework) and PowerShell 7 (RandomNumberGenerator.GetInt32 is 7-only). #>
    param([System.Security.Cryptography.RandomNumberGenerator]$Rng, [int]$Count)
    $b = New-Object byte[] 4; $Rng.GetBytes($b)
    return [int]([System.BitConverter]::ToUInt32($b, 0) % $Count)
}

function Get-PassphraseWordList {
    <# Simple, distinct, inoffensive words (4-8 letters) for passphrase generation. #>
    @(
        'amber', 'anchor', 'arrow', 'autumn', 'basil', 'beacon', 'birch', 'bison', 'bloom', 'branch',
        'breeze', 'bridge', 'bronze', 'brook', 'canyon', 'cedar', 'cherry', 'cliff', 'clover', 'cobalt',
        'comet', 'copper', 'coral', 'cotton', 'crane', 'crater', 'creek', 'crystal', 'dawn', 'delta',
        'desert', 'dune', 'eagle', 'ember', 'falcon', 'fern', 'forest', 'garnet', 'glacier', 'granite',
        'grove', 'harbor', 'hazel', 'heron', 'hollow', 'ivory', 'jade', 'jasper', 'juniper', 'lagoon',
        'lantern', 'lemon', 'lily', 'linen', 'lotus', 'maple', 'marble', 'meadow', 'meteor', 'mint',
        'moss', 'nectar', 'nimbus', 'ocean', 'olive', 'onyx', 'opal', 'orchid', 'otter', 'pebble',
        'pepper', 'pine', 'plum', 'poppy', 'prairie', 'quartz', 'quill', 'rapid', 'raven', 'reef',
        'ridge', 'river', 'robin', 'rowan', 'ruby', 'saffron', 'sage', 'salmon', 'sapphire', 'shadow',
        'sierra', 'silver', 'slate', 'sparrow', 'spruce', 'stone', 'storm', 'stream', 'summit', 'thicket',
        'thistle', 'tiger', 'timber', 'topaz', 'trail', 'tulip', 'tundra', 'valley', 'velvet', 'violet',
        'walnut', 'willow', 'winter', 'zephyr'
    )
}

function New-Passphrase {
    <#
        Generate a readable passphrase: distinct capitalized words joined by '-', then a digit and a
        symbol -- e.g. "Tiger-Maple-Cloud7!". Guarantees upper + lower + digit + symbol, and (unlike a
        random string) never produces ugly symbol runs like '__'.
    #>
    param([int]$WordCount = 3)
    $words = Get-PassphraseWordList
    # Conservative symbol set: all are Entra/AD-policy-allowed AND broadly safe across apps/shells/URLs
    # (deliberately excludes & ^ ? + = _ etc. which can trip up legacy apps). '-' is the word separator.
    $specials = '!@#$%'.ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $picked = New-Object System.Collections.Generic.List[string]
    $guard = 0
    while ($picked.Count -lt $WordCount -and $guard -lt 300) {
        $guard++
        $w = $words[(Get-RandomIndex -Rng $rng -Count $words.Count)]
        $cap = $w.Substring(0, 1).ToUpper() + $w.Substring(1)
        if (-not $picked.Contains($cap)) { [void]$picked.Add($cap) }
    }
    $digit   = [string]((Get-RandomIndex -Rng $rng -Count 8) + 2)   # 2..9 (skip ambiguous 0/1)
    $special = [string]$specials[(Get-RandomIndex -Rng $rng -Count $specials.Count)]
    return (($picked -join '-') + $digit + $special)
}

function Set-CharFilter {
    <# Block typed characters that don't match an allowed-character regex (control keys pass; pasted
       text is still validated on save). No-op without a pattern. The pattern lives on the control's
       Tag so the plain KeyPress handler can read it via $s.Tag -- no closure, keeps module affinity. #>
    param([System.Windows.Forms.Control]$Control, [string]$Pattern)
    if (-not $Pattern -or -not $Control) { return }
    $Control.Tag = $Pattern
    $Control.Add_KeyPress({
            param($s, $e)
            if (-not [char]::IsControl($e.KeyChar) -and (([string]$e.KeyChar) -notmatch [string]$s.Tag)) { $e.Handled = $true }
        })
}

function Format-PersonLine {
    param($Person)
    if ($Person.Detail) { return "$($Person.DisplayName) <$($Person.Detail)>" }
    return [string]$Person.DisplayName
}

function New-CellTable {
    param([int]$Cols, [int]$Rows, [int]$Height)
    $tlp = New-Object System.Windows.Forms.TableLayoutPanel
    $tlp.ColumnCount = $Cols
    $tlp.RowCount = $Rows
    $tlp.Height = $Height
    $tlp.Anchor = 'Left,Right'
    $tlp.Margin = New-Object System.Windows.Forms.Padding(3, 3, 3, 3)
    return $tlp
}

function Add-ColumnStyle {
    param($Tlp, [string]$Type, [single]$Value = 0)
    [void]$Tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::$Type, $Value)))
}
function Add-RowStyle {
    param($Tlp, [string]$Type, [single]$Value = 0)
    [void]$Tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::$Type, $Value)))
}

function New-FieldRow {
    <#
        Build a label + control row for one catalog attribute and add it to the 2-column
        TableLayoutPanel $Tlp. Returns the field descriptor.
    #>
    param(
        [hashtable]$Attr,
        [ValidateSet('New', 'Edit')][string]$Mode,
        [System.Windows.Forms.TableLayoutPanel]$Tlp,
        [System.Windows.Forms.ToolTip]$Tooltip
    )
    $t = Get-Theme

    $label = New-Object System.Windows.Forms.Label
    $isRequiredNew = ($Attr.Required -and $Mode -eq 'New')
    $label.Text = $Attr.Label + $(if ($isRequiredNew) { ' *' } else { '' }) + ':'
    $label.AutoSize = $true
    $label.Anchor = 'Left'
    $label.Margin = New-Object System.Windows.Forms.Padding(3, 8, 10, 3)
    if ($isRequiredNew) { $label.Font = $t.FontBold }   # bold + '*' marks a field required to create

    $field = @{
        Attr = $Attr; Mode = $Mode; Kind = $Attr.Input
        Main = $null; Aux = $null; Cell = $null; Label = $null
        People = (New-Object System.Collections.Generic.List[object])
        Baseline = ''
        # Original selections, captured on load (Edit mode) and diffed on save. Initialised here
        # so the add/remove diff is correct even for a freshly-built (never-loaded) field --
        # an uninitialised value would make @($field.OriginalIds) become @($null), not @().
        OriginalIds = @()
        OriginalSkuIds = @()
        # Snapshot of the loaded Person objects (with UPN), so a synced-group membership diff can be
        # resolved to AD accounts on save. Array (not the live List) so later edits don't mutate it.
        OriginalPeople = @()
        # Last value written by name-driven auto-generation; lets auto-fill stop once the user edits.
        AutoLast = ''
    }

    switch ($Attr.Input) {

        { $_ -in 'Text', 'ExtAttr' } {
            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Anchor = 'Left,Right'; $tb.Width = 320
            $tb.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
            if ($Attr.MaxLength) { $tb.MaxLength = [int]$Attr.MaxLength }
            Set-CharFilter -Control $tb -Pattern $Attr.CharFilter
            $field.Main = $tb; $field.Cell = $tb
        }

        'ReadOnly' {
            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Anchor = 'Left,Right'; $tb.Width = 320; $tb.ReadOnly = $true; $tb.TabStop = $false
            $tb.BackColor = $t.ReadOnlyBg
            $tb.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
            $field.Main = $tb; $field.Cell = $tb
        }

        'Upn' {
            # sign-in local part + "@" + a domain combo (the tenant's verified domains).
            $cell = New-CellTable -Cols 3 -Rows 1 -Height 30
            Add-ColumnStyle $cell 'Percent' 58; Add-ColumnStyle $cell 'AutoSize'; Add-ColumnStyle $cell 'Percent' 42
            Add-RowStyle $cell 'Percent' 100
            $local = New-Object System.Windows.Forms.TextBox; $local.Dock = 'Fill'; $local.Margin = New-Object System.Windows.Forms.Padding(3, 4, 1, 4)
            if ($Attr.MaxLength) { $local.MaxLength = [int]$Attr.MaxLength }
            Set-CharFilter -Control $local -Pattern $Attr.CharFilter
            $at = New-Object System.Windows.Forms.Label; $at.Text = '@'; $at.AutoSize = $true; $at.Anchor = 'Left'; $at.Margin = New-Object System.Windows.Forms.Padding(2, 8, 2, 3)
            $dom = New-Object System.Windows.Forms.ComboBox; $dom.Dock = 'Fill'; $dom.DropDownStyle = 'DropDown'   # editable: list verified domains, allow any if needed
            $dom.Margin = New-Object System.Windows.Forms.Padding(1, 4, 3, 4)
            foreach ($d in (Get-VerifiedDomainList)) { [void]$dom.Items.Add($d) }
            $def = Get-DefaultVerifiedDomain
            if ($def) { $dom.Text = $def }
            $cell.Controls.Add($local, 0, 0); $cell.Controls.Add($at, 1, 0); $cell.Controls.Add($dom, 2, 0)
            $field.Main = $local; $field.Aux = $dom; $field.Cell = $cell
        }

        'Multi' {
            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Multiline = $true; $tb.ScrollBars = 'Vertical'; $tb.AcceptsReturn = $true; $tb.WordWrap = $false
            $tb.Height = 56; $tb.Anchor = 'Left,Right'; $tb.Width = 320
            $tb.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
            $field.Main = $tb; $field.Cell = $tb
        }

        'Bool' {
            $cb = New-Object System.Windows.Forms.CheckBox
            $cb.AutoSize = $true; $cb.Text = ''; $cb.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
            $field.Main = $cb; $field.Cell = $cb
        }

        'Choice' {
            $cmb = New-Object System.Windows.Forms.ComboBox
            $cmb.Width = 220; $cmb.Anchor = 'Left'
            $cmb.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
            if ($Attr.ChoiceSource -eq 'Country') {
                # Show the full country name (sorted) but carry the 2-letter ISO code as the value.
                # DropDownList: type-ahead jumps to a country; the stored value is SelectedItem.Code.
                $cmb.DropDownStyle = 'DropDownList'
                $cmb.Width = 320; $cmb.DropDownWidth = 320
                $cmb.DisplayMember = 'Display'
                [void]$cmb.Items.Add([pscustomobject]@{ Display = ''; Code = '' })   # explicit "no value"
                foreach ($c in (Get-IsoCountry | Sort-Object Name)) {
                    [void]$cmb.Items.Add([pscustomobject]@{ Display = "$($c.Name) ($($c.Code))"; Code = $c.Code })
                }
                $cmb.SelectedIndex = 0
            } else {
                $cmb.DropDownStyle = 'DropDownList'    # closed set: pick-only
                [void]$cmb.Items.Add('')               # explicit "no value"
                foreach ($c in @($Attr.Choices)) { [void]$cmb.Items.Add($c) }
                $cmb.SelectedIndex = 0
            }
            $field.Main = $cmb; $field.Cell = $cmb
        }

        'Date' {
            $dt = New-Object System.Windows.Forms.DateTimePicker
            $dt.Format = 'Custom'; $dt.CustomFormat = 'yyyy-MM-dd'
            $dt.ShowCheckBox = $true; $dt.Checked = $false
            $dt.Width = 150; $dt.Anchor = 'Left'
            $dt.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
            $field.Main = $dt; $field.Cell = $dt
        }

        'Person' {
            if ($Attr.Multi) {
                $cell = New-CellTable -Cols 2 -Rows 2 -Height 96
                Add-ColumnStyle $cell 'Percent' 100; Add-ColumnStyle $cell 'Absolute' 84
                Add-RowStyle $cell 'Percent' 50; Add-RowStyle $cell 'Percent' 50
                $lb = New-Object System.Windows.Forms.ListBox
                $lb.Dock = 'Fill'; $lb.SelectionMode = 'MultiExtended'; $lb.IntegralHeight = $false
                $add = New-Object System.Windows.Forms.Button; $add.Text = '&Add...'; $add.Dock = 'Fill'; $add.Margin = New-Object System.Windows.Forms.Padding(3,2,1,1)
                $rem = New-Object System.Windows.Forms.Button; $rem.Text = '&Remove'; $rem.Dock = 'Fill'; $rem.Margin = New-Object System.Windows.Forms.Padding(3,1,1,2)
                Set-SecondaryButtonStyle $add; Set-SecondaryButtonStyle $rem
                $cell.Controls.Add($lb, 0, 0); $cell.SetRowSpan($lb, 2)
                $cell.Controls.Add($add, 1, 0); $cell.Controls.Add($rem, 1, 1)
                $add.Tag = $field; $rem.Tag = $field
                $add.Add_Click({ param($s, $e) Invoke-PersonAdd -Field $s.Tag })
                $rem.Add_Click({ param($s, $e) Invoke-PersonRemove -Field $s.Tag })
                $field.Main = $lb; $field.Cell = $cell
            } else {
                $cell = New-CellTable -Cols 3 -Rows 1 -Height 30
                Add-ColumnStyle $cell 'Percent' 100; Add-ColumnStyle $cell 'AutoSize'; Add-ColumnStyle $cell 'AutoSize'
                Add-RowStyle $cell 'Percent' 100
                $disp = New-Object System.Windows.Forms.TextBox; $disp.Dock = 'Fill'; $disp.ReadOnly = $true; $disp.TabStop = $false
                $disp.BackColor = $t.ReadOnlyBg
                $choose = New-Object System.Windows.Forms.Button; $choose.Text = '&Choose...'; $choose.Width = 80; $choose.Margin = New-Object System.Windows.Forms.Padding(2,1,1,1)
                $clear = New-Object System.Windows.Forms.Button; $clear.Text = 'Cl&ear'; $clear.Width = 56; $clear.Margin = New-Object System.Windows.Forms.Padding(1,1,1,1)
                Set-SecondaryButtonStyle $choose; Set-SecondaryButtonStyle $clear
                $cell.Controls.Add($disp, 0, 0); $cell.Controls.Add($choose, 1, 0); $cell.Controls.Add($clear, 2, 0)
                $choose.Tag = $field; $clear.Tag = $field
                $choose.Add_Click({ param($s, $e) Invoke-PersonChoose -Field $s.Tag })
                $clear.Add_Click({ param($s, $e) $f = $s.Tag; $f.People.Clear(); $f.Main.Text = '' })
                $field.Main = $disp; $field.Cell = $cell
            }
        }

        'Password' {
            if ($Mode -eq 'New') {
                $cell = New-CellTable -Cols 2 -Rows 2 -Height 56
                Add-ColumnStyle $cell 'Percent' 100; Add-ColumnStyle $cell 'AutoSize'
                Add-RowStyle $cell 'AutoSize'; Add-RowStyle $cell 'AutoSize'
                $pwd = New-Object System.Windows.Forms.TextBox; $pwd.Dock = 'Fill'; $pwd.UseSystemPasswordChar = $true
                $gen = New-Object System.Windows.Forms.Button; $gen.Text = '&Generate'; $gen.Width = 80; $gen.Margin = New-Object System.Windows.Forms.Padding(3,1,1,1)
                Set-SecondaryButtonStyle $gen
                $force = New-Object System.Windows.Forms.CheckBox; $force.Text = 'Force change at next sign-in'; $force.Checked = $true; $force.AutoSize = $true
                $cell.Controls.Add($pwd, 0, 0); $cell.Controls.Add($gen, 1, 0)
                $cell.Controls.Add($force, 0, 1); $cell.SetColumnSpan($force, 2)
                $gen.Tag = $pwd
                $gen.Add_Click({ param($s, $e) $box = $s.Tag; $box.UseSystemPasswordChar = $false; $box.Text = (New-Passphrase) })
                $field.Main = $pwd; $field.Aux = $force; $field.Cell = $cell
            } else {
                $btn = New-Object System.Windows.Forms.Button
                $btn.Text = 'Reset password...'; $btn.Width = 150; $btn.Height = 26; $btn.Anchor = 'Left'
                Set-SecondaryButtonStyle $btn
                $btn.Add_Click({ param($s, $e) Invoke-UserPasswordReset })
                $field.Main = $btn; $field.Cell = $btn
            }
        }

        'License' {
            $clb = New-Object System.Windows.Forms.CheckedListBox
            $clb.Height = 96; $clb.Anchor = 'Left,Right'; $clb.Width = 320
            $clb.CheckOnClick = $true; $clb.IntegralHeight = $false; $clb.DisplayMember = 'Display'
            $clb.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 4)
            $field.Main = $clb; $field.Cell = $clb
        }

        'GroupType' {
            $cell = New-Object System.Windows.Forms.FlowLayoutPanel
            $cell.AutoSize = $true; $cell.FlowDirection = 'LeftToRight'; $cell.WrapContents = $false; $cell.Anchor = 'Left'
            $cell.Margin = New-Object System.Windows.Forms.Padding(3, 3, 3, 3)
            $radSec = New-Object System.Windows.Forms.RadioButton; $radSec.Text = '&Security'; $radSec.AutoSize = $true; $radSec.Checked = $true
            $radM365 = New-Object System.Windows.Forms.RadioButton; $radM365.Text = '&Microsoft 365'; $radM365.AutoSize = $true
            $cell.Controls.Add($radSec); $cell.Controls.Add($radM365)
            $field.Main = $radSec; $field.Aux = $radM365; $field.Cell = $cell
        }

        default {
            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Anchor = 'Left,Right'; $tb.Width = 320; $tb.ReadOnly = $true
            $field.Main = $tb; $field.Cell = $tb
        }
    }

    if ($Attr.Help -and $Tooltip -and $field.Main) { $Tooltip.SetToolTip($field.Main, $Attr.Help) }
    $field.Label = $label

    # Build-TabForm positions $field.Label / $field.Cell itself (so it can interleave section
    # headers), calling without -Tlp. If a caller does pass -Tlp (e.g. the tests) add the pair.
    if ($Tlp) {
        [void]$Tlp.Controls.Add($label)
        [void]$Tlp.Controls.Add($field.Cell)
    }
    return $field
}

# ---------------------------------------------------------------------------- Person handlers

function Invoke-PersonChoose {
    param($Field)
    if (-not $Field -or -not $Field.Attr) { return }
    $source = if ($Field.Attr.PickerSource) { $Field.Attr.PickerSource } else { 'Graph' }
    $picked = Show-PersonPicker -TargetType $Field.Attr.TargetType -Source $source
    if ($picked) {
        $p = $picked[0]
        $Field.People.Clear(); [void]$Field.People.Add($p)
        $Field.Main.Text = (Format-PersonLine $p)
    }
}

function Invoke-PersonAdd {
    param($Field)
    if (-not $Field -or -not $Field.Attr -or -not $Field.Main) { return }
    $source = if ($Field.Attr.PickerSource) { $Field.Attr.PickerSource } else { 'Graph' }
    $picked = Show-PersonPicker -Multi -TargetType $Field.Attr.TargetType -Source $source
    if (-not $picked) { return }
    try {
        $Field.Main.BeginUpdate()
        foreach ($p in $picked) {
            if (-not ($Field.People | Where-Object { $_.Id -eq $p.Id })) {
                [void]$Field.People.Add($p)
                [void]$Field.Main.Items.Add((Format-PersonLine $p))
            }
        }
    } finally {
        $Field.Main.EndUpdate()
    }
}

function Invoke-PersonRemove {
    param($Field)
    if (-not $Field -or -not $Field.Main) { return }
    $idx = @($Field.Main.SelectedIndices) | Sort-Object -Descending
    try {
        $Field.Main.BeginUpdate()
        foreach ($i in $idx) { $Field.People.RemoveAt($i); $Field.Main.Items.RemoveAt($i) }
    } finally {
        $Field.Main.EndUpdate()
    }
}

# ---------------------------------------------------------------------------- Read / prefill

function Read-FieldValue {
    <# Current value in a normalised shape (string / bool / string[] / datetime|null / hashtable). #>
    param($Field)
    switch ($Field.Kind) {
        { $_ -in 'Text', 'ReadOnly', 'ExtAttr' } { return $Field.Main.Text.Trim() }
        'Upn' {
            $loc = $Field.Main.Text.Trim()
            if (-not $loc) { return '' }
            $dom = ([string]$Field.Aux.Text).Trim().TrimStart('@')
            if ($dom) { return "$loc@$dom" } else { return $loc }
        }
        'Multi'  { return (ConvertTo-StringList $Field.Main.Lines) }
        'Bool'   { return [bool]$Field.Main.Checked }
        'Choice' {
            if ($Field.Attr.ChoiceSource -eq 'Country') {
                $sel = $Field.Main.SelectedItem
                if ($sel -and $sel.Code) { return [string]$sel.Code } else { return '' }
            }
            return [string]$Field.Main.SelectedItem
        }
        'Date'   { if ($Field.Main.Checked) { return $Field.Main.Value.Date } else { return $null } }
        'Person' {
            if ($Field.Attr.Multi) { return @($Field.People | ForEach-Object { $_.Id }) }
            return ([string]($Field.People | Select-Object -First 1 -ExpandProperty Id -ErrorAction SilentlyContinue))
        }
        'Password' {
            if ($Field.Mode -eq 'New') { return @{ Password = $Field.Main.Text; Force = [bool]$Field.Aux.Checked } }
            return $null
        }
        'License' { return @($Field.Main.CheckedItems | ForEach-Object { [string]$_.SkuId }) }
        'GroupType' { if ($Field.Aux.Checked) { return 'Microsoft365' } else { return 'Security' } }
        default { return $null }
    }
}

function Get-FieldComparable {
    <# Canonical string for dirty comparison. #>
    param($Field)
    $v = Read-FieldValue $Field
    switch ($Field.Kind) {
        'Bool'    { return ([bool]$v).ToString() }
        'Date'    { if ($v) { return ([datetime]$v).ToString('yyyy-MM-dd') } else { return '' } }
        'Multi'   { return (@($v) -join "`n") }
        'License' { return ((@($v) | Sort-Object) -join ';') }
        'Person'  {
            if ($Field.Attr.Multi) { return ((@($v) | Sort-Object) -join ';') }
            return [string]$v
        }
        'Password' { return '' }   # never participates in dirty diff
        default    { return [string]$v }
    }
}

function Set-FieldValue {
    <# Prefill a scalar field from a Graph value. Person/License/GroupType have dedicated setters. #>
    param($Field, $Value)
    switch ($Field.Kind) {
        { $_ -in 'Text', 'ReadOnly', 'ExtAttr' } { $Field.Main.Text = [string](Format-Cell $Value) }
        'Upn' {
            $sv = [string](Format-Cell $Value)
            if ($sv -match '^(.+?)@(.+)$') {
                $Field.Main.Text = $Matches[1]
                $d = $Matches[2]
                if (-not ($Field.Aux.Items -contains $d)) { [void]$Field.Aux.Items.Add($d) }
                $Field.Aux.Text = $d
            } else {
                $Field.Main.Text = $sv
            }
        }
        'Multi' { $Field.Main.Text = ((ConvertTo-StringList $Value) -join [Environment]::NewLine) }
        'Bool'  { $Field.Main.Checked = [bool]$Value }
        'Choice' {
            $sv = [string]$Value
            if ($Field.Attr.ChoiceSource -eq 'Country') {
                $match = $null
                foreach ($it in $Field.Main.Items) { if ($it.Code -eq $sv) { $match = $it; break } }
                if ($match) { $Field.Main.SelectedItem = $match } else { $Field.Main.SelectedIndex = 0 }
            } elseif ($Field.Main.Items.Contains($sv)) {
                $Field.Main.SelectedItem = $sv
            } else {
                $Field.Main.SelectedIndex = 0
            }
        }
        'Date' {
            $parsed = [datetime]::MinValue
            if ($Value -and [datetime]::TryParse([string]$Value, [ref]$parsed)) {
                $Field.Main.Value = $parsed; $Field.Main.Checked = $true
            } else {
                $Field.Main.Checked = $false   # unparseable / empty -> "no value"; Read-FieldValue returns $null
            }
        }
        default { }   # Person / License / GroupType / Password use their own setters
    }
}

function Set-PersonFieldValue {
    <# Prefill a Person field from normalised directory objects (@{ Id; DisplayName; Detail }). #>
    param($Field, [object[]]$People)
    $Field.People.Clear()
    if ($Field.Attr.Multi) { $Field.Main.Items.Clear() }
    # NB: iterate $People directly. On Windows PowerShell 5.1, @($collectionOfHashtables) throws
    # "Argument types do not match" in the array-subexpression binder; foreach is safe.
    foreach ($p in $People) {
        if (-not $p) { continue }
        [void]$Field.People.Add($p)
        if ($Field.Attr.Multi) { [void]$Field.Main.Items.Add((Format-PersonLine $p)) }
    }
    if (-not $Field.Attr.Multi) {
        $first = $Field.People | Select-Object -First 1
        $Field.Main.Text = if ($first) { Format-PersonLine $first } else { '' }
    }
}

function Set-LicenseFieldItems {
    <# Fill the license checklist with the tenant's SKUs, checking those in $AssignedSkuIds. #>
    param($Field, [object[]]$Skus, [string[]]$AssignedSkuIds = @())
    $clb = $Field.Main
    $clb.BeginUpdate()
    $clb.Items.Clear()
    foreach ($s in $Skus) {   # not @($Skus): see Set-PersonFieldValue note (5.1 @()-of-objects bug)
        $display = "$($s.PartNumber)  ($($s.Available) of $($s.Enabled) available)"
        $idx = $clb.Items.Add([pscustomobject]@{ Display = $display; SkuId = $s.SkuId })
        if ($AssignedSkuIds -contains $s.SkuId) { $clb.SetItemChecked($idx, $true) }
    }
    $clb.EndUpdate()
}

function Set-GroupTypeField {
    <# Select Security / Microsoft365 and optionally lock it (Edit mode: type is immutable). #>
    param($Field, [string]$Type, [switch]$Lock)
    if ($Type -eq 'Microsoft365') { $Field.Aux.Checked = $true } else { $Field.Main.Checked = $true }
    if ($Lock) { $Field.Main.Enabled = $false; $Field.Aux.Enabled = $false }
}

function Set-FieldBaseline {
    param($Field)
    $Field.Baseline = Get-FieldComparable $Field
}

function Test-FieldDirty {
    param($Field)
    if ($Field.Kind -eq 'Password' -and $Field.Mode -eq 'Edit') { return $false }
    return ((Get-FieldComparable $Field) -ne $Field.Baseline)
}

function Set-FieldEnabled {
    param($Field, [bool]$Enabled)
    if ($Field.Main) { $Field.Main.Enabled = $Enabled }
    if ($Field.Aux)  { $Field.Aux.Enabled = $Enabled }
}

function Set-FieldReadOnlyForSync {
    <#
        Render a field non-editable but still READABLE, for an on-prem-mastered attribute on a
        directory-synced object (P0 hybrid gating -- no AD write path yet). Text-like fields go
        ReadOnly so the AD-sourced value stays legible; Person fields keep the list readable but
        disable the Add/Remove/Choose/Clear buttons; other controls are simply disabled.
    #>
    param($Field)
    $t = Get-Theme
    switch ($Field.Kind) {
        { $_ -in 'Text', 'Multi', 'ExtAttr' } {
            $Field.Main.ReadOnly = $true; $Field.Main.TabStop = $false; $Field.Main.BackColor = $t.ReadOnlyBg
        }
        'Person' {
            # Keep the list/box readable; disable only the action buttons that live in the cell.
            if ($Field.Cell -and $Field.Cell.Controls) {
                foreach ($c in $Field.Cell.Controls) {
                    if ($c -is [System.Windows.Forms.Button]) { $c.Enabled = $false }
                }
            }
        }
        default {
            if ($Field.Main) { $Field.Main.Enabled = $false }
            if ($Field.Aux)  { $Field.Aux.Enabled = $false }
        }
    }
}

function Get-FieldValidationError {
    <# Returns a validation message, or $null if the field is acceptable. #>
    param($Field)
    $a = $Field.Attr
    $v = Read-FieldValue $Field

    # Required (only enforced when creating).
    if ($a.Required -and $Field.Mode -eq 'New') {
        $empty = switch ($a.Input) {
            'Password'  { [string]::IsNullOrWhiteSpace($v.Password) }
            'Person'    { @($v).Count -eq 0 -or -not ($v | Where-Object { $_ }) }
            'GroupType' { $false }
            'Bool'      { $false }
            default     { [string]::IsNullOrWhiteSpace([string]$v) }
        }
        if ($empty) { return "$($a.Label) is required." }
    }

    # Auto-generated-but-required-to-create fields (display name / alias / UPN) must still be
    # non-empty to create, even though they aren't marked with a * (they normally auto-fill).
    if ($a.RequiredForCreate -and $Field.Mode -eq 'New' -and [string]::IsNullOrWhiteSpace([string]$v)) {
        return "$($a.Label) is required (it normally auto-fills from the first/last name)."
    }

    # A distribution group / mail-enabled security group must always keep >=1 owner (Exchange
    # rejects zero), so enforce it in BOTH New and Edit -- otherwise clearing owners would either
    # be silently skipped or rejected server-side.
    if ($a.Name -eq 'managedBy' -and @($v).Count -eq 0) { return 'At least one owner is required.' }

    switch ($a.Name) {
        'userPrincipalName' { if ($v -and ($v -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$')) { return 'User Principal Name must look like name@domain.' } }
        'mailNickname'      { if ($v -and ($v -match '\s')) { return 'Mail nickname cannot contain spaces.' } }
        'alias'             { if ($v -and ($v -match '\s')) { return 'Alias cannot contain spaces.' } }
        'usageLocation'     { if ($v -and ($v -notmatch '^[A-Za-z]{2}$')) { return 'Usage location must be a 2-letter country code.' } }
    }
    return $null
}
