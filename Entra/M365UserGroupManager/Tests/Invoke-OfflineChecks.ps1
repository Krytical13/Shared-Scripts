<#
.SYNOPSIS
    Dependency-free offline smoke test for M365UserGroupManager (no Pester, no Graph connection).

.DESCRIPTION
    Parses every source file, imports the module, validates the catalog, exercises the field
    factory (read / prefill / dirty), and builds the main form headless (M365UGM_NOLAUNCH) so
    layout runs without showing a window. Prints PASS/FAIL per check and exits non-zero on failure.

    Run on Windows PowerShell 5.1 or pwsh 7 (STA recommended for the form-build check):
        pwsh -STA -File .\Tests\Invoke-OfflineChecks.ps1
#>
[CmdletBinding()]
param(
    # Robust under both `pwsh -File` and `powershell.exe -File` (5.1), where $PSScriptRoot can be empty.
    [string]$ModuleRoot = $(
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } elseif ($PSCommandPath) { Split-Path -Parent $PSCommandPath } else { (Get-Location).Path }
        Split-Path -Parent $scriptDir
    )
)

$ErrorActionPreference = 'Stop'
$script:Failures = 0
$script:Passed = 0

function Assert-That {
    param([string]$Name, [scriptblock]$Test)
    try {
        $ok = & $Test
        if ($ok) { Write-Host "  PASS  $Name" -ForegroundColor Green; $script:Passed++ }
        else     { Write-Host "  FAIL  $Name" -ForegroundColor Red;   $script:Failures++ }
    } catch {
        Write-Host "  FAIL  $Name  -> $($_.Exception.Message)" -ForegroundColor Red
        $script:Failures++
    }
}

Write-Host "`n== Parse check ==" -ForegroundColor Cyan
$files = Get-ChildItem -Path $ModuleRoot -Recurse -Include *.ps1, *.psm1, *.psd1 -File
foreach ($f in $files) {
    Assert-That "parses: $($f.Name)" {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
        (-not $errs -or $errs.Count -eq 0)
    }
}

Write-Host "`n== Closure affinity lint ==" -ForegroundColor Cyan
# Guard against a Windows PowerShell 5.1 trap: a `{ ... }.GetNewClosure()` scriptblock loses module
# affinity, so it CANNOT call module-private functions and CANNOT see module `$script:` variables
# (it captures plain LOCALS only). Any closure that does either is a latent runtime bug -- the kind
# that only surfaces when a particular button is clicked. This lint parses every source file via the
# AST and fails if it finds such a closure, so the fix can't silently regress.
$srcFiles = $files | Where-Object { $_.Extension -in '.ps1', '.psm1' }

# 1) Collect every function name defined anywhere in the module.
$moduleFnNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($f in $srcFiles) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        [void]$moduleFnNames.Add($fn.Name)
    }
}

# 2) Inspect every `{ ... }.GetNewClosure()` block for affinity-breaking content.
$closureCount = 0
$closureViolations = New-Object System.Collections.Generic.List[string]
foreach ($f in $srcFiles) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    $closures = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $n.Member.Value -eq 'GetNewClosure' -and
            $n.Expression -is [System.Management.Automation.Language.ScriptBlockExpressionAst]
        }, $true)
    foreach ($cl in $closures) {
        $closureCount++
        $sb = $cl.Expression.ScriptBlock
        # (a) module-private function calls -- bareword commands only; `& $var` invocations have a null name and are fine
        foreach ($cmd in $sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $name = $cmd.GetCommandName()
            if ($name -and $moduleFnNames.Contains($name)) {
                $closureViolations.Add("$($f.Name):$($cmd.Extent.StartLineNumber)  calls module fn '$name' inside .GetNewClosure()")
            }
        }
        # (b) any $script: variable access (read or write both break under the lost affinity)
        foreach ($v in $sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
            if ($v.VariablePath.IsScript) {
                $closureViolations.Add("$($f.Name):$($v.Extent.StartLineNumber)  uses '$($v.Extent.Text)' inside .GetNewClosure()")
            }
        }
    }
}
Write-Host "  (scanned $closureCount .GetNewClosure() block(s) against $($moduleFnNames.Count) module functions)" -ForegroundColor DarkGray
Assert-That 'no .GetNewClosure() block calls a module fn or touches $script: (PS 5.1 affinity trap)' {
    if ($closureViolations.Count) { $closureViolations | ForEach-Object { Write-Host "        $_" -ForegroundColor Yellow } }
    $closureViolations.Count -eq 0
}
# Category-1 binder trap guard: wrapping a List-of-hashtables in the array-subexpression operator
# throws on BOTH 5.1 AND 7 (Add-PeopleToGroup shipped this once; the closure lint above only covers
# the GetNewClosure trap). Strip comments first so documentation mentioning the idiom doesn't trip it.
Assert-That 'no source wraps a .People / .OriginalPeople list in the array-subexpression operator (5.1+7 binder crash idiom)' {
    $hits = foreach ($f in $srcFiles) {
        $code = (Get-Content -LiteralPath $f.FullName -Raw) -replace '(?s)<#.*?#>', ''
        $code = (($code -split "`n") | ForEach-Object { $_ -replace '#.*$', '' }) -join "`n"
        if ($code -match '@\(\s*\$[A-Za-z_][\w\.]*\.(People|OriginalPeople)\s*\)') { $f.Name }
    }
    if ($hits) { $hits | ForEach-Object { Write-Host "        array-wrapped People list in $_" -ForegroundColor Yellow } }
    -not $hits
}
Assert-That 'iterating a List[object] of hashtables works without the array operator (the safe Add-PeopleToGroup pattern)' {
    $l = New-Object System.Collections.Generic.List[object]
    [void]$l.Add(@{ Id = '1'; DisplayName = 'A' }); [void]$l.Add(@{ Id = '2'; DisplayName = 'B' })
    $n = 0; foreach ($p in $l) { $n++ }
    $n -eq 2
}

Write-Host "`n== Import module ==" -ForegroundColor Cyan
$manifest = Join-Path $ModuleRoot 'M365UserGroupManager.psd1'
Assert-That 'module imports' { Import-Module $manifest -Force; $true }
Assert-That 'exports Show-M365UserGroupManager' { [bool](Get-Command Show-M365UserGroupManager -ErrorAction SilentlyContinue) }

# Pull module-internal state/functions into this scope for white-box checks.
$mod = Get-Module M365UserGroupManager

Write-Host "`n== Catalog ==" -ForegroundColor Cyan
$catalog = & $mod { $script:Catalog }
Assert-That 'catalog has User + Group' { $catalog.User -and $catalog.Group }
$allAttrs = @()
foreach ($g in @($catalog.User) + @($catalog.Group)) { $allAttrs += $g.Attributes }
Assert-That 'every attribute has Name/Label/Input' {
    -not ($allAttrs | Where-Object { -not $_.Name -or -not $_.Label -or -not $_.Input })
}
$validInputs = 'Text', 'Multi', 'Bool', 'Choice', 'Date', 'Person', 'ReadOnly', 'Password', 'License', 'ExtAttr', 'GroupType', 'Upn'
Assert-That 'all Input types are known' {
    -not ($allAttrs | Where-Object { $validInputs -notcontains $_.Input })
}
Assert-That 'exactly 15 extension attributes' {
    @($allAttrs | Where-Object { $_.Input -eq 'ExtAttr' }).Count -eq 15
}
Assert-That 'attribute Names are unique within each tab' {
    $u = @($catalog.User.Attributes | ForEach-Object { $_.Name })
    $g = @($catalog.Group.Attributes | ForEach-Object { $_.Name })
    ($u.Count -eq ($u | Select-Object -Unique).Count) -and ($g.Count -eq ($g | Select-Object -Unique).Count)
}

Write-Host "`n== Config ==" -ForegroundColor Cyan
$cfg = & $mod { New-DefaultConfig }
Assert-That 'default config has accounts list + enabled sets' {
    ($null -ne $cfg.Accounts) -and ($cfg.Users.Enabled.Count -gt 0) -and ($cfg.Groups.Enabled.Count -gt 0)
}
Assert-That 'config JSON round-trips' {
    $json = $cfg | ConvertTo-Json -Depth 6
    $back = $json | ConvertFrom-Json
    @($back.Users.Enabled).Count -eq @($cfg.Users.Enabled).Count
}

Write-Host "`n== Hybrid SOA gating ==" -ForegroundColor Cyan
Assert-That 'Test-ObjectSynced is true ONLY for onPremisesSyncEnabled=true' {
    & $mod {
        (Test-ObjectSynced @{ onPremisesSyncEnabled = $true }) -and
        -not (Test-ObjectSynced @{ onPremisesSyncEnabled = $false }) -and
        -not (Test-ObjectSynced @{ onPremisesSyncEnabled = $null }) -and
        -not (Test-ObjectSynced $null)
    }
}
Assert-That 'OnPrem field: read-only when synced, editable when cloud-only / New' {
    & $mod {
        $a = @{ Name = 'displayName'; Input = 'Text'; Writable = $true }
        (-not (Test-FieldCloudEditable -Attr $a -Object @{ onPremisesSyncEnabled = $true })) -and
        (Test-FieldCloudEditable -Attr $a -Object @{ onPremisesSyncEnabled = $null }) -and
        (Test-FieldCloudEditable -Attr $a -Object $null)
    }
}
Assert-That 'Cloud-authority field stays editable even when synced' {
    & $mod {
        $a = @{ Name = 'assignedLicenses'; Input = 'License'; Writable = $true; Authority = 'Cloud' }
        Test-FieldCloudEditable -Attr $a -Object @{ onPremisesSyncEnabled = $true }
    }
}
Assert-That 'source label is correct + ASCII (mojibake guard)' {
    & $mod {
        $s = Get-ObjectSourceLabel @{ onPremisesSyncEnabled = $true }
        (Get-ObjectSourceLabel $null) -eq 'New' -and
        (Get-ObjectSourceLabel @{ onPremisesSyncEnabled = $null }) -eq 'Cloud' -and
        $s -eq 'Synced from AD' -and [regex]::IsMatch($s, '^[\x20-\x7E]+$')
    }
}
Assert-That 'catalog Authority values are all known (Cloud/OnPrem/ReadOnly)' {
    & $mod {
        $valid = 'Cloud', 'OnPrem', 'ReadOnly'
        $bad = foreach ($tab in 'User', 'Group') {
            foreach ($a in (Get-CatalogAttributeList -Tab $tab)) {
                if ($a.Authority -and ($valid -notcontains $a.Authority)) { $a.Name }
            }
        }
        -not $bad
    }
}
Assert-That 'expected Cloud-authoritative user fields, identity fields excluded' {
    & $mod {
        $cloud = @(Get-CatalogAttributeList -Tab 'User' | Where-Object { (Resolve-FieldAuthority $_) -eq 'Cloud' } | ForEach-Object { $_.Name })
        ($cloud -contains 'assignedLicenses') -and ($cloud -contains 'usageLocation') -and
        ($cloud -notcontains 'displayName') -and ($cloud -notcontains 'accountEnabled') -and ($cloud -notcontains 'passwordProfile') -and ($cloud -notcontains 'userType')
    }
}
Assert-That 'ConvertTo-AdAttributeWrites: Replace/Clear/Unsupported + multi-first (5.1 array path)' {
    & $mod {
        $changes = @(
            @{ Name = 'jobTitle'; Value = 'Analyst' },
            @{ Name = 'department'; Value = '' },
            @{ Name = 'businessPhones'; Value = @('+1 555 0100', '+1 555 0199') },
            @{ Name = 'otherMails'; Value = 'x@y.com' }
        )
        $w = ConvertTo-AdAttributeWrites -Changes $changes
        ($w.Replace['title'] -eq 'Analyst') -and ($w.Replace['telephoneNumber'] -eq '+1 555 0100') -and
        ($w.Clear -contains 'department') -and ($w.Unsupported -contains 'otherMails')
    }
}
Assert-That 'Protect-AdFilterValue doubles single quotes (AD -Filter injection guard)' {
    & $mod { (Protect-AdFilterValue "o'brien") -eq "o''brien" -and (Protect-AdFilterValue 'plain') -eq 'plain' -and (Protect-AdFilterValue $null) -eq '' }
}
Assert-That 'every on-prem-mastered user scalar field maps to AD (only otherMails unsupported)' {
    & $mod {
        $map = Get-CloudToAdAttributeMap
        $unmapped = foreach ($a in (Get-CatalogAttributeList -Tab 'User')) {
            if ($a.Input -in 'Person', 'License', 'Password', 'Bool', 'ReadOnly', 'GroupType', 'Date') { continue }
            if ((Resolve-FieldAuthority $a) -ne 'OnPrem') { continue }
            if (-not $map.ContainsKey($a.Name)) { $a.Name }
        }
        -not @($unmapped | Where-Object { $_ -ne 'otherMails' })
    }
}

Write-Host "`n== Field factory ==" -ForegroundColor Cyan
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
# Build one row per Input type into a throwaway TableLayoutPanel and verify it gets a control.
& $mod {
    $tlp = New-Object System.Windows.Forms.TableLayoutPanel
    $tlp.ColumnCount = 2
    $tt = New-Object System.Windows.Forms.ToolTip
    foreach ($g in @($script:Catalog.User) + @($script:Catalog.Group)) {
        foreach ($a in $g.Attributes) {
            $field = New-FieldRow -Attr $a -Mode 'Edit' -Tlp $tlp -Tooltip $tt
            if (-not $field.Main) { throw "no Main control for $($a.Name) ($($a.Input))" }
            if (-not $field.Cell) { throw "no Cell control for $($a.Name) ($($a.Input))" }
        }
    }
}
Assert-That 'every catalog attribute builds a control (Edit mode)' { $true }

# Hybrid read-only rendering (P0-UI): on-prem-mastered fields become non-editable but readable.
Assert-That 'Set-FieldReadOnlyForSync: Text -> ReadOnly, Bool -> disabled' {
    & $mod {
        $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
        $tt = New-Object System.Windows.Forms.ToolTip
        $textF = New-FieldRow -Attr @{ Name = 'displayName'; Label = 'Display'; Input = 'Text'; Writable = $true } -Mode 'Edit' -Tlp $tlp -Tooltip $tt
        $boolF = New-FieldRow -Attr @{ Name = 'accountEnabled'; Label = 'Enabled'; Input = 'Bool'; Writable = $true } -Mode 'Edit' -Tlp $tlp -Tooltip $tt
        Set-FieldReadOnlyForSync -Field $textF
        Set-FieldReadOnlyForSync -Field $boolF
        $textF.Main.ReadOnly -and (-not $boolF.Main.Enabled)
    }
}
Assert-That 'Set-FieldReadOnlyForSync: gated Person keeps list readable, disables its buttons' {
    & $mod {
        $tt = New-Object System.Windows.Forms.ToolTip
        $pf = New-FieldRow -Attr @{ Name = 'members'; Label = 'Members'; Input = 'Person'; Writable = $true; Multi = $true; TargetType = 'Any' } -Mode 'Edit' -Tooltip $tt
        Set-FieldReadOnlyForSync -Field $pf
        $btns = @($pf.Cell.Controls | Where-Object { $_ -is [System.Windows.Forms.Button] })
        ($pf.Main.Enabled) -and ($btns.Count -gt 0) -and (-not ($btns | Where-Object { $_.Enabled }))
    }
}
Assert-That 'usage location dropdown: full-name items, 2-letter code value round-trip' {
    & $mod {
        $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
        $f = New-FieldRow -Attr @{ Name = 'usageLocation'; Label = 'Usage'; Input = 'Choice'; ChoiceSource = 'Country'; Writable = $true } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
        $us = $f.Main.Items | Where-Object { $_.Code -eq 'US' }
        Set-FieldValue -Field $f -Value 'gb'
        ($us -and ($us.Display -match 'United States')) -and ((Read-FieldValue $f) -eq 'GB')
    }
}
Assert-That 'New-Passphrase: has upper+lower+digit+symbol and no symbol runs (e.g. no "__")' {
    & $mod {
        $ok = $true
        foreach ($n in 1..25) {
            $p = New-Passphrase
            if ($p -cnotmatch '[A-Z]') { $ok = $false }                 # uppercase (capitalized words)
            if ($p -cnotmatch '[a-z]') { $ok = $false }                 # lowercase
            if ($p -notmatch '[0-9]') { $ok = $false }                  # a digit
            if ($p -notmatch '[!@#$%\-]') { $ok = $false }              # a symbol
            if ($p -match '[!@#$%\-]{2,}') { $ok = $false }             # NO run of symbols
            if ($p -match '[&^?+=_]') { $ok = $false }                  # none of the shell/URL-risky symbols
            if ($p.Length -lt 10) { $ok = $false }
        }
        $ok
    }
}
Assert-That 'CharFilter: alias field allows letters/dot but blocks space/@' {
    & $mod {
        $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
        $f = New-FieldRow -Attr @{ Name = 'mailNickname'; Label = 'Alias'; Input = 'Text'; Writable = $true; CharFilter = '[A-Za-z0-9.\-_]' } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
        $pat = [string]$f.Main.Tag
        $pat -and ('a' -match $pat) -and ('.' -match $pat) -and ('@' -notmatch $pat) -and (' ' -notmatch $pat)
    }
}
Assert-That 'catalog CharFilter patterns are valid regex' {
    & $mod {
        $bad = foreach ($a in (Get-CatalogAttributeList -Tab 'User')) {
            if ($a.CharFilter) { try { [void][regex]::new($a.CharFilter) } catch { $a.Name } }
        }
        -not $bad
    }
}
Assert-That 'UPN field round-trips local@domain' {
    & $mod {
        $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
        $f = New-FieldRow -Attr @{ Name = 'userPrincipalName'; Label = 'UPN'; Input = 'Upn'; Writable = $true } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
        Set-FieldValue -Field $f -Value 'jane.doe@contoso.com'
        (Read-FieldValue $f) -eq 'jane.doe@contoso.com'
    }
}
Assert-That 'name generation: First/Last -> "First Last" + sanitized first.last alias' {
    & $mod {
        $g = Get-GeneratedUserNames -First "O'Brien" -Last 'Smith'
        ($g.Display -eq "O'Brien Smith") -and ($g.Alias -eq 'obrien.smith')
    }
}
Assert-That 'new-user required model: First/Last marked required; display/alias/UPN required-to-create (unmarked); accountEnabled not required' {
    & $mod {
        $b = @{}; foreach ($a in (Get-CatalogAttributeList -Tab 'User')) { $b[$a.Name] = $a }
        $b['givenName'].Required -and $b['surname'].Required -and
        (-not $b['displayName'].Required) -and $b['displayName'].RequiredForCreate -and
        (-not $b['userPrincipalName'].Required) -and $b['userPrincipalName'].RequiredForCreate -and ($b['userPrincipalName'].Input -eq 'Upn') -and
        (-not $b['accountEnabled'].Required)
    }
}
Assert-That 'New-user form is CURATED: create essentials shown; profile detail (job/dept/manager/etc.) hidden until Edit' {
    & $mod {
        $newSet = @(Get-CatalogAttributeList -Tab 'User' | Where-Object { $_.ShowOnNew -or $_.Required -or $_.RequiredForCreate } | ForEach-Object { $_.Name })
        $missingEssentials = @('givenName', 'surname', 'displayName', 'userPrincipalName', 'mailNickname', 'passwordProfile', 'accountEnabled', 'usageLocation', 'assignedLicenses') | Where-Object { $newSet -notcontains $_ }
        $leakedExtras = @('jobTitle', 'department', 'manager', 'employeeId', 'streetAddress', 'extensionAttribute1', 'mobilePhone', 'otherMails', 'userType', 'companyName') | Where-Object { $newSet -contains $_ }
        (-not $missingEssentials) -and (-not $leakedExtras)
    }
}
Assert-That 'User section order guides the New flow: Name, Account, Identity, Licensing' {
    & $mod {
        $secs = @(Get-CatalogTab -Tab 'User' | ForEach-Object { $_.Name })
        ($secs[0] -eq 'Name') -and ($secs[1] -eq 'Account') -and ($secs[2] -eq 'Identity & Sign-in') -and ($secs[3] -eq 'Licensing')
    }
}
Assert-That 'New-group form shows type/name/description/members/owners, not read-only fields' {
    & $mod {
        $newSet = @(Get-CatalogAttributeList -Tab 'Group' | Where-Object { $_.ShowOnNew -or $_.Required -or $_.RequiredForCreate } | ForEach-Object { $_.Name })
        ($newSet -contains '__groupType') -and ($newSet -contains 'displayName') -and ($newSet -contains 'mailNickname') -and
        ($newSet -contains 'description') -and ($newSet -contains 'members') -and ($newSet -contains 'owners') -and
        ($newSet -notcontains 'id') -and ($newSet -notcontains 'groupTypes')
    }
}

# Exchange catalog attributes also build controls.
& $mod {
    $tt = New-Object System.Windows.Forms.ToolTip
    foreach ($g in $script:Catalog.Exchange.Groups) {
        foreach ($a in $g.Attributes) {
            $field = New-FieldRow -Attr $a -Mode 'Edit' -Tooltip $tt
            if (-not $field.Main) { throw "no Exchange control for $($a.Name)" }
        }
    }
}
Assert-That 'every Exchange attribute builds a control' { $true }
Assert-That 'Exchange catalog has 5 object types' { (& $mod { $script:Catalog.Exchange.Types.Count }) -eq 5 }
Assert-That 'main form builds headless, including the guest-invite panel + handles' {
    & $mod {
        $script:AppReady = $false
        $script:Config = New-DefaultConfig
        $form = New-MainForm
        $ok = $script:UI.User.GuestBox -and $script:UI.User.TypeMember -and $script:UI.User.TypeGuest -and `
              $script:UI.User.GuestEmail -and $script:UI.User.GuestUrl -and $script:UI.User.GuestSend
        $form.Dispose()
        [bool]$ok
    }
}
Assert-That 'guest invite wired: User.Invite.All scope + Send-GuestInvitation present' {
    & $mod {
        ($script:GraphScopes -contains 'User.Invite.All') -and [bool](Get-Command Send-GuestInvitation -ErrorAction SilentlyContinue)
    }
}
Assert-That 'New/Edit and Member/Guest are INDEPENDENT radio groups (Guest does not deselect New)' {
    & $mod {
        $script:AppReady = $false; $script:Config = New-DefaultConfig
        $form = New-MainForm
        $u = $script:UI.User
        $u.TypeGuest.Checked = $true
        $ok = ($u.ModeNew.Checked) -and ($u.TypeGuest.Checked) -and (-not $u.ModeEdit.Checked) -and (-not $u.TypeMember.Checked)
        # and the panel really is a separate parent (not $left), so grouping is independent
        $sep = ($u.TypeMember.Parent -ne $u.ModeNew.Parent)
        $form.Dispose()
        $ok -and $sep
    }
}

# Text field read / set / dirty.
$dirtyResult = & $mod {
    $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
    $attr = @{ Name = 'displayName'; Label = 'Display Name'; Input = 'Text'; Writable = $true; Required = $true }
    $field = New-FieldRow -Attr $attr -Mode 'Edit' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
    Set-FieldValue -Field $field -Value 'Jane Doe'
    Set-FieldBaseline -Field $field
    $cleanRead = Read-FieldValue $field
    $cleanDirty = Test-FieldDirty $field
    $field.Main.Text = 'Jane Smith'
    $afterDirty = Test-FieldDirty $field
    [pscustomobject]@{ Read = $cleanRead; CleanDirty = $cleanDirty; AfterDirty = $afterDirty }
}
Assert-That 'Text field reads prefilled value'       { $dirtyResult.Read -eq 'Jane Doe' }
Assert-That 'Text field clean baseline is not dirty'  { $dirtyResult.CleanDirty -eq $false }
Assert-That 'Text field becomes dirty after edit'     { $dirtyResult.AfterDirty -eq $true }

# Bool tri-detect + GroupType + Choice country read.
$misc = & $mod {
    $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
    $tt = New-Object System.Windows.Forms.ToolTip
    $boolF = New-FieldRow -Attr @{ Name = 'accountEnabled'; Label = 'Enabled'; Input = 'Bool'; Writable = $true } -Mode 'New' -Tlp $tlp -Tooltip $tt
    Set-FieldValue -Field $boolF -Value $true
    $gtF = New-FieldRow -Attr @{ Name = '__groupType'; Label = 'Type'; Input = 'GroupType'; Writable = $true } -Mode 'Edit' -Tlp $tlp -Tooltip $tt
    Set-GroupTypeField -Field $gtF -Type 'Microsoft365' -Lock
    $ctyF = New-FieldRow -Attr @{ Name = 'usageLocation'; Label = 'Usage'; Input = 'Choice'; ChoiceSource = 'Country'; Writable = $true } -Mode 'New' -Tlp $tlp -Tooltip $tt
    Set-FieldValue -Field $ctyF -Value 'us'
    [pscustomobject]@{
        Bool = (Read-FieldValue $boolF)
        GroupType = (Read-FieldValue $gtF)
        GroupTypeLocked = (-not $gtF.Main.Enabled)
        Country = (Read-FieldValue $ctyF)
    }
}
Assert-That 'Bool field reads $true'              { $misc.Bool -eq $true }
Assert-That 'GroupType reads Microsoft365'         { $misc.GroupType -eq 'Microsoft365' }
Assert-That 'GroupType is locked after Set -Lock'  { $misc.GroupTypeLocked }
Assert-That 'Country choice uppercases code'       { $misc.Country -eq 'US' }

# Regression: a List[object] of hashtables through the person/people path must not hit the
# Windows PowerShell 5.1 "@() over a collection of hashtables" binder crash. (Run this harness
# under powershell.exe 5.1 to actually exercise that path.)
$peopleResult = & $mod {
    $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
    $f = New-FieldRow -Attr @{ Name = 'members'; Label = 'M'; Input = 'Person'; Writable = $true; Multi = $true; TargetType = 'Any' } -Mode 'Edit' -Tooltip (New-Object System.Windows.Forms.ToolTip)
    $list = New-Object System.Collections.Generic.List[object]
    $list.Add(@{ Id = 'a@x.com'; DisplayName = 'A'; Detail = 'a@x.com' })
    $list.Add(@{ Id = 'b@x.com'; DisplayName = 'B'; Detail = 'b@x.com' })
    Set-PersonFieldValue -Field $f -People $list                 # would crash on 5.1 if @() were used
    $copy = New-Object System.Collections.Generic.List[object]; $copy.Add(@{ Id = 'c' })
    $arr = , $copy.ToArray()                                     # picker-return pattern
    @{ Count = @(Read-FieldValue $f).Count; ArrOk = ($arr[0].Id -eq 'c') }
}
Assert-That 'List-of-hashtables person round-trip (5.1 binder guard)' { $peopleResult.Count -eq 2 -and $peopleResult.ArrOk }

Write-Host "`n== Validation ==" -ForegroundColor Cyan
$valid = & $mod {
    $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
    $tt = New-Object System.Windows.Forms.ToolTip
    $upn = New-FieldRow -Attr @{ Name = 'userPrincipalName'; Label = 'UPN'; Input = 'Text'; Writable = $true; Required = $true } -Mode 'New' -Tlp $tlp -Tooltip $tt
    $upn.Main.Text = 'not-an-upn'
    $bad = Get-FieldValidationError -Field $upn
    $upn.Main.Text = 'jane@contoso.com'
    $good = Get-FieldValidationError -Field $upn
    [pscustomobject]@{ Bad = $bad; Good = $good }
}
Assert-That 'invalid UPN is rejected' { $null -ne $valid.Bad }
Assert-That 'valid UPN passes'        { $null -eq $valid.Good }

Write-Host "`n== Headless form build ==" -ForegroundColor Cyan
$env:M365UGM_NOLAUNCH = '1'
$form = $null
Assert-That 'main form builds headless' {
    $form = Show-M365UserGroupManager
    $null = $form.Handle
    $form.CreateControl()
    $form.PerformLayout()
    $form -is [System.Windows.Forms.Form]
}
Assert-That 'has Users, Groups and Exchange tabs' {
    $tabs = & $mod { $script:UI.Tabs }
    ($tabs.TabPages.Count -eq 3) -and ($tabs.TabPages[2].Text -eq 'Exchange')
}
Assert-That 'Exchange tab starts gated (not connected, management panel hidden)' {
    # Note: Control.Visible reports EFFECTIVE visibility (false for any control on a form that was
    # never shown), so we assert the real gate condition instead: not EXO-connected + manage hidden.
    $ex = & $mod { $script:UI.Exchange }
    (-not (& $mod { Test-ExoConnected })) -and ($null -ne $ex.ActivationPanel) -and (-not $ex.ManagePanel.Visible)
}
Assert-That 'both tabs built field rows' {
    $u = & $mod { $script:UI.User.FormTlp.Controls.Count }
    $g = & $mod { $script:UI.Group.FormTlp.Controls.Count }
    ($u -gt 0) -and ($g -gt 0)
}
Assert-That 'connection label starts disconnected' {
    (& $mod { $script:UI.ConnLabel.Text }) -eq 'Not connected'
}
if ($form) { $form.Dispose() }
Remove-Item Env:\M365UGM_NOLAUNCH -ErrorAction SilentlyContinue

Write-Host "`n== Summary ==" -ForegroundColor Cyan
Write-Host ("  Passed: {0}   Failed: {1}" -f $script:Passed, $script:Failures) -ForegroundColor $(if ($script:Failures) { 'Red' } else { 'Green' })
if ($script:Failures -gt 0) { exit 1 } else { exit 0 }
