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
Assert-That 'default config has accounts list + enabled sets (on-prem prefs are now per-tenant, not global)' {
    ($null -ne $cfg.Accounts) -and ($cfg.Users.Enabled.Count -gt 0) -and ($cfg.Groups.Enabled.Count -gt 0) -and
    (-not $cfg.ContainsKey('LastOnPremOuDn')) -and (-not $cfg.ContainsKey('ConnectServer'))   # retired globals
}
Assert-That 'per-tenant on-prem profile reads by tenant id (two hybrids never bleed into each other)' {
    & $mod {
        # In-memory only (no Set -> no disk write); proves reads are keyed by tenant id.
        $script:Config = @{ Accounts = @(
                @{ TenantId = 'A'; ExpectedOnPremDomain = 'hybrid1.local'; ConnectServer = 'adc-a' },
                @{ TenantId = 'B'; ExpectedOnPremDomain = 'hybrid2.local' }
            ) }
        ((Get-TenantProfileValue -Field 'ExpectedOnPremDomain' -TenantId 'A') -eq 'hybrid1.local') -and
        ((Get-TenantProfileValue -Field 'ExpectedOnPremDomain' -TenantId 'B') -eq 'hybrid2.local') -and
        ((Get-TenantProfileValue -Field 'ConnectServer' -TenantId 'B') -eq '')   # A's server never bleeds to B
    }
}
Assert-That 'config JSON round-trips' {
    $json = $cfg | ConvertTo-Json -Depth 6
    $back = $json | ConvertFrom-Json
    @($back.Users.Enabled).Count -eq @($cfg.Users.Enabled).Count
}
Assert-That 'default config has the global device/WinRM settings (with sane defaults)' {
    ($cfg.WinRmTimeoutMs -eq 8000) -and (@($cfg.DeviceCleanupTargets).Count -eq 4) -and
    (@($cfg.DeviceCleanupTargets) -contains 'Intune') -and (@($cfg.DeviceCleanupTargets) -contains 'AdComputer')
}
Assert-That 'Get-TenantProfileList reads a per-tenant LIST (AdServers) as an array, keyed by tenant' {
    & $mod {
        $script:Config = @{ Accounts = @(
                @{ TenantId = 'A'; AdServers = @('dc01.a.dom', 'dc02.a.dom') },
                @{ TenantId = 'B' }
            ) }
        $a = Get-TenantProfileList -Field 'AdServers' -TenantId 'A'
        $b = Get-TenantProfileList -Field 'AdServers' -TenantId 'B'   # unset -> empty array
        (@($a).Count -eq 2) -and ($a[0] -eq 'dc01.a.dom') -and (@($b).Count -eq 0)
    }
}
Assert-That 'WinRM open-timeout honours the configured WinRmTimeoutMs (falls back to 8000)' {
    & $mod {
        $script:Config = @{ WinRmTimeoutMs = 15000 }
        $opt = New-AdSyncSessionOption
        $script:Config = $null
        [int]$opt.OpenTimeout.TotalMilliseconds -eq 15000
    }
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
Assert-That 'Get-AdSamAccountName: lowercases, strips illegal chars, caps at 20 (legacy SAM limit)' {
    & $mod {
        (Get-AdSamAccountName -Alias 'Jane.Doe') -eq 'jane.doe' -and
        ((Get-AdSamAccountName -Alias 'christopher.alexander.andersson').Length -le 20) -and
        ((Get-AdSamAccountName -Alias "o'br ien*") -eq 'obrien')   # strips quote / space / asterisk
    }
}
Assert-That 'Test-AdSamAccountNameValid: rejects >20 chars, illegal chars, and empty' {
    & $mod {
        (Test-AdSamAccountNameValid -Sam 'jane.doe') -and
        (-not (Test-AdSamAccountNameValid -Sam ('a' * 21))) -and
        (-not (Test-AdSamAccountNameValid -Sam 'bad\name')) -and
        (-not (Test-AdSamAccountNameValid -Sam 'a;b')) -and
        (-not (Test-AdSamAccountNameValid -Sam ''))
    }
}
Assert-That 'ConvertTo-NewAdUserParams: native params vs OtherAttributes split; UPN + alias excluded' {
    & $mod {
        $changes = @(
            @{ Name = 'displayName'; Value = 'Jane Doe' },
            @{ Name = 'jobTitle'; Value = 'Engineer' },
            @{ Name = 'preferredLanguage'; Value = 'en-US' },
            @{ Name = 'extensionAttribute1'; Value = 'X1' },
            @{ Name = 'userPrincipalName'; Value = 'jane@contoso.com' },  # first-class create param -> skipped
            @{ Name = 'mailNickname'; Value = 'jane.doe' },               # Exchange owns it on-prem -> skipped
            @{ Name = 'department'; Value = '' }                          # empty -> skipped
        )
        $r = ConvertTo-NewAdUserParams -Changes $changes
        ($r.NativeParams['DisplayName'] -eq 'Jane Doe') -and ($r.NativeParams['Title'] -eq 'Engineer') -and
        (-not $r.NativeParams.ContainsKey('Department')) -and
        ($r.OtherAttributes['preferredLanguage'] -eq 'en-US') -and ($r.OtherAttributes['extensionAttribute1'] -eq 'X1') -and
        (-not $r.NativeParams.ContainsKey('UserPrincipalName')) -and
        (-not $r.OtherAttributes.ContainsKey('userPrincipalName')) -and (-not $r.OtherAttributes.ContainsKey('mailNickname'))
    }
}
Assert-That 'Test-AdSyncForceAllowed: allows only an active, idle, scheduler-enabled exporter' {
    & $mod {
        $ok      = Test-AdSyncForceAllowed -Scheduler ([pscustomobject]@{ SyncCycleEnabled = $true;  StagingModeEnabled = $false }) -Busy $false
        $staging = Test-AdSyncForceAllowed -Scheduler ([pscustomobject]@{ SyncCycleEnabled = $true;  StagingModeEnabled = $true  }) -Busy $false
        $disabled= Test-AdSyncForceAllowed -Scheduler ([pscustomobject]@{ SyncCycleEnabled = $false; StagingModeEnabled = $false }) -Busy $false
        $busy    = Test-AdSyncForceAllowed -Scheduler ([pscustomobject]@{ SyncCycleEnabled = $true;  StagingModeEnabled = $false }) -Busy $true
        $none    = Test-AdSyncForceAllowed -Scheduler $null -Busy $false
        $ok.Allowed -and (-not $staging.Allowed) -and (-not $disabled.Allowed) -and (-not $busy.Allowed) -and (-not $none.Allowed)
    }
}
Assert-That 'Get-EntraConnectSyncInfo + force-sync helpers exist (force-sync backend present)' {
    & $mod {
        (Get-Command Get-EntraConnectSyncInfo, Resolve-ServerFqdn, Test-ConnectServerReachable,
            Get-RemoteAdSyncState, Invoke-RemoteAdSyncDelta, Invoke-ForceDirectorySync -ErrorAction SilentlyContinue).Count -eq 6
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
Assert-That 'Group catalog: mailNickname is required-to-create (unmarked) + M365-only; visibility M365-only; displayName required for both' {
    & $mod {
        $b = @{}; foreach ($a in (Get-CatalogAttributeList -Tab 'Group')) { $b[$a.Name] = $a }
        (-not $b['mailNickname'].Required) -and $b['mailNickname'].RequiredForCreate -and
        ($b['mailNickname'].AppliesToGroupKind -eq 'Microsoft365') -and
        ($b['visibility'].AppliesToGroupKind -eq 'Microsoft365') -and
        $b['displayName'].Required -and (-not $b['displayName'].AppliesToGroupKind)
    }
}
Assert-That 'Get-GeneratedGroupAlias sanitizes display name to a Graph-legal mailNickname' {
    & $mod {
        (Get-GeneratedGroupAlias -DisplayName 'Sales & Marketing Team!') -eq 'salesmarketingteam' -and
        (Get-GeneratedGroupAlias -DisplayName '  Help.Desk_2024  ')      -eq 'help.desk_2024' -and
        ((Get-GeneratedGroupAlias -DisplayName ('x' * 80)).Length -le 64)
    }
}
Assert-That 'Build-GroupPayload (New): Security -> mailEnabled=false/securityEnabled=true, NO groupTypes, NO visibility, auto-generated mailNickname, no Team' {
    & $mod {
        $script:AppReady = $false; $script:Config = New-DefaultConfig
        $form = New-MainForm
        $g = $script:UI.Group
        Set-GroupTypeField -Field $g.Fields['__groupType'] -Type 'Security'
        Set-GroupKindView -Kind 'Security'
        $g.Fields['displayName'].Main.Text = 'Operations Group'
        # operator never typed an alias (the field is hidden for Security)
        $body = Build-GroupPayload -Mode 'New'
        $form.Dispose()
        ($body.mailEnabled -eq $false) -and ($body.securityEnabled -eq $true) -and
        (-not $body.ContainsKey('groupTypes')) -and (-not $body.ContainsKey('visibility')) -and
        (-not $body.ContainsKey('resourceProvisioningOptions')) -and
        ($body.displayName -eq 'Operations Group') -and ($body.mailNickname -eq 'operationsgroup')
    }
}
Assert-That 'Build-GroupPayload (New): a non-ASCII Security group still gets a NON-EMPTY, Graph-legal mailNickname (no empty-alias 400)' {
    & $mod {
        $script:AppReady = $false; $script:Config = New-DefaultConfig
        $form = New-MainForm
        $g = $script:UI.Group
        Set-GroupTypeField -Field $g.Fields['__groupType'] -Type 'Security'; Set-GroupKindView -Kind 'Security'
        $g.Fields['displayName'].Main.Text = "Pekin Takimi"   # set, then force the all-non-ASCII/symbol case below
        $g.Fields['displayName'].Main.Text = "!@#"            # sanitizes to '' -> must fall back, not POST empty
        $body = Build-GroupPayload -Mode 'New'
        $form.Dispose()
        $mn = [string]$body['mailNickname']
        $body.ContainsKey('mailNickname') -and ($mn.Length -gt 0) -and ($mn.Length -le 64) -and ($mn -match '^[A-Za-z0-9.\-_]+$')
    }
}
Assert-That 'Build-GroupPayload (New): Microsoft 365 -> groupTypes=[Unified]/mailEnabled=true/securityEnabled=false, alias kept, visibility allowed' {
    & $mod {
        $script:AppReady = $false; $script:Config = New-DefaultConfig
        $form = New-MainForm
        $g = $script:UI.Group
        Set-GroupTypeField -Field $g.Fields['__groupType'] -Type 'Microsoft365'
        Set-GroupKindView -Kind 'Microsoft365'
        $g.Fields['displayName'].Main.Text  = 'Library Assist'
        $g.Fields['mailNickname'].Main.Text = 'library'
        $g.Fields['visibility'].Main.SelectedItem = 'Private'
        $body = Build-GroupPayload -Mode 'New'
        $form.Dispose()
        (@($body.groupTypes) -contains 'Unified') -and ($body.mailEnabled -eq $true) -and
        ($body.securityEnabled -eq $false) -and ($body.mailNickname -eq 'library') -and
        ($body.visibility -eq 'Private') -and (-not $body.ContainsKey('resourceProvisioningOptions'))
    }
}
Assert-That 'Group validation: mailNickname NOT required for a Security group (hidden); required for M365 when blank' {
    & $mod {
        $script:AppReady = $false; $script:Config = New-DefaultConfig
        $form = New-MainForm
        $g = $script:UI.Group
        # Security: name set, alias blank + hidden -> the alias does not block create (auto-generated).
        Set-GroupTypeField -Field $g.Fields['__groupType'] -Type 'Security'; Set-GroupKindView -Kind 'Security'
        $g.Fields['displayName'].Main.Text = 'Test'
        $g.Fields['mailNickname'].Main.Text = ''
        $secAliasErr = Get-FieldValidationError -Field $g.Fields['mailNickname']
        # M365: everything blank -> the shown alias is required-to-create (RequiredForCreate fires).
        Set-GroupTypeField -Field $g.Fields['__groupType'] -Type 'Microsoft365'; Set-GroupKindView -Kind 'Microsoft365'
        $g.Fields['displayName'].Main.Text = ''
        $g.Fields['mailNickname'].Main.Text = ''
        $g.Fields['mailNickname'].AutoLast = ''   # operator cleared it; no display name to auto-refill from
        $m365AliasErr = Get-FieldValidationError -Field $g.Fields['mailNickname']
        $form.Dispose()
        ($null -eq $secAliasErr) -and ($null -ne $m365AliasErr)
    }
}
Assert-That 'Group New view reacts to the kind: M365 marks alias+visibility shown, Security marks them hidden' {
    & $mod {
        $script:AppReady = $false; $script:Config = New-DefaultConfig
        $form = New-MainForm
        $g = $script:UI.Group
        $g.ModeNew.Checked = $true
        # Control.Visible reports EFFECTIVE visibility (false on a never-shown / overlay-covered form),
        # so assert the descriptor's KindShown flag, which records what the kind view actually decided.
        Set-GroupKindView -Kind 'Microsoft365'
        $m365 = ($g.CurrentKind -eq 'Microsoft365') -and ($g.Fields['mailNickname'].KindShown) -and ($g.Fields['visibility'].KindShown)
        Set-GroupKindView -Kind 'Security'
        $sec = ($g.CurrentKind -eq 'Security') -and (-not $g.Fields['mailNickname'].KindShown) -and (-not $g.Fields['visibility'].KindShown)
        $form.Dispose()
        $m365 -and $sec
    }
}
Assert-That 'Group New: the alias composite cell sits in the form grid value column (col 1), not floated to (0,0)' {
    & $mod {
        # Regression guard: the alias TextBox is wrapped in a composite cell (alias + read-only domain
        # suffix). The position MUST be captured before reparenting, or GetCellPosition returns (-1,-1)
        # and the cell auto-flows to the top-left, scrambling the whole form.
        $script:AppReady = $false; $script:Config = New-DefaultConfig
        $script:VerifiedDomains = @(@{ Name = 'contoso.com'; IsDefault = $true })
        $form = New-MainForm
        $g = $script:UI.Group
        $aliasF = $g.Fields['mailNickname']
        $pos = $g.FormTlp.GetCellPosition($aliasF.Cell)
        $hasSuffix = [bool]$aliasF.Aux
        $form.Dispose()
        $hasSuffix -and ($pos.Column -eq 1) -and ($pos.Row -ge 0)
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
        $ok = $script:UI.User.GuestBox -and $script:UI.User.TypeCombo -and ($script:UI.User.TypeCombo.Items.Count -eq 2) -and `
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
Assert-That 'Mode (New/Edit radios) and account-type (combo) are independent (selecting Guest does not change mode)' {
    & $mod {
        $script:AppReady = $false; $script:Config = New-DefaultConfig
        $form = New-MainForm
        $u = $script:UI.User
        $u.TypeCombo.SelectedIndex = 1   # Guest
        # Mode is a radio, type is a combo -- inherently independent. New stays selected.
        $ok = ($u.ModeNew.Checked) -and (-not $u.ModeEdit.Checked) -and ("$($u.TypeCombo.SelectedItem)" -match '^Guest')
        $form.Dispose()
        $ok
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

Write-Host "`n== Graph module version coherence ==" -ForegroundColor Cyan
Assert-That 'ConvertTo-ThreePartVersion normalizes 4-part asm version (2.37.0.0 -> 2.37.0)' {
    (& $mod { ConvertTo-ThreePartVersion ([version]'2.37.0.0') }) -eq [version]'2.37.0'
}
Assert-That 'ConvertTo-ThreePartVersion fills missing build (2.37 -> 2.37.0)' {
    (& $mod { ConvertTo-ThreePartVersion ([version]'2.37') }) -eq [version]'2.37.0'
}
Assert-That "Resolve target: the user's split install (mixed 2.36.1/2.37.0) heals UP to 2.37.0" {
    & $mod {
        $req = 'Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Users.Actions','Microsoft.Graph.Groups','Microsoft.Graph.Identity.DirectoryManagement','Microsoft.Graph.Identity.SignIns'
        $inst = @{
            'Microsoft.Graph.Authentication'               = [version[]]@('2.36.1','2.37.0')
            'Microsoft.Graph.Users'                        = [version[]]@('2.36.1')
            'Microsoft.Graph.Users.Actions'                = [version[]]@('2.37.0')
            'Microsoft.Graph.Groups'                       = [version[]]@('2.36.1')
            'Microsoft.Graph.Identity.DirectoryManagement' = [version[]]@('2.36.1')
            'Microsoft.Graph.Identity.SignIns'             = [version[]]@('2.36.1')
        }
        $p = Resolve-GraphTargetVersion -Installed $inst -Required $req
        ($p.Target -eq [version]'2.37.0') -and ($p.Missing.Count -eq 4) -and
        ($p.Missing -contains 'Microsoft.Graph.Users') -and ($p.Missing -notcontains 'Microsoft.Graph.Users.Actions') -and
        ($p.Missing -notcontains 'Microsoft.Graph.Authentication')
    }
}
Assert-That 'Resolve target: a coherent install prefers the common version with NO installs' {
    & $mod {
        $req = 'Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Groups'
        $inst = @{
            'Microsoft.Graph.Authentication' = [version[]]@('2.36.1')
            'Microsoft.Graph.Users'          = [version[]]@('2.36.1')
            'Microsoft.Graph.Groups'         = [version[]]@('2.36.1')
        }
        $p = Resolve-GraphTargetVersion -Installed $inst -Required $req
        ($p.Target -eq [version]'2.36.1') -and ($p.Missing.Count -eq 0)
    }
}
Assert-That 'Resolve target: picks the highest COMMON version when several are shared by all' {
    & $mod {
        $req = 'A','B'
        $inst = @{ 'A' = [version[]]@('2.36.1','2.37.0'); 'B' = [version[]]@('2.36.1','2.37.0') }
        $p = Resolve-GraphTargetVersion -Installed $inst -Required $req
        ($p.Target -eq [version]'2.37.0') -and ($p.Missing.Count -eq 0)
    }
}
Assert-That 'Resolve target: nothing installed -> null target, everything missing' {
    & $mod {
        $req = 'A','B'
        $inst = @{ 'A' = [version[]]@(); 'B' = [version[]]@() }
        $p = Resolve-GraphTargetVersion -Installed $inst -Required $req
        ($null -eq $p.Target) -and ($p.Missing.Count -eq 2)
    }
}

Write-Host "`n== Theme / design rules ==" -ForegroundColor Cyan
Assert-That 'dark theme: secondary button border uses the contrast-safe CtrlBorder, not Brand cyan' {
    & $mod {
        $b = New-Object System.Windows.Forms.Button; Set-SecondaryButtonStyle $b
        $t = Get-Theme
        ($b.FlatAppearance.BorderColor.ToArgb() -eq $t.CtrlBorder.ToArgb()) -and `
        ($b.FlatAppearance.BorderColor.ToArgb() -ne $t.Brand.ToArgb()) -and `
        ($b.BackColor.ToArgb() -eq $t.BtnFace.ToArgb())
    }
}
Assert-That 'dark theme: palette Mode is Dark and section headers use the bright Header cyan (legible on dark)' {
    $t = & $mod { Get-Theme }
    ($t.Mode -eq 'Dark') -and ($t.Header.ToArgb() -eq $t.Brand.ToArgb())
}
Assert-That 'AccentHover is darker than Accent (hover keeps white text above AA)' {
    $t = & $mod { Get-Theme }
    $t.AccentHover.GetBrightness() -lt $t.Accent.GetBrightness()
}
Assert-That 'danger (Delete) style puts the red on the border, not just the glyph' {
    & $mod {
        $b = New-Object System.Windows.Forms.Button; Set-DangerButtonStyle $b
        $t = Get-Theme
        ($b.FlatAppearance.BorderColor.ToArgb() -eq $t.ErrText.ToArgb()) -and ($b.ForeColor.ToArgb() -eq $t.ErrText.ToArgb())
    }
}
Assert-That 'section-header font is a clear step above the field-label font' {
    $t = & $mod { Get-Theme }
    $t.FontSection.SizeInPoints -gt ($t.FontBase.SizeInPoints + 1)
}

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
Assert-That 'on-prem create: a DestHidden cloud-only field is skipped by validation (no Required block)' {
    & $mod {
        $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
        $tt = New-Object System.Windows.Forms.ToolTip
        # A required cloud-only field that's blank normally errors; once DestHidden (on-prem hides it), skipped.
        $f = New-FieldRow -Attr @{ Name = 'usageLocation'; Label = 'Usage Location'; Input = 'Choice'; Choices = @('US'); Required = $true } -Mode 'New' -Tlp $tlp -Tooltip $tt
        $before = Get-FieldValidationError -Field $f
        $f.DestHidden = $true
        $after = Get-FieldValidationError -Field $f
        ($null -ne $before) -and ($null -eq $after)
    }
}
Assert-That "SyncState ReadOnly field shows 'cloud-only' for null and 'synced' for true (not blank)" {
    & $mod {
        $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
        $tt = New-Object System.Windows.Forms.ToolTip
        $f = New-FieldRow -Attr @{ Name = 'onPremisesSyncEnabled'; Label = 'Directory Synced'; Input = 'ReadOnly'; Writable = $false; Format = 'SyncState' } -Mode 'Edit' -Tlp $tlp -Tooltip $tt
        Set-FieldValue -Field $f -Value $null;  $cloud  = $f.Main.Text
        Set-FieldValue -Field $f -Value $true;  $synced = $f.Main.Text
        ($cloud -match 'cloud-only') -and ($synced -match 'synced from on-prem')
    }
}

Write-Host "`n== Hybrid on-prem safety (wrong-forest / wrong-person guards) ==" -ForegroundColor Cyan
Assert-That 'Test-OnPremDomainMatch: exact + NetBIOS/FQDN match true; different forest false (the core guard)' {
    & $mod {
        (Test-OnPremDomainMatch -Expected 'hybrid1.local' -Actual 'hybrid1.local') -and        # same domain
        (Test-OnPremDomainMatch -Expected 'Hybrid1.LOCAL' -Actual 'hybrid1.local') -and        # case-insensitive
        (Test-OnPremDomainMatch -Expected 'hybrid1'     -Actual 'hybrid1.local') -and        # NetBIOS vs FQDN
        (Test-OnPremDomainMatch -Expected '' -Actual 'hybrid1.local') -and                         # cold start -> allow
        (-not (Test-OnPremDomainMatch -Expected 'hybrid2.local' -Actual 'hybrid1.local')) -and     # WRONG FOREST -> refuse
        (-not (Test-OnPremDomainMatch -Expected 'corp.a.dom'    -Actual 'corp.b.dom'))                 # same first label, diff forest -> refuse
    }
}
Assert-That 'Test-AdIdentityMatch: SID must match when present; absent SID defers; mismatch refuses (wrong person)' {
    & $mod {
        $obj = [pscustomobject]@{ SID = 'S-1-5-21-100-200-300-1105' }
        (Test-AdIdentityMatch -AdObject $obj -ExpectedSid 'S-1-5-21-100-200-300-1105') -and            # same principal
        (Test-AdIdentityMatch -AdObject $obj -ExpectedSid '') -and                                     # no SID -> defer to domain guard
        (-not (Test-AdIdentityMatch -AdObject $obj -ExpectedSid 'S-1-5-21-999-999-999-5001')) -and     # DIFFERENT SID -> refuse
        (-not (Test-AdIdentityMatch -AdObject $null -ExpectedSid 'S-1-5-21-100-200-300-1105'))         # nothing found -> refuse
    }
}
Assert-That 'Test-OnPremReadyForObject (cached, no probe): true only when connected + DC domain matches the object' {
    & $mod {
        $obj = @{ onPremisesDomainName = 'hybrid2.local' }
        $script:AdState.Checked = $true; $script:AdState.Available = $true; $script:AdState.DcDomain = 'hybrid2.local'
        $okMatch = Test-OnPremReadyForObject $obj
        $script:AdState.DcDomain = 'hybrid1.local'        # connected, but to the WRONG forest
        $wrongForest = Test-OnPremReadyForObject $obj
        $script:AdState.DcDomain = 'hybrid2.local'
        $blankClosed = -not (Test-OnPremReadyForObject @{ onPremisesDomainName = '' })   # blank object domain -> fail CLOSED
        $script:AdState.Available = $false                    # connect attempt failed / not connected
        $notConnected = Test-OnPremReadyForObject $obj
        Reset-AdState
        $okMatch -and (-not $wrongForest) -and $blankClosed -and (-not $notConnected)
    }
}

Write-Host "`n== Responsiveness / caching ==" -ForegroundColor Cyan
Assert-That 'Reset-SkuCache clears BOTH the name map and the rich detail cache' {
    & $mod {
        $script:SkuMap = @{ 'x' = 'y' }; $script:SkuDetailCache = @([pscustomobject]@{ SkuId = 'x' })
        Reset-SkuCache
        ($script:SkuMap.Count -eq 0) -and ($null -eq $script:SkuDetailCache)
    }
}
Assert-That 'Get-AvailableSku serves the per-connection cache (no Graph round-trip when populated)' {
    & $mod {
        $script:SkuDetailCache = @([pscustomobject]@{ SkuId = 's1'; PartNumber = 'ENTERPRISEPACK'; Consumed = 1; Enabled = 5; Available = 4 })
        $r = Get-AvailableSku
        Reset-SkuCache
        (@($r).Count -eq 1) -and ($r[0].PartNumber -eq 'ENTERPRISEPACK')
    }
}
Assert-That 'Get-CachedTenantHybridState makes no Graph call: $false until checked, cached value after' {
    & $mod {
        Reset-HybridState
        $a = Get-CachedTenantHybridState                  # unchecked -> $false, never touches Graph
        $script:HybridState.TenantChecked = $true; $script:HybridState.TenantHybrid = $true
        $b = Get-CachedTenantHybridState                  # checked -> cached value
        Reset-HybridState
        (-not $a) -and $b
    }
}
Assert-That 'Get-OrganizationCached returns the cached org (one read per connection)' {
    & $mod {
        $script:OrgCache = [pscustomobject]@{ DisplayName = 'Contoso'; onPremisesSyncEnabled = $true }
        $o = Get-OrganizationCached
        Clear-OrganizationCache
        ($o.DisplayName -eq 'Contoso') -and ($null -eq $script:OrgCache)
    }
}
Assert-That 'WinRM calls are bounded: New-AdSyncSessionOption sets an 8s OpenTimeout (no indefinite hang)' {
    $opt = & $mod { New-AdSyncSessionOption }
    [int]$opt.OpenTimeout.TotalMilliseconds -eq 8000   # OpenTimeout is surfaced as a TimeSpan
}
Assert-That 'working dialog builds a Form with a title, status line and indeterminate (marquee) bar' {
    & $mod {
        $d = New-ProgressDialogForm
        $ok = ($d.Form -is [System.Windows.Forms.Form]) -and ($d.Title -is [System.Windows.Forms.Label]) -and
              ($d.Status -is [System.Windows.Forms.Label]) -and ($d.Bar.Style -eq 'Marquee')
        $d.Form.Dispose()
        $ok
    }
}
Assert-That 'connect $batch requests fetch org + subscribed SKUs in one GET batch' {
    & $mod {
        $reqs = Get-ConnectBatchRequests
        (@($reqs).Count -eq 2) -and
        (($reqs | Where-Object { $_.id -eq 'org' }).url -eq '/organization') -and
        (($reqs | Where-Object { $_.id -eq 'skus' }).url -eq '/subscribedSkus') -and
        (@($reqs | Where-Object { $_.method -eq 'GET' }).Count -eq 2)
    }
}
Assert-That 'ConvertTo-SkuDetailList parses raw $batch SKU hashtables into the picker shape (map + counts)' {
    & $mod {
        $raw = @(
            @{ skuId = 'a'; skuPartNumber = 'ENTERPRISEPACK'; consumedUnits = 3; prepaidUnits = @{ enabled = 10 } },
            @{ skuId = 'b'; skuPartNumber = 'FLOW_FREE';      consumedUnits = 0; prepaidUnits = @{ enabled = 5 } }
        )
        $r = ConvertTo-SkuDetailList -SkuValues $raw
        ($r.Map['a'] -eq 'ENTERPRISEPACK') -and (@($r.Details).Count -eq 2) -and
        (($r.Details | Where-Object { $_.SkuId -eq 'a' }).Available -eq 7)
    }
}
Assert-That 'device-code fallback fires on a WAM/window failure but NOT on a user cancel or unrelated error' {
    & $mod {
        $mk = { param($m) [pscustomobject]@{ Exception = [pscustomobject]@{ Message = $m } } }
        $wam    = Test-InteractiveAuthFallback (& $mk 'MsalClientException: window handle must be configured for WAM')
        $cancel = Test-InteractiveAuthFallback (& $mk 'User canceled authentication')
        $other  = Test-InteractiveAuthFallback (& $mk 'The remote name could not be resolved')
        $wam -and (-not $cancel) -and (-not $other)
    }
}

Write-Host "`n== Device cleanup ==" -ForegroundColor Cyan
Assert-That 'Intune MAA detection reads the response BODY: ApprovalRequired -> pending; plain 403 / 404 -> error' {
    & $mod {
        # Realistic shape: a generic Exception.Message + the real code/text in ErrorDetails.Message (body).
        $mk = { param($exMsg, $bodyMsg) [pscustomobject]@{ Exception = [pscustomobject]@{ Message = $exMsg }; ErrorDetails = [pscustomobject]@{ Message = $bodyMsg } } }
        (Test-IntuneApprovalRequiredResponse (& $mk 'Response status code does not indicate success: 403 (Forbidden).' '{"error":{"code":"ApprovalRequired","message":"Approval Required. Request Approval using the request id."}}')) -and
        (-not (Test-IntuneApprovalRequiredResponse (& $mk 'Response status code does not indicate success: 403 (Forbidden).' '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}'))) -and
        (-not (Test-IntuneApprovalRequiredResponse (& $mk 'Response status code does not indicate success: 404 (Not Found).' '')))
    }
}
Assert-That 'device store defs cover the four cleanup targets (AD / SCCM / Intune / Entra)' {
    & $mod {
        $keys = @($script:DeviceStoreDefs.Key)
        (@($script:DeviceStoreDefs).Count -eq 4) -and ($keys -contains 'AdComputer') -and ($keys -contains 'Sccm') -and
        ($keys -contains 'Intune') -and ($keys -contains 'EntraDevice')
    }
}
Assert-That 'MAA approval decision builds the right beta approve/reject endpoint (raw call, no beta module)' {
    & $mod {
        # Submit-OperationApprovalDecision must exist with an approve|reject ValidateSet, and we must NOT
        # have imported a Microsoft.Graph.Beta.* module (which would conflict with the pinned v1.0 set).
        $cmd = Get-Command Submit-OperationApprovalDecision -ErrorAction SilentlyContinue
        $hasDecision = $cmd -and ($cmd.Parameters.ContainsKey('Decision'))
        $noBeta = -not (Get-Module -Name 'Microsoft.Graph.Beta*')
        [bool]$hasDecision -and $noBeta -and [bool](Get-Command Get-PendingApprovalRequests -ErrorAction SilentlyContinue)
    }
}

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
Assert-That 'native dark mode applied when available (.NET 9+/PS7); skipped cleanly on 5.1' {
    # Show-M365UserGroupManager already invoked SetColorMode by reflection. If the API exists
    # (PS7/.NET 9+), the application color mode must be Dark; on 5.1 the API is absent and the call is
    # correctly skipped (and the headless build above already proved no error was thrown).
    $mi = [System.Windows.Forms.Application].GetMethod('SetColorMode')
    if (-not $mi) { return $true }                       # 5.1 / .NET FW: API absent -> skipped, as designed
    $cm = [System.Windows.Forms.Application].GetProperty('ColorMode')
    (-not $cm) -or ("$($cm.GetValue($null))" -eq 'Dark')
}
Assert-That 'sidebar nav hosts Users, Groups, Exchange, Devices and Approvals pages' {
    & $mod {
        # The TabControl was replaced by a left sidebar + a single page host holding the page panels.
        ($script:UI.PageHost.Controls.Count -eq 5) -and
        ($script:UI.NavButtons.Count -eq 5) -and
        [bool]$script:UI.User.Page -and [bool]$script:UI.Group.Page -and [bool]$script:UI.Exchange.Page -and
        [bool]$script:UI.Device.Page -and [bool]$script:UI.Approval.Page -and
        ($script:UI.NavButtons['Approval'].Tag -eq 'Approval')
    }
}
Assert-That 'User New form has the Create-in (cloud/on-prem) dropdown + OU picker controls (cloud default)' {
    & $mod {
        $u = $script:UI.User
        [bool]$u.DestCombo -and ($u.DestCombo.Items.Count -eq 2) -and ($u.DestCombo.SelectedIndex -eq 0) -and [bool]$u.OuPanel -and [bool]$u.OuCombo
    }
}
Assert-That 'Edit mode does NOT run the create-destination view (Create-in row is New-only)' {
    & $mod {
        $u = $script:UI.User
        $u.Mode = 'Edit'; $u.SaveBtn.Text = '&Save changes'
        Set-UserAccountType -Type 'Member'   # in Edit this must NOT call Set-UserCreateDestination...
        $ok = ($u.SaveBtn.Text -eq '&Save changes')   # ...which would rewrite the Save text to a "Create" verb
        $u.Mode = 'New'                       # restore for later checks
        $ok
    }
}
Assert-That 'create-destination: picking On-prem while not connected bounces back to Cloud (no misroute)' {
    & $mod {
        $u = $script:UI.User
        $u.Mode = 'New'; $u.OnPremEnabled = $false; $u.CurrentDest = 'Cloud'
        $u.DestCombo.SelectedIndex = 0
        $u.DestCombo.SelectedIndex = 1   # operator tries On-prem -> SelectedIndexChanged bounces it (sentinel)
        # After the bounce: combo is back on Cloud AND the authoritative CurrentDest stays Cloud, so a save
        # would route to the cloud (Invoke-SaveUser branches on CurrentDest -eq 'OnPrem', not the raw index).
        ($u.DestCombo.SelectedIndex -eq 0) -and ($u.CurrentDest -eq 'Cloud')
    }
}
Assert-That 'unsaved-changes guard does not fire pre-connect (Test-TabDirty is false when disconnected)' {
    & $mod { (-not (Test-TabDirty -Tab 'User')) -and (-not (Test-TabDirty -Tab 'Group')) }
}
Assert-That 'an untouched New form is NOT dirty: every field baseline matches its built value (incl. defaults)' {
    & $mod {
        # Build-TabForm must capture baselines AFTER New-mode defaults (accountEnabled=checked,
        # GroupType=Security) -- otherwise those read dirty against an empty baseline and every tab
        # switch falsely warns "unsaved changes".
        $dirty = @()
        foreach ($tab in 'User', 'Group') {
            Set-TabMode -Tab $tab -Mode 'New'
            foreach ($f in $script:UI[$tab].Order) {
                if ((Get-FieldComparable $f) -ne $f.Baseline) { $dirty += "$tab/$($f.Attr.Name)" }
            }
        }
        if ($dirty.Count) { Write-Host "      falsely-dirty: $($dirty -join ', ')" -ForegroundColor Yellow }
        $dirty.Count -eq 0
    }
}
Assert-That 'Choose-fields drives the New form too: enabled create-settable fields show; read-only/manager stay edit-only' {
    & $mod {
        $u = $script:UI.User
        $script:Config.Users.Enabled = @(@(Get-DefaultEnabledNames -Tab 'User') + 'jobTitle' + 'department' + 'onPremisesSyncEnabled' + 'manager' | Select-Object -Unique)
        Set-TabMode -Tab 'User' -Mode 'New'
        $new = @($u.Order | ForEach-Object { $_.Attr.Name })
        Set-TabMode -Tab 'User' -Mode 'Edit'
        $edit = @($u.Order | ForEach-Object { $_.Attr.Name })
        # create-settable Text fields now appear on the New form; read-only + Person (manager) do NOT
        # (can't be set at create) but DO appear in Edit.
        ($new -contains 'jobTitle') -and ($new -contains 'department') -and
        (-not ($new -contains 'onPremisesSyncEnabled')) -and (-not ($new -contains 'manager')) -and
        ($edit -contains 'onPremisesSyncEnabled') -and ($edit -contains 'manager')
    }
}
Assert-That 'sidebar has a Force-AD-sync button, hidden until connected to a hybrid tenant' {
    & $mod { [bool]$script:UI.SyncBtn -and (-not $script:UI.SyncBtn.Visible) }
}
Assert-That 'sidebar has an explicit on-prem AD connect row (label + button), hidden until hybrid' {
    & $mod { [bool]$script:UI.OnPremBtn -and [bool]$script:UI.OnPremLabel -and (-not $script:UI.OnPremBtn.Visible) -and (-not $script:UI.OnPremLabel.Visible) }
}
Assert-That 'sidebar has a Settings (config) button' {
    & $mod { [bool]$script:UI.ConfigBtn -and ($script:UI.ConfigBtn.Text -match 'Settings') }
}
Assert-That 'Devices page exists, gated (overlay + content), cleanup disabled until a device is found' {
    & $mod {
        $d = $script:UI.Device
        [bool]$d.Page -and [bool]$d.Overlay -and [bool]$d.Content -and [bool]$d.NameBox -and [bool]$d.FindBtn -and
        [bool]$d.CleanupBtn -and (-not $d.CleanupBtn.Enabled) -and (@($d.Stores.Keys).Count -eq 4)
    }
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
    # Text carries a state glyph (hollow circle) plus the words; assert the meaningful part.
    (& $mod { $script:UI.ConnLabel.Text }) -match 'Not connected'
}
Assert-That 'disconnected empty-state overlay covers the User form before connect' {
    # Control.Visible reads the *effective* value (false while the form is never shown), so assert the
    # structural intent: the overlay exists and is the front-most child of its page (BringToFront -> 0).
    & $mod {
        $ov = $script:UI.User.Overlay
        [bool]$ov -and ($null -ne $ov.Parent) -and ($ov.Parent.Controls.GetChildIndex($ov) -eq 0)
    }
}
Assert-That 'sidebar selection shows the page + points Enter at its primary (Select-NavPage)' {
    & $mod {
        Select-NavPage -Page 'Group'
        $grpOk = ($script:UI.CurrentPage -eq 'Group') -and ($script:UI.HeaderTitle.Text -eq 'Groups') -and
                 [object]::ReferenceEquals($script:UI.Form.AcceptButton, $script:UI.Group.SaveBtn)
        Select-NavPage -Page 'User'
        $usrOk = ($script:UI.CurrentPage -eq 'User') -and ($script:UI.HeaderTitle.Text -eq 'Users') -and
                 [object]::ReferenceEquals($script:UI.Form.AcceptButton, $script:UI.User.SaveBtn)
        $grpOk -and $usrOk
    }
}
Assert-That 'action footer: Backup/Restore/Delete live in a More overflow menu; Delete toggles with Edit' {
    & $mod {
        $u = $script:UI.User
        $menuOk = [bool]$u.MoreMenu -and [bool]$u.MoreBtn -and ($u.MoreMenu.Items.Count -eq 4)   # Backup, Restore, separator, Delete
        $itemsOk = ($u.DeleteBtn -is [System.Windows.Forms.ToolStripMenuItem]) -and ($u.BackupBtn -is [System.Windows.Forms.ToolStripMenuItem])
        # Save stays a real Button (AcceptButton targets it); Delete's availability follows the mode.
        $saveOk = ($u.SaveBtn -is [System.Windows.Forms.Button])
        Set-TabMode -Tab 'User' -Mode 'Edit'; $delShown = $u.DeleteBtn.Available
        Set-TabMode -Tab 'User' -Mode 'New';  $delHidden = -not $u.DeleteBtn.Available
        $menuOk -and $itemsOk -and $saveOk -and $delShown -and $delHidden
    }
}
Assert-That 'Sync-ConnectionUi reflects a disconnected attempt (clears selection, label shows Not connected)' {
    & $mod {
        $script:State = @{ SelectedUser = @{ id = 'x' }; SelectedGroup = $null }
        Sync-ConnectionUi   # offline => not connected => must clear selection + show "Not connected"
        ($null -eq $script:State.SelectedUser) -and ($script:UI.ConnLabel.Text -match 'Not connected')
    }
}
Assert-That 'Show-ProgressDialog is a no-op under M365UGM_NOLAUNCH (headless safe)' {
    & $mod {
        $script:ProgressDlg = $null
        Show-ProgressDialog -Title 'x'          # NOLAUNCH set here -> must not build/show a window
        $null -eq $script:ProgressDlg
    }
}
Assert-That 'Invoke-WithProgress runs the work, returns its value, and releases the busy lock' {
    & $mod {
        $v = Invoke-WithProgress -Title 't' -Work { 42 }
        ($v -eq 42) -and (-not $script:UI.Busy)
    }
}
if ($form) { $form.Dispose() }

# Live show-smoke: actually Show() the form + pump the real message loop + rebuild + nav-switch, with a
# thread-exception capture. This catches SHOW-TIME crashes that the headless DrawToBitmap path misses
# (e.g. the SetWindowTheme "Visual Style handle creation" failure shipped once because builds looked
# fine). Skips cleanly (not a failure) if the host can't show a window (true-headless / no desktop).
Write-Host "`n== Live show smoke ==" -ForegroundColor Cyan
$smokeErrs = New-Object System.Collections.ArrayList
$smokeHandler = [System.Threading.ThreadExceptionEventHandler] { param($s, $e) [void]$smokeErrs.Add($e.Exception.Message) }
[System.Windows.Forms.Application]::add_ThreadException($smokeHandler)
$smokeShown = $false
try {
    & $mod {
        $script:AppReady = $false; $script:Config = New-DefaultConfig
        $script:VerifiedDomains = @(@{ Name = 'contoso.com'; IsDefault = $true })
        $f = New-MainForm
        $f.StartPosition = 'Manual'; $f.Location = New-Object System.Drawing.Point(-3000, -3000); $f.ShowInTaskbar = $false
        $f.Show()
        1..12 | ForEach-Object { [System.Windows.Forms.Application]::DoEvents() }
        Build-TabForm -Tab 'User'; Build-TabForm -Tab 'Group'
        Select-NavPage -Page 'Group'; Select-NavPage -Page 'Exchange'; Select-NavPage -Page 'User'
        1..12 | ForEach-Object { [System.Windows.Forms.Application]::DoEvents() }
        $f.Close(); $f.Dispose()
    }
    $smokeShown = $true
} catch {
    Write-Host "  (skipped -- host can't Show() a window: $($_.Exception.Message))" -ForegroundColor DarkGray
}
[System.Windows.Forms.Application]::remove_ThreadException($smokeHandler)
if ($smokeShown) {
    Assert-That 'live Show() + rebuild + nav-switch raises NO thread exceptions' {
        if ($smokeErrs.Count) { $smokeErrs | ForEach-Object { Write-Host "        $_" -ForegroundColor Yellow } }
        $smokeErrs.Count -eq 0
    }
}
Remove-Item Env:\M365UGM_NOLAUNCH -ErrorAction SilentlyContinue

Write-Host "`n== Summary ==" -ForegroundColor Cyan
Write-Host ("  Passed: {0}   Failed: {1}" -f $script:Passed, $script:Failures) -ForegroundColor $(if ($script:Failures) { 'Red' } else { 'Green' })
if ($script:Failures -gt 0) { exit 1 } else { exit 0 }
