<#
    Pester 5 tests for config + the field factory's read / prefill / dirty / validation logic.
    These exercise pure logic against synthetic inputs -- no Graph connection required.
    Run:  Invoke-Pester -Path .\Tests   (requires Pester 5+)
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:ModuleRoot 'M365UserGroupManager.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
}

Describe 'Configuration' {

    It 'builds a default config with saved-accounts list and non-empty enabled sets' {
        InModuleScope M365UserGroupManager {
            $cfg = New-DefaultConfig
            $cfg.ContainsKey('Accounts') | Should -BeTrue   # defaults to an empty array
            $cfg.Users.Enabled.Count | Should -BeGreaterThan 0
            $cfg.Groups.Enabled.Count | Should -BeGreaterThan 0
        }
    }

    It 'returns enabled attribute objects in catalog order, filtered to the enabled set' {
        InModuleScope M365UserGroupManager {
            $script:Config = New-DefaultConfig
            $script:Config.Users.Enabled = @('givenName', 'displayName')   # deliberately out of catalog order
            $objs = Get-EnabledAttributeObjects -Tab 'User'
            @($objs).Count | Should -Be 2
            # displayName precedes givenName in the catalog, so it must come first regardless of config order.
            $objs[0].Name | Should -Be 'displayName'
            $objs[1].Name | Should -Be 'givenName'
        }
    }

    It 'round-trips through JSON' {
        InModuleScope M365UserGroupManager {
            $cfg = New-DefaultConfig
            $back = ($cfg | ConvertTo-Json -Depth 6) | ConvertFrom-Json
            @($back.Users.Enabled).Count | Should -Be @($cfg.Users.Enabled).Count
        }
    }
}

Describe 'Field factory: read / prefill / dirty' {

    It 'reads a prefilled Text field and detects edits' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'displayName'; Label = 'Display'; Input = 'Text'; Writable = $true } -Mode 'Edit' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            Set-FieldValue -Field $f -Value 'Jane Doe'
            Set-FieldBaseline -Field $f
            (Read-FieldValue $f) | Should -Be 'Jane Doe'
            (Test-FieldDirty $f) | Should -BeFalse
            $f.Main.Text = 'Jane Smith'
            (Test-FieldDirty $f) | Should -BeTrue
        }
    }

    It 'splits a Multi field into a string array, ignoring blank lines' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'otherMails'; Label = 'Other'; Input = 'Multi'; Writable = $true } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            $f.Main.Text = "a@x.com`r`n`r`nb@x.com"
            $v = Read-FieldValue $f
            @($v).Count | Should -Be 2
            $v[0] | Should -Be 'a@x.com'
        }
    }

    It 'uppercases a country code from an editable Choice' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'usageLocation'; Label = 'Usage'; Input = 'Choice'; ChoiceSource = 'Country'; Writable = $true } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            Set-FieldValue -Field $f -Value 'gb'
            (Read-FieldValue $f) | Should -Be 'GB'
        }
    }

    It 'reads only the checked SKU ids from a License field' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'assignedLicenses'; Label = 'Licenses'; Input = 'License'; Writable = $true } -Mode 'Edit' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            $skus = @(
                [pscustomobject]@{ SkuId = 's1'; PartNumber = 'E3'; Available = 1; Enabled = 5 }
                [pscustomobject]@{ SkuId = 's2'; PartNumber = 'E5'; Available = 0; Enabled = 2 }
            )
            Set-LicenseFieldItems -Field $f -Skus $skus -AssignedSkuIds @('s2')
            (Read-FieldValue $f) | Should -Be @('s2')
        }
    }

    It 'detects added/removed members on a multi Person field' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'members'; Label = 'Members'; Input = 'Person'; Writable = $true; Multi = $true; TargetType = 'Any' } -Mode 'Edit' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            Set-PersonFieldValue -Field $f -People @(@{ Id = 'a'; DisplayName = 'A' }, @{ Id = 'b'; DisplayName = 'B' })
            Set-FieldBaseline -Field $f
            (Test-FieldDirty $f) | Should -BeFalse
            # Simulate removing 'b'
            $f.People.RemoveAt(1); $f.Main.Items.RemoveAt(1)
            (Test-FieldDirty $f) | Should -BeTrue
        }
    }
}

Describe 'Field factory: relationship diff initialisation (regression)' {

    It 'initialises OriginalIds/OriginalSkuIds to empty arrays on a freshly-built field' {
        # Regression: an uninitialised property makes @($field.OriginalIds) become @($null)
        # (Count 1) instead of @() (Count 0), which corrupts the member/license add-remove diff
        # when a field is rebuilt without being re-loaded (e.g. after the Fields... dialog).
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $tt = New-Object System.Windows.Forms.ToolTip
            $person = New-FieldRow -Attr @{ Name = 'members'; Label = 'Members'; Input = 'Person'; Writable = $true; Multi = $true; TargetType = 'Any' } -Mode 'New' -Tlp $tlp -Tooltip $tt
            $license = New-FieldRow -Attr @{ Name = 'assignedLicenses'; Label = 'Licenses'; Input = 'License'; Writable = $true } -Mode 'New' -Tlp $tlp -Tooltip $tt
            @($person.OriginalIds).Count | Should -Be 0
            @($license.OriginalSkuIds).Count | Should -Be 0
        }
    }

    It 'computes an add-only diff when nothing was originally assigned' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'members'; Label = 'Members'; Input = 'Person'; Writable = $true; Multi = $true; TargetType = 'Any' } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            Set-PersonFieldValue -Field $f -People @(@{ Id = 'x'; DisplayName = 'X' })
            $now = @($f.People | ForEach-Object { $_.Id })
            $orig = @($f.OriginalIds)
            $add = @($now | Where-Object { $orig -notcontains $_ })
            $remove = @($orig | Where-Object { $now -notcontains $_ })
            $add | Should -Be @('x')
            @($remove).Count | Should -Be 0   # would be 1 (a null) if OriginalIds were uninitialised
        }
    }
}

Describe 'Field factory: validation' {

    It 'rejects a malformed UPN and accepts a valid one' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'userPrincipalName'; Label = 'UPN'; Input = 'Text'; Writable = $true; Required = $true } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            $f.Main.Text = 'nope'
            (Get-FieldValidationError -Field $f) | Should -Not -BeNullOrEmpty
            $f.Main.Text = 'jane@contoso.com'
            (Get-FieldValidationError -Field $f) | Should -BeNullOrEmpty
        }
    }

    It 'rejects spaces in a mail nickname' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'mailNickname'; Label = 'Nick'; Input = 'Text'; Writable = $true; Required = $true } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            $f.Main.Text = 'jane doe'
            (Get-FieldValidationError -Field $f) | Should -Not -BeNullOrEmpty
        }
    }

    It 'requires a 2-letter usage location when provided' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'usageLocation'; Label = 'Usage'; Input = 'Choice'; ChoiceSource = 'Country'; Writable = $true } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            $f.Main.Text = 'USA'
            (Get-FieldValidationError -Field $f) | Should -Not -BeNullOrEmpty
            $f.Main.Text = 'US'
            (Get-FieldValidationError -Field $f) | Should -BeNullOrEmpty
        }
    }

    It 'flags a required field left empty in New mode' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'displayName'; Label = 'Display'; Input = 'Text'; Writable = $true; Required = $true } -Mode 'New' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            (Get-FieldValidationError -Field $f) | Should -Not -BeNullOrEmpty
        }
    }

    It 'requires at least one owner for a distribution group' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $f = New-FieldRow -Attr @{ Name = 'managedBy'; Label = 'Owners'; Input = 'Person'; Writable = $true; Required = $true; Multi = $true; TargetType = 'User'; PickerSource = 'Exchange' } -Mode 'Edit' -Tlp $tlp -Tooltip (New-Object System.Windows.Forms.ToolTip)
            (Get-FieldValidationError -Field $f) | Should -Not -BeNullOrEmpty   # zero owners rejected even in Edit
            Set-PersonFieldValue -Field $f -People @(@{ Id = 'o@x.com'; DisplayName = 'O' })
            (Get-FieldValidationError -Field $f) | Should -BeNullOrEmpty
        }
    }
}

Describe 'Backup / restore (config snapshots)' {

    It 'builds a snapshot with the required metadata' {
        InModuleScope M365UserGroupManager {
            $snap = New-Snapshot -Tab 'User' -ObjectType 'User' -DisplayName 'Jane' -Fields @{ displayName = 'Jane' } -People @{}
            $snap.Tool | Should -Be 'M365UserGroupManager'
            $snap.SchemaVersion | Should -Be 1
            $snap.Tab | Should -Be 'User'
            $snap.Timestamp | Should -Not -BeNullOrEmpty
        }
    }

    It 'overlays a JSON-round-tripped snapshot onto form fields without touching baselines' {
        InModuleScope M365UserGroupManager {
            $tlp = New-Object System.Windows.Forms.TableLayoutPanel; $tlp.ColumnCount = 2
            $tt = New-Object System.Windows.Forms.ToolTip
            $fields = @{}
            $fields['displayName'] = New-FieldRow -Attr @{ Name = 'displayName'; Label = 'D'; Input = 'Text'; Writable = $true } -Mode 'New' -Tooltip $tt
            $fields['members'] = New-FieldRow -Attr @{ Name = 'members'; Label = 'M'; Input = 'Person'; Writable = $true; Multi = $true; TargetType = 'Any' } -Mode 'New' -Tooltip $tt
            $snap = New-Snapshot -Tab 'Group' -ObjectType 'Security' -DisplayName 'X' `
                -Fields @{ displayName = 'Hello' } `
                -People @{ members = @(@{ Id = 'a@x.com'; DisplayName = 'A'; Detail = 'a@x.com' }, @{ Id = 'b@x.com'; DisplayName = 'B'; Detail = 'b@x.com' }) }
            # Simulate writing + reading the file (PSCustomObject shape that Set-FieldFromSnapshot sees).
            $snapObj = $snap | ConvertTo-Json -Depth 8 | ConvertFrom-Json
            Set-FieldFromSnapshot -Fields $fields -Snapshot $snapObj
            (Read-FieldValue $fields['displayName']) | Should -Be 'Hello'
            @(Read-FieldValue $fields['members']) | Should -Be @('a@x.com', 'b@x.com')
        }
    }
}
