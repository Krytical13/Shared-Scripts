<#
    Pester 5 tests for the hybrid Source-of-Authority gating logic (Private/HybridDetection.ps1).
    Pure logic against synthetic objects -- no Graph / AD connection required.
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:ModuleRoot 'M365UserGroupManager.psd1') -Force
}

Describe 'Hybrid SOA gating (pure logic)' {

    It 'detects a synced object only when onPremisesSyncEnabled is exactly $true' {
        InModuleScope M365UserGroupManager {
            (Test-ObjectSynced @{ onPremisesSyncEnabled = $true })  | Should -BeTrue
            (Test-ObjectSynced @{ onPremisesSyncEnabled = $false }) | Should -BeFalse   # orphaned -> cloud
            (Test-ObjectSynced @{ onPremisesSyncEnabled = $null })  | Should -BeFalse   # cloud-only
            (Test-ObjectSynced @{})                                 | Should -BeFalse
            (Test-ObjectSynced $null)                               | Should -BeFalse
        }
    }

    It 'resolves authority: explicit wins, ReadOnly inputs default ReadOnly, else OnPrem' {
        InModuleScope M365UserGroupManager {
            (Resolve-FieldAuthority @{ Authority = 'Cloud'; Input = 'Text' }) | Should -Be 'Cloud'
            (Resolve-FieldAuthority @{ Input = 'ReadOnly' })                  | Should -Be 'ReadOnly'
            (Resolve-FieldAuthority @{ Input = 'Text'; Writable = $true })    | Should -Be 'OnPrem'
        }
    }

    It 'makes OnPrem fields non-cloud-editable for a synced object but editable for a cloud-only one' {
        InModuleScope M365UserGroupManager {
            $attr   = @{ Name = 'displayName'; Input = 'Text'; Writable = $true }   # defaults OnPrem
            $synced = @{ onPremisesSyncEnabled = $true }
            $cloud  = @{ onPremisesSyncEnabled = $null }
            (Test-FieldCloudEditable -Attr $attr -Object $synced) | Should -BeFalse
            (Test-FieldCloudEditable -Attr $attr -Object $cloud)  | Should -BeTrue
            (Test-FieldCloudEditable -Attr $attr -Object $null)   | Should -BeTrue   # New mode
        }
    }

    It 'keeps Cloud-authority fields editable even for a synced object' {
        InModuleScope M365UserGroupManager {
            $lic    = @{ Name = 'assignedLicenses'; Input = 'License'; Writable = $true; Authority = 'Cloud' }
            $synced = @{ onPremisesSyncEnabled = $true }
            (Test-FieldCloudEditable -Attr $lic -Object $synced) | Should -BeTrue
        }
    }

    It 'never makes ReadOnly or non-writable fields editable' {
        InModuleScope M365UserGroupManager {
            $synced = @{ onPremisesSyncEnabled = $true }
            (Test-FieldCloudEditable -Attr @{ Input = 'ReadOnly'; Writable = $false } -Object $null)   | Should -BeFalse
            (Test-FieldCloudEditable -Attr @{ Input = 'Text'; Writable = $false } -Object $synced)     | Should -BeFalse
        }
    }

    It 'labels the object source for the badge (ASCII only)' {
        InModuleScope M365UserGroupManager {
            (Get-ObjectSourceLabel $null)                                    | Should -Be 'New'
            (Get-ObjectSourceLabel @{ onPremisesSyncEnabled = $null })       | Should -Be 'Cloud'
            (Get-ObjectSourceLabel @{ onPremisesSyncEnabled = $true; onPremisesDomainName = 'corp.contoso.com' }) | Should -Be 'Synced from AD (corp.contoso.com)'
            $label = Get-ObjectSourceLabel @{ onPremisesSyncEnabled = $true }
            $label | Should -Be 'Synced from AD'
            # guard against mojibake: label must be plain ASCII
            ([regex]::IsMatch($label, '^[\x20-\x7E]+$')) | Should -BeTrue
        }
    }

    It 'Get-FieldHybridState flags OnPrem-mastered fields on synced objects with a hint' {
        InModuleScope M365UserGroupManager {
            $st = Get-FieldHybridState -Attr @{ Name = 'jobTitle'; Input = 'Text'; Writable = $true } -Object @{ onPremisesSyncEnabled = $true }
            $st.Synced         | Should -BeTrue
            $st.OnPremMastered | Should -BeTrue
            $st.CloudEditable  | Should -BeFalse
            $st.Hint           | Should -Not -BeNullOrEmpty

            $st2 = Get-FieldHybridState -Attr @{ Name = 'assignedLicenses'; Input = 'License'; Writable = $true; Authority = 'Cloud' } -Object @{ onPremisesSyncEnabled = $true }
            $st2.OnPremMastered | Should -BeFalse
            $st2.CloudEditable  | Should -BeTrue
        }
    }
}

Describe 'Catalog Authority metadata' {

    It 'only ever uses known Authority values' {
        InModuleScope M365UserGroupManager {
            $valid = 'Cloud', 'OnPrem', 'ReadOnly'
            foreach ($tab in 'User', 'Group') {
                foreach ($a in (Get-CatalogAttributeList -Tab $tab)) {
                    if ($a.Authority) { $valid | Should -Contain $a.Authority }
                }
            }
        }
    }

    It 'classifies the expected fields as Cloud-authoritative (editable even when synced)' {
        InModuleScope M365UserGroupManager {
            $cloudUser = @(Get-CatalogAttributeList -Tab 'User' |
                Where-Object { (Resolve-FieldAuthority $_) -eq 'Cloud' } | ForEach-Object { $_.Name })
            # licenses, usageLocation, userType, employeeHireDate stay cloud-writable for synced users
            $cloudUser | Should -Contain 'assignedLicenses'
            $cloudUser | Should -Contain 'usageLocation'
            $cloudUser | Should -Contain 'userType'
            # identity attrs + password + enable/disable go to AD when synced -> NOT cloud-authoritative
            $cloudUser | Should -Not -Contain 'displayName'
            $cloudUser | Should -Not -Contain 'jobTitle'
            $cloudUser | Should -Not -Contain 'accountEnabled'
            $cloudUser | Should -Not -Contain 'passwordProfile'
        }
    }
}

Describe 'On-prem AD attribute translation (pure)' {

    It 'maps cloud scalar attributes to the right AD LDAP names' {
        InModuleScope M365UserGroupManager {
            $m = Get-CloudToAdAttributeMap
            $m['jobTitle'] | Should -Be 'title'
            $m['surname']  | Should -Be 'sn'
            $m['city']     | Should -Be 'l'
            $m['state']    | Should -Be 'st'
            $m['country']  | Should -Be 'co'
            $m['officeLocation'] | Should -Be 'physicalDeliveryOfficeName'
            $m['extensionAttribute7'] | Should -Be 'extensionAttribute7'
        }
    }

    It 'builds Replace for values, Clear for empties, flags unsupported, takes first of a multi value' {
        InModuleScope M365UserGroupManager {
            $changes = @(
                @{ Name = 'jobTitle';       Value = 'Analyst' }
                @{ Name = 'department';     Value = '' }                       # empty -> Clear
                @{ Name = 'businessPhones'; Value = @('+1 555 0100', '+1 555 0199') }  # multi -> first
                @{ Name = 'otherMails';     Value = 'x@y.com' }               # unmapped -> Unsupported
            )
            $w = ConvertTo-AdAttributeWrites -Changes $changes
            $w.Replace['title']           | Should -Be 'Analyst'
            $w.Replace['telephoneNumber'] | Should -Be '+1 555 0100'
            $w.Clear        | Should -Contain 'department'
            $w.Unsupported  | Should -Contain 'otherMails'
            $w.Replace.ContainsKey('mail') | Should -BeFalse
        }
    }

    It 'uses a supplied map (groups) when given' {
        InModuleScope M365UserGroupManager {
            $gm = Get-CloudToAdGroupAttributeMap
            $w = ConvertTo-AdAttributeWrites -Changes @(@{ Name = 'description'; Value = 'Team' }) -Map $gm
            $w.Replace['description'] | Should -Be 'Team'
        }
    }

    It 'every on-prem-mastered USER scalar field has an AD mapping (only otherMails is knowingly unsupported)' {
        InModuleScope M365UserGroupManager {
            $map = Get-CloudToAdAttributeMap
            $unmapped = foreach ($a in (Get-CatalogAttributeList -Tab 'User')) {
                if ($a.Input -in 'Person', 'License', 'Password', 'Bool', 'ReadOnly', 'GroupType', 'Date') { continue }
                if ((Resolve-FieldAuthority $a) -ne 'OnPrem') { continue }
                if (-not $map.ContainsKey($a.Name)) { $a.Name }
            }
            @($unmapped | Where-Object { $_ -ne 'otherMails' }) | Should -BeNullOrEmpty
        }
    }
}
