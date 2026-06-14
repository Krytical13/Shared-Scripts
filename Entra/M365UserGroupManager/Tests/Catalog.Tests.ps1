<#
    Pester 5 tests for the attribute catalog (the schema that drives the whole tool).
    Run:  Invoke-Pester -Path .\Tests   (requires Pester 5+)
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:ModuleRoot 'M365UserGroupManager.psd1') -Force
    $script:Catalog = InModuleScope M365UserGroupManager { $script:Catalog }
    $script:AllAttrs = @()
    foreach ($g in @($script:Catalog.User) + @($script:Catalog.Group)) { $script:AllAttrs += $g.Attributes }
}

Describe 'Attribute catalog' {

    It 'defines both User and Group tabs' {
        $script:Catalog.User | Should -Not -BeNullOrEmpty
        $script:Catalog.Group | Should -Not -BeNullOrEmpty
    }

    It 'gives every attribute a Name, Label and Input' {
        ($script:AllAttrs | Where-Object { -not $_.Name -or -not $_.Label -or -not $_.Input }) | Should -BeNullOrEmpty
    }

    It 'uses only known Input types' {
        $valid = 'Text', 'Multi', 'Bool', 'Choice', 'Date', 'Person', 'ReadOnly', 'Password', 'License', 'ExtAttr', 'GroupType'
        ($script:AllAttrs | Where-Object { $valid -notcontains $_.Input }) | Should -BeNullOrEmpty
    }

    It 'has exactly 15 extension attributes (extensionAttribute1..15)' {
        @($script:AllAttrs | Where-Object { $_.Input -eq 'ExtAttr' }).Count | Should -Be 15
    }

    It 'has unique attribute names within each tab' {
        foreach ($tab in 'User', 'Group') {
            $names = @($script:Catalog.$tab.Attributes | ForEach-Object { $_.Name })
            $names.Count | Should -Be (@($names | Select-Object -Unique).Count)
        }
    }

    It 'never marks a ReadOnly attribute as Writable' {
        ($script:AllAttrs | Where-Object { $_.Input -eq 'ReadOnly' -and $_.Writable }) | Should -BeNullOrEmpty
    }

    It 'gives every Person attribute a TargetType' {
        ($script:AllAttrs | Where-Object { $_.Input -eq 'Person' -and -not $_.TargetType }) | Should -BeNullOrEmpty
    }

    It 'gives every closed-set Choice either Choices or a ChoiceSource' {
        $bad = $script:AllAttrs | Where-Object { $_.Input -eq 'Choice' -and -not $_.Choices -and -not $_.ChoiceSource }
        $bad | Should -BeNullOrEmpty
    }

    It 'treats proxyAddresses as read-only (Graph cannot write it)' {
        $p = $script:Catalog.User.Attributes | Where-Object { $_.Name -eq 'proxyAddresses' }
        $p.Writable | Should -BeFalse
    }
}

Describe 'Exchange catalog' {
    BeforeAll {
        $script:Exo = InModuleScope M365UserGroupManager { $script:Catalog.Exchange }
        $script:ExoAttrs = @()
        foreach ($g in $script:Exo.Groups) { $script:ExoAttrs += $g.Attributes }
    }

    It 'defines the five Exchange object types with a backend each' {
        @($script:Exo.Types).Count | Should -Be 5
        ($script:Exo.Types | Where-Object { -not $_.Backend }) | Should -BeNullOrEmpty
    }

    It 'gives every Exchange attribute a Types list' {
        ($script:ExoAttrs | Where-Object { -not $_.Types }) | Should -BeNullOrEmpty
    }

    It 'every Exchange attribute Type references a real object type' {
        $keys = @($script:Exo.Types | ForEach-Object { $_.Key })
        $bad = $script:ExoAttrs | Where-Object { @($_.Types | Where-Object { $keys -notcontains $_ }).Count -gt 0 }
        $bad | Should -BeNullOrEmpty
    }

    It 'routes Exchange Person fields through the Exchange picker' {
        $people = $script:ExoAttrs | Where-Object { $_.Input -eq 'Person' }
        $people | Should -Not -BeNullOrEmpty
        ($people | Where-Object { $_.PickerSource -ne 'Exchange' }) | Should -BeNullOrEmpty
    }

    It 'gives distribution lists members + owners and mailboxes delegates' {
        $names = @($script:ExoAttrs | ForEach-Object { $_.Name })
        $names | Should -Contain 'members'
        $names | Should -Contain 'managedBy'
        $names | Should -Contain 'fullAccess'
        $names | Should -Contain 'sendAs'
    }
}
