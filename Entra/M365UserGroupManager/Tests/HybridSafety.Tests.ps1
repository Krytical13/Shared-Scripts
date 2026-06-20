<#
    Pester 5 tests for the hybrid multi-tenant SAFETY guards (Private/OnPremAd.ps1, Configuration.ps1).
    Run:  Invoke-Pester -Path .\Tests   (requires Pester 5+)

    The scenario these protect against: a tech is signed into Hybrid tenant #2's cloud but the only
    reachable DC is the LOCAL tenant's (Hybrid1) -- e.g. on the office LAN with the other VPN down.
    Without the forest-pairing guard, an on-prem edit would target the WRONG forest. These mock the AD
    layer so the pure routing/guard logic is verified offline (no domain join / RSAT needed).
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:ModuleRoot 'M365UserGroupManager.psd1') -Force
}

Describe 'On-prem capability: forest-pairing guard' {

    BeforeEach {
        # Common: tenant is synced and RSAT is present; each test controls which DC is "reachable".
        InModuleScope M365UserGroupManager {
            Mock Get-TenantHybridState { $true }
            Mock Import-AdModule       { $true }
            Reset-AdState
        }
    }

    It 'REFUSES when the reachable DC is in a different forest than the tenant expects (the hazard)' {
        InModuleScope M365UserGroupManager {
            Mock Resolve-WritableDc { 'dc01.hybrid1.local' }   # wrong forest is what answers
            Mock Get-AdServerDomain { 'hybrid1.local' }
            $cap = Get-AdWriteCapability -ExpectedDomain 'hybrid2.local' -Force
            $cap.Available | Should -BeFalse
            $cap.Reason    | Should -Match 'hybrid2\.local'
            $cap.DcDomain  | Should -Be 'hybrid1.local'
        }
    }

    It 'ALLOWS when the reachable DC really is in the tenant''s expected forest' {
        InModuleScope M365UserGroupManager {
            Mock Resolve-WritableDc { 'dc01.hybrid2.local' }
            Mock Get-AdServerDomain { 'hybrid2.local' }
            $cap = Get-AdWriteCapability -ExpectedDomain 'hybrid2.local' -Force
            $cap.Available | Should -BeTrue
            $cap.Dc        | Should -Be 'dc01.hybrid2.local'
        }
    }

    It 'scopes DC discovery to the expected domain (passes -DomainName through)' {
        InModuleScope M365UserGroupManager {
            Mock Get-AdServerDomain { 'hybrid2.local' }
            Mock Resolve-WritableDc { 'dc01.hybrid2.local' }
            Get-AdWriteCapability -ExpectedDomain 'hybrid2.local' -Force | Out-Null
            Should -Invoke Resolve-WritableDc -Times 1 -ParameterFilter { $DomainName -eq 'hybrid2.local' }
        }
    }

    It 'reports "not reachable" when no DC for the expected domain answers (VPN down)' {
        InModuleScope M365UserGroupManager {
            Mock Resolve-WritableDc { $null }   # expected forest unreachable from here
            $cap = Get-AdWriteCapability -ExpectedDomain 'hybrid2.local' -Force
            $cap.Available | Should -BeFalse
            $cap.Reason    | Should -Match 'reachable'
        }
    }

    It 'recomputes when the expected domain changes (never reuses forest A''s capability for forest B)' {
        InModuleScope M365UserGroupManager {
            Mock Get-AdServerDomain { param($Dc) ($Dc -replace '^dc01\.', '') }
            Mock Resolve-WritableDc { param($DomainName) "dc01.$DomainName" }
            (Get-AdWriteCapability -ExpectedDomain 'hybrid1.local').Dc | Should -Be 'dc01.hybrid1.local'
            # switch tenants/objects -> different expected domain -> must re-resolve, not serve the cache
            (Get-AdWriteCapability -ExpectedDomain 'hybrid2.local').Dc     | Should -Be 'dc01.hybrid2.local'
            Should -Invoke Resolve-WritableDc -Times 2
        }
    }
}

Describe 'On-prem sidebar state machine (Get-OnPremUiState, cached -> no probe)' {

    BeforeEach {
        InModuleScope M365UserGroupManager {
            Mock Test-GraphConnected        { $true }
            Mock Get-CachedTenantHybridState { $true }
            Mock Get-ConnectedTenantOnPremDomain { 'hybrid2.local' }
            Reset-AdState
        }
    }

    It 'CloudOnly when the tenant is not hybrid (no on-prem row)' {
        InModuleScope M365UserGroupManager {
            Mock Get-CachedTenantHybridState { $false }
            (Get-OnPremUiState).State | Should -Be 'CloudOnly'
        }
    }
    It 'NotConnected for a hybrid tenant before the operator connects on-prem' {
        InModuleScope M365UserGroupManager { (Get-OnPremUiState).State | Should -Be 'NotConnected' }
    }
    It 'Connected after a verified connect' {
        InModuleScope M365UserGroupManager {
            $script:AdState.Checked = $true; $script:AdState.Available = $true
            $script:AdState.Dc = 'dc01.hybrid2.local'; $script:AdState.DcDomain = 'hybrid2.local'
            (Get-OnPremUiState).State | Should -Be 'Connected'
        }
    }
    It 'WrongNetwork when a DC answered but in a different forest (local LAN, other VPN down)' {
        InModuleScope M365UserGroupManager {
            $script:AdState.Checked = $true; $script:AdState.Available = $false
            $script:AdState.DcDomain = 'hybrid1.local'; $script:AdState.Reason = 'reachable DC is in hybrid1.local...'
            (Get-OnPremUiState).State | Should -Be 'WrongNetwork'
        }
    }
    It 'Unreachable when no DC for the expected domain answered' {
        InModuleScope M365UserGroupManager {
            $script:AdState.Checked = $true; $script:AdState.Available = $false
            $script:AdState.DcDomain = $null; $script:AdState.Reason = 'No writable domain controller ... is reachable ...'
            (Get-OnPremUiState).State | Should -Be 'Unreachable'
        }
    }
    It 'NoRsat when the RSAT module is missing' {
        InModuleScope M365UserGroupManager {
            $script:AdState.Checked = $true; $script:AdState.Available = $false
            $script:AdState.Reason = 'The ActiveDirectory (RSAT) module is not installed on this workstation.'
            (Get-OnPremUiState).State | Should -Be 'NoRsat'
        }
    }
}

Describe 'Per-tenant on-prem profile persistence' {

    It 'Set/Get round-trips by tenant id, with no cross-tenant bleed, and persists each change' {
        InModuleScope M365UserGroupManager {
            Mock Save-AppConfig { }   # keep the test off disk
            $script:Config = @{ Accounts = @() }
            Set-TenantProfileValue -Field 'ExpectedOnPremDomain' -Value 'hybrid1.local' -TenantId 'A'
            Set-TenantProfileValue -Field 'ConnectServer'        -Value 'adc-a'             -TenantId 'A'
            Set-TenantProfileValue -Field 'ExpectedOnPremDomain' -Value 'hybrid2.local'     -TenantId 'B'
            (Get-TenantProfileValue -Field 'ExpectedOnPremDomain' -TenantId 'A') | Should -Be 'hybrid1.local'
            (Get-TenantProfileValue -Field 'ExpectedOnPremDomain' -TenantId 'B') | Should -Be 'hybrid2.local'
            (Get-TenantProfileValue -Field 'ConnectServer' -TenantId 'B')        | Should -Be ''   # A's server doesn't bleed to B
            Should -Invoke Save-AppConfig -Times 3
        }
    }
}
