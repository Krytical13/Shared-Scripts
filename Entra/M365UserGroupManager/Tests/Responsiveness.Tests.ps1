<#
    Pester 5 tests for the responsiveness / fewer-Graph-round-trips work.
    Run:  Invoke-Pester -Path .\Tests   (requires Pester 5+)

    These assert the INVARIANTS that keep the connect path fast: the connection label never triggers a
    Graph read, hybrid + verified-domains share ONE Get-MgOrganization call, the SKU list is fetched once
    and cached, and the per-tenant caches invalidate on reset. We stub the Graph cmdlets when the SDK
    isn't installed so the assertions run on any box (incl. the offline dev box).
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:ModuleRoot 'M365UserGroupManager.psd1') -Force

    # The module calls these Graph cmdlets by name; provide no-op stubs when the SDK isn't loaded so
    # Mock has a command to intercept (and Should -Invoke can count the calls).
    $script:StubbedGraph = @()
    foreach ($c in 'Get-MgOrganization', 'Get-MgSubscribedSku', 'Invoke-MgGraphRequest') {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) {
            New-Item -Path "function:global:$c" -Value { } -Force | Out-Null
            $script:StubbedGraph += $c
        }
    }
}

AfterAll {
    foreach ($c in $script:StubbedGraph) { Remove-Item "function:global:$c" -ErrorAction SilentlyContinue }
}

Describe 'Connection caching: fewer Graph round-trips' {

    It 'the connection label path (Get-CachedTenantHybridState) never calls Graph' {
        InModuleScope M365UserGroupManager {
            Mock Get-MgOrganization { throw 'the label must not read the org' }
            Reset-HybridState
            Get-CachedTenantHybridState | Should -BeFalse        # unchecked -> $false, no read
            $script:HybridState.TenantChecked = $true; $script:HybridState.TenantHybrid = $true
            Get-CachedTenantHybridState | Should -BeTrue          # cached value
            Should -Invoke Get-MgOrganization -Times 0
            Reset-HybridState
        }
    }

    It 'hybrid detection + verified domains share ONE Get-MgOrganization read (not two)' {
        InModuleScope M365UserGroupManager {
            Reset-HybridState
            $script:VerifiedDomains = @()
            Mock Get-MgOrganization {
                [pscustomobject]@{
                    onPremisesSyncEnabled = $true
                    VerifiedDomains       = @([pscustomobject]@{ Name = 'contoso.com'; IsDefault = $true })
                }
            }
            Get-TenantHybridState   | Should -BeTrue
            Initialize-VerifiedDomains
            Get-VerifiedDomainList  | Should -Contain 'contoso.com'
            Should -Invoke Get-MgOrganization -Times 1 -Exactly   # the merged single read
            Reset-HybridState
        }
    }

    It 'Get-TenantHybridState caches: a second call does not re-read the org' {
        InModuleScope M365UserGroupManager {
            Reset-HybridState
            Mock Get-MgOrganization { [pscustomobject]@{ onPremisesSyncEnabled = $false } }
            Get-TenantHybridState | Out-Null
            Get-TenantHybridState | Out-Null
            Should -Invoke Get-MgOrganization -Times 1 -Exactly
            Reset-HybridState
        }
    }

    It 'Reset-HybridState clears the org + hybrid cache so a tenant switch re-reads' {
        InModuleScope M365UserGroupManager {
            Mock Get-MgOrganization { [pscustomobject]@{ onPremisesSyncEnabled = $true } }
            Reset-HybridState
            Get-TenantHybridState | Should -BeTrue
            Reset-HybridState
            $script:OrgCache                  | Should -BeNullOrEmpty
            $script:HybridState.TenantChecked | Should -BeFalse
        }
    }
}

Describe 'License SKU caching: one fetch, reused' {

    It 'Get-AvailableSku serves the cache without calling Graph' {
        InModuleScope M365UserGroupManager {
            Mock Get-MgSubscribedSku { throw 'SKUs must come from the cache' }
            $script:SkuDetailCache = @([pscustomobject]@{ SkuId = 's'; PartNumber = 'X'; Consumed = 0; Enabled = 1; Available = 1 })
            (Get-AvailableSku)[0].PartNumber | Should -Be 'X'
            Should -Invoke Get-MgSubscribedSku -Times 0
            Reset-SkuCache
        }
    }

    It 'Initialize-SkuMap builds the name map AND the detail list in ONE pass' {
        InModuleScope M365UserGroupManager {
            Reset-SkuCache
            Mock Get-MgSubscribedSku {
                [pscustomobject]@{ SkuId = 's1'; SkuPartNumber = 'ENTERPRISEPACK'; ConsumedUnits = 2; PrepaidUnits = [pscustomobject]@{ Enabled = 10 } }
            }
            Initialize-SkuMap -Force
            $script:SkuMap['s1']              | Should -Be 'ENTERPRISEPACK'
            $script:SkuDetailCache[0].Available | Should -Be 8         # Enabled 10 - Consumed 2
            Should -Invoke Get-MgSubscribedSku -Times 1 -Exactly
            Reset-SkuCache
        }
    }
}

Describe 'Connect $batch bootstrap: org + SKUs in one round trip' {

    It 'seeds the org + SKU caches from a single $batch response' {
        InModuleScope M365UserGroupManager {
            Reset-HybridState; Reset-SkuCache
            Mock Invoke-MgGraphRequest {
                @{ responses = @(
                    @{ id = 'org';  status = 200; body = @{ value = @(@{ id = 't1'; displayName = 'Contoso'; onPremisesSyncEnabled = $true }) } },
                    @{ id = 'skus'; status = 200; body = @{ value = @(@{ skuId = 's1'; skuPartNumber = 'ENTERPRISEPACK'; consumedUnits = 2; prepaidUnits = @{ enabled = 10 } }) } }
                ) }
            }
            Initialize-ConnectionData
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly
            (Get-GraphVal $script:OrgCache 'onPremisesSyncEnabled') | Should -BeTrue
            $script:SkuMap['s1']                | Should -Be 'ENTERPRISEPACK'
            $script:SkuDetailCache[0].Available | Should -Be 8
            Reset-HybridState; Reset-SkuCache
        }
    }

    It 'after the batch, hybrid + SKU reads make NO further Graph call' {
        InModuleScope M365UserGroupManager {
            Reset-HybridState; Reset-SkuCache
            Mock Invoke-MgGraphRequest {
                @{ responses = @(
                    @{ id = 'org';  status = 200; body = @{ value = @(@{ onPremisesSyncEnabled = $true }) } },
                    @{ id = 'skus'; status = 200; body = @{ value = @(@{ skuId = 's1'; skuPartNumber = 'X'; consumedUnits = 0; prepaidUnits = @{ enabled = 1 } }) } }
                ) }
            }
            Mock Get-MgOrganization { throw 'must not be called after batch' }
            Mock Get-MgSubscribedSku { throw 'must not be called after batch' }
            Initialize-ConnectionData
            (Get-TenantHybridState) | Should -BeTrue
            Initialize-SkuMap                       # cache already seeded -> no-op
            (Get-AvailableSku)[0].PartNumber | Should -Be 'X'
            Should -Invoke Get-MgOrganization  -Times 0
            Should -Invoke Get-MgSubscribedSku -Times 0
            Reset-HybridState; Reset-SkuCache
        }
    }

    It 'falls back gracefully (no throw, caches empty) when $batch itself fails' {
        InModuleScope M365UserGroupManager {
            Reset-HybridState; Reset-SkuCache
            Mock Invoke-MgGraphRequest { throw 'batch endpoint unavailable' }
            { Initialize-ConnectionData } | Should -Not -Throw
            $script:OrgCache       | Should -BeNullOrEmpty
            $script:SkuDetailCache | Should -BeNullOrEmpty
            Reset-SkuCache
        }
    }

    It 'skips a non-200 sub-response (partial batch) without poisoning the cache' {
        InModuleScope M365UserGroupManager {
            Reset-HybridState; Reset-SkuCache
            Mock Invoke-MgGraphRequest {
                @{ responses = @(
                    @{ id = 'org';  status = 200; body = @{ value = @(@{ onPremisesSyncEnabled = $false }) } },
                    @{ id = 'skus'; status = 403; body = @{ error = @{ code = 'Forbidden' } } }
                ) }
            }
            Initialize-ConnectionData
            $script:OrgCache       | Should -Not -BeNullOrEmpty   # org seeded
            $script:SkuDetailCache | Should -BeNullOrEmpty        # 403 skus skipped -> left for fallback
            Reset-HybridState; Reset-SkuCache
        }
    }
}
