BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\Claudit.psd1') -Force
}

Describe 'Claudit governed finding exceptions' {
    It 'suppresses one exact finding and preserves its original status' {
        InModuleScope Claudit {
            $finding = New-CaFinding -Service AWS -CheckId 'AWS-006' -Title 'Fixture' -Status Fail -Severity High -ResourceType bucket -ResourceId public-site
            $policyPath = Join-Path $TestDrive 'exceptions.json'
            @{
                SchemaVersion = '1.0'
                Rules = @(@{
                    RuleId='EXC-AWS-001'; Enabled=$true; CheckId='AWS-006'; FindingId=$finding.FindingId; AllowBroad=$false
                    Reason='Approved public site'; Owner='cloud-security'; Ticket='RISK-42'; ExpiresUtc='2030-01-01T00:00:00Z'
                })
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $policyPath

            $result = Resolve-CaFindingExceptions -Findings @($finding) -Path $policyPath -NowUtc ([datetimeoffset]'2026-07-21T10:00:00Z')

            $result.Findings[0].Status | Should -Be 'Fail'
            $result.Findings[0].IsSuppressed | Should -BeTrue
            $result.Findings[0].Suppression.RuleId | Should -Be 'EXC-AWS-001'
            $result.Policy.SuppressedFindingCount | Should -Be 1
            $finding.IsSuppressed | Should -BeFalse
            $finding.Suppression | Should -BeNullOrEmpty
        }
    }

    It 'does not suppress an expired rule or an execution error' {
        InModuleScope Claudit {
            $failure = New-CaFinding -Service AWS -CheckId 'AWS-006' -Title 'Failure' -Status Fail -Severity High
            $error = Invoke-CaCheck -Service AWS -CheckId 'AWS-006' -Title 'Error' -Body { throw 'access denied' }
            $policyPath = Join-Path $TestDrive 'expired.json'
            @{
                SchemaVersion = '1.0'
                Rules = @(@{
                    RuleId='EXC-AWS-OLD'; Enabled=$true; CheckId='AWS-006'; AllowBroad=$true
                    Reason='Expired acceptance'; Owner='cloud-security'; Ticket='RISK-1'; ExpiresUtc='2026-01-01T00:00:00Z'
                })
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $policyPath

            $result = Resolve-CaFindingExceptions -Findings @($failure, $error) -Path $policyPath -NowUtc ([datetimeoffset]'2026-07-21T10:00:00Z')

            @($result.Findings | Where-Object IsSuppressed).Count | Should -Be 0
            $result.Policy.ExpiredRuleCount | Should -Be 1
        }
    }

    It 'rejects broad rules without explicit authorization and governance fields' {
        InModuleScope Claudit {
            $policyPath = Join-Path $TestDrive 'invalid.json'
            @{ SchemaVersion='1.0'; Rules=@(@{ RuleId='EXC-BAD'; Enabled=$true; CheckId='AWS-006'; ExpiresUtc='2030-01-01T00:00:00Z' }) } |
                ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $policyPath

            { Import-CaExceptionPolicy -Path $policyPath } | Should -Throw '*AllowBroad=true*missing Reason*missing Owner*missing Ticket*'
        }
    }

    It 'fails closed when two active rules match one finding' {
        InModuleScope Claudit {
            $finding = New-CaFinding -Service AWS -CheckId 'AWS-006' -Title 'Fixture' -Status Fail -Severity High
            $policyPath = Join-Path $TestDrive 'ambiguous.json'
            $base = @{ Enabled=$true; CheckId='AWS-006'; AllowBroad=$true; Reason='Accepted'; Owner='cloud-security'; ExpiresUtc='2030-01-01T00:00:00Z' }
            @{ SchemaVersion='1.0'; Rules=@(
                ($base + @{ RuleId='EXC-ONE'; Ticket='RISK-1' })
                ($base + @{ RuleId='EXC-TWO'; Ticket='RISK-2' })
            ) } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $policyPath

            { Resolve-CaFindingExceptions -Findings @($finding) -Path $policyPath } | Should -Throw '*matches multiple exception rules*'
        }
    }

    It 'projects suppression consistently across report formats and OCSF' {
        $finding = New-CaFinding -Service AWS -CheckId 'AWS-006' -Title 'Public fixture' -Status Fail -Severity High -Detail 'Public by design.'
        $policyPath = Join-Path $TestDrive 'report-exceptions.json'
        @{
            SchemaVersion = '1.0'
            Rules = @(@{
                RuleId='EXC-REPORT-001'; Enabled=$true; CheckId='AWS-006'; FindingId=$finding.FindingId; AllowBroad=$false
                Reason='Accepted public endpoint'; Owner='cloud-security'; Ticket='RISK-99'; ExpiresUtc='2030-01-01T00:00:00Z'
            })
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $policyPath

        $report = $finding | New-CaReport -OutputDirectory $TestDrive -Format All -TenantName 'Fixture' -ExceptionPath $policyPath

        $report.Summary.Outcome | Should -Be 'Attention'
        $report.Summary.Fail | Should -Be 0
        $report.Summary.Suppressed | Should -Be 1
        $report.Problems.Count | Should -Be 0
        $report.SuppressedFindings.Count | Should -Be 1

        $jsonPath = $report.Files | Where-Object { $_ -like '*.json' -and $_ -notlike '*.catalog.json' -and $_ -notlike '*.oscal-ar.json' } | Select-Object -First 1
        $json = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        $json.Findings[0].Status | Should -Be 'Fail'
        $json.Findings[0].IsSuppressed | Should -BeTrue
        $json.ExceptionPolicy.Sha256 | Should -Match '^[0-9a-f]{64}$'
        (Test-Json -Json (Get-Content -LiteralPath $jsonPath -Raw) -SchemaFile (Join-Path $PSScriptRoot '..\schemas\claudit-report-v2.schema.json') -ErrorAction Stop) | Should -BeTrue

        $ocsfPath = $report.Files | Where-Object { $_ -like '*.ocsf.jsonl' } | Select-Object -First 1
        $ocsf = Get-Content -LiteralPath $ocsfPath -Raw | ConvertFrom-Json
        $ocsf.status_id | Should -Be 3
        $ocsf.status | Should -Be 'Suppressed'

        (Get-Content -LiteralPath ($report.Files | Where-Object { $_ -like '*.csv' }) -Raw) | Should -Match 'EXC-REPORT-001'
        (Get-Content -LiteralPath ($report.Files | Where-Object { $_ -like '*.md' }) -Raw) | Should -Match 'Suppressed findings'
        (Get-Content -LiteralPath ($report.Files | Where-Object { $_ -like '*.html' }) -Raw) | Should -Match 'Suppressed findings'
    }
}
