BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\Claudit.psd1') -Force
}

Describe 'Claudit result collection and reporting' {
    It 'turns a thrown check into a structured blocking execution error' {
        $finding = Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-901' -Title 'Timeout probe' -Body {
            throw 'Provider request timed out after 3 seconds.'
        }

        $finding.Status | Should -Be 'Error'
        $finding.Outcome | Should -Be 'ExecutionError'
        $finding.IsBlocking | Should -BeTrue
        $finding.FailureCategory | Should -Be 'Timeout'
        $finding.DiagnosticId | Should -Match '^CA-\d{14}-[a-f0-9]{8}$'
        $finding.Recommendation | Should -Not -BeNullOrEmpty
    }

    It 'isolates a failed service collector and continues with the next service' {
        InModuleScope Claudit {
            Mock Get-CaDomainFindings {
                New-CaFinding -Service Domain -CheckId 'DOMAIN-900' -Title 'Collected before failure' -Status Pass
                throw 'collector exploded'
            }
            Mock Get-CaInventoryFindings {
                New-CaFinding -Service Inventory -CheckId 'INVENTORY-901' -Title 'Inventory survived' -Status Pass
            }

            $findings = @(Get-CaAllFindings -Service @('Domain', 'Inventory'))

            $findings.Count | Should -Be 3
            @($findings | Where-Object Service -eq 'Domain' | Where-Object Status -eq 'Pass').Count | Should -Be 1
            ($findings | Where-Object Service -eq 'Domain' | Where-Object Status -eq 'Error').CheckId | Should -Be 'DOMAIN-000'
            ($findings | Where-Object Service -eq 'Inventory').Status | Should -Be 'Pass'
        }
    }

    It 'builds an operator summary and separates problems from execution errors' {
        $findings = @(
            New-CaFinding -Service Domain -CheckId 'DOMAIN-911' -Title 'Healthy' -Status Pass
            New-CaFinding -Service Domain -CheckId 'DOMAIN-912' -Title 'Exposure' -Status Fail -Severity High -Recommendation 'Restrict exposure.'
            New-CaFinding -Service Domain -CheckId 'DOMAIN-913' -Title 'Manual review' -Status Investigate -Severity Low
            Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-914' -Title 'Permission gate' -Body { throw 'Access denied by provider permission.' }
            New-CaFinding -Service Domain -CheckId 'DOMAIN-915' -Title 'Optional control' -Status Skipped -SkippedReason 'Not enabled.'
        )

        $report = $findings | New-CaReport -OutputDirectory $TestDrive -Format All -TenantName 'Test tenant'

        $report.Summary.Outcome | Should -Be 'ExecutionError'
        $report.Summary.ProblemsDetected | Should -Be 2
        $report.Summary.BlockingErrors | Should -Be 1
        $report.Summary.NotEvaluated | Should -Be 2
        $report.Summary.CoveragePercent | Should -Be 60
        $report.Summary.RecommendedExitCode | Should -Be 3
        $report.Problems.Count | Should -Be 2
        $report.ExecutionErrors.Count | Should -Be 1

        $jsonPath = $report.Files | Where-Object { $_ -like '*.json' } | Select-Object -First 1
        $htmlPath = $report.Files | Where-Object { $_ -like '*.html' } | Select-Object -First 1
        $markdownPath = $report.Files | Where-Object { $_ -like '*.md' } | Select-Object -First 1
        $json = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        $html = Get-Content -LiteralPath $htmlPath -Raw
        $markdown = Get-Content -LiteralPath $markdownPath -Raw

        $json.SchemaVersion | Should -Be '2.0'
        $json.ReportId | Should -Match '^[0-9a-f-]{36}$'
        $json.Provenance.Producer.Version | Should -Be '0.3.1'
        $html | Should -Match 'Claudit 0\.3\.1'
        $json.Provenance.Baseline.Sha256 | Should -Match '^[0-9a-f]{64}$'
        @($json.Provenance.Completeness).Count | Should -Be 1
        @($json.Problems).Count | Should -Be 2
        @($json.ExecutionErrors).Count | Should -Be 1
        $html | Should -Match 'Problems detected'
        $html | Should -Match 'Execution errors blocking evaluation'
        $markdown | Should -Match '## Service coverage'
        $markdown | Should -Match '## Complete results'

        $schemaPath = Join-Path $PSScriptRoot '..\schemas\claudit-report-v2.schema.json'
        (Test-Json -Json (Get-Content -LiteralPath $jsonPath -Raw) -SchemaFile $schemaPath -ErrorAction Stop) | Should -BeTrue

        $ocsfPath = $report.Files | Where-Object { $_ -like '*.ocsf.jsonl' } | Select-Object -First 1
        $ocsfRows = @(Get-Content -LiteralPath $ocsfPath | ForEach-Object { $_ | ConvertFrom-Json })
        $ocsfRows.Count | Should -Be $findings.Count
        $ocsfRows[0].class_uid | Should -Be 2003
        $ocsfRows[0].type_uid | Should -Be 200301
        $ocsfRows[0].compliance.control | Should -Be $findings[0].CheckId
        $ocsfRows[0].compliance.status_id | Should -Be 1
        $ocsfRows[0].metadata.version | Should -Be '1.8.0'

        $oscalPath = $report.Files | Where-Object { $_ -like '*.oscal-ar.json' } | Select-Object -First 1
        $oscal = Get-Content -LiteralPath $oscalPath -Raw | ConvertFrom-Json
        $oscal.'assessment-results'.metadata.'oscal-version' | Should -Be '1.2.1'
        @($oscal.'assessment-results'.results[0].observations).Count | Should -Be $findings.Count
        @($oscal.'assessment-results'.results[0].findings).Count | Should -Be $findings.Count

        $catalogPath = $report.Files | Where-Object { $_ -like '*.catalog.json' } | Select-Object -First 1
        $catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json
        $catalog.CatalogVersion | Should -Be '2026.07.0'
        $catalog.FullFrameworkCoverage | Should -BeFalse

        $checksumPath = $report.Files | Where-Object { $_ -like '*.sha256' } | Select-Object -First 1
        $checksumLines = @(Get-Content -LiteralPath $checksumPath | Where-Object { $_ })
        $checksumLines.Count | Should -Be ($report.Files.Count - 1)
        foreach ($line in $checksumLines) {
            $line | Should -Match '^[0-9a-f]{64}  .+$'
        }
    }

    It 'fails closed when required checks are skipped' {
        InModuleScope Claudit {
            $finding = New-CaFinding -Service Domain -CheckId 'DOMAIN-916' -Title 'Required fixture' -Status Skipped -SkippedReason 'Provider denied access.'
            $summary = Get-CaSummary -Findings @($finding)

            $summary.Outcome | Should -Be 'Incomplete'
            $summary.CoveragePercent | Should -Be 0
            $summary.NotEvaluated | Should -Be 1
            $summary.RecommendedExitCode | Should -Be 3
            $finding.IsBlocking | Should -BeTrue
        }
    }

    It 'fails closed when the selected catalog scope omits expected control results' {
        $finding = New-CaFinding -Service AWS -CheckId 'AWS-001' -Title 'Partial fixture' -Status Pass -Detail 'Only one control returned.'

        $report = $finding | New-CaReport -OutputDirectory $TestDrive -Format Json -TenantName 'Partial fixture' `
            -ExpectedService AWS -ExpectedControlLevel Passive
        $missing = @($report.ExecutionErrors | Where-Object FailureCode -eq 'MissingControlResult')
        $awsCompleteness = @($report.Provenance.Completeness | Where-Object Service -eq 'AWS')[0]

        $report.Summary.Outcome | Should -Be 'ExecutionError'
        $report.Summary.RecommendedExitCode | Should -Be 3
        $report.Summary.CoveragePercent | Should -Be 9.1
        $missing.Count | Should -Be 10
        $awsCompleteness.Expected | Should -Be 11
        $awsCompleteness.Returned | Should -Be 1
        @($awsCompleteness.MissingControls).Count | Should -Be 10
        $awsCompleteness.Complete | Should -BeFalse
    }

    It 'applies cumulative Formal Passive and Active catalog levels' {
        InModuleScope Claudit {
            @(Get-CaExpectedCheckIds -Service Domain -ControlLevel Formal).Count | Should -Be 13
            @(Get-CaExpectedCheckIds -Service Domain -ControlLevel Passive).Count | Should -Be 15
            @(Get-CaExpectedCheckIds -Service Domain -ControlLevel Active).Count | Should -Be 16
            @(Get-CaExpectedCheckIds -Service VPS -ControlLevel Passive).Count | Should -Be 6
            @(Get-CaExpectedCheckIds -Service VPS -ControlLevel Active).Count | Should -Be 7
        }
    }

    It 'maps Claudit outcomes to OCSF compliance status without false pass' {
        InModuleScope Claudit {
            $expected = @{
                Pass=@(1, 'Pass'); Fail=@(3, 'Fail'); Warning=@(2, 'Warning')
                Investigate=@(2, 'Warning'); Error=@(0, 'Unknown')
                Skipped=@(0, 'Unknown'); NotApplicable=@(99, 'NotApplicable')
                Info=@(99, 'Other')
            }
            foreach ($status in $expected.Keys) {
                $mapped = Get-CaOcsfComplianceStatus -Status $status
                $mapped.Id | Should -Be $expected[$status][0]
                $mapped.Name | Should -Be $expected[$status][1]
            }
        }
    }

    It 'excludes positively non-applicable checks from the coverage denominator' {
        InModuleScope Claudit {
            $findings = @(
                New-CaFinding -Service Domain -CheckId 'DOMAIN-917' -Title 'Healthy fixture' -Status Pass
                New-CaFinding -Service Domain -CheckId 'DOMAIN-918' -Title 'Not applicable fixture' -Status NotApplicable
            )
            $summary = Get-CaSummary -Findings $findings

            $summary.Outcome | Should -Be 'Pass'
            $summary.Applicable | Should -Be 1
            $summary.NotApplicable | Should -Be 1
            $summary.CoveragePercent | Should -Be 100
        }
    }

    It 'never sends a green notification for incomplete evaluation' {
        InModuleScope Claudit {
            Mock Invoke-RestMethod {}
            $summary = [pscustomobject]@{
                Outcome='ExecutionError'; CoveragePercent=0; Total=1; Pass=0; Fail=0
                Error=1; Skipped=0; BlockingErrors=1; Critical=0; High=0
            }

            Send-CaNotification -WebhookUrl 'https://fixture.invalid/hook' -Summary $summary -Type Slack

            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Body -match 'incomplete' -and $Body -match 'Errors 1' -and $Body -notmatch '✅'
            }
        }
    }

    It 'classifies allowed malformed JSON as an explicit adapter failure' {
        InModuleScope Claudit {
            Mock Invoke-CaExternalCommand { [pscustomobject]@{ Success=$true; State='Ok'; ExitCode=0; Text='not-json' } }
            $result = Invoke-CaExternalJson -Command fixture -Arguments @('list') -AllowFailure

            $result.Success | Should -BeFalse
            $result.State | Should -Be 'Malformed'
            $result.Json | Should -BeNullOrEmpty
        }
    }

    It 'builds stable resource-scoped finding identities without exposing them in the key' {
        $one = New-CaFinding -Service AWS -CheckId 'AWS-099' -Title 'Fixture' -Status Fail -ResourceType 'bucket' -ResourceId 'sensitive-name' -ScopeId 'account-1'
        $same = New-CaFinding -Service AWS -CheckId 'AWS-099' -Title 'Renamed title' -Status Pass -ResourceType 'bucket' -ResourceId 'sensitive-name' -ScopeId 'account-1'
        $other = New-CaFinding -Service AWS -CheckId 'AWS-099' -Title 'Fixture' -Status Fail -ResourceType 'bucket' -ResourceId 'other-name' -ScopeId 'account-1'

        $one.FindingId | Should -BeExactly $same.FindingId
        $one.FindingId | Should -Not -Be $other.FindingId
        $one.FindingId | Should -Match '^claudit:[0-9a-f]{64}$'
        $one.FindingId | Should -Not -Match 'sensitive-name|account-1'
    }

    It 'compares a schema v1 report with v2 using compatible stable identities' {
        $v1Path = Join-Path $TestDrive 'v1.json'
        $v2Path = Join-Path $TestDrive 'v2.json'
        $legacyFinding = [pscustomobject]@{ Service='Domain'; CheckId='DOMAIN-099'; Title='Fixture'; Status='Pass'; Severity='Info' }
        [pscustomobject]@{ SchemaVersion='1.0'; Findings=@($legacyFinding) } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $v1Path
        $currentFinding = New-CaFinding -Service Domain -CheckId 'DOMAIN-099' -Title 'Fixture' -Status Fail -Severity High
        [pscustomobject]@{ SchemaVersion='2.0'; Findings=@($currentFinding) } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $v2Path

        $drift = @(Compare-ClauditResult -ReferencePath $v1Path -DifferencePath $v2Path)

        $drift.Count | Should -Be 1
        $drift[0].CheckId | Should -Be 'DOMAIN-099'
        $drift[0].Change | Should -Be 'Regressed'
        $drift[0].FindingId | Should -Be $currentFinding.FindingId
    }

    It 'detects evidence drift even when aggregate status is unchanged' {
        $referencePath = Join-Path $TestDrive 'evidence-old.json'
        $differencePath = Join-Path $TestDrive 'evidence-new.json'
        $old = New-CaFinding -Service AWS -CheckId 'AWS-098' -Title 'Aggregate fixture' -Status Fail -Severity High -Evidence @{ Missing=@('vpc-a') }
        $new = New-CaFinding -Service AWS -CheckId 'AWS-098' -Title 'Aggregate fixture' -Status Fail -Severity High -Evidence @{ Missing=@('vpc-b') }
        [pscustomobject]@{ SchemaVersion='2.0'; Findings=@($old) } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $referencePath
        [pscustomobject]@{ SchemaVersion='2.0'; Findings=@($new) } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $differencePath

        $drift = @(Compare-ClauditResult -ReferencePath $referencePath -DifferencePath $differencePath)

        $drift.Count | Should -Be 1
        $drift[0].Change | Should -Be 'EvidenceChanged'
        $drift[0].OldEvidenceHash | Should -Not -Be $drift[0].NewEvidenceHash
    }

    It 'loads one versioned catalog that maps every production check ID' {
        $catalog = Get-CaControlCatalog
        $catalog.GeneratedFrom | Should -Be 'config/control-catalog.json'
        $catalog.CatalogVersion | Should -Be '2026.07.0'
        $catalogIds = @($catalog.Controls.CheckId | Sort-Object -Unique)
        $sourceIds = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '..\src\Checks') -Filter '*.ps1' -File |
            ForEach-Object { [regex]::Matches((Get-Content -LiteralPath $_.FullName -Raw), "'[A-Z]+-\d{3}'") } |
            ForEach-Object { $_.Value.Trim("'") } | Sort-Object -Unique)

        $unmapped = @($sourceIds | Where-Object { $catalogIds -notcontains $_ })
        $unmapped | Should -BeNullOrEmpty
        $catalogIds.Count | Should -Be $catalog.Controls.Count
    }

    It 'drops non-HTTPS external references before rendering' {
        (New-CaFinding -Service Domain -CheckId 'DOMAIN-097' -Title 'Unsafe link' -Status Warning -Reference 'javascript:alert(1)').Reference | Should -BeNullOrEmpty
        (New-CaFinding -Service Domain -CheckId 'DOMAIN-097' -Title 'Safe link' -Status Warning -Reference 'https://example.com/reference').Reference | Should -Be 'https://example.com/reference'
    }
}
