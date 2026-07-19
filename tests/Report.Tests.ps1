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

        $json.SchemaVersion | Should -Be '1.0'
        @($json.Problems).Count | Should -Be 2
        @($json.ExecutionErrors).Count | Should -Be 1
        $html | Should -Match 'Problems detected'
        $html | Should -Match 'Execution errors blocking evaluation'
        $markdown | Should -Match '## Service coverage'
        $markdown | Should -Match '## Complete results'
    }
}
