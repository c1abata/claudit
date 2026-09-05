BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\Claudit.psd1') -Force
}

Describe 'Claudit check metadata catalog' {
    It 'resolves every production control exactly once' {
        $controls = @(Get-CaControlCatalog).Controls
        $catalog = Get-CaCheckMetadataCatalog
        $assigned = @($catalog.Assignments | ForEach-Object { @($_.CheckIds) })

        $assigned.Count | Should -Be $controls.Count
        @($assigned | Sort-Object -Unique).Count | Should -Be $controls.Count
        foreach ($checkId in $controls.CheckId) {
            (Get-CaCheckMetadata -CheckId $checkId).CheckId | Should -Be $checkId
        }
    }

    It 'applies narrow risk overrides without changing observed check behavior' {
        $metadata = Get-CaCheckMetadata -CheckId 'AWS-002'
        $finding = New-CaFinding -Service AWS -CheckId 'AWS-002' -Title 'Root MFA fixture' -Status Fail -Severity High

        $metadata.Profile | Should -Be 'identity-access'
        $metadata.DefaultSeverity | Should -Be 'Critical'
        $metadata.Threats | Should -Contain 'root-account-takeover'
        $finding.Severity | Should -Be 'High'
        $finding.DefaultSeverity | Should -Be 'Critical'
        $finding.Recommendation | Should -Match 'FIDO2'
    }

    It 'returns defensive copies and keeps uncataloged runtime IDs explicit' {
        $copy = Get-CaCheckMetadata -CheckId 'AWS-002'
        $copy.Categories[0] = 'tampered'

        (Get-CaCheckMetadata -CheckId 'AWS-002').Categories | Should -Not -Contain 'tampered'
        { Get-CaCheckMetadata -CheckId 'AWS-099' } | Should -Throw "*No check metadata*"
        $runtime = New-CaFinding -Service AWS -CheckId 'AWS-099' -Title 'Runtime fixture' -Status Error -Severity High
        $runtime.MetadataProfile | Should -Be 'runtime-unclassified'
        $runtime.MetadataSource | Should -Be 'runtime-fallback'
    }

    It 'projects metadata to governed artifacts and OCSF' {
        $finding = New-CaFinding -Service AWS -CheckId 'AWS-002' -Title 'Root MFA fixture' -Status Fail -Severity Critical
        $report = $finding | New-CaReport -OutputDirectory $TestDrive -Format All -TenantName 'Metadata fixture'

        $checksPath = $report.Files | Where-Object { $_ -like '*.checks.json' } | Select-Object -First 1
        $jsonPath = $report.Files | Where-Object { $_ -like '*.json' -and $_ -notlike '*.checks.json' -and $_ -notlike '*.catalog.json' -and $_ -notlike '*.oscal-ar.json' } | Select-Object -First 1
        $csvPath = $report.Files | Where-Object { $_ -like '*.csv' } | Select-Object -First 1
        $ocsfPath = $report.Files | Where-Object { $_ -like '*.ocsf.jsonl' } | Select-Object -First 1
        $manifestPath = $report.Files | Where-Object { $_ -like '*.sha256' } | Select-Object -First 1

        $checksPath | Should -Exist
        (Get-Content -LiteralPath $checksPath -Raw | ConvertFrom-Json).CatalogVersion | Should -Be '2026.07.0'
        $json = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        $json.CheckMetadataCatalog.Checks | Should -Be 88
        $json.Findings[0].Categories | Should -Contain 'identity-access'
        (Test-Json -Json (Get-Content -LiteralPath $jsonPath -Raw) -SchemaFile (Join-Path $PSScriptRoot '..\schemas\claudit-report-v2.schema.json') -ErrorAction Stop) | Should -BeTrue
        (Get-Content -LiteralPath $csvPath -Raw) | Should -Match 'MetadataCatalogVersion'

        $ocsf = Get-Content -LiteralPath $ocsfPath -Raw | ConvertFrom-Json
        $ocsf.finding_info.tags | Should -Contain 'category:identity-access'
        $ocsf.finding_info.tags | Should -Contain 'threat:root-account-takeover'
        $ocsf.unmapped.claudit.metadata_profile | Should -Be 'identity-access'
        (Get-Content -LiteralPath $manifestPath -Raw) | Should -Match ([regex]::Escape((Split-Path -Leaf $checksPath)))
    }
}
