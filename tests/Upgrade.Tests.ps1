BeforeAll {
    $script:UpgradeRoot = Join-Path $PSScriptRoot '..'
    $script:MergeScript = Join-Path $script:UpgradeRoot 'service\Merge-ClauditBaseline.ps1'
}

Describe 'Claudit upgrade compatibility' {
    It 'keeps legacy policy values while adding new defaults' {
        $defaultPath = Join-Path $TestDrive 'default.json'
        $legacyPath = Join-Path $TestDrive 'legacy.json'
        $destinationPath = Join-Path $TestDrive 'merged.json'

        @{
            AWS = @{ Regions = @('eu-west-1'); RequireVpcFlowLogs = $true }
            Domain = @{ AuthorizedDomains = @(); RequireDnssec = $true }
            NewSection = @{ Enabled = $true }
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $defaultPath -Encoding UTF8
        @{
            AWS = @{ Regions = @('eu-central-1'); PrivateExtension = 'kept' }
            Domain = @{ AuthorizedDomains = @('example.test') }
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $legacyPath -Encoding UTF8

        & $script:MergeScript -DefaultPath $defaultPath -LegacyPath $legacyPath -DestinationPath $destinationPath
        $merged = Get-Content -LiteralPath $destinationPath -Raw -Encoding UTF8 | ConvertFrom-Json

        @($merged.AWS.Regions) | Should -Be @('eu-central-1')
        $merged.AWS.RequireVpcFlowLogs | Should -BeTrue
        $merged.AWS.PrivateExtension | Should -Be 'kept'
        @($merged.Domain.AuthorizedDomains) | Should -Be @('example.test')
        $merged.Domain.RequireDnssec | Should -BeTrue
        $merged.NewSection.Enabled | Should -BeTrue
    }

    It 'does not replace the destination when the legacy baseline is invalid' {
        $defaultPath = Join-Path $TestDrive 'valid-default.json'
        $legacyPath = Join-Path $TestDrive 'invalid-legacy.json'
        $destinationPath = Join-Path $TestDrive 'existing.json'
        '{"Section":{"Value":1}}' | Set-Content -LiteralPath $defaultPath -Encoding UTF8
        '{"Section":' | Set-Content -LiteralPath $legacyPath -Encoding UTF8
        'operator-data' | Set-Content -LiteralPath $destinationPath -Encoding UTF8

        { & $script:MergeScript -DefaultPath $defaultPath -LegacyPath $legacyPath -DestinationPath $destinationPath } |
            Should -Throw
        Get-Content -LiteralPath $destinationPath -Raw | Should -Match '^operator-data'
    }

    It 'orders backup and migration before destructive source replacement' {
        $installer = Get-Content -LiteralPath (Join-Path $script:UpgradeRoot 'install-ubuntu.sh') -Raw
        $backupIndex = $installer.IndexOf('legacy_baseline_backup=')
        $cleanupIndex = $installer.IndexOf('rm -rf -- "${install_root:?}/${directory}"')
        $mergeIndex = $installer.IndexOf('Merge-ClauditBaseline.ps1')

        $backupIndex | Should -BeGreaterThan -1
        $mergeIndex | Should -BeGreaterThan $backupIndex
        $cleanupIndex | Should -BeGreaterThan $backupIndex
        $cleanupIndex | Should -BeGreaterThan $mergeIndex
        $installer | Should -Match 'find -P "\$\{install_root\}/reports" -type f'
        $installer | Should -Match 'reports/legacy-pre-0\.3'
        $installer | Should -Match 'refusing symlinked persistent path'
    }
}
