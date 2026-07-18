BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\Claudit.psd1') -Force
}

Describe 'Claudit dashboard assets' {
    InModuleScope Claudit {
        It 'ships the configured logo and favicon' {
            Test-Path -LiteralPath (Join-Path $script:CaDashboardAssetRoot 'icons\logo\claudit-logo-96.png') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $script:CaDashboardAssetRoot 'icons\logo\favicon.png') | Should -BeTrue
        }

        It 'renders portable asset URLs in the cockpit HTML' {
            $html = Get-CaDashboardHtml -RequestToken ('a' * 64) -RetentionCount 100
            $html | Should -Match '/assets/icons/logo/favicon\.png'
            $html | Should -Match '/assets/icons/cloud/icons8-amazon-aws-50\.png'
            $html | Should -Match '/assets/icons/cloud/icons8-google-cloud-50\.png'
        }

        It 'confines asset resolution to the packaged asset root' {
            { Resolve-CaDashboardSafePath -Root $script:CaDashboardAssetRoot -RelativePath 'icons/logo/favicon.png' } | Should -Not -Throw
            { Resolve-CaDashboardSafePath -Root $script:CaDashboardAssetRoot -RelativePath '..\..\README.md' } | Should -Throw
        }
    }
}
