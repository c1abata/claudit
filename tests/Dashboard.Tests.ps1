BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\Claudit.psd1') -Force
}

Describe 'Claudit dashboard assets' {
    InModuleScope Claudit {
        It 'ships the configured logo and favicon' {
            Test-Path -LiteralPath (Join-Path $script:CaDashboardAssetRoot 'icons\logo\claudit-logo-96.png') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $script:CaDashboardAssetRoot 'icons\logo\favicon.png') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $script:CaDashboardAssetRoot 'dashboard.css') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $script:CaDashboardAssetRoot 'dashboard.js') | Should -BeTrue
        }

        It 'renders portable asset URLs in the cockpit HTML' {
            $html = Get-CaDashboardHtml -RequestToken ('a' * 64) -RetentionCount 100
            $javascript = Get-Content -LiteralPath (Join-Path $script:CaDashboardAssetRoot 'dashboard.js') -Raw
            $html | Should -Match '/assets/icons/logo/favicon\.png'
            $javascript | Should -Match '/assets/icons/cloud/icons8-amazon-aws-50\.png'
            $javascript | Should -Match '/assets/icons/cloud/icons8-google-cloud-50\.png'
            $html | Should -Match '/assets/dashboard\.css'
            $html | Should -Match '/assets/dashboard\.js'
            $html | Should -Not -Match '<style>'
            $html | Should -Not -Match '<script(?![^>]+src=)'
        }

        It 'uses DOM-safe dashboard rendering without HTML string sinks' {
            $scriptPath = Join-Path $script:CaDashboardAssetRoot 'dashboard.js'
            $javascript = Get-Content -LiteralPath $scriptPath -Raw
            $javascript | Should -Not -Match '\.innerHTML\s*='
            $javascript | Should -Not -Match '\.outerHTML\s*='
            $javascript | Should -Not -Match 'insertAdjacentHTML\s*\('
        }

        It 'serves dashboard assets with explicit web content types' {
            Get-CaDashboardContentType -Path 'dashboard.css' | Should -Be 'text/css; charset=utf-8'
            Get-CaDashboardContentType -Path 'dashboard.js' | Should -Be 'text/javascript; charset=utf-8'
        }

        It 'confines asset resolution to the packaged asset root' {
            { Resolve-CaDashboardSafePath -Root $script:CaDashboardAssetRoot -RelativePath 'icons/logo/favicon.png' } | Should -Not -Throw
            { Resolve-CaDashboardSafePath -Root $script:CaDashboardAssetRoot -RelativePath '..\..\README.md' } | Should -Throw
        }
    }
}
