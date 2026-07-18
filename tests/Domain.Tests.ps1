BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\Claudit.psd1') -Force
}

Describe 'Claudit DNS analyzers' {
    InModuleScope Claudit {
        It 'detects unsafe SPF mechanisms without network access' {
            $result = Get-CaSpfPolicyAnalysis -Records @('v=spf1 include:mail.example ptr +all')
            $result.Issues | Should -Contain 'permit_all'
            $result.Issues | Should -Contain 'ptr'
            $result.DirectDnsLookups | Should -Be 2
        }

        It 'detects multiple SPF records' {
            $result = Get-CaSpfPolicyAnalysis -Records @('v=spf1 -all', 'v=spf1 include:x.example -all')
            $result.Issues | Should -Contain 'multiple'
        }

        It 'parses DMARC policy and partial enforcement' {
            $result = Get-CaDmarcPolicyAnalysis -Records @('v=DMARC1; p=reject; pct=50')
            $result.Policy | Should -Be 'reject'
            $result.Percentage | Should -Be 50
            $result.Issues | Should -Contain 'partial_pct'
        }

        It 'classifies a dnsx dangling CNAME record' {
            $sample = '{"host":"app.example.com","status_code":"NOERROR","cname":["gone.vendor.example"]}'
            $rows = @(ConvertFrom-CaDnsxOutput -Text $sample)
            $rows.Count | Should -Be 1
            $rows[0].Status | Should -Be 'dangling_cname'
            $rows[0].CNAME | Should -Contain 'gone.vendor.example'
        }

        It 'preserves NXDOMAIN from the DoH response' {
            Clear-CaDnsQueryCache
            Mock Invoke-RestMethod { [pscustomobject]@{ Status = 3; AD = $false } }
            $query = Resolve-CaDnsQuery -Name 'missing.example' -Type SOA
            $query.Status | Should -Be 'NXDOMAIN'
            @($query.Records).Count | Should -Be 0
        }

        It 'keeps only the requested record type from a DoH answer chain' {
            Clear-CaDnsQueryCache
            Mock Invoke-RestMethod {
                [pscustomobject]@{
                    Status = 0
                    AD = $true
                    Answer = @(
                        [pscustomobject]@{ name = 'www.example.'; type = 5; TTL = 60; data = 'target.example.' }
                        [pscustomobject]@{ name = 'target.example.'; type = 1; TTL = 60; data = '192.0.2.10' }
                    )
                }
            }
            $query = Resolve-CaDnsQuery -Name 'www.example' -Type A
            @($query.Records).Count | Should -Be 1
            $query.Records[0].Data | Should -Be '192.0.2.10'
            $query.AuthenticatedData | Should -BeTrue
        }
    }
}

Describe 'Claudit DNS policy integration' {
    It 'loads the shipped baseline with the optional DNS policy' {
        { Get-CaBaseline -Force } | Should -Not -Throw
        (Get-CaBaseline).Domain.DnsxRateLimit | Should -Be 100
        (Get-CaBaseline).Domain.EnableDnsx | Should -BeFalse
    }

    It 'maps every new DNS check to at least one control' {
        foreach ($id in 9..16) {
            @(Get-CaControlIds -CheckId ('DOMAIN-{0:d3}' -f $id)).Count | Should -BeGreaterThan 0
        }
    }
}
