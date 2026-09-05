<#
    Domain.ps1 - passive public-domain exposure checks.

    This service only inspects domains explicitly supplied by the operator.
    It performs DNS lookups; it does not brute-force, crawl, authenticate or
    touch target services.
#>

function Get-CaDomainPolicyValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        $Default
    )

    $baseline = Get-CaBaseline
    if ($baseline.PSObject.Properties.Name -contains 'Domain' -and
        $baseline.Domain.PSObject.Properties.Name -contains $Name -and
        $null -ne $baseline.Domain.$Name) {
        return $baseline.Domain.$Name
    }
    return $Default
}

function Get-CaSpfPolicyAnalysis {
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Records = @())

    $spf = @($Records | Where-Object { $_ -match '(?i)^v=spf1\b' })
    $issues = [System.Collections.Generic.List[string]]::new()
    if ($spf.Count -eq 0) { $issues.Add('missing') }
    if ($spf.Count -gt 1) { $issues.Add('multiple') }
    $lookupCount = 0
    if ($spf.Count -eq 1) {
        $tokens = @($spf[0].ToLowerInvariant() -split '\s+' | Where-Object { $_ })
        foreach ($token in $tokens) {
            $mechanism = $token.TrimStart('+', '-', '~', '?')
            if ($mechanism -match '^(include:|a(?::|/|$)|mx(?::|/|$)|ptr(?::|$)|exists:)') { $lookupCount++ }
            if ($mechanism -match '^redirect=') { $lookupCount++ }
        }
        if ($tokens | Where-Object { $_ -match '^\+?all$' }) { $issues.Add('permit_all') }
        if ($tokens | Where-Object { $_.TrimStart('+', '-', '~', '?') -match '^ptr(?::|$)' }) { $issues.Add('ptr') }
        if ($lookupCount -gt 10) { $issues.Add('lookup_limit') }
    }
    [pscustomobject]@{ Records = $spf; Issues = @($issues); DirectDnsLookups = $lookupCount }
}

function Get-CaDmarcPolicyAnalysis {
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Records = @())

    $dmarc = @($Records | Where-Object { $_ -match '(?i)^v=DMARC1\b' })
    $issues = [System.Collections.Generic.List[string]]::new()
    $policy = ''
    $percentage = 100
    if ($dmarc.Count -eq 0) { $issues.Add('missing') }
    elseif ($dmarc.Count -gt 1) { $issues.Add('multiple') }
    else {
        if ($dmarc[0] -match '(?i)(?:^|;)\s*p\s*=\s*([^;\s]+)') { $policy = $Matches[1].ToLowerInvariant() }
        if ($policy -notin @('none', 'quarantine', 'reject')) { $issues.Add('invalid_policy') }
        if ($dmarc[0] -match '(?i)(?:^|;)\s*pct\s*=\s*([^;\s]+)') {
            if (-not [int]::TryParse($Matches[1], [ref]$percentage) -or $percentage -lt 0 -or $percentage -gt 100) {
                $issues.Add('invalid_pct')
            }
            elseif ($percentage -lt 100) { $issues.Add('partial_pct') }
        }
    }
    [pscustomobject]@{ Records = $dmarc; Issues = @($issues); Policy = $policy; Percentage = $percentage }
}

function ConvertTo-CaDomainNameList {
    param($Value)

    $domains = [System.Collections.Generic.List[string]]::new()
    foreach ($raw in @(ConvertTo-CaStringList $Value)) {
        $domain = $raw.Trim().TrimEnd('.').ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($domain)) { continue }
        if ($domain -match '[:/\\*?]' -or $domain -notmatch '^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') {
            throw "Invalid authorized domain '$raw'. Use plain FQDNs only, for example contoso.com."
        }
        if (-not $domains.Contains($domain)) { $domains.Add($domain) }
    }
    return @($domains)
}

function Get-CaAuthorizedDomains {
    $options = Get-CaProviderOption -Provider Domain
    $domains = @(ConvertTo-CaDomainNameList $options.Domains)
    if ($domains.Count -gt 0) { return $domains }

    $baseline = Get-CaBaseline
    if ($baseline.PSObject.Properties.Name -contains 'Domain') {
        return @(ConvertTo-CaDomainNameList $baseline.Domain.AuthorizedDomains)
    }
    return @()
}

function Get-CaDomainSubdomains {
    $options = Get-CaProviderOption -Provider Domain
    $subs = @(ConvertTo-CaStringList $options.Subdomains | ForEach-Object {
        $_.Trim().TrimEnd('.').ToLowerInvariant()
    } | Where-Object { $_ -match '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$' })
    if ($subs.Count -gt 0) { return $subs }

    $baseline = Get-CaBaseline
    if ($baseline.PSObject.Properties.Name -contains 'Domain') {
        return @(ConvertTo-CaStringList $baseline.Domain.Subdomains)
    }
    return @('www', 'autodiscover', 'mail', 'vpn', 'portal', 'admin', 'dev', 'staging')
}

function Get-CaDomainFindings {
    [CmdletBinding()]
    param()

    try { $domains = @(Get-CaAuthorizedDomains) }
    catch {
        return New-CaFinding -Service Domain -CheckId 'DOMAIN-001' -Title 'Authorized domain scope is valid' -ControlLevel Formal `
            -Status Error -Severity High -Detail $_.Exception.Message `
            -Recommendation 'Pass only pre-authorized plain domain names with -Domain, never URLs, wildcards or unapproved targets.'
    }

    if ($domains.Count -eq 0) {
        return New-CaFinding -Service Domain -CheckId 'DOMAIN-001' -Title 'Authorized domain scope is declared' -ControlLevel Formal `
            -Status Error -Severity High `
            -Detail 'No authorized domains supplied. Domain audit intentionally refuses implicit targets.' `
            -Recommendation 'Run with -Service Domain -Domain example.com or add Domain.AuthorizedDomains to a private baseline.'
    }

    Test-CaDomainScope -Domains $domains
    Test-CaDomainDnsHealth -Domains $domains
    Test-CaDomainNameServers -Domains $domains
    Test-CaDomainSoa -Domains $domains
    Test-CaDomainDnssec -Domains $domains
    Test-CaDomainMailExchange -Domains $domains
    Test-CaDomainSpf -Domains $domains
    Test-CaDomainSpfRfc -Domains $domains
    Test-CaDomainDmarc -Domains $domains
    Test-CaDomainDmarcRfc -Domains $domains
    Test-CaDomainCaa -Domains $domains
    Test-CaDomainDkim -Domains $domains
    Test-CaDomainMailTransportSecurity -Domains $domains
    Test-CaDomainDanglingCname -Domains $domains
    Test-CaDomainDnsx -Domains $domains
}

function Test-CaDomainScope {
    param([Parameter(Mandatory)][string[]]$Domains)

    New-CaFinding -Service Domain -CheckId 'DOMAIN-001' -Title 'Authorized domain scope is declared' -ControlLevel Formal `
        -Status Pass -Detail "Domain audit limited to $($Domains.Count) authorized domain(s): $($Domains -join ', ')." `
        -Evidence @{ Domains = $Domains }
}

function Test-CaDomainDnsHealth {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-009' -Title 'DNS zones answer with a valid response code' -ControlLevel Formal -Body {
        $bad = [System.Collections.Generic.List[object]]::new()
        $evidence = [ordered]@{}
        foreach ($domain in $Domains) {
            $query = Resolve-CaDnsQuery -Name $domain -Type SOA
            $evidence[$domain] = @{ Status = $query.Status; Resolver = $query.Resolver; Error = $query.Error }
            if ($query.Status -ne 'NOERROR') { $bad.Add([pscustomobject]@{ Domain = $domain; Status = $query.Status }) }
        }
        if ($bad.Count -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-009' -Title 'DNS zones answer with a valid response code' -ControlLevel Formal `
                -Status Pass -Detail 'All authorized domains returned NOERROR for the SOA query.' -Evidence $evidence
        }
        else {
            $detail = @($bad | ForEach-Object { "$($_.Domain)=$($_.Status)" }) -join ', '
            New-CaFinding -Service Domain -CheckId 'DOMAIN-009' -Title 'DNS zones answer with a valid response code' -ControlLevel Formal `
                -Status Fail -Severity High -Detail "Unhealthy DNS response codes: $detail." `
                -Recommendation 'Check registration, delegation and authoritative DNS availability. SERVFAIL can indicate a broken DNSSEC chain.' -Evidence $evidence
        }
    }
}

function Test-CaDomainSoa {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-010' -Title 'SOA records are present and structurally valid' -ControlLevel Formal -Body {
        $bad = [System.Collections.Generic.List[string]]::new()
        $warnings = [System.Collections.Generic.List[string]]::new()
        $evidence = [ordered]@{}
        foreach ($domain in $Domains) {
            $soa = @(Resolve-CaDnsRecord -Name $domain -Type SOA | ForEach-Object { $_.Data })
            $evidence[$domain] = $soa
            if ($soa.Count -eq 0) { $bad.Add("$domain (missing)"); continue }
            $parts = @($soa[0] -split '\s+' | Where-Object { $_ })
            if ($parts.Count -lt 7) { $bad.Add("$domain (malformed)"); continue }
            $timers = [System.Collections.Generic.List[long]]::new()
            $numeric = $true
            foreach ($value in $parts[2..6]) {
                $parsed = 0L
                if (-not [long]::TryParse($value, [ref]$parsed)) { $numeric = $false; break }
                $timers.Add($parsed)
            }
            if (-not $numeric) { $bad.Add("$domain (non-numeric timers)"); continue }
            $refresh = $timers[1]; $retry = $timers[2]; $expire = $timers[3]; $minimum = $timers[4]
            if ($expire -lt ($refresh + $retry) -or $expire -lt 1209600) { $warnings.Add("$domain (low expire)") }
            if ($refresh -lt $retry -or $minimum -le 0) { $warnings.Add("$domain (unusual timers)") }
        }
        if ($bad.Count -gt 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-010' -Title 'SOA records are present and structurally valid' -ControlLevel Formal `
                -Status Fail -Severity High -Detail "Invalid SOA: $($bad -join ', ')." `
                -Recommendation 'Publish one valid SOA record with numeric serial, refresh, retry, expire and minimum fields.' -Evidence $evidence
        }
        elseif ($warnings.Count -gt 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-010' -Title 'SOA records are present and structurally valid' -ControlLevel Formal `
                -Status Warning -Severity Low -Detail "SOA timer review: $($warnings -join ', ')." `
                -Recommendation 'Review SOA timers; keep expire comfortably above refresh plus retry and normally at least two weeks.' -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-010' -Title 'SOA records are present and structurally valid' -ControlLevel Formal `
                -Status Pass -Detail 'SOA records are present and their timer fields passed structural checks.' -Evidence $evidence
        }
    }
}

function Test-CaDomainDnssec {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-011' -Title 'DNSSEC validation state is healthy' -ControlLevel Formal -Body {
        $states = [ordered]@{}
        foreach ($domain in $Domains) { $states[$domain] = Resolve-CaDnssecStatus -Name $domain }
        $bogus = @($states.Keys | Where-Object { $states[$_] -eq 'Bogus' })
        $unknown = @($states.Keys | Where-Object { $states[$_] -eq 'Indeterminate' })
        $insecure = @($states.Keys | Where-Object { $states[$_] -eq 'Insecure' })
        $requireDnssec = [bool](Get-CaDomainPolicyValue -Name RequireDnssec -Default $false)
        if ($bogus.Count -gt 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-011' -Title 'DNSSEC validation state is healthy' -ControlLevel Formal `
                -Status Fail -Severity High -Detail "Bogus DNSSEC validation chain: $($bogus -join ', ')." `
                -Recommendation 'Repair or remove the broken DS/DNSKEY chain immediately; validating resolvers may return SERVFAIL.' -Evidence $states
        }
        elseif ($unknown.Count -gt 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-011' -Title 'DNSSEC validation state is healthy' -ControlLevel Formal `
                -Status Investigate -Severity Medium -Detail "DNSSEC state could not be established for: $($unknown -join ', ')." `
                -Recommendation 'Repeat against a validating resolver and inspect DS/DNSKEY records.' -Evidence $states
        }
        elseif ($requireDnssec -and $insecure.Count -gt 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-011' -Title 'DNSSEC validation state is healthy' -ControlLevel Formal `
                -Status Fail -Severity Medium -Detail "Unsigned zones while DNSSEC is required: $($insecure -join ', ')." `
                -Recommendation 'Enable zone signing and publish the correct DS record at the parent zone.' -Evidence $states
        }
        elseif ($insecure.Count -gt 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-011' -Title 'DNSSEC validation state is healthy' -ControlLevel Formal `
                -Status Info -Detail "Unsigned zones (policy does not require DNSSEC): $($insecure -join ', ')." -Evidence $states
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-011' -Title 'DNSSEC validation state is healthy' -ControlLevel Formal `
                -Status Pass -Detail 'All authorized zones validated with authenticated DNS data.' -Evidence $states
        }
    }
}

function Test-CaDomainNameServers {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-002' -Title 'Authoritative name servers are present' -ControlLevel Formal -Body {
        $bad = @()
        $evidence = [ordered]@{}
        foreach ($domain in $Domains) {
            $ns = @(Resolve-CaDnsRecord -Name $domain -Type NS | ForEach-Object { $_.Data })
            $evidence[$domain] = $ns
            if ($ns.Count -lt 2) { $bad += $domain }
        }
        if ($bad.Count -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-002' -Title 'Authoritative name servers are present' -ControlLevel Formal `
                -Status Pass -Detail "All authorized domains expose at least two NS records." -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-002' -Title 'Authoritative name servers are present' -ControlLevel Formal `
                -Status Fail -Severity Medium -Detail "Domains with fewer than two NS records: $($bad -join ', ')." `
                -Recommendation 'Confirm registrar/DNS hosting delegation and maintain redundant authoritative name servers.' -Evidence $evidence
        }
    }
}

function Test-CaDomainMailExchange {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-003' -Title 'Mail domains publish MX records' -ControlLevel Formal -Body {
        $missing = @()
        $evidence = [ordered]@{}
        foreach ($domain in $Domains) {
            $mx = @(Resolve-CaDnsRecord -Name $domain -Type MX | ForEach-Object { $_.Data })
            $evidence[$domain] = $mx
            if ($mx.Count -eq 0) { $missing += $domain }
        }
        if ($missing.Count -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-003' -Title 'Mail domains publish MX records' -ControlLevel Formal `
                -Status Pass -Detail "All authorized domains publish MX records." -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-003' -Title 'Mail domains publish MX records' -ControlLevel Formal `
                -Status Warning -Severity Low -Detail "No MX record found for: $($missing -join ', ')." `
                -Recommendation 'If the domain sends or receives email, publish explicit MX records. If it never handles mail, document that decision.' -Evidence $evidence
        }
    }
}

function Test-CaDomainSpf {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-004' -Title 'SPF is present and terminates with fail policy' -ControlLevel Formal -Body {
        $missing = @(); $multiple = @(); $weak = @()
        $evidence = [ordered]@{}
        foreach ($domain in $Domains) {
            $spf = @(Resolve-CaDnsTxt -Name $domain | Where-Object { $_ -match '^v=spf1\b' })
            $evidence[$domain] = $spf
            if ($spf.Count -eq 0) { $missing += $domain }
            elseif ($spf.Count -gt 1) { $multiple += $domain }
            elseif ($spf[0] -notmatch '(?i)(~all|-all)\s*$') { $weak += $domain }
        }
        if (($missing.Count + $multiple.Count + $weak.Count) -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-004' -Title 'SPF is present and terminates with fail policy' -ControlLevel Formal `
                -Status Pass -Detail "All authorized domains publish a single SPF record ending in -all or ~all." -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-004' -Title 'SPF is present and terminates with fail policy' -ControlLevel Formal `
                -Status Fail -Severity Medium `
                -Detail "Missing SPF: $($missing -join ', '); multiple SPF: $($multiple -join ', '); weak SPF: $($weak -join ', ')." `
                -Recommendation 'Publish exactly one SPF TXT record per sending domain and end it with -all or ~all.' -Evidence $evidence `
                -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure'
        }
    }
}

function Test-CaDomainDmarc {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-005' -Title 'DMARC is enforced' -ControlLevel Formal -Body {
        $missing = @(); $monitorOnly = @()
        $evidence = [ordered]@{}
        foreach ($domain in $Domains) {
            $dmarc = @(Resolve-CaDnsTxt -Name "_dmarc.$domain" | Where-Object { $_ -match '^v=DMARC1\b' })
            $evidence[$domain] = $dmarc
            if ($dmarc.Count -eq 0) { $missing += $domain }
            elseif (($dmarc | Select-Object -First 1) -notmatch '(?i)\bp\s*=\s*(quarantine|reject)\b') { $monitorOnly += $domain }
        }
        if (($missing.Count + $monitorOnly.Count) -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-005' -Title 'DMARC is enforced' -ControlLevel Formal `
                -Status Pass -Detail "All authorized domains enforce DMARC with p=quarantine or p=reject." -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-005' -Title 'DMARC is enforced' -ControlLevel Formal `
                -Status Fail -Severity Medium `
                -Detail "Missing DMARC: $($missing -join ', '); monitor-only DMARC: $($monitorOnly -join ', ')." `
                -Recommendation 'Publish _dmarc TXT records and move from p=none to p=quarantine or p=reject after monitoring.' -Evidence $evidence `
                -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure'
        }
    }
}

function Test-CaDomainCaa {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-006' -Title 'CAA records restrict certificate issuance' -ControlLevel Formal -Body {
        $missing = @()
        $evidence = [ordered]@{}
        foreach ($domain in $Domains) {
            $caa = @(Resolve-CaDnsRecord -Name $domain -Type CAA | ForEach-Object { $_.Data })
            $evidence[$domain] = $caa
            if ($caa.Count -eq 0) { $missing += $domain }
        }
        if ($missing.Count -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-006' -Title 'CAA records restrict certificate issuance' -ControlLevel Formal `
                -Status Pass -Detail "All authorized domains publish CAA records." -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-006' -Title 'CAA records restrict certificate issuance' -ControlLevel Formal `
                -Status Warning -Severity Low -Detail "No CAA record found for: $($missing -join ', ')." `
                -Recommendation 'Publish CAA records to restrict which certificate authorities may issue for the domain.' -Evidence $evidence
        }
    }
}

function Test-CaDomainSpfRfc {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-012' -Title 'SPF avoids unsafe or excessive DNS mechanisms' -ControlLevel Formal -Body {
        $evidence = [ordered]@{}
        $bad = [System.Collections.Generic.List[string]]::new()
        foreach ($domain in $Domains) {
            $analysis = Get-CaSpfPolicyAnalysis -Records @(Resolve-CaDnsTxt -Name $domain)
            $evidence[$domain] = $analysis
            $blocking = @($analysis.Issues | Where-Object { $_ -in @('missing', 'multiple', 'permit_all', 'lookup_limit', 'ptr') })
            if ($blocking.Count -gt 0) { $bad.Add("$domain ($($blocking -join ','))") }
        }
        if ($bad.Count -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-012' -Title 'SPF avoids unsafe or excessive DNS mechanisms' -ControlLevel Formal `
                -Status Pass -Detail 'SPF records avoid +all, ptr and more than ten direct lookup mechanisms.' -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-012' -Title 'SPF avoids unsafe or excessive DNS mechanisms' -ControlLevel Formal `
                -Status Fail -Severity High -Detail "Unsafe SPF posture: $($bad -join '; ')." `
                -Recommendation 'Remove +all and ptr, publish exactly one SPF record and reduce direct DNS lookup mechanisms to ten or fewer.' `
                -Reference 'https://www.rfc-editor.org/rfc/rfc7208' -Evidence $evidence
        }
    }
}

function Test-CaDomainDmarcRfc {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-013' -Title 'DMARC records are singular and syntactically valid' -ControlLevel Formal -Body {
        $evidence = [ordered]@{}
        $bad = [System.Collections.Generic.List[string]]::new()
        $partial = [System.Collections.Generic.List[string]]::new()
        foreach ($domain in $Domains) {
            $analysis = Get-CaDmarcPolicyAnalysis -Records @(Resolve-CaDnsTxt -Name "_dmarc.$domain")
            $evidence[$domain] = $analysis
            $blocking = @($analysis.Issues | Where-Object { $_ -in @('missing', 'multiple', 'invalid_policy', 'invalid_pct') })
            if ($blocking.Count -gt 0) { $bad.Add("$domain ($($blocking -join ','))") }
            if ($analysis.Issues -contains 'partial_pct') { $partial.Add("$domain ($($analysis.Percentage)%)") }
        }
        if ($bad.Count -gt 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-013' -Title 'DMARC records are singular and syntactically valid' -ControlLevel Formal `
                -Status Fail -Severity Medium -Detail "Invalid DMARC posture: $($bad -join '; ')." `
                -Recommendation 'Publish exactly one DMARC record with a valid p= value and pct between 0 and 100.' -Evidence $evidence
        }
        elseif ($partial.Count -gt 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-013' -Title 'DMARC records are singular and syntactically valid' -ControlLevel Formal `
                -Status Warning -Severity Low -Detail "DMARC enforcement applies to less than 100% of mail: $($partial -join ', ')." `
                -Recommendation 'Raise pct to 100 after validating legitimate mail streams.' -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-013' -Title 'DMARC records are singular and syntactically valid' -ControlLevel Formal `
                -Status Pass -Detail 'DMARC records are singular with valid policy and percentage tags.' -Evidence $evidence
        }
    }
}

function Test-CaDomainDkim {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-014' -Title 'A non-revoked DKIM selector is published' -ControlLevel Formal -Body {
        $selectors = @(ConvertTo-CaStringList (Get-CaDomainPolicyValue -Name DkimSelectors -Default @('default', 'google', 'selector1', 'selector2', 'k1', 's1', 's2', 'mail')))
        $missing = [System.Collections.Generic.List[string]]::new()
        $evidence = [ordered]@{}
        foreach ($domain in $Domains) {
            $found = [ordered]@{}
            foreach ($selector in $selectors) {
                $records = @(Resolve-CaDnsTxt -Name "$selector._domainkey.$domain")
                foreach ($record in $records) {
                    if ($record -match '(?i)(?:^|;)\s*p\s*=\s*([^;\s]+)') { $found[$selector] = $record; break }
                }
            }
            $evidence[$domain] = $found
            if ($found.Count -eq 0) { $missing.Add($domain) }
        }
        if ($missing.Count -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-014' -Title 'A non-revoked DKIM selector is published' -ControlLevel Formal `
                -Status Pass -Detail 'At least one non-empty DKIM public key was found for every authorized domain.' -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-014' -Title 'A non-revoked DKIM selector is published' -ControlLevel Formal `
                -Status Investigate -Severity Low -Detail "No key found among configured/common selectors for: $($missing -join ', ')." `
                -Recommendation 'Confirm the real selector from the mail platform and add it to Domain.DkimSelectors; selector discovery is not defined by DKIM.' `
                -Reference 'https://www.rfc-editor.org/rfc/rfc6376' -Evidence @{ Selectors = $selectors; Records = $evidence }
        }
    }
}

function Test-CaDomainMailTransportSecurity {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-015' -Title 'MTA-STS and TLS reporting discovery records are published' -ControlLevel Formal -Body {
        $missingMta = [System.Collections.Generic.List[string]]::new()
        $missingRpt = [System.Collections.Generic.List[string]]::new()
        $evidence = [ordered]@{}
        foreach ($domain in $Domains) {
            $mta = @(Resolve-CaDnsTxt -Name "_mta-sts.$domain" | Where-Object { $_ -match '(?i)^v=STSv1\b' })
            $rpt = @(Resolve-CaDnsTxt -Name "_smtp._tls.$domain" | Where-Object { $_ -match '(?i)^v=TLSRPTv1\b' })
            $evidence[$domain] = @{ MtaSts = $mta; TlsRpt = $rpt }
            if ($mta.Count -eq 0) { $missingMta.Add($domain) }
            if ($rpt.Count -eq 0) { $missingRpt.Add($domain) }
        }
        if (($missingMta.Count + $missingRpt.Count) -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-015' -Title 'MTA-STS and TLS reporting discovery records are published' -ControlLevel Formal `
                -Status Pass -Detail 'MTA-STS and TLS-RPT discovery records are present for every authorized domain.' -Evidence $evidence
        }
        else {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-015' -Title 'MTA-STS and TLS reporting discovery records are published' -ControlLevel Formal `
                -Status Warning -Severity Low -Detail "Missing MTA-STS: $($missingMta -join ', '); missing TLS-RPT: $($missingRpt -join ', ')." `
                -Recommendation 'Publish _mta-sts and _smtp._tls TXT records, then validate the HTTPS MTA-STS policy separately.' -Evidence $evidence
        }
    }
}

function Test-CaDomainDnsx {
    param([Parameter(Mandatory)][string[]]$Domains)

    if (-not [bool](Get-CaDomainPolicyValue -Name EnableDnsx -Default $false)) { return }
    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-016' -Title 'dnsx resolution reports no DNS availability or dangling-CNAME issue' -ControlLevel Passive -Body {
        $binary = [string](Get-CaDomainPolicyValue -Name DnsxBinary -Default 'dnsx')
        $rate = [int](Get-CaDomainPolicyValue -Name DnsxRateLimit -Default 100)
        $resolvers = @(ConvertTo-CaStringList (Get-CaDomainPolicyValue -Name DnsxResolvers -Default @()))
        $timeout = [int](Get-CaDomainPolicyValue -Name DnsxTimeoutSeconds -Default 300)
        $result = Invoke-CaDnsxQuery -Domain $Domains -Binary $binary -RateLimit $rate -Resolvers $resolvers -TimeoutSec $timeout
        if (-not $result.Available) {
            return New-CaFinding -Service Domain -CheckId 'DOMAIN-016' -Title 'dnsx resolution reports no DNS availability or dangling-CNAME issue' `
                -ControlLevel Passive -Status Skipped -SkippedReason $result.Error `
                -Detail 'Optional dnsx engine is enabled in policy but the binary is unavailable.' `
                -Recommendation 'Install projectdiscovery/dnsx or disable Domain.EnableDnsx.'
        }
        if (-not $result.Success -and $result.Rows.Count -eq 0) {
            return New-CaFinding -Service Domain -CheckId 'DOMAIN-016' -Title 'dnsx resolution reports no DNS availability or dangling-CNAME issue' `
                -ControlLevel Passive -Status Error -Severity Medium -Detail "dnsx execution failed: $($result.Error)" `
                -Recommendation 'Validate the dnsx version, resolver list and local network path.'
        }
        $issues = @($result.Rows | Where-Object { $_.Status -in @('nxdomain', 'servfail', 'dangling_cname') })
        if ($issues.Count -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-016' -Title 'dnsx resolution reports no DNS availability or dangling-CNAME issue' `
                -ControlLevel Passive -Status Pass -Detail "dnsx checked $($result.Queried) authorized domain(s); no high-signal DNS issue was returned." -Evidence $result.Rows
        }
        else {
            $detail = @($issues | ForEach-Object { "$($_.Domain)=$($_.Status)" }) -join ', '
            New-CaFinding -Service Domain -CheckId 'DOMAIN-016' -Title 'dnsx resolution reports no DNS availability or dangling-CNAME issue' `
                -ControlLevel Passive -Status Fail -Severity High -Detail "dnsx issues: $detail." `
                -Recommendation 'Repair NXDOMAIN/SERVFAIL conditions and remove or reclaim dangling CNAME targets.' -Evidence $issues
        }
    }
}

function Test-CaDomainDanglingCname {
    param([Parameter(Mandatory)][string[]]$Domains)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-007' -Title 'Common subdomains do not have dangling CNAMEs' -Body {
        $subs = @(Get-CaDomainSubdomains)
        $dangling = [System.Collections.Generic.List[object]]::new()
        $checked = 0
        foreach ($domain in $Domains) {
            foreach ($sub in $subs) {
                $name = "$sub.$domain"
                $cname = @(Resolve-CaDnsRecord -Name $name -Type CNAME | Select-Object -First 1)
                if ($cname.Count -eq 0) { continue }
                $checked++
                $target = $cname[0].Data.TrimEnd('.')
                $a = @(Resolve-CaDnsRecord -Name $target -Type A)
                $aaaa = @(Resolve-CaDnsRecord -Name $target -Type AAAA)
                if (($a.Count + $aaaa.Count) -eq 0) {
                    $dangling.Add([pscustomobject]@{ Name = $name; Target = $target })
                }
            }
        }
        if ($dangling.Count -eq 0) {
            New-CaFinding -Service Domain -CheckId 'DOMAIN-007' -Title 'Common subdomains do not have dangling CNAMEs' `
                -Status Pass -Detail "Checked $checked existing CNAME record(s) across common authorized subdomains; no dangling target found." `
                -Evidence @{ Subdomains = $subs; CheckedCnames = $checked }
        }
        else {
            $details = @($dangling | ForEach-Object { "$($_.Name) -> $($_.Target)" })
            New-CaFinding -Service Domain -CheckId 'DOMAIN-007' -Title 'Common subdomains do not have dangling CNAMEs' `
                -Status Fail -Severity High -Detail "Dangling CNAME candidates: $($details -join '; ')." `
                -Recommendation 'Remove stale CNAMEs or recreate/claim the referenced service before an attacker can take it over.' `
                -Evidence @{ Dangling = @($dangling); Subdomains = $subs }
        }
    }
}
