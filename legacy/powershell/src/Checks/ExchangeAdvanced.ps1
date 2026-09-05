<#
    ExchangeAdvanced.ps1 - email-authentication DNS checks (SPF, DMARC) that
    complement the EXO policy checks. Named Test-CaExchange* for auto-discovery.

    These enumerate accepted domains from Exchange Online and inspect their public
    DNS records, so they need both an Exchange connection and outbound DNS-over-HTTPS.
#>

function Get-CaAcceptedDomainNames {
    Assert-CaExchange
    # Authoritative custom domains; skip the onmicrosoft.com routing domain.
    Get-AcceptedDomain -ErrorAction Stop |
        Select-Object -ExpandProperty DomainName |
        Where-Object { $_ -and $_ -notlike '*.onmicrosoft.com' }
}

function Test-CaExchangeSpf {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-010' -Title 'SPF published with hard/soft fail on all domains' -Body {
        $domains = @(Get-CaAcceptedDomainNames)
        if ($domains.Count -eq 0) {
            return New-CaFinding -Service Exchange -CheckId 'EXO-010' -Title 'SPF published with hard/soft fail on all domains' -Status Skipped `
                -SkippedReason 'No custom accepted domains.' -Detail 'Only the onmicrosoft.com domain is present; SPF managed by Microsoft.'
        }
        $missing = @(); $weak = @()
        foreach ($d in $domains) {
            $txt = @(Resolve-CaDnsTxt -Name $d)
            $spf = $txt | Where-Object { $_ -match '^v=spf1' } | Select-Object -First 1
            if (-not $spf) { $missing += $d }
            elseif ($spf -notmatch '[~-]all') { $weak += $d }
        }
        if ($missing.Count -eq 0 -and $weak.Count -eq 0) {
            New-CaFinding -Service Exchange -CheckId 'EXO-010' -Title 'SPF published with hard/soft fail on all domains' -Status Pass `
                -Detail "All $($domains.Count) custom domain(s) publish SPF ending in -all/~all."
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-010' -Title 'SPF published with hard/soft fail on all domains' -Status Fail -Severity Medium `
                -Detail "Missing SPF: $(( $missing) -join ', '); weak/neutral SPF: $(( $weak) -join ', ')." -Evidence @{ Missing = $missing; Weak = $weak } `
                -Recommendation 'Publish an SPF TXT record ending in -all (hard fail) for every sending domain.' `
                -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure'
        }
    }
}

function Test-CaExchangeDmarc {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-011' -Title 'DMARC enforced (p=quarantine or reject)' -Body {
        $domains = @(Get-CaAcceptedDomainNames)
        if ($domains.Count -eq 0) {
            return New-CaFinding -Service Exchange -CheckId 'EXO-011' -Title 'DMARC enforced (p=quarantine or reject)' -Status Skipped `
                -SkippedReason 'No custom accepted domains.' -Detail 'Only the onmicrosoft.com domain is present.'
        }
        $missing = @(); $monitorOnly = @()
        foreach ($d in $domains) {
            $txt = @(Resolve-CaDnsTxt -Name "_dmarc.$d")
            $dmarc = $txt | Where-Object { $_ -match '^v=DMARC1' } | Select-Object -First 1
            if (-not $dmarc) { $missing += $d }
            elseif ($dmarc -notmatch 'p=\s*(quarantine|reject)') { $monitorOnly += $d }
        }
        if ($missing.Count -eq 0 -and $monitorOnly.Count -eq 0) {
            New-CaFinding -Service Exchange -CheckId 'EXO-011' -Title 'DMARC enforced (p=quarantine or reject)' -Status Pass `
                -Detail "All $($domains.Count) custom domain(s) enforce DMARC."
        }
        else {
            $sev = if ($missing.Count -gt 0) { 'Medium' } else { 'Low' }
            New-CaFinding -Service Exchange -CheckId 'EXO-011' -Title 'DMARC enforced (p=quarantine or reject)' -Status Fail -Severity $sev `
                -Detail "Missing DMARC: $(( $missing) -join ', '); monitor-only (p=none): $(( $monitorOnly) -join ', ')." -Evidence @{ Missing = $missing; MonitorOnly = $monitorOnly } `
                -Recommendation 'Publish a _dmarc TXT record with p=quarantine or p=reject (after a monitoring period) on every domain.' `
                -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure'
        }
    }
}
