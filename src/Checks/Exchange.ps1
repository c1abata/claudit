<#
    Exchange.ps1 - Exchange Online read-only checks via ExchangeOnlineManagement.
    All cmdlets used are Get-* only. Claudit never changes mail flow or policy.
#>

function Get-CaExchangeFindings {
    [CmdletBinding()]
    param()

    try {
        Assert-CaExchange
    }
    catch {
        return New-CaFinding -Service Exchange -CheckId 'EXO-000' -Title 'Exchange Online session ready' `
            -Status 'Error' -Severity 'Medium' `
            -Detail "Exchange checks cannot run: $($_.Exception.Message)" `
            -Recommendation 'Run Connect-ExchangeOnline through Claudit and verify the account/app has read-only Exchange Online RBAC.'
    }

    $missing = @(Get-CaExchangeMissingCommandNames)
    if ($missing.Count -gt 0) {
        return New-CaFinding -Service Exchange -CheckId 'EXO-000' -Title 'Exchange Online cmdlet surface available' `
            -Status 'Error' -Severity 'Medium' `
            -Detail "Connected Exchange session did not expose required read-only cmdlets: $($missing -join ', ')." `
            -Recommendation 'Use an account assigned View-Only Organization Management or Organization Management in Exchange Online. Then reconnect and verify Get-Command Get-OrganizationConfig, Get-TransportRule and Get-AcceptedDomain are available.'
    }

    Get-CaFindingsByPrefix -Prefix 'Test-CaExchange*'
}

function Get-CaExchangeMissingCommandNames {
    $required = @(
        'Get-OrganizationConfig',
        'Get-HostedOutboundSpamFilterPolicy',
        'Get-TransportRule',
        'Get-DkimSigningConfig',
        'Get-TransportConfig',
        'Get-RemoteDomain',
        'Get-AntiPhishPolicy',
        'Get-AcceptedDomain'
    )

    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $required) {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            $missing.Add($name)
        }
    }
    if (-not (Get-Command -Name 'Get-CASMailbox' -ErrorAction SilentlyContinue) -and
        -not (Get-Command -Name 'Get-EXOCasMailbox' -ErrorAction SilentlyContinue)) {
        $missing.Add('Get-CASMailbox or Get-EXOCasMailbox')
    }
    return @($missing)
}

function Get-CaExchangeCasMailbox {
    $classic = Get-Command -Name 'Get-CASMailbox' -ErrorAction SilentlyContinue
    if ($classic -and $classic.Parameters.ContainsKey('ResultSize')) {
        return @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop)
    }

    if (Get-Command -Name 'Get-EXOCasMailbox' -ErrorAction SilentlyContinue) {
        return @(Get-EXOCasMailbox -ResultSize Unlimited -Properties PopEnabled,ImapEnabled -ErrorAction Stop)
    }

    throw 'Neither Get-CASMailbox nor Get-EXOCasMailbox is available in the connected Exchange session.'
}

function Test-CaExchangeModernAuth {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-001' -Title 'Modern authentication enabled' -Body {
        Assert-CaExchange
        $bl = Get-CaBaseline
        if (-not $bl.Exchange.RequireModernAuthentication) {
            return New-CaFinding -Service Exchange -CheckId 'EXO-001' -Title 'Modern authentication enabled' -Status Info -Detail 'Baseline does not require this control.'
        }
        $org = Get-OrganizationConfig -ErrorAction Stop
        if ($org.OAuth2ClientProfileEnabled) {
            New-CaFinding -Service Exchange -CheckId 'EXO-001' -Title 'Modern authentication enabled' -Status Pass -Detail 'OAuth2ClientProfileEnabled = True.' -Evidence $true
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-001' -Title 'Modern authentication enabled' -Status Fail -Severity High `
                -Detail 'Modern authentication (OAuth2ClientProfileEnabled) is disabled.' -Evidence $false `
                -Recommendation 'Enable modern authentication for Exchange Online.' `
                -Reference 'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online'
        }
    }
}

function Test-CaExchangeAuditEnabled {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-002' -Title 'Organization-wide mailbox auditing enabled' -Body {
        Assert-CaExchange
        $bl = Get-CaBaseline
        if (-not $bl.Exchange.RequireOrganizationAuditEnabled) {
            return New-CaFinding -Service Exchange -CheckId 'EXO-002' -Title 'Organization-wide mailbox auditing enabled' -Status Info -Detail 'Baseline does not require this control.'
        }
        $org = Get-OrganizationConfig -ErrorAction Stop
        # AuditDisabled = $false means auditing is ON.
        if (-not $org.AuditDisabled) {
            New-CaFinding -Service Exchange -CheckId 'EXO-002' -Title 'Organization-wide mailbox auditing enabled' -Status Pass -Detail 'AuditDisabled = False (auditing on).' -Evidence $false
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-002' -Title 'Organization-wide mailbox auditing enabled' -Status Fail -Severity High `
                -Detail 'Mailbox auditing is disabled organization-wide (AuditDisabled = True).' -Evidence $true `
                -Recommendation 'Set-OrganizationConfig -AuditDisabled $false to re-enable auditing.' `
                -Reference 'https://learn.microsoft.com/purview/audit-mailboxes'
        }
    }
}

function Test-CaExchangeExternalForwarding {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-003' -Title 'External auto-forwarding blocked' -Body {
        Assert-CaExchange
        $bl = Get-CaBaseline
        if (-not $bl.Exchange.BlockExternalAutoForwarding) {
            return New-CaFinding -Service Exchange -CheckId 'EXO-003' -Title 'External auto-forwarding blocked' -Status Info -Detail 'Baseline does not require this control.'
        }
        $policies = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)
        $permissive = @($policies | Where-Object { $_.AutoForwardingMode -ne 'Off' })
        if (-not $permissive) {
            New-CaFinding -Service Exchange -CheckId 'EXO-003' -Title 'External auto-forwarding blocked' -Status Pass `
                -Detail 'All outbound spam filter policies set AutoForwardingMode = Off.' -Evidence 'Off'
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-003' -Title 'External auto-forwarding blocked' -Status Fail -Severity High `
                -Detail "Policies allowing auto-forwarding: $(( $permissive.Name) -join ', ')." -Evidence ($permissive.Name -join ', ') `
                -Recommendation 'Set AutoForwardingMode to Off (or Automatic with intent) on outbound spam filter policies.' `
                -Reference 'https://learn.microsoft.com/defender-office-365/outbound-spam-policies-external-email-forwarding'
        }
    }
}

function Test-CaExchangeForwardingRules {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-004' -Title 'No transport rules redirect mail externally' -Body {
        Assert-CaExchange
        $rules = @(Get-TransportRule -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
        $risky = @($rules | Where-Object {
            $_.RedirectMessageTo -or $_.BlindCopyTo -or $_.AddToRecipients -or $_.CopyTo
        })
        if (-not $risky) {
            New-CaFinding -Service Exchange -CheckId 'EXO-004' -Title 'No transport rules redirect mail externally' -Status Pass `
                -Detail "$($rules.Count) enabled transport rules; none redirect/bcc/copy mail."
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-004' -Title 'No transport rules redirect mail externally' -Status Warning -Severity Medium `
                -Detail "Rules with redirect/bcc/copy actions: $(( $risky.Name) -join ', '). Review recipients for external addresses." -Evidence ($risky.Name -join ', ') `
                -Recommendation 'Review each rule; remove unintended external redirection or BCC exfiltration paths.' `
                -Reference 'https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules'
        }
    }
}

function Test-CaExchangeDkim {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-005' -Title 'DKIM signing enabled on all domains' -Body {
        Assert-CaExchange
        $bl = Get-CaBaseline
        if (-not $bl.Exchange.RequireDkimOnAllDomains) {
            return New-CaFinding -Service Exchange -CheckId 'EXO-005' -Title 'DKIM signing enabled on all domains' -Status Info -Detail 'Baseline does not require this control.'
        }
        $configs = @(Get-DkimSigningConfig -ErrorAction Stop)
        $disabled = @($configs | Where-Object { -not $_.Enabled })
        if (-not $disabled) {
            New-CaFinding -Service Exchange -CheckId 'EXO-005' -Title 'DKIM signing enabled on all domains' -Status Pass `
                -Detail "DKIM enabled on all $($configs.Count) domains."
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-005' -Title 'DKIM signing enabled on all domains' -Status Fail -Severity Medium `
                -Detail "Domains without DKIM: $(( $disabled.Domain) -join ', ')." -Evidence ($disabled.Domain -join ', ') `
                -Recommendation 'Enable DKIM signing and publish the CNAME records for each custom domain.' `
                -Reference 'https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure'
        }
    }
}

function Test-CaExchangeSmtpClientAuth {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-006' -Title 'SMTP AUTH disabled tenant-wide' -Body {
        Assert-CaExchange
        $bl = Get-CaBaseline
        if (-not $bl.Exchange.BlockSmtpClientAuthentication) {
            return New-CaFinding -Service Exchange -CheckId 'EXO-006' -Title 'SMTP AUTH disabled tenant-wide' -Status Info -Detail 'Baseline does not require this control.'
        }
        $tc = Get-TransportConfig -ErrorAction Stop
        if ($tc.SmtpClientAuthenticationDisabled) {
            New-CaFinding -Service Exchange -CheckId 'EXO-006' -Title 'SMTP AUTH disabled tenant-wide' -Status Pass -Detail 'SmtpClientAuthenticationDisabled = True.' -Evidence $true
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-006' -Title 'SMTP AUTH disabled tenant-wide' -Status Fail -Severity High `
                -Detail 'Legacy SMTP AUTH is enabled tenant-wide.' -Evidence $false `
                -Recommendation 'Disable SMTP AUTH globally; enable per-mailbox only where strictly required.' `
                -Reference 'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission'
        }
    }
}

function Test-CaExchangeLegacyProtocols {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-007' -Title 'POP3/IMAP4 disabled on mailboxes' -Body {
        Assert-CaExchange
        $bl = Get-CaBaseline
        $cas = Get-CaExchangeCasMailbox
        $popOn = @($cas | Where-Object { $_.PopEnabled })
        $imapOn = @($cas | Where-Object { $_.ImapEnabled })

        $problems = @()
        if ($bl.Exchange.DisablePop3 -and $popOn.Count -gt 0) { $problems += "POP3 enabled on $($popOn.Count) mailbox(es)" }
        if ($bl.Exchange.DisableImap4 -and $imapOn.Count -gt 0) { $problems += "IMAP4 enabled on $($imapOn.Count) mailbox(es)" }

        if ($problems.Count -eq 0) {
            New-CaFinding -Service Exchange -CheckId 'EXO-007' -Title 'POP3/IMAP4 disabled on mailboxes' -Status Pass -Detail 'No mailboxes have POP3/IMAP4 enabled per baseline.'
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-007' -Title 'POP3/IMAP4 disabled on mailboxes' -Status Fail -Severity Medium `
                -Detail ($problems -join '; ') -Evidence @{ Pop = $popOn.PrimarySmtpAddress; Imap = $imapOn.PrimarySmtpAddress } `
                -Recommendation 'Disable POP3/IMAP4 where not required (Set-CASMailbox).' `
                -Reference 'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/pop3-and-imap4/pop3-and-imap4'
        }
    }
}

function Test-CaExchangeRemoteDomainForwarding {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-008' -Title 'Default remote domain disallows auto-forward' -Body {
        Assert-CaExchange
        $rd = Get-RemoteDomain -Identity 'Default' -ErrorAction Stop
        if (-not $rd.AutoForwardEnabled) {
            New-CaFinding -Service Exchange -CheckId 'EXO-008' -Title 'Default remote domain disallows auto-forward' -Status Pass -Detail 'AutoForwardEnabled = False on Default remote domain.' -Evidence $false
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-008' -Title 'Default remote domain disallows auto-forward' -Status Fail -Severity Medium `
                -Detail 'Default remote domain allows client auto-forwarding (AutoForwardEnabled = True).' -Evidence $true `
                -Recommendation 'Set-RemoteDomain Default -AutoForwardEnabled $false unless explicitly required.' `
                -Reference 'https://learn.microsoft.com/exchange/mail-flow-best-practices/remote-domains/remote-domains'
        }
    }
}

function Test-CaExchangeAntiPhishPolicy {
    Invoke-CaCheck -Service Exchange -CheckId 'EXO-009' -Title 'Anti-phishing policy present and enabled' -Body {
        Assert-CaExchange
        $policies = @(Get-AntiPhishPolicy -ErrorAction Stop)
        $enabled = @($policies | Where-Object { $_.Enabled })
        if ($enabled) {
            New-CaFinding -Service Exchange -CheckId 'EXO-009' -Title 'Anti-phishing policy present and enabled' -Status Pass `
                -Detail "$($enabled.Count) enabled anti-phishing policy(ies)."
        }
        else {
            New-CaFinding -Service Exchange -CheckId 'EXO-009' -Title 'Anti-phishing policy present and enabled' -Status Fail -Severity Medium `
                -Detail 'No enabled anti-phishing policy found.' `
                -Recommendation 'Configure a Defender for Office 365 anti-phishing policy (impersonation + mailbox intelligence).' `
                -Reference 'https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about'
        }
    }
}
