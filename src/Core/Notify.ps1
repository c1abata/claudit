<#
    Notify.ps1 - optional result notification to Microsoft Teams or Slack via an
    incoming webhook (Maester sends to email/Teams/Slack). This is a single
    outbound HTTPS POST - no CI/CD, no extra modules. The webhook URL is a secret
    the caller supplies at run time; Claudit never stores it.
#>

function Send-CaNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WebhookUrl,
        [Parameter(Mandatory)][object]$Summary,
        [ValidateSet('Teams', 'Slack')][string]$Type = 'Teams',
        [string]$TenantName = 'Cloud tenant'
    )

    $highImpact = [int]$Summary.Critical + [int]$Summary.High
    $headline = if ($highImpact -gt 0) { "⚠️ Claudit: $highImpact high-impact finding(s)" } else { '✅ Claudit: no high-impact findings' }
    $safeTenantName = ConvertTo-CaRedactedText -Text $TenantName
    $line = "Tenant: $safeTenantName | Checks $($Summary.Total) | Pass $($Summary.Pass) | Fail $($Summary.Fail) | Critical $($Summary.Critical) | High $($Summary.High)"

    if ($Type -eq 'Slack') {
        $payload = @{ text = "*$headline*`n$line" } | ConvertTo-Json -Depth 4
    }
    else {
        # Microsoft Teams MessageCard (works with classic incoming webhooks).
        $payload = @{
            '@type'    = 'MessageCard'
            '@context' = 'http://schema.org/extensions'
            themeColor = if ($highImpact -gt 0) { 'CF222E' } else { '1A7F37' }
            summary    = $headline
            title      = $headline
            text       = $line
        } | ConvertTo-Json -Depth 6
    }

    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Write-Verbose 'Notification sent.'
}
