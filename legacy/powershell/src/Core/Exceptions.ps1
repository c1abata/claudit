<#
    Exceptions.ps1 - governed, exact-match suppression of accepted findings.

    Inspired by Prowler's mutelist, but deliberately narrower: rules never use
    regular expressions, always expire, and must carry owner/reason/ticket
    evidence. The original finding status is preserved for auditability.
#>

function Get-CaExceptionProperty {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )

    if ($InputObject.PSObject.Properties.Name -contains $Name) {
        return $InputObject.$Name
    }
    return $Default
}

function Copy-CaFindingForException {
    param([Parameter(Mandatory)]$Finding)

    $values = [ordered]@{}
    foreach ($property in $Finding.PSObject.Properties) {
        $values[$property.Name] = $property.Value
    }
    $values['IsSuppressed'] = $false
    $values['Suppression'] = $null
    $copy = [pscustomobject]$values
    $copy.PSObject.TypeNames.Insert(0, 'Claudit.Finding')
    return $copy
}

function Import-CaExceptionPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [datetimeoffset]$NowUtc = [datetimeoffset]::UtcNow
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Claudit exception policy not found: $Path"
    }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        $document = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Invalid Claudit exception policy JSON: $($_.Exception.Message)"
    }

    $issues = [System.Collections.Generic.List[string]]::new()
    if ([string](Get-CaExceptionProperty -InputObject $document -Name 'SchemaVersion') -ne '1.0') {
        $issues.Add("SchemaVersion must be '1.0'")
    }
    $sourceRules = @(Get-CaExceptionProperty -InputObject $document -Name 'Rules' -Default @())
    $rules = [System.Collections.Generic.List[object]]::new()
    $seen = @{}

    foreach ($sourceRule in $sourceRules) {
        $ruleId = [string](Get-CaExceptionProperty -InputObject $sourceRule -Name 'RuleId')
        $checkId = [string](Get-CaExceptionProperty -InputObject $sourceRule -Name 'CheckId')
        $findingId = [string](Get-CaExceptionProperty -InputObject $sourceRule -Name 'FindingId')
        $reason = [string](Get-CaExceptionProperty -InputObject $sourceRule -Name 'Reason')
        $owner = [string](Get-CaExceptionProperty -InputObject $sourceRule -Name 'Owner')
        $ticket = [string](Get-CaExceptionProperty -InputObject $sourceRule -Name 'Ticket')
        $expiresValue = Get-CaExceptionProperty -InputObject $sourceRule -Name 'ExpiresUtc'
        $expiresText = if ($expiresValue -is [datetime]) {
            ([datetime]$expiresValue).ToString('o')
        }
        elseif ($expiresValue -is [datetimeoffset]) {
            ([datetimeoffset]$expiresValue).ToString('o')
        }
        else {
            [string]$expiresValue
        }
        $enabledValue = Get-CaExceptionProperty -InputObject $sourceRule -Name 'Enabled' -Default $true
        $allowBroadValue = Get-CaExceptionProperty -InputObject $sourceRule -Name 'AllowBroad' -Default $false
        $enabled = $enabledValue -is [bool] -and $enabledValue
        $allowBroad = $allowBroadValue -is [bool] -and $allowBroadValue

        if ($ruleId -notmatch '^[A-Z][A-Z0-9_.-]{2,63}$') { $issues.Add("invalid RuleId '$ruleId'") }
        elseif ($seen.ContainsKey($ruleId)) { $issues.Add("duplicate RuleId '$ruleId'") }
        else { $seen[$ruleId] = $true }
        if ($checkId -notmatch '^[A-Z]+-\d{3}$') { $issues.Add("invalid CheckId for '$ruleId'") }
        if ($findingId -and $findingId -notmatch '^claudit:[0-9a-f]{64}$') { $issues.Add("invalid FindingId for '$ruleId'") }
        if (-not $findingId -and -not $allowBroad) { $issues.Add("'$ruleId' needs FindingId or AllowBroad=true") }
        if ([string]::IsNullOrWhiteSpace($reason)) { $issues.Add("missing Reason for '$ruleId'") }
        if ([string]::IsNullOrWhiteSpace($owner)) { $issues.Add("missing Owner for '$ruleId'") }
        if ([string]::IsNullOrWhiteSpace($ticket)) { $issues.Add("missing Ticket for '$ruleId'") }
        if ($enabledValue -isnot [bool]) { $issues.Add("Enabled must be boolean for '$ruleId'") }
        if ($allowBroadValue -isnot [bool]) { $issues.Add("AllowBroad must be boolean for '$ruleId'") }
        $hasExplicitOffset = if ($expiresValue -is [datetime]) {
            ([datetime]$expiresValue).Kind -ne [DateTimeKind]::Unspecified
        }
        elseif ($expiresValue -is [datetimeoffset]) {
            $true
        }
        else {
            $expiresText -match '(?:Z|[+-]\d{2}:\d{2})$'
        }
        if (-not $hasExplicitOffset) { $issues.Add("ExpiresUtc needs an explicit UTC offset for '$ruleId'") }

        $expires = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse(
            $expiresText,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$expires
        )) {
            $issues.Add("invalid ExpiresUtc for '$ruleId'")
        }

        $rules.Add([pscustomobject]@{
            RuleId       = $ruleId
            Enabled      = $enabled
            CheckId      = $checkId
            FindingId    = $findingId
            AllowBroad   = $allowBroad
            Reason       = ConvertTo-CaRedactedText -Text $reason
            Owner        = ConvertTo-CaRedactedText -Text $owner
            Ticket       = ConvertTo-CaRedactedText -Text $ticket
            ExpiresUtc   = $expires.ToUniversalTime().ToString('o')
            IsExpired    = ($expires -le $NowUtc)
        })
    }

    if ($issues.Count -gt 0) {
        throw "Invalid Claudit exception policy: $($issues -join '; ')."
    }

    [pscustomobject]@{
        SchemaVersion = '1.0'
        File          = Split-Path -Leaf $Path
        Sha256        = Get-CaSha256Text -Text $raw
        Rules         = @($rules)
    }
}

function Test-CaExceptionRuleMatch {
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)]$Finding
    )

    if (-not $Rule.Enabled -or $Rule.IsExpired) { return $false }
    if ($Finding.Status -notin @('Fail', 'Warning', 'Investigate')) { return $false }
    if ([string]$Finding.CheckId -cne [string]$Rule.CheckId) { return $false }
    if ($Rule.FindingId -and [string]$Finding.FindingId -cne [string]$Rule.FindingId) { return $false }
    return $true
}

function Resolve-CaFindingExceptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [string]$Path,
        [datetimeoffset]$NowUtc = [datetimeoffset]::UtcNow
    )

    $normalized = @($Findings | ForEach-Object { Copy-CaFindingForException -Finding $_ })
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{
            Findings = $normalized
            Policy = [pscustomobject]@{
                Enabled=$false; SchemaVersion='1.0'; File=''; Sha256=''; RuleCount=0
                ActiveRuleCount=0; ExpiredRuleCount=0; AppliedRuleCount=0; SuppressedFindingCount=0
            }
        }
    }

    $policy = Import-CaExceptionPolicy -Path $Path -NowUtc $NowUtc
    $appliedRuleIds = @{}
    $suppressedCount = 0
    foreach ($finding in $normalized) {
        $matches = @($policy.Rules | Where-Object { Test-CaExceptionRuleMatch -Rule $_ -Finding $finding })
        if ($matches.Count -gt 1) {
            throw "Finding '$($finding.FindingId)' matches multiple exception rules: $(@($matches.RuleId) -join ', ')."
        }
        if ($matches.Count -eq 1) {
            $rule = $matches[0]
            $finding.IsSuppressed = $true
            $finding.Suppression = [pscustomobject]@{
                RuleId     = $rule.RuleId
                Reason     = $rule.Reason
                Owner      = $rule.Owner
                Ticket     = $rule.Ticket
                ExpiresUtc = $rule.ExpiresUtc
                AppliedUtc = $NowUtc.ToUniversalTime().ToString('o')
            }
            $appliedRuleIds[$rule.RuleId] = $true
            $suppressedCount++
        }
    }

    [pscustomobject]@{
        Findings = $normalized
        Policy = [pscustomobject]@{
            Enabled                = $true
            SchemaVersion          = $policy.SchemaVersion
            File                   = $policy.File
            Sha256                 = $policy.Sha256
            RuleCount              = $policy.Rules.Count
            ActiveRuleCount        = @($policy.Rules | Where-Object { $_.Enabled -and -not $_.IsExpired }).Count
            ExpiredRuleCount       = @($policy.Rules | Where-Object IsExpired).Count
            AppliedRuleCount       = $appliedRuleIds.Count
            SuppressedFindingCount = $suppressedCount
        }
    }
}
