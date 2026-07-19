<#
    Findings.ps1 - the data model shared by every check.

    A "finding" is a single, immutable observation about the tenant. Every check
    emits one or more findings and never mutates anything. Keeping a single,
    flat shape makes reporting, filtering and Pester assertions trivial.

    Maester-inspired upgrades (v0.2):
      * Statuses extended with 'Skipped' (e.g. not licensed / not connected) and
        'Investigate' (passed but needs human review).
      * Each finding is auto-tagged with control-framework IDs (CISA SCuBA / CIS)
        looked up by CheckId, so reports can show governance coverage.
      * Optional MarkdownDetail for rich, portal-deep-linked evidence.
#>

$script:CaSeverityRank = @{
    'Critical' = 4
    'High'     = 3
    'Medium'   = 2
    'Low'      = 1
    'Info'     = 0
}

function New-CaDiagnosticId {
    'CA-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
}

function Get-CaFailureCategory {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$ErrorRecord)

    $exception = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    $message = [string]$exception.Message
    $typeName = if ($exception) { $exception.GetType().FullName } else { '' }
    $signal = "$typeName $message".ToLowerInvariant()

    if ($signal -match '429|throttl|rate.?limit|too many requests') { return 'RateLimit' }
    if ($signal -match 'timed?\s*out|timeout|taskcanceledexception') { return 'Timeout' }
    if ($signal -match 'unauthenticated|authentication|not logged|login required|invalid token|expired token|credential') { return 'Authentication' }
    if ($signal -match 'unauthorized|forbidden|access denied|insufficient privilege|permission|rbac|scope') { return 'Authorization' }
    if ($signal -match 'commandnotfound|not installed|not recognized|cannot find.*(module|command|executable)|no such file') { return 'Prerequisite' }
    if ($signal -match 'dns|socket|network|connection|connectivity|name resolution|host unreachable|tls|ssl') { return 'Connectivity' }
    if ($signal -match 'json|parse|format|schema|invalid data|unexpected response') { return 'Data' }
    return 'Internal'
}

function Get-CaFailureRecommendation {
    param([Parameter(Mandatory)][string]$FailureCategory)

    switch ($FailureCategory) {
        'Prerequisite'   { 'Install or expose the required module/CLI, then rerun the affected service.' }
        'Authentication' { 'Refresh the selected read-only identity or provider session, then rerun the affected service.' }
        'Authorization'  { 'Grant the selected identity the documented read-only scopes/roles required by this control.' }
        'Connectivity'   { 'Verify DNS, proxy, TLS and provider endpoint reachability from the executor.' }
        'Timeout'        { 'Retry the control; if repeatable, verify provider latency and increase only the bounded timeout.' }
        'RateLimit'      { 'Wait for the provider retry window, reduce concurrent requests and rerun the affected control.' }
        'Data'           { 'Inspect the redacted evidence and provider response shape; update the adapter if the upstream schema changed.' }
        default          { 'Use the diagnostic ID to correlate this result with the local execution log, then rerun after correcting the software fault.' }
    }
}

function New-CaFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Service,

        [Parameter(Mandatory)][ValidatePattern('^[A-Z]+-\d{3}$')]
        [string]$CheckId,

        [Parameter(Mandatory)][string]$Title,

        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Error', 'Skipped', 'Investigate')]
        [string]$Status,

        [ValidateSet('Formal', 'Passive', 'Active')]
        [string]$ControlLevel = 'Passive',

        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity = 'Info',

        [string]$Detail = '',
        [string]$Recommendation = '',
        [string]$Reference = '',

        # Markdown-formatted detail (tables, lists, portal deep-links). Optional.
        [string]$MarkdownDetail = '',

        # Reason a check was skipped (not licensed, not connected, ...).
        [string]$SkippedReason = '',

        # Raw evidence (the actual value observed) so the report is auditable.
        $Evidence,

        [ValidateSet('None', 'Prerequisite', 'Authentication', 'Authorization', 'Connectivity', 'Timeout', 'RateLimit', 'Data', 'Internal')]
        [string]$FailureCategory = 'None',

        [string]$FailureCode = '',
        [string]$ExceptionType = '',
        [string]$DiagnosticId = ''
    )

    $Service = (Get-CaServiceSpec -Name $Service).Name

    # A passing / informational / skipped check carries no risk weight.
    $effectiveSeverity = if ($Status -in @('Pass', 'Info', 'Skipped')) { 'Info' } else { $Severity }

    # Control-framework mapping is centralised in Controls.ps1 and looked up by id.
    $controlIds = @()
    if (Get-Command -Name Get-CaControlIds -ErrorAction SilentlyContinue) {
        $controlIds = @(Get-CaControlIds -CheckId $CheckId)
    }

    $outcome = switch ($Status) {
        'Pass'        { 'Passed' }
        'Fail'        { 'Issue' }
        'Warning'     { 'Attention' }
        'Investigate' { 'Attention' }
        'Error'       { 'ExecutionError' }
        'Skipped'     { 'NotEvaluated' }
        default       { 'Informational' }
    }
    if ($Status -ne 'Error') {
        $FailureCategory = 'None'
        $FailureCode = ''
        $ExceptionType = ''
        $DiagnosticId = ''
    }
    else {
        if ($FailureCategory -eq 'None') { $FailureCategory = 'Internal' }
        if ([string]::IsNullOrWhiteSpace($DiagnosticId)) { $DiagnosticId = New-CaDiagnosticId }
    }

    [pscustomobject]@{
        PSTypeName     = 'Claudit.Finding'
        Service        = $Service
        CheckId        = $CheckId
        ControlLevel   = $ControlLevel
        Title          = ConvertTo-CaRedactedText -Text $Title
        Status         = $Status
        Outcome        = $outcome
        Severity       = $effectiveSeverity
        SeverityRank   = $script:CaSeverityRank[$effectiveSeverity]
        IsBlocking     = ($Status -eq 'Error')
        Detail         = ConvertTo-CaRedactedText -Text $Detail
        MarkdownDetail = ConvertTo-CaRedactedText -Text $MarkdownDetail
        Recommendation = ConvertTo-CaRedactedText -Text $Recommendation
        Reference      = ConvertTo-CaRedactedText -Text $Reference
        ControlIds     = $controlIds
        SkippedReason  = ConvertTo-CaRedactedText -Text $SkippedReason
        FailureCategory = $FailureCategory
        FailureCode    = ConvertTo-CaRedactedText -Text $FailureCode
        ExceptionType  = ConvertTo-CaRedactedText -Text $ExceptionType
        DiagnosticId   = $DiagnosticId
        Evidence       = ConvertTo-CaRedactedObject -InputObject $Evidence
        TimestampUtc   = [DateTime]::UtcNow.ToString('o')
    }
}

<#
    Invoke-CaCheck wraps a single check body. If the body throws (missing
    permission, throttling, unexpected null) we degrade to an 'Error' finding
    instead of aborting the whole audit. One broken check must never hide the
    rest of the report.
#>
function Invoke-CaCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Formal', 'Passive', 'Active')][string]$ControlLevel = 'Passive',
        [Parameter(Mandatory)][scriptblock]$Body
    )

    try {
        & $Body
    }
    catch {
        $category = Get-CaFailureCategory -ErrorRecord $_
        $errorCode = if ($_.FullyQualifiedErrorId) { [string]$_.FullyQualifiedErrorId } else { 'UnhandledCheckException' }
        New-CaFinding -Service $Service -CheckId $CheckId -Title $Title `
            -ControlLevel $ControlLevel -Status 'Error' -Severity 'Medium' `
            -Detail "Check could not be evaluated: $(ConvertTo-CaRedactedText -Text $_.Exception.Message)" `
            -Recommendation (Get-CaFailureRecommendation -FailureCategory $category) `
            -FailureCategory $category -FailureCode $errorCode -ExceptionType ($_.Exception.GetType().FullName)
    }
}

<#
    Helper: run every Test-Ca<Service>* function defined in the module and stream
    their findings. Auto-discovery keeps the per-service entry points tiny and
    means adding a check is just adding a function.
#>
function Get-CaFindingsByPrefix {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Prefix)

    Get-Command -CommandType Function -Name $Prefix -ErrorAction SilentlyContinue |
        Sort-Object Name |
        ForEach-Object { & $_.Name }
}
