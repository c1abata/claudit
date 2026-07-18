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
        $Evidence
    )

    $Service = (Get-CaServiceSpec -Name $Service).Name

    # A passing / informational / skipped check carries no risk weight.
    $effectiveSeverity = if ($Status -in @('Pass', 'Info', 'Skipped')) { 'Info' } else { $Severity }

    # Control-framework mapping is centralised in Controls.ps1 and looked up by id.
    $controlIds = @()
    if (Get-Command -Name Get-CaControlIds -ErrorAction SilentlyContinue) {
        $controlIds = @(Get-CaControlIds -CheckId $CheckId)
    }

    [pscustomobject]@{
        PSTypeName     = 'Claudit.Finding'
        Service        = $Service
        CheckId        = $CheckId
        ControlLevel   = $ControlLevel
        Title          = ConvertTo-CaRedactedText -Text $Title
        Status         = $Status
        Severity       = $effectiveSeverity
        SeverityRank   = $script:CaSeverityRank[$effectiveSeverity]
        Detail         = ConvertTo-CaRedactedText -Text $Detail
        MarkdownDetail = ConvertTo-CaRedactedText -Text $MarkdownDetail
        Recommendation = ConvertTo-CaRedactedText -Text $Recommendation
        Reference      = ConvertTo-CaRedactedText -Text $Reference
        ControlIds     = $controlIds
        SkippedReason  = ConvertTo-CaRedactedText -Text $SkippedReason
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
        New-CaFinding -Service $Service -CheckId $CheckId -Title $Title `
            -ControlLevel $ControlLevel -Status 'Error' -Severity 'Medium' `
            -Detail "Check could not be evaluated: $(ConvertTo-CaRedactedText -Text $_.Exception.Message)" `
            -Recommendation 'Confirm the required module or CLI is installed, authenticated read-only, and has the scopes/roles listed in the README.'
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
