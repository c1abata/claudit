<#
    CheckContract.ps1 - small data contract between provider adapters and findings.

    Collectors gather read-only provider data. Pure analyzers turn that data into
    one assessment. The final conversion adds Claudit identity, metadata and
    redaction. Operational provider failures are explicit Error assessments;
    programming faults are still contained by Invoke-CaCheck.
#>

function New-CaCheckAssessment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'NotApplicable', 'Error')]
        [string]$Status,

        [Parameter(Mandatory)][string]$Detail,

        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity = 'Info',

        [string]$Recommendation = '',
        [string]$Reference = '',
        [string]$MarkdownDetail = '',
        $Evidence,

        [ValidateSet('None', 'Prerequisite', 'Authentication', 'Authorization', 'Connectivity', 'Timeout', 'RateLimit', 'Data', 'Internal')]
        [string]$FailureCategory = 'None',
        [string]$FailureCode = '',
        [string]$ExceptionType = '',

        [string]$ScopeId = '',
        [string]$ResourceType = '',
        [string]$ResourceId = ''
    )

    if ([string]::IsNullOrWhiteSpace($Detail)) {
        throw 'Check assessment Detail must explain the observed state.'
    }
    if ($Status -in @('Pass', 'NotApplicable') -and $Severity -ne 'Info') {
        throw "$Status assessments must use Severity Info."
    }
    if ($Status -in @('Fail', 'Error') -and $Severity -eq 'Info') {
        throw "$Status assessments require a non-Info severity."
    }
    if ($Status -eq 'Error' -and $FailureCategory -eq 'None') {
        throw 'Error assessments require an explicit FailureCategory.'
    }
    if ($Status -ne 'Error' -and $FailureCategory -ne 'None') {
        throw "$Status assessments cannot carry a failure category."
    }

    if ($Status -eq 'Error') {
        if ([string]::IsNullOrWhiteSpace($FailureCode)) { $FailureCode = 'ProviderEvaluationFailed' }
        if ([string]::IsNullOrWhiteSpace($Recommendation)) {
            $Recommendation = Get-CaFailureRecommendation -FailureCategory $FailureCategory
        }
    }

    [pscustomobject]@{
        PSTypeName      = 'Claudit.CheckAssessment'
        ContractVersion = '1.0'
        Status          = $Status
        Severity        = $Severity
        Detail          = $Detail
        Recommendation  = $Recommendation
        Reference       = $Reference
        MarkdownDetail  = $MarkdownDetail
        Evidence        = $Evidence
        FailureCategory = $FailureCategory
        FailureCode     = $FailureCode
        ExceptionType   = $ExceptionType
        ScopeId         = $ScopeId
        ResourceType    = $ResourceType
        ResourceId      = $ResourceId
    }
}

function ConvertTo-CaFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Assessment,
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][ValidatePattern('^[A-Z]+-\d{3}$')][string]$CheckId,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Formal', 'Passive', 'Active')][string]$ControlLevel = 'Passive'
    )

    process {
        if ($Assessment.PSObject.TypeNames -notcontains 'Claudit.CheckAssessment' -or $Assessment.ContractVersion -ne '1.0') {
            throw 'ConvertTo-CaFinding requires a Claudit.CheckAssessment contract v1.0 object.'
        }

        New-CaFinding -Service $Service -CheckId $CheckId -Title $Title -ControlLevel $ControlLevel `
            -Status $Assessment.Status -Severity $Assessment.Severity -Detail $Assessment.Detail `
            -Recommendation $Assessment.Recommendation -Reference $Assessment.Reference `
            -MarkdownDetail $Assessment.MarkdownDetail -Evidence $Assessment.Evidence `
            -FailureCategory $Assessment.FailureCategory -FailureCode $Assessment.FailureCode `
            -ExceptionType $Assessment.ExceptionType -ScopeId $Assessment.ScopeId `
            -ResourceType $Assessment.ResourceType -ResourceId $Assessment.ResourceId
    }
}
