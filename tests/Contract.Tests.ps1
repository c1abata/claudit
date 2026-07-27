BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\Claudit.psd1') -Force
}

Describe 'Claudit provider check contract' {
    It 'accepts the four policy-check states with explicit semantics' {
        (New-CaCheckAssessment -Status Pass -Detail 'Compliant.').Severity | Should -Be 'Info'
        (New-CaCheckAssessment -Status NotApplicable -Detail 'No resource exists.').Status | Should -Be 'NotApplicable'
        (New-CaCheckAssessment -Status Fail -Severity High -Detail 'Non-compliant.').Severity | Should -Be 'High'
        (New-CaCheckAssessment -Status Error -Severity Medium -FailureCategory Authorization -Detail 'Access denied.').FailureCode | Should -Be 'ProviderEvaluationFailed'
    }

    It 'rejects ambiguous or internally inconsistent assessments' {
        { New-CaCheckAssessment -Status Fail -Detail 'Missing non-info severity.' } | Should -Throw '*non-Info severity*'
        { New-CaCheckAssessment -Status Error -Severity Medium -Detail 'Missing category.' } | Should -Throw '*FailureCategory*'
        { New-CaCheckAssessment -Status Pass -Severity High -Detail 'Contradictory severity.' } | Should -Throw '*Severity Info*'
        { New-CaCheckAssessment -Status Pass -Detail ' ' } | Should -Throw '*Detail*'
    }

    It 'converts an assessment into the normal finding pipeline' {
        $assessment = New-CaCheckAssessment -Status Fail -Severity Critical -Detail 'Root MFA disabled.' -Evidence @{ Enabled=0 }
        $finding = $assessment | ConvertTo-CaFinding -Service AWS -CheckId 'AWS-002' -Title 'Root account MFA enabled'

        $finding.PSObject.TypeNames | Should -Contain 'Claudit.Finding'
        $finding.Status | Should -Be 'Fail'
        $finding.Severity | Should -Be 'Critical'
        $finding.MetadataProfile | Should -Be 'identity-access'
        $finding.Evidence.Enabled | Should -Be 0
    }
}
