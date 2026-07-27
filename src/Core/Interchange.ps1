<#
    Interchange.ps1 - dependency-free SOC and audit interchange projections.

    OCSF output uses Compliance Finding/Create from OCSF 1.8.0. OSCAL output
    follows the NIST OSCAL 1.2.1 assessment-results model and binds controls to
    Claudit's versioned local assessment-plan URN.
#>

function Get-CaOcsfSeverityId {
    param([string]$Severity)
    switch ($Severity) { 'Critical' { 5 } 'High' { 4 } 'Medium' { 3 } 'Low' { 2 } default { 1 } }
}

function Get-CaOcsfComplianceStatus {
    param([Parameter(Mandatory)][string]$Status)
    switch ($Status) {
        'Pass'          { [pscustomobject]@{ Id=1; Name='Pass' } }
        'Fail'          { [pscustomobject]@{ Id=3; Name='Fail' } }
        'Warning'       { [pscustomobject]@{ Id=2; Name='Warning' } }
        'Investigate'   { [pscustomobject]@{ Id=2; Name='Warning' } }
        'Error'         { [pscustomobject]@{ Id=0; Name='Unknown' } }
        'Skipped'       { [pscustomobject]@{ Id=0; Name='Unknown' } }
        'NotApplicable' { [pscustomobject]@{ Id=99; Name='NotApplicable' } }
        default         { [pscustomobject]@{ Id=99; Name='Other' } }
    }
}

function ConvertTo-CaOcsfJsonLines {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)]$Provenance
    )

    $lines = @($Findings | ForEach-Object {
        $finding = $_
        $severityId = Get-CaOcsfSeverityId -Severity $finding.Severity
        $complianceStatus = Get-CaOcsfComplianceStatus -Status $finding.Status
        $statusId = if ($finding.IsSuppressed) { 3 } elseif ($finding.Status -in @('Pass', 'Info', 'NotApplicable')) { 4 } elseif ($finding.Status -in @('Error', 'Skipped')) { 99 } else { 1 }
        $timestamp = [DateTimeOffset]::Parse($finding.TimestampUtc).ToUnixTimeMilliseconds()
        $metadataTags = @(
            @($finding.Categories | ForEach-Object { "category:$_" })
            @($finding.Threats | ForEach-Object { "threat:$_" })
        )
        [ordered]@{
            activity_id = 1
            activity_name = 'Create'
            category_uid = 2
            category_name = 'Findings'
            class_uid = 2003
            class_name = 'Compliance Finding'
            type_uid = 200301
            type_name = 'Compliance Finding: Create'
            time = $timestamp
            severity_id = $severityId
            severity = @('Unknown','Informational','Low','Medium','High','Critical')[$severityId]
            status_id = $statusId
            status = if ($statusId -eq 3) { 'Suppressed' } elseif ($statusId -eq 4) { 'Resolved' } elseif ($statusId -eq 1) { 'New' } else { 'Other' }
            message = [string]$finding.Detail
            finding_info = [ordered]@{
                uid = [string]$finding.FindingId
                title = [string]$finding.Title
                desc = [string]$finding.Detail
                created_time = $timestamp
                product = [ordered]@{ name='Claudit'; version=$Provenance.Producer.Version; vendor_name='Claudit Project' }
                tags = @("check_id:$($finding.CheckId)", "service:$($finding.Service)", "status:$($finding.Status)") + $metadataTags
            }
            compliance = [ordered]@{
                control = [string]$finding.CheckId
                standards = @($finding.ControlIds)
                status_id = $complianceStatus.Id
                status = $complianceStatus.Name
                status_code = [string]$finding.Status
                desc = [string]$finding.Detail
            }
            metadata = [ordered]@{
                version = '1.8.0'
                product = [ordered]@{ name='Claudit'; version=$Provenance.Producer.Version; vendor_name='Claudit Project' }
            }
            unmapped = [ordered]@{
                claudit = [ordered]@{
                    check_id=$finding.CheckId; control_level=$finding.ControlLevel; controls=@($finding.ControlIds)
                    outcome=$finding.Outcome; failure_category=$finding.FailureCategory; run_id=$Provenance.RunId
                    metadata_catalog_version=$finding.MetadataCatalogVersion; metadata_profile=$finding.MetadataProfile
                    categories=@($finding.Categories); threats=@($finding.Threats); risk=$finding.Risk
                    depends_on=@($finding.DependsOn); related_to=@($finding.RelatedTo)
                    suppression=$(if ($finding.IsSuppressed) { $finding.Suppression } else { $null })
                }
            }
        } | ConvertTo-Json -Depth 10 -Compress
    })
    ($lines -join "`n") + "`n"
}

function ConvertTo-CaOscalAssessmentResults {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)]$Provenance,
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)]$ControlCatalog
    )

    $observations = [System.Collections.Generic.List[object]]::new()
    $oscalFindings = [System.Collections.Generic.List[object]]::new()
    foreach ($finding in $Findings) {
        $observationUuid = (ConvertTo-CaDeterministicUuid -Value "observation|$($finding.FindingId)").ToString('D')
        $findingUuid = (ConvertTo-CaDeterministicUuid -Value "finding|$($finding.FindingId)").ToString('D')
        $state = if ($finding.Status -in @('Pass', 'Info', 'NotApplicable')) { 'satisfied' } else { 'not-satisfied' }
        $reason = if ($finding.Status -eq 'Pass') { 'pass' } elseif ($finding.Status -in @('Fail', 'Warning', 'Investigate')) { 'fail' } else { 'other' }
        $observations.Add([ordered]@{
            uuid=$observationUuid; title=$finding.Title; description=$(if ($finding.Detail) { $finding.Detail } else { $finding.Status })
            props=@(
                [ordered]@{ name='check-id'; value=$finding.CheckId },
                [ordered]@{ name='finding-id'; value=$finding.FindingId },
                [ordered]@{ name='status'; value=$finding.Status },
                [ordered]@{ name='severity'; value=$finding.Severity }
            )
            methods=@('TEST'); types=@('discovery'); collected=$finding.TimestampUtc
        })
        $oscalFindings.Add([ordered]@{
            uuid=$findingUuid; title=$finding.Title; description=$(if ($finding.Detail) { $finding.Detail } else { $finding.Status })
            props=@([ordered]@{ name='claudit-finding-id'; value=$finding.FindingId })
            target=[ordered]@{
                type='objective-id'; 'target-id'=$finding.CheckId; title=$finding.Title
                status=[ordered]@{ state=$state; reason=$reason; remarks="Claudit status: $($finding.Status)." }
            }
            'related-observations'=@([ordered]@{ 'observation-uuid'=$observationUuid })
            remarks=$(if ($finding.Recommendation) { "Recommendation: $($finding.Recommendation)" } else { '' })
        })
    }

    $controlIds = @($Findings.CheckId | Sort-Object -Unique)
    $started = if ($Provenance.StartedUtc) { $Provenance.StartedUtc } else { $Summary.GeneratedUtc }
    [ordered]@{
        'assessment-results' = [ordered]@{
            uuid=$Provenance.RunId
            metadata=[ordered]@{
                title="Claudit assessment results - $($Provenance.Scope.TenantName)"
                'last-modified'=$Provenance.CompletedUtc
                version=$Provenance.Producer.Version
                'oscal-version'='1.2.1'
                props=@(
                    [ordered]@{ name='claudit-schema-version'; value='2.0' },
                    [ordered]@{ name='claudit-catalog-version'; value=$ControlCatalog.CatalogVersion },
                    [ordered]@{ name='claudit-baseline-sha256'; value=$Provenance.Baseline.Sha256 }
                )
            }
            'import-ap'=[ordered]@{
                href="urn:claudit:assessment-plan:$($ControlCatalog.CatalogVersion)"
                remarks='Claudit local automated assessment plan; bind this URN to an organization-owned OSCAL AP/SSP for certification workflows.'
            }
            results=@([ordered]@{
                uuid=(ConvertTo-CaDeterministicUuid -Value "result|$($Provenance.RunId)").ToString('D')
                title='Claudit automated control evaluation'
                description="Read-only automated assessment; outcome $($Summary.Outcome), coverage $($Summary.CoveragePercent) percent."
                start=$started; end=$Provenance.CompletedUtc
                props=@(
                    [ordered]@{ name='outcome'; value=$Summary.Outcome },
                    [ordered]@{ name='coverage-percent'; value=[string]$Summary.CoveragePercent }
                )
                'reviewed-controls'=[ordered]@{
                    description='Claudit controls evaluated in this run.'
                    'control-selections'=@([ordered]@{ 'include-controls'=@($controlIds | ForEach-Object { [ordered]@{ 'control-id'=$_ } }) })
                }
                observations=@($observations)
                findings=@($oscalFindings)
                remarks='External framework mappings are indicative cross-references and do not claim complete framework assessment.'
            })
        }
    }
}
