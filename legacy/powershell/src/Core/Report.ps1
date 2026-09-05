<#
    Report.ps1 - aggregation and rendering.

    Get-CaAllFindings runs the per-service collectors. New-CaReport turns a flat
    finding list into report artifacts. Formats (Maester-inspired): HTML
    (self-contained), JSON (machine-readable, for drift diffing), Markdown
    (great for PRs / wikis) and CSV (for Excel / GRC tooling).
#>

function Get-CaAllFindings {
    [CmdletBinding()]
    param(
        [string[]]$Service = (Get-CaDefaultServices)
    )

    foreach ($svc in (Resolve-CaServices -Service $Service)) {
        $spec = Get-CaServiceSpec -Name $svc
        $collector = "Get-Ca$($spec.Prefix)Findings"
        $checkId = (($spec.Prefix -replace '[^A-Za-z]', '').ToUpperInvariant()) + '-000'
        $collected = [System.Collections.Generic.List[object]]::new()
        try {
            $captureFinding = {
                param($Item)
                if ($null -eq $Item) { return }
                $properties = @($Item.PSObject.Properties.Name)
                if ('CheckId' -notin $properties -or 'Status' -notin $properties -or 'Service' -notin $properties) {
                    throw "Collector '$collector' returned an invalid result object."
                }
                $collected.Add($Item)
            }
            if (Get-Command -Name $collector -CommandType Function -ErrorAction SilentlyContinue) {
                & $collector | ForEach-Object { & $captureFinding $_ }
            }
            else {
                Get-CaFindingsByPrefix -Prefix "Test-Ca$($spec.Prefix)*" | ForEach-Object { & $captureFinding $_ }
            }
            if ($collected.Count -eq 0) {
                throw "Collector '$collector' produced no findings."
            }
            foreach ($item in $collected) { $item }
        }
        catch {
            foreach ($item in $collected) { $item }
            $category = Get-CaFailureCategory -ErrorRecord $_
            $errorCode = if ($_.FullyQualifiedErrorId) { [string]$_.FullyQualifiedErrorId } else { 'CollectorFailure' }
            New-CaFinding -Service $svc -CheckId $checkId -Title "$svc result collection completed" `
                -Status Error -Severity High `
                -Detail "The $svc collector stopped before all controls were returned: $($_.Exception.Message)" `
                -Recommendation (Get-CaFailureRecommendation -FailureCategory $category) `
                -FailureCategory $category -FailureCode $errorCode -ExceptionType ($_.Exception.GetType().FullName)
        }
    }
}

function Get-CaSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Findings)

    $activeFindings = @($Findings | Where-Object { -not $_.IsSuppressed })
    $suppressed = @($Findings | Where-Object IsSuppressed).Count
    $byStatus = $activeFindings | Group-Object Status -AsHashTable -AsString
    $get = { param($k) if ($byStatus -and $byStatus.ContainsKey($k)) { @($byStatus[$k]).Count } else { 0 } }

    $fails = $activeFindings | Where-Object { $_.Status -eq 'Fail' }
    $bySev = $fails | Group-Object Severity -AsHashTable -AsString
    $getSev = { param($k) if ($bySev -and $bySev.ContainsKey($k)) { @($bySev[$k]).Count } else { 0 } }

    $total = $Findings.Count
    $pass = & $get 'Pass'
    $fail = & $get 'Fail'
    $warning = & $get 'Warning'
    $info = & $get 'Info'
    $errorCount = & $get 'Error'
    $skipped = & $get 'Skipped'
    $notApplicable = & $get 'NotApplicable'
    $investigate = & $get 'Investigate'
    $applicable = $total - $notApplicable
    $evaluated = $applicable - $errorCount - $skipped
    $problems = $fail + $warning + $investigate
    $coverage = if ($applicable -gt 0) {
        [math]::Round(($evaluated / $applicable) * 100, 1)
    }
    elseif ($total -gt 0) { 100 }
    else { 0 }
    $outcome = if ($errorCount -gt 0) {
        'ExecutionError'
    }
    elseif ($skipped -gt 0) {
        'Incomplete'
    }
    elseif ($fail -gt 0) {
        'IssuesFound'
    }
    elseif (($warning + $investigate) -gt 0) {
        'Attention'
    }
    elseif ($suppressed -gt 0) {
        'Attention'
    }
    elseif ($applicable -gt 0) {
        'Pass'
    }
    elseif ($notApplicable -gt 0) {
        'NotApplicable'
    }
    else {
        'Empty'
    }
    $serviceSummary = @($Findings | Group-Object Service | ForEach-Object {
        $items = @($_.Group)
        $activeItems = @($items | Where-Object { -not $_.IsSuppressed })
        $serviceSuppressed = @($items | Where-Object IsSuppressed).Count
        $serviceFail = @($activeItems | Where-Object Status -eq 'Fail').Count
        $serviceWarning = @($activeItems | Where-Object { $_.Status -in @('Warning', 'Investigate') }).Count
        $serviceError = @($activeItems | Where-Object Status -eq 'Error').Count
        $serviceSkipped = @($activeItems | Where-Object Status -eq 'Skipped').Count
        $serviceNotApplicable = @($activeItems | Where-Object Status -eq 'NotApplicable').Count
        [pscustomobject]@{
            Service      = $_.Name
            Outcome      = if ($serviceError) { 'ExecutionError' } elseif ($serviceSkipped) { 'Incomplete' } elseif ($serviceFail) { 'IssuesFound' } elseif ($serviceWarning -or $serviceSuppressed) { 'Attention' } elseif ($items.Count -eq $serviceNotApplicable) { 'NotApplicable' } else { 'Pass' }
            Total        = $items.Count
            Pass         = @($activeItems | Where-Object Status -eq 'Pass').Count
            Problems     = $serviceFail + $serviceWarning
            Suppressed   = $serviceSuppressed
            NotEvaluated = $serviceError + $serviceSkipped
            NotApplicable = $serviceNotApplicable
            Errors       = $serviceError
        }
    } | Sort-Object Service)

    [pscustomobject]@{
        Outcome      = $outcome
        Total        = $Findings.Count
        Applicable   = $applicable
        Evaluated    = $evaluated
        NotEvaluated = $errorCount + $skipped
        CoveragePercent = $coverage
        ProblemsDetected = $problems
        Suppressed   = $suppressed
        BlockingErrors = $errorCount
        Pass         = $pass
        Fail         = $fail
        Warning      = $warning
        Info         = $info
        Error        = $errorCount
        Skipped      = $skipped
        NotApplicable = $notApplicable
        Investigate  = $investigate
        Critical     = & $getSev 'Critical'
        High         = & $getSev 'High'
        Medium       = & $getSev 'Medium'
        Low          = & $getSev 'Low'
        RecommendedExitCode = if (($errorCount + $skipped) -gt 0) { 3 } elseif (((& $getSev 'Critical') + (& $getSev 'High')) -gt 0) { 2 } else { 0 }
        Services     = $serviceSummary
        GeneratedUtc = [DateTime]::UtcNow.ToString('o')
    }
}

function ConvertTo-CaHtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-CaMarkdownTableCell {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }

    $safe = ConvertTo-CaRedactedText -Text $Text
    $safe = $safe -replace '[\r\n]+', ' '
    $safe = $safe -replace '\|', '\|'
    $safe = $safe -replace '<', '&lt;'
    $safe = $safe -replace '>', '&gt;'
    return $safe
}

function Write-CaUtf8FileAtomic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )

    $directory = Split-Path -Parent $Path
    $leaf = Split-Path -Leaf $Path
    $temporaryPath = Join-Path $directory (".$leaf.$([guid]::NewGuid().ToString('N')).tmp")
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $Content, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::Move($temporaryPath, $Path, $false)
        if (-not $IsWindows) {
            [System.IO.File]::SetUnixFileMode($Path, [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite)
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-CaReportStem {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
    return "claudit-$stamp-$suffix"
}

function Add-CaMissingControlFindings {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [string[]]$ExpectedService = @(),
        [AllowEmptyString()][string]$ExpectedControlLevel = ''
    )

    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($finding in $Findings) { $result.Add($finding) }
    if ($ExpectedService.Count -eq 0) { return @($result) }
    if ($ExpectedControlLevel -notin @('Formal', 'Passive', 'Active')) {
        throw 'ExpectedControlLevel must be Formal, Passive or Active when ExpectedService is supplied.'
    }

    $completeness = @(Get-CaReportCompleteness -Findings $Findings -ExpectedService $ExpectedService -ExpectedControlLevel $ExpectedControlLevel)
    foreach ($service in $completeness) {
        foreach ($checkId in @($service.MissingControls)) {
            $result.Add((New-CaFinding -Service $service.Service -CheckId $checkId `
                -Title 'Expected control result missing' -ControlLevel $service.ControlLevel `
                -Status Error -Severity High `
                -Detail "The selected $($service.Service) $($service.ControlLevel) assessment expected a result for $checkId, but the collector returned none." `
                -Recommendation 'Treat the run as incomplete. Inspect the collector path and restore one explicit result for every expected control.' `
                -FailureCategory Internal -FailureCode MissingControlResult `
                -Evidence ([pscustomobject]@{
                    Service=$service.Service
                    ControlLevel=$service.ControlLevel
                    ExpectedCheckId=$checkId
                })))
        }
    }
    return @($result)
}

function New-CaReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings,
        [string]$OutputDirectory,
        [ValidateSet('Html', 'Json', 'Markdown', 'Csv', 'Ocsf', 'Oscal', 'Catalog', 'All')][string]$Format = 'All',
        [string]$TenantName = 'Cloud tenant',
        [string]$ExceptionPath,
        [string[]]$ExpectedService = @(),
        [AllowEmptyString()][string]$ExpectedControlLevel = ''
    )

    begin { $all = [System.Collections.Generic.List[object]]::new() }
    process { foreach ($f in $Findings) { $all.Add($f) } }
    end {
        if ($all.Count -eq 0) { Write-Warning 'No findings to report.'; return }

        if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot '..\..\reports' }
        if (-not (Test-Path -LiteralPath $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }
        $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

        $compatibleFindings = @($all | ForEach-Object { ConvertTo-CaCompatibleFinding -Finding $_ })
        $compatibleFindings = @(Add-CaMissingControlFindings -Findings $compatibleFindings -ExpectedService $ExpectedService -ExpectedControlLevel $ExpectedControlLevel)
        $exceptionResult = Resolve-CaFindingExceptions -Findings $compatibleFindings -Path $ExceptionPath
        $findingArray = @($exceptionResult.Findings)
        $exceptionPolicy = $exceptionResult.Policy
        $stem = New-CaReportStem
        $runId = [guid]::NewGuid()
        $summary = Get-CaSummary -Findings $findingArray
        $files = @()
        $want = { param($f) $Format -eq 'All' -or $Format -eq $f }
        $safeTenantName = ConvertTo-CaRedactedText -Text $TenantName
        $problems = @(Get-CaSortedFindings -Findings @($findingArray | Where-Object { -not $_.IsSuppressed -and $_.Status -in @('Fail', 'Warning', 'Investigate') }))
        $suppressedFindings = @(Get-CaSortedFindings -Findings @($findingArray | Where-Object IsSuppressed))
        $executionErrors = @(Get-CaSortedFindings -Findings @($findingArray | Where-Object Status -eq 'Error'))
        $notEvaluated = @(Get-CaSortedFindings -Findings @($findingArray | Where-Object Status -eq 'Skipped'))
        $artifactManifestName = "$stem.sha256"
        $catalog = Get-CaControlCatalog
        $catalogArtifactName = if (& $want 'Catalog') { "$stem.catalog.json" } else { '' }
        $checkMetadataCatalog = Get-CaCheckMetadataCatalog
        $checkMetadataArtifactName = if (& $want 'Catalog') { "$stem.checks.json" } else { '' }
        $checkMetadataCount = @($checkMetadataCatalog.Assignments | ForEach-Object { @($_.CheckIds) }).Count
        $provenance = Get-CaReportProvenance -Findings $findingArray -Summary $summary -TenantName $safeTenantName -RunId $runId -ArtifactManifest $artifactManifestName `
            -ExpectedService $ExpectedService -ExpectedControlLevel $ExpectedControlLevel

        if (& $want 'Json') {
            $jsonPath = Join-Path $OutputDirectory "$stem.json"
            $json = [pscustomobject]@{
                SchemaVersion   = '2.0'
                Schema          = 'https://github.com/c1abata/claudit/blob/main/schemas/claudit-report-v2.schema.json'
                ReportType      = 'ClauditAudit'
                ReportId        = $runId.ToString('D')
                Tenant          = $safeTenantName
                Provenance      = $provenance
                ControlCatalog  = [pscustomobject]@{
                    Version=$catalog.CatalogVersion; FullFrameworkCoverage=$catalog.FullFrameworkCoverage
                    CoverageModel=$catalog.CoverageModel; Artifact=$catalogArtifactName
                }
                CheckMetadataCatalog = [pscustomobject]@{
                    Version=$checkMetadataCatalog.CatalogVersion; Profiles=@($checkMetadataCatalog.Profiles).Count
                    Checks=$checkMetadataCount; CoverageModel=$checkMetadataCatalog.CoverageModel; Artifact=$checkMetadataArtifactName
                }
                ExceptionPolicy = $exceptionPolicy
                Summary         = $summary
                Problems        = $problems
                SuppressedFindings = $suppressedFindings
                ExecutionErrors = $executionErrors
                NotEvaluated    = $notEvaluated
                Findings        = $findingArray
            } | ConvertTo-Json -Depth 12
            Write-CaUtf8FileAtomic -Path $jsonPath -Content $json
            $files += $jsonPath
        }
        if (& $want 'Html') {
            $htmlPath = Join-Path $OutputDirectory "$stem.html"
            $html = New-CaHtmlBody -Findings $findingArray -Summary $summary -TenantName $safeTenantName -Version $provenance.Producer.Version
            Write-CaUtf8FileAtomic -Path $htmlPath -Content $html
            $files += $htmlPath
        }
        if (& $want 'Markdown') {
            $mdPath = Join-Path $OutputDirectory "$stem.md"
            $markdown = New-CaMarkdownBody -Findings $findingArray -Summary $summary -TenantName $safeTenantName
            Write-CaUtf8FileAtomic -Path $mdPath -Content $markdown
            $files += $mdPath
        }
        if (& $want 'Csv') {
            $csvPath = Join-Path $OutputDirectory "$stem.csv"
            $csvRows = $findingArray | ForEach-Object {
                [pscustomobject]@{
                    FindingId     = ConvertTo-CaCsvSafeText -Text $_.FindingId
                    CheckId        = ConvertTo-CaCsvSafeText -Text $_.CheckId
                    ScopeId        = ConvertTo-CaCsvSafeText -Text $_.ScopeId
                    ResourceType   = ConvertTo-CaCsvSafeText -Text $_.ResourceType
                    ResourceId     = ConvertTo-CaCsvSafeText -Text $_.ResourceId
                    EvidenceHash   = ConvertTo-CaCsvSafeText -Text $_.EvidenceHash
                    ControlLevel   = ConvertTo-CaCsvSafeText -Text $_.ControlLevel
                    Service        = ConvertTo-CaCsvSafeText -Text $_.Service
                    Title          = ConvertTo-CaCsvSafeText -Text $_.Title
                    Status         = ConvertTo-CaCsvSafeText -Text $_.Status
                    Outcome        = ConvertTo-CaCsvSafeText -Text $_.Outcome
                    Severity       = ConvertTo-CaCsvSafeText -Text $_.Severity
                    MetadataCatalogVersion = ConvertTo-CaCsvSafeText -Text $_.MetadataCatalogVersion
                    MetadataProfile = ConvertTo-CaCsvSafeText -Text $_.MetadataProfile
                    MetadataSource = ConvertTo-CaCsvSafeText -Text $_.MetadataSource
                    DefaultSeverity = ConvertTo-CaCsvSafeText -Text $_.DefaultSeverity
                    Categories     = ConvertTo-CaCsvSafeText -Text ($_.Categories -join '; ')
                    Threats        = ConvertTo-CaCsvSafeText -Text ($_.Threats -join '; ')
                    Risk           = ConvertTo-CaCsvSafeText -Text $_.Risk
                    DependsOn      = ConvertTo-CaCsvSafeText -Text ($_.DependsOn -join '; ')
                    RelatedTo      = ConvertTo-CaCsvSafeText -Text ($_.RelatedTo -join '; ')
                    IsBlocking     = [bool]$_.IsBlocking
                    IsSuppressed   = [bool]$_.IsSuppressed
                    SuppressionRuleId = ConvertTo-CaCsvSafeText -Text $(if ($_.Suppression) { $_.Suppression.RuleId } else { '' })
                    SuppressionReason = ConvertTo-CaCsvSafeText -Text $(if ($_.Suppression) { $_.Suppression.Reason } else { '' })
                    SuppressionOwner = ConvertTo-CaCsvSafeText -Text $(if ($_.Suppression) { $_.Suppression.Owner } else { '' })
                    SuppressionTicket = ConvertTo-CaCsvSafeText -Text $(if ($_.Suppression) { $_.Suppression.Ticket } else { '' })
                    SuppressionExpiresUtc = ConvertTo-CaCsvSafeText -Text $(if ($_.Suppression) { $_.Suppression.ExpiresUtc } else { '' })
                    FailureCategory = ConvertTo-CaCsvSafeText -Text $_.FailureCategory
                    FailureCode    = ConvertTo-CaCsvSafeText -Text $_.FailureCode
                    DiagnosticId   = ConvertTo-CaCsvSafeText -Text $_.DiagnosticId
                    Controls       = ConvertTo-CaCsvSafeText -Text ($_.ControlIds -join '; ')
                    Detail         = ConvertTo-CaCsvSafeText -Text $_.Detail
                    Recommendation = ConvertTo-CaCsvSafeText -Text $_.Recommendation
                    Reference      = ConvertTo-CaCsvSafeText -Text $_.Reference
                    TimestampUtc   = ConvertTo-CaCsvSafeText -Text $_.TimestampUtc
                }
            }
            $csv = (@($csvRows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine) + [Environment]::NewLine
            Write-CaUtf8FileAtomic -Path $csvPath -Content $csv
            $files += $csvPath
        }
        if (& $want 'Ocsf') {
            $ocsfPath = Join-Path $OutputDirectory "$stem.ocsf.jsonl"
            Write-CaUtf8FileAtomic -Path $ocsfPath -Content (ConvertTo-CaOcsfJsonLines -Findings $findingArray -Provenance $provenance)
            $files += $ocsfPath
        }
        if (& $want 'Oscal') {
            $oscalPath = Join-Path $OutputDirectory "$stem.oscal-ar.json"
            $oscal = ConvertTo-CaOscalAssessmentResults -Findings $findingArray -Provenance $provenance -Summary $summary -ControlCatalog $catalog
            Write-CaUtf8FileAtomic -Path $oscalPath -Content ($oscal | ConvertTo-Json -Depth 15)
            $files += $oscalPath
        }
        if (& $want 'Catalog') {
            $catalogPath = Join-Path $OutputDirectory "$stem.catalog.json"
            Write-CaUtf8FileAtomic -Path $catalogPath -Content ($catalog | ConvertTo-Json -Depth 10)
            $files += $catalogPath
            $checkMetadataPath = Join-Path $OutputDirectory "$stem.checks.json"
            Write-CaUtf8FileAtomic -Path $checkMetadataPath -Content ($checkMetadataCatalog | ConvertTo-Json -Depth 10)
            $files += $checkMetadataPath
        }

        $artifactManifestPath = Join-Path $OutputDirectory $artifactManifestName
        Write-CaArtifactManifest -Paths $files -ManifestPath $artifactManifestPath
        $files += $artifactManifestPath

        [pscustomobject]@{
            SchemaVersion = '2.0'
            ReportId = $runId.ToString('D')
            Summary = $summary
            Provenance = $provenance
            ControlCatalog = $catalog
            CheckMetadataCatalog = $checkMetadataCatalog
            ExceptionPolicy = $exceptionPolicy
            Problems = $problems
            SuppressedFindings = $suppressedFindings
            ExecutionErrors = $executionErrors
            NotEvaluated = $notEvaluated
            OutputDirectory = $OutputDirectory
            Files = $files
        }
    }
}

function Get-CaSortedFindings {
    param([object[]]$Findings)
    $sortOrder = @(
        @{ Expression = { switch ($_.Status) { 'Error' { 6 } 'Fail' { 5 } 'Investigate' { 4 } 'Warning' { 3 } 'Skipped' { 2 } 'NotApplicable' { 1 } default { 0 } } }; Descending = $true }
        @{ Expression = 'SeverityRank'; Descending = $true }
        @{ Expression = 'Service'; Descending = $false }
        @{ Expression = 'CheckId'; Descending = $false }
    )
    $Findings | Sort-Object -Property $sortOrder
}

function Add-CaMarkdownFindingTable {
    param(
        [Parameter(Mandatory)][System.Text.StringBuilder]$Builder,
        [object[]]$Findings,
        [switch]$IncludeDiagnostics
    )

    if (-not $Findings -or $Findings.Count -eq 0) {
        [void]$Builder.AppendLine('_None._')
        [void]$Builder.AppendLine('')
        return
    }

    $diagnosticHeader = if ($IncludeDiagnostics) { ' | Diagnostic' } else { '' }
    $diagnosticRule = if ($IncludeDiagnostics) { '|------------' } else { '' }
    [void]$Builder.AppendLine("| ID | Service | Status | Severity | Categories | Check | Detail | Recommendation$diagnosticHeader |")
    [void]$Builder.AppendLine("|----|---------|--------|----------|------------|-------|--------|---------------$diagnosticRule|")
    foreach ($f in (Get-CaSortedFindings -Findings $Findings)) {
        $cells = @(
            (ConvertTo-CaMarkdownTableCell -Text $f.CheckId)
            (ConvertTo-CaMarkdownTableCell -Text $f.Service)
            (ConvertTo-CaMarkdownTableCell -Text $(if ($f.IsSuppressed) { "$($f.Status) (Suppressed)" } else { $f.Status }))
            (ConvertTo-CaMarkdownTableCell -Text $f.Severity)
            (ConvertTo-CaMarkdownTableCell -Text ($f.Categories -join ', '))
            (ConvertTo-CaMarkdownTableCell -Text $f.Title)
            (ConvertTo-CaMarkdownTableCell -Text $(if ($f.IsSuppressed) { "$($f.Suppression.Reason) [$($f.Suppression.RuleId); $($f.Suppression.Ticket); expires $($f.Suppression.ExpiresUtc)]" } elseif ($f.Status -eq 'Skipped' -and $f.SkippedReason) { $f.SkippedReason } else { $f.Detail }))
            (ConvertTo-CaMarkdownTableCell -Text $f.Recommendation)
        )
        if ($IncludeDiagnostics) {
            $cells += ConvertTo-CaMarkdownTableCell -Text "$($f.DiagnosticId) / $($f.FailureCategory) / $($f.FailureCode)"
        }
        [void]$Builder.AppendLine('| ' + ($cells -join ' | ') + ' |')
    }
    [void]$Builder.AppendLine('')
}

function New-CaMarkdownBody {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][object]$Summary,
        [string]$TenantName
    )
    $safeTenant = ConvertTo-CaMarkdownTableCell -Text $TenantName
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Claudit - multi-cloud diagnostic audit")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("**Tenant:** $safeTenant  ")
    [void]$sb.AppendLine("**Generated:** $($Summary.GeneratedUtc) UTC  ")
    [void]$sb.AppendLine("**Mode:** read-only  ")
    [void]$sb.AppendLine("**Overall outcome:** $($Summary.Outcome)  ")
    [void]$sb.AppendLine("**Evaluation coverage:** $($Summary.CoveragePercent)% ($($Summary.Evaluated)/$($Summary.Applicable))")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("| Problems | Suppressed | Execution errors | Not evaluated | Pass | Critical | High |")
    [void]$sb.AppendLine("|---------:|-----------:|-----------------:|--------------:|-----:|---------:|-----:|")
    [void]$sb.AppendLine("| $($Summary.ProblemsDetected) | $($Summary.Suppressed) | $($Summary.BlockingErrors) | $($Summary.NotEvaluated) | $($Summary.Pass) | $($Summary.Critical) | $($Summary.High) |")
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Problems detected')
    [void]$sb.AppendLine('')
    Add-CaMarkdownFindingTable -Builder $sb -Findings @($Findings | Where-Object { -not $_.IsSuppressed -and $_.Status -in @('Fail', 'Warning', 'Investigate') })

    [void]$sb.AppendLine('## Suppressed findings')
    [void]$sb.AppendLine('')
    Add-CaMarkdownFindingTable -Builder $sb -Findings @($Findings | Where-Object IsSuppressed)

    [void]$sb.AppendLine('## Execution errors blocking evaluation')
    [void]$sb.AppendLine('')
    Add-CaMarkdownFindingTable -Builder $sb -Findings @($Findings | Where-Object Status -eq 'Error') -IncludeDiagnostics

    [void]$sb.AppendLine('## Not evaluated')
    [void]$sb.AppendLine('')
    Add-CaMarkdownFindingTable -Builder $sb -Findings @($Findings | Where-Object Status -eq 'Skipped')

    [void]$sb.AppendLine('## Service coverage')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Service | Outcome | Total | Pass | Problems | Suppressed | Not evaluated | Errors |')
    [void]$sb.AppendLine('|---------|---------|------:|-----:|---------:|-----------:|--------------:|-------:|')
    foreach ($service in @($Summary.Services)) {
        [void]$sb.AppendLine("| $(ConvertTo-CaMarkdownTableCell $service.Service) | $(ConvertTo-CaMarkdownTableCell $service.Outcome) | $($service.Total) | $($service.Pass) | $($service.Problems) | $($service.Suppressed) | $($service.NotEvaluated) | $($service.Errors) |")
    }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Complete results')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("| ID | Level | Service | Status | Severity | Categories | Check | Controls | Detail | Recommendation |")
    [void]$sb.AppendLine("|----|-------|---------|--------|----------|------------|-------|----------|--------|----------------|")
    foreach ($f in (Get-CaSortedFindings -Findings $Findings)) {
        $id = ConvertTo-CaMarkdownTableCell -Text $f.CheckId
        $level = ConvertTo-CaMarkdownTableCell -Text $f.ControlLevel
        $svc = ConvertTo-CaMarkdownTableCell -Text $f.Service
        $status = ConvertTo-CaMarkdownTableCell -Text $(if ($f.IsSuppressed) { "$($f.Status) (Suppressed)" } else { $f.Status })
        $severity = ConvertTo-CaMarkdownTableCell -Text $f.Severity
        $categories = ConvertTo-CaMarkdownTableCell -Text ($f.Categories -join ', ')
        $title = ConvertTo-CaMarkdownTableCell -Text $f.Title
        $controls = ConvertTo-CaMarkdownTableCell -Text ($f.ControlIds -join ', ')
        $detail = ConvertTo-CaMarkdownTableCell -Text $(if ($f.IsSuppressed) { "$($f.Detail) [suppressed by $($f.Suppression.RuleId); $($f.Suppression.Ticket); expires $($f.Suppression.ExpiresUtc)]" } elseif ($f.Status -eq 'Skipped' -and $f.SkippedReason) { $f.SkippedReason } else { $f.Detail })
        $recommendation = ConvertTo-CaMarkdownTableCell -Text $f.Recommendation
        [void]$sb.AppendLine("| $id | $level | $svc | $status | $severity | $categories | $title | $controls | $detail | $recommendation |")
    }
    $sb.ToString()
}

function New-CaHtmlBody {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][object]$Summary,
        [string]$TenantName,
        [Parameter(Mandatory)][string]$Version
    )

    $statusColor = @{ Pass = '#1a7f37'; Fail = '#cf222e'; Warning = '#bf8700'; Info = '#0969da'; Error = '#6e7781'; Skipped = '#8b949e'; NotApplicable = '#57606a'; Investigate = '#8250df' }
    $sevColor    = @{ Critical = '#cf222e'; High = '#d1242f'; Medium = '#bf8700'; Low = '#0969da'; Info = '#6e7781' }

    $rowList = [System.Collections.Generic.List[string]]::new()
    $problemRowList = [System.Collections.Generic.List[string]]::new()
    $suppressedRowList = [System.Collections.Generic.List[string]]::new()
    $errorRowList = [System.Collections.Generic.List[string]]::new()
    $skippedRowList = [System.Collections.Generic.List[string]]::new()
    foreach ($f in (Get-CaSortedFindings -Findings $Findings)) {
        $sc = $statusColor[$f.Status]; if (-not $sc) { $sc = '#6e7781' }
        $vc = $sevColor[$f.Severity];  if (-not $vc) { $vc = '#6e7781' }
        $recCell = ConvertTo-CaHtmlEncoded $f.Recommendation
        if ($f.Reference) {
            $refUrl = ConvertTo-CaHtmlEncoded $f.Reference
            $recCell = $recCell + ' <a href="' + $refUrl + '">ref</a>'
        }
        $id    = ConvertTo-CaHtmlEncoded $f.CheckId
        $level = ConvertTo-CaHtmlEncoded $f.ControlLevel
        $svc   = ConvertTo-CaHtmlEncoded $f.Service
        $title = ConvertTo-CaHtmlEncoded $f.Title
        $stat  = ConvertTo-CaHtmlEncoded $(if ($f.IsSuppressed) { "$($f.Status) (Suppressed)" } else { $f.Status })
        $sev   = ConvertTo-CaHtmlEncoded $f.Severity
        $categories = ConvertTo-CaHtmlEncoded (($f.Categories) -join ', ')
        $detailText = if ($f.Status -eq 'Skipped' -and $f.SkippedReason) { $f.SkippedReason } else { $f.Detail }
        if ($f.Status -eq 'Error') {
            $detailText = "$detailText [diagnostic $($f.DiagnosticId); $($f.FailureCategory); $($f.FailureCode)]"
        }
        if ($f.IsSuppressed) {
            $detailText = "$detailText [suppressed by $($f.Suppression.RuleId); $($f.Suppression.Ticket); expires $($f.Suppression.ExpiresUtc)]"
            $sc = '#6e7781'
        }
        $det   = ConvertTo-CaHtmlEncoded $detailText
        $ctrl  = ConvertTo-CaHtmlEncoded (($f.ControlIds) -join ', ')
        $row = "<tr><td><code>$id</code></td><td>$level</td><td>$svc</td><td>$title</td>" +
               "<td><span class=`"pill`" style=`"background:$sc`">$stat</span></td>" +
               "<td><span class=`"pill`" style=`"background:$vc`">$sev</span></td><td>$categories</td>" +
               "<td class=`"ctrl`">$ctrl</td><td>$det</td><td>$recCell</td></tr>"
        $rowList.Add($row)
        if (-not $f.IsSuppressed -and $f.Status -in @('Fail', 'Warning', 'Investigate')) { $problemRowList.Add($row) }
        if ($f.IsSuppressed) { $suppressedRowList.Add($row) }
        if ($f.Status -eq 'Error') { $errorRowList.Add($row) }
        if ($f.Status -eq 'Skipped') { $skippedRowList.Add($row) }
    }
    $rowsHtml = $rowList -join "`n"
    $problemRowsHtml = if ($problemRowList.Count) { $problemRowList -join "`n" } else { '<tr><td colspan="10" class="empty">No audit problems detected.</td></tr>' }
    $suppressedRowsHtml = if ($suppressedRowList.Count) { $suppressedRowList -join "`n" } else { '<tr><td colspan="10" class="empty">No findings were suppressed.</td></tr>' }
    $errorRowsHtml = if ($errorRowList.Count) { $errorRowList -join "`n" } else { '<tr><td colspan="10" class="empty">No execution errors blocked evaluation.</td></tr>' }
    $skippedRowsHtml = if ($skippedRowList.Count) { $skippedRowList -join "`n" } else { '<tr><td colspan="10" class="empty">No controls were intentionally skipped.</td></tr>' }

    $serviceRows = @($Summary.Services | ForEach-Object {
        $service = ConvertTo-CaHtmlEncoded $_.Service
        $outcome = ConvertTo-CaHtmlEncoded $_.Outcome
        "<tr><td>$service</td><td>$outcome</td><td>$($_.Total)</td><td>$($_.Pass)</td><td>$($_.Problems)</td><td>$($_.Suppressed)</td><td>$($_.NotEvaluated)</td><td>$($_.Errors)</td></tr>"
    }) -join "`n"

    $passRate = if ($Summary.Evaluated -gt 0) { [math]::Round((($Summary.Pass) / $Summary.Evaluated) * 100, 1) } else { 0 }
    $tenant = ConvertTo-CaHtmlEncoded $TenantName
    $gen = ConvertTo-CaHtmlEncoded $Summary.GeneratedUtc
    $outcome = ConvertTo-CaHtmlEncoded $Summary.Outcome
    $outcomeClass = switch ($Summary.Outcome) { 'ExecutionError' { 'error' } 'Incomplete' { 'warning' } 'IssuesFound' { 'fail' } 'Attention' { 'warning' } default { 'pass' } }

    $css = @'
 body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f6f8fa;color:#1f2328}
 .wrap{max-width:1280px;margin:0 auto;padding:24px}
 h1{font-size:22px;margin:0 0 4px} .sub{color:#57606a;font-size:13px;margin-bottom:20px}
 .cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px}
 .card{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:14px 18px;min-width:92px}
 .card .n{font-size:26px;font-weight:700} .card .l{font-size:12px;color:#57606a;text-transform:uppercase;letter-spacing:.04em}
 table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d0d7de;border-radius:8px;overflow:hidden}
 th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #eaeef2;font-size:13px;vertical-align:top}
 th{background:#f6f8fa;font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:#57606a}
 code{background:#eff1f3;padding:1px 5px;border-radius:4px;font-size:12px}
 .ctrl{font-size:11px;color:#57606a;white-space:nowrap}
 .pill{color:#fff;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
 .outcome{background:#fff;border:1px solid #d0d7de;border-left:5px solid #1a7f37;border-radius:8px;padding:14px 16px;margin:0 0 20px}.outcome.fail,.outcome.error{border-left-color:#cf222e}.outcome.warning{border-left-color:#bf8700}.outcome strong{display:block;font-size:16px;margin-bottom:4px}
 h2{font-size:17px;margin:28px 0 10px}.empty{color:#57606a;font-style:italic}.table-wrap{overflow:auto}
 a{color:#0969da}
 footer{color:#8b949e;font-size:12px;margin-top:18px}
'@

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>Claudit report - $tenant</title>")
    [void]$sb.AppendLine("<style>$css</style></head><body><div class=`"wrap`">")
    [void]$sb.AppendLine('<h1>Claudit &mdash; multi-cloud diagnostic audit</h1>')
    [void]$sb.AppendLine("<div class=`"sub`">$tenant &middot; generated $gen UTC &middot; read-only</div>")
    [void]$sb.AppendLine("<div class=`"outcome $outcomeClass`"><strong>Overall outcome: $outcome</strong><span>Evaluation coverage $($Summary.CoveragePercent)% ($($Summary.Evaluated)/$($Summary.Applicable)); $($Summary.ProblemsDetected) problems detected; $($Summary.Suppressed) suppressed; $($Summary.BlockingErrors) execution errors; $($Summary.Skipped) required checks skipped.</span></div>")
    [void]$sb.AppendLine('<div class="cards">')
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`">$($Summary.Total)</div><div class=`"l`">Checks</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#1a7f37`">$($Summary.Pass)</div><div class=`"l`">Pass ($passRate%)</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#cf222e`">$($Summary.Fail)</div><div class=`"l`">Fail</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#bf8700`">$($Summary.Warning)</div><div class=`"l`">Warning</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#6e7781`">$($Summary.Suppressed)</div><div class=`"l`">Suppressed</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#8b949e`">$($Summary.NotEvaluated)</div><div class=`"l`">Not evaluated</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#cf222e`">$($Summary.BlockingErrors)</div><div class=`"l`">Execution errors</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#cf222e`">$($Summary.Critical)</div><div class=`"l`">Critical</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#d1242f`">$($Summary.High)</div><div class=`"l`">High</div></div>")
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<h2>Problems detected</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Level</th><th>Service</th><th>Check</th><th>Status</th><th>Severity</th><th>Categories</th><th>Controls</th><th>Detail</th><th>Recommendation</th></tr></thead><tbody>')
    [void]$sb.AppendLine($problemRowsHtml)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Suppressed findings</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Level</th><th>Service</th><th>Check</th><th>Status</th><th>Severity</th><th>Categories</th><th>Controls</th><th>Detail / exception</th><th>Recommendation</th></tr></thead><tbody>')
    [void]$sb.AppendLine($suppressedRowsHtml)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Execution errors blocking evaluation</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Level</th><th>Service</th><th>Check</th><th>Status</th><th>Severity</th><th>Categories</th><th>Controls</th><th>Detail / diagnostic</th><th>Recovery</th></tr></thead><tbody>')
    [void]$sb.AppendLine($errorRowsHtml)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Not evaluated</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Level</th><th>Service</th><th>Check</th><th>Status</th><th>Severity</th><th>Categories</th><th>Controls</th><th>Reason</th><th>Recommendation</th></tr></thead><tbody>')
    [void]$sb.AppendLine($skippedRowsHtml)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Service coverage</h2><div class="table-wrap"><table><thead><tr><th>Service</th><th>Outcome</th><th>Total</th><th>Pass</th><th>Problems</th><th>Suppressed</th><th>Not evaluated</th><th>Errors</th></tr></thead><tbody>')
    [void]$sb.AppendLine($serviceRows)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Complete results</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Level</th><th>Service</th><th>Check</th><th>Status</th><th>Severity</th><th>Categories</th><th>Controls</th><th>Detail</th><th>Recommendation</th></tr></thead><tbody>')
    [void]$sb.AppendLine($rowsHtml)
    [void]$sb.AppendLine('</tbody></table></div>')
    $safeVersion = ConvertTo-CaHtmlEncoded $Version
    [void]$sb.AppendLine("<footer>Claudit $safeVersion &middot; schema v2 &middot; read-only audit &middot; control IDs are indicative cross-references &middot; verify findings against your own policy before acting.</footer>")
    [void]$sb.AppendLine('</div></body></html>')
    $sb.ToString()
}
