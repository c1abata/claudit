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

    $byStatus = $Findings | Group-Object Status -AsHashTable -AsString
    $get = { param($k) if ($byStatus -and $byStatus.ContainsKey($k)) { @($byStatus[$k]).Count } else { 0 } }

    $fails = $Findings | Where-Object { $_.Status -eq 'Fail' }
    $bySev = $fails | Group-Object Severity -AsHashTable -AsString
    $getSev = { param($k) if ($bySev -and $bySev.ContainsKey($k)) { @($bySev[$k]).Count } else { 0 } }

    $total = $Findings.Count
    $pass = & $get 'Pass'
    $fail = & $get 'Fail'
    $warning = & $get 'Warning'
    $info = & $get 'Info'
    $errorCount = & $get 'Error'
    $skipped = & $get 'Skipped'
    $investigate = & $get 'Investigate'
    $evaluated = $total - $errorCount - $skipped
    $problems = $fail + $warning + $investigate
    $coverage = if ($total -gt 0) { [math]::Round(($evaluated / $total) * 100, 1) } else { 0 }
    $outcome = if ($errorCount -gt 0) {
        'ExecutionError'
    }
    elseif ($fail -gt 0) {
        'IssuesFound'
    }
    elseif (($warning + $investigate) -gt 0) {
        'Attention'
    }
    elseif ($total -gt 0) {
        'Pass'
    }
    else {
        'Empty'
    }
    $serviceSummary = @($Findings | Group-Object Service | ForEach-Object {
        $items = @($_.Group)
        $serviceFail = @($items | Where-Object Status -eq 'Fail').Count
        $serviceWarning = @($items | Where-Object { $_.Status -in @('Warning', 'Investigate') }).Count
        $serviceError = @($items | Where-Object Status -eq 'Error').Count
        [pscustomobject]@{
            Service      = $_.Name
            Outcome      = if ($serviceError) { 'ExecutionError' } elseif ($serviceFail) { 'IssuesFound' } elseif ($serviceWarning) { 'Attention' } else { 'Pass' }
            Total        = $items.Count
            Pass         = @($items | Where-Object Status -eq 'Pass').Count
            Problems     = $serviceFail + $serviceWarning
            NotEvaluated = @($items | Where-Object { $_.Status -in @('Error', 'Skipped') }).Count
            Errors       = $serviceError
        }
    } | Sort-Object Service)

    [pscustomobject]@{
        Outcome      = $outcome
        Total        = $Findings.Count
        Evaluated    = $evaluated
        NotEvaluated = $errorCount + $skipped
        CoveragePercent = $coverage
        ProblemsDetected = $problems
        BlockingErrors = $errorCount
        Pass         = $pass
        Fail         = $fail
        Warning      = $warning
        Info         = $info
        Error        = $errorCount
        Skipped      = $skipped
        Investigate  = $investigate
        Critical     = & $getSev 'Critical'
        High         = & $getSev 'High'
        Medium       = & $getSev 'Medium'
        Low          = & $getSev 'Low'
        RecommendedExitCode = if ($errorCount -gt 0) { 3 } elseif (((& $getSev 'Critical') + (& $getSev 'High')) -gt 0) { 2 } else { 0 }
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

function New-CaReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings,
        [string]$OutputDirectory,
        [ValidateSet('Html', 'Json', 'Markdown', 'Csv', 'All')][string]$Format = 'All',
        [string]$TenantName = 'Cloud tenant'
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

        $stem = New-CaReportStem
        $summary = Get-CaSummary -Findings $all
        $files = @()
        $want = { param($f) $Format -eq 'All' -or $Format -eq $f }
        $safeTenantName = ConvertTo-CaRedactedText -Text $TenantName
        $problems = @(Get-CaSortedFindings -Findings @($all | Where-Object { $_.Status -in @('Fail', 'Warning', 'Investigate') }))
        $executionErrors = @(Get-CaSortedFindings -Findings @($all | Where-Object Status -eq 'Error'))
        $notEvaluated = @(Get-CaSortedFindings -Findings @($all | Where-Object Status -eq 'Skipped'))

        if (& $want 'Json') {
            $jsonPath = Join-Path $OutputDirectory "$stem.json"
            $json = [pscustomobject]@{
                SchemaVersion   = '1.0'
                ReportType      = 'ClauditAudit'
                Tenant          = $safeTenantName
                Summary         = $summary
                Problems        = $problems
                ExecutionErrors = $executionErrors
                NotEvaluated    = $notEvaluated
                Findings        = $all
            } | ConvertTo-Json -Depth 8
            Write-CaUtf8FileAtomic -Path $jsonPath -Content $json
            $files += $jsonPath
        }
        if (& $want 'Html') {
            $htmlPath = Join-Path $OutputDirectory "$stem.html"
            $html = New-CaHtmlBody -Findings $all -Summary $summary -TenantName $safeTenantName
            Write-CaUtf8FileAtomic -Path $htmlPath -Content $html
            $files += $htmlPath
        }
        if (& $want 'Markdown') {
            $mdPath = Join-Path $OutputDirectory "$stem.md"
            $markdown = New-CaMarkdownBody -Findings $all -Summary $summary -TenantName $safeTenantName
            Write-CaUtf8FileAtomic -Path $mdPath -Content $markdown
            $files += $mdPath
        }
        if (& $want 'Csv') {
            $csvPath = Join-Path $OutputDirectory "$stem.csv"
            $csvRows = $all | ForEach-Object {
                [pscustomobject]@{
                    CheckId        = ConvertTo-CaCsvSafeText -Text $_.CheckId
                    ControlLevel   = ConvertTo-CaCsvSafeText -Text $_.ControlLevel
                    Service        = ConvertTo-CaCsvSafeText -Text $_.Service
                    Title          = ConvertTo-CaCsvSafeText -Text $_.Title
                    Status         = ConvertTo-CaCsvSafeText -Text $_.Status
                    Outcome        = ConvertTo-CaCsvSafeText -Text $_.Outcome
                    Severity       = ConvertTo-CaCsvSafeText -Text $_.Severity
                    IsBlocking     = [bool]$_.IsBlocking
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

        [pscustomobject]@{
            Summary = $summary
            Problems = $problems
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
        @{ Expression = { switch ($_.Status) { 'Error' { 5 } 'Fail' { 4 } 'Investigate' { 3 } 'Warning' { 2 } 'Skipped' { 1 } default { 0 } } }; Descending = $true }
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
    [void]$Builder.AppendLine("| ID | Service | Status | Severity | Check | Detail | Recommendation$diagnosticHeader |")
    [void]$Builder.AppendLine("|----|---------|--------|----------|-------|--------|---------------$diagnosticRule|")
    foreach ($f in (Get-CaSortedFindings -Findings $Findings)) {
        $cells = @(
            (ConvertTo-CaMarkdownTableCell -Text $f.CheckId)
            (ConvertTo-CaMarkdownTableCell -Text $f.Service)
            (ConvertTo-CaMarkdownTableCell -Text $f.Status)
            (ConvertTo-CaMarkdownTableCell -Text $f.Severity)
            (ConvertTo-CaMarkdownTableCell -Text $f.Title)
            (ConvertTo-CaMarkdownTableCell -Text $(if ($f.Status -eq 'Skipped' -and $f.SkippedReason) { $f.SkippedReason } else { $f.Detail }))
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
    [void]$sb.AppendLine("**Evaluation coverage:** $($Summary.CoveragePercent)% ($($Summary.Evaluated)/$($Summary.Total))")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("| Problems | Execution errors | Not evaluated | Pass | Critical | High |")
    [void]$sb.AppendLine("|---------:|-----------------:|--------------:|-----:|---------:|-----:|")
    [void]$sb.AppendLine("| $($Summary.ProblemsDetected) | $($Summary.BlockingErrors) | $($Summary.NotEvaluated) | $($Summary.Pass) | $($Summary.Critical) | $($Summary.High) |")
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Problems detected')
    [void]$sb.AppendLine('')
    Add-CaMarkdownFindingTable -Builder $sb -Findings @($Findings | Where-Object { $_.Status -in @('Fail', 'Warning', 'Investigate') })

    [void]$sb.AppendLine('## Execution errors blocking evaluation')
    [void]$sb.AppendLine('')
    Add-CaMarkdownFindingTable -Builder $sb -Findings @($Findings | Where-Object Status -eq 'Error') -IncludeDiagnostics

    [void]$sb.AppendLine('## Not evaluated')
    [void]$sb.AppendLine('')
    Add-CaMarkdownFindingTable -Builder $sb -Findings @($Findings | Where-Object Status -eq 'Skipped')

    [void]$sb.AppendLine('## Service coverage')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Service | Outcome | Total | Pass | Problems | Not evaluated | Errors |')
    [void]$sb.AppendLine('|---------|---------|------:|-----:|---------:|--------------:|-------:|')
    foreach ($service in @($Summary.Services)) {
        [void]$sb.AppendLine("| $(ConvertTo-CaMarkdownTableCell $service.Service) | $(ConvertTo-CaMarkdownTableCell $service.Outcome) | $($service.Total) | $($service.Pass) | $($service.Problems) | $($service.NotEvaluated) | $($service.Errors) |")
    }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Complete results')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("| ID | Level | Service | Status | Severity | Check | Controls | Detail | Recommendation |")
    [void]$sb.AppendLine("|----|-------|---------|--------|----------|-------|----------|--------|----------------|")
    foreach ($f in (Get-CaSortedFindings -Findings $Findings)) {
        $id = ConvertTo-CaMarkdownTableCell -Text $f.CheckId
        $level = ConvertTo-CaMarkdownTableCell -Text $f.ControlLevel
        $svc = ConvertTo-CaMarkdownTableCell -Text $f.Service
        $status = ConvertTo-CaMarkdownTableCell -Text $f.Status
        $severity = ConvertTo-CaMarkdownTableCell -Text $f.Severity
        $title = ConvertTo-CaMarkdownTableCell -Text $f.Title
        $controls = ConvertTo-CaMarkdownTableCell -Text ($f.ControlIds -join ', ')
        $detail = ConvertTo-CaMarkdownTableCell -Text $(if ($f.Status -eq 'Skipped' -and $f.SkippedReason) { $f.SkippedReason } else { $f.Detail })
        $recommendation = ConvertTo-CaMarkdownTableCell -Text $f.Recommendation
        [void]$sb.AppendLine("| $id | $level | $svc | $status | $severity | $title | $controls | $detail | $recommendation |")
    }
    $sb.ToString()
}

function New-CaHtmlBody {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][object]$Summary,
        [string]$TenantName
    )

    $statusColor = @{ Pass = '#1a7f37'; Fail = '#cf222e'; Warning = '#bf8700'; Info = '#0969da'; Error = '#6e7781'; Skipped = '#8b949e'; Investigate = '#8250df' }
    $sevColor    = @{ Critical = '#cf222e'; High = '#d1242f'; Medium = '#bf8700'; Low = '#0969da'; Info = '#6e7781' }

    $rowList = [System.Collections.Generic.List[string]]::new()
    $problemRowList = [System.Collections.Generic.List[string]]::new()
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
        $stat  = ConvertTo-CaHtmlEncoded $f.Status
        $sev   = ConvertTo-CaHtmlEncoded $f.Severity
        $detailText = if ($f.Status -eq 'Skipped' -and $f.SkippedReason) { $f.SkippedReason } else { $f.Detail }
        if ($f.Status -eq 'Error') {
            $detailText = "$detailText [diagnostic $($f.DiagnosticId); $($f.FailureCategory); $($f.FailureCode)]"
        }
        $det   = ConvertTo-CaHtmlEncoded $detailText
        $ctrl  = ConvertTo-CaHtmlEncoded (($f.ControlIds) -join ', ')
        $row = "<tr><td><code>$id</code></td><td>$level</td><td>$svc</td><td>$title</td>" +
               "<td><span class=`"pill`" style=`"background:$sc`">$stat</span></td>" +
               "<td><span class=`"pill`" style=`"background:$vc`">$sev</span></td>" +
               "<td class=`"ctrl`">$ctrl</td><td>$det</td><td>$recCell</td></tr>"
        $rowList.Add($row)
        if ($f.Status -in @('Fail', 'Warning', 'Investigate')) { $problemRowList.Add($row) }
        if ($f.Status -eq 'Error') { $errorRowList.Add($row) }
        if ($f.Status -eq 'Skipped') { $skippedRowList.Add($row) }
    }
    $rowsHtml = $rowList -join "`n"
    $problemRowsHtml = if ($problemRowList.Count) { $problemRowList -join "`n" } else { '<tr><td colspan="9" class="empty">No audit problems detected.</td></tr>' }
    $errorRowsHtml = if ($errorRowList.Count) { $errorRowList -join "`n" } else { '<tr><td colspan="9" class="empty">No execution errors blocked evaluation.</td></tr>' }
    $skippedRowsHtml = if ($skippedRowList.Count) { $skippedRowList -join "`n" } else { '<tr><td colspan="9" class="empty">No controls were intentionally skipped.</td></tr>' }

    $serviceRows = @($Summary.Services | ForEach-Object {
        $service = ConvertTo-CaHtmlEncoded $_.Service
        $outcome = ConvertTo-CaHtmlEncoded $_.Outcome
        "<tr><td>$service</td><td>$outcome</td><td>$($_.Total)</td><td>$($_.Pass)</td><td>$($_.Problems)</td><td>$($_.NotEvaluated)</td><td>$($_.Errors)</td></tr>"
    }) -join "`n"

    $passRate = if ($Summary.Evaluated -gt 0) { [math]::Round((($Summary.Pass) / $Summary.Evaluated) * 100, 1) } else { 0 }
    $tenant = ConvertTo-CaHtmlEncoded $TenantName
    $gen = ConvertTo-CaHtmlEncoded $Summary.GeneratedUtc
    $outcome = ConvertTo-CaHtmlEncoded $Summary.Outcome
    $outcomeClass = switch ($Summary.Outcome) { 'ExecutionError' { 'error' } 'IssuesFound' { 'fail' } 'Attention' { 'warning' } default { 'pass' } }

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
    [void]$sb.AppendLine("<div class=`"outcome $outcomeClass`"><strong>Overall outcome: $outcome</strong><span>Evaluation coverage $($Summary.CoveragePercent)% ($($Summary.Evaluated)/$($Summary.Total)); $($Summary.ProblemsDetected) problems detected; $($Summary.BlockingErrors) execution errors.</span></div>")
    [void]$sb.AppendLine('<div class="cards">')
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`">$($Summary.Total)</div><div class=`"l`">Checks</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#1a7f37`">$($Summary.Pass)</div><div class=`"l`">Pass ($passRate%)</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#cf222e`">$($Summary.Fail)</div><div class=`"l`">Fail</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#bf8700`">$($Summary.Warning)</div><div class=`"l`">Warning</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#8b949e`">$($Summary.NotEvaluated)</div><div class=`"l`">Not evaluated</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#cf222e`">$($Summary.BlockingErrors)</div><div class=`"l`">Execution errors</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#cf222e`">$($Summary.Critical)</div><div class=`"l`">Critical</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"n`" style=`"color:#d1242f`">$($Summary.High)</div><div class=`"l`">High</div></div>")
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<h2>Problems detected</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Level</th><th>Service</th><th>Check</th><th>Status</th><th>Severity</th><th>Controls</th><th>Detail</th><th>Recommendation</th></tr></thead><tbody>')
    [void]$sb.AppendLine($problemRowsHtml)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Execution errors blocking evaluation</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Level</th><th>Service</th><th>Check</th><th>Status</th><th>Severity</th><th>Controls</th><th>Detail / diagnostic</th><th>Recovery</th></tr></thead><tbody>')
    [void]$sb.AppendLine($errorRowsHtml)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Not evaluated</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Level</th><th>Service</th><th>Check</th><th>Status</th><th>Severity</th><th>Controls</th><th>Reason</th><th>Recommendation</th></tr></thead><tbody>')
    [void]$sb.AppendLine($skippedRowsHtml)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Service coverage</h2><div class="table-wrap"><table><thead><tr><th>Service</th><th>Outcome</th><th>Total</th><th>Pass</th><th>Problems</th><th>Not evaluated</th><th>Errors</th></tr></thead><tbody>')
    [void]$sb.AppendLine($serviceRows)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<h2>Complete results</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Level</th><th>Service</th><th>Check</th><th>Status</th><th>Severity</th><th>Controls</th><th>Detail</th><th>Recommendation</th></tr></thead><tbody>')
    [void]$sb.AppendLine($rowsHtml)
    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine('<footer>Claudit 0.1 &middot; read-only audit &middot; control IDs are an indicative cross-reference &middot; verify findings against your own policy before acting.</footer>')
    [void]$sb.AppendLine('</div></body></html>')
    $sb.ToString()
}
