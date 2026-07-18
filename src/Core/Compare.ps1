<#
    Compare.ps1 - configuration drift detection between two audit runs
    (Maester's Compare-MtTestResult pattern).

    Point it at two Claudit JSON reports (a known-good baseline and the latest
    run) to see what changed: regressions (Pass -> Fail), fixes (Fail -> Pass),
    new checks and removed checks. Ideal for a scheduled task that flags drift.
#>

function Import-CaFindingFile {
    param([Parameter(Mandatory)][string]$Path)
    $doc = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($doc.PSObject.Properties.Name -contains 'Findings') { return @($doc.Findings) }
    return @($doc)
}

function Compare-ClauditResult {
    [CmdletBinding()]
    param(
        # Previous/known-good report JSON.
        [Parameter(Mandatory)][string]$ReferencePath,
        # Latest report JSON.
        [Parameter(Mandatory)][string]$DifferencePath
    )

    $ref = @{}
    foreach ($f in (Import-CaFindingFile -Path $ReferencePath)) { $ref[$f.CheckId] = $f }
    $cur = @{}
    foreach ($f in (Import-CaFindingFile -Path $DifferencePath)) { $cur[$f.CheckId] = $f }

    $allIds = ($ref.Keys + $cur.Keys) | Sort-Object -Unique
    $worse = @('Fail', 'Error')

    foreach ($id in $allIds) {
        $old = $ref[$id]; $new = $cur[$id]
        $oldStatus = if ($old) { $old.Status } else { $null }
        $newStatus = if ($new) { $new.Status } else { $null }

        $change =
            if (-not $old) { 'New' }
            elseif (-not $new) { 'Removed' }
            elseif ($oldStatus -eq $newStatus) { 'Unchanged' }
            elseif ($oldStatus -eq 'Pass' -and $newStatus -in $worse) { 'Regressed' }
            elseif ($oldStatus -in $worse -and $newStatus -eq 'Pass') { 'Fixed' }
            else { 'Changed' }

        [pscustomobject]@{
            PSTypeName = 'Claudit.Drift'
            CheckId    = $id
            Service    = if ($new) { $new.Service } elseif ($old) { $old.Service } else { '' }
            Title      = if ($new) { $new.Title } elseif ($old) { $old.Title } else { '' }
            Change     = $change
            OldStatus  = $oldStatus
            NewStatus  = $newStatus
            Severity   = if ($new) { $new.Severity } elseif ($old) { $old.Severity } else { 'Info' }
        }
    }
}
