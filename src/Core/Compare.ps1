<#
    Compare.ps1 - configuration drift detection between two audit runs
    (Maester's Compare-MtTestResult pattern).

    Point it at two Claudit JSON reports (a known-good baseline and the latest
    run) to see what changed: regressions (Pass -> Fail), fixes (Fail -> Pass),
    new checks and removed checks. Ideal for a scheduled task that flags drift.
#>

function ConvertTo-CaCompatibleFinding {
    param([Parameter(Mandatory)]$Finding)

    $properties = @($Finding.PSObject.Properties.Name)
    if ('FindingId' -notin $properties -or [string]::IsNullOrWhiteSpace([string]$Finding.FindingId)) {
        $scopeId = if ('ScopeId' -in $properties) { [string]$Finding.ScopeId } else { '' }
        $resourceType = if ('ResourceType' -in $properties) { [string]$Finding.ResourceType } else { '' }
        $resourceId = if ('ResourceId' -in $properties) { [string]$Finding.ResourceId } else { '' }
        $identity = Get-CaFindingIdentity -Service ([string]$Finding.Service) -CheckId ([string]$Finding.CheckId) `
            -ScopeId $scopeId -ResourceType $resourceType -ResourceId $resourceId
        $Finding | Add-Member -NotePropertyName FindingId -NotePropertyValue $identity.FindingId -Force
        $Finding | Add-Member -NotePropertyName ResourceKeyHash -NotePropertyValue $identity.ResourceKeyHash -Force
    }
    if ('EvidenceHash' -notin $properties -or [string]::IsNullOrWhiteSpace([string]$Finding.EvidenceHash)) {
        $evidence = if ('Evidence' -in $properties) { $Finding.Evidence } else { $null }
        $Finding | Add-Member -NotePropertyName EvidenceHash -NotePropertyValue (Get-CaObjectSha256 -Value $evidence) -Force
    }
    if ('IsSuppressed' -notin $properties) {
        $Finding | Add-Member -NotePropertyName IsSuppressed -NotePropertyValue $false -Force
    }
    if ('Suppression' -notin $properties) {
        $Finding | Add-Member -NotePropertyName Suppression -NotePropertyValue $null -Force
    }
    if ('MetadataCatalogVersion' -notin $properties) {
        $metadata = Get-CaCheckMetadata -CheckId ([string]$Finding.CheckId) -AllowUncataloged
        $Finding | Add-Member -NotePropertyName MetadataCatalogVersion -NotePropertyValue ([string]$metadata.CatalogVersion) -Force
        $Finding | Add-Member -NotePropertyName MetadataProfile -NotePropertyValue ([string]$metadata.Profile) -Force
        $Finding | Add-Member -NotePropertyName MetadataSource -NotePropertyValue ([string]$metadata.Source) -Force
        $Finding | Add-Member -NotePropertyName DefaultSeverity -NotePropertyValue ([string]$metadata.DefaultSeverity) -Force
        $Finding | Add-Member -NotePropertyName Categories -NotePropertyValue @($metadata.Categories) -Force
        $Finding | Add-Member -NotePropertyName Threats -NotePropertyValue @($metadata.Threats) -Force
        $Finding | Add-Member -NotePropertyName Risk -NotePropertyValue ([string]$metadata.Risk) -Force
        $Finding | Add-Member -NotePropertyName DependsOn -NotePropertyValue @($metadata.DependsOn) -Force
        $Finding | Add-Member -NotePropertyName RelatedTo -NotePropertyValue @($metadata.RelatedTo) -Force
    }
    return $Finding
}

function Import-CaFindingFile {
    param([Parameter(Mandatory)][string]$Path)
    $doc = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $findings = if ($doc.PSObject.Properties.Name -contains 'Findings') { @($doc.Findings) } else { @($doc) }
    @($findings | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-CaCompatibleFinding -Finding $_ })
}

function Get-CaDriftStatusRank {
    param([AllowNull()][string]$Status)
    switch ($Status) {
        'Pass'          { 0 }
        'Info'          { 0 }
        'NotApplicable' { 0 }
        'Warning'       { 1 }
        'Investigate'   { 2 }
        'Fail'          { 3 }
        'Skipped'       { 4 }
        'Error'         { 5 }
        default         { 2 }
    }
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
    foreach ($f in (Import-CaFindingFile -Path $ReferencePath)) { $ref[$f.FindingId] = $f }
    $cur = @{}
    foreach ($f in (Import-CaFindingFile -Path $DifferencePath)) { $cur[$f.FindingId] = $f }

    $allIds = ($ref.Keys + $cur.Keys) | Sort-Object -Unique

    foreach ($id in $allIds) {
        $old = $ref[$id]; $new = $cur[$id]
        $oldStatus = if ($old) { $old.Status } else { $null }
        $newStatus = if ($new) { $new.Status } else { $null }

        $change =
            if (-not $old) { 'New' }
            elseif (-not $new) { 'Removed' }
            elseif ($oldStatus -eq $newStatus -and $old.EvidenceHash -ne $new.EvidenceHash) { 'EvidenceChanged' }
            elseif ($oldStatus -eq $newStatus) { 'Unchanged' }
            elseif ((Get-CaDriftStatusRank $newStatus) -gt (Get-CaDriftStatusRank $oldStatus)) { 'Regressed' }
            elseif ((Get-CaDriftStatusRank $newStatus) -lt (Get-CaDriftStatusRank $oldStatus)) { 'Fixed' }
            else { 'Changed' }

        [pscustomobject]@{
            PSTypeName = 'Claudit.Drift'
            FindingId  = $id
            CheckId    = if ($new) { $new.CheckId } elseif ($old) { $old.CheckId } else { '' }
            Service    = if ($new) { $new.Service } elseif ($old) { $old.Service } else { '' }
            Title      = if ($new) { $new.Title } elseif ($old) { $old.Title } else { '' }
            Change     = $change
            OldStatus  = $oldStatus
            NewStatus  = $newStatus
            OldEvidenceHash = if ($old) { $old.EvidenceHash } else { '' }
            NewEvidenceHash = if ($new) { $new.EvidenceHash } else { '' }
            Severity   = if ($new) { $new.Severity } elseif ($old) { $old.Severity } else { 'Info' }
        }
    }
}
