<#
    Provenance.ps1 - compact run identity, scope and artifact integrity.
#>

function Get-CaSourceCommit {
    $root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $gitEntry = Join-Path $root '.git'
    if (-not (Test-Path -LiteralPath $gitEntry)) { return '' }
    try {
        $item = Get-Item -LiteralPath $gitEntry -Force
        $gitDirectory = if ($item.PSIsContainer) {
            $item.FullName
        }
        else {
            $pointer = Get-Content -LiteralPath $item.FullName -Raw -ErrorAction Stop
            if ($pointer -notmatch '^gitdir:\s*(.+)\s*$') { return '' }
            [System.IO.Path]::GetFullPath((Join-Path $root $Matches[1]))
        }
        $head = (Get-Content -LiteralPath (Join-Path $gitDirectory 'HEAD') -Raw -ErrorAction Stop).Trim()
        if ($head -match '^ref:\s*(.+)$') {
            $refName = $Matches[1]
            $refPath = Join-Path $gitDirectory ($refName -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            if (Test-Path -LiteralPath $refPath) { return (Get-Content -LiteralPath $refPath -Raw).Trim() }
            $packedPath = Join-Path $gitDirectory 'packed-refs'
            if (Test-Path -LiteralPath $packedPath) {
                $line = Get-Content -LiteralPath $packedPath | Where-Object { $_ -match "^[0-9a-f]{40}\s+$([regex]::Escape($refName))$" } | Select-Object -First 1
                if ($line) { return ($line -split '\s+')[0] }
            }
            return ''
        }
        if ($head -match '^[0-9a-f]{40,64}$') { return $head }
    }
    catch { return '' }
    return ''
}

function Get-CaReportScope {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)][string]$TenantName
    )

    $services = @($Findings.Service | Sort-Object -Unique)
    $providerScopes = [ordered]@{}
    foreach ($provider in @('Azure', 'AWS', 'GCP', 'Tailscale', 'Domain', 'VPS', 'Inventory')) {
        $include = $services -contains $provider
        if (-not $include) { continue }
        try { $providerScopes[$provider] = Get-CaProviderOption -Provider $provider }
        catch { }
    }
    $levels = @($Findings.ControlLevel | Sort-Object -Unique)
    [pscustomobject]@{
        TenantName    = ConvertTo-CaRedactedText -Text $TenantName
        Services      = $services
        ControlLevels = $levels
        Providers     = [pscustomobject]$providerScopes
    }
}

function Get-CaReportCompleteness {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [string[]]$ExpectedService = @(),
        [AllowEmptyString()][string]$ExpectedControlLevel = ''
    )

    $levelRank = @{ Formal=1; Passive=2; Active=3 }
    $services = if ($ExpectedService.Count -gt 0) {
        @(Resolve-CaServices -Service $ExpectedService)
    }
    else {
        @($Findings.Service | Sort-Object -Unique)
    }

    @($services | ForEach-Object {
        $service = [string]$_
        $items = @($Findings | Where-Object Service -eq $service)
        $controlLevel = if (-not [string]::IsNullOrWhiteSpace($ExpectedControlLevel)) {
            $ExpectedControlLevel
        }
        else {
            $observedLevels = @($items.ControlLevel | Where-Object { $_ -in $levelRank.Keys })
            if ($observedLevels.Count -eq 0) {
                'Passive'
            }
            else {
                @($observedLevels | Sort-Object { $levelRank[$_] } -Descending)[0]
            }
        }
        $expectedIds = @(Get-CaExpectedCheckIds -Service $service -ControlLevel $controlLevel)
        $collectorItems = @($items | Where-Object FailureCode -ne 'MissingControlResult')
        $returnedIds = @($collectorItems.CheckId | Sort-Object -Unique)
        $missingIds = @($expectedIds | Where-Object { $returnedIds -notcontains $_ })
        $errors = @($items | Where-Object Status -eq 'Error').Count
        $skipped = @($items | Where-Object Status -eq 'Skipped').Count
        $notApplicable = @($collectorItems | Where-Object Status -eq 'NotApplicable').Count
        $queried = $collectorItems.Count -
            @($collectorItems | Where-Object Status -eq 'Error').Count -
            @($collectorItems | Where-Object Status -eq 'Skipped').Count
        [pscustomobject]@{
            Service         = $service
            ControlLevel    = $controlLevel
            Expected        = $expectedIds.Count
            Returned        = $collectorItems.Count
            Queried         = $queried
            Evaluated       = $queried - $notApplicable
            NotApplicable   = $notApplicable
            Errors          = $errors
            Skipped         = $skipped
            MissingControls = $missingIds
            Complete        = ($errors -eq 0 -and $skipped -eq 0 -and $missingIds.Count -eq 0)
        }
    })
}

function Get-CaReportProvenance {
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)][string]$TenantName,
        [Parameter(Mandatory)][guid]$RunId,
        [Parameter(Mandatory)][string]$ArtifactManifest,
        [string[]]$ExpectedService = @(),
        [AllowEmptyString()][string]$ExpectedControlLevel = ''
    )

    $root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $root 'Claudit.psd1')
    $dependencyLockPath = Join-Path $root 'config\dependencies.psd1'
    $dependencyLock = Import-PowerShellDataFile -LiteralPath $dependencyLockPath
    $modules = @($dependencyLock.PowerShellModules.Keys | Sort-Object | ForEach-Object {
        $required = [string]$dependencyLock.PowerShellModules[$_]
        $loaded = Get-Module -Name $_ | Select-Object -First 1
        $available = Get-Module -ListAvailable -Name $_ | Where-Object Version -eq ([version]$required) | Select-Object -First 1
        [pscustomobject]@{ Name=$_; RequiredVersion=$required; LoadedVersion=$(if ($loaded) { [string]$loaded.Version } else { '' }); Available=[bool]$available }
    })

    $baselinePath = if ($script:CaBaselinePath) { $script:CaBaselinePath } else { Join-Path $root 'config\baseline.json' }
    $baselineHash = if (Test-Path -LiteralPath $baselinePath -PathType Leaf) { (Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' }
    $started = @($Findings.TimestampUtc | Where-Object { $_ } | Sort-Object | Select-Object -First 1)
    $completeness = @(Get-CaReportCompleteness -Findings $Findings -ExpectedService $ExpectedService -ExpectedControlLevel $ExpectedControlLevel)

    [pscustomobject]@{
        RunId = $RunId.ToString('D')
        Producer = [pscustomobject]@{
            Name='Claudit'; Version=[string]$manifest.ModuleVersion; Commit=Get-CaSourceCommit
            Project='https://github.com/c1abata/claudit'; ReportSchema='2.0'
        }
        StartedUtc = if ($started.Count) { [string]$started[0] } else { $Summary.GeneratedUtc }
        CompletedUtc = $Summary.GeneratedUtc
        Runtime = [pscustomobject]@{
            PowerShell=[string]$PSVersionTable.PSVersion
            Platform=[System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        }
        Baseline = [pscustomobject]@{ Name=[System.IO.Path]::GetFileName($baselinePath); Sha256=$baselineHash }
        DependencyLock = [pscustomobject]@{
            Version=[string]$dependencyLock.LockVersion
            Sha256=(Get-FileHash -LiteralPath $dependencyLockPath -Algorithm SHA256).Hash.ToLowerInvariant()
            Modules=$modules
        }
        Scope = Get-CaReportScope -Findings $Findings -TenantName $TenantName
        Completeness = $completeness
        ArtifactManifest = $ArtifactManifest
    }
}

function Write-CaArtifactManifest {
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [Parameter(Mandatory)][string]$ManifestPath
    )

    $lines = @($Paths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Sort-Object | ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $([System.IO.Path]::GetFileName($_))"
    })
    Write-CaUtf8FileAtomic -Path $ManifestPath -Content (($lines -join "`n") + "`n")
}
