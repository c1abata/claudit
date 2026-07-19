<#
    Dashboard.ps1 - local web cockpit.

    The dashboard is intentionally self-contained: PowerShell TCP listener,
    packaged HTML/CSS/vanilla JS assets, no external runtime and no tenant
    secrets persisted.
    It starts only known Claudit scripts and confines report access to ReportRoot.
#>

$script:CaDashboardRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$script:CaDashboardAssetRoot = Join-Path $script:CaDashboardRoot 'web\assets'
$script:CaDashboardOperations = @{}
$script:CaDashboardMaxHeaderBytes = 16384
$script:CaDashboardMaxBodyBytes = 1048576
$script:CaDashboardIoTimeoutMs = 10000
$script:CaDashboardRetentionCount = 100
$script:CaDashboardStatePath = ''

function New-CaDashboardRequestToken {
    return [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
}

function ConvertTo-CaDashboardJson {
    param([AllowNull()]$InputObject)
    $InputObject | ConvertTo-Json -Depth 10 -Compress
}

function ConvertTo-CaDashboardRelativePath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Root).Path)
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $relative = [System.IO.Path]::GetRelativePath($rootFull, $pathFull)
    return ($relative -replace '\\', '/')
}

function Resolve-CaDashboardSafePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RelativePath
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw 'Missing report path.'
    }

    $rootFull = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Root).Path)
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $RelativePath))
    $prefix = $rootFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($candidate -ne $rootFull -and -not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Report path escapes dashboard report root.'
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Report file not found: $RelativePath"
    }
    return $candidate
}

function Get-CaDashboardContentType {
    param([Parameter(Mandatory)][string]$Path)

    switch ([System.IO.Path]::GetExtension($Path).ToLowerInvariant()) {
        '.html' { 'text/html; charset=utf-8' }
        '.json' { 'application/json; charset=utf-8' }
        '.md'   { 'text/markdown; charset=utf-8' }
        '.csv'  { 'text/csv; charset=utf-8' }
        '.log'  { 'text/plain; charset=utf-8' }
        '.css'  { 'text/css; charset=utf-8' }
        '.js'   { 'text/javascript; charset=utf-8' }
        '.png'  { 'image/png' }
        '.svg'  { 'image/svg+xml' }
        '.ico'  { 'image/x-icon' }
        default { 'application/octet-stream' }
    }
}

function Get-CaDashboardQuery {
    param([Parameter(Mandatory)][uri]$Uri)

    $result = @{}
    $query = $Uri.Query.TrimStart('?')
    if ([string]::IsNullOrWhiteSpace($query)) { return $result }

    foreach ($pair in ($query -split '&')) {
        if ([string]::IsNullOrWhiteSpace($pair)) { continue }
        $parts = $pair -split '=', 2
        $name = [System.Net.WebUtility]::UrlDecode($parts[0])
        $value = if ($parts.Count -gt 1) { [System.Net.WebUtility]::UrlDecode($parts[1]) } else { '' }
        $result[$name] = $value
    }
    return $result
}

function Get-CaDashboardStringList {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [array]) {
        return @($Value | ForEach-Object { Get-CaDashboardStringList $_ } | Where-Object { $_ })
    }
    return @(([string]$Value -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-CaDashboardProperty {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Default = $null
    )

    if ($null -eq $Object) { return $Default }
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $value = $Object.$Name
        if ($null -eq $value) { return $Default }
        return $value
    }
    return $Default
}

function Add-CaDashboardProcessArgument {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Arguments,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Value
    )

    if ($null -eq $Value) { return }
    if ($Value -is [bool]) {
        if ($Value) { $Arguments.Add("-$Name") }
        return
    }
    if ($Value -is [array]) {
        $items = @($Value | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($items.Count -eq 0) { return }
        $Arguments.Add("-$Name")
        $Arguments.Add(($items | ForEach-Object { [string]$_ }) -join ',')
        return
    }
    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return }
    $Arguments.Add("-$Name")
    $Arguments.Add([string]$Value)
}

function Save-CaDashboardOperationMetadata {
    param(
        [Parameter(Mandatory)][object]$Operation,
        [string]$MetadataPath
    )

    if ([string]::IsNullOrWhiteSpace($MetadataPath)) { return }
    try {
        $Operation | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $MetadataPath -Encoding UTF8
    }
    catch {
        Write-Warning "Cannot update dashboard operation metadata '$MetadataPath': $($_.Exception.Message)"
    }
}

function ConvertTo-CaDashboardRetentionCount {
    param(
        [AllowNull()]$Value,
        [ValidateRange(1, 10000)][int]$Default = 100
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $Default }
    $count = 0
    if (-not [int]::TryParse([string]$Value, [ref]$count) -or $count -lt 1 -or $count -gt 10000) {
        throw [System.IO.InvalidDataException]::new('Retention count must be an integer between 1 and 10000 completed runs.')
    }
    return $count
}

function Get-CaDashboardSettings {
    param(
        [string]$StatePath,
        [ValidateRange(1, 10000)][int]$DefaultRetentionCount = 100
    )

    $retentionCount = $DefaultRetentionCount
    if (-not [string]::IsNullOrWhiteSpace($StatePath) -and (Test-Path -LiteralPath $StatePath)) {
        try {
            $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            $retentionCount = ConvertTo-CaDashboardRetentionCount -Value (Get-CaDashboardProperty -Object $state -Name retentionCount) -Default $DefaultRetentionCount
        }
        catch {
            Write-Warning "Cannot read dashboard state '$StatePath'; using retention $DefaultRetentionCount. $($_.Exception.Message)"
        }
    }
    [pscustomobject]@{ RetentionCount = $retentionCount }
}

function Save-CaDashboardSettings {
    param(
        [Parameter(Mandatory)][string]$StatePath,
        [ValidateRange(1, 10000)][int]$RetentionCount
    )

    $directory = Split-Path -Parent $StatePath
    if ([string]::IsNullOrWhiteSpace($directory)) { throw 'Dashboard state path must include a parent directory.' }
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $temporaryPath = Join-Path $directory ('.dashboard-state-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $json = [pscustomobject]@{
            RetentionCount = $RetentionCount
            UpdatedUtc     = [DateTime]::UtcNow.ToString('o')
        } | ConvertTo-Json -Depth 3
        [System.IO.File]::WriteAllText($temporaryPath, $json, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::Move($temporaryPath, $StatePath, $true)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-CaDashboardRetention {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OperationRoot,
        [ValidateRange(1, 10000)][int]$KeepCount
    )

    if (-not (Test-Path -LiteralPath $OperationRoot)) {
        New-Item -ItemType Directory -Path $OperationRoot -Force | Out-Null
    }
    $resolvedRoot = (Resolve-Path -LiteralPath $OperationRoot).Path
    $completed = [System.Collections.Generic.List[object]]::new()
    $runningCount = 0

    foreach ($directory in @(Get-ChildItem -LiteralPath $resolvedRoot -Directory -ErrorAction SilentlyContinue | Where-Object Name -Match '^dashboard-\d{8}-\d{6}-\d{3}-[a-f0-9]{8}$')) {
        $metadataPath = Join-Path $directory.FullName 'metadata.json'
        if (-not (Test-Path -LiteralPath $metadataPath)) { continue }
        try {
            $operation = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            $view = Get-CaDashboardOperationView -Operation $operation -MetadataPath $metadataPath
            if ($view.Status -eq 'Running') {
                $runningCount++
                continue
            }
            $completed.Add([pscustomobject]@{ Directory = $directory; Operation = $view })
        }
        catch {
            Write-Warning "Retention skipped unreadable run '$($directory.Name)': $($_.Exception.Message)"
        }
    }

    $remove = @($completed | Sort-Object { $_.Operation.StartedUtc } -Descending | Select-Object -Skip $KeepCount)
    $removedCount = 0
    foreach ($entry in $remove) {
        $directory = $entry.Directory
        $fullPath = [System.IO.Path]::GetFullPath($directory.FullName)
        $parentPath = [System.IO.Path]::GetFullPath($directory.Parent.FullName)
        if ($parentPath -ne [System.IO.Path]::GetFullPath($resolvedRoot) -or $directory.Name -notmatch '^dashboard-\d{8}-\d{6}-\d{3}-[a-f0-9]{8}$') {
            throw "Retention refused unsafe run path '$fullPath'."
        }
        if ($script:CaDashboardOperations.ContainsKey($entry.Operation.Id)) {
            $tracked = $script:CaDashboardOperations[$entry.Operation.Id].Process
            if ($tracked -and -not $tracked.HasExited) { continue }
            $script:CaDashboardOperations.Remove($entry.Operation.Id)
        }
        Remove-Item -LiteralPath $fullPath -Recurse -Force
        $removedCount++
    }

    [pscustomobject]@{
        KeepCount    = $KeepCount
        Completed    = $completed.Count
        Running      = $runningCount
        Removed      = $removedCount
    }
}

function New-CaDashboardProcessArgumentList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][ValidateSet('preflight', 'safe', 'audit')][string]$Mode,
        [Parameter(Mandatory)][string[]]$Services,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$ScriptPath
    )

    $argList = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)) { $argList.Add($item) }
    Add-CaDashboardProcessArgument -Arguments $argList -Name Service -Value $Services
    Add-CaDashboardProcessArgument -Arguments $argList -Name OutputDirectory -Value $OutputDirectory
    Add-CaDashboardProcessArgument -Arguments $argList -Name BaselinePath -Value (Get-CaDashboardProperty -Object $Request -Name baselinePath)
    Add-CaDashboardProcessArgument -Arguments $argList -Name GraphAuthMode -Value (Get-CaDashboardProperty -Object $Request -Name graphAuthMode -Default 'DeviceCode')
    $authMode = [string](Get-CaDashboardProperty -Object $Request -Name authMode -Default 'Interactive')
    if ($Mode -eq 'preflight') {
        Add-CaDashboardProcessArgument -Arguments $argList -Name AuthMode -Value $authMode
    }
    else {
        Add-CaDashboardProcessArgument -Arguments $argList -Name AppOnly -Value ($authMode -eq 'AppOnly')
    }

    if ($Mode -eq 'preflight') {
        Add-CaDashboardProcessArgument -Arguments $argList -Name JsonOutputPath -Value (Join-Path $OutputDirectory 'preflight.json')
        Add-CaDashboardProcessArgument -Arguments $argList -Name RequirePester -Value ([bool](Get-CaDashboardProperty -Object $Request -Name runPester -Default $false))
    }
    else {
        Add-CaDashboardProcessArgument -Arguments $argList -Name ControlLevel -Value (Get-CaDashboardProperty -Object $Request -Name controlLevel -Default 'Passive')
        Add-CaDashboardProcessArgument -Arguments $argList -Name VpsProbePort -Value @(Get-CaDashboardStringList (Get-CaDashboardProperty -Object $Request -Name vpsProbePort))
        Add-CaDashboardProcessArgument -Arguments $argList -Name ActiveTimeoutMs -Value (Get-CaDashboardProperty -Object $Request -Name activeTimeoutMs -Default 3000)
        Add-CaDashboardProcessArgument -Arguments $argList -Name ConfirmActiveProbes -Value ([bool](Get-CaDashboardProperty -Object $Request -Name confirmActiveProbes -Default $false))
        Add-CaDashboardProcessArgument -Arguments $argList -Name Format -Value (Get-CaDashboardProperty -Object $Request -Name format -Default 'All')
        Add-CaDashboardProcessArgument -Arguments $argList -Name TenantName -Value (Get-CaDashboardProperty -Object $Request -Name tenantName -Default 'Cloud tenant')
        Add-CaDashboardProcessArgument -Arguments $argList -Name Environment -Value (Get-CaDashboardProperty -Object $Request -Name environment -Default 'Global')
        Add-CaDashboardProcessArgument -Arguments $argList -Name ConfirmTenantConnection -Value ($Mode -eq 'audit')
        Add-CaDashboardProcessArgument -Arguments $argList -Name RunPester -Value ([bool](Get-CaDashboardProperty -Object $Request -Name runPester -Default $false))
    }

    Add-CaDashboardProcessArgument -Arguments $argList -Name AzureSubscription -Value (Get-CaDashboardProperty -Object $Request -Name azureSubscription)
    Add-CaDashboardProcessArgument -Arguments $argList -Name AzureTenant -Value (Get-CaDashboardProperty -Object $Request -Name azureTenant)
    Add-CaDashboardProcessArgument -Arguments $argList -Name AwsProfile -Value (Get-CaDashboardProperty -Object $Request -Name awsProfile)
    Add-CaDashboardProcessArgument -Arguments $argList -Name AwsRegion -Value @(Get-CaDashboardStringList (Get-CaDashboardProperty -Object $Request -Name awsRegion))
    Add-CaDashboardProcessArgument -Arguments $argList -Name GcpProject -Value (Get-CaDashboardProperty -Object $Request -Name gcpProject)
    Add-CaDashboardProcessArgument -Arguments $argList -Name GcpAccount -Value (Get-CaDashboardProperty -Object $Request -Name gcpAccount)
    Add-CaDashboardProcessArgument -Arguments $argList -Name GcpOrganization -Value (Get-CaDashboardProperty -Object $Request -Name gcpOrganization)
    Add-CaDashboardProcessArgument -Arguments $argList -Name TailscaleTailnet -Value (Get-CaDashboardProperty -Object $Request -Name tailscaleTailnet)
    Add-CaDashboardProcessArgument -Arguments $argList -Name TailscaleApiTokenEnv -Value (Get-CaDashboardProperty -Object $Request -Name tailscaleApiTokenEnv -Default 'TAILSCALE_API_TOKEN')
    Add-CaDashboardProcessArgument -Arguments $argList -Name TailscaleAuthScheme -Value (Get-CaDashboardProperty -Object $Request -Name tailscaleAuthScheme -Default 'Auto')
    Add-CaDashboardProcessArgument -Arguments $argList -Name Domain -Value @(Get-CaDashboardStringList (Get-CaDashboardProperty -Object $Request -Name domain))
    Add-CaDashboardProcessArgument -Arguments $argList -Name DomainSubdomain -Value @(Get-CaDashboardStringList (Get-CaDashboardProperty -Object $Request -Name domainSubdomain))
    Add-CaDashboardProcessArgument -Arguments $argList -Name VpsTarget -Value (Get-CaDashboardProperty -Object $Request -Name vpsTarget)
    Add-CaDashboardProcessArgument -Arguments $argList -Name VpsSshUser -Value (Get-CaDashboardProperty -Object $Request -Name vpsSshUser)
    Add-CaDashboardProcessArgument -Arguments $argList -Name VpsSshPort -Value (Get-CaDashboardProperty -Object $Request -Name vpsSshPort)
    Add-CaDashboardProcessArgument -Arguments $argList -Name VpsAllowedPublicPort -Value @(Get-CaDashboardStringList (Get-CaDashboardProperty -Object $Request -Name vpsAllowedPublicPort))
    Add-CaDashboardProcessArgument -Arguments $argList -Name CompareWith -Value (Get-CaDashboardProperty -Object $Request -Name compareWith)
    Add-CaDashboardProcessArgument -Arguments $argList -Name TenantId -Value (Get-CaDashboardProperty -Object $Request -Name tenantId)
    Add-CaDashboardProcessArgument -Arguments $argList -Name ClientId -Value (Get-CaDashboardProperty -Object $Request -Name clientId)
    Add-CaDashboardProcessArgument -Arguments $argList -Name CertificateThumbprint -Value (Get-CaDashboardProperty -Object $Request -Name certificateThumbprint)
    Add-CaDashboardProcessArgument -Arguments $argList -Name Organization -Value (Get-CaDashboardProperty -Object $Request -Name organization)

    return $argList
}

function ConvertTo-CaDashboardProcessArgument {
    param([Parameter(Mandatory)][string]$Argument)

    if ($Argument -notmatch '[\s"]') { return $Argument }
    return '"' + ($Argument -replace '"', '\"') + '"'
}

function Get-CaDashboardReportSummary {
    param([Parameter(Mandatory)][string]$Path)

    if ([System.IO.Path]::GetExtension($Path).ToLowerInvariant() -ne '.json') { return $null }
    try {
        $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($json.PSObject.Properties.Name -contains 'Summary') {
            $summary = $json.Summary
            $legacyError = [int](Get-CaDashboardProperty -Object $summary -Name Error -Default 0)
            $legacyFail = [int](Get-CaDashboardProperty -Object $summary -Name Fail -Default 0)
            $legacyWarning = [int](Get-CaDashboardProperty -Object $summary -Name Warning -Default 0)
            $legacyOutcome = if ($legacyError -gt 0) { 'ExecutionError' } elseif ($legacyFail -gt 0) { 'IssuesFound' } elseif ($legacyWarning -gt 0) { 'Attention' } else { 'Pass' }
            return [pscustomobject]@{
                Kind         = 'audit'
                Outcome      = [string](Get-CaDashboardProperty -Object $summary -Name Outcome -Default $legacyOutcome)
                Total        = [int](Get-CaDashboardProperty -Object $summary -Name Total -Default 0)
                Pass         = [int](Get-CaDashboardProperty -Object $summary -Name Pass -Default 0)
                Fail         = [int](Get-CaDashboardProperty -Object $summary -Name Fail -Default 0)
                Warning      = [int](Get-CaDashboardProperty -Object $summary -Name Warning -Default 0)
                Error        = [int](Get-CaDashboardProperty -Object $summary -Name Error -Default 0)
                Problems     = [int](Get-CaDashboardProperty -Object $summary -Name ProblemsDetected -Default ($legacyFail + $legacyWarning))
                NotEvaluated = [int](Get-CaDashboardProperty -Object $summary -Name NotEvaluated -Default $legacyError)
                Coverage     = [double](Get-CaDashboardProperty -Object $summary -Name CoveragePercent -Default 100)
                Critical     = [int](Get-CaDashboardProperty -Object $summary -Name Critical -Default 0)
                High         = [int](Get-CaDashboardProperty -Object $summary -Name High -Default 0)
                GeneratedUtc = [string](Get-CaDashboardProperty -Object $summary -Name GeneratedUtc -Default '')
            }
        }
        if ($json.PSObject.Properties.Name -contains 'Status' -and $json.PSObject.Properties.Name -contains 'Checks') {
            $checks = @($json.Checks)
            return [pscustomobject]@{
                Kind         = 'preflight'
                Status       = [string]$json.Status
                Total        = $checks.Count
                Pass         = @($checks | Where-Object Status -eq 'Pass').Count
                Warning      = @($checks | Where-Object Status -eq 'Warning').Count
                Fail         = @($checks | Where-Object Status -eq 'Fail').Count
                GeneratedUtc = ''
            }
        }
    }
    catch {
        return [pscustomobject]@{ Kind = 'json'; Error = $_.Exception.Message }
    }
    return $null
}

function Get-CaDashboardReportIndex {
    [CmdletBinding()]
    param([string]$ReportRoot = (Join-Path $script:CaDashboardRoot 'reports'))

    if (-not (Test-Path -LiteralPath $ReportRoot)) {
        New-Item -ItemType Directory -Path $ReportRoot -Force | Out-Null
    }
    $resolvedRoot = (Resolve-Path -LiteralPath $ReportRoot).Path
    $extensions = @('.json', '.html', '.md', '.csv')
    $internalNames = @('metadata.json', 'dashboard-state.json')
    $files = @(Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() -and $_.Name -notin $internalNames } |
        Sort-Object LastWriteTimeUtc -Descending)

    foreach ($file in $files) {
        [pscustomobject]@{
            Name         = $file.Name
            Extension    = $file.Extension.TrimStart('.').ToLowerInvariant()
            RelativePath = ConvertTo-CaDashboardRelativePath -Root $resolvedRoot -Path $file.FullName
            Directory    = ConvertTo-CaDashboardRelativePath -Root $resolvedRoot -Path $file.DirectoryName
            SizeBytes    = $file.Length
            LastWriteUtc = $file.LastWriteTimeUtc.ToString('o')
            Summary      = Get-CaDashboardReportSummary -Path $file.FullName
        }
    }
}

function Read-CaDashboardTail {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$LineCount = 240
    )

    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    try {
        $text = (Get-Content -LiteralPath $Path -Tail $LineCount -ErrorAction Stop) -join "`n"
        $ansiPattern = [string][char]27 + '\[[0-?]*[ -/]*[@-~]'
        $text = $text -replace $ansiPattern, ''
        return (ConvertTo-CaRedactedText -Text $text)
    }
    catch {
        return (ConvertTo-CaRedactedText -Text "Cannot read log: $($_.Exception.Message)")
    }
}

function Get-CaDashboardOperationView {
    param(
        [Parameter(Mandatory)][object]$Operation,
        [string]$MetadataPath
    )

    $status = [string]$Operation.Status
    $exitCode = $Operation.ExitCode
    if ($status -eq 'Running' -and $Operation.ProcessId) {
        try {
            $isTracked = $script:CaDashboardOperations.ContainsKey($Operation.Id)
            $proc = if ($isTracked) {
                $script:CaDashboardOperations[$Operation.Id].Process
            } else {
                $null
            }
            if ($proc -and $proc.HasExited) {
                $exitCode = $proc.ExitCode
                $status = if ($exitCode -eq 0) { 'Succeeded' } else { 'Failed' }
            }
            elseif (-not (Get-Process -Id $Operation.ProcessId -ErrorAction SilentlyContinue)) {
                $status = 'Finished'
            }
            elseif (-not $isTracked) {
                $status = 'Finished'
            }
        }
        catch {
            $status = 'Finished'
        }
    }
    if ($status -ne [string]$Operation.Status -or $exitCode -ne $Operation.ExitCode) {
        $Operation.Status = $status
        $Operation.ExitCode = $exitCode
        Save-CaDashboardOperationMetadata -Operation $Operation -MetadataPath $MetadataPath
    }

    [pscustomobject]@{
        Id              = $Operation.Id
        Mode            = $Operation.Mode
        ControlLevel    = [string](Get-CaDashboardProperty -Object $Operation -Name ControlLevel -Default 'Passive')
        RetentionCount  = ConvertTo-CaDashboardRetentionCount -Value (Get-CaDashboardProperty -Object $Operation -Name RetentionCount) -Default $script:CaDashboardRetentionCount
        Status          = $status
        ExitCode        = $exitCode
        ProcessId       = $Operation.ProcessId
        StartedUtc      = $Operation.StartedUtc
        Services        = @($Operation.Services)
        OutputDirectory = $Operation.OutputDirectory
        StdoutPath      = $Operation.StdoutPath
        StderrPath      = $Operation.StderrPath
    }
}

function Get-CaDashboardOperations {
    [CmdletBinding()]
    param([string]$OperationRoot = (Join-Path $script:CaDashboardRoot 'reports\dashboard'))

    if (-not (Test-Path -LiteralPath $OperationRoot)) {
        New-Item -ItemType Directory -Path $OperationRoot -Force | Out-Null
    }

    $ops = [System.Collections.Generic.List[object]]::new()
    foreach ($meta in @(Get-ChildItem -LiteralPath $OperationRoot -Filter 'metadata.json' -Recurse -File -ErrorAction SilentlyContinue)) {
        try {
            $loaded = Get-Content -LiteralPath $meta.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $ops.Add((Get-CaDashboardOperationView -Operation $loaded -MetadataPath $meta.FullName))
        }
        catch {
            $ops.Add([pscustomobject]@{
                Id = $meta.Directory.Name; Mode = 'unknown'; Status = 'Unreadable'
                ExitCode = $null; ProcessId = $null; StartedUtc = $meta.LastWriteTimeUtc.ToString('o')
                Services = @(); OutputDirectory = $meta.Directory.FullName; StdoutPath = ''; StderrPath = ''
            })
        }
    }

    foreach ($id in $script:CaDashboardOperations.Keys) {
        $view = Get-CaDashboardOperationView -Operation $script:CaDashboardOperations[$id].Meta
        if (-not @($ops | Where-Object Id -eq $view.Id)) { $ops.Add($view) }
    }

    @($ops | Sort-Object StartedUtc -Descending)
}

function Start-CaDashboardOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Request,
        [string]$OperationRoot = (Join-Path $script:CaDashboardRoot 'reports\dashboard'),
        [ValidateRange(1, 10000)][int]$RetentionCount = $script:CaDashboardRetentionCount
    )

    $mode = ([string](Get-CaDashboardProperty -Object $Request -Name mode -Default 'preflight')).ToLowerInvariant()
    if ($mode -notin @('preflight', 'safe', 'audit')) {
        throw "Unsupported operation mode '$mode'."
    }
    $controlLevel = [string](Get-CaDashboardProperty -Object $Request -Name controlLevel -Default 'Passive')
    if ($controlLevel -notin @('Formal', 'Passive', 'Active')) {
        throw "Unsupported control level '$controlLevel'."
    }
    if ($controlLevel -eq 'Active' -and -not [bool](Get-CaDashboardProperty -Object $Request -Name confirmActiveProbes -Default $false)) {
        throw 'Active control level requires explicit probe authorization.'
    }

    $services = Resolve-CaServices -Service @(Get-CaDashboardStringList (Get-CaDashboardProperty -Object $Request -Name service -Default @('M365')))
    $runId = 'dashboard-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $runRoot = Join-Path $OperationRoot $runId
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
    $outputDirectory = Join-Path $runRoot 'output'
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

    $scriptName = if ($mode -eq 'preflight') { 'Test-ClauditPreflight.ps1' } else { 'Start-ClauditSafeAudit.ps1' }
    $scriptPath = Join-Path $script:CaDashboardRoot $scriptName

    $argList = New-CaDashboardProcessArgumentList -Request $Request -Mode $mode -Services $services -OutputDirectory $outputDirectory -ScriptPath $scriptPath

    $stdout = Join-Path $runRoot 'stdout.log'
    $stderr = Join-Path $runRoot 'stderr.log'
    $pwsh = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($pwsh) -or -not (Test-Path -LiteralPath $pwsh)) { $pwsh = 'pwsh' }
    $argumentString = (@($argList | ForEach-Object { ConvertTo-CaDashboardProcessArgument $_ }) -join ' ')
    $process = Start-Process -FilePath $pwsh -ArgumentList $argumentString -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru

    $meta = [pscustomobject]@{
        Id              = $runId
        Mode            = $mode
        ControlLevel    = $controlLevel
        RetentionCount  = $RetentionCount
        Status          = 'Running'
        ExitCode        = $null
        ProcessId       = $process.Id
        StartedUtc      = [DateTime]::UtcNow.ToString('o')
        Services        = $services
        OutputDirectory = $outputDirectory
        StdoutPath      = $stdout
        StderrPath      = $stderr
        Command         = $scriptName
        Arguments       = @($argList)
    }
    $meta | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runRoot 'metadata.json') -Encoding UTF8
    $script:CaDashboardOperations[$runId] = [pscustomobject]@{ Meta = $meta; Process = $process }
    Get-CaDashboardOperationView -Operation $meta
}

function Get-CaDashboardHtml {
    param(
        [Parameter(Mandatory)][string]$RequestToken,
        [ValidateRange(1, 10000)][int]$RetentionCount = 100
    )

    $html = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0d1821">
<link rel="icon" type="image/png" href="/assets/icons/logo/favicon.png">
<link rel="stylesheet" href="/assets/dashboard.css">
<script src="/assets/dashboard.js" defer></script>
<title>Claudit Cockpit</title>
</head>
<body data-request-token="__CLAUDIT_REQUEST_TOKEN__">
<div class="shell">
  <aside class="sidebar" aria-label="Primary navigation">
    <div class="brand-row">
      <img class="brand-logo" src="/assets/icons/logo/claudit-logo-96.png" alt="" width="36" height="36">
      <div><p class="brand-name">Claudit</p><div class="brand-mode">Local security cockpit</div></div>
    </div>
    <nav class="nav" role="tablist" aria-label="Cockpit sections">
      <button id="tab-overview" type="button" role="tab" aria-selected="true" aria-controls="overview" data-tab="overview">Overview</button>
      <button id="tab-operations" type="button" role="tab" aria-selected="false" aria-controls="operations" data-tab="operations" tabindex="-1">Operations</button>
      <button id="tab-reports" type="button" role="tab" aria-selected="false" aria-controls="reports" data-tab="reports" tabindex="-1">Reports</button>
    </nav>
    <div class="sidebar-foot">Loopback only · read-only audit controls</div>
  </aside>

  <main class="workspace">
    <div class="workspace-inner">
      <header class="topbar">
        <div>
          <p class="eyebrow">Security operations / local</p>
          <h1>Cloud audit cockpit</h1>
          <p class="topbar-copy">Plan bounded checks, follow execution, and review audit evidence without leaving the local console.</p>
        </div>
        <div id="connectionState" class="connection" data-state="online" role="status" aria-live="polite">
          <span class="connection-dot" aria-hidden="true"></span><span id="serverState">Connected</span>
        </div>
      </header>

      <section id="overview" class="tab" role="tabpanel" aria-labelledby="tab-overview">
        <div class="metrics" aria-label="Audit summary">
          <div class="metric"><div class="metric-value" id="mReports">0</div><div class="metric-label">Report files</div></div>
          <div class="metric"><div class="metric-value" id="mRuns">0</div><div class="metric-label">Operations</div></div>
          <div class="metric" data-tone="accent"><div class="metric-value" id="mRunning">0</div><div class="metric-label">Running</div></div>
          <div class="metric" data-tone="warning"><div class="metric-value" id="mProblems">0</div><div class="metric-label">Latest problems</div></div>
          <div class="metric" data-tone="warning"><div class="metric-value" id="mNotEvaluated">0</div><div class="metric-label">Not evaluated</div></div>
          <div class="metric" data-tone="danger"><div class="metric-value" id="mErrors">0</div><div class="metric-label">Execution errors</div></div>
        </div>

        <div class="dashboard-grid">
          <section class="panel" aria-labelledby="operationPlanTitle">
            <div class="panel-head"><div><h2 id="operationPlanTitle">New operation</h2><p>Scope the audit before any provider connection is opened.</p></div></div>
            <div class="panel-body">
              <div class="config-section">
                <div class="section-title"><h3>1. Execution policy</h3><span>Required</span></div>
                <div class="form-grid compact">
                  <label class="field"><span class="field-label">Mode</span><select id="opMode"><option value="preflight">Offline preflight</option><option value="safe">Guarded launcher</option><option value="audit">Direct read-only audit</option></select></label>
                  <label class="field"><span class="field-label">Control level</span><select id="controlLevel"><option>Formal</option><option selected>Passive</option><option>Active</option></select><span class="hint">Cumulative; Active is bounded and opt-in.</span></label>
                  <label class="field"><span class="field-label">Report format</span><select id="format"><option>All</option><option>Html</option><option>Json</option><option>Markdown</option><option>Csv</option></select></label>
                  <div class="field"><label class="field-label" for="retentionCount">Results to keep</label><div class="input-action"><input id="retentionCount" type="number" min="1" max="10000" list="retentionPresets" value="__CLAUDIT_RETENTION_COUNT__"><button id="saveRetention" type="button">Save</button></div><span class="hint">Completed runs only.</span><datalist id="retentionPresets"><option value="10"><option value="25"><option value="50"><option value="100"><option value="250"><option value="500"><option value="1000"></datalist></div>
                </div>
              </div>

              <div class="config-section">
                <div class="section-title"><h3>2. Audit surface</h3><span>Select one or more</span></div>
                <div id="serviceList" class="services" aria-label="Services"></div>
              </div>

              <details class="details" open>
                <summary>Identity and provider context</summary>
                <div class="details-content">
                  <div class="form-grid">
                    <label class="field"><span class="field-label">Tenant label</span><input id="tenantName" value="Cloud tenant"></label>
                    <label class="field"><span class="field-label">Cloud</span><select id="environment"><option>Global</option><option>USGov</option><option>USGovDOD</option><option>China</option></select></label>
                    <label class="field"><span class="field-label">Run Pester</span><select id="runPester"><option value="false">No</option><option value="true">Yes</option></select></label>
                    <label class="field m365" hidden><span class="field-label">Microsoft auth</span><select id="authMode"><option value="Interactive">Delegated operator</option><option value="AppOnly">App-only certificate</option></select><span class="hint">Client secrets are not used.</span></label>
                    <label class="field m365 delegated" hidden><span class="field-label">Graph auth</span><select id="graphAuthMode"><option>DeviceCode</option><option>Browser</option></select></label>
                    <label class="field m365 apponly" hidden><span class="field-label">Tenant ID</span><input id="tenantId" placeholder="00000000-0000-0000-0000-000000000000"></label>
                    <label class="field m365 apponly" hidden><span class="field-label">Client ID</span><input id="clientId" placeholder="App registration ID"></label>
                    <label class="field m365 apponly" hidden><span class="field-label">Certificate thumbprint</span><input id="certificateThumbprint" placeholder="Local certificate thumbprint"></label>
                    <label class="field m365 apponly" hidden><span class="field-label">Exchange organization</span><input id="organization" placeholder="contoso.onmicrosoft.com"></label>
                    <label class="field azure" hidden><span class="field-label">Azure subscription</span><input id="azureSubscription" placeholder="Optional"></label>
                    <label class="field azure" hidden><span class="field-label">Azure tenant</span><input id="azureTenant" placeholder="Optional"></label>
                    <label class="field aws" hidden><span class="field-label">AWS profile</span><input id="awsProfile" placeholder="Optional"></label>
                    <label class="field aws" hidden><span class="field-label">AWS regions</span><input id="awsRegion" placeholder="eu-west-1, eu-central-1"></label>
                    <label class="field gcp" hidden><span class="field-label">GCP project</span><input id="gcpProject" placeholder="Optional"></label>
                    <label class="field gcp" hidden><span class="field-label">GCP account</span><input id="gcpAccount" placeholder="Optional"></label>
                    <label class="field gcp" hidden><span class="field-label">GCP organization</span><input id="gcpOrganization" placeholder="Optional"></label>
                    <label class="field tailscale" hidden><span class="field-label">Tailscale tailnet</span><input id="tailscaleTailnet" placeholder="example.com"></label>
                    <label class="field tailscale" hidden><span class="field-label">Tailscale token env</span><input id="tailscaleApiTokenEnv" value="TAILSCALE_API_TOKEN"></label>
                    <label class="field tailscale" hidden><span class="field-label">Tailscale auth</span><select id="tailscaleAuthScheme"><option>Auto</option><option>Basic</option><option>Bearer</option></select></label>
                    <label class="field domain wide" hidden><span class="field-label">Authorized domains</span><input id="domain" placeholder="example.com, example.org"><span class="hint">Public checks run only for operator-authorized domains.</span></label>
                    <label class="field domain wide" hidden><span class="field-label">Domain probes</span><input id="domainSubdomain" value="www,autodiscover,mail,vpn,portal,admin,dev,staging"></label>
                    <label class="field vps" hidden><span class="field-label">VPS target</span><input id="vpsTarget" placeholder="Host or user@host; blank = local"></label>
                    <label class="field vps" hidden><span class="field-label">VPS SSH user</span><input id="vpsSshUser" placeholder="Optional"></label>
                    <label class="field vps" hidden><span class="field-label">VPS SSH port</span><input id="vpsSshPort" value="22" inputmode="numeric"></label>
                    <label class="field vps" hidden><span class="field-label">VPS allowed ports</span><input id="vpsAllowedPublicPort" placeholder="80,443"></label>
                    <label class="field active vps" hidden><span class="field-label">Active VPS probe ports</span><input id="vpsProbePort" placeholder="22,443"><span class="hint">Explicit ports only; ranges are rejected.</span></label>
                    <label class="field active" hidden><span class="field-label">Active timeout (ms)</span><input id="activeTimeoutMs" value="3000" inputmode="numeric"></label>
                    <label class="field active" hidden><span class="field-label">Authorize active probes</span><select id="confirmActiveProbes"><option value="false">No</option><option value="true">Yes, targets are authorized</option></select></label>
                  </div>
                </div>
              </details>

              <details class="details">
                <summary>Authentication gates</summary>
                <div class="details-content"><div id="authPlan" class="auth-plan"></div></div>
              </details>

              <div class="action-bar">
                <button class="primary" id="startOp" type="button">Start operation</button>
                <button id="refreshAll" type="button">Refresh</button>
                <span class="action-note">Live authentication prompts appear in the operation log.</span>
              </div>
            </div>
          </section>

          <section class="panel activity-panel" aria-labelledby="activityTitle">
            <div class="panel-head"><div><h2 id="activityTitle">Live activity</h2><p id="logTitle">No operation selected</p></div></div>
            <div class="panel-body">
              <div class="activity-summary">
                <div class="activity-fact"><span>Latest run</span><strong id="latestRun">None</strong></div>
                <div class="activity-fact"><span>Status</span><strong id="latestStatus">Idle</strong></div>
              </div>
              <pre id="logPane" class="log" aria-live="polite">Select an operation to inspect its output.</pre>
            </div>
          </section>
        </div>
      </section>

      <section id="operations" class="tab" role="tabpanel" aria-labelledby="tab-operations" hidden>
        <div class="panel table-panel">
          <div class="panel-head"><div><h2>Operations</h2><p>Execution history and process outcomes.</p></div></div>
          <div class="panel-body"><div class="table-scroll"><table><thead><tr><th>Run</th><th>Mode</th><th>Status</th><th>Services</th><th>Output</th><th>Log</th></tr></thead><tbody id="operationsBody"></tbody></table></div></div>
        </div>
      </section>

      <section id="reports" class="tab" role="tabpanel" aria-labelledby="tab-reports" hidden>
        <div class="panel table-panel">
          <div class="panel-head"><div><h2>Report files</h2><p>Generated evidence, summaries, and exports.</p></div></div>
          <div class="panel-body">
            <div class="table-tools"><input id="reportFilter" aria-label="Filter reports" placeholder="Filter by name, path, status, or service"><button id="reloadReports" type="button">Refresh reports</button></div>
            <div class="table-scroll"><table><thead><tr><th>File</th><th>Type</th><th>Last write</th><th>Signal</th><th>Size</th><th>Open</th></tr></thead><tbody id="reportsBody"></tbody></table></div>
          </div>
        </div>
      </section>
    </div>
  </main>
</div>
<div id="toastRegion" class="toast-region" aria-live="polite" aria-atomic="true"></div>
</body>
</html>
'@
    return $html.Replace('__CLAUDIT_REQUEST_TOKEN__', $RequestToken).Replace('__CLAUDIT_RETENTION_COUNT__', [string]$RetentionCount)
}

function Read-CaDashboardRequest {
    param([Parameter(Mandatory)][System.Net.Sockets.TcpClient]$Client)

    $stream = $Client.GetStream()
    $stream.ReadTimeout = $script:CaDashboardIoTimeoutMs
    $stream.WriteTimeout = $script:CaDashboardIoTimeoutMs

    $headerBytes = [System.Collections.Generic.List[byte]]::new()
    while ($true) {
        $next = $stream.ReadByte()
        if ($next -lt 0) {
            if ($headerBytes.Count -eq 0) { return $null }
            throw [System.IO.InvalidDataException]::new('HTTP headers ended unexpectedly.')
        }
        $headerBytes.Add([byte]$next)
        if ($headerBytes.Count -gt $script:CaDashboardMaxHeaderBytes) {
            throw [System.IO.InvalidDataException]::new("HTTP headers exceed $($script:CaDashboardMaxHeaderBytes) bytes.")
        }
        $count = $headerBytes.Count
        if ($count -ge 4 -and $headerBytes[$count - 4] -eq 13 -and $headerBytes[$count - 3] -eq 10 -and
            $headerBytes[$count - 2] -eq 13 -and $headerBytes[$count - 1] -eq 10) { break }
    }

    $headerArray = $headerBytes.ToArray()
    $headerText = [System.Text.Encoding]::ASCII.GetString($headerArray, 0, $headerArray.Length - 4)
    $lines = @($headerText -split "`r`n")
    if ($lines.Count -eq 0 -or [string]::IsNullOrWhiteSpace($lines[0])) { return $null }
    $parts = $lines[0] -split ' ', 3
    if ($parts.Count -ne 3 -or $parts[2] -notin @('HTTP/1.0', 'HTTP/1.1')) {
        throw [System.IO.InvalidDataException]::new('Malformed HTTP request line.')
    }

    $headers = @{}
    foreach ($line in @($lines | Select-Object -Skip 1)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $kv = $line -split ':', 2
        if ($kv.Count -ne 2 -or [string]::IsNullOrWhiteSpace($kv[0])) {
            throw [System.IO.InvalidDataException]::new('Malformed HTTP header.')
        }
        $name = $kv[0].Trim().ToLowerInvariant()
        if ($headers.ContainsKey($name)) {
            throw [System.IO.InvalidDataException]::new("Duplicate HTTP header '$name'.")
        }
        $headers[$name] = $kv[1].Trim()
    }

    if ($headers.ContainsKey('transfer-encoding')) {
        throw [System.IO.InvalidDataException]::new('Transfer-Encoding is not supported.')
    }

    $length = 0
    if ($headers.ContainsKey('content-length') -and
        (-not [int]::TryParse($headers['content-length'], [ref]$length) -or $length -lt 0)) {
        throw [System.IO.InvalidDataException]::new('Invalid Content-Length header.')
    }
    if ($length -gt $script:CaDashboardMaxBodyBytes) {
        throw [System.IO.InvalidDataException]::new("HTTP body exceeds $($script:CaDashboardMaxBodyBytes) bytes.")
    }

    $body = ''
    if ($length -gt 0) {
        $buffer = [byte[]]::new($length)
        $offset = 0
        while ($offset -lt $length) {
            $read = $stream.Read($buffer, $offset, $length - $offset)
            if ($read -le 0) {
                throw [System.IO.InvalidDataException]::new('HTTP body ended unexpectedly.')
            }
            $offset += $read
        }
        try {
            $body = [System.Text.UTF8Encoding]::new($false, $true).GetString($buffer)
        }
        catch {
            throw [System.IO.InvalidDataException]::new('HTTP body is not valid UTF-8.', $_.Exception)
        }
    }

    $target = $parts[1]
    if (-not $target.StartsWith('/')) {
        throw [System.IO.InvalidDataException]::new('Only origin-form HTTP targets are supported.')
    }
    $uri = [uri]("http://127.0.0.1$target")
    [pscustomobject]@{
        Method  = $parts[0].ToUpperInvariant()
        Version = $parts[2]
        Uri     = $uri
        Path    = $uri.AbsolutePath
        Query   = Get-CaDashboardQuery -Uri $uri
        Headers = $headers
        Body    = $body
        Stream  = $stream
    }
}

function Assert-CaDashboardRequestTrust {
    param(
        [Parameter(Mandatory)]$Request,
        [Parameter(Mandatory)][int]$BoundPort,
        [Parameter(Mandatory)][string]$RequestToken
    )

    if ($Request.Method -notin @('GET', 'POST')) {
        throw [System.UnauthorizedAccessException]::new("HTTP method '$($Request.Method)' is not allowed.")
    }
    if (-not $Request.Headers.ContainsKey('host')) {
        throw [System.UnauthorizedAccessException]::new('Missing Host header.')
    }
    $hostHeader = $Request.Headers['host'].ToLowerInvariant()
    $allowedHosts = @("127.0.0.1:$BoundPort", "localhost:$BoundPort", "[::1]:$BoundPort")
    if ($hostHeader -notin $allowedHosts) {
        throw [System.UnauthorizedAccessException]::new('Host header is not a permitted loopback endpoint.')
    }

    if ($Request.Headers.ContainsKey('sec-fetch-site') -and
        $Request.Headers['sec-fetch-site'].ToLowerInvariant() -notin @('same-origin', 'none')) {
        throw [System.UnauthorizedAccessException]::new('Cross-site dashboard request rejected.')
    }

    if ($Request.Method -eq 'POST') {
        if (-not $Request.Headers.ContainsKey('content-type') -or
            $Request.Headers['content-type'] -notmatch '(?i)^application/json(?:\s*;|$)') {
            throw [System.UnauthorizedAccessException]::new('Dashboard POST requests require application/json.')
        }
        if (-not $Request.Headers.ContainsKey('x-claudit-token') -or
            $Request.Headers['x-claudit-token'] -cne $RequestToken) {
            throw [System.UnauthorizedAccessException]::new('Invalid dashboard request token.')
        }
    }
}

function Send-CaDashboardResponse {
    param(
        [Parameter(Mandatory)][System.Net.Sockets.TcpClient]$Client,
        [int]$StatusCode = 200,
        [string]$Reason = 'OK',
        [string]$ContentType = 'application/json; charset=utf-8',
        [byte[]]$Body = [byte[]]@(),
        [switch]$DashboardDocument
    )

    $stream = $Client.GetStream()
    $resourcePolicy = if ($DashboardDocument) { "'self'" } else { "'none'" }
    $csp = "default-src 'none'; style-src $resourcePolicy; script-src $resourcePolicy; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'"
    $header = "HTTP/1.1 $StatusCode $Reason`r`nContent-Type: $ContentType`r`nContent-Length: $($Body.Length)`r`nCache-Control: no-store`r`nContent-Security-Policy: $csp`r`nCross-Origin-Resource-Policy: same-origin`r`nReferrer-Policy: no-referrer`r`nX-Content-Type-Options: nosniff`r`nX-Frame-Options: DENY`r`nConnection: close`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $stream.Write($headerBytes, 0, $headerBytes.Length)
    if ($Body.Length -gt 0) { $stream.Write($Body, 0, $Body.Length) }
}

function Send-CaDashboardJsonResponse {
    param(
        [Parameter(Mandatory)][System.Net.Sockets.TcpClient]$Client,
        [AllowNull()]$Data,
        [int]$StatusCode = 200,
        [string]$Reason = 'OK'
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-CaDashboardJson $Data))
    Send-CaDashboardResponse -Client $Client -StatusCode $StatusCode -Reason $Reason -ContentType 'application/json; charset=utf-8' -Body $bytes
}

function Invoke-CaDashboardRoute {
    param(
        [Parameter(Mandatory)][System.Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory)]$Request,
        [Parameter(Mandatory)][string]$ReportRoot,
        [Parameter(Mandatory)][string]$OperationRoot,
        [Parameter(Mandatory)][string]$StatePath,
        [Parameter(Mandatory)][string]$RequestToken
    )

    if ($Request.Method -eq 'GET' -and $Request.Path -eq '/') {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes((Get-CaDashboardHtml -RequestToken $RequestToken -RetentionCount $script:CaDashboardRetentionCount))
        Send-CaDashboardResponse -Client $Client -ContentType 'text/html; charset=utf-8' -Body $bytes -DashboardDocument
        return
    }

    if ($Request.Method -eq 'GET' -and $Request.Path.StartsWith('/assets/', [System.StringComparison]::Ordinal)) {
        $relativeAsset = [System.Net.WebUtility]::UrlDecode($Request.Path.Substring('/assets/'.Length))
        $path = Resolve-CaDashboardSafePath -Root $script:CaDashboardAssetRoot -RelativePath $relativeAsset
        $bytes = [System.IO.File]::ReadAllBytes($path)
        Send-CaDashboardResponse -Client $Client -ContentType (Get-CaDashboardContentType -Path $path) -Body $bytes
        return
    }

    if ($Request.Method -eq 'GET' -and $Request.Path -eq '/api/state') {
        $retention = Invoke-CaDashboardRetention -OperationRoot $OperationRoot -KeepCount $script:CaDashboardRetentionCount
        $data = [pscustomobject]@{
            services   = @(Get-CaServiceCatalog)
            authCatalog = @(Get-CaAuthCatalog)
            reports    = @(Get-CaDashboardReportIndex -ReportRoot $ReportRoot)
            operations = @(Get-CaDashboardOperations -OperationRoot $OperationRoot)
            reportRoot = (Resolve-Path -LiteralPath $ReportRoot).Path
            retentionCount = $script:CaDashboardRetentionCount
            retention = $retention
        }
        Send-CaDashboardJsonResponse -Client $Client -Data $data
        return
    }

    if ($Request.Method -eq 'GET' -and $Request.Path -eq '/api/reports') {
        Send-CaDashboardJsonResponse -Client $Client -Data @(Get-CaDashboardReportIndex -ReportRoot $ReportRoot)
        return
    }

    if ($Request.Method -eq 'GET' -and $Request.Path -eq '/api/report') {
        $path = Resolve-CaDashboardSafePath -Root $ReportRoot -RelativePath $Request.Query['path']
        $bytes = [System.IO.File]::ReadAllBytes($path)
        Send-CaDashboardResponse -Client $Client -ContentType (Get-CaDashboardContentType -Path $path) -Body $bytes
        return
    }

    if ($Request.Method -eq 'GET' -and $Request.Path -eq '/api/operations') {
        Send-CaDashboardJsonResponse -Client $Client -Data @(Get-CaDashboardOperations -OperationRoot $OperationRoot)
        return
    }

    if ($Request.Method -eq 'GET' -and $Request.Path -eq '/api/operations/log') {
        $id = $Request.Query['id']
        $op = @(Get-CaDashboardOperations -OperationRoot $OperationRoot | Where-Object Id -eq $id | Select-Object -First 1)
        if (-not $op) { throw "Operation not found: $id" }
        Send-CaDashboardJsonResponse -Client $Client -Data ([pscustomobject]@{
            id     = $id
            stdout = Read-CaDashboardTail -Path $op.StdoutPath
            stderr = Read-CaDashboardTail -Path $op.StderrPath
        })
        return
    }

    if ($Request.Method -eq 'POST' -and $Request.Path -eq '/api/settings') {
        try {
            $body = if ([string]::IsNullOrWhiteSpace($Request.Body)) { [pscustomobject]@{} } else { $Request.Body | ConvertFrom-Json -ErrorAction Stop }
        }
        catch {
            throw [System.IO.InvalidDataException]::new('Request body is not valid JSON.', $_.Exception)
        }
        $retentionCount = ConvertTo-CaDashboardRetentionCount -Value (Get-CaDashboardProperty -Object $body -Name retentionCount) -Default $script:CaDashboardRetentionCount
        Save-CaDashboardSettings -StatePath $StatePath -RetentionCount $retentionCount
        $script:CaDashboardRetentionCount = $retentionCount
        $retention = Invoke-CaDashboardRetention -OperationRoot $OperationRoot -KeepCount $retentionCount
        Send-CaDashboardJsonResponse -Client $Client -Data ([pscustomobject]@{ retentionCount = $retentionCount; retention = $retention })
        return
    }

    if ($Request.Method -eq 'POST' -and $Request.Path -eq '/api/operations') {
        try {
            $body = if ([string]::IsNullOrWhiteSpace($Request.Body)) { [pscustomobject]@{} } else { $Request.Body | ConvertFrom-Json -ErrorAction Stop }
        }
        catch {
            throw [System.IO.InvalidDataException]::new('Request body is not valid JSON.', $_.Exception)
        }
        $retentionCount = ConvertTo-CaDashboardRetentionCount -Value (Get-CaDashboardProperty -Object $body -Name retentionCount) -Default $script:CaDashboardRetentionCount
        Save-CaDashboardSettings -StatePath $StatePath -RetentionCount $retentionCount
        $script:CaDashboardRetentionCount = $retentionCount
        $op = Start-CaDashboardOperation -Request $body -OperationRoot $OperationRoot -RetentionCount $retentionCount
        Invoke-CaDashboardRetention -OperationRoot $OperationRoot -KeepCount $retentionCount | Out-Null
        Send-CaDashboardJsonResponse -Client $Client -Data $op
        return
    }

    Send-CaDashboardJsonResponse -Client $Client -StatusCode 404 -Reason 'Not Found' -Data ([pscustomobject]@{ error = 'Not found' })
}

function Start-CaDashboard {
    [CmdletBinding()]
    param(
        [string]$BindAddress = '127.0.0.1',
        [ValidateRange(1, 65535)][int]$Port = 8765,
        [ValidateRange(0, 100)][int]$PortFallbackCount = 20,
        [string]$ReportRoot = (Join-Path $script:CaDashboardRoot 'reports'),
        [string]$OperationRoot = (Join-Path $script:CaDashboardRoot 'reports\dashboard'),
        [ValidateRange(1, 10000)][int]$RetentionCount = 100,
        [string]$StatePath
    )

    $address = [System.Net.IPAddress]::Parse($BindAddress)
    if (-not [System.Net.IPAddress]::IsLoopback($address)) {
        throw "Claudit dashboard is loopback-only; refusing non-loopback bind address '$BindAddress'."
    }
    if (($Port + $PortFallbackCount) -gt 65535) {
        throw 'Port plus PortFallbackCount must not exceed 65535.'
    }
    $requestToken = New-CaDashboardRequestToken

    if (-not (Test-Path -LiteralPath $ReportRoot)) { New-Item -ItemType Directory -Path $ReportRoot -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $OperationRoot)) { New-Item -ItemType Directory -Path $OperationRoot -Force | Out-Null }
    if ([string]::IsNullOrWhiteSpace($StatePath)) { $StatePath = Join-Path $OperationRoot 'dashboard-state.json' }
    $settings = Get-CaDashboardSettings -StatePath $StatePath -DefaultRetentionCount $RetentionCount
    $script:CaDashboardRetentionCount = $settings.RetentionCount
    $script:CaDashboardStatePath = $StatePath
    Save-CaDashboardSettings -StatePath $StatePath -RetentionCount $script:CaDashboardRetentionCount
    Invoke-CaDashboardRetention -OperationRoot $OperationRoot -KeepCount $script:CaDashboardRetentionCount | Out-Null
    $listener = $null
    $boundPort = $null
    $lastError = $null
    for ($i = 0; $i -le $PortFallbackCount; $i++) {
        $candidatePort = $Port + $i
        try {
            $candidate = [System.Net.Sockets.TcpListener]::new($address, $candidatePort)
            $candidate.Start()
            $listener = $candidate
            $boundPort = $candidatePort
            break
        }
        catch {
            $lastError = $_
            $socketError = $_.Exception
            if ($socketError.InnerException -is [System.Net.Sockets.SocketException]) {
                $socketError = $socketError.InnerException
            }
            $retryableSocketErrors = @(
                [System.Net.Sockets.SocketError]::AddressAlreadyInUse,
                [System.Net.Sockets.SocketError]::AccessDenied
            )
            if ($socketError -isnot [System.Net.Sockets.SocketException] -or
                $socketError.SocketErrorCode -notin $retryableSocketErrors) {
                throw
            }
            Write-Warning "Port $candidatePort cannot be used ($($socketError.SocketErrorCode)); trying $($candidatePort + 1)."
        }
    }
    if (-not $listener) {
        throw "Cannot bind dashboard to $BindAddress starting at port $Port. Last error: $($lastError.Exception.Message)"
    }

    $urlHost = if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { "[$BindAddress]" } else { $BindAddress }
    $listenUrl = "http://$urlHost`:$boundPort/"
    $localUrl = "http://127.0.0.1:$boundPort/"
    Write-Host "Claudit dashboard listening on $listenUrl" -ForegroundColor Cyan
    Write-Host "Local URL: $localUrl" -ForegroundColor Cyan
    Write-Host 'Press Ctrl+C to stop.' -ForegroundColor DarkGray

    try {
        while ($true) {
            $client = $listener.AcceptTcpClient()
            try {
                $request = Read-CaDashboardRequest -Client $client
                if ($null -ne $request) {
                    Assert-CaDashboardRequestTrust -Request $request -BoundPort $boundPort -RequestToken $requestToken
                    Invoke-CaDashboardRoute -Client $client -Request $request -ReportRoot $ReportRoot -OperationRoot $OperationRoot -StatePath $StatePath -RequestToken $requestToken
                }
            }
            catch [System.UnauthorizedAccessException] {
                $message = [pscustomobject]@{ error = ConvertTo-CaRedactedText -Text $_.Exception.Message }
                try { Send-CaDashboardJsonResponse -Client $client -StatusCode 403 -Reason 'Forbidden' -Data $message } catch {}
            }
            catch [System.IO.InvalidDataException] {
                $message = [pscustomobject]@{ error = ConvertTo-CaRedactedText -Text $_.Exception.Message }
                try { Send-CaDashboardJsonResponse -Client $client -StatusCode 400 -Reason 'Bad Request' -Data $message } catch {}
            }
            catch {
                $detail = ConvertTo-CaRedactedText -Text $_.Exception.Message
                Write-Warning "Dashboard request failed: $detail"
                $message = [pscustomobject]@{ error = 'Internal dashboard error. See the local console for details.' }
                try { Send-CaDashboardJsonResponse -Client $client -StatusCode 500 -Reason 'Internal Server Error' -Data $message } catch {}
            }
            finally {
                $client.Close()
            }
        }
    }
    finally {
        $listener.Stop()
    }
}
