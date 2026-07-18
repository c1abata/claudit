<#
    Dashboard.ps1 - local web cockpit.

    The dashboard is intentionally self-contained: PowerShell TCP listener,
    HTML/CSS/vanilla JS, no external runtime and no tenant secrets persisted.
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
            return [pscustomobject]@{
                Kind         = 'audit'
                Total        = [int]$json.Summary.Total
                Pass         = [int]$json.Summary.Pass
                Fail         = [int]$json.Summary.Fail
                Warning      = [int]$json.Summary.Warning
                Error        = [int]$json.Summary.Error
                Critical     = [int]$json.Summary.Critical
                High         = [int]$json.Summary.High
                GeneratedUtc = [string]$json.Summary.GeneratedUtc
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
<link rel="icon" type="image/png" href="/assets/icons/logo/favicon.png">
<title>Claudit Cockpit</title>
<style>
:root{--bg:#f4f6f8;--panel:#fff;--ink:#17212b;--muted:#65717f;--line:#d9e0e7;--blue:#2166c2;--green:#16794c;--red:#bc2f34;--amber:#a96900;--violet:#6b4bb8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:14px}
button,input,select,textarea{font:inherit}button{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:6px;padding:8px 11px;cursor:pointer}button.primary{background:var(--blue);border-color:var(--blue);color:#fff}button.danger{border-color:#e2b3b5;color:var(--red)}button:disabled{opacity:.55;cursor:not-allowed}
.app{min-height:100vh;display:grid;grid-template-columns:260px minmax(0,1fr)}.side{background:#101820;color:#e9eef3;padding:18px 16px;border-right:1px solid #0b1117}.brandrow{display:flex;align-items:center;gap:10px}.brandlogo{width:42px;height:42px;object-fit:contain}.brand{font-size:19px;font-weight:700;margin-bottom:3px}.mode{color:#9fb0c1;font-size:12px}.nav{margin-top:26px;display:grid;gap:6px}.nav button{width:100%;text-align:left;background:transparent;border-color:transparent;color:#c9d5df}.nav button.active{background:#1f2d3b;color:#fff;border-color:#2e4257}
.main{padding:18px 22px 28px}.top{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:16px}.top h1{margin:0;font-size:24px;letter-spacing:0}.top p{margin:5px 0 0;color:var(--muted);max-width:820px}.status{display:flex;gap:8px;align-items:center;white-space:nowrap;color:var(--muted);font-size:12px}.dot{width:9px;height:9px;border-radius:50%;background:var(--green)}
.grid{display:grid;gap:14px}.metrics{grid-template-columns:repeat(6,minmax(120px,1fr))}.metric{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}.metric .n{font-size:24px;font-weight:700}.metric .l{font-size:11px;text-transform:uppercase;color:var(--muted);margin-top:3px}
.section{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}.section h2{font-size:15px;margin:0 0 12px}.cols{display:grid;grid-template-columns:1.1fr .9fr;gap:14px;margin-top:14px}.formgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.wide{grid-column:1/-1}label{display:grid;gap:5px;color:var(--muted);font-size:12px}input,select,textarea{width:100%;border:1px solid var(--line);border-radius:6px;padding:8px 9px;background:#fff;color:var(--ink)}textarea{min-height:68px;resize:vertical}.services{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}.check{display:flex;align-items:center;gap:7px;color:var(--ink);font-size:13px}.check input{width:auto}.svcicon{width:20px;height:20px;object-fit:contain;flex:0 0 auto}.actions{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-top:12px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #edf0f3;padding:8px 7px;vertical-align:top}th{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700}td{font-size:13px}.pill{display:inline-block;border-radius:999px;padding:2px 8px;color:#fff;font-size:12px;font-weight:600}.pill.pass,.pill.succeeded{background:var(--green)}.pill.fail,.pill.failed{background:var(--red)}.pill.warning,.pill.finished{background:var(--amber)}.pill.running{background:var(--blue)}.pill.info{background:var(--muted)}
.hint{font-size:12px;color:var(--muted);margin-top:4px}.authplan{display:grid;gap:8px;margin-top:8px}.gate{border:1px solid var(--line);border-radius:8px;padding:9px;background:#fbfcfd}.gate b{display:block;margin-bottom:2px}.gate small{color:var(--muted)}.gate .meta{margin-top:5px;font-size:12px;color:var(--muted)}
.tools{display:flex;gap:8px;margin-bottom:10px}.tools input{max-width:360px}.link{color:var(--blue);text-decoration:none;font-weight:600}.log{background:#0d1117;color:#dbe7f3;border-radius:8px;padding:12px;min-height:240px;max-height:460px;overflow:auto;white-space:pre-wrap;font:12px Consolas,Monaco,monospace}.muted{color:var(--muted)}.hidden{display:none}.bar{height:7px;background:#e8edf2;border-radius:999px;overflow:hidden}.bar span{display:block;height:100%;background:var(--blue)}
@media(max-width:1050px){.app{grid-template-columns:1fr}.side{position:sticky;top:0;z-index:2}.nav{grid-template-columns:repeat(3,1fr);margin-top:12px}.metrics{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}.formgrid{grid-template-columns:1fr}.services{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brandrow"><img class="brandlogo" src="/assets/icons/logo/claudit-logo-96.png" alt=""><div><div class="brand">Claudit Cockpit</div><div class="mode">local loopback operations console</div></div></div>
    <div class="nav">
      <button class="active" data-tab="overview">Overview</button>
      <button data-tab="operations">Operations</button>
      <button data-tab="reports">Reports</button>
    </div>
  </aside>
  <main class="main">
    <div class="top">
      <div>
        <h1>Audit surface dashboard</h1>
        <p>Run offline preflight, launch guarded formal/passive/active audits, follow logs, and inspect generated evidence files from one local console.</p>
      </div>
      <div class="status"><span class="dot"></span><span id="serverState">connected</span></div>
    </div>

    <section id="overview" class="tab">
      <div class="grid metrics">
        <div class="metric"><div class="n" id="mReports">0</div><div class="l">report files</div></div>
        <div class="metric"><div class="n" id="mRuns">0</div><div class="l">operations</div></div>
        <div class="metric"><div class="n" id="mRunning">0</div><div class="l">running</div></div>
        <div class="metric"><div class="n" id="mFail">0</div><div class="l">latest fail</div></div>
        <div class="metric"><div class="n" id="mHigh">0</div><div class="l">latest high</div></div>
        <div class="metric"><div class="n" id="mCritical">0</div><div class="l">latest critical</div></div>
      </div>
      <div class="cols">
        <div class="section">
          <h2>Operation plan</h2>
          <div class="formgrid">
            <label>Mode<select id="opMode"><option value="preflight">Offline preflight</option><option value="safe">Guarded launcher</option><option value="audit">Direct read-only audit</option></select></label>
            <label>Control level<select id="controlLevel"><option>Formal</option><option selected>Passive</option><option>Active</option></select><div class="hint">Levels are cumulative; Active is bounded and opt-in.</div></label>
            <label>Report format<select id="format"><option>All</option><option>Html</option><option>Json</option><option>Markdown</option><option>Csv</option></select></label>
            <label>Results to keep<input id="retentionCount" type="number" min="1" max="10000" list="retentionPresets" value="__CLAUDIT_RETENTION_COUNT__"><datalist id="retentionPresets"><option value="10"><option value="25"><option value="50"><option value="100"><option value="250"><option value="500"><option value="1000"></datalist><button id="saveRetention" type="button">Apply retention</button><div class="hint">Completed runs; running jobs are never removed.</div></label>
            <label>Tenant label<input id="tenantName" value="Cloud tenant"></label>
            <label class="m365">Microsoft auth<select id="authMode"><option value="Interactive">Delegated operator</option><option value="AppOnly">App-only certificate</option></select><div class="hint">Client secrets are not used.</div></label>
            <label class="m365 delegated">Graph auth<select id="graphAuthMode"><option>DeviceCode</option><option>Browser</option></select></label>
            <label>Cloud<select id="environment"><option>Global</option><option>USGov</option><option>USGovDOD</option><option>China</option></select></label>
            <label>Run Pester<select id="runPester"><option value="false">No</option><option value="true">Yes</option></select></label>
            <div class="wide">
              <label>Services</label>
              <div id="serviceList" class="services"></div>
            </div>
            <label class="m365 apponly">TenantId<input id="tenantId" placeholder="00000000-0000-0000-0000-000000000000"></label>
            <label class="m365 apponly">ClientId<input id="clientId" placeholder="app registration id"></label>
            <label class="m365 apponly">Certificate thumbprint<input id="certificateThumbprint" placeholder="local certificate thumbprint"></label>
            <label class="m365 apponly">Exchange organization<input id="organization" placeholder="contoso.onmicrosoft.com"></label>
            <label class="azure">Azure subscription<input id="azureSubscription" placeholder="optional"></label>
            <label class="azure">Azure tenant<input id="azureTenant" placeholder="optional"></label>
            <label class="aws">AWS profile<input id="awsProfile" placeholder="optional"></label>
            <label class="aws">AWS regions<input id="awsRegion" placeholder="eu-west-1,eu-central-1"></label>
            <label class="gcp">GCP project<input id="gcpProject" placeholder="optional"></label>
            <label class="gcp">GCP account<input id="gcpAccount" placeholder="optional"></label>
            <label class="gcp">GCP organization<input id="gcpOrganization" placeholder="optional"></label>
            <label class="tailscale">Tailscale tailnet<input id="tailscaleTailnet" placeholder="example.com"></label>
            <label class="tailscale">Tailscale token env<input id="tailscaleApiTokenEnv" value="TAILSCALE_API_TOKEN"></label>
            <label class="tailscale">Tailscale auth<select id="tailscaleAuthScheme"><option>Auto</option><option>Basic</option><option>Bearer</option></select></label>
            <label class="domain wide">Authorized domains<input id="domain" placeholder="example.com,example.org"><div class="hint">Public checks run only for authorized domains.</div></label>
            <label class="domain wide">Domain probes<input id="domainSubdomain" value="www,autodiscover,mail,vpn,portal,admin,dev,staging"></label>
            <label class="vps">VPS target<input id="vpsTarget" placeholder="host or user@host; blank = local"></label>
            <label class="vps">VPS SSH user<input id="vpsSshUser" placeholder="optional"></label>
            <label class="vps">VPS SSH port<input id="vpsSshPort" value="22"></label>
            <label class="vps">VPS allowed ports<input id="vpsAllowedPublicPort" placeholder="80,443"></label>
            <label class="active vps">Active VPS probe ports<input id="vpsProbePort" placeholder="22,443"><div class="hint">Explicit ports only; ranges are not accepted.</div></label>
            <label class="active">Active timeout (ms)<input id="activeTimeoutMs" value="3000"></label>
            <label class="active">Authorize active probes<select id="confirmActiveProbes"><option value="false">No</option><option value="true">Yes, targets are authorized</option></select></label>
            <div class="wide">
              <label>Auth gates</label>
              <div id="authPlan" class="authplan"></div>
            </div>
          </div>
          <div class="actions">
            <button class="primary" id="startOp">Start operation</button>
            <button id="refreshAll">Refresh</button>
            <span class="muted">Live mode may require device-code auth in the process log.</span>
          </div>
        </div>
        <div class="section">
          <h2>Latest operation log</h2>
          <pre id="logPane" class="log">No operation selected.</pre>
        </div>
      </div>
    </section>

    <section id="operations" class="tab hidden">
      <div class="section">
        <h2>Operations</h2>
        <table><thead><tr><th>Run</th><th>Mode</th><th>Status</th><th>Services</th><th>Output</th><th>Log</th></tr></thead><tbody id="operationsBody"></tbody></table>
      </div>
    </section>

    <section id="reports" class="tab hidden">
      <div class="section">
        <h2>Report files</h2>
        <div class="tools"><input id="reportFilter" placeholder="Filter by name, path, status, service"><button id="reloadReports">Reload</button></div>
        <table><thead><tr><th>File</th><th>Type</th><th>Last write</th><th>Signal</th><th>Size</th><th>Open</th></tr></thead><tbody id="reportsBody"></tbody></table>
      </div>
    </section>
  </main>
</div>
<script>
const state={services:[],authCatalog:[],reports:[],operations:[],selectedOperation:null};
const requestToken='__CLAUDIT_REQUEST_TOKEN__';
const qs=s=>document.querySelector(s);
const qsa=s=>Array.from(document.querySelectorAll(s));
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function fmtBytes(n){if(!n)return '0 B';const u=['B','KB','MB','GB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return `${n.toFixed(i?1:0)} ${u[i]}`}
function pill(text){const c=String(text||'info').toLowerCase().replace(/[^a-z0-9_-]/g,'')||'info';return `<span class="pill ${c}">${esc(text||'Info')}</span>`}
function localTime(iso){if(!iso)return '';try{return new Date(iso).toLocaleString()}catch{return iso}}
function selectedServices(){return qsa('.svc:checked').map(x=>x.value)}
function selectedSpecs(){const names=new Set(selectedServices());return state.services.filter(s=>names.has(s.Name))}
function hasProvider(p){return selectedSpecs().some(s=>s.Provider===p)}
function hasService(n){return selectedServices().includes(n)}
const providerIcons={Microsoft365:'/assets/icons/cloud/icons8-azure-1-50.png',Azure:'/assets/icons/cloud/icons8-azure-50.png',AWS:'/assets/icons/cloud/icons8-amazon-aws-50.png',GCP:'/assets/icons/cloud/icons8-google-cloud-50.png',Internet:'/assets/icons/cloud/icons8-cloudflare-50.png',MultiCloud:'/assets/icons/cloud/icons8-cloud-50.png',SaaS:'/assets/icons/cloud/icons8-cloud-50.png',VPS:'/assets/icons/cloud/icons8-cloud-50.png'};
function renderServices(){qs('#serviceList').innerHTML=state.services.map(s=>`<label class="check"><input class="svc" type="checkbox" value="${esc(s.Name)}" ${s.Default?'checked':''}><img class="svcicon" src="${esc(providerIcons[s.Provider]||providerIcons.MultiCloud)}" alt="">${esc(s.Name)}<span class="muted">${esc(s.Provider)}</span></label>`).join('');qsa('.svc').forEach(x=>x.onchange=refreshWizard);refreshWizard()}
function setGroup(cls,show){qsa('.'+cls).forEach(x=>x.classList.toggle('hidden',!show))}
function authMethod(provider){const app=qs('#authMode').value==='AppOnly';if(provider==='Microsoft365')return app?'AppCertificate':(qs('#graphAuthMode').value==='Browser'?'DelegatedBrowser':'DelegatedDeviceCode');if(provider==='Azure')return 'AzCli';if(provider==='AWS')return 'AwsCliProfile';if(provider==='GCP')return 'Gcloud';if(provider==='SaaS')return 'ApiTokenEnv';if(provider==='VPS')return 'LocalOrSsh';if(provider==='Internet')return 'Public';return 'ExistingProviderContexts'}
function methodDescription(provider,method){const hit=state.authCatalog.find(x=>x.Provider===provider&&x.Method===method);return hit?hit.Description:''}
function buildAuthPlan(){const specs=selectedSpecs();const plan=[];if(hasService('Domain'))plan.push({stage:10,name:'Public domain recon',provider:'Internet',method:'Public',services:['Domain'],gate:'Authorized domain scope'});const m365=specs.filter(s=>s.Provider==='Microsoft365').map(s=>s.Name);if(m365.length){const method=authMethod('Microsoft365');plan.push({stage:20,name:'Microsoft 365 credential gate',provider:'Microsoft365',method,services:m365,gate:'Graph/Exchange read-only connection'});plan.push({stage:30,name:'Microsoft 365 authenticated controls',provider:'Microsoft365',method,services:m365,gate:'Connected session'});}for(const p of ['Azure','AWS','GCP','SaaS','VPS','MultiCloud']){const items=specs.filter(s=>s.Provider===p).map(s=>s.Name);if(!items.length)continue;const method=authMethod(p);plan.push({stage:20,name:`${p} credential gate`,provider:p,method,services:items,gate:'CLI/API identity validation'});plan.push({stage:30,name:`${p} authenticated controls`,provider:p,method,services:items,gate:'Provider read-only context'});}return plan.sort((a,b)=>a.stage-b.stage||a.provider.localeCompare(b.provider))}
function renderAuthPlan(){const plan=buildAuthPlan();qs('#authPlan').innerHTML=plan.map(p=>`<div class="gate"><b>${esc(p.stage)}. ${esc(p.name)}</b><small>${esc(p.gate)}</small><div class="meta">${esc(p.provider)} / ${esc(p.method)} / ${esc((p.services||[]).join(', '))}</div><div class="hint">${esc(methodDescription(p.provider,p.method))}</div></div>`).join('')||'<div class="muted">Select at least one service.</div>'}
function refreshWizard(){const m365=hasProvider('Microsoft365');const app=qs('#authMode').value==='AppOnly';const active=qs('#controlLevel').value==='Active';setGroup('m365',m365);setGroup('delegated',m365&&!app);setGroup('apponly',m365&&app);setGroup('azure',hasProvider('Azure'));setGroup('aws',hasProvider('AWS'));setGroup('gcp',hasProvider('GCP'));setGroup('tailscale',hasService('Tailscale'));setGroup('domain',hasService('Domain'));setGroup('vps',hasService('VPS'));setGroup('active',active);qsa('.active.vps').forEach(x=>x.classList.toggle('hidden',!(active&&hasService('VPS'))));renderAuthPlan()}
function reportSignal(r){const s=r.Summary;if(!s)return '<span class="muted">raw file</span>';if(s.Kind==='audit')return `F ${s.Fail||0} / H ${s.High||0} / C ${s.Critical||0}`;if(s.Kind==='preflight')return `${pill(s.Status)} ${s.Fail||0} fail, ${s.Warning||0} warn`;if(s.Error)return 'parse error';return s.Kind}
function latestAudit(){return state.reports.find(r=>r.Summary&&r.Summary.Kind==='audit')}
function renderMetrics(){const latest=latestAudit();qs('#mReports').textContent=state.reports.length;qs('#mRuns').textContent=state.operations.length;qs('#mRunning').textContent=state.operations.filter(o=>o.Status==='Running').length;qs('#mFail').textContent=latest?.Summary?.Fail||0;qs('#mHigh').textContent=latest?.Summary?.High||0;qs('#mCritical').textContent=latest?.Summary?.Critical||0}
function renderOperations(){qs('#operationsBody').innerHTML=state.operations.map(o=>`<tr><td><strong>${esc(o.Id)}</strong><br><span class="muted">${esc(localTime(o.StartedUtc))}</span></td><td>${esc(o.Mode)} / ${esc(o.ControlLevel||'Passive')}</td><td>${pill(o.Status)} ${o.ExitCode!==null&&o.ExitCode!==undefined?'code '+esc(o.ExitCode):''}</td><td>${esc((o.Services||[]).join(', '))}</td><td><span class="muted">${esc(o.OutputDirectory||'')}</span></td><td><button data-log="${esc(o.Id)}">View</button></td></tr>`).join('')||'<tr><td colspan="6" class="muted">No operations yet.</td></tr>';qsa('[data-log]').forEach(b=>b.onclick=()=>loadLog(b.dataset.log))}
function renderReports(){const f=qs('#reportFilter').value.toLowerCase();const rows=state.reports.filter(r=>(r.Name+' '+r.RelativePath+' '+reportSignal(r)).toLowerCase().includes(f));qs('#reportsBody').innerHTML=rows.map(r=>`<tr><td><strong>${esc(r.Name)}</strong><br><span class="muted">${esc(r.RelativePath)}</span></td><td>${esc(r.Extension)}</td><td>${esc(localTime(r.LastWriteUtc))}</td><td>${reportSignal(r)}</td><td>${esc(fmtBytes(r.SizeBytes))}</td><td><a class="link" target="_blank" href="/api/report?path=${encodeURIComponent(r.RelativePath)}">open</a></td></tr>`).join('')||'<tr><td colspan="6" class="muted">No reports found.</td></tr>'}
async function api(path,opts={}){opts.headers={...(opts.headers||{}),'x-claudit-token':requestToken};const res=await fetch(path,opts);if(!res.ok)throw new Error(await res.text());return res.json()}
async function refresh(){try{const s=await api('/api/state');state.services=s.services;state.authCatalog=s.authCatalog||[];state.reports=s.reports;state.operations=s.operations;if(document.activeElement!==qs('#retentionCount'))qs('#retentionCount').value=s.retentionCount||100;if(!qs('#serviceList').children.length)renderServices();refreshWizard();renderMetrics();renderOperations();renderReports();qs('#serverState').textContent='connected'}catch(e){qs('#serverState').textContent=e.message}}
async function loadLog(id){state.selectedOperation=id;const data=await api('/api/operations/log?id='+encodeURIComponent(id));qs('#logPane').textContent=(data.stdout||'')+(data.stderr?'\n\n[stderr]\n'+data.stderr:'')||'No log output yet.'}
async function saveRetention(){await api('/api/settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({retentionCount:Number(qs('#retentionCount').value)})});await refresh()}
async function startOperation(){const body={mode:qs('#opMode').value,retentionCount:Number(qs('#retentionCount').value),controlLevel:qs('#controlLevel').value,confirmActiveProbes:qs('#confirmActiveProbes').value==='true',activeTimeoutMs:qs('#activeTimeoutMs').value,vpsProbePort:qs('#vpsProbePort').value,service:selectedServices(),format:qs('#format').value,tenantName:qs('#tenantName').value,environment:qs('#environment').value,authMode:qs('#authMode').value,graphAuthMode:qs('#graphAuthMode').value,tenantId:qs('#tenantId').value,clientId:qs('#clientId').value,certificateThumbprint:qs('#certificateThumbprint').value,organization:qs('#organization').value,runPester:qs('#runPester').value==='true',azureSubscription:qs('#azureSubscription').value,azureTenant:qs('#azureTenant').value,awsProfile:qs('#awsProfile').value,awsRegion:qs('#awsRegion').value,gcpProject:qs('#gcpProject').value,gcpAccount:qs('#gcpAccount').value,gcpOrganization:qs('#gcpOrganization').value,tailscaleTailnet:qs('#tailscaleTailnet').value,tailscaleApiTokenEnv:qs('#tailscaleApiTokenEnv').value,tailscaleAuthScheme:qs('#tailscaleAuthScheme').value,domain:qs('#domain').value,domainSubdomain:qs('#domainSubdomain').value,vpsTarget:qs('#vpsTarget').value,vpsSshUser:qs('#vpsSshUser').value,vpsSshPort:qs('#vpsSshPort').value,vpsAllowedPublicPort:qs('#vpsAllowedPublicPort').value};const op=await api('/api/operations',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});await refresh();await loadLog(op.Id)}
qsa('.nav button').forEach(b=>b.onclick=()=>{qsa('.nav button').forEach(x=>x.classList.remove('active'));b.classList.add('active');qsa('.tab').forEach(x=>x.classList.add('hidden'));qs('#'+b.dataset.tab).classList.remove('hidden')});
qs('#authMode').onchange=refreshWizard;qs('#graphAuthMode').onchange=refreshWizard;qs('#controlLevel').onchange=refreshWizard;qs('#saveRetention').onclick=()=>saveRetention().catch(e=>alert(e.message));qs('#startOp').onclick=()=>startOperation().catch(e=>alert(e.message));qs('#refreshAll').onclick=refresh;qs('#reloadReports').onclick=refresh;qs('#reportFilter').oninput=renderReports;setInterval(()=>{refresh();if(state.selectedOperation)loadLog(state.selectedOperation).catch(()=>{})},5000);refresh();
</script>
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
    $scriptPolicy = if ($DashboardDocument) { "'unsafe-inline'" } else { "'none'" }
    $csp = "default-src 'none'; style-src 'unsafe-inline'; script-src $scriptPolicy; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
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
