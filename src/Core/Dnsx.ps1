<#
    Dnsx.ps1 - optional projectdiscovery/dnsx adapter.

    Execution is argv-only through System.Diagnostics.Process: no shell, bounded
    timeout, captured output and deterministic cleanup of the target list.
#>

function Invoke-CaBoundedProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Arguments = @(),
        [ValidateRange(1, 3600)][int]$TimeoutSec = 300,
        [ValidateRange(1024, 10000000)][int]$MaxOutputChars = 400000
    )

    $resolved = Get-Command -Name $Command -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $resolved) {
        return [pscustomobject]@{ Success = $false; ExitCode = $null; TimedOut = $false; Text = ''; Error = "$Command is not installed or not in PATH." }
    }

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $resolved.Source
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add([string]$argument) }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "Failed to start $Command." }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $waitTask = $process.WaitForExitAsync()
        $delayTask = [System.Threading.Tasks.Task]::Delay([TimeSpan]::FromSeconds($TimeoutSec))
        $completed = [System.Threading.Tasks.Task]::WhenAny($waitTask, $delayTask).GetAwaiter().GetResult()
        if ($completed -ne $waitTask) {
            try { $process.Kill($true) } catch {}
            try { $process.WaitForExit() } catch {}
            return [pscustomobject]@{
                Success = $false; ExitCode = $null; TimedOut = $true; Text = ''
                Error = "$Command exceeded the ${TimeoutSec}s timeout and was terminated."
            }
        }
        $waitTask.GetAwaiter().GetResult()
        $stdout = [string]$stdoutTask.GetAwaiter().GetResult()
        $stderr = [string]$stderrTask.GetAwaiter().GetResult()
        if ($stdout.Length -gt $MaxOutputChars) { $stdout = $stdout.Substring(0, $MaxOutputChars) + "`n... output truncated" }
        if ($stderr.Length -gt 8000) { $stderr = $stderr.Substring(0, 8000) + "`n... stderr truncated" }
        return [pscustomobject]@{
            Success = ($process.ExitCode -eq 0)
            ExitCode = $process.ExitCode
            TimedOut = $false
            Text = $stdout
            Error = ConvertTo-CaRedactedText -Text $stderr
        }
    }
    catch {
        return [pscustomobject]@{
            Success = $false; ExitCode = $null; TimedOut = $false; Text = ''
            Error = ConvertTo-CaRedactedText -Text $_.Exception.Message
        }
    }
    finally {
        $process.Dispose()
    }
}

function ConvertFrom-CaDnsxOutput {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($line in @($Text -split '[\r\n]+')) {
        $trimmed = $line.Trim()
        if (-not $trimmed.StartsWith('{')) { continue }
        try { $record = $trimmed | ConvertFrom-Json -ErrorAction Stop }
        catch { continue }
        $domainValue = if ($record.PSObject.Properties.Name -contains 'host') { $record.host }
            elseif ($record.PSObject.Properties.Name -contains 'name') { $record.name }
            else { '' }
        $domain = [string]$domainValue
        if ([string]::IsNullOrWhiteSpace($domain)) { continue }
        $rcodeValue = if ($record.PSObject.Properties.Name -contains 'status_code') { $record.status_code }
            elseif ($record.PSObject.Properties.Name -contains 'rcode') { $record.rcode }
            else { '' }
        $rcode = [string]$rcodeValue
        $rcode = $rcode.ToUpperInvariant()
        $a = @()
        $aaaa = @()
        $cname = @()
        $ns = @()
        $mx = @()
        $txt = @()
        if ($record.PSObject.Properties.Name -contains 'a') { $a = @($record.a | Where-Object { $_ }) }
        if ($record.PSObject.Properties.Name -contains 'aaaa') { $aaaa = @($record.aaaa | Where-Object { $_ }) }
        if ($record.PSObject.Properties.Name -contains 'cname') { $cname = @($record.cname | Where-Object { $_ }) }
        if ($record.PSObject.Properties.Name -contains 'ns') { $ns = @($record.ns | Where-Object { $_ }) }
        if ($record.PSObject.Properties.Name -contains 'mx') { $mx = @($record.mx | Where-Object { $_ }) }
        if ($record.PSObject.Properties.Name -contains 'txt') { $txt = @($record.txt | Where-Object { $_ }) }
        $status = if ($rcode -eq 'NXDOMAIN') { 'nxdomain' }
            elseif ($rcode -in @('SERVFAIL', 'REFUSED')) { 'servfail' }
            elseif ($cname.Count -gt 0 -and ($a.Count + $aaaa.Count) -eq 0) { 'dangling_cname' }
            elseif (($a.Count + $aaaa.Count) -gt 0) { 'ok' }
            else { 'no_records' }
        $rows.Add([pscustomobject]@{
            Domain = $domain.TrimEnd('.').ToLowerInvariant()
            Status = $status
            Rcode = $rcode
            A = $a
            AAAA = $aaaa
            CNAME = $cname
            NS = $ns
            MX = $mx
            TXT = $txt
        })
    }
    return @($rows)
}

function Invoke-CaDnsxQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Domain,
        [string]$Binary = 'dnsx',
        [ValidateRange(1, 10000)][int]$RateLimit = 100,
        [string[]]$Resolvers = @(),
        [ValidateRange(1, 3600)][int]$TimeoutSec = 300
    )

    $targets = @(ConvertTo-CaDomainNameList $Domain)
    if ($targets.Count -eq 0) { throw 'dnsx requires at least one authorized domain.' }
    if (-not (Get-Command -Name $Binary -CommandType Application -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Available = $false; Success = $false; Rows = @(); Error = "$Binary is not installed or not in PATH." }
    }

    $targetFile = [System.IO.Path]::GetTempFileName()
    try {
        $targets | Set-Content -LiteralPath $targetFile -Encoding UTF8
        $arguments = [System.Collections.Generic.List[string]]::new()
        foreach ($value in @('-silent', '-json', '-l', $targetFile, '-rl', [string]$RateLimit, '-retry', '2', '-rcode', 'noerror,nxdomain,servfail,refused')) {
            $arguments.Add($value)
        }
        foreach ($recordType in @('a', 'aaaa', 'cname', 'ns', 'mx', 'txt')) { $arguments.Add("-$recordType") }
        if ($Resolvers.Count -gt 0) {
            $arguments.Add('-r')
            $arguments.Add(($Resolvers -join ','))
        }
        $result = Invoke-CaBoundedProcess -Command $Binary -Arguments @($arguments) -TimeoutSec $TimeoutSec
        $rows = @(ConvertFrom-CaDnsxOutput -Text $result.Text)
        return [pscustomobject]@{
            Available = $true
            Success = $result.Success
            ExitCode = $result.ExitCode
            TimedOut = $result.TimedOut
            Queried = $targets.Count
            Rows = $rows
            Error = $result.Error
        }
    }
    finally {
        Remove-Item -LiteralPath $targetFile -Force -ErrorAction SilentlyContinue
    }
}
