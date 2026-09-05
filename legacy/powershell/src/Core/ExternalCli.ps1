<#
    ExternalCli.ps1 - tiny wrappers around provider CLIs.

    AWS and GCP support deliberately uses their official local CLIs. The wrapper
    captures stdout/stderr, checks exit code, and parses JSON centrally so checks
    stay short and auditable.
#>

function ConvertTo-CaStringList {
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
        return @($Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    $items = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
            $items.Add(([string]$item).Trim())
        }
    }
    return @($items)
}

function Assert-CaCliCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Command)

    if (-not (Get-Command -Name $Command -ErrorAction SilentlyContinue)) {
        throw "Required CLI '$Command' was not found in PATH."
    }
}

function Get-CaExternalFailureState {
    param([AllowNull()][string]$Text)

    $signal = [string]$Text
    if ($signal -match '(?i)access.?denied|forbidden|unauthorized|insufficient.?permission|permission.?denied') { return 'Denied' }
    if ($signal -match '(?i)throttl|rate.?limit|too many requests|\b429\b') { return 'RateLimited' }
    if ($signal -match '(?i)timed?\s*out|timeout') { return 'Timeout' }
    if ($signal -match '(?i)could not resolve|name resolution|connection refused|network is unreachable|service unavailable') { return 'Unavailable' }
    return 'Failed'
}

function Invoke-CaExternalCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Arguments = @(),
        [switch]$AllowFailure
    )

    Assert-CaCliCommand -Command $Command
    $output = & $Command @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ConvertTo-CaRedactedText -Text (($output | ForEach-Object { $_.ToString() }) -join "`n")

    $result = [pscustomobject]@{
        Success  = ($exitCode -eq 0)
        State    = if ($exitCode -eq 0) { 'Ok' } else { Get-CaExternalFailureState -Text $text }
        ExitCode = $exitCode
        Text     = $text
    }

    if (-not $result.Success -and -not $AllowFailure) {
        $joined = if ($Arguments) { ConvertTo-CaRedactedText -Text ($Arguments -join ' ') } else { '' }
        throw "$Command $joined failed with exit code $exitCode. $text"
    }
    return $result
}

function Invoke-CaExternalJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Arguments = @(),
        [switch]$AllowFailure
    )

    $result = Invoke-CaExternalCommand -Command $Command -Arguments $Arguments -AllowFailure:$AllowFailure
    $json = $null
    if ($result.Success -and -not [string]::IsNullOrWhiteSpace($result.Text)) {
        try { $json = $result.Text | ConvertFrom-Json -ErrorAction Stop }
        catch {
            $joined = ConvertTo-CaRedactedText -Text ($Arguments -join ' ')
            $message = ConvertTo-CaRedactedText -Text $_.Exception.Message
            if (-not $AllowFailure) {
                throw "$Command returned non-JSON output for '$joined': $message"
            }
            $result.Success = $false
            $result.State = 'Malformed'
            $result.Text = "$Command returned non-JSON output for '$joined': $message"
        }
    }

    if ($AllowFailure) {
        $result | Add-Member -NotePropertyName Json -NotePropertyValue $json
        return $result
    }
    return $json
}
