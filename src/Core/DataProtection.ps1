<#
    DataProtection.ps1 - output-side leak guards.

    Claudit reads sensitive control planes. Even read-only tooling can leak
    tokens through provider errors, CLI stderr, webhook URLs or raw evidence.
    Keep the guard central and boring: redact at finding/output boundaries.
#>

$script:CaSensitiveFieldPattern = '(?i)(authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?token|api[_-]?key|client[_-]?secret|password|passwd|secret|private[_-]?key|webhook|credential|certificate)'

function Test-CaSensitiveFieldName {
    [CmdletBinding()]
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($Name -match $script:CaSensitiveFieldPattern)
}

function ConvertTo-CaRedactedText {
    [CmdletBinding()]
    param([AllowNull()][string]$Text)

    if ($null -eq $Text) { return $null }
    if ($Text.Length -eq 0) { return '' }

    $out = $Text
    $out = $out -replace '(?i)(Authorization\s*[:=]\s*)(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+', '$1$2 <redacted>'
    $out = $out -replace '(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}', '$1 <redacted>'
    $out = $out -replace '(?i)(https://hooks\.slack\.com/services/)[^\s''"<>]+', '$1<redacted>'
    $out = $out -replace '(?i)(https://[^\s''"<>]*webhook[^\s''"<>]*/)[^\s''"<>]+', '$1<redacted>'
    $out = $out -replace '(?i)([?&](?:access_token|refresh_token|id_token|client_secret|api_key|apikey|token|sig|signature|code|password|secret)=)[^&\s''"<>]+', '$1<redacted>'
    $out = $out -replace '(?i)\b((?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|apikey|api[_-]?token|token|password|secret|private[_-]?key)\s*[:=]\s*)[^\s,;''"<>]+', '$1<redacted>'
    $out = $out -replace '(?i)("(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|apikey|api[_-]?token|token|password|secret|private[_-]?key)"\s*:\s*")[^"]+(")', '$1<redacted>$2'
    $out = $out -replace '\b(AKIA|ASIA)[A-Z0-9]{16}\b', '<redacted:aws-access-key-id>'
    $out = $out -replace '\b(tskey-[A-Za-z0-9_-]{12,})\b', '<redacted:tailscale-token>'
    $out = $out -replace '\b(xox[pbar]-[A-Za-z0-9-]{12,})\b', '<redacted:slack-token>'
    $out = $out -replace '\b(gh[pousr]_[A-Za-z0-9_]{20,})\b', '<redacted:github-token>'

    return $out
}

function ConvertTo-CaCsvSafeText {
    [CmdletBinding()]
    param([AllowNull()][string]$Text)

    $safe = ConvertTo-CaRedactedText -Text $Text
    if ($null -eq $safe -or $safe.Length -eq 0) { return $safe }

    # Excel and similar tools may execute cells beginning with these chars.
    if ($safe -match '^[=+\-@]') { return "'$safe" }
    return $safe
}

function ConvertTo-CaRedactedObject {
    [CmdletBinding()]
    param(
        [AllowNull()]$InputObject,
        [int]$Depth = 0
    )

    if ($null -eq $InputObject) { return $null }
    if ($Depth -gt 12) { return '<redacted:max-depth>' }

    if ($InputObject -is [string]) { return (ConvertTo-CaRedactedText -Text $InputObject) }
    if ($InputObject -is [securestring]) { return '<redacted:secure-string>' }
    if ($InputObject -is [System.ValueType]) { return $InputObject }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $name = [string]$key
            if (Test-CaSensitiveFieldName -Name $name) {
                $copy[$name] = '<redacted>'
            }
            else {
                $copy[$name] = ConvertTo-CaRedactedObject -InputObject $InputObject[$key] -Depth ($Depth + 1)
            }
        }
        return [pscustomobject]$copy
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) {
            $items.Add((ConvertTo-CaRedactedObject -InputObject $item -Depth ($Depth + 1)))
        }
        return @($items)
    }

    $props = @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -in @('NoteProperty', 'Property') })
    if ($props.Count -eq 0) {
        return (ConvertTo-CaRedactedText -Text ([string]$InputObject))
    }

    $copy = [ordered]@{}
    foreach ($prop in $props) {
        if (Test-CaSensitiveFieldName -Name $prop.Name) {
            $copy[$prop.Name] = '<redacted>'
        }
        else {
            $copy[$prop.Name] = ConvertTo-CaRedactedObject -InputObject $prop.Value -Depth ($Depth + 1)
        }
    }
    return [pscustomobject]$copy
}
