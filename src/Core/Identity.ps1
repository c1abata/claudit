<#
    Identity.ps1 - deterministic, privacy-preserving identifiers.

    CheckId identifies the control. FindingId identifies one control/resource
    instance across runs. DiagnosticId remains unique to one execution error.
#>

function Get-CaSha256Text {
    param([AllowNull()][string]$Text)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Text)
    [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function ConvertTo-CaDeterministicUuid {
    param([Parameter(Mandatory)][string]$Value)

    $chars = (Get-CaSha256Text -Text $Value).Substring(0, 32).ToCharArray()
    $chars[12] = '5'
    $variant = ([Convert]::ToInt32([string]$chars[16], 16) -band 3) -bor 8
    $chars[16] = $variant.ToString('x')[0]
    $hex = -join $chars
    [guid]::ParseExact("$($hex.Substring(0,8))-$($hex.Substring(8,4))-$($hex.Substring(12,4))-$($hex.Substring(16,4))-$($hex.Substring(20,12))", 'D')
}

function Get-CaFindingIdentity {
    param(
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$CheckId,
        [AllowNull()][string]$ScopeId,
        [AllowNull()][string]$ResourceType,
        [AllowNull()][string]$ResourceId
    )

    $canonical = @($Service, $CheckId, $ScopeId, $ResourceType, $ResourceId) |
        ForEach-Object { ([string]$_).Trim().ToLowerInvariant() }
    $hash = Get-CaSha256Text -Text ($canonical -join '|')
    [pscustomobject]@{
        FindingId       = "claudit:$hash"
        ResourceKeyHash = $hash
    }
}

function ConvertTo-CaCanonicalValue {
    param([AllowNull()]$Value)

    if ($null -eq $Value -or $Value -is [string] -or $Value -is [bool] -or
        $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or
        $Value -is [int64] -or $Value -is [decimal] -or $Value -is [double] -or
        $Value -is [single]) { return $Value }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [datetimeoffset]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            $ordered[$key] = ConvertTo-CaCanonicalValue -Value $Value[$key]
        }
        return [pscustomobject]$ordered
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $encoded = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $canonicalItem = ConvertTo-CaCanonicalValue -Value $item
            $encoded.Add([pscustomobject]@{ Json=($canonicalItem | ConvertTo-Json -Depth 20 -Compress); Value=$canonicalItem })
        }
        return ,@($encoded | Sort-Object Json | ForEach-Object { $_.Value })
    }
    $properties = @($Value.PSObject.Properties | Where-Object MemberType -in @('NoteProperty', 'Property') | Sort-Object Name)
    if ($properties.Count -gt 0) {
        $ordered = [ordered]@{}
        foreach ($property in $properties) { $ordered[$property.Name] = ConvertTo-CaCanonicalValue -Value $property.Value }
        return [pscustomobject]$ordered
    }
    return [string]$Value
}

function Get-CaObjectSha256 {
    param([AllowNull()]$Value)
    $canonical = ConvertTo-CaCanonicalValue -Value $Value
    Get-CaSha256Text -Text ($canonical | ConvertTo-Json -Depth 20 -Compress)
}
