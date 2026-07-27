<#
    Dns.ps1 - one cross-platform DNS resolver for Claudit.

    Queries two validating DNS-over-HTTPS resolvers and preserves the DNS RCODE,
    AD bit and backend used. Resolve-DnsName is only a last-resort transport
    fallback. A per-process cache prevents duplicate queries during one audit.
#>

$script:CaDnsQueryCache = @{}
$script:CaDnsResolvers = @(
    'https://cloudflare-dns.com/dns-query',
    'https://dns.google/resolve'
)
$script:CaDnsTypeCodes = @{
    A = 1; NS = 2; CNAME = 5; SOA = 6; PTR = 12; MX = 15; TXT = 16
    AAAA = 28; SRV = 33; DS = 43; DNSKEY = 48; TLSA = 52; CAA = 257
}
$script:CaDnsStatusCodes = @{
    0 = 'NOERROR'; 1 = 'FORMERR'; 2 = 'SERVFAIL'; 3 = 'NXDOMAIN'
    4 = 'NOTIMP'; 5 = 'REFUSED'
}

function Clear-CaDnsQueryCache {
    [CmdletBinding()]
    param()
    $script:CaDnsQueryCache = @{}
}

function Invoke-CaDnsResolverQuery {
    param(
        [Parameter(Mandatory)][string]$Resolver,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Type,
        [ValidateRange(1, 60)][int]$TimeoutSec = 10
    )

    $uri = "$Resolver`?name=$([uri]::EscapeDataString($Name))&type=$Type&do=true&cd=false"
    $response = Invoke-RestMethod -Uri $uri -Headers @{ accept = 'application/dns-json' } `
        -TimeoutSec $TimeoutSec -ErrorAction Stop
    $statusNumber = if ($response.PSObject.Properties.Name -contains 'Status') { [int]$response.Status } else { -1 }
    $status = if ($script:CaDnsStatusCodes.ContainsKey($statusNumber)) {
        $script:CaDnsStatusCodes[$statusNumber]
    }
    else { "RCODE-$statusNumber" }
    $authenticated = ($response.PSObject.Properties.Name -contains 'AD') -and [bool]$response.AD
    $answers = if ($response.PSObject.Properties.Name -contains 'Answer') { @($response.Answer) } else { @() }
    $records = @($answers | Where-Object {
        -not $script:CaDnsTypeCodes.ContainsKey($Type) -or [int]$_.type -eq $script:CaDnsTypeCodes[$Type]
    } | ForEach-Object {
        [pscustomobject]@{
            Name = ([string]$_.name).TrimEnd('.')
            Type = $Type
            TTL  = [int]$_.TTL
            Data = ConvertTo-CaDnsText -Text ([string]$_.data)
        }
    })
    [pscustomobject]@{
        Name=$Name; Type=$Type; Status=$status; StatusCode=$statusNumber
        AuthenticatedData=$authenticated; Records=$records; Resolver=$Resolver; Error=''
    }
}

function Resolve-CaDnsQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]
        [ValidateSet('A', 'AAAA', 'CAA', 'CNAME', 'DNSKEY', 'DS', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TLSA', 'TXT')]
        [string]$Type,
        [ValidateRange(1, 60)][int]$TimeoutSec = 10,
        [switch]$NoCache
    )

    $queryName = $Name.Trim().TrimEnd('.').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($queryName)) { throw 'DNS query name is empty.' }
    $queryType = $Type.ToUpperInvariant()
    $cacheKey = "$queryName|$queryType"
    if (-not $NoCache -and $script:CaDnsQueryCache.ContainsKey($cacheKey)) {
        return $script:CaDnsQueryCache[$cacheKey]
    }

    $errors = [System.Collections.Generic.List[string]]::new()
    $protocolResults = [System.Collections.Generic.List[object]]::new()
    foreach ($resolver in $script:CaDnsResolvers) {
        try {
            $result = Invoke-CaDnsResolverQuery -Resolver $resolver -Name $queryName -Type $queryType -TimeoutSec $TimeoutSec
            if ($result.Status -in @('NOERROR', 'NXDOMAIN')) {
                if (-not $NoCache) { $script:CaDnsQueryCache[$cacheKey] = $result }
                return $result
            }
            $protocolResults.Add($result)
            $errors.Add("${resolver}: $($result.Status)")
        }
        catch {
            $errors.Add("${resolver}: $($_.Exception.Message)")
        }
    }

    if ($protocolResults.Count -gt 0 -and -not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
        $result = $protocolResults[0]
        $result.Error = $errors -join ' | '
        if (-not $NoCache) { $script:CaDnsQueryCache[$cacheKey] = $result }
        return $result
    }

    if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            $records = @(Resolve-DnsName -Name $queryName -Type $queryType -DnsOnly -ErrorAction Stop | ForEach-Object {
                $data = ConvertTo-CaDnsNativeData -Record $_ -Type $queryType
                if (-not [string]::IsNullOrWhiteSpace($data)) {
                    [pscustomobject]@{ Name = $_.Name; Type = $queryType; TTL = $_.TTL; Data = $data }
                }
            })
            $result = [pscustomobject]@{
                Name = $queryName; Type = $queryType; Status = 'NOERROR'; StatusCode = 0
                AuthenticatedData = $false; Records = $records; Resolver = 'Resolve-DnsName'; Error = ''
            }
            if (-not $NoCache) { $script:CaDnsQueryCache[$cacheKey] = $result }
            return $result
        }
        catch {
            $errors.Add("Resolve-DnsName: $($_.Exception.Message)")
        }
    }

    return [pscustomobject]@{
        Name = $queryName; Type = $queryType; Status = 'ERROR'; StatusCode = -1
        AuthenticatedData = $false; Records = @(); Resolver = ''; Error = ($errors -join ' | ')
    }
}

function Resolve-CaDnsRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]
        [ValidateSet('A', 'AAAA', 'CAA', 'CNAME', 'DNSKEY', 'DS', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TLSA', 'TXT')]
        [string]$Type
    )

    $query = Resolve-CaDnsQuery -Name $Name -Type $Type
    if ($query.Status -eq 'ERROR') { throw "DNS query failed for $Name/$Type. $($query.Error)" }
    return @($query.Records)
}

function Resolve-CaDnssecStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    $queryName = $Name.Trim().TrimEnd('.').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($queryName)) { throw 'DNS query name is empty.' }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($resolver in $script:CaDnsResolvers) {
        try { $results.Add((Invoke-CaDnsResolverQuery -Resolver $resolver -Name $queryName -Type SOA)) }
        catch { }
    }
    if ($results.Count -eq 0) { return 'Indeterminate' }

    $healthy = @($results | Where-Object Status -eq 'NOERROR')
    if ($healthy.Count -ne $results.Count) { return 'Indeterminate' }
    $secure = @($healthy | Where-Object AuthenticatedData).Count
    if ($secure -eq $healthy.Count) { return 'Secure' }
    if ($secure -eq 0) { return 'Insecure' }
    return 'Indeterminate'
}

function ConvertTo-CaDnsText {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return (($Text -replace '^"|"$', '') -replace '" "', '')
}

function ConvertTo-CaDnsNativeData {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$Type
    )

    switch ($Type) {
        'TXT'   { if ($Record.Strings) { return ($Record.Strings -join '') } }
        'MX'    { if ($Record.NameExchange) { return "$($Record.Preference) $($Record.NameExchange)" } }
        'NS'    { if ($Record.NameHost) { return [string]$Record.NameHost } }
        'CNAME' { if ($Record.NameHost) { return [string]$Record.NameHost } }
        'PTR'   { if ($Record.NameHost) { return [string]$Record.NameHost } }
        'A'     { if ($Record.IPAddress) { return [string]$Record.IPAddress } }
        'AAAA'  { if ($Record.IPAddress) { return [string]$Record.IPAddress } }
        'CAA'   { if ($Record.Value) { return "$($Record.Flags) $($Record.Tag) $($Record.Value)" } }
        'SOA'   {
            if ($Record.PrimaryServer) {
                return "$($Record.PrimaryServer) $($Record.NameAdministrator) $($Record.SerialNumber) $($Record.RefreshInterval) $($Record.RetryDelay) $($Record.ExpireLimit) $($Record.MinimumTTL)"
            }
        }
        'SRV'   { if ($Record.NameTarget) { return "$($Record.Priority) $($Record.Weight) $($Record.Port) $($Record.NameTarget)" } }
        'DS'    { if ($Record.Digest) { return "$($Record.KeyTag) $($Record.Algorithm) $($Record.DigestType) $($Record.Digest)" } }
    }
    return [string]$Record
}

function Resolve-CaDnsTxt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    @(Resolve-CaDnsRecord -Name $Name -Type TXT | ForEach-Object { $_.Data })
}
