<#
    Active.ps1 - explicitly authorized, bounded network validation.

    Active controls are cumulative with the normal read-only audit. They only
    touch operator-declared domains and VPS ports. No target discovery, port
    range expansion, crawling, authentication or payload delivery occurs here.
#>

function Resolve-CaActiveProbeHost {
    param([Parameter(Mandatory)][string]$Target)

    $hostName = $Target.Trim()
    if ($hostName.Contains('@')) { $hostName = $hostName.Substring($hostName.LastIndexOf('@') + 1) }
    $hostName = $hostName.Trim('[', ']')
    if ([string]::IsNullOrWhiteSpace($hostName) -or $hostName.StartsWith('-') -or $hostName -match '[\s/\\*?]') {
        throw "Invalid active probe host '$Target'. Use a plain DNS name or IP address."
    }

    $ip = $null
    if ([System.Net.IPAddress]::TryParse($hostName, [ref]$ip)) { return $hostName }
    if ($hostName -notmatch '^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$') {
        throw "Invalid active probe host '$Target'. Use a plain DNS name or IP address."
    }
    return $hostName.ToLowerInvariant()
}

function Invoke-CaTcpProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [ValidateRange(250, 10000)][int]$TimeoutMs = 3000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $task = $client.ConnectAsync($HostName, $Port)
        if (-not $task.Wait($TimeoutMs)) {
            throw [System.TimeoutException]::new("TCP connection timed out after $TimeoutMs ms.")
        }
        [pscustomobject]@{
            HostName  = $HostName
            Port      = $Port
            Reachable = $true
            LatencyMs = [int]$timer.ElapsedMilliseconds
            Error     = ''
        }
    }
    catch {
        $message = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        [pscustomobject]@{
            HostName  = $HostName
            Port      = $Port
            Reachable = $false
            LatencyMs = [int]$timer.ElapsedMilliseconds
            Error     = ConvertTo-CaRedactedText -Text $message
        }
    }
    finally {
        $timer.Stop()
        $client.Dispose()
    }
}

function Invoke-CaTlsProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [ValidateRange(1, 65535)][int]$Port = 443,
        [ValidateRange(250, 10000)][int]$TimeoutMs = 3000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    $stream = $null
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $connect = $client.ConnectAsync($HostName, $Port)
        if (-not $connect.Wait($TimeoutMs)) {
            throw [System.TimeoutException]::new("TCP connection timed out after $TimeoutMs ms.")
        }

        $stream = [System.Net.Security.SslStream]::new($client.GetStream(), $false)
        $handshake = $stream.AuthenticateAsClientAsync($HostName)
        if (-not $handshake.Wait($TimeoutMs)) {
            throw [System.TimeoutException]::new("TLS handshake timed out after $TimeoutMs ms.")
        }
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($stream.RemoteCertificate)
        [pscustomobject]@{
            HostName                = $HostName
            Port                    = $Port
            Valid                   = $true
            Protocol                = [string]$stream.SslProtocol
            Subject                 = $certificate.Subject
            Issuer                  = $certificate.Issuer
            NotAfterUtc             = $certificate.NotAfter.ToUniversalTime().ToString('o')
            CertificateDaysRemaining = [int][Math]::Floor(($certificate.NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalDays)
            LatencyMs               = [int]$timer.ElapsedMilliseconds
            Error                   = ''
        }
    }
    catch {
        $message = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        [pscustomobject]@{
            HostName                = $HostName
            Port                    = $Port
            Valid                   = $false
            Protocol                = ''
            Subject                 = ''
            Issuer                  = ''
            NotAfterUtc             = ''
            CertificateDaysRemaining = $null
            LatencyMs               = [int]$timer.ElapsedMilliseconds
            Error                   = ConvertTo-CaRedactedText -Text $message
        }
    }
    finally {
        $timer.Stop()
        if ($stream) { $stream.Dispose() }
        $client.Dispose()
    }
}

function Test-CaActiveDomainTls {
    param([ValidateRange(250, 10000)][int]$TimeoutMs = 3000)

    Invoke-CaCheck -Service Domain -CheckId 'DOMAIN-008' -Title 'Authorized domain TLS endpoint is valid' -ControlLevel Active -Body {
        $domains = @(Get-CaAuthorizedDomains)
        if ($domains.Count -eq 0) { throw 'Active domain validation requires at least one explicitly authorized domain.' }
        if ($domains.Count -gt 32) { throw 'Active domain validation is limited to 32 explicitly authorized domains per run.' }

        $evidence = @($domains | ForEach-Object { Invoke-CaTlsProbe -HostName $_ -Port 443 -TimeoutMs $TimeoutMs })
        $failed = @($evidence | Where-Object { -not $_.Valid -or $null -eq $_.CertificateDaysRemaining -or $_.CertificateDaysRemaining -lt 30 })
        if ($failed.Count -eq 0) {
            return New-CaFinding -Service Domain -CheckId 'DOMAIN-008' -Title 'Authorized domain TLS endpoint is valid' `
                -ControlLevel Active -Status Pass -Detail "TLS handshakes succeeded for all $($domains.Count) authorized domain(s); certificates have at least 30 days remaining." -Evidence $evidence
        }

        $names = @($failed | ForEach-Object { $_.HostName })
        New-CaFinding -Service Domain -CheckId 'DOMAIN-008' -Title 'Authorized domain TLS endpoint is valid' `
            -ControlLevel Active -Status Fail -Severity Medium `
            -Detail "TLS validation failed or the certificate expires within 30 days for: $($names -join ', ')." `
            -Recommendation 'Validate DNS routing, certificate trust/name coverage and renewal automation for the affected authorized endpoints.' -Evidence $evidence
    }
}

function Test-CaActiveVpsReachability {
    param(
        [int[]]$Ports,
        [ValidateRange(250, 10000)][int]$TimeoutMs = 3000
    )

    Invoke-CaCheck -Service VPS -CheckId 'VPS-007' -Title 'Declared VPS ports are externally reachable' -ControlLevel Active -Body {
        $target = Get-CaVpsTarget
        if ([string]::IsNullOrWhiteSpace($target) -or -not $Ports -or $Ports.Count -eq 0) {
            return New-CaFinding -Service VPS -CheckId 'VPS-007' -Title 'Declared VPS ports are externally reachable' `
                -ControlLevel Active -Status Skipped `
                -SkippedReason 'Active VPS validation requires both a remote -VpsTarget and explicit -VpsProbePort values.' `
                -Detail 'No implicit target or port discovery is performed.'
        }

        $hostName = Resolve-CaActiveProbeHost -Target $target
        $cleanPorts = @($Ports | ForEach-Object {
            if ($_ -lt 1 -or $_ -gt 65535) { throw "Invalid active VPS port '$_'." }
            [int]$_
        } | Sort-Object -Unique)
        if ($cleanPorts.Count -gt 16) { throw 'Active VPS validation is limited to 16 explicitly declared ports per run.' }

        $evidence = @($cleanPorts | ForEach-Object { Invoke-CaTcpProbe -HostName $hostName -Port $_ -TimeoutMs $TimeoutMs })
        $unreachable = @($evidence | Where-Object { -not $_.Reachable })
        if ($unreachable.Count -eq 0) {
            return New-CaFinding -Service VPS -CheckId 'VPS-007' -Title 'Declared VPS ports are externally reachable' `
                -ControlLevel Active -Status Pass -Detail "All explicitly declared ports are reachable on ${hostName}: $($cleanPorts -join ', ')." -Evidence $evidence
        }

        New-CaFinding -Service VPS -CheckId 'VPS-007' -Title 'Declared VPS ports are externally reachable' `
            -ControlLevel Active -Status Warning -Severity Low `
            -Detail "Declared ports not reachable on ${hostName}: $(@($unreachable | ForEach-Object Port) -join ', ')." `
            -Recommendation 'Confirm whether the service should be public, then inspect cloud security groups, network ACLs, routing and host firewall policy.' -Evidence $evidence
    }
}

function Get-CaActiveFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Service,
        [int[]]$VpsProbePort = @(),
        [ValidateRange(250, 10000)][int]$TimeoutMs = 3000
    )

    $resolved = Resolve-CaServices -Service $Service
    if ($resolved -contains 'Domain') { Test-CaActiveDomainTls -TimeoutMs $TimeoutMs }
    if ($resolved -contains 'VPS') { Test-CaActiveVpsReachability -Ports $VpsProbePort -TimeoutMs $TimeoutMs }
}
