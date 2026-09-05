<#
    Tailscale.ps1 - read-only tailnet posture checks via the Tailscale API.

    Tailscale is often the control plane for cloud admin access. These checks
    cover the highest-signal areas from tailnet audit tooling: device lifecycle,
    auth-key hygiene and overly broad ACLs. API tokens are read from an
    environment variable and are never persisted in the wizard profile.
#>

function Get-CaTailscaleFindings {
    [CmdletBinding()]
    param()
    Get-CaFindingsByPrefix -Prefix 'Test-CaTailscale*'
}

function Get-CaTailscaleTailnet {
    $opt = Get-CaProviderOption -Provider Tailscale
    if (-not [string]::IsNullOrWhiteSpace($opt.Tailnet)) { return $opt.Tailnet }
    if (-not [string]::IsNullOrWhiteSpace($env:TAILSCALE_TAILNET)) { return $env:TAILSCALE_TAILNET }

    $bl = Get-CaBaseline
    if ($bl.PSObject.Properties.Name -contains 'Tailscale' -and
        $bl.Tailscale.PSObject.Properties.Name -contains 'Tailnet' -and
        -not [string]::IsNullOrWhiteSpace([string]$bl.Tailscale.Tailnet)) {
        return [string]$bl.Tailscale.Tailnet
    }
    return ''
}

function Get-CaTailscaleApiToken {
    $opt = Get-CaProviderOption -Provider Tailscale
    $envName = if ([string]::IsNullOrWhiteSpace($opt.ApiTokenEnv)) { 'TAILSCALE_API_TOKEN' } else { [string]$opt.ApiTokenEnv }
    return [Environment]::GetEnvironmentVariable($envName, 'Process')
}

function Get-CaTailscaleConfigIssue {
    $tailnet = Get-CaTailscaleTailnet
    $token = Get-CaTailscaleApiToken
    if ([string]::IsNullOrWhiteSpace($tailnet)) { return 'No tailnet selected. Pass -TailscaleTailnet or set TAILSCALE_TAILNET.' }
    if ([string]::IsNullOrWhiteSpace($token)) {
        $opt = Get-CaProviderOption -Provider Tailscale
        $envName = if ([string]::IsNullOrWhiteSpace($opt.ApiTokenEnv)) { 'TAILSCALE_API_TOKEN' } else { [string]$opt.ApiTokenEnv }
        return "No Tailscale API token found in $envName."
    }
    return ''
}

function New-CaTailscaleAuthHeader {
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][ValidateSet('Basic', 'Bearer')][string]$Scheme
    )
    if ($Scheme -eq 'Basic') {
        $raw = [System.Text.Encoding]::UTF8.GetBytes("${Token}:")
        return @{ Authorization = 'Basic ' + [Convert]::ToBase64String($raw) }
    }
    return @{ Authorization = "Bearer $Token" }
}

function Invoke-CaTailscaleApi {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $issue = Get-CaTailscaleConfigIssue
    if ($issue) { throw $issue }

    $tailnet = [System.Uri]::EscapeDataString((Get-CaTailscaleTailnet))
    $token = Get-CaTailscaleApiToken
    $opt = Get-CaProviderOption -Provider Tailscale
    $scheme = [string]$opt.AuthScheme
    if ([string]::IsNullOrWhiteSpace($scheme)) { $scheme = 'Auto' }
    $uri = "https://api.tailscale.com/api/v2/tailnet/$tailnet/$Path"

    $schemes = if ($scheme -eq 'Auto') { @('Basic', 'Bearer') } else { @($scheme) }
    $lastError = $null
    foreach ($candidate in $schemes) {
        try {
            return Invoke-RestMethod -Method Get -Uri $uri -Headers (New-CaTailscaleAuthHeader -Token $token -Scheme $candidate) -ErrorAction Stop
        }
        catch {
            $lastError = $_
        }
    }
    throw "Tailscale API request failed for '$Path': $($lastError.Exception.Message)"
}

function Get-CaTailscaleDevices {
    $doc = Invoke-CaTailscaleApi -Path 'devices'
    return @($doc.devices | Where-Object { $_ })
}

function Test-CaTailscaleContext {
    Invoke-CaCheck -Service Tailscale -CheckId 'TAILSCALE-001' -Title 'Tailscale API context resolved' -Body {
        $issue = Get-CaTailscaleConfigIssue
        if ($issue) {
            return New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-001' -Title 'Tailscale API context resolved' -Status Skipped `
                -SkippedReason $issue -Detail $issue
        }

        $devices = @(Get-CaTailscaleDevices)
        New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-001' -Title 'Tailscale API context resolved' -Status Info `
            -Detail "Tailnet=$(Get-CaTailscaleTailnet); Devices=$($devices.Count)." -Evidence $devices
    }
}

function Test-CaTailscaleStaleDevices {
    Invoke-CaCheck -Service Tailscale -CheckId 'TAILSCALE-002' -Title 'Tailnet has no stale devices beyond baseline' -Body {
        $issue = Get-CaTailscaleConfigIssue
        if ($issue) {
            return New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-002' -Title 'Tailnet has no stale devices beyond baseline' -Status Skipped `
                -SkippedReason $issue -Detail $issue
        }

        $bl = Get-CaBaseline
        $maxDays = [int]$bl.Tailscale.MaxStaleDeviceDays
        $cutoff = [DateTime]::UtcNow.AddDays(-$maxDays)
        $stale = [System.Collections.Generic.List[object]]::new()
        foreach ($d in @(Get-CaTailscaleDevices)) {
            if (-not $d.lastSeen) { continue }
            $lastSeen = [DateTime]$d.lastSeen
            if ($lastSeen -lt $cutoff) {
                $stale.Add([pscustomobject]@{
                    Name     = $d.name
                    User     = $d.user
                    LastSeen = $lastSeen.ToString('o')
                    Id       = $d.id
                })
            }
        }

        if ($stale.Count -eq 0) {
            New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-002' -Title 'Tailnet has no stale devices beyond baseline' -Status Pass `
                -Detail "No device lastSeen older than $maxDays day(s)." -Evidence $stale
        }
        else {
            New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-002' -Title 'Tailnet has no stale devices beyond baseline' -Status Fail -Severity Medium `
                -Detail "$($stale.Count) stale tailnet device(s) older than $maxDays day(s)." -Evidence $stale `
                -Recommendation 'Remove or disable unused devices and require re-authentication for long-idle admin workstations.' `
                -Reference 'https://tailscale.com/kb/1068/acl-tags'
        }
    }
}

function Test-CaTailscaleAuthKeys {
    Invoke-CaCheck -Service Tailscale -CheckId 'TAILSCALE-003' -Title 'Tailscale auth keys are constrained' -Body {
        $issue = Get-CaTailscaleConfigIssue
        if ($issue) {
            return New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-003' -Title 'Tailscale auth keys are constrained' -Status Skipped `
                -SkippedReason $issue -Detail $issue
        }

        $bl = Get-CaBaseline
        $maxExpiryDays = [int]$bl.Tailscale.MaxAuthKeyExpiryDays
        $disallowReusable = [bool]$bl.Tailscale.DisallowReusableAuthKeys
        $disallowPreauthorized = [bool]$bl.Tailscale.DisallowPreauthorizedAuthKeys
        $r = Invoke-CaTailscaleApi -Path 'keys'
        $bad = [System.Collections.Generic.List[object]]::new()

        foreach ($key in @($r.keys | Where-Object { $_ })) {
            $reasons = [System.Collections.Generic.List[string]]::new()
            if ($disallowReusable -and [bool]$key.reusable) { $reasons.Add('reusable') }
            if ($disallowPreauthorized -and [bool]$key.preauthorized) { $reasons.Add('preauthorized') }
            if ($key.expires) {
                $days = ([DateTime]$key.expires - [DateTime]::UtcNow).TotalDays
                if ($days -gt $maxExpiryDays) { $reasons.Add("expires in $([math]::Round($days, 1)) days") }
            }
            else {
                $reasons.Add('no expiry in API response')
            }
            if ($reasons.Count -gt 0) {
                $bad.Add([pscustomobject]@{
                    Id      = $key.id
                    Created = $key.created
                    Expires = $key.expires
                    Issues  = @($reasons)
                })
            }
        }

        if ($bad.Count -eq 0) {
            New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-003' -Title 'Tailscale auth keys are constrained' -Status Pass `
                -Detail "No reusable, preauthorized or long-lived auth key exceeds $maxExpiryDays day(s)." -Evidence $r.keys
        }
        else {
            New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-003' -Title 'Tailscale auth keys are constrained' -Status Fail -Severity High `
                -Detail "$($bad.Count) auth key(s) violate baseline constraints." -Evidence $bad `
                -Recommendation 'Use short-lived, ephemeral, non-preauthorized auth keys for automation; revoke stale/reusable keys.' `
                -Reference 'https://tailscale.com/kb/1085/auth-keys'
        }
    }
}

function Test-CaTailscalePermissiveAcl {
    Invoke-CaCheck -Service Tailscale -CheckId 'TAILSCALE-004' -Title 'Tailscale ACL policy avoids allow-all rules' -Body {
        $issue = Get-CaTailscaleConfigIssue
        if ($issue) {
            return New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-004' -Title 'Tailscale ACL policy avoids allow-all rules' -Status Skipped `
                -SkippedReason $issue -Detail $issue
        }

        $bl = Get-CaBaseline
        if ($bl.Tailscale.PSObject.Properties.Name -contains 'DisallowAllowAllAcl' -and -not [bool]$bl.Tailscale.DisallowAllowAllAcl) {
            return New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-004' -Title 'Tailscale ACL policy avoids allow-all rules' -Status Info `
                -Detail 'Baseline does not disallow allow-all ACL rules.'
        }

        $policy = Invoke-CaTailscaleApi -Path 'acl'
        $bad = [System.Collections.Generic.List[object]]::new()
        foreach ($acl in @($policy.acls | Where-Object { $_ })) {
            $src = ConvertTo-CaStringList $acl.src
            $dst = ConvertTo-CaStringList $acl.dst
            if ([string]$acl.action -eq 'accept' -and ($src -contains '*' -or $src -contains 'autogroup:member') -and ($dst -contains '*:*' -or $dst -contains '*')) {
                $bad.Add([pscustomobject]@{ Type = 'acl'; Source = $src; Destination = $dst })
            }
        }
        foreach ($grant in @($policy.grants | Where-Object { $_ })) {
            $src = ConvertTo-CaStringList $grant.src
            $dst = ConvertTo-CaStringList $grant.dst
            if (($src -contains '*' -or $src -contains 'autogroup:member') -and ($dst -contains '*:*' -or $dst -contains '*')) {
                $bad.Add([pscustomobject]@{ Type = 'grant'; Source = $src; Destination = $dst })
            }
        }

        if ($bad.Count -eq 0) {
            New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-004' -Title 'Tailscale ACL policy avoids allow-all rules' -Status Pass `
                -Detail 'No ACL/grant rule allows broad source to all destinations.' -Evidence $policy
        }
        else {
            New-CaFinding -Service Tailscale -CheckId 'TAILSCALE-004' -Title 'Tailscale ACL policy avoids allow-all rules' -Status Fail -Severity Critical `
                -Detail "$($bad.Count) allow-all style tailnet policy rule(s) detected." -Evidence $bad `
                -Recommendation 'Replace broad allow-all ACLs with groups/tags and explicit service destinations; require review for autogroup:member to *:* patterns.' `
                -Reference 'https://tailscale.com/kb/1337/acl-syntax'
        }
    }
}
