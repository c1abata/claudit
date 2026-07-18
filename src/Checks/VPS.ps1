<#
    VPS.ps1 - read-only Linux VPS posture checks.

    The provider runs small POSIX commands locally or through OpenSSH BatchMode.
    It never installs packages, writes remote files, or changes host state.
#>

function Get-CaVpsFindings {
    [CmdletBinding()]
    param()
    Get-CaFindingsByPrefix -Prefix 'Test-CaVps*'
}

function Get-CaVpsBaseline {
    $bl = Get-CaBaseline
    if ($bl.PSObject.Properties.Name -contains 'VPS') { return $bl.VPS }
    return [pscustomobject]@{
        AllowedPublicPorts = @(80, 443)
        MaxPendingUpdates = 20
        RequireFirewall = $true
        RequireAuthLog = $true
        RequireSshPasswordAuthenticationDisabled = $true
        RequireSshRootLoginDisabled = $true
    }
}

function Get-CaVpsTarget {
    $opt = Get-CaProviderOption -Provider VPS
    if ([string]::IsNullOrWhiteSpace($opt.Target)) { return '' }
    if (-not [string]::IsNullOrWhiteSpace($opt.SshUser) -and $opt.Target -notmatch '@') {
        return "$($opt.SshUser)@$($opt.Target)"
    }
    return [string]$opt.Target
}

function Get-CaVpsLabel {
    $target = Get-CaVpsTarget
    if ([string]::IsNullOrWhiteSpace($target)) { return 'local host' }
    return $target
}

function Invoke-CaVpsCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Script,
        [switch]$AllowFailure
    )

    $target = Get-CaVpsTarget
    if ([string]::IsNullOrWhiteSpace($target)) {
        return Invoke-CaExternalCommand -Command 'sh' -Arguments @('-lc', $Script) -AllowFailure:$AllowFailure
    }

    $opt = Get-CaProviderOption -Provider VPS
    $args = [System.Collections.Generic.List[string]]::new()
    $args.Add('-o'); $args.Add('BatchMode=yes')
    $args.Add('-o'); $args.Add('ConnectTimeout=10')
    if ([int]$opt.SshPort -gt 0 -and [int]$opt.SshPort -ne 22) {
        $args.Add('-p')
        $args.Add([string][int]$opt.SshPort)
    }
    $args.Add($target)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Script)
    $encoded = [Convert]::ToBase64String($bytes)
    $args.Add("printf %s $encoded | base64 -d | sh")
    Invoke-CaExternalCommand -Command 'ssh' -Arguments @($args) -AllowFailure:$AllowFailure
}

function Get-CaVpsAllowedPublicPorts {
    $opt = Get-CaProviderOption -Provider VPS
    $ports = @(ConvertTo-CaStringList $opt.AllowedPublicPorts)
    if ($ports.Count -eq 0) {
        $bl = Get-CaVpsBaseline
        $ports = @(ConvertTo-CaStringList $bl.AllowedPublicPorts)
    }
    @($ports | ForEach-Object { [int]$_ } | Sort-Object -Unique)
}

function Get-CaVpsPublicListeners {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$Text,
        [int[]]$AllowedPorts = @()
    )

    $listeners = [System.Collections.Generic.List[object]]::new()
    foreach ($line in @($Text -split "`n")) {
        $raw = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        if ($raw -notmatch '\b(LISTEN|UNCONN)\b') { continue }
        $parts = @($raw -split '\s+' | Where-Object { $_ })
        if ($parts.Count -lt 4) { continue }

        $localIndex = if ($parts.Count -ge 5 -and $parts[1] -in @('LISTEN', 'UNCONN')) { 4 } else { 3 }
        if ($parts.Count -le $localIndex) { continue }
        $local = [string]$parts[$localIndex]
        $portText = ''
        if ($local -match ':(\d+)$') { $portText = $Matches[1] }
        if ([string]::IsNullOrWhiteSpace($portText)) { continue }
        $port = [int]$portText

        $isPublic = (
            $local -match '^(0\.0\.0\.0|\*)[:]' -or
            $local -match '^\[::\]:' -or
            $local -match '^:::' -or
            $local -match '^\*:' -or
            $local -match '^\[::ffff:0\.0\.0\.0\]:'
        )
        if (-not $isPublic) { continue }
        if ($AllowedPorts -contains $port) { continue }

        $listeners.Add([pscustomobject]@{
            Protocol = $parts[0]
            State = $parts[1]
            LocalAddress = $local
            Port = $port
            Raw = $raw
        })
    }
    @($listeners)
}

function Get-CaVpsSshSettings {
    [CmdletBinding()]
    param([AllowNull()][string]$Text)

    $settings = @{}
    foreach ($line in @($Text -split "`n")) {
        $raw = $line.Trim()
        if ($raw -match '^\s*#' -or [string]::IsNullOrWhiteSpace($raw)) { continue }
        if ($raw -match '^(?<key>permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication)\s+(?<value>\S+)') {
            $settings[$Matches['key'].ToLowerInvariant()] = $Matches['value'].ToLowerInvariant()
        }
    }
    $settings
}

function Test-CaVpsContext {
    Invoke-CaCheck -Service VPS -CheckId 'VPS-001' -Title 'Linux VPS host context resolved' -Body {
        $script = @'
echo "HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"
echo "KERNEL=$(uname -srmo 2>/dev/null || uname -a 2>/dev/null || echo unknown)"
echo "USER=$(id -un 2>/dev/null || whoami 2>/dev/null || echo unknown)"
echo "UPTIME=$(uptime -p 2>/dev/null || true)"
'@
        $r = Invoke-CaVpsCommand -Script $script -AllowFailure
        if (-not $r.Success) {
            return New-CaFinding -Service VPS -CheckId 'VPS-001' -Title 'Linux VPS host context resolved' -Status Error -Severity Medium `
                -Detail "Could not run POSIX shell on $(Get-CaVpsLabel): $($r.Text)" `
                -Recommendation 'Run locally on Linux or pass -VpsTarget for an SSH-reachable Linux host with a non-interactive key.'
        }
        New-CaFinding -Service VPS -CheckId 'VPS-001' -Title 'Linux VPS host context resolved' -Status Info `
            -Detail "$(Get-CaVpsLabel): $($r.Text -replace '[\r\n]+', '; ')" -Evidence $r.Text
    }
}

function Test-CaVpsSshHardening {
    Invoke-CaCheck -Service VPS -CheckId 'VPS-002' -Title 'SSH root and password authentication hardened' -Body {
        $script = @'
if command -v sshd >/dev/null 2>&1; then
  sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication)[[:space:]]' || true
fi
grep -hEi '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication)[[:space:]]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
'@
        $r = Invoke-CaVpsCommand -Script $script -AllowFailure
        if (-not $r.Success) { throw $r.Text }
        if ([string]::IsNullOrWhiteSpace($r.Text)) {
            return New-CaFinding -Service VPS -CheckId 'VPS-002' -Title 'SSH root and password authentication hardened' -Status Skipped `
                -SkippedReason 'No readable sshd effective configuration found.' -Detail 'Install/read access to sshd configuration is required for this check.'
        }

        $bl = Get-CaVpsBaseline
        $settings = Get-CaVpsSshSettings -Text $r.Text
        $problems = [System.Collections.Generic.List[string]]::new()
        if ([bool]$bl.RequireSshRootLoginDisabled -and $settings['permitrootlogin'] -and $settings['permitrootlogin'] -ne 'no') {
            $problems.Add("PermitRootLogin=$($settings['permitrootlogin'])")
        }
        if ([bool]$bl.RequireSshPasswordAuthenticationDisabled -and $settings['passwordauthentication'] -eq 'yes') {
            $problems.Add('PasswordAuthentication=yes')
        }
        foreach ($key in @('kbdinteractiveauthentication', 'challengeresponseauthentication')) {
            if ($settings[$key] -eq 'yes') { $problems.Add("$key=yes") }
        }

        if ($problems.Count -eq 0) {
            New-CaFinding -Service VPS -CheckId 'VPS-002' -Title 'SSH root and password authentication hardened' -Status Pass `
                -Detail 'No enabled root/password/keyboard-interactive SSH setting was observed.' -Evidence $settings
        }
        else {
            New-CaFinding -Service VPS -CheckId 'VPS-002' -Title 'SSH root and password authentication hardened' -Status Fail -Severity High `
                -Detail ($problems -join '; ') -Evidence $settings `
                -Recommendation 'Set PermitRootLogin no, PasswordAuthentication no and disable keyboard-interactive auth; use named sudo users and key/FIDO-backed access.'
        }
    }
}

function Test-CaVpsPublicListeners {
    Invoke-CaCheck -Service VPS -CheckId 'VPS-003' -Title 'No unexpected services listen on public interfaces' -Body {
        $script = @'
if command -v ss >/dev/null 2>&1; then
  ss -H -tuln
elif command -v netstat >/dev/null 2>&1; then
  netstat -tuln
else
  echo "__NO_SOCKET_TOOL__"
fi
'@
        $allowed = @(Get-CaVpsAllowedPublicPorts)
        $r = Invoke-CaVpsCommand -Script $script -AllowFailure
        if (-not $r.Success) { throw $r.Text }
        if ($r.Text -match '__NO_SOCKET_TOOL__') {
            return New-CaFinding -Service VPS -CheckId 'VPS-003' -Title 'No unexpected services listen on public interfaces' -Status Skipped `
                -SkippedReason 'Neither ss nor netstat is available.' -Detail 'Install iproute2 or net-tools to enumerate listeners.'
        }

        $unexpected = @(Get-CaVpsPublicListeners -Text $r.Text -AllowedPorts $allowed)
        if ($unexpected.Count -eq 0) {
            New-CaFinding -Service VPS -CheckId 'VPS-003' -Title 'No unexpected services listen on public interfaces' -Status Pass `
                -Detail "Only allowed public ports were observed: $($allowed -join ', ')." -Evidence $r.Text
        }
        else {
            $ports = @($unexpected | ForEach-Object { $_.Port } | Sort-Object -Unique)
            New-CaFinding -Service VPS -CheckId 'VPS-003' -Title 'No unexpected services listen on public interfaces' -Status Fail -Severity High `
                -Detail "Unexpected public listener port(s): $($ports -join ', ')." -Evidence $unexpected `
                -Recommendation 'Bind admin/internal services to localhost or private interfaces and enforce cloud firewall/security-group allow lists.'
        }
    }
}

function Test-CaVpsFirewall {
    Invoke-CaCheck -Service VPS -CheckId 'VPS-004' -Title 'Host firewall appears active' -Body {
        $script = @'
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'Status: active'; then echo FIREWALL=ufw-active; exit 0; fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi running; then echo FIREWALL=firewalld-running; exit 0; fi
if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -Eq 'hook input|chain input'; then echo FIREWALL=nft-rules; exit 0; fi
if command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -Eq '^-P INPUT DROP|^-A INPUT .* -j (DROP|REJECT)'; then echo FIREWALL=iptables-filtering; exit 0; fi
echo FIREWALL=none
'@
        $r = Invoke-CaVpsCommand -Script $script -AllowFailure
        if (-not $r.Success) { throw $r.Text }
        $mode = (($r.Text -split "`n") | Where-Object { $_ -match '^FIREWALL=' } | Select-Object -First 1)
        if ($mode -and $mode -notmatch 'none') {
            New-CaFinding -Service VPS -CheckId 'VPS-004' -Title 'Host firewall appears active' -Status Pass -Detail $mode -Evidence $r.Text
        }
        elseif (-not [bool](Get-CaVpsBaseline).RequireFirewall) {
            New-CaFinding -Service VPS -CheckId 'VPS-004' -Title 'Host firewall appears active' -Status Info -Detail 'Baseline does not require a host firewall.'
        }
        else {
            New-CaFinding -Service VPS -CheckId 'VPS-004' -Title 'Host firewall appears active' -Status Warning -Severity Medium `
                -Detail 'No active ufw/firewalld/nftables/iptables input filtering was detected.' `
                -Recommendation 'Enable a host firewall as a second guardrail behind cloud security groups.'
        }
    }
}

function Test-CaVpsPendingUpdates {
    Invoke-CaCheck -Service VPS -CheckId 'VPS-005' -Title 'Pending package updates within baseline' -Body {
        $script = @'
if command -v apt-get >/dev/null 2>&1; then
  apt-get -s upgrade 2>/dev/null | awk '/^Inst /{c++} END{print "UPDATES=" c+0}'
elif command -v dnf >/dev/null 2>&1; then
  dnf -q check-update 2>/dev/null | awk '/^[A-Za-z0-9_.:+-]+\./{c++} END{print "UPDATES=" c+0}'
elif command -v yum >/dev/null 2>&1; then
  yum -q check-update 2>/dev/null | awk '/^[A-Za-z0-9_.:+-]+\./{c++} END{print "UPDATES=" c+0}'
elif command -v pacman >/dev/null 2>&1; then
  pacman -Qu 2>/dev/null | awk 'END{print "UPDATES=" NR+0}'
else
  echo UPDATES=UNKNOWN
fi
'@
        $r = Invoke-CaVpsCommand -Script $script -AllowFailure
        if (-not $r.Success) { throw $r.Text }
        if ($r.Text -notmatch 'UPDATES=(\d+)') {
            return New-CaFinding -Service VPS -CheckId 'VPS-005' -Title 'Pending package updates within baseline' -Status Skipped `
                -SkippedReason 'No supported package manager was detected.' -Detail $r.Text
        }
        $count = [int]$Matches[1]
        $max = [int](Get-CaVpsBaseline).MaxPendingUpdates
        if ($count -le $max) {
            New-CaFinding -Service VPS -CheckId 'VPS-005' -Title 'Pending package updates within baseline' -Status Pass `
                -Detail "$count pending package update(s), baseline max $max." -Evidence $count
        }
        else {
            New-CaFinding -Service VPS -CheckId 'VPS-005' -Title 'Pending package updates within baseline' -Status Warning -Severity Medium `
                -Detail "$count pending package update(s), baseline max $max." -Evidence $count `
                -Recommendation 'Patch the host or document the maintenance window and compensating controls.'
        }
    }
}

function Test-CaVpsAuthLogs {
    Invoke-CaCheck -Service VPS -CheckId 'VPS-006' -Title 'Authentication logs are available for investigation' -Body {
        $script = @'
if [ -r /var/log/auth.log ]; then echo AUTH_LOG=/var/log/auth.log
elif [ -r /var/log/secure ]; then echo AUTH_LOG=/var/log/secure
elif command -v journalctl >/dev/null 2>&1 && journalctl -n 1 _COMM=sshd >/dev/null 2>&1; then echo AUTH_LOG=journalctl:sshd
else echo AUTH_LOG=missing
fi
'@
        $r = Invoke-CaVpsCommand -Script $script -AllowFailure
        if (-not $r.Success) { throw $r.Text }
        $line = (($r.Text -split "`n") | Where-Object { $_ -match '^AUTH_LOG=' } | Select-Object -First 1)
        if ($line -and $line -notmatch 'missing') {
            New-CaFinding -Service VPS -CheckId 'VPS-006' -Title 'Authentication logs are available for investigation' -Status Pass -Detail $line -Evidence $r.Text
        }
        elseif (-not [bool](Get-CaVpsBaseline).RequireAuthLog) {
            New-CaFinding -Service VPS -CheckId 'VPS-006' -Title 'Authentication logs are available for investigation' -Status Info -Detail 'Baseline does not require auth log verification.'
        }
        else {
            New-CaFinding -Service VPS -CheckId 'VPS-006' -Title 'Authentication logs are available for investigation' -Status Warning -Severity Low `
                -Detail 'No readable /var/log/auth.log, /var/log/secure or sshd journal entry was detected.' `
                -Recommendation 'Ensure SSH/authentication logs are retained locally and forwarded to central logging/SIEM.'
        }
    }
}
