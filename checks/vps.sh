#!/usr/bin/env bash
ca_vps_collect() {
    ca_run_cli ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -- "$1" 'sh -s' <<'REMOTE'
ports=unknown
if command -v ss >/dev/null 2>&1; then
  ports=$(ss -H -ltn 2>/dev/null | awk '$4 ~ /^(0\.0\.0\.0|\[::\]|\*):[0-9]+$/ {sub(/^.*:/,"",$4); print $4}' | sort -nu | paste -sd, -)
  ports=${ports:-none}
fi
pending=unknown
if command -v apt-get >/dev/null 2>&1; then pending=$(LC_ALL=C apt-get -s upgrade 2>/dev/null | awk '/^Inst /{n++} END{print n+0}')
elif command -v dnf >/dev/null 2>&1; then pending=$(dnf -q check-update 2>/dev/null | awk 'NF >= 3 && $1 !~ /^(Last|Obsoleting)/{n++} END{print n+0}')
fi
firewall=unknown
if command -v ufw >/dev/null 2>&1; then if ufw status 2>/dev/null | grep -qi '^Status: active'; then firewall=true; else firewall=false; fi
elif command -v firewall-cmd >/dev/null 2>&1; then if firewall-cmd --state 2>/dev/null | grep -qx running; then firewall=true; else firewall=false; fi
elif command -v nft >/dev/null 2>&1; then if nft list ruleset 2>/dev/null | grep -q '[{}]'; then firewall=true; else firewall=false; fi
fi
authlog=false
if test -r /var/log/auth.log || test -r /var/log/secure; then authlog=true
elif command -v journalctl >/dev/null 2>&1 && (journalctl -n 1 -u ssh --no-pager 2>/dev/null || journalctl -n 1 -u sshd --no-pager 2>/dev/null) | grep -q .; then authlog=true
fi
passwordauth=unknown; rootlogin=unknown
if command -v sshd >/dev/null 2>&1; then
  effective=$(sshd -T 2>/dev/null || true)
  passwordauth=$(printf '%s\n' "$effective" | awk '$1=="passwordauthentication"{print $2; exit}')
  rootlogin=$(printf '%s\n' "$effective" | awk '$1=="permitrootlogin"{print $2; exit}')
  passwordauth=${passwordauth:-unknown}; rootlogin=${rootlogin:-unknown}
fi
printf 'ports\t%s\npending\t%s\nfirewall\t%s\nauthlog\t%s\npasswordauth\t%s\nrootlogin\t%s\n' "$ports" "$pending" "$firewall" "$authlog" "$passwordauth" "$rootlogin"
REMOTE
}

ca_check_vps() {
    local target="$CLAUDIT_VPS_TARGET"
    if [[ -z "$target" ]]; then ca_finding CA-VPS-000 VPS unknown medium 'VPS scope required' 'Provide --vps-target for an authorized host audit.'; return; fi
    [[ "$target" =~ ^([a-zA-Z0-9_][a-zA-Z0-9_-]*@)?[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] || { ca_finding CA-VPS-000 VPS error high 'Invalid VPS scope' 'Use a hostname or IPv4 address, optionally prefixed by user@.'; return; }
    ca_finding CA-VPS-000 VPS pass info 'VPS scope accepted' "Declared target: $target."
    [[ "$CLAUDIT_LEVEL" != formal ]] || return 0
    if ! ca_command_exists ssh; then ca_finding CA-VPS-001 VPS unknown medium 'OpenSSH unavailable' 'Install the OpenSSH client to run VPS checks.'; return; fi
    if [[ "$CLAUDIT_LEVEL" == active ]]; then
        if timeout 5 bash -c 'exec 3<>"/dev/tcp/$1/22"' -- "${target##*@}" 2>/dev/null; then ca_finding CA-VPS-PORT-22 VPS pass info 'SSH port reachable' "Authorized active probe reached $target:22."; else ca_finding CA-VPS-PORT-22 VPS unknown medium 'SSH port not reachable' "Authorized active probe could not reach $target:22."; fi
    fi
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-VPS-002 VPS unknown info 'VPS connection not confirmed' 'Use --confirm-tenant-connection before SSH collection.'; return; fi
    if ca_run_cli ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -- "$target" 'uname -s' >/dev/null 2>&1; then ca_finding CA-VPS-002 VPS pass info 'VPS SSH access verified' 'Read-only SSH connectivity succeeded.'; else ca_finding CA-VPS-002 VPS unknown high 'VPS SSH unavailable' 'Read-only SSH connectivity failed or exceeded the command deadline.'; return; fi
    local posture ports pending firewall authlog passwordauth rootlogin allowed_ports invalid=0 key value
    if ! posture="$(ca_vps_collect "$target" 2>/dev/null)"; then
        for key in CA-VPS-PORTS CA-VPS-UPDATES CA-VPS-FIREWALL CA-VPS-AUTHLOG CA-VPS-SSH-PASSWORD CA-VPS-SSH-ROOT; do ca_finding "$key" VPS unknown high 'VPS posture collection unavailable' 'The bounded read-only host posture command failed or exceeded its deadline.'; done
        return
    fi
    while IFS=$'\t' read -r key value; do
        case "$key" in ports) ports="$value" ;; pending) pending="$value" ;; firewall) firewall="$value" ;; authlog) authlog="$value" ;; passwordauth) passwordauth="$value" ;; rootlogin) rootlogin="$value" ;; *) invalid=1 ;; esac
    done <<<"$posture"
    [[ -n "${ports:-}" && -n "${pending:-}" && -n "${firewall:-}" && -n "${authlog:-}" && -n "${passwordauth:-}" && -n "${rootlogin:-}" ]] || invalid=1
    if (( invalid )); then
        for key in CA-VPS-PORTS CA-VPS-UPDATES CA-VPS-FIREWALL CA-VPS-AUTHLOG CA-VPS-SSH-PASSWORD CA-VPS-SSH-ROOT; do ca_finding "$key" VPS error high 'VPS posture response malformed' 'The remote posture response does not satisfy the fixed evidence contract.'; done
        return
    fi
    allowed_ports="$(ca_baseline_get '.VPS.AllowedPublicPorts')"
    if [[ "$ports" == unknown ]]; then ca_finding CA-VPS-PORTS VPS unknown medium 'Public listener evidence unavailable' 'The remote host does not provide a supported socket inventory command.'
    elif [[ "$ports" == none ]] || jq -en --arg ports "$ports" --argjson allowed "$allowed_ports" '($ports | split(",") | map(tonumber) | map(select(. as $port | $port != 22 and ($allowed | index($port) | not))) | length) == 0' >/dev/null; then ca_finding CA-VPS-PORTS VPS pass info 'Public listeners within baseline' 'Wildcard TCP listeners are limited to SSH and explicitly allowed public ports.'
    else ca_finding CA-VPS-PORTS VPS fail high 'Unexpected public listeners found' 'One or more wildcard TCP listeners are outside the SSH and baseline allow-list.'; fi
    if [[ "$pending" =~ ^[0-9]+$ ]] && (( pending <= $(ca_baseline_get '.VPS.MaxPendingUpdates') )); then ca_finding CA-VPS-UPDATES VPS pass info 'Pending updates within baseline' "$pending pending package update(s) were reported."
    elif [[ "$pending" =~ ^[0-9]+$ ]]; then ca_finding CA-VPS-UPDATES VPS fail high 'Too many pending updates' "$pending pending updates exceed the configured maximum."
    else ca_finding CA-VPS-UPDATES VPS unknown medium 'Pending update evidence unavailable' 'No supported package manager returned a simulation result.'; fi
    if ! ca_baseline_enabled '.VPS.RequireFirewall'; then ca_finding CA-VPS-FIREWALL VPS info info 'Host firewall not required' 'The local baseline does not require an active host firewall.'
    elif [[ "$firewall" == true ]]; then ca_finding CA-VPS-FIREWALL VPS pass info 'Host firewall active' 'A supported host firewall reports an active ruleset.'
    elif [[ "$firewall" == false ]]; then ca_finding CA-VPS-FIREWALL VPS fail critical 'Host firewall inactive' 'A supported host firewall is installed but does not report an active ruleset.'
    else ca_finding CA-VPS-FIREWALL VPS unknown high 'Host firewall evidence unavailable' 'No supported firewall status could be collected.'; fi
    if ! ca_baseline_enabled '.VPS.RequireAuthLog'; then ca_finding CA-VPS-AUTHLOG VPS info info 'Authentication logging not required' 'The local baseline does not require readable authentication logs.'
    elif [[ "$authlog" == true ]]; then ca_finding CA-VPS-AUTHLOG VPS pass info 'Authentication logging available' 'A supported authentication log or SSH journal contains readable evidence.'
    else ca_finding CA-VPS-AUTHLOG VPS fail high 'Authentication logging unavailable' 'No supported readable authentication log evidence was found.'; fi
    if ! ca_baseline_enabled '.VPS.RequireSshPasswordAuthenticationDisabled'; then ca_finding CA-VPS-SSH-PASSWORD VPS info info 'SSH password policy not required' 'The local baseline does not require password authentication to be disabled.'
    elif [[ "$passwordauth" == no ]]; then ca_finding CA-VPS-SSH-PASSWORD VPS pass info 'SSH password authentication disabled' 'The effective sshd configuration reports passwordauthentication no.'
    elif [[ "$passwordauth" == yes ]]; then ca_finding CA-VPS-SSH-PASSWORD VPS fail critical 'SSH password authentication enabled' 'The effective sshd configuration permits password authentication.'
    else ca_finding CA-VPS-SSH-PASSWORD VPS unknown high 'SSH password policy unavailable' 'The effective sshd password-authentication setting could not be collected.'; fi
    if ! ca_baseline_enabled '.VPS.RequireSshRootLoginDisabled'; then ca_finding CA-VPS-SSH-ROOT VPS info info 'SSH root-login policy not required' 'The local baseline does not require root login to be disabled.'
    elif [[ "$rootlogin" == no ]]; then ca_finding CA-VPS-SSH-ROOT VPS pass info 'SSH root login disabled' 'The effective sshd configuration reports permitrootlogin no.'
    elif [[ "$rootlogin" == yes || "$rootlogin" == without-password || "$rootlogin" == prohibit-password || "$rootlogin" == forced-commands-only ]]; then ca_finding CA-VPS-SSH-ROOT VPS fail critical 'SSH root login not fully disabled' "The effective sshd configuration reports permitrootlogin $rootlogin."
    else ca_finding CA-VPS-SSH-ROOT VPS unknown high 'SSH root-login policy unavailable' 'The effective sshd root-login setting could not be collected.'; fi
}
