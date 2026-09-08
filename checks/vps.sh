#!/usr/bin/env bash
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
    if ca_run_cli ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -- "$target" 'uname -s' >/dev/null 2>&1; then ca_finding CA-VPS-002 VPS pass info 'VPS SSH access verified' 'Read-only SSH connectivity succeeded.'; else ca_finding CA-VPS-002 VPS unknown high 'VPS SSH unavailable' 'Read-only SSH connectivity failed or exceeded the command deadline.'; fi
}
