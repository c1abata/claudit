#!/usr/bin/env bash
ca_check_vps() {
    local target="$CLAUDIT_VPS_TARGET"
    if [[ -z "$target" ]]; then ca_finding CA-VPS-000 VPS unknown medium 'VPS scope required' 'Provide --vps-target for an authorized host audit.'; return; fi
    if ! ca_command_exists ssh; then ca_finding CA-VPS-001 VPS unknown medium 'OpenSSH unavailable' 'Install the OpenSSH client to run VPS checks.'; return; fi
    if [[ "$CLAUDIT_LEVEL" == active ]]; then
        if timeout 5 bash -c "</dev/tcp/$target/22" 2>/dev/null; then ca_finding CA-VPS-PORT-22 VPS pass info 'SSH port reachable' "Authorized active probe reached $target:22."; else ca_finding CA-VPS-PORT-22 VPS unknown medium 'SSH port not reachable' "Authorized active probe could not reach $target:22."; fi
    fi
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then ca_finding CA-VPS-002 VPS unknown info 'VPS connection not confirmed' 'Use --confirm-tenant-connection before SSH collection.'; return; fi
    if ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -- "$target" 'uname -s' >/dev/null 2>&1; then ca_finding CA-VPS-002 VPS pass info 'VPS SSH access verified' 'Read-only SSH connectivity succeeded.'; else ca_finding CA-VPS-002 VPS unknown high 'VPS SSH unavailable' 'Read-only SSH connectivity failed.'; fi
}
