#!/usr/bin/env bash
ca_start_dashboard() {
    local config="$CLAUDIT_ROOT/service/service.json" bind port data_root
    ca_command_exists python3 || ca_die 'dashboard requires Python 3'
    bind="$(jq -r '.BindAddress // "127.0.0.1"' "$config")"
    port="$(jq -r '.Port // 8765' "$config")"
    data_root="${CLAUDIT_OUTPUT_DIRECTORY:-$(jq -r '.DataRoot // "./reports"' "$config")}"
    ca_log "dashboard: http://$bind:$port/ (Ctrl-C to stop)"
    exec python3 "$CLAUDIT_ROOT/service/dashboard.py" --bind "$bind" --port "$port" --data-root "$data_root" --web-root "$CLAUDIT_ROOT/web"
}
