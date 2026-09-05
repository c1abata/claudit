#!/usr/bin/env bash
ca_start_dashboard() {
    local config="$CLAUDIT_ROOT/service/service.json" bind port data_root
    ca_command_exists python3 || ca_die 'dashboard requires python3 for its standard-library local HTTP server'
    [[ -r "$config" ]] || ca_die "cannot read dashboard configuration '$config'"
    bind="$(jq -r '.BindAddress // "127.0.0.1"' "$config")"
    port="$(jq -r '.Port // 8765' "$config")"
    data_root="$(jq -r '.DataRoot // "./reports"' "$config")"
    [[ "$bind" == 127.0.0.1 || "$bind" == ::1 ]] || ca_die 'dashboard only permits a loopback bind address'
    if ! [[ "$port" =~ ^[0-9]{2,5}$ ]] || (( port > 65535 )); then
        ca_die 'dashboard port is invalid'
    fi
    mkdir -p -- "$data_root/dashboard"
    cp -f -- "$CLAUDIT_ROOT"/web/assets/dashboard.{css,js} "$data_root/dashboard/" 2>/dev/null || true
    cat > "$data_root/dashboard/index.html" <<'EOF'
<!doctype html><meta charset="utf-8"><title>Claudit dashboard</title><h1>Claudit reports</h1><p>Static local report directory. Open the generated <code>claudit-report.html</code> artifacts.</p>
EOF
    ca_log "dashboard: http://$bind:$port/ (Ctrl-C to stop)"
    (cd "$data_root" && exec python3 -m http.server "$port" --bind "$bind")
}
