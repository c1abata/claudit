#!/usr/bin/env bash
set -euo pipefail

config="/etc/claudit/service.json"
command -v jq >/dev/null 2>&1 || { echo 'claudit: jq is required' >&2; exit 69; }
[[ -r "$config" ]] || { echo "claudit: cannot read $config" >&2; exit 66; }
bind="$(jq -r '.BindAddress // "127.0.0.1"' "$config")"
port="$(jq -r '.Port // 8765' "$config")"
data_root="$(jq -r '.DataRoot // "/var/lib/claudit"' "$config")"
[[ "$bind" == "127.0.0.1" || "$bind" == "::1" ]] || { echo 'claudit: dashboard must bind to loopback' >&2; exit 64; }
if ! [[ "$port" =~ ^[0-9]{2,5}$ ]] || (( port > 65535 )); then
  echo 'claudit: invalid dashboard port' >&2
  exit 64
fi
mkdir -p "$data_root/reports/dashboard"
cd "$data_root/reports/dashboard"
exec python3 -m http.server "$port" --bind "$bind"
