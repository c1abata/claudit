#!/usr/bin/env bash
set -euo pipefail

config="/etc/claudit/service.json"
command -v jq >/dev/null 2>&1 || { echo 'claudit: jq is required' >&2; exit 69; }
[[ -r "$config" ]] || { echo "claudit: cannot read $config" >&2; exit 66; }
bind="$(jq -r '.BindAddress // "127.0.0.1"' "$config")"
port="$(jq -r '.Port // 8765' "$config")"
data_root="$(jq -r '.DataRoot // "/var/lib/claudit"' "$config")"
case "$bind" in
  127.0.0.1|::1|0.0.0.0) ;;
  *) echo 'claudit: dashboard bind address must be 127.0.0.1, ::1, or 0.0.0.0' >&2; exit 64 ;;
esac
if ! [[ "$port" =~ ^[0-9]{2,5}$ ]] || (( port > 65535 )); then
  echo 'claudit: invalid dashboard port' >&2
  exit 64
fi
mkdir -p "$data_root/reports/dashboard"
exec python3 "$(dirname "$0")/dashboard.py" \
  --bind "$bind" --port "$port" --data-root "$data_root" \
  --web-root "$(dirname "$(dirname "$0")")/web"
