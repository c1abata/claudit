#!/usr/bin/env bash
set -euo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_root="/opt/claudit"
config_root="/etc/claudit"
data_root="/var/lib/claudit"
start_service=1

usage() {
  cat <<'EOF'
Usage: sudo bash ./install-ubuntu.sh [--no-start]

Installs Claudit under /opt/claudit, creates the restricted claudit service
account, persistent storage under /var/lib/claudit and a systemd unit.
Existing /etc/claudit/service.json and /etc/claudit/claudit.env are preserved.
EOF
}

case "${1:-}" in
  '') ;;
  --no-start) start_service=0 ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 64 ;;
esac

if [[ ${EUID} -ne 0 ]]; then
  echo "claudit: installer must run as root (use sudo)." >&2
  exit 77
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "claudit: systemd/systemctl is required." >&2
  exit 69
fi
if [[ ! -x /usr/bin/pwsh ]]; then
  echo "claudit: /usr/bin/pwsh 7.2+ is required before installation." >&2
  echo "See https://learn.microsoft.com/powershell/scripting/install/install-ubuntu" >&2
  exit 69
fi
if ! /usr/bin/pwsh -NoLogo -NoProfile -NonInteractive -Command 'if ($PSVersionTable.PSVersion -lt [version]"7.2") { exit 1 }'; then
  echo "claudit: PowerShell 7.2 or newer is required." >&2
  exit 69
fi
if [[ ! -f "${source_root}/Claudit.psd1" || ! -f "${source_root}/service/claudit.service" ]]; then
  echo "claudit: run this installer from a complete Claudit source tree." >&2
  exit 66
fi

if ! id -u claudit >/dev/null 2>&1; then
  useradd --system --home-dir "${data_root}" --create-home --shell /usr/sbin/nologin claudit
fi

install -d -o root -g root -m 0755 "${install_root}" "${install_root}/src" "${install_root}/config" "${install_root}/docs" "${install_root}/service" "${install_root}/tests" "${install_root}/web"
cp -a "${source_root}/src/." "${install_root}/src/"
cp -a "${source_root}/config/." "${install_root}/config/"
cp -a "${source_root}/docs/." "${install_root}/docs/"
cp -a "${source_root}/service/." "${install_root}/service/"
cp -a "${source_root}/tests/." "${install_root}/tests/"
cp -a "${source_root}/web/." "${install_root}/web/"

for file in Claudit.psd1 Claudit.psm1 Invoke-ClauditAudit.ps1 Start-ClauditSafeAudit.ps1 Test-ClauditPreflight.ps1; do
  install -o root -g root -m 0644 "${source_root}/${file}" "${install_root}/${file}"
done
find "${install_root}" -type d -exec chmod 0755 {} +
find "${install_root}" -type f -exec chmod 0644 {} +
chown -R root:root "${install_root}"

install -d -o root -g claudit -m 0750 "${config_root}"
if [[ ! -f "${config_root}/service.json" ]]; then
  install -o root -g claudit -m 0640 "${source_root}/service/service.json" "${config_root}/service.json"
fi
if [[ ! -f "${config_root}/claudit.env" ]]; then
  install -o root -g claudit -m 0640 /dev/null "${config_root}/claudit.env"
fi

install -d -o claudit -g claudit -m 0750 "${data_root}" "${data_root}/reports" "${data_root}/reports/dashboard" "${data_root}/.config" "${data_root}/.aws" "${data_root}/.azure"
install -o root -g root -m 0644 "${source_root}/service/claudit.service" /etc/systemd/system/claudit.service

runuser -u claudit -- /usr/bin/pwsh -NoLogo -NoProfile -NonInteractive -File "${install_root}/service/Start-ClauditService.ps1" -ConfigPath "${config_root}/service.json" -ValidateOnly

systemctl daemon-reload
systemctl enable claudit.service
if [[ ${start_service} -eq 1 ]]; then
  systemctl restart claudit.service
fi

echo "claudit: installed successfully."
echo "claudit: status: sudo systemctl status claudit --no-pager"
echo "claudit: UI tunnel: ssh -L 8765:127.0.0.1:8765 <ubuntu-host>"
echo "claudit: then open http://127.0.0.1:8765/"
