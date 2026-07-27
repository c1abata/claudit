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
Legacy baselines, wizard profiles and reports are migrated without overwrite.
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

if [[ "${install_root}" != "/opt/claudit" || -L "${install_root}" ]]; then
  echo "claudit: refusing unsafe install root '${install_root}'." >&2
  exit 78
fi

for persistent_path in "${data_root}" "${data_root}/reports" "${data_root}/reports/dashboard" "${data_root}/.config" "${data_root}/.aws" "${data_root}/.azure" "${data_root}/upgrade-backups"; do
  if [[ -L "${persistent_path}" ]]; then
    echo "claudit: refusing symlinked persistent path '${persistent_path}'." >&2
    exit 78
  fi
done
install -d -o claudit -g claudit -m 0750 "${data_root}" "${data_root}/reports" "${data_root}/reports/dashboard" "${data_root}/.config" "${data_root}/.aws" "${data_root}/.azure"

# Preserve the mutable files used by pre-0.3 source-tree installs before
# replacing the managed application set. Raw backups make this recoverable;
# the active baseline is merged later with the new packaged defaults.
upgrade_stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
upgrade_backup="${data_root}/upgrade-backups/${upgrade_stamp}"
legacy_baseline_backup=""
merged_baseline=""
legacy_profile="${install_root}/config/wizard.profile.json"
if [[ -f "${install_root}/config/baseline.json" || -f "${legacy_profile}" ]]; then
  install -d -o root -g claudit -m 0750 "${upgrade_backup}"
  if [[ -f "${install_root}/config/baseline.json" ]]; then
    install -o root -g claudit -m 0640 "${install_root}/config/baseline.json" "${upgrade_backup}/baseline.json"
    legacy_baseline_backup="${upgrade_backup}/baseline.json"
  fi
  if [[ -f "${legacy_profile}" ]]; then
    install -o claudit -g claudit -m 0600 "${legacy_profile}" "${upgrade_backup}/wizard.profile.json"
    if [[ -L "${data_root}/.config/claudit" ]]; then
      echo "claudit: refusing symlinked profile directory '${data_root}/.config/claudit'." >&2
      exit 78
    fi
    install -d -o claudit -g claudit -m 0700 "${data_root}/.config/claudit"
    if [[ ! -e "${data_root}/.config/claudit/wizard.profile.json" && ! -L "${data_root}/.config/claudit/wizard.profile.json" ]]; then
      install -o claudit -g claudit -m 0600 "${legacy_profile}" "${data_root}/.config/claudit/wizard.profile.json"
    fi
  fi
fi

if [[ -n "${legacy_baseline_backup}" ]]; then
  merged_baseline="${upgrade_backup}/merged-baseline.json"
  /usr/bin/pwsh -NoLogo -NoProfile -NonInteractive -File "${source_root}/service/Merge-ClauditBaseline.ps1" \
    -DefaultPath "${source_root}/config/baseline.json" \
    -LegacyPath "${legacy_baseline_backup}" \
    -DestinationPath "${merged_baseline}"
  chmod 0640 "${merged_baseline}"
  /usr/bin/pwsh -NoLogo -NoProfile -NonInteractive -Command \
    '& { param($modulePath, $baselinePath) Import-Module -LiteralPath $modulePath -Force -ErrorAction Stop; Get-CaBaseline -Path $baselinePath -Force | Out-Null }' \
    "${source_root}/Claudit.psd1" "${merged_baseline}"
fi

# Older wizard runs lived below /opt/claudit/reports. Copy regular files into
# one immutable compatibility tree and leave the legacy source untouched.
if [[ -d "${install_root}/reports" && ! -L "${install_root}/reports" ]]; then
  legacy_report_root="${data_root}/reports/legacy-pre-0.3"
  if [[ -L "${legacy_report_root}" ]]; then
    echo "claudit: refusing symlinked legacy report path '${legacy_report_root}'." >&2
    exit 78
  fi
  if [[ ! -e "${legacy_report_root}" ]]; then
    legacy_report_stage="${data_root}/reports/.legacy-pre-0.3-${upgrade_stamp}.tmp"
    install -d -o root -g claudit -m 0750 "${legacy_report_stage}"
    while IFS= read -r -d '' legacy_report; do
      relative_report="${legacy_report#"${install_root}/reports/"}"
      destination_report="${legacy_report_stage}/${relative_report}"
      install -d -o root -g claudit -m 0750 "$(dirname "${destination_report}")"
      install -o root -g claudit -m 0640 "${legacy_report}" "${destination_report}"
    done < <(find -P "${install_root}/reports" -type f -print0)
    mv -- "${legacy_report_stage}" "${legacy_report_root}"
  fi
fi

install -d -o root -g root -m 0755 "${install_root}"
for directory in src config docs service tests web schemas; do
  rm -rf -- "${install_root:?}/${directory}"
done
find "${install_root}" -mindepth 1 -maxdepth 1 -type f \( -name '*.ps1' -o -name '*.psm1' -o -name '*.psd1' -o -name '*.sh' -o -name '*.md' \) -delete
install -d -o root -g root -m 0755 "${install_root}/src" "${install_root}/config" "${install_root}/docs" "${install_root}/service" "${install_root}/tests" "${install_root}/web" "${install_root}/schemas"
cp -a "${source_root}/src/." "${install_root}/src/"
cp -a "${source_root}/config/." "${install_root}/config/"
cp -a "${source_root}/docs/." "${install_root}/docs/"
cp -a "${source_root}/service/." "${install_root}/service/"
cp -a "${source_root}/tests/." "${install_root}/tests/"
cp -a "${source_root}/web/." "${install_root}/web/"
cp -a "${source_root}/schemas/." "${install_root}/schemas/"

for file in LICENSE README.md CHANGELOG.md SECURITY.md Claudit.psd1 Claudit.psm1 claudit.ps1 claudit.sh Install-ClauditPrerequisites.ps1 Invoke-ClauditAudit.ps1 Reset-ClauditEnvironment.ps1 Start-ClauditDashboard.ps1 Start-ClauditSafeAudit.ps1 Start-ClauditWizard.ps1 Test-ClauditPreflight.ps1; do
  install -o root -g root -m 0644 "${source_root}/${file}" "${install_root}/${file}"
done

if [[ -n "${merged_baseline}" ]]; then
  install -o root -g root -m 0644 "${merged_baseline}" "${install_root}/config/baseline.json"
fi

find "${install_root}" -type d -exec chmod 0755 {} +
find "${install_root}" -type f -exec chmod 0644 {} +
chmod 0755 "${install_root}/claudit.sh"
chown -R root:root "${install_root}"

install -d -o root -g claudit -m 0750 "${config_root}"
if [[ ! -f "${config_root}/service.json" ]]; then
  install -o root -g claudit -m 0640 "${source_root}/service/service.json" "${config_root}/service.json"
fi
if [[ ! -f "${config_root}/claudit.env" ]]; then
  install -o root -g claudit -m 0640 /dev/null "${config_root}/claudit.env"
fi

install -o root -g root -m 0644 "${source_root}/service/claudit.service" /etc/systemd/system/claudit.service

/usr/bin/pwsh -NoLogo -NoProfile -NonInteractive -Command \
  '& { param($modulePath, $baselinePath) Import-Module -LiteralPath $modulePath -Force -ErrorAction Stop; Get-CaBaseline -Path $baselinePath -Force | Out-Null }' \
  "${install_root}/Claudit.psd1" "${install_root}/config/baseline.json"
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
