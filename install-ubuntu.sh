#!/usr/bin/env bash
set -euo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_root="/opt/claudit"
config_root="/etc/claudit"
data_root="/var/lib/claudit"
start_service=1
dry_run=0

usage() {
  cat <<'EOF'
Usage: sudo bash ./install-ubuntu.sh [--no-start] [--dry-run]

Installs Claudit under /opt/claudit, creates the restricted claudit service
account, persistent storage under /var/lib/claudit and a systemd unit.
Existing /etc/claudit/service.json and /etc/claudit/claudit.env are preserved.
Legacy baselines, wizard profiles and reports are migrated without overwrite.
--dry-run validates the source tree and deployment prerequisites without
changing the host; it does not require root.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-start) start_service=0 ;;
    --dry-run) dry_run=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 64 ;;
  esac
  shift
done

if [[ ${EUID} -ne 0 && ${dry_run} -ne 1 ]]; then
  echo "claudit: installer must run as root (use sudo)." >&2
  exit 77
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "claudit: systemd/systemctl is required." >&2
  exit 69
fi
if ! command -v bash >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  echo "claudit: bash, jq and curl are required before installation." >&2
  exit 69
fi
if [[ ! -f "${source_root}/claudit.sh" || ! -f "${source_root}/service/claudit.service" ]]; then
  echo "claudit: run this installer from a complete Claudit source tree." >&2
  exit 66
fi
if [[ ! -x "${source_root}/service/claudit-service.sh" || ! -f "${source_root}/config/runtime-control-catalog.json" ]]; then
  echo "claudit: Bash runtime service launcher or control catalog is missing." >&2
  exit 66
fi
if ! bash -n "${source_root}/claudit.sh" "${source_root}/lib/"*.sh "${source_root}/checks/"*.sh "${source_root}/service/claudit-service.sh"; then
  echo "claudit: source tree has a Bash syntax error." >&2
  exit 65
fi
jq -e '.Version | type == "string"' "${source_root}/config/runtime-control-catalog.json" >/dev/null || { echo 'claudit: runtime control catalog is invalid.' >&2; exit 65; }
if [[ ${dry_run} -eq 1 ]]; then
  echo 'claudit: deployment dry-run passed; no host state was changed.'
  exit 0
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
  # Preserve a pre-Bash baseline verbatim. The Bash core treats baselines as
  # policy input and never mutates operator data during an upgrade.
  install -o root -g claudit -m 0640 "${legacy_baseline_backup}" "${merged_baseline}"
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
for directory in backends checks config docs lib service tests web schemas legacy; do
  rm -rf -- "${install_root:?}/${directory}"
done
find "${install_root}" -mindepth 1 -maxdepth 1 -type f \( -name '*.ps1' -o -name '*.psm1' -o -name '*.psd1' -o -name '*.sh' -o -name '*.md' \) -delete
install -d -o root -g root -m 0755 "${install_root}/backends" "${install_root}/checks" "${install_root}/config" "${install_root}/docs" "${install_root}/lib" "${install_root}/service" "${install_root}/tests" "${install_root}/web" "${install_root}/schemas" "${install_root}/legacy"
cp -a "${source_root}/backends/." "${install_root}/backends/"
cp -a "${source_root}/checks/." "${install_root}/checks/"
cp -a "${source_root}/config/." "${install_root}/config/"
cp -a "${source_root}/docs/." "${install_root}/docs/"
cp -a "${source_root}/lib/." "${install_root}/lib/"
cp -a "${source_root}/service/." "${install_root}/service/"
cp -a "${source_root}/tests/." "${install_root}/tests/"
cp -a "${source_root}/web/." "${install_root}/web/"
cp -a "${source_root}/schemas/." "${install_root}/schemas/"

cp -a "${source_root}/legacy/." "${install_root}/legacy/"

for file in LICENSE README.md CHANGELOG.md SECURITY.md claudit.sh; do
  install -o root -g root -m 0644 "${source_root}/${file}" "${install_root}/${file}"
done

if [[ -n "${merged_baseline}" ]]; then
  install -o root -g root -m 0644 "${merged_baseline}" "${install_root}/config/baseline.json"
fi

find "${install_root}" -type d -exec chmod 0755 {} +
find "${install_root}" -type f -exec chmod 0644 {} +
chmod 0755 "${install_root}/claudit.sh" "${install_root}/tests/run.sh" "${install_root}/service/claudit-service.sh"
chown -R root:root "${install_root}"

install -d -o root -g claudit -m 0750 "${config_root}"
if [[ ! -f "${config_root}/service.json" ]]; then
  install -o root -g claudit -m 0640 "${source_root}/service/service.json" "${config_root}/service.json"
fi
if [[ ! -f "${config_root}/claudit.env" ]]; then
  install -o root -g claudit -m 0640 /dev/null "${config_root}/claudit.env"
fi

install -o root -g root -m 0644 "${source_root}/service/claudit.service" /etc/systemd/system/claudit.service

runuser -u claudit -- "${install_root}/claudit.sh" doctor --output-directory "${data_root}/reports/install-preflight" >/dev/null

systemctl daemon-reload
systemctl enable claudit.service
if [[ ${start_service} -eq 1 ]]; then
  systemctl restart claudit.service
fi

echo "claudit: installed successfully."
echo "claudit: status: sudo systemctl status claudit --no-pager"
echo "claudit: UI tunnel: ssh -L 8765:127.0.0.1:8765 <ubuntu-host>"
echo "claudit: then open http://127.0.0.1:8765/"
