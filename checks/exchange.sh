#!/usr/bin/env bash

ca_check_exchange() {
    local source_file line status severity id title detail backend
    if [[ "$CLAUDIT_CONFIRM_CONNECTION" -ne 1 ]]; then
        ca_finding CA-EXO-000 Exchange unknown info 'Exchange connection not confirmed' 'Use --confirm-tenant-connection to permit read-only Exchange Online collection.'
        return
    fi
    if [[ -n "$CLAUDIT_EXCHANGE_FIXTURE" ]]; then
        source_file="$CLAUDIT_EXCHANGE_FIXTURE"
        [[ -r "$source_file" ]] || { ca_finding CA-EXO-000 Exchange unknown high 'Exchange fixture unavailable' 'The specified offline Exchange fixture is not readable.'; return; }
    else
        ca_command_exists pwsh || { ca_finding CA-EXO-000 Exchange unknown high 'PowerShell Exchange backend unavailable' 'Install PowerShell 7 and ExchangeOnlineManagement only for Exchange Online controls.'; return; }
        backend="$CLAUDIT_ROOT/backends/exchange.ps1"
        source_file="$(mktemp "$CLAUDIT_OUTPUT_DIRECTORY/.exchange.XXXXXX")"
        if ! pwsh -NoLogo -NoProfile -NonInteractive -File "$backend" -BaselinePath "$(ca_baseline_path)" \
            -Organization "$CLAUDIT_EXCHANGE_ORGANIZATION" -TenantId "$CLAUDIT_EXCHANGE_TENANT_ID" \
            -ClientId "$CLAUDIT_EXCHANGE_CLIENT_ID" -CertificateThumbprint "$CLAUDIT_EXCHANGE_CERTIFICATE_THUMBPRINT" > "$source_file"; then
            rm -f -- "$source_file"
            ca_finding CA-EXO-000 Exchange unknown high 'Exchange collection unavailable' 'The isolated read-only Exchange backend did not complete; verify its module, authentication and read-only RBAC.'
            return
        fi
    fi
    while IFS= read -r line; do
        jq -e 'type == "object" and (.id|type == "string") and (.status|type == "string")' >/dev/null 2>&1 <<<"$line" || continue
        id="$(jq -r .id <<<"$line")"; status="$(jq -r .status <<<"$line")"; severity="$(jq -r '.severity // "info"' <<<"$line")"
        title="$(jq -r '.title // "Exchange control"' <<<"$line")"; detail="$(jq -r '.detail // "No detail returned."' <<<"$line")"
        case "$status" in pass|fail|warning|info|unknown) ;; *) status=unknown ;; esac
        case "$severity" in critical|high|medium|low|info) ;; *) severity=info ;; esac
        ca_finding "$id" Exchange "$status" "$severity" "$title" "$detail"
    done < "$source_file"
    [[ -z "$CLAUDIT_EXCHANGE_FIXTURE" ]] && rm -f -- "$source_file"
    return 0
}
