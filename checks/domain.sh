#!/usr/bin/env bash
# Public-business-domain checks. Passive collection is DNS only; active mode
# performs one bounded TLS/HEAD handshake to the exact declared root domain.

ca_dns_lookup() {
    local name="$1" type="$2" key response
    key="${name}|${type}"
    if [[ -n "$CLAUDIT_DOH_FIXTURE" ]]; then
        [[ -r "$CLAUDIT_DOH_FIXTURE" && ! -L "$CLAUDIT_DOH_FIXTURE" ]] || return 1
        jq -cer --arg key "$key" '.[$key]' "$CLAUDIT_DOH_FIXTURE" 2>/dev/null
        return
    fi
    response="$(curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 10 --get \
        --data-urlencode "name=$name" --data-urlencode "type=$type" \
        'https://cloudflare-dns.com/dns-query' -H 'accept: application/dns-json' 2>/dev/null)" || return 1
    jq -ce . <<<"$response" 2>/dev/null
}

ca_dns_answers() { jq -r '.Answer[]?.data // empty' <<<"$1"; }
ca_domain_authorized() {
    local domain="$1"
    jq -e --arg domain "$domain" '(.Domain.AuthorizedDomains // []) as $domains | ($domains | length == 0) or ($domains | index($domain) != null)' "$(ca_baseline_path)" >/dev/null
}

ca_check_domain() {
    local domain="$CLAUDIT_DOMAIN" response records spf dmarc policy selector found=0 dkim_collected=0
    if [[ -z "$domain" ]]; then ca_finding CA-DNS-000 Domain unknown medium 'Business domain scope required' 'Provide one explicitly authorized business domain.'; return; fi
    [[ "$domain" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]$ ]] || { ca_finding CA-DNS-000 Domain error high 'Invalid business domain scope' 'The supplied domain is not a valid hostname.'; return; }
    if ! ca_domain_authorized "$domain"; then ca_finding CA-DNS-000 Domain error high 'Business domain is outside policy scope' "The declared domain is not present in Domain.AuthorizedDomains."; return; fi
    ca_finding CA-DNS-000 Domain pass info 'Business domain scope accepted' "Declared domain '$domain' is valid and within the local authorized scope policy."
    [[ "$CLAUDIT_LEVEL" != formal ]] || return

    for selector in A AAAA MX NS CAA; do
        response="$(ca_dns_lookup "$domain" "$selector" || true)"
        if [[ -z "$response" ]]; then ca_finding "CA-DNS-$selector" Domain unknown medium "DNS $selector lookup unavailable" "The DNS resolver did not return a valid $selector response for $domain."; continue; fi
        records="$(ca_dns_answers "$response")"
        if [[ -n "$records" ]]; then
            if [[ "$selector" == NS ]] && (( $(wc -l <<<"$records") < 2 )); then ca_finding CA-DNS-NS Domain warning medium 'Insufficient authoritative DNS redundancy' "Only one NS record was returned for $domain."; else ca_finding "CA-DNS-$selector" Domain pass info "DNS $selector record resolved" "Public DNS returned $(wc -l <<<"$records") $selector record(s) for $domain."; fi
        elif [[ "$selector" == NS ]]; then ca_finding CA-DNS-NS Domain fail high 'Authoritative name servers absent' "No NS record was returned for $domain."; else ca_finding "CA-DNS-$selector" Domain unknown low "DNS $selector record absent" "No public $selector answer was returned for $domain; applicability requires operator review."; fi
    done

    response="$(ca_dns_lookup "$domain" TXT || true)"
    if [[ -z "$response" ]]; then ca_finding CA-DNS-SPF Domain unknown medium 'SPF lookup unavailable' "TXT records could not be collected for $domain."; else
        spf="$(ca_dns_answers "$response" | tr -d '"' | awk 'tolower($0) ~ /^v=spf1([[:space:]]|$)/ {print}')"
        if (( $(wc -l <<<"$spf") > 1 )); then ca_finding CA-DNS-SPF Domain fail high 'Multiple SPF records published' 'Multiple SPF records create an invalid and unpredictable sender policy.'
        elif [[ -z "$spf" ]]; then ca_finding CA-DNS-SPF Domain warning medium 'SPF record absent' 'No SPF policy was found; confirm that this business domain does not send mail.'
        elif (( $(grep -Eo '(^|[[:space:]])(include:|a[:[:space:]]|mx[:[:space:]]|exists:|ptr[:[:space:]])' <<<"$spf" | wc -l) > 10 )); then ca_finding CA-DNS-SPF Domain warning high 'SPF may exceed DNS lookup limit' 'The published SPF text contains more than ten DNS-lookup mechanisms; validate it with the active mail providers.'
        else ca_finding CA-DNS-SPF Domain pass info 'SPF policy present' 'One SPF policy was found with no obvious static lookup-limit violation.'; fi
    fi

    response="$(ca_dns_lookup "_dmarc.$domain" TXT || true)"
    dmarc="$(ca_dns_answers "$response" | tr -d '"' | awk 'tolower($0) ~ /^v=dmarc1;/ {print; exit}')"
    if [[ -z "$response" ]]; then ca_finding CA-DNS-DMARC Domain unknown medium 'DMARC lookup unavailable' "The resolver could not collect _dmarc.$domain."
    elif [[ -z "$dmarc" ]]; then ca_finding CA-DNS-DMARC Domain fail high 'DMARC record absent' "No DMARC policy was found for _dmarc.$domain."
    else
        policy="$(tr '[:upper:]' '[:lower:]' <<<"$dmarc" | sed -nE 's/.*(^|;[[:space:]]*)p=([^;[:space:]]+).*/\2/p')"
        case "$policy" in reject|quarantine) ca_finding CA-DNS-DMARC Domain pass info 'DMARC enforcement enabled' "DMARC policy '$policy' is published for $domain.";; none) ca_finding CA-DNS-DMARC Domain warning medium 'DMARC monitoring-only policy' 'DMARC is present but p=none does not enforce spoofing protection.';; *) ca_finding CA-DNS-DMARC Domain unknown medium 'DMARC policy unreadable' 'A DMARC record was returned but its p= value could not be evaluated.';; esac
    fi

    response="$(ca_dns_lookup "$domain" DNSKEY || true)"
    if ca_baseline_enabled '.Domain.RequireDnssec'; then
        if [[ -n "$response" ]] && jq -e '(.AD == true) or ((.Answer // []) | length > 0)' >/dev/null <<<"$response"; then ca_finding CA-DNS-DNSSEC Domain pass info 'DNSSEC material observed' 'The resolver returned authenticated DNSSEC material for the declared domain.'; else ca_finding CA-DNS-DNSSEC Domain unknown medium 'DNSSEC not verified' 'DNSSEC could not be verified from the configured resolver; do not treat this as proof of absence.'; fi
    else ca_finding CA-DNS-DNSSEC Domain info info 'DNSSEC policy not required' 'The local baseline does not require DNSSEC for this domain.'; fi

    response="$(ca_dns_lookup "_mta-sts.$domain" TXT || true)"
    if [[ -z "$response" ]]; then ca_finding CA-DNS-MTA-STS Domain unknown low 'MTA-STS lookup unavailable' 'MTA-STS applicability could not be assessed because DNS collection failed.'
    elif ca_dns_answers "$response" | tr -d '"' | grep -qi '^v=STSv1;'; then ca_finding CA-DNS-MTA-STS Domain pass info 'MTA-STS policy advertised' 'An MTA-STS DNS policy is published.'
    else ca_finding CA-DNS-MTA-STS Domain warning low 'MTA-STS policy absent' 'No MTA-STS TXT policy was found; assess applicability for inbound business mail.'; fi
    response="$(ca_dns_lookup "_smtp._tls.$domain" TXT || true)"
    if [[ -z "$response" ]]; then ca_finding CA-DNS-TLS-RPT Domain unknown low 'TLS-RPT lookup unavailable' 'TLS-RPT applicability could not be assessed because DNS collection failed.'
    elif ca_dns_answers "$response" | tr -d '"' | grep -qi '^v=TLSRPTv1;'; then ca_finding CA-DNS-TLS-RPT Domain pass info 'TLS-RPT policy advertised' 'A TLS-RPT DNS policy is published.'
    else ca_finding CA-DNS-TLS-RPT Domain warning low 'TLS-RPT policy absent' 'No TLS-RPT policy was found; failed mail TLS delivery will have less visibility.'; fi

    for selector in $(jq -r '.Domain.DkimSelectors[]?' "$(ca_baseline_path)"); do
        response="$(ca_dns_lookup "${selector}._domainkey.$domain" TXT || true)"
        [[ -n "$response" ]] || continue
        dkim_collected=1
        if ca_dns_answers "$response" | tr -d '"' | grep -qi 'v=DKIM1'; then found=1; break; fi
    done
    if (( found )); then ca_finding CA-DNS-DKIM Domain pass info 'Configured DKIM selector found' 'At least one selector from the local business-domain baseline published a DKIM key.'
    elif (( dkim_collected )); then ca_finding CA-DNS-DKIM Domain warning medium 'No configured DKIM selector found' 'No configured selector returned a DKIM key; update the baseline or publish the current provider selector.'
    else ca_finding CA-DNS-DKIM Domain unknown medium 'DKIM selector lookup unavailable' 'Configured DKIM selectors could not be collected; this is not evidence that keys are absent.'; fi

    if [[ "$CLAUDIT_LEVEL" == active ]]; then
        if curl --fail --silent --show-error --proto '=https' --tlsv1.2 --head --max-time 12 "https://$domain/" >/dev/null 2>&1; then ca_finding CA-DNS-TLS Domain pass info 'Declared HTTPS endpoint completed TLS' "One bounded HTTPS HEAD request completed for $domain."; else ca_finding CA-DNS-TLS Domain unknown medium 'Declared HTTPS endpoint not verified' "The bounded TLS/HTTPS HEAD request to $domain did not complete; inspect DNS, certificate and listener state."; fi
    fi
}
