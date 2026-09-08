"""Private, file-backed assessment sessions and evidence-grounded guidance."""
from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCOPE_FIELDS = ('service', 'domain', 'vpsTarget', 'awsProfile', 'awsRegion',
                'azureSubscription', 'gcpProject', 'tailscaleTailnet', 'organization')
DNS_TYPES = {'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA'}
HISTORY_LIMIT = 500
OPERATION_LIMIT = 200


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, value: Any) -> None:
    temporary = path.with_name(path.name + '.' + secrets.token_hex(4) + '.tmp')
    with temporary.open('x', encoding='utf-8') as stream:
        temporary.chmod(0o600)
        json.dump(value, stream, indent=2)
    temporary.replace(path)


def dns_name(value: str) -> bool:
    return len(value) <= 253 and all(re.fullmatch(r'[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?', label) for label in value.split('.'))


class Workspace:
    def __init__(self, cockpit: Any) -> None:
        self.cockpit = cockpit
        self.root = cockpit.data_root / 'sessions'
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.archive_root = self.root / 'archive'
        self.quarantine_root = self.root / 'quarantine'
        self.archive_root.mkdir(mode=0o700, exist_ok=True)
        self.quarantine_root.mkdir(mode=0o700, exist_ok=True)

    def path(self, session_id: str, archived: bool = False) -> Path:
        if not re.fullmatch(r'[a-f0-9]{24}', session_id):
            raise ValueError('Invalid session identifier.')
        return (self.archive_root if archived else self.root) / (session_id + '.json')

    def load(self, session_id: str) -> dict:
        path = self.path(session_id)
        if not path.is_file():
            path = self.path(session_id, archived=True)
        try:
            session = json.loads(path.read_text())
            if not isinstance(session, dict) or session.get('schema') != 'claudit/session-v1' or session.get('id') != session_id:
                raise ValueError('Invalid session document.')
            session['archived'] = path.parent == self.archive_root
            return session
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError('Session is unavailable.') from exc

    def index(self) -> list[dict]:
        result = []
        for path in [*self.root.glob('*.json'), *self.archive_root.glob('*.json')]:
            try:
                session = self.load(path.stem)
            except ValueError:
                result.append({'id': path.stem, 'title': 'Unreadable session', 'scope': {}, 'updatedAt': '', 'status': 'error', 'archived': path.parent == self.archive_root})
                continue
            result.append({**{key: session[key] for key in ('id', 'title', 'scope', 'updatedAt')}, 'archived': session['archived']})
        return sorted(result, key=lambda item: item['updatedAt'], reverse=True)

    def create(self, request: dict) -> dict:
        title = request.get('title', '')
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 120:
            raise ValueError('Give the work session a title (1–120 characters).')
        source = request.get('scope', {})
        if not isinstance(source, dict):
            raise ValueError('Scope must be an object.')
        scope = {key: source[key] for key in SCOPE_FIELDS if key in source}
        if isinstance(scope.get('domain'), str): scope['domain'] = scope['domain'].lower().rstrip('.')
        self.cockpit.validate_request({**scope, 'mode': 'safe', 'controlLevel': 'formal'})
        records = request.get('dnsRecords', [])
        if not isinstance(records, list) or len(records) > 50:
            raise ValueError('Declare at most 50 DNS RRsets.')
        domain = str(scope.get('domain', '')).lower().rstrip('.')
        seen = set()
        for record in records:
            if not isinstance(record, dict) or set(record) != {'name', 'type', 'values'}:
                raise ValueError('Each DNS RRset needs name, type and values.')
            name, kind, values = record['name'], record['type'], record['values']
            if not isinstance(name, str) or not isinstance(kind, str):
                raise ValueError('DNS name and type must be text.')
            name = name.lower().rstrip('.')
            kind = kind.upper()
            if not domain or not dns_name(name) or not (name == domain or name.endswith('.' + domain)) or kind not in DNS_TYPES:
                raise ValueError('DNS RRsets must be within the declared domain and use a supported record type.')
            if (name, kind) in seen:
                raise ValueError('Duplicate DNS RRset; combine its values.')
            seen.add((name, kind))
            if not isinstance(values, list) or len(values) > 30 or any(not isinstance(v, str) or not 1 <= len(v) <= 2048 or '\n' in v for v in values):
                raise ValueError('DNS values must be a list of at most 30 single-line strings; an empty list means expected absence.')
            record.update(name=name, type=kind, values=sorted(set(values)))
        expectations = request.get('expectedStatuses', {})
        catalog = json.loads((self.cockpit.app_root / 'config/runtime-control-catalog.json').read_text())
        ids = {entry['Id'] for entry in catalog['Controls']}
        if not isinstance(expectations, dict) or any(key not in ids or value not in ('pass', 'not_applicable', 'info') for key, value in expectations.items()):
            raise ValueError('Expected statuses must map catalog IDs to pass, info or not_applicable.')
        baseline = json.loads((self.cockpit.app_root / 'config/baseline.json').read_text())
        allowed = baseline['Domain']['AuthorizedDomains']
        if domain and allowed and domain not in allowed:
            raise ValueError('The domain is outside the configured authorization policy.')
        baseline['Domain']['ExpectedRecords'] = records
        session = {'schema': 'claudit/session-v1', 'id': secrets.token_hex(12), 'title': title.strip(),
                   'scope': scope, 'baseline': baseline, 'expectedStatuses': expectations,
                   'createdAt': now(), 'updatedAt': now(), 'history': [], 'operations': []}
        write_json(self.path(session['id']), session)
        return session

    def save(self, session: dict) -> dict:
        if session.get('archived'):
            raise ValueError('Archived sessions are read-only; restore by exporting into a new session.')
        session['history'] = session.get('history', [])[-HISTORY_LIMIT:]
        session['operations'] = session.get('operations', [])[-OPERATION_LIMIT:]
        session.pop('archived', None)
        session['updatedAt'] = now()
        write_json(self.path(session['id']), session)
        return session

    def export(self, session_id: str) -> dict:
        return self.load(session_id)

    def plan(self, session_id: str) -> dict:
        session = self.load(session_id)
        services = set(session['scope'].get('service', []))
        if 'M365' in services:
            services.update({'Entra', 'SharePoint', 'OneDrive', 'Exchange'})
        catalog = json.loads((self.cockpit.app_root / 'config/runtime-control-catalog.json').read_text())['Controls']
        controls = [{'id': item['Id'], 'service': item['Service'], 'level': item['Level'], 'category': item['Category']}
                    for item in catalog if item['Service'] in services]
        capabilities = [item for item in self.cockpit.baseline_capabilities
                        if item['Path'].split('.', 1)[0] in services]
        questions = []
        for service in sorted(services):
            questions.extend({
                'Domain': ['Which DNS records differ from the known configuration?', 'Is DNSSEC evidence authenticated?', 'What should be changed before reassessment?'],
                'AWS': ['Are root MFA, CloudTrail and VPC Flow Logs verified?', 'Are privileged ingress or stale access keys present?'],
                'Azure': ['Do Activity Log alerts cover required categories?', 'Are privileged roles, storage and Key Vault settings within baseline?'],
                'GCP': ['Are audit logs, OS Login and the central sink verified?', 'Are primitive roles or stale service-account keys present?'],
                'VPS': ['Was the declared SSH endpoint reachable and host-key trusted?'],
                'Entra': ['Which Entra controls have usable Graph evidence?'],
                'SharePoint': ['Does sharing and legacy authentication meet the baseline?'],
                'OneDrive': ['Do sync restrictions and retention meet the baseline?'],
                'Exchange': ['Which Exchange controls failed or lack evidence?'],
            }.get(service, []))
        return {'session': session['id'], 'steps': [
            'Run Formal to validate local scope and prerequisites without provider contact.',
            'Authorize Passive to collect read-only evidence for the fixed scope.',
            'Review failed, warning, unknown and error findings with their cited remediation.',
            'Apply approved changes outside Claudit, record the decision, then reassess the same scope.',
        ], 'controls': controls, 'capabilities': capabilities, 'suggestedQuestions': questions,
                'limitations': ['Active adds only declared HTTPS and SSH reachability probes.', 'Unsupported baseline entries remain descriptive and never pass.', 'DNS changes are review plans; Claudit does not mutate provider zones.']}

    def normalize_dns_import(self, request: dict) -> dict:
        provider, domain, payload = request.get('provider'), str(request.get('domain', '')).lower().rstrip('.'), request.get('data')
        if provider not in {'route53', 'azure', 'gcp', 'cloudflare'} or not domain or not dns_name(domain):
            raise ValueError('Choose a supported DNS export format and declared root domain.')
        grouped: dict[tuple[str, str], set[str]] = {}

        def add(name: Any, kind: Any, value: Any) -> None:
            if not all(isinstance(item, str) for item in (name, kind, value)):
                return
            owner, record_type = name.lower().rstrip('.'), kind.upper()
            if record_type in DNS_TYPES and (owner == domain or owner.endswith('.' + domain)) and value:
                grouped.setdefault((owner, record_type), set()).add(value)

        try:
            if provider == 'route53':
                for record in payload['ResourceRecordSets']:
                    for value in record.get('ResourceRecords', []): add(record.get('Name'), record.get('Type'), value.get('Value'))
            elif provider == 'gcp':
                for record in payload:
                    for value in record.get('rrdatas', []): add(record.get('name'), record.get('type'), value)
            elif provider == 'cloudflare':
                for record in payload['result']:
                    value = record.get('content')
                    if record.get('type') == 'MX' and isinstance(record.get('priority'), int): value = f"{record['priority']} {value}"
                    add(record.get('name'), record.get('type'), value)
            else:
                properties = {'A': ('aRecords', 'ipv4Address'), 'AAAA': ('aaaaRecords', 'ipv6Address'), 'MX': ('mxRecords', 'exchange'), 'NS': ('nsRecords', 'nsdname')}
                for record in payload:
                    kind = str(record.get('type', '')).rsplit('/', 1)[-1].upper()
                    name = record.get('fqdn') or record.get('name')
                    if kind in properties:
                        collection, field = properties[kind]
                        for value in record.get(collection, []):
                            rendered = value.get(field)
                            if kind == 'MX' and isinstance(value.get('preference'), int): rendered = f"{value['preference']} {rendered}"
                            add(name, kind, rendered)
                    elif kind == 'CNAME': add(name, kind, (record.get('cnameRecord') or {}).get('cname'))
                    elif kind == 'TXT':
                        for value in record.get('txtRecords', []): add(name, kind, '"' + ''.join(value.get('value', [])) + '"')
                    elif kind == 'CAA':
                        for value in record.get('caaRecords', []): add(name, kind, f"{value.get('flags', 0)} {value.get('tag', '')} \"{value.get('value', '')}\"")
        except (KeyError, TypeError) as exc:
            raise ValueError('The DNS export does not match the selected provider format.') from exc
        records = [{'name': name, 'type': kind, 'values': sorted(values)} for (name, kind), values in sorted(grouped.items())]
        if not records or len(records) > 50 or any(len(item['values']) > 30 for item in records):
            raise ValueError('The DNS export has no usable in-scope RRsets or exceeds session limits.')
        return {'provider': provider, 'domain': domain, 'records': records, 'readOnly': True}

    def archive(self, request: dict) -> dict:
        session_id = str(request.get('id', ''))
        source, target = self.path(session_id), self.path(session_id, archived=True)
        if not source.is_file():
            raise ValueError('Only an active session can be archived.')
        source.replace(target)
        return {'id': session_id, 'archived': True}

    def delete(self, session_id: str) -> dict:
        target = self.path(session_id, archived=True)
        if not target.is_file():
            raise ValueError('Archive the session before permanent deletion.')
        target.unlink()
        return {'id': session_id, 'deleted': True}

    def quarantine(self, request: dict) -> dict:
        session_id = str(request.get('id', ''))
        source = self.path(session_id)
        if not source.is_file():
            source = self.path(session_id, archived=True)
        try:
            self.load(session_id)
        except ValueError:
            target = self.quarantine_root / f'{session_id}-{datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")}.json'
            source.replace(target)
            return {'id': session_id, 'quarantined': True}
        raise ValueError('The session is readable and does not require recovery.')

    def run(self, request: dict) -> dict:
        session = self.load(str(request.get('id', '')))
        if session.get('archived'):
            raise ValueError('Archived sessions are read-only; restore by exporting into a new session.')
        level = request.get('controlLevel', 'formal')
        operation = self.cockpit.start_operation({**session['scope'], 'mode': 'audit', 'controlLevel': level,
                    'confirmTenantConnection': request.get('confirmTenantConnection'),
                    'confirmActiveProbes': request.get('confirmActiveProbes'), 'format': 'all'},
                    baseline=session['baseline'], session_id=session['id'])
        session['operations'].append(operation['Id'])
        session['history'].append({'at': now(), 'kind': 'run', 'operation': operation['Id'], 'level': level})
        self.save(session)
        return operation

    def evidence(self, session: dict) -> tuple[dict | None, str | None]:
        operations = {item['Id']: item for item in self.cockpit.operation_views()}
        for operation_id in reversed(session['operations']):
            operation = operations.get(operation_id, {})
            if operation.get('Status') != 'Succeeded' or operation.get('Command') not in ('passive', 'active'):
                continue
            relative = f'dashboard/{operation_id}/output/claudit-report.json'
            try:
                return json.loads(self.cockpit.report_path(relative).read_text()), relative
            except (ValueError, OSError, json.JSONDecodeError):
                continue
        return None, None

    def query(self, request: dict) -> dict:
        session = self.load(str(request.get('id', '')))
        question = request.get('question', '')
        if not isinstance(question, str) or not 1 <= len(question.strip()) <= 2000:
            raise ValueError('Enter a question or note (1–2000 characters).')
        if request.get('kind') == 'note':
            session['history'].append({'at': now(), 'kind': 'note', 'text': question})
            self.save(session)
            return {'answer': 'Note saved in this work session.', 'findings': []}
        document, source = self.evidence(session)
        result = {'answer': '', 'source': source, 'findings': [], 'configurationDrift': [], 'generatedAt': now()}
        if document is None:
            result['answer'] = 'No completed passive or active evidence is available for this session. Start with Formal to validate scope, then authorize Passive collection. Formal checks do not establish security posture.'
        else:
            latest_attempt = session['operations'][-1] if session['operations'] else None
            result['usesEarlierRun'] = latest_attempt is not None and latest_attempt not in source
            result['dnsPlan'] = []
            plan_path = self.cockpit.reports_root / source.replace('claudit-report.json', 'claudit-dns-plan.jsonl')
            if plan_path.is_file():
                result['dnsPlan'] = [json.loads(line) for line in plan_path.read_text().splitlines()]
            findings = document.get('findings', [])
            terms = set(re.findall(r'[a-z0-9-]{3,}', question.lower())) - {'what', 'the', 'are', 'and', 'why', 'how', 'should', 'next', 'check', 'checks'}
            selected = [f for f in findings if any(term in ' '.join(str(f.get(k, '')) for k in ('id', 'service', 'title', 'category')).lower() for term in terms)]
            if not selected:
                selected = [f for f in findings if f['status'] in ('fail', 'error', 'unknown', 'warning')]
            priority = {'error': 0, 'unknown': 1, 'fail': 2, 'warning': 3}
            selected.sort(key=lambda f: (priority.get(f['status'], 4), f['id']))
            result['findings'] = [{key: f.get(key) for key in ('id', 'status', 'title', 'detail', 'remediation', 'observed_at')} for f in selected[:12]]
            indexed = {f['id']: f for f in findings}
            result['configurationDrift'] = [{'id': key, 'expected': expected, 'observed': indexed.get(key, {}).get('status', 'unknown')} for key, expected in session['expectedStatuses'].items() if indexed.get(key, {}).get('status') != expected]
            missing = sum(f['status'] in ('unknown', 'error') for f in findings)
            result['answer'] = (f"Using session evidence observed at {document.get('generated_at', 'unknown time')}. "
                                f"{missing} controls lack usable evidence. Resolve collection gaps and review each cited remediation; repeat the same scope after changes. "
                                'Active mode adds only the declared HTTPS/SSH probes. These observations do not establish overall cloud compliance.')
        if result.get('usesEarlierRun'):
            result['answer'] = 'A newer attempt has no completed assessment evidence; this answer uses an earlier run. ' + result['answer']
        session['history'].append({'at': now(), 'kind': 'query', 'question': question, 'response': result})
        self.save(session)
        return result
