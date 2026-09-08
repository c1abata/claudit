import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class RuntimeSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.environment = dict(os.environ)
        self.fixture = json.loads((ROOT / 'tests/fixtures/domain/business-example.json').read_text())

    def run_audit(self, *args, fixture=None, baseline=None):
        out = self.root / str(len(list(self.root.iterdir())))
        env = dict(self.environment)
        if fixture is not None:
            p = self.root / 'dns.json'; p.write_text(json.dumps(fixture)); env['CLAUDIT_DOH_FIXTURE'] = str(p)
        command = [str(ROOT / 'claudit.sh'), *args]
        if baseline is not None:
            p = self.root / 'baseline.json'; p.write_text(json.dumps(baseline)); command += ['--baseline', str(p)]
        result = subprocess.run([*command, '--output-directory', str(out), '--format', 'json'], env=env, capture_output=True, text=True, timeout=40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.last_output = out
        return json.loads((out / 'claudit-report.json').read_text())

    def test_formal_overrides_connection_authorization(self):
        binaries = self.root / 'bin'; binaries.mkdir(); marker = self.root / 'network-used'
        for name in ('aws', 'az', 'gcloud', 'ssh', 'curl', 'pwsh'):
            p = binaries / name; p.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 1\n'); p.chmod(0o755)
        self.environment['PATH'] = str(binaries) + ':' + os.environ['PATH']
        self.environment['CLAUDIT_TAILSCALE_TOKEN'] = 'fixture'
        self.run_audit('formal', '--service', 'All', '--domain', 'example.com', '--vps-target', 'example.com', '--confirm-tenant-connection', '--gcp-project', 'fixture')
        self.assertFalse(marker.exists())

    def test_vps_shell_expression_is_rejected_without_execution(self):
        marker = self.root / 'injected'
        doc = self.run_audit('active', '--service', 'VPS', '--vps-target', f'$(touch {marker})', '--confirm-active-probes')
        self.assertFalse(marker.exists())
        self.assertTrue(any(f['id'] == 'CA-VPS-000' and f['status'] == 'error' for f in doc['findings']))

    def test_resolver_errors_do_not_become_absent_records(self):
        fixture = {key: {'Status': 2, 'Answer': []} for key in self.fixture}
        doc = self.run_audit('passive', '--service', 'Domain', '--domain', 'example.com', fixture=fixture)
        results = {f['id']: f['status'] for f in doc['findings']}
        self.assertEqual(results['CA-DNS-DMARC'], 'unknown')
        self.assertEqual(results['CA-DNS-NS'], 'unknown')
        self.assertEqual(results['CA-DNS-SPF'], 'unknown')

    def test_cname_alone_does_not_pass_an_a_check(self):
        self.fixture['example.com|A']['Answer'] = [{'type': 5, 'data': 'elsewhere.example.net.'}]
        doc = self.run_audit('passive', '--service', 'Domain', '--domain', 'example.com', fixture=self.fixture)
        self.assertEqual(next(f['status'] for f in doc['findings'] if f['id'] == 'CA-DNS-A'), 'unknown')

    def test_dnskey_without_authentication_is_not_verified(self):
        self.fixture['example.com|DNSKEY']['AD'] = False
        baseline = json.loads((ROOT / 'config/baseline.json').read_text()); baseline['Domain']['RequireDnssec'] = True
        p = self.root / 'baseline.json'; p.write_text(json.dumps(baseline))
        doc = self.run_audit('passive', '--service', 'Domain', '--domain', 'example.com', '--baseline', str(p), fixture=self.fixture)
        self.assertEqual(next(f['status'] for f in doc['findings'] if f['id'] == 'CA-DNS-DNSSEC'), 'unknown')

    def test_explicit_private_resolver_is_retained_without_fallback(self):
        baseline = json.loads((ROOT / 'config/baseline.json').read_text())
        baseline['Domain']['Resolver'] = {
            'Name': 'Internal DNS-over-HTTPS',
            'Endpoint': 'https://resolver.audit.internal/dns-query',
            'Private': True,
            'TimeoutSeconds': 7,
        }
        self.run_audit('passive', '--service', 'Domain', '--domain', 'example.com', fixture=self.fixture, baseline=baseline)
        evidence = [json.loads(line) for line in (self.last_output / 'claudit-dns-evidence.jsonl').read_text().splitlines()]
        self.assertTrue(evidence)
        self.assertTrue(all(item['resolver'] == {
            'name': 'Internal DNS-over-HTTPS', 'endpoint': 'https://resolver.audit.internal/dns-query',
            'private': True, 'timeout_seconds': 7, 'transport': 'dns-over-https', 'fallback': 'disabled',
        } for item in evidence))

    def test_resolver_endpoint_rejects_credentials_or_query_fallback(self):
        baseline = json.loads((ROOT / 'config/baseline.json').read_text())
        baseline['Domain']['Resolver']['Endpoint'] = 'https://token@example.com/dns-query?fallback=https://public.example'
        path = self.root / 'invalid-resolver.json'; path.write_text(json.dumps(baseline))
        result = subprocess.run([str(ROOT / 'claudit.sh'), 'passive', '--service', 'Domain', '--domain', 'example.com',
                                 '--baseline', str(path), '--output-directory', str(self.root / 'invalid'), '--format', 'json'],
                                env=self.environment, capture_output=True, text=True, timeout=40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid Domain.Resolver', result.stderr)

    def test_drift_unavailable_is_not_fixed_and_scope_must_match(self):
        reference, difference = self.root / 'old.json', self.root / 'new.json'
        old = {'scope': {'domain': 'example.com'}, 'findings': [{'id': 'X', 'service': 'Domain', 'status': 'fail'}]}
        new = {'scope': {'domain': 'example.com'}, 'findings': [{'id': 'X', 'service': 'Domain', 'status': 'unknown'}]}
        reference.write_text(json.dumps(old)); difference.write_text(json.dumps(new))
        args = [str(ROOT / 'claudit.sh'), 'compare', '--reference', str(reference), '--difference', str(difference), '--output-directory', str(self.root / 'diff')]
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
        self.assertEqual(json.loads((self.root / 'diff/claudit-drift.json').read_text())[0]['change'], 'Changed')
        new['scope']['domain'] = 'different.example'; difference.write_text(json.dumps(new))
        self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)

    def test_finding_identity_is_bound_to_hashed_resource_scope(self):
        first = self.run_audit('formal', '--service', 'Domain', '--domain', 'example.com')
        second = self.run_audit('formal', '--service', 'Domain', '--domain', 'example.net')
        a = next(item for item in first['findings'] if item['id'] == 'CA-DNS-000')
        b = next(item for item in second['findings'] if item['id'] == 'CA-DNS-000')
        self.assertNotEqual(a['finding_id'], b['finding_id'])
        self.assertNotEqual(a['resource_uid'], b['resource_uid'])
        self.assertNotIn('example.com', a['resource_uid'])

    def test_skipped_aws_control_reduces_coverage(self):
        doc = self.run_audit('passive', '--service', 'AWS')
        self.assertTrue(any(f['id'] == 'CA-AWS-TRAIL' and f['status'] == 'unknown' for f in doc['findings']))
        self.assertLess(doc['summary']['coverage'], 100)

    def test_malformed_cloud_lists_remain_errors(self):
        binaries = self.root / 'bin'; binaries.mkdir()
        for name in ('az', 'gcloud'):
            p = binaries / name
            p.write_text("#!/bin/sh\necho '{\"unexpected\":\"object\"}'\n")
            p.chmod(0o755)
        self.environment['PATH'] = str(binaries) + ':' + os.environ['PATH']
        doc = self.run_audit('passive', '--service', 'Azure,GCP', '--gcp-project', 'fixture', '--confirm-tenant-connection')
        findings = {f['id']: f['status'] for f in doc['findings']}
        self.assertEqual(findings['CA-AZ-ACTIVITY'], 'error')
        self.assertEqual(findings['CA-GCP-LOGGING'], 'error')

    def test_graph_scope_and_missing_fields(self):
        script = self.root / 'graph.sh'
        script.write_text("""#!/usr/bin/env bash
set -euo pipefail
CLAUDIT_ROOT=$1
source "$CLAUDIT_ROOT/lib/core.sh"
export CLAUDIT_GRAPH_TOKEN=fixture
ca_graph_get() {
    case "$2" in
      /organization*) printf '%s\\n' '{"value":[{"id":"fixture"}]}' ;;
      /admin/sharepoint/settings) printf '%s\\n' '{"sharingCapability":"disabled"}' ;;
      *) echo 'Out-of-scope Graph endpoint' >&2; exit 99 ;;
    esac
}
main passive --service SharePoint --confirm-tenant-connection --output-directory "$2" --format json
""")
        out = self.root / 'graph-output'
        result = subprocess.run(['bash', str(script), str(ROOT), str(out)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = json.loads((out / 'claudit-report.json').read_text())
        self.assertFalse(any(f['service'] in ('Entra', 'OneDrive') for f in doc['findings']))
        self.assertEqual(next(f['status'] for f in doc['findings'] if f['id'] == 'CA-SPO-LEGACY'), 'unknown')

    def test_graph_pagination_is_bounded_and_rejects_untrusted_links(self):
        script = self.root / 'graph-pages.sh'
        script.write_text("""#!/usr/bin/env bash
set -euo pipefail
source "$1/checks/m365.sh"
calls=0
ca_graph_get() {
    calls=$((calls + 1))
    case "$2" in
      /first) printf '%s\\n' '{"value":[{"id":"one"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/second?token=opaque"}' ;;
      /second*) printf '%s\\n' '{"value":[{"id":"two"}]}' ;;
      /untrusted) printf '%s\\n' '{"value":[],"@odata.nextLink":"https://attacker.invalid/steal"}' ;;
      /loop*) printf '%s\\n' '{"value":[],"@odata.nextLink":"https://graph.microsoft.com/v1.0/loop"}' ;;
    esac
}
result="$(ca_graph_get_all token /first)"
jq -e '.value | map(.id) == ["one","two"]' <<<"$result" >/dev/null
if ca_graph_get_all token /untrusted >/dev/null; then exit 81; else [[ $? == 2 ]]; fi
if ca_graph_get_all token /loop >/dev/null; then exit 82; else [[ $? == 3 ]]; fi
""")
        result = subprocess.run(['bash', str(script), str(ROOT)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__': unittest.main()
