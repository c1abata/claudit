import base64
import functools
import http.client
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from test_dashboard import dashboard, ROOT


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cockpit = dashboard.Cockpit(ROOT, Path(self.tmp.name), ROOT / 'web')
        self.workspace = self.cockpit.workspace

    def create(self, **kwargs):
        return self.workspace.create({'title': 'DNS review', 'scope': {'service': ['Domain'], 'domain': 'example.com'}, **kwargs})

    def test_scope_and_dns_validation(self):
        with self.assertRaises(ValueError):
            self.create(dnsRecords=[{'name': 'example.com.evil.org', 'type': 'A', 'values': ['1.2.3.4']}])
        with self.assertRaises(ValueError):
            self.create(expectedStatuses={'made-up-control': 'pass'})
        with self.assertRaises(ValueError):
            self.cockpit.operation_log('../../outside')
        with self.assertRaises(ValueError):
            self.workspace.load('../outside')
        session = self.create(dnsRecords=[{'name': 'www.example.com', 'type': 'A', 'values': ['192.0.2.10']},
                                          {'name': 'old.example.com', 'type': 'AAAA', 'values': []}])
        zone = self.workspace.dns_zone_export(session['id'])
        self.assertEqual(zone['filename'], 'example.com.zone')
        self.assertIn('$ORIGIN example.com.', zone['content'])
        self.assertIn('www 300 IN A 192.0.2.10', zone['content'])
        self.assertIn('; EXPECT ABSENT: old AAAA', zone['content'])

    def test_incomplete_never_passes(self):
        p = Path(self.tmp.name) / 'claudit-report.json'
        for findings in ([], [{'status': 'unknown'}]):
            p.write_text(json.dumps({'findings': findings, 'summary': {}}))
            self.assertEqual(self.cockpit.report_summary(p)['Outcome'], 'Incomplete')

    def test_auth_gate_and_input_validation(self):
        request = {'service': ['AWS'], 'mode': 'audit', 'controlLevel': 'passive'}
        with self.assertRaises(ValueError):
            self.cockpit.start_operation(request)
        self.assertEqual(list(self.cockpit.operations_root.iterdir()), [])
        for bad in ('$(touch /tmp/pwn)', '--profile', 'host;id'):
            with self.assertRaises(ValueError):
                self.cockpit.start_operation({**request, 'confirmTenantConnection': True, 'awsProfile': bad})

    def test_session_survives_restart_and_has_no_fabricated_guidance(self):
        session = self.create()
        response = self.workspace.query({'id': session['id'], 'question': 'What next?'})
        self.assertIn('No completed', response['answer'])
        self.assertIsNone(response['source'])
        self.workspace.query({'id': session['id'], 'question': '<script>example note</script>', 'kind': 'note'})
        again = dashboard.Cockpit(ROOT, Path(self.tmp.name), ROOT / 'web')
        self.assertEqual(len(again.workspace.load(session['id'])['history']), 2)
        self.assertEqual(self.workspace.path(session['id']).stat().st_mode & 0o777, 0o600)

    def test_session_lifecycle_history_bounds_and_corruption_recovery(self):
        session = self.create()
        session['history'] = [{'at': str(index), 'kind': 'note'} for index in range(550)]
        session['operations'] = [str(index) for index in range(250)]
        self.workspace.save(session)
        bounded = self.workspace.load(session['id'])
        self.assertEqual(len(bounded['history']), 500)
        self.assertEqual(len(bounded['operations']), 200)
        self.assertEqual(self.workspace.export(session['id'])['id'], session['id'])
        self.workspace.archive({'id': session['id']})
        self.assertTrue(self.workspace.load(session['id'])['archived'])
        self.assertFalse(self.workspace.path(session['id']).exists())
        operations_before = set(self.cockpit.operations_root.iterdir())
        with self.assertRaisesRegex(ValueError, 'read-only'):
            self.workspace.run({'id': session['id'], 'controlLevel': 'formal'})
        self.assertEqual(set(self.cockpit.operations_root.iterdir()), operations_before)
        self.workspace.delete(session['id'])
        with self.assertRaises(ValueError):
            self.workspace.load(session['id'])
        corrupt = 'a' * 24
        self.workspace.path(corrupt).write_text('{broken')
        self.assertEqual(next(item for item in self.workspace.index() if item['id'] == corrupt)['status'], 'error')
        self.workspace.quarantine({'id': corrupt})
        self.assertFalse(self.workspace.path(corrupt).exists())
        self.assertEqual(len(list(self.workspace.quarantine_root.glob(corrupt + '-*.json'))), 1)

    def test_report_index_is_paginated(self):
        for index in range(4):
            report = self.cockpit.reports_root / f'run-{index}'
            report.mkdir()
            (report / 'claudit-report.json').write_text(json.dumps({'findings': [], 'summary': {}}))
            time.sleep(0.01)
        first = self.cockpit.report_index(0, 2)
        second = self.cockpit.report_index(2, 2)
        self.assertEqual(len(first), 2)
        self.assertEqual(len(second), 2)
        self.assertTrue(set(item['RelativePath'] for item in first).isdisjoint(item['RelativePath'] for item in second))
        with self.assertRaises(ValueError):
            self.cockpit.report_index(0, 501)

    def test_guided_plan_uses_real_catalog_and_capability_boundaries(self):
        session = self.create()
        plan = self.workspace.plan(session['id'])
        ids = {item['id'] for item in plan['controls']}
        self.assertIn('CA-DNS-BASELINE', ids)
        self.assertTrue(any(item['Path'] == 'Domain.ExpectedRecords' and item['State'] == 'enforced' for item in plan['capabilities']))
        self.assertTrue(any('DNS changes' in item for item in plan['limitations']))
        self.assertTrue(any('Which DNS records' in item for item in plan['suggestedQuestions']))

    def test_read_only_dns_provider_imports_are_normalized_and_scoped(self):
        route53 = {'ResourceRecordSets': [{'Name': 'example.com.', 'Type': 'MX', 'ResourceRecords': [{'Value': '10 mail.example.com.'}]}, {'Name': 'outside.test.', 'Type': 'A', 'ResourceRecords': [{'Value': '192.0.2.1'}]}]}
        result = self.workspace.normalize_dns_import({'provider': 'route53', 'domain': 'example.com', 'data': route53})
        self.assertTrue(result['readOnly'])
        self.assertEqual(result['records'], [{'name': 'example.com', 'type': 'MX', 'values': ['10 mail.example.com.']}])
        gcp = [{'name': 'www.example.com.', 'type': 'A', 'rrdatas': ['203.0.113.10']}]
        self.assertEqual(self.workspace.normalize_dns_import({'provider': 'gcp', 'domain': 'example.com', 'data': gcp})['records'][0]['values'], ['203.0.113.10'])
        with self.assertRaises(ValueError):
            self.workspace.normalize_dns_import({'provider': 'cloudflare', 'domain': 'example.com', 'data': {'result': [{'name': 'outside.test', 'type': 'A', 'content': '192.0.2.1'}]}})

    def test_real_session_dns_assessment_and_grounded_query(self):
        session = self.create(dnsRecords=[{'name': 'example.com', 'type': 'A', 'values': ['203.0.113.99']}], expectedStatuses={'CA-DNS-BASELINE': 'pass'})
        with patch.dict(os.environ, {'CLAUDIT_DOH_FIXTURE': str(ROOT / 'tests/fixtures/domain/business-example.json')}):
            operation = self.workspace.run({'id': session['id'], 'controlLevel': 'passive', 'confirmTenantConnection': True})
        self.cockpit.processes[operation['Id']].wait(timeout=30)
        self.assertEqual(self.cockpit.operation_views()[0]['Status'], 'Succeeded')
        response = self.workspace.query({'id': session['id'], 'question': 'Explain CA-DNS-BASELINE'})
        self.assertIn(operation['Id'], response['source'])
        self.assertEqual(response['findings'][0]['status'], 'fail')
        self.assertEqual(response['configurationDrift'][0]['observed'], 'fail')
        plan = Path(operation['OutputDirectory']) / 'claudit-dns-plan.jsonl'
        self.assertEqual(json.loads(plan.read_text())['observed'], ['203.0.113.10'])
        self.assertTrue((Path(operation['OutputDirectory']) / 'claudit-baseline.json').is_file())

    def test_http_auth_csp_and_host(self):
        self.cockpit.access_token = 'a-private-password-of-sufficient-length'
        handler = functools.partial(dashboard.DashboardHandler, cockpit=self.cockpit)
        server = dashboard.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port)
        self.addCleanup(connection.close)
        for path in ('/', '/api/state', '/api/sessions', '/api/report?path=anything', '/assets/dashboard.js'):
            connection.request('GET', path); response = connection.getresponse(); response.read()
            self.assertEqual(response.status, 401)
        auth = {'Authorization': 'Basic ' + base64.b64encode(('claudit:' + self.cockpit.access_token).encode()).decode()}
        connection.request('GET', '/api/sessions', headers=auth); response = connection.getresponse(); response.read()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader('Cache-Control'), 'no-store')
        self.assertIn("frame-ancestors 'none'", response.getheader('Content-Security-Policy'))
        connection.request('POST', '/api/sessions', '{}', auth); response = connection.getresponse(); response.read()
        self.assertEqual(response.status, 403)
        connection.request('GET', '/', headers={**auth, 'Host': 'attacker.example'}); response = connection.getresponse(); response.read()
        self.assertEqual(response.status, 403)


if __name__ == '__main__': unittest.main()
