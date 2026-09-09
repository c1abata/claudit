#!/usr/bin/env python3
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("dashboard", ROOT / "service" / "dashboard.py")
dashboard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(dashboard)


class DashboardReportTests(unittest.TestCase):
    def test_dashboard_authentication_mode_is_explicit_and_disabled_by_default(self) -> None:
        password = "a-private-password-of-sufficient-length"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {
            "CLAUDIT_DASHBOARD_PASSWORD": password,
        }):
            os.environ.pop("CLAUDIT_DASHBOARD_AUTHENTICATION", None)
            cockpit = dashboard.Cockpit(ROOT, Path(temporary), ROOT / "web")
            self.assertEqual(cockpit.access_token, "")
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {
            "CLAUDIT_DASHBOARD_AUTHENTICATION": "required",
            "CLAUDIT_DASHBOARD_PASSWORD": password,
        }):
            cockpit = dashboard.Cockpit(ROOT, Path(temporary), ROOT / "web")
            self.assertEqual(cockpit.access_token, password)

    def test_dashboard_loads_capability_map(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cockpit = dashboard.Cockpit(ROOT, Path(temporary), ROOT / "web")
            self.assertTrue(cockpit.baseline_capabilities)
            self.assertNotIn("unsupported", {item["State"] for item in cockpit.baseline_capabilities})
            self.assertEqual({item["State"] for item in cockpit.baseline_capabilities}, {"enforced", "scope_only"})
            self.assertEqual(cockpit.dns_resolver["fallback"], "disabled")
            self.assertGreater(len(cockpit.control_catalog), 80)

    def test_assessment_summary_separates_coverage_from_info_and_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "claudit-report.json"
            findings = [
                {"status": "pass", "severity": "high"},
                {"status": "fail", "severity": "critical"},
                {"status": "warning", "severity": "medium"},
                {"status": "unknown", "severity": "high"},
                {"status": "error", "severity": "high"},
                {"status": "info", "severity": "info"},
                {"status": "not_applicable", "severity": "info"},
            ]
            path.write_text(json.dumps({"summary": {"coverage": 71.4}, "findings": findings}))
            summary = dashboard.Cockpit.report_summary(path, {"Command": "passive"})
            self.assertEqual(summary["Assessed"], 3)
            self.assertEqual(summary["Applicable"], 5)
            self.assertEqual(summary["Coverage"], 60.0)
            self.assertEqual(summary["LegacyCoverage"], 71.4)
            self.assertEqual(summary["ConfirmedHighCritical"], 1)

    def test_operation_request_identifier_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cockpit = dashboard.Cockpit(ROOT, Path(temporary), ROOT / "web")
            with self.assertRaisesRegex(ValueError, "request identifier"):
                cockpit.start_operation({"service": ["Domain"], "mode": "preflight", "controlLevel": "Formal", "requestId": "bad"})

    def test_domain_collection_needs_no_allow_list_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cockpit = dashboard.Cockpit(ROOT, Path(temporary), ROOT / "web")
            services, _, _, command = cockpit.validate_request({"service": ["Domain"], "mode": "audit",
                                                                 "controlLevel": "Passive", "domain": "example.com"})
            self.assertEqual(services, ["Domain"])
            self.assertEqual(command, "passive")
            with self.assertRaisesRegex(ValueError, "Explicit authorization"):
                cockpit.validate_request({"service": ["AWS"], "mode": "audit", "controlLevel": "Passive"})

    def test_operation_request_identifier_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch.object(dashboard.subprocess, "Popen") as popen:
            process = popen.return_value
            process.pid = 1234
            process.poll.return_value = None
            cockpit = dashboard.Cockpit(ROOT, Path(temporary), ROOT / "web")
            request = {"service": ["Domain"], "mode": "preflight", "controlLevel": "Formal",
                       "requestId": "web-12345678-1234-1234-1234-123456789abc"}
            first = cockpit.start_operation(request)
            second = cockpit.start_operation(request)
            self.assertEqual(first["Id"], second["Id"])
            popen.assert_called_once()

    def test_dashboard_rejects_resolver_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config"; config.mkdir()
            (config / "baseline-capabilities.json").write_text((ROOT / "config" / "baseline-capabilities.json").read_text())
            baseline = json.loads((ROOT / "config" / "baseline.json").read_text())
            baseline["Domain"]["Resolver"]["Endpoint"] = "https://token@example.com/dns-query"
            (config / "baseline.json").write_text(json.dumps(baseline))
            with self.assertRaisesRegex(RuntimeError, "resolver configuration is invalid"):
                dashboard.Cockpit(root, root / "data", ROOT / "web")

    def report(self, root: Path, operation: dict, findings: list[dict]) -> Path:
        output = root / "reports" / "dashboard" / operation["Id"] / "output"
        output.mkdir(parents=True)
        (output.parent / "metadata.json").write_text(json.dumps(operation), encoding="utf-8")
        report = {"summary": {"coverage": 100}, "findings": findings}
        path = output / "claudit-report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def test_overview_excludes_preflight_and_formal_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cockpit = dashboard.Cockpit(ROOT, root, ROOT / "web")
            self.report(root, {"Id": "preflight", "Mode": "preflight", "Command": "doctor"}, [])
            self.report(root, {"Id": "formal", "Mode": "safe", "Command": "formal"}, [])
            reports = cockpit.report_index()
            overview = cockpit.report_overview(reports)
            self.assertEqual(overview["analysisRuns"], 0)
            self.assertIsNone(overview["latest"])

    def test_overview_selects_passive_evidence_and_keeps_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cockpit = dashboard.Cockpit(ROOT, root, ROOT / "web")
            self.report(root, {"Id": "passive", "Mode": "audit", "Command": "passive", "Services": ["Domain"], "Domain": "example.com"}, [{"status": "warning", "severity": "medium", "title": "DMARC monitoring", "id": "CA-DNS-DMARC", "service": "Domain", "remediation": "Enforce DMARC."}])
            report = cockpit.report_index()[0]
            self.assertEqual(report["Summary"]["Assessment"], "Passive")
            self.assertEqual(report["Operation"]["Domain"], "example.com")
            self.assertEqual(cockpit.report_overview([report])["analysisRuns"], 1)

    def test_asset_history_aggregates_unique_domain_and_control_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cockpit = dashboard.Cockpit(ROOT, root, ROOT / "web")
            for number, status in enumerate(("fail", "pass"), start=1):
                operation = {"Id": f"run-{number}", "Mode": "audit", "Command": "passive", "Services": ["Domain"], "Domain": "Example.COM"}
                path = self.report(root, operation, [])
                document = {"generated_at": f"2026-09-0{number}T10:00:00Z",
                            "scope": {"level": "passive", "services": "Domain", "domain": "Example.COM."},
                            "summary": {"coverage": 100},
                            "findings": [{"id": "CA-DNS-DMARC", "service": "Domain", "status": status,
                                          "severity": "high", "category": "email", "title": "DMARC"}]}
                path.write_text(json.dumps(document), encoding="utf-8")
            assets = cockpit.asset_history(cockpit.report_files())
            self.assertEqual(len(assets), 1)
            self.assertEqual(assets[0]["key"], "domain:example.com")
            self.assertEqual(assets[0]["assessmentCount"], 2)
            self.assertEqual(assets[0]["changes"]["fixed"], 1)
            self.assertEqual(assets[0]["controls"][0]["transitions"], 1)
            self.assertTrue((root / "asset-history.json").is_file())

    def test_legacy_safe_operation_is_normalized_to_formal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cockpit = dashboard.Cockpit(ROOT, root, ROOT / "web")
            metadata = root / "reports" / "dashboard" / "legacy" / "metadata.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text(json.dumps({"Id": "legacy", "Mode": "safe", "ControlLevel": "Passive", "Status": "Failed"}), encoding="utf-8")
            operation = cockpit.operation_views()[0]
            self.assertEqual(operation["Command"], "formal")
            self.assertEqual(operation["EffectiveControlLevel"], "Formal")


if __name__ == "__main__":
    unittest.main()
