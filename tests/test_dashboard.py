#!/usr/bin/env python3
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("dashboard", ROOT / "service" / "dashboard.py")
dashboard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(dashboard)


class DashboardReportTests(unittest.TestCase):
    def test_dashboard_loads_capability_map(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cockpit = dashboard.Cockpit(ROOT, Path(temporary), ROOT / "web")
            self.assertTrue(cockpit.baseline_capabilities)
            self.assertNotIn("unsupported", {item["State"] for item in cockpit.baseline_capabilities})
            self.assertEqual({item["State"] for item in cockpit.baseline_capabilities}, {"enforced", "scope_only"})
            self.assertEqual(cockpit.dns_resolver["fallback"], "disabled")

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
