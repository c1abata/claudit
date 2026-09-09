#!/usr/bin/env python3
"""Local Claudit cockpit for the Bash runtime; no credentials are persisted."""

from __future__ import annotations

import argparse
import base64
import functools
import ipaddress
import threading
import re
import sys
import signal
import socket
import json
import mimetypes
import os
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workspace import Workspace, write_json


def serialized(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return wrapped


SERVICES = [
    {"Name": "Entra", "Provider": "Microsoft365", "Default": True},
    {"Name": "Exchange", "Provider": "Microsoft365", "Default": True},
    {"Name": "SharePoint", "Provider": "Microsoft365", "Default": True},
    {"Name": "OneDrive", "Provider": "Microsoft365", "Default": True},
    {"Name": "Azure", "Provider": "Azure", "Default": False},
    {"Name": "AWS", "Provider": "AWS", "Default": False},
    {"Name": "GCP", "Provider": "GCP", "Default": False},
    {"Name": "Tailscale", "Provider": "SaaS", "Default": False},
    {"Name": "Domain", "Provider": "Internet", "Default": False},
    {"Name": "VPS", "Provider": "VPS", "Default": False},
    {"Name": "Inventory", "Provider": "MultiCloud", "Default": False},
]
AUTH_CATALOG = [
    {"Provider": "Internet", "Method": "Public", "Description": "Public-domain DNS checks; every entered domain is accepted automatically and no credential is used."},
    {"Provider": "Microsoft365", "Method": "DelegatedDeviceCode", "Description": "Uses an existing read-only Microsoft Graph or Azure CLI session."},
    {"Provider": "Microsoft365", "Method": "DelegatedBrowser", "Description": "Uses an existing read-only Microsoft Graph or Azure CLI session."},
    {"Provider": "Microsoft365", "Method": "AppCertificate", "Description": "Uses the configured Exchange app-only environment settings; client secrets are not stored."},
    {"Provider": "Azure", "Method": "AzCli", "Description": "Uses the current Azure CLI read-only context."},
    {"Provider": "AWS", "Method": "AwsCliProfile", "Description": "Uses the selected AWS CLI read-only profile."},
    {"Provider": "GCP", "Method": "Gcloud", "Description": "Uses the current gcloud read-only context."},
    {"Provider": "SaaS", "Method": "ApiTokenEnv", "Description": "Reads the configured token only from the service environment."},
    {"Provider": "VPS", "Method": "LocalOrSsh", "Description": "Uses bounded read-only SSH checks against the declared target."},
]
REPORT_SUFFIXES = {".json", ".html", ".md", ".csv", ".jsonl"}
ARTIFACTS = {
    "JSON": "claudit-report.json", "HTML": "claudit-report.html", "CSV": "claudit-report.csv",
    "Markdown": "claudit-report.md", "OCSF": "claudit-ocsf.jsonl", "OSCAL": "claudit-oscal-assessment-results.json",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Cockpit:
    def __init__(self, app_root: Path, data_root: Path, web_root: Path) -> None:
        self.app_root, self.data_root, self.web_root = app_root.resolve(), data_root.resolve(), web_root.resolve()
        self.reports_root = self.data_root / "reports"
        self.operations_root = self.reports_root / "dashboard"
        self.state_path = self.data_root / "dashboard-state.json"
        self.asset_history_path = self.data_root / "asset-history.json"
        self.token = secrets.token_hex(32)
        self.lock = threading.RLock()
        authentication = os.environ.get('CLAUDIT_DASHBOARD_AUTHENTICATION', 'disabled')
        if authentication not in {'disabled', 'required'}:
            raise RuntimeError('Dashboard authentication mode must be disabled or required.')
        self.access_token = os.environ.get('CLAUDIT_DASHBOARD_PASSWORD', '') if authentication == 'required' else ''
        self.processes: dict[str, subprocess.Popen[bytes]] = {}
        self.baseline_capabilities = self.load_baseline_capabilities()
        self.dns_resolver = self.load_dns_resolver()
        self.control_catalog = self.load_control_catalog()
        self.reports_root.mkdir(parents=True, exist_ok=True)
        self.operations_root.mkdir(parents=True, exist_ok=True)
        self.workspace = Workspace(self)

    def load_control_catalog(self) -> list[dict[str, Any]]:
        path = self.app_root / "config" / "runtime-control-catalog.json"
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            controls = document["Controls"]
            if not isinstance(controls, list) or any(not isinstance(item, dict) for item in controls):
                raise ValueError
            return controls
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Runtime control catalog is unavailable or invalid.") from exc

    def load_baseline_capabilities(self) -> list[dict[str, Any]]:
        path = self.app_root / "config" / "baseline-capabilities.json"
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            entries = document["Capabilities"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Claudit baseline capability map is unavailable.") from exc
        if not isinstance(entries, list) or not entries:
            raise RuntimeError("Claudit baseline capability map is invalid.")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("Path"), str) or entry.get("State") not in {"enforced", "scope_only", "unsupported"} or not isinstance(entry.get("Controls"), list) or not isinstance(entry.get("Explanation"), str):
                raise RuntimeError("Claudit baseline capability map is invalid.")
        return entries

    def load_dns_resolver(self) -> dict[str, Any]:
        try:
            resolver = json.loads((self.app_root / "config" / "baseline.json").read_text(encoding="utf-8"))["Domain"]["Resolver"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Claudit DNS resolver configuration is unavailable.") from exc
        endpoint = resolver.get("Endpoint") if isinstance(resolver, dict) else None
        parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
        if (not isinstance(resolver, dict) or not isinstance(resolver.get("Name"), str) or
                not resolver["Name"].strip() or not isinstance(resolver.get("Endpoint"), str) or
                parsed is None or parsed.scheme != "https" or not parsed.netloc or parsed.username or
                parsed.password or parsed.query or parsed.fragment or not isinstance(resolver.get("Private"), bool) or
                not isinstance(resolver.get("TimeoutSeconds"), int) or not 1 <= resolver["TimeoutSeconds"] <= 30):
            raise RuntimeError("Claudit DNS resolver configuration is invalid.")
        return {"name": resolver["Name"], "endpoint": resolver["Endpoint"], "private": resolver["Private"],
                "timeoutSeconds": resolver["TimeoutSeconds"], "fallback": "disabled"}

    def retention_count(self) -> int:
        try:
            value = int(json.loads(self.state_path.read_text(encoding="utf-8")).get("retentionCount", 100))
            return value if 1 <= value <= 10000 else 100
        except (OSError, ValueError, json.JSONDecodeError):
            return 100

    @serialized
    def save_retention(self, value: Any) -> int:
        try:
            retention = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("Results to keep must be an integer between 1 and 10000.") from exc
        if not 1 <= retention <= 10000:
            raise ValueError("Results to keep must be an integer between 1 and 10000.")
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"retentionCount": retention, "updatedAt": utc_now()}), encoding="utf-8")
        temporary.replace(self.state_path)
        self.prune_operations(retention)
        return retention

    def dashboard_html(self) -> bytes:
        html = (self.web_root / 'dashboard.html').read_text(encoding='utf-8')
        return html.replace('__CLAUDIT_REQUEST_TOKEN__', self.token).replace('__CLAUDIT_RETENTION_COUNT__', str(self.retention_count())).encode()

    def report_index(self, offset: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        if not 0 <= offset <= 100000 or not 1 <= limit <= 500:
            raise ValueError('Report page must use offset 0–100000 and limit 1–500.')
        page = self.report_files()[offset:offset + limit]
        return [self.report_view(path) for path in page]

    def report_files(self) -> list[Path]:
        files = [path for path in self.reports_root.rglob("claudit-report.json") if path.is_file() and not path.is_symlink()]
        return sorted(files, key=lambda item: item.stat().st_mtime, reverse=True)

    @staticmethod
    def asset_identity(scope: dict[str, Any]) -> tuple[str, str] | None:
        fields = (("domain", "Domain"), ("vps", "VPS"), ("aws_profile", "AWS"),
                  ("azure_subscription", "Azure"), ("gcp_project", "GCP"),
                  ("m365_tenant", "Microsoft365"), ("tailscale_tailnet", "Tailscale"))
        for field, kind in fields:
            value = scope.get(field)
            if isinstance(value, str) and value.strip() and value.strip() != "-":
                return kind, value.strip().lower().rstrip(".")
        return None

    @staticmethod
    def observation_risk(findings: list[dict[str, Any]]) -> int:
        severity = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        status = {"fail": 1.0, "error": 0.8, "warning": 0.5, "unknown": 0.25}
        return round(sum(severity.get(str(item.get("severity")), 1) * status.get(str(item.get("status")), 0) for item in findings))

    def asset_observation(self, path: Path) -> tuple[str, dict[str, Any]] | None:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            scope = document.get("scope", {})
            if not isinstance(scope, dict):
                return None
            identity = self.asset_identity(scope)
            if not identity:
                return None
            operation = self.report_operation(path)
            command = str((operation or {}).get("Command") or scope.get("level") or "").lower()
            if command not in {"passive", "active"}:
                return None
            findings = document.get("findings", [])
            if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
                return None
            summary = self.report_summary(path, {"Command": command})
            if not summary or summary.get("Kind") != "audit":
                return None
            kind, value = identity
            services = scope.get("services", (operation or {}).get("Services", []))
            if isinstance(services, str):
                services = [item.strip() for item in services.split(",") if item.strip()]
            controls = [{"id": str(item.get("id") or item.get("finding_id") or "unknown"),
                         "status": str(item.get("status") or "unknown"),
                         "severity": str(item.get("severity") or "info"),
                         "title": str(item.get("title") or item.get("id") or "Untitled control"),
                         "category": str(item.get("category") or "other"),
                         "service": str(item.get("service") or "unknown")}
                        for item in findings]
            relative = path.relative_to(self.reports_root).as_posix()
            observed = str(document.get("generated_at") or datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat())
            observation = {"reportPath": relative, "observedAt": observed, "level": command,
                           "services": services if isinstance(services, list) else [], "summary": summary,
                           "riskScore": self.observation_risk(findings), "controls": controls}
            return f"{kind.lower()}:{value}", {"kind": kind, "value": value, "observation": observation}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    @serialized
    def asset_history(self, report_files: list[Path]) -> list[dict[str, Any]]:
        try:
            ledger = json.loads(self.asset_history_path.read_text(encoding="utf-8"))
            if ledger.get("schema") != "claudit/asset-history-v1" or not isinstance(ledger.get("assets"), dict):
                raise ValueError
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            ledger = {"schema": "claudit/asset-history-v1", "assets": {}}
        changed = False
        for path in report_files:
            parsed = self.asset_observation(path)
            if not parsed:
                continue
            key, item = parsed
            asset = ledger["assets"].setdefault(key, {"kind": item["kind"], "value": item["value"], "observations": []})
            observations = asset.get("observations", [])
            replacement = item["observation"]
            existing = next((index for index, entry in enumerate(observations) if entry.get("reportPath") == replacement["reportPath"]), None)
            if existing is None:
                observations.append(replacement); changed = True
            elif observations[existing] != replacement:
                observations[existing] = replacement; changed = True
            asset["observations"] = sorted(observations, key=lambda entry: entry.get("observedAt", ""))[-200:]
        if changed or not self.asset_history_path.exists():
            ledger["updatedAt"] = utc_now()
            write_json(self.asset_history_path, ledger)
        retained = {path.relative_to(self.reports_root).as_posix() for path in report_files}
        result = []
        for key, asset in ledger["assets"].items():
            observations = sorted(asset.get("observations", []), key=lambda entry: entry.get("observedAt", ""))
            if not observations:
                continue
            controls: dict[str, dict[str, Any]] = {}
            for observation in observations:
                for control in observation.get("controls", []):
                    control_id = control["id"]
                    aggregate = controls.setdefault(control_id, {**control, "observations": 0, "transitions": 0, "firstSeen": observation["observedAt"], "lastSeen": observation["observedAt"]})
                    if aggregate["observations"] and aggregate["status"] != control["status"]:
                        aggregate["transitions"] += 1
                    aggregate.update(control, observations=aggregate["observations"] + 1, lastSeen=observation["observedAt"])
            latest, previous = observations[-1], observations[-2] if len(observations) > 1 else None
            history = [{"observedAt": item["observedAt"], "level": item["level"], "coverage": item["summary"].get("Coverage", 0),
                        "failed": item["summary"].get("Fail", 0), "warnings": item["summary"].get("Warning", 0),
                        "gaps": item["summary"].get("NotEvaluated", 0), "riskScore": item.get("riskScore", 0),
                        "reportPath": item["reportPath"], "retained": item["reportPath"] in retained}
                       for item in observations[-30:]]
            latest_statuses = {item["id"]: item["status"] for item in latest.get("controls", [])}
            previous_statuses = {item["id"]: item["status"] for item in (previous or {}).get("controls", [])}
            changes = {"new": 0, "fixed": 0, "regressed": 0, "changed": 0}
            for control_id, status in latest_statuses.items():
                before = previous_statuses.get(control_id)
                if before is None: changes["new"] += 1
                elif before == status: continue
                elif status == "pass" and before in {"fail", "warning", "error"}: changes["fixed"] += 1
                elif before == "pass" and status in {"fail", "warning", "error"}: changes["regressed"] += 1
                else: changes["changed"] += 1
            result.append({"key": key, "kind": asset.get("kind"), "value": asset.get("value"),
                           "firstSeen": observations[0]["observedAt"], "lastSeen": latest["observedAt"],
                           "assessmentCount": len(observations), "latest": history[-1],
                           "delta": {"risk": latest.get("riskScore", 0) - (previous or latest).get("riskScore", 0),
                                     "coverage": round(latest["summary"].get("Coverage", 0) - (previous or latest)["summary"].get("Coverage", 0), 1)},
                           "changes": changes, "history": history,
                           "controls": sorted(controls.values(), key=lambda item: (-item["transitions"], item["id"]))})
        return sorted(result, key=lambda item: item["lastSeen"], reverse=True)

    def report_view(self, path: Path) -> dict[str, Any]:
        relative = path.relative_to(self.reports_root).as_posix()
        artifacts = {label: (path.parent / filename).relative_to(self.reports_root).as_posix() for label, filename in ARTIFACTS.items() if (path.parent / filename).is_file()}
        operation = self.report_operation(path)
        return {"Name": path.name, "Extension": path.suffix.removeprefix(".").lower(), "RelativePath": relative, "Artifacts": artifacts,
                "Directory": path.parent.relative_to(self.reports_root).as_posix(), "SizeBytes": path.stat().st_size,
                "LastWriteUtc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(), "Operation": operation,
                "Summary": self.report_summary(path, operation)}

    def report_operation(self, path: Path) -> dict[str, Any] | None:
        if path.parent.name != "output" or path.parent.parent.parent != self.operations_root:
            return None
        try:
            operation = json.loads((path.parent.parent / "metadata.json").read_text(encoding="utf-8"))
            command = str(operation.get("Command") or self.operation_command(operation))
            return {"Id": operation.get("Id"), "Mode": operation.get("Mode"), "Command": command,
                    "ControlLevel": operation.get("ControlLevel"), "EffectiveControlLevel": command.title(),
                    "Services": operation.get("Services", []), "Domain": operation.get("Domain", "")}
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def operation_command(operation: dict[str, Any]) -> str:
        mode = str(operation.get("Mode", "")).lower()
        if mode == "preflight":
            return "doctor"
        if mode == "safe":
            return "formal"
        return str(operation.get("ControlLevel", "passive")).lower()

    @staticmethod
    def report_summary(path: Path, operation: dict[str, Any] | None = None) -> dict[str, Any] | None:
        if path.name != "claudit-report.json":
            return None
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            summary = document.get("summary", {})
            findings = document.get("findings", [])
            if not isinstance(findings, list) or any(not isinstance(item, dict) or item.get('status') not in {'pass', 'fail', 'warning', 'info', 'not_applicable', 'unknown', 'error'} for item in findings):
                raise ValueError('Invalid finding data')
            count = lambda state: sum(item.get("status") == state for item in findings)
            errors, failed, warnings, unknown = count("error"), count("fail"), count("warning"), count("unknown")
            problems = failed + warnings
            assessed = sum(item.get("status") in {"pass", "fail", "warning"} for item in findings)
            applicable = assessed + unknown + errors
            command = str((operation or {}).get("Command", "")).lower()
            assessment = "Preflight" if command == "doctor" else ("Formal validation" if command == "formal" else (command.title() if command else "Unclassified"))
            return {"Kind": "audit", "Assessment": assessment, "Outcome": "ExecutionError" if errors else ("IssuesFound" if problems else ("Incomplete" if unknown or not findings else "Pass")),
                    "Problems": problems, "Pass": count("pass"), "Fail": failed, "Warning": warnings, "Error": errors,
                    "Unknown": unknown, "NotApplicable": count("not_applicable"), "Info": count("info"),
                    "NotEvaluated": unknown + errors,
                    "ConfirmedHighCritical": sum(item.get("status") == "fail" and item.get("severity") in {"high", "critical"} for item in findings),
                    "High": sum(item.get("severity") in {"high", "critical"} for item in findings),
                    "Assessed": assessed, "Applicable": applicable,
                    "Coverage": round(100 * assessed / applicable, 1) if applicable else 0.0,
                    "LegacyCoverage": round(float(summary.get("coverage", 0)), 1)}
        except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
            return {"Kind": "json", "Outcome": "InvalidReport", "Error": "parse error"}

    def report_overview(self, reports: list[dict[str, Any]]) -> dict[str, Any]:
        if not reports:
            return {"runs": 0, "analysisRuns": 0, "latest": None, "salient": [], "matrix": {}}
        analyses = [report for report in reports if (report.get("Operation") or {}).get("Command") in {"passive", "active"}]
        if not analyses:
            return {"runs": len(reports), "analysisRuns": 0, "latest": None, "salient": [], "matrix": {}}
        latest = analyses[0]
        try:
            document = json.loads(self.report_path(str(latest["RelativePath"])).read_text(encoding="utf-8"))
            priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            findings = [item for item in document.get("findings", []) if item.get("status") in {"error", "fail", "warning"}]
            findings.sort(key=lambda item: (priority.get(item.get("severity"), 9), item.get("title", "")))
            salient = [{"id": item.get("id"), "service": item.get("service"), "status": item.get("status"), "severity": item.get("severity"), "category": item.get("category"), "title": item.get("title"), "remediation": item.get("remediation")} for item in findings[:5]]
            matrix: dict[str, dict[str, int]] = {}
            for item in document.get("findings", []):
                category = str(item.get("category") or "other")
                status = str(item.get("status") or "unknown")
                matrix.setdefault(category, {})[status] = matrix.setdefault(category, {}).get(status, 0) + 1
        except (OSError, ValueError, json.JSONDecodeError):
            salient = []
            matrix = {}
        return {"runs": len(reports), "analysisRuns": len(analyses), "latest": latest, "salient": salient, "matrix": matrix}

    @serialized
    def operation_views(self) -> list[dict[str, Any]]:
        operations: list[dict[str, Any]] = []
        for metadata_path in self.operations_root.glob("*/metadata.json"):
            try:
                operation = json.loads(metadata_path.read_text(encoding="utf-8"))
                self.update_operation(operation, metadata_path)
                operations.append(operation)
            except (OSError, json.JSONDecodeError):
                continue
        return sorted(operations, key=lambda item: item.get("StartedUtc", ""), reverse=True)

    def update_operation(self, operation: dict[str, Any], metadata_path: Path) -> None:
        changed = False
        command = str(operation.get("Command") or self.operation_command(operation))
        if operation.get("Command") != command:
            operation["Command"] = command
            changed = True
        if operation.get("EffectiveControlLevel") != command.title():
            operation["EffectiveControlLevel"] = command.title()
            changed = True
        if "Domain" not in operation:
            operation["Domain"] = ""
            changed = True
        process = self.processes.get(operation.get("Id", ""))
        if process and process.poll() is not None and operation.get("Status") == "Running":
            operation["ExitCode"] = process.returncode
            operation["Status"] = "Succeeded" if process.returncode == 0 else "Failed"
            changed = True
        elif not process and operation.get("Status") == "Running":
            operation["Status"] = "Interrupted"
            changed = True
        if operation.get("Status") == "Succeeded" and not (metadata_path.parent / "output" / "claudit-report.json").is_file():
            operation["Status"] = "EvidenceMissing"
            changed = True
        evidence = metadata_path.parent / "output" / "claudit-report.json"
        evidence_status = "available" if evidence.is_file() else ("pending" if operation.get("Status") == "Running" else "unavailable")
        if operation.get("EvidenceStatus") != evidence_status:
            operation["EvidenceStatus"] = evidence_status
            changed = True
        if changed:
            metadata_path.write_text(json.dumps(operation, indent=2), encoding="utf-8")

    def operation_log(self, operation_id: str) -> dict[str, str]:
        if not re.fullmatch(r'dashboard-[0-9]{8}-[0-9]{6}-[a-f0-9]{8}', operation_id):
            raise ValueError("Invalid operation identifier")
        metadata = self.operations_root / operation_id / "metadata.json"
        if not metadata.is_file():
            raise ValueError("Operation not found")
        operation = json.loads(metadata.read_text(encoding="utf-8"))
        return {"id": operation_id, "stdout": self.tail(metadata.parent / "stdout.log"), "stderr": self.tail(metadata.parent / "stderr.log")}

    def report_path(self, relative: str) -> Path:
        candidate = (self.reports_root / unquote(relative)).resolve()
        candidate.relative_to(self.reports_root)
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError("Report not found")
        if candidate.suffix not in REPORT_SUFFIXES:
            raise ValueError("Unsupported report artifact")
        return candidate

    @serialized
    def delete_report_run(self, relative: str) -> dict[str, str]:
        report = self.report_path(relative)
        if report.name != "claudit-report.json":
            raise ValueError("Only a complete Claudit report run can be deleted.")
        target = report.parent
        # Dashboard operation logs are retained; only their generated output is removed.
        if target.name == "output" and target.parent.parent == self.operations_root:
            pass
        elif target.parent == self.reports_root:
            pass
        else:
            raise ValueError("Report deletion refused for this path.")
        shutil.rmtree(target)
        return {"deleted": relative}

    @staticmethod
    def tail(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")[-65536:]
        except OSError:
            return ""

    def validate_request(self, request: dict[str, Any]) -> tuple[list[str], str, str, str]:
        services = request.get("service", [])
        if not isinstance(services, list) or not services or any(not isinstance(item, str) or item not in {entry["Name"] for entry in SERVICES} for item in services):
            raise ValueError("Select one or more supported services.")
        mode = str(request.get("mode", "preflight")).lower()
        if mode not in {"preflight", "safe", "audit"}:
            raise ValueError("Unsupported operation mode.")
        requested_level = str(request.get("controlLevel", "Passive")).lower()
        if requested_level not in {"formal", "passive", "active"}:
            raise ValueError("Unsupported control level.")
        if requested_level == "active" and request.get("confirmActiveProbes") is not True:
            raise ValueError("Active controls require explicit probe authorization.")
        command = "doctor" if mode == "preflight" else ("formal" if mode == "safe" else requested_level)
        if command in {'passive', 'active'} and set(services) != {'Domain'} and request.get('confirmTenantConnection') is not True:
            raise ValueError('Explicit authorization for read-only DNS/provider connections is required.')
        if str(request.get('format', 'all')).lower() not in {'all', 'json', 'csv', 'markdown', 'html'}:
            raise ValueError('Unsupported report format.')
        for field in ('domain', 'vpsTarget', 'awsProfile', 'awsRegion', 'azureSubscription', 'gcpProject', 'tailscaleTailnet', 'organization'):
            value = request.get(field, '')
            if not isinstance(value, str) or len(value) > 253 or (value and not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.@,-]*', value)):
                raise ValueError(f'Invalid {field}; use a declared identifier, not a command or URL.')
        if 'Domain' in services and command != 'doctor' and not request.get('domain'):
            raise ValueError('Declare one root domain.')
        if 'VPS' in services and command != 'doctor' and not request.get('vpsTarget'):
            raise ValueError('Declare one authorized VPS target.')
        if ',' in request.get('awsRegion', ''):
            raise ValueError('Select one AWS region per assessment.')
        return services, mode, requested_level, command

    @serialized
    def start_operation(self, request: dict[str, Any], baseline: dict | None = None, session_id: str | None = None) -> dict[str, Any]:
        services, mode, requested_level, command = self.validate_request(request)
        client_request_id = str(request.get("requestId", ""))
        if client_request_id and not re.fullmatch(r"[a-zA-Z0-9-]{12,80}", client_request_id):
            raise ValueError("Invalid operation request identifier.")
        if client_request_id:
            for operation in self.operation_views():
                if operation.get("ClientRequestId") == client_request_id:
                    return operation
        if sum(process.poll() is None for process in self.processes.values()) >= 2:
            raise ValueError('Two operations are already running; wait for completion.')
        operation_id = f"dashboard-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{secrets.token_hex(4)}"
        run_root, output = self.operations_root / operation_id, self.operations_root / operation_id / "output"
        output.mkdir(parents=True, exist_ok=False)
        arguments = [str(self.app_root / "claudit.sh"), command, "--output-directory", str(output), "--format", str(request.get("format", "all")).lower()]
        if mode != "preflight":
            arguments += ["--service", ",".join(services)]
            self.add_option(arguments, "--domain", request.get("domain"))
            self.add_option(arguments, "--vps-target", request.get("vpsTarget"))
            self.add_option(arguments, "--aws-profile", request.get("awsProfile"))
            self.add_option(arguments, "--aws-region", request.get("awsRegion"))
            self.add_option(arguments, "--azure-subscription", request.get("azureSubscription"))
            self.add_option(arguments, "--gcp-project", request.get("gcpProject"))
            self.add_option(arguments, "--tailscale-tailnet", request.get("tailscaleTailnet"))
            self.add_option(arguments, "--exchange-organization", request.get("organization"))
            if command in {"passive", "active"}:
                arguments.append("--confirm-tenant-connection")
            if command == "active":
                arguments.append("--confirm-active-probes")
        if baseline is not None:
            baseline_path = run_root / 'baseline.json'
            write_json(baseline_path, baseline)
            arguments += ['--baseline', str(baseline_path)]
        stdout, stderr = run_root / "stdout.log", run_root / "stderr.log"
        with stdout.open("wb") as out, stderr.open("wb") as err:
            environment = dict(os.environ)
            environment.pop('CLAUDIT_DASHBOARD_PASSWORD', None)
            environment.pop('CLAUDIT_WEBHOOK_URL', None)
            process = subprocess.Popen(arguments, env=environment, cwd=self.app_root, stdout=out, stderr=err, start_new_session=True)
        target = "Local engine" if mode == "preflight" else str(request.get("domain") or request.get("vpsTarget") or request.get("awsProfile") or request.get("azureSubscription") or request.get("gcpProject") or "Provider scope")
        operation = {"Id": operation_id, "ClientRequestId": client_request_id or None, "SessionId": session_id, "Title": str(request.get("title") or f"{command.title()} · {target}")[:120], "Target": target, "Scope": {key: request.get(key) for key in ("domain", "vpsTarget", "awsProfile", "awsRegion", "azureSubscription", "gcpProject")}, "Mode": mode, "ControlLevel": requested_level.title(), "Command": command,
                     "EffectiveControlLevel": command.title(), "Domain": str(request.get("domain", "")).strip(), "Status": "Running", "ExitCode": None,
                     "EvidenceStatus": "pending", "ProcessId": process.pid, "StartedUtc": utc_now(), "Services": services, "OutputDirectory": str(output),
                     "StdoutPath": str(stdout), "StderrPath": str(stderr)}
        (run_root / "metadata.json").write_text(json.dumps(operation, indent=2), encoding="utf-8")
        self.processes[operation_id] = process
        threading.Thread(target=self.watch_operation, args=(process, run_root), daemon=True).start()
        self.prune_operations(self.retention_count())
        return operation

    def watch_operation(self, process: subprocess.Popen, run_root: Path) -> None:
        try:
            process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            # Kill the whole collector group so a hung CLI cannot occupy the runner indefinitely.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            with (run_root / 'stderr.log').open('a') as stream:
                stream.write('\nClaudit stopped this operation after the 600-second execution limit.\n')

    @staticmethod
    def add_option(arguments: list[str], name: str, value: Any) -> None:
        if isinstance(value, str) and value.strip():
            arguments.extend([name, value.strip()])

    @serialized
    def prune_operations(self, keep: int) -> None:
        completed = []
        for metadata in self.operations_root.glob("*/metadata.json"):
            try:
                operation = json.loads(metadata.read_text(encoding="utf-8"))
                if operation.get("Status") != "Running":
                    completed.append(metadata.parent)
            except (OSError, json.JSONDecodeError):
                continue
        for directory in sorted(completed, key=lambda path: path.stat().st_mtime, reverse=True)[keep:]:
            for child in sorted(directory.rglob("*"), reverse=True):
                if child.is_file(): child.unlink()
                elif child.is_dir(): child.rmdir()
            directory.rmdir()


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, cockpit: Cockpit, **kwargs: Any) -> None:
        self.cockpit = cockpit
        super().__init__(*args, directory=str(cockpit.reports_root), **kwargs)

    def authorized(self) -> bool:
        try:
            host = urlsplit('http://' + self.headers.get('Host', '')).hostname
            if host != 'localhost':
                ipaddress.ip_address(host)
        except (ValueError, TypeError):
            self._json({'error': 'Use the server IP address or localhost.'}, HTTPStatus.FORBIDDEN)
            return False
        if self.cockpit.access_token:
            expected = 'Basic ' + base64.b64encode(('claudit:' + self.cockpit.access_token).encode()).decode()
            if not secrets.compare_digest(self.headers.get('Authorization', ''), expected):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Private Claudit", charset="UTF-8"')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return False
        return True

    def do_HEAD(self) -> None:
        if self.authorized():
            self._json({'error': 'HEAD is not supported.'}, HTTPStatus.METHOD_NOT_ALLOWED)

    def do_GET(self) -> None:  # noqa: N802
        if not self.authorized(): return
        parsed = urlsplit(self.path)
        if parsed.path == "/": return self._bytes(self.cockpit.dashboard_html(), "text/html; charset=utf-8")
        if parsed.path.startswith("/assets/"): return self._asset(parsed.path)
        if parsed.path == "/api/state":
            report_files = self.cockpit.report_files()
            reports = [self.cockpit.report_view(path) for path in report_files[:200]]
            asset_history = self.cockpit.asset_history(report_files)
            return self._json({"services": SERVICES, "authCatalog": AUTH_CATALOG, "controlCatalog": self.cockpit.control_catalog,
                               "baselineCapabilities": self.cockpit.baseline_capabilities, "dnsResolver": self.cockpit.dns_resolver,
                               "reports": reports, "reportTotal": len(report_files), "assetHistory": asset_history,
                               "overview": self.cockpit.report_overview(reports), "operations": self.cockpit.operation_views(),
                               "operationLimit": 2, "operationTimeoutSeconds": 600, "retentionCount": self.cockpit.retention_count()})
        if parsed.path == '/api/sessions': return self._call(self.cockpit.workspace.index)
        if parsed.path == '/api/session': return self._call(lambda: self.cockpit.workspace.load(parse_qs(parsed.query).get('id', [''])[0]))
        if parsed.path == '/api/session/export': return self._call(lambda: self.cockpit.workspace.export(parse_qs(parsed.query).get('id', [''])[0]))
        if parsed.path == '/api/session/dns/export': return self._call(lambda: self.cockpit.workspace.dns_zone_export(parse_qs(parsed.query).get('id', [''])[0]))
        if parsed.path == '/api/session/plan': return self._call(lambda: self.cockpit.workspace.plan(parse_qs(parsed.query).get('id', [''])[0]))
        if parsed.path == "/api/reports":
            query = parse_qs(parsed.query)
            return self._call(lambda: self.cockpit.report_index(int(query.get('offset', ['0'])[0]), int(query.get('limit', ['200'])[0])))
        if parsed.path == "/api/operations": return self._json(self.cockpit.operation_views())
        if parsed.path == "/api/operations/log":
            return self._call(lambda: self.cockpit.operation_log(parse_qs(parsed.query).get("id", [""])[0]))
        if parsed.path == "/api/report": return self._report(parse_qs(parsed.query).get("path", [""])[0])
        self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if not self.authorized(): return
        if self.headers.get("x-claudit-token") != self.cockpit.token:
            return self._json({"error": "Invalid dashboard request token."}, HTTPStatus.FORBIDDEN)
        try:
            length = int(self.headers.get("content-length", "0"))
            if not 0 <= length <= 1048576: raise ValueError("Request body is too large.")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict): raise ValueError("Request body must be a JSON object.")
            if self.path in {'/api/sessions', '/api/session/query', '/api/session/run', '/api/session/archive', '/api/session/quarantine', '/api/session/dns/import'}:
                with self.cockpit.lock:
                    action = {'/api/sessions': self.cockpit.workspace.create, '/api/session/query': self.cockpit.workspace.query, '/api/session/run': self.cockpit.workspace.run, '/api/session/archive': self.cockpit.workspace.archive, '/api/session/quarantine': self.cockpit.workspace.quarantine, '/api/session/dns/import': self.cockpit.workspace.normalize_dns_import}[self.path]
                    return self._json(action(body))
            if self.path == "/api/settings": return self._json({"retentionCount": self.cockpit.save_retention(body.get("retentionCount"))})
            if self.path == "/api/operations": return self._json(self.cockpit.start_operation(body))
            self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_DELETE(self) -> None:  # noqa: N802
        if not self.authorized(): return
        if self.headers.get("x-claudit-token") != self.cockpit.token:
            return self._json({"error": "Invalid dashboard request token."}, HTTPStatus.FORBIDDEN)
        parsed = urlsplit(self.path)
        if parsed.path == '/api/session':
            try:
                return self._json(self.cockpit.workspace.delete(parse_qs(parsed.query).get('id', [''])[0]))
            except ValueError as exc:
                return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if parsed.path != "/api/report":
            return self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        try:
            self._json(self.cockpit.delete_report_run(parse_qs(parsed.query).get("path", [""])[0]))
        except ValueError as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _call(self, action: Any) -> None:
        try: self._json(action())
        except ValueError as exc: self._json({"error": str(exc)}, HTTPStatus.NOT_FOUND)

    def _asset(self, path: str) -> None:
        candidate = (self.cockpit.web_root / unquote(path).lstrip("/")).resolve()
        try: candidate.relative_to(self.cockpit.web_root)
        except ValueError: return self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        try: self._bytes(candidate.read_bytes(), mimetypes.guess_type(candidate.name)[0] or "application/octet-stream")
        except OSError: self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def _report(self, relative: str) -> None:
        try:
            candidate = self.cockpit.report_path(relative)
            self.report_document = candidate.suffix == '.html'
            self._bytes(candidate.read_bytes(), mimetypes.guess_type(candidate.name)[0] or "application/octet-stream")
        except (OSError, ValueError): self._json({"error": "Report not found"}, HTTPStatus.NOT_FOUND)

    def _json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._bytes(json.dumps(value, separators=(",", ":")).encode(), "application/json; charset=utf-8", status)

    def _bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        if getattr(self, 'report_document', False):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Security-Policy', "sandbox; default-src 'none'; style-src 'unsafe-inline'")
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            self.report_document = False
            return
        self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(body))); self.send_header('Cache-Control', 'no-store'); self.send_header('X-Content-Type-Options', 'nosniff'); self.send_header('Referrer-Policy', 'no-referrer'); self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"); self.end_headers(); self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Claudit Bash cockpit")
    parser.add_argument("--bind", required=True); parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data-root", type=Path, required=True); parser.add_argument("--web-root", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    authentication = os.environ.get('CLAUDIT_DASHBOARD_AUTHENTICATION', 'disabled')
    password = os.environ.get('CLAUDIT_DASHBOARD_PASSWORD', '')
    if authentication not in {'disabled', 'required'}:
        parser.error('CLAUDIT_DASHBOARD_AUTHENTICATION must be disabled or required.')
    if authentication == 'required' and len(password) < 24:
        parser.error('Required dashboard authentication needs CLAUDIT_DASHBOARD_PASSWORD with at least 24 characters.')
    cockpit = Cockpit(Path(__file__).resolve().parent.parent, args.data_root, args.web_root)
    handler = lambda *items, **kwargs: DashboardHandler(*items, cockpit=cockpit, **kwargs)
    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ':' in args.bind else socket.AF_INET
        daemon_threads = True
    Server((args.bind, args.port), handler).serve_forever()


if __name__ == "__main__": main()
