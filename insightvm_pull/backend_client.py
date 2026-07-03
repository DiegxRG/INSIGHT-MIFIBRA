from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import requests

from insightvm_pull.config import Settings

log = logging.getLogger("insightvm_pull.backend")

FIXED_ALARM_TYPE = "Alarma de seguridad de InsightVM x TXDXSecure"
FIXED_SOURCE = "Rapid7-InsightVM"


class BackendAlarmClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.session = requests.Session()

    def prepare_filtered_findings(
        self,
        filtered_payload: dict[str, Any],
        snapshot_id: str | None = None,
    ) -> dict[str, Any]:
        findings = filtered_payload.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        snapshot_id = snapshot_id or build_snapshot_id()

        alarms: list[dict[str, Any]] = []
        skipped_findings: list[dict[str, Any]] = []
        validation_errors = 0

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            alarm = self._build_alarm_payload(finding)
            if alarm is None:
                validation_errors += 1
                skipped_findings.append(
                    {
                        "success": False,
                        "message": "Missing required fields: servidor/ip/asset_id/vulnerability_id",
                        "finding": finding,
                    }
                )
                continue
            alarms.append(alarm)

        request_payload = {
            "snapshot_id": snapshot_id,
            "alarms": alarms,
        }
        payload = {
            "enabled": self.settings.backend_enabled,
            "snapshot_id": snapshot_id,
            "total_filtered_findings": len(findings),
            "prepared_alarms_count": len(alarms),
            "validation_errors": validation_errors,
            "alarms": alarms,
            "request_payload": request_payload,
        }
        if skipped_findings:
            payload["skipped_findings"] = skipped_findings
        return payload

    def send_filtered_findings(self, filtered_payload: dict[str, Any], snapshot_id: str | None = None) -> dict[str, Any]:
        prepared_payload = self.prepare_filtered_findings(filtered_payload, snapshot_id=snapshot_id)
        return self.send_prepared_alarms(prepared_payload)

    def send_prepared_alarms(self, prepared_payload: dict[str, Any]) -> dict[str, Any]:
        request_payload = prepared_payload.get("request_payload")
        if not isinstance(request_payload, dict):
            request_payload = {
                "snapshot_id": prepared_payload.get("snapshot_id") or build_snapshot_id(),
                "alarms": prepared_payload.get("alarms", []),
            }

        alarms = request_payload.get("alarms", [])
        if not isinstance(alarms, list):
            alarms = []
        snapshot_id = str(request_payload.get("snapshot_id") or "").strip()

        validation_errors = int(prepared_payload.get("validation_errors", 0))
        details: list[dict[str, Any]] = list(prepared_payload.get("skipped_findings", []))
        if not self.settings.backend_enabled:
            return {
                "enabled": False,
                "skipped": True,
                "snapshot_id": snapshot_id,
                "total_filtered_findings": int(prepared_payload.get("total_filtered_findings", len(alarms))),
                "prepared_alarms": len(alarms),
                "sent_ok": 0,
                "conflicts": 0,
                "validation_errors": validation_errors,
                "backend_errors": 0,
                "details": details,
            }

        sent_ok = 0
        conflicts = 0
        backend_errors = 0

        result = self._post_snapshot(request_payload)
        details.append(result)
        if result.get("success") is True:
            sent_ok = len(alarms)
        elif "Ya existe" in str(result.get("message", "")):
            conflicts = len(alarms)
        else:
            backend_errors = len(alarms)

        return {
            "enabled": self.settings.backend_enabled,
            "skipped": False,
            "snapshot_id": snapshot_id,
            "total_filtered_findings": int(prepared_payload.get("total_filtered_findings", len(alarms))),
            "prepared_alarms": len(alarms),
            "sent_ok": sent_ok,
            "conflicts": conflicts,
            "validation_errors": validation_errors,
            "backend_errors": backend_errors,
            "details": details,
        }

    def _build_alarm_payload(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        servidor = str(finding.get("asset_hostname") or "").strip()
        ip = str(finding.get("asset_ip") or "").strip()
        asset_id = str(finding.get("asset_id") or "").strip()
        vulnerability_id = str(finding.get("vulnerability_id") or "").strip()
        if not servidor:
            servidor = ip
        if not servidor or not ip or not asset_id or not vulnerability_id:
            return None

        sev = str(finding.get("severity") or "").lower()
        title = str(finding.get("vulnerability_title") or finding.get("title") or "Alarma de seguridad").strip()
        fecha = str(finding.get("fechaalarma") or "").strip() or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cves = finding.get("cves")
        if isinstance(cves, list):
            cves = [str(item).strip() for item in cves if str(item).strip()]
        elif isinstance(cves, str) and cves.strip():
            cves = [item.strip() for item in cves.split(",") if item.strip()]
        else:
            cves = []

        cvss_score = finding.get("cvss_score")
        if cvss_score is None:
            cvss_score = finding.get("cvss")

        finding_id = _build_finding_id(asset_id, vulnerability_id)

        return {
            "finding_id": finding_id,
            "servidor": servidor,
            "ip": ip,
            "TipoAlarma": FIXED_ALARM_TYPE,
            "Local": self.settings.backend_local,
            "fechaalarma": fecha,
            "asset_id": asset_id,
            "vulnerability_id": vulnerability_id,
            "vulnerability_title": title,
            "severity": _display_severity(sev),
            "cvss_score": cvss_score,
            "cves": cves,
            "source": FIXED_SOURCE,
        }

    def _post_snapshot(self, snapshot_payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.session.post(
                self.settings.backend_url,
                json=snapshot_payload,
                timeout=self.settings.backend_timeout,
                verify=self.settings.backend_verify_ssl,
                headers={"Content-Type": "application/json"},
            )
        except Exception as exc:
            log.error("Backend connection error: %s", exc)
            return {"success": False, "message": f"Connection error: {exc}", "snapshot_payload": snapshot_payload}

        try:
            data = response.json()
        except Exception:
            data = {"success": False, "message": f"Non-JSON backend response HTTP {response.status_code}"}

        if not isinstance(data, dict):
            data = {"success": False, "message": "Invalid backend response format"}

        data["http_status"] = response.status_code
        data["snapshot_payload"] = snapshot_payload
        return data


def _display_severity(value: str) -> str:
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "unknown": "Unknown",
    }
    return mapping.get(value, value.title() if value else "Unknown")


def _build_finding_id(asset_id: str, vulnerability_id: str) -> str:
    return f"{asset_id}_{vulnerability_id}"


def build_snapshot_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

