from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import requests

from insightvm_pull.config import Settings

log = logging.getLogger("insightvm_pull.backend")


class BackendAlarmClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.session = requests.Session()

    def prepare_filtered_findings(self, filtered_payload: dict[str, Any]) -> dict[str, Any]:
        findings = filtered_payload.get("findings", [])
        if not isinstance(findings, list):
            findings = []

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
                    {"success": False, "message": "Missing required fields: servidor/ip", "finding": finding}
                )
                continue
            alarms.append(alarm)

        return {
            "enabled": self.settings.backend_enabled,
            "total_filtered_findings": len(findings),
            "prepared_alarms_count": len(alarms),
            "validation_errors": validation_errors,
            "alarms": alarms,
            "skipped_findings": skipped_findings,
        }

    def send_filtered_findings(self, filtered_payload: dict[str, Any]) -> dict[str, Any]:
        prepared_payload = self.prepare_filtered_findings(filtered_payload)
        return self.send_prepared_alarms(prepared_payload)

    def send_prepared_alarms(self, prepared_payload: dict[str, Any]) -> dict[str, Any]:
        alarms = prepared_payload.get("alarms", [])
        if not isinstance(alarms, list):
            alarms = []

        validation_errors = int(prepared_payload.get("validation_errors", 0))
        details: list[dict[str, Any]] = list(prepared_payload.get("skipped_findings", []))
        if not self.settings.backend_enabled:
            return {
                "enabled": False,
                "skipped": True,
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

        for alarm in alarms:
            if not isinstance(alarm, dict):
                continue
            result = self._post_alarm(alarm)
            details.append(result)
            if result.get("success") is True:
                sent_ok += 1
            elif "Ya existe un registro activo" in str(result.get("message", "")):
                conflicts += 1
            else:
                backend_errors += 1

        return {
            "enabled": self.settings.backend_enabled,
            "skipped": False,
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
        if not servidor:
            servidor = ip
        if not servidor or not ip:
            return None

        sev = str(finding.get("severity") or "").lower()
        title = str(finding.get("vulnerability_title") or finding.get("title") or "Alarma de seguridad").strip()
        tipo = f"{self.settings.backend_alarm_type} [{_display_severity(sev)}] - {title}"
        fecha = str(finding.get("fechaalarma") or "").strip() or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cves = finding.get("cves")
        if isinstance(cves, list):
            cves = ", ".join(str(item).strip() for item in cves if str(item).strip())
        elif cves is None:
            cves = ""

        cvss_score = finding.get("cvss_score")
        if cvss_score is None:
            cvss_score = finding.get("cvss")

        insightvm_status = str(finding.get("insightvm_status") or "").strip().lower()

        return {
            "servidor": servidor,
            "ip": ip,
            "TipoAlarma": tipo,
            "Local": self.settings.backend_local,
            "fechaalarma": fecha,
            "asset_id": str(finding.get("asset_id") or "").strip(),
            "vulnerability_id": str(finding.get("vulnerability_id") or "").strip(),
            "vulnerability_title": title,
            "severity": _display_severity(sev),
            "cvss_score": cvss_score,
            "cves": cves,
            "source": str(finding.get("source") or "insightvm").strip() or "insightvm",
            "insightvm_status": insightvm_status,
        }

    def _post_alarm(self, alarm_payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.session.post(
                self.settings.backend_url,
                json=alarm_payload,
                timeout=self.settings.backend_timeout,
                verify=self.settings.backend_verify_ssl,
                headers={"Content-Type": "application/json"},
            )
        except Exception as exc:
            log.error("Backend connection error: %s", exc)
            return {"success": False, "message": f"Connection error: {exc}", "alarm_payload": alarm_payload}

        try:
            data = response.json()
        except Exception:
            data = {"success": False, "message": f"Non-JSON backend response HTTP {response.status_code}"}

        if not isinstance(data, dict):
            data = {"success": False, "message": "Invalid backend response format"}

        data["http_status"] = response.status_code
        data["alarm_payload"] = alarm_payload
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

