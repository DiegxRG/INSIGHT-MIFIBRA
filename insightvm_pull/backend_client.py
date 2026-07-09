from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from insightvm_pull.config import Settings

log = logging.getLogger("insightvm_pull.backend")

FIXED_ALARM_TYPE = "Alarma de seguridad de InsightVM x TXDXSecure"
FIXED_SOURCE = "Rapid7-InsightVM"
LAST_BACKEND_SNAPSHOT_FILE = "backend_last_snapshot.json"


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
        dedupe_enabled = bool(self.settings.backend_dedupe_last_snapshot)
        notify_no_changes = bool(self.settings.backend_notify_no_changes)
        baseline_path = _last_backend_snapshot_path(self.settings)
        duplicate_skipped = 0
        alarms_to_send = alarms
        if dedupe_enabled:
            previous_ids = _load_last_snapshot_finding_ids(baseline_path)
            alarms_to_send, duplicate_skipped = _filter_new_alarms(alarms, previous_ids)

        if not self.settings.backend_enabled:
            return {
                "enabled": False,
                "skipped": True,
                "snapshot_id": snapshot_id,
                "total_filtered_findings": int(prepared_payload.get("total_filtered_findings", len(alarms))),
                "prepared_alarms": len(alarms),
                "new_alarms": len(alarms_to_send),
                "duplicate_skipped": duplicate_skipped,
                "dedupe_enabled": dedupe_enabled,
                "notify_no_changes": notify_no_changes,
                "sent_ok": 0,
                "conflicts": 0,
                "validation_errors": validation_errors,
                "backend_errors": 0,
                "details": details,
            }

        sent_ok = 0
        conflicts = 0
        backend_errors = 0

        if dedupe_enabled and not alarms_to_send:
            _write_last_snapshot(baseline_path, snapshot_id, alarms)
            post_skipped = True
            no_change_notification_sent = False
            no_change_notification_error = False
            if notify_no_changes:
                result = self._post_snapshot(
                    _build_no_changes_payload(
                        snapshot_id=snapshot_id,
                        prepared_alarms=len(alarms),
                        duplicate_skipped=duplicate_skipped,
                    )
                )
                details.append(result)
                post_skipped = False
                no_change_notification_sent = result.get("success") is True
                no_change_notification_error = not no_change_notification_sent
            else:
                details.append(
                    {
                        "success": True,
                        "message": "No new alarms to send after last-snapshot dedupe",
                        "snapshot_payload": {"snapshot_id": snapshot_id, "alarms": []},
                    }
                )
            log.info(
                "snapshot_id=%s no new backend alarms prepared=%s duplicate_skipped=%s notify_no_changes=%s",
                snapshot_id,
                len(alarms),
                duplicate_skipped,
                notify_no_changes,
            )
            return {
                "enabled": self.settings.backend_enabled,
                "skipped": False,
                "post_skipped": post_skipped,
                "snapshot_id": snapshot_id,
                "total_filtered_findings": int(prepared_payload.get("total_filtered_findings", len(alarms))),
                "prepared_alarms": len(alarms),
                "new_alarms": 0,
                "duplicate_skipped": duplicate_skipped,
                "dedupe_enabled": dedupe_enabled,
                "notify_no_changes": notify_no_changes,
                "no_change_notification_sent": no_change_notification_sent,
                "no_change_notification_error": no_change_notification_error,
                "sent_ok": 0,
                "conflicts": 0,
                "validation_errors": validation_errors,
                "backend_errors": 0,
                "details": details,
            }

        send_payload = {"snapshot_id": snapshot_id, "alarms": alarms_to_send}
        result = self._post_snapshot(send_payload)
        details.append(result)
        if result.get("success") is True:
            sent_ok = len(alarms_to_send)
            if dedupe_enabled:
                _write_last_snapshot(baseline_path, snapshot_id, alarms)
        elif "Ya existe" in str(result.get("message", "")):
            conflicts = len(alarms_to_send)
        else:
            backend_errors = len(alarms_to_send)

        return {
            "enabled": self.settings.backend_enabled,
            "skipped": False,
            "snapshot_id": snapshot_id,
            "total_filtered_findings": int(prepared_payload.get("total_filtered_findings", len(alarms))),
            "prepared_alarms": len(alarms),
            "new_alarms": len(alarms_to_send),
            "duplicate_skipped": duplicate_skipped,
            "dedupe_enabled": dedupe_enabled,
            "notify_no_changes": notify_no_changes,
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


def _last_backend_snapshot_path(settings: Settings) -> Path:
    return Path(settings.payload_dir) / LAST_BACKEND_SNAPSHOT_FILE


def _load_last_snapshot_finding_ids(path: Path) -> set[str]:
    if not path.exists() or not path.is_file():
        return set()
    try:
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as exc:
        log.warning("Could not load backend last snapshot baseline %s: %s", path, exc)
        return set()
    alarms = payload.get("alarms", []) if isinstance(payload, dict) else []
    if not isinstance(alarms, list):
        return set()
    return {
        str(alarm.get("finding_id")).strip()
        for alarm in alarms
        if isinstance(alarm, dict) and str(alarm.get("finding_id") or "").strip()
    }


def _filter_new_alarms(alarms: list[Any], previous_ids: set[str]) -> tuple[list[dict[str, Any]], int]:
    new_alarms: list[dict[str, Any]] = []
    current_ids: set[str] = set()
    duplicate_skipped = 0
    for alarm in alarms:
        if not isinstance(alarm, dict):
            continue
        finding_id = str(alarm.get("finding_id") or "").strip()
        if finding_id and (finding_id in previous_ids or finding_id in current_ids):
            duplicate_skipped += 1
            continue
        if finding_id:
            current_ids.add(finding_id)
        new_alarms.append(alarm)
    return new_alarms, duplicate_skipped


def _write_last_snapshot(path: Path, snapshot_id: str, alarms: list[Any]) -> None:
    payload = {
        "snapshot_id": snapshot_id,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "alarms": [alarm for alarm in alarms if isinstance(alarm, dict)],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def _build_no_changes_payload(snapshot_id: str, prepared_alarms: int, duplicate_skipped: int) -> dict[str, Any]:
    return {
        "snapshot_id": snapshot_id,
        "alarms": [],
        "no_changes": True,
        "message": "Data extracted successfully; no new vulnerabilities detected",
        "prepared_alarms": prepared_alarms,
        "new_alarms": 0,
        "duplicate_skipped": duplicate_skipped,
        "source": FIXED_SOURCE,
    }


def build_snapshot_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

