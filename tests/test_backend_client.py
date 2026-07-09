from __future__ import annotations

import json
import re

from insightvm_pull.backend_client import BackendAlarmClient
from insightvm_pull.config import Settings


def _settings(
    url: str,
    backend_enabled: bool = True,
    payload_dir: str = "payloads",
    backend_dedupe_last_snapshot: bool = False,
    backend_notify_no_changes: bool = False,
) -> Settings:
    return Settings(
        insightvm_base_url="https://example/api/3",
        insightvm_user="u",
        insightvm_password="p",
        insightvm_timeout=5,
        insightvm_verify_ssl=False,
        page_size=200,
        interval_seconds=3600,
        max_retries=1,
        retry_backoff_seconds=0.0,
        severities=("critical", "high"),
        log_level="INFO",
        log_file="logs/integration.log",
        payload_dir=payload_dir,
        persist_payload_artifacts=True,
        backend_enabled=backend_enabled,
        backend_url=url,
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
        backend_dedupe_last_snapshot=backend_dedupe_last_snapshot,
        backend_notify_no_changes=backend_notify_no_changes,
    )


def test_backend_send_success(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"]))
    payload = {
        "findings": [
            {
                "asset_hostname": "OLT-1",
                "asset_ip": "192.168.1.100",
                "asset_id": "282",
                "vulnerability_id": "windows-hotfix-ms03-007",
                "vulnerability_title": "Test vuln",
                "severity": "critical",
                "cvss_score": 9.8,
                "cves": ["CVE-2017-11804"],
                "source": "insightvm",
            }
        ]
    }
    result = client.send_filtered_findings(payload)
    assert result["sent_ok"] == 1
    assert result["backend_errors"] == 0
    assert result["snapshot_id"]
    sent_payload = backend_alarm_test_server["state"].requests[0]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", sent_payload["snapshot_id"])
    assert len(sent_payload["alarms"]) == 1
    alarm = sent_payload["alarms"][0]
    assert alarm["finding_id"] == "282_windows-hotfix-ms03-007"
    assert alarm["asset_id"] == "282"
    assert alarm["vulnerability_id"] == "windows-hotfix-ms03-007"
    assert alarm["severity"] == "Critical"
    assert alarm["cvss_score"] == 9.8
    assert alarm["cves"] == ["CVE-2017-11804"]
    assert alarm["source"] == "Rapid7-InsightVM"
    assert alarm["TipoAlarma"] == "Alarma de seguridad de InsightVM x TXDXSecure"
    assert "insightvm_status" not in alarm


def test_backend_send_conflict(backend_alarm_test_server):
    backend_alarm_test_server["state"].mode = "conflict"
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"]))
    payload = {
        "findings": [
            {
                "asset_hostname": "OLT-CENTRAL-01",
                "asset_ip": "192.168.1.100",
                "asset_id": "282",
                "vulnerability_id": "windows-hotfix-ms03-007",
                "severity": "high",
                "title": "Conflict vuln",
            }
        ]
    }
    result = client.send_filtered_findings(payload)
    assert result["sent_ok"] == 0
    assert result["conflicts"] == 1


def test_backend_missing_required_fields(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"]))
    payload = {"findings": [{"severity": "critical", "title": "Missing host/ip"}]}
    result = client.send_filtered_findings(payload)
    assert result["validation_errors"] == 1
    assert result["sent_ok"] == 0


def test_backend_prepare_filtered_findings_includes_extended_fields(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"]))
    payload = {
        "findings": [
            {
                "asset_hostname": "OLT-PRUEBA-01",
                "asset_ip": "10.0.0.100",
                "asset_id": "282",
                "vulnerability_id": "windows-hotfix-ms03-007",
                "vulnerability_title": "Microsoft CVE-2017-11804",
                "severity": "critical",
                "cvss_score": 9.8,
                "cves": ["CVE-2017-11804"],
                "source": "insightvm",
                "fechaalarma": "2026-05-27 16:10:00",
            }
        ]
    }

    prepared = client.prepare_filtered_findings(payload, snapshot_id="2026-07-02T11:00:00Z")

    assert prepared["prepared_alarms_count"] == 1
    assert prepared["snapshot_id"] == "2026-07-02T11:00:00Z"
    alarm = prepared["alarms"][0]
    assert alarm == {
        "finding_id": "282_windows-hotfix-ms03-007",
        "servidor": "OLT-PRUEBA-01",
        "ip": "10.0.0.100",
        "TipoAlarma": "Alarma de seguridad de InsightVM x TXDXSecure",
        "Local": "Txdxsecure",
        "fechaalarma": "2026-05-27 16:10:00",
        "asset_id": "282",
        "vulnerability_id": "windows-hotfix-ms03-007",
        "vulnerability_title": "Microsoft CVE-2017-11804",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cves": ["CVE-2017-11804"],
        "source": "Rapid7-InsightVM",
    }
    assert prepared["request_payload"] == {
        "snapshot_id": "2026-07-02T11:00:00Z",
        "alarms": [alarm],
    }
    assert "skipped_findings" not in prepared


def test_backend_disabled_does_not_send_requests(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"], backend_enabled=False))
    payload = {
        "findings": [
            {
                "asset_hostname": "OLT-1",
                "asset_ip": "192.168.1.100",
                "asset_id": "282",
                "vulnerability_id": "windows-hotfix-ms03-007",
                "vulnerability_title": "Test vuln",
                "severity": "critical",
                "source": "insightvm",
            }
        ]
    }

    result = client.send_filtered_findings(payload)

    assert result["enabled"] is False
    assert result["skipped"] is True
    assert result["prepared_alarms"] == 1
    assert result["sent_ok"] == 0
    assert backend_alarm_test_server["state"].requests == []


def test_backend_prepare_uses_ip_when_hostname_missing(backend_alarm_test_server):
    client = BackendAlarmClient(_settings(backend_alarm_test_server["url"]))

    prepared = client.prepare_filtered_findings(
        {
            "findings": [
                {
                    "asset_ip": "10.0.0.100",
                    "asset_id": "282",
                    "vulnerability_id": "windows-hotfix-ms03-007",
                    "severity": "critical",
                    "title": "Fallback host",
                }
            ]
        },
        snapshot_id="2026-07-02T11:00:00Z",
    )

    alarm = prepared["alarms"][0]
    assert alarm["finding_id"] == "282_windows-hotfix-ms03-007"
    assert alarm["servidor"] == "10.0.0.100"
    assert alarm["ip"] == "10.0.0.100"


def test_backend_dedupe_sends_only_new_alarms(backend_alarm_test_server, tmp_path):
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()
    (payload_dir / "backend_last_snapshot.json").write_text(
        json.dumps({"snapshot_id": "previous", "alarms": [{"finding_id": "a1_v1"}]}),
        encoding="utf-8",
    )
    client = BackendAlarmClient(
        _settings(backend_alarm_test_server["url"], payload_dir=str(payload_dir), backend_dedupe_last_snapshot=True)
    )
    current_alarm = {"finding_id": "a1_v1", "asset_id": "a1", "vulnerability_id": "v1"}
    new_alarm = {"finding_id": "a1_v2", "asset_id": "a1", "vulnerability_id": "v2"}

    result = client.send_prepared_alarms(
        {
            "snapshot_id": "current",
            "total_filtered_findings": 2,
            "validation_errors": 0,
            "request_payload": {"snapshot_id": "current", "alarms": [current_alarm, new_alarm]},
        }
    )

    assert result["prepared_alarms"] == 2
    assert result["new_alarms"] == 1
    assert result["duplicate_skipped"] == 1
    assert result["sent_ok"] == 1
    sent_payload = backend_alarm_test_server["state"].requests[0]
    assert sent_payload["alarms"] == [new_alarm]
    baseline = json.loads((payload_dir / "backend_last_snapshot.json").read_text(encoding="utf-8"))
    assert {alarm["finding_id"] for alarm in baseline["alarms"]} == {"a1_v1", "a1_v2"}


def test_backend_dedupe_allows_alarm_to_reappear_after_missing_snapshot(backend_alarm_test_server, tmp_path):
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()
    (payload_dir / "backend_last_snapshot.json").write_text(
        json.dumps({"snapshot_id": "previous", "alarms": [{"finding_id": "a1_v1"}, {"finding_id": "a1_v2"}]}),
        encoding="utf-8",
    )
    client = BackendAlarmClient(
        _settings(backend_alarm_test_server["url"], payload_dir=str(payload_dir), backend_dedupe_last_snapshot=True)
    )
    alarm_v1 = {"finding_id": "a1_v1", "asset_id": "a1", "vulnerability_id": "v1"}
    alarm_v2 = {"finding_id": "a1_v2", "asset_id": "a1", "vulnerability_id": "v2"}

    first_result = client.send_prepared_alarms(
        {
            "snapshot_id": "current-without-v2",
            "request_payload": {"snapshot_id": "current-without-v2", "alarms": [alarm_v1]},
        }
    )

    assert first_result["post_skipped"] is True
    assert first_result["new_alarms"] == 0
    assert backend_alarm_test_server["state"].requests == []
    baseline_after_missing = json.loads((payload_dir / "backend_last_snapshot.json").read_text(encoding="utf-8"))
    assert [alarm["finding_id"] for alarm in baseline_after_missing["alarms"]] == ["a1_v1"]

    second_result = client.send_prepared_alarms(
        {
            "snapshot_id": "current-with-v2-again",
            "request_payload": {"snapshot_id": "current-with-v2-again", "alarms": [alarm_v1, alarm_v2]},
        }
    )

    assert second_result["new_alarms"] == 1
    assert second_result["duplicate_skipped"] == 1
    assert second_result["sent_ok"] == 1
    assert backend_alarm_test_server["state"].requests[0]["alarms"] == [alarm_v2]


def test_backend_can_notify_no_changes_with_empty_post(backend_alarm_test_server, tmp_path):
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()
    (payload_dir / "backend_last_snapshot.json").write_text(
        json.dumps({"snapshot_id": "previous", "alarms": [{"finding_id": "a1_v1"}]}),
        encoding="utf-8",
    )
    client = BackendAlarmClient(
        _settings(
            backend_alarm_test_server["url"],
            payload_dir=str(payload_dir),
            backend_dedupe_last_snapshot=True,
            backend_notify_no_changes=True,
        )
    )
    alarm = {"finding_id": "a1_v1", "asset_id": "a1", "vulnerability_id": "v1"}

    result = client.send_prepared_alarms(
        {
            "snapshot_id": "current",
            "request_payload": {"snapshot_id": "current", "alarms": [alarm]},
        }
    )

    assert result["post_skipped"] is False
    assert result["notify_no_changes"] is True
    assert result["no_change_notification_sent"] is True
    assert result["new_alarms"] == 0
    assert result["duplicate_skipped"] == 1
    assert result["sent_ok"] == 0
    sent_payload = backend_alarm_test_server["state"].requests[0]
    assert sent_payload["alarms"] == []
    assert sent_payload["no_changes"] is True
    assert sent_payload["message"] == "Data extracted successfully; no new vulnerabilities detected"

