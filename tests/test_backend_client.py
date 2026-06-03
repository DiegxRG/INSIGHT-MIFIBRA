from __future__ import annotations

from insightvm_pull.backend_client import BackendAlarmClient
from insightvm_pull.config import Settings


def _settings(url: str, backend_enabled: bool = True) -> Settings:
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
        payload_dir="payloads",
        backend_enabled=backend_enabled,
        backend_url=url,
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
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
    sent_payload = backend_alarm_test_server["state"].requests[0]
    assert sent_payload["finding_id"] == "282_windows-hotfix-ms03-007"
    assert sent_payload["asset_id"] == "282"
    assert sent_payload["vulnerability_id"] == "windows-hotfix-ms03-007"
    assert sent_payload["severity"] == "Critical"
    assert sent_payload["cvss_score"] == 9.8
    assert sent_payload["cves"] == "CVE-2017-11804"
    assert sent_payload["source"] == "insightvm"
    assert "insightvm_status" not in sent_payload


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

    prepared = client.prepare_filtered_findings(payload)

    assert prepared["prepared_alarms_count"] == 1
    alarm = prepared["alarms"][0]
    assert alarm == {
        "finding_id": "282_windows-hotfix-ms03-007",
        "servidor": "OLT-PRUEBA-01",
        "ip": "10.0.0.100",
        "TipoAlarma": "1 - Alarma de seguridad [Critical] - Microsoft CVE-2017-11804",
        "Local": "Txdxsecure",
        "fechaalarma": "2026-05-27 16:10:00",
        "asset_id": "282",
        "vulnerability_id": "windows-hotfix-ms03-007",
        "vulnerability_title": "Microsoft CVE-2017-11804",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cves": "CVE-2017-11804",
        "source": "insightvm",
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
        }
    )

    alarm = prepared["alarms"][0]
    assert alarm["finding_id"] == "282_windows-hotfix-ms03-007"
    assert alarm["servidor"] == "10.0.0.100"
    assert alarm["ip"] == "10.0.0.100"

