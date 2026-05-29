from __future__ import annotations

from insightvm_pull.client import InsightVMClient
from insightvm_pull.collector import InsightVMCollector, _extract_alert_time, filter_payload_by_severity
from insightvm_pull.config import Settings


def test_filter_payload_by_severity():
    payload = {
        "assets": [{"id": 1}],
        "findings": [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
        ],
        "meta": {"assets_count": 1, "findings_count": 3},
    }
    out = filter_payload_by_severity(payload, ("critical", "high"))
    assert out["meta"]["findings_count"] == 2
    assert [f["severity"] for f in out["findings"]] == ["critical", "high"]


def test_collect_filters_before_fetching_vulnerability_detail(insightvm_test_server):
    settings = Settings(
        insightvm_base_url=insightvm_test_server["base_url"],
        insightvm_user="u",
        insightvm_password="p",
        insightvm_timeout=5,
        insightvm_verify_ssl=False,
        page_size=1,
        interval_seconds=3600,
        max_retries=1,
        retry_backoff_seconds=0.0,
        severities=("critical", "high"),
        log_level="INFO",
        log_file="logs/integration.log",
        payload_dir="payloads",
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))

    payload = collector.collect(page_size=1, allowed_severities=("critical", "high"))

    assert payload["meta"]["findings_count"] == 1
    assert payload["meta"]["filtered_before_detail_count"] == 1
    assert payload["meta"]["vulnerability_detail_requests"] == 1
    assert insightvm_test_server["state"].vuln_detail_calls == ["v1"]


def test_collect_reads_all_asset_vulnerability_pages(insightvm_test_server):
    insightvm_test_server["state"].asset_vulns = {
        "a1": {
            0: [{"id": "v1", "severity": "critical"}],
            1: [{"id": "v3", "severity": "high"}],
            2: [],
        }
    }
    insightvm_test_server["state"].vuln_defs["v3"] = {
        "id": "v3",
        "title": "High vuln",
        "severity": "high",
        "riskScore": 700,
    }
    settings = Settings(
        insightvm_base_url=insightvm_test_server["base_url"],
        insightvm_user="u",
        insightvm_password="p",
        insightvm_timeout=5,
        insightvm_verify_ssl=False,
        page_size=1,
        interval_seconds=3600,
        max_retries=1,
        retry_backoff_seconds=0.0,
        severities=("critical", "high"),
        log_level="INFO",
        log_file="logs/integration.log",
        payload_dir="payloads",
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))

    payload = collector.collect(page_size=1, allowed_severities=("critical", "high"))

    assert payload["meta"]["findings_count"] == 2
    assert payload["meta"]["vulnerability_detail_requests"] == 2
    assert [finding["vulnerability_id"] for finding in payload["findings"]] == ["v1", "v3"]
    assert [call["query"]["page"][0] for call in insightvm_test_server["state"].asset_vuln_calls] == ["0", "1", "2"]


def test_collect_fetches_shared_vulnerability_detail_once_for_multiple_assets(insightvm_test_server):
    insightvm_test_server["state"].assets_pages = {
        0: [
            {"id": "a1", "hostName": "srv-1", "addresses": [{"ip": "10.0.0.1"}]},
            {"id": "a2", "hostName": "srv-2", "addresses": [{"ip": "10.0.0.2"}]},
        ],
        1: [],
    }
    insightvm_test_server["state"].asset_vulns = {
        "a1": [{"id": "v1", "severity": "critical"}],
        "a2": [{"id": "v1", "severity": "critical"}],
    }
    settings = Settings(
        insightvm_base_url=insightvm_test_server["base_url"],
        insightvm_user="u",
        insightvm_password="p",
        insightvm_timeout=5,
        insightvm_verify_ssl=False,
        page_size=10,
        interval_seconds=3600,
        max_retries=1,
        retry_backoff_seconds=0.0,
        severities=("critical", "high"),
        log_level="INFO",
        log_file="logs/integration.log",
        payload_dir="payloads",
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))

    payload = collector.collect(page_size=10, allowed_severities=("critical", "high"))

    assert payload["meta"]["findings_count"] == 2
    assert payload["meta"]["vulnerability_detail_requests"] == 1
    assert insightvm_test_server["state"].vuln_detail_calls == ["v1"]


def test_extract_alert_time_prefers_operational_dates_over_published():
    ref = {
        "lastSeen": "2026-05-27T16:10:00Z",
        "firstDiscovered": "2026-05-10T08:00:00Z",
    }
    vdef = {
        "published": "2017-10-10T00:00:00Z",
    }

    alert_time = _extract_alert_time(ref, vdef)

    assert alert_time == "2026-05-27 16:10:00"


def test_extract_alert_time_falls_back_to_first_discovered_then_now():
    ref = {
        "firstDiscovered": "2026-05-10T08:00:00Z",
    }
    vdef = {
        "published": "2017-10-10T00:00:00Z",
    }

    alert_time = _extract_alert_time(ref, vdef)

    assert alert_time == "2026-05-10 08:00:00"

