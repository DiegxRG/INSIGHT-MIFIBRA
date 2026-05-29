from __future__ import annotations

from insightvm_pull.client import InsightVMClient
from insightvm_pull.collector import InsightVMCollector, filter_payload_by_severity
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

