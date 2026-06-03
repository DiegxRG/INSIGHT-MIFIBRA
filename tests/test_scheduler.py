from __future__ import annotations

import json
from pathlib import Path

from insightvm_pull.client import InsightVMClient
from insightvm_pull.collector import InsightVMCollector
from insightvm_pull.config import Settings
from insightvm_pull.scheduler import run_service


def test_run_service_retries_and_persists_real_server(tmp_path: Path, insightvm_test_server):
    server = insightvm_test_server
    server["state"].fail_assets_times = 1
    settings = Settings(
        insightvm_base_url=server["base_url"],
        insightvm_user="u",
        insightvm_password="p",
        insightvm_timeout=5,
        insightvm_verify_ssl=False,
        page_size=1,
        interval_seconds=3600,
        max_retries=3,
        retry_backoff_seconds=0.0,
        severities=("critical", "high"),
        log_level="INFO",
        log_file=str(tmp_path / "logs" / "integration.log"),
        payload_dir=str(tmp_path / "payloads"),
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))
    run_service(settings=settings, collector=collector, once=True)

    payload_files = sorted((tmp_path / "payloads").glob("*.json"))
    assert len(payload_files) == 3
    filtered_file = tmp_path / "payloads" / "filtered_latest.json"
    prepared_file = tmp_path / "payloads" / "prepared_backend_latest.json"
    meta_file = tmp_path / "payloads" / "run_latest.meta.json"

    filtered_data = json.loads(filtered_file.read_text(encoding="utf-8"))
    prepared_data = json.loads(prepared_file.read_text(encoding="utf-8"))
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))

    assert filtered_data["meta"]["findings_count"] == 1
    assert set(filtered_data.keys()) == {"findings", "meta"}
    assert filtered_data["findings"][0]["asset_hostname"] == "srv-1"
    assert "raw" not in filtered_data["findings"][0]
    assert "raw_ref" not in filtered_data["findings"][0]
    assert prepared_data["prepared_alarms_count"] == 1
    assert prepared_data["alarms"][0]["finding_id"] == "a1_v1"
    assert prepared_data["alarms"][0]["severity"] == "Critical"
    assert "insightvm_status" not in prepared_data["alarms"][0]
    assert "estado" not in prepared_data["alarms"][0]
    assert "skipped_findings" not in prepared_data
    assert meta_data["success"] is True
    assert server["state"].assets_calls == 3


def test_run_service_persists_raw_api_in_debug_mode(tmp_path: Path, insightvm_test_server):
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
        log_file=str(tmp_path / "logs" / "integration.log"),
        payload_dir=str(tmp_path / "payloads"),
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
        persist_raw_api_debug=True,
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))

    run_service(settings=settings, collector=collector, once=True)

    payload_files = sorted((tmp_path / "payloads").glob("*.json"))
    assert len(payload_files) == 4
    assert (tmp_path / "payloads" / "filtered_latest.json").exists()
    assert (tmp_path / "payloads" / "prepared_backend_latest.json").exists()
    assert (tmp_path / "payloads" / "run_latest.meta.json").exists()
    raw_api_file = [p for p in payload_files if p.name.startswith("raw_api_")][0]
    raw_api_data = json.loads(raw_api_file.read_text(encoding="utf-8"))

    assert "assets_pages" in raw_api_data
    assert "asset_vulnerabilities" in raw_api_data
    assert "vulnerability_definitions" in raw_api_data


def test_run_service_does_not_retry_unauthorized_and_only_persists_meta(tmp_path: Path, insightvm_test_server):
    server = insightvm_test_server
    server["state"].fail_assets_times = 10
    server["state"].assets_failure_status = 401
    settings = Settings(
        insightvm_base_url=server["base_url"],
        insightvm_user="u",
        insightvm_password="p",
        insightvm_timeout=5,
        insightvm_verify_ssl=False,
        page_size=1,
        interval_seconds=3600,
        max_retries=3,
        retry_backoff_seconds=0.0,
        severities=("critical", "high"),
        log_level="INFO",
        log_file=str(tmp_path / "logs" / "integration.log"),
        payload_dir=str(tmp_path / "payloads"),
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
    )
    collector = InsightVMCollector(client=InsightVMClient(settings=settings))

    run_service(settings=settings, collector=collector, once=True)

    payload_files = sorted((tmp_path / "payloads").glob("*.json"))
    assert len(payload_files) == 1
    meta_file = tmp_path / "payloads" / "run_latest.meta.json"
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))

    assert meta_data["success"] is False
    assert "HTTP 401" in meta_data["error"]
    assert server["state"].assets_calls == 1


def test_run_service_failed_cycle_keeps_previous_latest_payloads(tmp_path: Path, insightvm_test_server):
    payload_dir = tmp_path / "payloads"
    settings_ok = Settings(
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
        log_file=str(tmp_path / "logs" / "integration.log"),
        payload_dir=str(payload_dir),
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
    )
    collector_ok = InsightVMCollector(client=InsightVMClient(settings=settings_ok))
    run_service(settings=settings_ok, collector=collector_ok, once=True)

    filtered_before = (payload_dir / "filtered_latest.json").read_text(encoding="utf-8")
    prepared_before = (payload_dir / "prepared_backend_latest.json").read_text(encoding="utf-8")

    insightvm_test_server["state"].fail_assets_times = 10
    insightvm_test_server["state"].assets_failure_status = 401
    settings_fail = Settings(
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
        log_file=str(tmp_path / "logs" / "integration.log"),
        payload_dir=str(payload_dir),
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
    )
    collector_fail = InsightVMCollector(client=InsightVMClient(settings=settings_fail))
    run_service(settings=settings_fail, collector=collector_fail, once=True)

    assert (payload_dir / "filtered_latest.json").read_text(encoding="utf-8") == filtered_before
    assert (payload_dir / "prepared_backend_latest.json").read_text(encoding="utf-8") == prepared_before
    meta_data = json.loads((payload_dir / "run_latest.meta.json").read_text(encoding="utf-8"))
    assert meta_data["success"] is False
