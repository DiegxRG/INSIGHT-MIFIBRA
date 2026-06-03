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
    filtered_file = [p for p in payload_files if p.name.startswith("filtered_")][0]
    prepared_file = [p for p in payload_files if p.name.startswith("prepared_backend_")][0]
    meta_file = [p for p in payload_files if p.name.startswith("run_")][0]

    filtered_data = json.loads(filtered_file.read_text(encoding="utf-8"))
    prepared_data = json.loads(prepared_file.read_text(encoding="utf-8"))
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))

    assert filtered_data["meta"]["findings_count"] == 1
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
    meta_file = [p for p in payload_files if p.name.startswith("run_")][0]
    meta_data = json.loads(meta_file.read_text(encoding="utf-8"))

    assert meta_data["success"] is False
    assert "HTTP 401" in meta_data["error"]
    assert server["state"].assets_calls == 1
