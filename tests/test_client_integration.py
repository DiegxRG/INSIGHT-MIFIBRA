from __future__ import annotations

import pytest

from insightvm_pull.client import InsightVMClient
from insightvm_pull.config import Settings


def _settings(base_url: str) -> Settings:
    return Settings(
        insightvm_base_url=base_url,
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
        log_file="logs/test.log",
        payload_dir="payloads",
        persist_payload_artifacts=True,
        backend_enabled=False,
        backend_url="http://127.0.0.1:9999/txdxsecure/guarda_alarma.php",
        backend_local="Txdxsecure",
        backend_alarm_type="1 - Alarma de seguridad",
        backend_timeout=5,
        backend_verify_ssl=False,
    )


def test_client_pagination_real_server(insightvm_test_server):
    client = InsightVMClient(settings=_settings(insightvm_test_server["base_url"]))
    items = list(client.get_paged("/assets", size=1))
    assert len(items) == 1
    assert items[0]["id"] == "a1"


def test_client_http_error_real_server(insightvm_test_server):
    server = insightvm_test_server
    server["state"].fail_assets_times = 10
    client = InsightVMClient(settings=_settings(server["base_url"]))
    with pytest.raises(RuntimeError):
        list(client.get_paged("/assets", size=1))
