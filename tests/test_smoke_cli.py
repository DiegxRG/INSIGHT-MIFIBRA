from __future__ import annotations

import json
from pathlib import Path

from insightvm_pull import cli


def test_cli_once_smoke_real_server(monkeypatch, tmp_path: Path, insightvm_test_server):
    base_url = insightvm_test_server["base_url"]
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                f"INSIGHTVM_BASE_URL={base_url}",
                "INSIGHTVM_USER=u",
                "INSIGHTVM_PASSWORD=p",
                "PULL_INTERVAL_SECONDS=3600",
                "MAX_RETRIES=1",
                "ALERT_SEVERITIES=critical,high",
                "BACKEND_ENABLED=false",
                f"LOG_FILE={tmp_path / 'logs' / 'integration.log'}",
                f"PAYLOAD_DIR={tmp_path / 'payloads'}",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.argv", ["insightvm-pull", "--env-file", str(env_file), "--once"])
    cli.main()
    files = sorted((tmp_path / "payloads").glob("*.json"))
    assert len(files) == 4
    filtered = [p for p in files if p.name.startswith("filtered_")][0]
    prepared = [p for p in files if p.name.startswith("prepared_backend_")][0]
    filtered_data = json.loads(filtered.read_text(encoding="utf-8"))
    prepared_data = json.loads(prepared.read_text(encoding="utf-8"))
    assert filtered_data["meta"]["allowed_severities"] == ["critical", "high"]
    assert prepared_data["prepared_alarms_count"] == 1
