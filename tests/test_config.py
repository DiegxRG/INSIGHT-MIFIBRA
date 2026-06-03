from __future__ import annotations

import pytest

from insightvm_pull.config import load_settings


def test_load_settings_defaults(monkeypatch):
    monkeypatch.setenv("INSIGHTVM_BASE_URL", "https://example/api/3")
    monkeypatch.setenv("INSIGHTVM_USER", "u")
    monkeypatch.setenv("INSIGHTVM_PASSWORD", "p")
    s = load_settings(overrides={})
    assert s.interval_seconds == 3600
    assert s.max_retries == 3
    assert s.severities == ("critical", "high")
    assert s.persist_raw_api_debug is False


def test_invalid_severity(monkeypatch):
    monkeypatch.setenv("INSIGHTVM_BASE_URL", "https://example/api/3")
    monkeypatch.setenv("INSIGHTVM_USER", "u")
    monkeypatch.setenv("INSIGHTVM_PASSWORD", "p")
    with pytest.raises(ValueError):
        load_settings(env_file=".env.missing", overrides={"severities": "critical,bad"})


def test_persist_raw_api_debug_setting(monkeypatch):
    monkeypatch.setenv("INSIGHTVM_BASE_URL", "https://example/api/3")
    monkeypatch.setenv("INSIGHTVM_USER", "u")
    monkeypatch.setenv("INSIGHTVM_PASSWORD", "p")
    monkeypatch.setenv("PERSIST_RAW_API_DEBUG", "true")

    s = load_settings(overrides={})

    assert s.persist_raw_api_debug is True
