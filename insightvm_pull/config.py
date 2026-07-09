from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from insightvm_pull.models import VALID_SEVERITIES


def _truthy(v: str | None, default: bool) -> bool:
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


def _parse_severities(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ("critical", "high")
    parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
    invalid = [p for p in parts if p not in VALID_SEVERITIES]
    if invalid:
        raise ValueError(f"Invalid severities: {', '.join(invalid)}")
    if not parts:
        raise ValueError("At least one severity must be configured.")
    return tuple(parts)


@dataclass(frozen=True)
class Settings:
    insightvm_base_url: str
    insightvm_user: str
    insightvm_password: str
    insightvm_timeout: int
    insightvm_verify_ssl: bool
    page_size: int
    interval_seconds: int
    max_retries: int
    retry_backoff_seconds: float
    severities: tuple[str, ...]
    log_level: str
    log_file: str
    payload_dir: str
    persist_payload_artifacts: bool
    backend_enabled: bool
    backend_url: str
    backend_local: str
    backend_alarm_type: str
    backend_timeout: int
    backend_verify_ssl: bool
    persist_raw_api_debug: bool = False
    backend_dedupe_last_snapshot: bool = True
    backend_notify_no_changes: bool = False


def load_settings(env_file: str = ".env", overrides: dict | None = None) -> Settings:
    load_dotenv(dotenv_path=Path(env_file), override=True)
    ov = overrides or {}

    base_url = (ov.get("insightvm_base_url") or os.getenv("INSIGHTVM_BASE_URL") or "").strip()
    user = (ov.get("insightvm_user") or os.getenv("INSIGHTVM_USER") or "").strip()
    password = (ov.get("insightvm_password") or os.getenv("INSIGHTVM_PASSWORD") or "").strip()
    timeout = int(ov.get("insightvm_timeout") or os.getenv("INSIGHTVM_TIMEOUT", "30"))
    verify_ssl = _truthy(str(ov.get("insightvm_verify_ssl")) if ov.get("insightvm_verify_ssl") is not None else os.getenv("INSIGHTVM_VERIFY_SSL"), True)
    page_size = int(ov.get("page_size") or os.getenv("PAGE_SIZE", "200"))
    interval = int(ov.get("interval_seconds") or os.getenv("PULL_INTERVAL_SECONDS", "3600"))
    max_retries = int(ov.get("max_retries") or os.getenv("MAX_RETRIES", "3"))
    backoff = float(ov.get("retry_backoff_seconds") or os.getenv("RETRY_BACKOFF_SECONDS", "1.0"))
    severities = _parse_severities(ov.get("severities") or os.getenv("ALERT_SEVERITIES", "critical,high"))
    log_level = str(ov.get("log_level") or os.getenv("LOG_LEVEL", "INFO")).upper()
    log_file = str(ov.get("log_file") or os.getenv("LOG_FILE", "logs/integration.log"))
    payload_dir = str(ov.get("payload_dir") or os.getenv("PAYLOAD_DIR", "payloads"))
    persist_payload_artifacts = _truthy(
        str(ov.get("persist_payload_artifacts"))
        if ov.get("persist_payload_artifacts") is not None
        else os.getenv("PERSIST_PAYLOAD_ARTIFACTS"),
        True,
    )
    backend_enabled = _truthy(str(ov.get("backend_enabled")) if ov.get("backend_enabled") is not None else os.getenv("BACKEND_ENABLED"), False)
    backend_url = str(ov.get("backend_url") or os.getenv("BACKEND_URL", "https://10.208.232.208/txdxsecure/guarda_alarma.php")).strip()
    backend_local = str(ov.get("backend_local") or os.getenv("BACKEND_LOCAL", "Txdxsecure")).strip()
    backend_alarm_type = str(ov.get("backend_alarm_type") or os.getenv("BACKEND_ALARM_TYPE", "1 - Alarma de seguridad")).strip()
    backend_timeout = int(ov.get("backend_timeout") or os.getenv("BACKEND_TIMEOUT", "30"))
    backend_verify_ssl = _truthy(str(ov.get("backend_verify_ssl")) if ov.get("backend_verify_ssl") is not None else os.getenv("BACKEND_VERIFY_SSL"), False)
    persist_raw_api_debug = _truthy(
        str(ov.get("persist_raw_api_debug")) if ov.get("persist_raw_api_debug") is not None else os.getenv("PERSIST_RAW_API_DEBUG"),
        False,
    )
    backend_dedupe_last_snapshot = _truthy(
        str(ov.get("backend_dedupe_last_snapshot"))
        if ov.get("backend_dedupe_last_snapshot") is not None
        else os.getenv("BACKEND_DEDUPE_LAST_SNAPSHOT"),
        True,
    )
    backend_notify_no_changes = _truthy(
        str(ov.get("backend_notify_no_changes"))
        if ov.get("backend_notify_no_changes") is not None
        else os.getenv("BACKEND_NOTIFY_NO_CHANGES"),
        False,
    )

    if not base_url:
        raise ValueError("INSIGHTVM_BASE_URL is required.")
    if not user or not password:
        raise ValueError("INSIGHTVM_USER and INSIGHTVM_PASSWORD are required.")
    if interval <= 0:
        raise ValueError("PULL_INTERVAL_SECONDS must be > 0.")
    if max_retries < 1:
        raise ValueError("MAX_RETRIES must be >= 1.")
    if page_size < 1:
        raise ValueError("PAGE_SIZE must be >= 1.")
    if backend_enabled and not backend_url:
        raise ValueError("BACKEND_URL is required when BACKEND_ENABLED=true.")

    return Settings(
        insightvm_base_url=base_url,
        insightvm_user=user,
        insightvm_password=password,
        insightvm_timeout=timeout,
        insightvm_verify_ssl=verify_ssl,
        page_size=page_size,
        interval_seconds=interval,
        max_retries=max_retries,
        retry_backoff_seconds=backoff,
        severities=severities,
        log_level=log_level,
        log_file=log_file,
        payload_dir=payload_dir,
        persist_payload_artifacts=persist_payload_artifacts,
        backend_enabled=backend_enabled,
        backend_url=backend_url,
        backend_local=backend_local,
        backend_alarm_type=backend_alarm_type,
        backend_timeout=backend_timeout,
        backend_verify_ssl=backend_verify_ssl,
        persist_raw_api_debug=persist_raw_api_debug,
        backend_dedupe_last_snapshot=backend_dedupe_last_snapshot,
        backend_notify_no_changes=backend_notify_no_changes,
    )
