from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from insightvm_pull.backend_client import BackendAlarmClient, build_snapshot_id
from insightvm_pull.client import InsightVMRequestError
from insightvm_pull.collector import InsightVMCollector, filter_payload_by_severity
from insightvm_pull.config import Settings
from insightvm_pull.storage import persist_cycle_payloads

log = logging.getLogger("insightvm_pull.scheduler")


def run_service(settings: Settings, collector: InsightVMCollector, once: bool = False) -> None:
    cycle = 0
    backend_client = BackendAlarmClient(settings=settings)
    while True:
        cycle += 1
        started = time.monotonic()
        cycle_time = datetime.now(timezone.utc).isoformat()
        log.info("cycle=%s started_at=%s", cycle, cycle_time)

        success = False
        last_error: str | None = None
        raw_payload: dict[str, Any] = {}
        filtered_payload: dict[str, Any] = {}
        prepared_backend_payload: dict[str, Any] = {}
        snapshot_id: str | None = None

        for attempt in range(1, settings.max_retries + 1):
            try:
                raw_payload = collector.collect(page_size=settings.page_size, allowed_severities=settings.severities)
                filtered_payload = filter_payload_by_severity(raw_payload, settings.severities)
                snapshot_id = build_snapshot_id()
                prepared_backend_payload = backend_client.prepare_filtered_findings(filtered_payload, snapshot_id=snapshot_id)
                success = True
                log.info("cycle=%s attempt=%s status=success", cycle, attempt)
                break
            except Exception as exc:
                last_error = str(exc)
                log.exception("cycle=%s attempt=%s status=error error=%s", cycle, attempt, exc)
                if not _should_retry_cycle_error(exc):
                    log.error("cycle=%s attempt=%s retry=false reason=non_retryable_error", cycle, attempt)
                    break
                if attempt < settings.max_retries:
                    sleep_seconds = settings.retry_backoff_seconds * (2 ** (attempt - 1))
                    log.warning("cycle=%s retrying_in=%.2fs", cycle, sleep_seconds)
                    time.sleep(sleep_seconds)

        elapsed = round(time.monotonic() - started, 3)
        backend_result: dict[str, Any] = {
            "enabled": settings.backend_enabled,
            "prepared_alarms": prepared_backend_payload.get("prepared_alarms_count", 0),
            "validation_errors": prepared_backend_payload.get("validation_errors", 0),
        }
        if success and settings.backend_enabled:
            backend_result = backend_client.send_prepared_alarms(prepared_backend_payload)
            log.info(
                "cycle=%s backend sent_ok=%s conflicts=%s validation_errors=%s backend_errors=%s",
                cycle,
                backend_result.get("sent_ok", 0),
                backend_result.get("conflicts", 0),
                backend_result.get("validation_errors", 0),
                backend_result.get("backend_errors", 0),
            )

        run_meta = {
            "cycle": cycle,
            "started_at": cycle_time,
            "success": success,
            "error": last_error,
            "total_assets": raw_payload.get("meta", {}).get("assets_count", 0),
            "total_findings": raw_payload.get("meta", {}).get("findings_count", 0),
            "filtered_findings": filtered_payload.get("meta", {}).get("findings_count", 0),
            "snapshot_id": snapshot_id,
            "allowed_severities": list(settings.severities),
            "duration_seconds": elapsed,
            "max_retries": settings.max_retries,
            "backend": backend_result,
        }
        paths = persist_cycle_payloads(
            settings.payload_dir,
            raw_payload if success else None,
            filtered_payload if success else None,
            prepared_backend_payload if success else None,
            run_meta,
            persist_payload_artifacts=settings.persist_payload_artifacts,
            persist_raw_api_debug=settings.persist_raw_api_debug,
        )
        if settings.persist_payload_artifacts:
            log.info(
                "cycle=%s persisted raw_api=%s filtered=%s prepared_backend=%s meta=%s",
                cycle,
                paths.get("raw_api"),
                paths.get("filtered"),
                paths.get("prepared_backend"),
                paths.get("meta"),
            )
        else:
            log.info("cycle=%s payload_persistence=disabled", cycle)

        if once:
            return

        log.info("cycle=%s sleeping interval_seconds=%s", cycle, settings.interval_seconds)
        time.sleep(settings.interval_seconds)


def _should_retry_cycle_error(exc: Exception) -> bool:
    return isinstance(exc, InsightVMRequestError) and exc.retryable
