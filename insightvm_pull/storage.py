from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def persist_cycle_payloads(
    payload_dir: str,
    raw_payload: dict[str, Any] | None,
    filtered_payload: dict[str, Any] | None,
    prepared_backend_payload: dict[str, Any] | None,
    run_meta: dict[str, Any],
    persist_payload_artifacts: bool = True,
    persist_raw_api_debug: bool = False,
) -> dict[str, str]:
    if not persist_payload_artifacts:
        return {}

    base = Path(payload_dir)
    base.mkdir(parents=True, exist_ok=True)
    stamp = utc_stamp()
    raw_api_path = base / f"raw_api_{stamp}.json"
    filtered_path = base / "filtered_latest.json"
    prepared_backend_path = base / "prepared_backend_latest.json"
    meta_path = base / "run_latest.meta.json"

    paths = {"meta": str(meta_path)}

    raw_api_payload = (raw_payload or {}).get("raw_api", {})
    if persist_raw_api_debug and isinstance(raw_api_payload, dict) and raw_api_payload:
        write_json(raw_api_path, raw_api_payload)
        paths["raw_api"] = str(raw_api_path)

    if isinstance(filtered_payload, dict):
        write_json(filtered_path, filtered_payload)
        paths["filtered"] = str(filtered_path)

    if isinstance(prepared_backend_payload, dict):
        request_payload = prepared_backend_payload.get("request_payload")
        if isinstance(request_payload, dict):
            write_json(prepared_backend_path, request_payload)
        else:
            write_json(prepared_backend_path, prepared_backend_payload)
        paths["prepared_backend"] = str(prepared_backend_path)

    write_json(meta_path, run_meta)
    return paths
