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
    raw_payload: dict[str, Any],
    filtered_payload: dict[str, Any],
    prepared_backend_payload: dict[str, Any],
    run_meta: dict[str, Any],
) -> dict[str, str]:
    base = Path(payload_dir)
    stamp = utc_stamp()
    raw_api_path = base / f"raw_api_{stamp}.json"
    filtered_path = base / f"filtered_{stamp}.json"
    prepared_backend_path = base / f"prepared_backend_{stamp}.json"
    meta_path = base / f"run_{stamp}.meta.json"

    raw_api_payload = raw_payload.get("raw_api", {})

    write_json(raw_api_path, raw_api_payload if isinstance(raw_api_payload, dict) else {})
    write_json(filtered_path, filtered_payload)
    write_json(prepared_backend_path, prepared_backend_payload if isinstance(prepared_backend_payload, dict) else {})
    write_json(meta_path, run_meta)
    return {
        "raw_api": str(raw_api_path),
        "filtered": str(filtered_path),
        "prepared_backend": str(prepared_backend_path),
        "meta": str(meta_path),
    }
