from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def load_json_file(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else None


def list_snapshot_files(payload_dir: Path) -> list[Path]:
    candidates = sorted(payload_dir.glob("prepared_backend*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    latest = payload_dir / "prepared_backend_latest.json"
    if latest.exists() and latest not in candidates:
        candidates.insert(0, latest)
    return candidates


def build_snapshot_catalog(payload_dir: Path) -> list[dict[str, Any]]:
    catalog: list[dict[str, Any]] = []
    for path in list_snapshot_files(payload_dir):
        payload = load_json_file(path) or {}
        alarms = payload.get("alarms", []) if isinstance(payload.get("alarms"), list) else []
        catalog.append(
            {
                "key": path.name,
                "snapshot_id": payload.get("snapshot_id"),
                "alarms_count": len(alarms),
                "modified_at": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "is_latest": path.name == "prepared_backend_latest.json",
            }
        )
    return catalog


def load_selected_snapshot(payload_dir: Path, snapshot_key: str | None = None) -> tuple[dict[str, Any], str | None]:
    candidates = list_snapshot_files(payload_dir)
    if not candidates:
        return {}, None

    selected_path: Path | None = None
    if snapshot_key:
        for candidate in candidates:
            if candidate.name == snapshot_key:
                selected_path = candidate
                break

    if selected_path is None:
        selected_path = candidates[0]

    return load_json_file(selected_path) or {}, selected_path.name


def build_alarmas_rows(snapshot_payload: dict[str, Any]) -> list[dict[str, Any]]:
    snapshot_id = str(snapshot_payload.get("snapshot_id") or "").strip()
    alarms = snapshot_payload.get("alarms", [])
    if not isinstance(alarms, list):
        return []

    rows: list[dict[str, Any]] = []
    for alarm in alarms:
        if not isinstance(alarm, dict):
            continue
        rows.append(
            {
                "finding_id": alarm.get("finding_id"),
                "snapshot_id": snapshot_id,
                "servidor": alarm.get("servidor"),
                "ip": alarm.get("ip"),
                "TipoAlarma": alarm.get("TipoAlarma"),
                "Local": alarm.get("Local"),
                "fechaalarma": alarm.get("fechaalarma"),
            }
        )
    return rows


def build_detalle_rows(snapshot_payload: dict[str, Any]) -> list[dict[str, Any]]:
    snapshot_id = str(snapshot_payload.get("snapshot_id") or "").strip()
    alarms = snapshot_payload.get("alarms", [])
    if not isinstance(alarms, list):
        return []

    rows: list[dict[str, Any]] = []
    for alarm in alarms:
        if not isinstance(alarm, dict):
            continue
        rows.append(
            {
                "finding_id": alarm.get("finding_id"),
                "snapshot_id": snapshot_id,
                "asset_id": alarm.get("asset_id"),
                "vulnerability_id": alarm.get("vulnerability_id"),
                "vulnerability_title": alarm.get("vulnerability_title"),
                "severity": alarm.get("severity"),
                "cvss_score": alarm.get("cvss_score"),
                "cves": alarm.get("cves"),
                "source": alarm.get("source"),
            }
        )
    return rows


def build_table_views(snapshot_payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {
        "alarmas": build_alarmas_rows(snapshot_payload),
        "detalle_alerta_insightvm": build_detalle_rows(snapshot_payload),
    }


def load_view_state(payload_dir: Path, snapshot_key: str | None = None) -> dict[str, Any]:
    prepared, selected_snapshot = load_selected_snapshot(payload_dir, snapshot_key=snapshot_key)
    filtered = load_json_file(payload_dir / "filtered_latest.json") or {}
    meta = load_json_file(payload_dir / "run_latest.meta.json") or {}
    snapshot_catalog = build_snapshot_catalog(payload_dir)

    tables = build_table_views(prepared) if prepared else {"alarmas": [], "detalle_alerta_insightvm": []}
    alarms = prepared.get("alarms", []) if isinstance(prepared.get("alarms"), list) else []

    return {
        "selected_snapshot": selected_snapshot,
        "available_snapshots": snapshot_catalog,
        "snapshot": prepared,
        "tables": tables,
        "meta": meta,
        "filtered": filtered,
        "summary": {
            "selected_snapshot": selected_snapshot,
            "snapshot_id": prepared.get("snapshot_id"),
            "alarms_count": len(alarms),
            "alarmas_rows": len(tables["alarmas"]),
            "detalle_rows": len(tables["detalle_alerta_insightvm"]),
            "findings_count": filtered.get("meta", {}).get("findings_count", 0) if isinstance(filtered.get("meta"), dict) else 0,
            "last_success": meta.get("success"),
            "started_at": meta.get("started_at"),
        },
    }
