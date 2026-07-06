from __future__ import annotations

import json

from backend.view_model import build_table_views, load_view_state


def test_build_table_views_projects_snapshot_into_alarmas_and_detalle():
    snapshot_payload = {
        "snapshot_id": "2026-07-02T11:00:00Z",
        "alarms": [
            {
                "finding_id": "515_apache-httpd-cve-2024-42516",
                "servidor": "Cacti-Cajamarca",
                "ip": "10.208.172.5",
                "TipoAlarma": "Alarma de seguridad de InsightVM x TXDXSecure",
                "Local": "Mi Fibra",
                "fechaalarma": "2026-03-20 20:15:55",
                "asset_id": "515",
                "vulnerability_id": "apache-httpd-cve-2024-42516",
                "vulnerability_title": "Apache HTTPD: CVE-2024-42516: Improper Input Validation",
                "severity": "Critical",
                "cvss_score": 7.5,
                "cves": ["CVE-2024-42516"],
                "source": "Rapid7-InsightVM",
            }
        ],
    }

    tables = build_table_views(snapshot_payload)

    assert tables["alarmas"] == [
        {
            "finding_id": "515_apache-httpd-cve-2024-42516",
            "snapshot_id": "2026-07-02T11:00:00Z",
            "servidor": "Cacti-Cajamarca",
            "ip": "10.208.172.5",
            "TipoAlarma": "Alarma de seguridad de InsightVM x TXDXSecure",
            "Local": "Mi Fibra",
            "fechaalarma": "2026-03-20 20:15:55",
        }
    ]
    assert tables["detalle_alerta_insightvm"] == [
        {
            "finding_id": "515_apache-httpd-cve-2024-42516",
            "snapshot_id": "2026-07-02T11:00:00Z",
            "asset_id": "515",
            "vulnerability_id": "apache-httpd-cve-2024-42516",
            "vulnerability_title": "Apache HTTPD: CVE-2024-42516: Improper Input Validation",
            "severity": "Critical",
            "cvss_score": 7.5,
            "cves": ["CVE-2024-42516"],
            "source": "Rapid7-InsightVM",
        }
    ]


def test_load_view_state_can_select_snapshot_file(tmp_path):
    latest = {
        "snapshot_id": "2026-07-03T11:00:00Z",
        "alarms": [{"finding_id": "f1", "servidor": "srv1", "ip": "10.0.0.1", "TipoAlarma": "A", "Local": "Mi Fibra", "fechaalarma": "2026-03-20 20:15:55", "asset_id": "1", "vulnerability_id": "v1", "vulnerability_title": "T1", "severity": "Critical", "cvss_score": 9.1, "cves": ["CVE-1"], "source": "Rapid7-InsightVM"}],
    }
    older = {
        "snapshot_id": "2026-07-02T11:00:00Z",
        "alarms": [{"finding_id": "f2", "servidor": "srv2", "ip": "10.0.0.2", "TipoAlarma": "A", "Local": "Mi Fibra", "fechaalarma": "2026-03-20 20:15:55", "asset_id": "2", "vulnerability_id": "v2", "vulnerability_title": "T2", "severity": "High", "cvss_score": 7.5, "cves": ["CVE-2"], "source": "Rapid7-InsightVM"}],
    }
    (tmp_path / "prepared_backend_latest.json").write_text(json.dumps(latest), encoding="utf-8")
    (tmp_path / "prepared_backend_older.json").write_text(json.dumps(older), encoding="utf-8")
    (tmp_path / "filtered_latest.json").write_text(json.dumps({"meta": {"findings_count": 1}}), encoding="utf-8")
    (tmp_path / "run_latest.meta.json").write_text(json.dumps({"success": True, "started_at": "2026-07-03T11:00:00Z"}), encoding="utf-8")

    state = load_view_state(tmp_path, snapshot_key="prepared_backend_older.json")

    assert state["selected_snapshot"] == "prepared_backend_older.json"
    assert state["snapshot"]["snapshot_id"] == "2026-07-02T11:00:00Z"
    assert len(state["available_snapshots"]) == 2
    assert state["tables"]["alarmas"][0]["finding_id"] == "f2"
