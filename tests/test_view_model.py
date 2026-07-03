from __future__ import annotations

from backend.view_model import build_table_views


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
