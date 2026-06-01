from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime
from typing import Any

from insightvm_pull.client import InsightVMClient
from insightvm_pull.models import normalize_severity

log = logging.getLogger("insightvm_pull.collector")

MAX_COLLECTOR_WORKERS = 8


class InsightVMCollector:
    def __init__(self, client: InsightVMClient) -> None:
        self.client = client

    def collect(self, page_size: int, allowed_severities: tuple[str, ...] | None = None) -> dict[str, Any]:
        assets: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        assets_pages: list[dict[str, Any]] = []
        asset_vulns_raw: dict[str, dict[str, Any]] = {}
        vuln_defs_raw: dict[str, dict[str, Any]] = {}
        allowed = set(allowed_severities or ())
        vulnerability_refs_count = 0
        filtered_before_detail_count = 0
        filtered_after_detail_count = 0
        filtered_inactive_count = 0
        vulnerability_detail_requests = 0

        assets, assets_pages = self._fetch_assets_with_raw_pages(page_size=page_size)
        asset_vuln_results = self._fetch_asset_vulnerabilities_for_assets(assets=assets, page_size=page_size)
        candidate_findings: list[dict[str, Any]] = []
        needed_vulnerability_ids: list[str] = []
        seen_needed_vulnerability_ids: set[str] = set()

        for asset in assets:
            asset_id = asset.get("id")
            if not asset_id:
                continue
            result = asset_vuln_results.get(str(asset_id))
            if not isinstance(result, dict):
                continue
            asset_vulns_raw[str(asset_id)] = {"pages": result.get("pages", [])}
            vuln_refs = result.get("refs", [])

            for ref in vuln_refs:
                if not isinstance(ref, dict):
                    continue
                vuln_id = ref.get("id")
                if not vuln_id:
                    continue
                vuln_id = str(vuln_id)
                vulnerability_refs_count += 1

                ref_status = _extract_status(ref)
                if ref_status and ref_status != "vulnerable":
                    filtered_inactive_count += 1
                    continue
                if not ref_status:
                    ref_status = "vulnerable"

                ref_severity = _extract_severity(ref)
                if allowed and ref_severity != "unknown" and ref_severity not in allowed:
                    filtered_before_detail_count += 1
                    continue

                candidate_findings.append(
                    {
                        "asset_id": asset_id,
                        "asset_ip": _extract_asset_ip(asset),
                        "asset_hostname": asset.get("hostName") or asset.get("hostname") or asset.get("name"),
                        "vulnerability_id": vuln_id,
                        "insightvm_status": ref_status,
                        "raw_ref": ref,
                    }
                )
                if vuln_id not in seen_needed_vulnerability_ids:
                    seen_needed_vulnerability_ids.add(vuln_id)
                    needed_vulnerability_ids.append(vuln_id)

        if needed_vulnerability_ids:
            vuln_defs_raw = self._fetch_vulnerability_definitions(needed_vulnerability_ids)
            vulnerability_detail_requests = len(needed_vulnerability_ids)

        for candidate in candidate_findings:
            vuln_id = candidate["vulnerability_id"]
            vdef = vuln_defs_raw.get(vuln_id)
            if not isinstance(vdef, dict):
                continue
            ref = candidate["raw_ref"]

            sev = _extract_severity(vdef, ref)
            if allowed and sev not in allowed:
                filtered_after_detail_count += 1
                continue

            title = _extract_title(vdef, ref)
            cvss_score = _extract_cvss(vdef, ref)
            cves = _extract_cves(vdef, ref)
            findings.append(
                {
                    "asset_id": candidate["asset_id"],
                    "asset_ip": candidate["asset_ip"],
                    "asset_hostname": candidate["asset_hostname"],
                    "vulnerability_id": vuln_id,
                    "title": title,
                    "vulnerability_title": title,
                    "severity": sev,
                    "cvss": cvss_score,
                    "cvss_score": cvss_score,
                    "risk_score": vdef.get("riskScore"),
                    "cves": cves,
                    "source": "insightvm",
                    "insightvm_status": candidate["insightvm_status"],
                    "fechaalarma": _extract_alert_time(ref, vdef),
                    "raw": vdef,
                    "raw_ref": ref,
                }
            )

        return {
            "assets": assets,
            "findings": findings,
            "meta": {
                "assets_count": len(assets),
                "findings_count": len(findings),
                "allowed_severities": list(allowed_severities or ()),
                "vulnerability_refs_count": vulnerability_refs_count,
                "vulnerability_detail_requests": vulnerability_detail_requests,
                "filtered_before_detail_count": filtered_before_detail_count,
                "filtered_after_detail_count": filtered_after_detail_count,
                "filtered_inactive_count": filtered_inactive_count,
            },
            "raw_api": {
                "assets_pages": assets_pages,
                "asset_vulnerabilities": asset_vulns_raw,
                "vulnerability_definitions": vuln_defs_raw,
            },
        }

    def _fetch_assets_with_raw_pages(self, page_size: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        assets: list[dict[str, Any]] = []
        pages: list[dict[str, Any]] = []
        page = 0
        while True:
            response = self.client.get("/assets", params={"page": page, "size": page_size})
            if not isinstance(response, dict):
                raise RuntimeError("Unexpected non-dict response for /assets")
            pages.append(response)
            resources = response.get("resources")
            if not isinstance(resources, list):
                raise RuntimeError("Missing 'resources' list in /assets response")
            for item in resources:
                if isinstance(item, dict):
                    assets.append(item)
            if len(resources) < page_size:
                break
            page += 1
        return assets, pages

    def _fetch_asset_vulnerabilities_with_raw_pages(
        self,
        asset_id: Any,
        page_size: int,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        vulnerabilities: list[dict[str, Any]] = []
        pages: list[dict[str, Any]] = []
        seen_page_signatures: set[tuple[str, ...]] = set()
        page = 0
        endpoint = f"/assets/{asset_id}/vulnerabilities"
        while True:
            response = self.client.get(endpoint, params={"page": page, "size": page_size})
            if not isinstance(response, dict):
                raise RuntimeError(f"Unexpected non-dict response for {endpoint}")
            resources = response.get("resources")
            if not isinstance(resources, list):
                raise RuntimeError(f"Missing 'resources' list in {endpoint} response")

            signature = tuple(_resource_signature(item) for item in resources if isinstance(item, dict))
            if page > 0 and signature in seen_page_signatures:
                log.warning("asset_id=%s repeated vulnerability page detected on %s; stopping pagination", asset_id, endpoint)
                break

            seen_page_signatures.add(signature)
            pages.append(response)
            for item in resources:
                if isinstance(item, dict):
                    vulnerabilities.append(item)
            if len(resources) < page_size:
                break
            page += 1
        return vulnerabilities, pages

    def _fetch_asset_vulnerabilities_for_assets(
        self,
        assets: list[dict[str, Any]],
        page_size: int,
    ) -> dict[str, dict[str, Any]]:
        asset_ids = [str(asset.get("id")) for asset in assets if asset.get("id")]
        if not asset_ids:
            return {}

        results: dict[str, dict[str, Any]] = {}
        worker_count = min(MAX_COLLECTOR_WORKERS, len(asset_ids))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(self._fetch_asset_vulnerabilities_worker, asset_id, page_size): asset_id for asset_id in asset_ids
            }
            for future in as_completed(futures):
                asset_id = futures[future]
                try:
                    refs, pages = future.result()
                except Exception as exc:
                    log.warning("asset_id=%s vulnerabilities fetch failed: %s", asset_id, exc)
                    continue
                results[asset_id] = {"refs": refs, "pages": pages}
        return results

    def _fetch_asset_vulnerabilities_worker(
        self,
        asset_id: str,
        page_size: int,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        worker_client = InsightVMClient(settings=self.client.settings)
        worker_collector = InsightVMCollector(client=worker_client)
        return worker_collector._fetch_asset_vulnerabilities_with_raw_pages(asset_id=asset_id, page_size=page_size)

    def _fetch_vulnerability_definitions(self, vulnerability_ids: list[str]) -> dict[str, dict[str, Any]]:
        worker_count = min(MAX_COLLECTOR_WORKERS, len(vulnerability_ids))
        if worker_count < 1:
            return {}

        vulnerability_definitions: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(self._fetch_vulnerability_definition_worker, vuln_id): vuln_id for vuln_id in vulnerability_ids
            }
            for future in as_completed(futures):
                vuln_id = futures[future]
                vulnerability_definitions[vuln_id] = future.result()
        return vulnerability_definitions

    def _fetch_vulnerability_definition_worker(self, vuln_id: str) -> dict[str, Any]:
        worker_client = InsightVMClient(settings=self.client.settings)
        return worker_client.get(f"/vulnerabilities/{vuln_id}")


def filter_payload_by_severity(payload: dict[str, Any], allowed_severities: tuple[str, ...]) -> dict[str, Any]:
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    filtered_findings = [f for f in findings if isinstance(f, dict) and f.get("severity") in allowed_severities]
    meta = payload.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}
    return {
        "assets": payload.get("assets", []),
        "findings": filtered_findings,
        "meta": {
            **meta,
            "assets_count": meta.get("assets_count", 0),
            "findings_count": len(filtered_findings),
            "allowed_severities": list(allowed_severities),
        },
    }


def _extract_asset_ip(asset: dict[str, Any]) -> str | None:
    if isinstance(asset.get("ip"), str):
        return asset["ip"]
    addresses = asset.get("addresses")
    if isinstance(addresses, list):
        for item in addresses:
            if isinstance(item, str):
                return item
            if isinstance(item, dict):
                candidate = item.get("ip") or item.get("address")
                if isinstance(candidate, str):
                    return candidate
    return None


def _extract_severity(*records: dict[str, Any]) -> str:
    for record in records:
        if not isinstance(record, dict):
            continue
        severity = normalize_severity(record.get("severity") or record.get("severityScore") or record.get("cvss_score"))
        if severity != "unknown":
            return severity
    return "unknown"


def _extract_title(*records: dict[str, Any]) -> str:
    for record in records:
        if not isinstance(record, dict):
            continue
        for key in ("title", "name"):
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return "Vulnerability"


def _extract_cvss(*records: dict[str, Any]) -> float | None:
    for record in records:
        if not isinstance(record, dict):
            continue
        value = record.get("cvss_score")
        if isinstance(value, (int, float)):
            return float(value)
        cvss = record.get("cvss")
        if isinstance(cvss, dict):
            for version in ("v3", "v2"):
                sub = cvss.get(version)
                if isinstance(sub, dict) and isinstance(sub.get("score"), (int, float)):
                    return float(sub["score"])
        if isinstance(record.get("severityScore"), (int, float)):
            return float(record["severityScore"])
    return None


def _extract_cves(*records: dict[str, Any]) -> list[str]:
    for record in records:
        if not isinstance(record, dict):
            continue
        raw_cves = record.get("cves")
        if isinstance(raw_cves, list):
            return [str(item).strip() for item in raw_cves if str(item).strip()]
        if isinstance(raw_cves, str) and raw_cves.strip():
            return [item.strip() for item in raw_cves.split(",") if item.strip()]
    return []


def _extract_alert_time(*records: dict[str, Any]) -> str:
    # Prefer dates tied to the asset occurrence, not vulnerability publication dates.
    for record in records:
        if not isinstance(record, dict):
            continue
        for key in (
            "lastFound",
            "lastSeen",
            "mostRecentInstance",
            "since",
            "date",
            "discovered",
            "firstDiscovered",
        ):
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().replace("T", " ")[:19]
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _extract_status(record: dict[str, Any]) -> str | None:
    value = record.get("status")
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value or None


def _resource_signature(item: dict[str, Any]) -> str:
    vuln_id = item.get("id")
    severity = item.get("severity")
    return f"{vuln_id}|{severity}"
