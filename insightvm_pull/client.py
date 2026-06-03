from __future__ import annotations

import logging
from typing import Any, Iterator

import requests

from insightvm_pull.config import Settings

log = logging.getLogger("insightvm_pull.client")


class InsightVMRequestError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool, status_code: int | None = None) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code


def is_retryable_status_code(status_code: int) -> bool:
    return status_code in {429, 500, 502, 503, 504}


class InsightVMClient:
    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        self.settings = settings
        self.session = session or requests.Session()

    def get(self, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.settings.insightvm_base_url.rstrip("/") + "/" + endpoint.lstrip("/")
        log.debug("GET %s params=%s", endpoint, params)
        try:
            response = self.session.get(
                url,
                auth=(self.settings.insightvm_user, self.settings.insightvm_password),
                params=params,
                timeout=self.settings.insightvm_timeout,
                verify=self.settings.insightvm_verify_ssl,
            )
        except requests.Timeout as exc:
            raise InsightVMRequestError(f"InsightVM timeout on {endpoint}: {exc}", retryable=True) from exc
        except requests.ConnectionError as exc:
            raise InsightVMRequestError(f"InsightVM connection error on {endpoint}: {exc}", retryable=True) from exc
        except requests.RequestException as exc:
            raise InsightVMRequestError(f"InsightVM request error on {endpoint}: {exc}", retryable=False) from exc

        if response.status_code >= 400:
            raise InsightVMRequestError(
                f"InsightVM HTTP {response.status_code} on {endpoint}: {response.text[:300]}",
                retryable=is_retryable_status_code(response.status_code),
                status_code=response.status_code,
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise InsightVMRequestError(f"Non-JSON response from {endpoint}", retryable=False) from exc
        if not isinstance(data, dict):
            raise InsightVMRequestError(
                f"Unexpected response type from {endpoint}: {type(data)!r}",
                retryable=False,
            )
        return data

    def get_paged(
        self,
        endpoint: str,
        size: int,
        params: dict[str, Any] | None = None,
        items_key: str = "resources",
    ) -> Iterator[dict[str, Any]]:
        page = 0
        while True:
            query = dict(params or {})
            query.update({"page": page, "size": size})
            data = self.get(endpoint, params=query)
            items = data.get(items_key)
            if not isinstance(items, list):
                raise RuntimeError(f"Missing list key '{items_key}' in paged response for {endpoint}.")

            log.info("endpoint=%s page=%s items=%s", endpoint, page, len(items))
            for item in items:
                if isinstance(item, dict):
                    yield item

            if len(items) < size:
                break
            page += 1

