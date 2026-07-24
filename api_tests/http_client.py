"""HTTP client with request/response logging."""

from __future__ import annotations

import json
import logging
from typing import Any, Mapping, MutableMapping, Optional
from urllib.parse import urljoin

import requests

from api_tests.config import ApiConfig

logger = logging.getLogger(__name__)


class ApiClient:
    """Thin wrapper around requests with structured logging."""

    def __init__(self, config: ApiConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(dict(config.default_headers))
        self._apply_auth(config.auth)

    def _apply_auth(self, auth: Mapping[str, str]) -> None:
        for header_name, header_value in auth.items():
            if header_value:
                self.session.headers[header_name] = header_value

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> requests.Response:
        url = self._build_url(path)
        merged_headers: MutableMapping[str, str] = {}
        if headers:
            merged_headers.update(headers)

        self._log_request(method, url, params, json_body, merged_headers)

        response = self.session.request(
            method=method.upper(),
            url=url,
            params=params,
            json=json_body,
            data=data,
            headers=merged_headers or None,
            timeout=timeout or self.config.timeout,
            verify=self.config.verify_ssl,
        )

        self._log_response(response)
        return response

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("DELETE", path, **kwargs)

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        base = self.config.base_url_normalized
        if not path.startswith("/"):
            path = f"/{path}"
        return urljoin(f"{base}/", path.lstrip("/"))

    def _log_request(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]],
        json_body: Optional[Any],
        headers: Mapping[str, str],
    ) -> None:
        payload_repr = ""
        if json_body is not None:
            payload_repr = json.dumps(json_body, default=str)
        logger.info(
            "HTTP REQUEST | %s %s | params=%s | headers=%s | json=%s",
            method.upper(),
            url,
            dict(params or {}),
            dict(headers),
            payload_repr,
        )

    def _log_response(self, response: requests.Response) -> None:
        body_preview = response.text[:1000]
        logger.info(
            "HTTP RESPONSE | %s %s | status=%s | headers=%s | body=%s",
            response.request.method,
            response.url,
            response.status_code,
            dict(response.headers),
            body_preview,
        )
