"""Sync and async API clients for the deepidv chain layer public surface.

The public registry endpoints are read-only and accept anonymous traffic from
the proof.deepidv.com origin. Tenant-issued API keys (``api_key=...``) unlock
issuer-scoped queries and higher rate limits but are not required for the
basic surface.

Both clients close their underlying httpx instances when used as a context
manager. Pass ``http_client`` to inject a pre-configured httpx client (for
proxies, custom timeouts, mTLS, etc.).
"""

import asyncio
import json
import time
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional, Type, Union
from urllib.parse import urljoin

import httpx
from pydantic import TypeAdapter

from deepidv_chain._internal.http import (
    build_default_headers,
    iter_sse_blocks,
    parse_sse_block,
    raise_for_status,
)
from deepidv_chain.types import (
    AttestationDetail,
    ConsistencyProof,
    IssuerProfile,
    LogView,
    RegistryFilters,
    RegistryPage,
    SegmentProfile,
    StreamEvent,
    Sth,
)

DEFAULT_BASE_URL = "https://staging-api.deepidv.com"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_RECONNECT_INITIAL_SECONDS = 1.0
DEFAULT_RECONNECT_MAX_SECONDS = 30.0


def _filters_to_params(filters: Optional[Union[RegistryFilters, Dict[str, Any]]]) -> Dict[str, Any]:
    if filters is None:
        return {}
    if isinstance(filters, RegistryFilters):
        raw = filters.model_dump(exclude_none=True)
    else:
        raw = {k: v for k, v in filters.items() if v is not None}
    out: Dict[str, Any] = {}
    for k, v in raw.items():
        if isinstance(v, bool):
            out[k] = "true" if v else "false"
        else:
            out[k] = v
    return out


def _resolve_url(base_url: str, path: str) -> str:
    if not base_url.endswith("/"):
        base_url = base_url + "/"
    if path.startswith("/"):
        path = path[1:]
    return urljoin(base_url, path)


def _parse_model(model_cls: Type[Any], payload: Any) -> Any:
    return TypeAdapter(model_cls).validate_python(payload)


class _BaseClient:
    """Shared configuration. Concrete clients use it via composition."""

    def __init__(
        self,
        api_url: str = DEFAULT_BASE_URL,
        *,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: Optional[str] = None,
    ) -> None:
        self.api_url = api_url.rstrip("/") + "/"
        self.api_key = api_key
        self.timeout = timeout
        self.headers = build_default_headers(api_key, user_agent)


class Client(_BaseClient):
    """Synchronous client for the deepidv chain layer public API.

    Example::

        from deepidv_chain import Client

        with Client("https://staging-api.deepidv.com") as chain:
            page = chain.list_registry({"record_type": "IDV"})
            for summary in page.items:
                print(summary.attestation_id)
    """

    def __init__(
        self,
        api_url: str = DEFAULT_BASE_URL,
        *,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: Optional[str] = None,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        super().__init__(api_url, api_key=api_key, timeout=timeout, user_agent=user_agent)
        self._http: httpx.Client
        self._owns_http = http_client is None
        if http_client is not None:
            self._http = http_client
        else:
            self._http = httpx.Client(timeout=timeout, headers=self.headers)

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        accept: str = "application/json",
    ) -> httpx.Response:
        url = _resolve_url(self.api_url, path)
        headers = dict(self.headers)
        headers["accept"] = accept
        response = self._http.request(method, url, params=params, headers=headers)
        raise_for_status(response)
        return response

    def get_attestation(self, attestation_id: str) -> AttestationDetail:
        response = self._request("GET", f"/v1/attestations/{attestation_id}")
        return _parse_model(AttestationDetail, response.json())

    def list_registry(
        self,
        filters: Optional[Union[RegistryFilters, Dict[str, Any]]] = None,
        cursor: Optional[str] = None,
    ) -> RegistryPage:
        params = _filters_to_params(filters)
        if cursor is not None:
            params["cursor"] = cursor
        response = self._request("GET", "/v1/registry", params=params)
        return _parse_model(RegistryPage, response.json())

    def get_issuer(self, issuer_id: str) -> IssuerProfile:
        response = self._request("GET", f"/v1/issuers/{issuer_id}")
        return _parse_model(IssuerProfile, response.json())

    def get_segment(self, segment_id: str) -> SegmentProfile:
        response = self._request("GET", f"/v1/segments/{segment_id}")
        return _parse_model(SegmentProfile, response.json())

    def list_sths(self, segment_id: str, *, limit: Optional[int] = None) -> List[Sth]:
        params = {"limit": limit} if limit is not None else None
        response = self._request("GET", f"/v1/segments/{segment_id}/sths", params=params)
        payload = response.json()
        items = payload.get("items") if isinstance(payload, dict) else payload
        return _parse_model(List[Sth], items)

    def get_consistency_proof(
        self,
        from_size: int,
        to_size: int,
        segment_id: str,
    ) -> ConsistencyProof:
        params = {"from_size": from_size, "to_size": to_size, "segment_id": segment_id}
        response = self._request("GET", "/v1/log/consistency", params=params)
        return _parse_model(ConsistencyProof, response.json())

    def get_log(self) -> LogView:
        response = self._request("GET", "/v1/log")
        return _parse_model(LogView, response.json())

    def download_bundle(self, attestation_id: str) -> bytes:
        response = self._request(
            "GET",
            f"/v1/attestations/{attestation_id}/bundle",
            accept="application/octet-stream",
        )
        return response.content

    def stream_attestations(
        self,
        *,
        last_event_id: Optional[str] = None,
        max_reconnect_attempts: Optional[int] = None,
    ) -> Iterator[StreamEvent]:
        """Iterate SSE events from /v1/stream/attestations.

        On a transient disconnect the iterator reconnects with exponential
        backoff, replaying ``last_event_id`` so the server can resume. Pass
        ``max_reconnect_attempts=0`` to disable reconnects.
        """
        url = _resolve_url(self.api_url, "/v1/stream/attestations")
        backoff = DEFAULT_RECONNECT_INITIAL_SECONDS
        attempts = 0
        current_id = last_event_id
        while True:
            headers = dict(self.headers)
            headers["accept"] = "text/event-stream"
            if current_id:
                headers["last-event-id"] = current_id
            try:
                with self._http.stream("GET", url, headers=headers, timeout=None) as resp:
                    raise_for_status(resp)
                    backoff = DEFAULT_RECONNECT_INITIAL_SECONDS
                    for block in iter_sse_blocks(resp.iter_lines()):
                        parsed = parse_sse_block(block)
                        if parsed is None:
                            continue
                        if parsed["id"]:
                            current_id = parsed["id"]
                        try:
                            data = json.loads(parsed["data"])
                        except json.JSONDecodeError:
                            data = {"raw": parsed["data"]}
                        yield StreamEvent(event=parsed["event"], id=parsed["id"], data=data)
            except (httpx.TransportError, httpx.RemoteProtocolError):
                attempts += 1
                if max_reconnect_attempts is not None and attempts > max_reconnect_attempts:
                    raise
                time.sleep(min(backoff, DEFAULT_RECONNECT_MAX_SECONDS))
                backoff = min(backoff * 2, DEFAULT_RECONNECT_MAX_SECONDS)
                continue


class AsyncClient(_BaseClient):
    """Asynchronous client. Public surface mirrors :class:`Client`."""

    def __init__(
        self,
        api_url: str = DEFAULT_BASE_URL,
        *,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: Optional[str] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        super().__init__(api_url, api_key=api_key, timeout=timeout, user_agent=user_agent)
        self._http: httpx.AsyncClient
        self._owns_http = http_client is None
        if http_client is not None:
            self._http = http_client
        else:
            self._http = httpx.AsyncClient(timeout=timeout, headers=self.headers)

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        accept: str = "application/json",
    ) -> httpx.Response:
        url = _resolve_url(self.api_url, path)
        headers = dict(self.headers)
        headers["accept"] = accept
        response = await self._http.request(method, url, params=params, headers=headers)
        raise_for_status(response)
        return response

    async def get_attestation(self, attestation_id: str) -> AttestationDetail:
        response = await self._request("GET", f"/v1/attestations/{attestation_id}")
        return _parse_model(AttestationDetail, response.json())

    async def list_registry(
        self,
        filters: Optional[Union[RegistryFilters, Dict[str, Any]]] = None,
        cursor: Optional[str] = None,
    ) -> RegistryPage:
        params = _filters_to_params(filters)
        if cursor is not None:
            params["cursor"] = cursor
        response = await self._request("GET", "/v1/registry", params=params)
        return _parse_model(RegistryPage, response.json())

    async def get_issuer(self, issuer_id: str) -> IssuerProfile:
        response = await self._request("GET", f"/v1/issuers/{issuer_id}")
        return _parse_model(IssuerProfile, response.json())

    async def get_segment(self, segment_id: str) -> SegmentProfile:
        response = await self._request("GET", f"/v1/segments/{segment_id}")
        return _parse_model(SegmentProfile, response.json())

    async def list_sths(self, segment_id: str, *, limit: Optional[int] = None) -> List[Sth]:
        params = {"limit": limit} if limit is not None else None
        response = await self._request("GET", f"/v1/segments/{segment_id}/sths", params=params)
        payload = response.json()
        items = payload.get("items") if isinstance(payload, dict) else payload
        return _parse_model(List[Sth], items)

    async def get_consistency_proof(
        self,
        from_size: int,
        to_size: int,
        segment_id: str,
    ) -> ConsistencyProof:
        params = {"from_size": from_size, "to_size": to_size, "segment_id": segment_id}
        response = await self._request("GET", "/v1/log/consistency", params=params)
        return _parse_model(ConsistencyProof, response.json())

    async def get_log(self) -> LogView:
        response = await self._request("GET", "/v1/log")
        return _parse_model(LogView, response.json())

    async def download_bundle(self, attestation_id: str) -> bytes:
        response = await self._request(
            "GET",
            f"/v1/attestations/{attestation_id}/bundle",
            accept="application/octet-stream",
        )
        return response.content

    async def stream_attestations(
        self,
        *,
        last_event_id: Optional[str] = None,
        max_reconnect_attempts: Optional[int] = None,
    ) -> AsyncIterator[StreamEvent]:
        """Async iterator over SSE events with auto-reconnect."""
        url = _resolve_url(self.api_url, "/v1/stream/attestations")
        backoff = DEFAULT_RECONNECT_INITIAL_SECONDS
        attempts = 0
        current_id = last_event_id
        while True:
            headers = dict(self.headers)
            headers["accept"] = "text/event-stream"
            if current_id:
                headers["last-event-id"] = current_id
            try:
                async with self._http.stream("GET", url, headers=headers, timeout=None) as resp:
                    raise_for_status(resp)
                    backoff = DEFAULT_RECONNECT_INITIAL_SECONDS
                    buffer: List[str] = []
                    async for raw_line in resp.aiter_lines():
                        if raw_line == "":
                            if not buffer:
                                continue
                            block = "\n".join(buffer)
                            buffer = []
                            parsed = parse_sse_block(block)
                            if parsed is None:
                                continue
                            if parsed["id"]:
                                current_id = parsed["id"]
                            try:
                                data = json.loads(parsed["data"])
                            except json.JSONDecodeError:
                                data = {"raw": parsed["data"]}
                            yield StreamEvent(event=parsed["event"], id=parsed["id"], data=data)
                        else:
                            buffer.append(raw_line)
            except (httpx.TransportError, httpx.RemoteProtocolError):
                attempts += 1
                if max_reconnect_attempts is not None and attempts > max_reconnect_attempts:
                    raise
                await asyncio.sleep(min(backoff, DEFAULT_RECONNECT_MAX_SECONDS))
                backoff = min(backoff * 2, DEFAULT_RECONNECT_MAX_SECONDS)
                continue
