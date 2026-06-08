"""HTTP plumbing shared by the sync and async clients.

Centralizes URL building, error mapping, and SSE line parsing so the public
surface stays small. ``Client`` and ``AsyncClient`` are thin wrappers over
httpx; this module is intentionally low-level.
"""

from typing import Any, Dict, Iterator, List, Mapping, Optional

import httpx

from deepidv_chain.errors import (
    DeepidvApiError,
    DeepidvAuthError,
    DeepidvNotFoundError,
    DeepidvRateLimitError,
    DeepidvServerError,
)

DEFAULT_USER_AGENT = "deepidv-chain-python/1.1.0"


def map_response_to_error(response: httpx.Response) -> DeepidvApiError:
    """Build the typed exception for a non-2xx httpx response.

    The body is parsed as JSON when possible; otherwise the raw text is kept.
    The request_id header (``x-request-id``) is captured if the API returned one.
    """
    try:
        body: Any = response.json()
    except ValueError:
        body = response.text

    status = response.status_code
    request_id = response.headers.get("x-request-id")
    url = str(response.request.url) if response.request else None

    if isinstance(body, Mapping) and isinstance(body.get("message"), str):
        message = body["message"]
    elif isinstance(body, str) and body:
        message = body[:200]
    else:
        message = f"HTTP {status} from {url}"

    kwargs = {"status_code": status, "url": url, "body": body, "request_id": request_id}

    if status in (401, 403):
        return DeepidvAuthError(message, **kwargs)
    if status == 404:
        return DeepidvNotFoundError(message, **kwargs)
    if status == 429:
        retry_after = response.headers.get("retry-after")
        retry_after_seconds: Optional[float] = None
        if retry_after is not None:
            try:
                retry_after_seconds = float(retry_after)
            except ValueError:
                retry_after_seconds = None
        return DeepidvRateLimitError(
            message, retry_after_seconds=retry_after_seconds, **kwargs
        )
    if 500 <= status < 600:
        return DeepidvServerError(message, **kwargs)
    return DeepidvApiError(message, **kwargs)


def raise_for_status(response: httpx.Response) -> None:
    """Raise the typed exception if ``response`` is non-2xx."""
    if response.is_success:
        return
    raise map_response_to_error(response)


def build_default_headers(api_key: Optional[str], user_agent: Optional[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "user-agent": user_agent or DEFAULT_USER_AGENT,
        "accept": "application/json",
    }
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    return headers


def parse_sse_block(block: str) -> Optional[Dict[str, Any]]:
    """Parse one SSE record (lines separated by single \\n, blocks by \\n\\n).

    Returns a dict with keys ``event``, ``id``, ``data`` (the joined data lines),
    or ``None`` if the block carried no data line. Comment lines (starting with
    ``:``) are dropped.
    """
    event = "message"
    event_id: Optional[str] = None
    data_lines = []
    for raw_line in block.split("\n"):
        line = raw_line.rstrip("\r")
        if not line or line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "event":
            event = value
        elif field == "id":
            event_id = value
        elif field == "data":
            data_lines.append(value)
    if not data_lines:
        return None
    return {"event": event, "id": event_id, "data": "\n".join(data_lines)}


def iter_sse_blocks(line_iter: Iterator[str]) -> Iterator[str]:
    """Group raw lines from an SSE stream into blocks separated by blank lines."""
    buffer: List[str] = []
    for line in line_iter:
        if line == "":
            if buffer:
                yield "\n".join(buffer)
                buffer = []
        else:
            buffer.append(line)
    if buffer:
        yield "\n".join(buffer)
