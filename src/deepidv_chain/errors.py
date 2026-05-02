"""Typed error hierarchy for the deepidv chain SDK.

All API errors derive from :class:`DeepidvApiError`. Catch the specific subclass
for the failure mode you care about, or the base class to handle "any API
problem". Errors raised before the request leaves the client (validation,
local hash mismatch) are :class:`ValueError`, not API errors.
"""

from __future__ import annotations

from typing import Any


class DeepidvApiError(Exception):
    """Base class for any error returned by the deepidv chain HTTP API."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        url: str | None = None,
        body: Any | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.url = url
        self.body = body
        self.request_id = request_id

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        parts = [f"status={self.status_code!r}", f"url={self.url!r}"]
        if self.request_id:
            parts.append(f"request_id={self.request_id!r}")
        return f"{type(self).__name__}({self.message!r}, {', '.join(parts)})"


class DeepidvAuthError(DeepidvApiError):
    """401 / 403 — the request was rejected for auth reasons."""


class DeepidvNotFoundError(DeepidvApiError):
    """404 — the resource does not exist (or is hidden by tenant scoping)."""


class DeepidvRateLimitError(DeepidvApiError):
    """429 — the caller exceeded the request budget."""

    def __init__(
        self,
        message: str,
        *,
        retry_after_seconds: float | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after_seconds = retry_after_seconds


class DeepidvServerError(DeepidvApiError):
    """5xx — the server failed to handle the request."""
