"""`.dpiv-bundle` archive shapes and verification result types."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class BundleManifest(BaseModel):
    """Manifest entries are sha256sum-compatible: ``"<hex>  <path>\\n"``.

    The manifest covers every other file in the bundle. The manifest itself is
    not in the manifest — its integrity is enforced by being signed alongside
    the envelope and STH within the bundle's outer signature block.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    schema_version: str = Field("manifest/v1")
    files: list[str] = Field(default_factory=list)


class VerifyCheck(BaseModel):
    """One check in the offline bundle verification report.

    `passed=True` and `passed=False` are independent of `skipped`. A skipped
    check is never silently treated as a pass — it is reported as a separate
    `skipped=True, passed=False` line so that downstream policy can decide
    whether to allow it.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    name: str
    passed: bool
    skipped: bool = False
    detail: str | None = None


class VerifyResult(BaseModel):
    """Output of :func:`deepidv_chain.verify_bundle`.

    `valid` is true only when every non-skipped check passed AND the count of
    skipped checks equals the documented set (currently: TSA timestamp).
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    valid: bool
    checks: list[VerifyCheck]
    attestation_id: str | None = None
    issuer_id: str | None = None
    tree_size: int | None = None
    skipped_checks: list[str] = Field(default_factory=list)
    envelope: dict[str, Any] | None = Field(
        default=None,
        description="Envelope contents with the salt field stripped. Safe for display.",
    )
