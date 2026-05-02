"""HTTP API response shapes for the public registry endpoints.

These mirror the proof.deepidv.com surface served by the M02..M06 backend.
All field names are snake_case on both wire and Python sides.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from deepidv_chain.types.envelope import EnvelopeV1, Label, RecordType
from deepidv_chain.types.sth import Sth


class InclusionProof(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    leaf_index: int = Field(..., ge=0)
    tree_size: int = Field(..., ge=0)
    audit_path: list[str] = Field(default_factory=list)


class ConsistencyProof(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    from_size: int = Field(..., ge=0)
    to_size: int = Field(..., ge=0)
    audit_path: list[str] = Field(default_factory=list)
    segment_id: str


class IssuerProfile(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    issuer_id: str
    display_name: str
    status: Literal["active", "suspended", "retired"]
    public_key_pem: str
    activated_at: str
    retired_at: str | None = None
    segment_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SegmentProfile(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    segment_id: str
    issuer_id: str
    status: Literal["open", "sealed"]
    opened_at: str
    sealed_at: str | None = None
    tree_size: int = Field(..., ge=0)
    last_sth_timestamp: str | None = None


class AttestationDetail(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    attestation_id: str
    record_type: RecordType
    issuer_id: str
    segment_id: str
    leaf_index: int = Field(..., ge=0)
    tree_size_at_inclusion: int = Field(..., ge=0)
    issued_at: str
    labels: list[Label] = Field(default_factory=list)
    envelope: EnvelopeV1
    inclusion_proof: InclusionProof
    sth: Sth
    bundle_url: str | None = None
    revoked: bool = False
    revoked_reason: str | None = None
    onchain_anchor: dict[str, Any] | None = None


class RegistrySummary(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    attestation_id: str
    record_type: RecordType
    issuer_id: str
    issued_at: str
    labels: list[Label] = Field(default_factory=list)
    revoked: bool = False


class RegistryFilters(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=False)

    issuer_id: str | None = None
    record_type: RecordType | None = None
    label_name: str | None = None
    label_value: str | None = None
    issued_after: str | None = None
    issued_before: str | None = None
    revoked: bool | None = None
    limit: int | None = Field(default=None, ge=1, le=200)


class RegistryPage(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    items: list[RegistrySummary]
    next_cursor: str | None = None
    page_size: int


class LogView(BaseModel):
    """Public summary of every active segment in the chain layer's transparency log."""

    model_config = ConfigDict(extra="allow", frozen=True)

    segments: list[SegmentProfile]
    latest_sths: list[Sth]
    fetched_at: str


class StreamEvent(BaseModel):
    """One event emitted by the SSE attestation stream."""

    model_config = ConfigDict(extra="allow", frozen=True)

    event: Literal["attestation.minted", "attestation.revoked", "sth.signed", "heartbeat"]
    id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    received_at: str | None = None
