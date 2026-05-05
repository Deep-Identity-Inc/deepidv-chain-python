"""HTTP API response shapes for the public registry endpoints.

These mirror the proof.deepidv.com surface served by the M02..M06 backend.
All field names are snake_case on both wire and Python sides.
"""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from deepidv_chain.types.envelope import EnvelopeV1, Label, RecordType
from deepidv_chain.types.sth import Sth


class InclusionProof(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    leaf_index: int = Field(..., ge=0)
    tree_size: int = Field(..., ge=0)
    audit_path: List[str] = Field(default_factory=list)


class ConsistencyProof(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    from_size: int = Field(..., ge=0)
    to_size: int = Field(..., ge=0)
    audit_path: List[str] = Field(default_factory=list)
    segment_id: str


class IssuerProfile(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    issuer_id: str
    display_name: str
    status: Literal["active", "suspended", "retired"]
    public_key_pem: str
    activated_at: str
    retired_at: Optional[str] = None
    segment_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SegmentProfile(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    segment_id: str
    issuer_id: str
    status: Literal["open", "sealed"]
    opened_at: str
    sealed_at: Optional[str] = None
    tree_size: int = Field(..., ge=0)
    last_sth_timestamp: Optional[str] = None


class AttestationDetail(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    attestation_id: str
    record_type: RecordType
    issuer_id: str
    segment_id: str
    leaf_index: int = Field(..., ge=0)
    tree_size_at_inclusion: int = Field(..., ge=0)
    issued_at: str
    labels: List[Label] = Field(default_factory=list)
    envelope: EnvelopeV1
    inclusion_proof: InclusionProof
    sth: Sth
    bundle_url: Optional[str] = None
    revoked: bool = False
    revoked_reason: Optional[str] = None
    onchain_anchor: Optional[Dict[str, Any]] = None


class RegistrySummary(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    attestation_id: str
    record_type: RecordType
    issuer_id: str
    issued_at: str
    labels: List[Label] = Field(default_factory=list)
    revoked: bool = False


class RegistryFilters(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=False)

    issuer_id: Optional[str] = None
    record_type: Optional[RecordType] = None
    label_name: Optional[str] = None
    label_value: Optional[str] = None
    issued_after: Optional[str] = None
    issued_before: Optional[str] = None
    revoked: Optional[bool] = None
    limit: Optional[int] = Field(default=None, ge=1, le=200)


class RegistryPage(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    items: List[RegistrySummary]
    next_cursor: Optional[str] = None
    page_size: int


class LogView(BaseModel):
    """Public summary of every active segment in the chain layer's transparency log."""

    model_config = ConfigDict(extra="allow", frozen=True)

    segments: List[SegmentProfile]
    latest_sths: List[Sth]
    fetched_at: str


class StreamEvent(BaseModel):
    """One event emitted by the SSE attestation stream."""

    model_config = ConfigDict(extra="allow", frozen=True)

    event: Literal["attestation.minted", "attestation.revoked", "sth.signed", "heartbeat"]
    id: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    received_at: Optional[str] = None
