"""Envelope v1 — the canonical wire shape for an attestation record.

The envelope is the byte sequence that gets hashed into the transparency-log
leaf. Field order is normative because envelope hashing uses RFC 8785 (JCS),
which is order-independent inside an object — but the documented schema still
fixes the field set to keep parity readers honest.

v1 record_types
---------------

`IDV` is the only active record type in v1. `BIO`, `DOC`, and `ADDR` are
reserved for Phase 2 and will validate as inputs but not yet appear in the
registry. `RSK`, `AML`, `AGR`, and `ACT` are intentionally not in the enum
in v1 — the chain layer does not mint those record types.
"""

from typing import Any, Dict, List, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

RecordType = Literal["IDV", "BIO", "DOC", "ADDR"]
"""Record types accepted by the v1 chain layer.

`IDV` is active. `BIO` / `DOC` / `ADDR` are reserved for Phase 2.
`RSK` / `AML` / `AGR` / `ACT` are deliberately excluded.
"""


class Label(BaseModel):
    """A semantic label attached to an attestation.

    Labels are the public, queryable surface — for example "Age >= 18", "Country",
    "Sanctions Clear". The label *value* is restricted to JSON primitives so it
    survives canonicalization round-trips.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    name: str = Field(..., min_length=1, max_length=128)
    value: Union[bool, int, float, str] = Field(...)


class EnvelopeV1(BaseModel):
    """Envelope v1 — RFC 8785 canonicalized for hashing.

    The `salt` field is the per-record privacy salt. It MUST never be rendered
    in user-facing UI or log output. Verifiers compute the envelope hash over
    the full envelope including the salt; consumers reading bundles for display
    must explicitly strip it before rendering.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    schema_version: Literal["envelope/v1"] = Field("envelope/v1")
    attestation_id: str = Field(..., pattern=r"^attest_[0-9A-HJKMNP-TV-Z]{26}$")
    record_type: RecordType
    issuer_id: str = Field(..., min_length=1)
    subject_pseudonym: str = Field(..., pattern=r"^sha256:[0-9a-f]{64}$")
    issued_at: str = Field(..., description="RFC 3339 timestamp in UTC, with millisecond precision.")
    claim_hash: str = Field(..., pattern=r"^sha256:[0-9a-f]{64}$")
    labels: List[Label] = Field(default_factory=list)
    salt: str = Field(..., min_length=32, description="Per-record privacy salt. Never render in UI.")
    extensions: Dict[str, Any] = Field(default_factory=dict)
