"""Pydantic v2 models for the deepidv chain layer public API.

Field naming uses snake_case in Python. The wire format uses snake_case too
(matching the M02 envelope spec), so no aliasing is needed for the round-trip.

These models are deliberately permissive about extra fields (`extra="allow"`)
because the chain layer evolves additively — a new optional field on the wire
must not break a 1.0 client.
"""

from deepidv_chain.types.api import (
    AttestationDetail,
    ConsistencyProof,
    InclusionProof,
    IssuerProfile,
    LogView,
    RegistryFilters,
    RegistryPage,
    RegistrySummary,
    SegmentProfile,
    StreamEvent,
)
from deepidv_chain.types.bundle import (
    BundleManifest,
    VerifyCheck,
    VerifyResult,
)
from deepidv_chain.types.envelope import EnvelopeV1, Label
from deepidv_chain.types.sth import Sth

__all__ = [
    "AttestationDetail",
    "BundleManifest",
    "ConsistencyProof",
    "EnvelopeV1",
    "InclusionProof",
    "IssuerProfile",
    "Label",
    "LogView",
    "RegistryFilters",
    "RegistryPage",
    "RegistrySummary",
    "SegmentProfile",
    "Sth",
    "StreamEvent",
    "VerifyCheck",
    "VerifyResult",
]
