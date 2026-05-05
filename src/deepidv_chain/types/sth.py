"""Signed Tree Head — the periodically-published log checkpoint.

An STH commits the issuer (`segment_id`) to a Merkle tree of size `tree_size`
with root hash `root_hash`. The signature is ECDSA P-256 over a JCS-canonical
serialization of the unsigned fields. Verifiers compare a fresh inclusion
proof against the `root_hash` of an STH they already trust.
"""

from pydantic import BaseModel, ConfigDict, Field


class Sth(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    schema_version: str = Field("sth/v1")
    segment_id: str
    tree_size: int = Field(..., ge=0)
    root_hash: str = Field(..., pattern=r"^sha256:[0-9a-f]{64}$")
    timestamp: str = Field(..., description="RFC 3339 UTC timestamp at which this STH was signed.")
    signer_key_id: str = Field(..., description="KMS key alias or fingerprint of the signing key.")
    signature: str = Field(..., description="Base64-encoded ECDSA P-256 signature over the JCS-canonical unsigned form.")
