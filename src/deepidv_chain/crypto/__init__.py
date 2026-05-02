"""Crypto primitives — JCS, envelope hash, STH hash, manifest, ECDSA verify.

Every function in this package is intentionally pure. Same input → same byte
output. Cross-language parity with the TypeScript SDK depends on it.
"""

from deepidv_chain.crypto.ecdsa_verify import (
    InvalidSignatureError,
    UnsupportedKeyError,
    verify_ecdsa_p256,
)
from deepidv_chain.crypto.envelope_hash import envelope_hash, envelope_hash_hex
from deepidv_chain.crypto.jcs import jcs_canonicalize
from deepidv_chain.crypto.manifest import (
    ManifestParseError,
    parse_manifest,
    render_manifest,
    sha256_hex,
)
from deepidv_chain.crypto.merkle import (
    MerkleVerificationError,
    leaf_hash,
    verify_consistency,
    verify_inclusion,
)
from deepidv_chain.crypto.sth_hash import sth_signing_payload, sth_signing_payload_hex

__all__ = [
    "InvalidSignatureError",
    "ManifestParseError",
    "MerkleVerificationError",
    "UnsupportedKeyError",
    "envelope_hash",
    "envelope_hash_hex",
    "jcs_canonicalize",
    "leaf_hash",
    "parse_manifest",
    "render_manifest",
    "sha256_hex",
    "sth_signing_payload",
    "sth_signing_payload_hex",
    "verify_consistency",
    "verify_ecdsa_p256",
    "verify_inclusion",
]
