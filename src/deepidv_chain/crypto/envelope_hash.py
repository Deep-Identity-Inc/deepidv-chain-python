"""Envelope hash — sha256 over the JCS-canonical envelope.

Cross-language parity contract: ``envelope_hash(envelope_dict)`` MUST match
the hash computed by the TypeScript SDK's ``envelopeHash(envelope)`` for the
same logical envelope. Tests in tests/parity/ enforce this via shared fixtures.
"""

from __future__ import annotations

import hashlib
from typing import Any

from deepidv_chain.crypto.jcs import jcs_canonicalize


def envelope_hash(envelope: Any) -> bytes:
    """Return the raw 32 bytes of sha256(JCS(envelope))."""
    return hashlib.sha256(jcs_canonicalize(envelope)).digest()


def envelope_hash_hex(envelope: Any) -> str:
    """Return ``"sha256:<hex>"`` for the envelope hash."""
    return "sha256:" + envelope_hash(envelope).hex()
