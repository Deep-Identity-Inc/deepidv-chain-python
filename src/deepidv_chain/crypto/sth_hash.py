"""STH signing payload — JCS over the unsigned STH fields.

The signer (chain-master, in M03) signs ``sha256(JCS(unsigned_sth))``. We
reproduce the same payload here so the Python SDK can verify any STH signed
by the system. The ``signature`` field is excluded from the payload; every
other field is included in canonical order.
"""

import hashlib
from typing import Any, Dict

from deepidv_chain.crypto.jcs import jcs_canonicalize


def sth_signing_payload(sth: Dict[str, Any]) -> bytes:
    """Return the bytes that the chain-master signs for ``sth``."""
    unsigned = {k: v for k, v in sth.items() if k != "signature"}
    return jcs_canonicalize(unsigned)


def sth_signing_payload_hex(sth: Dict[str, Any]) -> str:
    """Return the hex-encoded sha256 digest of the STH signing payload."""
    return hashlib.sha256(sth_signing_payload(sth)).hexdigest()
