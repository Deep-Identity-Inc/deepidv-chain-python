"""ECDSA P-256 signature verification.

Uses the ``cryptography`` library. Signatures are DER-encoded over a SHA-256
digest of the message. PEM-encoded SubjectPublicKeyInfo is the canonical
public-key wire format.
"""

import base64
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class InvalidSignatureError(Exception):
    """The signature did not verify against the public key for this message."""


class UnsupportedKeyError(Exception):
    """The public key is not an ECDSA P-256 key."""


def _decode_signature(signature: Union[str, bytes]) -> bytes:
    if isinstance(signature, bytes):
        return signature
    # Accept base64 (with or without padding) or hex.
    s = signature.strip()
    if all(c in "0123456789abcdefABCDEF" for c in s):
        return bytes.fromhex(s)
    # Pad base64 if needed.
    pad = (-len(s)) % 4
    return base64.b64decode(s + ("=" * pad))


def _load_public_key(public_key_pem: str) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise UnsupportedKeyError(f"could not parse PEM public key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise UnsupportedKeyError(f"public key is not an EC key: {type(key).__name__}")
    if not isinstance(key.curve, ec.SECP256R1):
        raise UnsupportedKeyError(f"public key curve is not P-256: {key.curve.name}")
    return key


def verify_ecdsa_p256(
    *,
    public_key_pem: str,
    message: bytes,
    signature: Union[str, bytes],
) -> bool:
    """Verify a DER-encoded ECDSA P-256 signature over SHA-256(``message``).

    Returns True on success. Raises :class:`InvalidSignatureError` if the
    signature does not match. Raises :class:`UnsupportedKeyError` if the
    public key is not P-256 ECDSA.
    """
    key = _load_public_key(public_key_pem)
    sig_bytes = _decode_signature(signature)
    try:
        key.verify(sig_bytes, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise InvalidSignatureError("ECDSA P-256 signature verification failed") from exc
    return True
