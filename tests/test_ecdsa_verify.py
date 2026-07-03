"""ECDSA P-256 verify — happy path + tampering rejection."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from deepidv_chain.crypto.ecdsa_verify import (
    InvalidSignatureError,
    UnsupportedKeyError,
    verify_ecdsa_p256,
)


@pytest.fixture
def p256_keypair():
    sk = ec.generate_private_key(ec.SECP256R1())
    pem = (
        sk.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return sk, pem


def test_verify_round_trip(p256_keypair):
    sk, pem = p256_keypair
    msg = b"hello deepidv"
    sig = sk.sign(msg, ec.ECDSA(hashes.SHA256()))
    assert verify_ecdsa_p256(public_key_pem=pem, message=msg, signature=sig)


def test_verify_rejects_tampered_message(p256_keypair):
    sk, pem = p256_keypair
    sig = sk.sign(b"original", ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignatureError):
        verify_ecdsa_p256(public_key_pem=pem, message=b"tampered", signature=sig)


def test_verify_rejects_non_p256_key():
    sk = ec.generate_private_key(ec.SECP384R1())
    pem = (
        sk.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    sig = sk.sign(b"x", ec.ECDSA(hashes.SHA256()))
    with pytest.raises(UnsupportedKeyError):
        verify_ecdsa_p256(public_key_pem=pem, message=b"x", signature=sig)
