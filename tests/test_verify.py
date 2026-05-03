"""End-to-end offline bundle verification tests.

Cover the 5-of-6 contract:
  - Happy path: 5 checks pass, 1 (TSA) is loud-skipped.
  - Tampered envelope, manifest, manifest signature, STH signature → fail loudly.
  - Salt is stripped from the returned envelope.
"""

from __future__ import annotations

import pytest

from deepidv_chain import verify_bundle
from tests._bundle_helpers import build_bundle


def _check(result, name):
    for c in result.checks:
        if c.name == name:
            return c
    raise AssertionError(f"check {name!r} not found in result")


def test_happy_path_valid_bundle():
    bundle_bytes, envelope = build_bundle()
    result = verify_bundle(bundle_bytes)

    assert result.valid is True
    assert result.attestation_id == envelope["attestation_id"]
    assert result.issuer_id == "iss_test"
    assert result.tree_size == 8
    assert _check(result, "manifest-integrity").passed is True
    assert _check(result, "manifest-signature").passed is True
    assert _check(result, "envelope-hash").passed is True
    assert _check(result, "inclusion-proof").passed is True
    assert _check(result, "sth-signature").passed is True

    tsa = _check(result, "tsa-timestamp")
    assert tsa.skipped is True
    assert tsa.passed is False
    assert "not implemented in v1" in (tsa.detail or "")
    assert result.skipped_checks == ["tsa-timestamp"]


def test_returned_envelope_strips_salt():
    bundle_bytes, envelope = build_bundle()
    result = verify_bundle(bundle_bytes)
    assert result.envelope is not None
    assert "salt" not in result.envelope
    # Same other fields are preserved.
    assert result.envelope["attestation_id"] == envelope["attestation_id"]
    assert result.envelope["record_type"] == "IDV"


def test_tampered_envelope_fails_envelope_hash():
    bundle_bytes, _ = build_bundle(tamper="envelope")
    result = verify_bundle(bundle_bytes)
    assert result.valid is False
    integrity = _check(result, "manifest-integrity")
    # The tamper modifies the envelope AFTER manifest rendering — manifest
    # checksum should catch it before envelope-hash even runs.
    assert integrity.passed is False


def test_tampered_manifest_signature_fails():
    bundle_bytes, _ = build_bundle(tamper="manifest-signature")
    result = verify_bundle(bundle_bytes)
    assert result.valid is False
    sig = _check(result, "manifest-signature")
    assert sig.passed is False


def test_tampered_sth_signature_fails():
    bundle_bytes, _ = build_bundle(tamper="sth-signature")
    result = verify_bundle(bundle_bytes)
    assert result.valid is False
    sth_check = _check(result, "sth-signature")
    assert sth_check.passed is False


def test_tampered_manifest_checksum_fails_integrity():
    bundle_bytes, _ = build_bundle(tamper="manifest-checksum")
    result = verify_bundle(bundle_bytes)
    assert result.valid is False
    integrity = _check(result, "manifest-integrity")
    assert integrity.passed is False


def test_invalid_zip_input_returns_failure_not_exception():
    result = verify_bundle(b"not a zip file at all")
    assert result.valid is False
    readable = _check(result, "bundle-readable")
    assert readable.passed is False


def test_verify_rejects_non_bytes_input():
    with pytest.raises(TypeError):
        verify_bundle("not bytes")  # type: ignore[arg-type]


def test_tsa_skip_is_loud_with_or_without_token():
    without = verify_bundle(build_bundle(include_tsa=False)[0])
    assert "omits a timestamp.tsr" in (_check(without, "tsa-timestamp").detail or "")
    with_tsa = verify_bundle(build_bundle(include_tsa=True)[0])
    assert "includes a timestamp.tsr" in (_check(with_tsa, "tsa-timestamp").detail or "")
    # Both must report the skip. Both must be valid (since TSA is documented-skipped).
    assert without.valid is True
    assert with_tsa.valid is True
