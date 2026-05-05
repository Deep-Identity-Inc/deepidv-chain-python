"""Envelope-hash parity test.

The expected digest is computed once at test time from the canonical bytes
in jcs-vectors.json, so this test will track any future change to the JCS
implementation. The fixture envelope itself is shared with the TS SDK.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from deepidv_chain.crypto.envelope_hash import envelope_hash, envelope_hash_hex
from deepidv_chain.crypto.jcs import jcs_canonicalize

ENVELOPE_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "envelope-hashes.json"
JCS_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "jcs-vectors.json"


def _envelope_vectors():
    payload = json.loads(ENVELOPE_FIXTURE.read_text())
    return [(v["name"], v["envelope"]) for v in payload["vectors"]]


def _shared_canonical_for(name: str) -> str:
    payload = json.loads(JCS_FIXTURE.read_text())
    for v in payload["vectors"]:
        if v["name"] == name:
            return v["canonical"]
    raise KeyError(name)


@pytest.mark.parametrize(("name", "envelope"), _envelope_vectors())
def test_envelope_hash_matches_jcs_then_sha256(name, envelope):
    canonical = _shared_canonical_for(name)
    expected_digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    assert envelope_hash(envelope) == expected_digest
    assert envelope_hash_hex(envelope) == "sha256:" + expected_digest.hex()


def test_envelope_hash_matches_jcs_pipe():
    envelope = {"a": 1, "b": [1, 2, 3]}
    via_pipe = hashlib.sha256(jcs_canonicalize(envelope)).digest()
    assert envelope_hash(envelope) == via_pipe
