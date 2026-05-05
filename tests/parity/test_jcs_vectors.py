"""Cross-language parity tests for JCS canonicalization.

The fixtures in tests/fixtures/jcs-vectors.json are the SAME fixtures used by
the TypeScript SDK's parity tests (and by ``shared-deps``). If a vector here
fails, a TS-side fix is needed before the Python SDK can ship.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from deepidv_chain.crypto.jcs import jcs_canonicalize

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "jcs-vectors.json"


def _load_vectors():
    payload = json.loads(FIXTURE.read_text())
    return [(v["name"], v["input"], v["canonical"]) for v in payload["vectors"]]


@pytest.mark.parametrize(("name", "value", "canonical"), _load_vectors())
def test_jcs_vector(name, value, canonical):
    actual = jcs_canonicalize(value).decode("utf-8")
    assert actual == canonical, f"vector {name!r}: {actual!r} != {canonical!r}"
