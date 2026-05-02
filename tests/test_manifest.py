"""Manifest helpers — sha256sum-compatible round trip + parsing rules."""

from __future__ import annotations

import hashlib

import pytest

from deepidv_chain.crypto.manifest import (
    ManifestParseError,
    parse_manifest,
    render_manifest,
    sha256_hex,
)


def test_render_manifest_is_sorted_and_two_spaces():
    rendered = render_manifest({
        "b.txt": b"second",
        "a.txt": b"first",
    }).decode()
    lines = rendered.splitlines()
    assert len(lines) == 2
    assert lines[0].endswith("  a.txt")
    assert lines[1].endswith("  b.txt")
    assert "  " in lines[0]  # exactly two spaces between hash and path
    parts = lines[0].split("  ", 1)
    assert len(parts[0]) == 64
    assert parts[0] == hashlib.sha256(b"first").hexdigest()


def test_parse_manifest_round_trip():
    rendered = render_manifest({"a.txt": b"hi", "b/c.json": b"{}"})
    parsed = parse_manifest(rendered)
    assert parsed == [
        (sha256_hex(b"hi"), "a.txt"),
        (sha256_hex(b"{}"), "b/c.json"),
    ]


def test_parse_manifest_rejects_one_space():
    bad = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff a.txt\n"
    with pytest.raises(ManifestParseError):
        parse_manifest(bad)


def test_parse_manifest_rejects_short_hash():
    bad = b"deadbeef  a.txt\n"
    with pytest.raises(ManifestParseError):
        parse_manifest(bad)
