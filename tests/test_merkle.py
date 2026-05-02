"""RFC 6962 Merkle primitives — inclusion + consistency.

We construct a small reference tree (8 leaves) directly and check that
``verify_inclusion`` matches a freshly computed root for every leaf.
"""

from __future__ import annotations

import hashlib

import pytest

from deepidv_chain.crypto.merkle import (
    MerkleVerificationError,
    leaf_hash,
    verify_consistency,
    verify_inclusion,
)


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _build_tree(leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """Return (root, levels) where levels[0] is leaf hashes."""
    levels = [[leaf_hash(leaf) for leaf in leaves]]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        nxt = []
        for i in range(0, len(prev), 2):
            if i + 1 < len(prev):
                nxt.append(_node(prev[i], prev[i + 1]))
            else:
                nxt.append(prev[i])
        levels.append(nxt)
    return levels[-1][0], levels


def _audit_path(levels: list[list[bytes]], leaf_index: int) -> list[str]:
    path: list[str] = []
    idx = leaf_index
    for level in levels[:-1]:
        sibling = idx ^ 1
        if sibling < len(level):
            path.append(level[sibling].hex())
        idx //= 2
    return path


def test_inclusion_proof_round_trip_for_each_leaf():
    leaves = [f"leaf-{i}".encode() for i in range(8)]
    root, levels = _build_tree(leaves)
    for i, leaf in enumerate(leaves):
        path = _audit_path(levels, i)
        assert verify_inclusion(
            leaf_index=i,
            tree_size=len(leaves),
            leaf_hash_bytes=leaf_hash(leaf),
            audit_path=path,
            expected_root=root,
        )


def test_inclusion_proof_rejects_wrong_root():
    leaves = [b"a", b"b", b"c", b"d"]
    root, levels = _build_tree(leaves)
    bad_root = bytes(32)
    with pytest.raises(MerkleVerificationError):
        verify_inclusion(
            leaf_index=1,
            tree_size=4,
            leaf_hash_bytes=leaf_hash(leaves[1]),
            audit_path=_audit_path(levels, 1),
            expected_root=bad_root,
        )
    assert root != bad_root


def test_consistency_trivial_empty_from_size():
    assert verify_consistency(
        from_size=0,
        to_size=4,
        from_root=bytes(32),
        to_root=bytes(32),
        audit_path=[],
    )


def test_consistency_equal_sizes_identical_roots():
    leaves = [b"a", b"b", b"c", b"d"]
    root, _ = _build_tree(leaves)
    assert verify_consistency(
        from_size=4,
        to_size=4,
        from_root=root,
        to_root=root,
        audit_path=[],
    )


def test_consistency_equal_sizes_mismatched_roots():
    with pytest.raises(MerkleVerificationError):
        verify_consistency(
            from_size=2,
            to_size=2,
            from_root=bytes(32),
            to_root=b"\xff" * 32,
            audit_path=[],
        )
