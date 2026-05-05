"""RFC 6962 Merkle tree primitives — leaf hash + inclusion + consistency.

The chain layer's transparency log is RFC 6962, byte-for-byte. Domain
separation tags are 0x00 for leaves and 0x01 for internal nodes.
"""

import hashlib
from typing import List, Union


class MerkleVerificationError(Exception):
    """Raised when a Merkle proof fails to match the expected root."""


def leaf_hash(leaf_bytes: bytes) -> bytes:
    """RFC 6962 leaf hash: sha256(0x00 || leaf_bytes)."""
    return hashlib.sha256(b"\x00" + leaf_bytes).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _hex_to_bytes(value: str) -> bytes:
    if value.startswith("sha256:"):
        value = value[len("sha256:") :]
    return bytes.fromhex(value)


def verify_inclusion(
    *,
    leaf_index: int,
    tree_size: int,
    leaf_hash_bytes: bytes,
    audit_path: List[str],
    expected_root: Union[str, bytes],
) -> bool:
    """Verify an RFC 6962 inclusion proof. Returns True or raises.

    Mirrors RFC 6962 §2.1.1.
    """
    if leaf_index < 0 or leaf_index >= tree_size:
        raise MerkleVerificationError(
            f"leaf_index {leaf_index} out of range for tree_size {tree_size}"
        )
    expected = expected_root if isinstance(expected_root, bytes) else _hex_to_bytes(expected_root)

    fn = leaf_index
    sn = tree_size - 1
    h = leaf_hash_bytes
    for sibling_hex in audit_path:
        sibling = _hex_to_bytes(sibling_hex)
        if sn == 0:
            raise MerkleVerificationError("audit path longer than tree depth")
        if fn % 2 == 1 or fn == sn:
            h = _node_hash(sibling, h)
            if fn % 2 == 0:
                # Walk up while we are on a right edge.
                while fn % 2 == 0:
                    fn //= 2
                    sn //= 2
        else:
            h = _node_hash(h, sibling)
        fn //= 2
        sn //= 2

    if h != expected:
        raise MerkleVerificationError("inclusion proof root mismatch")
    return True


def verify_consistency(
    *,
    from_size: int,
    to_size: int,
    from_root: Union[str, bytes],
    to_root: Union[str, bytes],
    audit_path: List[str],
) -> bool:
    """Verify an RFC 6962 consistency proof. Returns True or raises.

    Mirrors RFC 6962 §2.1.2.
    """
    if from_size < 0 or to_size < from_size:
        raise MerkleVerificationError(
            f"invalid sizes: from_size={from_size}, to_size={to_size}"
        )
    fr = from_root if isinstance(from_root, bytes) else _hex_to_bytes(from_root)
    tr = to_root if isinstance(to_root, bytes) else _hex_to_bytes(to_root)

    if from_size == 0:
        # Trivially consistent: any tree is consistent with the empty tree.
        return True
    if from_size == to_size:
        if fr != tr:
            raise MerkleVerificationError("consistency proof: equal sizes but roots differ")
        if audit_path:
            raise MerkleVerificationError("consistency proof: equal sizes but path is non-empty")
        return True

    path = [_hex_to_bytes(s) for s in audit_path]
    if not path:
        raise MerkleVerificationError("consistency proof: empty path for unequal sizes")

    fn = from_size - 1
    sn = to_size - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2

    if fn == 0:
        # The from-tree was a perfect subtree at the left edge.
        fr_hash = fr
        path_iter = iter(path)
    else:
        fr_hash = path[0]
        path_iter = iter(path[1:])

    tr_hash = fr_hash

    for sibling in path_iter:
        if sn == 0:
            raise MerkleVerificationError("consistency proof: path longer than tree depth")
        if fn % 2 == 1 or fn == sn:
            fr_hash = _node_hash(sibling, fr_hash)
            tr_hash = _node_hash(sibling, tr_hash)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            tr_hash = _node_hash(tr_hash, sibling)
        fn //= 2
        sn //= 2

    if fr_hash != fr:
        raise MerkleVerificationError("consistency proof: from-root mismatch")
    if tr_hash != tr:
        raise MerkleVerificationError("consistency proof: to-root mismatch")
    return True
