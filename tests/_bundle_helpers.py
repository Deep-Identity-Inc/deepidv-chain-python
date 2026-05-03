"""Helpers for tests: build a valid `.dpiv-bundle` against an in-memory log.

These helpers are intentionally NOT shipped in the published package — they
generate test fixtures on the fly. The published SDK is a verifier, not a
signer; signing belongs in M02/M03 backend services.
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from deepidv_chain.crypto.envelope_hash import envelope_hash
from deepidv_chain.crypto.jcs import (
    jcs_canonicalize,
)
from deepidv_chain.crypto.manifest import render_manifest
from deepidv_chain.crypto.merkle import leaf_hash


def _public_pem(sk: ec.EllipticCurvePrivateKey) -> str:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _node(left: bytes, right: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(b"\x01" + left + right).digest()


def _build_tree_with_leaves(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
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


def _audit_path_for(levels: List[List[bytes]], leaf_index: int) -> List[str]:
    path: List[str] = []
    idx = leaf_index
    for level in levels[:-1]:
        sibling = idx ^ 1
        if sibling < len(level):
            path.append(level[sibling].hex())
        idx //= 2
    return path


def make_envelope(seed: int = 0, salt: Optional[str] = None) -> Dict[str, object]:
    digits = f"{seed:026d}".upper()
    return {
        "schema_version": "envelope/v1",
        "attestation_id": "attest_" + digits,
        "record_type": "IDV",
        "issuer_id": "iss_test",
        "subject_pseudonym": "sha256:" + ("a" * 64),
        "issued_at": "2026-04-01T12:34:56.789Z",
        "claim_hash": "sha256:" + ("b" * 64),
        "labels": [{"name": "Country", "value": "USA"}],
        "salt": salt or "5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e",
        "extensions": {},
    }


def build_bundle(
    *,
    issuer_sk: Optional[ec.EllipticCurvePrivateKey] = None,
    chain_master_sk: Optional[ec.EllipticCurvePrivateKey] = None,
    extra_leaves: int = 7,
    target_index: int = 3,
    include_tsa: bool = False,
    tamper: Optional[str] = None,
) -> Tuple[bytes, Dict[str, object]]:
    """Build a valid `.dpiv-bundle` byte string and return (bytes, envelope).

    ``tamper`` can be used by tests to corrupt one specific component:
        - "envelope" → the envelope payload is changed AFTER hashing
        - "manifest-checksum" → one manifest line gets a wrong hash
        - "manifest-signature" → bundle-signature.bin is replaced with random
        - "sth-signature" → the STH signature is replaced with a wrong one
    """
    issuer_sk = issuer_sk or ec.generate_private_key(ec.SECP256R1())
    chain_master_sk = chain_master_sk or ec.generate_private_key(ec.SECP256R1())

    leaves: List[bytes] = []
    target_envelope = make_envelope(seed=target_index + 1)
    for i in range(extra_leaves + 1):
        if i == target_index:
            leaves.append(envelope_hash(target_envelope))
        else:
            leaves.append(envelope_hash(make_envelope(seed=i + 100)))

    root, levels = _build_tree_with_leaves(leaves)
    audit_path = _audit_path_for(levels, target_index)

    inclusion_proof = {
        "leaf_index": target_index,
        "tree_size": len(leaves),
        "audit_path": audit_path,
        "leaf_hash": "sha256:" + leaf_hash(envelope_hash(target_envelope)).hex(),
    }

    sth_unsigned = {
        "schema_version": "sth/v1",
        "segment_id": "seg_test",
        "tree_size": len(leaves),
        "root_hash": "sha256:" + root.hex(),
        "timestamp": "2026-04-01T13:00:00.000Z",
        "signer_key_id": "kms-alias/chain-master-test",
    }
    sth_signature = chain_master_sk.sign(jcs_canonicalize(sth_unsigned), ec.ECDSA(hashes.SHA256()))
    sth = dict(sth_unsigned)
    if tamper == "sth-signature":
        sth["signature"] = (b"\x00" * 70).hex()
    else:
        sth["signature"] = sth_signature.hex()

    files: Dict[str, bytes] = {
        "envelope.json": json.dumps(target_envelope, sort_keys=True).encode(),
        "inclusion-proof.json": json.dumps(inclusion_proof, sort_keys=True).encode(),
        "sth.json": json.dumps(sth, sort_keys=True).encode(),
        "issuer.pem": _public_pem(issuer_sk).encode(),
        "chain-master.pem": _public_pem(chain_master_sk).encode(),
    }
    if include_tsa:
        files["timestamp.tsr"] = b"\x30\x82\x00\x00fake-tsa-token"

    manifest_inputs = dict(files)
    manifest = render_manifest(manifest_inputs)

    # Tampers that mutate file contents AFTER manifest rendering — the manifest
    # checksum check should catch these.
    if tamper == "envelope":
        tampered = dict(target_envelope)
        tampered["issued_at"] = "1999-01-01T00:00:00.000Z"
        files["envelope.json"] = json.dumps(tampered, sort_keys=True).encode()
    elif tamper == "manifest-checksum":
        files["envelope.json"] = files["envelope.json"] + b"\x00garbage"

    manifest_signature = chain_master_sk.sign(manifest, ec.ECDSA(hashes.SHA256()))
    if tamper == "manifest-signature":
        manifest_signature = b"\x30\x44\x02\x20" + b"\x00" * 32 + b"\x02\x20" + b"\x00" * 32

    out_buffer = io.BytesIO()
    with zipfile.ZipFile(out_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
        zf.writestr("manifest.txt", manifest)
        zf.writestr("bundle-signature.bin", manifest_signature)

    return out_buffer.getvalue(), target_envelope
