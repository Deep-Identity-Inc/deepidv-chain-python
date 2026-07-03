"""Offline verification of `.dpiv-bundle` archives.

A bundle is a ZIP with the following layout (every file optional unless noted):

    envelope.json              required — the canonical attestation envelope
    inclusion-proof.json       required — RFC 6962 inclusion proof
    sth.json                   required — Signed Tree Head witnessing the proof
    issuer.pem                 required — issuer public key (PEM SPKI)
    chain-master.pem           required — chain-master public key (PEM SPKI)
    bundle-signature.bin       required — DER ECDSA P-256 signature over manifest
    manifest.txt               required — sha256sum-compatible covering all
                                          files except itself and bundle-signature.bin
    timestamp.tsr              optional — RFC 3161 TSA token (NOT VERIFIED in v1)

Verification is intentionally a 5-of-6 contract:

    1. Manifest integrity — every file listed matches its sha256.
    2. Manifest signature — bundle-signature.bin is a valid chain-master ECDSA
       P-256 signature over manifest.txt.
    3. Envelope hash — sha256(JCS(envelope)) appears as the leaf-hashed input
       in the inclusion proof's leaf hash.
    4. Inclusion proof — the audit path reconstructs the STH root.
    5. STH signature — the chain-master signed the unsigned form of the STH.
    6. TSA timestamp — SKIPPED. We attach the token but do not verify it in v1.
       The caller MUST treat the skip as a non-pass and decide policy.

The verifier returns a :class:`VerifyResult` with one :class:`VerifyCheck`
per item above. ``valid`` is True only if every non-skipped check passed AND
``skipped_checks`` is exactly the documented set (currently: ``["tsa-timestamp"]``).

The salt field is stripped from the returned envelope so callers can render
``result.envelope`` without leaking the per-record privacy salt.
"""

import io
import json
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from deepidv_chain.crypto.ecdsa_verify import (
    InvalidSignatureError,
    UnsupportedKeyError,
    verify_ecdsa_p256,
)
from deepidv_chain.crypto.envelope_hash import envelope_hash
from deepidv_chain.crypto.manifest import ManifestParseError, parse_manifest, sha256_hex
from deepidv_chain.crypto.merkle import (
    MerkleVerificationError,
    leaf_hash,
    verify_inclusion,
)
from deepidv_chain.crypto.sth_hash import sth_signing_payload
from deepidv_chain.types import VerifyCheck, VerifyResult

REQUIRED_FILES = {
    "envelope.json",
    "inclusion-proof.json",
    "sth.json",
    "issuer.pem",
    "chain-master.pem",
    "bundle-signature.bin",
    "manifest.txt",
}

OPTIONAL_FILES = {"timestamp.tsr"}

DOCUMENTED_SKIPS = ["tsa-timestamp"]


def _read_zip(bundle_bytes: bytes) -> Tuple[Dict[str, bytes], List[str]]:
    """Return (file_map, errors). ``file_map`` is path → raw bytes."""
    errors: List[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(bundle_bytes))
    except zipfile.BadZipFile as exc:
        return {}, [f"could not open bundle as zip: {exc}"]

    files: Dict[str, bytes] = {}
    for info in zf.infolist():
        if info.is_dir():
            continue
        files[info.filename] = zf.read(info)
    return files, errors


def _strip_salt(envelope: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(envelope)
    out.pop("salt", None)
    return out


def verify_bundle(bundle_bytes: bytes) -> VerifyResult:
    """Verify a `.dpiv-bundle` archive end-to-end and return a structured result.

    This function never raises for a malformed bundle — it captures the failure
    in :class:`VerifyCheck` rows so callers can surface every problem at once.
    Programmer-error inputs (e.g. ``bundle_bytes`` is not bytes) raise normally.
    """
    if not isinstance(bundle_bytes, (bytes, bytearray)):
        raise TypeError(f"verify_bundle expected bytes, got {type(bundle_bytes).__name__}")

    checks: List[VerifyCheck] = []
    files, zip_errors = _read_zip(bytes(bundle_bytes))
    if zip_errors:
        for msg in zip_errors:
            checks.append(VerifyCheck(name="bundle-readable", passed=False, detail=msg))
        return VerifyResult(valid=False, checks=checks, skipped_checks=list(DOCUMENTED_SKIPS))

    checks.append(VerifyCheck(name="bundle-readable", passed=True))

    missing = [path for path in REQUIRED_FILES if path not in files]
    if missing:
        checks.append(
            VerifyCheck(
                name="required-files-present",
                passed=False,
                detail=f"missing files: {sorted(missing)}",
            )
        )
        return _finalize(checks, skipped=list(DOCUMENTED_SKIPS))
    checks.append(VerifyCheck(name="required-files-present", passed=True))

    manifest_bytes = files["manifest.txt"]
    bundle_signature = files["bundle-signature.bin"]
    issuer_pem = files["issuer.pem"].decode("utf-8")
    chain_master_pem = files["chain-master.pem"].decode("utf-8")

    # 1. Manifest integrity (BEFORE parsing potentially-tampered JSON)
    try:
        manifest_entries = parse_manifest(manifest_bytes)
    except ManifestParseError as exc:
        checks.append(VerifyCheck(name="manifest-integrity", passed=False, detail=str(exc)))
        return _finalize(checks, skipped=list(DOCUMENTED_SKIPS))

    manifest_paths = {path for _, path in manifest_entries}
    expected_manifest_paths = set(files) - {"manifest.txt", "bundle-signature.bin"}
    if manifest_paths != expected_manifest_paths:
        checks.append(
            VerifyCheck(
                name="manifest-integrity",
                passed=False,
                detail=(
                    "manifest path set mismatch — "
                    f"missing: {sorted(expected_manifest_paths - manifest_paths)}, "
                    f"extra: {sorted(manifest_paths - expected_manifest_paths)}"
                ),
            )
        )
        return _finalize(checks, skipped=list(DOCUMENTED_SKIPS))

    bad = [
        (path, expected, sha256_hex(files[path]))
        for expected, path in manifest_entries
        if files.get(path) is None or sha256_hex(files[path]) != expected
    ]
    if bad:
        checks.append(
            VerifyCheck(
                name="manifest-integrity",
                passed=False,
                detail=f"manifest checksum mismatch on {[b[0] for b in bad]}",
            )
        )
        return _finalize(checks, skipped=list(DOCUMENTED_SKIPS))
    checks.append(VerifyCheck(name="manifest-integrity", passed=True))

    # 2. Manifest signature (chain-master)
    try:
        verify_ecdsa_p256(
            public_key_pem=chain_master_pem,
            message=manifest_bytes,
            signature=bundle_signature,
        )
        checks.append(VerifyCheck(name="manifest-signature", passed=True))
    except (InvalidSignatureError, UnsupportedKeyError) as exc:
        checks.append(VerifyCheck(name="manifest-signature", passed=False, detail=str(exc)))
        return _finalize(checks, skipped=list(DOCUMENTED_SKIPS))

    # JSON parse — only after the bytes were authenticated above.
    envelope: Optional[Dict[str, Any]] = None
    inclusion: Optional[Dict[str, Any]] = None
    sth: Optional[Dict[str, Any]] = None
    try:
        envelope = json.loads(files["envelope.json"])
        inclusion = json.loads(files["inclusion-proof.json"])
        sth = json.loads(files["sth.json"])
    except json.JSONDecodeError as exc:
        checks.append(VerifyCheck(name="json-parseable", passed=False, detail=str(exc)))
        return _finalize(checks, skipped=list(DOCUMENTED_SKIPS))
    checks.append(VerifyCheck(name="json-parseable", passed=True))

    # 3. Envelope hash matches the inclusion proof leaf
    env_hash = envelope_hash(envelope)
    expected_leaf_hash = leaf_hash(env_hash)
    inclusion_leaf_hash = inclusion.get("leaf_hash")
    if inclusion_leaf_hash:
        prefix = inclusion_leaf_hash
        if prefix.startswith("sha256:"):
            prefix = prefix[len("sha256:") :]
        if bytes.fromhex(prefix) != expected_leaf_hash:
            checks.append(
                VerifyCheck(
                    name="envelope-hash",
                    passed=False,
                    detail="envelope hash does not match inclusion proof leaf hash",
                )
            )
            return _finalize(checks, envelope=_strip_salt(envelope), skipped=list(DOCUMENTED_SKIPS))
    checks.append(VerifyCheck(name="envelope-hash", passed=True))

    # 4. Inclusion proof reconstructs the STH root
    try:
        verify_inclusion(
            leaf_index=int(inclusion["leaf_index"]),
            tree_size=int(inclusion["tree_size"]),
            leaf_hash_bytes=expected_leaf_hash,
            audit_path=list(inclusion.get("audit_path", [])),
            expected_root=sth["root_hash"],
        )
        checks.append(VerifyCheck(name="inclusion-proof", passed=True))
    except (MerkleVerificationError, KeyError, ValueError) as exc:
        checks.append(VerifyCheck(name="inclusion-proof", passed=False, detail=str(exc)))
        return _finalize(
            checks,
            envelope=_strip_salt(envelope),
            tree_size=int(inclusion.get("tree_size", 0) or 0),
            skipped=list(DOCUMENTED_SKIPS),
        )

    # 5. STH signature
    try:
        verify_ecdsa_p256(
            public_key_pem=chain_master_pem,
            message=sth_signing_payload(sth),
            signature=sth["signature"],
        )
        checks.append(VerifyCheck(name="sth-signature", passed=True))
    except (InvalidSignatureError, UnsupportedKeyError) as exc:
        checks.append(VerifyCheck(name="sth-signature", passed=False, detail=str(exc)))
        return _finalize(
            checks,
            envelope=_strip_salt(envelope),
            tree_size=int(sth.get("tree_size", 0) or 0),
            skipped=list(DOCUMENTED_SKIPS),
        )

    # 6. TSA timestamp — SKIPPED in v1. Loud, never silent.
    tsa_present = "timestamp.tsr" in files
    checks.append(
        VerifyCheck(
            name="tsa-timestamp",
            passed=False,
            skipped=True,
            detail=(
                "TSA token verification is not implemented in v1; the bundle "
                + ("includes" if tsa_present else "omits")
                + " a timestamp.tsr file. Treat this as a non-pass for any "
                "policy that requires a trusted external timestamp."
            ),
        )
    )

    # Issuer public key sanity (record only — does not gate validity in v1).
    try:
        verify_ecdsa_p256(
            public_key_pem=issuer_pem,
            message=b"_keycheck",
            signature=b"\x00",
        )
    except UnsupportedKeyError as exc:
        checks.append(VerifyCheck(name="issuer-key-format", passed=False, detail=str(exc)))
        return _finalize(
            checks,
            envelope=_strip_salt(envelope),
            tree_size=int(sth.get("tree_size", 0) or 0),
            attestation_id=str(envelope.get("attestation_id")),
            issuer_id=str(envelope.get("issuer_id")),
            skipped=list(DOCUMENTED_SKIPS),
        )
    except InvalidSignatureError:
        # Expected — the dummy signature does not verify. The point is that
        # the key parsed as a P-256 SPKI; the dummy verify call exercises that.
        checks.append(VerifyCheck(name="issuer-key-format", passed=True))

    return _finalize(
        checks,
        envelope=_strip_salt(envelope),
        attestation_id=str(envelope.get("attestation_id")),
        issuer_id=str(envelope.get("issuer_id")),
        tree_size=int(sth.get("tree_size", 0) or 0),
        skipped=list(DOCUMENTED_SKIPS),
    )


def _finalize(
    checks: List[VerifyCheck],
    *,
    envelope: Optional[Dict[str, Any]] = None,
    attestation_id: Optional[str] = None,
    issuer_id: Optional[str] = None,
    tree_size: Optional[int] = None,
    skipped: Optional[List[str]] = None,
) -> VerifyResult:
    skipped = skipped if skipped is not None else []
    actual_skipped = [c.name for c in checks if c.skipped]
    skipped_match = sorted(actual_skipped) == sorted(skipped)
    non_skipped_pass = all(c.passed for c in checks if not c.skipped)
    valid = bool(non_skipped_pass and skipped_match)
    return VerifyResult(
        valid=valid,
        checks=checks,
        attestation_id=attestation_id,
        issuer_id=issuer_id,
        tree_size=tree_size,
        skipped_checks=actual_skipped,
        envelope=envelope,
    )
