"""Verify a `.dpiv-bundle` file end-to-end and print the per-check report.

Usage:
    python examples/verify_bundle.py path/to/attestation.dpiv-bundle

Exits non-zero if the bundle is not valid.
"""

from __future__ import annotations

import sys
from pathlib import Path

from deepidv_chain import verify_bundle


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    bundle_path = Path(sys.argv[1])
    if not bundle_path.is_file():
        print(f"not a file: {bundle_path}", file=sys.stderr)
        return 2

    result = verify_bundle(bundle_path.read_bytes())

    print(f"bundle:        {bundle_path}")
    print(f"valid:         {result.valid}")
    if result.attestation_id:
        print(f"attestation:   {result.attestation_id}")
    if result.issuer_id:
        print(f"issuer:        {result.issuer_id}")
    if result.tree_size is not None:
        print(f"tree size:     {result.tree_size}")
    print(f"skipped:       {', '.join(result.skipped_checks) or '<none>'}")
    print()
    print(f"{'check':<26} {'status':<10} detail")
    print("-" * 80)
    for check in result.checks:
        status = "skipped" if check.skipped else ("passed" if check.passed else "FAILED")
        detail = (check.detail or "").replace("\n", " ")
        print(f"{check.name:<26} {status:<10} {detail}")

    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
