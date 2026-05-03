"""Page through the public registry synchronously and print every match.

Usage:
    python examples/registry_search.py [--record-type IDV] [--issuer iss_acme]

Defaults to https://staging-api.deepidv.com. Set DEEPIDV_API_URL to override.
"""

from __future__ import annotations

import argparse
import os
import sys

from deepidv_chain import Client


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-type", default=None)
    parser.add_argument("--issuer", default=None, dest="issuer_id")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    api_url = os.environ.get("DEEPIDV_API_URL", "https://staging-api.deepidv.com")
    api_key = os.environ.get("DEEPIDV_API_KEY")

    filters = {
        "record_type": args.record_type,
        "issuer_id": args.issuer_id,
        "limit": args.limit,
    }

    total = 0
    cursor = None
    with Client(api_url, api_key=api_key) as chain:
        while True:
            page = chain.list_registry(filters, cursor=cursor)
            for summary in page.items:
                print(
                    f"{summary.attestation_id}  "
                    f"{summary.record_type}  "
                    f"{summary.issuer_id}  "
                    f"{summary.issued_at}  "
                    f"revoked={summary.revoked}"
                )
                total += 1
            if page.next_cursor:
                cursor = page.next_cursor
            else:
                break

    print(f"\n{total} attestation(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
