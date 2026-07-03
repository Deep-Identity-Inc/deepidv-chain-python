"""Async equivalent of registry_search.py — useful when you want to issue
several queries concurrently.

Usage:
    python examples/registry_search_async.py
"""

from __future__ import annotations

import argparse
import asyncio
import os

from deepidv_chain import AsyncClient


async def page_through(client: AsyncClient, filters: dict) -> int:
    total = 0
    cursor = None
    while True:
        page = await client.list_registry(filters, cursor=cursor)
        for summary in page.items:
            print(
                f"{summary.attestation_id}  "
                f"{summary.record_type}  "
                f"{summary.issuer_id}  "
                f"{summary.issued_at}"
            )
            total += 1
        if page.next_cursor:
            cursor = page.next_cursor
        else:
            return total


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-type", default="IDV")
    args = parser.parse_args()

    api_url = os.environ.get("DEEPIDV_API_URL", "https://staging-api.deepidv.com")
    api_key = os.environ.get("DEEPIDV_API_KEY")

    async with AsyncClient(api_url, api_key=api_key) as chain:
        # Two concurrent reads as a demo: one paged search, one log snapshot.
        search_task = asyncio.create_task(page_through(chain, {"record_type": args.record_type}))
        log_task = asyncio.create_task(chain.get_log())

        total, log = await asyncio.gather(search_task, log_task)

    print(f"\n{total} attestation(s); log holds {len(log.segments)} active segment(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
