"""Follow the live attestation stream via Server-Sent Events.

Usage:
    python examples/sse_stream.py

Press Ctrl-C to exit. The iterator reconnects automatically on transient
disconnects and replays Last-Event-ID so the server can resume.
"""

from __future__ import annotations

import asyncio
import os

from deepidv_chain import AsyncClient


async def main() -> int:
    api_url = os.environ.get("DEEPIDV_API_URL", "https://staging-api.deepidv.com")
    api_key = os.environ.get("DEEPIDV_API_KEY")

    async with AsyncClient(api_url, api_key=api_key) as chain:
        async for event in chain.stream_attestations():
            if event.event == "heartbeat":
                # Quiet heartbeats — print one tick per minute or so depending
                # on the server cadence. Drop entirely if you want signal only.
                print(".", end="", flush=True)
                continue
            attestation_id = event.data.get("attestation_id", "?")
            print(
                f"\n[{event.event}] id={event.id} attestation={attestation_id}"
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nbye")
