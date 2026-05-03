# deepidv-chain

Python SDK for the [deepidv](https://proof.deepidv.com) chain layer — read the public attestation registry, follow the transparency log, and verify offline `.dpiv-bundle` archives end-to-end.

```bash
pip install deepidv-chain
```

- **Sync and async** clients (`Client`, `AsyncClient`) over [httpx](https://www.python-httpx.org/).
- **Offline bundle verification** (`verify_bundle`) — RFC 6962 inclusion + RFC 8785 envelope hash + ECDSA P-256 manifest and STH signatures.
- **Pydantic v2** models throughout. Fully typed (`py.typed`), passes `mypy --strict`.
- **Cross-language parity** with the Node SDK ([@deepidv/chain](https://www.npmjs.com/package/@deepidv/chain)): byte-identical hashes for the same fixtures.
- **Python 3.9 → 3.13.**

## Quickstart — sync

```python
from deepidv_chain import Client

with Client("https://staging-api.deepidv.com") as chain:
    # Pull a single attestation by id.
    attestation = chain.get_attestation("attest_01J9X9YQ7W7N2T0M5K8P3R4Q6V")
    print(attestation.record_type, attestation.issuer_id)

    # Page through the public registry.
    page = chain.list_registry({"record_type": "IDV"})
    for summary in page.items:
        print(summary.attestation_id, summary.issued_at)

    # Download the offline-verifiable bundle.
    bundle_bytes = chain.download_bundle(attestation.attestation_id)
```

## Quickstart — async

```python
import asyncio
from deepidv_chain import AsyncClient

async def main():
    async with AsyncClient("https://staging-api.deepidv.com") as chain:
        log = await chain.get_log()
        for segment in log.segments:
            print(segment.segment_id, segment.tree_size)

asyncio.run(main())
```

## Streaming — Server-Sent Events

```python
async with AsyncClient() as chain:
    async for event in chain.stream_attestations():
        print(event.event, event.id, event.data)
```

The iterator reconnects with exponential backoff on transient disconnects and replays `Last-Event-ID` so the server can resume. Pass `max_reconnect_attempts=0` to disable reconnection.

## Offline bundle verification

```python
from deepidv_chain import verify_bundle

with open("attestation.dpiv-bundle", "rb") as f:
    result = verify_bundle(f.read())

if result.valid:
    print("verified:", result.attestation_id)
else:
    for check in result.checks:
        if not check.passed and not check.skipped:
            print(f"FAIL {check.name}: {check.detail}")
```

`verify_bundle` runs a **5-of-6** contract end-to-end:

1. Manifest integrity (sha256sum-compatible).
2. Manifest signature (chain-master ECDSA P-256).
3. Envelope hash (`sha256(JCS(envelope))`).
4. RFC 6962 inclusion proof reconstructs the STH root.
5. STH signature (chain-master ECDSA P-256 over the JCS-canonical unsigned form).
6. **TSA timestamp — SKIPPED in v1.** Reported as `skipped=True, passed=False`. The detail string explicitly notes whether `timestamp.tsr` was present or absent. **Never silently treated as a pass.** If your policy requires a trusted external timestamp, treat the skip as a non-pass and gate accordingly.

`result.envelope` is the envelope dict with the per-record privacy salt stripped — safe to render directly. The full envelope (with salt) is what the verifier hashes; do not reconstruct it from `result.envelope` for a re-hash.

## Errors

```python
from deepidv_chain import (
    DeepidvApiError,         # base
    DeepidvAuthError,        # 401 / 403
    DeepidvNotFoundError,    # 404
    DeepidvRateLimitError,   # 429 (carries .retry_after_seconds)
    DeepidvServerError,      # 5xx
)
```

Every error carries `status_code`, `url`, `body`, and `request_id` (from the `x-request-id` response header).

## Type checking

The package ships a `py.typed` marker and is fully type-annotated. The typed surface lives at `deepidv_chain` (top-level re-exports) and `deepidv_chain.types`.

```python
from deepidv_chain import AttestationDetail, RegistryFilters
```

## Configuration

```python
Client(
    api_url="https://api.proof.deepidv.com",   # default: staging-api.deepidv.com
    api_key="dpiv_live_...",                   # bearer token; optional for public reads
    timeout=30.0,                              # httpx timeout
    user_agent="my-app/1.0",                   # appended User-Agent
    http_client=my_pre_configured_httpx,       # inject your own httpx.Client
)
```

The same kwargs apply to `AsyncClient` (with `httpx.AsyncClient`).

## Cross-language parity

Hashes computed by this SDK are byte-identical to those computed by [@deepidv/chain](https://www.npmjs.com/package/@deepidv/chain) for the same logical input. The shared parity fixtures live in `tests/fixtures/jcs-vectors.json` and `tests/fixtures/envelope-hashes.json`. If you discover a divergence, file an issue with the offending input — both SDKs gate releases on parity.

## Privacy

- Bundle-verify return values **never** include the per-record privacy salt.
- `claim_hash` is `sha256` over the JCS-canonical claim and is intentionally one-way.
- The SDK never logs claim bodies, salts, or signatures.

## License

Apache-2.0. See [LICENSE](./LICENSE).

## Links

- Public surface: [proof.deepidv.com](https://proof.deepidv.com)
- API host: `https://api.proof.deepidv.com` (staging: `https://staging-api.deepidv.com`)
- Node SDK: [`@deepidv/chain`](https://www.npmjs.com/package/@deepidv/chain) on npm
- Repo: [github.com/deep-identity-inc/deepidv-chain-python](https://github.com/deep-identity-inc/deepidv-chain-python)
