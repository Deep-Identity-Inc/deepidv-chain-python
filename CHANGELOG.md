# Changelog

All notable changes to `deepidv-chain` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-02

The first production release of the Python SDK for the deepidv chain layer.

### Added
- `Client` — synchronous read-only client over `httpx`, with context-manager close.
- `AsyncClient` — asynchronous variant, public surface mirrors `Client`.
- Read endpoints: `get_attestation`, `list_registry`, `get_issuer`, `get_segment`, `list_sths`, `get_consistency_proof`, `get_log`, `download_bundle`.
- `stream_attestations()` — Server-Sent Events iterator with exponential-backoff auto-reconnect and `Last-Event-ID` resumption.
- `verify_bundle(bytes) -> VerifyResult` — offline `.dpiv-bundle` verification implementing the documented 5-of-6 contract (TSA timestamp loud-skipped in v1).
- Pydantic v2 models for envelope, STH, bundle, registry, log, and stream events.
- Typed error hierarchy: `DeepidvApiError` base; `DeepidvAuthError`, `DeepidvNotFoundError`, `DeepidvRateLimitError` (with `retry_after_seconds`), `DeepidvServerError`.
- RFC 8785 JCS canonicalization with cross-language parity fixtures (`tests/fixtures/jcs-vectors.json`).
- RFC 6962 Merkle inclusion + consistency primitives.
- ECDSA P-256 verify over PEM SubjectPublicKeyInfo via `cryptography`.
- sha256sum-compatible manifest helpers.
- `py.typed` marker; passes `mypy --strict`.
- Python 3.9 → 3.13 supported.

### Notes
- The 0.0.1 placeholder published earlier reserved the `deepidv-chain` name on PyPI. v1.0.0 is the first usable release; do not depend on 0.0.1.
- Mint, revoke, and issuer-key signing are NOT exposed by this SDK — those are server-side, gated behind tenant API keys, and remain on the M02 backend surface. This SDK is the *consumer* side: read the registry, stream the log, verify offline.
- TSA timestamp verification is intentionally not implemented in v1. Bundles that ship `timestamp.tsr` will have it carried through but never silently treated as a pass. Track [#tsa-v2] for the trusted-timestamp work.

[1.0.0]: https://github.com/deep-identity-inc/deepidv-chain-python/releases/tag/v1.0.0
