# M08 — Python SDK (`deepidv-chain`) — initial v1.0.0

## Discovery summary

Branch cut from `main` at `c72849b` (Initial commit). Repo state was
the 0.0.1 PyPI placeholder: `pyproject.toml` on setuptools, a
`src/deepidv_chain/__init__.py` exposing only `__version__`, an
Apache-2.0 LICENSE, and the README pointing at the public repo. Local
sibling `deepidv-chain-node` was also a 0.0.1 placeholder, so this
build follows the surface described in the M08 prompt directly. Full
discovery doc: `claude-code/discovery/M08.md`.

## Files added

| Area | Files |
| --- | --- |
| Package | `src/deepidv_chain/__init__.py`, `py.typed`, `errors.py`, `client.py`, `verify.py` |
| Types | `src/deepidv_chain/types/{__init__,envelope,sth,bundle,api}.py` |
| Crypto | `src/deepidv_chain/crypto/{__init__,jcs,envelope_hash,sth_hash,manifest,merkle,ecdsa_verify}.py` |
| Internal | `src/deepidv_chain/_internal/{__init__,http}.py` |
| Tests | `tests/__init__.py`, `tests/_bundle_helpers.py`, `tests/test_{manifest,merkle,ecdsa_verify,client,verify}.py`, `tests/parity/{__init__,test_jcs_vectors,test_envelope_hash}.py`, `tests/fixtures/{jcs-vectors,envelope-hashes}.json` |
| Examples | `examples/{verify_bundle,registry_search,registry_search_async,sse_stream}.py` |
| CI | `.github/workflows/{ci,publish}.yml` |
| Docs | `README.md` (rewrite), `CHANGELOG.md`, `docs/handoffs/M08-luka-verification.md`, `claude-code/discovery/M08.md`, `claude-code/handoff/M08-PR-body.md` |
| Tooling | `pyproject.toml` (rewrite), `.gitignore` |

## Files modified

| File | Change | Diff size |
| --- | --- | --- |
| `pyproject.toml` | Replaced 0.0.1 setuptools placeholder with v1.0.0 hatchling config + ruff/mypy/pytest sections | ~115 lines |
| `README.md` | Replaced placeholder with full v1 docs | ~140 lines |
| `src/deepidv_chain/__init__.py` | Replaced placeholder with public re-exports | ~55 lines |

## Files NOT modified

- `LICENSE` — Apache-2.0, untouched.
- `dist/` (placeholder 0.0.1 artifacts) — moved to `.gitignore`, not
  deleted from the working tree by this PR.

## Test coverage delta

| Module | Tests |
| --- | --- |
| `crypto/jcs.py` + `crypto/envelope_hash.py` | 11 cross-language parity vectors (`tests/parity/`) |
| `crypto/manifest.py` | 4 round-trip + parser-rejection tests |
| `crypto/merkle.py` | 5 RFC 6962 inclusion / consistency tests |
| `crypto/ecdsa_verify.py` | 3 happy-path + tamper + non-P-256 rejection tests |
| `client.py` (sync + async) | 12 respx-mocked tests covering every read endpoint, all four error mappings, SSE parser, query encoding, auth header toggle |
| `verify.py` | 9 end-to-end bundle tests covering happy path, every tamper vector, salt strip, and TSA loud-skip wording |

**Total: 44 tests, all passing locally on Python 3.9.6. ruff + mypy
strict both clean.**

## Impact on production

**Zero impact on the chain backend or any deployed surface.** This PR
is a brand-new public SDK on its own repo; it does not touch the
`ChainStack` CDK code, any Lambda handler, any DynamoDB table, or any
EventBridge rule. It does not change the public API contract — it
*consumes* it. `FEATURE_CHAIN=on/off` is irrelevant; the SDK can talk
to any cluster that exposes `/v1/*` endpoints.

The only externally visible side effect of merging this PR is that
PyPI will gain a `deepidv-chain==1.0.0` release once a `v1.0.0` tag is
pushed, and the Node SDK's parity claim becomes a verifiable, tested
property.

## Open decisions (full detail in §6 of the Luka handoff)

The following structural calls were made mid-flight to align with M07
without stopping to ask:

1. `httpx` runtime dep instead of stdlib `urllib` — needed for SSE +
   sync/async parity at reasonable code size.
2. Pydantic v2 instead of `dataclasses` — wire validation + extras
   tolerance.
3. `Client` / `AsyncClient` class names instead of `Chain` —
   convergent with `openai`, `anthropic`, etc.
4. Mint / revoke / issuer signing intentionally NOT in v1 — those
   require issuer-key custody or tenant API keys not yet provisioned.
   v1 ships read + verify only.
5. No `dpiv` CLI in v1 — example scripts cover the smoke-test surface;
   CLI lands once mint + revoke do.
6. Build backend hatchling instead of setuptools — perf + clean
   configuration; no consumer-visible difference.
7. Verify check ordering: manifest integrity BEFORE JSON parse.
8. Verify never raises for bundle-side problems; only `TypeError` for
   programmer-error inputs.
9. Non-gating `issuer-key-format` check in verify_bundle for
   diagnosability.

## Acceptance checklist

- [x] Discovery doc at `claude-code/discovery/M08.md`.
- [x] Apache-2.0 license preserved.
- [x] Hash parity test passes against the shared fixture.
- [x] README structurally mirrors `@deepidv/chain` (install, quickstart,
  verify, errors, types, parity, privacy, license).
- [x] mypy strict passes.
- [x] Zero references to Arc / UAIIP / getai.id in the published
  package surface.
- [x] Zero references to deeprisk, deepsign, "DeepIDV", "Deep IDV",
  Dallas, Toronto, Truly in user-facing strings.
- [x] `python -m build` + `twine check` both pass locally.
- [ ] PyPI publish — held until verification per Luka handoff §5 and
  Shawn-Marc sign-off per runbook §5.

## STOPs that need Shawn-Marc

1. **PyPI publish** — held. Cut `v1.0.0` tag when ready; `publish.yml`
   takes it from there. Requires `PYPI_TOKEN` configured outside this
   session.
2. **Push branch + open PR** — branch lives locally on
   `chain/08-sdk-pip`. The remote slug should be confirmed
   (`deep-identity-inc` per `pyproject.toml`, or `deepidv` per the
   runbook §1 module table) before pushing. If the canonical slug is
   different, update the URLs in `pyproject.toml`, `README.md`, and
   `CHANGELOG.md` in a follow-up commit before tagging.
3. **Optional yank of 0.0.1** — purely cosmetic; the PyPI UI handles
   this manually post-1.0.0 if desired.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
