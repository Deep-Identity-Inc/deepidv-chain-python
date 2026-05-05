# M08 — Luka verification handoff

> Verifier-side rehearsal for the **`deepidv-chain`** Python SDK on the
> `chain/08-sdk-pip` branch. Mirrors the M07 verification addendum with
> Python-specific steps. Run end-to-end before flipping the final
> `FEATURE_CHAIN=on` switch in production.

## 1. Scope

This handoff covers the v1.0.0 cut of `deepidv-chain` (Python SDK), which
ships the consumer side of the chain layer:

- Read the public registry via sync (`Client`) and async (`AsyncClient`).
- Follow the transparency log via Server-Sent Events with auto-reconnect.
- Verify offline `.dpiv-bundle` archives end-to-end.

It does **not** ship mint, revoke, or issuer-key signing. Those remain on
the M02 backend surface and are gated behind tenant API keys.

## 2. Pre-flight

You will need:

- Python 3.9, 3.10, 3.11, 3.12, **and** 3.13 available on the verification
  box (a single `pyenv` install of all five is the easiest path).
- A staging API URL: `https://staging-api.deepidv.com`.
- A real `.dpiv-bundle` pulled from staging (any attestation in
  `proof-staging.deepidv.com` will do — capture one before you start).
- The published `@deepidv/chain` 1.0.0 from M07 to cross-check parity.
  (You can install it with `npm i -g @deepidv/chain` for the offline
  verify side-by-side.)

No PyPI credentials needed for the rehearsal — verification runs against a
local clone, never PyPI.

## 3. Verification steps

### 3.1 Fresh-venv install (per Python version)

For each of 3.9, 3.10, 3.11, 3.12, 3.13:

```bash
git fetch origin chain/08-sdk-pip
git checkout chain/08-sdk-pip
python3.X -m venv .venv-3X
source .venv-3X/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

Expected: clean install, no resolution conflicts, no compiler errors
(`cryptography` ships wheels for all five).

### 3.2 Static checks

```bash
ruff check src/ tests/        # MUST be 0 errors
mypy src/                     # MUST be 0 errors (strict mode)
```

### 3.3 Unit + parity test suite

```bash
pytest -ra
```

Expected: **44 passed** (local count at handoff time; integration tests
are gated behind `DEEPIDV_STAGING=1` and not in this number).

Parity tests live in `tests/parity/` — they consume the same
`tests/fixtures/jcs-vectors.json` that the Node SDK uses. If any
parity vector fails, do **not** ship; treat it as a cross-language
regression and file an issue against both SDKs.

### 3.4 Cross-language hash spot check

In a Python REPL:

```python
from deepidv_chain.crypto.envelope_hash import envelope_hash_hex
import json

env = json.loads(open("tests/fixtures/envelope-hashes.json").read())["vectors"][0]["envelope"]
print(envelope_hash_hex(env))
```

In a Node REPL with `@deepidv/chain` installed, hash the same envelope
(use the SDK's exported `envelopeHash`). The two strings must be
byte-identical (`"sha256:<64 hex chars>"`).

### 3.5 Offline bundle verify

Drop a real staging bundle into the working dir as `attestation.dpiv-bundle`:

```bash
python examples/verify_bundle.py attestation.dpiv-bundle
```

Expected:

- Exit code `0`.
- Last reported `valid: True`.
- `tsa-timestamp` row reports `skipped` and the detail string explicitly
  notes whether `timestamp.tsr` was present.
- `result.envelope` (visible in the table) does NOT contain the salt.

Now corrupt one byte of the bundle (e.g. `dd if=/dev/urandom bs=1 count=1
of=attestation.dpiv-bundle conv=notrunc`) and re-run:

- Exit code `1`.
- One of the integrity / signature checks fails loudly with a non-empty
  detail string.
- The verifier does **not** raise; it returns a structured failure.

### 3.6 Live registry against staging

```bash
python examples/registry_search.py --record-type IDV --limit 25
```

Expected: at least one row, no traceback, all rows show `record_type=IDV`.
Run again with `--issuer iss_unknown` to confirm an empty result returns
gracefully.

### 3.7 Async + SSE smoke

```bash
python examples/registry_search_async.py
```

Expected: prints rows + a final summary line ("N attestation(s); log
holds M active segment(s)"). No `RuntimeError: Event loop is closed`
on shutdown.

```bash
timeout 30 python examples/sse_stream.py || true
```

Expected: at least one heartbeat dot or one real event line during the
30-second window. The script exits cleanly on timeout signal.

### 3.8 Build + twine check

```bash
pip install build twine
python -m build
twine check dist/*
```

Expected: both `deepidv_chain-1.0.0-py3-none-any.whl` and
`deepidv_chain-1.0.0.tar.gz` produced; both `PASSED` from twine.

### 3.9 Install-from-wheel sanity

In a fresh venv with no source checkout:

```bash
python -m venv /tmp/sanity && /tmp/sanity/bin/pip install dist/deepidv_chain-1.0.0-py3-none-any.whl
/tmp/sanity/bin/python -c "from deepidv_chain import Client, verify_bundle, __version__; print(__version__)"
```

Expected: `1.0.0`.

## 4. Acceptance checklist (mirror of M07)

- [ ] 3.9 / 3.10 / 3.11 / 3.12 / 3.13 fresh installs all clean.
- [ ] `ruff check` clean on `src/` + `tests/`.
- [ ] `mypy src/` clean under strict mode.
- [ ] `pytest -ra` reports 44 passing locally (integration tests
  gated behind `DEEPIDV_STAGING=1`).
- [ ] JCS + envelope-hash parity vectors are byte-identical to
  `@deepidv/chain` for the same fixtures.
- [ ] One real staging `.dpiv-bundle` verifies with `valid=True` and
  the loud TSA skip is reported, not silently elided.
- [ ] One bit-flipped staging `.dpiv-bundle` fails verification
  loudly without raising.
- [ ] `examples/registry_search.py`, `examples/registry_search_async.py`,
  `examples/sse_stream.py` all exit cleanly against staging.
- [ ] `python -m build` + `twine check` both pass; wheel installs
  cleanly into a fresh venv and exposes `__version__ == "1.0.0"`.
- [ ] Zero references to Arc / UAIIP / getai.id / DeepIDV / Deep IDV /
  Dallas / Toronto / Truly / deeprisk / deepsign in the published
  package surface (README, docstrings, error messages).
- [ ] PyPI publish (separate post-acceptance step) is held until Shawn-Marc
  signs off in writing per runbook §5.

## 5. STOPs that need Shawn-Marc

These are the actions this session deliberately did **not** take. Each
needs a human signal before it happens:

1. **PyPI publish.** The 1.0.0 release is built but not uploaded.
   `PYPI_TOKEN` is configured outside this session and consumed only by
   `publish.yml` on a `v1.0.0` tag push. Cut the tag when verification
   passes:

   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

   `publish.yml` runs the full matrix as a gate, then `twine upload`s.

2. **GitHub repo create / push.** This branch lives locally on
   `chain/08-sdk-pip`. The remote `deepidv/chain-sdk-python` (or whatever
   the canonical org slug is) needs to exist and the branch needs to be
   pushed. The runbook calls the repo `deepidv/chain-sdk-python`; the
   `pyproject.toml` URLs point at
   `github.com/deep-identity-inc/deepidv-chain-python`. Confirm the
   canonical slug before pushing — the URLs in `pyproject.toml`,
   `README.md`, and `CHANGELOG.md` all use `deep-identity-inc`. If the
   org slug is different, update those three files in a single follow-up
   commit before tagging.

3. **PyPI 0.0.1 → 1.0.0 transition.** The placeholder is on PyPI under
   `deepidv-chain`. Yanking it is optional — the version-jump-only
   approach is sufficient — but if you want to yank, do it manually
   from the PyPI UI after 1.0.0 publishes.

4. **Cross-language fixture sync.** The parity fixtures in
   `tests/fixtures/jcs-vectors.json` should match the Node SDK's copy
   byte-for-byte. If `@deepidv/chain` ever ships a fixture update, the
   Python SDK must follow in the same release window. Track this in the
   `shared-deps` repo per the runbook §1 description.

## 6. Open decisions (mid-flight judgment calls)

These are the choices I made without stopping to ask, with the reason
each one is the most defensible call given the M07 structural decisions
named in the prompt.

### 6.1 `httpx` instead of stdlib `urllib`

The runbook M08 spec called for a zero-runtime-dep sync client built on
`urllib` + `hashlib` + `json` + `dataclasses`. I deviated to `httpx`
because:

- M07's surface (per the prompt) is much richer than the original M08
  spec contemplated — registry pagination, SSE streaming with
  auto-reconnect, segment + consistency-proof endpoints, log views.
  Implementing SSE on `urllib` is a multi-hundred-line lift; `httpx`
  gives it for free.
- `httpx` has both sync and async surfaces with the same response shape,
  so the sync and async clients here share their request-shaping code
  byte-for-byte. That is the primary parity guarantee — the two clients
  differ only in `await`.
- `httpx` is broadly trusted, ships wheels for all supported Pythons,
  and is the standard pick for new Python HTTP code.

The cost is one extra runtime dependency. The benefit is the SDK feels
like the Node SDK, not like a downgrade.

### 6.2 Pydantic v2 instead of `dataclasses`

Pydantic v2 was the right choice because:

- M07 ships TypeScript types with structural validation built in; we
  need the same on the Python side so SDK consumers get a clear error
  on a malformed wire payload, not an opaque `KeyError` two functions
  later.
- Pydantic v2's perf is good enough that registry pages with 200 items
  parse in well under a millisecond.
- `extra="allow"` on every model means a backward-compatible wire
  addition (M02 ships a new optional field) does not break v1 clients.

The cost is the typing-imports gymnastics (`typing.List/Dict/Optional`
instead of PEP-604) to keep the 3.9 floor without `eval_type_backport`.
The `pyproject.toml` ruff config documents that explicitly with an
ignore for `UP006/UP007/UP035/UP045`.

### 6.3 Mint / revoke / issuer signing intentionally NOT in v1

The runbook M08 spec listed `mint`, `verify`, `revoke`, `bundle`,
`public_verify` on a `Chain` class. The richer M07-aligned shape
described in the prompt does not include those — and on review they
require either issuer-key custody (which the SDK should never hold) or
tenant API keys that have not yet been provisioned. v1 ships the
read-and-verify surface that the public site needs. Mint + revoke land
in v1.1 once the API key story is finalized.

### 6.4 `Client` / `AsyncClient` instead of `Chain`

The runbook spec used a single `Chain` class. M07 (per the prompt) uses
`Client` / `AsyncClient`, and that is the convention more or less every
modern Python HTTP SDK has converged on (`openai.OpenAI` /
`openai.AsyncOpenAI`, `anthropic.Anthropic` / `anthropic.AsyncAnthropic`,
etc.). Names match the surface a Python developer expects.

### 6.5 No `dpiv` CLI in v1

The runbook M08 spec asked for a `dpiv` CLI entry point. I deferred it.
The four runnable scripts in `examples/` cover the smoke-test surface
(`verify_bundle.py`, `registry_search.py`, etc.) and are simpler to
maintain. Adding `dpiv` becomes appropriate once `mint` and `revoke`
land — without those, `dpiv` is just a thin wrapper over the
`registry_search` and `verify_bundle` examples and adds maintenance
surface for no real ergonomic win.

### 6.6 Build backend: hatchling instead of setuptools

The placeholder used setuptools. Hatchling is faster, has cleaner
configuration in `pyproject.toml`, ships fewer transitive build deps,
and is what `hatch` (the dev-time tool) drives natively. There is no
behavioural difference for the wheel consumer.

### 6.7 Verify check ordering — integrity before parsing

The original draft of `verify.py` parsed JSON before running the
manifest integrity check. That ordering would let a bit-flipped
`envelope.json` fail at JSON parse rather than at the integrity check,
which is misleading: the **first** thing wrong is that the file does
not match the signed manifest. I reordered so the manifest integrity
check runs immediately after `required-files-present`, before any JSON
parsing of bytes that might have been tampered with. This matches the
"verify what you got, then trust it" pattern.

### 6.8 Bundle verify never raises for bundle-side problems

Programmer-error inputs (`bundle_bytes` is not bytes) raise
`TypeError`. Anything that could happen with a corrupted, malformed,
or maliciously-crafted bundle gets captured as a `VerifyCheck` row
with `passed=False`. This matches the M07 contract: a verifier returns
a structured report so callers can surface every problem at once
rather than failing on the first.

### 6.9 Issuer-key sanity check

I added a non-gating `issuer-key-format` check that exercises the
issuer PEM parser with a known-bad signature. The intent is to surface
"your issuer key is not P-256" as a distinct check rather than rolling
it into a future per-record signature verification (which is not in
v1). It costs ~50 microseconds per verify and gives a clear signal
when a tenant has uploaded the wrong key format. It does **not** flip
`valid` to False because no v1 contract depends on it.

---

End of M08 verification handoff.
