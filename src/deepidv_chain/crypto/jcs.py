"""JSON Canonicalization Scheme (RFC 8785) implementation.

This is the same canonicalization that ``shared-deps`` and the TypeScript SDK
use. It produces UTF-8 bytes that any JCS-compliant implementation in any
language MUST also produce for the same logical input.

Key rules:

- Object members are emitted in lexicographic order of UTF-16 code units of
  the JSON-encoded key (RFC 8785 §3.2.3). For ASCII keys this matches a normal
  Python ``sorted(...)``; for non-BMP keys we sort on the UTF-16 surrogate
  pair encoding to stay correct.
- Numbers are serialized via ECMA-404 / IEEE-754 → ECMAScript ``Number.toString``
  semantics (RFC 8785 §3.2.2). For integers in the safe-integer range we emit
  the decimal integer; for floats we use Python's ``repr`` and then normalize
  to match ECMAScript output (e.g. ``1e+21`` ↔ ``1e+21``, ``-0`` → ``0``).
- Strings are JSON-encoded with the smallest legal escape set (RFC 8785 §3.2.4).
- ``None`` → ``null``, ``True`` → ``true``, ``False`` → ``false``.
- ``NaN`` / ``Infinity`` are not valid JSON and raise.
"""

import math
import re
from typing import Any, Tuple

# Characters that MUST be escaped per RFC 8785 §3.2.4.
_ESCAPE_TABLE = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def jcs_canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical JSON byte string for ``value``.

    Raises:
        ValueError: if ``value`` contains a NaN, +Inf, -Inf, or an unsupported
            type (e.g. set, bytes, custom object without a JSON repr).
    """

    return _encode(value).encode("utf-8")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, bool):  # pragma: no cover - handled above
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _encode_number(value)
    if isinstance(value, list) or isinstance(value, tuple):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = list(value.keys())
        for k in keys:
            if not isinstance(k, str):
                raise ValueError(f"JCS object keys must be strings, got {type(k).__name__}")
        keys.sort(key=_sort_key)
        return "{" + ",".join(_encode_string(k) + ":" + _encode(value[k]) for k in keys) + "}"
    raise ValueError(f"JCS cannot encode value of type {type(value).__name__}")


def _sort_key(key: str) -> Tuple[int, ...]:
    """Sort key as the sequence of UTF-16 code units (RFC 8785 §3.2.3)."""
    encoded = key.encode("utf-16-be")
    return tuple(int.from_bytes(encoded[i : i + 2], "big") for i in range(0, len(encoded), 2))


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _ESCAPE_TABLE.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_number(n: float) -> str:
    if math.isnan(n):
        raise ValueError("JCS cannot encode NaN")
    if math.isinf(n):
        raise ValueError("JCS cannot encode Infinity")
    if n == 0:
        # Normalize -0.0 → 0
        return "0"
    if n == int(n) and abs(n) < 1e16:
        # Whole-number floats serialize as integers in ECMAScript Number.toString
        return str(int(n))
    # Match ECMAScript Number.toString: shortest decimal that round-trips.
    # Python's `repr` is shortest-round-trip for floats since 3.1.
    s = repr(n)
    # Normalize exponent form: Python emits "1e+21", ECMAScript emits "1e+21" — same.
    # Python emits "1e-07", ECMAScript emits "1e-7" — strip the leading zero.
    s = re.sub(r"e([+-])0*(\d)", r"e\1\2", s)
    # Python may emit "1.0" for 1.0; ECMAScript emits "1". Already handled above.
    return s
