"""sha256sum-compatible manifest helpers.

A manifest line is ``"<hex>  <path>\\n"`` — exactly two spaces, lower-case hex.
This matches GNU coreutils' ``sha256sum`` output so that anyone can verify
a bundle with ``sha256sum -c manifest.txt`` without our SDK.
"""

import hashlib
import re
from typing import Dict, List, Tuple

_LINE_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")


class ManifestParseError(ValueError):
    """Raised when a manifest line fails sha256sum-compatible parsing."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render_manifest(entries: Dict[str, bytes]) -> bytes:
    """Render a sha256sum-compatible manifest from path → content bytes.

    Paths are emitted in lexicographic order so the output is deterministic.
    """
    lines = []
    for path in sorted(entries):
        digest = sha256_hex(entries[path])
        lines.append(f"{digest}  {path}\n")
    return "".join(lines).encode("utf-8")


def parse_manifest(manifest_bytes: bytes) -> List[Tuple[str, str]]:
    """Parse manifest bytes into a list of ``(sha256_hex, path)`` tuples.

    Order is preserved. Empty trailing lines are skipped. Raises
    :class:`ManifestParseError` on the first non-conforming line.
    """
    text = manifest_bytes.decode("utf-8")
    out: List[Tuple[str, str]] = []
    for lineno, raw in enumerate(text.split("\n"), start=1):
        if not raw:
            continue
        m = _LINE_RE.match(raw)
        if not m:
            raise ManifestParseError(f"line {lineno}: not sha256sum-compatible: {raw!r}")
        out.append((m.group(1), m.group(2)))
    return out
