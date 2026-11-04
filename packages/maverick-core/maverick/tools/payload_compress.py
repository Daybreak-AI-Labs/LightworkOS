"""world_model compression helper.

Estimate how much a world-model payload shrinks under compression, and verify
that compression is lossless before relying on it. zstd would compress better,
but its binding may be absent, so this uses stdlib ``zlib`` (deflate) and the
helper is always available offline. ``stats`` reports original/compressed bytes
and the ratio; ``roundtrip`` checks that decompress(compress(text)) == text.
Deterministic and offline.

ops:
  - stats(text, [level])  — original/compressed bytes + ratio.
  - roundtrip(text)       — OK if compress+decompress is lossless, else FAIL.
"""
from __future__ import annotations

import zlib
from typing import Any

from . import Tool


def _stats(text: str, level: Any) -> str:
    lvl = 6 if level is None else level
    try:
        lvl = int(lvl)
    except (TypeError, ValueError):
        return "ERROR: level must be an integer in [0, 9]"
    if not 0 <= lvl <= 9:
        return "ERROR: level must be in [0, 9]"
    raw = text.encode("utf-8")
    comp = zlib.compress(raw, lvl)
    orig = len(raw)
    csize = len(comp)
    ratio = (csize / orig) if orig else 0.0
    saved = orig - csize
    pct = (saved / orig * 100.0) if orig else 0.0
    return (
        f"OK level={lvl} original={orig} compressed={csize} "
        f"ratio={ratio:.4f} saved={saved} ({pct:.1f}%)"
    )


def _roundtrip(text: str) -> str:
    raw = text.encode("utf-8")
    restored = zlib.decompress(zlib.compress(raw)).decode("utf-8")
    if restored == text:
        return f"OK lossless: {len(raw)} bytes roundtripped"
    return "FAIL: roundtrip is lossy"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op in (None, "stats"):
        text = args.get("text")
        if not isinstance(text, str):
            return "ERROR: text (string) is required"
        return _stats(text, args.get("level"))
    if op == "roundtrip":
        text = args.get("text")
        if not isinstance(text, str):
            return "ERROR: text (string) is required"
        return _roundtrip(text)
    return f"ERROR: unknown op {op!r} (expected 'stats' or 'roundtrip')"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["stats", "roundtrip"]},
        "text": {"type": "string", "description": "Payload text to compress"},
        "level": {
            "type": "integer",
            "description": "zlib compression level 0..9 (default 6; op=stats)",
        },
    },
    "required": ["text"],
}


def payload_compress() -> Tool:
    return Tool(
        name="payload_compress",
        description=(
            "world_model compression helper (stdlib zlib, zstd-substitute). "
            "op=stats with 'text' and optional 'level' (0..9) reports original/"
            "compressed bytes and ratio. op=roundtrip with 'text' verifies "
            "compress+decompress is lossless (OK/FAIL). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
