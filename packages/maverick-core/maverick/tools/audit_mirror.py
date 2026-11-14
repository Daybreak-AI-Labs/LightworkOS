"""Independent audit-log mirror verification.

Cross-check a primary audit log against an independent mirror: do the two
agree entry-for-entry (same hash at each sequence number), and is the sequence
gap-free (no missing seq, no duplicates)? A tamper-evidence check — if one copy
is altered or an entry is dropped, the two diverge. Pure, deterministic, offline.

ops:
  - verify(primary, mirror)  — CONSISTENT, or DIVERGED with the first problem.

Each list holds ``{seq, hash}`` entries. ``seq`` is an integer; entries are
ordered by ``seq`` before comparison so input order doesn't matter. Gap-freeness
is checked over the union of sequence numbers.
"""
from __future__ import annotations

from itertools import pairwise
from typing import Any

from . import Tool


def _index(entries: list[dict], side: str) -> dict[int, str] | str:
    out: dict[int, str] = {}
    for e in entries:
        if not isinstance(e, dict):
            return f"ERROR: each {side}[] entry must be an object {{seq, hash}}"
        try:
            seq = int(e.get("seq"))
        except (TypeError, ValueError):
            return f"ERROR: {side} entry has a non-integer 'seq'"
        if "hash" not in e:
            return f"ERROR: {side} entry seq={seq} is missing 'hash'"
        if seq in out:
            return f"DIVERGED: duplicate seq={seq} in {side}"
        out[seq] = str(e.get("hash"))
    return out


def _verify(primary: list[dict], mirror: list[dict]) -> str:
    p = _index(primary, "primary")
    if isinstance(p, str):
        return p
    m = _index(mirror, "mirror")
    if isinstance(m, str):
        return m

    all_seqs = sorted(set(p) | set(m))
    if not all_seqs:
        return "CONSISTENT: both logs empty (0 entries)"

    # Gap check across the full observed range.
    # Scan the sorted list for the first hole instead of materializing the
    # whole range: two model-supplied seqs far apart must not allocate memory
    # proportional to their distance.
    lo, hi = all_seqs[0], all_seqs[-1]
    for prev, cur in pairwise(all_seqs):
        if cur != prev + 1:
            return f"DIVERGED: sequence gap — seq={prev + 1} missing (range {lo}..{hi})"

    # Entry-for-entry agreement.
    for seq in all_seqs:
        if seq not in p:
            return f"DIVERGED: seq={seq} present in mirror but missing from primary"
        if seq not in m:
            return f"DIVERGED: seq={seq} present in primary but missing from mirror"
        if p[seq] != m[seq]:
            return (f"DIVERGED: hash mismatch at seq={seq} "
                    f"(primary={p[seq]!r}, mirror={m[seq]!r})")

    return f"CONSISTENT: {len(all_seqs)} entries agree, gap-free (seq {lo}..{hi})"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "verify"):
        return f"ERROR: unknown op {args.get('op')!r} (expected verify)"
    primary = args.get("primary")
    mirror = args.get("mirror")
    if not isinstance(primary, list):
        return "ERROR: primary (array of {seq, hash}) is required"
    if not isinstance(mirror, list):
        return "ERROR: mirror (array of {seq, hash}) is required"
    return _verify(primary, mirror)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["verify"]},
        "primary": {
            "type": "array",
            "description": "primary audit log; each {seq, hash}",
            "items": {
                "type": "object",
                "properties": {
                    "seq": {"type": "integer"},
                    "hash": {"type": "string"},
                },
                "required": ["seq", "hash"],
            },
        },
        "mirror": {
            "type": "array",
            "description": "independent mirror; each {seq, hash}",
            "items": {
                "type": "object",
                "properties": {
                    "seq": {"type": "integer"},
                    "hash": {"type": "string"},
                },
                "required": ["seq", "hash"],
            },
        },
    },
    "required": ["primary", "mirror"],
}


def audit_mirror() -> Tool:
    return Tool(
        name="audit_mirror",
        description=(
            "Verify a primary audit log against an independent mirror. "
            "op=verify with 'primary' and 'mirror' (each an array of {seq, "
            "hash}). Sorts by seq, checks the two agree entry-for-entry and the "
            "sequence is gap-free, and returns CONSISTENT or DIVERGED naming the "
            "first hash mismatch, gap, or duplicate. Tamper-evidence check; "
            "pure, deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
