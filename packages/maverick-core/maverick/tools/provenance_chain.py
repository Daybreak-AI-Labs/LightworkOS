"""Provenance chain tool — verify a tamper-evident chain of agent actions.

Each link records {actor, action, prev_hash} plus a content hash computed as
sha256("actor|action|prev_hash"). The chain starts from a genesis prev_hash of
64 zeros; every subsequent link's prev_hash must equal the previous link's
recomputed content hash. This catches reordering, edits, or forged links.
Deterministic and offline; pure stdlib (hashlib.sha256). No disk.

ops:
  - verify(links)  -> VALID, or BROKEN at the first bad link.
"""
from __future__ import annotations

import hashlib
from typing import Any

from . import Tool

_GENESIS = "0" * 64


def _content_hash(actor: str, action: str, prev_hash: str) -> str:
    msg = f"{actor}|{action}|{prev_hash}".encode()
    return hashlib.sha256(msg).hexdigest()


def _verify(args: dict[str, Any]) -> str:
    links = args.get("links")
    if not isinstance(links, list):
        return "ERROR: links must be an array of {actor, action, prev_hash, hash?}"
    if not links:
        return "ERROR: links must be non-empty"

    expected_prev = _GENESIS
    for i, link in enumerate(links):
        if not isinstance(link, dict):
            return f"BROKEN: link {i} is not an object"
        actor = str(link.get("actor") or "").strip()
        action = str(link.get("action") or "").strip()
        if not actor or not action:
            return f"BROKEN: link {i} missing actor/action"
        prev = str(link.get("prev_hash") or "").strip()
        if prev != expected_prev:
            return (
                f"BROKEN: link {i} ({actor}/{action}) prev_hash mismatch "
                f"(expected {expected_prev[:12]}..., got {prev[:12]}...)"
            )
        computed = _content_hash(actor, action, prev)
        # If the link carries its own content hash, it must match what we recompute.
        stated = link.get("hash")
        if stated is not None and str(stated).strip().lower() != computed:
            return f"BROKEN: link {i} ({actor}/{action}) content hash mismatch"
        expected_prev = computed

    return f"VALID: {len(links)} link(s), head {expected_prev[:12]}..."


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "verify"):
        return f"ERROR: unknown op {args.get('op')!r} (expected verify)"
    if not isinstance(args.get("links"), list):
        return "ERROR: links (array of {actor, action, prev_hash, hash?}) is required"
    return _verify(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["verify"]},
        "links": {
            "type": "array",
            "description": "ordered chain; each {actor, action, prev_hash, hash?}",
            "items": {
                "type": "object",
                "properties": {
                    "actor": {"type": "string"},
                    "action": {"type": "string"},
                    "prev_hash": {"type": "string"},
                    "hash": {"type": "string"},
                },
                "required": ["actor", "action", "prev_hash"],
            },
        },
    },
    "required": ["links"],
}


def provenance_chain() -> Tool:
    return Tool(
        name="provenance_chain",
        description=(
            "Verify a tamper-evident provenance chain of agent actions. op=verify "
            "with 'links' (each {actor, action, prev_hash, hash?}). Recomputes "
            "sha256('actor|action|prev_hash') per link and checks linkage from a "
            "genesis of 64 zeros. Returns VALID or BROKEN at the first bad link. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
