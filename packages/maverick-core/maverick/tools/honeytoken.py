"""Honeytoken planting + tripwire.

Mint decoy secrets (canary tokens) that look like real credentials but are
never valid, then detect them in any text the agent is about to send or store.
If a planted token ever shows up in output, exfiltration is in progress —
deterministic tripwire, no model. The token format is recognizable by its
fixed prefix so detection needs only the prefix, not a stored list.

ops:
  - mint([label], [kind])  — return a fresh decoy token.
  - scan(text)             — report any honeytokens found in text.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any

from . import Tool

_PREFIX = "MAVHT"  # Lightwork HoneyToken — the recognizable, never-valid marker.
_KINDS = {"aws", "api", "pat", "generic"}
_TOKEN_RE = re.compile(re.escape(_PREFIX) + r"_[A-Za-z0-9_]+")


def _mint(label: str, kind: str) -> str:
    rnd = secrets.token_hex(12)
    # A short keyed digest binds the label so a found token can be traced back.
    tag = hashlib.sha256(f"{kind}:{label}:{rnd}".encode()).hexdigest()[:8]
    token = f"{_PREFIX}_{kind}_{rnd}{tag}"
    return f"OK minted honeytoken (label={label!r}, kind={kind}): {token}"


def _scan(text: str) -> str:
    # Match the token prefix ANYWHERE, not just as a whitespace-delimited word
    # after edge-trimming: a honeytoken embedded in structured text (JSON
    # "k":"MAVHT_...", key=MAVHT_..., Bearer MAVHT_..., ?q=MAVHT_...) is a word
    # whose interior separators str.split()/strip() left attached, so the
    # tripwire silently failed to fire for the most common exfil shapes.
    hits = _TOKEN_RE.findall(text)
    if not hits:
        return "CLEAN: no honeytokens present"
    uniq = sorted(set(hits))
    return (f"TRIPPED: {len(uniq)} honeytoken(s) found — possible exfiltration:\n- "
            + "\n- ".join(uniq))


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op in (None, "mint"):
        label = str(args.get("label", "default")).strip() or "default"
        kind = str(args.get("kind", "generic")).strip().lower()
        if kind not in _KINDS:
            return f"ERROR: kind must be one of {sorted(_KINDS)}"
        return _mint(label, kind)
    if op == "scan":
        text = args.get("text")
        if not isinstance(text, str) or not text:
            return "ERROR: text is required for scan"
        return _scan(text)
    return f"ERROR: unknown op {op!r}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["mint", "scan"]},
        "label": {"type": "string", "description": "Trace label for a minted token"},
        "kind": {"type": "string", "enum": sorted(_KINDS)},
        "text": {"type": "string", "description": "Text to scan for honeytokens"},
    },
}


def honeytoken() -> Tool:
    return Tool(
        name="honeytoken",
        description=(
            "Mint decoy credentials (canary tokens) and detect them. op=mint "
            "([label],[kind: aws|api|pat|generic]) returns a never-valid token; "
            "op=scan with 'text' returns CLEAN or TRIPPED if a planted token "
            "appears (exfiltration tripwire). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
