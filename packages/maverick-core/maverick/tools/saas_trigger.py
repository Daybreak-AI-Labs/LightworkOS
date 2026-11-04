"""Generic SaaS-trigger framework.

Turn an inbound SaaS webhook into a Lightwork goal, safely. ``verify`` checks the
delivery's HMAC signature (constant-time) so a forged payload can't drive the
swarm, and ``route`` maps an event type to the goal that should handle it via
glob patterns (most-specific wins). Deterministic; offline; pure stdlib
(hmac + hashlib + fnmatch). No disk, no network.

ops:
  - verify(secret, payload, signature[, algo=sha256]) -> VALID / INVALID.
  - route(event_type, routes={pattern: goal}) -> the matched goal, or none.

The signature is compared as a lowercase hex digest; an optional ``algo=`` prefix
on the signature (e.g. ``sha256=...``, GitHub style) is stripped before compare.
"""
from __future__ import annotations

import hashlib
import hmac
from fnmatch import fnmatchcase
from typing import Any

from . import Tool

# hashlib constructors we accept for the HMAC. Restricting the set keeps an
# attacker from selecting a weird/weak digest by name.
_ALGOS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}


def _verify(args: dict[str, Any]) -> str:
    secret = args.get("secret")
    payload = args.get("payload")
    signature = args.get("signature")
    if not isinstance(secret, str) or not secret:
        return "ERROR: secret is required"
    if not isinstance(payload, str):
        return "ERROR: payload (string) is required"
    if not isinstance(signature, str) or not signature.strip():
        return "ERROR: signature is required"
    algo = str(args.get("algo") or "sha256").strip().lower()
    if algo not in _ALGOS:
        return f"ERROR: unsupported algo {algo!r} (sha1, sha256, sha512)"

    presented = signature.strip()
    # Accept a GitHub-style "algo=hexdigest" prefix.
    if "=" in presented:
        prefix, _, rest = presented.partition("=")
        if prefix.strip().lower() in _ALGOS:
            presented = rest.strip()
    presented = presented.lower()

    expected = hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), _ALGOS[algo]
    ).hexdigest()
    if hmac.compare_digest(expected.encode(), presented.encode()):
        return f"VALID: {algo} signature"
    return "INVALID: signature mismatch"


def _route(args: dict[str, Any]) -> str:
    event_type = args.get("event_type")
    routes = args.get("routes")
    if not isinstance(event_type, str) or not event_type.strip():
        return "ERROR: event_type is required"
    if not isinstance(routes, dict) or not routes:
        return "ERROR: routes ({pattern: goal}) is required"
    event = event_type.strip()

    # Most-specific pattern wins: rank candidates by literal (non-wildcard)
    # length so "issues.opened" beats "issues.*" beats "*".
    matches: list[tuple[int, str]] = []
    for pattern, goal in routes.items():
        pat = str(pattern)
        if fnmatchcase(event, pat):
            specificity = sum(1 for c in pat if c not in "*?[]")
            matches.append((specificity, str(goal)))
    if not matches:
        return f"NONE: no route for {event!r}"
    matches.sort(key=lambda m: m[0], reverse=True)
    return f"ROUTE: {matches[0][1]}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "verify":
        return _verify(args)
    if op == "route":
        return _route(args)
    return f"ERROR: unknown op {op!r} (expected verify or route)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["verify", "route"]},
        "secret": {"type": "string", "description": "shared HMAC secret for op=verify"},
        "payload": {"type": "string", "description": "raw request body for op=verify"},
        "signature": {"type": "string", "description": "presented signature for op=verify"},
        "algo": {"type": "string", "enum": ["sha1", "sha256", "sha512"], "description": "HMAC digest (default sha256)"},
        "event_type": {"type": "string", "description": "event name for op=route"},
        "routes": {
            "type": "object",
            "description": "for op=route; {glob-pattern: goal}",
            "additionalProperties": {"type": "string"},
        },
    },
    "required": ["op"],
}


def saas_trigger() -> Tool:
    return Tool(
        name="saas_trigger",
        description=(
            "Generic SaaS-webhook trigger framework. op=verify {secret, payload, "
            "signature, algo?=sha256} -> VALID/INVALID (constant-time HMAC). "
            "op=route {event_type, routes:{pattern: goal}} -> the matched goal "
            "(fnmatch; most-specific wins) or NONE. Deterministic; offline; "
            "stdlib hmac+hashlib+fnmatch only."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
