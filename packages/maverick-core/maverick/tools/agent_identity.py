"""Per-agent identity + signing.

Gives each agent in the swarm a stable, derivable identity and lets it sign
the artifacts it produces so a downstream consumer (or the audit log) can
prove which agent emitted a payload and that it wasn't altered. Offline and
deterministic: a content-addressed id from name+namespace, and HMAC-SHA256
signatures over a canonical encoding of the payload.

HMAC (shared-secret) keeps this dependency-free; the format leaves room for
an asymmetric scheme later without changing the call sites.

ops:
  - id(name[, namespace])              — derive the stable agent id.
  - sign(name, key, payload)           — sign a payload, return id + signature.
  - verify(name, key, payload, signature) — VALID / INVALID.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from . import Tool

_NS = "maverick.agent"


def _agent_id(name: str, namespace: str) -> str:
    digest = hashlib.sha256(f"{namespace}:{name}".encode()).hexdigest()
    return f"agent:{digest[:16]}"


def _canonical(payload: Any) -> bytes:
    # Stable encoding so the same logical payload always signs the same way.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sign_bytes(key: str, name: str, namespace: str, payload: Any) -> str:
    msg = _agent_id(name, namespace).encode() + b"\n" + _canonical(payload)
    return hmac.new(str(key).encode(), msg, hashlib.sha256).hexdigest()


def _require(args: dict[str, Any], *keys: str) -> str:
    for k in keys:
        if k not in args or args[k] in (None, ""):
            return f"ERROR: {k} is required"
    return ""


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    namespace = str(args.get("namespace", _NS))

    if op == "id":
        if err := _require(args, "name"):
            return err
        return _agent_id(str(args["name"]), namespace)

    if op == "sign":
        if err := _require(args, "name", "key"):
            return err
        if "payload" not in args:
            return "ERROR: payload is required"
        sig = _sign_bytes(str(args["key"]), str(args["name"]), namespace, args["payload"])
        return f"id: {_agent_id(str(args['name']), namespace)}\nsignature: {sig}"

    if op == "verify":
        if err := _require(args, "name", "key", "signature"):
            return err
        if "payload" not in args:
            return "ERROR: payload is required"
        expected = _sign_bytes(str(args["key"]), str(args["name"]), namespace, args["payload"])
        ok = hmac.compare_digest(expected.encode(), str(args["signature"]).encode())
        return "VALID" if ok else "INVALID"

    return f"ERROR: unknown op {op!r} (expected id/sign/verify)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["id", "sign", "verify"]},
        "name": {"type": "string", "description": "agent name (role or instance)"},
        "namespace": {"type": "string", "description": f"identity namespace (default {_NS!r})"},
        "key": {"type": "string", "description": "shared HMAC key (sign/verify)"},
        "payload": {"description": "any JSON-serialisable payload to sign/verify"},
        "signature": {"type": "string", "description": "hex signature to verify"},
    },
    "required": ["op"],
}


def agent_identity() -> Tool:
    return Tool(
        name="agent_identity",
        description=(
            "Per-agent identity + signing, offline. op=id derives a stable "
            "agent id from name(+namespace). op=sign HMAC-signs a JSON payload "
            "(returns id + signature). op=verify checks a signature "
            "(VALID/INVALID) with a constant-time compare. Deterministic; "
            "stdlib hmac/sha256."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
