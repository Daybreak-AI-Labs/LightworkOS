"""Supply-chain pinning tool — flag unpinned/unhashed dependencies.

Audit a dependency list against a pinning policy: every package should carry an
exact version (no version ranges) and, optionally, an integrity hash. This is
the building block for "all deps must be pinned and hashed before release".
Deterministic and offline; pure inspection of the supplied list. No disk.

ops:
  - check(deps[, policy])  — OK or VIOLATIONS with the offending packages.

policy: ``{"require_hash": bool}`` (default True). Version ranges are always a
violation (a pin must be exact).
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

# Operators/markers that turn a "version" into a range/wildcard rather than a
# pin. NOTE: 'x'/'X' are wildcards only as a whole version *component*
# (e.g. '1.x', '1.2.X'), never as an incidental letter inside a real version
# (e.g. '1.0.0+linux', '2.0.0b1xenial') -- matched separately below as a token
# so an exact pin that merely contains the letter x isn't a false positive.
# Bare '=' is intentionally NOT here: pip's exact pin is '==1.0.0' (and '==='),
# which must read as a PIN, not a range. '>'/'<' already catch '>='/'<=', '~'
# catches '~='/'~1.0', and '!=' is an explicit exclusion range.
_RANGE_CHARS = ("^", "~", ">", "<", "*", "!=", "||", " - ")
# A component that is exactly 'x'/'X' (start-of-string or after a '.'), i.e. the
# wildcard forms '1.x' / '1.2.x' / 'x'. Avoids flagging 'x' inside a token.
_WILDCARD_X_RE = re.compile(r"(?:^|\.)[xX](?:\.|$)")


def _is_range(version: str) -> bool:
    v = version.strip()
    if not v:
        return False
    if any(tok in v for tok in _RANGE_CHARS):
        return True
    return _WILDCARD_X_RE.search(v) is not None


def _check(args: dict[str, Any]) -> str:
    deps = args.get("deps")
    if not isinstance(deps, list):
        return "ERROR: deps must be an array of {name, version, hash?}"
    policy = args.get("policy") or {}
    if not isinstance(policy, dict):
        return "ERROR: policy must be an object"
    require_hash = bool(policy.get("require_hash", True))

    violations: list[str] = []
    checked = 0
    for dep in deps:
        if not isinstance(dep, dict):
            violations.append("entry is not an object {name, version, hash?}")
            continue
        name = str(dep.get("name") or "").strip()
        if not name:
            violations.append("entry missing name")
            continue
        checked += 1
        version = str(dep.get("version") or "").strip()
        if not version:
            violations.append(f"{name}: unpinned (no version)")
        elif _is_range(version):
            violations.append(f"{name}: version range/wildcard {version!r} is not a pin")
        if require_hash:
            h = str(dep.get("hash") or "").strip()
            if not h:
                violations.append(f"{name}: unhashed (no integrity hash)")

    if violations:
        body = "\n".join(f"- {v}" for v in violations)
        return f"VIOLATIONS: {len(violations)} issue(s) across {checked} package(s)\n{body}"
    return f"OK: {checked} package(s) pinned" + (" and hashed" if require_hash else "")


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r} (expected check)"
    if not isinstance(args.get("deps"), list):
        return "ERROR: deps (array of {name, version, hash?}) is required"
    return _check(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "deps": {
            "type": "array",
            "description": "dependencies; each {name, version, hash?}",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                    "hash": {"type": "string"},
                },
                "required": ["name"],
            },
        },
        "policy": {
            "type": "object",
            "description": "{require_hash: bool} (default true)",
            "properties": {"require_hash": {"type": "boolean"}},
        },
    },
    "required": ["deps"],
}


def supply_chain_pin() -> Tool:
    return Tool(
        name="supply_chain_pin",
        description=(
            "Audit dependency pinning. op=check with 'deps' (each {name, version, "
            "hash?}) and optional 'policy' {require_hash: bool, default true}. "
            "Flags unpinned (no version), version-range/wildcard "
            "(^,~,>,<,*,=,x,||,-), and unhashed packages. Returns OK or "
            "VIOLATIONS listing the offenders. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
