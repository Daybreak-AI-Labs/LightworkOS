"""Containment-mode resolver.

Turn a coarse containment *level* into the concrete restrictions an executor
should apply, and answer whether a specific action is permitted at that level.
Pure policy — no side effects, no shell. Three levels, increasingly locked down:

  - off     — no extra restrictions (everything allowed).
  - network — deny network egress; the filesystem is left as-is.
  - full    — "no-network ephemeral fs": deny network, ephemeral filesystem,
              run in a throwaway tmp workdir, and withhold credentials.

ops:
  - plan(level)            — structured list of restrictions for that level.
  - check(action, level)   — ALLOW/DENY for one action at that level.

Known actions: http_fetch, dns_lookup, send_email (network);
write_file, persist_state (filesystem persistence); read_secret, use_credential
(credentials); read_file, compute (always-local). Unknown actions fail-OPEN
(ALLOW) at off/network — those levels make only a targeted promise — but
fail-CLOSED (DENY) at full: the maximal containment level is a comprehensive
lockdown, so anything it can't classify is denied by default.
"""
from __future__ import annotations

from typing import Any

from . import Tool

_LEVELS = ("off", "network", "full")

# Restriction descriptors keyed by level, most→least permissive.
_RESTRICTIONS: dict[str, list[str]] = {
    "off": [],
    "network": ["network: deny all egress"],
    "full": [
        "network: deny all egress",
        "filesystem: ephemeral (changes discarded on exit)",
        "workdir: throwaway tmp directory",
        "credentials: none injected (scrubbed env)",
    ],
}

# Action -> the category it belongs to. A level denies a category when its
# restriction list mentions it.
_NETWORK_ACTIONS = {"http_fetch", "dns_lookup", "send_email", "network"}
_PERSIST_ACTIONS = {"write_file", "persist_state", "save", "commit"}
_CRED_ACTIONS = {"read_secret", "use_credential", "read_credential"}
_LOCAL_ACTIONS = {"read_file", "compute", "list_dir"}


def _norm_level(level: Any) -> str | None:
    lvl = str(level or "").strip().lower()
    return lvl if lvl in _LEVELS else None


def _plan(level: str) -> str:
    items = _RESTRICTIONS[level]
    if not items:
        return f"level: {level}\nrestrictions: none (no containment)"
    body = "\n".join(f"- {r}" for r in items)
    return f"level: {level}\nrestrictions:\n{body}"


def _check(action: str, level: str) -> str:
    act = action.strip().lower()
    if not act:
        return "ERROR: action is required"
    if level == "full":
        denies_net = denies_persist = denies_creds = True
    elif level == "network":
        denies_net, denies_persist, denies_creds = True, False, False
    else:  # off
        denies_net = denies_persist = denies_creds = False

    if act in _NETWORK_ACTIONS:
        return _verdict(denies_net, act, level, "network egress denied")
    if act in _PERSIST_ACTIONS:
        return _verdict(denies_persist, act, level,
                        "filesystem persistence denied (ephemeral fs)")
    if act in _CRED_ACTIONS:
        return _verdict(denies_creds, act, level,
                        "credential access denied (no creds injected)")
    if act in _LOCAL_ACTIONS:
        return f"ALLOW {act} at level={level}: local, no restriction applies"
    # Unknown action: fail-CLOSED at the maximal containment level (``full``),
    # whose contract is a comprehensive lockdown — an unclassified action can't
    # be assumed safe there. Lower levels make only targeted promises (egress at
    # ``network``, nothing at ``off``), so they fail-open and say so.
    if level == "full":
        return (f"DENY {act} at level={level}: unknown action, fail-closed "
                "(full containment denies unclassified actions)")
    return f"ALLOW {act} at level={level}: unknown action, no policy (fail-open)"


def _verdict(denied: bool, act: str, level: str, reason: str) -> str:
    if denied:
        return f"DENY {act} at level={level}: {reason}"
    return f"ALLOW {act} at level={level}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op not in (None, "plan", "check"):
        return f"ERROR: unknown op {op!r} (expected plan or check)"
    level = _norm_level(args.get("level"))
    if level is None:
        return "ERROR: level must be one of off|network|full"
    if op == "check":
        action = args.get("action")
        if not isinstance(action, str) or not action.strip():
            return "ERROR: action (string) is required for op=check"
        return _check(action, level)
    return _plan(level)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["plan", "check"]},
        "level": {"type": "string", "enum": ["off", "network", "full"]},
        "action": {"type": "string",
                   "description": "action to check (e.g. http_fetch, write_file)"},
    },
    "required": ["level"],
}


def containment_mode() -> Tool:
    return Tool(
        name="containment_mode",
        description=(
            "Resolve a containment level into concrete restrictions, or check "
            "an action against it. Levels: off | network (deny egress) | full "
            "(no-network ephemeral fs, tmp workdir, no creds). op=plan(level) "
            "returns the restriction list; op=check(action, level) returns "
            "ALLOW/DENY for an action like 'http_fetch' or 'write_file'. Pure "
            "policy, deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
