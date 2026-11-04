"""Power-user keymap.

A validated keybinding layer for the TUI surfaces: actions (quit, refresh,
expand, collapse, focus next/prev, toggle follow) bound to keys via
``[tui.keys]`` in config, with the safety rails an *editor* needs —
:func:`validate` rejects conflicts (two actions on one key), unknown
actions, and rebinding of the reserved interrupt (Ctrl-C stays the
emergency exit no matter what), so a typo can't brick the TUI. ``python -m
maverick.keymap`` lists the effective bindings and lints a config.

``resolve()`` merges defaults < config; :func:`handle_key` is the pure
key→action adapter the monitor/focus model consume (composes with
``tui_mouse.FocusModel``). Key names: single printable characters or the
``f1``-``f12`` / ``up``/``down``/``left``/``right``/``tab``/``enter``/
``esc`` names.
"""
from __future__ import annotations

import os

ACTIONS = ("quit", "refresh", "expand", "collapse", "focus_next",
           "focus_prev", "toggle_follow")

DEFAULTS: dict[str, str] = {
    "quit": "q",
    "refresh": "r",
    "expand": "enter",
    "collapse": "esc",
    "focus_next": "down",
    "focus_prev": "up",
    "toggle_follow": "f",
}

_NAMED_KEYS = {"up", "down", "left", "right", "tab", "enter", "esc",
               *{f"f{i}" for i in range(1, 13)}}
RESERVED = {"ctrl+c"}  # the emergency exit can never be rebound


def _valid_key(key: str) -> bool:
    k = key.strip().lower()
    return (len(k) == 1 and k.isprintable()) or k in _NAMED_KEYS


def validate(bindings: dict) -> list[str]:
    """Lint a ``[tui.keys]`` mapping (action -> key). [] == OK."""
    problems: list[str] = []
    seen: dict[str, str] = {}
    for action, key in (bindings or {}).items():
        if action not in ACTIONS:
            problems.append(f"unknown action {action!r} (known: {ACTIONS})")
            continue
        k = str(key).strip().lower()
        if k in RESERVED:
            problems.append(f"{action}: {k!r} is reserved (emergency exit)")
            continue
        if not _valid_key(k):
            problems.append(f"{action}: invalid key {key!r}")
            continue
        if k in seen:
            problems.append(
                f"conflict: {action!r} and {seen[k]!r} both bound to {k!r}")
            continue
        seen[k] = action
    return problems


def _config_bindings() -> dict:
    env = os.environ.get("MAVERICK_TUI_KEYS", "").strip()
    if env:
        # "quit=x,refresh=g" — the env escape hatch
        out = {}
        for pair in env.split(","):
            if "=" in pair:
                a, _, k = pair.partition("=")
                out[a.strip()] = k.strip()
        return out
    try:
        from .config import load_config
        return ((load_config() or {}).get("tui") or {}).get("keys") or {}
    except Exception:  # pragma: no cover -- config never bricks the TUI
        return {}


def resolve() -> dict[str, str]:
    """Effective bindings: defaults overridden by VALID config entries only.

    Invalid/conflicting overrides are dropped (defaults kept) — a bad config
    degrades to the stock keymap rather than an unusable one.
    """
    merged = dict(DEFAULTS)
    overrides = _config_bindings()
    if not overrides:
        return merged
    candidate = dict(merged)
    for action, key in overrides.items():
        if action in ACTIONS:
            candidate[action] = str(key).strip().lower()
    if validate(candidate):
        return merged  # any conflict in the merged result -> stock keymap
    return candidate


def handle_key(key: str, *, bindings: dict[str, str] | None = None) -> str | None:
    """Map a pressed key to its action under the effective bindings."""
    b = bindings or resolve()
    k = (key or "").strip().lower()
    for action, bound in b.items():
        if bound == k:
            return action
    return None


def render(bindings: dict[str, str] | None = None) -> str:
    b = bindings or resolve()
    lines = ["TUI keymap (override via [tui.keys] / MAVERICK_TUI_KEYS):"]
    for action in ACTIONS:
        lines.append(f"  {b.get(action, '?'):>6}  {action}")
    lines.append("  ctrl+c  (reserved: emergency exit, not rebindable)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.keymap")
    p.add_argument("--validate", action="store_true",
                   help="lint the configured [tui.keys]; exit 1 on problems")
    args = p.parse_args(argv)
    if args.validate:
        problems = validate({**DEFAULTS, **_config_bindings()})
        for prob in problems:
            print(f"INVALID: {prob}")
        return 1 if problems else 0
    print(render())
    return 0


__all__ = ["ACTIONS", "DEFAULTS", "RESERVED", "validate", "resolve",
           "handle_key", "render"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
