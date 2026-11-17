"""Copilot reads and changes a code project's test commands and protected
paths through the Code page's own functions in ``code_actions_api``: the same
administrator check, the same limits and refusals, the same audit record, and
the saved values read back afterwards."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import code_actions_api as native
from .auth import require_permission
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_PAGES = ("/code",)
_FAMILY = "tasks"
# The Code page's labels, in its order.
_LABELS = {"quick_test_command": "Quick tests", "test_command": "All tests",
           "gate_command": "Other checks", "heavy_test_command": "Tests that need services",
           "protected_paths": "Protected paths"}


class Checks(StrictInput):
    """A missing value is kept and an empty one is cleared, as on the page.
    The vault's own checks set the limits, so they give the page's message."""
    name: str = Field(min_length=1, max_length=64)
    quick_test_command: str | None = Field(default=None, max_length=10_000)
    test_command: str | None = Field(default=None, max_length=10_000)
    gate_command: str | None = Field(default=None, max_length=10_000)
    heavy_test_command: str | None = Field(default=None, max_length=10_000)
    protected_paths: str | None = Field(default=None, max_length=40_000)


def _projects() -> list[dict]:
    from maverick.codebase import vault
    if not vault.enabled():
        return []
    return [native._commands(repo) for repo in vault.list_repos()]


def _words(row: dict) -> dict:
    """One project's commands and protected paths in the page's words."""
    paths = ", ".join(row["protected_paths"])
    return {"Code project": row["name"],
            **{label: (paths if key == "protected_paths" else row[key]) or "None"
               for key, label in _LABELS.items()}}


def _state(request) -> list[dict]:
    require_permission(request, "admin")
    return _projects()


def _snapshot(rows: list[dict], *, fields=()) -> Snapshot:
    from maverick.codebase import vault
    blocked = ("Code projects are turned off." if not vault.enabled() else
               "" if rows else "Add a code project on the Code page first.")
    summary = (f"{len(rows)} code project(s). A change to a protected path needs a second "
               "checker and two people to approve it.")
    return Snapshot(digest(rows), "Current code projects' test commands and protected paths",
                    summary, {"Code projects": [_words(row) for row in rows]},
                    fields=list(fields), blocked=blocked)


def show_snapshot(request, _selection):
    return _snapshot(_state(request))


def show_prepare(request, selection, _arguments):
    return Preview("Current test commands and protected paths", native=show_snapshot(request, selection).details)


def set_snapshot(request, _selection):
    rows = _state(request)
    first = rows[0] if rows else None
    fields = [{"name": "name", "label": "Code project", "kind": "select",
               "value": first["name"] if first else "",
               "choices": [{"value": row["name"], "label": row["name"]} for row in rows]}]
    for key, label in _LABELS.items():
        value = (", ".join(first[key]) if key == "protected_paths" else first[key]) if first else ""
        fields.append({"name": key, "label": f"{label} (optional)", "kind": "text", "value": value})
    fields[-1]["label"] = "Protected paths, separated by commas (optional)"
    return _snapshot(rows, fields=fields)


def _change(arguments: dict) -> tuple[dict, list[str] | None]:
    """The page's request body: commands as given, paths split at commas."""
    given = {key: arguments[key] for key in _LABELS
             if key != "protected_paths" and arguments.get(key) is not None}
    raw = arguments.get("protected_paths")
    paths = None if raw is None else [p.strip() for p in raw.split(",") if p.strip()]
    return given, paths


def set_prepare(request, _selection, arguments):
    given, paths = _change(arguments)
    native.check_commands_change(request, arguments["name"], given, paths)
    row = next(row for row in _state(request) if row["name"] == arguments["name"])
    before = _words(row)
    after = _words({**row, **{k: v.strip(" ") for k, v in given.items()},
                    **({} if paths is None else {"protected_paths": paths})})
    changes = [{"field": label, "before": before[label], "after": after[label]}
               for label in _LABELS.values() if before[label] != after[label]]
    if not changes:
        raise HTTPException(422, "These are the same as now. Nothing was changed.")
    return Preview(f"Change the test commands and protected paths for {row['name']}. "
                   "Changes apply to the next change Lightwork builds.", changes=changes)


def set_execute(request, _selection, arguments, _review, _operation):
    given, paths = _change(arguments)
    native.apply_commands_change(request, arguments["name"], given, paths)
    saved = next(row for row in _state(request) if row["name"] == arguments["name"])
    return Outcome("confirmed", f"The test commands and protected paths for {saved['name']} are saved.",
                   _words(saved))


def entries():
    return (
        Adapter("code.checks.show", "Show code projects' test commands and protected paths", _FAMILY,
                "/code", _PAGES, EmptyInput, show_snapshot, show_prepare,
                aliases=("show protected paths", "show test commands")),
        Adapter("code.checks.set", "Change a code project's test commands and protected paths", _FAMILY,
                "/code", _PAGES, Checks, set_snapshot, set_prepare, set_execute,
                aliases=("set protected paths", "change protected paths", "change test commands")),
    )
