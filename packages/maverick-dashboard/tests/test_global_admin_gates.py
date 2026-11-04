"""A route that writes a deployment-global sink must use the global gate.

The bug this pins: ``POST /users/set`` wrote ``dashboard-users.json`` -- the
deployment-wide RBAC roster, at ``maverick_home()/dashboard-users.json`` with no
tenant segment -- behind ``auth.require_permission``, which honours tenant
memberships. ``auth.require_global_permission`` exists precisely because
"tenant memberships are intentionally ignored so a tenant-local admin cannot
satisfy global admin gates" (auth.has_global_permission). So a tenant-local
admin could call it and assign themselves a global role in one request; the same
mismatch let one write an attacker-controlled provider ``base_url`` into the
deployment-global config overlay, routing every tenant's prompts through them.

The inconsistency was visible inside one file: ``/users/suites/set`` used the
global gate while ``/users/set``, two routes above it, did not.

This test is written as an INVARIANT rather than a list of route names, because
a list is what drifted. It derives the requirement from the write sink: if a
handler calls a mutator on a module whose store is deployment-global, the gate
must be the global one. Adding a route that writes a global sink therefore fails
here without anyone remembering to update a list.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ADMIN_PAGES = (
    Path(__file__).resolve().parents[1]
    / "maverick_dashboard" / "admin_pages.py"
)

#: Modules whose stores carry no tenant segment, verified by reading them:
#:   rbac.store_path()      -> maverick_home()/dashboard-users.json
#:   invites.store_path()   -> maverick_home()/dashboard-invites.json
#:   settings_store._write  -> config.dashboard_overrides_path(), which is
#:                             config_path().parent/<basename>
#:   suite_grants, ui_visibility -> same maverick_home() root
#:   runtime_overrides      -> overrides_path(), resolved per call at the
#:                             operator floor (MAVERICK_HOME / MAVERICK_TENANT /
#:                             client binding). A workspace selected for a
#:                             request deliberately does not move it: the
#:                             overlay is deployment-wide policy every
#:                             workspace runs under, so the sink is global and
#:                             the gate must match. A per-workspace overlay
#:                             would be a separate, layered design.
GLOBAL_SINK_MODULES = frozenset({
    "rbac", "invites", "settings_store", "suite_grants", "ui_visibility",
    "runtime_overrides",
})

#: Mutators on those modules. Read-only helpers are irrelevant here.
MUTATOR_PREFIXES = ("set_", "clear_", "remove_", "revoke_", "create_",
                    "delete_", "update_", "save_", "write_", "rotate_", "apply_")

MUTATING_METHODS = frozenset({"post", "put", "patch", "delete"})


def _routes() -> list[tuple[str, str, ast.AST]]:
    """(method, path, function-node) for every mutating route in admin_pages."""
    tree = ast.parse(ADMIN_PAGES.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for d in node.decorator_list:
            if (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                    and d.func.attr in MUTATING_METHODS and d.args
                    and isinstance(d.args[0], ast.Constant)):
                out.append((d.func.attr.upper(), d.args[0].value, node))
    return out


def _global_sinks_written(fn: ast.AST) -> set[str]:
    """Global-sink mutators this handler calls, as ``module.function``."""
    imports = {}
    for imp in ast.walk(fn):
        if isinstance(imp, ast.ImportFrom) and imp.module:
            module = imp.module.rsplit(".", 1)[-1]
            if module in GLOBAL_SINK_MODULES:
                for item in imp.names:
                    imports[item.asname or item.name] = (module, item.name)
    found = set()
    for c in ast.walk(fn):
        if not isinstance(c, ast.Call):
            continue
        target = c.func
        # Moving blocking I/O off the event loop must not hide its write sink.
        call_name = getattr(target, "id", None) or getattr(target, "attr", None)
        if call_name in {"run_in_threadpool", "to_thread", "run_sync"} and c.args:
            target = c.args[0]
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            mod, name = target.value.id, target.attr
        elif isinstance(target, ast.Name) and target.id in imports:
            mod, name = imports[target.id]
        else:
            continue
        if mod in GLOBAL_SINK_MODULES and name.startswith(MUTATOR_PREFIXES):
            found.add(f"{mod}.{name}")
    return found


@pytest.mark.parametrize("body,expected", [
    ("rbac.set_role('user:alice', 'viewer')", {"rbac.set_role"}),
    ("await run_in_threadpool(rbac.set_role, 'user:alice', 'viewer')", {"rbac.set_role"}),
    ("await run_in_threadpool(settings_store.rotate_provider, 'provider')", {"settings_store.rotate_provider"}),
    ("await asyncio.to_thread(ui_visibility.apply_selection, set())", {"ui_visibility.apply_selection"}),
    ("from maverick.runtime_overrides import set_budget as save\nawait run_in_threadpool(save, 10)", {"runtime_overrides.set_budget"}),
    ("from maverick.runtime_overrides import clear_budget\nawait anyio.to_thread.run_sync(clear_budget)", {"runtime_overrides.clear_budget"}),
    ("await run_in_threadpool(settings_store.state)", set()),
])
def test_global_sink_scan_follows_worker_calls(body, expected):
    handler = ast.parse("async def handler():\n" + "\n".join("    " + line for line in body.splitlines())).body[0]
    assert _global_sinks_written(handler) == expected


def _gates(fn: ast.AST) -> set[str]:
    return {
        c.func.attr if isinstance(c.func, ast.Attribute) else c.func.id
        for c in ast.walk(fn)
        if isinstance(c, ast.Call)
        and (getattr(c.func, "attr", None) or getattr(c.func, "id", None))
        in {"require_permission", "require_global_permission"}
    }


#: Workspace invitations write the shared invite store, but each invite is bound
#: to one workspace and authorized against that exact workspace: a workspace
#: administrator may offer at most their own role there, and only that
#: workspace's administrator may cancel it. They must call the workspace gate.
WORKSPACE_SCOPED_INVITES = frozenset({
    ("POST", "/users/workspace-invite"),
    ("POST", "/users/workspace-invite/revoke"),
})


def _called(fn: ast.AST) -> set[str]:
    return {
        c.func.attr if isinstance(c.func, ast.Attribute) else c.func.id
        for c in ast.walk(fn)
        if isinstance(c, ast.Call) and isinstance(c.func, (ast.Attribute, ast.Name))
    }


ROUTES_WRITING_GLOBAL = [
    (m, p, fn, sinks) for m, p, fn in _routes()
    if (sinks := _global_sinks_written(fn))
]


def test_the_scan_actually_finds_routes() -> None:
    """Anti-vacuity: an invariant over an empty set proves nothing.

    If a refactor moves these handlers elsewhere, this fails loudly rather than
    letting the file below it pass by inspecting zero routes.
    """
    assert len(ROUTES_WRITING_GLOBAL) >= 12, [
        (m, p) for m, p, _, _ in ROUTES_WRITING_GLOBAL]


@pytest.mark.parametrize(
    "method,path,sinks",
    [(m, p, sorted(s)) for m, p, _, s in ROUTES_WRITING_GLOBAL],
    ids=[f"{m} {p}" for m, p, _, _ in ROUTES_WRITING_GLOBAL],
)
def test_global_sink_routes_use_the_global_gate(method, path, sinks) -> None:
    fn = next(f for m, p, f, _ in ROUTES_WRITING_GLOBAL if (m, p) == (method, path))
    gates = _gates(fn)
    if (method, path) in WORKSPACE_SCOPED_INVITES:
        # Checked, not waived: the exact workspace's administrator gate must run.
        assert "_workspace_invite_authority" in _called(fn), (method, path)
        return
    assert "require_global_permission" in gates, (
        f"{method} {path} writes deployment-global state ({', '.join(sinks)}) "
        f"but gates with {gates or '{nothing}'}. require_permission honours "
        "tenant memberships, so a tenant-local admin passes it -- and for a "
        "global sink that is privilege escalation. Use "
        "auth.require_global_permission(request, 'admin')."
    )


def test_the_two_gates_have_not_become_the_same_function() -> None:
    """The whole invariant rests on them differing. Pin that they still do."""
    import inspect

    from maverick_dashboard import auth

    assert inspect.getsource(auth.has_global_permission) != inspect.getsource(
        auth.has_permission)
    # The distinguishing behaviour, stated in has_global_permission's docstring.
    assert "memberships" in (auth.has_global_permission.__doc__ or "")
