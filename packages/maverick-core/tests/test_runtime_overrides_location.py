"""Where the dashboard overlay file lives: resolved per call, never frozen at import.

``runtime-overrides.toml`` carries the deployment's tool deny-list, model
allow-list/pins, spend cap and MCP servers. It was located by ``data_dir()``
evaluated once at import, so a home, tenant floor or client binding established
after import was ignored and the file stayed wherever the import happened to
land. It is now resolved on every call.

The overlay is DELIBERATELY still deployment-wide: a request- or run-scoped
workspace (``set_tenant`` / ``tenant_scope``) does not move it. Moving it would
stop a global admin's tool denies from applying inside workspaces, and in
per-user isolation mode would make a global admin's settings apply only to that
admin. Making workspaces carry their own layered overlay is an owner decision
(see the ``test_workspace_scope_does_not_move_the_deployment_overlay`` pin).

These scenarios run in a fresh interpreter because the suite-wide fixture pins
``OVERRIDES_PATH`` for every test, which would hide an import-time freeze.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path


def _run(tmp_path: Path, body: str, **extra_env: str) -> dict:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("MAVERICK_", "ANTHROPIC_"))
    }
    env["HOME"] = env["USERPROFILE"] = str(tmp_path / "home")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(body)],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_overlay_follows_a_home_chosen_after_import(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    out = _run(
        tmp_path,
        """
        import json, os
        from pathlib import Path
        os.environ["MAVERICK_HOME"] = os.environ["LW_FIRST"]
        from maverick import runtime_overrides as ro
        os.environ["MAVERICK_HOME"] = os.environ["LW_SECOND"]
        ro.disable_tool("shell")
        print(json.dumps({
            "first": (Path(os.environ["LW_FIRST"]) / "runtime-overrides.toml").exists(),
            "second": (Path(os.environ["LW_SECOND"]) / "runtime-overrides.toml").exists(),
            "denied": sorted(ro.denied_tools()),
        }))
        """,
        LW_FIRST=str(first),
        LW_SECOND=str(second),
    )
    assert out == {"first": False, "second": True, "denied": ["shell"]}


def test_overlay_refuses_to_guess_when_its_location_cannot_be_resolved(tmp_path):
    out = _run(
        tmp_path,
        """
        import json, os
        os.environ["MAVERICK_HOME"] = os.environ["LW_HOME"]
        from maverick import runtime_overrides as ro
        os.environ["MAVERICK_TENANT"] = "x" * 400  # cannot be a path segment
        try:
            result = {"denied": sorted(ro.denied_tools())}
        except ro.RuntimeOverridesSecurityError as exc:
            result = {"refused": type(exc).__name__}
        print(json.dumps(result))
        """,
        LW_HOME=str(tmp_path / "home-x"),
    )
    # An unlocatable policy file must fail closed like an unreadable one, not
    # read as "no deny-list" (tool_acl swallows every other exception type).
    assert out == {"refused": "RuntimeOverridesSecurityError"}


def test_workspace_scope_does_not_move_the_deployment_overlay(tmp_path):
    out = _run(
        tmp_path,
        """
        import json, os
        from pathlib import Path
        os.environ["MAVERICK_HOME"] = os.environ["LW_HOME"]
        from maverick import runtime_overrides as ro
        from maverick.paths import tenant_scope
        home = Path(os.environ["LW_HOME"])
        ro.disable_tool("shell")                # deployment administrator
        with tenant_scope(tenant="acme"):       # a goal running in a workspace
            inside_denied = sorted(ro.denied_tools())
            ro.set_budget(1.5)                  # a global-gated save while a workspace is selected
        print(json.dumps({
            "inside_denied": inside_denied,
            "budget": ro.budget_override(),
            "shared_file": (home / "runtime-overrides.toml").exists(),
            "workspace_file": (home / "tenants" / "acme" / "runtime-overrides.toml").exists(),
        }))
        """,
        LW_HOME=str(tmp_path / "home-y"),
    )
    assert out == {
        "inside_denied": ["shell"],
        "budget": 1.5,
        "shared_file": True,
        "workspace_file": False,
    }


def test_last_known_good_policy_is_kept_per_file(monkeypatch, tmp_path):
    from maverick import runtime_overrides as ro

    first, second = tmp_path / "a.toml", tmp_path / "b.toml"
    monkeypatch.setattr(ro, "OVERRIDES_PATH", first)
    ro.disable_tool("shell")
    assert ro.denied_tools() == {"shell"}

    # Another location has never held a policy: it is empty, not "a valid
    # policy that disappeared".
    monkeypatch.setattr(ro, "OVERRIDES_PATH", second)
    assert ro.denied_tools() == set()

    monkeypatch.setattr(ro, "OVERRIDES_PATH", first)
    first.write_text("[security\n", encoding="utf-8")  # damaged: keep the last good policy
    assert ro.denied_tools() == {"shell"}
