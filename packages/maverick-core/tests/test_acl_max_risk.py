"""Per-identity max-risk ceiling for tool ACLs.

A ``max_risk`` config key (global / per-channel / per-user) caps the risk
level a context may reach. Default: no ceiling, so behaviour matches the
existing per-user tool subset unless configured.
"""
from __future__ import annotations

import importlib


def _write_config(tmp_path, body: str) -> None:
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.toml").write_text(body)
    import maverick.config as cfg_mod
    importlib.reload(cfg_mod)


class _FakeSandbox:
    workdir = "."


class _FakeWorld:
    pass


# ---------- risk classification ----------

def test_tool_risk_defaults():
    from maverick.safety.tool_risk import tool_risk
    assert tool_risk("shell") == "high"
    assert tool_risk("code_exec") == "high"
    assert tool_risk("memory") == "high"
    assert tool_risk("obsidian") == "high"
    for mutating_tool in ("github_issues", "gitlab_issues", "anki"):
        assert tool_risk(mutating_tool) == "high"
    assert tool_risk("ros") == "high"
    assert tool_risk("serial") == "high"
    for connector in (
        "servicenow",
        "snowflake",
        "databricks",
        "onetrust",
        "vertex",
    ):
        assert tool_risk(connector) == "high"
    assert tool_risk("read_file") == "low"
    # Unclassified tool fails safe to high (cannot slip under a medium ceiling).
    assert tool_risk("some_unknown_tool") == "high"


def test_tool_risk_config_override(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security.tool_risk]
read_file = "high"
"mcp_*" = "high"
''')
    from maverick.safety.tool_risk import tool_risk
    assert tool_risk("read_file") == "high"            # exact override
    assert tool_risk("mcp_github__list") == "high"     # glob override


def test_risk_map_classifies_each_name():
    from maverick.safety.tool_risk import risk_map
    m = risk_map(["shell", "read_file", "some_unknown_tool"])
    assert m == {"shell": "high", "read_file": "low", "some_unknown_tool": "high"}


def test_risk_map_honors_config_override_loaded_once(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security.tool_risk]
read_file = "high"
''')
    from maverick.safety.tool_risk import risk_map
    # The override is applied (loaded a single time for the whole sweep).
    assert risk_map(["read_file", "shell"]) == {"read_file": "high", "shell": "high"}


# ---------- resolve_max_risk: most restrictive wins ----------

def test_resolve_max_risk_unset_follows_the_posture(tmp_path, monkeypatch):
    # No configured ceiling: uncapped in legacy mode, capped at "high" under
    # the secure default (critical-risk tools need an explicit opt-in).
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '[security]\ndenied_tools = ["computer"]\n')
    from maverick.safety.tool_acl import resolve_max_risk
    from maverick.security_defaults import secure_by_default
    expected = "high" if secure_by_default() else None
    assert resolve_max_risk(user_id="tg:1") == expected


def test_resolve_max_risk_tightest_layer_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security]
max_risk = "high"

[security.users."tg:42"]
max_risk = "low"
''')
    from maverick.safety.tool_acl import resolve_max_risk
    # Global high + user low -> low (most restrictive).
    assert resolve_max_risk(user_id="tg:42") == "low"
    # Without the user, only the global high applies.
    assert resolve_max_risk() == "high"


# ---------- apply_to_registry: ceiling drops high-risk tools ----------

def test_user_low_ceiling_drops_high_risk_tool(tmp_path, monkeypatch):
    """A user with max_risk=low cannot resolve a high-risk tool (shell)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security.users."tg:42"]
max_risk = "low"
''')
    from maverick.tools import base_registry
    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    assert "shell" in {t.name for t in reg.all()}

    from maverick.safety.tool_acl import apply_to_registry
    apply_to_registry(reg, user_id="tg:42")
    names = {t.name for t in reg.all()}
    assert "shell" not in names         # high-risk dropped
    assert "write_file" not in names    # high-risk dropped
    assert "read_file" in names         # low-risk kept


def test_medium_ceiling_drops_memory_tool(tmp_path, monkeypatch):
    """Persistent host-side memory mutation must not pass a medium ceiling."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security]
max_risk = "medium"
''')
    from maverick.tools import base_registry

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    assert "memory" not in names
    assert "obsidian" not in names
    assert "serial" not in names
    assert "write_file" not in names
    for mutating_tool in ("github_issues", "gitlab_issues", "anki"):
        assert mutating_tool not in names
    assert "read_file" in names


def test_medium_ceiling_drops_strategic_connectors(tmp_path, monkeypatch):
    """Credentialed enterprise connectors must not bypass medium risk caps."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security]
max_risk = "medium"
''')
    from maverick.tools import base_registry

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    for connector in (
        "servicenow",
        "snowflake",
        "databricks",
        "onetrust",
        "vertex",
    ):
        assert connector not in names
    assert "read_file" in names


def test_user_high_ceiling_keeps_high_risk_tool(tmp_path, monkeypatch):
    """max_risk=high (or unset) keeps current behaviour -- shell stays."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security.users."tg:42"]
max_risk = "high"
''')
    from maverick.tools import base_registry
    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())

    from maverick.safety.tool_acl import apply_to_registry
    apply_to_registry(reg, user_id="tg:42")
    names = {t.name for t in reg.all()}
    assert "shell" in names
    assert "read_file" in names


def test_no_ceiling_keeps_high_risk_tool(tmp_path, monkeypatch):
    """No max_risk anywhere -> no cap; shell is resolvable."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '[security]\ndenied_tools = ["computer"]\n')
    from maverick.tools import base_registry
    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())

    from maverick.safety.tool_acl import apply_to_registry
    apply_to_registry(reg, user_id="tg:42")
    assert "shell" in {t.name for t in reg.all()}


def test_max_risk_applies_to_late_registered_tools(tmp_path, monkeypatch):
    """Risk ceilings also block tools registered after the ACL pass."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security]
max_risk = "low"

[security.tool_risk]
"mcp_*" = "high"
''')
    from maverick.safety.tool_acl import apply_to_registry
    from maverick.tools import Tool, ToolRegistry

    reg = ToolRegistry()
    reg.register(Tool(
        name="read_file",
        description="read-only",
        input_schema={"type": "object"},
        fn=lambda _: "ok",
    ))
    apply_to_registry(reg)

    reg.register(Tool(
        name="mcp_evil__shell",
        description="late MCP shell",
        input_schema={"type": "object"},
        fn=lambda _: "pwned",
    ))

    names = {t.name for t in reg.all()}
    assert "read_file" in names
    assert "mcp_evil__shell" not in names


def test_medium_ceiling_drops_late_code_exec_tool(tmp_path, monkeypatch):
    """code_exec runs arbitrary Python, so max_risk=medium must block it."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security]
max_risk = "medium"
''')
    from maverick.safety.tool_acl import apply_to_registry
    from maverick.tools import Tool, ToolRegistry

    reg = ToolRegistry()
    apply_to_registry(reg)

    reg.register(Tool(
        name="code_exec",
        description="run Python",
        input_schema={"type": "object"},
        fn=lambda _: "pwned",
    ))

    assert "code_exec" not in {t.name for t in reg.all()}


def test_max_risk_blocks_late_plugin_tools_in_base_registry(tmp_path, monkeypatch):
    """Plugin tools registered after the first ACL pass still honor max_risk."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    _write_config(tmp_path, '''
[security]
max_risk = "low"

[security.tool_risk]
plugin_evil = "high"
''')
    from maverick import plugins
    from maverick.tools import Tool, base_registry

    def factory():
        return Tool(
            name="plugin_evil",
            description="late plugin shell",
            input_schema={"type": "object"},
            fn=lambda _: "pwned",
        )

    monkeypatch.setattr(plugins, "discover_tools", lambda: [("plugin_evil", factory)])

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    assert "read_file" in names
    assert "shell" not in names
    assert "plugin_evil" not in names


def test_unapplicable_acl_stops_registry_construction(tmp_path, monkeypatch):
    """A [security] value the ACL cannot apply must not leave an unfiltered
    registry (shell included) behind a logged warning."""
    import pytest

    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security]
allowed_tools = ["read_file"]
denied_tools = 5
max_risk = "low"
''')
    from maverick.tools import ToolAclConfigError, base_registry
    with pytest.raises(ToolAclConfigError, match=r"\[security\] denied_tools must be a list"):
        base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    _write_config(tmp_path, '[security]\nchannels = "x"\n')
    with pytest.raises(ToolAclConfigError, match=r"\[security.channels\] must be a table"):
        base_registry(world=_FakeWorld(), sandbox=_FakeSandbox(), channel="slack")
