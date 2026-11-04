"""Tests for tool access control (maverick.safety.tool_acl), including per-channel
and per-user lists.
"""
from __future__ import annotations

import importlib

# ---------- tool_acl ----------

def test_tool_acl_no_lists_keeps_all():
    from maverick.safety.tool_acl import filter_tools
    out = filter_tools({"a", "b", "c"}, allowed=set(), denied=set())
    assert out == {"a", "b", "c"}


def test_tool_acl_allow_list_filters():
    from maverick.safety.tool_acl import filter_tools
    out = filter_tools({"a", "b", "c"}, allowed={"a", "b"})
    assert out == {"a", "b"}


def test_tool_acl_deny_list_drops():
    from maverick.safety.tool_acl import filter_tools
    out = filter_tools({"a", "b", "c"}, denied={"b"})
    assert out == {"a", "c"}


def test_tool_acl_allow_then_deny():
    """When both lists set, allow filters first, then deny drops further."""
    from maverick.safety.tool_acl import filter_tools
    out = filter_tools({"a", "b", "c", "d"}, allowed={"a", "b", "c"}, denied={"b"})
    assert out == {"a", "c"}


def test_tool_acl_apply_to_registry(tmp_path, monkeypatch):
    """apply_to_registry mutates the registry in place per config."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Write a config with denied_tools.
    config_dir = tmp_path / ".maverick"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        '[security]\ndenied_tools = ["computer", "browser"]\n'
    )
    # Force reload of the cached default config path.
    import importlib

    import maverick.config as cfg_mod
    importlib.reload(cfg_mod)

    from maverick.tools import base_registry

    class _FakeSandbox:
        pass

    class _FakeWorld:
        pass

    # Include the optional tools so we can verify they get dropped.
    reg = base_registry(
        world=_FakeWorld(), sandbox=_FakeSandbox(),
        enable_computer_use=True, enable_browser=True,
    )
    names = {t.name for t in reg.all()}
    assert "computer" not in names
    assert "browser" not in names
    # Core tools survived.
    assert "shell" in names


def test_tool_acl_blocks_late_registered_tools(tmp_path, monkeypatch):
    """ACL should also apply to tools registered after apply_to_registry."""
    monkeypatch.setenv("HOME", str(tmp_path))
    config_dir = tmp_path / ".maverick"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        '[security]\nallowed_tools = ["read_file"]\n'
    )
    import importlib

    import maverick.config as cfg_mod
    importlib.reload(cfg_mod)

    from maverick.tools import Tool, base_registry

    class _FakeSandbox:
        pass

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    reg.register(Tool(name="late_tool", description="x", input_schema={}, fn=lambda _a: "ok"))
    names = {t.name for t in reg.all()}
    assert "read_file" in names
    assert "late_tool" not in names


# ---------- tool_acl: per-channel + per-user ----------

def _write_config(tmp_path, body: str) -> None:
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.toml").write_text(body)
    import maverick.config as cfg_mod
    importlib.reload(cfg_mod)


def test_tool_acl_per_channel_deny(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security.channels.telegram]
denied_tools = ["computer", "shell"]
''')
    from maverick.safety.tool_acl import resolve_lists
    allowed, denied = resolve_lists(channel="telegram")
    assert "computer" in denied
    assert "shell" in denied


def test_tool_acl_per_user_allow_intersects(tmp_path, monkeypatch):
    """Per-user allow intersects with global allow -- most restrictive wins."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security]
allowed_tools = ["shell", "read_file", "write_file", "web_search"]

[security.users."tg:42"]
allowed_tools = ["read_file", "web_search"]
''')
    from maverick.safety.tool_acl import resolve_lists
    allowed, _ = resolve_lists(user_id="tg:42")
    # Intersection of global + user allow lists.
    assert allowed == {"read_file", "web_search"}


def test_tool_acl_deny_union(tmp_path, monkeypatch):
    """Deny lists union across global + channel + user."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security]
denied_tools = ["computer"]

[security.channels.slack]
denied_tools = ["browser"]

[security.users."slack:U1"]
denied_tools = ["shell"]
''')
    from maverick.safety.tool_acl import resolve_lists
    _, denied = resolve_lists(channel="slack", user_id="slack:U1")
    assert denied == {"computer", "browser", "shell"}


def test_tool_acl_no_channel_or_user_is_global_only(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security]
denied_tools = ["x"]

[security.channels.telegram]
denied_tools = ["y"]
''')
    from maverick.safety.tool_acl import resolve_lists
    _, denied = resolve_lists()
    assert "x" in denied
    # Channel-scoped y NOT applied when channel is None.
    assert "y" not in denied


def test_tool_acl_apply_to_registry_with_channel(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _write_config(tmp_path, '''
[security.channels.telegram]
denied_tools = ["computer", "browser"]
''')
    from maverick.tools import base_registry

    class _FakeSandbox:
        workdir = "."

    class _FakeWorld:
        pass

    # Register with optional tools, then drop them via channel ACL.
    reg = base_registry(
        world=_FakeWorld(), sandbox=_FakeSandbox(),
        enable_computer_use=True, enable_browser=True,
    )
    # Initial state: computer + browser present.
    names_before = {t.name for t in reg.all()}
    assert "computer" in names_before
    assert "browser" in names_before

    from maverick.safety.tool_acl import apply_to_registry
    apply_to_registry(reg, channel="telegram")
    names_after = {t.name for t in reg.all()}
    assert "computer" not in names_after
    assert "browser" not in names_after
