"""Dashboard-managed MCP servers: added via the runtime overlay (never
config.toml) and unioned into the kernel's MCP loader."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    yield


def test_add_then_read_stdio_server():
    import maverick.runtime_overrides as ro
    from maverick.runtime_overrides import add_mcp_server, mcp_overlay

    stored = add_mcp_server("filesystem", {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        "env": {"API_TOKEN": "stdio-secret-value"},
    })
    assert stored["command"] == "npx"
    persisted = ro.OVERRIDES_PATH.read_text(encoding="utf-8")
    assert "stdio-secret-value" not in persisted
    assert "MVKAR1:" in persisted
    overlay = mcp_overlay()
    assert "filesystem" in overlay
    assert overlay["filesystem"]["args"][0] == "-y"
    assert overlay["filesystem"]["env"]["API_TOKEN"] == "stdio-secret-value"


def test_add_http_server_roundtrips_via_toml():
    import maverick.runtime_overrides as ro
    from maverick.runtime_overrides import add_mcp_server, mcp_overlay
    add_mcp_server("remote", {
        "url": "https://host.example/mcp",
        "auth_token": "t0ken",
        "headers": {"X-Org": "acme"},
        "oauth": {
            "token_url": "https://host.example/token",
            "client_id": "client-one",
            "client_secret": "oauth-secret",  # pragma: allowlist secret
        },
    })
    persisted = ro.OVERRIDES_PATH.read_text(encoding="utf-8")
    for plaintext in ("t0ken", "acme", "client-one", "oauth-secret"):
        assert plaintext not in persisted
    assert persisted.count("MVKAR1:") >= 4
    overlay = mcp_overlay()
    assert overlay["remote"]["url"] == "https://host.example/mcp"
    assert overlay["remote"]["headers"]["X-Org"] == "acme"
    assert overlay["remote"]["oauth"]["client_secret"] == "oauth-secret"  # pragma: allowlist secret
    # the inline-table / list rendering must parse back cleanly
    assert overlay["remote"]["auth_token"] == "t0ken"


def test_remove_server():
    from maverick.runtime_overrides import add_mcp_server, mcp_overlay, remove_mcp_server
    add_mcp_server("gone", {"command": "true"})
    assert remove_mcp_server("gone") is True
    assert "gone" not in mcp_overlay()
    assert remove_mcp_server("gone") is False  # already absent


def test_invalid_name_and_spec_rejected():
    from maverick.runtime_overrides import add_mcp_server
    with pytest.raises(ValueError):
        add_mcp_server("bad name", {"command": "npx"})  # space in name
    with pytest.raises(ValueError):
        add_mcp_server("ok", {})  # neither command nor url
    with pytest.raises(ValueError):
        add_mcp_server("ok", {"command": "rm; reboot"})  # shell metachar -> from_config


def test_overlay_unions_into_kernel_loader():
    from maverick.mcp_client import load_mcp_specs_from_config
    from maverick.runtime_overrides import add_mcp_server
    add_mcp_server("fs", {"command": "npx", "args": ["server-fs"]})
    specs = load_mcp_specs_from_config()
    by_name = {s.name: s for s in specs}
    assert "fs" in by_name
    assert by_name["fs"].command == "npx"
    assert by_name["fs"].args == ["server-fs"]


def test_config_wins_on_name_clash(monkeypatch):
    import maverick.mcp_client as mc
    from maverick.runtime_overrides import add_mcp_server

    # config defines "dup" as a stdio server; the overlay also defines "dup".
    def _fake_load_config():
        return {"mcp_servers": {"dup": {"command": "config-cmd"}}}
    monkeypatch.setattr("maverick.config.load_config", _fake_load_config)
    add_mcp_server("dup", {"command": "overlay-cmd"})
    by_name = {s.name: s for s in mc.load_mcp_specs_from_config()}
    assert by_name["dup"].command == "config-cmd"  # config not shadowed


def test_mcp_coexists_with_other_overlays():
    from maverick.runtime_overrides import (
        add_mcp_server,
        budget_override,
        denied_tools,
        disable_tool,
        mcp_overlay,
        set_allowed_models,
        set_budget,
    )
    disable_tool("browser")
    set_budget(9.0)
    set_allowed_models(["claude-sonnet-4-6"])
    add_mcp_server("fs", {"command": "npx"})
    # one file, full-state writes: adding a server keeps the rest intact
    assert denied_tools() == {"browser"}
    assert budget_override() == 9.0
    assert "fs" in mcp_overlay()
