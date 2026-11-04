"""`maverick mcp-registry` CLI: browse / add / remove / list."""
from __future__ import annotations

from click.testing import CliRunner
from maverick import catalog, mcp_client, mcp_registry
from maverick.cli import main


def test_browse_lists_entries(monkeypatch):
    entries = [
        catalog.CatalogEntry(name="github", version="1.0.0", kind="mcp",
                             summary="GitHub MCP", source="", sha256="",
                             verified=True, spec={"command": "npx"}),
        catalog.CatalogEntry(name="remote", version="2.0.0", kind="mcp",
                             summary="Remote MCP", source="", sha256="",
                             spec={"url": "https://h/sse"}),
    ]
    monkeypatch.setattr(mcp_registry, "load_mcp_registry", lambda: entries)
    r = CliRunner().invoke(main, ["mcp-registry", "browse"])
    assert r.exit_code == 0, r.output
    assert "github" in r.output and "[verified]" in r.output
    assert "(http)" in r.output and "(stdio)" in r.output


def test_browse_empty(monkeypatch):
    monkeypatch.setattr(mcp_registry, "load_mcp_registry", list)
    r = CliRunner().invoke(main, ["mcp-registry", "browse"])
    assert r.exit_code == 0 and "no registry entries" in r.output


def test_add_installs_and_writes(monkeypatch):
    spec = mcp_client.MCPServerSpec(name="github", command="npx", args=["-y", "pkg"])
    written = {}
    monkeypatch.setattr(mcp_registry, "install_mcp_from_registry", lambda name: spec)
    monkeypatch.setattr(mcp_registry, "add_mcp_server_to_config",
                        lambda n, d: written.update({"name": n, "dict": d}))
    r = CliRunner().invoke(main, ["mcp-registry", "add", "github"])
    assert r.exit_code == 0, r.output
    assert "added: github" in r.output
    assert written["name"] == "github"
    assert written["dict"]["command"] == "npx"


def test_add_unknown_name_errors(monkeypatch):
    def _boom(name):
        raise ValueError("no MCP server 'nope' in the registry")
    monkeypatch.setattr(mcp_registry, "install_mcp_from_registry", _boom)
    r = CliRunner().invoke(main, ["mcp-registry", "add", "nope"])
    assert r.exit_code == 2 and "no MCP server" in r.output


def test_remove(monkeypatch):
    monkeypatch.setattr(mcp_registry, "remove_mcp_server_from_config", lambda n: True)
    r = CliRunner().invoke(main, ["mcp-registry", "remove", "github"])
    assert r.exit_code == 0 and "removed: github" in r.output

    monkeypatch.setattr(mcp_registry, "remove_mcp_server_from_config", lambda n: False)
    r2 = CliRunner().invoke(main, ["mcp-registry", "remove", "absent"])
    assert r2.exit_code == 2 and "no MCP server" in r2.output


def test_list_configured(monkeypatch):
    specs = [
        mcp_client.MCPServerSpec(name="github", command="npx", args=["-y", "pkg"]),
        mcp_client.MCPServerSpec(name="remote", url="https://h/sse"),
    ]
    monkeypatch.setattr(mcp_client, "load_mcp_specs_from_config", lambda: specs)
    r = CliRunner().invoke(main, ["mcp-registry", "list"])
    assert r.exit_code == 0, r.output
    assert "github  (stdio)  npx -y pkg" in r.output
    assert "remote  (http)  https://h/sse" in r.output
