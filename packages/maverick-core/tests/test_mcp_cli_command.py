"""`maverick mcp` must launch the stdio MCP server, not re-parse argv.

Regression: the command delegated to maverick_mcp.server.main(), which
argparse-parses sys.argv and rejected the `mcp` subcommand token -- so
`maverick mcp` (the command every client quickstart and IDE integration uses)
exited with "unrecognized arguments: mcp" before serving a single byte. It now
calls MCPServer().run() directly. Caught by actually executing the TS client;
this guards it in the Python CI without needing Node.
"""
from click.testing import CliRunner


def test_maverick_mcp_launches_stdio_server(monkeypatch):
    import maverick_mcp.server as server
    calls = {"run": 0}
    monkeypatch.setattr(server.MCPServer, "run", lambda self: calls.__setitem__("run", calls["run"] + 1))

    from maverick.cli import main
    result = CliRunner().invoke(main, ["mcp"])

    assert result.exit_code == 0, result.output
    assert calls["run"] == 1, "`maverick mcp` did not start the stdio server"


def test_maverick_mcp_help_still_advertises_cross_language():
    # Surface contract: --help must not regress when we add options.
    from maverick.cli import main
    result = CliRunner().invoke(main, ["mcp", "--help"])
    assert result.exit_code == 0
    low = result.output.lower()
    assert "cross-language" in low
    for lang in ("typescript", "go", "rust"):
        assert lang in low


def test_maverick_mcp_runs_enterprise_preflight_before_stdio(monkeypatch):
    import maverick.deployment as deployment
    import maverick_mcp.server as server

    calls = {"gate": 0, "run": 0}

    def _gate():
        calls["gate"] += 1
        raise RuntimeError("enterprise gate blocked")

    monkeypatch.setattr(deployment, "require_enterprise_or_die", _gate)
    monkeypatch.setattr(server.MCPServer, "run", lambda self: calls.__setitem__("run", calls["run"] + 1))

    from maverick.cli import main
    result = CliRunner().invoke(main, ["mcp"])

    assert result.exit_code != 0
    assert "enterprise gate blocked" in repr(result.exception)
    assert calls == {"gate": 1, "run": 0}
