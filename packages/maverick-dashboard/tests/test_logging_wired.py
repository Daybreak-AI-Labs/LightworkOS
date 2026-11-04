"""The dashboard + MCP server apply Lightwork's shared logging config at their
real process entrypoint (main()) — not in the lifespan/at import, so the
in-process TestClient and bare imports never reconfigure global logging."""
from __future__ import annotations

import logging
import sys


def test_dashboard_main_configures_logging(monkeypatch):
    import maverick_dashboard.app as app_mod

    calls: list[int] = []
    monkeypatch.setattr("maverick.logging_config.configure_logging",
                        lambda *a, **k: calls.append(1))
    # Stub the bounded server entrypoint so main() does not bind a socket.
    monkeypatch.setattr("maverick_dashboard._server.run_dashboard_server", lambda *a, **k: None)
    monkeypatch.setattr(sys, "argv",
                        ["maverick-dashboard", "--host", "127.0.0.1", "--port", "0"])
    app_mod.main()
    assert calls == [1]


def test_mcp_main_configures_logging(monkeypatch):
    import maverick_mcp.server as server

    calls: list[int] = []
    monkeypatch.setattr(server, "_configure_mcp_logging", lambda: calls.append(1))
    monkeypatch.setattr(server.MCPServer, "run", lambda self: None)
    monkeypatch.setattr(sys, "argv", ["maverick-mcp"])
    server.main()
    assert calls == [1]


def test_shared_logging_targets_stderr_not_stdout():
    # MCP runs over stdio: a log handler on stdout would corrupt the protocol.
    import maverick.logging_config as lc

    saved_handlers = logging.getLogger().handlers[:]
    saved_configured = lc._configured
    lc._configured = False
    try:
        lc.configure_logging()
        streams = [getattr(h, "stream", None) for h in logging.getLogger().handlers]
        assert sys.stdout not in streams
        assert sys.stderr in streams
    finally:
        lc._configured = saved_configured
        logging.getLogger().handlers[:] = saved_handlers
