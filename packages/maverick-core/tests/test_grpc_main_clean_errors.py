"""`python -m maverick.grpc_api` must fail cleanly on operator-config errors.

Previously, the gRPC entrypoint's main() called serve()
with no error handling, so the two expected, actionable startup errors --
a missing bearer token (ValueError, the fail-closed auth default) and a
missing grpcio extra (ImportError) -- each dumped a full traceback instead of
the one-line message they already carry. main() now catches both and returns
a non-zero exit with the message on stderr.
"""
from __future__ import annotations

import maverick.grpc_api.server as srv


def test_main_missing_token_is_clean(monkeypatch, capsys):
    monkeypatch.delenv("MAVERICK_GRPC_BEARER_TOKEN", raising=False)
    rc = srv.main(["--address", "127.0.0.1:0"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "bearer token" in err
    assert "Traceback" not in err


def test_main_missing_grpc_is_clean(monkeypatch, capsys):
    monkeypatch.setenv("MAVERICK_GRPC_BEARER_TOKEN", "tok")

    def _boom():
        raise ImportError("grpc not installed. Run: pip install 'maverick-agent[grpc]'")

    monkeypatch.setattr(srv, "_require_grpc", _boom)
    rc = srv.main(["--address", "127.0.0.1:0"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "pip install" in err
    assert "Traceback" not in err
