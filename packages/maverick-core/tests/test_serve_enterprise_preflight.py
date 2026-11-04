"""Channel serve must honor the required enterprise deployment gate."""
from click.testing import CliRunner


def test_channel_serve_runs_enterprise_preflight_before_start(monkeypatch):
    import maverick.deployment as deployment
    import maverick.server as server_mod

    calls = {"gate": 0, "build": 0}

    def _gate():
        calls["gate"] += 1
        raise RuntimeError("enterprise gate blocked")

    def _build():
        calls["build"] += 1
        raise AssertionError("server should not be built after failed gate")

    monkeypatch.setattr(deployment, "require_enterprise_or_die", _gate)
    monkeypatch.setattr(server_mod, "build_from_config", _build)

    from maverick.cli import main
    result = CliRunner().invoke(main, ["serve"])

    assert result.exit_code != 0
    assert "enterprise gate blocked" in repr(result.exception)
    assert calls == {"gate": 1, "build": 0}
