"""`maverick whoami`: resolve + display a principal's effective capability.

A read-only introspection command so operators can verify what a principal is
allowed to do -- the [security] ACL narrowed by any assigned role -- before
deploying.
"""
from __future__ import annotations

import json

from click.testing import CliRunner


def _cfg(monkeypatch, cfg):
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: cfg)


def _no_enforce_env(monkeypatch):
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)


def test_whoami_registered():
    from maverick.cli import main
    assert "whoami" in main.commands


def test_whoami_default_unrestricted(monkeypatch):
    _cfg(monkeypatch, {})
    _no_enforce_env(monkeypatch)
    from maverick.cli import main
    res = CliRunner().invoke(main, ["whoami"])
    assert res.exit_code == 0, res.output
    assert "principal: user:local" in res.output
    assert "all" in res.output            # empty allow_tools -> all
    assert "advisory" in res.output       # enforcement off by default


def test_whoami_shows_acl_deny(monkeypatch):
    _cfg(monkeypatch, {"security": {"denied_tools": ["shell"]}})
    _no_enforce_env(monkeypatch)
    from maverick.cli import main
    res = CliRunner().invoke(main, ["whoami", "--principal", "user:alice"])
    assert res.exit_code == 0, res.output
    assert "user:alice" in res.output
    assert "shell" in res.output          # listed under deny_tools


def test_whoami_json(monkeypatch):
    _cfg(monkeypatch, {"security": {"denied_tools": ["shell"], "max_risk": "low"}})
    _no_enforce_env(monkeypatch)
    from maverick.cli import main
    res = CliRunner().invoke(main, ["whoami", "--principal", "user:bob", "--json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["principal"] == "user:bob"
    assert "shell" in data["deny_tools"]
    assert data["max_risk"] == "low"
    assert data["allow_tools"] == "all"   # empty allow-list sentinel
    assert data["enforcement"] is False


def test_whoami_reports_enforcement_on(monkeypatch):
    _cfg(monkeypatch, {"capabilities": {"enforce": True}})
    _no_enforce_env(monkeypatch)
    from maverick.cli import main
    res = CliRunner().invoke(main, ["whoami", "--json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["enforcement"] is True
