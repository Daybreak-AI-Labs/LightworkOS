"""`maverick governance` CLI: inspect + test the oversight control-plane policy."""
from __future__ import annotations

import json

from click.testing import CliRunner


def _cfg(monkeypatch, cfg):
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: cfg)


def test_governance_registered():
    from maverick.cli import main
    assert "governance" in main.commands
    assert set(main.commands["governance"].commands) >= {"show", "check"}


def test_show_default_allow(monkeypatch):
    _cfg(monkeypatch, {})
    from maverick.cli import main
    res = CliRunner().invoke(main, ["governance", "show"])
    assert res.exit_code == 0, res.output
    assert "default-allow" in res.output


def test_show_policy(monkeypatch):
    _cfg(monkeypatch, {"governance": {
        "deny_actions": ["delete_file"], "require_human_min_risk": "high",
    }})
    from maverick.cli import main
    res = CliRunner().invoke(main, ["governance", "show"])
    assert res.exit_code == 0, res.output
    assert "delete_file" in res.output and "high" in res.output


def test_check_require_human(monkeypatch):
    _cfg(monkeypatch, {"governance": {"require_human_min_risk": "high"}})
    from maverick.cli import main
    res = CliRunner().invoke(main, ["governance", "check", "shell"])
    assert res.exit_code == 0, res.output
    assert "REQUIRE_HUMAN" in res.output


def test_check_json_deny(monkeypatch):
    _cfg(monkeypatch, {"governance": {"deny_actions": ["delete_file"]}})
    from maverick.cli import main
    res = CliRunner().invoke(main, ["governance", "check", "delete_file", "--json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["decision"] == "deny" and data["rule"] == "deny_actions"


def test_check_default_allow(monkeypatch):
    _cfg(monkeypatch, {})
    from maverick.cli import main
    res = CliRunner().invoke(main, ["governance", "check", "read_file"])
    assert res.exit_code == 0, res.output
    assert "ALLOW" in res.output
