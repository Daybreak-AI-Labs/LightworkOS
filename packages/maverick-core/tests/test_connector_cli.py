"""`maverick connectors` CLI: list + simulate the governed write path.

simulate previews effect WITHOUT committing (no network); commit is not exposed.
"""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick.cli import main


def _run(args, env=None):
    base = {"MAVERICK_GOVERNED_CONNECTORS": "1"}
    return CliRunner().invoke(main, args, env={**base, **(env or {})})


def _with_salesforce(monkeypatch):
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "get_governed_connectors",
                        lambda: {"enable": True, "connectors": ["salesforce"]})


def test_list_shows_registered(monkeypatch):
    _with_salesforce(monkeypatch)
    r = _run(["connectors", "list"])
    assert r.exit_code == 0, r.output
    rows = json.loads(r.output)
    sf = next(x for x in rows if x["connector"] == "salesforce")
    assert sf["write_action"] == "salesforce.write"
    assert sf["write_risk"] == "high"
    assert sf["write_requires_approval"] is True


def test_list_none_configured_clean_error(monkeypatch):
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "get_governed_connectors",
                        lambda: {"enable": False, "connectors": []})
    r = CliRunner().invoke(main, ["connectors", "list"],
                           env={"MAVERICK_GOVERNED_CONNECTORS": "0"})
    assert r.exit_code != 0
    assert "no governed connectors configured" in r.output
    assert "Traceback" not in r.output


def test_simulate_previews_without_commit(monkeypatch):
    _with_salesforce(monkeypatch)
    params = json.dumps({"op": "post", "path": "/services/data/v60.0/sobjects/Account",
                         "body": {"Name": "Acme"}})
    r = _run(["connectors", "simulate", "salesforce.write", "--params", params])
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    assert out["committed"] is False
    assert out["requires_approval"] is True
    assert "POST" in out["effect"] and "Name" in out["effect"]


def test_simulate_bad_json_clean_error(monkeypatch):
    _with_salesforce(monkeypatch)
    r = _run(["connectors", "simulate", "salesforce.write", "--params", "{not json"])
    assert r.exit_code != 0
    assert "invalid --params JSON" in r.output
    assert "Traceback" not in r.output


def test_simulate_unknown_action_clean_error(monkeypatch):
    _with_salesforce(monkeypatch)
    r = _run(["connectors", "simulate", "nope.write", "--params", "{}"])
    assert r.exit_code != 0
    assert "unknown action" in r.output
    assert "Traceback" not in r.output
