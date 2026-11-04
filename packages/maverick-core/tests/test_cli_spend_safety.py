"""The ``maverick spend`` and ``maverick safety`` CLI commands.

``spend`` is the scriptable face of the /spend dashboard (FinOps export);
``safety`` prints the shield / sandbox / egress posture for CI assertions.
"""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick.cli import main


def _seed(tmp_path, monkeypatch):
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    w = world_model.WorldModel(db)
    g = w.create_goal("Pay invoices", "seed")
    ep = w.start_episode(g)
    w.end_episode(ep, "done", "success", cost_dollars=0.25,
                  input_tokens=1000, output_tokens=500, tool_calls=3)
    w.close()
    return db


def test_spend_human_output(tmp_path, monkeypatch):
    db = _seed(tmp_path, monkeypatch)
    # The CLI reports on the Workspace database; point it at the seeded file.
    r = CliRunner().invoke(main, ["--db", str(db), "spend"])
    assert r.exit_code == 0, r.output
    assert "Total spend" in r.output
    assert "$0.2500" in r.output
    assert "Pay invoices" in r.output


def test_spend_json_is_machine_readable(tmp_path, monkeypatch):
    db = _seed(tmp_path, monkeypatch)
    r = CliRunner().invoke(main, ["--db", str(db), "spend", "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert {"total", "by_goal", "by_tag", "tag_field"} <= set(data)
    assert data["total"]["dollars"] == 0.25
    assert data["by_goal"][0]["goal_id"] == 1
    assert data["by_goal"][0]["title"] == "Pay invoices"


def test_spend_empty_world_ok(tmp_path, monkeypatch):
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    world_model.WorldModel(db).close()
    r = CliRunner().invoke(main, ["--db", str(db), "spend"])
    assert r.exit_code == 0, r.output
    assert "no priced episodes" in r.output.lower()


def test_safety_human_output(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))  # isolate from any real config
    r = CliRunner().invoke(main, ["safety"])
    assert r.exit_code == 0, r.output
    assert "Safety posture" in r.output
    assert "sandbox" in r.output and "egress" in r.output


def test_safety_json_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    r = CliRunner().invoke(main, ["safety", "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert {"profile", "shield", "sandbox", "egress"} <= set(data)
    assert "backend" in data["sandbox"]
    assert isinstance(data["sandbox"]["isolated"], bool)
    assert isinstance(data["egress"]["locked"], bool)
    assert isinstance(data["shield"]["installed"], bool)
