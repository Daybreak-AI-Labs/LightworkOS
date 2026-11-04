"""`maverick import` CLI: clean errors, not tracebacks, on bad inputs."""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick.cli import main


def _run(args, env=None):
    return CliRunner().invoke(main, args, env={"MAVERICK_AUTOMATION_IMPORT": "1", **(env or {})})


def test_sources_lists_platforms():
    r = _run(["import", "sources"])
    assert r.exit_code == 0
    names = {s["source"] for s in json.loads(r.output)}
    assert {"n8n", "make", "zapier"} <= names


def test_gate_off_is_clean_error():
    r = _run(["import", "run", "n8n", "--from-file", "/nope.json"],
             env={"MAVERICK_AUTOMATION_IMPORT": "0"})
    assert r.exit_code != 0
    assert "automation import is off" in r.output


def test_missing_file_is_clean_error(tmp_path):
    r = _run(["import", "run", "n8n", "--from-file", str(tmp_path / "nope.json")])
    assert r.exit_code != 0
    assert "cannot read" in r.output
    assert "Traceback" not in r.output


def test_bad_json_is_clean_error(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not json")
    r = _run(["import", "run", "n8n", "--from-file", str(f)])
    assert r.exit_code != 0
    assert "not valid JSON" in r.output
    assert "Traceback" not in r.output


def test_unknown_source_with_file_is_clean_error(tmp_path):
    # Regression: the --from-file path skipped source validation, so an unknown
    # source raised an uncaught ImporterError (traceback) at translate time.
    f = tmp_path / "wf.json"
    f.write_text(json.dumps({"name": "x", "nodes": [], "connections": {}}))
    r = _run(["import", "run", "totally-unknown", "--from-file", str(f)])
    assert r.exit_code != 0
    assert "unknown automation source" in r.output
    assert "Traceback" not in r.output


def test_import_from_file_dry_run(tmp_path):
    wf = {"id": "1", "name": "Flow", "active": True,
          "nodes": [{"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}},
                    {"name": "Do", "type": "n8n-nodes-base.set", "parameters": {}}],
          "connections": {"Hook": {"main": [[{"node": "Do"}]]}}}
    f = tmp_path / "wf.json"
    f.write_text(json.dumps(wf))
    r = _run(["import", "run", "n8n", "--from-file", str(f), "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "Would import" in r.output
    assert "Traceback" not in r.output
