"""CLI polish: empty-state messages + `plugin list`.

`maverick facts` printed nothing on a fresh install (every other list command
says "no X yet"); the `plugin` group only had `new`, so `plugin list` -- the
natural command -- didn't exist.
"""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from maverick.cli import main


def test_facts_empty_prints_hint(tmp_path: Path):
    db = tmp_path / "world.db"
    result = CliRunner().invoke(main, ["--db", str(db), "facts"])
    assert result.exit_code == 0
    assert "no facts yet" in result.output


def test_facts_lists_set_fact(tmp_path: Path):
    db = tmp_path / "world.db"
    runner = CliRunner()
    assert runner.invoke(main, ["--db", str(db), "fact", "name", "Alex"]).exit_code == 0
    result = runner.invoke(main, ["--db", str(db), "facts"])
    assert "name: Alex" in result.output


def test_plugin_list_exists_and_runs():
    result = CliRunner().invoke(main, ["plugin", "list"])
    assert result.exit_code == 0
    # No plugins installed in the test env -> the empty-state hint + allowlist.
    assert "plugin" in result.output.lower()
    assert "allowlist" in result.output
