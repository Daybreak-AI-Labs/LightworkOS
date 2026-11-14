"""Harness smoke test.

Verifies the dry-run path works end-to-end without invoking the LLM, so
CI can prove the harness machinery itself isn't broken even when there
are no API credentials in the environment.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def harness():
    """Import the harness module by file path so this test works whether
    benchmarks/ is on PYTHONPATH or not."""
    import importlib.util
    p = Path(__file__).parent / "harness.py"
    spec = importlib.util.spec_from_file_location("benchmarks.harness", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_dry_run_produces_row(harness, tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_BENCH_DRY_RUN", "1")
    bench = tmp_path / "fake.md"
    bench.write_text("dummy benchmark spec")

    row = harness.run_one(
        benchmark_path=bench,
        max_dollars=1.0,
        max_wall_seconds=10.0,
        tag="ci",
        db_path=tmp_path / "world.db",
    )

    assert row["agent"] == "maverick"
    # Provenance: a dry run measured nothing, so it is never tagged as a
    # measured row (nor confused with hand-added comparator rows).
    assert row["source"] == "dry-run"
    assert row["outcome"] == "dry-run"
    assert row["wall_seconds"] >= 0
    assert row["cost_dollars"] == 0.0


def test_failed_run_never_inherits_an_older_episode(harness, tmp_path, monkeypatch):
    import subprocess

    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_BENCH_DRY_RUN", raising=False)
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    episode = wm.start_episode(wm.create_goal("earlier run"))
    wm.end_episode(episode, "done", "success", cost_dollars=1.5, input_tokens=10)
    monkeypatch.setattr(
        harness.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 2, "", "boom"),
    )
    bench = tmp_path / "fake.md"
    bench.write_text("dummy benchmark spec")

    row = harness.run_one(bench, 1.0, 10.0, "ci", db_path=db)

    assert row["outcome"] == "exit-2"
    assert row["cost_dollars"] == 0.0
    assert row["input_tokens"] == 0


def test_append_results_creates_table(harness, tmp_path):
    out = tmp_path / "RESULTS.md"
    row = {
        "benchmark": "x.md", "tag": "v0.1", "agent": "maverick",
        "source": "measured",
        "wall_seconds": 0.5, "cost_dollars": 0.01,
        "input_tokens": 100, "output_tokens": 50, "tool_calls": 2,
        "outcome": "success",
    }
    harness.append_results(row, out)

    content = out.read_text()
    assert "Lightwork benchmark results" in content
    assert "| benchmark |" in content
    assert "| source |" in content
    assert "| x.md | v0.1 | maverick | measured | 0.5 |" in content


def test_append_is_idempotent_per_table_creation(harness, tmp_path):
    """Calling append_results twice doesn't duplicate the header."""
    out = tmp_path / "RESULTS.md"
    row1 = {
        "benchmark": "a.md", "tag": "v1", "agent": "maverick",
        "wall_seconds": 1, "cost_dollars": 0.1,
        "input_tokens": 10, "output_tokens": 5, "tool_calls": 1,
        "outcome": "success",
    }
    row2 = {**row1, "benchmark": "b.md"}
    harness.append_results(row1, out)
    harness.append_results(row2, out)
    content = out.read_text()
    assert content.count("| benchmark |") == 1
    assert "a.md" in content
    assert "b.md" in content


def test_append_results_migrates_existing_table_for_source(harness, tmp_path):
    out = tmp_path / "RESULTS.md"
    out.write_text(
        "# Lightwork benchmark results\n\n"
        "| benchmark | tag | agent | wall_seconds | cost_dollars | "
        "input_tokens | output_tokens | tool_calls | outcome |\n"
        "|---|---|---|---|---|---|---|---|---|\n"
        "| old.md | v0 | maverick | 1 | 0 | 10 | 5 | 1 | success |\n",
        encoding="utf-8",
    )
    row = {
        "benchmark": "x.md", "tag": "v0.1", "agent": "maverick",
        "source": "measured",
        "wall_seconds": 0.5, "cost_dollars": 0.01,
        "input_tokens": 100, "output_tokens": 50, "tool_calls": 2,
        "outcome": "success",
    }

    harness.append_results(row, out)

    lines = out.read_text(encoding="utf-8").splitlines()
    assert "| source |" in lines[2]
    assert "| old.md | v0 | maverick |  | 1 |" in lines[4]
    assert "| x.md | v0.1 | maverick | measured | 0.5 |" in lines[5]
