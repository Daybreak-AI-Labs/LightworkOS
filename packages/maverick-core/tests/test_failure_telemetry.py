"""Failure-mode telemetry: classify, default-on record, summarize, CLI."""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick import failure_telemetry as ft
from maverick.budget import BudgetExceeded
from maverick.cli import main
from maverick.file_lock import private_path_is_restricted


def test_classify_exception():
    assert ft.classify_exception(BudgetExceeded("over")) == "budget"
    assert ft.classify_exception(TimeoutError("timed out")) == "timeout"
    assert ft.classify_exception(ConnectionError("network down")) == "network"
    assert ft.classify_exception(RuntimeError("401 unauthorized: bad api key")) == "auth"
    assert ft.classify_exception(RuntimeError("shield blocked it")) == "shield"
    assert ft.classify_exception(ValueError("something else")) == "error"


def test_record_is_noop_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "0")
    monkeypatch.setattr("maverick.config.load_config", dict)
    p = tmp_path / "f.jsonl"
    assert ft.record("budget", path=p) is False
    assert not p.exists()


def test_record_and_summarize_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "1")
    p = tmp_path / "f.jsonl"
    assert ft.record("budget", goal_id=1, detail="cap hit", path=p) is True
    ft.record("budget", path=p)
    ft.record("auth", path=p)
    ft.record("bogus_mode", path=p)  # normalizes to "error"
    s = ft.summarize(path=p)
    assert s["total"] == 4
    assert s["by_mode"]["budget"] == 2
    assert s["by_mode"]["auth"] == 1
    assert s["by_mode"]["error"] == 1
    assert private_path_is_restricted(p, 0o600)


def test_record_appends_without_reading_or_rewriting_prior_jsonl(
    tmp_path, monkeypatch,
):
    import maverick.file_lock as file_lock

    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "1")
    monkeypatch.setattr(
        file_lock,
        "atomic_read_text",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("full read")),
    )
    monkeypatch.setattr(
        file_lock,
        "atomic_write_text",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("full rewrite")),
    )
    path = tmp_path / "failure-modes.jsonl"

    assert ft.record("budget", path=path)
    assert ft.record("auth", path=path)
    assert [json.loads(line)["mode"] for line in path.read_text().splitlines()] == [
        "budget",
        "auth",
    ]


def test_concurrent_records_append_complete_lines(tmp_path, monkeypatch):
    import threading

    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "1")
    path = tmp_path / "failure-modes.jsonl"
    count = 32
    barrier = threading.Barrier(count)
    outcomes: list[bool] = []

    def worker(i):
        barrier.wait()
        outcomes.append(ft.record("timeout", goal_id=i, path=path))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert all(not thread.is_alive() for thread in threads)
    assert outcomes == [True] * count
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == count
    assert {record["goal_id"] for record in records} == set(range(count))


def test_record_failure_from_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "1")
    p = tmp_path / "f.jsonl"
    ft.record_failure(TimeoutError("slow"), goal_id=7, path=p)
    rec = json.loads(p.read_text().strip())
    assert rec["mode"] == "timeout" and rec["goal_id"] == 7 and "slow" in rec["detail"]


def test_recorded_detail_is_scrubbed(tmp_path, monkeypatch):
    # record_failure feeds the raw exception string, which for provider auth
    # errors carries the API key. It must be scrubbed before hitting disk.
    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "1")
    p = tmp_path / "f.jsonl"
    ft.record_failure(
        RuntimeError("401 from provider key=sk-ant-abcdefghij1234567890XYZ"),
        goal_id=9, path=p)
    detail = json.loads(p.read_text().strip())["detail"]
    assert "sk-ant-abcdefghij" not in detail
    assert "[REDACTED" in detail


def test_record_failure_from_mode_string(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "1")
    p = tmp_path / "f.jsonl"
    ft.record_failure("shield", goal_id=3, detail="blocked", path=p)
    assert json.loads(p.read_text().strip())["mode"] == "shield"


def test_summarize_missing_and_malformed(tmp_path):
    assert ft.summarize(path=tmp_path / "absent.jsonl") == {"total": 0, "by_mode": {}}
    p = tmp_path / "f.jsonl"
    p.write_text('{"mode": "budget"}\nnot json\n\n{"mode": "auth"}\n')
    s = ft.summarize(path=p)
    assert s["total"] == 2  # the malformed line is skipped


def test_cli_failures_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "0")
    monkeypatch.setattr("maverick.config.load_config", dict)
    res = CliRunner().invoke(main, ["failures"])
    assert res.exit_code == 0
    assert "no recorded failures" in res.output and "telemetry is off" in res.output


def test_cli_failures_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_FAILURE_TELEMETRY", "1")
    from maverick.failure_telemetry import record
    record("budget")
    record("budget")
    record("auth")
    res = CliRunner().invoke(main, ["failures"])
    assert res.exit_code == 0
    assert "Failure modes (3 recorded)" in res.output
    assert "budget" in res.output
