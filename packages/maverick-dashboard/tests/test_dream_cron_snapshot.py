"""The scheduled dream cycle takes the same rollback snapshot as `maverick dream`."""
from __future__ import annotations

import pytest
from maverick import dreaming
from maverick_dashboard import automation_queue as aq


@pytest.fixture
def calls(monkeypatch, safe_learning_stores):
    seen: list[str] = []
    monkeypatch.setattr(aq, "_run_for_active_tenants", lambda _op, fn: fn() or True)
    monkeypatch.setattr(aq, "_world", lambda: object())
    monkeypatch.setattr(dreaming, "enabled", lambda: True)
    original_snapshot = dreaming.snapshot_learning_state

    def snapshot(*, keep_last, publish_empty, raise_on_error):
        assert publish_empty is True and raise_on_error is True
        seen.append(f"snapshot:{keep_last}")
        return original_snapshot(keep_last=keep_last, publish_empty=publish_empty, raise_on_error=raise_on_error)

    monkeypatch.setattr(dreaming, "snapshot_learning_state", snapshot)
    monkeypatch.setattr(dreaming, "dream_cycle", lambda _w: seen.append("cycle"))
    monkeypatch.setattr("maverick.self_improvement_runner.nightly_self_harness_enabled", lambda: False)
    return seen


@pytest.fixture(autouse=True)
def safe_learning_stores(monkeypatch, tmp_path):
    # Unit worker seams must never copy import-time paths from a user's home.
    monkeypatch.setattr(dreaming, "_live_stores", lambda: {"guardrails.json": tmp_path / "guardrails.json"})
    monkeypatch.setattr(dreaming, "snapshots_dir", lambda: tmp_path / "snapshots")


def test_snapshot_precedes_the_cycle(calls, monkeypatch):
    monkeypatch.setattr(dreaming, "settings", lambda: {"snapshot_keep_last": 3})
    aq._handle_dream()
    assert calls == ["snapshot:3", "cycle"]


def test_snapshots_off_blocks_unprotected_learning(calls, monkeypatch):
    monkeypatch.setattr(dreaming, "settings", lambda: {"snapshots": False})
    with pytest.raises(RuntimeError, match="safety copies"):
        aq._handle_dream()
    assert calls == []


def test_failed_snapshot_blocks_the_cycle(calls, monkeypatch):
    monkeypatch.setattr(dreaming, "settings", dict)

    def boom(**kwargs):
        assert kwargs["publish_empty"] and kwargs["raise_on_error"]
        raise OSError("disk full")

    monkeypatch.setattr(dreaming, "snapshot_learning_state", boom)
    with pytest.raises(OSError):
        aq._handle_dream()
    assert calls == []


def test_dashboard_runs_improvement_review_without_dreaming(calls, monkeypatch):
    monkeypatch.setattr(dreaming, "enabled", lambda: False)
    monkeypatch.setattr(dreaming, "settings", lambda: {"snapshot_keep_last": 2})
    monkeypatch.setattr("maverick.self_improvement_runner.nightly_self_harness_enabled", lambda: True)
    monkeypatch.setattr("maverick.self_improvement_runner.run_nightly_self_harness",
                        lambda _w: calls.append("improvement"))
    aq._handle_dream()
    assert calls == ["snapshot:2", "improvement"]


def test_harness_only_installation_receives_a_durable_schedule(monkeypatch, tmp_path):
    from maverick.job_queue import JobQueue

    jobs = JobQueue(tmp_path / "jobs.db")
    monkeypatch.setattr(aq, "queue", lambda: jobs)
    for module in ("automation_events", "dreaming", "data_engine", "flow"):
        monkeypatch.setattr(f"maverick.{module}.enabled", lambda: False)
    monkeypatch.setattr("maverick.flow.auto_evolve_enabled", lambda: False)
    monkeypatch.setattr("maverick.self_improvement_runner.nightly_self_harness_enabled", lambda: True)
    aq.reconcile()
    assert len(list(jobs.iter_pending(aq.DREAM_KIND))) == 1
    aq.reconcile()
    assert len(list(jobs.iter_pending(aq.DREAM_KIND))) == 1


def test_nightly_review_records_results_and_shares_one_allowance(monkeypatch):
    from maverick import self_improvement_runner as runner
    from maverick.self_harness import SelfHarnessReport

    receipts = []
    budget = object()
    monkeypatch.setattr(runner, "nightly_self_harness_enabled", lambda: True)
    monkeypatch.setattr("maverick.learning_guard.check_learning_halt", lambda *_a: None)
    monkeypatch.setattr("maverick.self_harness.settings",
                        lambda: {"transfer_auto": True, "risk_limited": False, "eval_corpus": "cases"})
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **kw: receipts.append(kw) or True)
    monkeypatch.setattr(runner, "_eval_budget", lambda _st: budget)
    seen = []

    def fleet(**kw):
        seen.append(kw)
        return {"configured": (SelfHarnessReport(model_id="configured", mined=2, promoted=1), 0)}

    monkeypatch.setattr(runner, "run_self_harness_all_models", fleet)
    monkeypatch.setattr(runner, "run_self_harness_transfer_sweep", lambda **kw: seen.append(kw))
    monkeypatch.setattr(runner, "run_corpus_harvest", lambda _w, **kw: 3)
    result = runner.run_nightly_self_harness(object())
    assert result["patterns_found"] == 2 and result["examples_prepared"] == 3
    assert seen[0]["evaluation_budget"] is seen[1]["evaluation_budget"] is budget
    assert seen[0]["work_item_id"] == seen[1]["work_item_id"]
    assert [row["phase"] for row in receipts] == ["started", "completed"]
    assert all("model_id" not in row and "applied_lines" not in row for row in receipts)


def test_unrecordable_nightly_review_cannot_change_learning(monkeypatch):
    from maverick import self_improvement_runner as runner

    monkeypatch.setattr(runner, "nightly_self_harness_enabled", lambda: True)
    monkeypatch.setattr("maverick.learning_guard.check_learning_halt", lambda *_a: None)
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **kw: False)
    touched = []
    monkeypatch.setattr(runner, "run_self_harness_all_models", lambda **kw: touched.append(1))
    with pytest.raises(RuntimeError, match="could not be recorded"):
        runner.run_nightly_self_harness(object())
    assert touched == []


def test_nightly_failure_records_an_incomplete_review(monkeypatch):
    from maverick import self_improvement_runner as runner

    receipts = []
    monkeypatch.setattr(runner, "nightly_self_harness_enabled", lambda: True)
    monkeypatch.setattr("maverick.learning_guard.check_learning_halt", lambda *_a: None)
    monkeypatch.setattr("maverick.self_harness.settings", dict)
    monkeypatch.setattr(runner, "_eval_budget", lambda _st: object())
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **kw: receipts.append(kw) or True)

    def interrupted(**kw):
        raise OSError("record store unavailable")

    monkeypatch.setattr(runner, "run_self_harness_all_models", interrupted)
    with pytest.raises(OSError):
        runner.run_nightly_self_harness(object())
    assert [row["phase"] for row in receipts] == ["started", "stopped"]
