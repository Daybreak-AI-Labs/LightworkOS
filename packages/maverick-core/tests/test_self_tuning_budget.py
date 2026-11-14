"""Self-tuning budgets: learn a per-task-class default cap from run costs."""
from __future__ import annotations

from random import Random

from maverick.self_tuning_budget import SelfTuningBudget


def _learner(tmp_path, **kw):
    return SelfTuningBudget(path=tmp_path / "bt.json", rng=Random(0), **kw)


def test_learned_limit_requires_an_explicit_boolean_opt_in(monkeypatch):
    from maverick import config, self_tuning_budget

    monkeypatch.setattr(config, "governed_learning_env_flag", lambda _name: None)
    for value, expected in ((None, False), ("false", False), (False, False), (True, True)):
        section = {} if value is None else {"self_tuning": value}
        monkeypatch.setattr(config, "load_config", lambda section=section: {"budget": section})
        assert self_tuning_budget.enabled() is expected


def test_cold_class_returns_none(tmp_path):
    b = _learner(tmp_path, min_samples=5)
    b.observe("research", 1.0)
    assert b.suggest("research") is None  # under min_samples
    assert b.suggest("never-seen") is None


def test_suggests_quantile_times_margin(tmp_path):
    b = _learner(tmp_path, min_samples=4, quantile=0.9, margin=1.5,
                 floor=0.1, ceiling=100)
    for v in (1.0, 1.0, 2.0, 8.0):  # q90 ~ 8.0
        b.observe("big", v)
    cap = b.suggest("big")
    assert cap == round(8.0 * 1.5, 2)


def test_clamped_to_floor_and_ceiling(tmp_path):
    lo = _learner(tmp_path, min_samples=2, floor=5.0, ceiling=50.0, margin=1.0)
    lo.observe("tiny", 0.01)
    lo.observe("tiny", 0.02)
    assert lo.suggest("tiny") == 5.0  # floored
    hi = _learner(tmp_path, min_samples=2, floor=0.1, ceiling=10.0, margin=1.0,
                  quantile=1.0)
    hi.observe("huge", 999.0)
    hi.observe("huge", 999.0)
    assert hi.suggest("huge") == 10.0  # ceilinged


def test_persisted_across_instances(tmp_path):
    b = _learner(tmp_path, min_samples=3)
    for v in (2.0, 3.0, 4.0):
        b.observe("research", v)
    again = SelfTuningBudget(path=tmp_path / "bt.json", min_samples=3)
    assert again.suggest("research") is not None
    assert again.stats("research")["count"] == 3


def test_reservoir_is_bounded(tmp_path):
    import maverick.self_tuning_budget as m
    b = _learner(tmp_path, min_samples=1)
    for i in range(m._RESERVOIR + 50):
        b.observe("spammy", float(i))
    assert len(b._classes["spammy"].samples) == m._RESERVOIR
    assert b._classes["spammy"].count == m._RESERVOIR + 50


def test_negative_and_blank_ignored(tmp_path):
    b = _learner(tmp_path, min_samples=1)
    b.observe("", 5.0)
    b.observe("x", -1.0)
    assert b.stats("x")["count"] == 0


def test_non_finite_rejected_and_store_stays_valid_json(tmp_path):
    """inf/nan must not be recorded: they serialize as non-standard JSON
    tokens (Infinity/NaN) and a NaN sample poisons the quantile."""
    import json

    p = tmp_path / "bt.json"
    b = SelfTuningBudget(path=p, rng=Random(0), min_samples=1)
    b.observe("x", float("inf"))
    b.observe("x", float("-inf"))
    b.observe("y", float("nan"))
    assert b.stats("x")["count"] == 0
    assert b.stats("y")["count"] == 0
    # On-disk store stays strict-JSON-parseable (no Infinity/NaN tokens).
    if p.exists():
        raw = p.read_text(encoding="utf-8")
        assert "Infinity" not in raw
        assert "NaN" not in raw
        json.loads(raw, parse_constant=_reject_constant)


def test_tampered_store_cannot_force_the_ceiling(tmp_path):
    p = tmp_path / "bt.json"
    p.write_text('{"x": {"count": 3, "samples": [NaN, Infinity, 1.0]}, "bad": [1]}',
                 encoding="utf-8")
    b = SelfTuningBudget(path=p, rng=Random(0), min_samples=1)
    assert b.stats("x")["count"] == 3
    assert b.suggest("x") is not None and b.suggest("x") < 100.0


def _reject_constant(token):  # pragma: no cover - only fires on a regression
    raise AssertionError(f"non-standard JSON token persisted: {token}")


def test_suggested_max_dollars_respects_enabled(tmp_path, monkeypatch):
    import maverick.self_tuning_budget as m
    b = _learner(tmp_path, min_samples=2)
    b.observe("research", 3.0)
    b.observe("research", 3.0)
    monkeypatch.setattr(m, "enabled", lambda: False)
    assert m.suggested_max_dollars("research", learner=b) is None
    monkeypatch.setattr(m, "enabled", lambda: True)
    assert m.suggested_max_dollars("research", learner=b) is not None


def test_record_run_cost_noop_when_disabled(tmp_path, monkeypatch):
    import maverick.self_tuning_budget as m
    b = _learner(tmp_path, min_samples=1)
    monkeypatch.setattr(m, "enabled", lambda: False)
    m.record_run_cost("research", 5.0, learner=b)
    assert b.stats("research")["count"] == 0


def test_shared_learner_is_tenant_scoped(tmp_path, monkeypatch):
    import maverick.self_tuning_budget as m
    from maverick.paths import data_dir, tenant_scope

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(m, "enabled", lambda: True)
    m.reset_shared()

    with tenant_scope(tenant="victim"):
        victim_path = data_dir("budget_tuning.json")
        for _ in range(8):
            m.record_run_cost("research", 1.0)
        assert m.suggested_max_dollars("research") == 1.3

    with tenant_scope(tenant="attacker"):
        attacker_path = data_dir("budget_tuning.json")
        assert attacker_path != victim_path
        assert m.shared().path == attacker_path
        assert m.suggested_max_dollars("research") is None
        for _ in range(8):
            m.record_run_cost("research", 100.0)
        assert m.suggested_max_dollars("research") == 100.0

    assert victim_path.exists()
    assert attacker_path.exists()
    with tenant_scope(tenant="victim"):
        assert m.shared().path == victim_path
        assert m.suggested_max_dollars("research") == 1.3


def test_budget_from_config_uses_suggestion_as_lowest_precedence(tmp_path, monkeypatch):
    import maverick.self_tuning_budget as stb
    learner = _learner(tmp_path, min_samples=2, margin=1.0, quantile=1.0,
                       floor=0.1, ceiling=100)
    learner.observe("research", 7.0)
    learner.observe("research", 7.0)
    monkeypatch.setattr(stb, "enabled", lambda: True)
    monkeypatch.setattr(stb, "shared", lambda: learner)
    # no config/overrides -> learned cap fills max_dollars
    from maverick.budget import budget_from_config
    monkeypatch.setattr("maverick.config.get_budget_overrides", dict)
    b = budget_from_config(task_class="research")
    assert b.max_dollars == 7.0
    # an explicit override still wins over the learned suggestion
    b2 = budget_from_config(task_class="research", max_dollars=2.0)
    assert b2.max_dollars == 2.0


def test_task_class_helper_buckets_by_verb():
    from maverick.orchestrator import _budget_task_class

    class _G:
        title = "Research the market for X"
    assert _budget_task_class(_G()) == "research"

    class _Empty:
        title = ""
    assert _budget_task_class(_Empty()) == "default"

    class _Numeric:
        title = "2027 roadmap"
    assert _budget_task_class(_Numeric()) == "default"


def test_observe_is_concurrency_safe(tmp_path):
    """Separate learners at one path (≈ separate processes) must accumulate
    observations, not clobber each other."""
    import threading

    p = tmp_path / "bt.json"
    n, per = 8, 25

    def worker():
        b = SelfTuningBudget(path=p, rng=Random(0))
        for _ in range(per):
            b.observe("research", 1.0)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = SelfTuningBudget(path=p, rng=Random(0))
    assert final.stats("research")["count"] == n * per
    assert list(tmp_path.glob("*.tmp")) == []
