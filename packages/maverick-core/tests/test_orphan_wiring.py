"""Wiring of previously-orphaned capabilities into live chokepoints."""
from __future__ import annotations

import pytest

# ---- energy-aware routing wired into model_for_role -------------------------

def test_cheaper_model_tiers():
    from maverick.llm import MODEL_HAIKU, MODEL_OPUS, MODEL_SONNET, _cheaper_model
    assert _cheaper_model(MODEL_OPUS) == MODEL_SONNET
    assert _cheaper_model(MODEL_SONNET) == MODEL_HAIKU
    assert _cheaper_model(MODEL_HAIKU) == MODEL_HAIKU  # no lower tier


def test_model_for_role_downgrades_on_low_battery(monkeypatch):
    import maverick.energy_aware_router as ear
    import maverick.llm as llm
    # Force energy-aware ON + a low-battery reading.
    monkeypatch.setattr(ear, "enabled", lambda: True)
    monkeypatch.setattr(ear, "battery_state",
                        lambda: ear.BatteryState(on_battery=True, percent=10))
    # No config/override pinned -> default path -> orchestrator is Opus -> Sonnet.
    monkeypatch.setattr(llm, "get_role_model", lambda role: None, raising=False)
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE_ORCHESTRATOR", raising=False)
    assert llm.model_for_role("orchestrator") == llm.MODEL_SONNET


def test_model_for_role_no_downgrade_on_wall_power(monkeypatch):
    import maverick.energy_aware_router as ear
    import maverick.llm as llm
    monkeypatch.setattr(ear, "enabled", lambda: True)
    monkeypatch.setattr(ear, "battery_state",
                        lambda: ear.BatteryState(on_battery=False, percent=100))
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    assert llm.model_for_role("orchestrator") == llm.MODEL_OPUS


# ---- rate-limit predictor + circuit breaker fed from dispatch helpers --------

def test_record_provider_call_feeds_predictor():
    from maverick import rate_limit_predictor as rlp
    from maverick.llm import _record_provider_call
    rlp.reset()
    _record_provider_call("anthropic")
    _record_provider_call("anthropic")
    rows = {r["provider"]: r["recorded"] for r in rlp.report()}
    assert rows.get("anthropic") == 2


def test_feed_circuit_trips_breaker_on_failures():
    from maverick import circuit_breaker as cb
    from maverick.llm import _feed_circuit
    cb.reset_all()
    for _ in range(10):  # well past the default threshold
        _feed_circuit("flaky-provider", error=True)
    states = {s["key"]: s["state"] for s in cb.snapshot()}
    assert states.get("llm:flaky-provider") == "open"


def test_feed_circuit_success_keeps_closed():
    from maverick import circuit_breaker as cb
    from maverick.llm import _feed_circuit
    cb.reset_all()
    _feed_circuit("good-provider", error=False)
    states = {s["key"]: s["state"] for s in cb.snapshot()}
    assert states.get("llm:good-provider") == "closed"


# ---- diag CLI surfaces the read-only utilities ------------------------------

def test_diag_cli_group_registered():
    from maverick.cli import main
    names = main.commands["diag"].commands
    assert {"circuits", "ratelimits", "health", "cost-by-tag"} <= set(names)


# ---- approval delegation reachable from the consent path --------------------

def test_approval_delegation_route_importable_and_noop_without_rules():
    from maverick.approval_delegation import route
    # No rules configured -> None (default queue), so consent wiring is a no-op.
    assert route({"risk": "high", "tool": "shell"}, rules=[]) is None


# ---- queue dispatcher install reachable -------------------------------------

def test_queue_install_noop_without_backend(monkeypatch):
    import maverick.config as cfg
    import maverick.queue_dispatcher as qd
    import maverick.runner as runner
    monkeypatch.setattr(cfg, "load_config", dict)
    original = runner.get_dispatcher()
    try:
        assert qd.install_from_config() is False
        assert runner.get_dispatcher() is original
    finally:
        runner.set_dispatcher(original)


# ---- local skill distillation reachable -------------------------------------

def test_replay_trace_wired_into_blackboard(tmp_path):
    from maverick.blackboard import Blackboard
    from maverick.replay.trace import TraceWriter, read_trace
    bb = Blackboard()
    # Default: no trace writer -> posts don't crash and nothing is written.
    bb.post("a", "plan", "x")
    # Attach a writer -> every post is mirrored to the JSONL trace.
    path = tmp_path / "g.jsonl"
    bb.attach_trace(TraceWriter(path))
    bb.post("orchestrator", "plan", "do the thing")
    bb.post("coder", "tool", "ran tests")
    events = read_trace(path)
    assert [e["kind"] for e in events] == ["plan", "tool"]
    assert events[0]["agent"] == "orchestrator"


@pytest.mark.parametrize("enabled", [False, True])
def test_skill_distillation_local_gate(monkeypatch, enabled):
    import maverick.skill.distillation_local as sdl
    monkeypatch.setenv("MAVERICK_DISTILL_LOCAL", "1" if enabled else "0")
    assert sdl.enabled() is enabled


def test_skill_distillation_frozen_reflects_calibration(monkeypatch):
    """orchestrator._skill_distillation_frozen() gates per-run local skill
    distillation on calibration.learning_frozen() -- the same interlock
    dreaming._consolidate_learning already enforces. Without this, the
    busiest distillation path (every run, not just the nightly dream cycle)
    bypassed the freeze entirely."""
    import maverick.calibration as calibration
    import maverick.orchestrator as orchestrator

    monkeypatch.setattr(calibration, "learning_frozen", lambda: True)
    assert orchestrator._skill_distillation_frozen() is True

    monkeypatch.setattr(calibration, "learning_frozen", lambda: False)
    assert orchestrator._skill_distillation_frozen() is False


def test_skill_distillation_frozen_fails_open(monkeypatch):
    import maverick.calibration as calibration
    import maverick.orchestrator as orchestrator

    def _boom():
        raise RuntimeError("calibration unavailable")

    monkeypatch.setattr(calibration, "learning_frozen", _boom)
    assert orchestrator._skill_distillation_frozen() is False


def _split_run_goal_impl_distillation_blocks() -> tuple[str, str]:
    """(auto_distill block source, local-distillation block source).

    The two distillation call sites both invoke a function literally named
    ``_skill_distillation_frozen``, just with different arguments (the
    auto_distill site calls it bare; the local-distillation site passes
    ``config=``). A single whole-function ``src.index("_skill_distillation_frozen()")``
    search is fragile: since the substring with empty parens only matches
    the FIRST (auto_distill) call site, a test checking the SECOND
    (local-distillation) site's ordering against ITS OWN nearby call would
    silently pass by finding the unrelated earlier one instead. Splitting on
    the local-distillation block's own leading comment makes each half
    unambiguous."""
    import inspect

    import maverick.orchestrator as orchestrator

    # The main lifecycle must call the extracted success-learning stage, and
    # the freeze checks must guard both distillation paths inside that stage.
    entry = inspect.getsource(orchestrator._run_goal_impl)
    assert "await _finish_goal_learning(" in entry
    src = inspect.getsource(orchestrator._finish_goal_learning)
    marker = "# Default-on local continuous learning"
    split_at = src.index(marker)
    return src[:split_at], src[split_at:]


def test_run_goal_impl_checks_the_freeze_before_distilling():
    """Guard against the gate rotting back out of the call site: the actual
    per-run LOCAL distillation block in ``_finish_goal_learning`` must call
    ``_skill_distillation_frozen(...)`` before ``distill_and_save_gated``."""
    _auto_block, local_block = _split_run_goal_impl_distillation_blocks()
    frozen_idx = local_block.index("_skill_distillation_frozen(")
    distill_idx = local_block.index("distill_and_save_gated(")
    assert frozen_idx < distill_idx


def test_run_goal_impl_checks_the_freeze_before_auto_distill():
    """The SECOND distillation call site in the same function -- the older,
    LLM-based MAVERICK_AUTO_DISTILL=1 path (``skills.distill``) -- must also
    refuse while learning is frozen. Only gating the newer local-distillation
    path left this one, still live behind its opt-in flag, bypassing the
    same interlock."""
    auto_block, _local_block = _split_run_goal_impl_distillation_blocks()
    frozen_idx = auto_block.index("_skill_distillation_frozen(")
    auto_distill_idx = auto_block.index("distill(goal.title")
    assert frozen_idx < auto_distill_idx


def test_skill_distillation_frozen_reuses_passed_config(monkeypatch):
    """The local-distillation gate (``_sdl.enabled(config=...) and not
    _skill_distillation_frozen(config=...)``) must load config ONCE and
    reuse it for both checks, not once per check -- the two checks used to
    each independently call ``config.load_config()``.

    ``distillation_local.enabled()`` has its OWN unrelated, unavoidable
    ``load_config()`` call inside ``governed_learning_env_flag`` (it
    verifies every config source parses cleanly before honoring an env
    override) -- that one fires with or without this fix and is not what's
    being tested. The claim this test pins is narrower and unambiguous:
    the calibration half (``_skill_distillation_frozen`` ->
    ``learning_frozen_safe`` -> ``learning_frozen`` -> ``_settings`` ->
    ``get_calibration``), which has no such confounder, makes ZERO calls
    when given an already-loaded config -- it used to make exactly one."""
    import maverick.calibration as calibration
    import maverick.config as config
    import maverick.orchestrator as orchestrator

    calls = []
    real_load_config = config.load_config

    def _counting_load_config(*a, **kw):
        calls.append(1)
        return real_load_config(*a, **kw)

    _cfg = config.load_config()
    expected = calibration.learning_frozen()  # real behavior, computed before mocking
    monkeypatch.setattr(config, "load_config", _counting_load_config)
    assert orchestrator._skill_distillation_frozen(config=_cfg) is expected
    assert calls == []


def test_distillation_local_enabled_reuses_passed_config_for_the_section_read(
    monkeypatch,
):
    """The other half of the same gate: ``distillation_local.enabled()``'s
    OWN section read (``get_self_learning``) must reuse a passed-in config
    instead of loading it again. ``governed_learning_env_flag`` makes its
    own unrelated, unavoidable ``load_config()`` call first (see the
    docstring on the sibling test above) -- that's the ONE call this test
    expects; a second one would mean the section read stopped reusing it."""
    import maverick.config as config
    import maverick.skill.distillation_local as distillation_local

    monkeypatch.delenv("MAVERICK_DISTILL_LOCAL", raising=False)
    calls = []
    real_load_config = config.load_config

    def _counting_load_config(*a, **kw):
        calls.append(1)
        return real_load_config(*a, **kw)

    _cfg = config.load_config()
    expected = distillation_local.enabled()  # real behavior, computed before mocking
    monkeypatch.setattr(config, "load_config", _counting_load_config)
    assert distillation_local.enabled(config=_cfg) is expected
    assert len(calls) == 1  # governed_learning_env_flag's own check, not a second section read
