"""Long-running plugin reliability drill: properties over injected faults."""
from __future__ import annotations

from random import Random

from maverick.plugin_reliability import (
    FaultRates,
    PluginCrash,
    PluginTimeout,
    run_drill,
)
from maverick.tool_results import ToolOutcome, ToolResultState


def _healthy_plugin():
    """Honors the inject directive; a crash 'restarts' transparently."""
    alive = {"v": True}

    def call(payload):
        inject = payload.get("_inject")
        if inject == "crash":
            alive["v"] = False
            raise PluginCrash("boom")
        alive["v"] = True  # host restarted us
        if inject == "timeout":
            raise PluginTimeout("slow")
        if inject == "error":
            return "ERROR: handled"
        return f"ok i={payload.get('i')}"

    return call


def test_drill_respects_explicit_tool_outcomes():
    def call(payload):
        if payload["i"] == 0:
            return ToolOutcome(ToolResultState.SUCCEEDED, "ERROR: valid data i=0")
        return ToolOutcome(ToolResultState.INDETERMINATE, "remote response was inconclusive")

    report = run_drill(call, iterations=2, max_surfaced_rate=1.0)
    assert report.successes == 1
    assert report.surfaced_failures == 1
    assert report.isolation_violations == 0


def test_healthy_plugin_passes_all_properties():
    rep = run_drill(_healthy_plugin(), iterations=500,
                    rates=FaultRates(crash=0.02, timeout=0.03, error=0.04),
                    rng=Random(1))
    assert rep.ok, rep.problems
    assert rep.crashes - rep.recoveries <= 1  # at most a trailing crash unrecovered
    assert rep.isolation_violations == 0
    assert rep.success_rate > 0.8


def test_clean_run_no_faults():
    rep = run_drill(_healthy_plugin(), iterations=100, rates=FaultRates(),
                    rng=Random(0))
    assert rep.ok and rep.successes == 100 and rep.surfaced_failures == 0


def test_wedged_plugin_fails_recovery_property():
    # A plugin that STAYS dead after a crash (host never restarts it) -> the
    # next calls keep crashing, so recoveries < crashes.
    dead = {"v": False}

    def call(payload):
        if payload.get("_inject") == "crash" or dead["v"]:
            dead["v"] = True
            raise PluginCrash("permanently wedged")
        return f"ok i={payload.get('i')}"

    rep = run_drill(call, iterations=200, rates=FaultRates(crash=0.05),
                    rng=Random(2))
    assert not rep.ok
    assert any("recovery" in p for p in rep.problems)


def test_isolation_violation_detected():
    # A plugin that echoes the PREVIOUS call's index (state carry-over).
    last = {"i": None}

    def call(payload):
        prev = last["i"]
        last["i"] = payload.get("i")
        # on a clean call, wrongly report the previous index
        if payload.get("_inject") is None and prev is not None:
            return f"ok i={prev}"
        return f"ok i={payload.get('i')}"

    rep = run_drill(call, iterations=100, rates=FaultRates(), rng=Random(3))
    assert not rep.ok
    assert any("isolation" in p for p in rep.problems)


def test_high_error_rate_flagged():
    def call(payload):
        return "ERROR: always fails"

    rep = run_drill(call, iterations=100, rates=FaultRates(error=1.0),
                    rng=Random(4), max_surfaced_rate=0.1)
    assert not rep.ok
    assert any("error rate" in p for p in rep.problems)


def test_memory_leak_detected():
    growing = {"v": 0.0}

    def sampler():
        growing["v"] += 1.0  # strictly monotonic == a leak
        return growing["v"]

    rep = run_drill(_healthy_plugin(), iterations=50, rates=FaultRates(),
                    rng=Random(5), mem_sampler=sampler)
    assert rep.growth_detected and any("memory" in p for p in rep.problems)


def test_sawtooth_memory_is_healthy():
    vals = iter([10, 20, 5, 25, 8, 30, 6])  # dips -> not a leak

    def sampler():
        try:
            return float(next(vals))
        except StopIteration:
            return 7.0

    rep = run_drill(_healthy_plugin(), iterations=12, rates=FaultRates(),
                    rng=Random(6), mem_sampler=sampler)
    assert not rep.growth_detected


def test_deterministic_with_seed():
    a = run_drill(_healthy_plugin(), iterations=200,
                  rates=FaultRates(crash=0.05, timeout=0.05), rng=Random(42))
    b = run_drill(_healthy_plugin(), iterations=200,
                  rates=FaultRates(crash=0.05, timeout=0.05), rng=Random(42))
    assert (a.crashes, a.surfaced_failures, a.successes) == \
           (b.crashes, b.surfaced_failures, b.successes)
