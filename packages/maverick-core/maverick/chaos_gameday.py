"""Chaos game-day script.

The chaos harness (:mod:`maverick.chaos`) injects faults; a *game day* is the
drill that uses it: a scripted sequence of fault scenarios run against a
work-shaped probe, each verifying the resilience property it targets — "tool
dispatch flakes at 20%: did retries absorb it?", "the LLM fails outright:
did the run degrade to a terminal status instead of hanging?".

Deterministic by construction (the chaos PRNG is seeded), offline (the probe
is a scripted callable, not a live model), CI-runnable:
``python -m maverick.chaos_gameday`` exits 1 if any scenario's resilience
property does not hold — the drill you run before relying on the recovery
paths in production.

The default probe exercises the real retry layer
(:mod:`maverick.tool_reliability`) under injected ``tool_dispatch`` faults.
Operators add scenarios for their own deployment in a copy of this script;
the point of a game day is rehearsing *your* failure modes.

Run it as a STANDALONE drill (CI job or terminal), not inside a serving
process: backoff virtualization patches ``asyncio.sleep`` for the drill's
duration (restored in ``finally``), which would distort concurrent work.
"""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from typing import Any

from .chaos import ChaosController, ChaosInjected, maybe_fail


def _inject_transient(stage: str, message: str) -> None:
    """Roll the chaos dice for ``stage``; on a hit, raise a TRANSIENT-shaped
    fault (TimeoutError). Chaos decides *where* to fail; the drill decides
    *what kind* of failure — and the resilience property under test is the
    retry layer's handling of transient faults, which the classifier
    correctly refuses to do for unknown exception types like ChaosInjected."""
    try:
        maybe_fail(stage, message=message)
    except ChaosInjected as e:
        raise TimeoutError(str(e)) from e


@dataclass
class ScenarioResult:
    name: str
    holds: bool
    detail: str


@dataclass
class GameDayReport:
    results: list[ScenarioResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(r.holds for r in self.results)


def _flaky_tool_probe(calls: int = 30) -> dict[str, Any]:
    """Run a read-shaped tool through the REAL retry layer under chaos.

    Returns {attempted, succeeded, surfaced_failures} — with retries working,
    injected sub-100% fault rates must not surface as failures. Backoff
    sleeps are virtualized (recorded, not slept): the drill verifies retry
    DECISIONS, and a CI drill that sleeps for real would dwarf the suite.
    """
    from . import tool_reliability
    from .tool_reliability import run_with_retry

    succeeded = 0
    raw_failures = 0

    async def _one() -> None:
        nonlocal succeeded

        async def probe() -> str:
            _inject_transient("tool_dispatch", "gameday: injected tool fault")
            return "ok"

        result = await run_with_retry("repo_map", probe)
        if result == "ok":
            succeeded += 1

    async def fake_sleep(delay: float) -> None:
        return None

    async def _all() -> None:
        for _ in range(calls):
            try:
                await _one()
            except TimeoutError:
                nonlocal raw_failures
                raw_failures += 1

    real_sleep = tool_reliability.asyncio.sleep
    tool_reliability.asyncio.sleep = fake_sleep  # type: ignore[assignment]
    try:
        asyncio.run(_all())
    finally:
        tool_reliability.asyncio.sleep = real_sleep  # type: ignore[assignment]
    return {"attempted": calls, "succeeded": succeeded, "surfaced_failures": raw_failures}


def scenario_tool_flake_absorbed() -> ScenarioResult:
    """20% tool-dispatch fault rate: the retry layer must absorb (almost) all.

    Property: surfaced failures stay under 5% of calls — a fault rate the
    retry/backoff layer is designed for must not reach the agent loop.
    """
    # NB: rates go INTO active() -- it snapshots+restores state and calls
    # set() with ITS kwargs, so a prior bare set() would be wiped.
    with ChaosController().active(tool_dispatch_fail_pct=20, seed=7):
        stats = _flaky_tool_probe()
    surfaced = stats["surfaced_failures"]
    holds = surfaced <= max(1, stats["attempted"] // 20)
    return ScenarioResult(
        "tool_flake_absorbed", holds,
        f"20% injected faults over {stats['attempted']} calls -> "
        f"{stats['succeeded']} succeeded, {surfaced} surfaced",
    )


def scenario_hard_outage_fails_fast() -> ScenarioResult:
    """100% fault rate: the property is *bounded failure*, not a hang.

    With everything failing, run_with_retry must exhaust its policy and
    surface the error after a BOUNDED number of attempts — never spin
    forever. Backoff sleeps are virtualized (recorded, not slept) so the
    drill verifies the bound in milliseconds; the property under test is
    attempt exhaustion, not wall-clock waiting.
    """
    from . import tool_reliability
    from .tool_reliability import run_with_retry

    surfaced = False
    attempts = 0
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    real_sleep = tool_reliability.asyncio.sleep
    tool_reliability.asyncio.sleep = fake_sleep  # type: ignore[assignment]
    try:
        with ChaosController().active(tool_dispatch_fail_pct=100, seed=7):
            async def probe() -> str:
                nonlocal attempts
                attempts += 1
                _inject_transient("tool_dispatch", "gameday: hard outage")
                return "ok"

            try:
                asyncio.run(run_with_retry("repo_map", probe))
            except TimeoutError:
                surfaced = True
    finally:
        tool_reliability.asyncio.sleep = real_sleep  # type: ignore[assignment]
    holds = surfaced and 1 < attempts <= 20
    return ScenarioResult(
        "hard_outage_fails_fast", holds,
        f"total outage surfaced={surfaced} after {attempts} attempts "
        f"({sum(slept):.0f}s of backoff, virtualized)",
    )


def scenario_chaos_off_is_clean() -> ScenarioResult:
    """Control: with chaos inactive, the same probe is failure-free."""
    stats = _flaky_tool_probe(calls=10)
    holds = stats["succeeded"] == 10 and stats["surfaced_failures"] == 0
    return ScenarioResult(
        "control_no_chaos", holds,
        f"{stats['succeeded']}/10 clean without injection",
    )


SCENARIOS = (
    scenario_chaos_off_is_clean,
    scenario_tool_flake_absorbed,
    scenario_hard_outage_fails_fast,
)


def run_gameday() -> GameDayReport:
    report = GameDayReport()
    for scenario in SCENARIOS:
        try:
            report.results.append(scenario())
        except Exception as e:  # a crashed scenario is a failed drill
            report.results.append(ScenarioResult(scenario.__name__, False,
                                                 f"scenario crashed: {e}"))
    return report


def main() -> int:
    report = run_gameday()
    for r in report.results:
        print(f"[{'PASS' if r.holds else 'FAIL'}] {r.name}: {r.detail}")
    print(f"game day: {'PASS' if report.ok else 'FAIL'}")
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover -- exercised via main() in tests
    sys.exit(main())
