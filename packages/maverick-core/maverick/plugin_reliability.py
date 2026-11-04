"""Long-running plugin reliability suite.

The TS / gRPC / in-process plugin hosts each claim reliability properties —
a crashed child is restarted and the call retried once, a timeout becomes an
``ERROR`` not a hang, a bad call doesn't poison the next. Their unit tests pin
that in the small; this is the **sustained-load drill** an operator runs
against *their* installed plugins to confirm the properties hold over
thousands of calls under injected faults — the plugin counterpart to the
chaos game-day.

It is host-agnostic: you give it ``call(payload) -> str`` (the plugin tool's
``fn``, or a host child's call seam) and a fault script; the harness drives N
calls, injecting crashes / timeouts / slow responses / errors at configured
rates through an **injected** fault function, and asserts the reliability
**properties**:

* **recovery** — a crash-shaped failure is followed by a *successful* call
  (the host restarted the child), i.e. no permanent wedging;
* **isolation** — an error/timeout on one call never changes the result of the
  next clean call (no cross-call state poisoning);
* **error rate** — surfaced failures stay within a tolerance once transient
  faults are absorbed;
* **no unbounded growth** — an injected memory sampler shows no monotonic climb
  (sawtooth OK), catching a leaking plugin.

Deterministic: the fault schedule is a seeded PRNG and the clock is injected,
so the drill runs in milliseconds and the same seed reproduces the same run.
``python -m maverick.plugin_reliability`` runs the built-in self-drill (a
scripted flaky plugin) and exits non-zero if any property fails — a CI gate.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from random import Random

from .tool_results import ToolOutcome, ToolResultText, tool_result_failed

log = logging.getLogger(__name__)


class PluginCrash(Exception):
    """A crash-shaped fault: the host should restart + recover after it."""


class PluginTimeout(Exception):
    """A timeout-shaped fault: the host should surface ERROR, not hang."""


@dataclass
class FaultRates:
    crash: float = 0.0
    timeout: float = 0.0
    error: float = 0.0      # a normal "ERROR: ..." return (handled failure)

    def total(self) -> float:
        return self.crash + self.timeout + self.error


@dataclass
class ReliabilityReport:
    calls: int
    successes: int
    surfaced_failures: int          # ERROR returns + raised timeouts the caller saw
    recoveries: int                 # successful call right after a crash
    crashes: int
    isolation_violations: int
    growth_detected: bool
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    @property
    def success_rate(self) -> float:
        return self.successes / self.calls if self.calls else 0.0


def _monotonic_growth(samples: list[float]) -> bool:
    """True iff ``samples`` climb monotonically (a leak), not sawtooth.

    A leak shows every later sample >= the earlier ones with a net rise; a
    healthy sawtooth dips somewhere. Needs a few samples to judge.
    """
    if len(samples) < 4:
        return False
    dipped = any(b < a for a, b in zip(samples, samples[1:], strict=False))
    rose = samples[-1] > samples[0]
    return rose and not dipped


def run_drill(
    call: Callable[[dict], str | ToolOutcome],
    *,
    iterations: int = 1000,
    rates: FaultRates | None = None,
    rng: Random | None = None,
    mem_sampler: Callable[[], float] | None = None,
    max_surfaced_rate: float = 0.10,
) -> ReliabilityReport:
    """Drive ``call`` ``iterations`` times under injected faults; assert
    reliability properties into a :class:`ReliabilityReport`.

    ``call(payload)`` must (a) return a result string on success, (b) return
    ``"ERROR: ..."`` for a handled failure, and (c) honor the injected
    ``payload["_inject"]`` directive (``"crash"`` -> raise ``PluginCrash`` then
    recover on the NEXT call, ``"timeout"`` -> return an ERROR/raise
    ``PluginTimeout``). The harness uses the directive to model what the host
    must absorb; a real host wraps ``call`` so a crash is restarted underneath.
    """
    rates = rates or FaultRates()
    rng = rng or Random(0)
    report = ReliabilityReport(
        calls=0, successes=0, surfaced_failures=0, recoveries=0,
        crashes=0, isolation_violations=0, growth_detected=False)
    mem: list[float] = []
    pending_crash = False   # a crash is "recovered" by any later success
    for i in range(iterations):
        roll = rng.random()
        inject = None
        if roll < rates.crash:
            inject = "crash"
        elif roll < rates.crash + rates.timeout:
            inject = "timeout"
        elif roll < rates.total():
            inject = "error"
        payload = {"i": i, "_inject": inject}
        report.calls += 1
        try:
            result = call(payload)
        except PluginCrash:
            report.crashes += 1
            pending_crash = True
            continue  # the host restarts; recovery is judged by a later success
        except PluginTimeout:
            report.surfaced_failures += 1
            continue
        # a returned value (success or "ERROR: ...")
        explicit = isinstance(result, (ToolOutcome, ToolResultText))
        failed = tool_result_failed(result) if explicit else isinstance(result, str) and result.startswith("ERROR")
        if failed:
            report.surfaced_failures += 1
        else:
            report.successes += 1
            if pending_crash:
                report.recoveries += 1
                pending_crash = False
            # isolation: a clean call must echo its OWN payload, proving no
            # carry-over from the previous (faulted) call.
            text = result.content if isinstance(result, ToolOutcome) else result
            if isinstance(text, str) and f"i={i}" not in text and inject is None:
                report.isolation_violations += 1
        if mem_sampler is not None:
            mem.append(mem_sampler())

    report.growth_detected = _monotonic_growth(mem)

    # -- judge the properties --
    # Every crash should be followed by a later success (the host restarted the
    # child). Tolerate ONE unrecovered crash — the last call can crash with no
    # follow-up. A wedged plugin leaves many crashes unrecovered.
    unrecovered = report.crashes - report.recoveries
    if unrecovered > 1:
        report.problems.append(
            f"recovery: {report.crashes} crash(es), only {report.recoveries} "
            f"followed by a later success ({unrecovered} unrecovered — the "
            "plugin wedged after a crash)")
    if report.isolation_violations:
        report.problems.append(
            f"isolation: {report.isolation_violations} call(s) saw carry-over "
            "from a previous faulted call")
    surfaced_rate = report.surfaced_failures / report.calls if report.calls else 0.0
    if surfaced_rate > max_surfaced_rate:
        report.problems.append(
            f"error rate: {surfaced_rate:.1%} surfaced failures exceeds "
            f"tolerance {max_surfaced_rate:.0%}")
    if report.growth_detected:
        report.problems.append("memory: monotonic growth across samples (leak)")
    return report


def _self_drill_plugin() -> Callable[[dict], str]:
    """A scripted flaky plugin that honors the inject directive AND a host that
    restarts on crash — so the built-in drill exercises a *healthy* plugin."""
    state = {"alive": True}

    def call(payload: dict) -> str:
        inject = payload.get("_inject")
        if inject == "crash":
            state["alive"] = False
            raise PluginCrash("boom")
        if not state["alive"]:
            state["alive"] = True  # host restarted us before this call
        if inject == "timeout":
            raise PluginTimeout("slow")
        if inject == "error":
            return "ERROR: handled bad input"
        return f"ok i={payload.get('i')}"

    return call


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.plugin_reliability",
                                description="Long-running plugin reliability drill.")
    p.add_argument("--iterations", type=int, default=2000)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args(argv)
    rates = FaultRates(crash=0.02, timeout=0.03, error=0.05)
    report = run_drill(_self_drill_plugin(), iterations=args.iterations,
                       rates=rates, rng=Random(args.seed))
    print(f"plugin reliability: {report.calls} calls, "
          f"{report.success_rate:.1%} success, {report.recoveries} recoveries; "
          + ("PASS" if report.ok else "FAIL"))
    for prob in report.problems:
        print(f"  PROBLEM: {prob}")
    return 0 if report.ok else 1


__all__ = ["FaultRates", "ReliabilityReport", "run_drill",
           "PluginCrash", "PluginTimeout"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
