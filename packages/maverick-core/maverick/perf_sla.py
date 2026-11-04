"""Public performance SLA harness.

The SLA itself is published at ``docs/perf-sla.md``; this module is its
**enforcement**: each row of the SLA table that is measurable in-process is a
check here, run against the real code paths (no mocks), compared to the
published threshold. ``python -m maverick.perf_sla --ci`` exits non-zero on
any breach — the release gate that keeps the published numbers honest.

Thresholds are conservative cold-CI-runner numbers (see the doc). They live
in :data:`THRESHOLDS` so changing one is an explicit, reviewed act.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from statistics import quantiles

# Published thresholds (ms unless noted). Changing one == changing the SLA.
THRESHOLDS = {
    "dispatch_overhead_p95_ms": 5.0,
    "compaction_200msg_ms": 250.0,
    "world_write_p95_ms": 25.0,
    "world_read_p95_ms": 25.0,
}


@dataclass(frozen=True)
class SLAResult:
    name: str
    measured: float
    threshold: float
    unit: str = "ms"

    @property
    def passed(self) -> bool:
        return self.measured <= self.threshold


def _p95(samples_ms: list[float]) -> float:
    if len(samples_ms) < 2:
        return samples_ms[0] if samples_ms else 0.0
    return quantiles(samples_ms, n=20)[-1]  # 95th percentile


def _time_ms(fn: Callable[[], object], n: int) -> list[float]:
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


def check_dispatch_overhead(n: int = 200) -> SLAResult:
    """Registry lookup + dispatch of a no-op tool through the real registry."""
    import asyncio

    from .tools import Tool, ToolRegistry
    reg = ToolRegistry()
    reg.register(Tool(name="noop", description="sla probe",
                      fn=lambda args: "ok",
                      input_schema={"type": "object", "properties": {}}))

    async def once():
        return await reg.run("noop", {})

    loop = asyncio.new_event_loop()
    try:
        samples = _time_ms(lambda: loop.run_until_complete(once()), n)
    finally:
        loop.close()
    return SLAResult("dispatch_overhead_p95_ms", round(_p95(samples), 3),
                     THRESHOLDS["dispatch_overhead_p95_ms"])


def check_compaction_latency(messages: int = 200) -> SLAResult:
    """One real compaction pass over a representative long history."""
    from .compaction import compact_messages
    history = [{"role": "user", "content": "hi"}]
    for i in range(messages - 1):
        history.append({
            "role": "assistant" if i % 2 else "user",
            "content": [{"type": "tool_result", "tool_use_id": f"t{i}",
                         "content": "x" * 3000}] if i % 3 == 0 else f"turn {i}",
        })
    samples = _time_ms(lambda: compact_messages(list(history)), 5)
    return SLAResult("compaction_200msg_ms", round(min(samples), 3),
                     THRESHOLDS["compaction_200msg_ms"])


def check_world_write(n: int = 100) -> SLAResult:
    import tempfile
    from pathlib import Path

    from .world_model import WorldModel
    with tempfile.TemporaryDirectory() as d:
        world = WorldModel(Path(d) / "world.db")
        gid = world.create_goal("sla", "")
        samples = _time_ms(lambda: world.append_event(gid, "sla", "probe", "row"), n)
        world.close()
    return SLAResult("world_write_p95_ms", round(_p95(samples), 3),
                     THRESHOLDS["world_write_p95_ms"])


def check_world_read(n: int = 100) -> SLAResult:
    import tempfile
    from pathlib import Path

    from .world_model import WorldModel
    with tempfile.TemporaryDirectory() as d:
        world = WorldModel(Path(d) / "world.db")
        gid = world.create_goal("sla", "")
        for i in range(50):
            world.append_event(gid, "sla", "probe", f"row {i}")
        samples = _time_ms(
            lambda: (world.get_goal(gid), world.goal_events(gid, limit=50)), n)
        world.close()
    return SLAResult("world_read_p95_ms", round(_p95(samples), 3),
                     THRESHOLDS["world_read_p95_ms"])


CHECKS: tuple[Callable[[], SLAResult], ...] = (
    check_dispatch_overhead,
    check_compaction_latency,
    check_world_write,
    check_world_read,
)


def run_all() -> list[SLAResult]:
    return [check() for check in CHECKS]


def render(results: list[SLAResult]) -> str:
    lines = ["performance SLA (docs/perf-sla.md):"]
    for r in results:
        verdict = "PASS" if r.passed else "BREACH"
        lines.append(f"  {verdict}  {r.name}: {r.measured}{r.unit} "
                     f"(threshold {r.threshold}{r.unit})")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.perf_sla",
                                description="Measure the published perf SLA.")
    p.add_argument("--ci", action="store_true", help="exit 1 on any breach")
    args = p.parse_args(argv)
    results = run_all()
    print(render(results))
    if args.ci and any(not r.passed for r in results):
        return 1
    return 0


__all__ = ["THRESHOLDS", "SLAResult", "run_all", "render",
           "check_dispatch_overhead", "check_compaction_latency",
           "check_world_write", "check_world_read"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
