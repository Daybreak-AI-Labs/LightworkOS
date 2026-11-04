"""Repeatable local runtime measurements; never used as a timing pass/fail gate.

Run with ``python -m benchmarks.runtime_performance --output measurements.json``
from an installed source checkout. Results describe this host and workload;
they are not production latency forecasts or comparable across unlike hosts.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import platform
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from benchmarks._common.governance_metrics import latency_summary


def _measure(fn, samples: int) -> dict:
    timings = []
    for _ in range(samples):
        started = time.perf_counter_ns()
        fn()
        timings.append(time.perf_counter_ns() - started)
    return latency_summary(timings)


async def _idle_event_loop(samples: int) -> dict:
    timings = []
    for _ in range(samples):
        started = time.perf_counter_ns()
        await asyncio.sleep(0)
        timings.append(time.perf_counter_ns() - started)
    return latency_summary(timings)


def measure(samples: int = 10) -> dict:
    """Collect deterministic workload results with explicit scope metadata."""
    if samples < 1:
        raise ValueError("samples must be positive")
    from maverick.safety.unicode_filter import normalize
    from maverick.tools import base_registry
    from maverick_knowledge.store import SqliteVectorStore

    rng = random.Random(0)
    vectors = [[rng.random() for _ in range(384)] for _ in range(1000)]
    query = [rng.random() for _ in range(384)]
    store = SqliteVectorStore()
    store.add("performance", [(str(i), "example", vector, {}) for i, vector in enumerate(vectors)])
    text = "example\u200btext " * 2000
    try:
        with tempfile.TemporaryDirectory(prefix="lightwork-perf-") as workdir:
            sandbox = SimpleNamespace(workdir=Path(workdir))
            timings = {
                "cold_process_import": _measure(
                    lambda: subprocess.run(
                        [sys.executable, "-c", "import maverick"],
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    ), samples,
                ),
                "registry_assembly": _measure(
                    lambda: base_registry(SimpleNamespace(), sandbox, _include_generated_tools=False),
                    samples,
                ),
                "sqlite_vector_search_1000x384_k5": _measure(
                    lambda: store.search("performance", query, k=5), samples,
                ),
                "unicode_normalization": _measure(lambda: normalize(text), samples),
                "event_loop_idle_yield": asyncio.run(_idle_event_loop(samples)),
            }
    finally:
        store.close()
    return {
        "schema": "lightwork.runtime-performance.v1",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "units": "microseconds",
        "samples_per_workload": samples,
        "notes": "In-memory synthetic workloads; compare only on equivalent machines and environments.",
        "timings": timings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = measure(args.samples)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
