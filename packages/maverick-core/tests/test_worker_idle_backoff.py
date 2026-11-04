"""An idle queue worker backs off from a short wait up to idle_sleep."""
from __future__ import annotations

from maverick.worker import Worker


class _Queue:
    db_path = "memory"

    def reclaim_stale(self, *a, **k):
        return 0


def _run(worker: Worker, outcomes: list[bool]) -> list[float]:
    waits: list[float] = []
    remaining = list(outcomes)

    def run_once():
        return remaining.pop(0)

    def wait(seconds):
        waits.append(round(seconds, 3))
        if not remaining:
            worker._stop.set()
        return False

    worker.run_once = run_once  # type: ignore[method-assign]
    worker._reclaim_stale = lambda: None  # type: ignore[method-assign]
    worker._wire_signals = lambda: None  # type: ignore[method-assign]
    worker._stop.wait = wait  # type: ignore[method-assign]
    worker.run_forever()
    return waits


def test_idle_waits_double_from_the_start_value_up_to_idle_sleep():
    worker = Worker(queue=_Queue(), idle_sleep=2.0)
    assert _run(worker, [False] * 6) == [0.2, 0.4, 0.8, 1.6, 2.0, 2.0]


def test_a_processed_job_resets_the_backoff():
    worker = Worker(queue=_Queue(), idle_sleep=2.0)
    assert _run(worker, [False, False, False, True, False, False]) == [0.2, 0.4, 0.8, 0.2, 0.4]


def test_backoff_start_never_exceeds_idle_sleep():
    worker = Worker(queue=_Queue(), idle_sleep=0.1)
    assert worker.idle_backoff_start == 0.1
    assert _run(worker, [False, False]) == [0.1, 0.1]
