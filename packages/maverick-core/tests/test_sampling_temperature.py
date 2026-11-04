"""Per-context sampling temperature (providers.base).

Best-of-N sets a per-attempt sampling temperature. It must live in a ContextVar,
NOT a process-global ``os.environ["MAVERICK_TEMPERATURE"]`` — the old env
approach let a concurrent goal on the same process read another goal's
temperature. These tests pin the race-free contract.
"""
from __future__ import annotations

import asyncio
import contextvars
import os

from maverick.providers.base import (
    reset_sampling_temperature,
    sampling_temperature,
    set_sampling_temperature,
)


def test_default_is_none():
    assert sampling_temperature() is None


def test_set_reset_roundtrip():
    tok = set_sampling_temperature(0.7)
    assert sampling_temperature() == 0.7
    reset_sampling_temperature(tok)
    assert sampling_temperature() is None


def test_does_not_touch_process_env(monkeypatch):
    monkeypatch.delenv("MAVERICK_TEMPERATURE", raising=False)
    tok = set_sampling_temperature(0.95)
    try:
        # The point of the contextvar: no process-global mutation.
        assert "MAVERICK_TEMPERATURE" not in os.environ
    finally:
        reset_sampling_temperature(tok)


def test_concurrent_contexts_are_isolated():
    # Two independent contexts (= two concurrent goal tasks) must not see each
    # other's temperature. The old os.environ approach failed exactly this.
    seen: dict[str, float | None] = {}

    def _bind(label, temp):
        set_sampling_temperature(temp)  # deliberately not reset
        seen[label] = sampling_temperature()

    contextvars.copy_context().run(_bind, "a", 0.2)
    contextvars.copy_context().run(_bind, "b", 0.9)
    assert seen == {"a": 0.2, "b": 0.9}
    # neither child leaked into the parent context
    assert sampling_temperature() is None


def test_propagates_across_to_thread():
    # A sync provider runs in a worker thread (asyncio.to_thread copies the
    # context), so the value bound by the goal task must reach it.
    async def _main():
        tok = set_sampling_temperature(0.55)
        try:
            return await asyncio.to_thread(sampling_temperature)
        finally:
            reset_sampling_temperature(tok)

    assert asyncio.run(_main()) == 0.55
