"""Chaos injection harness for resilience testing.

Lets test suites (and the chaos test command) deterministically inject
failures into sandbox exec, tool dispatch, and LLM calls — so we know
the agent's retry / verifier / failure_classifier paths actually work
end-to-end, not just in isolation.

Usage (test code):

    from maverick.chaos import ChaosController, fail_pct

    chaos = ChaosController()
    chaos.set(sandbox_exec_fail_pct=20, tool_dispatch_fail_pct=10)
    with chaos.active():
        result = await orchestrator.run(...)

Usage (CLI gate):

    MAVERICK_CHAOS=sandbox:20,tool:10,llm:5 pytest tests/integration/

The controller is process-global (single threaded by design — we
never want concurrent test runs racing on the same dial). When
inactive it's a pure no-op; when active it consults a deterministic
PRNG seeded from the call site so failures are reproducible.

This is a TEST harness. ``maybe_fail()`` is a no-op in production
unless explicitly turned on via env or `ChaosController.set(active=True)`.
"""
from __future__ import annotations

import logging
import os
import random
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


class ChaosInjected(Exception):
    """Raised by ``maybe_fail()`` when the dice come up bad."""


# Per-stage failure rates (0-100 percent).
_STAGES = (
    "sandbox_exec",     # SandboxBackend.exec
    "tool_dispatch",    # ToolRegistry.run
    "llm_call",         # LLM.complete / complete_async
    "http_fetch",       # http_fetch tool
)


@dataclass
class ChaosState:
    active: bool = False
    seed: int = 0
    rates: dict[str, int] = field(default_factory=dict)
    _rng: random.Random = field(default_factory=random.Random, repr=False)
    # random.Random is not thread-safe and the async/swarm paths roll
    # concurrently while configure() may swap the generator; guard both.
    _rng_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def configure(self, *, seed: int) -> None:
        self.seed = seed
        with self._rng_lock:
            self._rng = random.Random(seed)

    def roll(self, stage: str) -> bool:
        if not self.active:
            return False
        pct = self.rates.get(stage, 0)
        if pct <= 0:
            return False
        with self._rng_lock:
            return self._rng.randint(1, 100) <= pct


class ChaosController:
    _lock = threading.Lock()
    _state = ChaosState()

    def set(
        self,
        *,
        active: bool = True,
        seed: int = 1337,
        sandbox_exec_fail_pct: int = 0,
        tool_dispatch_fail_pct: int = 0,
        llm_call_fail_pct: int = 0,
        http_fetch_fail_pct: int = 0,
    ) -> None:
        with self._lock:
            st = self._state
            st.active = active
            st.configure(seed=seed)
            st.rates = {
                "sandbox_exec": int(sandbox_exec_fail_pct),
                "tool_dispatch": int(tool_dispatch_fail_pct),
                "llm_call": int(llm_call_fail_pct),
                "http_fetch": int(http_fetch_fail_pct),
            }

    def disable(self) -> None:
        with self._lock:
            self._state.active = False
            self._state.rates = {}

    @contextmanager
    def active(self, **rates: int) -> Iterator[ChaosController]:
        """Scope chaos to a `with` block; restore prior state on exit."""
        with self._lock:
            prior_active = self._state.active
            prior_seed = self._state.seed
            prior_rates = dict(self._state.rates)
        try:
            self.set(active=True, **rates)
            yield self
        finally:
            with self._lock:
                # Mutate fields in place (don't reassign self._state — it
                # would create an instance attr shadowing the class-level
                # singleton other callers see).
                self._state.active = prior_active
                self._state.rates = prior_rates
                self._state.configure(seed=prior_seed)

    @property
    def state(self) -> ChaosState:
        return self._state


_singleton_lock = threading.Lock()
_singleton: ChaosController | None = None


def get() -> ChaosController:
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = ChaosController()
                _configure_from_env(_singleton)
    return _singleton


def _configure_from_env(c: ChaosController) -> None:
    """Read ``MAVERICK_CHAOS`` like ``sandbox:20,tool:10,llm:5``."""
    raw = os.environ.get("MAVERICK_CHAOS", "").strip()
    if not raw:
        return
    # Safety gate: chaos injects real failures into live LLM/tool/sandbox calls.
    # Only honor it under pytest or with an explicit opt-in, so a MAVERICK_CHAOS
    # value that leaks into a deployed env (copied .env, inherited export) can't
    # silently start failing real user requests.
    if not (os.environ.get("PYTEST_CURRENT_TEST")
            or os.environ.get("MAVERICK_CHAOS_ALLOW") == "1"):
        log.error(
            "MAVERICK_CHAOS is set (%r) but not under pytest and "
            "MAVERICK_CHAOS_ALLOW != 1; refusing to inject failures.", raw,
        )
        return
    rates: dict[str, int] = {}
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok or ":" not in tok:
            continue
        k, _, v = tok.partition(":")
        try:
            rates[k.strip().lower()] = int(v.strip())
        except ValueError:
            continue
    if not rates:
        return
    seed = int(os.environ.get("MAVERICK_CHAOS_SEED", "1337") or "1337")
    c.set(
        active=True, seed=seed,
        sandbox_exec_fail_pct=rates.get("sandbox", 0),
        tool_dispatch_fail_pct=rates.get("tool", 0),
        llm_call_fail_pct=rates.get("llm", 0),
        http_fetch_fail_pct=rates.get("http", 0),
    )
    log.warning("chaos: ACTIVE seed=%d rates=%s", seed, c.state.rates)


def maybe_fail(stage: str, *, message: str = "") -> None:
    """Raise :class:`ChaosInjected` if chaos rolls bad for this stage.

    Cheap no-op when chaos is off.
    """
    if stage not in _STAGES:
        return  # unknown stage = ignored
    c = get()
    if c.state.roll(stage):
        raise ChaosInjected(message or f"chaos injected at {stage}")


__all__ = [
    "ChaosController", "ChaosState", "ChaosInjected",
    "get", "maybe_fail",
]
