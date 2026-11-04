"""Cost-aware routing — contextual bandit.

``cost.router`` picks the cheapest *viable* provider by a static tier +
health table. This module learns which of those viable providers delivers the
best reward-per-dollar **for this kind of task**, adapting as quality and
prices drift. It's a contextual multi-armed bandit — arms are provider:model specs,
the context is a coarse task class (role + tier), the reward is operator-
defined (default: success ÷ dollars).

Deterministic and dependency-free: a per-(context, arm) running mean with an
epsilon-greedy policy over an injectable PRNG, so a test pins exactly what it
explores. Persists the learned table to ``data_dir("router_bandit.json")``
(atomic 0600) so learning survives restarts.

Opt-in and layered on top of ``cost.router``: the bandit only chooses among
the arms the router already deems viable and healthy (it never routes to a
down or unaffordable provider), and it falls back to the router's pick on a
cold context. ``[routing] bandit = true`` (env ``MAVERICK_ROUTING_BANDIT``);
off by default, which leaves the router's choice unchanged.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from collections import OrderedDict
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from random import Random

from ..config import env_flag

log = logging.getLogger(__name__)

DEFAULT_EPSILON = 0.1   # explore 10% of the time
_MIN_PULLS = 2          # try each arm at least twice before exploiting


def enabled() -> bool:
    """``MAVERICK_ROUTING_BANDIT`` (either way) wins over ``[routing] bandit``."""
    env = env_flag("MAVERICK_ROUTING_BANDIT")
    if env is not None:
        return env
    try:
        from ..config import load_config
        return bool(((load_config() or {}).get("routing") or {}).get("bandit", False))
    except Exception:  # pragma: no cover -- config never blocks routing
        return False


@dataclass
class _Arm:
    pulls: int = 0
    total_reward: float = 0.0

    @property
    def mean(self) -> float:
        return self.total_reward / self.pulls if self.pulls else 0.0


@dataclass
class ContextualBandit:
    """Per-(context, arm) running-mean reward with an epsilon-greedy policy."""

    epsilon: float = DEFAULT_EPSILON
    rng: Random = field(default_factory=lambda: Random(0))
    path: Path | None = None
    _table: dict[str, dict[str, _Arm]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        if self.path is not None:
            self._load()

    # -- learning ---------------------------------------------------------

    def _cplock(self):
        # Cross-process lock over the load-apply-save; no-op for an in-memory
        # (path-less) bandit. Without it two processes each hold a stale cached
        # _table and the second _save clobbers the first's accumulated pulls.
        if self.path is None:
            from contextlib import nullcontext
            return nullcontext()
        from ..file_lock import cross_process_lock
        return cross_process_lock(self.path)

    def _reload_locked(self) -> None:
        # Refresh the cached table from disk (picking up other processes'
        # writes) before applying this delta. Call only while holding _cplock.
        if self.path is None:
            return
        self._table = {}
        self._load()

    def record(self, context: str, arm: str, reward: float) -> None:
        with self._lock, self._cplock():
            self._reload_locked()
            a = self._table.setdefault(context, {}).setdefault(arm, _Arm())
            a.pulls += 1
            a.total_reward += float(reward)
            self._save()

    def record_outcome(self, context: str, arm: str, *, success: bool, dollars: float) -> None:
        """Convenience reward: success per dollar (free successes score high;
        failures score zero regardless of cost)."""
        reward = 0.0 if not success else 1.0 / max(dollars, 1e-4)
        self.record(context, arm, reward)

    # -- policy -----------------------------------------------------------

    def choose(self, context: str, arms: list[str]) -> str | None:
        """Epsilon-greedy choice among ``arms`` for ``context``.

        Returns None when ``arms`` is empty (caller keeps its default). Any arm
        pulled fewer than ``_MIN_PULLS`` times is explored first (cold-start
        coverage); otherwise exploit the best mean with ``epsilon`` random
        exploration.
        """
        if not arms:
            return None
        if len(arms) == 1:
            return arms[0]
        with self._lock:
            ctx = self._table.get(context, {})
            under = [a for a in arms if ctx.get(a, _Arm()).pulls < _MIN_PULLS]
        if under:
            return self.rng.choice(under)
        if self.rng.random() < self.epsilon:
            return self.rng.choice(arms)
        with self._lock:
            ctx = self._table.get(context, {})
            # Highest mean reward; ties broken by arm name for determinism.
            return max(arms, key=lambda a: (ctx.get(a, _Arm()).mean, a))

    def stats(self, context: str) -> dict[str, dict[str, float]]:
        with self._lock:
            ctx = self._table.get(context, {})
            return {a: {"pulls": v.pulls, "mean_reward": round(v.mean, 6)}
                    for a, v in sorted(ctx.items())}

    # -- persistence ------------------------------------------------------

    def _load(self) -> None:
        try:
            from ..file_lock import atomic_read_text, ensure_private_file

            ensure_private_file(Path(self.path))
            raw = json.loads(atomic_read_text(Path(self.path)))
        except (OSError, ValueError):
            return
        for ctx, arms in (raw or {}).items():
            self._table[ctx] = {
                a: _Arm(pulls=int(d.get("pulls", 0)), total_reward=float(d.get("total_reward", 0.0)))
                for a, d in arms.items()
            }

    def _save(self) -> None:
        if self.path is None:
            return
        try:
            p = Path(self.path)
            data = {ctx: {a: {"pulls": v.pulls, "total_reward": v.total_reward}
                          for a, v in arms.items()}
                    for ctx, arms in self._table.items()}
            # Unique temp + os.replace: a fixed ".tmp" collides between two
            # processes' saves (one os.replace moves it out from under the other).
            from ..file_lock import atomic_write_text

            atomic_write_text(p, json.dumps(data, sort_keys=True))
        except Exception:  # pragma: no cover -- persistence is best-effort
            log.debug("bandit save failed", exc_info=True)


def context_key(role: str, tier: int) -> str:
    return f"{role or 'default'}:t{int(tier)}"


_shared: OrderedDict[tuple[str | None, str], ContextualBandit] = OrderedDict()
_shared_lock = threading.Lock()
_SHARED_LIMIT = 64


def _storage_binding() -> tuple[tuple[str | None, str], Path]:
    from ..paths import canonical_tenant_id, current_tenant_id_strict, data_dir

    tenant = current_tenant_id_strict()
    tenant = canonical_tenant_id(tenant) if tenant is not None else None
    path = data_dir("router_bandit.json").resolve()
    return (tenant, os.path.normcase(str(path))), path


def shared() -> ContextualBandit:
    key, path = _storage_binding()
    with _shared_lock:
        bandit = _shared.get(key)
        if bandit is not None:
            _shared.move_to_end(key)
            return bandit
    # Loading native storage may wait. Keep unrelated tenants out of that wait.
    from ..file_lock import ensure_private_directory

    ensure_private_directory(path.parent)
    candidate = ContextualBandit(path=path)
    with _shared_lock:
        bandit = _shared.setdefault(key, candidate)
        _shared.move_to_end(key)
        while len(_shared) > _SHARED_LIMIT:
            _shared.popitem(last=False)
        return bandit


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()
    clear_choice()


def pick(role: str, tier: int, viable_arms: list[str],
         *, bandit: ContextualBandit | None = None,
         fallback: Callable[[], str | None] | None = None) -> str | None:
    """Learn and choose among the router's viable arms.

    ``viable_arms`` MUST already be the healthy/affordable set ``cost.router``
    produced — the bandit only reorders *within* it, never routes somewhere the
    router rejected. On a cold context (or empty arms) it defers to
    ``fallback`` (the router's pick).
    """
    if not enabled() or not viable_arms:
        return fallback() if fallback else None
    b = bandit or shared()
    chosen = b.choose(context_key(role, tier), viable_arms)
    return chosen or (fallback() if fallback else None)


@dataclass(frozen=True)
class _RoutingCredit:
    binding: tuple[str | None, str]
    role: str
    tier: int
    arm: str
    bandit: ContextualBandit = field(repr=False, compare=False)


class _RoutedModel(str):
    """A live route remains a string while retaining its original decision.

    Serialization deliberately produces an ordinary model string, not a new
    routing decision. Agents and retained LLM clients may hold the live value.
    """

    __slots__ = ("_credit",)

    def __new__(cls, credit: _RoutingCredit):
        value = str.__new__(cls, credit.arm)
        object.__setattr__(value, "_credit", credit)
        return value

    def __setattr__(self, name, value):
        raise AttributeError("A routing decision is immutable")

    def __reduce__(self):
        return str, (str(self),)


_pending: ContextVar[_RoutingCredit | None] = ContextVar("cost_bandit_choice", default=None)
_USE_PENDING = object()


def clear_choice() -> None:
    """Discard legacy pending credit at every native model-resolution entry."""
    _pending.set(None)


def _current_credit(credit: object, arm: str) -> bool:
    if not isinstance(credit, _RoutingCredit) or credit.arm != arm or not enabled():
        return False
    binding, _ = _storage_binding()
    path = credit.bandit.path
    return (binding == credit.binding and path is not None
            and os.path.normcase(str(path.resolve())) == binding[1])


def capture_call(model: str) -> _RoutingCredit | None:
    """Bind a logical call only to the original live routed model value.

    An equal explicit string is not evidence that the bandit selected this
    call. This also clears pending credit when the caller uses a fixed or
    unrouted model.
    """
    clear_choice()
    credit = model._credit if isinstance(model, _RoutedModel) else None
    return credit if _current_credit(credit, str(model)) else None


def choose_for(role: str, tier: int, viable_arms: list[str]) -> str | None:
    """The live router's entry point (``cost.router.pick``): choose among the
    viable arms and retain this exact decision, so :func:`note_call` can credit
    the outcome."""
    clear_choice()
    if not enabled() or not viable_arms:
        return None
    bandit = shared()
    chosen = pick(role, tier, viable_arms, bandit=bandit)
    if chosen:
        binding, _ = _storage_binding()
        credit = _RoutingCredit(binding, role, int(tier), chosen, bandit)
        _pending.set(credit)
        return _RoutedModel(credit)
    return None


def note_call(provider: str, model: str, *, success: bool, dollars: float,
              credit: object = _USE_PENDING) -> bool:
    """Credit one finished model call to the arm the router chose for it.

    Called by ``maverick.llm`` after every provider call; a no-op (False)
    unless the bandit is on and this arm was chosen by the router."""
    arm = f"{provider}:{model}"
    if credit is _USE_PENDING:
        credit = _pending.get()
        clear_choice()
    if not _current_credit(credit, arm):
        return False
    credit.bandit.record_outcome(context_key(credit.role, credit.tier), arm,
                                success=bool(success),
                                dollars=max(float(dollars or 0.0), 0.0))
    return True


__all__ = ["ContextualBandit", "context_key", "pick", "enabled",
           "shared", "reset_shared", "DEFAULT_EPSILON", "choose_for", "note_call",
           "capture_call", "clear_choice"]
