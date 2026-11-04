"""Just-In-Time RL: gradient-free test-time adaptation for a frozen agent.

JitRL (arxiv:2601.18510) lets a *frozen* model keep improving during deployment
with NO weight updates: it stores past experience as (state, action, return)
triplets, estimates each candidate action's advantage from nearby experience via
k-NN, and steers action selection toward high-advantage actions
(z'(s,a) = z(s,a) + beta * A(s,a)). Nothing is fine-tuned; adaptation lives
entirely in a retrievable experience store.

Why this shape fits a governed platform: a weight edit is the hardest thing to
govern (the ``weights`` rung -- irreversible-ish, opaque, human-gated). This
gives continual adaptation at the ``policy`` rung instead:

  * **Reversible** -- forget by dropping experience rows; no model to roll back.
  * **Auditable** -- the retrieved experiences that steered a decision are
    inspectable, unlike a gradient step folded into billions of weights.
  * **Tenant-isolated** -- experience is per-store, like fleet memory.

This module is the adaptation primitive: a triplet store with k-NN value /
advantage estimation over the SHARED :func:`maverick.prm.step_features` vector
(so a JitRL step and a PRM score read the same state encoding), and a steering
call that re-ranks candidate actions by advantage. It does not touch the agent
loop; a caller composes ``steer`` with best-of-N selection when opted in
(mirroring how :mod:`maverick.prm` ships the interface before the wiring).

Posture: ON by default (:func:`enabled`) but a no-op with a cold store --
enabling it changes nothing until experience accumulates -- fail-open, standard
library only (no torch, no gradients). Every hot-path method degrades to a
neutral signal (zero advantage / unchanged order) rather than raising, so a
cold or corrupt store can never block a run.
"""
from __future__ import annotations

import heapq
import json
import logging
import math
import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .file_lock import (
    atomic_read_text,
    atomic_write_text_chunks,
    cross_process_lock,
    ensure_private_file,
    open_private_append,
)

log = logging.getLogger(__name__)

# Defaults for the k-NN estimate. k = neighbourhood size; beta = steering gain
# on the advantage (the closed-form logit nudge in JitRL). Overridable via
# ``[jit_rl]`` config / method args.
DEFAULT_K = 8
DEFAULT_BETA = 1.0
# Bound store growth (memory + disk), oldest dropped first -- an experience
# buffer, not an unbounded ledger.
DEFAULT_MAX_EXPERIENCES = 5000


@dataclass(frozen=True)
class Experience:
    """One (state, action, return) triplet. ``features`` is the state encoding
    (a :func:`maverick.prm.step_features` vector); ``ret`` is the realised
    return for taking ``action`` in that state (e.g. a step/terminal reward)."""

    features: tuple[float, ...]
    action: str
    ret: float
    ts: float = 0.0

    def to_dict(self) -> dict:
        return {"features": list(self.features), "action": self.action,
                "ret": self.ret, "ts": self.ts}


def _distance(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    """Euclidean distance; ``inf`` for mismatched-length vectors (so a stray
    malformed row is ranked last, never crashing the neighbour search)."""
    if len(a) != len(b):
        return math.inf
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b, strict=True)))


class JitStore:
    """A bounded (state, action, return) experience buffer with k-NN queries.

    In-memory by default; pass ``path`` to persist as JSONL (append-on-record,
    load-on-init) for a store that survives restarts. Thread-safe. All query
    methods are read-only and never raise -- an empty or malformed store yields
    neutral answers (0 value, 0 advantage)."""

    def __init__(self, path: Path | None = None,
                 max_experiences: int = DEFAULT_MAX_EXPERIENCES):
        self.path = Path(path) if path is not None else None
        self.max_experiences = max(1, int(max_experiences))
        # A bounded ring buffer: deque(maxlen) evicts the oldest on overflow in
        # O(1), so no manual length check on the hot record path.
        self._items: deque[Experience] = deque(maxlen=self.max_experiences)
        self._lock = threading.Lock()
        self._since_check = 0
        if self.path is not None:
            self._load()

    # -- writes ----------------------------------------------------------

    def record(self, features, action: str, ret: float) -> None:
        """Append one experience. Never raises."""
        from .learning_guard import learning_write_allowed
        if not learning_write_allowed("jit_rl"):
            return
        try:
            exp = Experience(
                features=tuple(float(x) for x in features),
                action=str(action), ret=float(ret), ts=time.time(),
            )
        except (TypeError, ValueError):
            return
        with self._lock:
            self._items.append(exp)  # deque(maxlen=...) drops the oldest
            self._append(exp)

    # -- k-NN reads ------------------------------------------------------

    def neighbors(self, features, k: int = DEFAULT_K) -> list[Experience]:
        """The ``k`` nearest experiences to ``features`` (closest first)."""
        try:
            q = tuple(float(x) for x in features)
        except (TypeError, ValueError):
            return []
        with self._lock:
            items = list(self._items)
        if not items:
            return []
        # Partial selection: O(N log k) for the k closest, vs a full O(N log N)
        # sort (tie order among neighbours is irrelevant to the mean).
        return heapq.nsmallest(max(1, int(k)), items, key=lambda e: _distance(q, e.features))

    def value(self, features, k: int = DEFAULT_K) -> float:
        """V(s): mean return of the k nearest experiences (any action). 0 when
        the store is empty -- no evidence, no baseline."""
        nbrs = self.neighbors(features, k)
        return sum(e.ret for e in nbrs) / len(nbrs) if nbrs else 0.0

    def advantage(self, features, action: str, k: int = DEFAULT_K) -> float:
        """A(s,a) = Q(s,a) - V(s) for a single action (see :meth:`advantage_batch`)."""
        return self.advantage_batch(features, [action], k).get(str(action), 0.0)

    def advantage_batch(self, features, actions, k: int = DEFAULT_K) -> dict[str, float]:
        """A(s,a) for MANY actions in one state, sharing a SINGLE k-NN scan.

        Q(s,a) is the mean return of the k nearest experiences that took
        ``a``; V(s) is the mean over all k nearest. The neighbourhood and V(s)
        baseline depend only on the state, so they are computed ONCE and reused
        across actions (the steer hot path) rather than re-scanning the store per
        action. Returns ``{action: A(s,a)}``; an action no neighbour took maps to
        0.0 (no local evidence -> no steer), so an unseen action is never
        penalised or rewarded on a hunch."""
        wanted = [str(a) for a in actions]
        nbrs = self.neighbors(features, k)
        if not nbrs:
            return dict.fromkeys(wanted, 0.0)
        v_s = sum(e.ret for e in nbrs) / len(nbrs)
        out: dict[str, float] = {}
        for a in wanted:
            if a in out:
                continue
            same = [e.ret for e in nbrs if e.action == a]
            out[a] = (sum(same) / len(same) - v_s) if same else 0.0
        return out

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    # -- persistence -----------------------------------------------------

    def _load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        out: list[Experience] = []
        try:
            path = ensure_private_file(self.path)
            lines = atomic_read_text(path).splitlines()
        except OSError:
            return
        for raw in lines:
            if not raw.strip():
                continue
            try:
                d = json.loads(raw)
                if not isinstance(d, dict):
                    continue
                out.append(Experience(
                    features=tuple(float(x) for x in d.get("features", [])),
                    action=str(d.get("action", "")),
                    ret=float(d.get("ret", 0.0)),
                    ts=float(d.get("ts", 0.0) or 0.0),
                ))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
        # deque(iterable, maxlen) keeps only the most recent `maxlen` items.
        self._items = deque(out, maxlen=self.max_experiences)

    def _append(self, exp: Experience) -> None:
        if self.path is None:
            return
        try:
            with cross_process_lock(self.path, strict=True):
                fd = open_private_append(self.path)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(exp.to_dict()) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                self._since_check += 1
                if self._since_check >= max(1, self.max_experiences // 8):
                    self._since_check = 0
                    self._compact_disk()
        except (OSError, RuntimeError) as e:  # pragma: no cover -- best-effort
            log.debug("jit_rl: experience append failed: %s", e)

    def _compact_disk(self) -> None:
        """Keep the persistent buffer bounded like the in-memory deque.

        Called with the store's cross-process lock held.  The prior append-only
        implementation bounded RAM but let the on-disk training corpus grow
        forever, contrary to the class contract.
        """
        if self.path is None or not self.path.exists():
            return
        path = ensure_private_file(self.path)
        lines = atomic_read_text(path).splitlines(keepends=True)
        if len(lines) <= self.max_experiences:
            return
        kept = lines[-self.max_experiences:]
        atomic_write_text_chunks(
            path, (line if line.endswith("\n") else line + "\n" for line in kept),
        )


@dataclass
class SteerScore:
    """A candidate action's advantage-based steering score. ``score`` =
    beta * advantage is the JitRL logit nudge; higher = steer toward."""

    action: str
    advantage: float
    score: float


class JitAdapter:
    """Bind a :class:`JitStore` to the shared PRM state encoding.

    ``record_step`` logs a (StepContext, action, return) triplet; ``advantage``
    and ``steer`` estimate/re-rank from the store -- all keyed on
    :func:`maverick.prm.step_features` so the JitRL state matches what the PRM
    sees. Frozen model, no gradients: adaptation is entirely in the store."""

    def __init__(self, store: JitStore | None = None, *,
                 k: int = DEFAULT_K, beta: float = DEFAULT_BETA):
        self.store = store if store is not None else JitStore()
        self.k = max(1, int(k))
        self.beta = float(beta)

    @staticmethod
    def _features(ctx: object) -> tuple[float, ...]:
        """StepContext -> feature tuple via the shared PRM encoder. Falls back to
        an empty tuple if prm is unavailable, so the adapter degrades gracefully."""
        try:
            from .prm import step_features
            return tuple(step_features(ctx))  # type: ignore[arg-type]
        except Exception:  # pragma: no cover -- neutral if prm import/encode fails
            return ()

    def record_step(self, ctx: object, action: str, ret: float) -> None:
        """Record a step's realised return under its state encoding."""
        feats = self._features(ctx)
        if feats:
            self.store.record(feats, action, ret)

    def advantage(self, ctx: object, action: str) -> float:
        """Estimated advantage of ``action`` in state ``ctx`` (0.0 = no signal)."""
        feats = self._features(ctx)
        if not feats:
            return 0.0
        return self.store.advantage(feats, action, self.k)

    def steer(self, ctx: object, candidate_actions) -> list[SteerScore]:
        """Re-rank candidate actions by advantage (highest first).

        Returns a :class:`SteerScore` per candidate, sorted by ``score`` desc;
        ties keep the caller's original order (a stable sort), so with an empty
        store -- every advantage 0 -- the input order is preserved unchanged.
        The caller composes these scores with best-of-N selection."""
        return self._steer_from_features(self._features(ctx), candidate_actions)

    def _steer_from_features(self, feats: tuple[float, ...],
                             candidate_actions) -> list[SteerScore]:
        """Advantage-rank candidates for an already-encoded state (the core of
        :meth:`steer`, separated so the ranking is testable without a full
        StepContext). One k-NN scan covers every candidate; an empty ``feats``
        yields all-zero scores (no steer)."""
        advs = self.store.advantage_batch(feats, candidate_actions, self.k) if feats else {}
        scored = [
            SteerScore(action=str(a), advantage=advs.get(str(a), 0.0),
                       score=self.beta * advs.get(str(a), 0.0))
            for a in candidate_actions
        ]
        # Stable sort: equal scores preserve input order.
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored


# -- config / construction ---------------------------------------------------

def _settings() -> dict:
    """The ``[jit_rl]`` config section via the shared getter (config.get_jit_rl),
    matching the sibling capability modules. Falls back to the code defaults if
    config can't be loaded."""
    try:
        from .config import get_jit_rl
        return get_jit_rl()
    except Exception:  # pragma: no cover -- config never blocks
        return {"enable": False, "k": DEFAULT_K, "beta": DEFAULT_BETA,
                "max_experiences": DEFAULT_MAX_EXPERIENCES}


def enabled() -> bool:
    """Whether JitRL test-time adaptation is turned on. ON by default.

    Wired into verifier-guided best-of-N selection
    (:func:`make_best_of_n_selector`): it records candidate outcomes and factors
    learned advantage into the choice, reducing to the pure verifier selection
    with a cold store (so enabling it changes nothing until experience
    accumulates). ``MAVERICK_JIT_RL=0`` (or ``[jit_rl] enable = false``) turns
    it off. Fail-open: any error resolving the flag leaves it at the configured
    default."""
    try:
        from .config import governed_learning_env_flag
        v = governed_learning_env_flag("MAVERICK_JIT_RL")
        if v is not None:
            return v
    except Exception:  # pragma: no cover -- env parsing never blocks
        pass
    try:
        return bool(_settings()["enable"])
    except Exception:  # pragma: no cover
        return False


def make_best_of_n_selector(adapter: JitAdapter, ctx: object):
    """A ``best_of_n(select=...)`` hook that factors learned advantage into the
    choice and records each candidate's realised return for future adaptation.

    In state ``ctx``, each candidate's ordinal is its action; the verifier
    confidence is the return. The winner maximises
    ``(accepts, confidence + beta * advantage)``, so a position that has
    historically verified better in similar states gets a nudge -- and with a
    cold store every advantage is 0, reducing this to the default
    ``(accepts, confidence)`` selection (enabling JitRL is a no-op until it has
    learned something). Never raises: on any error it falls back to the default
    max-key winner so a selection is always returned.

    Note: ordinal-as-action is the minimal keying that needs no candidate
    metadata; richer keying (by the generating model/role) is a natural
    extension once callers thread that through.
    """
    def _select(candidates: list):
        try:
            feats = adapter._features(ctx)
            actions = [f"cand_{i}" for i in range(len(candidates))]
            advs = (adapter.store.advantage_batch(feats, actions, adapter.k)
                    if feats else {})
            best_i = max(
                range(len(candidates)),
                key=lambda i: (candidates[i].accepts,
                               candidates[i].confidence
                               + adapter.beta * advs.get(actions[i], 0.0)))
            # Record each candidate's realised return AFTER choosing, so this
            # selection isn't biased by its own just-observed outcomes.
            for i, c in enumerate(candidates):
                adapter.record_step(ctx, actions[i], c.confidence)
            return candidates[best_i]
        except Exception:  # pragma: no cover -- never lose the answer to a bad steer
            return max(candidates, key=lambda c: (c.accepts, c.confidence))
    return _select


def default_store_path() -> Path:
    """Tenant-scoped experience store path (``jit_experience.ndjson``)."""
    from .paths import data_dir
    return data_dir("jit_experience.ndjson")


def build_from_env(*, path: Path | None = None) -> JitAdapter:
    """Construct a :class:`JitAdapter` from config, bound to the tenant store.

    Pass ``path`` to override (tests use an in-memory store or a tmp path).
    Mirrors :func:`maverick.prm.build_from_env`: a single construction seam the
    live loop can call once the operator has opted in."""
    s = _settings()
    if path is None:
        from .file_lock import ensure_private_directory

        store_path = default_store_path()
        ensure_private_directory(store_path.parent)
    else:
        store_path = path
    store = JitStore(path=store_path, max_experiences=s["max_experiences"])
    return JitAdapter(store=store, k=s["k"], beta=s["beta"])


__all__ = [
    "Experience",
    "JitStore",
    "JitAdapter",
    "SteerScore",
    "DEFAULT_K",
    "DEFAULT_BETA",
    "DEFAULT_MAX_EXPERIENCES",
    "enabled",
    "make_best_of_n_selector",
    "default_store_path",
    "build_from_env",
]
