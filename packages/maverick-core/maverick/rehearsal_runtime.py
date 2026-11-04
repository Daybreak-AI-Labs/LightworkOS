"""Live wiring of the rehearsal gate into the agent's tool path.

This is the runtime glue between the Operating Twin and a running agent: it
encodes the current context as a world-model state, lazily fits a model from the
captured Operating Record, and exposes ``gate_tool`` -- which ``agent._run_tool``
consults before executing an *elevated-risk* tool.

The product decisions, made conservatively:
  * **What to gate:** only ``high``-risk tools (host mutation / arbitrary code /
    real-world control); everything else runs unrehearsed. Decided at the call
    site via ``safety.tool_risk``.
  * **State encoding:** ``(domain, role, last_tool)`` -- general to specific, the
    ordering the backoff model needs. It must match the fit-time encoding, so
    both live here.
  * **Model + refresh:** a :class:`BackoffTransitionModel` fit from the
    trajectory store, cached and rebuilt when the corpus grows materially.

Posture: default-on predictions, observed by the agent without a hold. With
``[rehearsal]`` explicitly disabled, no captured data yet, or any error,
``gate_tool`` returns ``proceed``. Only the explicit experimental hold mode
lets a poor or unvouchable verdict stop a high-risk action.
"""
from __future__ import annotations

import os
import threading
from collections import OrderedDict

from . import rehearsal
from .rehearsal import PROCEED, RehearsalVerdict

_REFRESH_EVERY = 64  # rebuild the model when the corpus grows by this many rows
_MAX_CACHE_SOURCES = 16


class _CacheEntry:
    __slots__ = ("lock", "model", "n")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.model = None
        self.n = -1


_SourceKey = tuple[str, str | int]
_cache_lock = threading.Lock()
_cache: OrderedDict[_SourceKey, _CacheEntry] = OrderedDict()


def encode_state(domain, role, last_tool) -> tuple:
    """World-model state: general -> specific (domain, role, last_tool)."""
    return (str(domain or ""), str(role or ""), str(last_tool or ""))


def _build_model(store=None):
    """Fit a backoff world-model from the captured Operating Record (None if no
    usable data). The fit-time state encoding MUST match :func:`encode_state`."""
    try:
        from .counterfactual_rollout import transitions_from_trajectories
        from .generative_world_model import BackoffTransitionModel
        if store is None:
            from .trajectory_store import shared

            store = shared()

        # Older records did not distinguish an executed tool failure from a
        # pre-dispatch refusal. Those ambiguous failed rows can contain the
        # rehearsal gate's own holds, so exclude them rather than teach the
        # model that an unexecuted action produced the task outcome. New rows
        # explicitly mark execution and retain real tool failures.
        steps = [
            step for step in store.iter_steps()
            if not step.tool or step.tool_executed is True
            or (step.tool_executed is None and step.tool_succeeded is not False)
        ]
        if not steps:
            return None

        def state_fn(ep, i):
            prev = ep[i - 1].tool if i > 0 else ""
            return encode_state(ep[i].domain, ep[i].role, prev)

        def action_fn(ep, i):
            return ep[i].tool or "finish"

        def outcome_fn(ep):
            for s in reversed(ep):
                if s.outcome is not None:
                    return s.outcome
                if s.is_final and s.verifier_confidence is not None:
                    return s.verifier_confidence
            return None

        trans = transitions_from_trajectories(
            steps, state_fn=state_fn, action_fn=action_fn, outcome_fn=outcome_fn)
        if not trans:
            return None
        return BackoffTransitionModel().fit(trans)
    except Exception:  # pragma: no cover -- model building must never break a run
        return None


def _source_key(store) -> _SourceKey:
    """Stable identity for one trajectory corpus.

    ``data_dir`` normally returns an absolute path, but custom deployments may
    configure a relative ``MAVERICK_HOME``. Resolve and normalise the path so a
    cwd change or a case/symlink alias cannot make two physical sources share a
    cache entry (or make one source needlessly occupy multiple entries).
    """
    path = getattr(store, "path", None)
    if path is None:
        return ("store", id(store))
    try:
        raw = os.fsdecode(path)
        normalised = os.path.normcase(
            os.path.realpath(os.path.abspath(os.path.expanduser(raw)))
        )
        return ("path", normalised)
    except Exception:  # pragma: no cover -- unusual PathLike implementations
        return ("store", id(store))


def _entry_for(source: _SourceKey) -> _CacheEntry:
    """Return one source's entry and enforce the small global LRU bound."""
    with _cache_lock:
        entry = _cache.get(source)
        if entry is None:
            entry = _CacheEntry()
            _cache[source] = entry
        else:
            _cache.move_to_end(source)
        while len(_cache) > _MAX_CACHE_SOURCES:
            _cache.popitem(last=False)
        return entry


def _model():
    """Cached world-model, isolated and refreshed per trajectory source.

    A tenant/path switch must never reuse another source's fitted model. The
    bounded LRU avoids rebuilding on every A -> B -> A switch, while per-source
    locks allow different tenants to fit concurrently. The global map lock is
    never held while reading trajectories or fitting a model.
    """
    try:
        from .trajectory_store import shared

        store = shared()
        source = _source_key(store)
    except Exception:  # pragma: no cover
        return None

    try:
        entry = _entry_for(source)
    except Exception:  # pragma: no cover -- cache bookkeeping must fail open
        return None
    try:
        with entry.lock:
            n = store.count()
            # A shrink means rows were rotated, erased, or the file was
            # replaced. Invalidate immediately so deleted learning evidence
            # cannot keep influencing rehearsal until another 64 rows arrive.
            if (
                entry.model is None
                or n < entry.n
                or n - entry.n >= _REFRESH_EVERY
            ):
                try:
                    entry.model = _build_model(store)
                except Exception:  # pragma: no cover -- fail open under test doubles too
                    entry.model = None
                entry.n = n
            return entry.model
    except Exception:  # pragma: no cover -- rehearsal must never break a run
        return None


def reset_cache() -> None:
    with _cache_lock:
        _cache.clear()


def gate_tool(*, domain, role, last_tool, tool_name) -> RehearsalVerdict:
    """Rehearse running ``tool_name`` in the current context.

    Returns ``proceed`` (fail-open) when rehearsal is disabled or no model exists
    yet; otherwise the world-model's verdict.
    """
    if not rehearsal.enabled():
        return RehearsalVerdict(PROCEED, 0.5, 0.0, 0, False, "rehearsal disabled")
    model = _model()
    if model is None:
        return RehearsalVerdict(PROCEED, 0.5, 0.0, 0, False, "no world-model yet")
    return rehearsal.gate_action(model, encode_state(domain, role, last_tool), [tool_name])


def world_model():
    """The cached Operating-Record world-model (None if no data). Public accessor
    so speculative execution shares one model with rehearsal."""
    return _model()


__all__ = ["encode_state", "gate_tool", "reset_cache", "world_model"]
