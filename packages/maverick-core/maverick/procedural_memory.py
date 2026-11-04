"""Retain and decay supported procedural memories.

Ordinary trajectory history can suggest a helpful action but cannot establish
that the action caused the result. Automatic consolidation requires a
promotion-grade comparison; observed task history alone creates no new habit.
Previously accepted memories still decay when fresh evidence is absent.
"""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path

from . import promotion_effect as pe
from .file_lock import atomic_read_text, atomic_write_text, ensure_private_file

log = logging.getLogger(__name__)

# Memory dynamics: a reinforced memory climbs (reinforce > decay) toward 1.0; an
# unreinforced one fades below the retire floor within a few cycles.
_BASE = 0.5
_REINFORCE = 0.5
_DECAY = 0.25
_RETIRE_BELOW = 0.2


@dataclass(frozen=True)
class Memory:
    """A consolidated 'this action helps' habit, with a reinforcement strength."""

    action: str
    benefit: float      # supported outcome difference (> 0)
    strength: float     # 0..1; grows on reinforcement, decays otherwise

    def to_dict(self) -> dict:
        return {"action": self.action, "benefit": self.benefit, "strength": self.strength}


def consolidate(steps, prior=(), *, decay: float = _DECAY, reinforce: float = _REINFORCE,
                base: float = _BASE, min_support: int = 8,
                retire_below: float = _RETIRE_BELOW, outcome_fn=None) -> list[Memory]:
    """One consolidation cycle: reinforce habits that still help, decay the rest.

    Beneficial = an action with promotion-grade controlled evidence and a
    positive lower confidence bound (``ci_low > 0``). Priors decay by ``decay``;
    still-beneficial ones are reinforced by ``reinforce`` (net climb); new ones
    enter at ``base``; anything below ``retire_below`` is forgotten. ``outcome_fn``
    (default ``_terminal_outcome``) lets the flywheel ground consolidation in real
    consequences.
    """
    steps = list(steps)
    outcome_fn = outcome_fn or _terminal_outcome
    beneficial: dict[str, float] = {}
    for tool in {s.tool for s in steps if s.tool}:
        units = pe.units_from_trajectories(
            steps,
            treatment_fn=lambda ep, t=tool: 1 if any(s.tool == t for s in ep) else 0,
            outcome_fn=outcome_fn,
            stratum_fn=lambda ep: (ep[0].domain,),
        )
        est = pe.estimate_effect(units, adjusted_for=("domain",), min_used=min_support)
        if est.trustworthy and est.ci_low > 0.0:
            beneficial[tool] = est.effect

    out: dict[str, Memory] = {}
    for m in prior:  # decay everything first
        out[m.action] = Memory(m.action, m.benefit, max(0.0, m.strength - decay))
    for action, benefit in beneficial.items():  # then reinforce / create
        cur = out.get(action)
        strength = min(1.0, cur.strength + reinforce) if cur else base
        out[action] = Memory(action, benefit, strength)

    return sorted((m for m in out.values() if m.strength >= retire_below),
                  key=lambda m: m.strength, reverse=True)


def _terminal_outcome(ep) -> float | None:
    for s in reversed(ep):
        if getattr(s, "outcome", None) is not None:
            return float(s.outcome)
        if s.is_final and getattr(s, "verifier_confidence", None) is not None:
            return float(s.verifier_confidence)
    return None


@dataclass
class MemoryStore:
    """Persistent procedural memory (atomic, 0600), keyed by action."""

    path: Path | None = None
    _mem: dict = None  # type: ignore[assignment]
    _lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._lock is None:
            self._lock = threading.Lock()
        if self._mem is None:
            self._mem = {}
        if self.path is not None:
            self._load()

    def update(self, memories, *, strict: bool = False, before_write=None) -> None:
        from .learning_store import derived_guidance_fence

        with derived_guidance_fence(), self._lock:
            if before_write is not None:
                before_write()
            previous = self._mem
            self._mem = {m.action: m for m in memories}
            try:
                self._save(strict=strict, before_write=before_write)
            except Exception:
                self._mem = previous
                raise

    def recall(self, *, top_k: int = 5) -> list[Memory]:
        """The strongest consolidated habits -- a learned prior the planner can
        prefer. Empty store -> []."""
        with self._lock:
            self._refresh()
            return sorted(self._mem.values(), key=lambda m: m.strength, reverse=True)[:top_k]

    def strength_of(self, action: str) -> float:
        with self._lock:
            self._refresh()
            m = self._mem.get(action)
            return m.strength if m else 0.0

    def _refresh(self) -> None:
        if self.path is not None:
            self._mem.clear()
            if Path(self.path).exists():
                self._load()

    def _load(self) -> None:
        try:
            path = ensure_private_file(Path(self.path))
            raw = json.loads(atomic_read_text(path))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        for d in (raw or []):
            try:
                m = Memory(str(d["action"]), float(d["benefit"]), float(d["strength"]))
                self._mem[m.action] = m
            except (KeyError, TypeError, ValueError):
                continue

    def _save(self, *, strict: bool = False, before_write=None) -> None:
        if self.path is None:
            return
        try:
            atomic_write_text(
                Path(self.path),
                json.dumps(
                    [m.to_dict() for m in self._mem.values()], sort_keys=True,
                ),
                **({"effect_guard": before_write} if before_write is not None else {}),
            )
        except Exception:  # pragma: no cover -- best-effort
            if strict:
                raise
            log.debug("procedural memory save failed", exc_info=True)


_shared: dict = {}
_shared_lock = threading.Lock()


def shared() -> MemoryStore:
    from .file_lock import ensure_private_directory
    from .paths import data_dir

    path = data_dir("procedural_memory.json")
    with _shared_lock:
        store = _shared.get(path)
        if store is None:
            # This is a Lightwork-owned default directory.  Caller-injected
            # MemoryStore parents are deliberately left untouched.
            ensure_private_directory(path.parent)
            store = MemoryStore(path=path)
            _shared[path] = store
        return store


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()


def refresh_shared() -> None:
    """Refresh the active tenant's existing objects after native restoration."""
    from .paths import data_dir

    with _shared_lock:
        store = _shared.get(data_dir("procedural_memory.json"))
        if store is not None:
            with store._lock:
                store._refresh()


def recall_prompt(*, store: MemoryStore | None = None, top_k: int = 5) -> str:
    """A planning-prior prompt fragment of the strongest learned habits, or ''.

    The read side of the Hippocampus: surface the causally-beneficial actions the
    workforce has consolidated so an agent can *prefer* them. Empty store -> ''
    (no prompt change), so it's safe to append unconditionally."""
    habits = (store or shared()).recall(top_k=top_k)
    if not habits:
        return ""
    lines = "\n".join(
        f"- prefer '{m.action}' (it has helped before; strength {m.strength:.2f})"
        for m in habits)
    return ("\n\nLearned habits (from your own past outcomes — prefer these where they "
            "fit; they are guidance, not mandatory):\n" + lines)


__all__ = [
    "Memory", "consolidate", "MemoryStore", "shared", "reset_shared", "recall_prompt",
]
