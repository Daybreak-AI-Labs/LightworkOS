"""Self-tuning budgets.

A fixed ``[budget] max_dollars`` is a blunt instrument: a one-line "summarize
this" goal and a multi-hour refactor get the same cap. This learns a sensible
**default cap per task class** from how much past runs of that class actually
needed — so the cap is generous where work is genuinely big and tight where it
isn't, without an operator hand-tuning per goal.

Per task class (a coarse key, e.g. ``research:t2`` or a goal-kind tag) it keeps
a small online summary of observed final spend (count + a P90-ish high
quantile via a capped reservoir), and suggests a cap at ``quantile * margin``
clamped to ``[floor, ceiling]``. Until a class has ``min_samples`` it returns
None and the caller keeps its configured default — the learner never *lowers*
safety below what the operator set unless it has evidence.

Deterministic + offline: a capped reservoir with an injectable PRNG, persisted
atomically (0600) to ``data_dir("budget_tuning.json")``. Off by default;
``[budget] self_tuning = true`` or ``MAVERICK_BUDGET_SELF_TUNING=1`` opts in.
An explicit configured cap still wins, and a cold class returns no suggestion.
"""
from __future__ import annotations

import json
import logging
import math
import threading
from dataclasses import dataclass, field
from pathlib import Path
from random import Random

log = logging.getLogger(__name__)

DEFAULT_MIN_SAMPLES = 8
DEFAULT_MARGIN = 1.3          # head-room over the observed high quantile
DEFAULT_QUANTILE = 0.9
_RESERVOIR = 200             # bounded memory per class


def enabled() -> bool:
    try:
        from .config import (
            governed_learning_env_flag,
            load_config,
        )
        override = governed_learning_env_flag("MAVERICK_BUDGET_SELF_TUNING")
        if override is not None:
            return override
        return ((load_config() or {}).get("budget") or {}).get("self_tuning") is True
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


@dataclass
class _Class:
    count: int = 0
    samples: list[float] = field(default_factory=list)  # capped reservoir

    def quantile(self, q: float) -> float:
        if not self.samples:
            return 0.0
        ordered = sorted(self.samples)
        idx = min(len(ordered) - 1, max(0, int(round(q * (len(ordered) - 1)))))
        return ordered[idx]


@dataclass
class SelfTuningBudget:
    """Learn a per-task-class default spend cap from observed run costs."""

    min_samples: int = DEFAULT_MIN_SAMPLES
    margin: float = DEFAULT_MARGIN
    quantile: float = DEFAULT_QUANTILE
    floor: float = 0.25
    ceiling: float = 100.0
    rng: Random = field(default_factory=lambda: Random(0))
    path: Path | None = None
    _classes: dict[str, _Class] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        if self.path is not None:
            self._load()

    def _cplock(self):
        # Cross-process lock over the load-apply-save; no-op for a path-less
        # store. Without it two processes each hold a stale cached _classes and
        # the second _save clobbers the first's accumulated samples.
        if self.path is None:
            from contextlib import nullcontext
            return nullcontext()
        from .file_lock import cross_process_lock
        return cross_process_lock(self.path)

    def _reload_locked(self) -> None:
        if self.path is None:
            return
        self._classes = {}
        self._load()

    def observe(self, task_class: str, final_dollars: float) -> None:
        """Record what a finished run of ``task_class`` actually spent."""
        if not task_class or not math.isfinite(final_dollars) or final_dollars < 0:
            return
        with self._lock, self._cplock():
            self._reload_locked()
            c = self._classes.setdefault(task_class, _Class())
            c.count += 1
            if len(c.samples) < _RESERVOIR:
                c.samples.append(float(final_dollars))
            else:
                # Reservoir sampling: keep a representative bounded window.
                j = self.rng.randint(0, c.count - 1)
                if j < _RESERVOIR:
                    c.samples[j] = float(final_dollars)
            self._save()

    def suggest(self, task_class: str) -> float | None:
        """Suggested default cap for ``task_class`` (None until enough data).

        ``quantile(observed spend) * margin``, clamped to [floor, ceiling]. The
        margin gives head-room so a typical run of this class isn't strangled;
        the ceiling stops a runaway class from learning an unsafe cap.
        """
        with self._lock:
            c = self._classes.get(task_class)
            if c is None or c.count < self.min_samples:
                return None
            cap = c.quantile(self.quantile) * self.margin
        return max(self.floor, min(self.ceiling, round(cap, 2)))

    def stats(self, task_class: str) -> dict:
        with self._lock:
            c = self._classes.get(task_class)
            if c is None:
                return {"count": 0}
            snap = {"count": c.count, "q": round(c.quantile(self.quantile), 4)}
        # suggest() re-acquires the lock; call it OUTSIDE to avoid a deadlock
        # (threading.Lock is non-reentrant).
        snap["suggested"] = self.suggest(task_class)
        return snap

    # -- persistence ------------------------------------------------------

    def _load(self) -> None:
        try:
            raw = json.loads(Path(self.path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        for name, d in raw.items():
            try:
                samples = [float(x) for x in (d.get("samples") or [])]
                count = int(d.get("count", 0))
            except (AttributeError, TypeError, ValueError):
                continue
            # A tampered file must not turn NaN/inf into the ceiling suggestion.
            self._classes[name] = _Class(
                count=count,
                samples=[x for x in samples if math.isfinite(x) and x >= 0],
            )

    def _save(self) -> None:
        if self.path is None:
            return
        try:
            p = Path(self.path)
            p.parent.mkdir(parents=True, exist_ok=True)
            data = {n: {"count": c.count, "samples": c.samples}
                    for n, c in self._classes.items()}
            # Unique temp + os.replace: a fixed ".tmp" collides between processes.
            from .file_lock import atomic_write_text
            atomic_write_text(p, json.dumps(data, sort_keys=True))
        except Exception:  # pragma: no cover -- persistence is best-effort
            log.debug("self-tuning budget save failed", exc_info=True)


_shared: dict[Path, SelfTuningBudget] = {}
_shared_lock = threading.Lock()


def shared() -> SelfTuningBudget:
    from .paths import data_dir

    path = data_dir("budget_tuning.json")
    with _shared_lock:
        learner = _shared.get(path)
        if learner is None:
            learner = SelfTuningBudget(path=path)
            _shared[path] = learner
        return learner


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()


def suggested_max_dollars(task_class: str, *,
                          learner: SelfTuningBudget | None = None) -> float | None:
    """Return the default-on learned cap for ``task_class``, or None.

    None when self-tuning is off, the class is cold, or anything fails — the
    caller keeps its configured static cap.
    """
    if not enabled():
        return None
    try:
        return (learner or shared()).suggest(task_class)
    except Exception:  # pragma: no cover -- never block a run
        return None


def record_run_cost(task_class: str, final_dollars: float, *,
                    learner: SelfTuningBudget | None = None) -> None:
    """Record a finished run's spend (always safe; only stores when on)."""
    if not enabled():
        return
    from .learning_guard import learning_write_allowed
    if not learning_write_allowed("self_tuning_budget"):
        return
    try:
        (learner or shared()).observe(task_class, final_dollars)
    except Exception:  # pragma: no cover
        pass


__all__ = ["SelfTuningBudget", "enabled", "shared", "reset_shared",
           "suggested_max_dollars", "record_run_cost"]
