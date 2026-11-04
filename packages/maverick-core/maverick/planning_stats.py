"""Learned planning-topology selection.

Tree-of-thought, debate, and plain planning are operator-chosen today; this
records which topology actually won per task class so ``[planning] mode =
"auto"`` can pick. Bandit-lite and deterministic: explore the under-sampled
mode until both have ``min_runs`` samples, then exploit the higher win rate
(ties keep the cheaper default). Storage mirrors role_stats:
``~/.maverick/planning_stats.json`` (chmod 600), fail-safe everywhere — stats
are an optimization, never a correctness dependency.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

from .paths import data_dir

log = logging.getLogger(__name__)

DEFAULT_PATH = data_dir("planning_stats.json")
_lock = threading.Lock()

MODES = ("default", "tree_of_thought")


def _resolve(path: Path | None) -> Path:
    if path is not None:
        return path
    return _tenant_path("planning_stats.json", DEFAULT_PATH)


def _tenant_path(name: str, legacy):
    """Item-30 isolation: with an ACTIVE tenant, this store lives under the
    tenant's data dir (one tenant's learned memory can never feed another's
    runs); single-tenant resolution keeps the legacy location unchanged."""
    try:
        from .paths import current_tenant, data_dir
        if current_tenant():
            return data_dir(*name.split("/"))
    except Exception:  # pragma: no cover -- isolation never blocks resolution
        pass
    return legacy



def _load(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def record(mode: str, task_class: str, success: bool,
           path: Path | None = None) -> None:
    """Accumulate one (mode, task_class, outcome) observation. Fail-safe."""
    if mode not in MODES or not task_class:
        return
    p = _resolve(path)
    # In-process lock + cross-process flock: a bare write_text truncates in
    # place (a concurrent _load() reader's JSONDecodeError is swallowed as an
    # empty store, wiping the win/loss counters), and without the flock two
    # processes lose updates that bias topology selection.
    from .file_lock import atomic_write_text, cross_process_lock
    with _lock, cross_process_lock(p):
        try:
            data = _load(p)
            entry = data.setdefault(f"{mode}::{task_class}", {})
            entry["runs"] = int(entry.get("runs", 0)) + 1
            entry["wins"] = int(entry.get("wins", 0)) + (1 if success else 0)
            entry["last"] = time.time()
            atomic_write_text(p, json.dumps(data))
        except OSError as e:  # pragma: no cover -- stats never block a run
            log.debug("planning_stats record failed: %s", e)


def _stat(data: dict, mode: str, task_class: str) -> tuple[int, int]:
    entry = data.get(f"{mode}::{task_class}") or {}
    try:
        return int(entry.get("runs", 0)), int(entry.get("wins", 0))
    except (TypeError, ValueError):
        return 0, 0


def prefer_tree_of_thought(task_class: str, *, min_runs: int = 3,
                           path: Path | None = None) -> bool:
    """Whether auto mode should plan with tree-of-thought for this class.

    Exploration phase: until BOTH modes have ``min_runs`` samples, pick the
    under-sampled one (ties keep the cheaper default). Exploitation phase:
    pick the higher win rate; ties keep the default (no extra tokens without
    evidence they pay off).
    """
    data = _load(_resolve(path))
    d_runs, d_wins = _stat(data, "default", task_class)
    t_runs, t_wins = _stat(data, "tree_of_thought", task_class)
    if d_runs < min_runs or t_runs < min_runs:
        return t_runs < d_runs
    d_rate = d_wins / d_runs if d_runs else 0.0
    t_rate = t_wins / t_runs if t_runs else 0.0
    return t_rate > d_rate


__all__ = ["MODES", "DEFAULT_PATH", "record", "prefer_tree_of_thought"]
