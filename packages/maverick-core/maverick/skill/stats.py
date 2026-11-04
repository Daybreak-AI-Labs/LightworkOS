"""Skill usage tracking + decay.

The distill-time quality gate judges a skill by the run that CREATED it.
This module judges a skill by how it PERFORMS once in circulation: every
time a skill is recalled into a run we record a use, and when that run
finishes we record the outcome against the skills it used. A skill that's
repeatedly recalled but rides along with failures loses rank (decay); one
that rarely helps and never wins can be evicted. This closes the learning
loop — the library curates itself instead of only growing.

Storage: ``~/.maverick/skill_stats.json`` (chmod 600), a flat map of
``name -> {uses, wins, losses, last_used}``. Writes are atomic (temp +
``os.replace``) and the recording load-modify-save is serialized by an
in-process lock **plus a cross-process flock** (the dashboard and serve are
separate processes hitting this per run); they are fully fail-safe — stats are
an optimization, never a correctness dependency, so any I/O error degrades to
"no signal" (neutral weight) and never blocks a run.

All recording is opt-in-friendly: disable the decay multiplier with
``MAVERICK_SKILL_DECAY=0`` and ranking falls back to relevance only.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from ..paths import data_dir
from ..wilson_score import wilson_upper_bound as _wilson_upper_bound

log = logging.getLogger(__name__)

DEFAULT_PATH = data_dir("skill_stats.json")
_lock = threading.Lock()


@dataclass
class SkillStat:
    uses: int = 0
    wins: int = 0
    losses: int = 0
    last_used: float = 0.0


def _enabled() -> bool:
    from ..env_setting import env_or_config

    return env_or_config("MAVERICK_SKILL_DECAY", "skills", "decay", "1") != "0"


def _resolve(path: Path | None) -> Path:
    """Resolve the stats path, reading the module attribute at CALL time.

    Binding ``DEFAULT_PATH`` as a function default would freeze it at import
    time, so a test that monkeypatches ``skill_stats.DEFAULT_PATH`` (or a
    future per-profile override) wouldn't take effect. Callers pass None to
    mean "use the current default."
    """
    if path is not None:
        return path
    # Item-30 isolation: an ACTIVE tenant gets its own stats store. The
    # module-attr lookup below stays last so tests monkeypatching
    # DEFAULT_PATH keep working in the single-tenant layout.
    try:
        from ..paths import current_tenant, data_dir
        if current_tenant():
            return data_dir("skill_stats.json")
    except Exception:  # pragma: no cover -- isolation never blocks resolution
        pass
    return DEFAULT_PATH


def _load(path: Path) -> dict[str, SkillStat]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    out: dict[str, SkillStat] = {}
    if not isinstance(raw, dict):
        return {}
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        try:
            out[name] = SkillStat(
                uses=int(entry.get("uses", 0)),
                wins=int(entry.get("wins", 0)),
                losses=int(entry.get("losses", 0)),
                last_used=float(entry.get("last_used", 0.0)),
            )
        except (TypeError, ValueError):
            continue
    return out


def _save(stats: dict[str, SkillStat], path: Path) -> None:
    # Atomic temp+replace: a bare write_text truncates in place, so a concurrent
    # _load() reader sees a half-written file -> its JSONDecodeError is swallowed
    # as an empty store and the accumulated use/win/loss + eviction state is lost.
    from ..file_lock import atomic_write_text
    atomic_write_text(path, json.dumps({k: asdict(v) for k, v in stats.items()}))


def record_use(names: list[str], path: Path | None = None) -> None:
    """Mark that ``names`` were recalled into a run. Fail-safe no-op on error."""
    if not _enabled() or not names:
        return
    path = _resolve(path)
    # In-process lock + cross-process flock: hit per run from separate processes
    # (dashboard + serve); without the flock two writers lose use/win/loss counts.
    from ..file_lock import cross_process_lock
    with _lock, cross_process_lock(path):
        try:
            stats = _load(path)
            now = time.time()
            for n in names:
                st = stats.get(n) or SkillStat()
                st.uses += 1
                st.last_used = now
                stats[n] = st
            _save(stats, path)
        except OSError as e:  # pragma: no cover
            log.debug("skill_stats record_use failed: %s", e)


def record_outcome(
    names: list[str], *, success: bool, path: Path | None = None,
) -> None:
    """Attribute a run's outcome to the skills it used. Fail-safe."""
    if not _enabled() or not names:
        return
    path = _resolve(path)
    from ..file_lock import cross_process_lock
    with _lock, cross_process_lock(path):
        try:
            stats = _load(path)
            for n in names:
                st = stats.get(n) or SkillStat()
                if success:
                    st.wins += 1
                else:
                    st.losses += 1
                stats[n] = st
            _save(stats, path)
        except OSError as e:  # pragma: no cover
            log.debug("skill_stats record_outcome failed: %s", e)


def _weight_from_stat(
    st: SkillStat | None, min_uses: int, floor: float,
) -> float:
    """Pure win-rate → multiplier in [floor, 1.0]. Shared by the single and
    batch accessors so the decay curve is defined in exactly one place."""
    if st is None or st.uses < min_uses:
        return 1.0
    decided = st.wins + st.losses
    if decided == 0:
        return 1.0
    return floor + (1.0 - floor) * (st.wins / decided)


def decay_weight(
    name: str,
    *,
    path: Path | None = None,
    min_uses: int = 3,
    floor: float = 0.5,
) -> float:
    """Track-record multiplier in [floor, 1.0] for a skill by name.

    Neutral (1.0) until a skill has been used ``min_uses`` times — we don't
    punish a skill before it's had a fair chance. After that, the weight is
    ``floor + (1-floor) * win_rate`` where win_rate = wins / (wins+losses).
    A skill that always rides along with successful runs stays at 1.0; one
    that consistently rides along with failures decays toward ``floor`` (it
    yields to alternatives but is never fully silenced — relevance can still
    surface it). Returns 1.0 on any error or when decay is disabled.
    """
    if not _enabled():
        return 1.0
    try:
        with _lock:
            stats = _load(_resolve(path))
        return _weight_from_stat(stats.get(name), min_uses, floor)
    except Exception:  # pragma: no cover -- stats never block recall
        return 1.0


def decay_weights(
    names: list[str],
    *,
    path: Path | None = None,
    min_uses: int = 3,
    floor: float = 0.5,
) -> dict[str, float]:
    """Batch ``decay_weight``: one file read for many names.

    Skill retrieval weights every candidate BEFORE truncating to top-N, so
    the per-name accessor would re-read the stats file once per candidate.
    This loads it once. Missing names and any error degrade to neutral 1.0,
    so callers never have to special-case a partial result.
    """
    if not _enabled():
        return dict.fromkeys(names, 1.0)
    try:
        with _lock:
            stats = _load(_resolve(path))
    except Exception:  # pragma: no cover -- stats never block recall
        return dict.fromkeys(names, 1.0)
    return {n: _weight_from_stat(stats.get(n), min_uses, floor) for n in names}


def evictable(
    *,
    path: Path | None = None,
    min_uses: int = 5,
    max_win_rate: float = 0.2,
) -> list[str]:
    """Names of skills that have had a fair trial and rarely help.

    A skill is evictable when it's been used at least ``min_uses`` times,
    has a decided outcome, and the Wilson-score UPPER bound on its true win
    rate is at or below ``max_win_rate`` -- i.e. even the most favorable
    plausible reading of the evidence still says "rarely helps". The raw
    point estimate (``wins / decided``) is not enough at small n: 1 win in 5
    uses has a 95% upper bound near 0.62, so a "≤ 0.2" point-estimate rule
    would evict a skill the data hasn't actually convicted yet. Callers (e.g.
    a maintenance command) decide whether to actually delete; this function
    only identifies candidates and never mutates state.
    """
    try:
        with _lock:
            stats = _load(_resolve(path))
    except Exception:  # pragma: no cover
        return []
    out: list[str] = []
    for name, st in stats.items():
        decided = st.wins + st.losses
        if (st.uses >= min_uses and decided > 0
                and _wilson_upper_bound(st.wins, decided) <= max_win_rate):
            out.append(name)
    return out


def usage_rows(names: list[str], *, path: Path | None = None) -> list[dict]:
    """Each named skill's track record, in ``names`` order, from one read.

    ``{name, uses, wins, losses, win_rate, weight, last_used}``: ``win_rate``
    is wins over decided runs (``None`` until a run was decided, ``0.0`` when
    used but undecided -- the ``skills stats`` reading) and ``weight`` is the
    recall multiplier :func:`decay_weight` applies. A skill with no recorded
    use has ``uses == 0``. Shared by ``maverick skills stats`` and the Skills
    page so both read the same numbers."""
    try:
        with _lock:
            stats = _load(_resolve(path))
    except Exception:  # pragma: no cover -- stats never block a read-out
        stats = {}
    rows: list[dict] = []
    for name in names:
        st = stats.get(name)
        if st is None or st.uses == 0:
            rows.append({"name": name, "uses": 0, "wins": 0, "losses": 0,
                         "win_rate": None, "weight": 1.0, "last_used": 0.0})
            continue
        decided = st.wins + st.losses
        weight = _weight_from_stat(st, 3, 0.5) if _enabled() else 1.0
        rows.append({"name": name, "uses": st.uses, "wins": st.wins, "losses": st.losses,
                     "win_rate": (st.wins / decided) if decided else 0.0,
                     "weight": weight, "last_used": st.last_used})
    return rows


def get(name: str, path: Path | None = None) -> SkillStat | None:
    """Return the stored stat for ``name``, or None."""
    try:
        with _lock:
            return _load(_resolve(path)).get(name)
    except Exception:  # pragma: no cover
        return None


__all__ = [
    "SkillStat",
    "DEFAULT_PATH",
    "record_use",
    "record_outcome",
    "decay_weight",
    "decay_weights",
    "evictable",
    "get",
    "usage_rows",
]
