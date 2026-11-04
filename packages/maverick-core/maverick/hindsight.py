"""Hindsight: does today's learned state still help on yesterday's work?

The learning loops add AND remove knowledge -- dreaming distills skills,
promotes insights, but also retires skills, expires insights, and prunes
reflexions. Removal is where a learning system silently regresses: a lesson
that was recalled for a class of goal quietly stops being recalled, and
nothing tells you. This module answers "did our own learning make us worse
anywhere, and where?"

It does NOT re-run agents (that needs an LLM and isn't reproducible).
Instead it measures *coverage*: for a historical goal, does a learned-state
snapshot surface a relevant lesson (reflexion, dream insight, or learned
skill)? Coverage is computed with the SAME deterministic lexical machinery
the live recall paths use, pointed at a snapshot directory -- so the answer
is exactly what the agent would have been handed, reproducibly.

Comparing coverage between two snapshots yields three sets:
  * **gained**    -- goals the newer state now covers that the older didn't
    (the learning loops working);
  * **regressed** -- goals the older state covered that the newer one no
    longer does (a retired skill / expired insight / pruned reflexion that
    cost real coverage -- the signal to surface);
  * **unchanged**.

`maverick dream` already snapshots every learned store before each cycle, so
those timestamped snapshot dirs ARE the history this replays against -- no
new state. Output is a deterministic report, optionally written as a signed
ledger line so the improvement/regression record is tamper-evident. Opt-in,
read-only, fail-open.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)

log = logging.getLogger(__name__)

_TOKEN_RE_MIN = 3


@dataclass
class Coverage:
    """What a learned-state snapshot surfaces for one goal."""
    covered: bool = False
    reflexion: bool = False
    insight: bool = False
    skill: str | None = None      # matched learned-skill name, if any
    top_score: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HindsightReport:
    n_goals: int = 0
    gained: list[str] = field(default_factory=list)       # goal titles
    regressed: list[str] = field(default_factory=list)
    covered_now: int = 0
    covered_before: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        delta = self.covered_now - self.covered_before
        sign = "+" if delta >= 0 else ""
        head = (
            f"Hindsight over {self.n_goals} past goal(s): coverage "
            f"{self.covered_before} -> {self.covered_now} ({sign}{delta}); "
            f"{len(self.gained)} gained, {len(self.regressed)} regressed."
        )
        if self.regressed:
            head += ("\nREGRESSIONS (a lesson that used to be recalled no "
                     "longer is):")
            for title in self.regressed[:10]:
                head += f"\n  - {title}"
            if len(self.regressed) > 10:
                head += f"\n  ... and {len(self.regressed) - 10} more"
        return head


def _store_paths(directory: Path | str | None) -> dict[str, Path]:
    """Resolve the (reflexions, insights, skills-dir) of a learned state.

    ``None`` means the LIVE state (current tenant's stores); a path means a
    snapshot directory written by ``dreaming.snapshot_learning_state``.
    """
    if directory is None:
        from . import dreaming, reflexion
        from .skill.distillation_local import _default_store
        return {
            "reflexions": reflexion.default_path(),
            "insights": Path(dreaming.insights_path()),
            "skills": _default_store(),
        }
    d = Path(directory)
    return {
        "reflexions": d / "reflexions.ndjson",
        "insights": d / "insights.ndjson",
        "skills": d / "learned-skills",
    }


def _skill_match(goal_text: str, skills_dir: Path, *, min_overlap: float = 0.34) -> str | None:
    """Name of a learned skill whose triggers/name cover this goal, or None.

    Lexical containment of the goal's content tokens by the skill file's
    tokens -- the same zero-dependency approach the distillation v2 dedup
    uses, so coverage matches what the live skill recall would surface."""
    if not skills_dir.is_dir():
        return None
    try:
        from .skill.distillation import _tokens as _sk_tokens
    except Exception:  # pragma: no cover
        return None
    gt = _sk_tokens(goal_text)
    if not gt:
        return None
    best, best_score = None, 0.0
    for md in sorted(skills_dir.glob("*.md")):
        try:
            st = _sk_tokens(md.read_text(encoding="utf-8"))
        except OSError:
            continue
        if not st:
            continue
        score = len(gt & st) / len(gt)
        if score > best_score:
            best, best_score = md.stem, score
    return best if best_score >= min_overlap else None


def coverage_under(
    goal_text: str, directory: Path | str | None, *, domain: str | None = None,
) -> Coverage:
    """Coverage a learned state (live or a snapshot dir) gives one goal.

    Deterministic: reuses ``reflexion.recall`` and ``dreaming.recall_insights``
    pointed at the snapshot's files, plus a lexical learned-skill match.
    Never raises -- a missing/garbled snapshot reads as "no coverage"."""
    paths = _store_paths(directory)
    cov = Coverage()
    try:
        from . import reflexion
        hits = reflexion.recall(goal_text, k=1, path=paths["reflexions"],
                                domain=domain)
        if hits:
            cov.reflexion = True
            cov.top_score = max(cov.top_score, float(hits[0][0]))
    except Exception:  # pragma: no cover -- coverage never raises
        pass
    try:
        from . import dreaming
        ins = dreaming.recall_insights(goal_text, domain=domain, k=1,
                                       path=paths["insights"])
        if ins:
            cov.insight = True
            cov.top_score = max(cov.top_score, float(ins[0][0]))
    except Exception:  # pragma: no cover
        pass
    cov.skill = _skill_match(goal_text, paths["skills"])
    cov.covered = bool(cov.reflexion or cov.insight or cov.skill)
    return cov


def _goal_texts(world: Any, *, limit: int, status: str | None) -> list[tuple[str, str | None]]:
    """(text, domain) for recent goals to replay; newest first."""
    out: list[tuple[str, str | None]] = []
    try:
        goals = world.list_goals(status=status, limit=limit, order="desc") \
            if status else world.list_goals(limit=limit, order="desc")
    except Exception as e:  # pragma: no cover -- world read never blocks
        log.debug("hindsight: goal read failed: %s", e)
        return out
    for g in goals:
        title = getattr(g, "title", "") or ""
        desc = getattr(g, "description", "") or ""
        text = f"{title}\n{desc}".strip()
        if text:
            out.append((text, getattr(g, "domain", "") or None))
    return out


def replay(
    world: Any, *, before: Path | str | None, after: Path | str | None = None,
    limit: int = 100, status: str | None = "blocked",
) -> HindsightReport:
    """Compare learned-state coverage of recent goals between two states.

    ``before`` is an older snapshot dir; ``after`` is the newer state
    (``None`` = live). Defaults to replaying recent FAILED goals (``status=
    "blocked"``) -- the ones a recalled lesson would most help -- but pass
    ``status=None`` to replay all. Pure read path; never raises into a run.
    """
    report = HindsightReport()
    goals = _goal_texts(world, limit=limit, status=status)
    report.n_goals = len(goals)
    for text, domain in goals:
        cov_b = coverage_under(text, before, domain=domain)
        cov_a = coverage_under(text, after, domain=domain)
        report.covered_before += int(cov_b.covered)
        report.covered_now += int(cov_a.covered)
        title = text.splitlines()[0][:120]
        if cov_a.covered and not cov_b.covered:
            report.gained.append(title)
        elif cov_b.covered and not cov_a.covered:
            report.regressed.append(title)
    return report


def write_ledger(
    report: HindsightReport, *, before_label: str, path: Path | str | None = None,
    now: float | None = None,
) -> bool:
    """Append an aggregate summary and a separate audit event; never raises.

    True means both writes reported success, not that signing was enabled or
    that coverage proves improved task outcomes. False can follow a committed
    local summary: these stores do not share a transaction, so inspect before
    retrying. The local summary file itself is not a signed ledger.
    """
    try:
        from . import dreaming
        p = Path(path) if path is not None else \
            Path(dreaming._tenant_path("dreams/hindsight.ndjson",
                                       dreaming.DEFAULT_DIR / "hindsight.ndjson"))
        ensure_private_directory(p.parent)
        # Goal titles/descriptions are sensitive world-model content.
        # Persist only aggregate counts in the plaintext ledger so --ledger
        # cannot become a side channel that copies decrypted goal text out of
        # the protected world model.
        row = {
            "ts": now if now is not None else time.time(),
            "before": before_label,
            "n_goals": report.n_goals,
            "covered_now": report.covered_now,
            "covered_before": report.covered_before,
            "gained": len(report.gained),
            "regressed": len(report.regressed),
        }
        line = json.dumps(row, default=str) + "\n"
        # The ledger is append-only logically, but an OS append open cannot
        # request a protected DACL at creation through Python on Windows. A
        # stable sidecar serializes the read/append/publish transaction while
        # the shared atomic writer creates the replacement privately.
        with cross_process_lock(p):
            try:
                ensure_private_file(p, 0o600)
                current = atomic_read_text(p)
            except FileNotFoundError:
                current = ""
            atomic_write_text(p, current + line, mode=0o600)
    except Exception as e:  # pragma: no cover -- ledger never blocks
        log.debug("hindsight: ledger write skipped: %s", e)
        return False
    try:
        from .audit import EventKind, record
        written = record(
            EventKind.LEARNING_UPDATE, agent="hindsight",
            replay="hindsight", before=before_label,
            n_goals=report.n_goals, covered_before=report.covered_before,
            covered_now=report.covered_now,
            gained=len(report.gained), regressed=len(report.regressed),
        )
    except Exception:
        # The local summary is already committed; report incomplete evidence
        # without implying rollback or inviting an automatic duplicate append.
        log.warning("hindsight: summary saved but audit write failed", exc_info=True)
        return False
    if written is not True:
        log.warning("hindsight: summary saved but audit write was not confirmed")
        return False
    return True


__all__ = [
    "Coverage",
    "HindsightReport",
    "coverage_under",
    "replay",
    "write_ledger",
]
