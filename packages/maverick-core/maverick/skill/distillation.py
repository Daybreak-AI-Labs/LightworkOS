"""Evidence-gated auto-skill distillation.

:mod:`maverick.skill.distillation_local` distills recent successful runs into a
``SKILL.md``. Run after every goal on its own, a learned-skills store would fill
with near-duplicates of the same lesson, and a one-off success could mint a
skill that never recurs. This module adds the two quality gates that keep
continuous learning useful:

* **gate on evidence** — don't distill from fewer than ``min_examples``
  successful trajectories (a single success is noise, not a repeatable skill);
* **dedup against the store** — don't save a skill whose content is already
  covered by one already learned (lexical **overlap/containment** over the skill
  text — the right metric when a compact candidate is checked against a fuller
  saved skill; the same zero-dep / no-embedding-model approach as
  ``distillation_local``), so the
  store stays a set of *distinct* lessons.
* **gate on quality** — don't save a skill too generic to retrieve precisely:
  one whose content signature is mostly glue words would over-fire on unrelated
  goals and *inject noise* into warm runs — the very failure the recall
  relevance gate fights — so it is worse than no skill at all. A learned skill
  must carry enough specific signal (distinct non-glue tokens) to be matched
  precisely, or it is dropped.

Pure and deterministic: the gates take plain skill dicts / signatures, tested
without touching disk; ``distill_and_save_gated`` is the drop-in the loop calls
and checks the strict global learning stop immediately before its durable save.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from .distillation_local import _default_store, distill, save_skill

# A small stop-list so the signature is content words, not glue.
_STOP = frozenset({
    "the", "and", "for", "with", "this", "that", "from", "into", "your", "you",
    "are", "was", "use", "using", "skill", "learned", "step", "steps", "when",
    "then", "run", "goal", "task",
})

DEFAULT_MIN_EXAMPLES = 2
DEFAULT_DEDUP_THRESHOLD = 0.6
# A learned skill needs at least this many distinct non-glue tokens in its
# content signature, or it is too generic to retrieve precisely (it would
# over-fire and inject noise). Conservative so real narrow skills still pass.
DEFAULT_MIN_SIGNAL_TOKENS = 4


def _tokens(text: str) -> frozenset[str]:
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return frozenset(w for w in words if len(w) >= 3 and w not in _STOP)


def _signature(skill: dict) -> frozenset[str]:
    parts = [skill.get("name", ""), skill.get("summary", "")]
    parts += list(skill.get("triggers", []) or [])
    parts += list(skill.get("tools_needed", []) or [])
    return _tokens(" ".join(str(p) for p in parts))


def _overlap(a: frozenset, b: frozenset) -> float:
    """Overlap (containment) coefficient: ``|a∩b| / min(|a|,|b|)``.

    Unlike Jaccard, this isn't deflated when one set is much larger — what we
    want when a compact candidate skill is checked against a fuller saved one.
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


def is_duplicate(signature: frozenset[str], existing: list[frozenset[str]], *,
                 threshold: float = DEFAULT_DEDUP_THRESHOLD) -> bool:
    return any(_overlap(signature, e) >= threshold for e in existing)


def signatures_from_store(store: Path | str | None = None) -> list[frozenset[str]]:
    """Content signatures of every already-learned skill in ``store``."""
    p = Path(store) if store is not None else _default_store()
    if not p.exists():
        return []
    out: list[frozenset[str]] = []
    for md in sorted(p.glob("*.md")):
        try:
            out.append(_tokens(md.read_text(encoding="utf-8")))
        except OSError:
            continue
    return out


def passes_quality(skill: dict, *,
                   min_signal: int = DEFAULT_MIN_SIGNAL_TOKENS) -> tuple[bool, str]:
    """Quality gate: a learned skill must be *specific enough to recall
    precisely*. A skill with no triggers can never match; a skill whose content
    signature is mostly glue words would over-fire on unrelated goals and inject
    noise into warm runs (precision >> recall for agent memory), making it worse
    than no skill. Returns ``(ok, reason)``; pure/deterministic."""
    if not (skill.get("triggers") or []):
        return False, "no triggers"
    n = len(_signature(skill))
    if n < min_signal:
        return False, f"too generic ({n} signal tokens < {min_signal})"
    return True, "ok"


def distill_gated(trajectories: list[dict], *,
                  existing_signatures: list[frozenset[str]] | None = None,
                  top_k: int = 3, min_examples: int = DEFAULT_MIN_EXAMPLES,
                  dedup_threshold: float = DEFAULT_DEDUP_THRESHOLD,
                  min_signal: int = DEFAULT_MIN_SIGNAL_TOKENS) -> tuple[dict | None, str]:
    """Distill with the evidence, quality and dedup gates. Returns
    ``(skill_or_None, reason)``."""
    skill = distill(trajectories, top_k=top_k)
    if skill is None:
        return None, "no successful trajectories"
    if int(skill.get("n_examples", 0)) < min_examples:
        return None, f"too few examples ({skill.get('n_examples', 0)} < {min_examples})"
    ok, why = passes_quality(skill, min_signal=min_signal)
    if not ok:
        return None, f"low quality: {why}"
    sig = _signature(skill)
    if is_duplicate(sig, existing_signatures or [], threshold=dedup_threshold):
        return None, "duplicate of an existing skill"
    return skill, "ok"


def distill_and_save_gated(trajectories: list[dict], *, store: Path | str | None = None,
                           top_k: int = 3, min_examples: int = DEFAULT_MIN_EXAMPLES,
                           dedup_threshold: float = DEFAULT_DEDUP_THRESHOLD,
                           min_signal: int = DEFAULT_MIN_SIGNAL_TOKENS,
                           before_save: Callable[[], None] | None = None,
                           ) -> tuple[Path | None, str]:
    """Gate (evidence + quality + dedup) against ``store``, save only a novel,
    specific skill. Returns ``(path_or_None, reason)``."""
    existing = signatures_from_store(store)
    skill, reason = distill_gated(
        trajectories, existing_signatures=existing, top_k=top_k,
        min_examples=min_examples, dedup_threshold=dedup_threshold,
        min_signal=min_signal)
    if skill is None:
        return None, reason
    # This is a durable learning transition even when a caller uses the helper
    # directly (the orchestrator does). Keep the canonical strict boundary in
    # the primitive; ``before_save`` lets a higher-level job add its own
    # phase-specific final check, but cannot replace the global operator stop.
    from ..learning_guard import check_learning_halt
    check_learning_halt("skill_distillation", "save")
    if before_save is not None:
        before_save()
    return save_skill(skill, store), "ok"


__all__ = ["distill_gated", "distill_and_save_gated", "is_duplicate",
           "passes_quality", "signatures_from_store"]
