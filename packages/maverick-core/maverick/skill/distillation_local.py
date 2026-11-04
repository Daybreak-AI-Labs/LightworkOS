"""Local continuous-learning skill loop: distill successful runs into a skill.

After a run succeeds, its trajectory (goal + the tools it used) is evidence of a
repeatable approach. This distills the top-k most recent successful trajectories
into a proposed micro-skill — a ``SKILL.md`` with frontmatter (name,
triggers, tools_needed) and numbered steps — written to the active tenant's
``learned-skills/`` store. A proposal enters later-run recall only after an
administrator reviews and admits its exact version on the Skills page.

Enabled by default (``MAVERICK_DISTILL_LOCAL=0`` opts out). Dependency-free:
ranking is by success + recency and the synthesis is
lexical (no embedding model required), so the loop runs anywhere. ``distill`` and
``to_skill_markdown`` are pure and unit-tested; the generated skill is valid for
``maverick.skills.validate_skill_file``.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..paths import data_dir

_STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "with", "from",
    "by", "at", "as", "is", "are", "be", "this", "that", "it", "your", "my",
    "please", "then", "into", "write", "run", "do", "make", "get", "use",
}


def enabled(*, config: dict | None = None) -> bool:
    """``config`` lets a caller reuse an already-loaded config snapshot
    instead of loading it again (see ``maverick.config.get_role_model``).
    Only ever forwarded when actually given one, so a test double for
    ``get_self_learning`` that (like most in this codebase) takes no
    arguments keeps working when this is called the old, plain way."""
    try:
        from ..config import get_self_learning, governed_learning_env_flag
        override = governed_learning_env_flag("MAVERICK_DISTILL_LOCAL")
        if override is not None:
            return override
        sl = get_self_learning() if config is None else get_self_learning(config=config)
        return bool(sl.get("distill_local", True))
    except Exception:  # pragma: no cover
        return False


def _keywords(texts: list[str], k: int = 3) -> list[str]:
    counts: dict[str, int] = {}
    for t in texts:
        for w in re.findall(r"[a-z0-9]+", (t or "").lower()):
            if len(w) < 3 or w in _STOPWORDS:
                continue
            counts[w] = counts.get(w, 0) + 1
    return [w for w, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:k]]


def distill(trajectories: list[dict], *, top_k: int = 3) -> dict | None:
    """Distill successful trajectories into a skill dict, or ``None`` if none.

    Each trajectory: ``{goal, success, tools: [str], t: float}``. Picks the
    most-recent ``top_k`` successful runs, derives a kebab name + triggers from
    their goals, and unions their tools.
    """
    from ..pilot_learning import excluded
    good = [t for t in (trajectories or []) if t.get("success") and not excluded(t.get("goal_id"))]
    if not good:
        return None
    good.sort(key=lambda t: t.get("t", 0), reverse=True)
    chosen = good[:top_k]
    goals = [str(t.get("goal", "")).strip() for t in chosen if t.get("goal")]
    if not goals:
        return None

    kws = _keywords(goals)
    name = "-".join(kws) if kws else "learned-skill"
    name = re.sub(r"[^a-z0-9-]", "", name).strip("-") or "learned-skill"

    tools: list[str] = []
    for t in chosen:
        for tool in t.get("tools", []) or []:
            if tool not in tools:
                tools.append(tool)

    # Collapse ALL whitespace (incl. embedded newlines) before slicing: goal
    # text is written into the learned SKILL.md's YAML frontmatter, so a goal
    # containing a newline could otherwise inject frontmatter keys / break the
    # document structure (str.strip only trims the edges).
    triggers = []
    for g in goals:
        trg = " ".join(g.split()).lower()[:80]
        if trg and trg not in triggers:
            triggers.append(trg)

    # Goal IDS, not just titles: the entity graph derives its
    # skill -> goal lineage from these, and lineage must come from exact
    # keys -- a title is prose, an id is provenance. Absent ids (older
    # callers) simply yield a skill with no source edges, never a guess.
    source_goal_ids = []
    for t in chosen:
        gid = t.get("goal_id")
        if isinstance(gid, int) and gid > 0 and gid not in source_goal_ids:
            source_goal_ids.append(gid)

    return {
        "name": name,
        "triggers": triggers,
        "tools_needed": tools,
        "summary": " ".join(goals[0].split()),
        "n_examples": len(chosen),
        "source_goal_ids": source_goal_ids,
    }


def _utc_now_iso() -> str:
    """UTC timestamp for skill provenance (the colons in the time round-trip
    through the line-based frontmatter parser; no other punctuation)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_skill_markdown(skill: dict) -> str:
    """Render a distilled skill as a validator-compliant ``SKILL.md`` string.

    Carries machine-readable PROVENANCE in the frontmatter -- when it was
    learned, from how many examples, and by which path -- so a learned skill is
    inspectable and auditable (governed learning), not an anonymous blob. The
    validator accepts these keys and the in-memory Skill ignores them, but they
    are preserved on disk; values are kept special-char-free so the line-based
    frontmatter parser round-trips them."""
    lines = ["---", f"name: {skill['name']}", "triggers:"]
    lines += [f"  - {t}" for t in skill["triggers"]]
    if skill.get("tools_needed"):
        lines.append("tools_needed:")
        lines += [f"  - {t}" for t in skill["tools_needed"]]
    # Provenance (governed learning): structured, special-char-free values.
    lines.append(f"distilled_at: {skill.get('distilled_at') or _utc_now_iso()}")
    lines.append(f"n_examples: {int(skill.get('n_examples', 1))}")
    lines.append(f"source: {skill.get('source') or 'auto-distilled-local-v2'}")
    # The exact goals this skill was distilled from (space-separated ids,
    # special-char-free). This is what lets the entity graph answer "this run
    # turned out to be tainted -- which learned skills depend on it?" with
    # lineage instead of guesswork; a skill written before this key simply
    # reads as provenance-unknown.
    gids = [str(int(g)) for g in (skill.get("source_goal_ids") or [])
            if isinstance(g, int) and g > 0]
    if gids:
        lines.append(f"source_goal_ids: {' '.join(gids[:16])}")
    lines.append("---")
    lines.append("")
    lines.append("# What this does")
    lines.append("")
    lines.append(
        f"Distilled from {skill.get('n_examples', 1)} successful run(s). "
        f"Approach for: {skill.get('summary', skill['name'])}.")
    lines.append("")
    lines.append("# Steps")
    lines.append("")
    if skill.get("tools_needed"):
        for i, tool in enumerate(skill["tools_needed"], 1):
            lines.append(f"{i}. Use the `{tool}` tool as the run did before.")
    else:
        lines.append("1. Follow the approach that succeeded on similar past goals.")
    return "\n".join(lines) + "\n"


def _default_store() -> Path:
    """Resolve the learned-skills store for the currently active tenant."""
    return data_dir("learned-skills")


def save_skill(skill: dict, store: Path | str | None = None) -> Path:
    """Write the distilled skill to ``<store>/<name>.md`` and return the path."""
    if not enabled():
        raise RuntimeError("local skill distillation is disabled")
    from ..learning_guard import learning_write_allowed
    if not learning_write_allowed("distillation_local", "save_skill"):
        raise RuntimeError("local skill distillation is halted")
    name = str(skill.get("name") or "")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 96:
        raise ValueError("distilled skill name must be bounded kebab-case")
    from ..file_lock import atomic_write_text, cross_process_lock, ensure_private_directory
    store = (Path(store) if store is not None else _default_store()).resolve()
    ensure_private_directory(store)
    path = store / f"{name}.md"
    with cross_process_lock(path):
        atomic_write_text(path, to_skill_markdown(skill), mode=0o600)
    return path


def distill_and_save(trajectories: list[dict], *, top_k: int = 3,
                     store: Path | str | None = None) -> Path | None:
    """Distill + persist in one call (caller checks the default-on gate)."""
    skill = distill(trajectories, top_k=top_k)
    return save_skill(skill, store) if skill else None


__all__ = [
    "enabled", "distill", "to_skill_markdown", "save_skill", "distill_and_save",
]
