"""Per-user preference notes, distilled by the dreaming loop.

Compaction summarizes WITHIN a conversation; this consolidates ACROSS them:
explicit preference statements a user has made ("I prefer tables", "never
use emoji", "call me Sam") become a short briefing note injected into that
user's future runs, so every conversation stops re-learning the same
preferences.

Extraction is deterministic — a conservative phrase grammar over the user's
own turns, no LLM — so nothing a third party smuggles into tool output can
become a persisted "preference". Notes are scoped to (channel, user_id) and
only ever injected for that same scope; recall sanitizes + Shield-scans the
text and frames it as untrusted data. Produced by ``maverick dream``
(``[dreaming] user_notes``); injection is a no-op when the store is empty.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from .paths import data_dir

log = logging.getLogger(__name__)

DEFAULT_PATH = data_dir("dreams", "user_notes.ndjson")


def default_path() -> Path:
    return _tenant_path("dreams/user_notes.ndjson", DEFAULT_PATH)


def _tenant_path(name: str, legacy):
    """Item-30 isolation: with an ACTIVE tenant, this store lives under the
    tenant's data dir (one tenant's learned memory can never feed another's
    runs); single-tenant resolution keeps the legacy location unchanged."""
    from .paths import current_tenant, data_dir
    if current_tenant():
        return data_dir(*name.split("/"))
    return legacy


# Sentences that are explicit self-reported preferences. Conservative on
# purpose: false negatives just mean we learn less.
_PREF_RE = re.compile(
    r"(?:\bi(?:'d)? prefer\b"
    r"|\bcall me\b"
    r"|\bfrom now on\b"
    r"|\bplease (?:always|never)\b"
    r"|^always\b"
    r"|^never\b"
    r"|\brespond (?:in|with|using)\b"
    r"|\banswer (?:in|with|using)\b)",
    re.IGNORECASE,
)
_SENT_SPLIT = re.compile(r"(?<=[.!?\n])\s+")
_MAX_NOTE_LEN = 160


def extract_preferences(text: str) -> list[str]:
    """Preference sentences in a user message. Pure and deterministic."""
    out: list[str] = []
    for sent in _SENT_SPLIT.split(str(text or "")):
        s = " ".join(sent.split()).strip()
        if not s or len(s) > _MAX_NOTE_LEN:
            continue
        if _PREF_RE.search(s):
            out.append(s)
    return out


def _tokens(s: str) -> set[str]:
    # Compare the topic without polarity: "always use emoji" and "never use
    # emoji" are competing preferences, not two instructions to retain.
    return {t for t in re.findall(r"[a-z0-9]+", (s or "").lower())
            if len(t) >= 3 and t not in {"always", "never", "not", "please"}}


def _near_dup(a: str, b: str) -> bool:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return False
    return len(ta & tb) / min(len(ta), len(tb)) >= 0.8


def _preference_rows(world: Any, conversations: list, ts: float,
                     max_conversations: int, turns_per_conversation: int,
                     max_notes_per_user: int) -> list[dict]:
    """Newest source wins within each exact person/channel scope."""
    grouped: dict[tuple[str, str], list] = {}
    for conv in sorted(conversations, key=lambda c: (c.last_seen, c.id), reverse=True):
        scope = (getattr(conv, "channel", ""), getattr(conv, "user_id", ""))
        if not all(scope):
            continue
        group = grouped.setdefault(scope, [])
        if len(group) < max(1, max_conversations):
            group.append(conv)
    notes: list[dict] = []
    from .personal_memory import collection_allowed
    from .pilot_learning import excluded
    from .safety.secret_detector import redact
    for (channel, user_id), group in grouped.items():
        turns = []
        for conv in group:
            # A failed source read is unavailable, not a retraction. Abort the
            # rebuild so a transient database failure cannot silently erase memory.
            turns.extend(world.recent_turns(conv.id, limit=turns_per_conversation))
        current: list[str] = []
        for turn in sorted(turns, key=lambda t: (t.ts, t.id), reverse=True):
            if turn.role != "user" or excluded(getattr(turn, "goal_id", None)):
                continue
            for candidate in reversed(extract_preferences(turn.content)):
                pref, _ = redact(candidate)
                pref = " ".join(pref.split())[:_MAX_NOTE_LEN]
                if not pref or not collection_allowed(channel, user_id, pref) or any(_near_dup(pref, prior) for prior in current):
                    continue
                if len(current) >= max(1, max_notes_per_user):
                    break
                current.append(pref)
                notes.append({
                    "ts": ts, "channel": channel, "user_id": user_id, "note": pref,
                    "conversation_id": turn.conversation_id, "turn_id": turn.id,
                    "source_ts": turn.ts,
                    "source_revision": hashlib.sha256(turn.content.encode()).hexdigest(),
                    "source_goal_id": getattr(turn, "goal_id", None),
                })
    return notes


def consolidate(
    world: Any, *, path: Path | str | None = None,
    max_conversations: int = 20, turns_per_conversation: int = 50,
    max_notes_per_user: int = 8, now: float | None = None,
) -> int:
    """Rebuild notes from each person's own recent source window.

    Coworkers cannot evict a quiet person's notes. Newest source turns take
    precedence, including an opposite-polarity correction. Source edits and
    deletions disappear on the next successful rebuild; a failed scan preserves
    the prior store. Erasure and rebuilding share the complete read/write lock.
    """
    p = Path(path) if path is not None else default_path()
    from .learning_guard import learning_write_allowed
    if not learning_write_allowed("user_notes", "consolidate"):
        return 0
    from .file_lock import atomic_write_text, cross_process_lock
    try:
        with cross_process_lock(p):
            notes = _preference_rows(
                world, world.list_conversations() or [],
                now if now is not None else time.time(), max_conversations,
                turns_per_conversation, max_notes_per_user,
            )
            body = "".join(json.dumps(n, default=str) + "\n" for n in notes)
            atomic_write_text(p, body)
    except Exception as exc:  # noqa: BLE001 - a failed rebuild preserves prior notes
        log.warning("user_notes: consolidation unavailable: %s", type(exc).__name__)
        return 0
    return len(notes)


def notes_for(
    channel: str | None, user_id: str | None,
    path: Path | str | None = None, *, k: int = 8, execution_identity: bool = False,
) -> list[str]:
    """The stored notes for exactly this (channel, user_id) scope."""
    if not channel or not user_id:
        return []
    try:
        from .personal_memory import recall
        return recall(channel, user_id, path=path, k=k, execution_identity=execution_identity)
    except Exception as exc:
        log.warning("Personal recall unavailable: %s", type(exc).__name__)
        return []


def erase_notes(
    channel: str | None, user_ids: str | list[str] | tuple[str, ...] | set[str],
    path: Path | str | None = None,
    *,
    strict: bool = False,
) -> int:
    """Remove persisted notes for ``channel`` and the given user id(s).

    Returns the number of scoped note records removed. Malformed lines and
    unrelated scopes are preserved so erasure is narrow. The normal dreaming
    cleanup remains best-effort; the legal-erasure command passes
    ``strict=True`` so an unreadable or unwritable note store cannot be
    mistaken for a verified zero.
    """
    if not channel:
        return 0
    if isinstance(user_ids, str):
        targets = {user_ids}
    else:
        targets = {str(u) for u in user_ids if u}
    if not targets:
        return 0

    p = Path(path) if path is not None else default_path()
    if not p.exists():
        return 0

    removed = 0
    try:
        # Hold the lock across the read-filter-write so a concurrent erase /
        # consolidate can't interleave and lose this removal.
        from .file_lock import atomic_write_text, cross_process_lock
        with cross_process_lock(p):
            kept: list[str] = []
            with open(p, encoding="utf-8") as f:
                for raw in f:
                    try:
                        d = json.loads(raw)
                    except json.JSONDecodeError:
                        kept.append(raw)
                        continue
                    if d.get("channel") == channel and d.get("user_id") in targets:
                        removed += 1
                        continue
                    kept.append(raw)
            if removed:
                atomic_write_text(p, "".join(kept))
    except OSError as e:
        log.warning("user_notes: erase failed: %s", e)
        if strict:
            raise
        return 0
    return removed


def format_context(notes: list[str], *, shield: Any | None = None) -> str:
    """Render notes as a brief addendum (untrusted, self-reported data)."""
    if not notes:
        return ""
    safe: list[str] = []
    for note in notes:
        text = str(note or "")
        try:
            from .safety.secret_detector import redact as _redact
            text, _ = _redact(text)
        except Exception:  # pragma: no cover
            pass
        if shield is not None:
            try:
                verdict = shield.scan_input(text)
                if not getattr(verdict, "allowed", True):
                    continue
            except Exception:  # pragma: no cover
                pass
        safe.append(text[:_MAX_NOTE_LEN])
    if not safe:
        return ""
    lines = [
        "",
        "## Known preferences for this user (self-reported, untrusted)",
        "",
    ]
    lines += [f"- {s}" for s in safe]
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_PATH",
    "extract_preferences",
    "consolidate",
    "notes_for",
    "erase_notes",
    "format_context",
]
