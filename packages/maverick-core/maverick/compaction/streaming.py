"""Streaming (incremental) compaction.

Digest-style compaction re-summarizes the WHOLE prefix every time it runs —
O(history) summarizer input per compaction. This strategy instead maintains a
*running summary* plus a *cursor* per conversation, persisted to a small
sidecar (``data_dir("compaction_stream.json")``, atomic write, chmod 600).
The separate history feature cache never stores these summaries.
Each call folds only the turns the cursor hasn't seen yet:

    summary' = fold(summary, new_turns)        # O(new) per call

The fold goes through the injected ``llm`` seam (configured summarizer role
model) when available; without one it appends deterministic one-line digests
of the new turns, so the strategy is fully offline-capable. A shrunk or
unrecognised turn list (the caller restarted the conversation) resets the
cursor and refolds from scratch rather than guessing.

API: :meth:`StreamingCompactor.fold` (incremental call-per-batch),
:meth:`StreamingCompactor.folder` (coroutine: ``send()`` new turns, receive
the running summary), and :func:`compact_streaming` (message-list strategy
entry used by ``compaction_strategies``).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import time
from collections.abc import Generator
from pathlib import Path

from ..context_compactor import _message_text
from ..file_lock import _retry_permission_error, atomic_read_text
from ..llm import model_for_role
from ..paths import data_dir
from . import KEEP_RECENT_TURNS, digest_cutoff
from .requests import request, run_async, run_sync

log = logging.getLogger(__name__)

SIDECAR_BASENAME = "compaction_stream.json"

# The sidecar holds one entry per conversation_id; without a reaper it grows
# one row per conversation forever on a long-running ``maverick serve``. Each
# entry carries a ``last`` write timestamp, so we prune entries untouched for
# longer than this TTL on every save. 0 disables pruning (durable forever).
_DEFAULT_TTL_DAYS = 30.0


def _ttl_seconds() -> float:
    """Stale-entry TTL for the sidecar, from ``[context]
    compaction_stream_ttl_days`` (default 30; <=0 disables pruning)."""
    try:
        from ..config import load_config

        raw = load_config().get("context", {}).get(
            "compaction_stream_ttl_days", _DEFAULT_TTL_DAYS)
        days = float(raw)
    except Exception:
        days = _DEFAULT_TTL_DAYS
    return days * 86400.0 if days > 0 else 0.0

_FOLD_SYSTEM = (
    "You maintain a running summary of an agent conversation. Merge the new "
    "turns into the summary: keep every fact, file path, decision and error "
    "already there, add the new ones, drop chit-chat. Return only the updated "
    "summary."
)
_FOLD_MAX_TOKENS = 768
# Heuristic (no-llm) fold bounds, so the running summary stays a summary.
_LINE_CHARS = 160
_MAX_SUMMARY_LINES = 200


def _sidecar_path() -> Path:
    return data_dir(SIDECAR_BASENAME)


# On Windows a reader that still has sidecar.json open (a concurrent fold's load)
# makes the rename fail with PermissionError until that reader closes it, so the
# save is retried briefly instead of being dropped. Elsewhere a PermissionError
# is a real failure and is reported at once.
_REPLACE_RETRY_SECONDS = 5.0 if os.name == "nt" else 0.0


def _turn_line(turn: dict) -> str:
    text = " ".join(_message_text(turn).split())
    if len(text) > _LINE_CHARS:
        text = text[:_LINE_CHARS].rstrip() + "..."
    return f"{turn.get('role', '?')}: {text}"


def _turns_fingerprint(turns: list[dict]) -> str:
    """Stable digest of the exact folded prefix stored in the sidecar."""
    blob = json.dumps(turns, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()


class StreamingCompactor:
    """Per-conversation running summary + cursor, persisted across calls."""

    def __init__(
        self, llm=None, *, path: Path | None = None, clock=None, budget=None,
        ttl_seconds: float | None = None,
    ):
        self.llm = llm
        self.budget = budget
        self.path = path if path is not None else _sidecar_path()
        self._clock = clock if clock is not None else time.time
        self.ttl_seconds = _ttl_seconds() if ttl_seconds is None else float(ttl_seconds)

    # ---- sidecar I/O (fail-safe, atomic, 0600) ----

    def _load(self, *, strict: bool = False) -> dict:
        try:
            raw = json.loads(atomic_read_text(self.path))
            return raw if isinstance(raw, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            if strict and isinstance(e, OSError):
                raise
            log.warning("compaction stream sidecar: cannot read %s: %s", self.path, e)
            return {}

    def _reload_under_lock(self) -> dict | None:
        """The sidecar as it is now, read while the cross-process lock is held.

        Returns None when it cannot be read. Saving then would replace every
        other conversation's state with this one's, so the caller keeps what is
        stored instead.
        """
        try:
            return self._load(strict=True)
        except OSError as e:
            log.warning("compaction stream sidecar: cannot reload %s, keeping stored state: %s",
                        self.path, e)
            return None

    def _prune_stale(self, data: dict) -> dict:
        """Drop entries untouched for longer than the TTL (one per stale
        conversation), bounding the sidecar on a long-running deployment.
        Entries missing/with an unreadable ``last`` are kept (fail-safe)."""
        if not self.ttl_seconds:
            return data
        cutoff = self._clock() - self.ttl_seconds
        kept = {}
        for cid, st in data.items():
            try:
                last = float(st.get("last")) if isinstance(st, dict) else None
            except (TypeError, ValueError):
                last = None
            if last is None or last >= cutoff:
                kept[cid] = st
        return kept

    def _save(self, data: dict) -> None:
        data = self._prune_stale(data)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                dir=str(self.path.parent), prefix=".stream-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                os.chmod(tmp, 0o600)
                _retry_permission_error(lambda: os.replace(tmp, self.path),
                                        retry_seconds=_REPLACE_RETRY_SECONDS)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError as e:
            log.warning("compaction stream sidecar: cannot write %s: %s", self.path, e)

    def _state_entry(self, conversation_id: str) -> tuple[int, str, str]:
        """The persisted ``(cursor, summary, fingerprint)`` for a conversation."""
        return self._decode_state(self._load().get(conversation_id))

    @staticmethod
    def _decode_state(st) -> tuple[int, str, str]:
        if not isinstance(st, dict):
            return 0, "", ""
        try:
            cursor = max(int(st.get("cursor", 0)), 0)
        except (TypeError, ValueError):
            cursor = 0
        fingerprint = st.get("fingerprint", "")
        if not isinstance(fingerprint, str):
            fingerprint = ""
        return cursor, str(st.get("summary", "") or ""), fingerprint

    def state(self, conversation_id: str) -> tuple[int, str]:
        """The persisted ``(cursor, summary)`` for a conversation."""
        cursor, summary, _fingerprint = self._state_entry(conversation_id)
        return cursor, summary

    def _cplock(self):
        # Cross-process lock around the sidecar's load-modify-save. The sidecar
        # holds every conversation's state in one dict, so without it two
        # concurrent folds on DIFFERENT conversations both load the dict and the
        # second save drops the other's entry. The lock wraps only the final
        # reload-merge-save (never the LLM fold), re-reading fresh under it.
        from ..file_lock import cross_process_lock
        return cross_process_lock(self.path)

    def reset(self, conversation_id: str) -> None:
        with self._cplock():
            data = self._load()
            if conversation_id in data:
                del data[conversation_id]
                self._save(data)

    # ---- folding ----

    def _fold_once(self, summary: str, new_turns: list[dict]) -> str:
        """Synchronous entry for the shared compaction algorithm."""
        return run_sync(self._fold_once_steps(summary, new_turns))

    def _fold_once_steps(self, summary: str, new_turns: list[dict]):
        rendered = "\n".join(_turn_line(t) for t in new_turns)
        if self.llm is not None:
            try:
                resp = yield request(self.llm,
                    system=_FOLD_SYSTEM,
                    messages=[{
                        "role": "user",
                        "content": (
                            f"<summary>\n{summary}\n</summary>\n"
                            f"<new-turns>\n{rendered}\n</new-turns>"
                        ),
                    }],
                    max_tokens=_FOLD_MAX_TOKENS,
                    model=model_for_role("summarizer"),
                    budget=self.budget,
                )
                folded = (getattr(resp, "text", "") or "").strip()
                if folded:
                    return folded
            except Exception as e:
                log.warning("streaming compaction fold failed (%s); heuristic fold", e)
        lines = [ln for ln in summary.splitlines() if ln.strip()]
        lines.extend(_turn_line(t) for t in new_turns)
        return "\n".join(lines[-_MAX_SUMMARY_LINES:])

    def fold(self, conversation_id: str, turns: list[dict]) -> str:
        """Synchronous entry for the shared compaction algorithm."""
        return run_sync(self._fold_steps(conversation_id, turns))

    async def fold_async(self, conversation_id: str, turns: list[dict]) -> str:
        """Native async entry; cancellation never falls back to sync I/O."""
        return await run_async(self._fold_steps(conversation_id, turns))

    def _fold_steps(self, conversation_id: str, turns: list[dict], seed: str | None = None):
        """Fold the turns the cursor hasn't seen into the running summary.

        ``turns`` is the conversation prefix so far (oldest first); only
        ``turns[cursor:]`` are summarized. Returns the updated summary and
        persists ``(cursor=len(turns), summary)``. A ``turns`` list shorter
        than the cursor means the conversation was rewound: state resets and
        everything is refolded. ``seed`` is the text of this strategy's own
        earlier summary when ``turns[0]`` is that summary message; a reset then
        continues from it instead of folding it as one clipped turn.
        """
        initial_state = self._load().get(conversation_id)
        cursor, summary, fingerprint = self._decode_state(initial_state)
        prefix_matches = (
            cursor == 0
            or (fingerprint and fingerprint == _turns_fingerprint(turns[:cursor]))
        )
        if cursor > len(turns) or not prefix_matches:
            cursor, summary = 0, ""
        if seed is not None and cursor == 0:
            cursor, summary = 1, seed
        new_turns = turns[cursor:]
        if new_turns:
            summary = yield from self._fold_once_steps(summary, new_turns)
        # Reload-merge-save under the cross-process lock (the LLM fold above ran
        # outside it) so a concurrent fold on another conversation isn't lost.
        with self._cplock():
            data = self._reload_under_lock()
            if data is None:
                return summary
            if data.get(conversation_id) != initial_state:
                # Another fold/reset won while native async I/O yielded. This
                # caller's result is valid for its own source, but it cannot
                # overwrite the newer sidecar cursor or resurrect reset state.
                return summary
            data[conversation_id] = {
                "cursor": len(turns),
                "summary": summary,
                "fingerprint": _turns_fingerprint(turns),
                "last": self._clock(),
            }
            self._save(data)
        return summary

    def folder(self, conversation_id: str) -> Generator[str, list[dict], None]:
        """Coroutine API: prime with ``next()``, then ``send(new_turns)``.

        Each ``send`` folds the sent turns (they are appended after the
        cursor, i.e. callers send only NEW turns) and yields the updated
        running summary.
        """
        cursor, summary = self.state(conversation_id)
        # The fingerprint must digest the FULL folded prefix (turns[:cursor]) so
        # the non-coroutine fold() path can validate it. We only have the full
        # prefix here when this coroutine folded from the very start; if it took
        # over an existing conversation (cursor > 0) we never see the prior
        # turns, so we must NOT write a partial fingerprint that misrepresents
        # the prefix -- store "" instead (fold() then safely refolds).
        folded_from_start = cursor == 0
        folded_turns: list[dict] = []
        while True:
            sent = yield summary
            if not sent:
                continue
            cursor += len(sent)
            folded_turns.extend(sent)
            summary = self._fold_once(summary, sent)
            with self._cplock():
                data = self._reload_under_lock()
                if data is None:
                    continue
                data[conversation_id] = {
                    "cursor": cursor,
                    "summary": summary,
                    "fingerprint": (_turns_fingerprint(folded_turns)
                                    if folded_from_start else ""),
                    "last": self._clock(),
                }
                self._save(data)


_SUMMARY_RE = re.compile(
    r'<stream-summary turns="(\d+)">\n(.*)\n</stream-summary>', re.DOTALL)


def _own_summary(msg: dict) -> tuple[int, str] | None:
    """``(turns, summary)`` when ``msg`` is a summary this strategy produced.

    Inside the agent loop the history is replaced by this strategy's output,
    so the next call sees ``[brief, <stream-summary>, ...]``. Treating that
    summary as one ordinary turn clipped it to 160 characters and lost every
    earlier fact on each turn.
    """
    if not isinstance(msg, dict) or msg.get("role") != "user":
        return None
    content = msg.get("content")
    if not isinstance(content, str):
        return None
    m = _SUMMARY_RE.fullmatch(content)
    return (int(m.group(1)), m.group(2)) if m else None


def _default_key(messages: list[dict]) -> str:
    """Stable conversation key: hash of the first message (preserved verbatim
    by every compaction pass, so it identifies the episode across calls)."""
    first = messages[0] if messages else {}
    blob = json.dumps(first, sort_keys=True, default=str)
    return "msg:" + hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:16]


def compact_streaming(
    messages: list[dict], *,
    conversation_id: str | None = None,
    keep_recent: int = KEEP_RECENT_TURNS,
    llm=None,
    path: Path | None = None,
    budget=None,
) -> list[dict]:
    """Synchronous entry for the shared compaction algorithm."""
    return run_sync(_compact_streaming_steps(messages, conversation_id=conversation_id, keep_recent=keep_recent, llm=llm, path=path, budget=budget))

async def compact_streaming_async(
    messages: list[dict], *,
    conversation_id: str | None = None,
    keep_recent: int = KEEP_RECENT_TURNS,
    llm=None,
    path: Path | None = None,
    budget=None,
) -> list[dict]:
    """Native async entry; cancellation never falls back to sync I/O."""
    return await run_async(_compact_streaming_steps(messages, conversation_id=conversation_id, keep_recent=keep_recent, llm=llm, path=path, budget=budget))

def _compact_streaming_steps(
    messages: list[dict], *,
    conversation_id: str | None = None,
    keep_recent: int = KEEP_RECENT_TURNS,
    llm=None,
    path: Path | None = None,
    budget=None,
):
    """Strategy entry: replace the old middle with the running summary.

    The first message and the last ``keep_recent`` pass through verbatim;
    ``messages[1:cutoff]`` are folded incrementally (only turns beyond the
    persisted cursor cost a fold).
    """
    if len(messages) <= keep_recent + 1:
        return list(messages)
    cutoff = digest_cutoff(messages, keep_recent)
    if cutoff <= 1:
        return list(messages)
    key = conversation_id or _default_key(messages)
    compactor = StreamingCompactor(llm=llm, path=path, budget=budget)
    prior = _own_summary(messages[1])
    seed = prior[1] if prior is not None else None
    summary = yield from compactor._fold_steps(key, messages[1:cutoff], seed=seed)
    turns = cutoff - 1 if prior is None else prior[0] + cutoff - 2
    summary_msg = {
        "role": "user",
        "content": (
            f'<stream-summary turns="{turns}">\n{summary}\n</stream-summary>'
        ),
    }
    return [messages[0], summary_msg, *messages[cutoff:]]


__all__ = ["SIDECAR_BASENAME", "StreamingCompactor", "compact_streaming"]
