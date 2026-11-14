"""Long-context compaction for the agent's running message list.

100k-token persistent episodes will choke and pay full price every
turn. The compaction policy:

* **Drop**: raw tool output blocks > MAX_TOOL_OUTPUT_BYTES (default
  2 KiB) older than KEEP_RECENT_TURNS turns; keep a one-line digest.
* **Ceiling**: when the whole window still exceeds MAX_TOTAL_BYTES
  (default 200 KB chars), the same shrink extends into the recent
  window, oldest first, sparing the brief and the newest message.
* **Summarize**: every DIGEST_EVERY turns, fold prior turns into one
  ``<digest>`` block prepended to the messages list; raw turns are
  removed.
* **Vector-index**: episode digests get embedded so RAG can
  recover deep history. See ``DigestIndex`` / ``recall_relevant_digests``
  below -- an opt-in, fail-open retrieval path. The embedder is injected
  (``Embedder`` protocol); the default one lazily wraps the repo's
  optional ``fastembed`` backend and is absent unless that lib is
  installed. ``compact_messages`` behavior is unchanged when no
  embedder/index is supplied.

The "drop vs keep" boundary is hardcoded; it is not learned from outcome
reward.

This module is pure-function: input is the current ``messages`` list
(Anthropic content-block format) plus a turn counter; output is the
new messages list. No I/O, no LLM calls (digest text uses a cheap
heuristic summary; the LLM-summarize variant is a follow-up).
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


# Tunables.
def _env_int(name: str, default: int, key: str = "") -> int:
    # A non-numeric env value falls back to the default instead of raising
    # ValueError at import and killing the compaction path.
    # With ``key`` the value may also come from ``[compaction] <key>`` (read
    # once at startup); the environment still wins.
    if key:
        from ..env_setting import env_or_config_int

        return env_or_config_int(name, "compaction", key, default)
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


MAX_TOOL_OUTPUT_BYTES = _env_int("MAVERICK_COMPACT_MAX_TOOL_BYTES", 2 * 1024, "max_tool_bytes")
# At least 1, as LearnedRunState clamps it: 0 also shrank the newest message,
# and a negative value pushed the cutoff past the end so nothing was shrunk.
KEEP_RECENT_TURNS = max(1, _env_int("MAVERICK_COMPACT_KEEP_RECENT", 4, "keep_recent"))
DIGEST_EVERY = _env_int("MAVERICK_COMPACT_DIGEST_EVERY", 10, "digest_every")
# Ceiling on the WHOLE live window. The per-block pass above only trims
# content behind keep_recent, so a few results at the per-result cap
# (agent._MAX_TOOL_RESULT_BYTES, default 100 KB) can still ride inside the
# recent window at ~100k tokens total. Over this ceiling the shrink extends
# into the recent window, oldest first — sparing the first message (the
# brief) and the last (the freshest results the model must act on). ~200 KB
# chars (~50k tokens). 0 disables.
MAX_TOTAL_BYTES = _env_int("MAVERICK_COMPACT_MAX_TOTAL_BYTES", 200_000, "max_total_bytes")


def _block_size(block: dict) -> int:
    """Rough byte size of a content block."""
    if isinstance(block, dict):
        if block.get("type") == "text":
            return len(block.get("text", "") or "")
        if block.get("type") == "tool_result":
            content = block.get("content", "")
            if isinstance(content, list):
                return sum(_block_size(c) for c in content if isinstance(c, dict))
            return len(str(content))
        if block.get("type") == "tool_use":
            # Approximate: str() is ~10x cheaper than json.dumps and this
            # runs for every block of the whole history on every turn (the
            # total-ceiling pass); sizing only needs the right magnitude.
            return len(str(block.get("input", {})))
        if block.get("type") == "image":
            src = block.get("source", {})
            return len(src.get("data", "")) if isinstance(src, dict) else 0
    return 0


_LOCATOR_KEYS = ("path", "url", "file", "filename", "target", "uri", "page")


def _source_locator(tool_use: dict | None) -> tuple[str, str]:
    """Best-effort ``(tool_name, locator)`` for the tool_use that produced a
    result, so a shrunk tool_result keeps the *identity* of what it read (the
    file path / url) instead of an opaque "output dropped". ``('', '')`` when
    unknown."""
    if not isinstance(tool_use, dict):
        return "", ""
    name = str(tool_use.get("name", "") or "")
    inp = tool_use.get("input") or {}
    locator = ""
    if isinstance(inp, dict):
        for k in _LOCATOR_KEYS:
            v = inp.get(k)
            if isinstance(v, str) and v.strip():
                locator = v.strip()
                break
    return name, locator


def _canonical_tool_result_text(text: str) -> str:
    """Return the stable tool payload for hashing.

    Agent._run_tool stores model-facing results inside a ``<tool_output ...>``
    frame with a fresh random nonce per call. Structural compaction references
    should identify the underlying tool output, not that per-call frame, so
    strip the frame when it is present. Any loop-guard guidance appended after
    the closing frame is also excluded because it is not tool output.
    """
    if not text.startswith("<tool_output "):
        return text
    nl = text.find("\n")
    if nl == -1:
        return text
    inner = text[nl + 1:]
    close = inner.rfind("\n</tool_output ")
    if close == -1:
        return text
    return inner[:close]


def _framed_tool_result_preview(preview: str, nonce: str) -> str:
    """Wrap compacted tool-output preview bytes so they remain data.

    Tool results can contain attacker-controlled text.  Agent._run_tool uses a
    nonce-delimited frame for full outputs; compacted previews need the same
    kind of boundary so raw preview bytes do not re-enter context as
    authoritative instructions.  The full canonical SHA is deterministic for
    idempotence and long enough that a payload cannot practically forge the
    matching close delimiter in its first preview bytes.
    """
    return (
        f"<tool_output_preview id={nonce}>\n"
        f"{preview}\n"
        f"</tool_output_preview {nonce}>"
    )


def frame_digest_body(body: str) -> str:
    """Wrap a compaction digest body in the agent loop's tool-output frame.

    Learned, graph and streaming digests are built from earlier turns,
    including ``tool_result`` text an attacker may control, and re-enter the
    history as a ``user`` message. Agent._run_tool marks tool output as data
    with ``<tool_output tool=... id=<nonce>>`` and a matching close; the
    digest body gets the same frame, so injected text cannot pass for the
    user's own words. As in ``_framed_tool_result_preview``, the nonce is the
    body's full SHA-256: sync and async compaction stay byte-identical, and a
    body cannot contain the close delimiter that names its own hash.
    """
    import hashlib

    nonce = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
    return (
        f"<tool_output tool='compaction_digest' id={nonce}>\n"
        f"{body}\n"
        f"</tool_output {nonce}>"
    )


def _shrink_tool_result(
    block: dict, max_bytes: int, source: tuple[str, str] | None = None
) -> dict:
    """Replace a large tool_result with a content-addressed structural reference.

    Rather than an opaque "full output dropped", the digest keeps a short preview
    plus a structural ref — the originating tool + locator (file path / url) and a
    ``sha256`` + byte size. So the agent retains *what* was read and can re-run the
    tool to retrieve the full output (and the hash lets it detect a change), which
    is far more useful than arbitrary truncated bytes for the common file-read /
    fetch case. Idempotent: a result already at/under ``max_bytes`` is returned
    unchanged, so a second compaction pass is a no-op.
    """
    if not isinstance(block, dict) or block.get("type") != "tool_result":
        return block
    content = block.get("content", "")
    if isinstance(content, list):
        # Anthropic supports content as a list of blocks; join + measure.
        text_parts = [
            c.get("text", "") if isinstance(c, dict) else str(c)
            for c in content
        ]
        joined = "\n".join(text_parts)
    else:
        joined = str(content)
    if len(joined) <= max_bytes:
        return block
    # Idempotence guard: a result already shrunk to a preview digest stays as
    # is, even though the digest text can exceed max_bytes (the preview frame +
    # truncation note have a fixed floor). Without this, a second compaction
    # pass re-shrinks the digest, nesting another <tool_output_preview> frame
    # and re-hashing on every turn — defeating both idempotence and the
    # content-addressed ref the digest is supposed to carry.
    if joined.startswith("<tool_output_preview "):
        return block
    canonical = _canonical_tool_result_text(joined)
    import hashlib
    full_sha = hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()
    sha = full_sha[:12]
    name, locator = source or ("", "")
    if name and locator:
        src = f"{name}({locator}) "
    elif name:
        src = f"{name} "
    else:
        src = ""
    preview = _framed_tool_result_preview(canonical[:160].rstrip(), full_sha)
    digest = (
        preview
        + f" ... [{src}output {len(canonical)}B truncated, sha256:{sha} — dropped from"
        " context; re-run the tool to retrieve the full output]"
    )
    new_block = dict(block)
    new_block["content"] = digest
    return new_block


_TEXT_TRUNC_RE = re.compile(r" \.\.\. \[\d+B truncated to \d+B\]$")
_STR_TRUNC_RE = re.compile(r" \.\.\. \[\d+B truncated\]$")


def _shrink_text_block(block: dict, max_bytes: int) -> dict:
    """Hint-and-truncate large 'text' blocks the agent emitted earlier."""
    if not isinstance(block, dict) or block.get("type") != "text":
        return block
    text = block.get("text", "") or ""
    if len(text) <= max_bytes:
        return block
    # Idempotence guard: an already-truncated block carries the truncation
    # note as its suffix and can still exceed max_bytes (the note itself has a
    # floor). Re-truncating it would churn the note's byte count every pass —
    # a second compaction must be a no-op. Leave it as is.
    if _TEXT_TRUNC_RE.search(text):
        return block
    new_block = dict(block)
    new_block["text"] = (
        text[:max_bytes].rstrip()
        + f" ... [{len(text)}B truncated to {max_bytes}B]"
    )
    return new_block


def _message_size(msg: dict) -> int:
    """Rough char size of one message's content."""
    content = msg.get("content")
    if isinstance(content, str):
        return len(content)
    if isinstance(content, list):
        return sum(_block_size(b) for b in content if isinstance(b, dict))
    return 0


def _shrink_message(
    msg: dict, max_tool_bytes: int, tool_use_by_id: dict[str, dict]
) -> dict:
    """One message through the per-block shrink (tool_result digest + text
    truncate). Returns the original object when nothing changed, so callers
    can cheaply detect a no-op."""
    content = msg.get("content")
    if isinstance(content, list):
        new_content = []
        changed = False
        for blk in content:
            if isinstance(blk, dict) and blk.get("type") == "tool_result":
                source = _source_locator(tool_use_by_id.get(blk.get("tool_use_id")))
                new_blk = _shrink_tool_result(blk, max_tool_bytes, source)
            elif isinstance(blk, dict) and blk.get("type") == "text":
                new_blk = _shrink_text_block(blk, max_tool_bytes)
            else:
                new_blk = blk
            changed = changed or new_blk is not blk
            new_content.append(new_blk)
        if not changed:
            return msg
        new_msg = dict(msg)
        new_msg["content"] = new_content
        return new_msg
    if (isinstance(content, str) and len(content) > max_tool_bytes
            and not _STR_TRUNC_RE.search(content)):
        # The trailing guard keeps a second pass a no-op: an already-
        # truncated string still exceeds max_tool_bytes (its note has a
        # floor) and would otherwise be re-truncated, churning the byte
        # count on every compaction.
        new_msg = dict(msg)
        new_msg["content"] = (
            content[:max_tool_bytes].rstrip()
            + f" ... [{len(content)}B truncated]"
        )
        return new_msg
    return msg


def excerpt(text: str, cap: int, note: str = "truncated") -> str:
    """Head of ``text`` with the canonical `` ... [<n>B <note>]`` marker.

    The one bounded-injection primitive for prompt-bound previews (blackboard
    renders, swarm results, brief facts, finding posts) so the marker format
    can't drift per site. The compaction shrink helpers above keep their own
    formats — those are frozen by the idempotence regexes."""
    if not isinstance(text, str):  # defensive: a bad post must not break
        text = "" if text is None else str(text)  # every brief that renders it
    if len(text) <= cap:
        return text
    return text[:cap].rstrip() + f" ... [{len(text)}B {note}]"


def compact_messages(
    messages: list[dict],
    *,
    keep_recent: int = KEEP_RECENT_TURNS,
    max_tool_bytes: int = MAX_TOOL_OUTPUT_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> list[dict]:
    """Return a compacted copy of ``messages``.

    Behavior:
    1. The last ``keep_recent`` messages pass through unchanged.
    2. Older messages have any tool_result block > ``max_tool_bytes``
       replaced with a digest, and any text block > ``max_tool_bytes``
       truncated.
    3. The first message (the user brief) is always preserved verbatim
       so the agent never loses the goal.
    4. If the whole window still exceeds ``max_total_bytes``, the same
       shrink extends INTO the recent window, oldest first, sparing the
       first and the last message. Messages are never dropped, so
       tool_use/tool_result pairing stays intact. A soft ceiling: with
       everything shrinkable already shrunk the window can still exceed
       it, but the dominant payloads (raw tool output) are bounded.
       ``max_total_bytes <= 0`` disables the overflow pass.
    """
    # Index tool_use blocks by id so a shrunk tool_result can name its source
    # (the tool + the file path / url it read) in the structural reference.
    tool_use_by_id: dict[str, dict] = {}
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, list):
            for blk in content:
                if isinstance(blk, dict) and blk.get("type") == "tool_use":
                    bid = blk.get("id")
                    if isinstance(bid, str):
                        tool_use_by_id[bid] = blk

    if len(messages) <= keep_recent + 1:
        # Everything is inside the recent window; only the ceiling below can
        # shrink anything (a short window can still be huge byte-wise).
        out = list(messages)
    else:
        out = []
        cutoff = len(messages) - keep_recent
        for i, msg in enumerate(messages):
            if i == 0 or i >= cutoff:
                out.append(msg)
                continue
            out.append(_shrink_message(msg, max_tool_bytes, tool_use_by_id))

    if max_total_bytes <= 0:
        return out
    total = sum(_message_size(m) for m in out)
    if total <= max_total_bytes:
        return out
    # Overflow pass: the recent window itself is over the ceiling (a few
    # results at the per-result cap add up fast). Shrink oldest-first until
    # under; never touch the brief (0) or the last message (the freshest
    # tool results, which the model needs whole to act).
    for i in range(1, len(out) - 1):
        if total <= max_total_bytes:
            break
        before = _message_size(out[i])
        shrunk = _shrink_message(out[i], max_tool_bytes, tool_use_by_id)
        if shrunk is not out[i]:
            out[i] = shrunk
            total += _message_size(shrunk) - before
    return out


def digest_cutoff(messages: list[dict], keep_recent: int) -> int:
    """Expand the preserved tail so a digest cannot orphan a tool exchange.

    Keep incomplete calls and any exchange crossing the digest/tail boundary.
    An exchange involving the preserved first message prevents middle removal.
    Supports the internal block shape and OpenAI-style tool call messages.
    """
    cutoff = max(1, len(messages) - max(keep_recent, 0))
    positions: dict[str, list[int]] = {}
    calls: set[str] = set()
    results: set[str] = set()
    for index, message in enumerate(messages):
        content = message.get("content")
        blocks = content if isinstance(content, list) else []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            key = block.get("id") if kind == "tool_use" else block.get("tool_use_id")
            if kind in {"tool_use", "tool_result"} and isinstance(key, str) and key:
                positions.setdefault(key, []).append(index)
                (calls if kind == "tool_use" else results).add(key)
        for call in message.get("tool_calls") or []:
            key = call.get("id") if isinstance(call, dict) else None
            if isinstance(key, str) and key:
                positions.setdefault(key, []).append(index)
                calls.add(key)
        key = message.get("tool_call_id")
        if message.get("role") == "tool" and isinstance(key, str) and key:
            positions.setdefault(key, []).append(index)
            results.add(key)
    while True:
        old_cutoff = cutoff
        for key, indices in positions.items():
            first, last = min(indices), max(indices)
            if first == 0 and 0 < last < cutoff:
                return 1
            if first < cutoff and (last >= cutoff or key not in calls or key not in results):
                cutoff = max(1, first)
        if cutoff == old_cutoff:
            return cutoff


def should_digest(step: int, every: int = DIGEST_EVERY) -> bool:
    """Returns True when the agent should fold prior turns into a digest.

    Called at the top of every loop iteration; the agent uses this to
    decide whether to call the LLM-summarizer for an episode digest
    (separate code path, since it spends budget).
    """
    return step > 0 and step % every == 0


def make_heuristic_digest(messages: list[dict]) -> str:
    """Build a structural digest of prior turns without calling an LLM.

    Used when budget is too tight to spend a summarizer call. The
    digest preserves: count of turns, tool names invoked + counts,
    and the original user brief. Keeps the agent oriented even after
    aggressive truncation.
    """
    if not messages:
        return ""
    n = len(messages)
    tool_counts: dict[str, int] = {}
    first_user = ""
    for msg in messages:
        content = msg.get("content")
        if msg.get("role") == "user" and not first_user:
            if isinstance(content, str):
                first_user = content[:400]
            elif isinstance(content, list):
                for blk in content:
                    if isinstance(blk, dict) and blk.get("type") == "text":
                        first_user = (blk.get("text", "") or "")[:400]
                        break
        if isinstance(content, list):
            for blk in content:
                if isinstance(blk, dict) and blk.get("type") == "tool_use":
                    name = blk.get("name", "?")
                    tool_counts[name] = tool_counts.get(name, 0) + 1
    tools_summary = ", ".join(
        f"{n}({c})" for n, c in sorted(tool_counts.items(), key=lambda kv: -kv[1])
    ) or "(no tools used)"
    return (
        f"<digest>\n"
        f"original brief: {first_user}\n"
        f"prior turns: {n}\n"
        f"tools invoked: {tools_summary}\n"
        f"</digest>"
    )


# --------------------------------------------------------------------------
# Vector-index (RAG) path for episode digests.
#
# Opt-in and fail-open: nothing here runs unless a caller builds a
# ``DigestIndex`` and supplies an ``Embedder``. ``compact_messages`` is
# untouched. Embedding the deep history lets a long run recall digests of
# turns that compaction has already dropped from the live context.
# --------------------------------------------------------------------------


@runtime_checkable
class Embedder(Protocol):
    """Injection seam for turning text into vectors.

    Tests pass a deterministic fake; production passes ``default_embedder()``
    (fastembed-backed) or any object with a matching ``embed``.
    """

    def embed(self, texts: list[str]) -> list[list[float]]:
        ...


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity. Returns 0.0 for mismatched/empty/zero vectors."""
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


@dataclass
class DigestEntry:
    text: str
    vector: list[float]
    turn: int


@dataclass
class DigestIndex:
    """In-memory store of embedded episode digests for similarity recall."""

    entries: list[DigestEntry] = field(default_factory=list)

    def add(self, text: str, turn: int, embedder: Embedder) -> None:
        """Embed and store one digest. Fail-open: skips on embed failure."""
        vectors = embedder.embed([text])
        if not vectors:
            return
        self.entries.append(DigestEntry(text=text, vector=vectors[0], turn=turn))

    def add_many(
        self, items: list[tuple[str, int]], embedder: Embedder
    ) -> None:
        """Embed and store ``(text, turn)`` pairs in one batched call."""
        if not items:
            return
        vectors = embedder.embed([t for t, _ in items])
        if not vectors:
            return
        for (text, turn), vec in zip(items, vectors, strict=False):
            self.entries.append(DigestEntry(text=text, vector=vec, turn=turn))

    def retrieve(
        self, query: str, embedder: Embedder, k: int = 3
    ) -> list[DigestEntry]:
        """Return the top-``k`` digests most similar to ``query``."""
        if not self.entries or k <= 0:
            return []
        query_vecs = embedder.embed([query])
        if not query_vecs:
            return []
        query_vec = query_vecs[0]
        scored = [(_cosine(query_vec, e.vector), e) for e in self.entries]
        scored.sort(key=lambda se: -se[0])
        return [e for _, e in scored[:k]]


class _FastembedEmbedder:
    """Default embedder backed by the repo's optional fastembed util."""

    def embed(self, texts: list[str]) -> list[list[float]]:
        from ..skill.embeddings import embed as _embed
        return _embed(texts) or []


def default_embedder() -> Embedder | None:
    """Construct the fastembed-backed embedder, or ``None`` if unavailable.

    Fail-open: when ``fastembed`` isn't installed, callers must inject their
    own ``Embedder``. Never raises.
    """
    try:
        from ..skill.embeddings import _have_fastembed
    except Exception:  # pragma: no cover - import guard
        return None
    if not _have_fastembed():
        return None
    return _FastembedEmbedder()


def recall_relevant_digests(
    query: str, index: DigestIndex, embedder: Embedder, k: int = 3
) -> str:
    """Format the top-``k`` recalled digests as a ``<recall>`` block.

    Returns ``""`` when nothing is retrieved, so an agent loop can safely
    prepend the result unconditionally. Wiring into the live loop is tracked
    separately; this is the tested hook.
    """
    hits = index.retrieve(query, embedder, k=k)
    if not hits:
        return ""
    body = "\n".join(f"[turn {e.turn}] {e.text}" for e in hits)
    return f"<recall>\n{body}\n</recall>"
