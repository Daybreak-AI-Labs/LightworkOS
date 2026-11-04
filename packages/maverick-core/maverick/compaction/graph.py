"""Graph-structured compaction.

Instead of prose, compact the old middle of a trajectory into a small
entity-relation graph: subject-relation-object triples plus a rendered text
digest the model can read back. Extraction reuses the deterministic
relation-verb heuristic from ``maverick.tools.knowledge_graph`` (no model
needed), and when an ``llm`` seam is injected it additionally asks the
configured summarizer role model to emit ``S | R | O`` lines, which the same
heuristic parser folds in — so the llm can only ADD triples, never change the
deterministic baseline.

The compacted message looks like::

    <graph-digest turns="12" entities="5" triples="6">
    parser service --depends_on--> redis
    deploy --requires--> green CI
    ...
    </graph-digest>

When no triples can be extracted the strategy declines and falls back to
``compact_messages`` rather than replacing history with an empty graph —
fail-open, like every compaction path.
"""
from __future__ import annotations

import logging

from ..context_compactor import _message_text
from ..llm import model_for_role
from . import KEEP_RECENT_TURNS, compact_messages, digest_cutoff
from .requests import request, run_async, run_sync

log = logging.getLogger(__name__)

MAX_TRIPLES = 40
_EXTRACT_SYSTEM = (
    "Extract the factual relationships from this agent trajectory as one "
    "'subject | relation | object' triple per line. Keep identifiers and "
    "paths verbatim. Output only triple lines."
)
_EXTRACT_MAX_TOKENS = 512
_MAX_EXTRACT_CHARS = 24_000


def _heuristic_triples(text: str) -> list[list[str]]:
    """Deterministic triples via the knowledge_graph relation-verb heuristic."""
    try:
        from ..tools.knowledge_graph import _extract
        return _extract(text)
    except Exception as e:  # pragma: no cover -- in-repo import never fails
        log.warning("graph compaction extractor unavailable (%s)", e)
        return []


def _llm_triples(text: str, llm, budget=None) -> list[list[str]]:
    """Synchronous entry for the shared compaction algorithm."""
    return run_sync(_llm_triples_steps(text, llm, budget))

def _llm_triples_steps(text: str, llm, budget=None):
    """Extra triples via the injected llm seam; [] on any failure."""
    if llm is None:
        return []
    try:
        resp = yield request(llm,
            system=_EXTRACT_SYSTEM,
            messages=[{"role": "user", "content": text}],
            max_tokens=_EXTRACT_MAX_TOKENS,
            model=model_for_role("summarizer"),
            budget=budget,
        )
        # The 'S | R | O' lines are exactly what the heuristic parser accepts.
        return _heuristic_triples(getattr(resp, "text", "") or "")
    except Exception as e:
        log.warning("graph compaction llm extract failed (%s); heuristic only", e)
        return []


def extract_triples(
    text: str, *, llm=None, budget=None, max_triples: int = MAX_TRIPLES,
) -> list[list[str]]:
    """Synchronous entry for the shared compaction algorithm."""
    return run_sync(_extract_triples_steps(text, llm=llm, budget=budget, max_triples=max_triples))

async def extract_triples_async(
    text: str, *, llm=None, budget=None, max_triples: int = MAX_TRIPLES,
) -> list[list[str]]:
    """Native async entry; cancellation never falls back to sync I/O."""
    return await run_async(_extract_triples_steps(text, llm=llm, budget=budget, max_triples=max_triples))

def _extract_triples_steps(
    text: str, *, llm=None, budget=None, max_triples: int = MAX_TRIPLES,
):
    """Deduped ``[subject, relation, object]`` triples from ``text``.

    Heuristic extraction always runs; llm-backed extraction (when a seam is
    given) appends. Order is deterministic: heuristic first, in source order.
    """
    out: list[list[str]] = []
    seen: set[tuple[str, str, str]] = set()
    for triple in _heuristic_triples(text) + (yield from _llm_triples_steps(text, llm, budget=budget)):
        if len(triple) != 3:
            continue
        key = (triple[0].lower(), triple[1].lower(), triple[2].lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(triple)
        if len(out) >= max_triples:
            break
    return out


def render_digest(triples: list[list[str]], *, turns: int) -> str:
    """Render triples as the ``<graph-digest>`` text block."""
    entities: list[str] = []
    seen: set[str] = set()
    for s, _r, o in triples:
        for node in (s, o):
            if node.lower() not in seen:
                seen.add(node.lower())
                entities.append(node)
    lines = [f"{s} --{r}--> {o}" for s, r, o in triples]
    return (
        f'<graph-digest turns="{turns}" entities="{len(entities)}" '
        f'triples="{len(triples)}">\n' + "\n".join(lines) + "\n</graph-digest>"
    )


def compact_graph(
    messages: list[dict], *,
    keep_recent: int = KEEP_RECENT_TURNS,
    llm=None,
    budget=None,
    max_triples: int = MAX_TRIPLES,
) -> list[dict]:
    """Synchronous entry for the shared compaction algorithm."""
    return run_sync(_compact_graph_steps(messages, keep_recent=keep_recent, llm=llm, budget=budget, max_triples=max_triples))

async def compact_graph_async(
    messages: list[dict], *,
    keep_recent: int = KEEP_RECENT_TURNS,
    llm=None,
    budget=None,
    max_triples: int = MAX_TRIPLES,
) -> list[dict]:
    """Native async entry; cancellation never falls back to sync I/O."""
    return await run_async(_compact_graph_steps(messages, keep_recent=keep_recent, llm=llm, budget=budget, max_triples=max_triples))

def _compact_graph_steps(
    messages: list[dict], *,
    keep_recent: int = KEEP_RECENT_TURNS,
    llm=None,
    budget=None,
    max_triples: int = MAX_TRIPLES,
):
    """Strategy entry: fold ``messages[1:-keep_recent]`` into a graph digest.

    The first message and the recent tail pass through verbatim (mirroring
    ``compact_messages``). When extraction yields nothing, falls back to
    ``compact_messages`` so history is never replaced by an empty graph.
    """
    if len(messages) <= keep_recent + 1:
        return list(messages)
    cutoff = digest_cutoff(messages, keep_recent)
    if cutoff <= 1:
        return list(messages)
    middle = messages[1:cutoff]
    # No role prefixes: a "user: " prefix would leak into triple subjects.
    text = "\n".join(_message_text(m) for m in middle)
    if len(text) > _MAX_EXTRACT_CHARS:
        text = text[-_MAX_EXTRACT_CHARS:]
    triples = yield from _extract_triples_steps(
        text, llm=llm, budget=budget, max_triples=max_triples)
    if not triples:
        return compact_messages(messages, keep_recent=keep_recent)
    digest_msg = {
        "role": "user",
        "content": render_digest(triples, turns=len(middle)),
    }
    return [messages[0], digest_msg, *messages[cutoff:]]


__all__ = ["MAX_TRIPLES", "extract_triples", "render_digest", "compact_graph"]
