"""Append-only shared workspace for a single run.

Specialists never talk to each other directly. They post observations,
findings, and artifacts to the blackboard. The orchestrator reads it to
decide what to do next.

The blackboard can mirror entries into ``world.goal_events`` so the
dashboard can stream live progress. Mirroring is opt-in via
``Blackboard.attach_world(world, goal_id)``; a blackboard with no world
attached stays in memory only.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Entry:
    ts: float
    agent: str
    kind: str  # plan | observation | finding | artifact | error | verify
    content: str
    meta: dict[str, Any]
    # Monotonic post sequence number (1-based); survives the oldest-entry trim
    # so a reader's cursor (see ``render_since``) never shifts under it.
    seq: int = 0


class Blackboard:
    _MODEL_DERIVED_KINDS = frozenset(
        {
            "artifact",
            "finding",
            "observation",
            "plan",
            "verify",
        }
    )
    _WITHHELD_CONTENT = (
        "[AI-generated run-event content withheld; the final "
        "evidence-ready result is available after completion]"
    )
    _REDACTION_UNAVAILABLE_CONTENT = (
        "[Run-event content withheld because secret redaction was unavailable]"
    )

    def __init__(self):
        self.entries: list[Entry] = []
        self._seq = 0
        self._world = None
        self._goal_id: int | None = None
        # Agent compartments: optional QuarantineRegistry. When attached, posts
        # by a sealed agent are withheld from render() so a poisoned finding
        # can't steer the rest of the swarm. None == disabled.
        self._quarantine = None
        # Optional replayable-trace writer (opt-in; see attach_trace).
        self._trace = None
        # Guards entries against a runner thread and the event loop touching
        # the same blackboard. (NOTE: this does not serialize same-thread
        # gather() coroutines against each other — the deeper swarm-shares-
        # one-connection issue is tracked as the async-DB-offload item.)
        self._lock = threading.Lock()

    def attach_world(self, world, goal_id: int) -> None:
        """Wire the blackboard to a WorldModel so posts are persisted as events."""
        self._world = world
        self._goal_id = goal_id

    def attach_trace(self, writer) -> None:
        """Mirror every post into a replayable JSONL trace (opt-in). ``writer``
        is a ``replay_trace.TraceWriter``; None detaches."""
        self._trace = writer

    def attach_quarantine(self, registry) -> None:
        """Wire a QuarantineRegistry so sealed agents' posts are withheld."""
        self._quarantine = registry

    def _is_sealed(self, agent: str) -> bool:
        q = self._quarantine
        if q is None:
            return False
        try:
            return q.is_sealed(agent)
        except Exception:  # pragma: no cover -- containment must never break reads
            return False

    # Hard cap on retained entries so a long run (or an agent posting in a
    # loop) can't grow this list without bound. Reads only ever take a
    # bounded tail / filtered subset, so dropping the oldest entries past the
    # cap is safe. Override via MAVERICK_BLACKBOARD_MAX_ENTRIES.
    _MAX_ENTRIES = max(100, int(os.environ.get("MAVERICK_BLACKBOARD_MAX_ENTRIES", "5000")))

    @classmethod
    def _is_model_derived_event(
        cls,
        kind: str,
        meta: dict[str, Any],
    ) -> bool:
        """Classify mirror provenance while keeping legacy callers safe."""

        explicit = meta.get("model_derived")
        if isinstance(explicit, bool):
            return explicit
        raw_provenance = meta.get("provenance")
        if isinstance(raw_provenance, Mapping):
            raw_provenance = (
                raw_provenance.get("source")
                or raw_provenance.get("kind")
                or raw_provenance.get("type")
                or ""
            )
        provenance = str(raw_provenance or "").strip().lower()
        if provenance in {"model", "model_derived", "llm"}:
            return True
        if provenance in {
            "capability",
            "compartment",
            "operator",
            "progress",
            "safety",
            "system",
        }:
            return False
        # Legacy model-bearing kinds default to withholding. Error, status,
        # denial, progress, and note events remain actionable after the normal
        # secret-redaction pass.
        return str(kind).strip().lower() in cls._MODEL_DERIVED_KINDS

    def post(self, agent: str, kind: str, content: str, **meta: Any) -> None:
        with self._lock:
            self._seq += 1
            self.entries.append(Entry(time.time(), agent, kind, content, meta, seq=self._seq))
            if len(self.entries) > self._MAX_ENTRIES:
                # Trim the oldest in one slice (amortised O(1) per post).
                del self.entries[: len(self.entries) - self._MAX_ENTRIES]
        # Redact secrets before any PERSISTED or DISPLAYED copy. The in-memory
        # `entries` above stay verbatim (the agents' shared working memory --
        # a value legitimately passed between siblings must survive), but the
        # mirror to world.goal_events (world.db on disk + the live dashboard
        # stream), the offline replay trace, and the external observation
        # channel must not leak a credential an agent reported -- otherwise a
        # secret would persist in cleartext to disk and to any dashboard viewer
        # even in a fully local deployment. Mirrors how the audit log redacts
        # its persisted record.
        mirror_content = content
        try:
            from .safety.secret_detector import redact as _redact
            mirror_content, _ = _redact(content)
        except Exception:
            # Persisted and live mirrors are security boundaries. If the
            # detector cannot load or execute, fail closed without disrupting
            # the agents' verbatim in-memory coordination record.
            mirror_content = self._REDACTION_UNAVAILABLE_CONTENT
        # The evidence gateway governs the final human-facing prose output in
        # the orchestrator.  Durable/live blackboard mirrors are also visible
        # through dashboard, SSE, WebSocket, gRPC, trace, and observation
        # surfaces, so they must not leak unreceipted model excerpts first.
        # In-memory content remains intact for agent coordination.
        try:
            from .ai_evidence import delivery as ai_evidence_gateway

            if (
                ai_evidence_gateway.enabled()
                and self._is_model_derived_event(kind, meta)
            ):
                mirror_content = self._WITHHELD_CONTENT
        except Exception:  # pragma: no cover -- an unknown gateway state withholds
            try:
                if self._is_model_derived_event(kind, meta):
                    mirror_content = self._WITHHELD_CONTENT
            except Exception:
                mirror_content = self._WITHHELD_CONTENT
        # Mirror to world.goal_events for live dashboard streaming. Best-effort:
        # if the world model write fails (e.g., disk full), the in-memory
        # blackboard still works for the agent loop.
        if self._world is not None and self._goal_id is not None:
            try:
                self._world.append_event(self._goal_id, agent, kind, mirror_content)
            except Exception:
                pass
        # Replayable trace (opt-in via MAVERICK_TRACE_DIR / [replay] record): one JSONL line per
        # post so a run can be reconstructed/replayed offline. Best-effort.
        tw = getattr(self, "_trace", None)
        if tw is not None:
            try:
                tw.record(kind, agent=agent, content=mirror_content)
            except Exception:  # pragma: no cover -- tracing never blocks the loop
                pass
        # Live observation channel (push): tee to any external observer watching
        # the swarm. No-op (a lock-free subscriber check) when nobody is
        # subscribed, so an unobserved run pays nothing. Best-effort.
        try:
            from .observation_channel import maybe_publish as _obs_publish
            _obs_publish(kind, agent, mirror_content)
        except Exception:  # pragma: no cover -- observation never blocks the loop
            pass

    def by_kind(self, kind: str) -> list[Entry]:
        with self._lock:
            snapshot = list(self.entries)
        # Withhold sealed agents' entries here too (not only in render): a sealed
        # agent's finding must not reach the swarm through a structured read.
        return [e for e in snapshot if e.kind == kind and not self._is_sealed(e.agent)]

    def by_agent(self, agent: str) -> list[Entry]:
        # Check sealed-ness AND read the entries atomically under the lock. With
        # the check outside the lock, a concurrent seal() could slip between it
        # and the read and leak a just-sealed agent's posts wholesale
        # (compartment Rung 1); a FastAPI threadpool caller makes the window
        # real. _is_sealed does not take this lock, so no deadlock.
        with self._lock:
            if self._is_sealed(agent):
                return []
            return [e for e in self.entries if e.agent == agent]

    def posters_since(self, cursor: int) -> set[str]:
        """Agents with posts after ``cursor`` (information-flow propagation:
        a reader is shown what they posted, so it absorbs their labels)."""
        with self._lock:
            return {e.agent for e in self.entries if e.seq > cursor}

    def cursor(self) -> int:
        """The sequence number of the latest post; feed it to ``render_since``."""
        with self._lock:
            return self._seq

    def render_since(
        self,
        cursor: int,
        *,
        exclude_agent: str | None = None,
        max_entries: int = 12,
    ) -> tuple[str, int]:
        """Entries posted after ``cursor`` by OTHER agents, rendered like
        :meth:`render`, plus the new cursor.

        Fan-out caps, quarantine seals, sibling findings and disagreement
        notes posted after an agent's first turn must still reach it, so
        callers keep a per-agent cursor and append this delta to each
        tool-running turn.
        Sealed agents' posts are withheld exactly as in ``render``; the
        caller's own posts (``exclude_agent``) are skipped since it wrote
        them; and the block is bounded to the newest ``max_entries`` entries
        (an omitted-count line notes any older ones) with each entry capped
        by ``MAVERICK_BB_RENDER_ENTRY_CHARS``.
        """
        with self._lock:
            snapshot = list(self.entries)
            latest = self._seq
        fresh = [
            e for e in snapshot
            if e.seq > cursor
            and e.agent != exclude_agent
            and not self._is_sealed(e.agent)
        ]
        if not fresh:
            return "", latest
        limit = max(1, int(max_entries))
        omitted = max(0, len(fresh) - limit)
        from .compaction import excerpt
        from .env_setting import env_or_config_int
        entry_cap = max(80, env_or_config_int(
            "MAVERICK_BB_RENDER_ENTRY_CHARS", "context", "blackboard_entry_chars", 800))
        lines = [
            f"[{e.agent}/{e.kind}] {excerpt(e.content, entry_cap)}"
            for e in fresh[-limit:]
        ]
        if omitted:
            lines.insert(0, f"({omitted} earlier new entr{'y' if omitted == 1 else 'ies'} omitted)")
        return "\n".join(lines), latest

    def render(self, max_entries: int = 50) -> str:
        with self._lock:
            snapshot = list(self.entries)
        # Withhold sealed agents' posts (compartment Rung 1): a quarantined
        # agent's findings must not steer the orchestrator or its siblings.
        visible = [e for e in snapshot if not self._is_sealed(e.agent)]
        recent = visible[-max_entries:]
        # Per-entry bound: render() is injected into every spawned worker's
        # first turn, so one oversized post (a long finding, a pasted dump)
        # would otherwise dominate every brief that includes it. Posts are
        # stored whole; only the rendered view is bounded.
        from .compaction import excerpt
        from .env_setting import env_or_config_int
        entry_cap = max(80, env_or_config_int(
            "MAVERICK_BB_RENDER_ENTRY_CHARS", "context", "blackboard_entry_chars", 800))
        lines = []
        for e in recent:
            lines.append(f"[{e.agent}/{e.kind}] {excerpt(e.content, entry_cap)}")
        rendered = "\n".join(lines)
        self._measure_codec(rendered)
        return rendered

    def _measure_codec(self, rendered: str) -> None:
        """Measure (never apply) what the token-aware codec would save on this real
        coordination block. OFF by default; the returned text is unchanged, so the
        audit/Shield path and the agents see exactly the plain English they did
        before. This only records telemetry once an operator opts in AND a codebook
        has been learned -- the safe way to confirm the bench numbers on live
        traffic before ever asking a model to read codes."""
        if not rendered:
            return
        try:
            from . import emergent_tokens as et
            if not et.enabled():
                return
            book = et.shared().book()
            if book.size == 0:
                return
            from . import codec_telemetry
            codec_telemetry.record(rendered, et.encode(rendered, book))
        except Exception:  # pragma: no cover -- measurement never blocks the loop
            pass

    def to_json(self) -> str:
        with self._lock:
            snapshot = list(self.entries)
        return json.dumps([asdict(e) for e in snapshot], indent=2)
