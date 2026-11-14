"""Per-goal key/value memory tool.

Lets long-running agents persist facts across turns without bloating
the conversation. Backed by the world_model's ``facts`` table (already
exists). Five ops:

  - set(key, value)  — write (overwrites if key already exists for goal)
  - get(key)         — read; returns missing-sentinel if absent
  - search(query)    — substring search across keys/values for the goal
  - delete(key)      — remove a key
  - list()           — list the goal's keys

Scoped to the current goal so memory doesn't leak across runs. Use the
``recall_past_goals`` tool when you need cross-goal context.
"""
from __future__ import annotations

import logging
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_KV_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["set", "get", "search", "delete", "list"],
            "description": "Operation.",
        },
        "key": {"type": "string", "description": "Fact key (for set/get/delete)."},
        "value": {"type": "string", "description": "Fact value (for set)."},
        "query": {"type": "string", "description": "Substring (for search)."},
        "max_results": {"type": "integer", "description": "Cap for search/list (default 50)."},
    },
    "required": ["op"],
}


def _scoped_key(goal_id: int, user_key: str) -> str:
    """Prefix the key so kv_memory is goal-scoped on the flat ``facts`` table."""
    return f"goal:{goal_id}:{user_key}"


def _unscope(scoped_key: str) -> str:
    """Strip the ``goal:N:`` prefix; returns the original user-supplied key."""
    parts = scoped_key.split(":", 2)
    if len(parts) == 3 and parts[0] == "goal":
        return parts[2]
    return scoped_key


def _run_factory(world, goal_id: int | None):
    observed: dict[str, int] = {}
    def _run(args: dict[str, Any]) -> str:
        if world is None or goal_id is None:
            return "ERROR: kv_memory requires an active goal (world / goal_id missing)"
        op = args.get("op")
        if not op:
            return "ERROR: op is required"
        try:
            cap = max(1, min(int(args.get("max_results") or 50), 500))
        except (TypeError, ValueError, OverflowError):
            return "ERROR: max_results must be an integer"
        if op == "set":
            user_key = (args.get("key") or "").strip()
            value = args.get("value") or ""
            if not user_key:
                return "ERROR: set requires key"
            # Cap the value: an unbounded write lets the agent stash hundreds
            # of MB in SQLite that a later get() floods the context window
            # with. 64 KB is plenty for a fact; store a summary or path else.
            if len(value) > 65536:
                return (
                    f"ERROR: value too large ({len(value)} chars; max 65536). "
                    "Store a summary or a file path instead."
                )
            scoped = _scoped_key(goal_id, user_key)
            # Memory Guard (OWASP ASI06): a fact the agent persists is TOOL-trust
            # -- the memory-poisoning surface, since it may parrot attacker-
            # controlled tool/web content. Screen the value and stamp provenance
            # before it enters the store; a flagged low-trust write is quarantined
            # (not stored) and audited. All a no-op when the guard is off.
            from .. import memory_guard as _mg
            _prov = _mg.agent_fact_provenance()
            _decision = _mg.screen_write(value, _prov)
            _mg.audit_write(scoped, _prov, _decision, goal_id=goal_id)
            if not _decision.allowed:
                return (
                    "ERROR: memory write blocked by Memory Guard "
                    f"({_decision.reason})"
                )
            # Atomic upsert through the locked WorldModel API. The prior
            # DELETE-then-INSERT on world.conn was (a) non-atomic -- a crash
            # or a concurrent commit between the two statements wiped the
            # existing value entirely -- and (b) bypassed WorldModel's write
            # lock, so it could flush another thread's half-written
            # transaction. upsert_fact does an ON CONFLICT upsert under
            # _writing().
            from ..fact_revision import FactConflict
            try:
                observed[scoped] = world.upsert_fact(
                    scoped, value, source=_prov.source,
                    trust_tier=int(_prov.trust), sensitivity=_prov.sensitivity.value,
                    expected_revision=observed.get(scoped, 0),
                )
            except FactConflict:
                return "ERROR: fact changed; get its current value before deciding whether to replace it"
            return f"set {user_key!r} ({len(value)} bytes)"
        if op == "get":
            user_key = (args.get("key") or "").strip()
            if not user_key:
                return "ERROR: get requires key"
            # Route through the locked, backend-portable helper instead of
            # world.conn.execute(... ?): the raw path took torn reads under the
            # serve threadpool and used `?` placeholders that break on Postgres.
            scoped = _scoped_key(goal_id, user_key)
            record = world.fact_record(scoped)
            observed[scoped] = record["revision"] if record else 0
            if record is None:
                return f"(no fact stored for {user_key!r})"
            return record["value"]
        if op == "delete":
            user_key = (args.get("key") or "").strip()
            if not user_key:
                return "ERROR: delete requires key"
            scoped = _scoped_key(goal_id, user_key)
            from ..fact_revision import FactConflict
            try:
                n = world.delete_fact(
                    scoped, expected_revision=observed.get(scoped, 0),
                )
            except FactConflict:
                return "ERROR: fact changed; get its current value before deciding whether to delete it"
            observed[scoped] = 0
            return f"deleted {n} row(s)"
        prefix = f"goal:{goal_id}:"
        if op == "list":
            rows = world.list_facts(prefix, cap)
            if not rows:
                return "(no facts stored for this goal)"
            return "\n".join(f"{_unscope(k)}  ({sz} bytes)" for k, sz in rows)
        if op == "search":
            return _search(world, prefix, args, cap)
        return f"ERROR: unknown op {op!r}"
    return _run


def _search(world, prefix, args, cap):
    query = (args.get("query") or "").strip()
    if not query:
        return "ERROR: search requires query"
    rows = world.search_facts(prefix, query, cap)
    if not rows:
        return f"no matches for {query!r}"
    return "\n".join(f"{_unscope(key)}: {(value or '')[:200]}" for key, value in rows)


def kv_memory(world, goal_id: int | None) -> Tool:
    """Factory: builds the kv_memory tool bound to (world, goal_id)."""
    return Tool(
        name="kv_memory",
        description=(
            "Persist facts across turns for the current goal. ops: "
            "set (create or replace a previously read revision), get (read), delete, list (recent keys), "
            "search (substring across keys+values). Goal-scoped -- "
            "memory doesn't leak across runs. Use recall_past_goals "
            "for cross-goal context."
        ),
        input_schema=_KV_SCHEMA,
        fn=_run_factory(world, goal_id),
    )
