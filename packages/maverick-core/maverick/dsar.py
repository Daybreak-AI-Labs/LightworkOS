"""Data-subject access request (DSAR) export — GDPR Art. 15 / 20.

The erase side of GDPR (``maverick.audit.erase`` + ``maverick erase``) already
covers Art. 17 right-to-erasure. This module is its read-only mirror: the
right of access / portability. :func:`export_subject_data` gathers the covered
world and audit records for one subject (a channel ``user_id``) into a
JSON-serializable bundle for controller review.

It only ever *reads*. Every store is consulted defensively: a missing or empty
world DB / audit dir yields an empty section, never an exception — an export
must not be the thing that crashes on a half-provisioned install.

Two stores are covered:

  - the **world model** (conversations + turns, their goals and descendant
    goals/episodes), read via :class:`maverick.world_model.WorldModel`
    read APIs and tenant-resolved through
    :func:`maverick.world_model.world_for_tenant`;
  - the **audit log** NDJSON, scoped to rows whose structured raw or HMAC-
    anonymized ``channel`` / ``user_id`` identify the subject.

Isolation is the load-bearing property: this is subject data, so the bundle
must contain the requested subject's rows and *only* those. Matching is on
exact ``user_id`` equality (optionally narrowed to a channel); we never
substring-match a serialized value, which would leak co-tenants whose ids
share a prefix.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

log = logging.getLogger(__name__)


class SubjectAmbiguousError(RuntimeError):
    """The subject id is on more than one channel and the request names none.

    Raised only under ``strict=True``; nothing is read for the subject then. A
    ``RuntimeError`` so a caller that treats every strict failure as "could not
    be verified" keeps doing so, and a subclass so a caller that can say why
    (the DSAR estate worksheet) tells it from unreadable storage.
    """


def _fact_subject_token(channel: str, user_id: str) -> str:
    """Stable, delimiter-safe token for explicitly user-scoped facts.

    Mirrors :func:`maverick.erasure_verify._fact_subject_token` and the CLI
    ``export-user`` path so the *exported* set of facts is exactly the set the
    erase path (``delete_facts_matching``) would remove -- the invariant the
    erasure verifier relies on ("a row that would be erased is a row that is
    exported"). Defined locally to avoid a dsar <-> erasure_verify import cycle.
    """
    return f"{quote(channel, safe='')}:{quote(user_id, safe='')}"


def _iso(ts: Any) -> Any:
    """Best-effort epoch-seconds -> ISO-8601 UTC string.

    World-model timestamps are ``REAL`` epoch seconds; rendering them as ISO
    strings keeps the bundle human-readable and, more importantly, free of raw
    floats that a downstream consumer might misread as a different unit. A
    non-numeric value is returned untouched (already a string, or ``None``).
    """
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return ts
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):  # pragma: no cover - exotic ts
        return str(ts)


def _resolve_world(tenant: str | None, *, strict: bool = False) -> Any:
    """Open the selected tenant's ``WorldModel``.

    ``world_for_tenant(None)`` deliberately forces the legacy shared
    ``~/.maverick/world.db``. A DSAR export with no explicit tenant, however,
    should follow the active tenant (environment / contextvar) just like audit
    export does. Pass the ``data_dir`` active-tenant sentinel through the world
    factory when ``tenant`` is omitted, falling back to the shared DB only when
    no tenant is active. Returns ``None`` (a fail-soft empty section) if the
    world cannot be opened at all.
    """
    try:
        from .world_model import world_for_tenant

        world_tenant = tenant or "__active__"
        return world_for_tenant(world_tenant)
    except Exception as e:  # pragma: no cover - defensive (corrupt/locked DB)
        if strict:
            raise RuntimeError("could not open world model") from e
        log.warning("dsar: could not open world model: %s", e)
        return None


def _matches_user(conv_user_id: str, user_id: str) -> bool:
    """Whether a conversation belongs to the requested subject.

    Exact ``user_id`` equality only. This deliberately does NOT replicate the
    CLI's ``local:`` family-match (``--channel cli --user local`` ->
    ``local:<uuid>``); an exact rule cannot over-match and so cannot leak
    another subject's data, which is the priority for a DSAR. The CLI export
    remains the place that understands that local-chat convenience alias.
    """
    return conv_user_id == user_id


def _export_facts(
    world: Any,
    user_id: str,
    channel: str,
    *,
    strict: bool = False,
) -> dict[str, Any]:
    """Export the subject's explicitly user-scoped global facts + history.

    Facts are global key/value memory with no per-user column, so -- exactly as
    the erase path does -- only keys deliberately namespaced ``user:<channel>:
    <user_id>:<name>`` are considered (``facts_matching``). Arbitrary substrings
    are never matched, so a short/common id can't pull an unrelated subject's
    data. ``fact_history`` (superseded values, when [memory] temporal is on) is
    itself the subject's personal data, so Art.15 completeness includes it.
    """
    out: dict[str, Any] = {"facts": {}, "fact_history": {}}
    if world is None or not hasattr(world, "facts_matching"):
        if strict:
            raise RuntimeError("subject fact store is unavailable")
        return out
    token = _fact_subject_token(channel, user_id)
    try:
        out["facts"] = dict(world.facts_matching(token))
    except Exception as e:  # pragma: no cover - defensive
        if strict:
            raise RuntimeError("could not count subject facts") from e
        log.warning("dsar: facts_matching failed: %s", e)
    try:
        history = world.fact_history_matching(token)
    except Exception as e:  # pragma: no cover - defensive
        if strict:
            raise RuntimeError("could not count subject fact history") from e
        log.warning("dsar: fact_history_matching failed: %s", e)
        history = {}
    out["fact_history"] = {
        k: [
            {
                "value": getattr(v, "value", None),
                "valid_from": _iso(getattr(v, "valid_from", None)),
                "valid_to": _iso(getattr(v, "valid_to", None)),
                "source": getattr(v, "source", ""),
            }
            for v in versions
        ]
        for k, versions in (history or {}).items()
    }
    return out


def _subject_goal_ids(world: Any, convs: list[Any], roots: list[int], *, strict: bool) -> list[int]:
    """Include the descendant goals in the subject's read-only erasure scope."""
    seen = set(roots)
    if convs:
        try:
            plan = world.plan_conversation_erasure([c.id for c in convs])
            for gid in plan["goal_ids"]:
                if gid not in seen:
                    seen.add(gid)
                    roots.append(gid)
        except Exception as e:  # pragma: no cover - defensive
            if strict:
                raise RuntimeError("could not read subject goal closure") from e
            log.warning("dsar: subject goal closure unavailable: %s", e)
    return roots


def _export_world(
    world: Any,
    user_id: str,
    channel: str | None,
    *,
    strict: bool = False,
) -> dict[str, Any]:
    """Collect the subject's conversations + turns and the goals they touch.

    Uses the world model's read-only erasure plan for the selected conversations
    so the export includes descendant goals that erasure would remove. A goal
    reachable only through a sibling subject's conversation is not included.

    Explicitly user-scoped global facts (``user:<channel>:<user_id>:*``) are
    included too, mirroring the erase path so export and erasure stay symmetric.
    """
    empty = {"conversations": [], "goals": [], "facts": {}, "fact_history": {}}
    if world is None:
        if strict:
            raise RuntimeError("world model is unavailable")
        return empty

    # --- conversations + turns -------------------------------------------
    if channel is None:
        # User ids are channel-scoped.  Exporting without a concrete channel is
        # ambiguous once another channel reuses the same id, so fail closed
        # rather than list every channel and risk cross-subject disclosure.
        return empty

    try:
        all_convs = world.list_conversations(channel)
    except Exception as e:  # pragma: no cover - defensive
        if strict:
            raise RuntimeError("could not read subject conversations") from e
        log.warning("dsar: list_conversations failed: %s", e)
        return empty

    convs = [c for c in all_convs if _matches_user(c.user_id, user_id)]

    conversations: list[dict[str, Any]] = []
    goal_ids: list[int] = []
    seen_goal_ids: set[int] = set()
    for c in convs:
        try:
            # limit high enough to capture full history; export must be complete.
            turns = world.recent_turns(c.id, limit=1_000_000)
        except Exception as e:  # pragma: no cover - defensive
            if strict:
                raise RuntimeError(
                    f"could not read turns for conversation {c.id}"
                ) from e
            log.warning("dsar: recent_turns failed for conv %s: %s", c.id, e)
            turns = []
        turn_dicts: list[dict[str, Any]] = []
        for t in turns:
            turn_dicts.append(
                {
                    "id": t.id,
                    "role": t.role,
                    "content": t.content,
                    "ts": _iso(t.ts),
                    "goal_id": t.goal_id,
                }
            )
            if t.goal_id is not None and t.goal_id not in seen_goal_ids:
                seen_goal_ids.add(t.goal_id)
                goal_ids.append(t.goal_id)
        conversations.append(
            {
                "id": c.id,
                "channel": c.channel,
                "user_id": c.user_id,
                "created_at": _iso(c.created_at),
                "last_seen": _iso(c.last_seen),
                "turns": turn_dicts,
            }
        )

    # The turn-derived roots remain a fail-soft fallback for older world stores.
    goal_ids = _subject_goal_ids(world, convs, goal_ids, strict=strict)

    # --- goals + episodes -------------------------------------------------
    goals: list[dict[str, Any]] = []
    for gid in goal_ids:
        try:
            goal = world.get_goal(gid)
        except Exception as e:  # pragma: no cover - defensive
            if strict:
                raise RuntimeError(f"could not read goal {gid}") from e
            log.warning("dsar: get_goal failed for %s: %s", gid, e)
            continue
        if goal is None:
            continue
        try:
            episodes = world.list_episodes(limit=1_000_000, goal_id=gid)
        except Exception as e:  # pragma: no cover - defensive
            if strict:
                raise RuntimeError(f"could not read episodes for goal {gid}") from e
            log.warning("dsar: list_episodes failed for goal %s: %s", gid, e)
            episodes = []
        goals.append(
            {
                "id": goal.id,
                "parent_id": goal.parent_id,
                "title": goal.title,
                "description": goal.description,
                "status": goal.status,
                "created_at": _iso(goal.created_at),
                "updated_at": _iso(goal.updated_at),
                "deadline": _iso(goal.deadline),
                "result": goal.result,
                "episodes": [
                    {
                        "id": e.id,
                        "started_at": _iso(e.started_at),
                        "ended_at": _iso(e.ended_at),
                        "outcome": e.outcome,
                        "cost_dollars": e.cost_dollars,
                        "input_tokens": e.input_tokens,
                        "output_tokens": e.output_tokens,
                        "tool_calls": e.tool_calls,
                    }
                    for e in episodes
                ],
            }
        )

    facts_section = _export_facts(world, user_id, channel, strict=strict)
    return {
        "conversations": conversations,
        "goals": goals,
        "facts": facts_section["facts"],
        "fact_history": facts_section["fact_history"],
    }


def _iter_audit_events(
    tenant: str | None,
    *,
    strict: bool = False,
) -> list[dict[str, Any]]:
    """Read audit NDJSON rows as dicts, skipping malformed/unreadable input.

    Delegates to the shared :func:`maverick.audit.reader.iter_events` (the
    single day-file enumeration + parsing path used by export and SOC 2 too), so
    the cross-file ``anchors.ndjson`` tip-ledger is excluded and at-rest-sealed
    segments are transparently decrypted — neither of which this module did when
    it had its own ad-hoc glob. Fail-soft: a missing dir or unreadable/malformed
    line is skipped, never raised.
    """
    from .audit import reader

    try:
        return list(
            reader.iter_events(
                tenant=tenant,
                all_days=True,
                strict=strict,
            )
        )
    except Exception as e:  # pragma: no cover - defensive
        if strict:
            raise RuntimeError("could not read subject audit events") from e
        log.warning("dsar: could not read audit events: %s", e)
        return []


def _audit_channels_for_user(
    user_id: str,
    tenant: str | None,
    *,
    strict: bool = False,
) -> set[str]:
    """Return structured audit channels observed for ``user_id``."""
    return {
        event["channel"]
        for event in _iter_audit_events(tenant, strict=strict)
        if event.get("user_id") == user_id and isinstance(event.get("channel"), str)
    }


def _resolve_subject_channel(
    world: Any,
    user_id: str,
    channel: str | None,
    tenant: str | None,
    *,
    strict: bool = False,
) -> str | None:
    """Return the concrete channel for a DSAR, or ``None`` if ambiguous.

    ``channel`` is part of Lightwork's subject identity.  For backward
    compatibility with callers that exported a user id from a single-channel
    install, an omitted channel is inferred only when the user's structured
    world/audit rows identify exactly one channel.  If multiple channels reuse
    the same ``user_id``, the export fails closed so one subject's DSAR cannot
    disclose another subject's data.
    """
    if channel is not None:
        if channel.strip() == "":
            log.warning(
                "dsar: refusing export with blank channel for user_id %r", user_id
            )
            return None
        return channel

    channels: set[str] = set()
    if world is not None:
        try:
            channels.update(
                c.channel
                for c in world.list_conversations(None)
                if _matches_user(c.user_id, user_id) and isinstance(c.channel, str)
            )
        except Exception as e:  # pragma: no cover - defensive
            if strict:
                raise RuntimeError(
                    "could not resolve subject channel from conversations"
                ) from e
            log.warning("dsar: list_conversations failed while resolving channel: %s", e)

    channels.update(
        _audit_channels_for_user(user_id, tenant, strict=strict)
    )
    if len(channels) == 1:
        return next(iter(channels))
    if len(channels) > 1:
        if strict:
            raise SubjectAmbiguousError("subject identity is ambiguous across channels")
        log.warning(
            "dsar: refusing ambiguous export for user_id %r across channels %s",
            user_id,
            sorted(channels),
        )
    return None


def _export_audit(
    user_id: str,
    channel: str | None,
    tenant: str | None,
    *,
    strict: bool = False,
) -> list[dict[str, Any]]:
    """Collect audit rows for the subject.

    Audit events are plain dicts (``AuditEvent.to_dict`` spreads the payload),
    and erasure keys off structured ``channel`` + ``user_id``. That is exactly
    the rule :func:`maverick.audit.erase._event_matches` erases on, so a row
    that *would* be erased is a row that *is* exported. Each kept row is
    JSON-safe by construction (it was parsed from JSON); we round-trip with
    ``default=str`` only to neutralise any value json can't emit. Fail-soft: a
    missing dir, unreadable file, or malformed line is skipped, never raised.
    """
    if channel is None:
        # Channel is part of the subject identity.  Without one we cannot match
        # the erase path's exact-field rule, so do not export audit rows.
        return []

    from .paths import tenant_scope
    from .privacy import audit_subject_matches

    out: list[dict[str, Any]] = []
    with tenant_scope(tenant=tenant):
        for event in _iter_audit_events(tenant, strict=strict):
            if not audit_subject_matches(event, channel, user_id):
                continue
            # Render ts to ISO; preserve the remaining stored evidence.
            if "ts" in event:
                event = {**event, "ts": _iso(event["ts"])}
            out.append(json.loads(json.dumps(event, default=str)))
    return out


def export_subject_data(
    user_id: str,
    *,
    channel: str | None = None,
    tenant: str | None = None,
    strict: bool = False,
    world: Any = None,
) -> dict[str, Any]:
    """Gather covered world and audit records for ``user_id`` into one bundle.

    GDPR Art. 15 (right of access) / Art. 20 (portability), and a SOC 2 Privacy
    expectation. Read-only and fail-soft by default: a missing world DB or
    audit dir produces an empty section rather than an error. ``strict=True``
    is reserved for proof-producing callers such as erasure verification; it
    propagates an internal store-read failure so an unreadable store cannot be
    represented as a verified zero.

    ``user_id`` plus ``channel`` identify the subject (the same pair the world
    model stores on ``conversations`` and that audit events carry as structured
    fields). For compatibility, ``channel`` may be omitted only when existing
    world/audit rows make it unambiguous; if the same ``user_id`` appears on
    multiple channels, the export fails closed instead of over-exporting.
    ``tenant`` selects the data plane: when given, the subject's world DB and
    audit chain are read from that tenant's isolated directory via
    :func:`maverick.world_model.world_for_tenant` / :func:`maverick.paths.data_dir`;
    when ``None`` the active tenant (env / contextvar) is used, falling back to
    the legacy shared store.

    The returned dict is guaranteed ``json.dumps``-able (timestamps are
    stringified to ISO-8601; no bytes leak through). Its shape::

        {
          "subject":      {"user_id": str, "channel": str | None},
          "tenant":       str | None,
          "generated_at": str,        # ISO-8601 UTC, when this export ran
          "world":        {"conversations": [...], "goals": [...],
                           "facts": {...}, "fact_history": {...}},
          "audit":        [ {...}, ... ],
          "counts":       {"conversations", "turns", "goals",
                           "episodes", "facts", "audit_events"},
        }
    """
    world = world if world is not None else _resolve_world(
        tenant,
        strict=strict,
    )
    channel = _resolve_subject_channel(
        world,
        user_id,
        channel,
        tenant,
        strict=strict,
    )
    world_section = _export_world(
        world,
        user_id,
        channel,
        strict=strict,
    )
    audit_section = _export_audit(
        user_id,
        channel,
        tenant,
        strict=strict,
    )

    turn_count = sum(len(c["turns"]) for c in world_section["conversations"])
    episode_count = sum(len(g["episodes"]) for g in world_section["goals"])

    return {
        "subject": {"user_id": user_id, "channel": channel},
        "tenant": tenant,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "world": world_section,
        "audit": audit_section,
        "counts": {
            "conversations": len(world_section["conversations"]),
            "turns": turn_count,
            "goals": len(world_section["goals"]),
            "episodes": episode_count,
            "facts": len(world_section["facts"]),
            "fact_history": sum(
                len(versions)
                for versions in world_section["fact_history"].values()
            ),
            "audit_events": len(audit_section),
        },
    }


__all__ = ["export_subject_data"]
