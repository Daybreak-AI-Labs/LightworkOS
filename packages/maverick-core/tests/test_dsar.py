"""DSAR subject-data export (GDPR Art. 15 / 20) — :mod:`maverick.dsar`.

The erase side is already tested (``test_erase_audit_scrub`` etc.); these cover
its read-only mirror. The load-bearing properties:

  - completeness: a subject's conversations, turns, the goals/episodes those
    turns reference, AND their audit rows all land in the bundle;
  - isolation: a *different* subject's world + audit data never leaks in;
  - fail-soft: an unknown subject (and an empty install) yields a structured,
    empty bundle rather than an error;
  - the bundle is ``json.dumps``-able (no datetimes / bytes leak through).

Hermetic + HOME-isolated: the autouse ``_isolate_maverick_home`` conftest
fixture points ``Path.home()`` at a per-test tmp dir, so the world DB the
exporter opens via ``world_for_tenant`` and the audit dir it scans both live
under the test's sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path

from maverick.audit.events import AuditEvent, EventKind
from maverick.audit.writer import AuditLog
from maverick.dsar import export_subject_data
from maverick.file_lock import ensure_private_directory
from maverick.world_model import WorldModel


def _world_db() -> Path:
    """The default (no-tenant) world DB path the exporter will open."""
    return Path.home() / ".maverick" / "world.db"


def _audit_dir() -> Path:
    """The default (no-tenant) audit dir the exporter will scan."""
    return Path.home() / ".maverick" / "audit"


def _audit_event(channel: str, user_id: str, title: str) -> AuditEvent:
    # channel/user_id ride in the payload and become top-level fields in the
    # on-disk row (AuditEvent.to_dict spreads payload) -- exactly what both the
    # erase matcher and the DSAR exporter key on.
    return AuditEvent(
        ts=1_700_000_000.0,
        kind=EventKind.GOAL_START,
        agent="system",
        goal_id=1,
        payload={"title": title, "channel": channel, "user_id": user_id},
    )


def _seed_world() -> WorldModel:
    """A world with two subjects so isolation is exercised everywhere."""
    wm = WorldModel(_world_db())

    # Subject under test: alice on telegram, a conversation + turns + a goal.
    conv = wm.get_or_create_conversation("telegram", "alice")
    gid = wm.create_goal("alice's goal", "do the alice thing")
    wm.set_goal_status(gid, "active")
    ep = wm.start_episode(gid)
    wm.end_episode(ep, summary="done", outcome="succeeded", cost_dollars=0.01)
    wm.append_turn(conv.id, "user", "alice secret message", goal_id=gid)
    wm.append_turn(conv.id, "assistant", "alice reply", goal_id=gid)

    # A different subject: bob. None of this may appear in alice's export.
    bob_conv = wm.get_or_create_conversation("telegram", "bob")
    bob_gid = wm.create_goal("bob's goal", "do the bob thing")
    wm.append_turn(bob_conv.id, "user", "bob secret message", goal_id=bob_gid)
    return wm


def test_export_contains_subject_world_and_audit():
    wm = _seed_world()
    wm.close()

    log = AuditLog(audit_dir=_audit_dir())
    assert log.record(_audit_event("telegram", "alice", "alice audited"))
    assert log.record(_audit_event("telegram", "alice", "alice audited 2"))

    bundle = export_subject_data("alice")

    # Envelope shape.
    assert bundle["subject"] == {"user_id": "alice", "channel": "telegram"}
    assert bundle["tenant"] is None
    assert isinstance(bundle["generated_at"], str)
    assert set(bundle["counts"]) == {
        "conversations", "turns", "goals", "episodes", "facts",
        "fact_history", "audit_events",
    }

    # World: the conversation + both turns + the goal + its episode.
    convs = bundle["world"]["conversations"]
    assert len(convs) == 1
    assert convs[0]["user_id"] == "alice"
    contents = [t["content"] for t in convs[0]["turns"]]
    assert "alice secret message" in contents
    assert "alice reply" in contents
    assert bundle["counts"]["turns"] == 2

    goals = bundle["world"]["goals"]
    assert len(goals) == 1
    assert goals[0]["title"] == "alice's goal"
    assert len(goals[0]["episodes"]) == 1
    assert goals[0]["episodes"][0]["outcome"] == "succeeded"
    assert bundle["counts"]["goals"] == 1
    assert bundle["counts"]["episodes"] == 1

    # Audit: exactly alice's two rows.
    assert bundle["counts"]["audit_events"] == 2
    titles = {e.get("title") for e in bundle["audit"]}
    assert titles == {"alice audited", "alice audited 2"}
    assert all(e["user_id"] == "alice" for e in bundle["audit"])


def test_export_excludes_other_users():
    wm = _seed_world()
    wm.close()

    log = AuditLog(audit_dir=_audit_dir())
    log.record(_audit_event("telegram", "alice", "alice audited"))
    log.record(_audit_event("telegram", "bob", "bob audited"))

    bundle = export_subject_data("alice")
    blob = json.dumps(bundle)

    # No trace of bob anywhere in the serialized bundle.
    assert "bob secret message" not in blob
    assert "bob's goal" not in blob
    assert "bob audited" not in blob
    assert "bob" not in {c["user_id"] for c in bundle["world"]["conversations"]}
    assert all(e["user_id"] == "alice" for e in bundle["audit"])

    # And the bob goal id is not pulled in via the goals section.
    alice_goal_titles = {g["title"] for g in bundle["world"]["goals"]}
    assert alice_goal_titles == {"alice's goal"}


def test_export_includes_descendant_goals_that_erasure_would_remove():
    wm = _seed_world()
    alice_root = next(g.id for g in wm.list_goals(limit=100) if g.title == "alice's goal")
    child = wm.create_goal("alice child task", parent_id=alice_root)
    wm.create_goal("alice grandchild task", parent_id=child)
    wm.close()

    bundle = export_subject_data("alice", channel="telegram")
    titles = {goal["title"] for goal in bundle["world"]["goals"]}
    assert titles == {"alice's goal", "alice child task", "alice grandchild task"}
    assert bundle["counts"]["goals"] == 3
    assert "bob's goal" not in json.dumps(bundle)


def test_anonymous_audit_rows_remain_in_subject_export_and_erasure_scope(monkeypatch):
    from maverick.audit.erase import scrub_user

    monkeypatch.setenv("MAVERICK_ANON", "1")
    wm = _seed_world()
    wm.close()
    log = AuditLog(audit_dir=_audit_dir())
    assert log.record(_audit_event("telegram", "alice", "alice audited"))
    assert log.record(_audit_event("telegram", "bob", "bob audited"))

    bundle = export_subject_data("alice", channel="telegram")
    assert bundle["counts"]["audit_events"] == 1
    assert bundle["audit"][0]["user_id"].startswith("user_id#")
    assert "bob" not in json.dumps(bundle["audit"])
    assert scrub_user("telegram", "alice", audit_dir=_audit_dir())[0] == 1
    assert export_subject_data("alice", channel="telegram")["counts"]["audit_events"] == 0


def test_export_with_channel_excludes_same_user_id_on_other_channels():
    """Channel is part of the subject identity, so ids may collide safely."""
    wm = WorldModel(_world_db())

    telegram = wm.get_or_create_conversation("telegram", "alice")
    telegram_gid = wm.create_goal("telegram alice goal", "telegram private goal")
    telegram_ep = wm.start_episode(telegram_gid)
    wm.end_episode(telegram_ep, summary="telegram done", outcome="succeeded")
    wm.append_turn(telegram.id, "user", "telegram alice secret", goal_id=telegram_gid)

    discord = wm.get_or_create_conversation("discord", "alice")
    discord_gid = wm.create_goal("discord alice goal", "discord private goal")
    discord_ep = wm.start_episode(discord_gid)
    wm.end_episode(discord_ep, summary="discord done", outcome="succeeded")
    wm.append_turn(discord.id, "user", "discord alice secret", goal_id=discord_gid)
    wm.close()

    log = AuditLog(audit_dir=_audit_dir())
    log.record(_audit_event("telegram", "alice", "telegram alice audited"))
    log.record(_audit_event("discord", "alice", "discord alice audited"))

    bundle = export_subject_data("alice", channel="telegram")
    blob = json.dumps(bundle)

    assert bundle["subject"] == {"user_id": "alice", "channel": "telegram"}
    assert "telegram alice secret" in blob
    assert "telegram alice goal" in blob
    assert "telegram alice audited" in blob
    assert "discord alice secret" not in blob
    assert "discord alice goal" not in blob
    assert "discord alice audited" not in blob
    assert {c["channel"] for c in bundle["world"]["conversations"]} == {"telegram"}
    assert {e["channel"] for e in bundle["audit"]} == {"telegram"}


def test_export_with_blank_channel_fails_closed_for_same_user_id_collision():
    """Blank explicit channels must not become an unscoped world export."""
    wm = WorldModel(_world_db())

    telegram = wm.get_or_create_conversation("telegram", "alice")
    telegram_gid = wm.create_goal("telegram alice goal", "telegram private goal")
    wm.append_turn(telegram.id, "user", "telegram alice secret", goal_id=telegram_gid)

    discord = wm.get_or_create_conversation("discord", "alice")
    discord_gid = wm.create_goal("discord alice goal", "discord private goal")
    wm.append_turn(discord.id, "user", "discord alice secret", goal_id=discord_gid)
    wm.close()

    log = AuditLog(audit_dir=_audit_dir())
    log.record(_audit_event("telegram", "alice", "telegram alice audited"))
    log.record(_audit_event("discord", "alice", "discord alice audited"))

    bundle = export_subject_data("alice", channel="")
    blob = json.dumps(bundle)

    assert bundle["subject"] == {"user_id": "alice", "channel": None}
    assert bundle["world"] == {"conversations": [], "goals": [], "facts": {}, "fact_history": {}}
    assert bundle["audit"] == []
    assert "telegram alice secret" not in blob
    assert "discord alice secret" not in blob
    assert "telegram alice audited" not in blob
    assert "discord alice audited" not in blob


def test_export_without_channel_fails_closed_when_user_id_is_ambiguous():
    wm = WorldModel(_world_db())
    telegram = wm.get_or_create_conversation("telegram", "alice")
    wm.append_turn(telegram.id, "user", "telegram alice secret")
    discord = wm.get_or_create_conversation("discord", "alice")
    wm.append_turn(discord.id, "user", "discord alice secret")
    wm.close()

    log = AuditLog(audit_dir=_audit_dir())
    log.record(_audit_event("telegram", "alice", "telegram alice audited"))
    log.record(_audit_event("discord", "alice", "discord alice audited"))

    bundle = export_subject_data("alice")
    blob = json.dumps(bundle)

    assert bundle["subject"] == {"user_id": "alice", "channel": None}
    assert bundle["world"] == {"conversations": [], "goals": [], "facts": {}, "fact_history": {}}
    assert bundle["audit"] == []
    assert "telegram alice secret" not in blob
    assert "discord alice secret" not in blob
    assert "telegram alice audited" not in blob
    assert "discord alice audited" not in blob


def test_unknown_user_returns_empty_structured_bundle():
    wm = _seed_world()
    wm.close()
    log = AuditLog(audit_dir=_audit_dir())
    log.record(_audit_event("telegram", "alice", "alice audited"))

    bundle = export_subject_data("nobody")

    assert bundle["subject"]["user_id"] == "nobody"
    assert bundle["world"]["conversations"] == []
    assert bundle["world"]["goals"] == []
    assert bundle["audit"] == []
    assert bundle["counts"] == {
        "conversations": 0, "turns": 0, "goals": 0,
        "episodes": 0, "facts": 0, "fact_history": 0, "audit_events": 0,
    }
    # Still serializable.
    json.dumps(bundle)


def test_export_on_empty_install_is_fail_soft():
    # No world DB written yet, no audit dir: every section is empty, no raise.
    bundle = export_subject_data("alice")
    assert bundle["world"] == {"conversations": [], "goals": [], "facts": {}, "fact_history": {}}
    assert bundle["audit"] == []
    assert bundle["counts"]["conversations"] == 0
    json.dumps(bundle)


def test_bundle_is_json_serializable_with_no_datetimes_or_bytes():
    wm = _seed_world()
    wm.close()
    log = AuditLog(audit_dir=_audit_dir())
    log.record(_audit_event("telegram", "alice", "alice audited"))

    bundle = export_subject_data("alice")

    # json.dumps must succeed with NO default= coercion -- proving timestamps
    # were already stringified and no bytes leaked through.
    text = json.dumps(bundle)
    assert isinstance(text, str)

    # Timestamps render as ISO-8601 strings, not raw floats.
    conv = bundle["world"]["conversations"][0]
    assert isinstance(conv["created_at"], str)
    assert isinstance(conv["turns"][0]["ts"], str)
    assert "T" in conv["turns"][0]["ts"]  # ISO date/time separator
    goal = bundle["world"]["goals"][0]
    assert isinstance(goal["created_at"], str)
    assert isinstance(goal["episodes"][0]["started_at"], str)


def test_tenant_isolation():
    """A tenant export reads that tenant's world/audit, not the shared one."""
    from maverick.paths import data_dir

    # Shared (no-tenant) store: alice has a conversation here.
    shared = WorldModel(_world_db())
    shared.get_or_create_conversation("telegram", "alice")
    shared.append_turn(
        shared.get_or_create_conversation("telegram", "alice").id,
        "user", "shared-store-message",
    )
    shared.close()

    # Tenant 'acme' store: a *different* alice conversation lives here.
    tenant_db = data_dir("world.db", tenant="acme")
    ensure_private_directory(tenant_db.parent)
    tw = WorldModel(tenant_db)
    tconv = tw.get_or_create_conversation("telegram", "alice")
    tw.append_turn(tconv.id, "user", "acme-store-message")
    tw.close()

    bundle = export_subject_data("alice", tenant="acme")
    assert bundle["tenant"] == "acme"
    blob = json.dumps(bundle)
    assert "acme-store-message" in blob
    # The shared-store conversation must NOT bleed into the tenant export.
    assert "shared-store-message" not in blob


def test_anonymous_audit_subject_lookup_uses_selected_tenant(monkeypatch):
    from maverick.paths import data_dir, tenant_scope

    monkeypatch.setenv("MAVERICK_ANON", "1")
    with tenant_scope(tenant="acme"):
        audit_dir = data_dir("audit")
        log = AuditLog(audit_dir=audit_dir)
        assert log.record(_audit_event("telegram", "alice", "tenant event"))
        assert log.record(_audit_event("telegram", "bob", "other tenant subject"))

    bundle = export_subject_data("alice", channel="telegram", tenant="acme")
    assert bundle["counts"]["audit_events"] == 1
    assert bundle["audit"][0]["channel"].startswith("channel#")


def test_dsar_exports_user_scoped_facts_and_excludes_others():
    wm = WorldModel(_world_db())
    # A conversation anchors the channel resolution for the bare-id export.
    wm.get_or_create_conversation("telegram", "alice")
    wm.upsert_fact("user:telegram:alice:preference", "alice likes blue")
    wm.upsert_fact("user:telegram:bob:preference", "bob likes red")
    wm.upsert_fact("global:telegram:alice", "not deliberately scoped")
    wm.close()

    bundle = export_subject_data("alice", channel="telegram")
    facts = bundle["world"]["facts"]
    assert facts == {"user:telegram:alice:preference": "alice likes blue"}
    assert bundle["counts"]["facts"] == 1
    # No cross-subject / unscoped leakage.
    import json
    blob = json.dumps(bundle)
    assert "bob likes red" not in blob
    assert "not deliberately scoped" not in blob


def test_dsar_export_includes_fact_history_key():
    # Shape guarantee: the bundle always carries fact_history (empty when
    # temporal memory is off), so downstream consumers can rely on it.
    wm = WorldModel(_world_db())
    wm.get_or_create_conversation("telegram", "alice")
    wm.close()
    bundle = export_subject_data("alice", channel="telegram")
    assert "fact_history" in bundle["world"]
    assert isinstance(bundle["world"]["fact_history"], dict)
