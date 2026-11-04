"""Owned memory and proof regressions; authored, deliberately not executed."""
from __future__ import annotations

import json

import pytest
from maverick import personal_identity as identity
from maverick import personal_memory as memory


@pytest.fixture
def personal_store(tmp_path, monkeypatch):
    from maverick import audit, config
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(identity, "_path", lambda: tmp_path / "identities.enc")
    monkeypatch.setattr(memory, "_path", lambda key: tmp_path / (key + ".enc"))
    monkeypatch.setattr(identity, "enabled", lambda: True)
    monkeypatch.setattr(identity, "principal_current", lambda principal: principal == "user:alice")
    monkeypatch.setattr(identity, "current_tenant_id_strict", lambda: "workspace-a")
    monkeypatch.setattr(memory, "current_tenant_id_strict", lambda: "workspace-a")
    monkeypatch.setattr(audit, "audit_event", lambda *a, **kw: True)
    monkeypatch.setattr(config, "get_dreaming", lambda: {"user_notes": True})
    for module in (identity, memory):
        monkeypatch.setattr(module, "seal", lambda value: value)
        monkeypatch.setattr(module, "unseal", lambda value: value)
    return tmp_path


def link_alice():
    request = identity.begin("user:alice", "slack")
    scope = identity.account_identity("U1", "a" * 64)
    reply = identity.prove_channel_command(request["command"], channel="slack", user_id=scope,
                                           sender_id="U1", account_sha256="a" * 64)
    assert "Nothing is shared yet" in reply
    assert identity.principal_for_channel("slack", scope) is None
    state = identity.state("user:alice")
    identity.confirm("user:alice", request["id"], expected_revision=state["revision"])
    return scope, request["id"]


def test_link_needs_both_proofs_and_exact_tenant_account(personal_store, monkeypatch):
    scope, _ = link_alice()
    assert identity.principal_for_channel("slack", scope) == "user:alice"
    assert identity.principal_for_channel("slack", identity.account_identity("U1", "b" * 64)) is None
    assert identity.principal_for_channel("telegram", scope) is None
    assert identity.linked_channels("user:bob") == []
    monkeypatch.setattr(identity, "current_tenant_id_strict", lambda: "workspace-b")
    with pytest.raises(ValueError):
        identity.linked_channels("user:alice")


def test_missing_account_proof_never_links_and_command_replay_denied(personal_store):
    challenge = identity.begin("user:alice", "slack")
    assert "no verified account" in identity.prove_channel_command(challenge["command"], channel="slack", user_id="U1")
    scope, _ = link_alice()
    assert scope.startswith("account:")
    assert "expired or was already used" in identity.prove_channel_command(challenge["command"], channel="slack", user_id=scope, account_sha256="a" * 64)


def test_unlink_and_feature_disable_stop_sharing(personal_store, monkeypatch):
    scope, link_id = link_alice()
    memory.share("user:alice", source=link_id, expected_revision=0)
    assert memory.shared_principal("slack", scope) == "user:alice"
    identity.unlink("user:alice", link_id, expected_revision=identity.state("user:alice")["revision"])
    assert memory.shared_principal("slack", scope) is None
    scope, link_id = link_alice()
    memory.share("user:alice", source=link_id, expected_revision=memory.profile("user:alice")["revision"])
    monkeypatch.setattr(identity, "enabled", lambda: False)
    assert memory.shared_principal("slack", scope) is None


def test_deleted_note_stays_suppressed_after_rebuild(personal_store, monkeypatch):
    from maverick import user_notes
    scope, _ = link_alice()
    path = personal_store / "user_notes.ndjson"
    row = {"channel": "slack", "user_id": scope, "note": "I prefer metric units.", "source_ts": 1}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    monkeypatch.setattr(user_notes, "default_path", lambda: path)
    note = memory.records("slack", scope)[0]
    memory.update("user:alice", "slack", scope, expected_revision=0, note=note["id"], operation="delete")
    assert not memory.collection_allowed("slack", scope, row["note"])
    assert memory.recall("slack", scope) == []
    assert memory.records("slack", scope) == []
    assert memory.collection_allowed("slack", "unlinked-other", row["note"])


def test_personal_recall_cannot_override_admin_ceiling(personal_store, monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "get_dreaming", lambda: {"user_notes": False})
    assert memory.recall("dashboard", "alice") == []


def test_unknown_identity_cannot_edit_a_note(personal_store):
    with pytest.raises(ValueError):
        memory.update("user:alice", "slack", "not-verified", expected_revision=0, recall=False)


def test_note_edit_conflict_keeps_current_revision(personal_store):
    memory.update("user:alice", "dashboard", "alice", expected_revision=0, recall=False)
    with pytest.raises(identity.IdentityConflict):
        memory.update("user:alice", "dashboard", "alice", expected_revision=0, recall=True)
    assert memory.controls("dashboard", "alice")["recall"] is False


def test_existing_source_exclusion_stops_prompt_recall(personal_store, monkeypatch):
    from maverick import pilot_learning, user_notes
    path = personal_store / "user_notes.ndjson"
    row = {"channel": "dashboard", "user_id": "alice", "note": "I prefer metric units.", "source_goal_id": 7}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    monkeypatch.setattr(user_notes, "default_path", lambda: path)
    monkeypatch.setattr(pilot_learning, "excluded", lambda gid: gid == 7)
    assert memory.records("dashboard", "alice")
    assert memory.recall("dashboard", "alice") == []


def test_a_deleted_fact_is_used_in_none_of_ten_recalls_and_pausing_stops_all_recall(personal_store, monkeypatch):
    """Personal-data controls checked at the recall layer every answer draws from: after a
    person deletes one remembered fact it is offered in 0 of 10 recalls while
    their other facts still are; pausing recall offers nothing until resumed."""
    from maverick import user_notes
    path = personal_store / "user_notes.ndjson"
    rows = [{"channel": "dashboard", "user_id": "alice", "note": note, "source_ts": index}
            for index, note in enumerate(("I prefer metric units.", "My cost center is 4410.",
                                          "Send summaries on Fridays."), start=1)]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    monkeypatch.setattr(user_notes, "default_path", lambda: path)
    forgotten = next(r for r in memory.records("dashboard", "alice") if r["note"] == "My cost center is 4410.")
    record = memory.update("user:alice", "dashboard", "alice", expected_revision=0, note=forgotten["id"],
                           operation="delete")
    used = 0
    for _ in range(10):
        offered = " ".join(str(item) for item in memory.recall("dashboard", "alice"))
        used += "cost center" in offered
        assert "metric units" in offered
    assert used == 0
    record = memory.update("user:alice", "dashboard", "alice", expected_revision=record["revision"], recall=False)
    assert memory.recall("dashboard", "alice") == []
    memory.update("user:alice", "dashboard", "alice", expected_revision=record["revision"], recall=True)
    assert "metric units" in " ".join(str(item) for item in memory.recall("dashboard", "alice"))


def test_a_personal_correction_is_recalled_after_a_rebuild_refills_automatic_notes(personal_store, monkeypatch):
    from maverick import user_notes
    path = personal_store / "user_notes.ndjson"
    row = {"channel": "dashboard", "user_id": "alice", "note": "I prefer metric units.", "source_ts": 1}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    monkeypatch.setattr(user_notes, "default_path", lambda: path)
    note = memory.records("dashboard", "alice")[0]
    memory.update("user:alice", "dashboard", "alice", expected_revision=0, note=note["id"],
                  operation="edit", replacement="I prefer imperial units.")
    rebuilt = [{"channel": "dashboard", "user_id": "alice", "note": f"Automatic note {index}.", "source_ts": index}
               for index in range(8)]
    path.write_text("".join(json.dumps(r) + "\n" for r in rebuilt), encoding="utf-8")
    recalled = memory.recall("dashboard", "alice", k=8)
    assert len(recalled) == 8
    assert "I prefer imperial units." in recalled
