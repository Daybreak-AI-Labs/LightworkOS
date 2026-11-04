"""A public conversation link releases exactly the owner's reviewed transcript."""
from __future__ import annotations

import json
import sqlite3
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick_dashboard.app import app


@pytest.fixture
def space(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    world = world_model.WorldModel(tmp_path / "world.db")
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world
    world.close()


def _conversation(world):
    root = world.create_goal("Plan the launch", "Launch details")
    world.set_goal_status(root, "done", result="## First answer\n\n- Draft plan")
    conversation = world.get_or_create_conversation("web", f"local/{root}")
    world.append_turn(conversation.id, "user", "Plan the launch <script>alert(1)</script>", goal_id=root)
    world.append_turn(conversation.id, "assistant", "## First answer\n\n- Draft plan", goal_id=root)
    question_id = world.ask("Which market?", goal_id=root)
    world.answer(question_id, "Chattanooga")
    latest = world.create_goal("Revise the plan", "Use the local market", parent_id=root)
    world.set_goal_status(latest, "done", result="## Final answer\n\n- Begin locally")
    world.append_turn(conversation.id, "user", "Revise the plan", goal_id=latest)
    world.append_turn(conversation.id, "assistant", "## Final answer\n\n- Begin locally", goal_id=latest)
    world.add_artifact(latest, "text", "Private attachment", "Attachment must stay out")
    return root, latest, conversation.id


def _preview(client, goal_id, scope="conversation"):
    return client.post(f"/api/v1/goals/{goal_id}/share/preview?scope={scope}")


def _mint(client, goal_id, preview, scope="conversation"):
    return client.post(f"/api/v1/goals/{goal_id}/share", json={
        "confirm": True, "scope": scope, "source_sha256": preview["source"]["sha256"],
        "lifetime_seconds": 3600, "label": "Launch conversation",
    })


def test_full_conversation_is_an_explicit_reviewed_choice_with_revocation(space):
    client, world = space
    root, latest, _ = _conversation(world)
    default = _preview(client, latest, "result")
    assert default.status_code == 200
    assert "transcript" not in default.json()["source"]
    assert "Plan the launch" not in default.json()["source"]["result"]
    preview = _preview(client, latest)
    assert preview.status_code == 200, preview.text
    reviewed = preview.json()
    assert [item["role"] for item in reviewed["source"]["transcript"]] == [
        "user", "clarification", "assistant", "user", "assistant",
    ]
    assert reviewed["source"]["transcript"][1]["answer"] == "Chattanooga"
    assert reviewed["source"]["transcript"][3]["text"] == "Revise the plan"
    assert "Use the local market" not in str(reviewed["source"]["transcript"])
    assert reviewed["source"]["artifacts"] == []
    assert not world.share_links_for_goal(latest)
    assert _mint(client, latest, reviewed, scope="result").status_code == 409
    created = _mint(client, latest, reviewed)
    assert created.status_code == 201, created.text
    token = created.json()["url"].split("/share/")[1]
    page = TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}")
    assert page.status_code == 200, page.text
    assert "Plan the launch" in page.text
    assert "First answer" in page.text and "Final answer" in page.text
    assert "Which market?" in page.text and "Chattanooga" in page.text
    assert "Attachment must stay out" not in page.text
    assert "Launch details" not in page.text  # prior task's internal description is not a turn
    assert "member_revisions" not in page.text
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "data-markdown" in page.text
    assert client.post(f"/api/v1/goals/{latest}/share/{created.json()['id']}/revoke").json()["ok"]
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404
    assert root != latest


def test_public_release_waits_for_audit_receipt_and_retry_mints_a_new_link(space, monkeypatch):
    from maverick import audit
    from maverick_dashboard import deliverable_sharing as sharing
    from maverick_dashboard import share_link_routing

    client, world = space
    _, latest, _ = _conversation(world)
    preview = _preview(client, latest).json()
    deliver = audit.record
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)

    refused = _mint(client, latest, preview)
    assert refused.status_code == 503
    failed_links = world.share_links_for_goal(latest)
    assert len(failed_links) == 1 and failed_links[0]["revoked"]
    failed_record = sharing._store().get(sharing._id(latest, failed_links[0]["id"]))
    assert failed_record["_audit_pending"]

    # Even if an older or interrupted publisher left both token and locator
    # active, a pending governed release must never render publicly.
    goal = world.get_goal(latest)
    link_id, token = world.create_share_link(latest, ttl_seconds=3600, token_prefix="r1_")
    with pytest.raises(sharing.ShareAuditPending):
        sharing.remember(world, goal, link_id=link_id, source=preview["source"],
                         label="Reviewed conversation", lifetime=3600, actor="local-operator")
    share_link_routing.register(token, expires_at=time.time() + 3600)
    assert sharing.release_snapshot(world, goal, token) is None
    assert client.get(f"/share/{token}").status_code == 404
    assert sharing.listing(world, goal)[-1]["active"] is False

    monkeypatch.setattr(audit, "record", deliver)
    recovered = _mint(client, latest, preview)
    assert recovered.status_code == 201
    assert recovered.json()["id"] != failed_links[0]["id"]
    assert client.get(recovered.json()["url"].replace("http://127.0.0.1", "")).status_code == 200
    assert next(row for row in world.share_links_for_goal(latest)
                if row["id"] == failed_links[0]["id"])["revoked"]


@pytest.mark.parametrize("metadata_state", ["missing", "wrong_goal"])
def test_share_listing_never_calls_unavailable_metadata_active(space, monkeypatch, metadata_state):
    from maverick_dashboard import deliverable_sharing as sharing

    client, world = space
    _, latest, _ = _conversation(world)
    created = _mint(client, latest, _preview(client, latest).json())
    assert created.status_code == 201, created.text
    token = created.json()["url"].split("/share/")[1]
    assert client.get(f"/share/{token}").status_code == 200

    record = sharing._store().get(sharing._id(latest, created.json()["id"]))
    assert record and record["goal_id"] == latest
    bad_record = None if metadata_state == "missing" else {**record, "goal_id": latest + 1,
                                                            "label": "Wrong goal's private label"}
    monkeypatch.setattr(sharing, "_store", lambda: SimpleNamespace(get=lambda _id: bad_record))

    listed = client.get(f"/api/v1/goals/{latest}/share")
    assert listed.status_code == 200
    assert len(listed.json()["links"]) == 1
    link = listed.json()["links"][0]
    assert link["active"] is False
    assert link["state"] == "unavailable"
    assert link["label"] == f"Read-only link #{created.json()['id']}"
    assert client.get(f"/share/{token}").status_code == 404


def test_public_conversation_scans_once_but_rechecks_revocation_during_read(space, monkeypatch):
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import deliverable_sharing as sharing

    client, world = space
    _, latest, _ = _conversation(world)
    created = _mint(client, latest, _preview(client, latest).json())
    assert created.status_code == 201, created.text
    token = created.json()["url"].split("/share/")[1]
    scans = []
    original_snapshot = sharing.conversation_snapshot

    def counted_snapshot(*args, **kwargs):
        scans.append(1)
        reader = args[0]._reader()
        assert reader is not args[0].conn
        assert reader.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            reader.execute("UPDATE goals SET title=title WHERE id=?", (latest,))
        return original_snapshot(*args, **kwargs)

    monkeypatch.setattr(sharing, "conversation_snapshot", counted_snapshot)
    public = TestClient(app, base_url="http://127.0.0.1")
    assert public.get(f"/share/{token}").status_code == 200
    assert len(scans) == 1

    original_render = dashboard._goal_deliverable

    def revoke_during_render(goal):
        world.revoke_share_link(created.json()["id"], goal_id=latest)
        return original_render(goal)

    scans.clear()
    monkeypatch.setattr(dashboard, "_goal_deliverable", revoke_during_render)
    assert public.get(f"/share/{token}").status_code == 404
    assert len(scans) == 1


def test_public_conversation_refuses_source_change_after_single_scan(space, monkeypatch):
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import deliverable_sharing as sharing

    client, world = space
    root, latest, _ = _conversation(world)
    created = _mint(client, latest, _preview(client, latest).json())
    assert created.status_code == 201, created.text
    token = created.json()["url"].split("/share/")[1]
    question_id = world.all_questions(root)[0].id
    scans = []
    original_snapshot = sharing.conversation_snapshot

    def counted_snapshot(*args, **kwargs):
        scans.append(1)
        return original_snapshot(*args, **kwargs)

    monkeypatch.setattr(sharing, "conversation_snapshot", counted_snapshot)
    original_render = dashboard._goal_deliverable

    def edit_during_render(goal):
        # Use the very WorldModel instance serving this public request. Its
        # writer is distinct from the pinned read-only connection.
        live = dashboard._world()
        assert live._reader() is not live.conn
        live.answer(question_id, "A different market")
        return original_render(goal)

    monkeypatch.setattr(dashboard, "_goal_deliverable", edit_during_render)
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404
    assert len(scans) == 1


def test_public_conversation_detects_same_reader_connection_write(space, monkeypatch):
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import deliverable_sharing as sharing

    client, world = space
    root, latest, _ = _conversation(world)
    created = _mint(client, latest, _preview(client, latest).json())
    assert created.status_code == 201, created.text
    token = created.json()["url"].split("/share/")[1]
    scans = []
    original_snapshot = sharing.conversation_snapshot

    def counted_snapshot(*args, **kwargs):
        scans.append(1)
        return original_snapshot(*args, **kwargs)

    monkeypatch.setattr(sharing, "conversation_snapshot", counted_snapshot)
    original_render = dashboard._goal_deliverable

    def same_connection_edit(goal):
        # Reproduce the SQLite blind spot even if an internal caller bypassed
        # the query-only guard: data_version stays fixed on its own connection.
        reader = dashboard._world()._reader()
        before_version = reader.execute("PRAGMA data_version").fetchone()[0]
        before_changes = reader.total_changes
        reader.execute("PRAGMA query_only = OFF")
        try:
            reader.execute("UPDATE goals SET title=? WHERE id=?", ("Changed prior title", root))
        finally:
            reader.execute("PRAGMA query_only = ON")
        assert reader.execute("PRAGMA data_version").fetchone()[0] == before_version
        assert reader.total_changes > before_changes
        return original_render(goal)

    monkeypatch.setattr(dashboard, "_goal_deliverable", same_connection_edit)
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404
    assert len(scans) == 1


def test_public_conversation_rechecks_prior_member_policy_without_second_scan(space, monkeypatch):
    from maverick import domain
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import deliverable_sharing as sharing

    client, world = space
    root = world.create_goal("Reviewed forecast", domain="finance_cash13w")
    world.set_goal_status(root, "done", result="Reviewed first answer")
    thread = world.get_or_create_conversation("web", f"local/{root}")
    world.append_turn(thread.id, "user", "What is the forecast?", goal_id=root)
    world.append_turn(thread.id, "assistant", "Reviewed first answer", goal_id=root)
    world.record_signoff(root, "approved", decided_by="reviewer")
    latest = world.create_goal("Summarize it", parent_id=root)
    world.set_goal_status(latest, "done", result="Approved summary")
    world.append_turn(thread.id, "user", "Summarize it", goal_id=latest)
    world.append_turn(thread.id, "assistant", "Approved summary", goal_id=latest)
    created = _mint(client, latest, _preview(client, latest).json())
    assert created.status_code == 201, created.text
    token = created.json()["url"].split("/share/")[1]

    scans = []
    original_snapshot = sharing.conversation_snapshot

    def counted_snapshot(*args, **kwargs):
        scans.append(1)
        return original_snapshot(*args, **kwargs)

    monkeypatch.setattr(sharing, "conversation_snapshot", counted_snapshot)
    original_render = dashboard._goal_deliverable

    def remove_policy_during_render(goal):
        result = original_render(goal)
        monkeypatch.setattr(domain, "available_domains", dict)
        return result

    monkeypatch.setattr(dashboard, "_goal_deliverable", remove_policy_during_render)
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404
    assert len(scans) == 1


def test_changed_included_message_or_clarification_invalidates_link(space):
    client, world = space
    root, latest, _ = _conversation(world)
    created = _mint(client, latest, _preview(client, latest).json())
    token = created.json()["url"].split("/share/")[1]
    world.set_goal_status(root, "done", result="Revised earlier answer")
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404
    assert client.get(f"/api/v1/goals/{latest}/share").json()["links"][0]["state"] == "source changed"

    fresh = _mint(client, latest, _preview(client, latest).json())
    fresh_token = fresh.json()["url"].split("/share/")[1]
    question_id = world.all_questions(root)[0].id
    world.answer(question_id, "Another market")
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{fresh_token}").status_code == 404


def test_selected_message_uses_exact_saved_turn_and_changed_review_never_revives_link(space, monkeypatch):
    from maverick import world_model

    client, world = space
    root, latest, conversation_id = _conversation(world)
    world.record_signoff(root, "approved", decided_by="reviewer")
    world.record_signoff(latest, "approved", decided_by="reviewer")
    reviewed = _preview(client, latest).json()
    selected = reviewed["source"]["transcript"][3]
    assert selected["text"] == "Revise the plan"
    assert isinstance(selected["turn_id"], int)
    assert "Use the local market" not in str(reviewed["source"]["transcript"])
    created = _mint(client, latest, reviewed)
    token = created.json()["url"].split("/share/")[1]
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 200
    original_review_time = world.signoff_for(root)["created_at"]
    with monkeypatch.context() as frozen:
        frozen.setattr(world_model, "time", SimpleNamespace(time=lambda: original_review_time))
        world.record_signoff(root, "rejected", decided_by="reviewer")
        rejected_time = world.signoff_for(root)["created_at"]
        assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404
        world.record_signoff(root, "approved", decided_by="reviewer")
    assert world.signoff_for(root)["created_at"] > rejected_time > original_review_time
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404

    next_goal = world.create_goal("First line", "First line\nSecond line", parent_id=root)
    world.set_goal_status(next_goal, "done", result="A reply")
    world.append_turn(conversation_id, "user", "First line\nSecond line", goal_id=next_goal)
    world.append_turn(conversation_id, "assistant", "A reply", goal_id=next_goal)
    exact = _preview(client, next_goal).json()["source"]["transcript"][-2]
    assert exact["text"] == "First line\nSecond line"


def test_later_messages_do_not_expand_an_existing_conversation_link(space):
    client, world = space
    root, latest, conversation_id = _conversation(world)
    created = _mint(client, latest, _preview(client, latest).json())
    token = created.json()["url"].split("/share/")[1]
    newer = world.create_goal("A later private question", parent_id=root)
    world.set_goal_status(newer, "done", result="A later private answer")
    world.append_turn(conversation_id, "user", "A later private question", goal_id=newer)
    world.append_turn(conversation_id, "assistant", "A later private answer", goal_id=newer)
    page = TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}")
    assert page.status_code == 200
    assert "Final answer" in page.text
    assert "A later private question" not in page.text
    assert _preview(client, latest).status_code == 409


def test_earlier_stopped_message_without_answer_is_visible_without_technical_detail(space):
    client, world = space
    root = world.create_goal("Earlier request")
    world.set_goal_status(root, "blocked", result="ConnectError: provider unavailable at C:\\private\\service")
    conversation = world.get_or_create_conversation("web", f"local/{root}")
    world.append_turn(conversation.id, "user", "Earlier request", goal_id=root)
    latest = world.create_goal("Try something else", parent_id=root)
    world.set_goal_status(latest, "done", result="A later answer")
    world.append_turn(conversation.id, "user", "Try something else", goal_id=latest)
    world.append_turn(conversation.id, "assistant", "A later answer", goal_id=latest)

    preview = _preview(client, latest)
    assert preview.status_code == 200, preview.text
    turns = preview.json()["source"]["transcript"]
    assert [turn["role"] for turn in turns] == ["user", "assistant", "user", "assistant"]
    assert turns[1]["stopped"] is True
    assert "couldn't reach the AI service" in turns[1]["text"]
    assert "C:\\private\\service" not in str(turns)
    created = _mint(client, latest, preview.json())
    page = TestClient(app, base_url="http://127.0.0.1").get(created.json()["url"])
    assert page.status_code == 200
    assert "Lightwork · stopped" in page.text
    assert "C:\\private\\service" not in page.text


def test_earlier_stopped_saved_answer_is_labeled_as_stopped(space):
    client, world = space
    root = world.create_goal("Earlier request")
    world.set_goal_status(root, "blocked", result="ConnectError: provider unavailable at C:\\private\\service")
    conversation = world.get_or_create_conversation("web", f"local/{root}")
    world.append_turn(conversation.id, "user", "Earlier request", goal_id=root)
    world.append_turn(conversation.id, "assistant", "Raw provider detail must stay private", goal_id=root)
    latest = world.create_goal("Try something else", parent_id=root)
    world.set_goal_status(latest, "done", result="A later answer")
    world.append_turn(conversation.id, "user", "Try something else", goal_id=latest)
    world.append_turn(conversation.id, "assistant", "A later answer", goal_id=latest)

    preview = _preview(client, latest)
    assert preview.status_code == 200, preview.text
    stopped = preview.json()["source"]["transcript"][1]
    assert stopped["stopped"] is True
    assert "couldn't reach the AI service" in stopped["text"]
    assert "Raw provider detail" not in str(preview.json())
    created = _mint(client, latest, preview.json())
    page = TestClient(app, base_url="http://127.0.0.1").get(created.json()["url"])
    assert page.status_code == 200
    assert "Lightwork · stopped" in page.text
    assert "Raw provider detail" not in page.text


def test_no_web_binding_or_unreleased_prior_answer_refuses_conversation_share(space):
    client, world = space
    plain = world.create_goal("Ordinary task")
    world.set_goal_status(plain, "done", result="A result")
    assert _preview(client, plain).status_code == 409

    root = world.create_goal("Reviewed forecast", domain="finance_cash13w")
    world.set_goal_status(root, "done", result="Private earlier forecast")
    conversation = world.get_or_create_conversation("web", f"local/{root}")
    world.append_turn(conversation.id, "user", "Reviewed forecast", goal_id=root)
    world.append_turn(conversation.id, "assistant", "Private earlier forecast", goal_id=root)
    latest = world.create_goal("Summarize the forecast", parent_id=root)
    world.set_goal_status(latest, "done", result="Public summary")
    world.append_turn(conversation.id, "user", "Summarize the forecast", goal_id=latest)
    world.append_turn(conversation.id, "assistant", "Public summary", goal_id=latest)
    assert _preview(client, latest).status_code == 409
    world.record_signoff(root, "approved", decided_by="reviewer")
    assert _preview(client, latest).status_code == 200
    world.set_goal_status(root, "done", result="Revised approved forecast")
    world.record_signoff(root, "approved", decided_by="reviewer")
    assert _preview(client, latest).status_code == 409  # old transcript is not the new approved version


def test_every_included_goal_is_checked_against_current_caller_access(space, monkeypatch):
    from maverick_dashboard import api

    client, world = space
    root, latest, _ = _conversation(world)
    original = api.assert_goal_access

    def deny_earlier(request, goal):
        if goal.id == root:
            raise HTTPException(403, "Earlier message is private.")
        return original(request, goal)

    monkeypatch.setattr(api, "assert_goal_access", deny_earlier)
    assert _preview(client, latest).status_code == 403
    assert not world.share_links_for_goal(latest)


def test_turn_and_byte_limits_fail_closed_even_for_an_existing_link(space, monkeypatch):
    from maverick_dashboard import deliverable_sharing as sharing

    client, _world = space
    _, latest, _ = _conversation(_world)
    reviewed = _preview(client, latest).json()
    created = _mint(client, latest, reviewed)
    assert created.status_code == 201
    token = created.json()["url"].split("/share/")[1]
    public = TestClient(app, base_url="http://127.0.0.1")

    # Two historical turns plus the selected message's user/assistant pair.
    monkeypatch.setattr(sharing, "MAX_CONVERSATION_TURNS", 4)
    assert _preview(client, latest).status_code == 200
    monkeypatch.setattr(sharing, "MAX_CONVERSATION_TURNS", 3)
    assert _preview(client, latest).status_code == 409
    assert public.get(f"/share/{token}").status_code == 404

    monkeypatch.setattr(sharing, "MAX_CONVERSATION_TURNS", 4)
    content = {key: value for key, value in reviewed["source"].items() if key != "sha256"}
    size = len(json.dumps(content, sort_keys=True, separators=(",", ":"), default=str).encode())
    monkeypatch.setattr(sharing, "MAX_CONVERSATION_BYTES", size)
    assert _preview(client, latest).status_code == 200
    monkeypatch.setattr(sharing, "MAX_CONVERSATION_BYTES", size - 1)
    assert _preview(client, latest).status_code == 409
    assert public.get(f"/share/{token}").status_code == 404
