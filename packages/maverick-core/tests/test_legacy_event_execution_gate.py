"""Pre-upgrade event work cannot cross either local or remote start boundary."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from maverick import event_admission
from maverick.event_admission import EventRegistryUnavailable, LegacyEventGoalHeld
from maverick.world_model import WorldModel


def _imap_binding(monkeypatch):
    from maverick_dashboard import event_poll, event_triggers_store, triggers_store

    trigger = {
        "name": "orders", "created": 1.0, "tenant": "", "owner": "user:alice",
        "source": "imap_email", "config": {
            "host": "mail.example.test", "username": "bot@example.test",
            "password_env": "SYNTHETIC_MAIL_PASSWORD",  # pragma: allowlist secret
            "trusted_authserv_id": "mx.example.test",
            "allowed_senders": "alice@example.test",
        },
        "params": {}, "template": "orders-template", "template_revision": "saved-revision",
        "flow": "", "flow_owner": "", "flow_revision": "",
    }
    current = [trigger]
    monkeypatch.setattr(
        event_triggers_store, "get_trigger",
        lambda name, *, tenant=None, strict=False: current[0] if name == "orders" else None,
    )
    monkeypatch.setattr(triggers_store, "bound_template", lambda _trigger: object())
    return current, event_poll._trigger_key(trigger)


def _admit_imap(world, generation, suffix):
    goal, _state = event_admission.admit(
        world, f"verified-email-{suffix}", f"Email {suffix}", "Verified sender",
        owner="user:alice", origin="orders", trigger_key=generation,
        origin_kind="event_v2",
    )
    return goal


def test_legacy_event_goal_is_held_at_both_execution_claims(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        local = world.create_goal("old local")
        world.record_goal_origin(local, "event", "orders")
        with pytest.raises(LegacyEventGoalHeld):
            world.set_goal_status(local, "active")
        assert world.get_goal(local).status == "blocked"

        remote = world.create_goal("old remote", owner="user:alice")
        world.record_goal_origin(remote, "event", "orders")
        assert not world.claim_goal_for_run(remote, expected_owner="user:bob")
        assert world.get_goal(remote).status == "pending"
        assert not world.claim_goal_for_run(remote, expected_owner="user:alice")
        assert world.get_goal(remote).status == "blocked"


def test_current_and_unrelated_goal_origins_still_start(tmp_path, monkeypatch):
    _current, generation = _imap_binding(monkeypatch)
    with WorldModel(tmp_path / "world.db") as world:
        current = _admit_imap(world, generation, "remote")
        assert world.claim_goal_for_run(current)
        assert world.get_goal(current).status == "active"

        local = _admit_imap(world, generation, "local")
        world.set_goal_status(local, "active")
        assert world.get_goal(local).status == "active"

        scheduled = world.create_goal("scheduled")
        world.record_goal_origin(scheduled, "schedule", "daily")
        world.set_goal_status(scheduled, "active")
        assert world.get_goal(scheduled).status == "active"


def test_current_event_without_durable_receipt_is_held_at_both_execution_claims(
    tmp_path, monkeypatch,
):
    _imap_binding(monkeypatch)
    with WorldModel(tmp_path / "world.db") as world:
        local = world.create_goal("missing receipt", owner="user:alice")
        world.record_goal_origin(local, "event_v2", "orders")
        with pytest.raises(LegacyEventGoalHeld):
            world.set_goal_status(local, "active")
        assert world.get_goal(local).status == "blocked"

        remote = world.create_goal("missing remote receipt", owner="user:alice")
        world.record_goal_origin(remote, "event_v2", "orders")
        assert not world.claim_goal_for_run(remote, expected_owner="user:alice")
        assert world.get_goal(remote).status == "blocked"


def test_pending_imap_template_goal_is_held_after_sender_policy_or_trigger_changes(
    tmp_path, monkeypatch,
):
    current, generation = _imap_binding(monkeypatch)
    with WorldModel(tmp_path / "world.db") as world:
        changed = _admit_imap(world, generation, "changed")
        current[0] = {
            **current[0],
            "config": {**current[0]["config"], "allowed_senders": "bob@example.test"},
        }
        with pytest.raises(LegacyEventGoalHeld):
            world.set_goal_status(changed, "active")
        assert world.get_goal(changed).status == "blocked"

        current[0] = None
        deleted = _admit_imap(world, generation, "deleted")
        assert not world.claim_goal_for_run(deleted, expected_owner="user:alice")
        assert world.get_goal(deleted).status == "blocked"


def test_already_active_legacy_event_is_not_retroactively_blocked(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        goal = world.create_goal("already started")
        world.set_goal_status(goal, "active")
        world.record_goal_origin(goal, "event", "orders")
        world.set_goal_status(goal, "running")
        assert world.get_goal(goal).status == "running"


def _stored_event(tmp_path, monkeypatch):
    from maverick.templates import Template
    from maverick_dashboard import event_poll, event_triggers_store, triggers_store

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    template = triggers_store.snapshot_from_template(
        Template(name="orders-template", title="Order {{title}}",
                 body="Process {{title}}", params=["title"]),
    )
    trigger = event_triggers_store.set_trigger(
        "orders", "orders-template", "http_json", owner="user:alice",
        config={"url": "https://first.example.test"}, template_snapshot=template,
    )
    world = WorldModel(tmp_path / "world.db")
    goal, _ = event_admission.admit(
        world, "event-one", "Order one", "Process one", owner="user:alice",
        origin="orders", trigger_key=event_poll._trigger_key(trigger),
        origin_kind="event_v2",
    )
    return world, goal, template


@pytest.mark.parametrize("start", ["claim", "status"])
def test_trigger_edit_waits_for_event_execution_claim(tmp_path, monkeypatch, start):
    from maverick import world_model
    from maverick_dashboard import event_triggers_store

    world, goal, template = _stored_event(tmp_path, monkeypatch)
    validated = Event()
    release_claim = Event()
    edit_started = Event()
    edit_finished = Event()
    original = world_model.compatible_event_goal

    def paused_proof(*args):
        result = original(*args)
        validated.set()
        assert release_claim.wait(5)
        return result

    def edit():
        edit_started.set()
        event_triggers_store.set_trigger(
            "orders", "orders-template", "http_json", owner="user:alice",
            config={"url": "https://second.example.test"},
            template_snapshot=template,
        )
        edit_finished.set()

    def claim():
        if start == "status":
            world.set_goal_status(goal, "active")
            return True
        return world.claim_goal_for_run(goal, expected_owner="user:alice")

    monkeypatch.setattr(world_model, "compatible_event_goal", paused_proof)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            started = pool.submit(claim)
            assert validated.wait(5)
            edited = pool.submit(edit)
            assert edit_started.wait(5)
            assert not edit_finished.wait(0.1)
            release_claim.set()
            assert started.result(timeout=5) is True
            edited.result(timeout=5)
        assert world.get_goal(goal).status == "active"
    finally:
        release_claim.set()
        world.close()


@pytest.mark.parametrize("start", ["claim", "status"])
def test_event_claim_rechecks_after_trigger_edit_wins(tmp_path, monkeypatch, start):
    from maverick_dashboard import event_triggers_store

    world, goal, template = _stored_event(tmp_path, monkeypatch)
    edit_holds_lock = Event()
    release_edit = Event()
    original_write = event_triggers_store._write

    def paused_write(triggers):
        edit_holds_lock.set()
        assert release_edit.wait(5)
        original_write(triggers)

    def edit():
        event_triggers_store.set_trigger(
            "orders", "orders-template", "http_json", owner="user:alice",
            config={"url": "https://second.example.test"},
            template_snapshot=template,
        )

    def claim():
        if start == "status":
            with pytest.raises(LegacyEventGoalHeld):
                world.set_goal_status(goal, "active")
            return False
        return world.claim_goal_for_run(goal, expected_owner="user:alice")

    monkeypatch.setattr(event_triggers_store, "_write", paused_write)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            edited = pool.submit(edit)
            assert edit_holds_lock.wait(5)
            started = pool.submit(claim)
            assert not started.done()
            release_edit.set()
            edited.result(timeout=5)
            assert started.result(timeout=5) is False
        assert world.get_goal(goal).status == "blocked"
    finally:
        release_edit.set()
        world.close()


@pytest.mark.parametrize("start", ["claim", "status"])
def test_event_origin_appearing_after_preflight_is_retried(tmp_path, monkeypatch, start):
    world, goal, _ = _stored_event(tmp_path, monkeypatch)
    original = world._read_one
    calls = 0

    def stale_preflight(sql, params=()):
        nonlocal calls
        calls += 1
        if calls == 1:
            return None
        return original(sql, params)

    monkeypatch.setattr(world, "_read_one", stale_preflight)
    try:
        with pytest.raises(EventRegistryUnavailable, match="binding changed"):
            if start == "claim":
                world.claim_goal_for_run(goal, expected_owner="user:alice")
            else:
                world.set_goal_status(goal, "active")
        assert world.get_goal(goal).status == "pending"
    finally:
        world.close()


@pytest.mark.parametrize("start", ["claim", "status"])
def test_event_origin_disappearing_after_preflight_is_not_started(tmp_path, monkeypatch, start):
    world, goal, _ = _stored_event(tmp_path, monkeypatch)
    original = world._read_one

    def disappearing_preflight(sql, params=()):
        row = original(sql, params)
        world.conn.execute("DELETE FROM goal_origins WHERE goal_id=?", (goal,))
        world.conn.commit()
        return row

    monkeypatch.setattr(world, "_read_one", disappearing_preflight)
    try:
        with pytest.raises(EventRegistryUnavailable, match="origin disappeared"):
            if start == "claim":
                world.claim_goal_for_run(goal, expected_owner="user:alice")
            else:
                world.set_goal_status(goal, "active")
        assert world.get_goal(goal).status == "pending"
    finally:
        world.close()


@pytest.mark.parametrize("start", ["claim", "status"])
def test_event_start_refuses_nested_world_transaction(tmp_path, monkeypatch, start):
    world, goal, _ = _stored_event(tmp_path, monkeypatch)
    try:
        with world._writing():
            with pytest.raises(EventRegistryUnavailable, match="outside a world transaction"):
                if start == "claim":
                    world.claim_goal_for_run(goal, expected_owner="user:alice")
                else:
                    world.set_goal_status(goal, "active")
        assert world.get_goal(goal).status == "pending"
    finally:
        world.close()


@pytest.mark.parametrize("start", ["claim", "status"])
def test_registry_lock_failure_leaves_event_pending_for_retry(tmp_path, monkeypatch, start):
    from maverick_dashboard import event_triggers_store

    world, goal, _ = _stored_event(tmp_path, monkeypatch)

    def unavailable():
        raise OSError("synthetic registry lock failure")

    monkeypatch.setattr(event_triggers_store, "registry_lock", unavailable)
    try:
        with pytest.raises(EventRegistryUnavailable, match="lock is unavailable"):
            if start == "claim":
                world.claim_goal_for_run(goal, expected_owner="user:alice")
            else:
                world.set_goal_status(goal, "active")
        assert world.get_goal(goal).status == "pending"
    finally:
        world.close()
