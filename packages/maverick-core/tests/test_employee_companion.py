"""Companion authority regression cases. No model or connector calls are used."""
from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from maverick import crypto_at_rest, employee_companion, file_lock
from maverick.employee_companion import (
    CompanionConflictError,
    CompanionError,
    CompanionPolicyDenied,
    CompanionValidationError,
    EmployeeCompanionStore,
)
from maverick.paths import tenant_scope

ALICE = "user:alice"
BOB = "user:bob"
ADMIN = "user:admin"


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    # A synthetic test-only at-rest key; no deployment credentials are read.
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "27" * 32)
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", tmp_path / "unused.key")
    with tenant_scope(tenant="companion-acme"):
        yield EmployeeCompanionStore()


def _enable(store, owner=ALICE, **overrides):
    values = {
        "actor": ADMIN, "expected_revision": store.policy(owner)["revision"],
        "enabled": True, "allowed_sources": ["own_tasks"],
        "allowed_tools": ["task_status"], "retention_days": 1,
    }
    values.update(overrides)
    return store.update_policy(owner, **values)


def _reply(store, owner=ALICE, **overrides):
    values = {
        "message": "Private employee question", "response": "You have one active task.",
        "source_refs": ["task:17"], "expected_revision": store.policy(owner)["revision"],
    }
    values.update(overrides)
    return store.record_exchange(owner, **values)


def _state(store, owner=ALICE):
    return json.loads(file_lock.atomic_read_text(store._path(owner)))


def _write_state(store, state, owner=ALICE):
    file_lock.atomic_write_text(store._path(owner), json.dumps(state))


def test_default_policy_is_disabled_private_read_only_and_has_no_saved_history(store):
    policy = store.policy(ALICE)
    assert policy["revision"] == 0
    assert policy["enabled"] is False
    assert policy["allowed_sources"] == policy["allowed_tools"] == []
    assert policy["retention_days"] == 0
    assert policy["memory_enabled"] is policy["admin_content_access"] is False
    assert policy["action_mode"] == "read_only"
    assert policy["approvals"] == "writes_blocked"
    assert store.history(ALICE) == store.policies() == store.events() == []
    with pytest.raises(CompanionPolicyDenied):
        _reply(store)


def test_employee_records_and_encrypted_histories_are_separate(store):
    _enable(store)
    _enable(store, BOB)
    alice_reply = _reply(store, message="Alice private planning")
    bob_reply = _reply(store, BOB, message="Bob private planning")
    assert store.history(ALICE) == alice_reply["history"]
    assert store.history(BOB) == bob_reply["history"]
    assert store._path(ALICE) != store._path(BOB)
    for owner, secret in [(ALICE, "Alice private planning"), (BOB, "Bob private planning")]:
        raw = file_lock.atomic_read_text(store._path(owner))
        assert secret not in raw
        assert "You have one active task." not in raw
        assert "task:17" not in raw
        assert owner not in store._path(owner).name


def test_reused_store_refuses_changed_tenant_and_new_tenant_has_no_access(store):
    _enable(store)
    _reply(store)
    with tenant_scope(tenant="companion-beta"):
        other = EmployeeCompanionStore()
        assert other.policy(ALICE)["enabled"] is False
        assert other.history(ALICE) == []
        assert other.policies() == other.events() == []
        operations = [
            lambda: store.policy(ALICE), store.policies, store.events,
            lambda: store.history(ALICE), lambda: _enable(store),
            lambda: _reply(store), lambda: store.clear_history(ALICE, actor=ALICE),
        ]
        for operation in operations:
            with pytest.raises(CompanionError, match="tenant context changed"):
                operation()
    assert len(store.history(ALICE)) == 1


def test_named_tenant_is_required(monkeypatch):
    monkeypatch.setattr(employee_companion, "current_tenant_id_strict", lambda: None)
    with pytest.raises(CompanionError, match="named workspace"):
        EmployeeCompanionStore()


def test_reused_store_refuses_changed_storage_root(store, tmp_path, monkeypatch):
    _enable(store)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "replacement"))
    with pytest.raises(CompanionError, match="storage root changed"):
        store.history(ALICE)


def test_policy_and_history_files_use_existing_private_permissions(store):
    _enable(store)
    _reply(store)
    assert file_lock.private_path_is_restricted(store.root, 0o700)
    assert file_lock.private_path_is_restricted(store._path(ALICE), 0o600)


@pytest.mark.parametrize("replicas", ["2", "0", "", "garbage"])
def test_multi_replica_or_invalid_topology_is_refused_at_every_operation(store, monkeypatch, replicas):
    _enable(store)
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", replicas)
    with pytest.raises(CompanionError, match="one control-plane replica"):
        store.policy(ALICE)
    with pytest.raises(CompanionError, match="one control-plane replica"):
        EmployeeCompanionStore()


def test_copied_ciphertext_cannot_open_for_another_employee_or_tenant(store):
    _enable(store)
    _enable(store, BOB)
    _reply(store)
    ciphertext = _state(store)["history"]
    bob = _state(store, BOB)
    bob["history"] = ciphertext
    _write_state(store, bob, BOB)
    with pytest.raises(CompanionError):
        store.history(BOB)
    with tenant_scope(tenant="companion-beta"):
        other = EmployeeCompanionStore()
        _enable(other)
        state = _state(other)
        state["history"] = ciphertext
        _write_state(other, state)
        with pytest.raises(CompanionError):
            other.history(ALICE)


def test_policy_compare_and_swap_and_reply_revision_fence(store):
    first = _enable(store)
    second = _enable(store, enabled=False)
    before = file_lock.atomic_read_text(store._path(ALICE))
    with pytest.raises(CompanionConflictError):
        _enable(store, expected_revision=first["revision"])
    with pytest.raises(CompanionConflictError):
        _reply(store, expected_revision=first["revision"])
    with pytest.raises(CompanionPolicyDenied):
        _reply(store, expected_revision=second["revision"])
    assert file_lock.atomic_read_text(store._path(ALICE)) == before


def test_independent_store_writers_cannot_both_win_same_policy_revision(store):
    policy = _enable(store)
    barrier = Barrier(2)

    def update(retention_days):
        with tenant_scope(tenant="companion-acme"):
            independent = EmployeeCompanionStore()
            barrier.wait(timeout=30)
            try:
                return _enable(independent, expected_revision=policy["revision"],
                               retention_days=retention_days)
            except CompanionConflictError:
                return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(update, [7, 30]))
    assert sum(result is not None for result in results) == 1
    assert store.policy(ALICE)["revision"] == policy["revision"] + 1
    assert len(store.events()) == 2


@pytest.mark.parametrize("override", [
    {"allowed_sources": ["all_company_documents"]}, {"allowed_tools": ["send_email"]},
    {"allowed_sources": ["own_tasks", "own_tasks"]}, {"allowed_tools": "task_status"},
    {"retention_days": 365}, {"retention_days": True}, {"enabled": "true"},
    {"expected_revision": True},
])
def test_unsupported_or_ambiguous_policy_values_are_rejected(store, override):
    with pytest.raises(CompanionValidationError):
        _enable(store, **override)
    assert store.policies() == []


@pytest.mark.parametrize("field,value", [
    ("memory_enabled", True), ("admin_content_access", True),
    ("action_mode", "write"), ("approvals", "skip"),
])
def test_capability_expanding_fields_cannot_be_passed_to_policy_update(store, field, value):
    with pytest.raises(TypeError):
        _enable(store, **{field: value})
    assert store.policies() == []


def test_task_source_references_require_both_policy_grants(store):
    _enable(store, allowed_tools=[])
    with pytest.raises(CompanionPolicyDenied):
        _reply(store)
    with pytest.raises(CompanionPolicyDenied):
        _reply(store, source_refs=[])
    _enable(store, allowed_sources=[])
    with pytest.raises(CompanionPolicyDenied):
        _reply(store)


def test_zero_retention_saves_only_event_metadata_without_encryption_call(store, monkeypatch):
    _enable(store, retention_days=0)

    def refuse_seal(*args, **kwargs):
        raise AssertionError("zero retention must not seal or persist conversations")

    monkeypatch.setattr(crypto_at_rest, "seal_bound", refuse_seal)
    reply = _reply(store)
    assert reply["history"] == []
    assert reply["trace"]["reason"] == "owner_and_policy"
    assert _state(store)["history"] is None
    assert "Private employee question" not in file_lock.atomic_read_text(store._path(ALICE))


def test_admin_policy_and_events_never_decrypt_or_return_private_content(store, monkeypatch):
    _enable(store)
    _reply(store, message="Sensitive personnel matter")

    def refuse_open(*args, **kwargs):
        raise AssertionError("administrative metadata must not decrypt history")

    monkeypatch.setattr(crypto_at_rest, "unseal_bound", refuse_open)
    metadata = {"policies": store.policies(), "events": store.events(), "policy": store.policy(ALICE)}
    rendered = json.dumps(metadata)
    assert "Sensitive personnel matter" not in rendered
    assert "You have one active task." not in rendered
    assert "task:17" not in rendered
    assert "history" not in metadata["policies"][0]
    assert {event["action"] for event in metadata["events"]} == {"policy_updated", "reply"}


@pytest.mark.parametrize("operation", ["policy", "reply", "delete"])
def test_required_audit_and_mutation_fail_together_on_publication_failure(store, monkeypatch, operation):
    _enable(store)
    _reply(store)
    before = file_lock.atomic_read_text(store._path(ALICE))

    def failed_write(*args, **kwargs):
        raise OSError("simulated durable write failure")

    monkeypatch.setattr(file_lock, "atomic_write_text", failed_write)
    with pytest.raises(CompanionError, match="storage is unavailable"):
        if operation == "policy":
            _enable(store, retention_days=0)
        elif operation == "reply":
            _reply(store, message="This must not be saved")
        else:
            store.clear_history(ALICE, actor=ALICE)
    assert file_lock.atomic_read_text(store._path(ALICE)) == before


def test_encryption_failure_never_falls_back_to_plaintext_or_records_success(store, monkeypatch):
    _enable(store)
    before = file_lock.atomic_read_text(store._path(ALICE))

    def failed_seal(*args, **kwargs):
        raise crypto_at_rest.EncryptionUnavailable("simulated unavailable encryption")

    monkeypatch.setattr(crypto_at_rest, "seal_bound", failed_seal)
    with pytest.raises(CompanionError):
        _reply(store)
    assert file_lock.atomic_read_text(store._path(ALICE)) == before


def test_history_expiry_removes_ciphertext_and_keeps_only_metadata(store, monkeypatch):
    clock = [1000000.0]
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock[0])
    _enable(store)
    _reply(store)
    clock[0] += 86400
    assert store.history(ALICE) == []
    assert _state(store)["history"] is None
    assert store.events()[-1]["action"] == "history_expired"


def test_shorter_retention_cannot_be_undone_by_later_retention_increase(store, monkeypatch):
    clock = [1000000.0]
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock[0])
    _enable(store, retention_days=30)
    _reply(store)
    _enable(store, retention_days=1)
    assert store.history(ALICE)[0]["expires_at"] == clock[0] + 86400
    _enable(store, retention_days=30)
    clock[0] += 86400
    assert store.history(ALICE) == []


def test_retention_increase_does_not_resurrect_expired_content(store, monkeypatch):
    clock = [1000000.0]
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock[0])
    _enable(store, retention_days=1)
    _reply(store)
    clock[0] += 86400
    _enable(store, retention_days=30)
    assert store.history(ALICE) == []


@pytest.mark.parametrize("override", [{"enabled": False}, {"retention_days": 0}])
def test_disabling_retention_or_companion_erases_saved_history(store, override):
    _enable(store)
    _reply(store)
    _enable(store, **override)
    assert store.history(ALICE) == []
    assert _state(store)["history"] is None


def test_clear_history_is_owner_only_and_does_not_change_another_employee(store, monkeypatch):
    _enable(store)
    _enable(store, BOB)
    _reply(store)
    _reply(store, BOB)
    bob_before = file_lock.atomic_read_text(store._path(BOB))
    with pytest.raises(CompanionPolicyDenied):
        store.clear_history(ALICE, actor=ADMIN)

    def unavailable_key(*args, **kwargs):
        raise crypto_at_rest.EncryptionUnavailable("key unavailable")

    monkeypatch.setattr(crypto_at_rest, "unseal_bound", unavailable_key)
    event = store.clear_history(ALICE, actor=ALICE)
    assert event["action"] == "history_cleared"
    assert store.history(ALICE) == []
    assert _state(store)["history"] is None
    assert file_lock.atomic_read_text(store._path(BOB)) == bob_before


@pytest.mark.parametrize("corruption", ["policy", "identity", "audit", "plaintext", "missing_audit"])
def test_corrupt_authority_is_refused_without_resetting_policy(store, corruption):
    _enable(store)
    state = _state(store)
    if corruption == "policy":
        state["policy"]["admin_content_access"] = True
    elif corruption == "identity":
        state["tenant"] = "some-other-workspace"
    elif corruption == "audit":
        state["events"][0]["message"] = "private content does not belong here"
    elif corruption == "plaintext":
        state["history"] = "unencrypted conversation"
    else:
        state["events"] = []
    _write_state(store, state)
    before = file_lock.atomic_read_text(store._path(ALICE))
    for operation in [lambda: store.policy(ALICE), store.policies, store.events,
                      lambda: store.history(ALICE), lambda: _enable(store)]:
        with pytest.raises(CompanionError):
            operation()
    assert file_lock.atomic_read_text(store._path(ALICE)) == before


def test_duplicate_json_fields_are_refused(store):
    _enable(store)
    raw = file_lock.atomic_read_text(store._path(ALICE))
    file_lock.atomic_write_text(store._path(ALICE), raw.replace('"version":2', '"version":2,"version":2'))
    with pytest.raises(CompanionError):
        store.policy(ALICE)


def test_history_and_metadata_journals_are_bounded(store, monkeypatch):
    monkeypatch.setattr(employee_companion, "MAX_HISTORY", 2)
    monkeypatch.setattr(employee_companion, "MAX_EVENTS", 3)
    _enable(store)
    for index in range(5):
        _reply(store, message=f"Question {index}")
    assert [entry["message"] for entry in store.history(ALICE)] == ["Question 3", "Question 4"]
    assert len(_state(store)["events"]) == len(store.events()) == 3


def test_employee_capacity_blocks_new_records_but_preserves_existing_ones(store, monkeypatch):
    monkeypatch.setattr(employee_companion, "MAX_EMPLOYEES", 1)
    _enable(store)
    with pytest.raises(CompanionError, match="capacity"):
        _enable(store, BOB)
    assert len(store.policies()) == 1
    assert _reply(store)["trace"]["owner"] == ALICE


@pytest.mark.parametrize("owner", ["", "alice", "service:alice", "user:", "user:\n../bob"])
def test_owner_must_be_an_exact_authenticated_employee_identity(store, owner):
    with pytest.raises(CompanionValidationError):
        store.policy(owner)


@pytest.mark.parametrize("override", [
    {"message": "x" * (employee_companion.MAX_MESSAGE + 1)},
    {"response": "x" * (employee_companion.MAX_RESPONSE + 1)},
    {"source_refs": ["https://private-document.invalid"]},
    {"source_refs": ["task:17", "task:17"]}, {"source_refs": ["task:-1"]},
])
def test_exchange_size_and_source_reference_contract(store, override):
    _enable(store)
    before = file_lock.atomic_read_text(store._path(ALICE))
    with pytest.raises(CompanionValidationError):
        _reply(store, **override)
    assert file_lock.atomic_read_text(store._path(ALICE)) == before


def _enable_draft(store, owner=ALICE, **overrides):
    values = {"allowed_sources": [], "allowed_tools": ["draft_reply"]}
    values.update(overrides)
    return _enable(store, owner, **values)


def _request_id(at=None):
    return f"{int((employee_companion.time.time() if at is None else at) * 1000)}.{uuid.uuid4().hex}"


def _reserve(store, owner=ALICE, **overrides):
    values = {"request_id": _request_id(), "expected_revision": store.policy(owner)["revision"],
              "expected_history_generation": store.conversation_state(owner)["history_generation"],
              "fingerprint": "ab" * 32}
    values.update(overrides)
    return store.reserve_turn(owner, **values)


def _ticket_args(ticket):
    return {"request_id": ticket["request_id"], "token": ticket["token"],
            "expected_revision": ticket["revision"], "history_generation": ticket["history_generation"]}


def _finish(store, ticket, owner=ALICE, **overrides):
    values = {**_ticket_args(ticket), "message": "Help draft my plan", "response": "Draft: outline next steps.",
              "source_refs": [], "model_route": "configured-provider/configured-model"}
    values.update(overrides)
    return store.finish_turn(owner, **values)


def test_legacy_records_are_read_without_enabling_drafts_and_upgrade_on_write(store):
    _enable(store)
    _reply(store)
    state = _state(store)
    history = store.history(ALICE)
    for entry in history:
        entry.pop("kind")
        entry.pop("model_route")
    store._set_history(state, history)
    for field in ("turns", "turn_clock", "history_generation"):
        state.pop(field)
    state["version"] = 1
    _write_state(store, state)
    before = file_lock.atomic_read_text(store._path(ALICE))
    assert store.policy(ALICE)["allowed_tools"] == ["task_status"]
    assert store.history(ALICE)[0]["kind"] == "task_status"
    assert store.history(ALICE)[0]["model_route"] is None
    assert store.conversation_state(ALICE) == {"history_generation": 0, "active_turn": None}
    assert file_lock.atomic_read_text(store._path(ALICE)) == before
    with pytest.raises(CompanionPolicyDenied):
        _reserve(store)
    store.clear_history(ALICE, actor=ALICE)
    assert _state(store)["version"] == 2
    assert _state(store)["history_generation"] == 1


def test_draft_permission_is_separate_from_task_status_and_task_sources(store):
    _enable(store)
    with pytest.raises(CompanionPolicyDenied):
        _reserve(store)
    _enable_draft(store)
    ticket = _reserve(store)
    result = _finish(store, ticket)
    assert result["response"] == "Draft: outline next steps."
    assert result["trace"]["action"] == "draft_reply"
    assert result["history"][-1]["kind"] == "draft"
    assert result["history"][-1]["model_route"] == "configured-provider/configured-model"
    with pytest.raises(CompanionPolicyDenied):
        _reply(store)


def test_draft_task_context_requires_own_tasks_but_not_status_tool(store):
    _enable_draft(store)
    denied = _reserve(store)
    with pytest.raises(CompanionPolicyDenied):
        _finish(store, denied, source_refs=["task:17"])
    store.abandon_turn(ALICE, request_id=denied["request_id"], token=denied["token"])
    _enable_draft(store, allowed_sources=["own_tasks"])
    allowed = _reserve(store)
    assert _finish(store, allowed, source_refs=["task:17"])["source_refs"] == ["task:17"]


def test_duplicate_request_never_gets_another_dispatch_ticket(store):
    _enable_draft(store)
    ticket = _reserve(store)
    duplicate = _reserve(store, request_id=ticket["request_id"])
    assert ticket["acquired"] is True
    assert duplicate["acquired"] is False
    assert duplicate["state"] == "pending"
    assert "token" not in duplicate
    with pytest.raises(CompanionConflictError, match="another message"):
        _reserve(store, request_id=ticket["request_id"], fingerprint="cd" * 32)
    with pytest.raises(CompanionConflictError, match="still replying"):
        _reserve(store)
    assert len(_state(store)["turns"]) == 1


def test_independent_workers_admit_only_one_dispatch_for_duplicate_request(store):
    _enable_draft(store)
    request_id = _request_id()
    barrier = Barrier(2)

    def reserve(_index):
        with tenant_scope(tenant="companion-acme"):
            independent = EmployeeCompanionStore()
            barrier.wait(timeout=30)
            return _reserve(independent, request_id=request_id)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(reserve, [0, 1]))
    assert sum(result["acquired"] for result in results) == 1
    assert len([event for event in store.events() if event["action"] == "turn_started"]) == 1


def test_success_is_published_once_and_completed_id_cannot_dispatch_again(store):
    _enable_draft(store)
    ticket = _reserve(store)
    assert store.validate_turn(ALICE, **_ticket_args(ticket))["state"] == "pending"
    result = _finish(store, ticket)
    assert len(result["history"]) == 1
    assert store.turn_status(ALICE, ticket["request_id"])["state"] == "completed"
    assert store.conversation_state(ALICE)["active_turn"] is None
    with pytest.raises(CompanionConflictError):
        _finish(store, ticket)
    duplicate = _reserve(store, request_id=ticket["request_id"])
    assert duplicate["state"] == "completed"
    assert duplicate["acquired"] is False
    assert "token" not in duplicate
    assert len(store.history(ALICE)) == 1


def test_turn_ticket_is_bound_to_employee_and_secret(store):
    _enable_draft(store)
    _enable_draft(store, BOB)
    ticket = _reserve(store)
    with pytest.raises(CompanionConflictError):
        store.validate_turn(BOB, **_ticket_args(ticket))
    with pytest.raises(CompanionConflictError):
        _finish(store, ticket, token="cd" * 16)
    assert store.turn_status(BOB, ticket["request_id"])["state"] == "not_started"
    assert store.history(BOB) == []


def test_clearing_empty_history_cancels_pending_reply_and_refuses_queued_old_generation(store):
    _enable_draft(store, retention_days=0)
    ticket = _reserve(store)
    store.clear_history(ALICE, actor=ALICE)
    generation = store.conversation_state(ALICE)["history_generation"]
    assert generation == ticket["history_generation"] + 1
    assert store.turn_status(ALICE, ticket["request_id"])["state"] == "cancelled"
    with pytest.raises(CompanionConflictError):
        store.validate_turn(ALICE, **_ticket_args(ticket))
    with pytest.raises(CompanionConflictError):
        _finish(store, ticket)
    with pytest.raises(CompanionConflictError):
        _reserve(store, expected_history_generation=ticket["history_generation"])
    assert store.history(ALICE) == []
    assert _state(store)["history"] is None


@pytest.mark.parametrize("override", [
    {"enabled": False}, {"allowed_tools": []}, {"retention_days": 7}, {},
])
def test_every_policy_change_invalidates_pending_model_turn(store, override):
    _enable_draft(store)
    ticket = _reserve(store)
    _enable_draft(store, **override)
    assert store.turn_status(ALICE, ticket["request_id"])["state"] == "cancelled"
    with pytest.raises(CompanionConflictError):
        _finish(store, ticket)
    assert store.history(ALICE) == []
    assert _reserve(store, request_id=ticket["request_id"])["acquired"] is False


def test_failed_turn_is_consumed_and_does_not_retry(store):
    _enable_draft(store)
    ticket = _reserve(store)
    failed = store.abandon_turn(ALICE, request_id=ticket["request_id"], token=ticket["token"])
    assert failed["state"] == "failed"
    assert _reserve(store, request_id=ticket["request_id"])["acquired"] is False
    with pytest.raises(CompanionConflictError):
        _finish(store, ticket)
    assert _reserve(store)["acquired"] is True


def test_expired_lease_is_consumed_and_late_completion_cannot_publish(store, monkeypatch):
    clock = [1000000.0]
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock[0])
    _enable_draft(store)
    ticket = _reserve(store)
    clock[0] += employee_companion.TURN_LEASE_SECONDS
    assert store.turn_status(ALICE, ticket["request_id"])["state"] == "expired"
    assert store.conversation_state(ALICE)["active_turn"] is None
    assert _reserve(store, request_id=ticket["request_id"])["acquired"] is False
    with pytest.raises(CompanionConflictError):
        _finish(store, ticket)
    assert store.history(ALICE) == []


def test_lease_expiring_during_encryption_cannot_publish_a_reply(store, monkeypatch):
    clock = [1000000.0]
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock[0])
    _enable_draft(store)
    ticket = _reserve(store)
    seal = crypto_at_rest.seal_bound

    def delayed_seal(*args, **kwargs):
        blob = seal(*args, **kwargs)
        clock[0] = ticket["expires_at"]
        return blob

    monkeypatch.setattr(crypto_at_rest, "seal_bound", delayed_seal)
    with pytest.raises(CompanionConflictError, match="expired"):
        _finish(store, ticket)
    assert store.history(ALICE) == []
    assert store.turn_status(ALICE, ticket["request_id"])["state"] == "expired"


def test_context_expiring_during_model_call_invalidates_completion(store, monkeypatch):
    clock = [1000000.0]
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock[0])
    _enable_draft(store)
    first = _reserve(store)
    _finish(store, first)
    clock[0] += 86400 - 30
    second = _reserve(store)
    clock[0] += 30
    with pytest.raises(CompanionConflictError):
        _finish(store, second)
    assert store.history(ALICE) == []
    assert store.turn_status(ALICE, second["request_id"])["state"] == "cancelled"


def test_context_expiring_during_reply_sealing_invalidates_completion(store, monkeypatch):
    clock = [1000000.0]
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock[0])
    _enable_draft(store)
    first = _reserve(store)
    _finish(store, first)
    clock[0] += 86400 - 1
    second = _reserve(store)
    seal = crypto_at_rest.seal_bound

    def delayed_seal(*args, **kwargs):
        blob = seal(*args, **kwargs)
        clock[0] += 1
        return blob

    monkeypatch.setattr(crypto_at_rest, "seal_bound", delayed_seal)
    with pytest.raises(CompanionConflictError, match="context expired"):
        _finish(store, second)
    assert store.history(ALICE) == []
    assert store.turn_status(ALICE, second["request_id"])["state"] == "cancelled"
    assert len([event for event in store.events() if event["action"] == "draft_reply"]) == 1


def test_status_write_prunes_expired_context_and_rejects_old_queued_draft_generation(store, monkeypatch):
    clock = [1000000.0]
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock[0])
    _enable_draft(store, allowed_sources=["own_tasks"], allowed_tools=["task_status", "draft_reply"])
    _reply(store)
    old_generation = store.conversation_state(ALICE)["history_generation"]
    clock[0] += 86400
    _reply(store, message="Current task status")
    assert store.conversation_state(ALICE)["history_generation"] == old_generation + 1
    assert [item["message"] for item in store.history(ALICE)] == ["Current task status"]
    with pytest.raises(CompanionConflictError):
        _reserve(store, expected_history_generation=old_generation)


@pytest.mark.parametrize("offset", [-901, 61])
def test_stale_or_excessively_future_request_id_is_refused(store, monkeypatch, offset):
    clock = 1000000.0
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock)
    _enable_draft(store)
    with pytest.raises(CompanionConflictError, match="identifier expired"):
        _reserve(store, request_id=_request_id(clock + offset))
    assert _state(store)["turns"] == []


def test_pruning_old_receipts_and_clock_rollback_cannot_make_old_id_dispatchable(store, monkeypatch):
    clock = [1000000.0]
    monkeypatch.setattr(employee_companion.time, "time", lambda: clock[0])
    _enable_draft(store, retention_days=0)
    ticket = _reserve(store)
    store.abandon_turn(ALICE, request_id=ticket["request_id"], token=ticket["token"])
    clock[0] += employee_companion.TURN_RECEIPT_SECONDS
    assert store.turn_status(ALICE, ticket["request_id"])["state"] == "not_started"
    assert _state(store)["turns"] == []
    clock[0] -= employee_companion.TURN_RECEIPT_SECONDS
    with pytest.raises(CompanionConflictError, match="identifier expired"):
        _reserve(store, request_id=ticket["request_id"])


def test_receipt_capacity_refuses_new_paid_request_without_evicting_live_dedup_records(store, monkeypatch):
    monkeypatch.setattr(employee_companion, "MAX_TURN_RECEIPTS", 2)
    _enable_draft(store)
    tickets = []
    for _index in range(2):
        ticket = _reserve(store)
        tickets.append(ticket)
        store.abandon_turn(ALICE, request_id=ticket["request_id"], token=ticket["token"])
    with pytest.raises(CompanionError, match="capacity"):
        _reserve(store)
    assert _reserve(store, request_id=tickets[0]["request_id"])["acquired"] is False
    assert len(_state(store)["turns"]) == 2


@pytest.mark.parametrize("phase", ["reserve", "finish"])
def test_turn_state_and_required_audit_publish_atomically(store, monkeypatch, phase):
    _enable_draft(store)
    ticket = _reserve(store) if phase == "finish" else None
    before = file_lock.atomic_read_text(store._path(ALICE))

    def failed_write(*args, **kwargs):
        raise OSError("simulated unavailable durable audit")

    with monkeypatch.context() as patch:
        patch.setattr(file_lock, "atomic_write_text", failed_write)
        with pytest.raises(CompanionError):
            if ticket:
                _finish(store, ticket)
            else:
                _reserve(store)
    assert file_lock.atomic_read_text(store._path(ALICE)) == before
    if ticket:
        duplicate = _reserve(store, request_id=ticket["request_id"])
        assert duplicate["state"] == "pending" and duplicate["acquired"] is False
    else:
        assert store.conversation_state(ALICE)["active_turn"] is None


def test_zero_retention_draft_receipts_and_admin_events_never_store_text_or_lease_secrets(store):
    _enable_draft(store, retention_days=0)
    ticket = _reserve(store)
    result = _finish(store, ticket)
    assert result["history"] == []
    state = _state(store)
    assert state["history"] is None
    raw = json.dumps(state)
    assert "Help draft my plan" not in raw
    assert "Draft: outline next steps." not in raw
    metadata = json.dumps({"policies": store.policies(), "events": store.events(),
                           "conversation": store.conversation_state(ALICE),
                           "status": store.turn_status(ALICE, ticket["request_id"])})
    assert ticket["token"] not in metadata
    assert "ab" * 32 not in metadata


@pytest.mark.parametrize("model_route", ["", "provider/model?api_key=secret", "x" * 161, ["model"]])
def test_model_route_provenance_accepts_only_safe_bounded_identifiers(store, model_route):
    _enable_draft(store)
    ticket = _reserve(store)
    with pytest.raises(CompanionValidationError):
        _finish(store, ticket, model_route=model_route)
    assert store.turn_status(ALICE, ticket["request_id"])["state"] == "pending"


def test_task_status_cannot_append_while_model_reply_is_pending(store):
    _enable_draft(store, allowed_sources=["own_tasks"], allowed_tools=["task_status", "draft_reply"])
    _reserve(store)
    with pytest.raises(CompanionConflictError, match="still replying"):
        _reply(store)
    assert store.history(ALICE) == []


@pytest.mark.parametrize("corruption", ["generation", "overlap", "token", "clock"])
def test_corrupt_turn_authority_is_refused_without_issuing_another_ticket(store, corruption):
    _enable_draft(store)
    ticket = _reserve(store)
    state = _state(store)
    if corruption == "generation":
        state["turns"][0]["history_generation"] += 1
    elif corruption == "overlap":
        other = dict(state["turns"][0], request_id=_request_id(), token=uuid.uuid4().hex)
        state["turns"].append(other)
    elif corruption == "token":
        state["turns"][0]["token"] = "not-a-secret-ticket"
    else:
        state["turn_clock"] = 0
    _write_state(store, state)
    with pytest.raises(CompanionError):
        store.turn_status(ALICE, ticket["request_id"])
    with pytest.raises(CompanionError):
        _reserve(store)
