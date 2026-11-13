from __future__ import annotations

import json
import sqlite3

import pytest
from maverick import ai_entity_tasks as tasks


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _authority(clock: Clock, *, tenant: str = "tenant-a", revision: int = 4):
    return tasks.issue_entity_authority(
        tenant_id=tenant,
        entity_id="model.customer-support",
        entity_revision=revision,
        entity_type="model",
        issuer_ref="registry-authority",
        issued_at=clock.value - 60,
        valid_until=clock.value + 86_400,
    )


def _store(tmp_path, *, maintenance: dict[str, bool] | None = None):
    clock = Clock()
    current = {"value": _authority(clock)}
    actor = {"value": "principal.owner"}
    maintenance_state = maintenance if maintenance is not None else {"allowed": False}

    def resolve(tenant_id: str, entity_id: str, entity_revision: int):
        authority = current["value"]
        assert tenant_id == "tenant-a"
        assert entity_id == authority.entity_id
        assert entity_revision == authority.entity_revision
        return authority

    store = tasks.AIEntityTaskStore(
        tmp_path / "ai-entity-tasks.sqlite3",
        tenant_id="tenant-a",
        entity_authority_resolver=resolve,
        principal_resolver=lambda: actor["value"],
        maintenance_authorizer=lambda: maintenance_state["allowed"],
        config_gate=lambda: None,
        retention_seconds=3_600,
        clock=clock,
        id_factory=lambda: "AIT-test-task",
    )
    return store, clock, current, actor, maintenance_state


def test_task_lifecycle_history_filters_and_idempotency(tmp_path) -> None:
    store, clock, _current, actor, _maintenance = _store(tmp_path)

    created = store.create_task(
        "tenant-a",
        entity_id="model.customer-support",
        entity_revision=4,
        kind="remediation",
        title="Resolve unapproved retrieval source",
        description="Remove or independently approve the source binding.",
        assignee_ref="principal.reviewer",
        collaborator_refs=("principal.security", "principal.privacy"),
        priority="critical",
        idempotency_key="create-task-1",
    )
    replayed = store.create_task(
        "tenant-a",
        entity_id="model.customer-support",
        entity_revision=4,
        kind="remediation",
        title="Resolve unapproved retrieval source",
        description="Remove or independently approve the source binding.",
        assignee_ref="principal.reviewer",
        collaborator_refs=("principal.security", "principal.privacy"),
        priority="critical",
        idempotency_key="create-task-1",
    )
    assert replayed == created
    assert created.revision == 1
    assert created.status == "open"
    assert created.collaborator_refs == ("principal.privacy", "principal.security")

    actor["value"] = "principal.reviewer"
    updated = store.update_task(
        "tenant-a",
        created.task_id,
        expected_revision=1,
        changes={
            "status": "in_progress",
            "priority": "high",
            "assignee_ref": "principal.reviewer",
            "collaborator_refs": ["principal.security", "principal.owner"],
            "due_at": clock.value + 1_000,
        },
        idempotency_key="update-task-1",
    )
    replayed_update = store.update_task(
        "tenant-a",
        created.task_id,
        expected_revision=1,
        changes={
            "status": "in_progress",
            "priority": "high",
            "assignee_ref": "principal.reviewer",
            "collaborator_refs": ["principal.security", "principal.owner"],
            "due_at": clock.value + 1_000,
        },
        idempotency_key="update-task-1",
    )
    assert replayed_update == updated
    assert updated.revision == 2
    assert updated.due_at == clock.value + 1_000
    assert updated.previous_integrity_sha256 == created.integrity_sha256

    history = store.history("tenant-a", created.task_id)
    assert [event.event_type for event in history] == ["created", "updated"]
    assert [event.actor_ref for event in history] == [
        "principal.owner",
        "principal.reviewer",
    ]
    assert history[-1].record == updated
    assert store.list_tasks(
        "tenant-a",
        entity_id=created.entity_id,
        status="in_progress",
        assignee_ref="principal.reviewer",
        priority="high",
    ) == (updated,)
    integrity = store.verify_integrity("tenant-a")
    assert integrity["ok"] is True
    assert integrity["task_count"] == 1
    assert integrity["history_count"] == 2


def test_task_authority_tenant_cas_and_closed_inputs_fail_closed(tmp_path) -> None:
    store, clock, current, _actor, _maintenance = _store(tmp_path)
    created = store.create_task(
        "tenant-a",
        entity_id="model.customer-support",
        entity_revision=4,
        kind="review",
        title="Review model change",
        idempotency_key="create-review",
    )

    with pytest.raises(tasks.AIEntityTaskNotFound):
        store.get_task("tenant-b", created.task_id)
    with pytest.raises(tasks.AIEntityTaskConflict):
        store.update_task(
            "tenant-a",
            created.task_id,
            expected_revision=9,
            changes={"status": "resolved"},
            idempotency_key="stale-update",
        )
    with pytest.raises(tasks.AIEntityTaskValidationError):
        store.update_task(
            "tenant-a",
            created.task_id,
            expected_revision=1,
            changes={"unbounded": "field"},
            idempotency_key="bad-field",
        )
    with pytest.raises(tasks.AIEntityTaskValidationError):
        store.create_task(
            "tenant-a",
            entity_id="model.customer-support",
            entity_revision=4,
            kind="generic",
            title="Not an AI governance task",
            idempotency_key="bad-kind",
        )

    current["value"] = tasks.issue_entity_authority(
        tenant_id="tenant-a",
        entity_id="model.customer-support",
        entity_revision=4,
        entity_type="model",
        issuer_ref="registry-authority",
        issued_at=clock.value - 60,
        valid_until=clock.value + 86_400,
        revoked=True,
    )
    with pytest.raises(tasks.AIEntityTaskConflict):
        store.update_task(
            "tenant-a",
            created.task_id,
            expected_revision=1,
            changes={"status": "blocked"},
            idempotency_key="revoked-authority",
        )


def test_entity_authority_is_double_resolved_and_must_not_drift(tmp_path) -> None:
    clock = Clock()
    first = _authority(clock)
    second = tasks.issue_entity_authority(
        tenant_id="tenant-a",
        entity_id=first.entity_id,
        entity_revision=first.entity_revision,
        entity_type=first.entity_type,
        issuer_ref="different-authority",
        issued_at=clock.value - 60,
        valid_until=clock.value + 86_400,
    )
    calls = iter((first, second))
    store = tasks.AIEntityTaskStore(
        tmp_path / "drift.sqlite3",
        tenant_id="tenant-a",
        entity_authority_resolver=lambda *_args: next(calls),
        principal_resolver=lambda: "principal.owner",
        config_gate=lambda: None,
        clock=clock,
    )
    with pytest.raises(tasks.AIEntityTaskConflict, match="authority changed"):
        store.create_task(
            "tenant-a",
            entity_id=first.entity_id,
            entity_revision=first.entity_revision,
            kind="review",
            title="Review drift",
            idempotency_key="drift",
        )


def test_history_tampering_is_detected(tmp_path) -> None:
    store, _clock, _current, _actor, _maintenance = _store(tmp_path)
    created = store.create_task(
        "tenant-a",
        entity_id="model.customer-support",
        entity_revision=4,
        kind="review",
        title="Review evidence",
        idempotency_key="tamper-create",
    )
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT record_json FROM ai_entity_tasks WHERE task_id=?",
            (created.task_id,),
        ).fetchone()
        payload = json.loads(row[0])
        payload["title"] = "tampered"
        connection.execute(
            "UPDATE ai_entity_tasks SET record_json=? WHERE task_id=?",
            (json.dumps(payload), created.task_id),
        )
    with pytest.raises(tasks.AIEntityTaskIntegrityError):
        store.get_task("tenant-a", created.task_id)


def test_non_ascii_text_is_refused_not_a_type_error(tmp_path) -> None:
    # Tenant ids may be Unicode, and stored digests can be edited; either used
    # to raise TypeError from hmac.compare_digest instead of the store's errors.
    store, _clock, _current, _actor, _maintenance = _store(tmp_path)
    created = store.create_task(
        "tenant-a",
        entity_id="model.customer-support",
        entity_revision=4,
        kind="review",
        title="Review evidence",
        idempotency_key="non-ascii-create",
    )
    with pytest.raises(tasks.AIEntityTaskNotFound):
        store.get_task("tenant-é", created.task_id)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER ai_entity_task_operation_no_update")
        connection.execute("DROP TRIGGER ai_entity_task_history_no_update")
        connection.execute("UPDATE ai_entity_task_operations SET request_sha256=?", ("é" * 64,))
        connection.execute("UPDATE ai_entity_task_history SET event_sha256=?", ("é" * 64,))
    with pytest.raises(tasks.AIEntityTaskConflict):
        store.create_task(
            "tenant-a",
            entity_id="model.customer-support",
            entity_revision=4,
            kind="review",
            title="Review evidence",
            idempotency_key="non-ascii-create",
        )
    with pytest.raises(tasks.AIEntityTaskIntegrityError):
        store.history("tenant-a", created.task_id)


def test_overdue_task_can_be_resolved_but_not_given_a_past_due_date(tmp_path) -> None:
    store, clock, _current, _actor, _maintenance = _store(tmp_path)
    created = store.create_task(
        "tenant-a",
        entity_id="model.customer-support",
        entity_revision=4,
        kind="remediation",
        title="Overdue finding",
        due_at=clock.value + 1_000,
        idempotency_key="overdue-create",
    )
    clock.advance(2_000)
    with pytest.raises(tasks.AIEntityTaskValidationError, match="due_at"):
        store.update_task(
            "tenant-a",
            created.task_id,
            expected_revision=1,
            changes={"due_at": clock.value - 1},
            idempotency_key="overdue-redate",
        )
    resolved = store.update_task(
        "tenant-a",
        created.task_id,
        expected_revision=1,
        changes={"status": "resolved"},
        idempotency_key="overdue-resolve",
    )
    assert resolved.status == "resolved"
    assert resolved.due_at == created.due_at


def test_terminal_retention_purge_keeps_replay_tombstone(tmp_path) -> None:
    store, clock, _current, _actor, maintenance = _store(tmp_path)
    created = store.create_task(
        "tenant-a",
        entity_id="model.customer-support",
        entity_revision=4,
        kind="remediation",
        title="Close finding",
        idempotency_key="retained-create",
    )
    closed = store.update_task(
        "tenant-a",
        created.task_id,
        expected_revision=1,
        changes={"status": "resolved"},
        idempotency_key="retained-close",
    )
    assert closed.closed_at == closed.updated_at
    clock.advance(3_601)
    assert store.retention_due("tenant-a") == (closed,)
    with pytest.raises(tasks.AIEntityTaskPermissionDenied):
        store.purge_expired("tenant-a")
    maintenance["allowed"] = True
    assert store.purge_expired("tenant-a") == 1
    with pytest.raises(tasks.AIEntityTaskNotFound):
        store.get_task("tenant-a", created.task_id)
    integrity = store.verify_integrity("tenant-a")
    assert integrity["task_count"] == 0
    assert integrity["tombstone_count"] == 1

    with pytest.raises(tasks.AIEntityTaskConflict, match="expired"):
        store.create_task(
            "tenant-a",
            entity_id="model.customer-support",
            entity_revision=4,
            kind="remediation",
            title="Close finding",
            idempotency_key="retained-create",
        )


def test_constructor_requires_authentication_and_configuration(tmp_path) -> None:
    clock = Clock()
    authority = _authority(clock)
    with pytest.raises(tasks.AIEntityTaskConfigError):
        tasks.AIEntityTaskStore(
            tmp_path / "gate.sqlite3",
            tenant_id="tenant-a",
            entity_authority_resolver=lambda *_args: authority,
            principal_resolver=lambda: "principal.owner",
            config_gate=lambda: (_ for _ in ()).throw(RuntimeError("disabled")),
            clock=clock,
        )

    store = tasks.AIEntityTaskStore(
        tmp_path / "auth.sqlite3",
        tenant_id="tenant-a",
        entity_authority_resolver=lambda *_args: authority,
        principal_resolver=lambda: None,
        config_gate=lambda: None,
        clock=clock,
    )
    with pytest.raises(tasks.AIEntityTaskPermissionDenied):
        store.create_task(
            "tenant-a",
            entity_id=authority.entity_id,
            entity_revision=authority.entity_revision,
            kind="review",
            title="No anonymous writes",
            idempotency_key="anonymous",
        )
