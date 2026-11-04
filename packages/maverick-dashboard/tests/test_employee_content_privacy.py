"""Scoped employee-content grants and metadata projection regressions."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from maverick_dashboard import auth, content_access


@pytest.fixture
def authority(monkeypatch):
    monkeypatch.setattr(auth, "_authorization_principal", lambda _: "user:admin")
    monkeypatch.setattr(auth, "has_global_permission", lambda *_: True)
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access, "tenant", lambda: "workspace-a")
    monkeypatch.setattr(content_access, "_reviewer_current", lambda _: True)
    from maverick_dashboard import scim_groups
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda _: True)
    return SimpleNamespace(method="GET", state=SimpleNamespace())


def grant(**updates):
    return {"id": "ECA-example", "tenant": "workspace-a", "requester": "user:admin",
            "owner": "user:employee", "resource_kind": "goal", "resource_id": "12",
            "status": "approved", "expires_at": time.time() + 60, "purpose": "employee_support",
            **updates}


def test_admin_role_alone_does_not_reveal_task(authority, monkeypatch):
    monkeypatch.setattr(content_access.STORE, "list", list)
    goal = SimpleNamespace(id=12, owner="user:employee")
    assert auth.goal_owner_filter(authority) == "user:admin"
    assert not auth.can_access_goal(authority, goal)
    assert not auth.can_access_goal_principal("user:admin", goal)


@pytest.mark.parametrize("updates", [
    {"tenant": "workspace-b"}, {"resource_id": "13"}, {"status": "revoked"},
    {"expires_at": 0}, {"_audit_pending": [{"event_id": "pending"}]},
])
def test_stale_or_wrong_scope_grant_denies(authority, monkeypatch, updates):
    monkeypatch.setattr(content_access.STORE, "list", lambda: [grant(**updates)])
    assert not content_access.may_read_employee_content(authority, "user:employee", resource_kind="goal", resource_id="12")


def test_exceptional_read_requires_confirmed_receipt(authority, monkeypatch):
    import maverick.audit
    monkeypatch.setattr(content_access.STORE, "list", lambda: [grant()])
    monkeypatch.setattr(maverick.audit, "record", lambda *_, **__: False)
    assert not auth.can_access_goal(authority, SimpleNamespace(id=12, owner="user:employee"))
    monkeypatch.setattr(maverick.audit, "record", lambda *_, **__: True)
    assert auth.can_access_goal(authority, SimpleNamespace(id=12, owner="user:employee"))
    authority.method = "POST"
    assert not auth.can_access_goal(authority, SimpleNamespace(id=12, owner="user:employee"))


def test_metadata_projection_removes_content_before_search():
    event = {"ts": 1, "kind": "tool_call", "agent": "private prompt", "goal_id": 12,
             "payload": {"actor": "user:employee", "args": {"text": "secret"},
                         "result": "private response", "title": "sensitive title", "cost_usd": 0.1}}
    projected = content_access.audit_metadata(event)
    assert projected["payload"] == {"actor": "user:employee", "cost_usd": 0.1}
    assert "secret" not in str(projected) and "private" not in str(projected)


@pytest.mark.parametrize("nested", [False, True])
def test_control_action_label_is_useful_without_exposing_recipient(nested):
    from maverick_dashboard.audit_actions_api import event_label

    fields = {"action": "invite_created", "email": "bob@example.test", "actor": "user:admin"}
    event = {"kind": "control_plane_action", **({"payload": fields} if nested else fields)}
    projected = content_access.audit_metadata(event)
    assert event_label(projected) == "Invite created"
    assert "bob@example.test" not in str(projected)


@pytest.mark.parametrize("action", ["patient_jane_doe", {"private": "text"}, None])
def test_unknown_control_action_stays_private(action):
    from maverick_dashboard.audit_actions_api import event_label

    projected = content_access.audit_metadata({"kind": "control_plane_action", "action": action})
    assert "action" not in projected
    assert event_label(projected) == "Administrator action"


def test_installation_credential_is_not_employee_identity(monkeypatch):
    request = SimpleNamespace(method="GET")
    monkeypatch.setattr(auth, "_authorization_principal", lambda _: None)
    assert auth.goal_owner_filter(request) == ""
    assert not auth.can_access_goal_principal(None, SimpleNamespace(owner="user:employee"))
    assert auth.can_access_goal_principal(None, SimpleNamespace(owner=""))
    assert not content_access.may_read_employee_content(request, "user:employee", resource_kind="goal", resource_id="12")


def test_owner_approval_requires_current_workspace_membership(monkeypatch):
    from maverick_dashboard import rbac, scim_groups
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda _: True)
    monkeypatch.setattr(rbac, "get_tenant_role", lambda *_: None)
    row = grant(reviewed_by="user:employee")
    assert not content_access._reviewer_current(row)
    monkeypatch.setattr(rbac, "get_tenant_role", lambda *_: "viewer")
    assert content_access._reviewer_current(row)


def test_approval_read_is_exact_card_and_does_not_authorize_task_mutation(authority, monkeypatch):
    import maverick.audit
    monkeypatch.setattr(auth, "has_permission", lambda *_: True)
    monkeypatch.setattr(maverick.audit, "record", lambda *_, **__: True)
    approval = SimpleNamespace(id=9, requested_by="agent:worker", goal_id=12,
        action="send", scope="one reviewed target", detail="private card", status="pending")
    world = SimpleNamespace(get_goal=lambda _: SimpleNamespace(owner="user:employee"))
    resource = content_access.approval_resource(approval, world)
    monkeypatch.setattr(content_access.STORE, "list", lambda: [grant(**resource)])
    assert content_access.can_read_approval(authority, approval, world)
    authority.method = "POST"
    assert not auth.can_access_goal(authority, SimpleNamespace(id=12, owner="user:employee"))
    approval.detail = "changed private card"
    assert not content_access.can_read_approval(authority, approval, world)


def test_private_approval_has_no_ambient_administrator_read(authority, monkeypatch):
    monkeypatch.setattr(auth, "has_permission", lambda *_: True)
    monkeypatch.setattr(content_access.STORE, "list", list)
    approval = SimpleNamespace(id=9, requested_by="user:employee", goal_id=None,
        action="send", scope="one reviewed target", detail="private card", status="pending")
    assert not content_access.can_read_approval(authority, approval, SimpleNamespace())


def test_unidentified_caller_cannot_access_a_missing_record():
    assert not auth.can_access_goal_principal(None, None)


@pytest.mark.parametrize("nested", [False, True])
def test_audit_projection_preserves_control_metadata_without_free_text(nested):
    fields = {"principal": "user:reviewer", "actor": "user:owner", "stage": "input", "score": 0.95,
              "obligation_id": "gdpr-art32-outbound-transfer", "regulation": "private substituted title",
              "article": "private substituted text", "obligations_checked": ["gdpr-art17-erasure-governed-path", "private rule"],
              "name": "private generated tool", "reason": "private prompt", "input_summary": "secret"}
    event = {"kind": "governance_denied", **({"payload": fields} if nested else fields)}
    projected = content_access.audit_metadata(event)
    visible = projected["payload"] if nested else projected
    assert visible["principal"] == "user:reviewer" and visible["actor"] == "user:owner"
    assert visible["stage"] == "input" and visible["score"] == 0.95
    assert visible["regulation"] == "GDPR" and visible["article"] == "Art. 32"
    assert visible["obligations_checked"] == ["gdpr-art17-erasure-governed-path"]
    assert "private" not in str(projected) and "secret" not in str(projected)


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -1, 2, True, "0.9"])
def test_audit_projection_rejects_unbounded_or_non_numeric_scores(score):
    assert "score" not in content_access.audit_metadata({"score": score})


@pytest.mark.parametrize("field", ["stage", "rule", "decision", "obligation_id"])
def test_malformed_control_fields_do_not_break_metadata_projection(field):
    assert field not in content_access.audit_metadata({field: {"private": "text"}})


def test_oversight_local_metadata_scope_never_adopts_named_or_unknown_goals():
    from maverick_dashboard.app import _audit_event_visible_to_caller
    world = SimpleNamespace(get_goal=lambda value: {
        1: SimpleNamespace(owner=""), 2: SimpleNamespace(owner="user:employee")}.get(value))

    def visible(event):
        return _audit_event_visible_to_caller(event, principal=None, owner_filter="", world=world, goal_owner_cache={})

    assert visible({"goal_id": 1})
    assert visible({"principal": "agent:worker"})
    assert visible({})
    for event in ({"goal_id": 2}, {"goal_id": 3}, {"goal_id": False}, {"goal_id": 1.2},
                  {"actor": "user:employee"}, {"principal": "user:employee"}):
        assert not visible(event)
