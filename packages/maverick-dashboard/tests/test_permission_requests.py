"""Permissions explain actual root grants; request reviews cannot grant access."""
from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick import capability, config
from maverick_dashboard import permission_requests as service
from maverick_dashboard import permission_requests_api as api


class Store:
    def __init__(self):
        self.rows = {}
    def list(self, **kwargs):
        return deepcopy(list(self.rows.values()))
    def new_id(self):
        return "PAR-1"
    def create(self, row, **kwargs):
        self.rows[row["id"]] = {**row, "revision": 1}
        return deepcopy(self.rows[row["id"]])
    def update(self, identifier, mutate, expected_revision, **kwargs):
        row = deepcopy(self.rows.get(identifier))
        if row is None:
            return None
        assert row["revision"] == expected_revision
        mutate(row)
        row["revision"] += 1
        self.rows[identifier] = row
        return deepcopy(row)


@pytest.fixture
def policy(monkeypatch):
    cfg = {"security": {"channels": {"dashboard": {"denied_tools": ["shell"]}}}}
    monkeypatch.setattr(config, "load_config", lambda: cfg)
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr("maverick.runtime_overrides.denied_tools", lambda: set())
    monkeypatch.setattr("maverick.regulatory_compiler.attenuate", lambda cap: cap)
    monkeypatch.setattr("maverick.personal_identity.principal_current", lambda actor: True)
    monkeypatch.setattr(service, "explain_role", lambda actor: {"role": "operator", "source": "Current workspace membership", "owner": "Workspace administrator"})
    monkeypatch.setattr(service.auth, "role_for_principal", lambda actor: "operator")
    monkeypatch.setattr(service.auth, "caller_principal", lambda request: request.actor)
    monkeypatch.setattr(service.auth, "has_global_permission", lambda request, permission: request.global_admin)
    monkeypatch.setattr(service.auth, "has_permission", lambda request, permission: request.admin)
    monkeypatch.setattr(api, "authority", lambda request, **kwargs: request.actor)
    monkeypatch.setattr(service, "authority_effect_fence", nullcontext)
    monkeypatch.setattr(service, "STORE", Store())
    return cfg


def test_named_channel_denial_matches_runtime_and_names_approver(policy):
    decision = service.explain("user:employee", "tool", "shell")
    cap = capability.capability_from_config("user:employee", channel="dashboard", user_id="employee")
    assert decision["allowed"] == cap.permits("shell") is False
    assert decision["approver_scope"] == "installation"
    assert any(row["source"] == "Dashboard channel ACL" and row["allowed"] is False for row in decision["layers"])
    assert "paths" not in str(decision)


def test_exact_user_acl_and_assigned_role_are_named(policy):
    policy["security"] = {"users": {"employee": {"allowed_tools": ["read_file"]}}}
    policy.update(role_assignments={"user:employee": "narrow"}, roles={"narrow": {"deny_tools": ["write_file"]}})
    decision = service.explain("user:employee", "tool", "write_file")
    assert not decision["allowed"]
    sources = {row["source"] for row in decision["layers"] if not row["allowed"]}
    assert sources == {"Your exact execution-user ACL", "Assigned capability role: narrow"}


def test_requested_permission_never_becomes_effective_from_review_alone(policy):
    employee = SimpleNamespace(actor="user:employee", admin=False, global_admin=False)
    admin = SimpleNamespace(actor="user:admin", admin=True, global_admin=True)
    current = service.explain(employee.actor, "tool", "shell")
    row = service.submit(employee, "tool", "shell", "Run a reviewed business command", current["snapshot"])
    assert row["status"] == "requested"
    with pytest.raises(HTTPException) as error:
        service.decide(admin, row["id"], row["revision"], "confirm_effective", "Reviewed actual policy change")
    assert error.value.status_code == 409
    assert service.STORE.rows[row["id"]]["status"] == "requested"
    policy["security"]["channels"]["dashboard"]["denied_tools"] = []
    result = service.decide(admin, row["id"], row["revision"], "confirm_effective", "Verified policy change in Settings")
    assert result["status"] == "effective" and result["current"]["allowed"]


def test_workspace_admin_cannot_review_installation_tool_policy_or_self(policy):
    employee = SimpleNamespace(actor="user:employee", admin=True, global_admin=False)
    current = service.explain(employee.actor, "tool", "shell")
    row = service.submit(employee, "tool", "shell", "A specific business purpose", current["snapshot"])
    other = SimpleNamespace(actor="user:other", admin=True, global_admin=False)
    assert not service.visible(other, row)
    assert not service.can_review(employee, row)
    with pytest.raises(HTTPException):
        service.decide(other, row["id"], row["revision"], "deny", "Reviewed by wrong administrator")


def test_changed_policy_refuses_stale_submission(policy):
    employee = SimpleNamespace(actor="user:employee", admin=False, global_admin=False)
    current = service.explain(employee.actor, "tool", "shell")
    policy["security"]["channels"]["dashboard"]["denied_tools"] = []
    with pytest.raises(HTTPException) as error:
        service.submit(employee, "tool", "shell", "A specific business purpose", current["snapshot"])
    assert error.value.status_code == 409
    assert service.STORE.rows == {}


def test_layer_reads_the_acl_as_the_kernel_does():
    # A lone string is one tool name and a mixed-case ceiling still applies.
    assert service._layer("x", {"denied_tools": "shell"}, "shell")["allowed"] is False
    assert service._layer("x", {"denied_tools": "shell"}, "s")["allowed"] is True
    capped = service._layer("x", {"max_risk": "LOW"}, "shell")
    assert capped["allowed"] is False and "low ceiling" in capped["reason"]
