"""Dashboard authority stores roll back or refuse before publishing state."""

from __future__ import annotations

from contextlib import nullcontext

import pytest
from fastapi import HTTPException
from maverick.audit import AuditRefused, AuditWriteRefused


def _audit_refuses(monkeypatch) -> None:
    import maverick.audit as audit

    def refuse(*_args, **_kwargs):
        raise AuditWriteRefused("configured signing floor refused the row")

    monkeypatch.setattr(audit, "record", refuse)
    monkeypatch.setattr(audit, "record_global", refuse)


def _audit_succeeds(monkeypatch) -> None:
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_EKKO", raising=False)


def test_global_and_tenant_role_refusals_restore_prior_rosters(monkeypatch):
    from maverick_dashboard import rbac

    _audit_succeeds(monkeypatch)
    rbac.set_role("user:analyst", "viewer", actor="user:admin")
    rbac.set_tenant_role(
        "acme",
        "user:analyst",
        "viewer",
        actor="user:admin",
    )
    _audit_refuses(monkeypatch)

    with pytest.raises(AuditRefused):
        rbac.set_role("user:analyst", "admin", actor="user:admin")
    with pytest.raises(AuditRefused):
        rbac.set_tenant_role(
            "acme",
            "user:analyst",
            "admin",
            actor="user:admin",
        )

    assert rbac.get_stored_role("user:analyst") == "viewer"
    assert rbac.get_tenant_role("acme", "user:analyst") == "viewer"


def test_scim_membership_refusal_restores_prior_group_store(monkeypatch):
    from maverick_dashboard import scim

    gid = "a" * 32
    first_uid = "1" * 32
    second_uid = "2" * 32
    prior = {
        gid: {
            "id": gid,
            "displayName": "Finance",
            "externalId": "",
            "members": [first_uid],
            "created_at": 1.0,
            "updated_at": 1.0,
        },
    }
    scim._save_groups(prior)
    changed = {
        gid: {
            **prior[gid],
            "members": [first_uid, second_uid],
            "updated_at": 2.0,
        },
    }
    _audit_refuses(monkeypatch)

    with pytest.raises(scim.ScimAuditPendingError):
        scim._save_groups_with_audit(
            changed,
            prior,
            operation="replace",
            group_id=gid,
        )

    assert scim._load_groups() == prior
    # The target revision is durable for an idempotent retry, but it is not
    # authorization state until the governed audit sink acknowledges it.
    assert scim._group_audit_outbox_path().is_file()


def test_learning_control_refusal_happens_before_overlay_write(monkeypatch):
    from maverick_dashboard import settings_store

    writes = []
    monkeypatch.setattr(settings_store, "_write", writes.append)
    _audit_refuses(monkeypatch)

    with pytest.raises(AuditRefused):
        settings_store.set_learning(True, actor="user:admin")

    assert writes == []


def test_dgm_control_refusal_happens_before_overlay_write(monkeypatch):
    from maverick import self_modify
    from maverick_dashboard import settings_store

    status = {
        "control_managed": False,
        "blockers": [],
        "requested": False,
        "effective": False,
        "state": "disabled",
    }
    writes = []
    monkeypatch.setattr(self_modify, "production_status", lambda: status)
    monkeypatch.setattr(settings_store, "_write", writes.append)
    _audit_refuses(monkeypatch)

    with pytest.raises(AuditRefused):
        settings_store.set_dgm(
            True,
            actor="user:admin",
            acknowledged=True,
        )

    assert writes == []


def test_ekko_control_refusal_happens_before_overlay_write(monkeypatch):
    from maverick import config, ekko_control
    from maverick_dashboard import settings_store

    writes = []
    monkeypatch.setattr(ekko_control, "control_barrier", nullcontext)
    monkeypatch.setattr(config, "get_ekko", lambda: {"enable": False})
    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(
        settings_store,
        "_higher_precedence_ekko_enable_owner",
        lambda: None,
    )
    monkeypatch.setattr(settings_store, "_write", writes.append)
    _audit_refuses(monkeypatch)

    with pytest.raises(AuditRefused):
        settings_store.set_ekko(True, actor="user:admin")

    assert writes == []


def test_ekko_route_refusal_never_returns_false_success(monkeypatch):
    from maverick_dashboard import ekko_routes

    _audit_refuses(monkeypatch)

    with pytest.raises(AuditRefused):
        ekko_routes._audit("ekko_session", state="paused")
    with pytest.raises(HTTPException) as exc:
        ekko_routes._audit(
            "ekko_session",
            required=True,
            state="start_authorized",
        )

    assert exc.value.status_code == 503
