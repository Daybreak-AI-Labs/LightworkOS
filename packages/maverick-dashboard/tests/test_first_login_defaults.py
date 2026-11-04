"""Deliberate first-login policy migration and exact reset provenance."""
from contextlib import nullcontext
from copy import deepcopy

import pytest
from fastapi import HTTPException
from maverick_dashboard import (
    access_explanations,
    auth,
    first_login_defaults,
    rbac,
    scim_groups,
    settings_store,
)


def test_role_reset_previews_verified_group_before_standard_default(monkeypatch):
    monkeypatch.setattr(auth, "is_dashboard_admin", lambda _: False)
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda _: True)
    monkeypatch.setattr(scim_groups, "role_for_principal", lambda _: "auditor")
    monkeypatch.setattr(rbac, "default_role", lambda: "operator")
    projection = access_explanations.standard_role("user:employee")
    assert projection["role"] == "auditor"
    assert projection["source"] == "Verified sign-in group mapping"
    assert "operate" not in projection["permissions"]


@pytest.fixture
def defaults(monkeypatch):
    from maverick import config
    overlay = {}
    monkeypatch.setattr(config, "load_global_config", lambda: deepcopy(overlay))
    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(config, "reset_config_cache", lambda: None)
    monkeypatch.setattr(settings_store, "_locked", lambda **_: nullcontext())
    monkeypatch.setattr(settings_store, "_load_overlay_for_update", lambda: deepcopy(overlay))
    def write(value):
        overlay.clear()
        overlay.update(deepcopy(value))
    monkeypatch.setattr(settings_store, "_write", write)
    monkeypatch.setattr(auth, "require_global_permission", lambda *_: None)
    monkeypatch.setattr(auth, "caller_principal", lambda _: "user:admin")
    return overlay


def test_first_login_change_requires_review_and_records_explicit_empty_departments(defaults, monkeypatch):
    import maverick.audit
    monkeypatch.setattr(maverick.audit, "audit_event", lambda *_, **__: True)
    reviewed = first_login_defaults.preview()
    with pytest.raises(HTTPException) as conflict:
        first_login_defaults.apply_conservative(None, "stale")
    assert conflict.value.status_code == 409 and defaults == {}
    effective = first_login_defaults.apply_conservative(None, reviewed["revision"])
    assert effective["conservative"] is True
    assert defaults["dashboard"] == {"default_role": "viewer", "default_suites": []}


def test_unrecorded_migration_restores_previous_policy(defaults, monkeypatch):
    import maverick.audit
    monkeypatch.setattr(maverick.audit, "audit_event", lambda *_, **__: False)
    reviewed = first_login_defaults.preview()
    with pytest.raises(HTTPException) as failure:
        first_login_defaults.apply_conservative(None, reviewed["revision"])
    assert failure.value.status_code == 503
    assert defaults == {}
