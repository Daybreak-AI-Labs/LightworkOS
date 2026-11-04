"""Background observations do not depend on a live browser credential."""
from types import SimpleNamespace

from maverick_dashboard import personal_notification_scheduler as scheduler


def test_fixed_workspace_does_not_scan_other_tenants(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "selected")
    assert scheduler._tenants() == ["selected"]


def test_revoked_identity_withdraws_before_reading_private_sources(monkeypatch):
    from contextlib import nullcontext

    from maverick import personal_identity, personal_notification_recipients, world_model
    from maverick.tenant import registry
    monkeypatch.setattr(scheduler, "authority_effect_fence", nullcontext)
    monkeypatch.setattr(scheduler, "_scheduler_stop", SimpleNamespace(is_set=lambda: False))
    monkeypatch.setattr(scheduler, "_enabled", lambda: True)
    monkeypatch.setattr(scheduler, "current_tenant_id_strict", lambda: "selected")
    monkeypatch.setattr(registry, "assert_tenant_active", lambda _: None)
    monkeypatch.setattr(personal_identity, "principal_current", lambda _: False)
    withdrawn = []
    monkeypatch.setattr(personal_notification_recipients, "withdraw", withdrawn.append)
    monkeypatch.setattr(world_model, "open_world", lambda: (_ for _ in ()).throw(AssertionError("Read after revocation")))
    assert scheduler.observe("user:alice") is False
    assert withdrawn == ["user:alice"]
