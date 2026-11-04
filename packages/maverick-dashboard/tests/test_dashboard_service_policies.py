"""Contracts for shared dashboard services used by multiple route families."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from maverick_dashboard.attachment_headers import attachment_content_disposition
from maverick_dashboard.privacy_access import privacy_ops_or_403
from maverick_dashboard.request_identity import document_source_principal
from maverick_dashboard.voice_policy import voice_commands_enabled


def test_document_credentials_use_verified_identity_and_limit_grant_size():
    request = object()
    assert document_source_principal(request, identity=lambda _: None) is None
    assert document_source_principal(request, identity=lambda _: "alice") == "alice"
    assert document_source_principal(request, identity=lambda _: "a" * 256) == "a" * 256
    with pytest.raises(HTTPException) as error:
        document_source_principal(request, identity=lambda _: "a" * 257)
    assert error.value.status_code == 403


def test_privacy_feature_gate_refuses_before_returning_native_service(monkeypatch):
    from maverick import privacy_ops

    monkeypatch.setattr(privacy_ops, "enabled", lambda: False)
    with pytest.raises(HTTPException) as error:
        privacy_ops_or_403()
    assert error.value.status_code == 403
    assert error.value.headers["X-Lightwork-Reason"] == "feature-off"
    monkeypatch.setattr(privacy_ops, "enabled", lambda: True)
    assert privacy_ops_or_403() is privacy_ops


def test_attachment_header_encodes_unicode_and_drops_header_controls():
    assert attachment_content_disposition("../../sample\r\nX: evil.txt") == (
        'attachment; filename="sample--X- evil.txt"'
    )
    assert attachment_content_disposition("résumé.txt") == (
        'attachment; filename="rsum.txt"; filename*=UTF-8\'\'r%C3%A9sum%C3%A9.txt'
    )


def test_voice_policy_keeps_environment_precedence_and_default(monkeypatch):
    from maverick import config

    monkeypatch.delenv("MAVERICK_VOICE_COMMANDS", raising=False)
    monkeypatch.setattr(config, "load_config", lambda: {"voice": {"dashboard_commands": False}})
    assert voice_commands_enabled() is False
    monkeypatch.setenv("MAVERICK_VOICE_COMMANDS", "yes")
    assert voice_commands_enabled() is True
    monkeypatch.setenv("MAVERICK_VOICE_COMMANDS", "off")
    assert voice_commands_enabled() is False
    monkeypatch.delenv("MAVERICK_VOICE_COMMANDS")
    monkeypatch.setattr(config, "load_config", dict)
    assert voice_commands_enabled() is True


def test_schedule_policy_respects_runtime_feature_gate(monkeypatch):
    from maverick import config
    from maverick_dashboard.schedule_policy import require_scheduling

    monkeypatch.setattr(config, "get_features", lambda: {"scheduling": False})
    with pytest.raises(HTTPException) as error:
        require_scheduling()
    assert error.value.status_code == 403
    assert "scheduling is disabled" in error.value.detail
    monkeypatch.setattr(config, "get_features", dict)
    assert require_scheduling() is None


def test_editor_policy_preserves_admin_scope_and_installation_checks(monkeypatch):
    from maverick import config
    from maverick_dashboard.editor_policy import (
        pack_editing_denial,
        require_pack_editing,
        require_role_editing,
    )

    request = object()
    monkeypatch.setattr(config, "get_features", dict)
    def caller(_request):
        return "user:admin"

    def is_admin(_principal):
        return True

    assert pack_editing_denial(request, caller=caller, is_admin=lambda _: False) == (
        "pack editing requires a dashboard admin"
    )
    assert pack_editing_denial(request, caller=caller, is_admin=is_admin, has_permission=lambda *_: False) == (
        "pack editing requires an API key with the administrator scope"
    )
    assert pack_editing_denial(request, caller=caller, is_admin=is_admin, has_permission=lambda *_: True) is None
    monkeypatch.setattr(config, "get_features", lambda: {"pack_editing": False, "role_editing": False})
    assert "turned off" in pack_editing_denial(
        request, caller=caller, is_admin=is_admin, has_permission=lambda *_: True,
    )
    with pytest.raises(HTTPException) as error:
        require_pack_editing(request, permission=lambda *_: None, denial=lambda _: "disabled")
    assert error.value.status_code == 403
    with pytest.raises(HTTPException) as error:
        require_role_editing(request, caller=caller, is_admin=is_admin, permission=lambda *_: None)
    assert error.value.status_code == 403


def test_deliverable_release_policy_fails_closed_when_domain_is_missing(monkeypatch):
    from maverick import domain
    from maverick_dashboard.deliverable_policy import goal_gate, goal_shape

    monkeypatch.setattr(domain, "available_domains", dict)
    assert goal_gate("") is None
    assert goal_shape("missing") == "prose"
    with pytest.raises(HTTPException) as error:
        goal_gate("missing")
    assert error.value.status_code == 409

    def unavailable():
        raise OSError("policy unavailable")

    monkeypatch.setattr(domain, "available_domains", unavailable)
    with pytest.raises(HTTPException) as error:
        goal_gate("customer")
    assert error.value.status_code == 503


def test_connection_policy_preserves_structured_disabled_reason(monkeypatch):
    from maverick import connections
    from maverick_dashboard.connection_dependencies import require_connections

    monkeypatch.setattr(connections, "enabled", lambda: False)
    with pytest.raises(HTTPException) as error:
        require_connections()
    assert error.value.status_code == 403
    assert error.value.detail["code"] == "connections_disabled"
    monkeypatch.setattr(connections, "enabled", lambda: True)
    assert require_connections() is None


def test_editor_policy_preserves_live_trial_gate(monkeypatch):
    from maverick import specialist_canary
    from maverick_dashboard.editor_policy import refuse_while_trial_live

    monkeypatch.setattr(specialist_canary, "live", lambda _name: {"candidate": "draft"})
    with pytest.raises(HTTPException) as error:
        refuse_while_trial_live("specialist")
    assert error.value.status_code == 409
    monkeypatch.setattr(specialist_canary, "live", lambda _name: None)
    assert refuse_while_trial_live("specialist") is None
