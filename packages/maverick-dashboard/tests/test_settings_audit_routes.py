"""Ordinary Settings writes have truthful, redacted activity receipts."""
from __future__ import annotations

import json
from contextlib import contextmanager

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from test_support.channel_review import channel_review_token


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, runtime_overrides, world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", tmp_path / "runtime.toml")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    config.reset_config_cache()
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


@pytest.fixture
def rows(monkeypatch):
    import maverick.audit as audit

    recorded = []

    def capture(kind, **payload):
        if str(kind) == "setting_changed":
            recorded.append(payload)
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return recorded


@pytest.mark.parametrize("path,data,section,key", [
    ("/settings/capabilities", {"web_search": "on"}, "capabilities", "all"),
    ("/settings/models", {"model": "openai:gpt-4o"}, "models", "default"),
    ("/settings/models/roles", {"coder": "openai:gpt-4o"}, "models", "roles"),
    ("/settings/models/allowed", {"models": "openai:gpt-4o"}, "models", "allowed"),
    ("/settings/models/discovery", {"enabled": "off"}, "models", "discovery"),
    ("/settings/budget", {"max_dollars": "2.50"}, "budget", "task_limit"),
    ("/settings/ui-visibility", {}, "ui_visibility", "matrix"),
    ("/settings/ui-visibility/reset", {}, "ui_visibility", "matrix"),
])
def test_settings_routes_record_before_and_after(
    client, rows, path, data, section, key,
):
    response = client.post(path, data=data, follow_redirects=False)
    assert response.status_code == 303, response.text
    assert [(r["section"], r["key"], r["phase"]) for r in rows] == [
        (section, key, "prepared"), (section, key, "completed"),
    ]
    assert rows[0]["old"] == rows[1]["old"]
    assert rows[0]["new"] == rows[1]["new"]
    assert all(r["actor"] for r in rows)


def test_retired_whole_feature_form_records_no_change(client, rows):
    """Feature switches are saved one at a time (see the switches API below);
    the old whole-form route refuses, so its receipt must not claim a change."""
    response = client.post("/settings/features", data={"skills": "on"}, follow_redirects=False)
    assert response.status_code == 409, response.text
    assert "was not saved" in response.json()["detail"]
    assert rows == []


def test_provider_rotation_and_clear_are_redacted(client, rows, monkeypatch):
    from maverick import config

    for name in config.PROVIDER_KEY_ENV_VARS + config.PROVIDER_BASE_URL_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    secret = "sk-private-do-not-log"  # pragma: allowlist secret
    response = client.post(
        "/settings/providers", data={"provider": "openai", "api_key": secret},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert [r["phase"] for r in rows] == ["prepared", "completed"]
    assert secret not in json.dumps(rows)
    assert rows[-1]["new"]["api_key"] == "set"  # pragma: allowlist secret
    assert rows[-1]["changed_fields"] == ["access key"]
    rows.clear()
    replacement = "sk-replaced-do-not-log"  # pragma: allowlist secret
    response = client.post(
        "/settings/providers", data={"provider": "openai", "api_key": replacement},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert rows[-1]["old"]["api_key"] == rows[-1]["new"]["api_key"] == "set"  # pragma: allowlist secret
    assert rows[-1]["changed_fields"] == ["access key"]
    assert replacement not in json.dumps(rows)
    rows.clear()
    response = client.post(
        "/settings/providers/clear", data={"provider": "openai"},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert rows[0]["old"]["api_key"] == "set"  # pragma: allowlist secret
    assert rows[-1]["new"]["api_key"] == "not set"  # pragma: allowlist secret
    assert rows[-1]["changed_fields"] == ["access key"]


def test_channel_credentials_are_redacted(client, rows):
    secret = "telegram-secret-do-not-log"  # pragma: allowlist secret
    response = client.post(
        "/channels/save", data={"channel": "telegram", "bot_token": secret,
                                "enabled": "on", "review_token": channel_review_token(client)}, follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert [r["phase"] for r in rows] == ["prepared", "completed"]
    assert rows[-1]["new"] == {"enabled": True, "fields_set": ["bot_token"]}
    assert secret not in json.dumps(rows)
    rows.clear()
    response = client.post("/channels/clear", data={"channel": "telegram", "confirm_people": "yes",
                                                    "review_token": channel_review_token(client)},
                           follow_redirects=False)
    assert response.status_code == 303, response.text
    assert rows[-1]["new"] == {"enabled": None, "fields_set": []}


def test_feature_module_and_sandbox_routes_record_changes(client, rows, monkeypatch):
    from maverick_dashboard import api

    response = client.post("/api/v1/features/switches",
                           json={"section": "dreaming", "enabled": False})
    assert response.status_code == 200, response.text
    assert rows[-1]["section"] == "features" and rows[-1]["key"] == "dreaming"
    rows.clear()
    response = client.post("/api/v1/features/modules",
                           json={"section": "consent_preferences", "enabled": False})
    assert response.status_code == 200, response.text
    assert rows[-1]["section"] == "modules"
    rows.clear()
    monkeypatch.setattr(api, "_probe_container_daemon", lambda _name: {
        "available": True, "detail": "ready",
    })
    response = client.post("/api/v1/sandbox/backend", json={"backend": "docker"})
    assert response.status_code == 200, response.text
    assert [(r["section"], r["key"], r["phase"]) for r in rows] == [
        ("sandbox", "backend", "prepared"), ("sandbox", "backend", "completed"),
    ]


def test_plugin_policy_and_model_cost_routes_record_changes(client, rows, monkeypatch):
    from maverick_dashboard import app as dashboard

    monkeypatch.setattr(dashboard, "_plugins_quorum", lambda *_args: (None, None))
    response = client.post("/plugins/approvals", data={"names": "acme-tools"},
                           follow_redirects=False)
    assert response.status_code == 303, response.text
    assert rows[-1]["section"] == "plugins" and rows[-1]["key"] == "installable"
    rows.clear()
    response = client.post("/plugins/install-switch", data={"enabled": "on"},
                           follow_redirects=False)
    assert response.status_code == 303, response.text
    assert rows[-1]["section"] == "plugins" and rows[-1]["key"] == "allow_install"
    rows.clear()
    response = client.post("/api/v1/model-cost-tiers",
                           json={"model": "openai:gpt-4o", "band": "low"})
    assert response.status_code == 200, response.text
    assert rows[-1]["section"] == "model_cost_tiers"


def test_audit_refusal_prevents_capability_and_sandbox_writes(
    client, monkeypatch,
):
    import maverick.audit as audit
    from maverick_dashboard import api, settings_store

    def refuse(kind, **payload):
        raise audit.AuditRefused("custody unavailable")

    monkeypatch.setattr(audit, "audit_event", refuse)
    response = client.post("/settings/capabilities", data={"code_exec": "on"},
                           follow_redirects=False)
    assert response.status_code == 503
    assert not settings_store.load_overlay().get("capabilities")
    monkeypatch.setattr(api, "_probe_container_daemon", lambda _name: {
        "available": True, "detail": "ready",
    })
    response = client.post("/api/v1/sandbox/backend", json={"backend": "docker"})
    assert response.status_code == 503
    assert not settings_store.load_overlay().get("sandbox")


def test_storage_failure_leaves_only_prepared_receipt(client, rows, monkeypatch):
    from maverick import file_lock
    from maverick_dashboard import settings_store

    def fail_write(*_args, **_kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr(file_lock, "atomic_write_text", fail_write)
    response = client.post("/settings/capabilities", data={"web_search": "on"},
                           follow_redirects=False)
    assert response.status_code == 503
    assert [r["phase"] for r in rows] == ["prepared"]
    assert not settings_store.load_overlay().get("capabilities")


def test_completion_refusal_reports_uncertain_saved_state(client, monkeypatch):
    import maverick.audit as audit
    from maverick_dashboard import settings_store

    phases = []

    def record(_kind, **payload):
        phases.append(payload["phase"])
        return payload["phase"] == "prepared"

    monkeypatch.setattr(audit, "audit_event", record)
    response = client.post("/settings/capabilities", data={"web_search": "on"},
                           follow_redirects=False)
    assert response.status_code == 503
    assert "may have changed" in response.json()["detail"]
    assert phases == ["prepared", "completed"]
    assert settings_store.load_overlay()["capabilities"]["web_search"] is True


def test_provider_completion_refusal_rolls_back_verified_rotation(client, monkeypatch):
    import maverick.audit as audit
    from maverick import config
    from maverick_dashboard import settings_store

    for name in config.PROVIDER_KEY_ENV_VARS + config.PROVIDER_BASE_URL_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        audit, "audit_event",
        lambda _kind, **payload: payload["phase"] == "prepared",
    )
    response = client.post(
        "/settings/providers", data={"provider": "openai", "api_key": "sk-new"},  # pragma: allowlist secret
        follow_redirects=False,
    )
    assert response.status_code == 503
    assert "openai" not in settings_store.load_overlay().get("providers", {})


def test_admin_demotion_at_write_boundary_prevents_save(client, rows, monkeypatch):
    from maverick_dashboard import auth, settings_store

    original_gate = auth.require_global_permission
    original_lock = settings_store._locked
    demoted = False

    def gate(request, permission):
        if demoted:
            raise HTTPException(status_code=403, detail="administrator access ended")
        return original_gate(request, permission)

    @contextmanager
    def acquired(*, strict=False):
        nonlocal demoted
        with original_lock(strict=strict):
            demoted = True
            yield

    monkeypatch.setattr(auth, "require_global_permission", gate)
    monkeypatch.setattr(settings_store, "_locked", acquired)
    response = client.post("/settings/capabilities", data={"web_search": "on"},
                           follow_redirects=False)
    assert response.status_code == 403
    assert rows == []
    assert not settings_store.load_overlay().get("capabilities")


def test_settings_page_links_review_and_explains_incomplete_receipts(client):
    text = client.get("/settings").text
    assert "/audit?kind=setting_changed" in text
    assert "A prepared entry alone does not confirm a save" in text
