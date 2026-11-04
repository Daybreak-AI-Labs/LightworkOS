"""Native effective-secret rotation checks; all credentials are synthetic."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick import config, webhooks, world_model
from maverick_dashboard.app import app


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_WEBHOOK_SECRET", "MAVERICK_SECRETS_BACKEND",
                 "MAVERICK_SECRETS_DIR", "MAVERICK_CONFIG_OVERLAY", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.mark.parametrize("source", ["environment", "mounted"])
def test_external_secret_cannot_report_saved_overlay_as_active(source, tmp_path, monkeypatch):
    external = "synthetic-deployment-secret"
    replacement = "synthetic-dashboard-secret"
    if source == "environment":
        monkeypatch.setenv("MAVERICK_WEBHOOK_SECRET", external)
    else:
        directory = tmp_path / "vault"
        directory.mkdir()
        (directory / "MAVERICK_WEBHOOK_SECRET").write_text(external, encoding="utf-8")
        monkeypatch.setenv("MAVERICK_SECRETS_BACKEND", "file")
        monkeypatch.setenv("MAVERICK_SECRETS_DIR", str(directory))
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.post("/settings/webhooks", data={"secret": replacement}, follow_redirects=False)
    # Actual verifier remains controlled by the deployment secret.
    assert webhooks._load_config_outbound()[1] == external
    body = b"native-effective-setting-probe"
    assert webhooks.verify_signature(body, webhooks._sign(body, external), external)
    assert not webhooks.verify_signature(body, webhooks._sign(body, replacement), external)
    assert response.status_code == 409
    assert not config.dashboard_overrides_path().exists()


def client():
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def status(http):
    response = http.get("/settings/webhooks")
    assert response.status_code == 200
    return response.json()


def save(http, secret, reviewed=None, action="set"):
    return http.post("/settings/webhooks", data={"secret": secret, "action": action,
        "expected_generation": (reviewed or status(http))["expected_generation"]})


def test_success_native_verifier_ciphertext_and_no_secret_echo():
    http = client()
    reviewed = status(http)
    assert reviewed["source"] == "none" and reviewed["can_set"] is True
    value = "synthetic-real-roundtrip-key"
    response = save(http, value, reviewed)
    assert response.status_code == 200
    assert response.json()["result"] == "active"
    assert response.json()["source"] == "dashboard"
    assert webhooks._load_config_outbound()[1] == value
    import time
    request_body = b'{"description":"No title: never dispatch a goal"}'
    timestamp = str(int(time.time()))
    headers = {"X-Maverick-Timestamp": timestamp,
               "X-Maverick-Signature": webhooks._sign(request_body, value, timestamp=timestamp)}
    # The outbound key does not authenticate the separate control endpoint.
    assert http.post("/webhook/start", content=request_body, headers=headers).status_code == 401
    headers["X-Maverick-Signature"] = webhooks._sign(request_body, "synthetic-wrong", timestamp=timestamp)
    assert http.post("/webhook/start", content=request_body, headers=headers).status_code == 401
    body = b"test body"
    assert webhooks.verify_signature(body, webhooks._sign(body, value), webhooks._load_config_outbound()[1])
    assert value not in response.text + http.get("/settings").text + http.get("/settings/webhooks").text
    assert value not in config.dashboard_overrides_path().read_text()
    # Secret-derived digests are inside an authenticated encrypted review token.
    import hashlib
    assert hashlib.sha256(value.encode()).hexdigest() not in response.text
    assert save(http, "another-synthetic-key", reviewed).status_code == 409
    assert webhooks._load_config_outbound()[1] == value


@pytest.mark.parametrize("mode", ["environment", "mounted", "operator", "tenant"])
def test_current_external_ownership_blocks_valid_review(mode, tmp_path, monkeypatch):
    value = "synthetic-external-ownership"
    if mode == "environment":
        monkeypatch.setenv("MAVERICK_WEBHOOK_SECRET", value)
    elif mode == "mounted":
        monkeypatch.setenv("MAVERICK_SECRETS_BACKEND", "file")
        monkeypatch.setenv("MAVERICK_SECRETS_DIR", str(tmp_path))
        (tmp_path / "MAVERICK_WEBHOOK_SECRET").write_text(value)
    else:
        if mode == "operator":
            path = tmp_path / "operator.toml"
            monkeypatch.setenv(config.CONFIG_OVERLAY_ENV, str(path))
        else:
            monkeypatch.setenv("MAVERICK_TENANT", "workspace-a")
            path = config.tenant_config_path()
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('[webhooks]\nsecret = "' + value + '"\n')
    http = client()
    reviewed = status(http)
    assert reviewed["can_set"] is False
    assert reviewed["configured"] is True
    response = save(http, "synthetic-blocked-key", reviewed)
    assert response.status_code == 409
    assert webhooks._load_config_outbound()[1] == value
    assert not config.dashboard_overrides_path().exists()
    assert value not in response.text + str(reviewed)


@pytest.mark.parametrize("fallback", [None, "synthetic-original-installation-key"])
def test_remove_reports_effective_fallback_instead_of_claiming_disabled(fallback):
    if fallback:
        path = config.config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('[webhooks]\nsecret = "' + fallback + '"\n')
    http = client()
    assert save(http, "synthetic-app-copy").status_code == 200
    reviewed = status(http)
    assert reviewed["remove_keeps_configured"] is bool(fallback)
    response = save(http, "", reviewed, "remove")
    assert response.status_code == 200
    assert response.json()["result"] == "app_copy_removed"
    assert response.json()["configured"] is bool(fallback)
    assert webhooks._load_config_outbound()[1] == fallback


def test_external_change_invalidates_old_review_without_saving(monkeypatch):
    http = client()
    reviewed = status(http)
    monkeypatch.setenv("MAVERICK_WEBHOOK_SECRET", "synthetic-new-external")
    assert save(http, "synthetic-new-app", reviewed).status_code == 409
    assert not config.dashboard_overrides_path().exists()


def test_post_write_effective_race_rolls_back_exact_previous_bytes(monkeypatch):
    from maverick_dashboard import settings_store
    http = client()
    assert save(http, "synthetic-first-app").status_code == 200
    reviewed = status(http)
    before = config.dashboard_overrides_path().read_bytes()
    real_write = settings_store._write

    def race(data):
        real_write(data)
        monkeypatch.setenv("MAVERICK_WEBHOOK_SECRET", "synthetic-raced-deployment")

    monkeypatch.setattr(settings_store, "_write", race)
    response = save(http, "synthetic-never-effective", reviewed)
    assert response.status_code == 409
    assert config.dashboard_overrides_path().read_bytes() == before
    assert webhooks._load_config_outbound()[1] == "synthetic-raced-deployment"


def test_secret_copy_cleanup_when_deployment_owns_runtime(monkeypatch):
    http = client()
    assert save(http, "synthetic-dormant-copy").status_code == 200
    monkeypatch.setenv("MAVERICK_WEBHOOK_SECRET", "synthetic-active-external")
    reviewed = status(http)
    assert not reviewed["can_set"] and reviewed["can_remove"]
    assert reviewed["outbound_configured"] is True
    assert reviewed["remove_keeps_configured"] is True
    assert reviewed["remove_keeps_outbound_configured"] is True
    response = save(http, "", reviewed, "remove")
    assert response.status_code == 200
    assert response.json()["configured"] is True
    assert response.json()["outbound_configured"] is True
    assert webhooks._load_config_outbound()[1] == "synthetic-active-external"
    assert webhooks._load_config_outbound()[1] == "synthetic-active-external"


def test_tampered_and_other_principal_reviews_refused(monkeypatch):
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:alice", "admin")
    rbac.set_role("user:bob", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    http = client()
    reviewed = status(http)
    assert status(http)["context"] == reviewed["context"]
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:bob")
    assert status(http)["context"] != reviewed["context"]
    assert save(http, "synthetic-new-key", reviewed).status_code == 409
    tampered = dict(reviewed, expected_generation="MVKAR1:not-a-token")
    assert save(http, "synthetic-new-key", tampered).status_code == 409
    assert not config.dashboard_overrides_path().exists()


def test_admin_revoked_after_review_refused(monkeypatch):
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:alice", "admin")
    rbac.set_role("user:recovery", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    http = client()
    reviewed = status(http)
    rbac.set_role("user:alice", "viewer")
    assert save(http, "synthetic-new-key", reviewed).status_code == 403
    assert http.get("/settings/webhooks").status_code == 403
    assert not config.dashboard_overrides_path().exists()


def test_current_authority_rechecked_inside_commit(monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import auth
    http = client()
    reviewed = status(http)
    calls = []

    def authorize(request, permission):
        calls.append(permission)
        if len(calls) >= 4:
            raise HTTPException(403, "administrator access changed")

    monkeypatch.setattr(auth, "require_global_permission", authorize)
    assert save(http, "synthetic-refused-key", reviewed).status_code == 403
    assert len(calls) == 4
    assert not config.dashboard_overrides_path().exists()


def test_unreadable_source_is_unavailable_not_unconfigured():
    from maverick_dashboard.webhook_settings import WebhookSettingsUnavailable, state
    path = config.dashboard_overrides_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[broken")
    before = path.read_bytes()
    http = client()
    # Native dashboard authentication fails closed before the service runs.
    assert http.get("/settings/webhooks").status_code == 401
    assert http.post("/settings/webhooks", data={"secret": "synthetic-key"}).status_code == 401  # pragma: allowlist secret
    with pytest.raises(WebhookSettingsUnavailable):
        state(principal="local-operator", authorize=lambda: None)
    assert path.read_bytes() == before


@pytest.mark.parametrize("value", ["", "${SOME_KEY}", "MVKAR1:stored-value", "x" * 4097])
def test_invalid_new_values_never_echoed(value):
    response = save(client(), value)
    assert response.status_code == 400
    if value:
        assert value not in response.text
    assert not config.dashboard_overrides_path().exists()


def test_cross_origin_current_token_still_denied():
    http = client()
    reviewed = status(http)
    response = TestClient(app, base_url="http://127.0.0.1").post("/settings/webhooks", data={"secret": "synthetic-key",
        "expected_generation": reviewed["expected_generation"]})
    assert response.status_code == 403


def test_oversized_and_nonregular_sources_refused(tmp_path):
    from maverick_dashboard.webhook_settings import WebhookSettingsUnavailable, _file_identity
    oversized = tmp_path / "large.toml"
    with oversized.open("wb") as handle:
        handle.truncate(4 * 1024 * 1024 + 1)
    for path in (oversized, tmp_path):
        with pytest.raises(WebhookSettingsUnavailable):
            _file_identity(path)


def test_readonly_link_resolution_identity_includes_target(tmp_path, monkeypatch):
    from pathlib import Path

    from maverick_dashboard.webhook_settings import _file_identity
    target = tmp_path / "secret-target"
    target.write_text("synthetic-target")
    link = tmp_path / "link"
    original = Path.resolve
    # Windows may not grant link-creation privileges. Exercise the resolver's
    # resolved-target branch with a real bounded target read, not a fake hash.
    monkeypatch.setattr(Path, "resolve", lambda self, **kw: target if self == link else original(self, **kw))
    identity = _file_identity(link)
    assert identity["target"] == str(target)
    assert identity["path"] == str(link)
    assert identity["sha256"] == _file_identity(target)["sha256"]


def test_dashboard_link_write_refused_even_when_resolved_state_is_readable(monkeypatch):
    from pathlib import Path
    http = client()
    assert save(http, "synthetic-saved-copy").status_code == 200
    dashboard = config.dashboard_overrides_path()
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: True if self == dashboard else original(self))
    reviewed = status(http)
    assert not reviewed["storage_writable"]
    assert not reviewed["can_set"] and not reviewed["can_remove"]
    before = dashboard.read_bytes()
    assert save(http, "synthetic-replacement", reviewed).status_code == 409
    assert dashboard.read_bytes() == before


def test_production_settings_serves_its_actual_script():
    http = client()
    page = http.get("/settings")
    assert page.status_code == 200
    assert "lightwork-webhook-settings.js" in page.text
    response = http.get("/static/lightwork-webhook-settings.js")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "expected_generation" in response.text


def test_set_and_remove_are_recorded_without_the_secret(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event",
                        lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    http = client()
    value = "synthetic-recorded-rotation-key"
    assert save(http, value).status_code == 200
    assert save(http, "", action="remove").status_code == 200
    changes = [r for r in rows if r.get("section") == "webhooks" and r.get("key") == "secret"]
    assert [(r["phase"], r["old"], r["new"]) for r in changes] == [
        ("reviewed", "not set", "unconfirmed"),
        ("confirmed", "not set", "set"),
        ("reviewed", "set", "unconfirmed"),
        ("confirmed", "set", "not set"),
    ]
    assert changes[0]["operation_id"] == changes[1]["operation_id"]
    assert changes[2]["operation_id"] == changes[3]["operation_id"]
    assert changes[0]["operation_id"] != changes[2]["operation_id"]
    assert all(r.get("_global") is True and r.get("actor") for r in changes)
    assert value not in repr(rows)


def test_a_refused_record_undoes_the_change(monkeypatch):
    import maverick.audit as audit
    from maverick.audit import AuditRefused

    def refuse(kind, **payload):
        raise AuditRefused("activity record unavailable")

    monkeypatch.setattr(audit, "audit_event", refuse)
    http = client()
    response = save(http, "synthetic-unrecorded-key")
    assert response.status_code == 503
    assert webhooks._load_config_outbound()[1] in (None, "")


@pytest.mark.parametrize("refused_phase", ["reviewed", "confirmed"])
def test_false_audit_result_never_reports_success_or_keeps_new_secret(monkeypatch, refused_phase):
    import maverick.audit as audit

    rows = []

    def record(kind, **payload):
        rows.append(payload)
        return payload["phase"] != refused_phase

    monkeypatch.setattr(audit, "audit_event", record)
    http = client()
    response = save(http, "synthetic-unrecorded-key")
    assert response.status_code == 503
    assert webhooks._load_config_outbound()[1] in (None, "")
    assert not config.dashboard_overrides_path().exists()
    assert [row["phase"] for row in rows] == (
        ["reviewed"] if refused_phase == "reviewed" else ["reviewed", "confirmed"]
    )


def test_review_and_confirm_are_durable_linked_activity_rows(tmp_path, monkeypatch):
    import time

    import maverick.audit as audit
    from maverick.audit import AuditEvent, AuditLog

    sink = AuditLog(tmp_path / "activity", sign=True)

    def persist(kind, *, agent, goal_id=None, **payload):
        return sink.record(AuditEvent(ts=time.time(), kind=kind, agent=agent,
                                      goal_id=goal_id, payload=payload))

    monkeypatch.setattr(audit, "record_global", persist)
    assert save(client(), "synthetic-activity-key").status_code == 200
    rows = [row for row in sink.tail(10)
            if row.get("section") == "webhooks" and row.get("key") == "secret"]
    assert [(row["phase"], row["new"]) for row in rows] == [
        ("reviewed", "unconfirmed"), ("confirmed", "set")]
    assert rows[0]["operation_id"] == rows[1]["operation_id"]
    assert "synthetic-activity-key" not in repr(rows)
    assert sink.signing_enabled
    assert all(row.get("sig") for row in rows)
