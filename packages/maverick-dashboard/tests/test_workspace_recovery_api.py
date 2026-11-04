from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import client, config, control_plane_lease, crypto_at_rest, world_model
from maverick.paths import data_dir
from maverick_dashboard import recovery_api, recovery_mode
from maverick_dashboard.app import app


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_BACKUP_SIGNING_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", raising=False)
    # This fixture exercises local recovery; an independently configured live
    # PostgreSQL test fixture must not turn it into an external-store restore.
    monkeypatch.delenv("MAVERICK_PG_DSN", raising=False)
    monkeypatch.delenv("MAVERICK_KNOWLEDGE_DSN", raising=False)
    monkeypatch.setattr(config, "load_config", lambda: {"features": {"workspace_recovery": True}})
    monkeypatch.setattr(config, "config_source_errors", lambda **_: [])
    monkeypatch.setattr(recovery_api.recovery, "application_identity", lambda: "test-build-one")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", tmp_path / "shared-keys" / "at_rest.key")
    client.reset_client_cache()
    root = data_dir()
    root.mkdir(parents=True, exist_ok=True)
    (root / "record.json").write_text('{"value":"before"}')
    lifespan = app.router.lifespan_context
    mode = getattr(app.state, "workspace_recovery_mode", False)
    started = getattr(app.state, "workspace_recovery_started", False)
    yield root
    app.router.lifespan_context = lifespan
    app.state.workspace_recovery_mode = mode
    app.state.workspace_recovery_started = started
    control_plane_lease.release()
    client.reset_client_cache()


def api_client():
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_identity_transition_review_and_grant_preserve_admin_context_and_explicit_binding(monkeypatch):
    client = api_client()
    headers = context(client)
    endpoint = "/api/v1/recovery/installation/identity-transition"
    calls = []
    def review(value, *, isolated):
        calls.append((value, isolated))
        if not isolated:
            raise recovery_api.installation_recovery.MaintenanceError("isolated recovery is required")
        return {"sha256": "a" * 64, "publisher_os_trust_checked": False}
    monkeypatch.setattr(recovery_api.installation_recovery, "review_identity_transition", review)
    assert client.post(endpoint, json={"envelope": "synthetic-public-envelope"}).status_code == 409
    assert calls == []
    assert client.post(endpoint, headers=headers, json={"envelope": "synthetic-public-envelope"}).status_code == 409
    assert calls == [("synthetic-public-envelope", False)]
    monkeypatch.setattr(recovery_api, "isolated", lambda app: True)
    response = client.post(endpoint, headers=headers, json={"envelope": "synthetic-public-envelope"})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert response.json()["publisher_os_trust_checked"] is False
    grants = []
    def authorize(**kwargs):
        grants.append(kwargs)
        if kwargs.get("confirm_identity_transition") is not True:
            raise recovery_api.installation_recovery.MaintenanceError("explicit trust review required")
        return {"authorization": "synthetic-test-only"}
    monkeypatch.setattr(recovery_api.installation_recovery, "authorize", authorize)
    body = {"confirm": True, "confirm_all_workspaces": True, "review_id": "a" * 32, "identity_transition": "synthetic-public-envelope", "transition_sha256": "a" * 64}
    assert client.post("/api/v1/recovery/installation/authorize", headers=headers, json=body).status_code == 409
    body["confirm_identity_transition"] = True
    assert client.post("/api/v1/recovery/installation/authorize", headers=headers, json=body).status_code == 200
    assert grants[-1]["identity_transition"] == body["identity_transition"]
    assert grants[-1]["transition_sha256"] == "a" * 64 and grants[-1]["isolated"] is True
    def deny(*args):
        raise HTTPException(403, "global admin required")
    monkeypatch.setattr(recovery_api, "require_global_permission", deny)
    before = len(calls)
    assert client.post(endpoint, headers=headers, json={"envelope": "synthetic-public-envelope"}).status_code == 403
    assert len(calls) == before


def context(client):
    response = client.get("/api/v1/recovery/status")
    assert response.status_code == 200, response.text
    data = response.json()
    return {"X-Lightwork-Recovery-Context": data["context"], "X-Lightwork-Expected-Tenant": data["expected_tenant"]}


def test_typed_channel_operation_is_closed_explicit_and_rechecks_admin(monkeypatch):
    client = api_client()
    headers = context(client)
    endpoint = "/api/v1/recovery/operations/channel-review"
    answers = {"kind": "imessage_position", "position": "9007199254740993",
               "checked_at": "2026-09-27T12:00:00-04:00", "evidence_reference": "source-review-123"}
    body = {"confirm": True, "item_id": "a" * 32, "expected_review_token": "b" * 64, "answers": answers}
    calls = []
    def resolve(*args, **kwargs):
        calls.append((args, kwargs))
        if not kwargs["isolated"]:
            raise recovery_api.recovery.RecoveryError("Use isolated recovery")
        return {"state": "resolved", "item_id": args[0], "unresolved": 0,
                "automatic_replay_blocked": True, "normal_start_blocked": True}
    monkeypatch.setattr(recovery_api.recovery, "resolve_reconciliation", resolve)
    assert client.post(endpoint, json=body).status_code == 409
    assert not calls
    for invalid in ({**body, "confirm": "true"}, {**body, "command": "anything"},
                    {**body, "answers": {**answers, "position": 9007199254740993}},
                    {**body, "answers": {**answers, "kind": "unknown"}},
                    {**body, "answers": {**answers, "checkpoint": {}}}):
        assert client.post(endpoint, headers=headers, json=invalid).status_code == 422
    assert not calls
    assert client.post(endpoint, headers=headers, json={**body, "confirm": False}).status_code == 400
    assert not calls
    assert client.post(endpoint, headers=headers, json=body).status_code == 409
    monkeypatch.setattr(recovery_api, "isolated", lambda app: True)
    response = client.post(endpoint, headers=headers, json=body)
    assert response.status_code == 200 and response.headers["cache-control"] == "private, no-store"
    assert calls[-1][1]["channel_answers"] == answers
    assert calls[-1][1]["expected_review_token"] == body["expected_review_token"]
    assert calls[-1][1]["actor"] == headers["X-Lightwork-Recovery-Context"]
    before = len(calls)
    def deny(*args):
        raise HTTPException(403, "global admin required")
    monkeypatch.setattr(recovery_api, "require_global_permission", deny)
    assert client.post(endpoint, headers=headers, json=body).status_code == 403
    assert len(calls) == before


def setup_snapshot(client):
    headers = context(client)
    response = client.post("/api/v1/recovery/key", json={"confirm": True}, headers=headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    result = client.post("/api/v1/recovery/snapshots", json={"confirm": True}, headers=headers)
    assert result.status_code == 201, result.text
    return headers, result.json()["id"]


def test_comparison_routes_are_read_only_private_and_context_bound(workspace):
    client = api_client()
    headers, identifier = setup_snapshot(client)
    (workspace / "record.json").write_text("changed private document")
    endpoint = "/api/v1/recovery/snapshots/" + identifier
    assert client.post(endpoint + "/compare", json={}).status_code == 409
    assert client.post(endpoint + "/compare", headers=headers, json={"waive_guard": True}).status_code == 422
    compared = client.post(endpoint + "/compare", headers=headers, json={})
    assert compared.status_code == 200, compared.text
    assert compared.headers["cache-control"] == "private, no-store"
    report = compared.json()
    assert report["restore_authorized"] is False and report["isolated"] is False
    assert any(row["path"] == "record.json" and row["change"] == "changed" for row in report["items"])
    assert "changed private document" not in compared.text
    page = client.post(endpoint + "/comparison", headers=headers, json={"report_id": report["report_id"], "offset": 0, "limit": 1})
    assert page.status_code == 200 and len(page.json()["items"]) == 1
    assert client.post(endpoint + "/comparison", headers=headers, json={"report_id": report["report_id"], "offset": True}).status_code == 422
    assert client.post(endpoint + "/comparison/download", json={"report_id": report["report_id"]}).status_code == 409
    downloaded = client.post(endpoint + "/comparison/download", headers=headers, json={"report_id": report["report_id"]})
    assert downloaded.status_code == 200 and downloaded.headers["cache-control"] == "private, no-store"
    assert downloaded.headers["content-disposition"].endswith(identifier + '.json"')
    assert downloaded.json()["authentication"]["algorithm"] == "HMAC-SHA256"
    assert downloaded.json()["restore_authorized"] is False
    assert (workspace / "record.json").read_text() == "changed private document"
    assert not (workspace / "backups" / "recovery" / "review.json").exists()


def test_comparison_routes_reject_other_actor_and_admin_revocation(monkeypatch):
    client = api_client()
    headers, identifier = setup_snapshot(client)
    endpoint = "/api/v1/recovery/snapshots/" + identifier
    report = client.post(endpoint + "/compare", headers=headers, json={}).json()
    monkeypatch.setattr(recovery_api, "_authorization_principal", lambda _: "another-admin")
    other_headers = context(client)
    assert other_headers["X-Lightwork-Recovery-Context"] != headers["X-Lightwork-Recovery-Context"]
    assert client.post(endpoint + "/comparison", headers=other_headers, json={"report_id": report["report_id"]}).status_code == 409
    def deny(*_):
        raise HTTPException(403, "global admin required")
    monkeypatch.setattr(recovery_api, "require_global_permission", deny)
    assert client.post(endpoint + "/compare", headers=other_headers, json={}).status_code == 403
    assert client.post(endpoint + "/comparison/download", headers=other_headers, json={"report_id": report["report_id"]}).status_code == 403


def test_drill_report_survives_a_fresh_client_and_requires_current_context(workspace):
    first = api_client()
    headers, identifier = setup_snapshot(first)
    endpoint = "/api/v1/recovery/snapshots/" + identifier
    absent = first.post(endpoint + "/drill/report", headers=headers, json={})
    assert absent.status_code == 200 and absent.json()["state"] == "not_recorded"
    result = first.post(endpoint + "/drill", headers=headers, json={"confirm": True})
    assert result.status_code == 200, result.text
    report_id = result.json()["report_id"]
    (workspace / "record.json").write_text("newer live work")
    second = api_client()
    fresh_headers = context(second)
    loaded = second.post(endpoint + "/drill/report", headers=fresh_headers, json={})
    assert loaded.status_code == 200 and loaded.headers["cache-control"] == "private, no-store"
    assert loaded.json()["report_id"] == report_id and loaded.json()["current_build_matches"] is True
    assert loaded.json()["restore_authorized"] is False
    assert loaded.json()["completed_at"] == result.json()["completed_at"]
    assert second.post(endpoint + "/drill/report/download", json={"report_id": report_id}).status_code == 409
    downloaded = second.post(endpoint + "/drill/report/download", headers=fresh_headers, json={"report_id": report_id})
    assert downloaded.status_code == 200 and downloaded.headers["cache-control"] == "private, no-store"
    assert downloaded.json()["authentication"]["algorithm"] == "HMAC-SHA256"
    assert downloaded.json()["archive_sha256"] == result.json()["archive_sha256"]
    assert (workspace / "record.json").read_text() == "newer live work"


def test_recovery_page_and_assets_render_from_real_routes():
    client = api_client()
    assert client.get("/workspace/recovery").status_code == 200
    for suffix in ("js", "css"):
        response = client.get("/static/lightwork-workspace-recovery." + suffix)
        assert response.status_code == 200
        assert response.content


def test_retained_key_upload_requires_review_identity_and_bounded_stream(monkeypatch):
    client = api_client()
    headers, identifier = setup_snapshot(client)
    endpoint = "/api/v1/recovery/snapshots/" + identifier + "/custody-test"
    sha = recovery_api.recovery.inspect(identifier)["sha256"]
    admitted = {**headers, "Content-Type": "application/octet-stream",
                "X-Lightwork-Confirm-Custody-Test": "true", "X-Lightwork-Snapshot-SHA256": sha}
    calls = []
    def test_copy(selected, payload, **kwargs):
        assert isinstance(payload, bytes)
        calls.append((selected, payload, kwargs))
        return {"state": "recorded", "fixture": "admission-only"}
    monkeypatch.setattr(recovery_api.recovery, "test_key_custody", test_copy)
    def no_upload_directory(*_, **__):
        raise AssertionError("The API must not retain a second plaintext key ZIP outside worker cleanup")
    monkeypatch.setattr(recovery_api, "tempfile", SimpleNamespace(TemporaryDirectory=no_upload_directory))
    assert client.post(endpoint, content=b"fixture").status_code == 409
    assert client.post(endpoint, headers=headers, content=b"fixture").status_code == 400
    assert client.post(endpoint, headers={**admitted, "X-Lightwork-Confirm-Custody-Test": "false"}, content=b"fixture").status_code == 400
    assert client.post(endpoint, headers={**admitted, "Content-Type": "application/zip"}, content=b"fixture").status_code == 415
    assert client.post(endpoint, headers={**admitted, "X-Lightwork-Snapshot-SHA256": "0" * 64}, content=b"fixture").status_code == 409
    assert client.post(endpoint, headers=admitted, content=b"").status_code == 400
    monkeypatch.setattr(recovery_api.recovery, "MAX_CUSTODY_UPLOAD_BYTES", 4)
    assert client.post(endpoint, headers=admitted, content=iter([b"123", b"456"])).status_code == 413
    assert not calls
    result = client.post(endpoint, headers=admitted, content=b"keys")
    assert result.status_code == 200 and result.headers["cache-control"] == "private, no-store"
    assert len(calls) == 1 and calls[0][0] == identifier and calls[0][1] == b"keys"
    assert calls[0][2] == {"expected_sha256": sha, "actor": headers["X-Lightwork-Recovery-Context"]}
    def deny(*_):
        raise HTTPException(403, "admin removed")
    monkeypatch.setattr(recovery_api, "require_global_permission", deny)
    assert client.post(endpoint, headers=admitted, content=b"keys").status_code == 403
    assert len(calls) == 1


def test_retained_key_report_routes_require_current_context_and_strict_request(monkeypatch):
    client = api_client()
    headers, identifier = setup_snapshot(client)
    endpoint = "/api/v1/recovery/snapshots/" + identifier + "/custody-test/report"
    assert client.post(endpoint, json={}).status_code == 409
    assert client.post(endpoint, headers=headers, json={"install_keys": True}).status_code == 422
    absent = client.post(endpoint, headers=headers, json={})
    assert absent.status_code == 200 and absent.json() == {"state": "not_recorded", "snapshot": identifier}
    assert absent.headers["cache-control"] == "private, no-store"
    report = {"report_id": "a" * 32}
    assert client.post(endpoint + "/download", json=report).status_code == 409
    assert client.post(endpoint + "/download", headers=headers, json={**report, "waive_restore_guard": True}).status_code == 422
    assert client.post(endpoint + "/download", headers=headers, json=report).status_code == 409
    def deny(*_):
        raise HTTPException(403, "admin removed")
    monkeypatch.setattr(recovery_api, "require_global_permission", deny)
    assert client.post(endpoint, headers=headers, json={}).status_code == 403
    assert client.post(endpoint + "/download", headers=headers, json=report).status_code == 403


def test_bootstrap_key_install_resume_and_reconciliation_routes_are_strict_and_bound(
    monkeypatch,
):
    client = api_client()
    headers = context(client)
    monkeypatch.setattr(recovery_api, "isolated", lambda app: True)
    calls = []

    def prepared(**kwargs):
        calls.append(("prepare", kwargs))
        return {"state": "prepared", "bootstrap_id": "a" * 32}

    def installed(identifier, payload, **kwargs):
        calls.append(("install", identifier, payload, kwargs))
        return {"state": "installed", "file_count": 1, "key_set_sha256": "b" * 64}

    def resumed(**kwargs):
        calls.append(("resume", kwargs))
        return {"state": "prepared", "outcome": "rolled_back_to_empty"}

    def status(*, actor):
        calls.append(("status", actor))
        return {"state": "reconciliation_required", "items": [], "unresolved": 0}

    def resolve(item_id, disposition, **kwargs):
        calls.append(("resolve", item_id, disposition, kwargs))
        return {"state": "resolved", "item_id": item_id, "unresolved": 0}

    def complete(**kwargs):
        calls.append(("complete", kwargs))
        return {"state": "completed", "post_restore_verified": True}

    monkeypatch.setattr(recovery_api.recovery, "prepare_bootstrap", prepared)
    monkeypatch.setattr(recovery_api.recovery, "install_retained_keys", installed)
    monkeypatch.setattr(recovery_api.recovery, "resume_bootstrap_restore", resumed)
    monkeypatch.setattr(recovery_api.recovery, "reconciliation_status", status)
    monkeypatch.setattr(recovery_api.recovery, "resolve_reconciliation", resolve)
    monkeypatch.setattr(recovery_api.recovery, "complete_reconciliation", complete)

    assert client.post("/api/v1/recovery/bootstrap/prepare", json={
        "confirm": True, "source_offline": True,
    }).status_code == 409
    assert client.post("/api/v1/recovery/bootstrap/prepare", headers=headers, json={
        "confirm": True, "source_offline": False,
    }).status_code == 400
    assert client.post("/api/v1/recovery/bootstrap/prepare", headers=headers, json={
        "confirm": True, "source_offline": "true",
    }).status_code == 422
    assert client.post("/api/v1/recovery/bootstrap/prepare", headers=headers, json={
        "confirm": True, "source_offline": True,
    }).status_code == 200

    install_path = "/api/v1/recovery/snapshots/" + "c" * 32 + "/retained-keys/install"
    key_headers = {
        **headers,
        "Content-Type": "application/octet-stream",
        "X-Lightwork-Confirm-Key-Install": "true",
        "X-Lightwork-Snapshot-SHA256": "d" * 64,
        "X-Lightwork-Custody-Report": "e" * 32,
    }
    assert client.post(install_path, headers=headers, content=b"keys").status_code == 400
    assert client.post(install_path, headers={**key_headers, "X-Lightwork-Custody-Report": "bad"}, content=b"keys").status_code == 400
    assert client.post(install_path, headers=key_headers, content=b"").status_code == 400
    installed_response = client.post(install_path, headers=key_headers, content=b"keys")
    assert installed_response.status_code == 200
    assert calls[-1] == ("install", "c" * 32, b"keys", {
        "expected_sha256": "d" * 64,
        "report_id": "e" * 32,
        "isolated": True,
        "actor": headers["X-Lightwork-Recovery-Context"],
    })

    assert client.post("/api/v1/recovery/bootstrap/resume", headers=headers, json={"confirm": False}).status_code == 400
    assert client.post("/api/v1/recovery/bootstrap/resume", headers=headers, json={"confirm": True}).status_code == 200
    reconciled = client.get("/api/v1/recovery/reconciliation")
    assert reconciled.status_code == 200 and reconciled.headers["cache-control"] == "private, no-store"
    assert reconciled.json()["state"] == "reconciliation_required"
    item = "f" * 32
    body = {"confirm": True, "disposition": "external_effect_absent", "evidence_reference": "ticket-123"}
    assert client.post(f"/api/v1/recovery/reconciliation/items/{item}", headers=headers, json={**body, "force": True}).status_code == 422
    assert client.post(f"/api/v1/recovery/reconciliation/items/{item}", headers=headers, json=body).status_code == 200
    assert calls[-1] == ("resolve", item, "external_effect_absent", {
        "evidence_reference": "ticket-123", "isolated": True,
        "actor": headers["X-Lightwork-Recovery-Context"],
    })
    channel_body = {"confirm": True, "disposition": "channel_readback_confirmed", "channel_readback": {"schema": 1}}
    assert client.post(f"/api/v1/recovery/reconciliation/items/{item}", json=channel_body).status_code == 409
    assert client.post(f"/api/v1/recovery/reconciliation/items/{item}", headers=headers, json=channel_body).status_code == 200
    assert calls[-1] == ("resolve", item, "channel_readback_confirmed", {
        "evidence_reference": None, "channel_readback": {"schema": 1}, "isolated": True,
        "actor": headers["X-Lightwork-Recovery-Context"],
    })
    assert client.post("/api/v1/recovery/reconciliation/complete", headers=headers, json={"confirm": True}).status_code == 200
    assert calls[-1] == ("complete", {
        "isolated": True, "actor": headers["X-Lightwork-Recovery-Context"],
    })


def test_disabled_feature_refuses_recovery_api(monkeypatch):
    monkeypatch.setattr(config, "get_features", lambda: {"workspace_recovery": False})
    assert api_client().get("/api/v1/recovery/status").status_code == 403


def test_installation_authorization_needs_admin_context_and_strict_whole_home_review(monkeypatch):
    client = api_client()
    headers = context(client)
    calls = []
    def authorize(**kwargs):
        calls.append(kwargs)
        return {"authorization": "a" * 32 + ":" + "b" * 64}
    monkeypatch.setattr(recovery_api.installation_recovery, "authorize", authorize)
    endpoint = "/api/v1/recovery/installation/authorize"
    assert client.post(endpoint, json={"confirm": True, "confirm_all_workspaces": True, "review_id": "a" * 32}).status_code == 409
    assert client.post(endpoint, headers=headers, json={"confirm": True, "confirm_all_workspaces": "true"}).status_code == 422
    response = client.post(endpoint, headers=headers, json={"confirm": True, "confirm_all_workspaces": True, "review_id": "a" * 32})
    assert response.status_code == 200 and response.headers["cache-control"] == "private, no-store"
    assert calls[0]["isolated"] is False  # the core must reject normal mode
    assert calls[0]["actor"] == headers["X-Lightwork-Recovery-Context"]
    def deny(*_):
        raise HTTPException(403, "global admin required")
    monkeypatch.setattr(recovery_api, "require_global_permission", deny)
    assert client.post(endpoint, headers=headers, json={"confirm": True, "confirm_all_workspaces": True, "review_id": "a" * 32}).status_code == 403
    assert client.get("/api/v1/recovery/installation").status_code == 403
    assert len(calls) == 1


def test_real_installation_core_refuses_normal_dashboard_authorization():
    client = api_client()
    response = client.post("/api/v1/recovery/installation/authorize", headers=context(client),
                           json={"confirm": True, "confirm_all_workspaces": True, "review_id": "a" * 32})
    assert response.status_code == 409
    assert "recovery mode" in response.json()["detail"]


def test_global_admin_gate_applies_before_recovery_reads_and_downloads(monkeypatch):
    def deny(*_):
        raise HTTPException(403, "global admin required")
    monkeypatch.setattr(recovery_api, "require_global_permission", deny)
    client = api_client()
    assert client.get("/workspace/recovery").status_code == 403
    assert client.get("/api/v1/recovery/status").status_code == 403
    assert client.post("/api/v1/recovery/key/download", json={"confirm": True}).status_code == 403


def test_key_creation_needs_same_account_context_and_explicit_true(monkeypatch):
    client = api_client()
    headers = context(client)
    path = "/api/v1/recovery/key"
    assert client.post(path, json={"confirm": True}).status_code == 409
    assert client.post(path, json={"confirm": False}, headers=headers).status_code == 400
    assert client.post(path, json={"confirm": "true"}, headers=headers).status_code == 422
    monkeypatch.setattr(recovery_api, "_authorization_principal", lambda _: "other-account")
    assert client.post(path, json={"confirm": True}, headers=headers).status_code == 409


def test_non_ascii_recovery_context_header_is_refused_as_changed_not_a_server_error():
    client = api_client()
    headers = {**context(client), "X-Lightwork-Recovery-Context": "contéxt".encode()}
    assert client.post("/api/v1/recovery/key", json={"confirm": True}, headers=headers).status_code == 409


def test_installation_retirement_requires_global_authority_context_and_explicit_review(monkeypatch):
    client = api_client()
    headers = context(client)
    path = "/api/v1/recovery/installation/" + "a" * 32 + "/retire"
    calls = []
    def retire(identifier, **kwargs):
        calls.append((identifier, kwargs))
        return {"retired": True, "id": identifier}
    monkeypatch.setattr(recovery_api.installation_recovery, "retire", retire)
    body = {"confirm": True, "sha256": "b" * 64}
    assert client.post(path, json=body).status_code == 409
    assert client.post(path, json={**body, "confirm": False}, headers=headers).status_code == 400
    assert client.post(path, json={**body, "confirm": "true"}, headers=headers).status_code == 422
    assert client.post(path, json={**body, "sha256": "changed"}, headers=headers).status_code == 422
    assert not calls
    result = client.post(path, json=body, headers=headers)
    assert result.status_code == 200 and result.json()["retired"]
    assert result.headers["cache-control"] == "private, no-store"
    assert calls == [("a" * 32, {"expected_sha256": "b" * 64, "actor": headers["X-Lightwork-Recovery-Context"], "confirm": True})]
    def deny(*_):
        raise HTTPException(403, "global admin required")
    monkeypatch.setattr(recovery_api, "require_global_permission", deny)
    assert client.post(path, json=body, headers=headers).status_code == 403
    assert len(calls) == 1


def test_installation_retirement_rejects_a_changed_review_without_claiming_success(monkeypatch):
    client = api_client()
    headers = context(client)
    def changed(*_, **kwargs):
        raise recovery_api.installation_recovery.MaintenanceError("The installation recovery point changed.")
    monkeypatch.setattr(recovery_api.installation_recovery, "retire", changed)
    result = client.post("/api/v1/recovery/installation/" + "a" * 32 + "/retire", json={"confirm": True, "sha256": "b" * 64}, headers=headers)
    assert result.status_code == 409
    assert "changed" in result.json()["detail"]


def test_encryption_key_export_requires_shared_key_consent_and_never_logs_keys():
    client = api_client()
    headers, _ = setup_snapshot(client)
    crypto_at_rest._KEY_PATH.parent.mkdir()
    crypto_at_rest._KEY_PATH.write_text(bytes(range(32)).hex())
    path = "/api/v1/recovery/encryption-keys/download"
    assert client.post(path, json={"confirm": True, "confirm_shared_keys": False}, headers=headers).status_code == 400
    assert client.post(path, json={"confirm": True, "confirm_shared_keys": "true"}, headers=headers).status_code == 422
    result = client.post(path, json={"confirm": True, "confirm_shared_keys": True}, headers=headers)
    assert result.status_code == 200 and result.content[:2] == b"PK"
    assert result.headers["cache-control"] == "private, no-store"
    assert bytes(range(32)).hex() not in client.get("/api/v1/recovery/status").text


def test_recovery_upload_preserves_same_origin_csrf_gate():
    client = api_client()
    headers = context(client)
    result = client.post("/api/v1/recovery/import", content=b"untrusted", headers={**headers, "Origin": "https://other.example.test", "Content-Type": "application/octet-stream"})
    assert result.status_code == 403


def test_snapshot_drill_and_download_never_enable_live_restore(workspace):
    client = api_client()
    headers, identifier = setup_snapshot(client)
    base = "/api/v1/recovery/snapshots/" + identifier
    assert client.post(base + "/inspect", headers=headers).json()["authenticated"]
    response = client.post(base + "/download", headers=headers)
    assert response.status_code == 200 and response.content[:2] == b"\x1f\x8b"
    result = client.post(base + "/drill", json={"confirm": True}, headers=headers)
    assert result.status_code == 200, result.text
    assert result.json()["live_workspace_changed"] is False
    assert client.post(base + "/prepare", json={"confirm": True}, headers=headers).status_code == 409
    assert (workspace / "record.json").read_text() == '{"value":"before"}'


def test_import_size_and_paths_are_bounded(monkeypatch):
    client = api_client()
    headers = context(client)
    monkeypatch.setattr(recovery_api.recovery, "MAX_UPLOAD_BYTES", 8)
    response = client.post("/api/v1/recovery/import", content=b"more than eight bytes", headers={**headers, "Content-Type": "application/octet-stream"})
    assert response.status_code == 413
    assert client.post("/api/v1/recovery/snapshots/not-a-server-id/inspect", headers=headers).status_code == 409


def test_isolated_startup_skips_all_composed_normal_lifespans_and_blocks_work(workspace):
    async def forbidden(*_):
        raise AssertionError("A normal background lifespan must never start in recovery mode")
    app.router.lifespan_context = forbidden
    recovery_mode.configure(app, host="127.0.0.1")
    with api_client() as client:
        assert recovery_mode.isolated(app)
        assert client.get("/livez").status_code == 200
        assert client.get("/get-started").status_code == 503
        assert client.post("/api/v1/goals", json={}).status_code == 503
        assert client.get("/workspace/recovery").status_code == 200
        support = client.get("/help")
        assert support.status_code == 200
        assert "Prepare support report" in support.text
        assert support.headers["cache-control"] == "private, no-store"
        # Recovery middleware admits the in-app support API. Feature or
        # authority policy may still refuse the operation, but normal-work
        # middleware must not replace that decision with its blanket 503.
        assert client.post("/api/v1/support/preview", json={}).status_code != 503
        headers, identifier = setup_snapshot(client)
        (workspace / "record.json").write_text("after")
        response = client.post("/api/v1/recovery/snapshots/" + identifier + "/prepare", json={"confirm": True}, headers=headers)
        assert response.status_code == 200, response.text
        review = response.json()
        result = client.post("/api/v1/recovery/restore", json={"confirm": True, "review": review["review"], "target": review["target"]}, headers=headers)
        assert result.status_code == 200, result.text
        assert result.json()["restored"] and result.json()["post_restore_verified"]
        assert (workspace / "record.json").read_text() == '{"value":"before"}'
    assert control_plane_lease.current() is None


def test_recovery_cannot_bind_an_external_network_interface():
    with pytest.raises(RuntimeError, match="loopback"):
        recovery_mode.configure(app, host="0.0.0.0")


def test_no_lease_means_no_restore_even_when_mode_flag_is_set():
    app.state.workspace_recovery_mode = True
    app.state.workspace_recovery_started = True
    control_plane_lease.release()
    assert recovery_mode.isolated(app) is False


@pytest.mark.parametrize("other_root", [False, True])
def test_existing_control_plane_lease_is_not_recovery_authority(tmp_path, other_root):
    control_plane_lease.acquire(tmp_path / "other" if other_root else None, role="control-plane")
    app.state.workspace_recovery_mode = True
    app.state.workspace_recovery_started = True
    assert recovery_mode.isolated(app) is False
    recovery_mode.configure(app, host="127.0.0.1")
    with pytest.raises(RuntimeError, match="existing control plane"):
        with api_client():
            pass
    assert control_plane_lease.current() is not None


def test_checkpoint_lookup_requires_context_and_rechecks_current_permission(monkeypatch):
    client = api_client()
    headers = context(client)
    monkeypatch.setattr(recovery_api, "isolated", lambda app: True)
    calls = []
    def lookup(item, **kwargs):
        calls.append((item, kwargs))
        return {"available": False, "candidates": [], "notice": "Source unavailable; no position guessed."}
    monkeypatch.setattr(recovery_api.recovery, "channel_checkpoint_lookup", lookup)
    body = {"item_id": "a" * 32, "expected_review_token": "b" * 64, "before": None}
    endpoint = "/api/v1/recovery/operations/channel-source-lookup"
    assert client.post(endpoint, json=body).status_code == 409
    assert calls == []
    result = client.post(endpoint, headers=headers, json=body)
    assert result.status_code == 200 and result.headers["cache-control"] == "private, no-store"
    assert result.json()["available"] is False
    assert calls[0][1]["actor"] == headers["X-Lightwork-Recovery-Context"]
    seen = []
    def revoked(*args):
        seen.append(1)
        if len(seen) == 2:
            raise HTTPException(403, "access revoked during lookup")
    monkeypatch.setattr(recovery_api, "require_global_permission", revoked)
    result = client.post(endpoint, headers=headers, json=body)
    assert result.status_code == 403


def handoff_request(monkeypatch, publish):
    from maverick import installation_handoff
    client = api_client()
    headers = context(client)
    monkeypatch.setattr(recovery_api, "isolated", lambda app: True)
    grant = {"id": "a" * 32, "authorization": "a" * 32 + ":" + "b" * 64}
    monkeypatch.setattr(recovery_api.installation_recovery, "authorize", lambda **kwargs: dict(grant))
    monkeypatch.setattr(installation_handoff, "publish", publish)
    discarded = []
    monkeypatch.setattr(recovery_api.installation_recovery, "discard_authorization",
                        lambda token, *, actor: discarded.append((token, actor)))
    body = {"confirm": True, "confirm_all_workspaces": True, "review_id": "c" * 32, "native_handoff": True}
    response = client.post("/api/v1/recovery/installation/authorize", headers=headers, json=body)
    return response, discarded, grant


def test_a_published_handoff_keeps_its_grant_for_the_native_application(monkeypatch):
    response, discarded, grant = handoff_request(monkeypatch, lambda token, *, actor_label: {"id": grant_id(token)})
    assert response.status_code == 200
    assert response.json()["native_handoff"] is True
    assert discarded == []


def test_a_handoff_that_cannot_be_published_retires_the_grant_the_browser_never_received(monkeypatch):
    def refused(token, *, actor_label):
        raise recovery_api.installation_recovery.MaintenanceError("The native handoff could not be saved.")
    response, discarded, grant = handoff_request(monkeypatch, refused)
    assert response.status_code == 409
    assert grant["authorization"] not in response.text
    assert [token for token, _ in discarded] == [grant["authorization"]]
    assert discarded[0][1]                                  # retired under the administrator's own name


def grant_id(token):
    return token.split(":", 1)[0]


def test_recovery_mode_still_identifies_itself_to_the_desktop_readiness_check(monkeypatch):
    # The desktop's recovery page waits for /healthz to answer 200 or 503 with
    # exactly one dashboard identity; the blanket 503 carried none, so entering
    # recovery from the desktop app always ended in "did not respond".
    async def no_deep_checks(**_kwargs):
        raise AssertionError("Recovery mode must not open the workspace for a health probe")

    monkeypatch.setattr("maverick_dashboard.app._health_response", no_deep_checks)
    recovery_mode.configure(app, host="127.0.0.1")
    with api_client() as client:
        response = client.get("/healthz")
        assert response.status_code == 503
        assert response.headers.get_list("X-Lightwork-Service") == ["dashboard-v1"]
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["status"] == "recovery"
        assert client.get("/readyz").status_code == 503
        assert "x-lightwork-service" not in client.get("/get-started").headers
        # The splash (Reconnect Lightwork) and Open in browser go to "/" once
        # the identity answers; in recovery mode that is the recovery page.
        for method in (client.get, client.head):
            home = method("/", follow_redirects=False)
            assert home.status_code == 303
            assert home.headers["location"] == "/workspace/recovery"
            assert home.headers["cache-control"] == "no-store"
        assert client.post("/", follow_redirects=False).status_code == 503
        assert client.get("/", follow_redirects=True).url.path == "/workspace/recovery"
