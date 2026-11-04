"""Support exports are reviewed, redacted, and bound to current authority."""
import hashlib
import json
import os
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import crypto_at_rest, world_model
from maverick_dashboard import support_api
from maverick_dashboard.app import app


@pytest.fixture
def support(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", bytes(range(32)).hex())
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(support_api.config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr(support_api.config, "get_features", lambda: {"support_center": True})
    monkeypatch.setattr(crypto_at_rest, "per_tenant_at_rest", lambda: False)
    monkeypatch.setattr(crypto_at_rest, "_active_keyring_key", lambda: None)
    identity = {"context": "a" * 64, "admin": True}
    def require_admin(request, permission):
        assert permission == "admin"
        if not identity["admin"]:
            raise HTTPException(403, "Administrator access ended.")
    monkeypatch.setattr(support_api, "require_global_permission", require_admin)
    monkeypatch.setattr(support_api, "context_for", lambda request: identity["context"])
    monkeypatch.setattr(support_api.support_bundle, "collect", lambda: {
        "correlation_id": "synthetic-reference", "readiness": {"client_binding": "ok"},
        "config_redacted": {"password": "synthetic-private-value"},  # pragma: allowlist secret
    })
    audits = []
    monkeypatch.setattr("maverick.audit.record", lambda *args, **kwargs: audits.append((args, kwargs)))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "X-Lightwork-Support-Context": identity["context"]}), identity, audits


def test_export_requires_review_and_downloads_exact_redacted_preview(support):
    client, _identity, audits = support
    preview = client.post("/api/v1/support/preview", json={})
    assert preview.status_code == 200, preview.text
    assert preview.headers["cache-control"] == "private, no-store"
    data = preview.json()
    assert "synthetic-private-value" not in preview.text
    assert data["bundle"]["config_redacted"]["password"] == "[REDACTED]"
    body = {key: data[key] for key in ("preview_id", "sha256")}
    assert client.post("/api/v1/support/download", json={**body, "confirm": False}).status_code == 422
    assert client.post("/api/v1/support/download", json={**body, "sha256": "0" * 64, "confirm": True}).status_code == 409
    response = client.post("/api/v1/support/download", json={**body, "confirm": True})
    assert response.status_code == 200, response.text
    assert hashlib.sha256(response.content).hexdigest() == data["sha256"]
    assert json.loads(response.content) == data["bundle"]
    assert response.headers["content-disposition"].startswith("attachment;")
    assert len(audits) == 1 and "config_redacted" not in json.dumps(audits)


def test_support_feature_lock_blocks_collection_and_existing_download(support, monkeypatch):
    client, _identity, audits = support
    preview = client.post("/api/v1/support/preview", json={}).json()
    monkeypatch.setattr(support_api.config, "get_features", lambda: {"support_center": False})
    body = {key: preview[key] for key in ("preview_id", "sha256")}
    assert client.post("/api/v1/support/preview", json={}).status_code == 403
    assert client.post("/api/v1/support/download", json={**body, "confirm": True}).status_code == 403
    assert not audits


def test_expired_context_or_admin_cannot_collect_or_download_preview(support):
    client, identity, audits = support
    preview = client.post("/api/v1/support/preview", json={}).json()
    body = {key: preview[key] for key in ("preview_id", "sha256")}
    body["confirm"] = True
    identity["admin"] = False
    assert client.post("/api/v1/support/preview", json={}).status_code == 403
    assert client.post("/api/v1/support/download", json=body).status_code == 403
    identity.update(admin=True, context="b" * 64)
    assert client.post("/api/v1/support/download", json=body).status_code == 409
    assert client.post("/api/v1/support/download", headers={"X-Lightwork-Support-Context": identity["context"]}, json=body).status_code == 409
    assert not audits


def test_non_ascii_support_context_header_is_refused_as_changed_not_a_server_error(support):
    client, _identity, audits = support
    stale = {"X-Lightwork-Support-Context": "contéxt".encode()}
    assert client.post("/api/v1/support/preview", headers=stale, json={}).status_code == 409
    assert not audits


def test_preview_expiry_and_encryption_refuse_unreviewed_download(support, monkeypatch):
    client, identity, audits = support
    preview = client.post("/api/v1/support/preview", json={}).json()
    path = support_api._directory(identity["context"]) / (preview["preview_id"] + ".preview")
    assert crypto_at_rest.is_sealed(path.read_bytes())
    body = {"preview_id": preview["preview_id"], "sha256": preview["sha256"], "confirm": True}
    now = support_api.time.time()
    with monkeypatch.context() as clock:
        clock.setattr(support_api.time, "time", lambda: now + support_api.LIFETIME + 1)
        assert client.post("/api/v1/support/download", json=body).status_code == 409
    path.write_text("{}")
    assert client.post("/api/v1/support/download", json=body).status_code == 409
    assert not audits


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-path regression")
def test_preview_download_supports_long_windows_profile_paths(support, monkeypatch):
    client, identity, audits = support
    base = Path(os.environ["MAVERICK_HOME"])
    long_home = base.joinpath(*(("profile-" + "x" * 55,) * 4))
    monkeypatch.setenv("MAVERICK_HOME", str(long_home))

    preview = client.post("/api/v1/support/preview", json={})
    assert preview.status_code == 200, preview.text
    data = preview.json()
    logical = support_api._directory(identity["context"]) / (data["preview_id"] + ".preview")
    assert len(str(logical.resolve())) > 260
    body = {
        "preview_id": data["preview_id"],
        "sha256": data["sha256"],
        "confirm": True,
    }
    downloaded = client.post("/api/v1/support/download", json=body)
    assert downloaded.status_code == 200, downloaded.text
    assert hashlib.sha256(downloaded.content).hexdigest() == data["sha256"]
    assert len(audits) == 1
