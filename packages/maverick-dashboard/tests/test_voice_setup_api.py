"""Real bounded download jobs with synthetic bytes; no provider/model network."""
from __future__ import annotations

import contextvars
import hashlib
import io
import threading

import pytest
from fastapi.testclient import TestClient
from maverick import config, voice_models, world_model
from maverick_dashboard import auth
from maverick_dashboard import voice_setup_api as setup
from maverick_dashboard.app import app

from test_support.starlette_state import patch_state

PAYLOAD = b"synthetic speech model"
ENDPOINT = "/api/v1/voice/setup"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_WHISPER_MODEL", "MAVERICK_WHISPER_CPP_MODEL", "MAVERICK_VOICE_STT_BACKEND",
                 "MAVERICK_VOICE_COMMANDS", "MAVERICK_VOICE_AUTO_FETCH", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(config, "load_global_config", dict)
    monkeypatch.setattr(config, "config_source_errors", lambda **_: [])
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(setup, "_engine_available", lambda: False)
    patch_state(monkeypatch, app.state, "voice_setup", setup.VoiceSetup())
    monkeypatch.setitem(voice_models.KNOWN_MODELS, "base", ("ggml-base.bin", hashlib.sha256(PAYLOAD).hexdigest(), len(PAYLOAD)))
    monkeypatch.setattr(voice_models, "_open_model_url", lambda *_, **__: io.BytesIO(PAYLOAD))
    yield
    app.state.voice_setup.stop()


def test_actual_lifespan_and_first_start_do_not_fetch_without_opt_in(monkeypatch):
    from maverick.tools import voice
    for key in ("OPENAI_API_KEY", "GROQ_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    calls = []
    def unexpected(*_, **__):
        calls.append("download")
        raise AssertionError("Opening the app must not download speech weights")
    monkeypatch.setattr(voice_models, "download_model", unexpected)
    with client() as c:
        app.state.voice_warmup_thread.join(timeout=3)
        assert c.get("/start").status_code == 200
        assert calls == []
    assert not voice.stt_warming()
    assert not app.state.voice_warmup_thread.is_alive()


def client():
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def review(c):
    response = c.get(ENDPOINT)
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "private, no-store"
    data = response.json()
    model = data["model"]
    return {"X-Lightwork-Voice-Context": data["context"]}, {
        "confirm": True, "model": model["id"], "sha256": model["sha256"], "size_bytes": model["size_bytes"]}


def finish():
    app.state.voice_setup.thread.join(timeout=3)
    assert not app.state.voice_setup.thread.is_alive()


def test_get_never_downloads_or_hashes_and_existing_files_are_unverified(monkeypatch):
    dest = voice_models.model_path("base")
    dest.parent.mkdir(parents=True)
    dest.write_bytes(PAYLOAD)
    monkeypatch.setattr(voice_models, "verify_model", lambda *_: pytest.fail("GET hashed weights"))
    monkeypatch.setattr(voice_models, "_open_model_url", lambda *_, **__: pytest.fail("GET downloaded"))
    data = client().get(ENDPOINT).json()
    assert data["model_state"] == "present_unverified"
    assert data["engine_available"] is False and data["job"] is None
    assert data["configuration"]["auto_fetch"] is False


def test_reviewed_download_repairs_corrupt_file_and_reload_preserves_evidence():
    c = client()
    headers, body = review(c)
    dest = voice_models.model_path("base")
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"corrupt")
    response = c.post(ENDPOINT + "/download", headers=headers, json=body)
    assert response.status_code == 202, response.text
    finish()
    data = client().get(ENDPOINT, headers=headers).json()
    assert data["model_state"] == "verified" and data["job"]["state"] == "ready"
    assert data["job"]["received_bytes"] == len(PAYLOAD)
    assert data["engine_available"] is False
    assert dest.read_bytes() == PAYLOAD
    dest.write_bytes(b"subsequent corruption")
    changed = c.get(ENDPOINT).json()
    assert changed["model_state"] == "present_unverified"
    assert changed["job"]["state"] == "failed"
    assert "changed or was removed" in changed["job"]["error"]
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 202
    finish()
    result = c.get(ENDPOINT).json()
    assert result["model_state"] == "verified", result


def test_replacement_after_download_verification_is_never_marked_ready(monkeypatch):
    dest = voice_models.model_path("base")
    dest.parent.mkdir(parents=True)
    dest.write_bytes(PAYLOAD)
    original = voice_models.verify_model
    def raced(path, **kwargs):
        verified = original(path, **kwargs)
        path.write_bytes(b"X" * len(PAYLOAD))
        return verified
    monkeypatch.setattr(voice_models, "verify_model", raced)
    c = client()
    headers, body = review(c)
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 202
    finish()
    data = c.get(ENDPOINT).json()
    assert data["job"]["state"] == "failed"
    assert data["model_state"] == "present_unverified"


def test_shutdown_cancels_read_and_removes_partial(monkeypatch):
    entered = threading.Event()
    class ShutdownRead(io.BytesIO):
        def read(self, n):
            entered.set()
            assert app.state.voice_setup.cancel.wait(2)
            return super().read(n)
    monkeypatch.setattr(voice_models, "_open_model_url", lambda *_, **__: ShutdownRead(PAYLOAD))
    c = client()
    headers, body = review(c)
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 202
    assert entered.wait(2)
    setup.stop_setup(app)
    assert not app.state.voice_setup.thread.is_alive()
    assert app.state.voice_setup.job["state"] == "cancelled"
    assert not list(voice_models.models_dir().glob("*.part"))


def test_mutation_requires_current_review_fixed_catalog_and_same_origin():
    c = client()
    headers, body = review(c)
    assert c.post(ENDPOINT + "/download", json=body).status_code == 409
    assert c.post(ENDPOINT + "/download", headers=headers, json={**body, "confirm": False}).status_code == 400
    assert c.post(ENDPOINT + "/download", headers=headers, json={**body, "size_bytes": 100}).status_code == 409
    assert c.post(ENDPOINT + "/download", headers=headers, json={**body, "model": "tiny"}).status_code == 409
    assert c.post(ENDPOINT + "/download", headers=headers, json={**body, "url": "https://example.com"}).status_code == 422
    assert c.post(ENDPOINT + "/download", headers={**headers, "Origin": "https://other.example"}, json=body).status_code == 403
    assert app.state.voice_setup.job is None


def test_non_ascii_voice_context_header_is_refused_as_changed_not_a_server_error():
    c = client()
    _headers, body = review(c)
    stale = {"X-Lightwork-Voice-Context": "contéxt".encode()}
    assert c.get(ENDPOINT, headers=stale).status_code == 409
    assert c.post(ENDPOINT + "/download", headers=stale, json=body).status_code == 409
    assert app.state.voice_setup.job is None


def test_tenant_admin_cannot_control_shared_model_and_old_account_context_is_refused(monkeypatch):
    c = client()
    headers, body = review(c)
    monkeypatch.setattr(setup, "_authorization_principal", lambda _: "another-admin")
    assert c.get(ENDPOINT, headers=headers).status_code == 409
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 409
    monkeypatch.setattr(auth, "_authorization_principal", lambda _: "tenant-admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda _: "operator")
    monkeypatch.setattr(auth, "role_for_principal", lambda _: "admin")
    assert c.get(ENDPOINT).status_code == 403
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 403


@pytest.mark.parametrize("_attempt", range(5))
def test_singleflight_cancel_keeps_good_file_and_deletes_partial(monkeypatch, _attempt):
    entered, release = threading.Event(), threading.Event()
    class Slow(io.BytesIO):
        def read(self, n):
            entered.set()
            assert release.wait(3)
            return super().read(n)
    monkeypatch.setattr(voice_models, "_open_model_url", lambda *_, **__: Slow(PAYLOAD))
    c = client()
    headers, body = review(c)
    first = c.post(ENDPOINT + "/download", headers=headers, json=body)
    assert first.status_code == 202
    assert entered.wait(2)
    try:
        assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 409
        job = c.get(ENDPOINT).json()["job"]
        assert job["id"] == first.json()["job"]["id"]
        assert c.post(ENDPOINT + "/cancel", headers=headers, json={"job_id": "0" * 32}).status_code == 409
        cancelled = c.post(ENDPOINT + "/cancel", headers=headers, json={"job_id": job["id"]})
        assert cancelled.json()["job"]["state"] == "cancelling"
    finally:
        release.set()
        finish()
    data = c.get(ENDPOINT).json()
    assert data["job"]["state"] == "cancelled" and data["model_state"] == "missing"
    assert not list(voice_models.models_dir().glob("*.part"))
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 202
    finish()
    result = c.get(ENDPOINT).json()
    assert result["model_state"] == "verified", (result["job"]["error"], app.state.voice_setup.fingerprint,
        voice_models.model_fingerprint(voice_models.model_path("base").stat()))


def test_failure_is_redacted_and_retry_works(monkeypatch):
    def failed(*_, **__):
        raise OSError("https://secret-user:secret-password@proxy/private-path")  # pragma: allowlist secret -- synthetic redaction fixture
    monkeypatch.setattr(voice_models, "_open_model_url", failed)
    c = client()
    headers, body = review(c)
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 202
    finish()
    response = c.get(ENDPOINT)
    assert response.json()["job"]["state"] == "failed"
    assert "secret" not in response.text and "private-path" not in response.text
    monkeypatch.setattr(voice_models, "_open_model_url", lambda *_, **__: io.BytesIO(PAYLOAD))
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 202
    finish()
    assert c.get(ENDPOINT).json()["model_state"] == "verified"


def test_worker_retains_request_context_and_refuses_changed_configuration(monkeypatch):
    scope = contextvars.ContextVar("test-voice-policy", default="missing")
    scope.set("reviewed-workspace")
    seen = []
    def open_url(*_, **__):
        seen.append(scope.get())
        monkeypatch.setenv("MAVERICK_WHISPER_MODEL", "tiny")
        return io.BytesIO(PAYLOAD)
    monkeypatch.setattr(voice_models, "_open_model_url", open_url)
    target = setup._target()
    manager = app.state.voice_setup
    manager.start(target, setup._target_key(target))
    finish()
    assert seen == ["reviewed-workspace"]
    assert manager.job["state"] == "cancelled"
    assert not voice_models.model_path("base").exists()
    assert not list(voice_models.models_dir().glob("*.part"))


def test_cancel_after_verification_cannot_publish_ready(monkeypatch):
    original = voice_models.verified_model_fingerprint
    def cancelled(path, **kwargs):
        fingerprint = original(path, **kwargs)
        app.state.voice_setup.cancel.set()
        return fingerprint
    monkeypatch.setattr(voice_models, "verified_model_fingerprint", cancelled)
    c = client()
    headers, body = review(c)
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 202
    finish()
    assert c.get(ENDPOINT).json()["job"]["state"] == "cancelled"
    assert app.state.voice_setup.fingerprint is None


@pytest.mark.parametrize("setting,value", [("MAVERICK_WHISPER_CPP_MODEL", "/private/model.bin"),
    ("MAVERICK_WHISPER_MODEL", "not-in-catalog"), ("MAVERICK_VOICE_STT_BACKEND", "openai"), ("MAVERICK_VOICE_COMMANDS", "0")])
def test_managed_or_disabled_settings_are_not_misrepresented(monkeypatch, setting, value):
    c = client()
    headers, body = review(c)
    monkeypatch.setenv(setting, value)
    response = c.get(ENDPOINT)
    assert response.status_code == 200
    data = response.json()
    assert data["can_download"] is False and data["reason"]
    assert "/private/model.bin" not in response.text
    assert c.post(ENDPOINT + "/download", headers={"X-Lightwork-Voice-Context": data["context"]}, json=body).status_code == 409
    assert c.post(ENDPOINT + "/download", headers=headers, json=body).status_code == 409
