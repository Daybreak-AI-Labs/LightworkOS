"""Fail-closed Ekko control and dashboard authorization tests."""
from __future__ import annotations

import copy
import threading
import time

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(tmp_path, monkeypatch, text: str = ""):
    cfg = tmp_path / "config.toml"
    cfg.write_text(text, encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    monkeypatch.delenv("MAVERICK_EKKO", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.config import reset_config_cache

    reset_config_cache()
    return cfg


def _capture_writes(monkeypatch):
    from maverick_dashboard import settings_store

    writes = []
    real_write = settings_store._write

    def capture(data):
        writes.append(copy.deepcopy(data))
        real_write(data)

    monkeypatch.setattr(settings_store, "_write", capture)
    return writes


def test_set_ekko_audit_failure_never_writes(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    writes = _capture_writes(monkeypatch)
    monkeypatch.setattr("maverick.audit.record_global", lambda *_a, **_k: False)
    from maverick_dashboard import settings_store

    with pytest.raises(RuntimeError, match="audit"):
        settings_store.set_ekko(True)
    assert writes == []
    assert "ekko" not in settings_store.load_overlay()


@pytest.mark.parametrize("value", ["0", "1", "definitely"])
def test_set_ekko_refuses_any_environment_owner_without_writing(
    tmp_path, monkeypatch, value,
):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("MAVERICK_EKKO", value)
    writes = _capture_writes(monkeypatch)
    from maverick_dashboard import settings_store

    with pytest.raises(PermissionError, match="MAVERICK_EKKO"):
        settings_store.set_ekko(value == "1")
    assert writes == []


def test_set_ekko_refuses_invalid_config_source_without_writing(
    tmp_path, monkeypatch,
):
    cfg = _isolate(tmp_path, monkeypatch)
    cfg.write_text("[ekko\nenable = true", encoding="utf-8")
    from maverick.config import reset_config_cache

    reset_config_cache()
    writes = _capture_writes(monkeypatch)
    from maverick_dashboard import settings_store

    with pytest.raises(PermissionError, match="config source"):
        settings_store.set_ekko(True)
    assert writes == []


@pytest.mark.parametrize("owner", ["operator", "tenant"])
def test_set_ekko_on_rejects_higher_owner_before_ambiguous_write(
    tmp_path, monkeypatch, owner,
):
    _isolate(tmp_path, monkeypatch, "[ekko]\nenable = false\n")
    if owner == "operator":
        policy = tmp_path / "operator.toml"
        monkeypatch.setenv("MAVERICK_CONFIG_OVERLAY", str(policy))
    else:
        monkeypatch.setenv("MAVERICK_TENANT", "acme")
        policy = tmp_path / "tenants" / "acme" / "config.toml"
        policy.parent.mkdir(parents=True)
    policy.write_text("[ekko]\nenable = false\n", encoding="utf-8")

    from maverick_dashboard import settings_store

    real_write = settings_store._write
    writes = []

    def write_then_raise(data):
        writes.append(copy.deepcopy(data))
        real_write(data)
        raise RuntimeError("ambiguous publish failure")

    monkeypatch.setattr(settings_store, "_write", write_then_raise)
    with pytest.raises(PermissionError, match="higher-precedence"):
        settings_store.set_ekko(True, actor="user:root")
    assert writes == []
    assert "ekko" not in settings_store.load_overlay()


def test_set_ekko_success_is_audited_before_atomic_publish(tmp_path, monkeypatch):
    cfg = _isolate(tmp_path, monkeypatch, "[ekko]\nenable = false\n")
    observed = []

    def authorize(*_args, **_kwargs):
        from maverick.config import get_ekko

        observed.append(get_ekko()["enable"])
        return True

    monkeypatch.setattr("maverick.audit.record_global", authorize)
    from maverick_dashboard import settings_store

    result = settings_store.set_ekko(True, actor="user:root")
    assert observed == [False]
    assert result["enable"] is True
    assert settings_store.load_overlay()["ekko"] == {"enable": True}
    assert cfg.read_text(encoding="utf-8") == "[ekko]\nenable = false\n"
    assert "[ekko]\nenable = true" in settings_store._dump(
        settings_store.load_overlay()
    )


def _enable_oidc(monkeypatch):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth,
        "verify_oidc_token",
        lambda token, **_kw: VerifiedPrincipal(
            sub=token,
            issuer="https://issuer.example",
            audience="maverick",
            claims={"sub": token},
        ),
    )


def test_control_is_global_admin_only_and_page_is_operator_floor(
    tmp_path, monkeypatch,
):
    _isolate(tmp_path, monkeypatch, '[dashboard]\ndefault_role = "viewer"\n')
    _enable_oidc(monkeypatch)
    from maverick_dashboard import settings_store

    monkeypatch.setattr(settings_store, "set_ekko", lambda enabled, actor: {"enable": enabled})
    viewer = {"Authorization": "Bearer alice"}
    assert client.get("/ekko", headers=viewer).status_code == 403
    denied = client.put(
        "/api/v1/ekko/control",
        json={"enabled": True},
        headers=viewer,
    )
    assert denied.status_code == 403

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    allowed = client.put(
        "/api/v1/ekko/control",
        json={"enabled": True},
        headers={"Authorization": "Bearer root"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["ekko"]["enable"] is True


def test_authenticated_sessions_are_owner_scoped_and_cross_owner_is_404(
    tmp_path, monkeypatch,
):
    _isolate(
        tmp_path,
        monkeypatch,
        "\n".join([
            "[ekko]",
            "enable = true",
            'allowed_apps = ["excel", "powerpoint"]',
            (
                'blocked_apps = ["email", "outlook", "gmail", "chat", "teams", '
                '"slack", "crm", "salesforce", "erp", "sap", "database"]'
            ),
            "min_occurrences = 2",
            "min_distinct_days = 2",
            "",
        ]),
    )
    _enable_oidc(monkeypatch)
    from maverick.config import get_ekko_policy
    from maverick.work_discovery_store import WorkDiscoveryStore
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    rbac.set_role("user:bob", "operator")

    WorkDiscoveryStore("user:alice", "desk").enroll(get_ekko_policy())
    alice_headers = {"Authorization": "Bearer alice"}
    bob_headers = {"Authorization": "Bearer bob"}
    started = client.post(
        "/api/v1/ekko/sessions",
        json={"device_id": "desk", "acknowledge_capture_scope": True},
        headers=alice_headers,
    )
    assert started.status_code == 201
    session_id = started.json()["session"]["session_id"]
    assert client.get(
        "/api/v1/ekko/status?device_id=desk", headers=bob_headers,
    ).json()["session"] is None
    denied = client.post(
        f"/api/v1/ekko/sessions/{session_id}/pause",
        json={"device_id": "desk"},
        headers=bob_headers,
    )
    assert denied.status_code == 404


def test_ekko_mutation_requires_same_origin(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    no_origin = TestClient(app, base_url="http://127.0.0.1")
    response = no_origin.post(
        "/api/v1/ekko/candidates/mine",
        json={"device_id": "desk"},
    )
    assert response.status_code == 403


def test_observation_start_fails_closed_when_tenant_audit_is_unavailable(
    tmp_path, monkeypatch,
):
    _isolate(
        tmp_path,
        monkeypatch,
        "\n".join([
            "[ekko]",
            "enable = true",
            'allowed_apps = ["excel", "powerpoint"]',
            "min_occurrences = 2",
            "min_distinct_days = 2",
            "",
        ]),
    )
    from maverick.config import get_ekko_policy
    from maverick.work_discovery_identity import local_os_principal
    from maverick.work_discovery_store import WorkDiscoveryStore

    store = WorkDiscoveryStore(local_os_principal(), "desk")
    store.enroll(get_ekko_policy())
    monkeypatch.setattr("maverick.audit.record", lambda *_a, **_k: False)

    response = client.post(
        "/api/v1/ekko/sessions",
        json={"device_id": "desk", "acknowledge_capture_scope": True},
    )

    assert response.status_code == 503
    assert store.list_sessions() == []


def test_global_off_waits_for_inflight_collector_commit(tmp_path, monkeypatch):
    _isolate(
        tmp_path,
        monkeypatch,
        '\n'.join([
            "[ekko]",
            "enable = true",
            'allowed_apps = ["chrome"]',
            "poll_interval_seconds = 1",
            "",
        ]),
    )
    monkeypatch.setenv("MAVERICK_KMS_KEK", "56" * 32)
    monkeypatch.setattr("maverick.killswitch.check", lambda **_kwargs: None)
    monkeypatch.setattr("maverick.audit.record_global", lambda *_a, **_k: True)
    from maverick.config import get_ekko_policy
    from maverick.work_discovery import WorkEvent
    from maverick.work_discovery_store import WorkDiscoveryStore
    from maverick_dashboard import settings_store

    reached = threading.Event()
    release = threading.Event()
    block = {"value": False}

    def authority(_policy):
        if block["value"]:
            reached.set()
            assert release.wait(5)

    store = WorkDiscoveryStore(
        "alice",
        "desk",
        tenant="acme",
        path=tmp_path / "ekko.sqlite3",
        authority_check=authority,
    )
    policy = get_ekko_policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    token = "collector-barrier-capability"
    store.claim_collector(session.session_id, token, policy=policy)
    event = WorkEvent(
        event_id="barrier-event",
        session_id=session.session_id,
        sequence=1,
        occurred_at=time.time(),
        app="chrome",
        action="switch",
        object_type="none",
    )
    append_errors = []
    disabled = threading.Event()

    def append():
        try:
            store.append_event(event, policy=policy, collector_id=token)
        except Exception as exc:  # pragma: no cover - diagnostic collection
            append_errors.append(exc)

    def disable():
        settings_store.set_ekko(False, actor="user:root")
        disabled.set()

    block["value"] = True
    append_thread = threading.Thread(target=append)
    disable_thread = threading.Thread(target=disable)
    append_thread.start()
    assert reached.wait(5)
    disable_thread.start()
    assert not disabled.wait(0.2)
    release.set()
    append_thread.join(5)
    disable_thread.join(5)

    assert append_errors == []
    assert disabled.is_set()
    assert store.list_events() == [event]
