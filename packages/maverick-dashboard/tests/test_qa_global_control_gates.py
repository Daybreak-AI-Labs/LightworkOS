"""Regression coverage for deployment-global QA control-plane boundaries."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import auth, rbac
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_ADMINS", raising=False)
    monkeypatch.delenv("MAVERICK_VALUE_HOURLY_RATE", raising=False)
    monkeypatch.delenv("MAVERICK_VALUE_HOURS", raising=False)
    monkeypatch.setattr(rbac, "store_path", lambda: home / "dashboard-users.json")
    monkeypatch.setattr(
        rbac,
        "tenant_store_path",
        lambda: home / "dashboard-tenant-roles.json",
    )
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
    from maverick import config, world_model
    from maverick_dashboard import api

    monkeypatch.setattr(world_model, "DEFAULT_DB", home / "world.db")
    config.reset_config_cache()
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    api._world_cache.clear()


def _headers(user: str = "alice") -> dict[str, str]:
    return {"Authorization": f"Bearer {user}"}


def _tenant_admin() -> None:
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    assert auth.role_for_principal("user:alice") == "admin"
    assert auth.global_role_for_principal("user:alice") == "viewer"


def test_tenant_admin_cannot_toggle_shared_halt(tmp_path, monkeypatch):
    from maverick_dashboard import api

    halt_file = tmp_path / "HALT"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_file))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    _tenant_admin()

    armed = client.post(
        "/api/v1/halt",
        json={"reason": "tenant-local administrator"},
        headers=_headers(),
    )
    assert armed.status_code == 403
    assert not halt_file.exists()

    halt_file.write_text("existing global stop\n", encoding="utf-8")
    cleared = client.delete("/api/v1/halt", headers=_headers())
    assert cleared.status_code == 403
    assert halt_file.exists()


def test_shared_halt_arm_failure_is_reported_and_keeps_local_stop(tmp_path, monkeypatch):
    from maverick import audit
    from maverick_dashboard import api

    class UnavailableWorld:
        def arm_halt(self, *_args, **_kwargs):
            raise RuntimeError("shared store offline")

    halt_file = tmp_path / "HALT"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_file))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    monkeypatch.setattr(api, "_world", lambda: UnavailableWorld())
    events = []
    monkeypatch.setattr(
        audit,
        "record_global",
        lambda kind, **payload: events.append((str(kind), payload)) or True,
    )
    rbac.set_role("user:alice", "admin")

    response = client.post(
        "/api/v1/halt",
        json={"reason": "safety incident"},
        headers=_headers(),
    )

    assert response.status_code == 503
    assert "cluster-wide propagation failed" in response.json()["detail"]
    local_detail = json.loads(halt_file.read_text(encoding="utf-8"))
    assert local_detail["reason"] == "safety incident"
    assert local_detail["actor"] == "user:alice"
    assert local_detail["scope"] == "cluster"
    assert response.headers[api._HALT_AUDIT_HEADER] == "true"
    assert events[0][1]["operation"] == "halt"
    assert events[0][1]["result"] == "partial"
    assert events[0][1]["scope"] == "cluster"
    assert events[0][1]["actor"] == "user:alice"
    assert events[0][1]["reason"] == "safety incident"


def test_shared_halt_clear_failure_leaves_local_file_armed(tmp_path, monkeypatch):
    from maverick_dashboard import api

    class UnavailableWorld:
        state = {
            "reason": "existing stop",
            "source": "dashboard",
            "armed_by": "user:alice",
            "armed_at": 123.0,
            "generation": "shared-generation-before-outage",
        }

        def active_halt(self):
            return self.state

        def disarm_halt(self, *, expected_generation, durable_clear=None):
            assert expected_generation == self.state["generation"]
            assert durable_clear is not None
            raise RuntimeError("shared store offline")

    halt_file = tmp_path / "HALT"
    halt_file.write_text("existing stop\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_file))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    monkeypatch.setattr(api, "_world", lambda: UnavailableWorld())
    rbac.set_role("user:alice", "admin")

    response = client.delete("/api/v1/halt", headers=_headers())

    assert response.status_code == 503
    assert "cluster halt clear is indeterminate" in response.json()["detail"]
    assert "local fail-safe was retained" in response.json()["detail"]
    assert halt_file.read_text(encoding="utf-8") == "existing stop\n"


def test_tenant_admin_cannot_set_deployment_model_cost_tier(monkeypatch):
    from maverick_dashboard import settings_store

    _tenant_admin()
    monkeypatch.setattr(
        settings_store,
        "set_model_cost_tier",
        lambda *_args, **_kwargs: pytest.fail("global cost tier was mutated"),
    )

    response = client.post(
        "/api/v1/model-cost-tiers",
        json={"model": "claude-opus-4-8", "band": "low"},
        headers=_headers(),
    )

    assert response.status_code == 403


def test_tenant_admin_cannot_set_global_savings_assumptions(monkeypatch):
    from maverick_dashboard import settings_store

    _tenant_admin()
    monkeypatch.setattr(
        settings_store,
        "set_value_assumptions",
        lambda **_kwargs: pytest.fail("global savings assumptions were mutated"),
    )

    response = client.put(
        "/api/v1/savings/assumptions",
        json={"hourly_rate": 999},
        headers=_headers(),
    )

    assert response.status_code == 403


def test_savings_reports_global_save_and_effective_tenant_override(tmp_path):
    from maverick import config

    rbac.set_role("user:alice", "operator")
    tenant_config = Path(config.tenant_config_path())
    tenant_config.parent.mkdir(parents=True, exist_ok=True)
    tenant_config.write_text(
        "[value]\nhourly_rate = 333.0\n",
        encoding="utf-8",
    )
    config.reset_config_cache()

    response = client.put(
        "/api/v1/savings/assumptions",
        json={"hourly_rate": 111.0, "hours_per_task": 4.0},
        headers=_headers(),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["saved"] is True
    assert body["global_assumptions"]["hourly_rate"] == 111.0
    assert body["global_assumptions"]["hours_per_task"] == 4.0
    assert body["effective_assumptions"]["hourly_rate"] == 333.0
    assert body["effective_assumptions"]["hours_per_task"] == 4.0
    assert body["assumptions"] == body["effective_assumptions"]
    assert body["effective_source"] == "tenant_override"
    assert body["tenant_override_fields"] == ["hourly_rate"]

    read_back = client.get("/api/v1/savings", headers=_headers()).json()
    assert read_back["global_assumptions"]["hourly_rate"] == 111.0
    assert read_back["effective_assumptions"]["hourly_rate"] == 333.0

    page = client.get("/savings", headers=_headers())
    assert page.status_code == 200
    assert "This workspace uses its own numbers" in page.text
    assert "$333.00 an hour" in page.text
    assert "$111.00 an hour" in page.text


def test_tenant_admin_cannot_accept_shared_harness_ground_truth(monkeypatch):
    from maverick import self_harness_eval

    _tenant_admin()
    monkeypatch.setattr(
        self_harness_eval,
        "resolve_pending",
        lambda *_args, **_kwargs: pytest.fail("shared ground truth was mutated"),
    )

    response = client.post(
        "/api/v1/harness-corpus/review",
        json={"key": "model", "accept": [1]},
        headers=_headers(),
    )

    assert response.status_code == 403


def test_halt_shell_reports_failed_mutations():
    response = client.get("/static/lightwork-ui.js", headers=_headers())
    assert response.status_code == 200
    assert "if (!response.ok)" in response.text
    assert "Emergency stop change failed" in response.text
    assert "let haltState = 'unknown'" in response.text
    assert "Stop status unavailable" in response.text
    assert "aria-pressed', known ?" in response.text
    assert ": 'mixed'" in response.text
    assert "if (pending || !knownState())" in response.text
    assert "haltState = 'unknown'" in response.text
    assert "renderVerifiedPayload(result.body)" in response.text
    assert "Partial stop — some workers are not confirmed stopped" in response.text
    assert "Stop requested — checking work status" in response.text
    assert "const verified = await refresh()" in response.text


def test_halt_shell_authority_copy_is_scope_neutral():
    _tenant_admin()
    page = client.get("/", headers=_headers())
    assert page.status_code == 200
    assert "Halt permission is required to change it." in page.text
    assert "You do not have permission to stop or resume this work." in page.text
    assert "A global administrator is required to change it." not in page.text

    script = client.get("/static/lightwork-ui.js", headers=_headers())
    assert script.status_code == 200
    assert "You do not have permission to stop or resume this work." in script.text
    assert "a global administrator is required to stop or resume" not in script.text
    assert "Stop all work?" not in script.text
