"""HTTP contract of the Agent Control Plane console API (CSRF, roles, the
plane's own gate, and that a verb's outcome is the core module's, unlaundered)."""
from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
BASE = "/api/v1/agent-control-plane"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import audit, config, killswitch, revocation, world_model
    from maverick_dashboard import api

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.setenv("MAVERICK_CONTROL_PLANE", "1")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN",
                 "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_OIDC_ENABLED",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(audit, "record", lambda *a, **k: True)
    monkeypatch.setattr(audit, "record_global", lambda *a, **k: True)
    config.reset_config_cache()
    revocation.reset_shared()
    killswitch._last_file_check_ts = 0.0
    killswitch._last_file_present = False
    api._world_cache.clear()
    yield
    try:
        killswitch.clear()
    except Exception:
        pass
    config.reset_config_cache()
    revocation.reset_shared()
    killswitch._last_file_check_ts = 0.0
    killswitch._last_file_present = False
    api._world_cache.clear()


def test_status_and_roster_read_on_an_enabled_plane():
    r = client.get(f"{BASE}/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is True and body["halted"] is False
    assert body["schema"] == "lightwork.agent-control-plane-status.v1"
    r = client.get(f"{BASE}/agents")
    assert r.status_code == 200
    agents = r.json()
    assert isinstance(agents.pop("captured_at"), float)
    assert agents == {
        "items": [],
        "count": 0,
        "total": 0,
        "offset": 0,
        "limit": 100,
        "has_more": False,
        "next_offset": None,
    }


def test_roster_is_bounded_and_reports_pagination_metadata(monkeypatch):
    from maverick_dashboard import agent_control_plane_api as api_mod

    def _page(offset, limit):
        values = ("user:a", "user:b", "user:c")
        selected = values[offset:offset + limit]
        return {
            "captured_at": 123.0,
            "offset": offset,
            "limit": limit,
            "total": len(values),
            "items": [{"principal": value} for value in selected],
        }

    monkeypatch.setattr(api_mod, "_agent_page", _page)

    response = client.get(f"{BASE}/agents?offset=1&limit=1")

    assert response.status_code == 200, response.text
    assert response.json() == {
        "items": [{"principal": "user:b"}],
        "captured_at": 123.0,
        "count": 1,
        "total": 3,
        "offset": 1,
        "limit": 1,
        "has_more": True,
        "next_offset": 2,
    }

    final = client.get(f"{BASE}/agents?offset=2&limit=200")
    assert final.status_code == 200, final.text
    assert final.json()["items"] == [{"principal": "user:c"}]
    assert final.json()["has_more"] is False
    assert final.json()["next_offset"] is None


def test_roster_reasons_require_audit_authority(monkeypatch):
    from maverick_dashboard import agent_control_plane_api as api_mod

    monkeypatch.setattr(
        api_mod,
        "_agent_page",
        lambda *_args: {
            "captured_at": 123.0,
            "offset": 0,
            "limit": 100,
            "total": 1,
            "items": [{
                "principal": "user:contained",
                "state": "contained",
                "revoked_reason": "soc@example.test: incident details",
            }],
        },
    )
    monkeypatch.setattr(
        api_mod,
        "has_permission",
        lambda _request, permission: permission != "audit",
    )

    viewer = client.get(f"{BASE}/agents")
    assert viewer.status_code == 200
    assert "revoked_reason" not in viewer.json()["items"][0]

    monkeypatch.setattr(api_mod, "has_permission", lambda *_args: True)
    auditor = client.get(f"{BASE}/agents")
    assert auditor.status_code == 200
    assert auditor.json()["items"][0]["revoked_reason"] == (
        "soc@example.test: incident details"
    )


@pytest.mark.parametrize("path", ["/status", "/agents", "/snapshot"])
def test_dependency_outages_are_sanitized_503(monkeypatch, path):
    from maverick import agent_control_plane as acp
    from maverick_dashboard import agent_control_plane_api as api_mod

    def _unavailable(*_args, **_kwargs):
        try:
            raise OSError("sentinel-secret-path")
        except OSError as cause:
            raise acp.ControlPlaneDependencyError("world model") from cause

    if path == "/status":
        monkeypatch.setattr(api_mod.acp, "status", _unavailable)
    else:
        monkeypatch.setattr(api_mod.acp, "snapshot", _unavailable)

    response = client.get(BASE + path)

    assert response.status_code == 503
    assert response.json()["detail"] == "control plane dependency is unavailable"
    assert "sentinel-secret-path" not in response.text


def test_combined_snapshot_scans_once_and_redacts_reason(monkeypatch):
    from maverick_dashboard import agent_control_plane_api as api_mod

    calls = []

    class _Source:
        captured_at = 123.5
        rows = (object(),)

        def page(self, *, offset, limit):
            return {
                "captured_at": self.captured_at,
                "offset": offset,
                "limit": limit,
                "total": 1,
                "items": [{
                    "principal": "user:contained",
                    "revoked_reason": "sentinel-incident-reason",
                }],
            }

    expected_source = _Source()

    def _snapshot():
        calls.append("scan")
        return expected_source

    def _status(*, source):
        calls.append("status")
        assert source is expected_source
        return {"captured_at": source.captured_at, "enabled": True}

    monkeypatch.setattr(api_mod.acp, "snapshot", _snapshot)
    monkeypatch.setattr(api_mod.acp, "status", _status)
    monkeypatch.setattr(
        api_mod,
        "has_permission",
        lambda _request, permission: permission != "audit",
    )

    response = client.get(f"{BASE}/snapshot?offset=0&limit=100")

    assert response.status_code == 200, response.text
    body = response.json()
    assert calls == ["scan", "status"]
    assert body["status"]["captured_at"] == body["agents"]["captured_at"] == 123.5
    assert "revoked_reason" not in body["agents"]["items"][0]
    assert "sentinel-incident-reason" not in response.text


def test_bounded_page_recovers_to_last_page_after_roster_shrink():
    from maverick_dashboard import agent_control_plane_api as api_mod

    class _Source:
        rows = ("a", "b", "c")

        def page(self, *, offset, limit):
            return {"offset": offset, "limit": limit}

    assert api_mod._bounded_page(_Source(), 200, 2) == {
        "offset": 2,
        "limit": 2,
    }


def test_bounded_page_recovers_to_zero_after_roster_becomes_empty():
    from maverick_dashboard import agent_control_plane_api as api_mod

    class _Source:
        rows = ()

        def page(self, *, offset, limit):
            return {"offset": offset, "limit": limit, "total": 0, "items": []}

    assert api_mod._bounded_page(_Source(), 100, 100) == {
        "offset": 0,
        "limit": 100,
        "total": 0,
        "items": [],
    }


def test_protected_resume_is_409_and_only_release_clears_it():
    from maverick.revocation import is_revoked, shared

    contained = client.post(
        f"{BASE}/agents/user:local/contain",
        json={"reason": "incident"},
    )
    assert contained.status_code == 200 and contained.json()["ok"] is True
    assert shared().revoked()["user:local"].protected is True

    refused = client.post(f"{BASE}/agents/user:local/resume")
    assert refused.status_code == 409
    assert refused.json()["ok"] is False
    assert refused.json()["code"] == "protected_containment"
    assert is_revoked("user:local")
    assert shared().revoked()["user:local"].protected is True

    released = client.post(f"{BASE}/agents/user:local/release")
    assert released.status_code == 200 and released.json()["ok"] is True
    assert not is_revoked("user:local")


def test_fail_soft_audit_state_is_preserved_in_http_result(monkeypatch):
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    response = client.post(
        f"{BASE}/agents/user:local/suspend",
        json={"reason": "incident"},
    )

    assert response.status_code == 200
    assert response.json()["audit_written"] is False
    assert "control action audit row was not written" in response.json()["notes"]


def test_strict_audit_refusal_re_reads_applied_principal_state(monkeypatch):
    from maverick import audit

    def _refuse(*_args, **_kwargs):
        raise audit.AuditRefused("sentinel-custody-secret")

    monkeypatch.setattr(audit, "record", _refuse)

    response = client.post(
        f"{BASE}/agents/user:local/suspend",
        json={"reason": "incident"},
    )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["code"] == "control_action_audit_refused"
    assert detail["operation"] == "suspend"
    assert detail["applied"] == "unknown"
    assert detail["observed"] is True
    assert detail["current_state"] == {
        "present": True,
        "state": "suspended",
        "revoked": True,
        "contained": False,
        "deny_tools": [],
        "max_risk": None,
        "max_dollars": None,
        "max_wall_seconds": None,
    }
    assert "current state was re-read" in detail["message"]
    assert "sentinel" not in response.text


@pytest.mark.parametrize(
    ("code", "status_code"),
    [("not_applied", 409), ("dependency_unavailable", 503)],
)
def test_unsuccessful_mutation_results_are_not_laundered_into_http_200(
    monkeypatch, code, status_code,
):
    from maverick import agent_control_plane as acp
    from maverick_dashboard import agent_control_plane_api as api_mod

    monkeypatch.setattr(
        api_mod.acp,
        "suspend",
        lambda *_args, **_kwargs: acp.ControlResult(
            "suspend",
            "user:local",
            ok=False,
            code=code,
            detail="stable refusal",
            audit_written=True,
        ),
    )

    response = client.post(
        f"{BASE}/agents/user:local/suspend",
        json={"reason": "incident"},
    )

    assert response.status_code == status_code
    assert response.json()["ok"] is False
    assert response.json()["code"] == code


@pytest.mark.parametrize("query", ["offset=-1", "limit=0", "limit=201"])
def test_roster_rejects_out_of_bounds_pagination(query):
    assert client.get(f"{BASE}/agents?{query}").status_code == 422


def test_suspend_then_resume_round_trips_through_the_revocation_registry():
    from maverick.revocation import is_revoked
    r = client.post(f"{BASE}/agents/user:local/suspend", json={"reason": "runaway"})
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True and r.json()["verb"] == "suspend"
    assert is_revoked("user:local")
    rows = client.get(f"{BASE}/agents").json()["items"]
    assert rows and rows[0]["principal"] == "user:local" and rows[0]["state"] == "suspended"
    assert "runaway" in rows[0]["revoked_reason"]
    r = client.post(f"{BASE}/agents/user:local/resume")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert not is_revoked("user:local")


def test_opaque_principal_uses_body_and_query_transport_end_to_end():
    from maverick.revocation import is_revoked

    principal = "user:auth0|North America/María 李"
    suspended = client.post(
        f"{BASE}/principals/suspend",
        json={"principal": principal, "reason": "identity incident"},
    )

    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["principal"] == principal
    assert is_revoked(principal)

    ledger = client.get(
        f"{BASE}/principals/ledger",
        params={"principal": principal, "limit": 5},
    )
    assert ledger.status_code == 200, ledger.text
    assert ledger.json() == {"principal": principal, "items": [], "count": 0}

    resumed = client.post(
        f"{BASE}/principals/resume",
        json={"principal": principal},
    )
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["principal"] == principal
    assert not is_revoked(principal)


def test_bulk_select_then_resume_uses_a_snapshot_pinned_tenant_roster(monkeypatch):
    from maverick.revocation import is_revoked

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    suspended = client.post(
        f"{BASE}/agents/user:fleet-one/suspend",
        json={"reason": "operator review"},
    )
    assert suspended.status_code == 200, suspended.text

    selected = client.post(f"{BASE}/bulk/select", json={"tenant": "tenant-a"})
    assert selected.status_code == 200, selected.text
    selection = selected.json()
    assert selection["schema"] == "lightwork.agent-control-plane-selection.v1"
    assert selection["tenant"] == "tenant-a"
    assert selection["principals"] == ["user:fleet-one"]

    resumed = client.post(
        f"{BASE}/bulk/actions",
        json={"selection": selection, "verb": "resume"},
    )
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["ok"] is True
    assert resumed.json()["results"][0]["principal"] == "user:fleet-one"
    assert not is_revoked("user:fleet-one")


def test_bulk_action_refuses_a_stale_snapshot_before_any_action(monkeypatch):
    from maverick.revocation import is_revoked

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    assert client.post(
        f"{BASE}/agents/user:fleet-one/suspend",
        json={"reason": "operator review"},
    ).status_code == 200
    selected = client.post(f"{BASE}/bulk/select", json={"tenant": "tenant-a"})
    assert selected.status_code == 200, selected.text
    assert client.post(
        f"{BASE}/agents/user:fleet-two/suspend",
        json={"reason": "new enrollment"},
    ).status_code == 200

    refused = client.post(
        f"{BASE}/bulk/actions",
        json={"selection": selected.json(), "verb": "resume"},
    )

    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"] == "control plane operation was refused"
    assert is_revoked("user:fleet-one")


def test_bulk_containment_requires_administrator_before_core_execution(monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import agent_control_plane_api as api_mod

    def _only_operate(_request, permission):
        if permission == "admin":
            raise HTTPException(status_code=403, detail="insufficient role")

    monkeypatch.setattr(api_mod, "require_permission", _only_operate)
    selection = {
        "schema": "lightwork.agent-control-plane-selection.v1",
        "tenant": "tenant-a",
        "platform": None,
        "principals": ["user:fleet-one"],
        "snapshot_sha256": "a" * 64,
        "captured_at": 123.0,
    }

    denied = client.post(
        f"{BASE}/bulk/actions",
        json={"selection": selection, "verb": "contain", "reason": "incident"},
    )

    assert denied.status_code == 403


def test_timeboxed_containment_and_schedule_projection_are_operator_safe(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    created = client.post(
        f"{BASE}/principals/contain-timeboxed",
        json={
            "principal": "user:timeboxed",
            "reason": "temporary investigation",
            "release_after_seconds": 120,
            "idempotency_key": "case-124",
        },
    )

    assert created.status_code == 200, created.text
    body = created.json()
    assert body["status"] == "scheduled"
    assert body["result"]["ok"] is True

    schedules = client.get(f"{BASE}/timeboxes")
    assert schedules.status_code == 200, schedules.text
    assert schedules.json()["count"] == 1
    record = schedules.json()["items"][0]
    assert record["principal"] == "user:timeboxed"
    assert record["status"] == "scheduled"
    assert "reason_sha256" not in record
    assert "request_sha256" not in record
    assert "idempotency_sha256" not in record

    sweep = client.post(f"{BASE}/timeboxes/sweep")
    assert sweep.status_code == 200, sweep.text
    assert sweep.json() == {"items": [], "count": 0}


@pytest.mark.parametrize(
    "principal",
    [" user:x", "user:x ", "user:x\nadmin", "x" * 513],
)
def test_opaque_principal_transport_rejects_ambiguous_values(principal):
    response = client.post(
        f"{BASE}/principals/suspend",
        json={"principal": principal, "reason": "incident"},
    )

    assert response.status_code == 422


def test_a_disabled_plane_answers_403_on_verbs_and_still_reads(monkeypatch):
    from maverick import config
    from maverick.revocation import is_revoked
    monkeypatch.delenv("MAVERICK_CONTROL_PLANE")
    config.reset_config_cache()
    r = client.post(f"{BASE}/agents/user:local/suspend", json={"reason": "x"})
    assert r.status_code == 403 and r.json()["detail"] == "control_plane_disabled"
    assert not is_revoked("user:local")
    assert client.get(f"{BASE}/status").json()["enabled"] is False


def test_bad_input_is_422_before_anything_lands():
    from maverick.revocation import is_revoked
    assert client.post(f"{BASE}/agents/user:local/suspend", json={}).status_code == 422
    assert client.post(f"{BASE}/agents/user:local/suspend",
                       json={"reason": "x", "extra": 1}).status_code == 422
    assert client.post(f"{BASE}/agents/..bad/suspend", json={"reason": "x"}).status_code == 422
    assert client.post(f"{BASE}/agents/user:local/attenuate",
                       json={"max_risk": "extreme"}).status_code == 422
    assert not is_revoked("user:local")


def test_attenuate_maps_core_refusals_to_http_codes():
    r = client.post(f"{BASE}/agents/user:local/attenuate", json={"max_risk": "low"})
    assert r.status_code == 422 and "external" in r.json()["detail"]
    r = client.post(f"{BASE}/agents/agent:ghost/attenuate", json={"max_risk": "low"})
    assert r.status_code == 404


@pytest.mark.parametrize("body", [{}, {"deny_tools": []}])
def test_attenuate_requires_at_least_one_requested_restriction(body):
    r = client.post(f"{BASE}/agents/agent:ghost/attenuate", json=body)
    assert r.status_code == 422
    assert "at least one attenuation restriction is required" in r.text


def test_duplicate_weak_halt_routes_are_not_exposed():
    assert client.post(f"{BASE}/halt", json={"reason": "incident"}).status_code == 404
    assert client.post(f"{BASE}/clear-halt").status_code == 404


def test_halt_scope_uncertainty_and_shared_status_outage_are_503(
    monkeypatch, tmp_path,
):
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-strict"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(
        api,
        "_shared_halt_backend",
        lambda: (_ for _ in ()).throw(OSError("sentinel-backend-secret")),
    )

    status = client.get("/api/v1/halt")
    armed = client.post("/api/v1/halt", json={"reason": "incident"})
    assert status.status_code == 503 and armed.status_code == 503
    assert "sentinel-backend-secret" not in status.text + armed.text
    assert not halt_path.exists()

    class _UnavailableWorld:
        def active_halt(self):
            raise OSError("sentinel-shared-secret")

    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    monkeypatch.setattr(api, "_world", lambda: _UnavailableWorld())
    shared = client.get("/api/v1/halt")
    assert shared.status_code == 503
    assert "sentinel-shared-secret" not in shared.text


def test_shared_halt_status_explicitly_confirms_inactive_cluster(monkeypatch):
    from maverick_dashboard import api

    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    monkeypatch.setattr(
        api,
        "_world",
        lambda: type("World", (), {"active_halt": lambda self: None})(),
    )

    response = client.get("/api/v1/halt")

    assert response.status_code == 200, response.text
    assert response.json()["active"] is False
    assert response.json()["scope"] == "cluster"
    assert response.json()["cluster_halt"] is False


def test_local_halt_mutation_requires_global_operator(monkeypatch, tmp_path):
    from fastapi import HTTPException
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-global-role"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)
    monkeypatch.setattr(
        api,
        "require_permission",
        lambda *_args: pytest.fail("tenant-local halt permission was consulted"),
    )

    def _require_global(_request, permission):
        if permission != "view":
            raise HTTPException(status_code=403, detail="global role")

    monkeypatch.setattr(
        api,
        "require_global_permission",
        _require_global,
    )

    denied = client.post("/api/v1/halt", json={"reason": "incident"})

    assert denied.status_code == 403
    assert not halt_path.exists()


def test_halt_get_redacts_and_parses_incident_detail(monkeypatch, tmp_path):
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-private"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    halt_path.write_text(json.dumps({
        "reason": "sentinel-incident-reason",
        "actor": "sentinel-actor",
        "source": "dashboard",
        "scope": "local-deployment",
    }), encoding="utf-8")
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)
    monkeypatch.setattr(api, "require_global_permission", lambda *_args: None)
    monkeypatch.setattr(api, "has_global_permission", lambda *_args: False)

    viewer = client.get("/api/v1/halt")
    assert viewer.status_code == 200
    assert viewer.json() == {"active": True, "scope": "local"}
    assert "sentinel" not in viewer.text
    assert str(halt_path) not in viewer.text

    monkeypatch.setattr(
        api,
        "has_global_permission",
        lambda _request, permission: permission == "audit",
    )
    auditor = client.get("/api/v1/halt")
    assert auditor.json()["reason"] == "sentinel-incident-reason"
    assert auditor.json()["armed_by"] == "sentinel-actor"
    assert "file" not in auditor.json()

    monkeypatch.setattr(api, "has_global_permission", lambda *_args: True)
    administrator = client.get("/api/v1/halt")
    assert administrator.json()["file"] == str(halt_path)


def test_halt_get_refuses_a_multiply_linked_authority(monkeypatch, tmp_path):
    from maverick_dashboard import api

    referent = tmp_path / "halt-referent"
    halt_path = tmp_path / "HALT-hardlink"
    referent.write_text("sensitive incident\n", encoding="utf-8")
    try:
        os.link(referent, halt_path)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)
    monkeypatch.setattr(api, "require_global_permission", lambda *_args: None)

    response = client.get("/api/v1/halt")

    assert response.status_code == 503
    assert response.json()["detail"] == "halt authority is unavailable"
    assert "sensitive incident" not in response.text


def test_halt_clear_refuses_a_multiply_linked_authority(monkeypatch, tmp_path):
    from maverick_dashboard import api

    referent = tmp_path / "halt-clear-referent"
    halt_path = tmp_path / "HALT-clear-hardlink"
    referent.write_text("stop remains armed\n", encoding="utf-8")
    try:
        os.link(referent, halt_path)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)

    response = client.delete("/api/v1/halt")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "halt clear was not attempted because its local authority is unavailable"
    )
    assert halt_path.read_text(encoding="utf-8") == "stop remains armed\n"
    assert referent.read_text(encoding="utf-8") == "stop remains armed\n"
    assert halt_path.stat().st_nlink == 2


def test_halt_post_atomically_replaces_alias_without_touching_referent(
    monkeypatch, tmp_path,
):
    from maverick_dashboard import api

    referent = tmp_path / "victim.txt"
    halt_path = tmp_path / "HALT-alias"
    referent.write_text("do not overwrite\n", encoding="utf-8")
    try:
        halt_path.symlink_to(referent)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links unavailable: {exc}")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)
    monkeypatch.setattr(api, "require_global_permission", lambda *_args: None)

    response = client.post("/api/v1/halt", json={"reason": "incident"})

    assert response.status_code == 204, response.text
    assert referent.read_text(encoding="utf-8") == "do not overwrite\n"
    assert not halt_path.is_symlink()
    detail = json.loads(halt_path.read_text(encoding="utf-8"))
    assert detail["reason"] == "incident"
    assert detail["actor"] == "local:dashboard"
    assert detail["scope"] == "local"


def test_halt_post_invalidates_a_cached_local_clear(monkeypatch, tmp_path):
    from maverick import killswitch
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-cache-refresh"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)
    killswitch._last_file_check_ts = time.monotonic()
    killswitch._last_file_present = False

    response = client.post("/api/v1/halt", json={"reason": "incident"})

    assert response.status_code == 204, response.text
    with pytest.raises(killswitch.Halted) as halted:
        killswitch.check()
    assert halted.value.source == "file"


def test_halt_post_uses_private_atomic_publication(monkeypatch, tmp_path):
    from maverick import file_lock
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-atomic"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)
    monkeypatch.setattr(api, "require_global_permission", lambda *_args: None)
    real_prepare = file_lock.prepare_private_directory
    real_atomic = file_lock.atomic_write_text
    calls = []

    def _prepare(path):
        calls.append(("directory", path))
        return real_prepare(path)

    def _atomic(path, text, *, mode=0o600, encoding="utf-8"):
        calls.append(("write", path, text, mode))
        return real_atomic(path, text, mode=mode, encoding=encoding)

    monkeypatch.setattr(file_lock, "prepare_private_directory", _prepare)
    monkeypatch.setattr(file_lock, "atomic_write_text", _atomic)

    response = client.post("/api/v1/halt", json={"reason": "incident"})

    assert response.status_code == 204, response.text
    assert calls[0] == ("directory", halt_path.parent)
    assert calls[1][0] == "write"
    assert calls[1][1] == halt_path
    assert calls[1][3] == 0o600
    detail = json.loads(calls[1][2])
    assert detail["actor"] == "local:dashboard"
    assert detail["reason"] == "incident"
    assert detail["source"] == "dashboard"


def test_local_halt_arm_and_clear_record_bounded_global_control_results(
    monkeypatch, tmp_path,
):
    from maverick import audit
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-audited"
    events = []
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)
    monkeypatch.setattr(
        audit,
        "record_global",
        lambda kind, **payload: events.append((str(kind), payload)) or True,
    )

    armed = client.post("/api/v1/halt", json={"reason": "incident"})
    cleared = client.delete("/api/v1/halt")

    assert armed.status_code == 204 and cleared.status_code == 204
    assert armed.headers[api._HALT_AUDIT_HEADER] == "true"
    assert cleared.headers[api._HALT_AUDIT_HEADER] == "true"
    assert [item[1]["operation"] for item in events] == ["halt", "clear-halt"]
    assert [item[1]["result"] for item in events] == ["succeeded", "succeeded"]
    assert all(item[0] == "control_plane_action" for item in events)
    assert all(item[1]["actor"] == "local:dashboard" for item in events)
    assert all(item[1]["scope"] == "local" for item in events)
    assert events[0][1]["reason"] == "incident"
    assert len(events[0][1]["reason"]) <= api._HALT_REASON_MAX_CHARS


def test_shared_halt_arm_and_clear_record_cluster_scope(monkeypatch, tmp_path):
    from maverick import audit, killswitch
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-cluster"

    class _World:
        state = None

        def arm_halt(self, reason, *, source, armed_by):
            self.armed = (reason, source, armed_by)
            self.state = {
                "reason": reason,
                "source": source,
                "armed_by": armed_by,
                "armed_at": 123.0,
                "generation": "shared-generation-1",
            }
            return self.state["generation"]

        def active_halt(self):
            return self.state

        def disarm_halt(self, *, expected_generation, durable_clear=None):
            assert expected_generation == self.state["generation"]
            assert durable_clear is not None
            with pytest.raises(killswitch.Halted) as held:
                killswitch.check(force_refresh=True)
            assert held.value.source == "control-plane-clear"
            durable_clear()
            assert not halt_path.exists()
            self.disarmed = True
            self.state = None
            return True

    world = _World()
    events = []
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(
        audit,
        "record_global",
        lambda kind, **payload: events.append((str(kind), payload)) or True,
    )

    armed = client.post("/api/v1/halt", json={"reason": "incident"})
    cleared = client.delete("/api/v1/halt")

    assert armed.status_code == 204 and cleared.status_code == 204
    assert world.armed == ("incident", "dashboard", "local:dashboard")
    assert world.disarmed is True
    assert [item[1]["scope"] for item in events] == ["cluster", "cluster"]


def test_shared_halt_status_prefers_authoritative_shared_attribution(
    monkeypatch, tmp_path,
):
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-attribution"
    halt_path.write_text(
        json.dumps({
            "reason": "stale-local-incident",
            "actor": "stale-local-actor",
        }),
        encoding="utf-8",
    )
    shared = {
        "reason": "authoritative-shared-incident",
        "source": "dashboard",
        "armed_by": "global:operator",
        "armed_at": 456.0,
        "generation": "shared-attribution-generation",
    }
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    monkeypatch.setattr(
        api,
        "_world",
        lambda: type("World", (), {"active_halt": lambda self: shared})(),
    )
    monkeypatch.setattr(api, "require_global_permission", lambda *_args: None)
    monkeypatch.setattr(api, "has_global_permission", lambda *_args: True)

    response = client.get("/api/v1/halt")

    assert response.status_code == 200, response.text
    assert response.json()["cluster_halt"] is True
    assert response.json()["file_present"] is True
    assert response.json()["reason"] == "authoritative-shared-incident"
    assert response.json()["armed_by"] == "global:operator"
    assert response.json()["armed_at"] == 456.0
    assert "stale-local-incident" not in response.text
    assert "stale-local-actor" not in response.text


def test_shared_clear_rearms_local_stop_when_cluster_clear_is_indeterminate(
    monkeypatch, tmp_path,
):
    from maverick import audit
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-clear-compensation"
    halt_path.write_text("incident\n", encoding="utf-8")

    class _World:
        state = {
            "reason": "incident",
            "source": "dashboard",
            "armed_by": "operator",
            "armed_at": 123.0,
            "generation": "shared-generation-before-clear",
        }

        def active_halt(self):
            return self.state

        def disarm_halt(self, *, expected_generation, durable_clear=None):
            assert expected_generation == self.state["generation"]
            assert durable_clear is not None
            durable_clear()
            assert not halt_path.exists()
            self.state = None
            raise OSError("sentinel-post-commit-secret")

    world = _World()
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)

    response = client.delete("/api/v1/halt")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "cluster halt clear is indeterminate; the local fail-safe was re-armed, "
        "but other replicas may be running"
    )
    assert "sentinel" not in response.text
    assert world.state is None
    compensation = json.loads(halt_path.read_text(encoding="utf-8"))
    assert compensation["source"] == "dashboard-clear-compensation"
    assert compensation["scope"] == "local-compensation"


def test_local_clear_does_not_delete_a_concurrent_newer_generation(
    monkeypatch, tmp_path,
):
    from maverick import file_lock, killswitch
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-local-race"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)

    armed = client.post("/api/v1/halt", json={"reason": "first incident"})
    assert armed.status_code == 204, armed.text
    first = halt_path.read_text(encoding="utf-8")
    replacement = json.dumps(
        {
            "actor": "concurrent:operator",
            "created_at": 456.0,
            "generation": "new-local-generation",
            "reason": "new incident",
            "scope": "local",
            "source": "concurrent-arm",
        },
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    authority = killswitch._halt_authority_lock_path(halt_path)
    real_lock = file_lock.cross_process_lock

    @contextmanager
    def _arm_before_clear_lock(target, *, strict=False):
        if Path(target) == authority:
            assert strict is True
            file_lock.atomic_write_text(halt_path, replacement, mode=0o600)
            yield
            return
        with real_lock(target, strict=strict):
            yield

    monkeypatch.setattr(file_lock, "cross_process_lock", _arm_before_clear_lock)

    response = client.delete("/api/v1/halt")

    assert response.status_code == 409, response.text
    assert response.headers[api._HALT_AUDIT_HEADER] == "true"
    assert response.json()["detail"] == (
        "halt clear was not applied because a newer local halt is armed"
    )
    assert halt_path.read_text(encoding="utf-8") == replacement
    assert halt_path.read_text(encoding="utf-8") != first


def test_shared_clear_compare_and_delete_preserves_a_concurrent_rearm(
    monkeypatch, tmp_path,
):
    from maverick import audit
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-shared-race"

    class _World:
        state = None
        expected_generation = None

        def arm_halt(self, reason, *, source, armed_by):
            self.state = {
                "reason": reason,
                "source": source,
                "armed_by": armed_by,
                "armed_at": 123.0,
                "generation": "shared-generation-before-clear",
            }
            return self.state["generation"]

        def active_halt(self):
            return self.state

        def disarm_halt(self, *, expected_generation, durable_clear=None):
            self.expected_generation = expected_generation
            assert durable_clear is not None
            self.state = {
                "reason": "new incident",
                "source": "concurrent-arm",
                "armed_by": "global:new-operator",
                "armed_at": 456.0,
                "generation": "shared-generation-after-rearm",
            }
            return False

    world = _World()
    events = []
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(
        audit,
        "record_global",
        lambda kind, **payload: events.append((str(kind), payload)) or True,
    )

    armed = client.post("/api/v1/halt", json={"reason": "first incident"})
    assert armed.status_code == 204, armed.text

    response = client.delete("/api/v1/halt")

    assert response.status_code == 409, response.text
    assert response.headers[api._HALT_AUDIT_HEADER] == "true"
    assert "superseded by a newer cluster halt" in response.json()["detail"]
    assert world.expected_generation == "shared-generation-before-clear"
    assert world.state["generation"] == "shared-generation-after-rearm"
    assert world.state["reason"] == "new incident"
    retained = json.loads(halt_path.read_text(encoding="utf-8"))
    assert retained["source"] == "dashboard"
    assert retained["scope"] == "cluster"
    assert events[-1][1]["operation"] == "clear-halt"
    assert events[-1][1]["result"] == "superseded"
    assert events[-1][1]["ok"] is False


def test_shared_clear_does_not_disarm_cluster_when_local_unlink_fails(
    monkeypatch, tmp_path,
):
    from pathlib import Path

    from maverick import audit
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-unlink-failure"
    halt_path.write_text("incident\n", encoding="utf-8")

    class _World:
        state = {
            "reason": "incident",
            "source": "dashboard",
            "armed_by": "operator",
            "armed_at": 123.0,
            "generation": "shared-generation-before-unlink",
        }
        disarm_calls = 0

        def active_halt(self):
            return self.state

        def disarm_halt(self, *, expected_generation, durable_clear=None):
            self.disarm_calls += 1
            assert expected_generation == self.state["generation"]
            assert durable_clear is not None
            durable_clear()
            self.state = None
            return True

    world = _World()
    real_unlink = Path.unlink

    def _unlink(path, *args, **kwargs):
        if path == halt_path:
            raise OSError("sentinel-unlink-secret")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(Path, "unlink", _unlink)

    response = client.delete("/api/v1/halt")

    assert response.status_code == 503
    assert "sentinel" not in response.text
    assert halt_path.exists()
    assert world.disarm_calls == 1
    assert world.state is not None


def test_halt_fail_soft_audit_is_exposed_without_rolling_back(monkeypatch, tmp_path):
    from maverick import audit
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-fail-soft"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: False)

    response = client.post("/api/v1/halt", json={"reason": "incident"})

    assert response.status_code == 204
    assert response.headers[api._HALT_AUDIT_HEADER] == "false"
    assert halt_path.is_file()


def test_strict_audit_refusal_reports_already_applied_halt_state(
    monkeypatch, tmp_path,
):
    from maverick import audit
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-strict-audit"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)

    def _refuse(*_args, **_kwargs):
        raise audit.AuditRefused("sentinel-custody-secret")

    monkeypatch.setattr(audit, "record_global", _refuse)

    response = client.post("/api/v1/halt", json={"reason": "incident"})

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "halt is armed, but the required control-plane audit was refused"
    )
    assert "sentinel" not in response.text
    assert halt_path.is_file()


def test_strict_audit_refusal_reports_already_applied_halt_clear(
    monkeypatch, tmp_path,
):
    from maverick import audit
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-strict-clear"
    halt_path.write_text("incident\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)

    def _refuse(*_args, **_kwargs):
        raise audit.AuditRefused("sentinel-custody-secret")

    monkeypatch.setattr(audit, "record_global", _refuse)

    response = client.delete("/api/v1/halt")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "halt was cleared, but the required control-plane audit was refused"
    )
    assert "sentinel" not in response.text
    assert not halt_path.exists()


def test_halt_get_does_not_read_oversized_incident_detail(monkeypatch, tmp_path):
    from maverick_dashboard import api

    halt_path = tmp_path / "HALT-oversized"
    halt_path.write_bytes(b"s" * (api._HALT_DETAIL_MAX_BYTES + 1))
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt_path))
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: False)
    monkeypatch.setattr(api, "require_global_permission", lambda *_args: None)
    monkeypatch.setattr(api, "has_global_permission", lambda *_args: True)

    response = client.get("/api/v1/halt")

    assert response.status_code == 200, response.text
    assert response.json()["active"] is True
    assert response.json()["file_present"] is True
    assert response.json()["reason"] is None


def test_cross_origin_mutations_are_refused_by_the_csrf_check():
    from maverick.revocation import is_revoked
    foreign = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://evil.example"})
    r = foreign.post(f"{BASE}/agents/user:local/suspend", json={"reason": "x"})
    assert r.status_code == 403
    assert not is_revoked("user:local")


def test_ledger_reads_the_forensic_timeline():
    r = client.get(f"{BASE}/agents/user:local/ledger?limit=5")
    assert r.status_code == 200, r.text
    assert r.json() == {"principal": "user:local", "items": [], "count": 0}


def test_roles_gate_the_verbs(monkeypatch):
    from maverick.revocation import is_revoked
    from maverick_dashboard import agent_control_plane_api as api_mod

    def _only(allowed):
        def _require(request, permission):
            if permission not in allowed:
                from fastapi import HTTPException
                raise HTTPException(status_code=403, detail="insufficient role")
        return _require

    monkeypatch.setattr(api_mod, "require_permission", _only({"view", "operate"}))
    assert client.post(f"{BASE}/agents/user:local/contain", json={"reason": "x"}).status_code == 403
    assert client.get(f"{BASE}/agents/user:local/ledger").status_code == 403
    assert client.post(f"{BASE}/agents/user:local/suspend", json={"reason": "x"}).status_code == 200
    assert is_revoked("user:local")
