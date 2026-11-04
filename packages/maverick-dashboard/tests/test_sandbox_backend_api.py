"""In-app sandbox backend switching (/api/v1/sandbox/*).

An admin switches the sandbox backend (local/docker/podman) from the
/permissions page, not only in the config file: a container backend must have a live,
reachable daemon before the switch lands (a selected-but-dead runtime would
strand every later goal), and switching to local demands an explicit risk
acknowledgement.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, runtime_overrides

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _daemons(monkeypatch, **up):
    """Pin the daemon probes so tests never touch real container runtimes."""
    import maverick_dashboard.api as api

    def probe(binary):
        if up.get(binary):
            return {"available": True, "detail": "daemon reachable (test)"}
        return {"available": False, "detail": f"{binary} is not installed (test)"}

    monkeypatch.setattr(api, "_probe_container_daemon", probe)


def test_status_reports_backend_and_daemons(monkeypatch):
    _daemons(monkeypatch, docker=True, podman=False)
    d = client.get("/api/v1/sandbox/status").json()
    assert d["backend"] == "local"
    assert d["backends"]["local"]["available"] is True
    assert d["backends"]["docker"]["available"] is True
    assert d["backends"]["podman"]["available"] is False


def test_switch_to_reachable_container_backend(monkeypatch):
    from maverick import config

    _daemons(monkeypatch, docker=True)
    r = client.post("/api/v1/sandbox/backend", json={"backend": "docker"})
    assert r.status_code == 200, r.text
    assert r.json() == {"backend": "docker"}
    assert (config.load_config().get("sandbox") or {}).get("backend") == "docker"
    assert client.get("/api/v1/sandbox/status").json()["backend"] == "docker"


def test_switch_refused_while_daemon_unreachable(monkeypatch):
    from maverick import config

    _daemons(monkeypatch)  # nothing reachable
    r = client.post("/api/v1/sandbox/backend", json={"backend": "docker"})
    assert r.status_code == 409
    assert "not ready" in r.json()["detail"]
    assert "Start Docker" in r.json()["detail"]  # actionable, not vague
    assert (config.load_config().get("sandbox") or {}).get("backend") is None


def test_switch_to_local_needs_explicit_acknowledgement(monkeypatch):
    _daemons(monkeypatch, docker=True)
    client.post("/api/v1/sandbox/backend", json={"backend": "docker"})

    r = client.post("/api/v1/sandbox/backend", json={"backend": "local"})
    assert r.status_code == 400
    assert "no isolation" in r.json()["detail"]

    r = client.post(
        "/api/v1/sandbox/backend",
        json={"backend": "local", "acknowledge_local_risk": True},
    )
    assert r.status_code == 200
    assert client.get("/api/v1/sandbox/status").json()["backend"] == "local"


def test_unknown_backend_rejected_by_schema():
    assert client.post(
        "/api/v1/sandbox/backend", json={"backend": "firecracker"}
    ).status_code == 422


def test_switching_requires_global_admin(monkeypatch):
    import maverick_dashboard.auth as auth

    _daemons(monkeypatch, docker=True)
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:viewer")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "viewer")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "viewer")
    assert client.post(
        "/api/v1/sandbox/backend", json={"backend": "docker"}
    ).status_code == 403
    # Status stays readable for any signed-in user.
    assert client.get("/api/v1/sandbox/status").status_code == 200


def test_permissions_page_carries_the_switcher(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    t = client.get("/permissions").text
    assert 'id="sbx-rows"' in t
    assert "/api/v1/sandbox/status" in t
    assert "/api/v1/sandbox/backend" in t
    assert "acknowledge_local_risk" in t  # local switch is never a bare click


@pytest.mark.parametrize(("binary", "query"), [
    ("docker", ["version", "--format", "{{.Server.Version}}"]),  # skips the CLI plugins' metadata
    ("podman", ["info", "--format", "{{.ServerVersion}}"]),
])
def test_the_daemon_probe_asks_for_the_server_version(monkeypatch, binary, query):
    import subprocess

    import maverick_dashboard.api as api

    calls, answers = [], iter([
        subprocess.CompletedProcess([], 0, stdout="27.1.1\n", stderr=""),
        subprocess.CompletedProcess([], 1, stdout="", stderr="\nfailed to connect to the daemon\n"),
    ])
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: calls.append((argv, kw)) or next(answers))

    assert api._probe_container_daemon(binary) == {"available": True, "detail": "Ready · version 27.1.1"}
    assert api._probe_container_daemon(binary) == {"available": False, "detail": "failed to connect to the daemon"}
    assert [argv for argv, _ in calls] == [[f"/usr/bin/{binary}", *query]] * 2
    assert all(kw.get("timeout") == 6 and "shell" not in kw for _, kw in calls)
