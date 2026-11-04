"""Actual first-run routes retain progress across separate local app processes.

HTTP requests use the real ASGI app through TestClient, with real owner sign-in
and filesystem stores. There is no injected identity, configuration response,
provider, or binding store. This is not a browser, MSI, or desktop qualification.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

RESULT_PREFIX = "APP02_RESTART_RESULT="
ORIGIN = "http://127.0.0.1:8765"
EMAIL = "restart-owner@example.test"
WORKSPACE = "customer-restart"


def _run_phase(phase: str) -> dict:
    import ipaddress
    import socket

    original_connect = socket.socket.connect

    def loopback_only(sock, address):
        try:
            local = ipaddress.ip_address(address[0]).is_loopback
        except ValueError:
            local = False
        if not local:
            raise AssertionError("External network is outside local setup acceptance")
        return original_connect(sock, address)

    # Windows asyncio uses a loopback socketpair; refuse external traffic.
    socket.socket.connect = loopback_only

    import maverick
    from fastapi.testclient import TestClient
    from maverick import config
    from maverick_dashboard.app import app

    repository = Path(__file__).resolve().parents[3]
    assert Path(maverick.__file__).resolve().is_relative_to(repository)
    assert config.config_path().parent == Path(os.environ["MAVERICK_HOME"])
    if phase == "first":
        assert not config.config_path().exists(), "Profile must have no prior config"
        assert not config.dashboard_overrides_path().exists()

    passphrase = os.environ["APP02_TEST_PASSPHRASE"]
    with TestClient(
        app, base_url=ORIGIN, client=("127.0.0.1", 53210),
        headers={"Origin": ORIGIN}, follow_redirects=False,
    ) as client:
        if phase == "first":
            assert client.get("/auth/local-owner").status_code == 200
            signed_in = client.post("/auth/local-owner", data={
                "email": EMAIL, "password": passphrase, "confirm": "yes",
            })
        else:
            # No copied cookie/session memory: read the persisted owner claim.
            assert client.get("/api/v1/vendor-setup").status_code == 401
            signed_in = client.post("/auth/local-login", data={
                "email": EMAIL, "password": passphrase,
            })
        assert signed_in.status_code == 303, signed_in.text
        assert "mvk_session" in client.cookies

        if phase == "first":
            active = client.get("/api/v1/workspace/active-tenant")
            assert active.status_code == 200, active.text
            assert active.json()["tenant_id"] is None
            created = client.post("/api/v1/admin/tenants", json={
                "id": WORKSPACE, "display_name": "Restart acceptance workspace",
                "plan": "free",
            })
            assert created.status_code == 201, created.text
            selected = client.put("/api/v1/workspace/active-tenant", json={
                "tenant_id": WORKSPACE,
            })
            assert selected.status_code == 200, selected.text

        active = client.get("/api/v1/workspace/active-tenant")
        assert active.status_code == 200, active.text
        assert active.json() == {
            "tenant_id": WORKSPACE, "source": "principal_selection",
            "selected": WORKSPACE, "env_tenant": None,
        }, active.text
        # The shared browser client carries the rendered workspace on writes.
        page = client.get("/third-party/vendor-onboarding")
        assert page.status_code == 200, page.text
        assert f'content="{WORKSPACE}"' in page.text
        client.headers["X-Lightwork-Expected-Tenant"] = active.json()["tenant_id"]
        before = client.get("/api/v1/vendor-setup")
        assert before.status_code == 200, before.text
        state = before.json()
        assert state["principal"] == "user:" + EMAIL
        if phase == "first":
            assert not state["modules_enabled"]
            assert "enable" in {row["id"] for row in state["readiness"]["actions"]}
            enabled = client.post("/api/v1/vendor-setup/enable", json={
                "confirm": True, "context": state["context"],
                "configuration": state["configuration"],
            })
            assert enabled.status_code == 200, enabled.text
            state = enabled.json()

        assert state["modules_enabled"] and state["connections_enabled"]
        assert state["revision"] == 0  # No invented connection or owner binding.
        assert state["binding"]["resource_owner"] == ""
        readiness = state["readiness"]
        assert readiness["state"] == "setup_required"
        assert readiness["configuration_complete"] is False
        assert readiness["live_provider_verified"] is False
        actions = readiness["actions"]
        assert {row["id"] for row in actions} == {"owner", "jira", "save"}
        assert len({row["id"] for row in actions}) == len(actions)

        page = client.get("/third-party/vendor-onboarding")
        assert page.status_code == 200, page.text
        assert f'content="{WORKSPACE}"' in page.text
        for action in actions:
            assert action["label"].strip()
            if action["href"].startswith("#"):
                assert f'id="{action["href"][1:]}"' in page.text
            else:
                target = client.get(action["href"])
                assert target.status_code == 200, target.text
        start = client.get("/start")
        assert start.status_code == 200, start.text
        assert config.dashboard_overrides_path().exists()
        return {
            "pid": os.getpid(), "workspace": active.json(),
            "modules_enabled": state["modules_enabled"],
            "connections_enabled": state["connections_enabled"],
            "revision": state["revision"], "readiness": readiness,
            "owner": state["principal"],
        }


def test_first_run_workspace_and_enabled_steps_survive_app_process_restart(tmp_path):
    profile = tmp_path / "profile"
    profile.mkdir()
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("MAVERICK_", "LIGHTWORK_"))
        and not key.endswith("_API_KEY")
    }
    environment.update({
        "HOME": str(tmp_path), "USERPROFILE": str(tmp_path),
        "MAVERICK_HOME": str(profile), "MAVERICK_SECURE_DEFAULT": "0",
        "MAVERICK_ENTERPRISE": "0", "MAVERICK_VOICE_AUTO_FETCH": "0",
        "MAVERICK_AUDIT_SIGNING_KEY": secrets.token_hex(32),
        "APP02_TEST_PASSPHRASE": "Disposable owner " + secrets.token_hex(16),
        "PYTHONIOENCODING": "utf-8",
    })
    results = []
    for phase in ("first", "restart"):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), phase],
            cwd=Path(__file__).resolve().parents[3], env=environment,
            capture_output=True, text=True, encoding="utf-8", timeout=90,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        payloads = [line.removeprefix(RESULT_PREFIX)
                    for line in result.stdout.splitlines()
                    if line.startswith(RESULT_PREFIX)]
        assert len(payloads) == 1, result.stdout
        results.append(json.loads(payloads[0]))
    assert results[0].pop("pid") != results[1].pop("pid")
    assert results[0] == results[1]


if __name__ == "__main__":
    assert sys.argv[1] in {"first", "restart"}
    print(RESULT_PREFIX + json.dumps(_run_phase(sys.argv[1]), sort_keys=True))
