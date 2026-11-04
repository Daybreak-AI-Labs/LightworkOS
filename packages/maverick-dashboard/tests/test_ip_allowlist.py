"""Allowed network addresses: parsing, the proxy-aware client address, the
middleware gate, the workspace gate and the lock-out rail."""
from __future__ import annotations

import ipaddress
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick import config, world_model
from maverick_dashboard import ip_allowlist, settings_access_guard
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard.app import app
from starlette.datastructures import Headers


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_IP_ALLOWLIST", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_PROXY_AUTH"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _write_config(tmp_path, text: str) -> None:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


def _req(host="203.0.113.7", headers=None):
    return SimpleNamespace(client=SimpleNamespace(host=host), headers=Headers(headers or {}))


# ---- parsing -----------------------------------------------------------------


def test_parse_networks_reports_bad_entries_instead_of_skipping():
    nets, rejected = ip_allowlist.parse_networks(["10.0.0.0/8", "not-an-ip", " ", "::1"])
    assert [str(n) for n in nets] == ["10.0.0.0/8", "::1/128"]
    assert rejected == ["not-an-ip"]


def test_address_allowed_semantics():
    ip = ipaddress.ip_address("10.1.2.3")
    assert ip_allowlist.address_allowed(ip, []) is True          # empty: everyone
    assert ip_allowlist.address_allowed(ip, ["10.0.0.0/8"]) is True
    assert ip_allowlist.address_allowed(ip, ["192.0.2.0/24"]) is False
    assert ip_allowlist.address_allowed(ip, ["garbage"]) is False  # bad entry matches nothing
    assert ip_allowlist.address_allowed(None, ["10.0.0.0/8"]) is False


def test_parse_address_collapses_mapped_and_testclient():
    assert str(ip_allowlist.parse_address("::ffff:10.0.0.5")) == "10.0.0.5"
    assert ip_allowlist.parse_address("testclient").is_loopback
    assert ip_allowlist.parse_address("bogus") is None


# ---- the client address behind a proxy --------------------------------------


def test_forwarded_header_is_ignored_from_an_unpinned_peer():
    req = _req(host="203.0.113.7", headers={"X-Forwarded-For": "10.9.9.9"})
    assert str(ip_allowlist.client_ip(req)) == "203.0.113.7"


def test_forwarded_chain_is_walked_past_trusted_hops(tmp_path):
    _write_config(tmp_path, "[auth.proxy]\ntrusted_proxies = [\"10.0.0.0/24\"]\n")
    req = _req(host="10.0.0.5", headers={"X-Forwarded-For": "198.51.100.4, 10.0.0.6"})
    assert str(ip_allowlist.client_ip(req)) == "198.51.100.4"
    # A spoofed left-most hop does not matter: the walk stops at the first
    # address no trusted proxy vouched for.
    req = _req(host="10.0.0.5",
               headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.4, 10.0.0.6"})
    assert str(ip_allowlist.client_ip(req)) == "198.51.100.4"
    # No header from the pinned proxy: the proxy itself is the client.
    assert str(ip_allowlist.client_ip(_req(host="10.0.0.5"))) == "10.0.0.5"
    # A garbled hop cannot name the client; keep the last good address.
    req = _req(host="10.0.0.5", headers={"X-Forwarded-For": "garbage, 10.0.0.6"})
    assert str(ip_allowlist.client_ip(req)) == "10.0.0.6"


# ---- the installation gate (middleware) ----------------------------------------


def test_middleware_lets_everyone_in_when_the_list_is_empty():
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/healthz").status_code in {200, 503}
    assert client.get("/api/v1/sessions").status_code == 200


def test_middleware_blocks_an_address_outside_the_list(monkeypatch):
    monkeypatch.setenv("MAVERICK_IP_ALLOWLIST", "10.0.0.0/8")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    api = client.get("/api/v1/sessions")
    assert api.status_code == 403
    assert api.json()["detail"] == ip_allowlist.BLOCKED_MESSAGE
    page = client.get("/users", headers={"Accept": "text/html"})
    assert page.status_code == 403
    assert "This network address isn" in page.text
    # A cross-site header cannot buy an address: the peer is what counts.
    spoofed = client.get("/api/v1/sessions", headers={"X-Forwarded-For": "10.1.1.1"})
    assert spoofed.status_code == 403
    # Probes still answer so a load balancer never marks the server dead.
    assert client.get("/livez").status_code != 403


def test_middleware_allows_a_listed_address(monkeypatch):
    monkeypatch.setenv("MAVERICK_IP_ALLOWLIST", "127.0.0.1/32, 10.0.0.0/8")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/api/v1/sessions").status_code == 200


def test_installation_list_also_gates_the_websocket(monkeypatch):
    """Starlette never runs ``@app.middleware("http")`` for a WebSocket, so the
    run-events firehose has to apply the installation list itself, before
    accepting."""
    from maverick_dashboard import app as app_mod
    from starlette.testclient import WebSocketDisconnect

    app_mod._world_cache.clear()
    gid = app_mod._world().create_goal("t", "d")
    app_mod._world().set_goal_status(gid, "done", result="ok")
    monkeypatch.setenv("MAVERICK_IP_ALLOWLIST", "10.0.0.0/8")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/api/v1/sessions").status_code == 403
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("ws://127.0.0.1" + f"/ws/v1/runs/{gid}/events") as ws:
            ws.receive_json()
    monkeypatch.setenv("MAVERICK_IP_ALLOWLIST", "127.0.0.0/8")
    with client.websocket_connect("ws://127.0.0.1" + f"/ws/v1/runs/{gid}/events") as ws:
        assert ws.receive_json()["kind"] == "status"


def test_config_list_is_read_and_env_wins(tmp_path, monkeypatch):
    _write_config(tmp_path, "[auth.ip_allowlist]\ncidrs = [\"192.0.2.0/24\"]\n")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/api/v1/sessions").status_code == 403
    monkeypatch.setenv("MAVERICK_IP_ALLOWLIST", "127.0.0.0/8")
    assert client.get("/api/v1/sessions").status_code == 200


def test_unreadable_policy_allows_only_loopback(monkeypatch):
    def broken(**_kw):
        return {"config.toml": "corrupt"}

    monkeypatch.setattr(config, "config_source_errors", broken)
    assert ip_allowlist.installation_allows(_req(host="127.0.0.1")) is True
    assert ip_allowlist.installation_allows(_req(host="203.0.113.7")) is False


@pytest.mark.parametrize("line", ["cidrs = 5", "cidrs = true", "workspace_cidrs = 7"])
def test_a_mistyped_list_allows_only_loopback_instead_of_everyone(tmp_path, line):
    _write_config(tmp_path, "[auth.ip_allowlist]\n" + line + "\n")
    assert ip_allowlist.installation_allows(_req(host="127.0.0.1")) is True
    assert ip_allowlist.installation_allows(_req(host="203.0.113.7")) is False
    assert ip_allowlist.workspace_allows(_req(host="203.0.113.7")) is False
    assert ip_allowlist.configured() is True


@pytest.mark.parametrize("gate", ["installation_allows", "workspace_allows"])
def test_a_source_that_breaks_during_the_load_fails_closed(tmp_path, monkeypatch, gate):
    # The check before the load sees a clean file; the file breaks just before
    # the load reads it, so only the check after the load can notice the error.
    _write_config(tmp_path, "[auth.ip_allowlist]\ncidrs = [\"192.0.2.0/24\"]\n")
    assert config.config_source_errors() == {}
    real_get = config.get_ip_allowlist

    def get_after_the_file_breaks():
        (tmp_path / "home" / "config.toml").write_text("[auth.ip_allowlist\n", encoding="utf-8")
        return real_get()

    monkeypatch.setattr(config, "get_ip_allowlist", get_after_the_file_breaks)
    check = getattr(ip_allowlist, gate)
    assert check(_req(host="203.0.113.7")) is False
    assert check(_req(host="127.0.0.1")) is True


# ---- the workspace gate ------------------------------------------------------------


def test_workspace_list_applies_after_the_workspace_is_known(tmp_path):
    _write_config(tmp_path, "[auth.ip_allowlist]\nworkspace_cidrs = [\"192.0.2.0/24\"]\n")
    assert ip_allowlist.installation_allows(_req(host="203.0.113.7")) is True
    assert ip_allowlist.workspace_allows(_req(host="203.0.113.7")) is False
    assert ip_allowlist.workspace_allows(_req(host="192.0.2.9")) is True


def _write_workspace_overlay(monkeypatch, text: str) -> None:
    """The pinned workspace's own config.toml (``tenants/<id>/config.toml``)."""
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    path = config.tenant_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    config.reset_config_cache()


def test_corrupt_workspace_overlay_fails_closed_to_loopback(monkeypatch):
    # An unparsable overlay must not read as "no workspace list", which would
    # allow every address: the workspace is then reachable from this computer only.
    _write_workspace_overlay(monkeypatch, "[auth.ip_allowlist\nworkspace_cidrs = [")
    assert ip_allowlist.workspace_allows(_req(host="127.0.0.1")) is True
    assert ip_allowlist.workspace_allows(_req(host="203.0.113.7")) is False


def test_healthy_empty_workspace_overlay_still_allows_everyone(monkeypatch):
    _write_workspace_overlay(monkeypatch, "[auth.ip_allowlist]\nworkspace_cidrs = []\n")
    assert ip_allowlist.workspace_allows(_req(host="203.0.113.7")) is True


def test_healthy_workspace_overlay_list_is_enforced(monkeypatch):
    _write_workspace_overlay(monkeypatch, "[auth.ip_allowlist]\nworkspace_cidrs = [\"192.0.2.0/24\"]\n")
    assert ip_allowlist.workspace_allows(_req(host="203.0.113.7")) is False
    assert ip_allowlist.workspace_allows(_req(host="192.0.2.9")) is True


# The installation list is read through the same load as the workspace list, so
# an active tenant's overlay can set it too, and a corrupt overlay fails closed.


def test_corrupt_tenant_overlay_fails_closed_for_the_installation_list(monkeypatch):
    _write_workspace_overlay(monkeypatch, "[auth.ip_allowlist\ncidrs = [")
    assert ip_allowlist.installation_allows(_req(host="127.0.0.1")) is True
    assert ip_allowlist.installation_allows(_req(host="203.0.113.7")) is False


def test_a_tenant_overlay_that_breaks_during_the_load_fails_closed(monkeypatch):
    # The healthy overlay passes the check before the load; it breaks just before
    # the load reads it, so only the check after the load can notice the error.
    _write_workspace_overlay(monkeypatch, "[auth.ip_allowlist]\ncidrs = [\"192.0.2.0/24\"]\n")
    assert config.config_source_errors() == {}
    overlay = config.tenant_config_path()
    real_get = config.get_ip_allowlist

    def get_after_the_overlay_breaks():
        overlay.write_text("[auth.ip_allowlist\n", encoding="utf-8")
        return real_get()

    monkeypatch.setattr(config, "get_ip_allowlist", get_after_the_overlay_breaks)
    assert ip_allowlist.installation_allows(_req(host="203.0.113.7")) is False
    assert ip_allowlist.installation_allows(_req(host="127.0.0.1")) is True


def test_healthy_tenant_overlay_list_is_enforced_for_the_installation_list(monkeypatch):
    _write_workspace_overlay(monkeypatch, "[auth.ip_allowlist]\ncidrs = [\"192.0.2.0/24\"]\n")
    assert ip_allowlist.installation_allows(_req(host="203.0.113.7")) is False
    assert ip_allowlist.installation_allows(_req(host="192.0.2.9")) is True


def test_workspace_gate_refuses_a_bound_principal(tmp_path):
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import auth

    _write_config(tmp_path, "[auth.ip_allowlist]\nworkspace_cidrs = [\"192.0.2.0/24\"]\n")
    principal = VerifiedPrincipal(sub="a", issuer="oidc-session", audience="",
                                  claims={"via": "session", "mfa": False})
    request = SimpleNamespace(client=SimpleNamespace(host="203.0.113.7"), headers=Headers({}),
                              url=SimpleNamespace(path="/metrics"), state=SimpleNamespace())
    with pytest.raises(auth.HTTPException) as exc:
        auth._bind_principal(request, principal)
    assert exc.value.status_code == 403 and exc.value.detail == ip_allowlist.BLOCKED_MESSAGE
    # Sign-out must still work from a refused address.
    request.url.path = "/auth/logout"
    assert auth._bind_principal(request, principal) is principal


# ---- the lock-out rail -----------------------------------------------------------


def _change(setting_id, new):
    return {"setting": catalog.BY_ID[setting_id], "old": [], "new": new}


def test_saving_a_list_without_your_own_address_is_refused():
    request = _req(host="203.0.113.7")
    changes = [_change("auth.ip_allowlist.cidrs", ["10.0.0.0/8"])]
    with pytest.raises(settings_access_guard.Refused) as exc:
        settings_access_guard.review_allowed_addresses(
            request, changes, {"auth.ip_allowlist.cidrs": ["10.0.0.0/8"]})
    assert "203.0.113.7" in exc.value.message and "lock you out" in exc.value.message
    # Listing the range you are on passes; an empty list always passes.
    settings_access_guard.review_allowed_addresses(
        request, changes, {"auth.ip_allowlist.cidrs": ["203.0.113.0/24"]})
    settings_access_guard.review_allowed_addresses(
        request, changes, {"auth.ip_allowlist.cidrs": []})


def test_saving_an_unparsable_entry_is_refused():
    request = _req(host="203.0.113.7")
    changes = [_change("auth.ip_allowlist.cidrs", ["203.0.113.7", "office"])]
    with pytest.raises(settings_access_guard.Refused) as exc:
        settings_access_guard.review_allowed_addresses(
            request, changes, {"auth.ip_allowlist.cidrs": ["203.0.113.7", "office"]})
    assert "office" in exc.value.message


def test_lockout_rail_runs_through_the_settings_api():
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    revision = client.get("/api/v1/settings/catalog").json()["revision"]
    resp = client.post("/api/v1/settings/catalog", json={"expected_revision": revision, "changes": [
        {"id": "auth.ip_allowlist.cidrs", "value": ["10.0.0.0/8"]}]})
    assert resp.status_code == 409
    assert resp.json().get("lockout") is True
    assert "127.0.0.1" in resp.json()["message"]
