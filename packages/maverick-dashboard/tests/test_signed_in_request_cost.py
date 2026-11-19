"""What one signed-in request costs on the shared request path, and what it still checks.

On network storage every file operation in the data folder is a round trip.
A signed-in request for a versioned script asked the configuration whether it
had changed (a stat of every file a read depends on) 11 times before the
script was sent; a page loads about 29 of them. Each gate still reads the
current configuration once. These tests pin the cost and pin that sign-out,
revocation and a saved address policy still apply to the very next request.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

ISSUER = "https://identity.example.test"
AUDIENCE = "lightwork"
SECRET = "0123456789abcdef0123456789abcdef"  # pragma: allowlist secret
BASE = "http://127.0.0.1"


@pytest.fixture
def signed_in(tmp_path, monkeypatch):
    from maverick import audit, config, world_model
    from maverick_dashboard import app as app_mod

    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("")
    monkeypatch.setenv("MAVERICK_OIDC_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("MAVERICK_OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_ID", "test-client")
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("MAVERICK_OIDC_REDIRECT_URI", BASE + "/auth/callback")
    monkeypatch.setenv("MAVERICK_OIDC_SESSION_SECRET", SECRET)
    monkeypatch.setenv("MAVERICK_OIDC_AUTHORIZATION_ENDPOINT", ISSUER + "/authorize")
    monkeypatch.setenv("MAVERICK_OIDC_TOKEN_ENDPOINT", ISSUER + "/token")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER",
                 "MAVERICK_IP_ALLOWLIST", "MAVERICK_ENCRYPTION_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(audit, "audit_event", lambda *args, **kwargs: True)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app_mod._world_cache.clear()
    config.reset_config_cache()
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    client = TestClient(app_mod.app, base_url=BASE, headers={"Origin": BASE},
                        follow_redirects=False)
    yield SimpleNamespace(client=client, home=home, config_file=tmp_path / "config.toml")
    app_mod._world_cache.clear()
    config.reset_config_cache()


def _sign_in(client, sub="alice") -> str:
    from maverick_dashboard.oidc_login import SESSION_COOKIE, mint_browser_session

    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                              headers={"user-agent": "test"})
    cookie = mint_browser_session(
        request, sub=sub, secret=SECRET, via="session", mfa=False, ttl=3600,
        extra={"oidc_issuer": ISSUER, "oidc_audience": AUDIENCE},
    )
    client.cookies.set(SESSION_COOKIE, cookie)
    return cookie


def _script() -> str:
    from maverick_dashboard.app import static_version

    return f"/static/lightwork-ui.js?v={static_version('lightwork-ui.js')}"


class _Cost:
    """Configuration checks, full reads and data-folder file operations of one request."""

    def __init__(self, monkeypatch, home):
        from maverick import config

        self.checks = self.reads = self.ops = 0
        self.home = str(home)
        real_witness, real_read = config._read_witness, config._read_global_config

        def witness():
            self.checks += 1
            return real_witness()

        def read():
            self.reads += 1
            return real_read()

        monkeypatch.setattr(config, "_read_witness", witness)
        monkeypatch.setattr(config, "_read_global_config", read)
        self.armed = False
        import builtins

        for module, name in ((os, "stat"), (os, "lstat"), (os, "scandir"), (builtins, "open")):
            monkeypatch.setattr(module, name, self._counting(getattr(module, name)))

    def _counting(self, real):
        def counted(path, *args, **kwargs):
            if self.armed and isinstance(path, (str, os.PathLike)) and os.fspath(path).startswith(self.home):
                self.ops += 1
            return real(path, *args, **kwargs)
        return counted

    def measure(self, client, path):
        client.get(path)  # warm: first-use files and connections
        self.checks = self.reads = self.ops = 0
        self.armed = True
        try:
            response = client.get(path)
        finally:
            self.armed = False
        return response


def test_a_signed_in_script_costs_one_configuration_check_per_gate(signed_in, monkeypatch):
    _sign_in(signed_in.client)
    cost = _Cost(monkeypatch, signed_in.home)
    response = cost.measure(signed_in.client, _script())
    assert response.status_code == 200
    assert "immutable" in response.headers["cache-control"]
    # The request's own read, then one check each for the sign-in mode, the
    # installation address list, the sign-in itself, the workspace choice and
    # the workspace policies (10 checks here before they were shared per gate).
    assert cost.reads <= 1
    assert cost.checks <= 6, cost.checks
    assert cost.ops <= 40, cost.ops  # 58 before


def test_a_signed_in_api_call_costs_one_configuration_check_per_gate(signed_in, monkeypatch):
    _sign_in(signed_in.client)
    cost = _Cost(monkeypatch, signed_in.home)
    response = cost.measure(signed_in.client, "/api/v1/features/modules")
    assert response.status_code == 200
    assert cost.reads <= 1
    assert cost.checks <= 8, cost.checks  # 12 before
    assert cost.ops <= 52, cost.ops  # 71 before


def test_protected_files_still_need_a_sign_in(signed_in):
    client = signed_in.client
    assert client.get(_script()).status_code == 401
    assert client.get("/goals").status_code in (302, 303, 307, 401)
    assert client.get("/static/lightwork.css").status_code == 200  # the public shell stylesheet


def test_signing_out_ends_access_to_scripts_pages_and_the_api_at_once(signed_in):
    from maverick_dashboard.oidc_login import SESSION_COOKIE

    client = signed_in.client
    cookie = _sign_in(client)
    for path in (_script(), "/api/v1/features/modules"):
        assert client.get(path).status_code == 200, path
    assert client.post("/auth/logout").status_code == 303
    client.cookies.set(SESSION_COOKIE, cookie)  # a copy of the old cookie
    assert client.get(_script()).status_code == 401
    assert client.get("/api/v1/features/modules").status_code == 401
    assert client.get("/goals").status_code != 200


def test_ending_one_session_or_every_session_applies_to_the_next_request(signed_in):
    import time

    from maverick_dashboard import session_registry
    from maverick_dashboard.oidc_login import _session_payload_unchecked
    from maverick_dashboard.session_revocation import revoke_principal

    client = signed_in.client
    cookie = _sign_in(client)
    assert client.get(_script()).status_code == 200
    request = SimpleNamespace(cookies={"mvk_session": cookie})
    session_registry.revoke(_session_payload_unchecked(request)["sid"], by="an administrator")
    assert client.get(_script()).status_code == 401

    _sign_in(client)
    assert client.get(_script()).status_code == 200
    time.sleep(0.01)
    revoke_principal("alice")  # Sign out everywhere / a deprovision
    assert client.get(_script()).status_code == 401
    assert client.get("/api/v1/features/modules").status_code == 401


def test_a_saved_address_policy_applies_to_the_next_script_request(signed_in):
    client = signed_in.client
    _sign_in(client)
    assert client.get(_script()).status_code == 200
    signed_in.config_file.write_text('[auth.ip_allowlist]\ncidrs = ["10.9.8.0/24"]\n')
    assert client.get(_script()).status_code == 403
    signed_in.config_file.write_text("")
    assert client.get(_script()).status_code == 200
    signed_in.config_file.write_text('[auth.ip_allowlist]\nworkspace_cidrs = ["10.9.8.0/24"]\n')
    assert client.get(_script()).status_code == 403


def test_the_home_page_reads_the_start_page_without_the_chat_choices(signed_in, monkeypatch):
    # Choosing where "/" lands needs only the person's start page. Reading the
    # model and specialist choices for it (thrown away, then read again for
    # Chat) was about 1,300 data-folder operations on the home page.
    from maverick_dashboard import (
        onboarding_state,
        product_operations_task_launch,
        task_model_selection_api,
    )

    calls = {"models": 0, "specialists": 0}
    models, specialists = task_model_selection_api.choices, product_operations_task_launch.published_specialists

    def counted_models(request):
        calls["models"] += 1
        return models(request)

    def counted_specialists(request, *args, **kwargs):
        calls["specialists"] += 1
        return specialists(request, *args, **kwargs)

    monkeypatch.setattr(task_model_selection_api, "choices", counted_models)
    monkeypatch.setattr(product_operations_task_launch, "published_specialists", counted_specialists)
    monkeypatch.setattr(onboarding_state, "selected_model_routes_ready", lambda: True)
    _sign_in(signed_in.client)
    response = signed_in.client.get("/")
    assert response.status_code == 200, response.headers.get("location")
    assert calls == {"models": 0, "specialists": 1}  # Chat's own shortened list only


def test_the_companion_links_follow_the_gate_without_the_effect_fence(monkeypatch):
    # The sidebar asks twice per page whether to show the companion links. The
    # answer only shows or hides a link (the page itself checks under the
    # fence), so it must not take the cross-process authority fence: a lock
    # file round trip per check, and every page waited on any authority change.
    from contextlib import contextmanager

    from fastapi import HTTPException
    from maverick_dashboard import employee_companion_api

    fenced = []

    @contextmanager
    def fence():
        fenced.append(1)
        yield

    monkeypatch.setattr(employee_companion_api, "authority_effect_fence", fence)
    seen = []
    monkeypatch.setattr(employee_companion_api, "_authority",
                        lambda request, *, admin=False: seen.append(admin))
    assert employee_companion_api.navigation_available(object()) is True
    assert employee_companion_api.navigation_available(object(), admin=True) is True
    assert seen == [False, True] and fenced == []

    def refused(request, *, admin=False):
        raise HTTPException(403, "not a member")

    monkeypatch.setattr(employee_companion_api, "_authority", refused)
    assert employee_companion_api.navigation_available(object()) is False


def _ai_service_saved():
    from maverick_dashboard import settings_store

    settings_store.set_provider("anthropic", api_key="sk-ant-api03-" + "x" * 80)  # pragma: allowlist secret


def test_one_ai_readiness_answer_reads_the_configuration_once(signed_in, monkeypatch):
    from maverick import config
    from maverick_dashboard import provider_readiness

    _ai_service_saved()
    checks = []
    real = config._read_witness
    monkeypatch.setattr(config, "_read_witness", lambda: checks.append(1) or real())
    with config.kept_reads():
        assert provider_readiness.workspace_readiness()["verdict"] != "not_ready"
    assert len(checks) <= 1, len(checks)


def test_the_chat_page_works_out_ai_readiness_once(signed_in, monkeypatch):
    from maverick_dashboard import provider_readiness

    _ai_service_saved()
    calls = []
    real = provider_readiness.workspace_readiness
    monkeypatch.setattr(provider_readiness, "workspace_readiness", lambda: calls.append(1) or real())
    _sign_in(signed_in.client)
    assert signed_in.client.get("/").status_code == 200
    assert len(calls) == 1  # the home redirect's answer, reused by Chat in the same request
    calls.clear()
    assert signed_in.client.get("/").status_code == 200
    assert len(calls) == 1  # the next request works it out again
