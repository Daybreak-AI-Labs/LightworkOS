"""Per-request memo for configuration-derived authorization predicates."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from maverick_dashboard import _request_memo, auth
from starlette.concurrency import run_in_threadpool


def test_memoized_is_uncached_outside_a_request_scope():
    calls = {"n": 0}

    def compute():
        calls["n"] += 1
        return calls["n"]

    assert _request_memo.in_scope() is False
    assert _request_memo.memoized("k", compute) == 1
    assert _request_memo.memoized("k", compute) == 2


def test_memo_is_per_request_and_follows_the_threadpool():
    calls = {"n": 0}

    def compute():
        calls["n"] += 1
        return calls["n"]

    app = FastAPI()
    app.add_middleware(_request_memo.RequestMemoMiddleware)

    @app.get("/x")
    async def x():
        first = _request_memo.memoized("k", compute)
        again = _request_memo.memoized("k", compute)
        pooled = await run_in_threadpool(_request_memo.memoized, "k", compute)
        return {"first": first, "again": again, "pooled": pooled}

    client = TestClient(app, base_url="http://127.0.0.1")
    assert client.get("/x").json() == {"first": 1, "again": 1, "pooled": 1}
    assert client.get("/x").json() == {"first": 2, "again": 2, "pooled": 2}
    assert _request_memo.in_scope() is False  # nothing leaks past the request


def test_auth_predicates_are_answered_once_per_request(monkeypatch):
    calls = {"n": 0}

    def _oidc_enabled():
        calls["n"] += 1
        return False

    monkeypatch.setattr(auth, "oidc_enabled", _oidc_enabled)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    app = FastAPI()
    app.add_middleware(_request_memo.RequestMemoMiddleware)

    @app.get("/x")
    async def x():
        for _ in range(10):
            auth.auth_genuinely_off()
            auth.non_static_auth_configured()
        return {"calls": calls["n"]}

    client = TestClient(app, base_url="http://127.0.0.1")
    assert client.get("/x").json() == {"calls": 1}
    assert client.get("/x").json() == {"calls": 2}  # a new request asks again
    # Outside a request the predicate still reads live configuration.
    auth.non_static_auth_configured()
    auth.non_static_auth_configured()
    assert calls["n"] == 4


def test_anonymous_access_is_rechecked_at_every_gate(monkeypatch):
    # Principal-less access is never remembered: each gate rechecks current
    # local policy, so a policy change takes effect inside the same request.
    import pytest

    checks = {"n": 0}
    allowed = {"v": True}

    def _allowed():
        checks["n"] += 1
        return allowed["v"]

    monkeypatch.setattr(auth, "anonymous_local_access_allowed", _allowed)
    monkeypatch.setattr(auth, "_dashboard_token_authenticated", lambda request: False)
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    request = Request(scope)
    assert auth._authorization_principal(request) is None
    assert auth._authorization_principal(Request(scope)) is None  # same scope, same state
    assert checks["n"] == 2

    allowed["v"] = False
    denied = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
    with pytest.raises(HTTPException):
        auth._authorization_principal(denied)
    with pytest.raises(HTTPException):
        auth._authorization_principal(denied)
    assert checks["n"] == 4


def test_a_request_still_reads_policy_errors_variables_and_the_key_live(tmp_path, monkeypatch):
    # A request-wide cache of the configuration was tried for speed and hid a
    # corrupt policy after reset_config_cache() (fail-closed checks then failed
    # open), kept a failed key read and missed ${VAR} changes. Each read inside
    # a request must stay live.
    import os

    from maverick import config, crypto_at_rest

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("MAVERICK_PROBE_VALUE", "one")
    config.reset_config_cache()
    (tmp_path / "config.toml").write_text(
        '[budget]\nmax_dollars = 5.0\n[probe]\nvalue = "${MAVERICK_PROBE_VALUE}"\n', encoding="utf-8",
    )
    with crypto_at_rest.deployment_key_scope():
        token = crypto_at_rest.seal_to_str("sk-test-not-a-real-key")  # pragma: allowlist secret
    config.dashboard_overrides_path().write_text(f'[providers.anthropic]\napi_key = "{token}"\n', encoding="utf-8")
    real = crypto_at_rest._load_or_create_key
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise crypto_at_rest.EncryptionUnavailable("the key file is held by its writer")
        return real()

    monkeypatch.setattr(crypto_at_rest, "_load_or_create_key", flaky)
    app = FastAPI()
    app.add_middleware(_request_memo.RequestMemoMiddleware)

    def api_key():
        return config.load_config().get("providers", {}).get("anthropic", {}).get("api_key")

    @app.get("/x")
    def x():
        seen = {"key": [api_key(), api_key()]}
        seen["value"] = [config.load_config()["probe"]["value"]]
        os.environ["MAVERICK_PROBE_VALUE"] = "two"
        seen["value"].append(config.load_config()["probe"]["value"])
        replacement = tmp_path / "config.toml.new"
        replacement.write_text("[budget]\nmax_dollars = 7.0\n", encoding="utf-8")
        os.replace(replacement, tmp_path / "config.toml")
        seen["budget"] = config.load_config()["budget"]["max_dollars"]
        (tmp_path / "config.toml").write_text("[budget\n", encoding="utf-8")  # corrupt policy
        config.load_config()
        config.reset_config_cache()  # what several settings readers do first
        config.load_config()
        seen["errors"] = sorted(config.config_source_errors())
        return seen

    try:
        assert TestClient(app, base_url="http://127.0.0.1").get("/x").json() == {
            "key": [None, "sk-test-not-a-real-key"],  # pragma: allowlist secret
            "value": ["one", "two"],
            "budget": 7.0,
            "errors": [str(tmp_path / "config.toml")],
        }
    finally:
        config.reset_config_cache()


def test_each_gate_reads_the_configuration_once_and_sees_a_policy_saved_before_it(tmp_path, monkeypatch):
    # A gate's sign-in decision asked about 15 questions of the configuration,
    # each reading and decrypting it again (about 350 reads per page).
    import os

    import pytest
    from maverick import config, crypto_at_rest

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_ENCRYPTION_KEY", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    (tmp_path / "config.toml").write_text("[budget]\nmax_dollars = 5.0\n", encoding="utf-8")
    with crypto_at_rest.deployment_key_scope():
        token = crypto_at_rest.seal_to_str("sk-test-not-a-real-key")  # pragma: allowlist secret
    config.dashboard_overrides_path().write_text(f'[providers.anthropic]\napi_key = "{token}"\n', encoding="utf-8")
    reads = []
    real = config._read_global_config
    monkeypatch.setattr(config, "_read_global_config", lambda: reads.append(1) or real())
    monkeypatch.setattr(auth, "caller_principal", lambda request: None)
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    try:
        assert auth._authorization_principal(Request(scope)) is None
        assert auth._authorization_principal(Request(scope)) is None
        assert len(reads) == 2
        replacement = tmp_path / "config.toml.new"
        replacement.write_text("[dashboard]\nrequire_auth = true\n", encoding="utf-8")
        os.replace(replacement, tmp_path / "config.toml")
        with pytest.raises(HTTPException):
            auth._authorization_principal(Request(scope))
        assert len(reads) == 3
    finally:
        config.reset_config_cache()


def test_a_gate_inside_a_page_render_reads_a_policy_saved_during_the_render(tmp_path, monkeypatch):
    # A page render reads the configuration once for its display; the
    # navigation's permission checks are gates and read the current files.
    import os

    import pytest
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    (tmp_path / "config.toml").write_text("[budget]\nmax_dollars = 5.0\n", encoding="utf-8")
    monkeypatch.setattr(auth, "caller_principal", lambda request: None)
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    try:
        with config.single_read():  # what templates.TemplateResponse opens
            assert config.load_config()["budget"]["max_dollars"] == 5.0  # the render's read
            assert auth._authorization_principal(Request(scope)) is None
            replacement = tmp_path / "config.toml.new"
            replacement.write_text("[dashboard]\nrequire_auth = true\n", encoding="utf-8")
            os.replace(replacement, tmp_path / "config.toml")
            assert "dashboard" not in config.load_config(), "the render keeps its own read"
            with pytest.raises(HTTPException):
                auth._authorization_principal(Request(scope))
            with pytest.raises(HTTPException):
                auth.has_permission(Request(scope), "view")  # what the navigation asks
    finally:
        config.reset_config_cache()


def test_a_signed_in_role_check_inside_a_render_reads_a_role_saved_during_it(tmp_path, monkeypatch):
    import os

    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    (tmp_path / "config.toml").write_text('[test_roles]\nx = "admin"\n', encoding="utf-8")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:x")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: config.load_config()["test_roles"]["x"])
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: config.load_config()["test_roles"]["x"])
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    try:
        with config.single_read():  # what templates.TemplateResponse opens
            assert config.load_config()["test_roles"]["x"] == "admin"  # the render's read
            assert auth.has_permission(Request(scope), "admin") is True
            replacement = tmp_path / "config.toml.new"
            replacement.write_text('[test_roles]\nx = "viewer"\n', encoding="utf-8")
            os.replace(replacement, tmp_path / "config.toml")
            assert auth.has_permission(Request(scope), "admin") is False
            assert auth.has_global_permission(Request(scope), "admin") is False
            assert auth.caller_role(Request(scope)) == "viewer"
    finally:
        config.reset_config_cache()


def test_a_page_reads_the_configuration_files_about_once(tmp_path, monkeypatch):
    # About 29 decisions per page each read the files, resolved the at-rest
    # key and decrypted the saved secrets again (6-11 ms a page here).
    from fastapi.testclient import TestClient
    from maverick import config, world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    config.reset_config_cache()
    (tmp_path / "config.toml").write_text("[budget]\nmax_dollars = 5.0\n", encoding="utf-8")
    reads = []
    real = config._read_global_config
    monkeypatch.setattr(config, "_read_global_config", lambda: reads.append(1) or real())
    monkeypatch.setattr(config, "_KEEP_READ_SECONDS", 600.0)  # a slow render is not what is tested
    client = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    try:
        assert client.get("/approvals").status_code == 200
        reads.clear()
        assert client.get("/approvals").status_code == 200
        assert 1 <= len(reads) <= 2, len(reads)
    finally:
        config.reset_config_cache()
        dashboard._world_cache.clear()
