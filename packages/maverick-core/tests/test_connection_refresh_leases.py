"""Real sealed stores and cross-process ownership; synthetic provider boundaries."""
from __future__ import annotations

import multiprocessing
import os
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from maverick import config, connections
from maverick import connection_oauth as oauth
from maverick.paths import tenant_scope

from test_support.connection_refresh_native import OWNER, _process_renew, _renew


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    config.config_path().write_text("[connections]\nenable=true\n[oauth]\nvault=true\n")
    monkeypatch.setattr(oauth, "_provider_identity", lambda *args, **_identity_inputs: {
        "provider": "google", "subject": "fixture-account", "display_name": "Fixture Account",
        "email": "fixture@example.test", "email_verified": True, "hosted_domain": "example.test",
    })
    with tenant_scope(tenant="tenant-a"):
        yield
    config.reset_config_cache()


def _seed(monkeypatch):
    oauth.save_application(OWNER, provider="google", client_id="synthetic-client-id",
                           client_secret="synthetic-client-secret", expected_revision="")  # pragma: allowlist secret - synthetic OAuth application fixture
    consent = oauth.begin(OWNER, profile="google-drive", name="evidence",
                          redirect_uri="https://lightwork.example/connections", context="fixture-context")
    monkeypatch.setattr(oauth, "_post_token", lambda *args: {
        "access_token": "synthetic-access-token", "refresh_token": "synthetic-refresh-token",
        "expires_in": 3600, "scope": " ".join(oauth.PROFILES["google-drive"]["scopes"]),
    })
    oauth.finish(OWNER, state=consent["state"], code="synthetic-code", context="fixture-context",
                 redirect_uri="https://lightwork.example/connections")
    with connections._mutation_lock():
        records = connections._load()
        records["evidence"]["oauth"]["expires_at"] = time.time() - 1
        connections._save(records)


def test_blocked_refresh_does_not_block_unrelated_reads_writes_or_renewal(monkeypatch):
    _seed(monkeypatch)
    with connections._mutation_lock():
        records = connections._load()
        import copy
        records["other"] = copy.deepcopy(records["evidence"])
        records["other"]["name"] = "other"
        records["other"]["oauth"]["refresh_token"] = "other-refresh"
        connections._save(records)
    entered, release = Event(), Event()

    def post(provider, payload):
        if payload["refresh_token"] != "other-refresh":
            entered.set()
            assert release.wait(10)
        return {"access_token": "new-fixture-token", "expires_in": 3600}

    monkeypatch.setattr(oauth, "_post_token", post)

    def other_operations():
        with tenant_scope(tenant="tenant-a"):
            assert connections.get_connection("evidence")["oauth"]["refresh_state"] == "pending"
            connections.set_connection("independent", owner=OWNER, token="independent-fixture")
            row = oauth.renew(connections.get_connection("other"), actor=OWNER)
            assert row["oauth"]["refresh_state"] == "ready"
            connections.record_test_result("evidence", reachable=True, authenticated=True)

    with ThreadPoolExecutor(max_workers=2) as executor:
        blocked = executor.submit(_renew)
        try:
            assert entered.wait(10)
            executor.submit(other_operations).result(timeout=5)
        finally:
            release.set()
        assert blocked.result(timeout=5)["last_test"]["authenticated"]
    assert connections.get_connection("independent")["token"] == "independent-fixture"


@pytest.mark.parametrize("change", ["delete", "replace", "grants", "application", "disabled"])
def test_authority_change_during_refresh_prevents_stale_promotion(monkeypatch, change):
    _seed(monkeypatch)
    entered, release = Event(), Event()

    def post(*args):
        entered.set()
        assert release.wait(10)
        return {"access_token": "must-not-publish", "expires_in": 3600}

    monkeypatch.setattr(oauth, "_post_token", post)

    def mutate():
        with tenant_scope(tenant="tenant-a"):
            if change == "delete":
                connections.delete_connection("evidence")
            elif change == "replace":
                connections.set_connection("evidence", token="replacement-fixture")
            elif change == "grants":
                connections.set_connection("evidence", allowed_principals=["user:changed"])
            elif change == "application":
                row = oauth.applications(OWNER)[0]
                oauth.save_application(OWNER, provider="google", client_id="changed-client",
                                       client_secret="changed-fixture", expected_revision=row["revision"])
            else:
                monkeypatch.setenv("MAVERICK_CONNECTIONS", "0")

    with ThreadPoolExecutor(max_workers=2) as executor:
        blocked = executor.submit(_renew)
        try:
            assert entered.wait(10)
            executor.submit(mutate).result(timeout=5)
        finally:
            release.set()
        with pytest.raises(PermissionError, match="could not be confirmed"):
            blocked.result(timeout=5)
    latest = connections.get_connection("evidence")
    assert latest is None or latest["token"] != "must-not-publish"
    if change in {"application", "grants", "disabled"}:
        assert latest["oauth"]["refresh_state"] == "pending"


def test_two_native_processes_refresh_one_credential_once(monkeypatch):
    _seed(monkeypatch)
    context = multiprocessing.get_context("spawn")
    entered, release, results = context.Event(), context.Event(), context.Queue()
    counter = context.Value("i", 0)
    children = [context.Process(target=_process_renew, args=(entered, release, counter, results)) for _ in range(2)]
    try:
        children[0].start()
        assert entered.wait(15)
        children[1].start()
        release.set()
        for child in children:
            child.join(20)
            assert child.exitcode == 0
        replies = [results.get(timeout=5) for _ in children]
        assert replies[0] == replies[1] == ("ready", connections.get_connection("evidence")["revision"])
        assert counter.value == 1
    finally:
        release.set()
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(5)
        results.close()
        results.join_thread()


@pytest.mark.parametrize("crash", ["pending", "consumed"])
def test_native_process_crash_never_replays_possibly_consumed_refresh(monkeypatch, crash):
    _seed(monkeypatch)
    context = multiprocessing.get_context("spawn")
    entered, release, results = context.Event(), context.Event(), context.Queue()
    counter = context.Value("i", 0)
    release.set()
    child = context.Process(target=_process_renew, args=(entered, release, counter, results), kwargs={"crash": crash})
    try:
        child.start()
        child.join(20)
        assert child.exitcode == (17 if crash == "pending" else 18)
        current = connections.get_connection("evidence")
        assert current["oauth"]["refresh_state"] == "pending"
        assert current["oauth"]["refresh_lease"]
        monkeypatch.setattr(oauth, "_post_token", lambda *args: pytest.fail("Ambiguous refresh was replayed"))
        with pytest.raises(PermissionError, match="interrupted"):
            _renew()
        assert counter.value == 1
        assert current["token"] == "synthetic-access-token"
    finally:
        if child.is_alive():
            child.terminate()
            child.join(5)
        results.close()
        results.join_thread()
