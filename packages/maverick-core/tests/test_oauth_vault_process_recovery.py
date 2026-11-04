"""Real encrypted vault operations in independent spawned processes."""
from __future__ import annotations

import multiprocessing
import queue
import time

import pytest
from maverick.oauth_vault import OAuthRefreshError, OAuthVault

from test_support.oauth_vault_native import _operate


@pytest.fixture
def vault(monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    from maverick.tenant import kms
    kms._clear_cache()
    value = OAuthVault("synthetic-tenant")
    value.put("provider", {"access_token": "synthetic-old", "refresh_token": "synthetic-original",
                           "expires_at": time.time() - 3600})
    return value


def _race(first_op, second_op):
    ctx = multiprocessing.get_context("spawn")
    loaded, results = ctx.Queue(), ctx.Queue()
    release_a, release_b = ctx.Event(), ctx.Event()
    ready_a, ready_b = ctx.Event(), ctx.Event()
    a = ctx.Process(target=_operate, args=(first_op, ready_a, loaded, release_a, results, "A"))
    b = ctx.Process(target=_operate, args=(second_op, ready_b, loaded, release_b, results, "B"))
    try:
        a.start()
        assert ready_a.wait(15)
        assert loaded.get(timeout=15) == "A"
        b.start()
        assert ready_b.wait(15)
        # B has entered the operation, but cannot read A's obsolete snapshot.
        with pytest.raises(queue.Empty):
            loaded.get(timeout=0.5)
        release_a.set()
        assert loaded.get(timeout=15) == "B"
        release_b.set()
        a.join(15)
        b.join(15)
        assert a.exitcode == b.exitcode == 0
        messages = []
        while True:
            try:
                messages.append(results.get(timeout=0.2))
            except queue.Empty:
                break
        assert not [row for row in messages if row[0] == "error"]
        assert len([row for row in messages if row[0] == "done"]) == 2
        return messages
    finally:
        release_a.set()
        release_b.set()
        for process in (a, b):
            if process.pid is not None:
                process.join(2)
                if process.is_alive():
                    process.terminate()
                    process.join(5)
        loaded.close()
        results.close()


def test_two_process_provider_authorizations_are_not_lost(vault):
    _race("put", "put")
    assert vault.providers() == ["A", "B", "provider"]
    assert vault.get("A")["access_token"] == "synthetic-A"
    assert vault.get("B")["access_token"] == "synthetic-B"
    assert b"synthetic-A" not in vault._path().read_bytes()
    assert not list(vault._path().parent.glob("*.tmp"))


def test_two_process_refresh_rotates_once_and_both_observe_new_authorization(vault):
    messages = _race("refresh", "refresh")
    assert [row for row in messages if row[0] == "refresh"] == [("refresh", "synthetic-original")]
    assert [row for row in messages if row[0] == "token"] == [("token", "synthetic-new")] * 2
    assert vault.get("provider")["refresh_token"] == "synthetic-rotated"


def test_delete_waits_for_rotation_then_remains_authoritative(vault):
    _race("refresh", "delete")
    assert vault.get("provider") is None


def test_uncertain_refresh_hold_survives_fresh_instance(vault):
    def uncertain(_record):
        raise ConnectionError("synthetic response lost")
    with pytest.raises(OAuthRefreshError):
        vault.access_token("provider", refresher=uncertain)
    calls = []
    with pytest.raises(OAuthRefreshError, match="unconfirmed"):
        OAuthVault("synthetic-tenant").access_token(
            "provider", refresher=lambda record: calls.append(record))
    assert calls == []
    vault.put("provider", {"access_token": "synthetic-reconnected"})
    assert vault.access_token("provider") == "synthetic-reconnected"
