"""Temporal fact_history parity on the Postgres backend (audit follow-up).

Runs only when MAVERICK_PG_DSN is set (the dedicated CI ``postgres`` job). Mirrors
the SQLite bitemporal behaviour: with [memory] temporal on, a changed value
appends a version and closes the prior window, ``get_fact(as_of=...)`` reads the
value as it stood at an instant, ``fact_history`` lists versions newest-first,
delete closes the open window, and the GDPR helpers cover history.
"""
from __future__ import annotations

import os
import time
from types import SimpleNamespace

import pytest

_DSN = os.environ.get("MAVERICK_PG_DSN")
pytestmark = [pytest.mark.usefixtures("postgres_test_dsn"), pytest.mark.skipif(
    not _DSN, reason="MAVERICK_PG_DSN not set (no Postgres service)"
)]


@pytest.fixture
def temporal_world(monkeypatch):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    from maverick.world_model_backends.postgres import PostgresWorldModel
    w = PostgresWorldModel(dsn=_DSN)
    # Isolate each test under a unique key prefix (the DB is shared/persistent).
    w._kp = f"th-{int(time.time()*1e6)}-"
    try:
        yield w
    finally:
        w.close()


def test_history_records_versions_and_as_of(temporal_world):
    w = temporal_world
    k = w._kp + "color"
    t0 = time.time()
    w.upsert_fact(k, "red")
    time.sleep(0.02)
    mid = time.time()
    time.sleep(0.02)
    w.upsert_fact(k, "blue")

    # Current value is the latest.
    assert w.get_fact(k) == "blue"

    # Two versions, newest first; the newest is the open (current) window.
    hist = w.fact_history(k)
    assert [h.value for h in hist] == ["blue", "red"]
    assert hist[0].valid_to is None
    assert hist[1].valid_to is not None

    # as_of reads the value as it stood at that instant.
    assert w.get_fact(k, as_of=mid) == "red"
    assert w.get_fact(k, as_of=t0 - 100) is None
    assert w.get_fact(k, as_of=time.time() + 100) == "blue"


def test_unchanged_value_adds_no_version(temporal_world):
    w = temporal_world
    k = w._kp + "stable"
    w.upsert_fact(k, "same")
    w.upsert_fact(k, "same")
    assert len(w.fact_history(k)) == 1


def test_trust_tier_change_records_version(temporal_world):
    w = temporal_world
    k = w._kp + "claim"
    w.upsert_fact(k, "x", trust_tier=3)
    w.upsert_fact(k, "x", trust_tier=1)  # same value, lower trust -> new belief
    hist = w.fact_history(k)
    assert len(hist) == 2
    assert hist[0].trust_tier == 1


def test_delete_closes_open_window(temporal_world):
    w = temporal_world
    k = w._kp + "gone"
    w.upsert_fact(k, "here")
    assert w.delete_fact(k) == 1
    assert w.get_fact(k) is None
    # History row is retained but its window is now closed.
    hist = w.fact_history(k)
    assert len(hist) == 1
    assert hist[0].valid_to is not None


def test_delete_window_survives_clock_rollback(
    temporal_world, monkeypatch,
):
    from maverick.world_model_backends import postgres

    w = temporal_world
    k = w._kp + "rollback-delete"
    times = iter((1_000.0, 999.0))
    monkeypatch.setattr(postgres, "time", SimpleNamespace(time=lambda: next(times)))

    w.upsert_fact(k, "here")
    assert w.delete_fact(k) == 1

    [version] = w.fact_history(k)
    assert version.valid_to is not None
    assert version.valid_to > version.valid_from


def test_gdpr_history_export_and_purge(temporal_world):
    w = temporal_world
    tok = w._kp.replace("-", "")  # token must be embeddable in a key
    k = f"user:{tok}:email"
    w.upsert_fact(k, "a@x.com")
    w.upsert_fact(k, "b@x.com")

    export = w.fact_history_matching(tok)
    assert k in export
    assert {v.value for v in export[k]} == {"a@x.com", "b@x.com"}

    # Art.17 erase purges the whole history for the subject prefix.
    removed = w.delete_facts_matching(tok)
    assert k in removed
    assert w.fact_history_matching(tok) == {}
    assert w.fact_history(k) == []


def test_revision_conflict_and_delete_recreate_parity(temporal_world):
    from maverick.fact_revision import FactConflict

    w = temporal_world
    key = w._kp + "revision"
    first = w.upsert_fact(key, "one", expected_revision=0)
    second = w.upsert_fact(key, "two", expected_revision=first)
    assert second > first
    assert w.fact_record(key)["revision"] == second
    history = w.fact_history(key)
    with pytest.raises(FactConflict):
        w.upsert_fact(key, "stale", expected_revision=first)
    with pytest.raises(FactConflict):
        w.delete_fact(key, expected_revision=first)
    assert w.fact_history(key) == history
    w.delete_fact(key, expected_revision=second)
    third = w.upsert_fact(key, "three", expected_revision=0)
    assert third > second
    with pytest.raises(FactConflict):
        w.delete_fact(key, expected_revision=second)


def test_revision_and_browsing_are_exact_tenant_scoped(temporal_world):
    from maverick.fact_revision import FactConflict
    from maverick.paths import tenant_scope

    w = temporal_world
    key = w._kp + "tenant-revision"
    with tenant_scope(tenant="revision-a"):
        a_revision = w.upsert_fact(key, "a", expected_revision=0)
    with tenant_scope(tenant="revision-b"):
        assert w.fact_record(key) is None
        b_revision = w.upsert_fact(key, "b", expected_revision=0)
        with pytest.raises(FactConflict):
            w.upsert_fact(key, "wrong", expected_revision=a_revision)
        assert w.fact_record(key)["value"] == "b"
    with tenant_scope(tenant="revision-a"):
        with pytest.raises(FactConflict):
            w.delete_fact(key, expected_revision=b_revision)
        assert w.fact_record(key)["value"] == "a"
