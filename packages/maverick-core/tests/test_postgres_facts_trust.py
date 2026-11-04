"""Postgres facts.trust_tier memory guard (schema v24).

Runs only when MAVERICK_PG_DSN is set (the dedicated CI ``postgres`` job).

Before v24 the Postgres ``facts`` table had no trust column, so when temporal
memory was OFF, ``get_facts_with_trust`` defaulted every fact to tier 3 and the
Memory Guard could not drop poisoned/external memory on this backend. v24 adds
``source``/``trust_tier``/``sensitivity`` to ``facts`` and wires ``upsert_fact``
to persist them; these tests prove the non-temporal fallback is now closed,
mirroring the SQLite end-to-end assertion in ``test_memory_guard.py``.
"""
from __future__ import annotations

import os
import time

import pytest

_DSN = os.environ.get("MAVERICK_PG_DSN")
pytestmark = [pytest.mark.usefixtures("postgres_test_dsn"), pytest.mark.skipif(
    not _DSN, reason="MAVERICK_PG_DSN not set (no Postgres service)"
)]


@pytest.fixture
def world(monkeypatch):
    # Temporal memory explicitly OFF — this is the fallback the finding targets.
    monkeypatch.delenv("MAVERICK_TEMPORAL_MEMORY", raising=False)
    from maverick.world_model_backends.postgres import PostgresWorldModel
    w = PostgresWorldModel(dsn=_DSN)
    # Unique key prefix per test (the DB is shared/persistent).
    w._kp = f"ft-{int(time.time() * 1e6)}-"
    try:
        yield w
    finally:
        w.close()


def test_trust_tier_persisted_and_read_without_temporal(world):
    """A TOOL-tier (1) fact reads back at tier 1 from the facts table directly,
    with temporal history off — the closed non-temporal fallback."""
    w = world
    k = w._kp + "ok"
    w.upsert_fact(k, "ship on friday", source="tool", trust_tier=1)
    meta = w.get_facts_with_trust()
    assert meta[k] == ("ship on friday", 1)


def test_default_tier_is_first_party(world):
    """A fact written with no explicit tier reads as first-party (3) via the
    column DEFAULT, so the guard keeps memory it cannot otherwise tier."""
    w = world
    k = w._kp + "plain"
    w.upsert_fact(k, "value")
    meta = w.get_facts_with_trust()
    assert meta[k] == ("value", 3)


def test_memory_guard_drops_low_trust_without_temporal(world, monkeypatch):
    """End-to-end parity with SQLite: a high-trust-only (high_risk) brief
    excludes the TOOL-tier fact, on the non-temporal Postgres backend."""
    from maverick import memory_guard as mg
    monkeypatch.setenv("MAVERICK_MEMORY_GUARD", "1")
    w = world
    k = w._kp + "tool"
    w.upsert_fact(k, "ship on friday", source="tool", trust_tier=1)
    meta = w.get_facts_with_trust()
    assert meta[k] == ("ship on friday", 1)
    assert k not in mg.filter_facts(meta, high_risk=True)


def test_trust_tier_updates_on_reupsert(world):
    """Re-upserting a key updates its persisted tier (ON CONFLICT DO UPDATE)."""
    w = world
    k = w._kp + "shift"
    w.upsert_fact(k, "v", source="tool", trust_tier=1)
    w.upsert_fact(k, "v", source="user", trust_tier=3)
    meta = w.get_facts_with_trust()
    assert meta[k] == ("v", 3)


def test_recall_does_not_open_a_second_snapshot_between_value_and_tier(world):
    """A separate writer cannot be interleaved between value and tier reads.

    The former implementation called ``get_facts`` and then opened a second
    transaction for tiers. Hooking that call lets a writer deterministically
    replace a tier-0 value with tier 3 between snapshots, producing the unsafe
    pair ``("external", 3)``. Atomic recall never calls the hook.
    """
    from maverick.world_model_backends.postgres import PostgresWorldModel

    reader = world
    writer = PostgresWorldModel(dsn=_DSN)
    k = reader._kp + "atomic"
    writer.upsert_fact(k, "external", source="import", trust_tier=0)
    original_get_facts = reader.get_facts
    interleaved = False

    def split_snapshot():
        nonlocal interleaved
        facts = original_get_facts()
        writer.upsert_fact(k, "approved", source="user", trust_tier=3)
        interleaved = True
        return facts

    reader.get_facts = split_snapshot
    try:
        meta = reader.get_facts_with_trust()
    finally:
        writer.close()

    assert interleaved is False
    assert meta[k] == ("external", 0)
