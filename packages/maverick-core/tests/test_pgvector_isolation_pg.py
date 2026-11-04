"""pgvector cross-collection isolation — runs only against a live Postgres.

Skipped locally / in the normal matrix (no Postgres, and pgvector may be
absent); the dedicated CI ``postgres`` job provides MAVERICK_PG_DSN. The
mock-based SQL assertions live in test_pgvector_store.py; this proves the real
behaviour: an add() in one collection must not overwrite a same-id row that
belongs to another collection (the old ``id``-only PRIMARY KEY + ON CONFLICT (id)
upsert stole it).
"""
from __future__ import annotations

import os

import pytest

_DSN = os.environ.get("MAVERICK_PG_DSN")
pytestmark = pytest.mark.skipif(
    not _DSN, reason="MAVERICK_PG_DSN not set (no Postgres service)"
)


def _embedder():
    return lambda texts: [[1.0, 0.0, 0.0] for _ in texts]


@pytest.fixture
def stores():
    pytest.importorskip("psycopg")
    from maverick.vector_store.pgvector_store import PgVectorStore
    try:
        a = PgVectorStore("iso_A", dsn=_DSN, embedder=_embedder())
    except Exception as e:  # pgvector extension unavailable on this server
        if "vector" in str(e).lower():
            pytest.skip(f"pgvector extension unavailable: {e}")
        raise
    b = PgVectorStore("iso_B", dsn=_DSN, embedder=_embedder())
    yield a, b
    # Clean up only our two collections so the shared DB stays reusable.
    for s in (a, b):
        try:
            s.reset()
        except Exception:
            pass


def test_same_id_across_collections_do_not_clobber(stores):
    a, b = stores
    a.add(["A private"], ids=["shared-1"])
    b.add(["B private"], ids=["shared-1"])  # same id, different collection

    # Each collection still holds its OWN document under that id.
    ra = a.query(embedding=[1.0, 0.0, 0.0], top_k=5)
    rb = b.query(embedding=[1.0, 0.0, 0.0], top_k=5)
    assert {r["id"]: r["document"] for r in ra}.get("shared-1") == "A private"
    assert {r["id"]: r["document"] for r in rb}.get("shared-1") == "B private"
    assert a.count() == 1
    assert b.count() == 1


def test_upsert_within_collection_still_updates(stores):
    # The composite key must not break intra-collection upsert: re-adding the
    # same id in the SAME collection updates in place, not duplicates.
    a, _ = stores
    a.add(["v1"], ids=["dup"])
    a.add(["v2"], ids=["dup"])
    assert a.count() == 1
    got = {r["id"]: r["document"] for r in a.query(embedding=[1.0, 0.0, 0.0], top_k=5)}
    assert got.get("dup") == "v2"
