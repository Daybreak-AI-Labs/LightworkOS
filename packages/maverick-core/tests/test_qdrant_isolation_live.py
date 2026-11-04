"""Qdrant tenant isolation against a REAL Qdrant server.

Skipped unless MAVERICK_QDRANT_URL points at a running server (the dedicated CI
qdrant job); needs qdrant-client + fastembed. The mock-based unit tests live in
test_qdrant_store.py. This proves the behaviour a mock can't: a real Qdrant
server only accepts uint/UUID point ids, so the store's tenant-namespaced string
ids must not be rejected with a 400 -- they're deterministic UUIDs with the
logical id in the payload, and add/query/delete are tenant-scoped end to end.
"""
from __future__ import annotations

import os

import pytest

_URL = os.environ.get("MAVERICK_QDRANT_URL")
pytestmark = pytest.mark.skipif(
    not _URL, reason="MAVERICK_QDRANT_URL not set (no Qdrant server)"
)


@pytest.fixture
def stores():
    pytest.importorskip("qdrant_client")
    pytest.importorskip("fastembed")
    from maverick.paths import reset_tenant, set_tenant
    from maverick.vector_store.qdrant_store import QdrantStore

    made = []

    def under(tenant):
        tok = set_tenant(tenant)
        try:
            s = QdrantStore(collection="iso_live", url=_URL)
            made.append(s)
            return s
        finally:
            reset_tenant(tok)

    # single shared collection; first store resets it clean
    a = under("acme")
    try:
        a.reset()
    except Exception:
        pass
    yield under


def _within(tenant, fn):
    from maverick.paths import reset_tenant, set_tenant
    tok = set_tenant(tenant)
    try:
        return fn()
    finally:
        reset_tenant(tok)


def test_tenant_scoped_add_query_delete(stores):
    under = stores
    a = under("acme")
    b = under("globex")
    # Same logical id in two tenants -- previously a 400 (invalid point id).
    _within("acme", lambda: a.add(["alpha from acme"], ids=["shared"]))
    _within("globex", lambda: b.add(["beta from globex"], ids=["shared"]))

    qa = _within("acme", lambda: a.query("from", top_k=5))
    qb = _within("globex", lambda: b.query("from", top_k=5))
    assert [(r["id"], r["document"]) for r in qa] == [("shared", "alpha from acme")]
    assert [(r["id"], r["document"]) for r in qb] == [("shared", "beta from globex")]

    # Deleting acme's id must not touch globex's same-id vector.
    _within("acme", lambda: a.delete(["shared"]))
    assert _within("acme", lambda: a.query("from", top_k=5)) == []
    assert [(r["id"], r["document"])
            for r in _within("globex", lambda: b.query("from", top_k=5))] == [
        ("shared", "beta from globex")]
