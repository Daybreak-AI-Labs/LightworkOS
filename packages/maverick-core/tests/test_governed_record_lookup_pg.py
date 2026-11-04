"""Native same-transaction index maintenance, migration and tenant isolation."""
from __future__ import annotations

import os

import pytest
from maverick import governed_records as gr
from maverick.governed_record_lookup import RecordLookupSpec, RecordLookupUnavailable, lookup_digest
from maverick.paths import tenant_scope

from test_support.postgres_authority import authority as authority

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"), reason="dedicated Postgres unavailable")


SPEC = RecordLookupSpec("test-tokens-v1", lambda row: [lookup_digest(value) for value in row.get("tokens", [])])


def save(backend, value):
    return backend.save({**value, "created_at": 1.0, "updated_at": 1.0})


def test_pg_lookup_migration_tenant_isolation_and_current_authority(authority, monkeypatch):
    factory, _, _ = authority
    legacy = factory("lookup_native")
    indexed = factory("lookup_native", lookup_spec=SPEC)
    with tenant_scope(tenant="alpha"):
        for i in range(23):
            save(legacy, {"id": f"PRB-{i:03d}", "tokens": [f"token-{i}"], "owner": "alpha"})
        with pytest.raises(RecordLookupUnavailable, match="rebuilding"):
            indexed.lookup(lookup_digest("token-22"))
        assert indexed.maintain_lookup(limit=3)["scanned"] == 13
        assert indexed.maintain_lookup()["ready"]
        original, sources = gr._row_record, []
        def counted(*args, **kwargs):
            if kwargs["prefix"] == "PRB":
                sources.append(kwargs["record_id"])
            return original(*args, **kwargs)
        monkeypatch.setattr(gr, "_row_record", counted)
        assert indexed.lookup(lookup_digest("token-0"))["owner"] == "alpha"
        assert sources == ["PRB-000"]
        sources.clear()
        assert indexed.lookup(lookup_digest("absent")) is None
        assert not sources
    with tenant_scope(tenant="beta"):
        save(indexed, {"id": "PRB-000", "tokens": ["token-0"], "owner": "beta"})
        assert indexed.lookup(lookup_digest("token-0"))["owner"] == "beta"
        with indexed._transaction("beta") as cursor:
            cursor.execute("SELECT DISTINCT tenant_id FROM governed_records")
            assert cursor.fetchall() == [("beta",)]
    with tenant_scope(tenant="alpha"):
        monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY_DIGEST")
        with pytest.raises(gr.GovernedRecordBackendError, match="identity"):
            indexed.lookup(lookup_digest("token-0"))


def test_pg_source_and_projection_rollback_together_and_collisions_fail_closed(authority, monkeypatch):
    factory, _, _ = authority
    indexed = factory("lookup_atomic", lookup_spec=SPEC)
    with tenant_scope(tenant="alpha"):
        source = save(indexed, {"id": "PRB-one", "tokens": ["old"]})
        assert indexed.lookup(lookup_digest("old"))
        replace = indexed._lookup.replace
        def failed(*args, **kwargs):
            replace(*args, **kwargs)
            raise RuntimeError("injected after index SQL")
        monkeypatch.setattr(indexed._lookup, "replace", failed)
        with pytest.raises(gr.GovernedRecordBackendError):
            indexed.update("PRB-one", lambda row: row.update(tokens=["new"]), expected_revision=source["revision"])
        monkeypatch.setattr(indexed._lookup, "replace", replace)
        assert indexed.lookup(lookup_digest("old"))["revision"] == source["revision"]
        assert indexed.lookup(lookup_digest("new")) is None
        duplicate = save(indexed, {"id": "PRB-two", "tokens": ["old"]})
        with pytest.raises(RecordLookupUnavailable, match="ambiguous"):
            indexed.lookup(lookup_digest("old"))
        indexed.delete("PRB-two", expected_revision=duplicate["revision"])
        assert indexed.lookup(lookup_digest("old"))["id"] == "PRB-one"
        newer = indexed.update("PRB-one", lambda row: row.update(tokens=["new"]), expected_revision=source["revision"])
        with pytest.raises(gr.RecordConflict):
            indexed.update("PRB-one", lambda row: row.update(tokens=["stale"]), expected_revision=source["revision"])
        assert indexed.lookup(lookup_digest("new"))["revision"] == newer["revision"]


def test_pg_rebuild_clears_in_bounded_batches_and_updates_behind_cursor(authority):
    factory, _, _ = authority
    indexed = factory("lookup_rebuild", lookup_spec=SPEC)
    with tenant_scope(tenant="alpha"):
        for i in range(12):
            save(indexed, {"id": f"PRB-{i:03d}", "tokens": [f"token-{i}"]})
        assert indexed.maintain_lookup()["ready"]
        step = indexed.maintain_lookup(limit=3, rebuild=True)
        assert not step["ready"] and step["phase"] == "clearing"
        while step["phase"] == "clearing":
            step = indexed.maintain_lookup(limit=3)
        step = indexed.maintain_lookup(limit=3)
        assert step["scanned"] == 3
        indexed.update("PRB-000", lambda row: row.update(tokens=["updated-behind-cursor"]), expected_revision=1)
        assert indexed.maintain_lookup()["ready"]
        assert indexed.lookup(lookup_digest("token-0")) is None
        assert indexed.lookup(lookup_digest("updated-behind-cursor"))["id"] == "PRB-000"


def test_pg_stale_positive_does_not_return_source_with_changed_association(authority):
    factory, _, _ = authority
    indexed = factory("lookup_stale", lookup_spec=SPEC)
    legacy = factory("lookup_stale")
    with tenant_scope(tenant="alpha"):
        save(indexed, {"id": "PRB-one", "tokens": ["old"]})
        assert indexed.lookup(lookup_digest("old"))
        legacy.update("PRB-one", lambda row: row.update(tokens=["new"]), expected_revision=1)
        with pytest.raises(RecordLookupUnavailable, match="needs rebuilding"):
            indexed.lookup(lookup_digest("old"))
        for _ in range(4):
            if indexed.maintain_lookup()["ready"]:
                break
        assert indexed.lookup(lookup_digest("old")) is None
        assert indexed.lookup(lookup_digest("new"))["id"] == "PRB-one"
