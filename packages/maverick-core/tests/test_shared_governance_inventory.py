from __future__ import annotations

import hashlib

import pytest
from maverick import shared_governance_inventory as inventory
from maverick.suite_audit_capture import build_suite_audit_capture
from maverick.unified_audit import GENESIS_SHA256, REQUIRED_SUITES, build_source_record


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _capture(tenant: str, source: str, *, suffix: str = "a"):
    record = build_source_record(
        sequence=1,
        occurred_at=1_800_000_000.0,
        action="record_created",
        actor_sha256=_sha(f"actor:{source}"),
        resource_sha256=_sha(f"resource:{source}"),
        payload_sha256=_sha(f"payload:{source}:{suffix}"),
        previous_sha256=GENESIS_SHA256,
    )
    return build_suite_audit_capture(
        tenant_id=tenant,
        source_id=source,
        source_revision=1 if suffix == "a" else 2,
        source_schema_version=1,
        observed_at=1_800_000_010.0,
        records=(record,),
        complete=False,
        retention_complete=False,
        integrity_verified=True,
        limitations=("source_history_incomplete", "source_retention_unverified"),
    )


class _Provider:
    provider_identity_sha256 = _sha("provider")

    def __init__(self, *, drift_source: str | None = None) -> None:
        self.calls: dict[str, int] = {}
        self.drift_source = drift_source

    def capture(self, *, tenant_id: str, source_id: str):
        self.calls[source_id] = self.calls.get(source_id, 0) + 1
        suffix = (
            "b"
            if source_id == self.drift_source and self.calls[source_id] == 2
            else "a"
        )
        return _capture(tenant_id, source_id, suffix=suffix)


def _graph(**_kwargs):
    return {
        "schema": "lightwork.entity-graph-inventory-provenance.v1",
        "state": "partial",
        "observed_at": 1_800_000_010.0,
        "graph_integrity_sha256": _sha("graph"),
        "entity_count": 0,
        "relationship_count": 0,
        "projected_entity_count": 0,
        "projected_relationship_count": 0,
        "limitations": ["source_completeness_unverified"],
        "entities": [],
        "relationships": [],
        "raw_names_included": False,
        "raw_aliases_included": False,
        "raw_record_ids_included": False,
        "raw_relationship_detail_included": False,
        "fuzzy_identity_merging_performed": False,
    }


def _projection(provider=None):
    return inventory.build_inventory_projection(
        tenant_id="tenant-a",
        provider=provider or _Provider(),
        provenance_reader=_graph,
        reference_key=b"k" * 32,
        clock=lambda: 1_800_000_020.0,
    )


def test_projection_is_source_complete_in_shape_but_candidly_partial_and_minimized():
    projection = _projection()
    assert projection["state"] == "partial"
    assert [item["source_id"] for item in projection["source_manifests"]] == list(
        REQUIRED_SUITES
    )
    assert len(projection["entities"]) == 6
    assert len({item["entity_ref_sha256"] for item in projection["entities"]}) == 6
    assert all(item["origin"] == "suite_capture" for item in projection["entities"])
    assert projection["limits"]["raw_source_records_persisted"] is False
    encoded = inventory._canonical(projection).decode("ascii")
    assert "resource:ai_governance" not in encoded
    assert "actor:ai_governance" not in encoded
    inventory.validate_inventory_projection(projection, tenant_id="tenant-a")


def test_source_drift_is_explicit_and_drifted_rows_are_not_projected():
    projection = _projection(_Provider(drift_source="ai_governance"))
    assert projection["state"] == "drifted"
    manifest = projection["source_manifests"][0]
    assert manifest["state"] == "drifted"
    assert manifest["projected_record_count"] == 0
    assert all(
        item.get("source_id") != "ai_governance" for item in projection["entities"]
    )


class _Clock:
    value = 1_800_000_100.0

    def __call__(self):
        return self.value


def _store(tmp_path, clock, *, name="inventory.sqlite3", recovery=None):
    return inventory.SharedGovernanceInventoryStore(
        tmp_path / name,
        tenant_id="tenant-a",
        integrity_key=b"s" * 32,
        principal_resolver=lambda: "principal-a",
        maintenance_authorizer=lambda: True,
        config_gate=lambda: None,
        clock=clock,
        retention_seconds=86_400,
        recovery_directory=recovery or (tmp_path / "recovery"),
    )


def test_store_cas_idempotency_queries_integrity_retention_and_recovery(tmp_path):
    clock = _Clock()
    store = _store(tmp_path, clock)
    first = store.reconcile(
        provider=_Provider(),
        provenance_reader=_graph,
        expected_active_revision=0,
        expected_active_integrity_sha256=GENESIS_SHA256,
        operation_id="reconcile-1",
    )
    replay = store.reconcile(
        provider=_Provider(drift_source="ai_governance"),
        provenance_reader=_graph,
        expected_active_revision=0,
        expected_active_integrity_sha256=GENESIS_SHA256,
        operation_id="reconcile-1",
    )
    assert replay == first
    with pytest.raises(inventory.SharedGovernanceInventoryConflict):
        store.reconcile(
            provider=_Provider(),
            provenance_reader=_graph,
            expected_active_revision=1,
            expected_active_integrity_sha256=GENESIS_SHA256,
            operation_id="reconcile-1",
        )
    page = store.query_entities(limit=2)
    assert page["count"] == 2 and page["next_cursor"] == 2
    exported = store.export_snapshot()
    assert "tenant-a" not in inventory._canonical(exported).decode("ascii")
    assert store.verify_integrity()["snapshot_count"] == 1

    active = store.active_authority()
    clock.value += 1
    second = store.reconcile(
        provider=_Provider(),
        provenance_reader=_graph,
        expected_active_revision=active["revision"],
        expected_active_integrity_sha256=active["integrity_sha256"],
        operation_id="reconcile-2",
    )
    clock.value += 90_000
    active = store.active_authority()
    retained = store.purge_expired(
        expected_active_revision=active["revision"],
        expected_active_integrity_sha256=active["integrity_sha256"],
        operation_id="retention-1",
        retain_latest=1,
    )
    assert retained["purged_count"] == 1
    with pytest.raises(inventory.SharedGovernanceInventoryGone):
        store.get_snapshot(first["metadata"]["snapshot_id"])
    assert store.get_snapshot(second["metadata"]["snapshot_id"])
    assert store.verify_integrity()["tombstone_count"] == 1
    # The revision-1 checkpoint embedded the purged payload and must not outlive it.
    checkpoints = sorted(path.name for path in (tmp_path / "recovery").iterdir())
    assert len(checkpoints) == 1 and checkpoints[0].startswith("inventory-00000002-")

    recovered = _store(
        tmp_path,
        clock,
        name="recovered.sqlite3",
        recovery=tmp_path / "recovery",
    )
    result = recovered.recover_latest()
    assert result["recovered"] is True and result["snapshot_count"] == 2
    assert recovered.verify_integrity()["tombstone_count"] == 1


def test_entity_graph_projection_contains_no_raw_labels(tmp_path, monkeypatch):
    from maverick import config, entity_graph

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "missing.toml"))
    config.reset_config_cache()
    value = entity_graph.inventory_provenance_manifest(
        tenant_id="tenant-a",
        reference_key=b"g" * 32,
        max_entities=10,
        max_relationships=10,
    )
    assert value["state"] == "partial"
    assert value["raw_names_included"] is False
    assert value["fuzzy_identity_merging_performed"] is False
