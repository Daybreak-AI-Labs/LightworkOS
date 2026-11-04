"""Tests for the Weaviate vector store adapter.

weaviate-client is an optional dep; we test the missing-import path and the
wired-up path with a fake client, with no real backend.
"""
from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from maverick import provider_cost_cap as cap
from maverick.paths import tenant_scope


@pytest.fixture
def provider_ledger(tmp_path, monkeypatch):
    path = tmp_path / "provider-spend.json"
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "_ledger_path", lambda: path)
    monkeypatch.setattr(
        cap,
        "period_key",
        lambda now=None, period=None: "2026-09-08",
    )
    return path


def test_weaviate_missing_import_raises(monkeypatch):
    monkeypatch.setitem(sys.modules, "weaviate", None)
    from maverick.vector_store.weaviate_store import WeaviateStore
    with pytest.raises(ImportError, match="weaviate-client not installed"):
        WeaviateStore()


def _install_fake_weaviate(monkeypatch) -> MagicMock:
    fake_collection = MagicMock(name="collection")
    fake_collections = MagicMock(name="collections")
    fake_collections.exists.return_value = False
    fake_collections.get.return_value = fake_collection
    fake_client = MagicMock(name="weaviate client")
    fake_client.collections = fake_collections
    fake_collection.batch.failed_objects = []

    fake_module = MagicMock(name="weaviate module")
    fake_module.connect_to_embedded.return_value = fake_client
    fake_module.connect_to_local.return_value = fake_client
    fake_module.connect_to_custom.return_value = fake_client
    fake_module.connect_to_weaviate_cloud.return_value = fake_client
    monkeypatch.setitem(sys.modules, "weaviate", fake_module)
    return fake_client


def test_weaviate_embedded_init_creates_collection(monkeypatch):
    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    monkeypatch.delenv("MAVERICK_WEAVIATE_VECTORIZER", raising=False)
    fake = _install_fake_weaviate(monkeypatch)
    from maverick.vector_store.weaviate_store import WeaviateStore
    WeaviateStore(collection="goals")
    # Capitalized class name, created because exists()==False, AND with a
    # server-side vectorizer configured (without it near_text cannot embed).
    fake.collections.create.assert_called_once()
    args, kwargs = fake.collections.create.call_args
    assert args[0] == "Goals"
    assert kwargs.get("vectorizer_config") is not None


def test_weaviate_vectorizer_none_skips_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    fake = _install_fake_weaviate(monkeypatch)
    from maverick.vector_store.weaviate_store import WeaviateStore
    WeaviateStore(collection="goals", vectorizer="none")
    # Explicit opt-out: created with no vectorizer_config.
    fake.collections.create.assert_called_once_with("Goals")


def test_weaviate_remote_url_uses_custom_connector(monkeypatch):
    _install_fake_weaviate(monkeypatch)
    from maverick.vector_store.weaviate_store import WeaviateStore

    WeaviateStore(url="https://weaviate.example:8443", vectorizer="none")

    sys.modules["weaviate"].connect_to_custom.assert_called_once_with(
        http_host="weaviate.example",
        http_port=8443,
        http_secure=True,
        grpc_host="weaviate.example",
        grpc_port=50051,
        grpc_secure=True,
    )


def test_weaviate_remote_url_honors_grpc_overrides(monkeypatch):
    _install_fake_weaviate(monkeypatch)
    monkeypatch.setenv("MAVERICK_WEAVIATE_GRPC_HOST", "grpc.internal")
    monkeypatch.setenv("MAVERICK_WEAVIATE_GRPC_PORT", "60051")
    from maverick.vector_store.weaviate_store import WeaviateStore

    WeaviateStore(url="http://weaviate.internal:8080", vectorizer="none")

    sys.modules["weaviate"].connect_to_custom.assert_called_once_with(
        http_host="weaviate.internal",
        http_port=8080,
        http_secure=False,
        grpc_host="grpc.internal",
        grpc_port=60051,
        grpc_secure=False,
    )


def test_weaviate_uuid_for_is_stable():
    from maverick.vector_store.weaviate_store import _uuid_for
    assert _uuid_for("abc") == _uuid_for("abc")
    assert _uuid_for("abc") != _uuid_for("def")


def test_weaviate_add_batches(monkeypatch):
    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    fake = _install_fake_weaviate(monkeypatch)
    batch_cm = MagicMock()
    batch = MagicMock()
    batch_cm.__enter__.return_value = batch
    fake.collections.get.return_value.batch.dynamic.return_value = batch_cm
    from maverick.vector_store.weaviate_store import WeaviateStore
    store = WeaviateStore()
    store.add(["d1", "d2"], ids=["a", "b"])
    assert batch.add_object.call_count == 2


def test_weaviate_add_empty_noop(monkeypatch):
    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    _install_fake_weaviate(monkeypatch)
    from maverick.vector_store.weaviate_store import WeaviateStore
    store = WeaviateStore()
    store.add([])  # no raise, no batch


def test_weaviate_query_shape(monkeypatch):
    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    fake = _install_fake_weaviate(monkeypatch)
    obj = SimpleNamespace(
        uuid="u1",
        properties={"document": "hello", "src": "t"},
        metadata=SimpleNamespace(distance=0.25),
    )
    fake.collections.get.return_value.query.near_text.return_value = \
        SimpleNamespace(objects=[obj])
    from maverick.vector_store.weaviate_store import WeaviateStore
    out = WeaviateStore().query("hi", top_k=3)
    assert out[0]["document"] == "hello"
    assert out[0]["distance"] == pytest.approx(0.25)
    assert out[0]["score"] == pytest.approx(0.75)
    assert out[0]["metadata"] == {"src": "t"}


def test_weaviate_query_empty_text(monkeypatch):
    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    _install_fake_weaviate(monkeypatch)
    from maverick.vector_store.weaviate_store import WeaviateStore
    assert WeaviateStore().query("") == []


def test_weaviate_count(monkeypatch):
    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    fake = _install_fake_weaviate(monkeypatch)
    fake.collections.get.return_value.aggregate.over_all.return_value = \
        SimpleNamespace(total_count=7)
    from maverick.vector_store.weaviate_store import WeaviateStore
    assert WeaviateStore().count() == 7


def test_semantic_recall_recognizes_weaviate(monkeypatch):
    monkeypatch.setenv("MAVERICK_VECTOR_STORE", "weaviate")
    from maverick import semantic_recall
    assert semantic_recall.backend_name() == "weaviate"


def test_weaviate_reset_single_tenant_drops_whole_collection(monkeypatch):
    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    fake = _install_fake_weaviate(monkeypatch)
    import maverick.vector_store.weaviate_store as ws
    monkeypatch.setattr(ws, "_active_tenant", lambda: None)
    store = ws.WeaviateStore(collection="goals", vectorizer="none")
    fake.collections.delete.reset_mock()
    store.reset()
    # Single-tenant: dropping the whole collection is fine.
    fake.collections.delete.assert_called_once_with("Goals")


def test_weaviate_reset_multitenant_deletes_only_tenant_objects(monkeypatch):
    # A tenant's reset() must NOT drop the shared collection -- that would wipe
    # every OTHER tenant's vectors. It deletes only this tenant's objects.
    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    fake = _install_fake_weaviate(monkeypatch)
    import maverick.vector_store.weaviate_store as ws
    monkeypatch.setattr(ws, "_active_tenant", lambda: "t1")
    marker = object()
    monkeypatch.setattr(ws.WeaviateStore, "_tenant_filter",
                        staticmethod(lambda tenant_id: marker))
    store = ws.WeaviateStore(collection="goals", vectorizer="none")
    fake.collections.delete.reset_mock()
    coll = fake.collections.get.return_value
    coll.data.delete_many.reset_mock()
    store.reset()
    fake.collections.delete.assert_not_called()          # collection preserved
    coll.data.delete_many.assert_called_once_with(where=marker)  # only this tenant


def test_weaviate_remote_operations_publish_unknown_cost_receipts(
    monkeypatch,
    provider_ledger,
):
    fake = _install_fake_weaviate(monkeypatch)
    batch_cm = MagicMock()
    batch_cm.__enter__.return_value = MagicMock()
    collection = fake.collections.get.return_value
    collection.batch.dynamic.return_value = batch_cm
    collection.query.near_text.return_value = SimpleNamespace(objects=[])
    collection.aggregate.over_all.return_value = SimpleNamespace(total_count=2)
    import maverick.vector_store.weaviate_store as ws

    tenant_marker = object()
    monkeypatch.setattr(
        ws.WeaviateStore,
        "_tenant_filter",
        staticmethod(lambda tenant_id: tenant_marker),
    )
    store = ws.WeaviateStore(
        url="https://weaviate.example.test",
        vectorizer="none",
    )
    work_item = "research:WEAVIATE-1"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        store.add([])
        assert store.query("") == []
        store.delete([])
        store.add(["doc"], ids=["doc-1"])
        assert store.query("query") == []
        store.delete(["doc-1"])
        assert store.count() == 2
        store.reset()
        receipts = cap.reservation_catalogue_for_work_item(
            work_item,
            path=provider_ledger,
        ).receipts

    assert len(receipts) == 5
    assert [row.operation["category"] for row in receipts].count("storage") == 1
    assert [row.operation["category"] for row in receipts].count("retrieval") == 2
    assert [row.operation["category"] for row in receipts].count("update") == 2
    assert all(row.provider == "weaviate" for row in receipts)
    assert all(row.state == "unknown" and row.actual is None for row in receipts)
    assert all(row.operation["attempt_state"] == "succeeded" for row in receipts)
    assert all(
        row.operation["service"] == "vector-store:weaviate" for row in receipts
    )


def test_weaviate_remote_count_failure_is_retained(
    monkeypatch,
    provider_ledger,
):
    original = OSError("synthetic weaviate outage")
    fake = _install_fake_weaviate(monkeypatch)
    fake.collections.get.return_value.aggregate.over_all.side_effect = original
    import maverick.vector_store.weaviate_store as ws

    monkeypatch.setattr(
        ws.WeaviateStore,
        "_tenant_filter",
        staticmethod(lambda tenant_id: None),
    )
    store = ws.WeaviateStore(
        url="https://weaviate.example.test",
        vectorizer="none",
    )
    work_item = "research:WEAVIATE-FAIL"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        assert store.count() == 0
        receipt = cap.reservation_catalogue_for_work_item(
            work_item,
            path=provider_ledger,
        ).receipts[0]

    assert receipt.state == "unknown"
    assert receipt.operation["category"] == "retrieval"
    assert receipt.operation["attempt_state"] == "failed"


def test_weaviate_batch_reported_failure_is_retained_and_raised(
    monkeypatch,
    provider_ledger,
):
    fake = _install_fake_weaviate(monkeypatch)
    batch_cm = MagicMock()
    batch_cm.__enter__.return_value = MagicMock()
    collection = fake.collections.get.return_value
    collection.batch.dynamic.return_value = batch_cm
    collection.batch.failed_objects = [object()]
    from maverick.vector_store.weaviate_store import WeaviateStore

    store = WeaviateStore(
        url="https://weaviate.example.test",
        vectorizer="none",
    )
    work_item = "research:WEAVIATE-BATCH-FAIL"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        with pytest.raises(RuntimeError, match="1 failed objects"):
            store.add(["doc"], ids=["doc-1"])
        receipt = cap.reservation_catalogue_for_work_item(
            work_item,
            path=provider_ledger,
        ).receipts[0]

    assert receipt.operation["category"] == "storage"
    assert receipt.operation["attempt_state"] == "failed"


def test_weaviate_partial_delete_failure_is_retained_after_full_sweep(
    monkeypatch,
    provider_ledger,
):
    original = OSError("synthetic weaviate delete outage")
    fake = _install_fake_weaviate(monkeypatch)
    collection = fake.collections.get.return_value
    collection.data.delete_by_id.side_effect = [original, None]
    from maverick.vector_store.weaviate_store import WeaviateStore

    store = WeaviateStore(
        url="https://weaviate.example.test",
        vectorizer="none",
    )
    work_item = "research:WEAVIATE-DELETE-FAIL"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        store.delete(["doc-1", "doc-2"])
        receipt = cap.reservation_catalogue_for_work_item(
            work_item,
            path=provider_ledger,
        ).receipts[0]

    assert collection.data.delete_by_id.call_count == 2
    assert receipt.operation["category"] == "update"
    assert receipt.operation["attempt_state"] == "failed"


def test_weaviate_tenant_reset_reported_failure_is_retained(
    monkeypatch,
    provider_ledger,
):
    fake = _install_fake_weaviate(monkeypatch)
    collection = fake.collections.get.return_value
    collection.data.delete_many.return_value = SimpleNamespace(failed=2)
    import maverick.vector_store.weaviate_store as ws

    monkeypatch.setattr(
        ws.WeaviateStore,
        "_tenant_filter",
        staticmethod(lambda tenant_id: object()),
    )
    store = ws.WeaviateStore(
        url="https://weaviate.example.test",
        vectorizer="none",
    )
    work_item = "research:WEAVIATE-RESET-FAIL"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        store.reset()
        receipt = cap.reservation_catalogue_for_work_item(
            work_item,
            path=provider_ledger,
        ).receipts[0]

    assert receipt.operation["category"] == "update"
    assert receipt.operation["attempt_state"] == "failed"


def test_weaviate_unknown_price_cap_blocks_before_remote_dispatch(
    monkeypatch,
    provider_ledger,
):
    fake = _install_fake_weaviate(monkeypatch)
    from maverick.vector_store.weaviate_store import WeaviateStore

    store = WeaviateStore(
        url="https://weaviate.example.test",
        vectorizer="none",
    )
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"weaviate": 10.0})
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(
        "research:WEAVIATE-CAPPED"
    ):
        with pytest.raises(cap.ProviderAccountingUnavailable):
            store.count()

    fake.collections.get.return_value.aggregate.over_all.assert_not_called()
    assert not provider_ledger.exists()


def test_weaviate_embedded_operations_are_never_metered(
    monkeypatch,
    provider_ledger,
):
    fake = _install_fake_weaviate(monkeypatch)
    batch_cm = MagicMock()
    batch_cm.__enter__.return_value = MagicMock()
    collection = fake.collections.get.return_value
    collection.batch.dynamic.return_value = batch_cm
    collection.query.near_text.return_value = SimpleNamespace(objects=[])
    collection.aggregate.over_all.return_value = SimpleNamespace(total_count=0)
    import maverick.vector_store.weaviate_store as ws

    monkeypatch.delenv("MAVERICK_WEAVIATE_URL", raising=False)
    monkeypatch.setattr(
        ws.WeaviateStore,
        "_tenant_filter",
        staticmethod(lambda tenant_id: object()),
    )
    store = ws.WeaviateStore(vectorizer="none")
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(
        "research:WEAVIATE-EMBEDDED"
    ):
        store.add(["doc"], ids=["doc-1"])
        assert store.query("query") == []
        store.delete(["doc-1"])
        assert store.count() == 0
        store.reset()

    assert not provider_ledger.exists()
