"""Tests for the Qdrant vector store adapter.

qdrant-client is an optional dep; we test both the missing-import path
and the wired-up path with a mock client.
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


def test_qdrant_missing_import_raises(monkeypatch):
    """No qdrant-client installed -> actionable ImportError."""
    monkeypatch.setitem(sys.modules, "qdrant_client", None)
    from maverick.vector_store.qdrant_store import QdrantStore
    with pytest.raises(ImportError, match="qdrant-client not installed"):
        QdrantStore()


def _install_fake_qdrant(monkeypatch) -> MagicMock:
    """Replace ``qdrant_client`` with a stub. Returns the fake client instance."""
    fake_client = MagicMock(name="QdrantClient instance")
    fake_module = MagicMock(name="qdrant_client module")
    fake_module.QdrantClient = MagicMock(return_value=fake_client)
    fake_models = MagicMock(name="qdrant_client.models module")

    class _PointIdsList:
        def __init__(self, points):
            self.points = points

    fake_models.PointIdsList = _PointIdsList
    monkeypatch.setitem(sys.modules, "qdrant_client", fake_module)
    monkeypatch.setitem(sys.modules, "qdrant_client.models", fake_models)
    return fake_client


def test_qdrant_local_path_init(monkeypatch, tmp_path):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)

    from maverick.vector_store.qdrant_store import QdrantStore
    store = QdrantStore(path=tmp_path / "qd")
    assert store is not None
    assert (tmp_path / "qd").exists()
    assert fake_client is not None  # client constructed


def test_qdrant_explicit_legacy_model_failure_does_not_fall_back(monkeypatch, tmp_path):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    fake_client.set_model.side_effect = ValueError("unsupported selected model")
    from maverick.vector_store.qdrant_store import QdrantStore

    with pytest.raises(ValueError, match="unsupported selected model"):
        QdrantStore(path=tmp_path / "qd", embedding_model="synthetic/selected")
    fake_client.set_model.assert_called_once_with("synthetic/selected")
    fake_client.close.assert_called_once()
    fake_client.add.assert_not_called()


def test_qdrant_url_init_skips_path(monkeypatch, tmp_path):
    _install_fake_qdrant(monkeypatch)
    monkeypatch.setenv("MAVERICK_QDRANT_URL", "http://example:6333")
    monkeypatch.setenv("MAVERICK_QDRANT_API_KEY", "secret")
    from maverick.vector_store.qdrant_store import QdrantStore
    # Should not raise -- url path bypasses local dir creation.
    QdrantStore()
    import qdrant_client
    qdrant_client.QdrantClient.assert_called_with(
        url="http://example:6333", api_key="secret",
    )


def test_qdrant_add_autogenerates_ids(monkeypatch, tmp_path):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    from maverick.vector_store.qdrant_store import QdrantStore
    store = QdrantStore(path=tmp_path / "qd")
    store.add(["doc1", "doc2"])
    fake_client.add.assert_called_once()
    kwargs = fake_client.add.call_args.kwargs
    assert kwargs["documents"] == ["doc1", "doc2"]
    assert len(kwargs["ids"]) == 2
    assert all(isinstance(i, str) for i in kwargs["ids"])


def test_qdrant_add_passes_metadata(monkeypatch, tmp_path):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    from maverick.vector_store.qdrant_store import QdrantStore
    store = QdrantStore(path=tmp_path / "qd")
    store.add(["doc"], ids=["x"], metadatas=[{"src": "test"}])
    kwargs = fake_client.add.call_args.kwargs
    # Point ids are deterministic UUIDs (Qdrant rejects arbitrary strings); the
    # caller's logical id rides in the payload under __nsid__.
    from maverick.vector_store.qdrant_store import _point_id
    assert kwargs["ids"] == [_point_id("x", None)]
    assert kwargs["metadata"] == [{"src": "test", "__nsid__": "x"}]


def test_qdrant_add_empty_noop(monkeypatch, tmp_path):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    from maverick.vector_store.qdrant_store import QdrantStore
    store = QdrantStore(path=tmp_path / "qd")
    store.add([])
    fake_client.add.assert_not_called()


def test_qdrant_query_shape(monkeypatch, tmp_path):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    fake_client.query.return_value = [
        SimpleNamespace(id="a", document="doc-a", score=0.9, metadata={"k": 1}),
        SimpleNamespace(id="b", document="doc-b", score=0.4, metadata=None),
    ]
    from maverick.vector_store.qdrant_store import QdrantStore
    store = QdrantStore(path=tmp_path / "qd")
    out = store.query("hello", top_k=2)
    assert len(out) == 2
    assert out[0]["id"] == "a"
    assert out[0]["document"] == "doc-a"
    assert out[0]["distance"] == pytest.approx(0.1, abs=1e-6)
    assert out[1]["metadata"] is None


def test_qdrant_query_empty_text(monkeypatch, tmp_path):
    _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    from maverick.vector_store.qdrant_store import QdrantStore
    store = QdrantStore(path=tmp_path / "qd")
    assert store.query("") == []


def test_qdrant_query_is_tenant_scoped(monkeypatch, tmp_path):
    """A query under tenant t1 must NOT return tenant t2's vectors, and must
    return t1's ids stripped of the namespace prefix."""
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    import maverick.vector_store.qdrant_store as qs
    monkeypatch.setattr(qs, "_active_tenant", lambda: "t1")
    fake_client.query.return_value = [
        SimpleNamespace(id="tenant:t2:secret", document="OTHER-TENANT", score=0.99, metadata=None),
        SimpleNamespace(id="tenant:t1:doc1", document="mine", score=0.8, metadata={"k": 1}),
        SimpleNamespace(id="tenant:t2:secret2", document="OTHER-TENANT-2", score=0.7, metadata=None),
    ]
    store = qs.QdrantStore(path=tmp_path / "qd")
    out = store.query("hello", top_k=5)
    assert [r["id"] for r in out] == ["doc1"]  # only t1's, prefix stripped
    assert all("OTHER-TENANT" not in r["document"] for r in out)


def test_qdrant_delete(monkeypatch, tmp_path):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    from maverick.vector_store.qdrant_store import QdrantStore
    store = QdrantStore(path=tmp_path / "qd")
    store.delete(["a", "b"])
    fake_client.delete.assert_called_once()
    # PointIdsList stub carries the points list -- deterministic UUIDs, not the
    # raw ids (Qdrant only accepts uint/UUID point ids).
    from maverick.vector_store.qdrant_store import _point_id
    kwargs = fake_client.delete.call_args.kwargs
    assert kwargs["collection_name"] == "maverick"
    assert kwargs["points_selector"].points == [_point_id("a", None), _point_id("b", None)]


def test_qdrant_count(monkeypatch, tmp_path):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    fake_client.count.return_value = SimpleNamespace(count=42)
    from maverick.vector_store.qdrant_store import QdrantStore
    store = QdrantStore(path=tmp_path / "qd")
    assert store.count() == 42


def test_qdrant_count_swallows_errors(monkeypatch, tmp_path):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    fake_client.count.side_effect = RuntimeError("no collection")
    from maverick.vector_store.qdrant_store import QdrantStore
    store = QdrantStore(path=tmp_path / "qd")
    assert store.count() == 0


def test_qdrant_remote_operations_publish_unknown_cost_receipts(
    monkeypatch,
    provider_ledger,
):
    fake_client = _install_fake_qdrant(monkeypatch)
    fake_client.query.return_value = []
    fake_client.count.return_value = SimpleNamespace(count=2)
    from maverick.vector_store.qdrant_store import QdrantStore

    store = QdrantStore(url="https://qdrant.example.test", api_key="synthetic")
    work_item = "research:QDRANT-1"
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
    assert all(row.provider == "qdrant" for row in receipts)
    assert all(row.state == "unknown" and row.actual is None for row in receipts)
    assert all(row.operation["attempt_state"] == "succeeded" for row in receipts)
    assert all(
        row.operation["service"] == "vector-store:qdrant" for row in receipts
    )


def test_qdrant_remote_count_failure_is_retained(
    monkeypatch,
    provider_ledger,
):
    original = OSError("synthetic qdrant outage")
    fake_client = _install_fake_qdrant(monkeypatch)
    fake_client.count.side_effect = original
    from maverick.vector_store.qdrant_store import QdrantStore

    store = QdrantStore(url="https://qdrant.example.test")
    work_item = "research:QDRANT-FAIL"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        assert store.count() == 0
        receipt = cap.reservation_catalogue_for_work_item(
            work_item,
            path=provider_ledger,
        ).receipts[0]

    assert receipt.state == "unknown"
    assert receipt.operation["category"] == "retrieval"
    assert receipt.operation["attempt_state"] == "failed"


def test_qdrant_remote_reset_failure_is_retained_after_recreate_attempt(
    monkeypatch,
    provider_ledger,
):
    original = OSError("synthetic qdrant delete outage")
    fake_client = _install_fake_qdrant(monkeypatch)
    fake_client.delete_collection.side_effect = original
    from maverick.vector_store.qdrant_store import QdrantStore

    store = QdrantStore(url="https://qdrant.example.test")
    work_item = "research:QDRANT-RESET-FAIL"
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(work_item):
        store.reset()
        receipt = cap.reservation_catalogue_for_work_item(
            work_item,
            path=provider_ledger,
        ).receipts[0]

    fake_client.create_collection.assert_called_once()
    assert receipt.operation["category"] == "update"
    assert receipt.operation["attempt_state"] == "failed"


def test_qdrant_best_effort_count_does_not_hide_accounting_failure(
    monkeypatch,
):
    fake_client = _install_fake_qdrant(monkeypatch)
    import maverick.vector_store.qdrant_store as qs

    store = qs.QdrantStore(url="https://qdrant.example.test")
    accounting_error = cap.ProviderAccountingUnavailable()
    monkeypatch.setattr(
        qs,
        "metered_transport_call",
        MagicMock(side_effect=accounting_error),
    )

    with pytest.raises(cap.ProviderAccountingUnavailable) as captured:
        store.count()

    assert captured.value is accounting_error
    fake_client.count.assert_not_called()


def test_qdrant_unknown_price_cap_blocks_before_remote_dispatch(
    monkeypatch,
    provider_ledger,
):
    fake_client = _install_fake_qdrant(monkeypatch)
    from maverick.vector_store.qdrant_store import QdrantStore

    store = QdrantStore(url="https://qdrant.example.test")
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"qdrant": 10.0})
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(
        "research:QDRANT-CAPPED"
    ):
        with pytest.raises(cap.ProviderAccountingUnavailable):
            store.count()

    fake_client.count.assert_not_called()
    assert not provider_ledger.exists()


def test_qdrant_unknown_price_cap_blocks_before_remote_connect(
    monkeypatch,
    provider_ledger,
):
    _install_fake_qdrant(monkeypatch)
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"qdrant": 10.0})
    from maverick.vector_store.qdrant_store import QdrantStore

    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(
        "research:QDRANT-CONNECT-CAPPED"
    ):
        with pytest.raises(cap.ProviderAccountingUnavailable):
            QdrantStore(url="https://qdrant.example.test")

    import qdrant_client

    qdrant_client.QdrantClient.assert_not_called()
    assert not provider_ledger.exists()


def test_qdrant_local_operations_are_never_metered(
    monkeypatch,
    tmp_path,
    provider_ledger,
):
    fake_client = _install_fake_qdrant(monkeypatch)
    monkeypatch.delenv("MAVERICK_QDRANT_URL", raising=False)
    fake_client.query.return_value = []
    fake_client.count.return_value = SimpleNamespace(count=0)
    from maverick.vector_store.qdrant_store import QdrantStore

    store = QdrantStore(path=tmp_path / "qd")
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope(
        "research:QDRANT-LOCAL"
    ):
        store.add(["doc"], ids=["doc-1"])
        assert store.query("query") == []
        store.delete(["doc-1"])
        assert store.count() == 0
        store.reset()

    assert not provider_ledger.exists()


def test_vector_transport_accounting_bridge_preserves_core_only_install(
    monkeypatch,
):
    monkeypatch.delitem(
        sys.modules,
        "maverick_knowledge.provider_accounting",
        raising=False,
    )
    monkeypatch.setitem(sys.modules, "maverick_knowledge", None)
    from maverick.vector_store._provider_accounting import metered_transport_call

    assert metered_transport_call(
        "qdrant",
        lambda: 7,
        category="retrieval",
    ) == 7
