"""Hosted knowledge calls publish work-bound provider cost receipts."""
from __future__ import annotations

import sys
import types

import pytest
from maverick import provider_cost_cap as cap
from maverick.paths import tenant_scope
from maverick_knowledge import provider_accounting
from maverick_knowledge.base import KnowledgeBase
from maverick_knowledge.embed import DeterministicEmbedder, HostedEmbedder
from maverick_knowledge.store import SqliteVectorStore


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    path = tmp_path / "provider-spend.json"
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "_ledger_path", lambda: path)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-08")
    return path


class _Store(SqliteVectorStore):
    """Use the actual identity-capable store under transport-only fixtures."""


def _httpx(monkeypatch, *, error: BaseException | None = None):
    class Response:
        def raise_for_status(self):
            if error is not None:
                raise error

        def json(self):
            return {"data": [{"index": 0, "embedding": [1.0, 0.0]}]}

    monkeypatch.setitem(
        sys.modules,
        "httpx",
        types.SimpleNamespace(post=lambda *_args, **_kwargs: Response()),
    )


def test_query_embedding_is_retrieval_and_unpriced_success_is_visible(
    ledger,
    monkeypatch,
):
    _httpx(monkeypatch)
    embedder = HostedEmbedder(
        model="voyage-3",
        base_url="https://api.voyageai.com/v1",
        api_key="synthetic",  # pragma: allowlist secret
        dim=2,
    )
    kb = KnowledgeBase(store=_Store(), embedder=embedder)

    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope("research:RUN-1"):
        assert kb.search("documents", "query") == []
        receipt = cap.reservation_catalogue_for_work_item(
            "research:RUN-1",
            path=ledger,
        ).receipts[0]

    assert receipt.provider == "voyage"
    assert receipt.state == "unknown" and receipt.actual is None
    assert receipt.operation["category"] == "retrieval"
    assert receipt.operation["parent_category"] == "retrieval"
    assert receipt.operation["attempt_state"] == "succeeded"
    assert receipt.operation["service"] == "embeddings:voyage-3"


def test_document_embedding_is_storage_work(ledger, monkeypatch):
    _httpx(monkeypatch)
    kb = KnowledgeBase(
        store=_Store(),
        embedder=HostedEmbedder(
            model="voyage-3",
            base_url="https://api.voyageai.com/v1",
            api_key="synthetic",  # pragma: allowlist secret
            dim=2,
        ),
    )

    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope("research:RUN-2"):
        assert kb.ingest_text("documents", "stored content") == 1
        receipt = cap.reservation_catalogue_for_work_item(
            "research:RUN-2",
            path=ledger,
        ).receipts[0]

    assert receipt.operation["category"] == "storage"
    assert receipt.operation["attempt_state"] == "succeeded"


def test_hosted_embedding_failure_is_retained_before_original_error(
    ledger,
    monkeypatch,
):
    original = OSError("hosted embedding failed")
    _httpx(monkeypatch, error=original)
    embedder = HostedEmbedder(
        model="custom-model",
        base_url="https://embeddings.example.test/v1",
        api_key="synthetic",  # pragma: allowlist secret
        dim=2,
    )

    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope("research:RUN-3"):
        with pytest.raises(OSError) as captured:
            embedder.embed(["query"])
        receipt = cap.reservation_catalogue_for_work_item(
            "research:RUN-3",
            path=ledger,
        ).receipts[0]

    assert captured.value is original
    assert receipt.provider == "embeddings.example.test"
    assert receipt.state == "unknown"
    assert receipt.operation["category"] == "other"
    assert receipt.operation["attempt_state"] == "failed"


def test_local_embedding_never_creates_a_provider_receipt(ledger):
    kb = KnowledgeBase(store=_Store(), embedder=DeterministicEmbedder(dim=8))
    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope("research:RUN-4"):
        assert kb.search("documents", "local query") == []
    assert not ledger.exists()


def test_hosted_embedding_with_unknown_price_is_blocked_before_capped_http(
    ledger,
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"voyage": 1.0})

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"data": [{"index": 0, "embedding": [1.0, 0.0]}]}

    monkeypatch.setitem(
        sys.modules,
        "httpx",
        types.SimpleNamespace(
            post=lambda *_args, **_kwargs: calls.append("http") or Response(),
        ),
    )
    embedder = HostedEmbedder(
        model="voyage-3",
        base_url="https://api.voyageai.com/v1",
        api_key="synthetic",  # pragma: allowlist secret
        dim=2,
    )

    with tenant_scope(tenant="knowledge-tenant"), cap.work_item_scope("research:RUN-cap"):
        with pytest.raises(cap.ProviderAccountingUnavailable):
            embedder.embed(["query"])

    assert calls == []
    assert not ledger.exists()


def test_optional_bridge_ignores_an_older_maverick_without_accounting_api(monkeypatch):
    older = types.SimpleNamespace(provider_operation_scope=lambda **_kwargs: None)
    original = provider_accounting.importlib.import_module
    monkeypatch.setattr(
        provider_accounting.importlib,
        "import_module",
        lambda name: older if name == "maverick.provider_cost_cap" else original(name),
    )
    calls = []

    assert provider_accounting.metered_call(
        "fixture",
        lambda: calls.append("called") or "ok",
        service="fixture",
    ) == "ok"
    assert calls == ["called"]
