"""Physical web-search provider attempts and their durable cost attribution."""
from __future__ import annotations

import pytest
from maverick import provider_cost_cap as cap
from maverick.budget import Budget
from maverick.paths import tenant_scope
from maverick.tools import _paid_call as paid_call
from maverick.tools import web_search as search


class _Response:
    def __init__(self, *, data=None, text=""):
        self._data = {} if data is None else data
        self.text = text

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


def _all_backends(monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tavily-key")
    monkeypatch.setenv("BRAVE_API_KEY", "brave-key")
    monkeypatch.setenv("SERPAPI_API_KEY", "serpapi-key")
    monkeypatch.delenv("MAVERICK_SEARCH_BACKEND", raising=False)
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)


def test_every_physical_failover_dispatch_is_metered_under_one_operation(monkeypatch):
    import httpx

    _all_backends(monkeypatch)
    attempts = []

    def meter(provider, callback, **metadata):
        attempts.append((provider, metadata))
        return callback()

    def post(*_args, **_kwargs):
        raise OSError("tavily transport failed")

    def get(url, *_args, **_kwargs):
        if "brave" in url:
            raise OSError("brave transport failed")
        if "serpapi" in url:
            return _Response(data={"organic_results": []})
        return _Response(text=(
            '<a class="result__a" href="/l/?uddg=https%3A%2F%2Fexample.com">hit</a>'
            '<a class="result__snippet">snippet</a>'
        ))

    monkeypatch.setattr(search, "metered_provider_call", meter)
    monkeypatch.setattr(paid_call, "metered_provider_call", meter)
    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(httpx, "get", get)

    result = search._run_search({"query": "governed evidence"}, Budget())

    assert "[backend: ddg]" in result
    assert [provider for provider, _ in attempts] == [
        "tavily", "brave", "serpapi", "duckduckgo",
    ]
    operation_ids = {metadata["operation_id"] for _, metadata in attempts}
    assert len(operation_ids) == 1
    assert next(iter(operation_ids)).startswith("web-search:")
    assert [metadata["attempt_no"] for _, metadata in attempts] == [1, 2, 3, 4]
    assert [metadata["category"] for _, metadata in attempts] == [
        "search", "retry", "retry", "retry",
    ]
    assert all(metadata["parent_category"] == "search" for _, metadata in attempts)
    assert [metadata["service"] for _, metadata in attempts] == [
        "tavily", "brave", "serpapi", "duckduckgo",
    ]
    assert all("work_item_id" not in metadata for _, metadata in attempts)


@pytest.mark.parametrize("kind", ["unavailable", "cap"])
def test_accounting_refusal_stops_failover_before_an_unmetered_retry(monkeypatch, kind):
    import httpx

    _all_backends(monkeypatch)
    calls = []
    error = (
        cap.ProviderAccountingUnavailable()
        if kind == "unavailable"
        else cap.ProviderCapExceeded("tavily", 1.0, 1.0, "2026-09-08")
    )

    def refuse(provider, _callback, **_metadata):
        calls.append(provider)
        raise error

    monkeypatch.setattr(search, "metered_provider_call", refuse)
    monkeypatch.setattr(paid_call, "metered_provider_call", refuse)
    monkeypatch.setattr(
        httpx, "post", lambda *_args, **_kwargs: pytest.fail("dispatch must be blocked"))
    monkeypatch.setattr(
        httpx, "get", lambda *_args, **_kwargs: pytest.fail("failover must stop"))

    with pytest.raises(type(error)) as captured:
        search._run_search({"query": "accounted search"}, Budget())

    assert captured.value is error
    assert calls == ["tavily"]


def test_receipt_is_discoverable_only_under_an_existing_work_item(monkeypatch, tmp_path):
    import httpx

    ledger = tmp_path / "provider-spend.json"
    monkeypatch.setenv("TAVILY_API_KEY", "tavily-key")
    monkeypatch.setenv("MAVERICK_SEARCH_BACKEND", "tavily")
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(
        cap, "period_key", lambda now=None, period=None: "2026-09-08")
    monkeypatch.setattr(httpx, "post", lambda *_args, **_kwargs: _Response(data={
        "results": [{
            "title": "result", "url": "https://example.com", "content": "hit",
        }],
    }))

    work_item = "research:search-run-17"
    with tenant_scope(tenant="workspace-one"):
        with cap.work_item_scope(work_item):
            assert "[backend: tavily]" in search._run_search({"query": "first"}, Budget())
        # The adapter must inherit an existing work item, never invent one.
        assert "[backend: tavily]" in search._run_search({"query": "second"}, Budget())
        receipts = cap.reservation_catalogue_for_work_item(
            work_item, path=ledger,
        ).receipts

    assert len(receipts) == 1
    receipt = receipts[0]
    # A paid search is charged to the run budget (the per-call safety ceiling
    # with no price set), so its receipt is settled with that charge.
    assert receipt.state == "settled" and receipt.actual == pytest.approx(0.10)
    assert receipt.operation is not None
    assert receipt.operation["operation_id"].startswith("web-search:")
    assert receipt.operation["category"] == "search"
    assert receipt.operation["parent_category"] == "search"
    assert receipt.operation["attempt_no"] == 1
    assert receipt.operation["service"] == "tavily"
    assert receipt.operation["attempt_state"] == "succeeded"


def test_accounted_provider_failure_falls_through_with_both_receipts(monkeypatch, tmp_path):
    import httpx

    ledger = tmp_path / "provider-spend.json"
    monkeypatch.setenv("TAVILY_API_KEY", "tavily-key")
    monkeypatch.setenv("BRAVE_API_KEY", "brave-key")
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_SEARCH_BACKEND", raising=False)
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(
        cap, "period_key", lambda now=None, period=None: "2026-09-08")
    monkeypatch.setattr(
        httpx, "post", lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("tavily transport failed")))
    monkeypatch.setattr(httpx, "get", lambda *_args, **_kwargs: _Response(data={
        "web": {"results": [{
            "title": "brave result", "url": "https://example.com",
            "description": "hit",
        }]},
    }))

    work_item = "research:search-failover-18"
    with tenant_scope(tenant="workspace-one"), cap.work_item_scope(work_item):
        assert "[backend: brave]" in search._run_search({"query": "fallback"}, Budget())
        receipts = cap.reservation_catalogue_for_work_item(
            work_item, path=ledger,
        ).receipts

    assert len(receipts) == 2
    by_provider = {receipt.provider: receipt for receipt in receipts}
    tavily = by_provider["tavily"].operation
    brave = by_provider["brave"].operation
    assert tavily is not None and brave is not None
    assert tavily["operation_id"] == brave["operation_id"]
    assert tavily["category"] == "search" and tavily["attempt_no"] == 1
    assert tavily["attempt_state"] == "failed" and tavily["service"] == "tavily"
    assert brave["category"] == "retry" and brave["attempt_no"] == 2
    assert brave["attempt_state"] == "succeeded" and brave["service"] == "brave"
    assert tavily["parent_category"] == brave["parent_category"] == "search"


def test_paid_search_is_charged_to_the_run_and_duckduckgo_is_not(monkeypatch):
    # A Tavily search is charged to the run budget (the per-call safety
    # ceiling with no price set); without a run budget it is refused before
    # sending. DuckDuckGo is free.
    import httpx

    monkeypatch.setenv("TAVILY_API_KEY", "tavily-key")
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)
    posts = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: posts.append(a) or _Response(data={
        "results": [{"title": "t", "url": "https://example.com", "content": "hit"}]}))
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _Response(text=(
        '<a class="result__a" href="/l/?uddg=https%3A%2F%2Fexample.com">hit</a>'
        '<a class="result__snippet">snippet</a>')))
    budget = Budget()
    monkeypatch.setenv("MAVERICK_SEARCH_BACKEND", "tavily")
    assert "[backend: tavily]" in search._run_search({"query": "q"}, budget)
    assert budget.dollars == pytest.approx(0.10) and len(posts) == 1
    out = search._run_search({"query": "q"})
    assert out.startswith("ERROR") and "nothing was sent" in out and len(posts) == 1
    monkeypatch.setenv("MAVERICK_SEARCH_BACKEND", "ddg")
    assert "[backend: ddg]" in search._run_search({"query": "q"}, budget)
    assert budget.dollars == pytest.approx(0.10)
