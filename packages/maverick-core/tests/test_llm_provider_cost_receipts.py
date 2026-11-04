"""Provider-cap settlement receipts on physical LLM call results."""
from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from dataclasses import asdict
from types import SimpleNamespace

import pytest
from maverick import llm as llm_mod
from maverick import provider_cost_cap as cap
from maverick.llm import LLM, LLMResponse
from maverick.logging_config import reset_goal_context, set_goal_context
from maverick.paths import tenant_scope


def _response(text: str = "synthetic") -> LLMResponse:
    return LLMResponse(
        text=text,
        thinking=None,
        tool_calls=[],
        stop_reason="end_turn",
        raw=SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=1, completion_tokens=0),
        ),
    )


@contextmanager
def _bound_work():
    with tenant_scope(tenant="receipt-tenant"):
        tokens = set_goal_context(goal_id=42)
        try:
            yield
        finally:
            reset_goal_context(tokens)


@pytest.fixture
def dispatcher(tmp_path, monkeypatch):
    ledger = tmp_path / "provider_spend.json"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"openai": 25.0})
    monkeypatch.setattr(cap, "period_from_config", lambda: "day")
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(
        cap,
        "period_key",
        lambda now=None, period=None: "2026-09-08",
    )
    monkeypatch.setattr(llm_mod, "_estimate_call_cost", lambda *a, **kw: 2.0)
    # Receipt mechanics use a synthetic model with no real rate-card entry.
    monkeypatch.setattr(llm_mod, "_lookup_price_quote", lambda _spec: None)
    monkeypatch.setattr(llm_mod, "_run_preflight", lambda *a, **kw: None)
    monkeypatch.setattr(llm_mod, "_enforce_circuit", lambda *a: None)
    monkeypatch.setattr(llm_mod, "_feed_circuit", lambda *a: None)
    monkeypatch.setattr(llm_mod, "_hedge_ms", lambda: None)
    monkeypatch.setattr(llm_mod, "require_model_allowed", lambda spec: spec)
    monkeypatch.setattr(
        "maverick.budget._lookup_price",
        lambda _model, **_kw: (1_000_000, 0),
    )
    # Attempt prices now come from the quote itself; keep its provenance
    # (an estimate for this synthetic model) and only fix the synthetic rate.
    from dataclasses import replace as _replace

    from maverick import budget as _budget
    _real_quote = _budget._lookup_price_quote
    monkeypatch.setattr(_budget, "_lookup_price_quote", lambda model, **kw: _replace(
        _real_quote(model, **kw), input_per_mtok=1_000_000, output_per_mtok=0))
    return LLM(model="openai:synthetic-receipt-model"), ledger


def _capture_settlements(monkeypatch):
    snapshots = []
    real_settle = cap.settle

    def settle(hold, actual, **metadata):
        snapshot = real_settle(hold, actual, **metadata)
        snapshots.append(snapshot)
        return snapshot

    monkeypatch.setattr(cap, "settle", settle)
    return snapshots


def _assert_json_receipt(response, snapshot):
    expected = asdict(snapshot)
    assert response.provider_cost_receipt == expected
    assert json.loads(json.dumps(response.provider_cost_receipt, allow_nan=False)) == expected


def test_sync_call_exposes_exact_work_bound_settlement(dispatcher, monkeypatch):
    llm, ledger = dispatcher
    snapshots = _capture_settlements(monkeypatch)

    class Client:
        def complete(self, **_kwargs):
            return _response()

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())
    assert _response("legacy").provider_cost_receipt is None

    with _bound_work():
        response = llm.complete("system", [])
        assert len(snapshots) == 1
        snapshot = snapshots[0]
        _assert_json_receipt(response, snapshot)
        assert snapshot.state == "settled" and snapshot.actual == 1
        assert snapshot.operation == {
            "operation_id": snapshot.operation["operation_id"],
            "category": "inference",
            "parent_category": "inference",
            "attempt_no": 1,
            "service": "openai:synthetic-receipt-model",
            "attempt_state": "succeeded",
        }
        assert cap.inspect_reservation(
            snapshot.reference,
            expected_work_item_id="goal:42",
            path=ledger,
        ) == snapshot


def test_async_call_exposes_exact_work_bound_settlement(dispatcher, monkeypatch):
    llm, ledger = dispatcher
    snapshots = _capture_settlements(monkeypatch)

    class Client:
        async def complete_async(self, **_kwargs):
            return _response()

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())

    with _bound_work():
        response = asyncio.run(llm.complete_async("system", []))
        assert len(snapshots) == 1
        snapshot = snapshots[0]
        _assert_json_receipt(response, snapshot)
        assert snapshot.operation["category"] == "inference"
        assert snapshot.operation["attempt_no"] == 1
        assert snapshot.operation["attempt_state"] == "succeeded"
        assert cap.inspect_reservation(
            snapshot.reference,
            expected_work_item_id="goal:42",
            path=ledger,
        ) == snapshot


def test_explicit_work_item_scope_overrides_goal_and_restores_it(dispatcher, monkeypatch):
    llm, ledger = dispatcher

    class Client:
        def complete(self, **_kwargs):
            return _response()

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())
    with _bound_work():
        with cap.work_item_scope("vendor:VON-explicit"):
            llm.complete("system", [])
        llm.complete("system", [])
        vendor = cap.reservations_for_work_item(
            "vendor:VON-explicit", path=ledger,
        )
        goal = cap.reservations_for_work_item("goal:42", path=ledger)

    assert len(vendor.receipts) == 1
    assert len(goal.receipts) == 1
    assert vendor.receipts[0].reference != goal.receipts[0].reference


def test_explicit_operation_scope_attributes_the_logical_llm_call(
    dispatcher,
    monkeypatch,
):
    llm, ledger = dispatcher

    class Client:
        def complete(self, **_kwargs):
            return _response()

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())
    with _bound_work(), cap.provider_operation_scope(
        operation_id="self-harness-judge-EVAL-42",
        category="evaluation",
        service="self-harness-judge",
    ):
        llm.complete("system", [])
        receipt = cap.reservation_catalogue_for_work_item(
            "goal:42",
            path=ledger,
        ).receipts[0]

    assert receipt.operation == {
        "operation_id": "self-harness-judge-EVAL-42",
        "category": "evaluation",
        "parent_category": "evaluation",
        "attempt_no": 1,
        "service": "self-harness-judge",
        "attempt_state": "succeeded",
    }


@pytest.mark.parametrize("identity", ["", " padded", "line\nbreak", "x" * 513])
def test_explicit_work_item_scope_rejects_ambiguous_identities(identity):
    with pytest.raises(cap.ProviderAccountingUnavailable):
        with cap.work_item_scope(identity):
            raise AssertionError("invalid scope became active")


def test_hedge_winner_exposes_its_receipt_and_cancelled_call_stays_durable(
    dispatcher,
    monkeypatch,
):
    llm, ledger = dispatcher
    snapshots = _capture_settlements(monkeypatch)
    monkeypatch.setattr(llm_mod, "_hedge_ms", lambda: 1)

    class Client:
        calls = 0

        async def complete_async(self, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                await asyncio.sleep(5)
                return _response("primary")
            return _response("backup")

    client = Client()
    monkeypatch.setattr(llm, "_get_client", lambda _provider: client)

    with _bound_work():
        response = asyncio.run(llm.complete_async("system", []))
        assert response.text == "backup" and client.calls == 2
        assert len(snapshots) == 2
        settled = next(row for row in snapshots if row.state == "settled")
        cancelled = next(row for row in snapshots if row.state == "unknown")
        _assert_json_receipt(response, settled)
        assert cancelled.actual is None
        assert cap.inspect_reservation(
            cancelled.reference,
            expected_work_item_id="goal:42",
            path=ledger,
        ) == cancelled

    assert settled.operation["operation_id"] == cancelled.operation["operation_id"]
    assert settled.operation["attempt_no"] == 2
    assert settled.operation["category"] == "retry"
    assert settled.operation["parent_category"] == "inference"
    assert settled.operation["attempt_state"] == "succeeded"
    assert cancelled.operation["attempt_no"] == 1
    assert cancelled.operation["category"] == "inference"
    assert cancelled.operation["attempt_state"] == "cancelled"

    status = cap.check("openai", path=ledger)
    assert status.spent == 1 and status.reserved == 2 and status.unresolved


def test_failed_physical_call_retains_unknown_ledger_receipt(dispatcher, monkeypatch):
    llm, ledger = dispatcher
    snapshots = _capture_settlements(monkeypatch)

    class Client:
        async def complete_async(self, **_kwargs):
            raise RuntimeError("provider failed after dispatch")

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())

    with _bound_work(), pytest.raises(RuntimeError, match="after dispatch"):
        asyncio.run(llm.complete_async("system", []))

    assert len(snapshots) == 1 and snapshots[0].state == "unknown"
    assert snapshots[0].operation["attempt_state"] == "failed"
    status = cap.check("openai", path=ledger)
    assert status.spent == 0 and status.reserved == 2 and status.unresolved


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_settlement_publication_failure_never_retries_incurred_call(
    dispatcher,
    monkeypatch,
    asynchronous,
):
    llm, ledger = dispatcher
    calls = []
    monkeypatch.setattr(
        llm_mod,
        "_fallback_chain_for_dispatch",
        lambda _raw, _requested: ["openai:synthetic-backup"],
    )
    monkeypatch.setattr(
        "maverick.failover_policy.order_chain",
        lambda models: list(models),
    )

    def unavailable(_hold, _actual):
        raise cap.ProviderAccountingUnavailable("synthetic publication failure")

    monkeypatch.setattr(cap, "settle", unavailable)

    class Client:
        def complete(self, **kwargs):
            calls.append(kwargs["model"])
            return _response()

        async def complete_async(self, **kwargs):
            calls.append(kwargs["model"])
            return _response()

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())

    with _bound_work():
        if asynchronous:
            response = asyncio.run(llm.complete_async("system", []))
        else:
            response = llm.complete("system", [])

    assert response.text == "synthetic"
    assert response.provider_cost_receipt is None
    assert calls == ["synthetic-receipt-model"]
    status = cap.check("openai", path=ledger)
    assert status.spent == 0 and status.reserved == 2


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_failed_attempt_accounting_failure_is_terminal_across_failover(
    dispatcher,
    monkeypatch,
    asynchronous,
):
    llm, ledger = dispatcher
    calls = []
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(
        llm_mod,
        "_fallback_chain_for_dispatch",
        lambda _raw, _requested: ["openai:synthetic-backup"],
    )
    monkeypatch.setattr(
        "maverick.failover_policy.order_chain",
        lambda models: list(models),
    )
    monkeypatch.setattr(
        cap,
        "settle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("authority offline")),
    )

    class Client:
        def complete(self, **kwargs):
            calls.append(kwargs["model"])
            if kwargs["model"] == "synthetic-receipt-model":
                raise RuntimeError("provider failed after dispatch")
            return _response("backup must not run")

        async def complete_async(self, **kwargs):
            return self.complete(**kwargs)

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())

    with _bound_work(), pytest.raises(cap.ProviderAccountingUnavailable):
        if asynchronous:
            asyncio.run(llm.complete_async("system", []))
        else:
            llm.complete("system", [])

    assert calls == ["synthetic-receipt-model"]
    status = cap.check("openai", path=ledger)
    assert status.spent == 0 and status.reserved == 2


def test_work_item_receipt_discovery_is_paginated_and_tenant_bound(
    dispatcher,
):
    _llm, ledger = dispatcher
    with tenant_scope(tenant="receipt-tenant"):
        for index in range(3):
            hold = cap.reserve(
                "openai",
                2,
                path=ledger,
                request_id=f"local-{index}",
                work_item_id="goal:42",
            )
            cap.settle(hold, index + 1)
        page_one = cap.reservations_for_work_item(
            "goal:42",
            path=ledger,
            limit=2,
        )
        page_two = cap.reservations_for_work_item(
            "goal:42",
            path=ledger,
            limit=2,
            cursor=page_one.next_cursor,
        )

    assert [row.request_id for row in page_one.receipts] == ["local-0", "local-1"]
    assert page_one.next_cursor == page_one.receipts[-1].reference
    assert [row.request_id for row in page_two.receipts] == ["local-2"]
    assert page_two.next_cursor is None
    with tenant_scope(tenant="different-tenant"):
        assert cap.reservations_for_work_item(
            "goal:42",
            path=ledger,
        ).receipts == ()
    with tenant_scope(tenant="receipt-tenant"), pytest.raises(
        cap.ProviderAccountingUnavailable,
    ):
        cap.reservations_for_work_item("goal:42", path=ledger, limit=201)


def test_shared_world_receipt_discovery_uses_the_same_bounded_authority(
    dispatcher,
    tmp_path,
    monkeypatch,
):
    from maverick.world_model import WorldModel

    _llm, local_ledger = dispatcher
    shared = WorldModel(tmp_path / "shared-world.db")
    monkeypatch.setattr(cap, "_shared_world", lambda: shared)
    try:
        with tenant_scope(tenant="receipt-tenant"):
            for index in range(3):
                hold = cap.reserve(
                    "openai",
                    2,
                    request_id=f"shared-{index}",
                    work_item_id="goal:42",
                )
                cap.settle(hold, 1)
            page_one = cap.reservations_for_work_item("goal:42", limit=2)
            page_two = cap.reservations_for_work_item(
                "goal:42",
                limit=2,
                cursor=page_one.next_cursor,
            )
        assert [row.request_id for row in page_one.receipts] == [
            "shared-0",
            "shared-1",
        ]
        assert [row.request_id for row in page_two.receipts] == ["shared-2"]
        with tenant_scope(tenant="different-tenant"):
            assert cap.reservations_for_work_item("goal:42").receipts == ()
        assert not local_ledger.exists()
    finally:
        shared.close()


def test_completeness_catalogue_cannot_miss_an_insert_before_a_page_cursor(
    dispatcher,
):
    _llm, ledger = dispatcher
    with tenant_scope(tenant="receipt-tenant"):
        for request_id in ("page-b", "page-c"):
            hold = cap.reserve(
                "openai", 2, path=ledger, request_id=request_id,
                work_item_id="goal:42",
            )
            cap.settle(hold, 1)
        page_one = cap.reservations_for_work_item(
            "goal:42", path=ledger, limit=1,
        )
        inserted = cap.reserve(
            "openai", 2, path=ledger, request_id="page-a",
            work_item_id="goal:42",
        )
        cap.settle(inserted, 1)
        page_two = cap.reservations_for_work_item(
            "goal:42", path=ledger, limit=2, cursor=page_one.next_cursor,
        )
        catalogue = cap.reservation_catalogue_for_work_item(
            "goal:42", path=ledger,
        )

    assert [row.request_id for row in page_one.receipts + page_two.receipts] == [
        "page-b", "page-c",
    ]
    assert [row.request_id for row in catalogue.receipts] == [
        "page-a", "page-b", "page-c",
    ]
    assert len(catalogue.version) == 64


def test_completeness_catalogue_is_bounded_and_claim_stable(dispatcher):
    _llm, ledger = dispatcher
    with tenant_scope(tenant="receipt-tenant"):
        holds = [cap.reserve(
            "openai", 2, path=ledger, request_id=f"catalogue-{index}",
            work_item_id="goal:42",
        ) for index in range(3)]
        for held in holds:
            cap.settle(held, 1)
        before = cap.reservation_catalogue_for_work_item("goal:42", path=ledger)
        cap.claim_reservation(
            before.receipts[0].reference,
            expected_work_item_id="goal:42",
            claim_id="COST-catalogue",
            path=ledger,
        )
        after = cap.reservation_catalogue_for_work_item("goal:42", path=ledger)
        with pytest.raises(cap.ProviderAccountingUnavailable):
            cap.reservation_catalogue_for_work_item(
                "goal:42", path=ledger, limit=2,
            )

    assert before.version == after.version
    assert before.receipts[0].outcome_claim is None
    assert after.receipts[0].outcome_claim == "COST-catalogue"


def test_shared_completeness_catalogue_uses_one_database_snapshot(
    dispatcher,
    tmp_path,
    monkeypatch,
):
    from maverick.world_model import WorldModel

    _llm, local_ledger = dispatcher
    shared = WorldModel(tmp_path / "catalogue-world.db")
    monkeypatch.setattr(cap, "_shared_world", lambda: shared)
    try:
        with tenant_scope(tenant="receipt-tenant"):
            for request_id in ("shared-a", "shared-b"):
                hold = cap.reserve(
                    "openai", 2, request_id=request_id,
                    work_item_id="goal:42",
                )
                cap.settle(hold, 1)
            catalogue = cap.reservation_catalogue_for_work_item("goal:42")
        assert [row.request_id for row in catalogue.receipts] == [
            "shared-a", "shared-b",
        ]
        assert len(catalogue.version) == 64
        assert not local_ledger.exists()
    finally:
        shared.close()


def _fast_retry(monkeypatch):
    from maverick import retry

    monkeypatch.setattr(retry, "MAX_ATTEMPTS", 2)
    monkeypatch.setattr(retry, "_retryable_exception_classes", lambda: (RuntimeError,))
    monkeypatch.setattr(retry, "_is_retryable_status_error", lambda _exc: True)
    monkeypatch.setattr(retry, "_is_terminal", lambda _exc: False)
    monkeypatch.setattr(retry.time, "sleep", lambda _seconds: None)
    return retry


def test_uncapped_retry_records_one_receipt_per_physical_attempt(
    dispatcher,
    monkeypatch,
):
    llm, ledger = dispatcher
    retry = _fast_retry(monkeypatch)
    monkeypatch.setattr(cap, "caps_from_config", dict)
    calls = 0

    class Client:
        def complete(self, **_kwargs):
            def physical():
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise RuntimeError("ambiguous first attempt")
                return _response("retried")

            return retry.sync_retry(physical)

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())
    with _bound_work():
        response = llm.complete("system", [])
        page = cap.reservations_for_work_item("goal:42", path=ledger)

    assert response.text == "retried" and calls == 2
    assert {row.state for row in page.receipts} == {"unknown", "settled"}
    attempts = sorted(page.receipts, key=lambda row: row.operation["attempt_no"])
    assert [row.operation["attempt_no"] for row in attempts] == [1, 2]
    assert [row.operation["category"] for row in attempts] == ["inference", "retry"]
    assert [row.operation["parent_category"] for row in attempts] == [
        "inference",
        "inference",
    ]
    assert [row.operation["attempt_state"] for row in attempts] == [
        "failed",
        "succeeded",
    ]
    assert len({row.operation["operation_id"] for row in attempts}) == 1
    settled = next(row for row in page.receipts if row.state == "settled")
    assert response.provider_cost_receipt["reference"] == settled.reference


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_uncapped_failover_keeps_one_operation_and_monotonic_attempts(
    dispatcher,
    monkeypatch,
    asynchronous,
):
    llm, ledger = dispatcher
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(
        llm_mod,
        "_fallback_chain_for_dispatch",
        lambda _raw, _requested: ["openai:synthetic-backup"],
    )
    monkeypatch.setattr(
        "maverick.failover_policy.order_chain",
        lambda models: list(models),
    )
    monkeypatch.setattr(
        "maverick.failover_policy.policy_should_retry",
        lambda _error: True,
    )

    class Client:
        def complete(self, **kwargs):
            if kwargs["model"] == "synthetic-receipt-model":
                raise RuntimeError("first provider path failed")
            return _response("backup")

        async def complete_async(self, **kwargs):
            return self.complete(**kwargs)

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())

    with _bound_work():
        response = (
            asyncio.run(llm.complete_async("system", []))
            if asynchronous
            else llm.complete("system", [])
        )
        receipts = cap.reservation_catalogue_for_work_item(
            "goal:42",
            path=ledger,
        ).receipts

    assert response.text == "backup"
    attempts = sorted(receipts, key=lambda row: row.operation["attempt_no"])
    assert [row.operation["attempt_no"] for row in attempts] == [1, 2]
    assert [row.operation["category"] for row in attempts] == ["inference", "retry"]
    assert [row.operation["attempt_state"] for row in attempts] == [
        "failed",
        "succeeded",
    ]
    assert len({row.operation["operation_id"] for row in attempts}) == 1


def test_configured_cap_stops_retry_after_ambiguous_charge(
    dispatcher,
    monkeypatch,
):
    llm, ledger = dispatcher
    retry = _fast_retry(monkeypatch)
    calls = 0

    class Client:
        def complete(self, **_kwargs):
            def physical():
                nonlocal calls
                calls += 1
                raise RuntimeError("ambiguous provider failure")

            return retry.sync_retry(physical)

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())
    with _bound_work(), pytest.raises(cap.ProviderAccountingUnavailable):
        llm.complete("system", [])
    with _bound_work():
        page = cap.reservations_for_work_item("goal:42", path=ledger)

    assert calls == 1
    assert len(page.receipts) == 1 and page.receipts[0].state == "unknown"


def test_prewarm_is_blocked_by_provider_cap_before_physical_call(
    dispatcher,
    monkeypatch,
):
    _ignored, _ledger = dispatcher
    llm = LLM(model="anthropic:synthetic-receipt-model")
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"anthropic": 1.0})
    calls = 0

    class Client:
        def prewarm(self, *_args, **_kwargs):
            nonlocal calls
            calls += 1
            return True

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())

    assert llm.prewarm("large system", budget=None) is False
    assert calls == 0


def test_prewarm_receipt_is_storage_work_with_successful_attempt(
    dispatcher,
    monkeypatch,
):
    _ignored, ledger = dispatcher
    llm = LLM(model="anthropic:synthetic-receipt-model")
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"anthropic": 25.0})

    class Client:
        def prewarm(self, *_args, **_kwargs):
            return True

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())

    with _bound_work():
        assert llm.prewarm("large system", budget=None) is True
        receipt = cap.reservation_catalogue_for_work_item(
            "goal:42",
            path=ledger,
        ).receipts[0]

    assert receipt.operation["category"] == "storage"
    assert receipt.operation["parent_category"] == "storage"
    assert receipt.operation["attempt_no"] == 1
    assert receipt.operation["service"] == (
        "anthropic:synthetic-receipt-model:prompt-cache"
    )
    assert receipt.operation["attempt_state"] == "succeeded"


def test_uncapped_prewarm_retains_work_bound_usage_receipt(
    dispatcher,
    monkeypatch,
):
    _ignored, ledger = dispatcher
    llm = LLM(model="anthropic:synthetic-receipt-model")
    monkeypatch.setattr(cap, "caps_from_config", dict)
    from maverick.retry import sync_physical_attempt

    class Client:
        def prewarm(self, *_args, **_kwargs):
            sync_physical_attempt(
                lambda: SimpleNamespace(
                    usage=SimpleNamespace(input_tokens=1, output_tokens=0),
                )
            )
            return True

    monkeypatch.setattr(llm, "_get_client", lambda _provider: Client())
    with _bound_work():
        assert llm.prewarm("large system", budget=None) is True
        page = cap.reservations_for_work_item("goal:42", path=ledger)

    assert len(page.receipts) == 1
    receipt = page.receipts[0]
    assert receipt.state == "settled" and receipt.actual is not None
    assert receipt.cost_basis == "estimated"
    assert receipt.pricing_evidence is not None
