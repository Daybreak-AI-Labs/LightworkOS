"""Automatic provider-call receipt projection into outcome accounting."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from types import SimpleNamespace

import pytest
from maverick import llm as llm_mod
from maverick import outcome_accounting as outcome_module
from maverick import provider_cost_cap as cap
from maverick.governed_records import GovernedRecordStore
from maverick.llm import LLM, LLMResponse
from maverick.logging_config import reset_goal_context, set_goal_context
from maverick.outcome_accounting import OutcomeAccounting
from maverick.paths import tenant_scope
from maverick.world_model import WorldModel
from maverick_dashboard import outcome_accounting_bridge as bridge
from maverick_dashboard import outcome_pilot_sources as sources
from maverick_dashboard import outcome_pilots


def _response(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        thinking=None,
        tool_calls=[],
        stop_reason="end_turn",
        raw=SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=1, completion_tokens=0),
        ),
    )


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    ledger = tmp_path / "provider_spend.json"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"openai": 100.0})
    monkeypatch.setattr(cap, "period_from_config", lambda: "day")
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(
        cap,
        "period_key",
        lambda now=None, period=None: "2026-09-08",
    )
    monkeypatch.setattr(llm_mod, "_estimate_call_cost", lambda *a, **kw: 2.0)
    monkeypatch.setattr(llm_mod, "_run_preflight", lambda *a, **kw: None)
    monkeypatch.setattr(llm_mod, "_enforce_circuit", lambda *a: None)
    monkeypatch.setattr(llm_mod, "_feed_circuit", lambda *a: None)
    monkeypatch.setattr(llm_mod, "_hedge_ms", lambda: None)
    monkeypatch.setattr(llm_mod, "require_model_allowed", lambda spec: spec)
    monkeypatch.setattr(
        "maverick.budget._lookup_price",
        lambda _model, **_kw: (1_000_000, 0),
    )
    return ledger


def _service(tmp_path) -> OutcomeAccounting:
    return OutcomeAccounting(
        store=GovernedRecordStore(
            "test_outcome_provider_receipts",
            "OPR",
            "outcome-accounting",
        ),
        reservation_resolver=outcome_module._inspect_provider_reservation,
        reservation_claimer=outcome_module._claim_provider_reservation,
        reservation_committer=outcome_module._commit_provider_reservation,
    )


def _coverage(*included):
    selected = {"provider_usage", *included}
    return {
        family: {
            "status": "included" if family in selected else "zero",
            "note": (
                "This family is bound to the reviewed receipt and pilot evidence."
                if family in selected else
                "The reviewed pilot evidence confirms zero for this family."
            ),
        }
        for family in outcome_module.COST_COVERAGE_FAMILIES
    }


def _pilot(source_version: str, *, service: OutcomeAccounting, total=None) -> dict:
    pilot = {
        "id": "OPL-" + "1" * 48,
        "plan_version": "2" * 64,
        "state": "frozen",
        "actor": "user:owner@example.test",
        "cases": [{
            "id": "case-one",
            "kind": "goal",
            "reference": "42",
            "input_version": "input-42",
            "measurement": {
                "source_version": source_version,
                "criteria_met": True,
                "evidence": "Reviewed the completed task result.",
                "ai_total_cost": total,
                "human_cost": "0",
                "rework_cost": "0",
                "ai_hands_on_minutes": 0,
                "review_minutes": 0,
                "rework_minutes": 0,
                "currency": "USD",
                "cost_coverage": _coverage(),
            },
        }],
    }
    pilot["admission_manifest"] = outcome_pilots.admission_manifest(pilot)
    pilot["admission_manifest"] = bridge.admit_pilot(
        pilot,
        resolve=lambda _kind, _reference: {
            "unstarted": True, "input_version": "input-42",
            "first_started_at": None,
        },
        service=service,
    )
    return pilot


def _source(version: str, receipts, *, runtime=None) -> dict:
    return {
        "version": version,
        "input_version": "input-42",
        "unstarted": False,
        "first_started_at": 2_000_000_000.0,
        "finished": True,
        "accepted": True,
        "reviewer": None,
        "status": "done",
        "runtime_cost_usd": runtime,
        "provider_cost_receipts": [asdict(row) for row in receipts],
        "provider_cost_receipts_complete": True,
        "provider_cost_receipts_catalog_version": "9" * 64,
    }


def _reserve(
    provider: str,
    projected: float,
    *,
    request_id: str,
    work_item_id: str = "goal:42",
    operation_id: str | None = None,
    category: str = "inference",
    parent_category: str | None = None,
    attempt_no: int = 1,
    service: str | None = None,
):
    return cap.reserve(
        provider,
        projected,
        request_id=request_id,
        work_item_id=work_item_id,
        operation_id=operation_id or f"provider-operation:{request_id}",
        category=category,
        parent_category=parent_category or category,
        attempt_no=attempt_no,
        service=service or provider,
    )


def test_goal_source_discovers_sync_and_hedged_physical_calls(
    isolated,
    tmp_path,
    monkeypatch,
):
    world = WorldModel(tmp_path / "world.db")
    # Exercise receipt wiring through a provider route with verified pricing.
    # A synthetic, unpriced route must stop before a paid call is dispatched.
    dispatcher = LLM(model="openai:gpt-5.5")

    class SyncClient:
        def complete(self, **_kwargs):
            return _response("sync")

    class HedgeClient:
        calls = 0

        async def complete_async(self, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                await asyncio.sleep(5)
                return _response("primary")
            return _response("backup")

    try:
        with tenant_scope(tenant="workspace-one"):
            goal_id = world.create_goal(
                "Receipt-backed task",
                "Exercise physical calls.",
                owner="user:owner@example.test",
                domain="privacy",
            )
            tokens = set_goal_context(goal_id=goal_id)
            try:
                monkeypatch.setattr(
                    dispatcher,
                    "_get_client",
                    lambda _provider: SyncClient(),
                )
                sync_response = dispatcher.complete("system", [])
                hedge_client = HedgeClient()
                monkeypatch.setattr(
                    dispatcher,
                    "_get_client",
                    lambda _provider: hedge_client,
                )
                monkeypatch.setattr(llm_mod, "_hedge_ms", lambda: 1)
                hedge_response = asyncio.run(
                    dispatcher.complete_async("system", []),
                )
            finally:
                reset_goal_context(tokens)

            episode = world.start_episode(goal_id)
            world.end_episode(
                episode,
                "Complete",
                "success",
                cost_dollars=2,
            )
            world.set_goal_status(goal_id, "done", result="Complete")
            monkeypatch.setattr("maverick_dashboard.app._world", lambda: world)
            monkeypatch.setattr(sources, "can_access_goal", lambda *a: True)
            monkeypatch.setattr(sources, "suite_allowed", lambda *a: True)
            monkeypatch.setattr(sources, "caller_principal", lambda *a: None)
            monkeypatch.setattr("maverick.domain.suite_for", lambda _domain: "privacy")

            source = sources.goal_source(None, str(goal_id))

        receipts = source["provider_cost_receipts"]
        assert source["provider_cost_receipts_complete"] is True
        assert len(receipts) == 3
        assert [row["state"] for row in receipts].count("settled") == 2
        assert [row["state"] for row in receipts].count("unknown") == 1
        returned = {
            sync_response.provider_cost_receipt["reference"],
            hedge_response.provider_cost_receipt["reference"],
        }
        assert returned <= {row["reference"] for row in receipts}
        assert hedge_client.calls == 2
        assert source["runtime_cost_usd"] == 2
        assert isolated.exists()
    finally:
        world.close()


def test_receipt_replay_is_idempotent_and_runtime_aggregate_is_not_added_twice(
    isolated,
    tmp_path,
):
    service = _service(tmp_path)
    with tenant_scope(tenant="workspace-one"):
        hold = _reserve(
            "openai",
            5,
            request_id="settled-call",
        )
        snapshot = cap.settle(hold, 3)
        source = _source("a" * 64, [snapshot], runtime=3)
        pilot = _pilot(source["version"], service=service)
        first = bridge.sync_case(
            pilot,
            "case-one",
            source,
            source_operation_id="receipt-backed-observation",
            actor="user:owner@example.test",
            service=service,
        )
        claimed = cap.reservations_for_work_item("goal:42").receipts
        replayed = bridge.sync_case(
            pilot,
            "case-one",
            _source("a" * 64, claimed, runtime=3),
            source_operation_id="receipt-backed-observation",
            actor="user:owner@example.test",
            service=service,
        )

    assert replayed["revision"] == first["revision"]
    assert first["costs"]["known_totals"] == {"USD": "3"}
    assert first["costs"]["reconciled_reservation_count"] == 1
    current = [row for row in first["costs"]["events"] if row["current"]]
    receipt_event = next(row for row in current if row["source_ref"] == snapshot.reference)
    runtime_event = next(row for row in current if row["source_ref"].endswith(":runtime"))
    assert receipt_event["aggregation"] == "additive"
    assert receipt_event["basis"] == "estimated"
    assert runtime_event["aggregation"] == "informational"
    assert isolated.exists()


def test_receipt_prefix_crash_cannot_publish_complete_coverage_and_exact_retry_totals_ten(
    isolated,
    tmp_path,
    monkeypatch,
):
    service = _service(tmp_path)
    with tenant_scope(tenant="workspace-one"):
        first_hold = _reserve(
            "openai", 2, request_id="catalogue-call-one",
        )
        second_hold = _reserve(
            "openai", 2, request_id="catalogue-call-two",
        )
        first_receipt = cap.settle(first_hold, 1)
        second_receipt = cap.settle(second_hold, 2)
        source = _source("a" * 64, [first_receipt, second_receipt])
        pilot = _pilot(source["version"], service=service)
        pilot["cases"][0]["measurement"].update(
            human_cost="5", rework_cost="2", ai_hands_on_minutes=5,
            review_minutes=0, rework_minutes=2,
            cost_coverage=_coverage("review", "rework"),
        )
        original_cost = bridge._cost
        interrupted = []

        def crash_before_second_receipt(accounting, raw, **kwargs):
            if (kwargs.get("source_ref") == second_receipt.reference
                    and not interrupted):
                interrupted.append(True)
                raise OSError("synthetic crash after receipt prefix")
            return original_cost(accounting, raw, **kwargs)

        monkeypatch.setattr(bridge, "_cost", crash_before_second_receipt)
        with pytest.raises(OSError, match="receipt prefix"):
            bridge.sync_case(
                pilot, "case-one", source,
                source_operation_id="two-receipt-catalogue-sync",
                actor="user:owner@example.test", service=service,
            )
        record_id = pilot["admission_manifest"]["entries"][0]["accounting_record_id"]
        partial = service.report(record_id)
        current = [row for row in partial["costs"]["events"] if row["current"]]
        receipt_refs = {first_receipt.reference, second_receipt.reference}
        assert sum(row["source_ref"] in receipt_refs for row in current) == 1
        assert not any(row["aggregation"] == "coverage" for row in current)
        assert partial["costs"]["coverage_complete"] is False
        assert partial["costs"]["complete"] is False

        monkeypatch.setattr(bridge, "_cost", original_cost)
        completed = bridge.sync_case(
            pilot, "case-one", source,
            source_operation_id="two-receipt-catalogue-sync",
            actor="user:owner@example.test", service=service,
        )
        replayed = bridge.sync_case(
            pilot, "case-one", source,
            source_operation_id="two-receipt-catalogue-sync",
            actor="user:owner@example.test", service=service,
        )

    assert completed["costs"]["known_totals"] == {"USD": "10"}
    assert completed["costs"]["coverage_complete"] is True
    assert replayed["revision"] == completed["revision"]
    assert isolated.exists()


def test_late_receipt_supersedes_additive_runtime_before_complete_coverage(
    isolated,
    tmp_path,
):
    service = _service(tmp_path)
    with tenant_scope(tenant="workspace-one"):
        source = _source("a" * 64, [], runtime=3)
        pilot = _pilot(source["version"], service=service)
        initial = bridge.sync_case(
            pilot,
            "case-one",
            source,
            source_operation_id="late-provider-receipt",
            actor="user:owner@example.test",
            service=service,
        )
        hold = _reserve(
            "openai",
            5,
            request_id="late-settled-call",
        )
        settled = cap.settle(hold, 3)
        advanced = bridge.sync_case(
            pilot,
            "case-one",
            _source("a" * 64, [settled], runtime=3),
            source_operation_id="late-provider-receipt",
            actor="user:owner@example.test",
            service=service,
        )
        replayed = bridge.sync_case(
            pilot,
            "case-one",
            _source("a" * 64, [settled], runtime=3),
            source_operation_id="late-provider-receipt",
            actor="user:owner@example.test",
            service=service,
        )

    initial_runtime = next(
        row for row in initial["costs"]["events"]
        if row["current"] and row["source_ref"].endswith(":runtime")
    )
    current = [row for row in advanced["costs"]["events"] if row["current"]]
    runtime_event = next(row for row in current if row["source_ref"].endswith(":runtime"))
    receipt_event = next(row for row in current if row["source_ref"] == settled.reference)
    assert initial_runtime["aggregation"] == "additive"
    assert runtime_event["aggregation"] == "informational"
    assert receipt_event["aggregation"] == "additive"
    assert advanced["costs"]["known_totals"] == {"USD": "3"}
    assert advanced["costs"]["coverage_complete"] is True
    assert replayed["revision"] == advanced["revision"]
    assert isolated.exists()


def test_unknown_receipt_advances_after_delayed_settlement_and_reconcile_replays(
    isolated,
    tmp_path,
    monkeypatch,
):
    service = _service(tmp_path)
    with tenant_scope(tenant="workspace-one"):
        hold = _reserve(
            "openai",
            5,
            request_id="delayed-call",
        )
        unknown = cap.settle(hold, None)
        source_a = _source("a" * 64, [unknown])
        pilot = _pilot(source_a["version"], service=service)
        initial = bridge.sync_case(
            pilot,
            "case-one",
            source_a,
            source_operation_id="unknown-provider-observation",
            actor="user:owner@example.test",
            service=service,
        )
        settled = cap.settle(hold, 2)
        # Receipt settlement is independently versioned and must not stale the
        # otherwise unchanged technical source observation.
        source_b = _source("a" * 64, [settled])
        monkeypatch.setattr(outcome_pilots, "get", lambda *_args: pilot)
        monkeypatch.setattr(sources, "resolve", lambda *_args: source_b)
        reconciled = bridge.reconcile_record(
            object(),
            "workspace-one",
            initial["id"],
            service=service,
            owner_id="user:owner@example.test",
        )
        replayed = bridge.reconcile_record(
            object(),
            "workspace-one",
            initial["id"],
            service=service,
            owner_id="user:owner@example.test",
        )

    assert initial["costs"]["known_totals"] == {"USD": "0"}
    assert initial["costs"]["unknown_event_count"] == 1
    assert reconciled["costs"]["known_totals"] == {"USD": "2"}
    assert reconciled["costs"]["unknown_event_count"] == 0
    assert reconciled["costs"]["reconciled_reservation_count"] == 1
    assert reconciled["technical_outcome"]["status"] == "verified"
    receipt_events = [
        row for row in reconciled["costs"]["events"]
        if row["source_ref"] == settled.reference
    ]
    assert [row["basis"] for row in receipt_events] == ["unknown", "estimated"]
    assert receipt_events[0]["current"] is False
    assert receipt_events[1]["current"] is True
    assert replayed["revision"] == reconciled["revision"]
    assert isolated.exists()


def test_reported_total_removal_promotes_receipt_without_erasing_settled_cost(
    isolated,
    tmp_path,
):
    service = _service(tmp_path)
    with tenant_scope(tenant="workspace-one"):
        hold = _reserve("openai", 5, request_id="aggregate-transition")
        settled = cap.settle(hold, 3)
        source_a = _source("a" * 64, [settled])
        pilot = _pilot(source_a["version"], service=service, total="10")
        initial = bridge.sync_case(
            pilot,
            "case-one",
            source_a,
            source_operation_id="aggregate-transition-a",
            actor="user:owner@example.test",
            service=service,
        )

        pilot["cases"][0]["measurement"].update(
            source_version="b" * 64,
            ai_total_cost=None,
        )
        source_b = _source("b" * 64, [settled])
        advanced = bridge.sync_case(
            pilot,
            "case-one",
            source_b,
            source_operation_id="aggregate-transition-b",
            actor="user:owner@example.test",
            service=service,
        )
        replayed = bridge.sync_case(
            pilot,
            "case-one",
            source_b,
            source_operation_id="aggregate-transition-b",
            actor="user:owner@example.test",
            service=service,
        )

    initial_receipt = next(
        row for row in initial["costs"]["events"]
        if row["current"] and row["source_ref"] == settled.reference
    )
    receipt_history = [
        row for row in advanced["costs"]["events"]
        if row["source_ref"] == settled.reference
    ]
    total_history = [
        row for row in advanced["costs"]["events"]
        if row["source_ref"].endswith(":reported-total")
    ]
    assert initial["costs"]["known_totals"] == {"USD": "10"}
    assert initial_receipt["aggregation"] == "informational"
    assert [row["aggregation"] for row in receipt_history] == [
        "informational", "additive",
    ]
    assert receipt_history[0]["current"] is False
    assert receipt_history[1]["current"] is True
    assert [row["all_in_total"] for row in total_history] == [True, False]
    assert total_history[0]["current"] is False
    assert total_history[1]["current"] is True
    assert advanced["costs"]["known_totals"] == {"USD": "3"}
    assert advanced["costs"]["coverage_complete"] is True
    assert replayed["revision"] == advanced["revision"]
    assert isolated.exists()


def test_settled_failed_search_and_retry_keep_operation_classification(
    isolated,
    tmp_path,
):
    service = _service(tmp_path)
    with tenant_scope(tenant="workspace-one"):
        failed_hold = _reserve(
            "tavily",
            2,
            request_id="failed-search",
            operation_id="web-search:classified-attempt",
            category="search",
            parent_category="search",
            attempt_no=1,
            service="tavily",
        )
        retry_hold = _reserve(
            "brave",
            3,
            request_id="successful-retry",
            operation_id="web-search:classified-attempt",
            category="retry",
            parent_category="search",
            attempt_no=2,
            service="brave",
        )
        failed = cap.settle(failed_hold, 1, attempt_state="failed")
        retry = cap.settle(retry_hold, 2, attempt_state="succeeded")
        source = _source("a" * 64, [failed, retry])
        pilot = _pilot(source["version"], service=service)
        pilot["cases"][0]["measurement"]["cost_coverage"] = _coverage(
            "failed_attempts",
        )
        report = bridge.sync_case(
            pilot,
            "case-one",
            source,
            source_operation_id="classified-search-retry",
            actor="user:owner@example.test",
            service=service,
        )

    events = {
        row["source_ref"]: row for row in report["costs"]["events"]
        if row["current"] and row["source_ref"] in {failed.reference, retry.reference}
    }
    assert report["costs"]["known_totals"] == {"USD": "3"}
    assert report["costs"]["failed_attempt_count"] == 1
    assert report["costs"]["coverage_complete"] is True
    assert events[failed.reference]["category"] == "search"
    assert events[failed.reference]["attempt_state"] == "failed"
    assert events[retry.reference]["category"] == "retry"
    assert events[retry.reference]["attempt_state"] == "succeeded"
    assert events[failed.reference]["attempt_ref"].endswith(":attempt:1")
    assert events[retry.reference]["attempt_ref"].endswith(":attempt:2")
    assert "via tavily" in events[failed.reference]["evidence_note"]
    assert isolated.exists()


def test_legacy_settled_receipt_without_operation_stays_incomplete(
    isolated,
    tmp_path,
):
    service = _service(tmp_path)
    with tenant_scope(tenant="workspace-one"):
        hold = cap.reserve(
            "openai",
            5,
            request_id="legacy-unclassified",
            work_item_id="goal:42",
        )
        settled = cap.settle(hold, 3)
        source = _source("a" * 64, [settled])
        pilot = _pilot(source["version"], service=service)
        report = bridge.sync_case(
            pilot,
            "case-one",
            source,
            source_operation_id="legacy-unclassified-receipt",
            actor="user:owner@example.test",
            service=service,
        )

    event = next(
        row for row in report["costs"]["events"]
        if row["current"] and row["source_ref"] == settled.reference
    )
    assert report["costs"]["known_totals"] == {"USD": "3"}
    assert report["costs"]["coverage_complete"] is False
    assert report["costs"]["complete"] is False
    assert event["category"] == "other"
    assert event["attempt_state"] == "unknown"
    assert "lacks trusted operation" in event["evidence_note"]
    assert isolated.exists()
