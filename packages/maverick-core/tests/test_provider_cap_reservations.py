"""Actual durable provider admission; synthetic local/shared stores, no network."""
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import provider_cost_cap as cap
from maverick.paths import tenant_scope


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"openai": 20.0})
    monkeypatch.setattr(cap, "period_from_config", lambda: "day")
    return tmp_path / "provider_spend.json"


def test_existing_unreadable_accounting_is_preserved_and_blocks(ledger):
    cap.record("openai", 25, path=ledger, now=0)
    ledger.write_text("{broken accounting", encoding="utf-8")
    before = ledger.read_bytes()
    with pytest.raises(cap.ProviderAccountingUnavailable):
        cap.enforce("openai", projected_dollars=1, path=ledger, now=0)
    cap.record("openai", 1, path=ledger, now=0)
    assert ledger.read_bytes() == before


def test_atomic_admission_counts_other_callers_and_keeps_abandoned_holds(ledger):
    cap.record("openai", 18, path=ledger, now=0)

    def admit(index):
        try:
            return cap.reserve("openai", 2, path=ledger, now=0, request_id=f"call-{index}")
        except cap.ProviderCapExceeded:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = [hold for hold in pool.map(admit, range(8)) if hold is not None]
    assert len(admitted) == 1
    assert cap.check("openai", path=ledger, now=0).remaining == 0
    # A new reader cannot auto-expire an abandoned process's durable hold.
    with pytest.raises(cap.ProviderCapExceeded):
        cap.reserve("openai", 1, path=ledger, now=30, request_id="after-crash")
    cap.settle(admitted[0], 1)
    cap.settle(admitted[0], 1)
    assert cap.check("openai", path=ledger, now=0).spent == 19
    with pytest.raises(cap.ProviderAccountingUnavailable):
        cap.settle(admitted[0], 0)


def test_ambiguous_settlement_does_not_refund_and_late_receipt_is_idempotent(ledger):
    held = cap.reserve("openai", 5, path=ledger, now=0, request_id="ambiguous-call")
    cap.settle(held, None)
    assert cap.check("openai", path=ledger, now=0).reserved == 5
    with pytest.raises(cap.ProviderAccountingUnavailable):
        cap.reserve("openai", 1, path=ledger, now=0, request_id="after-unknown")
    cap.settle(held, 3)
    assert cap.check("openai", path=ledger, now=0).spent == 3
    cap.settle(held, 3)
    assert cap.check("openai", path=ledger, now=0).spent == 3


def test_provider_operation_scope_persists_metadata_and_restores_nested_scope(ledger):
    with tenant_scope(tenant="workspace-one"), cap.work_item_scope("vendor:VON-42"):
        with cap.provider_operation_scope(
            operation_id="vendor-evidence-42",
            category="retrieval",
            service="evidence-store",
        ):
            outer = cap.current_provider_operation()
            held = cap.reserve(
                "openai",
                2,
                path=ledger,
                now=0,
                request_id="operation-attempt-one",
            )
            with cap.provider_operation_scope(
                operation_id="vendor-evidence-42-refresh",
                category="update",
                service="evidence-store",
            ):
                assert cap.current_provider_operation().category == "update"
            assert cap.current_provider_operation() == outer
        assert cap.current_provider_operation() is None

        snapshot = cap.settle(held, 1, attempt_state="succeeded")
        assert snapshot.operation == {
            "operation_id": "vendor-evidence-42",
            "category": "retrieval",
            "parent_category": "retrieval",
            "attempt_no": 1,
            "service": "evidence-store",
            "attempt_state": "succeeded",
        }
        catalogue = cap.reservation_catalogue_for_work_item(
            "vendor:VON-42",
            path=ledger,
        )
        assert catalogue.receipts == (snapshot,)


def test_metered_provider_call_keeps_unpriced_success_as_succeeded_unknown(
    ledger,
    monkeypatch,
):
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-08")

    with tenant_scope(tenant="workspace-one"), cap.work_item_scope("research:RUN-9"):
        with cap.provider_operation_scope(
            operation_id="research-search-9",
            category="search",
            service="tavily",
        ):
            assert cap.metered_provider_call(
                "tavily",
                lambda: {"results": ["found"]},
                projected_dollars=0,
                request_id="search-attempt-one",
            ) == {"results": ["found"]}
        receipt = cap.reservation_catalogue_for_work_item(
            "research:RUN-9",
            path=ledger,
        ).receipts[0]

    assert receipt.state == "unknown"
    assert receipt.actual is None
    assert receipt.operation == {
        "operation_id": "research-search-9",
        "category": "search",
        "parent_category": "search",
        "attempt_no": 1,
        "service": "tavily",
        "attempt_state": "succeeded",
    }


def test_metered_provider_call_blocks_unknown_projection_before_capped_dispatch(
    ledger,
    monkeypatch,
):
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    calls = []

    with tenant_scope(tenant="workspace-one"), cap.work_item_scope("research:RUN-cap"):
        with pytest.raises(cap.ProviderAccountingUnavailable):
            cap.metered_provider_call(
                "openai",
                lambda: calls.append("dispatched"),
                operation_id="unknown-priced-call",
                category="retrieval",
            )

    assert calls == []
    assert not ledger.exists()


def test_metered_provider_call_allows_uncapped_unknown_and_verified_free_cost(
    ledger,
    monkeypatch,
):
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-08")
    evidence = {
        "model_id": "free-fixture-v1",
        "input_per_mtok": "0",
        "output_per_mtok": "0",
        "source": "fixture:verified-free-rate-card",
        "as_of": "2026-09-08",
        "fetched_at": "2026-09-08T00:00:00Z",
        "currency": "USD",
        "confidence": 1.0,
        "verified": True,
        "rate_card_version": "free-v1",
        "evidence_id": "fixture-free-pricing",
        "pricing_basis": "The fixture transport has no external charge.",
        "applicability": "Only the named local fixture transport.",
    }

    with tenant_scope(tenant="workspace-one"), cap.work_item_scope("research:RUN-free"):
        monkeypatch.setattr(cap, "caps_from_config", dict)
        assert cap.metered_provider_call(
            "unpriced-host",
            lambda: "unknown",
            operation_id="uncapped-unknown-call",
            category="retrieval",
        ) == "unknown"
        monkeypatch.setattr(cap, "caps_from_config", lambda: {"free-host": 1.0})
        assert cap.metered_provider_call(
            "free-host",
            lambda: "free",
            projected_dollars=0,
            actual_dollars=0,
            cost_basis="observed",
            pricing_evidence=evidence,
            operation_id="verified-free-call",
            category="retrieval",
        ) == "free"
        receipts = cap.reservation_catalogue_for_work_item(
            "research:RUN-free",
            path=ledger,
        ).receipts

    assert [(row.provider, row.state, row.actual) for row in receipts] == [
        ("free-host", "settled", 0.0),
        ("unpriced-host", "unknown", None),
    ]


def test_operation_attempt_replay_is_global_across_provider_and_period(
    ledger,
    monkeypatch,
):
    current_period = ["2026-09-08"]
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(
        cap,
        "period_key",
        lambda now=None, period=None: current_period[0],
    )
    callbacks = []

    with tenant_scope(tenant="workspace-one"), cap.work_item_scope("goal:replay"):
        assert cap.metered_provider_call(
            "openai",
            lambda: callbacks.append("primary") or "ok",
            projected_dollars=1,
            actual_dollars=1,
            request_id="stable-primary-receipt",
            operation_id="stable-provider-operation",
            category="inference",
            attempt_no=1,
        ) == "ok"
        first = cap.reservation_catalogue_for_work_item(
            "goal:replay",
            path=ledger,
        ).receipts[0]
        current_period[0] = "2026-09-09"
        with pytest.raises(cap.ProviderAttemptAlreadyAdmitted) as duplicate:
            cap.metered_provider_call(
                "anthropic",
                lambda: callbacks.append("failover"),
                projected_dollars=1,
                actual_dollars=1,
                request_id="stable-failover-receipt",
                operation_id="stable-provider-operation",
                category="inference",
                attempt_no=1,
            )

    assert callbacks == ["primary"]
    assert duplicate.value.existing_reference == first.reference


def test_concurrent_operation_attempt_race_dispatches_one_callback(
    ledger,
    monkeypatch,
):
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-08")
    callbacks = []

    def dispatch(index):
        provider = "openai" if index % 2 == 0 else "anthropic"
        try:
            with tenant_scope(tenant="workspace-race"), cap.work_item_scope("goal:race"):
                return cap.metered_provider_call(
                    provider,
                    lambda: callbacks.append(index) or index,
                    projected_dollars=1,
                    actual_dollars=1,
                    request_id=f"race-receipt-{index}",
                    operation_id="one-physical-attempt",
                    category="inference",
                    attempt_no=1,
                )
        except cap.ProviderAttemptAlreadyAdmitted:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(dispatch, range(8)))

    assert len([result for result in results if result is not None]) == 1
    assert len(callbacks) == 1


def test_operation_attempt_metadata_mismatch_fails_as_corrupt_replay(
    ledger,
    monkeypatch,
):
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-08")

    with tenant_scope(tenant="workspace-one"), cap.work_item_scope("goal:metadata"):
        cap.metered_provider_call(
            "openai",
            lambda: "ok",
            projected_dollars=1,
            actual_dollars=1,
            operation_id="stable-metadata-operation",
            category="inference",
            service="model-one",
        )
        with pytest.raises(cap.ProviderAccountingUnavailable) as mismatch:
            cap.metered_provider_call(
                "openai",
                lambda: pytest.fail("mismatched replay dispatched"),
                projected_dollars=1,
                actual_dollars=1,
                operation_id="stable-metadata-operation",
                category="retrieval",
                service="model-two",
            )

    assert not isinstance(mismatch.value, cap.ProviderAttemptAlreadyAdmitted)


def test_operation_attempt_scope_is_tenant_and_work_bound(ledger, monkeypatch):
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-08")
    calls = []

    for tenant in ("workspace-one", "workspace-two"):
        with tenant_scope(tenant=tenant), cap.work_item_scope("goal:same-visible-id"):
            assert cap.metered_provider_call(
                "openai",
                lambda tenant=tenant: calls.append(tenant) or tenant,
                projected_dollars=1,
                actual_dollars=1,
                operation_id="tenant-local-operation",
                category="inference",
            ) == tenant

    assert calls == ["workspace-one", "workspace-two"]


def test_prune_keeps_operation_tombstone_and_cannot_reopen_dispatch(
    ledger,
    monkeypatch,
):
    current_period = ["2026-09-08"]
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(
        cap,
        "period_key",
        lambda now=None, period=None: current_period[0],
    )
    calls = []

    cap.metered_provider_call(
        "openai",
        lambda: calls.append("first") or "done",
        projected_dollars=1,
        actual_dollars=1,
        operation_id="unbound-pruned-operation",
        category="inference",
    )
    current_period[0] = "2026-09-09"
    assert cap.prune(path=ledger) == 1
    with pytest.raises(cap.ProviderAttemptAlreadyAdmitted):
        cap.metered_provider_call(
            "openai",
            lambda: calls.append("replay"),
            projected_dollars=1,
            actual_dollars=1,
            operation_id="unbound-pruned-operation",
            category="inference",
        )

    assert calls == ["first"]


def test_shared_attempt_claim_rolls_back_with_failed_budget_admission(
    ledger,
    monkeypatch,
    tmp_path,
):
    from maverick.world_model import WorldModel

    shared = WorldModel(tmp_path / "attempt-authority.db")
    monkeypatch.setattr(cap, "_shared_world", lambda: shared)
    try:
        with tenant_scope(tenant="workspace-one"), cap.work_item_scope("goal:shared"):
            with pytest.raises(cap.ProviderCapExceeded):
                cap.reserve(
                    "openai",
                    21,
                    request_id="rejected-shared-receipt",
                    operation_id="shared-operation",
                    category="inference",
                )
            hold = cap.reserve(
                "openai",
                1,
                request_id="accepted-shared-receipt",
                operation_id="shared-operation",
                category="inference",
            )
            with pytest.raises(cap.ProviderAttemptAlreadyAdmitted):
                cap.reserve(
                    "anthropic",
                    1,
                    request_id="cross-provider-shared-replay",
                    operation_id="shared-operation",
                    category="inference",
                )
            cap.settle(hold, 1)
        count = shared.conn.execute(
            "SELECT COUNT(*) FROM provider_operation_attempts",
        ).fetchone()[0]
        assert count == 1
        assert not ledger.exists()
    finally:
        shared.close()


def test_shared_legacy_attempt_collision_blocks_first_v35_admission(
    ledger,
    monkeypatch,
    tmp_path,
):
    from maverick.world_model import WorldModel

    path = tmp_path / "legacy-attempts.db"
    with WorldModel(path) as prepared:
        prepared.conn.execute("DROP TABLE provider_operation_attempts")
        prepared.conn.execute("DROP TABLE provider_operation_attempt_backfill")
        prepared.conn.execute("UPDATE schema_version SET version = 34")
        operation = {
            "operation_id": "legacy-duplicate-operation",
            "category": "inference",
            "parent_category": "inference",
            "attempt_no": 1,
            "service": "legacy-model",
            "attempt_state": "succeeded",
        }
        for provider, request_id in (
            ("openai", "legacy-openai"),
            ("anthropic", "legacy-anthropic"),
        ):
            receipt = {
                request_id: {
                    "projected": 1.0,
                    "state": "settled",
                    "actual": 1.0,
                    "cost_basis": "estimated",
                    "work_item_sha256": "a" * 64,
                    "operation": operation,
                },
            }
            prepared.conn.execute(
                "INSERT INTO provider_spend(period_key, provider, dollars) VALUES(?, ?, ?)",
                ("2026-09-08", provider, 1.0),
            )
            prepared.conn.execute(
                "INSERT INTO provider_cap_receipts(period_key, provider, receipts_json) VALUES(?, ?, ?)",
                ("2026-09-08", provider, json.dumps(receipt)),
            )
        prepared.conn.commit()

    shared = WorldModel(path)
    monkeypatch.setattr(cap, "_shared_world", lambda: shared)
    try:
        with tenant_scope(tenant="workspace-one"), cap.work_item_scope("goal:new"):
            with pytest.raises(cap.ProviderAccountingUnavailable):
                cap.reserve(
                    "openai",
                    1,
                    request_id="new-receipt",
                    operation_id="new-operation",
                    category="inference",
                )
        assert shared.conn.execute(
            "SELECT COUNT(*) FROM provider_operation_attempts",
        ).fetchone()[0] == 0
        assert shared.conn.execute(
            "SELECT COUNT(*) FROM provider_operation_attempt_backfill",
        ).fetchone()[0] == 0
        assert not ledger.exists()
    finally:
        shared.close()


def test_metered_provider_call_retains_failed_attempt_before_reraising(
    ledger,
    monkeypatch,
):
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-08")
    original = OSError("provider refused the request")

    def fail():
        raise original

    with tenant_scope(tenant="workspace-one"), cap.work_item_scope("research:RUN-10"):
        with pytest.raises(OSError) as captured:
            cap.metered_provider_call(
                "brave",
                fail,
                projected_dollars=0.25,
                request_id="search-attempt-failed",
                operation_id="research-search-10",
                category="retry",
                parent_category="search",
                attempt_no=2,
                service="brave",
            )
        receipt = cap.reservation_catalogue_for_work_item(
            "research:RUN-10",
            path=ledger,
        ).receipts[0]

    assert captured.value is original
    assert receipt.state == "unknown"
    assert receipt.projected == 0.25
    assert receipt.operation["category"] == "retry"
    assert receipt.operation["parent_category"] == "search"
    assert receipt.operation["attempt_no"] == 2
    assert receipt.operation["attempt_state"] == "failed"


def test_zero_projection_settlement_failure_becomes_unknown_and_blocks_next_call(
    ledger,
    monkeypatch,
):
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-08")
    calls = []

    with tenant_scope(tenant="workspace-one"), cap.work_item_scope("research:RUN-11"):
        assert cap.metered_provider_call(
            "openai",
            lambda: calls.append("first") or "completed",
            projected_dollars=0,
            actual_dollars=10,
            cost_basis="invalid",
            operation_id="unpriced-search-11",
            category="search",
        ) == "completed"
        with pytest.raises(cap.ProviderAccountingUnavailable):
            cap.metered_provider_call(
                "openai",
                lambda: calls.append("second"),
                projected_dollars=0,
                operation_id="unpriced-search-11",
                category="retry",
                parent_category="search",
                attempt_no=2,
            )
        receipt = cap.reservation_catalogue_for_work_item(
            "research:RUN-11",
            path=ledger,
        ).receipts[0]

    assert calls == ["first"]
    assert receipt.state == "unknown"
    assert receipt.operation["attempt_state"] == "succeeded"
    status = cap.check("openai", path=ledger)
    assert status.allowed is False and status.unresolved is True


def test_zero_projection_held_row_blocks_when_unknown_transition_is_unavailable(
    ledger,
    monkeypatch,
):
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-08")
    monkeypatch.setattr(
        cap,
        "settle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("authority offline")),
    )
    calls = []

    with tenant_scope(tenant="workspace-one"), cap.work_item_scope("research:RUN-12"):
        assert cap.metered_provider_call(
            "openai",
            lambda: calls.append("first") or "completed",
            projected_dollars=0,
            actual_dollars=10,
            cost_basis="observed",
            operation_id="unpriced-search-12",
            category="search",
        ) == "completed"
        with pytest.raises(cap.ProviderAccountingUnavailable):
            cap.metered_provider_call(
                "openai",
                lambda: calls.append("second"),
                projected_dollars=0,
                operation_id="unpriced-search-12",
                category="retry",
                parent_category="search",
                attempt_no=2,
            )

    assert calls == ["first"]
    status = cap.check("openai", path=ledger)
    assert status.allowed is False
    assert status.reserved == 0
    assert status.unresolved is True


def test_work_bound_reservation_reference_is_exact_and_claimed_once(ledger):
    with tenant_scope(tenant="workspace-one"):
        held = cap.reserve(
            "openai", 5, path=ledger, now=0, request_id="outcome-call",
            work_item_id="goal:42",
        )
        settled = cap.settle(held, 3)
        reference = cap.reservation_reference(held)
        assert settled.reference == reference
        assert settled.state == "settled" and settled.actual == 3
        assert cap.inspect_reservation(
            reference, expected_work_item_id="goal:42", path=ledger,
        ) == settled
        claimed = cap.claim_reservation(
            reference, expected_work_item_id="goal:42", claim_id="COST-one",
            expected_state="settled", expected_projected=5, expected_actual=3,
            path=ledger,
        )
        assert claimed.outcome_claim == "COST-one"
        assert claimed.outcome_claim_state == "prepared"
        assert cap.claim_reservation(
            reference, expected_work_item_id="goal:42", claim_id="COST-one",
            expected_state="settled", expected_projected=5, expected_actual=3,
            path=ledger,
        ) == claimed
        committed = cap.commit_reservation_claim(
            reference,
            expected_work_item_id="goal:42",
            claim_id="COST-one",
            event_id="COST-event-one",
            expected_state="settled",
            expected_projected=5,
            expected_actual=3,
            path=ledger,
        )
        assert committed.outcome_claim_state == "committed"
        assert committed.outcome_claim_event == "COST-event-one"
        assert cap.commit_reservation_claim(
            reference,
            expected_work_item_id="goal:42",
            claim_id="COST-one",
            event_id="COST-event-one",
            path=ledger,
        ) == committed
        with pytest.raises(cap.ProviderAccountingUnavailable):
            cap.claim_reservation(
                reference, expected_work_item_id="goal:42", claim_id="COST-two",
                path=ledger,
            )
        with pytest.raises(cap.ProviderAccountingUnavailable):
            cap.inspect_reservation(
                reference + "x", expected_work_item_id="goal:42", path=ledger,
            )

    with tenant_scope(tenant="workspace-two"):
        with pytest.raises(cap.ProviderAccountingUnavailable):
            cap.inspect_reservation(
                reference, expected_work_item_id="goal:42", path=ledger,
            )


def test_prune_retains_unclaimed_work_receipt_until_outcome_claim(ledger):
    with tenant_scope(tenant="workspace-one"):
        held = cap.reserve(
            "openai", 5, path=ledger, now=0, request_id="delayed-outcome",
            work_item_id="goal:42",
        )
        cap.settle(held, 3)
        assert cap.prune(now=86400, path=ledger) == 0
        cap.claim_reservation(
            cap.reservation_reference(held), expected_work_item_id="goal:42",
            claim_id="COST-delayed", path=ledger,
        )
        assert cap.prune(now=86400, path=ledger) == 0
        cap.commit_reservation_claim(
            cap.reservation_reference(held), expected_work_item_id="goal:42",
            claim_id="COST-delayed", event_id="COST-delayed-event", path=ledger,
        )
        assert cap.prune(now=86400, path=ledger) == 1


def test_settlement_is_bound_to_original_period_and_missing_ledger_fails_closed(ledger):
    held = cap.reserve("openai", 5, path=ledger, now=0, request_id="period-bound")
    cap.settle(held, 3)
    assert cap.check("openai", path=ledger, now=0).spent == 3
    assert cap.check("openai", path=ledger, now=86400).spent == 0
    ledger.unlink()
    with pytest.raises(cap.ProviderAccountingUnavailable):
        cap.enforce("openai", path=ledger, now=0)


def test_shared_authority_unavailable_never_falls_back(ledger, monkeypatch):
    monkeypatch.setattr("maverick.world_model_backends.is_postgres_configured", lambda: True)
    monkeypatch.setattr(cap, "_shared_world_cache", None)
    monkeypatch.setattr("maverick.world_model.open_world", lambda: (_ for _ in ()).throw(OSError("offline")))
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    with pytest.raises(cap.ProviderAccountingUnavailable):
        cap.reserve("openai", 1)
    assert not ledger.exists()


def test_shared_dsn_switch_selects_new_authority_but_settles_old_hold_on_its_original_store(ledger, monkeypatch, tmp_path):
    from maverick.world_model import WorldModel
    first, second = WorldModel(tmp_path / "first.db"), WorldModel(tmp_path / "second.db")
    monkeypatch.setattr("maverick.world_model_backends.is_postgres_configured", lambda: True)
    monkeypatch.setattr(cap, "_shared_world_cache", None)
    monkeypatch.setattr("maverick.world_model.open_world", lambda: first if os.environ["MAVERICK_PG_DSN"] == "host=first.invalid" else second)
    try:
        monkeypatch.setenv("MAVERICK_PG_DSN", "host=first.invalid")
        held = cap.reserve("openai", 3, now=0, request_id="original-authority")
        monkeypatch.setenv("MAVERICK_PG_DSN", "host=second.invalid")
        assert cap.check("openai", now=0).reserved == 0
        cap.settle(held, 2)
        assert first.get_provider_spend(held.period, "openai") == 2
        assert second.get_provider_spend(held.period, "openai") == 0
    finally:
        first.close()
        second.close()


def test_shared_transaction_retains_legacy_spend_and_serializes_separate_connections(ledger, monkeypatch, tmp_path):
    from maverick.world_model import WorldModel
    first = WorldModel(tmp_path / "shared.db")
    second = WorldModel(tmp_path / "shared.db")
    try:
        period = first.provider_cap_period("day")
        first.add_provider_spend(period, "openai", 18)
        monkeypatch.setattr(cap, "_shared_world", lambda: first)
        one = cap.reserve("openai", 2, now=0, request_id="shared-one")
        monkeypatch.setattr(cap, "_shared_world", lambda: second)
        with pytest.raises(cap.ProviderCapExceeded):
            cap.reserve("openai", 2, now=0, request_id="shared-two")
        cap.settle(one, 1)
        cap.settle(one, 1)
        assert cap.check("openai", now=0).spent == 19
        assert not ledger.exists()
    finally:
        first.close()
        second.close()


def test_shared_authority_uses_database_clock_for_current_window(
    ledger,
    monkeypatch,
    tmp_path,
):
    from maverick.world_model import WorldModel

    shared = WorldModel(tmp_path / "clock-authority.db")
    monkeypatch.setattr(cap, "_shared_world", lambda: shared)
    monkeypatch.setattr(cap, "period_key", lambda *_args, **_kwargs: "1999-12-31")
    try:
        authoritative = shared.provider_cap_period("day")
        held = cap.reserve("openai", 2, now=0, request_id="skewed-node-clock")
        assert held.period == authoritative
        assert held.period != "1999-12-31"
        assert cap.check("openai", now=0).reserved == 2
        assert shared.get_provider_spend(authoritative, "openai") == 2
        assert not ledger.exists()
    finally:
        shared.close()


def test_actual_process_crash_retains_provider_capacity(ledger):
    import subprocess
    import sys

    cap.record("openai", 18, path=ledger, now=0)
    source = """
import os, sys
from pathlib import Path
from maverick import provider_cost_cap as c
c.caps_from_config=lambda: {'openai':20.0}
c.period_from_config=lambda: 'day'
c.reserve('openai',2,path=Path(sys.argv[1]),now=0,request_id='crashed-process')
os._exit(0)
"""
    completed = subprocess.run([sys.executable, "-c", source, str(ledger)],
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert cap.check("openai", path=ledger, now=0).reserved == 2
    with pytest.raises(cap.ProviderCapExceeded):
        cap.reserve("openai", 1, path=ledger, now=0, request_id="new-process")


def test_process_restart_cannot_replay_stable_operation_attempt(ledger):
    import subprocess
    import sys

    first = """
import os, sys
from pathlib import Path
from maverick import provider_cost_cap as c
from maverick.paths import tenant_scope
with tenant_scope(tenant='process-tenant'):
    c.reserve(
        'openai', 1, path=Path(sys.argv[1]), now=0,
        request_id='process-first', work_item_id='goal:process-replay',
        operation_id='process-stable-operation', category='inference', attempt_no=1,
    )
os._exit(0)
"""
    second = """
import sys
from pathlib import Path
from maverick import provider_cost_cap as c
from maverick.paths import tenant_scope
with tenant_scope(tenant='process-tenant'):
    try:
        c.reserve(
            'anthropic', 1, path=Path(sys.argv[1]), now=86400,
            request_id='process-second', work_item_id='goal:process-replay',
            operation_id='process-stable-operation', category='inference', attempt_no=1,
        )
    except c.ProviderAttemptAlreadyAdmitted as exc:
        assert exc.existing_reference.startswith('provider-cap:v1:')
    else:
        raise SystemExit('stable attempt replay was admitted')
"""
    completed = subprocess.run(
        [sys.executable, "-c", first, str(ledger)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    replay = subprocess.run(
        [sys.executable, "-c", second, str(ledger)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert replay.returncode == 0, replay.stderr


@pytest.fixture
def dispatcher(ledger, monkeypatch):
    from maverick import llm

    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-09-06")
    monkeypatch.setattr(llm, "_estimate_call_cost", lambda *a, **kw: 2.0)
    # Capacity tests use a synthetic, non-billable model identity.
    monkeypatch.setattr(llm, "_lookup_price_quote", lambda _spec: None)
    monkeypatch.setattr(llm, "_run_preflight", lambda *a, **kw: None)
    monkeypatch.setattr(llm, "_enforce_circuit", lambda *a: None)
    monkeypatch.setattr(llm, "_hedge_ms", lambda: None)
    monkeypatch.setattr("maverick.budget._lookup_price", lambda _model, **_kw: (1_000_000, 0))
    # Attempt prices now come from the quote itself; keep its provenance
    # (an estimate for this synthetic model) and only fix the synthetic rate.
    from dataclasses import replace as _replace

    from maverick import budget as _budget
    _real_quote = _budget._lookup_price_quote
    monkeypatch.setattr(_budget, "_lookup_price_quote", lambda model, **kw: _replace(
        _real_quote(model, **kw), input_per_mtok=1_000_000, output_per_mtok=0))
    cap.record("openai", 18, path=ledger)
    return llm.LLM(model="openai:synthetic-cap-model")


def _response():
    from types import SimpleNamespace
    return SimpleNamespace(text="synthetic", raw=SimpleNamespace(usage=SimpleNamespace(
        prompt_tokens=1, completion_tokens=0)), cache_read_tokens=0, cache_creation_tokens=0)


def test_sync_dispatch_without_budget_reserves_and_prices_actual_response(dispatcher, ledger, monkeypatch):
    from threading import Event
    entered, finish = Event(), Event()
    calls = []

    class Client:
        def complete(self, **_kwargs):
            calls.append(1)
            entered.set()
            assert finish.wait(5)
            return _response()

    monkeypatch.setattr(dispatcher, "_get_client", lambda _: Client())
    with ThreadPoolExecutor(max_workers=1) as pool:
        call = pool.submit(dispatcher.complete, "synthetic", [])
        assert entered.wait(5)
        try:
            with pytest.raises(cap.ProviderCapExceeded):
                dispatcher.complete("synthetic", [])
        finally:
            finish.set()
        assert call.result(timeout=5).text == "synthetic"
    assert len(calls) == 1
    assert cap.check("openai", path=ledger).spent == 19
    assert cap.check("openai", path=ledger).reserved == 0


def test_async_hedge_needs_separate_provider_capacity(dispatcher, ledger, monkeypatch):
    import asyncio

    from maverick import llm
    calls = []

    class Client:
        async def complete_async(self, **_kwargs):
            calls.append(1)
            await asyncio.sleep(0.03)
            return _response()

    monkeypatch.setattr(dispatcher, "_get_client", lambda _: Client())
    monkeypatch.setattr(llm, "_hedge_ms", lambda: 1)
    assert asyncio.run(dispatcher.complete_async("synthetic", [])).text == "synthetic"
    assert len(calls) == 1
    assert cap.check("openai", path=ledger).spent == 19


def test_cancelled_physical_attempt_retains_ambiguous_charge(dispatcher, ledger, monkeypatch):
    import asyncio

    from maverick import llm

    # A fresh provider period has room for both physical calls.
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"openai": 25.0})
    calls = []

    class Client:
        async def complete_async(self, **_kwargs):
            calls.append(1)
            if len(calls) == 1:
                await asyncio.sleep(5)
            return _response()

    monkeypatch.setattr(dispatcher, "_get_client", lambda _: Client())
    monkeypatch.setattr(llm, "_hedge_ms", lambda: 1)
    assert asyncio.run(dispatcher.complete_async("synthetic", [])).text == "synthetic"
    state = cap.check("openai", path=ledger)
    assert len(calls) == 2 and state.spent == 19 and state.reserved == 2 and state.unresolved
    with pytest.raises(cap.ProviderAccountingUnavailable):
        dispatcher.complete("synthetic", [])
