"""Bounded customer-commitment feasibility and owner-reviewed learning edges."""
from __future__ import annotations

from dataclasses import replace

import pytest
from maverick.commitment_viability import (
    Commitment,
    Demand,
    Evidence,
    Lot,
    ReversibleOption,
    Snapshot,
    TraceObservation,
    assess,
    confirm_dependency,
    confirm_option,
    explain_resource_gaps,
    propose_shared_dependencies,
    recompute_after_dependency,
)

NOW = 1_000.0
FRESH = 3_000.0


def proof(source: str, *, revision: str = "v1", expires_at: float = FRESH) -> Evidence:
    return Evidence(source, revision, 900.0, expires_at)


def versions(*evidence: Evidence) -> dict[str, str]:
    return {item.source_id: item.revision for item in evidence}


def basic_snapshot() -> tuple[Snapshot, dict[str, str]]:
    order_a, order_b = proof("order-a"), proof("order-b")
    press, stock, supplier = proof("press"), proof("stock"), proof("supplier")
    snapshot = Snapshot(
        1,
        (
            Commitment("a", 2_000, (Demand("capacity", "press", 1), Demand("material", "m", 1)), order_a),
            Commitment("b", 2_000, (Demand("capacity", "press", 1), Demand("material", "m", 1)), order_b),
        ),
        (
            Lot("press-capacity", "capacity", "press", 2, 900, "confirmed", press),
            Lot("stock-one", "material", "m", 1, 900, "confirmed", stock),
        ),
        (ReversibleOption("supplier-hold", "material", "m", 1, 1_100, 1_200,
                          supplier, "Supplier may charge for the hold"),),
    )
    return snapshot, versions(order_a, order_b, press, stock, supplier)


def test_conditional_option_is_not_a_reserved_lot_even_after_owner_confirmation():
    snapshot, current = basic_snapshot()
    before = assess(snapshot, now=NOW, current_source_revisions=current)
    assert before.status == "infeasible"
    assert before.latest_safe_bundle_decision_at == 1_200
    assert before.components[0].plans[0].conditional_status == "feasible"
    assert before.components[0].plans[0].requires_owner_confirmation is True
    assert before.components[0].plans[0].external_effect_verified is False

    confirmed = confirm_option(snapshot, "supplier-hold", actor="owner-1",
                               expected_revision=1, now=NOW,
                               current_source_revisions=current)
    after = assess(confirmed, now=NOW, current_source_revisions=current)
    assert after.status == "infeasible"
    assert after.components[0].plans[0].requires_owner_confirmation is False
    assert after.components[0].plans[0].external_effect_verified is False

    provider_receipt = proof("provider-receipt")
    observed = replace(confirmed, revision=3, lots=(*confirmed.lots,
                       Lot("observed-hold", "material", "m", 1, 1_100,
                           "confirmed", provider_receipt)))
    current[provider_receipt.source_id] = provider_receipt.revision
    assert assess(observed, now=NOW, current_source_revisions=current).status == "feasible"


def test_resource_gap_separates_confirmed_shortfall_from_conditional_supply():
    snapshot, current = basic_snapshot()
    gap, = explain_resource_gaps(snapshot, now=NOW, current_source_revisions=current)
    assert (gap.kind, gap.key, gap.confirmed_shortfall_units,
            gap.remaining_shortfall_units) == ("material", "m", 1, 0)
    assert gap.first_shortfall_at == 2_000
    assert gap.option_ids == ("supplier-hold",)

    late = replace(snapshot.options[0], ready_at=2_100)
    gap, = explain_resource_gaps(replace(snapshot, options=(late,)), now=NOW,
                                current_source_revisions=current)
    assert gap.remaining_shortfall_units == 1
    assert gap.remaining_first_shortfall_at == 2_000

    unknown = replace(snapshot.lots[1], certainty="unknown")
    gap, = explain_resource_gaps(replace(snapshot, lots=(snapshot.lots[0], unknown), options=()),
                                now=NOW, current_source_revisions=current)
    assert gap.confirmed_shortfall_units == 2
    assert gap.remaining_shortfall_units == 1
    assert gap.conditional_source_ids == ("stock",)
    assert explain_resource_gaps(snapshot, now=2_001, current_source_revisions=current) == ()
    current["order-a"] = "changed"
    assert explain_resource_gaps(snapshot, now=NOW, current_source_revisions=current) == ()


def test_resource_gap_uses_peak_cumulative_deficit_across_deadlines():
    first, second, supply = proof("first"), proof("second"), proof("supply")
    snapshot = Snapshot(1, (
        Commitment("first", 1_100, (Demand("material", "m", 2),), first),
        Commitment("second", 2_000, (Demand("material", "m", 3),), second),
    ), (Lot("one", "material", "m", 1, 900, "confirmed", supply),))
    gap, = explain_resource_gaps(snapshot, now=NOW,
                                current_source_revisions=versions(first, second, supply))
    assert gap.first_shortfall_at == 1_100
    assert gap.confirmed_shortfall_units == 4
    assert gap.remaining_shortfall_units == 4


def test_source_staleness_and_uncertain_stock_are_never_counted_as_confirmed():
    snapshot, current = basic_snapshot()
    without_option = replace(snapshot, options=())
    unknown_lot = replace(without_option.lots[1], certainty="unknown")
    uncertain = replace(without_option, lots=(without_option.lots[0], unknown_lot,
                        Lot("possible-stock", "material", "m", 1, 900, "unknown", proof("possible"))))
    current["possible"] = "v1"
    assert assess(uncertain, now=NOW, current_source_revisions=current).status == "unknown"

    enough = replace(without_option, lots=(*without_option.lots,
                     Lot("stock-two", "material", "m", 1, 900, "confirmed", proof("second"))))
    current["second"] = "v1"
    assert assess(enough, now=NOW, current_source_revisions=current).status == "feasible"
    current["second"] = "v2"
    changed = assess(enough, now=NOW, current_source_revisions=current)
    assert changed.status == "unknown"
    assert changed.stale_source_ids == ("second",)
    current["order-a"] = "v2"
    after_due = assess(enough, now=2_001, current_source_revisions=current)
    assert after_due.status == "unknown"  # the accepted obligation itself changed


def test_expired_option_or_late_supply_cannot_rescue_a_promise():
    snapshot, current = basic_snapshot()
    assert assess(snapshot, now=1_200, current_source_revisions=current).components[0].plans == ()
    too_late = replace(snapshot.options[0], ready_at=2_100)
    assert assess(replace(snapshot, options=(too_late,)), now=NOW,
                  current_source_revisions=current).components[0].plans == ()
    past_due = assess(snapshot, now=2_001, current_source_revisions=current)
    assert past_due.status == "infeasible"
    assert past_due.latest_safe_bundle_decision_at is None


def test_a_later_pool_cannot_cover_an_earlier_deadline():
    first, second, capacity = proof("early"), proof("late"), proof("capacity")
    snapshot = Snapshot(1, (
        Commitment("early", 1_100, (Demand("capacity", "press", 1),), first),
        Commitment("late", 2_000, (Demand("capacity", "press", 1),), second),
    ), (Lot("late-capacity", "capacity", "press", 2, 1_200, "confirmed", capacity),))
    assert assess(snapshot, now=NOW,
                  current_source_revisions=versions(first, second, capacity)).status == "infeasible"


def test_two_conditional_paths_require_the_earliest_expiring_decision():
    snapshot, current = basic_snapshot()
    needed = replace(snapshot.commitments[1], demands=(Demand("capacity", "press", 1),
                     Demand("material", "m", 1), Demand("material", "n", 1)))
    second = ReversibleOption("second-hold", "material", "n", 1, 1_100, 1_150,
                              proof("second-supplier"))
    current["second-supplier"] = "v1"
    snapshot = replace(snapshot, commitments=(snapshot.commitments[0], needed),
                       options=(*snapshot.options, second))
    result = assess(snapshot, now=NOW, current_source_revisions=current)
    assert result.status == "infeasible"
    assert result.components[0].plans[0].option_ids == ("supplier-hold", "second-hold")
    assert result.latest_safe_bundle_decision_at == 1_150


def test_future_owner_confirmation_is_not_displayed_as_current_authority():
    snapshot, current = basic_snapshot()
    confirmed = confirm_option(snapshot, "supplier-hold", actor="owner-1",
                               expected_revision=1, now=1_100,
                               current_source_revisions=current)
    result = assess(confirmed, now=NOW, current_source_revisions=current)
    assert result.components[0].plans[0].requires_owner_confirmation is True


def test_option_cannot_be_confirmed_without_a_current_timely_feasible_path():
    snapshot, current = basic_snapshot()
    too_slow = replace(snapshot.options[0], lead_seconds=1_000)
    snapshot = replace(snapshot, options=(too_slow,))
    assert assess(snapshot, now=1_199, current_source_revisions=current).components[0].plans == ()
    with pytest.raises(ValueError, match="no current feasible path"):
        confirm_option(snapshot, "supplier-hold", actor="owner-1",
                       expected_revision=1, now=1_199,
                       current_source_revisions=current)


def test_latest_safe_bundle_decision_respects_due_time_evidence_and_action_lead():
    snapshot, current = basic_snapshot()
    soon = replace(snapshot.options[0], evidence=proof("supplier", expires_at=1_050),
                   expires_at=3_000, lead_seconds=100)
    early_orders = tuple(replace(item, due_at=1_180) for item in snapshot.commitments)
    result = assess(replace(snapshot, commitments=early_orders,
                            options=(soon,)), now=NOW, current_source_revisions=current)
    assert result.status == "infeasible"
    assert result.latest_safe_bundle_decision_at == 1_050

    long_evidence = replace(soon, evidence=proof("supplier"))
    deadline_result = assess(replace(snapshot, commitments=early_orders,
                                     options=(long_evidence,)), now=NOW,
                             current_source_revisions=current)
    assert deadline_result.latest_safe_bundle_decision_at == 1_080


def learning_snapshot() -> tuple[Snapshot, tuple[TraceObservation, ...], dict[str, str]]:
    a, b, c = proof("accepted-a"), proof("accepted-b"), proof("accepted-c")
    material_a, material_b, material_c, press = (
        proof("material-a"), proof("material-b"), proof("material-c"), proof("press-observed")
    )
    trace_a = Evidence("trace-a", "v1", 995, FRESH)
    trace_b = Evidence("trace-b", "v1", 995, FRESH)
    snapshot = Snapshot(4, (
        Commitment("a", 2_000, (Demand("material", "ma", 1),), a),
        Commitment("b", 2_000, (Demand("material", "mb", 1),), b),
        Commitment("c", 2_000, (Demand("material", "mc", 1),), c),
    ), (
        Lot("material-a", "material", "ma", 1, 900, "confirmed", material_a),
        Lot("material-b", "material", "mb", 1, 900, "confirmed", material_b),
        Lot("material-c", "material", "mc", 1, 900, "confirmed", material_c),
        Lot("shared-press", "capacity", "press", 1, 900, "confirmed", press),
    ))
    traces = (
        TraceObservation("trace-a-1", "a", "press", 1, 950, 980, False, trace_a),
        TraceObservation("trace-b-1", "b", "press", 1, 960, 990, True, trace_b),
    )
    return snapshot, traces, versions(a, b, c, material_a, material_b, material_c,
                                      press, trace_a, trace_b)


def test_observed_contention_requires_owner_confirmation_and_recomputes_only_linked_group():
    snapshot, traces, current = learning_snapshot()
    before = assess(snapshot, now=NOW, current_source_revisions=current)
    assert before.status == "feasible"
    assert tuple(item.commitment_ids for item in before.components) == (("a",), ("b",), ("c",))
    (proposal,) = propose_shared_dependencies(snapshot, traces, now=NOW,
                                              current_source_revisions=current)
    assert proposal.resource_key == "press"
    after_snapshot = confirm_dependency(snapshot, proposal, traces, actor="owner-1",
                                        expected_revision=4, now=NOW,
                                        current_source_revisions=current)
    after = recompute_after_dependency(before, snapshot, after_snapshot, now=NOW,
                                       current_source_revisions=current)
    assert after.status == "infeasible"
    assert after.recomputed_commitment_ids == ("a", "b")
    assert after.components[0].commitment_ids == ("a", "b")
    assert after.components[1] is before.components[2]
    assert assess(after_snapshot, now=NOW, current_source_revisions=current) == replace(
        after, recomputed_commitment_ids=("a", "b", "c"))


def test_confirmed_shared_work_cannot_be_suggested_or_appended_again():
    snapshot, traces, current = learning_snapshot()
    (proposal,) = propose_shared_dependencies(snapshot, traces, now=NOW,
                                              current_source_revisions=current)
    confirmed = confirm_dependency(snapshot, proposal, traces, actor="owner-1",
                                   expected_revision=snapshot.revision, now=NOW,
                                   current_source_revisions=current)
    assert propose_shared_dependencies(confirmed, traces, now=NOW,
                                       current_source_revisions=current) == ()
    with pytest.raises(ValueError, match="evidence changed"):
        confirm_dependency(confirmed, proposal, traces, actor="owner-1",
                           expected_revision=confirmed.revision, now=NOW,
                           current_source_revisions=current)
    with pytest.raises(ValueError, match="shared dependencies must be unique"):
        replace(confirmed, dependencies=(*confirmed.dependencies, confirmed.dependencies[0]))


def test_changed_trace_or_snapshot_refuses_stale_dependency_confirmation():
    snapshot, traces, current = learning_snapshot()
    (proposal,) = propose_shared_dependencies(snapshot, traces, now=NOW,
                                              current_source_revisions=current)
    with pytest.raises(ValueError, match="snapshot changed"):
        confirm_dependency(snapshot, proposal, traces, actor="owner-1",
                           expected_revision=3, now=NOW, current_source_revisions=current)
    current["trace-b"] = "v2"
    assert propose_shared_dependencies(snapshot, traces, now=NOW,
                                       current_source_revisions=current) == ()
    with pytest.raises(ValueError, match="evidence changed"):
        confirm_dependency(snapshot, proposal, traces, actor="owner-1",
                           expected_revision=4, now=NOW, current_source_revisions=current)


def test_future_or_changed_trace_cannot_be_confirmed_as_the_reviewed_content():
    snapshot, traces, current = learning_snapshot()
    (proposal,) = propose_shared_dependencies(snapshot, traces, now=NOW,
                                              current_source_revisions=current)
    changed_interval = (traces[0], replace(traces[1], start_at=970))
    with pytest.raises(ValueError, match="evidence changed"):
        confirm_dependency(snapshot, proposal, changed_interval, actor="owner-1",
                           expected_revision=4, now=NOW, current_source_revisions=current)
    future = (traces[0], replace(traces[1], start_at=5_000, end_at=5_010))
    assert propose_shared_dependencies(snapshot, future, now=NOW,
                                       current_source_revisions=current) == ()


def test_unavailable_or_stale_resource_does_not_support_new_dependency():
    snapshot, traces, current = learning_snapshot()
    unavailable_lots = tuple(replace(item, certainty="unavailable") if item.id == "shared-press"
                             else item for item in snapshot.lots)
    assert propose_shared_dependencies(replace(snapshot, lots=unavailable_lots), traces,
                                       now=NOW, current_source_revisions=current) == ()
    current["press-observed"] = "v2"
    assert propose_shared_dependencies(snapshot, traces, now=NOW,
                                       current_source_revisions=current) == ()


def test_incremental_recompute_rejects_changed_source_revisions_or_clock():
    snapshot, traces, current = learning_snapshot()
    before = assess(snapshot, now=NOW, current_source_revisions=current)
    (proposal,) = propose_shared_dependencies(snapshot, traces, now=NOW,
                                              current_source_revisions=current)
    updated = confirm_dependency(snapshot, proposal, traces, actor="owner-1",
                                 expected_revision=4, now=NOW, current_source_revisions=current)
    with pytest.raises(ValueError, match="exact unchanged"):
        recompute_after_dependency(before, snapshot, updated, now=NOW + 1,
                                   current_source_revisions=current)
    changed = {**current, "press-observed": "v2"}
    with pytest.raises(ValueError, match="exact unchanged"):
        recompute_after_dependency(before, snapshot, updated, now=NOW,
                                   current_source_revisions=changed)
    mutated_same_revision = replace(snapshot, lots=tuple(
        item for item in snapshot.lots if item.id != "material-c"
    ))
    with pytest.raises(ValueError, match="evidence changed"):
        confirm_dependency(mutated_same_revision, proposal, traces, actor="owner-1",
                           expected_revision=4, now=NOW,
                           current_source_revisions=current)
    altered = replace(mutated_same_revision, revision=5, dependencies=updated.dependencies)
    with pytest.raises(ValueError, match="exact unchanged"):
        recompute_after_dependency(before, mutated_same_revision, altered, now=NOW,
                                   current_source_revisions=current)


def test_invalid_units_or_duplicate_demand_fail_closed():
    with pytest.raises(ValueError, match="units"):
        Demand("capacity", "press", 0)
    order = proof("order")
    with pytest.raises(ValueError, match="unique"):
        Commitment("order", 2_000, (Demand("material", "m", 1),
                                    Demand("material", "m", 2)), order)


def _authored_robust_scheduler(snapshot: Snapshot) -> bool:
    """Independent exhaustive baseline for small fully observed schedules."""
    needs = sorted((item.due_at, part.kind, part.key)
                   for item in snapshot.commitments for part in item.demands
                   for _ in range(part.units))
    remaining = {lot.id: lot.units for lot in snapshot.lots}

    def place(index: int) -> bool:
        if index == len(needs):
            return True
        due, kind, key = needs[index]
        for lot in snapshot.lots:
            if (lot.kind, lot.key) != (kind, key) or lot.ready_at > due or remaining[lot.id] == 0:
                continue
            remaining[lot.id] -= 1
            if place(index + 1):
                return True
            remaining[lot.id] += 1
        return False

    return place(0)


def test_bounded_model_matches_an_authored_robust_scheduler_with_identical_facts():
    """Useful correctness comparator; matching it establishes no new algorithm."""
    accepted = (proof("order-a"), proof("order-b"), proof("order-c"))
    source = proof("finite-capacity")
    material = proof("known-stock")
    current = versions(*accepted, source, material)
    commitments = tuple(Commitment(name, due,
                                   (Demand("capacity", "press", 1),
                                    Demand("material", "m", 1)), evidence)
                        for name, due, evidence in zip(("a", "b", "c"),
                                                       (1_100, 2_000, 2_000),
                                                       accepted, strict=True))
    for early_capacity in range(3):
        for later_capacity in range(3):
            for stock_units in range(1, 4):
                lots = [Lot("stock", "material", "m", stock_units, 900,
                            "confirmed", material)]
                if early_capacity:
                    lots.append(Lot("early-press", "capacity", "press",
                                    early_capacity, 900, "confirmed", source))
                if later_capacity:
                    lots.append(Lot("late-press", "capacity", "press",
                                    later_capacity, 1_200, "confirmed", source))
                snapshot = Snapshot(1, commitments, tuple(lots))
                expected = _authored_robust_scheduler(snapshot)
                result = assess(snapshot, now=NOW, current_source_revisions=current)
                assert (result.status == "feasible") is expected
