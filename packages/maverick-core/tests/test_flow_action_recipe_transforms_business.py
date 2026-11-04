"""Independent numerical oracle and real local business effects for recipe v2."""
from __future__ import annotations

import copy
import itertools
import json
import multiprocessing
import time

from maverick import audit
from maverick.flow import action_recipe, composed_operator, store

from test_support.action_transforms_native import (
    INVOICE,
    LOOKUP,
    ORDER,
    TOOLS,
    oracle,
    replay_in_fresh_worker,
)
from test_support.action_transforms_native import (
    transformed_business as transformed_business,
)


def _flat(catalog, inputs, prior):
    values = {}
    for entry in catalog:
        value = inputs if entry["source"] == "input" else prior[entry["step"]]
        for key in entry["path"]:
            value = value[key]
        values[entry["name"]] = value
    return values


def _derives(child, expression):
    """Independent membership check of one explicit witness, not a learner."""
    def state_has(index, term):
        for production in child["states"][index]["alternatives"]:
            if production[0] != term[0]:
                continue
            if production[0] in {"field", "literal"}:
                if production[1] == term[1]:
                    return True
            elif len(production) == len(term) and all(
                state_has(part, subtree) for part, subtree in zip(production[1:], term[1:], strict=True)
            ):
                return True
        return False

    return any(state_has(index, expression) for index in child["roots"])


def _amount(artifact):
    step = artifact["steps"][2]
    binding = next(item for item in step["bindings"] if item["path"] == ["amount_cents"])
    assert binding["kind"] == "composed"
    return binding["artifact"], step["catalog"]


def _source_name(catalog, source, path, step=None):
    return next(item["name"] for item in catalog
                if item["source"] == source and item["path"] == path and item.get("step") == step)


def _calls(backend, offset):
    return [row["tool"] for row in backend.rows("attempts")[offset:]]


def test_observed_coincidence_partial_stop_refinement_and_567_case_business_oracle(transformed_business, record_property):
    harness = transformed_business
    backend = harness.business
    episodes = harness.coincident_episodes()
    assert len(harness.approvals) == 3 * len(episodes)
    started = time.perf_counter()
    artifact = harness.learn(episodes)
    synthesis_seconds = time.perf_counter() - started
    original = copy.deepcopy(artifact)
    assert artifact["schema"] == "lightwork.action-recipe.v2"
    child, catalog = _amount(artifact)
    assert len(catalog) == 6
    q = _source_name(catalog, "input", ["quantity"])
    d = _source_name(catalog, "input", ["discount_cents"])
    p = _source_name(catalog, "result", ["unit_price_cents"], 0)
    quote = _source_name(catalog, "result", ["quoted_total_cents"], 0)
    # Both independent witnesses must survive the same observed labels. The
    # formula below is a test assertion only; synthesis received no expression.
    assert _derives(child, ("field", quote))
    assert _derives(child, ("sub", ("mul", ("field", q), ("field", p)), ("field", d)))
    held_inputs = {"customer_ref": "customer-probe", "quantity": 2, "discount_cents": 1}
    held_prior = [{"unit_price_cents": 4, "quoted_total_cents": 0}, {"order_id": "order-probe"}]
    partitions = composed_operator.partitions(child, _flat(catalog, held_inputs, held_prior))
    assert {row["output"] for row in partitions}.issuperset({0, 7})
    assert action_recipe.resolve_step(artifact, 2, held_inputs, held_prior).reason == "ambiguity"

    flow = harness.draft(artifact, "coincident")
    inputs = backend.seed("stale-quote", 2, 4, 1, quote=0)
    before_orders, before_invoices = len(backend.rows("orders")), len(backend.rows("invoices"))
    offset = len(backend.rows("attempts"))
    stopped = harness.execute(flow, inputs, "transform-stale-quote")
    assert stopped.status == "indeterminate", stopped.error
    assert _calls(backend, offset) == [LOOKUP, ORDER]
    assert len(backend.rows("orders")) == before_orders + 1
    assert len(backend.rows("invoices")) == before_invoices
    committed_order = backend.rows("orders")[-1]
    assert stopped.data["_recipe_step_1"]["order_id"] == committed_order["order_id"]
    assert "_recipe_step_2" not in stopped.data
    assert harness.execute(flow, inputs, stopped.run_id).status == "indeterminate"
    worker = multiprocessing.get_context("spawn").Process(
        target=replay_in_fresh_worker, args=(str(backend.path), stopped.run_id),
    )
    worker.start()
    worker.join(45)
    if worker.is_alive():
        worker.terminate()
        worker.join(5)
        raise AssertionError("fresh native redelivery worker timed out")
    assert worker.exitcode == 0
    assert _calls(backend, offset) == [LOOKUP, ORDER]
    assert backend.rows("orders")[-1] == committed_order

    additional = harness.counterexamples()
    assert all(row["steps"][0]["result"]["quoted_total_cents"] != row["steps"][2]["arguments"]["amount_cents"]
               for row in additional)
    started = time.perf_counter()
    refined = action_recipe.refine(artifact, additional)
    refinement_seconds = time.perf_counter() - started
    assert artifact == original and refined["artifact_sha256"] != artifact["artifact_sha256"]
    refined_child, refined_catalog = _amount(refined)
    assert refined_child["candidate_count"] < child["candidate_count"]
    refined_quote = _source_name(refined_catalog, "result", ["quoted_total_cents"], 0)
    assert not _derives(refined_child, ("field", refined_quote))

    applied, abstentions = 0, []
    for quantity, price, discount, quoted in itertools.product(range(1, 4), range(3, 6), range(3), range(21)):
        inputs = {"customer_ref": "customer-new-oracle", "quantity": quantity, "discount_cents": discount}
        prior = [{"unit_price_cents": price, "quoted_total_cents": quoted}, {"order_id": "order-new-oracle"}]
        decision = action_recipe.resolve_step(refined, 2, inputs, prior)
        if decision.applied:
            applied += 1
            assert decision.arguments == {"order_id": "order-new-oracle", "amount_cents": oracle(quantity, price, discount)}
            assert type(decision.arguments["amount_cents"]) is int
        else:
            abstentions.append((quantity, price, discount, quoted, decision.reason))
    assert applied == 567 and abstentions == [], {"applied": applied, "abstentions": abstentions[:10]}

    fresh_flow = harness.draft(refined, "refined")
    training_ids = {step["result"][key] for row in [*episodes, *additional] for step in row["steps"]
                    for key in ("order_id", "invoice_id") if key in step["result"]}
    fresh_ids = set()
    for index, (quantity, price, discount, quoted) in enumerate([(1, 5, 2, 0), (2, 4, 0, 20), (3, 3, 2, 1)]):
        inputs = backend.seed(f"fresh-native-{index}", quantity, price, discount, quoted)
        offset = len(backend.rows("attempts"))
        run = harness.execute(fresh_flow, inputs, f"transform-fresh-{index}")
        assert run.status == "completed", run.error
        assert _calls(backend, offset) == TOOLS
        invoice = backend.assert_invoice(inputs, run.data["_recipe_step_2"])
        identifiers = {invoice["order_id"], invoice["invoice_id"]}
        assert identifiers.isdisjoint(training_ids | fresh_ids)
        fresh_ids.update(identifiers)
        saved = store.load_run(run.run_id)
        assert saved.status == "completed" and saved.data == run.data
        assert store.load_flow_snapshot(saved.definition_digest).learned_recipe == refined
        assert harness.execute(fresh_flow, inputs, run.run_id).status == "completed"
        assert _calls(backend, offset) == TOOLS

    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    decisions = [event for event in events if event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION]
    blocked = [event for event in decisions if event.get("flow_run_id") == stopped.run_id
               and event.get("status") == "blocked"]
    assert blocked and blocked[-1]["reason"] == "ambiguity" and blocked[-1]["step_index"] == 2
    for event in decisions:
        assert event["sig"] and len(event["artifact_sha256"]) == 64
        assert "arguments" not in event and "episodes" not in event and "input" not in event
    calls = [event for event in events if event["kind"] == audit.EventKind.TOOL_CALL and event.get("name") in TOOLS]
    results = [event for event in events if event["kind"] == audit.EventKind.TOOL_RESULT and event.get("name") in TOOLS]
    assert len(calls) == len(backend.rows("attempts")) == len(results)
    assert {event["call_id"] for event in calls} == {event["call_id"] for event in results}
    assert all(event["sig"] for event in calls + results)
    record_property("native_business_evidence", json.dumps({
        "initial_observed_episodes": len(episodes), "additional_observed_episodes": len(additional),
        "initial_amount_syntax_count": child["candidate_count"],
        "refined_amount_syntax_count": refined_child["candidate_count"],
        "initial_artifact_sha256": artifact["artifact_sha256"],
        "refined_artifact_sha256": refined["artifact_sha256"],
        "initial_synthesis_seconds": synthesis_seconds, "refinement_seconds": refinement_seconds,
        "numeric_oracle_cases": 567, "applied": applied, "abstained": len(abstentions), "wrong": 0,
        "partial_stop_native_calls": [LOOKUP, ORDER], "fresh_redelivery_worker_exitcode": worker.exitcode,
        "fresh_native_completions": 3, "fresh_generated_ids": sorted(fresh_ids),
        "native_call_receipts": len(calls), "native_terminal_receipts": len(results),
    }, sort_keys=True))


def test_actual_out_of_domain_lookup_result_stops_before_order_creation(transformed_business):
    harness = transformed_business
    episodes = harness.coincident_episodes()
    artifact = harness.learn(episodes)
    flow = harness.draft(artifact, "domain-result")
    inputs = harness.business.seed("bad-price-domain", 2, 6, 1, quote=11)
    before_orders = len(harness.business.rows("orders"))
    offset = len(harness.business.rows("attempts"))
    run = harness.execute(flow, inputs, "transform-bad-price")
    assert run.status == "indeterminate", run.error
    assert _calls(harness.business, offset) == [LOOKUP]
    assert len(harness.business.rows("orders")) == before_orders
    assert "_recipe_step_0" not in run.data
    assert harness.execute(flow, inputs, run.run_id).status == "indeterminate"
    assert _calls(harness.business, offset) == [LOOKUP]


def test_invoice_lost_ack_preserves_committed_amount_without_replay(transformed_business):
    harness = transformed_business
    artifact = harness.learn([*harness.coincident_episodes(), *harness.counterexamples()])
    flow = harness.draft(artifact, "lost-invoice-ack")
    inputs = harness.business.seed("lost-invoice", 3, 5, 1, quote=0)
    harness.business.faults[INVOICE] = "lost_ack"
    offset = len(harness.business.rows("attempts"))
    run = harness.execute(flow, inputs, "transform-lost-ack")
    assert run.status == "indeterminate", run.error
    assert _calls(harness.business, offset) == TOOLS
    invoice = harness.business.rows("invoices")[-1]
    harness.business.assert_invoice(inputs, {"invoice_id": invoice["invoice_id"]})
    assert "_recipe_step_2" not in run.data
    assert harness.execute(flow, inputs, run.run_id).status == "indeterminate"
    assert _calls(harness.business, offset) == TOOLS
    # Confirm the exact acknowledged-prefix order, not an inferred replacement.
    assert invoice["order_id"] == run.data["_recipe_step_1"]["order_id"]
    assert json.loads(harness.business.rows("attempts")[-1]["arguments"])["amount_cents"] == 14
