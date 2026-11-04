"""Business examples with held-out labels, supplied without intermediate steps.

These fixtures deliberately require composition. They are not claims about
learning arbitrary workflows, rounding currencies, or correct business policy.
All invoice amounts are integer cents; discounts are per-unit amounts.
"""
from __future__ import annotations

import copy
import json

import pytest
from maverick import audit, config, world_model
from maverick.flow import Flow, FlowNode, evolve, execution, store
from maverick.flow import composed_operator as composed
from maverick.flow import learned_operator as scalar

INVOICE_SPEC = {
    "inputs": {
        "qty": {"type": "integer", "min": 0, "max": 40},
        "unit_price": {"type": "integer", "min": 0, "max": 20000},
        "discount": {"type": "integer", "min": 0, "max": 5000},
        "shipping": {"type": "integer", "min": 0, "max": 3000},
    },
    "output_type": "integer",
    "constants": [],
}
INVOICE_OPERATORS = ["add", "sub", "mul"]

# Fixed before running the new engine. Every input changes independently;
# quantity zero and a zero net unit price distinguish the shipping behavior.
INVOICE_TRAINING = (
    (2, 1250, 150, 300, 2500),
    (5, 799, 99, 0, 3500),
    (1, 4500, 500, 125, 4125),
    (0, 900, 100, 700, 700),
    (3, 1000, 1000, 250, 250),
    (7, 240, 40, 800, 2200),
    (4, 1899, 0, 99, 7695),
    (12, 3050, 275, 1500, 34800),
)

# Independent expected totals, including declared-domain extremes, unseen
# quantities/prices, free units, free shipping, and all-zero input.
INVOICE_HELD_OUT = (
    (3, 850, 75, 120, 2445),
    (9, 1299, 199, 450, 10350),
    (40, 20000, 5000, 3000, 603000),
    (0, 20000, 5000, 3000, 3000),
    (11, 2500, 2500, 149, 149),
    (6, 0, 0, 200, 200),
    (1, 19999, 1, 1, 19999),
    (23, 1750, 333, 777, 33368),
    (17, 101, 1, 0, 1700),
    (2, 5000, 4999, 999, 1001),
    (31, 10000, 2500, 1200, 233700),
    (0, 0, 0, 0, 0),
)

TEXT_SPEC = {
    "inputs": {"value": {"type": "string", "max_length": 64}},
    "output_type": "string",
    "constants": [],
}
TEXT_TRAINING = (
    (" sku-17 ", "SKU-17"),
    ("\tmiXeD Case\n", "MIXED CASE"),
    ("\nÉcole\t", "ÉCOLE"),
    (" \t\n", ""),
)
TEXT_HELD_OUT = (
    ("  straße42\t", "STRASSE42"),
    ("\u00a0ab-17\u00a0", "AB-17"),
    ("  keep  inner\tspace  ", "KEEP  INNER\tSPACE"),
    ("already", "ALREADY"),
    ("UPPER", "UPPER"),
    ("", ""),
    ("\t \r\n", ""),
    ("  λογος  ", "ΛΟΓΟΣ"),
)


def invoice_row(values):
    qty, unit_price, discount, shipping, total = values
    return {
        "inputs": {
            "qty": qty,
            "unit_price": unit_price,
            "discount": discount,
            "shipping": shipping,
        },
        "output": total,
    }


def text_row(values):
    value, output = values
    return {"inputs": {"value": value}, "output": output}


@pytest.fixture(scope="module")
def invoice_artifact():
    return composed.synthesize(
        INVOICE_SPEC,
        [invoice_row(values) for values in INVOICE_TRAINING],
        max_operations=3,
        operators=INVOICE_OPERATORS,
    )


@pytest.fixture(scope="module")
def text_artifact():
    return composed.synthesize(
        TEXT_SPEC,
        [text_row(values) for values in TEXT_TRAINING],
        max_operations=2,
        operators=["strip", "upper"],
    )


def test_fixed_invoice_labels_are_independent_of_training_and_arithmetic_is_exact():
    training_inputs = {tuple(row[:4]) for row in INVOICE_TRAINING}
    assert training_inputs.isdisjoint(tuple(row[:4]) for row in INVOICE_HELD_OUT)
    for qty, unit_price, discount, shipping, total in (
        *INVOICE_TRAINING, *INVOICE_HELD_OUT
    ):
        # Check hand-calculated fixture labels; this expression is never passed
        # to either learner as an AST, hint, or intermediate label.
        assert total == qty * (unit_price - discount) + shipping


@pytest.mark.parametrize("values", INVOICE_HELD_OUT)
def test_invoice_composition_generalizes_to_unseen_business_inputs(invoice_artifact, values):
    example = invoice_row(values)
    result = composed.evaluate(invoice_artifact, example["inputs"])
    assert result.applied, result.reason
    assert result.reason == "agreement"
    assert type(result.value) is int
    assert result.value == example["output"]
    assert result.candidate_count == composed.candidate_count(invoice_artifact)


def test_invoice_requires_more_than_scalar_v1_or_two_operations():
    examples = [invoice_row(values) for values in INVOICE_TRAINING]
    with pytest.raises(ValueError, match="no program"):
        scalar.synthesize(INVOICE_SPEC, examples)
    with pytest.raises(ValueError, match="no composed program"):
        composed.synthesize(
            INVOICE_SPEC, examples, max_operations=2, operators=INVOICE_OPERATORS
        )


def test_confounded_invoice_examples_abstain_until_new_final_labels_resolve_them():
    # Unit quantity, zero discount and zero shipping leave many genuinely
    # different rules consistent. Do not choose the intended one by ranking.
    weak_examples = [
        invoice_row((1, 100, 0, 0, 100)),
        invoice_row((1, 400, 0, 0, 400)),
    ]
    weak = composed.synthesize(
        INVOICE_SPEC, weak_examples, max_operations=3, operators=INVOICE_OPERATORS
    )
    before = copy.deepcopy(weak)
    query = invoice_row(INVOICE_HELD_OUT[0])
    result = composed.evaluate(weak, query["inputs"])
    assert not result.applied
    assert result.reason == "ambiguity"
    assert result.value is None

    refined = composed.refine(
        weak, [invoice_row(values) for values in INVOICE_TRAINING]
    )
    assert weak == before
    assert composed.candidate_count(refined) < composed.candidate_count(weak)
    assert refined["artifact_sha256"] != weak["artifact_sha256"]
    for values in INVOICE_HELD_OUT:
        example = invoice_row(values)
        answer = composed.evaluate(refined, example["inputs"])
        assert answer.applied, answer.reason
        assert answer.value == example["output"]


@pytest.mark.parametrize("values", TEXT_HELD_OUT)
def test_text_composition_handles_unseen_whitespace_case_and_unicode(text_artifact, values):
    assert values[0] not in {item[0] for item in TEXT_TRAINING}
    example = text_row(values)
    result = composed.evaluate(text_artifact, example["inputs"])
    assert result.applied, result.reason
    assert result.reason == "agreement"
    assert type(result.value) is str
    assert result.value == example["output"]


def test_text_composition_requires_more_than_scalar_v1_or_one_operation():
    examples = [text_row(values) for values in TEXT_TRAINING]
    with pytest.raises(ValueError, match="no program"):
        scalar.synthesize(TEXT_SPEC, examples)
    with pytest.raises(ValueError, match="no composed program"):
        composed.synthesize(
            TEXT_SPEC, examples, max_operations=1, operators=["strip", "upper"]
        )


def test_text_examples_without_whitespace_abstain_on_unseen_outer_whitespace():
    weak = composed.synthesize(
        TEXT_SPEC,
        [text_row(("abc", "ABC")), text_row(("deF", "DEF"))],
        max_operations=2,
        operators=["strip", "upper"],
    )
    held_out = text_row((" mixed ", "MIXED"))
    decision = composed.evaluate(weak, held_out["inputs"])
    assert not decision.applied
    assert decision.reason == "ambiguity"
    refined = composed.refine(weak, [held_out])
    assert composed.candidate_count(refined) < composed.candidate_count(weak)
    after = composed.evaluate(refined, {"value": "\tother example\n"})
    assert after.applied and after.value == "OTHER EXAMPLE"


def test_invoice_runtime_guard_rejects_out_of_bounds_without_coercion(invoice_artifact):
    inputs = invoice_row(INVOICE_HELD_OUT[0])["inputs"]
    for field, value in (("qty", 41), ("shipping", -1), ("qty", True), ("unit_price", "850")):
        decision = composed.evaluate(invoice_artifact, {**inputs, field: value})
        assert not decision.applied and decision.reason == "outside_domain"


def test_text_runtime_guard_rejects_input_beyond_declared_length(text_artifact):
    result = composed.evaluate(text_artifact, {"value": "a" * 65})
    assert not result.applied and result.reason == "outside_domain"


def test_saved_invoice_flow_executes_pinned_composition_with_native_signed_receipt(
    invoice_artifact, monkeypatch, tmp_path
):
    # Native local persistence/audit under isolated pytest homes; no provider
    # runner is allowed to execute, and completion is not a quality label.
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "invoice-world.db")
    monkeypatch.setattr(
        config, "get_flows",
        lambda: {"enable": True, "learned_operators": True, "composed_operators": True},
    )
    original = Flow(
        id="reviewed-invoice", name="Reviewed invoice", owner="invoice-reviewer",
        start="calculate", nodes={
            "calculate": FlowNode(
                id="calculate", kind="agent", output="invoice_total",
                brief="Calculate the invoice total from reviewed commercial terms.",
            ),
        },
    )
    attached = evolve.attach_learned_operator(original, "calculate", invoice_artifact)
    store.save_flow(attached)
    stored_flow = store.load_flow(attached.id)
    assert stored_flow is not None
    envelope = copy.deepcopy(stored_flow.nodes["calculate"].learned_operator)
    assert envelope["artifact"] == invoice_artifact
    assert stored_flow.nodes["calculate"].brief == original.nodes["calculate"].brief
    assert stored_flow.nodes["calculate"].output == original.nodes["calculate"].output
    example = invoice_row(INVOICE_HELD_OUT[0])
    input_data = {**example["inputs"], "private_note": "PRIVATE-INVOICE-CONTEXT"}

    def forbidden_executor(*args, **kwargs):
        pytest.fail("composed agreement must not invoke an agent, provider, or tool")

    run = execution.execute(
        stored_flow, owner=stored_flow.owner, data=input_data,
        agent_runner=forbidden_executor, action_runner=forbidden_executor,
    )
    assert run.status == "completed" and run.run_id
    persisted = store.load_run(run.run_id, owner=stored_flow.owner, flow_id=stored_flow.id)
    assert persisted is not None and persisted.owner == stored_flow.owner
    assert persisted.run_id == run.run_id
    assert persisted.input_data == input_data
    assert type(persisted.data["invoice_total"]) is int
    assert persisted.data["invoice_total"] == example["output"]
    assert persisted.nodes["calculate"] == {"status": "done", "outcome": None}
    assert persisted.definition_digest
    assert persisted.definition_revision == stored_flow.revision
    assert persisted.definition_version == stored_flow.version
    snapshot = store.load_flow_snapshot(persisted.definition_digest)
    assert snapshot.nodes["calculate"].learned_operator == envelope
    assert snapshot.nodes["calculate"].brief == stored_flow.nodes["calculate"].brief

    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    receipts = [event for event in events
                if event["kind"] == audit.EventKind.FLOW_LEARNED_OPERATOR_DECISION]
    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt["sig"]
    assert receipt["flow_run_id"] == persisted.run_id
    assert receipt["flow_id"] == persisted.flow_id
    assert receipt["node_id"] == "calculate"
    assert receipt["artifact_sha256"] == invoice_artifact["artifact_sha256"]
    assert receipt["work_sha256"] == envelope["work_sha256"]
    assert receipt["candidate_count"] == composed.candidate_count(invoice_artifact)
    assert receipt["status"] == "applied" and receipt["reason"] == "agreement"
    assert {"inputs", "examples", "output", "value", "data", "brief"}.isdisjoint(receipt)
    serialized_receipt = json.dumps(receipt)
    assert "PRIVATE-INVOICE-CONTEXT" not in serialized_receipt
    assert "unit_price" not in serialized_receipt
    assert "invoice_total" not in serialized_receipt
