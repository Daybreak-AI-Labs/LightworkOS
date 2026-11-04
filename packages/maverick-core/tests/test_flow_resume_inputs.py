"""Resume input handling protects data already reviewed at a pause."""
from types import SimpleNamespace

from maverick.flow.ir import Flow, FlowNode
from maverick.flow.resume_inputs import prepare_resume_inputs


def test_form_limits_new_values_and_keeps_original_submission_for_binding():
    flow = Flow(id="f", name="f", start="a", nodes={
        "a": FlowNode(id="a", kind="approval", form=[{"name": "amount"}, {"name": "note"}]),
    })
    prior = SimpleNamespace(cursor="a", data={"amount": 10, "existing": "kept"})
    inputs = {"amount": 999, "note": "reviewed", "extra": "not declared"}

    submitted, data = prepare_resume_inputs(flow, prior, inputs)

    assert submitted == inputs
    assert data == {"amount": 10, "existing": "kept", "note": "reviewed"}
    assert prior.data == {"amount": 10, "existing": "kept"}


def test_formless_pause_accepts_new_fields_without_overwriting_existing():
    flow = Flow(id="f", name="f", start="a", nodes={
        "a": FlowNode(id="a", kind="approval"),
    })
    prior = SimpleNamespace(cursor="a", data={"amount": 10})
    submitted, data = prepare_resume_inputs(flow, prior, {"amount": 50, "note": "ok"})
    assert submitted == {"amount": 50, "note": "ok"}
    assert data == {"amount": 10, "note": "ok"}
