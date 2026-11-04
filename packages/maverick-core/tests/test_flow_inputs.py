"""Declared manual-run inputs: schema validation + typed coercion (coerce_inputs)."""
from __future__ import annotations

from maverick.flow.ir import Flow, FlowNode, coerce_inputs


def _flow(inputs):
    return Flow(id="f", name="f", start="a",
                nodes={"a": FlowNode(id="a", kind="agent", brief="go")}, inputs=inputs)


def test_no_declared_inputs_is_a_passthrough():
    out, errs = coerce_inputs(_flow([]), {"anything": 1})
    assert errs == [] and out == {"anything": 1}


def test_missing_required_input_is_an_error():
    out, errs = coerce_inputs(_flow([{"key": "email", "type": "text", "required": True}]), {})
    assert any("missing required input 'email'" in e for e in errs)


def test_default_fills_a_missing_optional_input():
    out, errs = coerce_inputs(_flow([{"key": "region", "type": "text", "default": "EU"}]), {})
    assert errs == [] and out["region"] == "EU"


def test_number_is_coerced_and_bad_number_errors():
    out, errs = coerce_inputs(_flow([{"key": "amount", "type": "number"}]), {"amount": "42"})
    assert errs == [] and out["amount"] == 42.0 and isinstance(out["amount"], float)
    _, errs2 = coerce_inputs(_flow([{"key": "amount", "type": "number"}]), {"amount": "lots"})
    assert any("must be a number" in e for e in errs2)


def test_bool_parses_truthy_strings():
    out, _ = coerce_inputs(_flow([{"key": "urgent", "type": "bool"}]), {"urgent": "yes"})
    assert out["urgent"] is True
    out2, _ = coerce_inputs(_flow([{"key": "urgent", "type": "bool"}]), {"urgent": "false"})
    assert out2["urgent"] is False


def test_date_is_iso_validated():
    _, errs = coerce_inputs(_flow([{"key": "due", "type": "date"}]), {"due": "2026-07-05"})
    assert errs == []
    _, errs2 = coerce_inputs(_flow([{"key": "due", "type": "date"}]), {"due": "not-a-date"})
    assert any("must be an ISO date" in e for e in errs2)


def test_schema_itself_is_validated():
    assert any("no key" in e for e in _flow([{"type": "text"}]).validate())
    assert any("unknown type" in e for e in _flow([{"key": "x", "type": "wat"}]).validate())
    assert any("duplicate input key" in e
               for e in _flow([{"key": "x"}, {"key": "x"}]).validate())


def test_valid_schema_passes_validation_and_round_trips():
    f = _flow([{"key": "amount", "type": "number", "label": "Amount", "required": True}])
    assert f.validate() == []
    assert Flow.from_dict(f.to_dict()).inputs == f.inputs
