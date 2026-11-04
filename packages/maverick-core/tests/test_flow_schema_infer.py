"""Output-shape inference from real runs (nested data pills)."""
from __future__ import annotations

from maverick.flow.ir import Flow, FlowNode
from maverick.flow.schema_infer import infer_output_shapes, infer_shape, merge_shapes


def test_infer_shape_object_array_scalar():
    assert infer_shape({"total": 5, "id": "x"}) == {"type": "object", "keys": ["id", "total"]}
    assert infer_shape([{"a": 1}, {"b": 2}]) == {"type": "array", "keys": ["a"]}   # first dict
    assert infer_shape([1, 2, 3]) == {"type": "array", "keys": []}
    assert infer_shape("hi")["type"] == "str"


def test_infer_output_shapes_maps_output_keys():
    flow = Flow(id="f", name="f", start="a", nodes={
        "a": FlowNode(id="a", kind="action", tool="web_search", output="order"),
        "b": FlowNode(id="b", kind="agent", brief="x", output="note"),
    })
    data = {"order": {"total": 10, "currency": "USD"}, "note": "ok"}
    shapes = infer_output_shapes(flow, data)
    assert shapes["order"] == {"type": "object", "keys": ["currency", "total"]}
    assert shapes["note"] == {"type": "str"}


def test_merge_unions_fields_and_newest_type_wins():
    prior = {"order": {"type": "object", "keys": ["total"]}}
    fresh = {"order": {"type": "object", "keys": ["currency"]},
             "extra": {"type": "str"}}
    merged = merge_shapes(prior, fresh)
    assert merged["order"]["keys"] == ["currency", "total"]     # unioned
    assert merged["extra"] == {"type": "str"}
    # a type change replaces (no stale key union across types)
    changed = merge_shapes({"x": {"type": "object", "keys": ["a"]}},
                           {"x": {"type": "array", "keys": ["b"]}})
    assert changed["x"] == {"type": "array", "keys": ["b"]}


def test_execute_records_schema_only_for_real_runs(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
    from maverick.flow import execution, store
    f = Flow(id="fs", name="f", start="a", nodes={
        "a": FlowNode(id="a", kind="action", tool="web_search", output="order")})
    f = store.save_flow(f)
    execution.execute(
        f, agent_runner=lambda b, d: ("", None),
        action_runner=lambda t, p, d: ({"total": 9, "id": "z"}, 1.0))
    assert store.load_flow_schema("fs")["order"] == {"type": "object", "keys": ["id", "total"]}
    # a dry run (record_outcomes=False) must NOT pollute the schema
    store2 = tmp_path / "flows" / "schema" / "fd.json"
    dry_flow = store.save_flow(Flow(id="fd", name="f", start="a", nodes={
        "a": FlowNode(id="a", kind="action", tool="web_search", output="order")}))
    execution.execute(
        dry_flow,
        agent_runner=lambda b, d: ("", None),
        action_runner=lambda t, p, d: ({"mock": True}, 1.0), record_outcomes=False)
    assert not store2.exists()
