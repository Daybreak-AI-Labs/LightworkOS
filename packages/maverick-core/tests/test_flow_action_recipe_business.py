"""Independent business-state oracle for learned native action sequences.

Only the connector backend is local: arguments/results pass through the real
ToolRegistry, default_action_runner, signed audit writer and durable executor.
Training episodes are observed native calls, never supplied binding programs.
"""
from __future__ import annotations

import copy
import json
import sqlite3
import uuid

import pytest
from maverick import audit, config
from maverick.audit.errors import AuditRefused
from maverick.flow import action_recipe, execution, recipe_flow, store
from maverick.tools import Tool, ToolRegistry

_LOOKUP = "fixture_lookup_customer"
_ORDER = "fixture_create_order"
_WORK = "fixture_create_work_item"
_TOOLS = [_LOOKUP, _ORDER, _WORK]
_ARGUMENT_TYPES = {
    _LOOKUP: {"external_ref": str},
    _ORDER: {"customer_id": str, "sku": str, "quantity": int, "client_ref": str},
    _WORK: {"order_id": str, "assignee_id": str, "summary": str},
}
_CUSTOMERS = [
    ("EXT-A17", "customer-alpha", "owner-avery", "USD"),
    ("EXT-B28", "customer-bravo", "owner-blake", "USD"),
    ("EXT-C39", "customer-charlie", "owner-casey", "USD"),
    ("EXT-D40", "customer-delta", "owner-drew", "USD"),
    ("EXT-E51", "customer-echo", "owner-ellis", "USD"),
    ("EXT-F62", "customer-foxtrot", "owner-frankie", "USD"),
]
_CATALOG = [("HUB", 1500), ("KIT", 2300), ("CABLE", 700)]


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _fresh_id(kind):
    return f"{kind}-{uuid.uuid4().hex}"


def _request(index):
    return {
        "customer_ref": _CUSTOMERS[index][0], "sku": _CATALOG[index % 3][0],
        "units": (2, 5, 3, 7, 4, 9)[index], "request_ref": f"REQ-{index + 101}",
        "summary": f"Prepare shipment batch {index + 11}",
        "legacy_order_hint": f"LEGACY-{index + 41}",
    }


class _Business:
    def __init__(self, path):
        self.path = path
        self.next_order_id = None
        self.faults = {}
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE customers(external_ref TEXT PRIMARY KEY, customer_id TEXT UNIQUE,
                                       owner_id TEXT UNIQUE, currency TEXT NOT NULL);
                CREATE TABLE catalog(sku TEXT PRIMARY KEY, unit_price_minor INTEGER NOT NULL);
                CREATE TABLE orders(order_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
                                    sku TEXT NOT NULL, quantity INTEGER NOT NULL,
                                    client_ref TEXT UNIQUE, total_minor INTEGER NOT NULL,
                                    currency TEXT NOT NULL);
                CREATE TABLE work_items(work_item_id TEXT PRIMARY KEY, order_id TEXT NOT NULL,
                                        assignee_id TEXT NOT NULL, summary TEXT NOT NULL);
                CREATE TABLE attempts(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                                      tool TEXT NOT NULL, arguments TEXT NOT NULL);
            """)
            db.executemany("INSERT INTO customers VALUES(?,?,?,?)", _CUSTOMERS)
            db.executemany("INSERT INTO catalog VALUES(?,?)", _CATALOG)

    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def rows(self, table):
        assert table in {"customers", "catalog", "orders", "work_items", "attempts"}
        with self.connect() as db:
            return [dict(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def snapshot(self):
        return {table: self.rows(table) for table in ("customers", "catalog", "orders", "work_items")}

    def dispatch(self, tool, arguments):
        with self.connect() as db:
            db.execute("INSERT INTO attempts(tool, arguments) VALUES(?, ?)", (tool, _json(arguments)))
        expected = _ARGUMENT_TYPES[tool]
        assert set(arguments) == set(expected)
        assert all(type(arguments[name]) is kind for name, kind in expected.items())
        if tool == _LOOKUP:
            result = self.lookup(arguments)
        elif tool == _ORDER:
            result = self.order(arguments)
        else:
            result = self.work(arguments)
        # Inject only after the corresponding business transaction committed.
        fault = self.faults.get(tool)
        if fault == "truncated_json":
            return '{"order_id":'
        if fault == "missing_id":
            result.pop("order_id")
        if fault == "wrong_id_type":
            result["order_id"] = 123
        if fault == "lost_ack":
            raise ConnectionError("local fixture lost acknowledgement after commit")
        return _json(result)

    def lookup(self, args):
        with self.connect() as db:
            row = db.execute("SELECT customer_id, owner_id, currency FROM customers WHERE external_ref=?",
                             (args["external_ref"],)).fetchone()
            assert row is not None
            return dict(row)

    def order(self, args):
        assert args["quantity"] > 0
        with self.connect() as db:
            customer = db.execute("SELECT * FROM customers WHERE customer_id=?", (args["customer_id"],)).fetchone()
            item = db.execute("SELECT * FROM catalog WHERE sku=?", (args["sku"],)).fetchone()
            assert customer is not None and item is not None
            identifier = self.next_order_id or _fresh_id("order")
            self.next_order_id = None
            total = item["unit_price_minor"] * args["quantity"]
            db.execute("INSERT INTO orders VALUES(?,?,?,?,?,?,?)",
                       (identifier, args["customer_id"], args["sku"], args["quantity"],
                        args["client_ref"], total, customer["currency"]))
            return {"order_id": identifier, "customer_id": args["customer_id"],
                    "client_ref": args["client_ref"], "total_minor": total, "currency": customer["currency"]}

    def work(self, args):
        with self.connect() as db:
            order = db.execute("SELECT * FROM orders WHERE order_id=?", (args["order_id"],)).fetchone()
            owner = db.execute("SELECT * FROM customers WHERE owner_id=?", (args["assignee_id"],)).fetchone()
            assert order is not None and owner is not None
            identifier = _fresh_id("work")
            db.execute("INSERT INTO work_items VALUES(?,?,?,?)",
                       (identifier, args["order_id"], args["assignee_id"], args["summary"]))
            return {"work_item_id": identifier, "order_id": args["order_id"], "assignee_id": args["assignee_id"]}


class _Harness:
    def __init__(self, business, native):
        self.business = business
        self.native = native
        self.agent_calls = []

    def no_agent(self, *args, **kwargs):
        self.agent_calls.append((args, kwargs))
        pytest.fail("a learned action recipe must not restart the original agent")

    def demonstrate(self, index, *, coincident=False):
        inputs = _request(index)
        if coincident:
            self.business.next_order_id = _fresh_id("order")
            inputs["legacy_order_hint"] = self.business.next_order_id
        steps = []

        def observe(tool, arguments):
            raw, outcome = self.native(tool, arguments, {})
            assert type(raw) is str and outcome == 1.0
            parsed = action_recipe.parse_result(raw)
            assert parsed == json.loads(raw)
            steps.append({"tool": tool, "arguments": copy.deepcopy(arguments), "result": parsed})
            return parsed

        # This is the reviewed teacher execution, not a supplied learner mapping.
        customer = observe(_LOOKUP, {"external_ref": inputs["customer_ref"]})
        order = observe(_ORDER, {"customer_id": customer["customer_id"], "sku": inputs["sku"],
                                 "quantity": inputs["units"], "client_ref": inputs["request_ref"]})
        work = observe(_WORK, {"order_id": order["order_id"], "assignee_id": customer["owner_id"],
                               "summary": inputs["summary"]})
        self.assert_complete(inputs, work, order)
        return {"id": f"reviewed-episode-{index}", "inputs": inputs, "steps": steps}

    def assert_complete(self, inputs, final, order_result):
        # Independent state oracle: never inspect an artifact or its bindings.
        customer = next(row for row in self.business.rows("customers")
                        if row["external_ref"] == inputs["customer_ref"])
        item = next(row for row in self.business.rows("catalog") if row["sku"] == inputs["sku"])
        orders = [row for row in self.business.rows("orders") if row["client_ref"] == inputs["request_ref"]]
        assert len(orders) == 1
        order = orders[0]
        assert {key: value for key, value in order.items() if key != "order_id"} == {
            "customer_id": customer["customer_id"], "sku": inputs["sku"], "quantity": inputs["units"],
            "client_ref": inputs["request_ref"], "total_minor": item["unit_price_minor"] * inputs["units"],
            "currency": customer["currency"],
        }
        assert type(order_result["total_minor"]) is int
        assert order_result["total_minor"] == order["total_minor"]
        assert order_result["order_id"] == order["order_id"]
        works = [row for row in self.business.rows("work_items") if row["order_id"] == order["order_id"]]
        assert len(works) == 1
        work = works[0]
        assert work["assignee_id"] == customer["owner_id"] and work["summary"] == inputs["summary"]
        assert final == {key: work[key] for key in ("work_item_id", "order_id", "assignee_id")}
        return order, work

    def learn(self, *, coincident=False):
        episodes = [self.demonstrate(index, coincident=coincident) for index in range(3)]
        artifact = action_recipe.synthesize(episodes, allowed_tools=_TOOLS)
        return artifact, episodes

    def execute(self, flow, inputs, run_id):
        return execution.execute(flow, owner="fixture-reviewer", run_id=run_id,
                                 data={"input": copy.deepcopy(inputs)}, agent_runner=self.no_agent,
                                 action_runner=self.native, approve_fn=lambda _node, _data: "approved")


@pytest.fixture
def business(tmp_path, monkeypatch):
    configuration = tmp_path / "fixture-config.toml"
    configuration.write_text(
        '[flows]\nenable = true\naction_recipes = true\n'
        '[security.tool_risk]\nfixture_lookup_customer = "low"\n'
        'fixture_create_order = "high"\nfixture_create_work_item = "high"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(configuration))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    # The receipts these tests verify are signed; pin signing so they hold under
    # the suite's ordinary posture as well as the secure one.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "0")
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    config.reset_config_cache()
    backend = _Business(tmp_path / "business.sqlite")
    registry = ToolRegistry(principal="fixture-reviewer")
    for name in _TOOLS:
        schema = {"type": "object", "additionalProperties": False,
                  "properties": {key: {"type": "integer" if kind is int else "string"}
                                 for key, kind in _ARGUMENT_TYPES[name].items()},
                  "required": list(_ARGUMENT_TYPES[name])}
        registry.register(Tool(name=name, description="Local business fixture connector",
                               input_schema=schema,
                               fn=lambda args, tool=name: backend.dispatch(tool, args),
                               parallel_safe=name == _LOOKUP))
    monkeypatch.setattr("maverick.tools.base_registry", lambda *args, **kwargs: registry)
    native = execution.default_action_runner(world=None, channel="test", user_id="fixture-reviewer")
    return _Harness(backend, native)


def _make_flow(artifact):
    flow = recipe_flow.make_flow(artifact, flow_id="learned-business-recipe", name="Order fulfilment")
    flow.owner = "fixture-reviewer"
    assert flow.validate() == []
    for index, tool in enumerate(_TOOLS):
        action = flow.nodes[f"action_{index}"]
        gate = flow.nodes[f"approval_{index}"]
        assert action.kind == "action" and action.tool == tool
        assert gate.kind == "approval" and gate.next == action.id
    return flow


def _assert_unchanged_prefix(backend, before):
    after = backend.snapshot()
    assert after["customers"] == before["customers"]
    assert after["catalog"] == before["catalog"]
    for table in ("orders", "work_items"):
        assert after[table][:len(before[table])] == before[table]


def _calls_since(backend, offset):
    return [row["tool"] for row in backend.rows("attempts")[offset:]]


def test_learned_native_three_step_recipe_completes_on_fresh_ids_and_typed_inputs(business):
    artifact, episodes = business.learn()
    frozen = copy.deepcopy(artifact)
    flow = _make_flow(artifact)
    training_ids = {step["result"][key] for episode in episodes for step in episode["steps"]
                    for key in ("order_id", "work_item_id") if key in step["result"]}
    generated = set()
    for index in range(3, 6):
        inputs = _request(index)
        before, offset = business.business.snapshot(), len(business.business.rows("attempts"))
        run = business.execute(flow, inputs, f"held-out-{index}")
        assert run.status == "completed", run.error
        assert _calls_since(business.business, offset) == _TOOLS
        order, work = business.assert_complete(inputs, run.data["_recipe_step_2"], run.data["_recipe_step_1"])
        fresh = {order["order_id"], work["work_item_id"]}
        assert fresh.isdisjoint(training_ids | generated)
        generated.update(fresh)
        _assert_unchanged_prefix(business.business, before)
        assert len(business.business.rows("orders")) == len(before["orders"]) + 1
        assert len(business.business.rows("work_items")) == len(before["work_items"]) + 1
        saved = store.load_run(run.run_id)
        assert saved.status == "completed" and saved.data["_recipe_step_2"] == run.data["_recipe_step_2"]
        repeated = business.execute(flow, inputs, run.run_id)
        assert repeated.status == "completed"
        assert _calls_since(business.business, offset) == _TOOLS
    assert artifact == frozen and business.agent_calls == []
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    for kind in (audit.EventKind.TOOL_CALL, audit.EventKind.TOOL_RESULT):
        relevant = [event for event in events if event["kind"] == kind and event.get("name") in _TOOLS]
        assert len(relevant) == 18 and all(event.get("sig") for event in relevant)


def test_coincident_training_ids_remain_ambiguous_after_order_commit_without_replay(business):
    artifact, episodes = business.learn(coincident=True)
    assert all(episode["inputs"]["legacy_order_hint"] == episode["steps"][1]["result"]["order_id"]
               for episode in episodes)
    flow = _make_flow(artifact)
    inputs = _request(3)
    before, offset = business.business.snapshot(), len(business.business.rows("attempts"))
    run = business.execute(flow, inputs, "ambiguous-after-order")
    assert run.status == "indeterminate", run.error
    assert _calls_since(business.business, offset) == [_LOOKUP, _ORDER]
    assert len(business.business.rows("orders")) == len(before["orders"]) + 1
    assert len(business.business.rows("work_items")) == len(before["work_items"])
    committed = business.business.rows("orders")[-1]
    assert committed["order_id"] != inputs["legacy_order_hint"]
    assert run.data["_recipe_step_1"]["order_id"] == committed["order_id"]
    assert "_recipe_step_2" not in run.data
    _assert_unchanged_prefix(business.business, before)
    saved = store.load_run(run.run_id)
    assert saved.status == "indeterminate" and saved.data["_recipe_step_1"] == run.data["_recipe_step_1"]
    repeated = business.execute(flow, inputs, run.run_id)
    assert repeated.status == "indeterminate"
    assert _calls_since(business.business, offset) == [_LOOKUP, _ORDER]
    assert business.agent_calls == []


@pytest.mark.parametrize("fault", ["truncated_json", "missing_id", "wrong_id_type", "lost_ack"])
def test_order_commits_but_bad_reply_never_replays_or_starts_downstream_work(business, fault):
    artifact, _ = business.learn()
    flow = _make_flow(artifact)
    business.business.faults[_ORDER] = fault
    inputs = _request(3)
    before, offset = business.business.snapshot(), len(business.business.rows("attempts"))
    run = business.execute(flow, inputs, f"order-{fault}")
    assert run.status == "indeterminate", run.error
    assert _calls_since(business.business, offset) == [_LOOKUP, _ORDER]
    assert len(business.business.rows("orders")) == len(before["orders"]) + 1
    assert len(business.business.rows("work_items")) == len(before["work_items"])
    assert "_recipe_step_2" not in run.data and business.agent_calls == []
    _assert_unchanged_prefix(business.business, before)
    assert store.load_run(run.run_id).status == "indeterminate"
    business.execute(flow, inputs, run.run_id)
    assert _calls_since(business.business, offset) == [_LOOKUP, _ORDER]


def test_final_mutation_lost_ack_keeps_both_effects_and_never_claims_completion(business):
    artifact, _ = business.learn()
    flow = _make_flow(artifact)
    business.business.faults[_WORK] = "lost_ack"
    inputs = _request(3)
    before, offset = business.business.snapshot(), len(business.business.rows("attempts"))
    run = business.execute(flow, inputs, "work-lost-ack")
    assert run.status == "indeterminate", run.error
    assert _calls_since(business.business, offset) == _TOOLS
    assert len(business.business.rows("orders")) == len(before["orders"]) + 1
    assert len(business.business.rows("work_items")) == len(before["work_items"]) + 1
    assert "_recipe_step_2" not in run.data and business.agent_calls == []
    _assert_unchanged_prefix(business.business, before)
    business.execute(flow, inputs, run.run_id)
    assert _calls_since(business.business, offset) == _TOOLS


def test_additional_reviewed_native_episode_removes_coincidental_binding(business):
    old, episodes = business.learn(coincident=True)
    before = copy.deepcopy(old)
    additional = business.demonstrate(3)
    assert additional["inputs"]["legacy_order_hint"] != additional["steps"][1]["result"]["order_id"]
    refined = action_recipe.synthesize([*episodes, additional], allowed_tools=_TOOLS)
    assert refined["artifact_sha256"] != old["artifact_sha256"] and old == before
    flow = _make_flow(refined)
    inputs = _request(4)
    offset = len(business.business.rows("attempts"))
    run = business.execute(flow, inputs, "new-evidence-fresh-order")
    assert run.status == "completed", run.error
    business.assert_complete(inputs, run.data["_recipe_step_2"], run.data["_recipe_step_1"])
    assert _calls_since(business.business, offset) == _TOOLS and business.agent_calls == []


@pytest.mark.parametrize("index", [0, 2])
@pytest.mark.parametrize("receipt", [False, 1])
def test_selective_decision_receipt_refusal_stops_at_exact_effect_boundary(business, monkeypatch, index, receipt):
    artifact, _ = business.learn()
    flow = _make_flow(artifact)
    before, offset = business.business.snapshot(), len(business.business.rows("attempts"))
    original = audit.record
    refused = []

    def selective_record(kind, **payload):
        if kind == audit.EventKind.FLOW_ACTION_RECIPE_DECISION and payload.get("step_index") == index:
            refused.append(copy.deepcopy(payload))
            return receipt
        return original(kind, **payload)

    monkeypatch.setattr(audit, "record", selective_record)
    inputs, run_id = _request(3), f"receipt-{index}-{receipt}"
    with pytest.raises(AuditRefused):
        business.execute(flow, inputs, run_id)
    expected_calls = [] if index == 0 else [_LOOKUP, _ORDER]
    assert refused and _calls_since(business.business, offset) == expected_calls
    assert len(business.business.rows("orders")) == len(before["orders"]) + (index == 2)
    assert len(business.business.rows("work_items")) == len(before["work_items"])
    assert business.agent_calls == []
    _assert_unchanged_prefix(business.business, before)
    assert store.load_run(run_id).status == "indeterminate"
    business.execute(flow, inputs, run_id)
    assert _calls_since(business.business, offset) == expected_calls
