"""Native SQLite business fixture for transformed action dataflow qualification."""
from __future__ import annotations

import copy
import json
import sqlite3
import uuid
from pathlib import Path

import pytest
from maverick import config, tools
from maverick.flow import Flow, FlowNode, action_recipe, execution, recipe_flow, store

LOOKUP = "transforms_lookup_price"
ORDER = "transforms_create_order"
INVOICE = "transforms_create_invoice"
TOOLS = [LOOKUP, ORDER, INVOICE]
OWNER = "fixture-transform-reviewer"
COINCIDENT = [(1, 3, 0), (2, 4, 1), (3, 5, 2), (1, 5, 1),
              (3, 3, 0), (2, 5, 2), (3, 4, 1), (2, 3, 2)]
COUNTEREXAMPLES = [(1, 4, 2), (3, 5, 0), (2, 3, 1), (3, 4, 2)]


def closed(fields):
    return {"type": "object", "properties": fields, "required": list(fields), "additionalProperties": False}


STRING = {"type": "string", "maxLength": 64}
QUANTITY = {"type": "integer", "minimum": 1, "maximum": 3}
DOMAIN = {
    "inputs": closed({"customer_ref": STRING, "quantity": QUANTITY,
                      "discount_cents": {"type": "integer", "minimum": 0, "maximum": 2}}),
    "steps": [
        {"arguments": closed({"customer_ref": STRING}),
         "result": closed({"unit_price_cents": {"type": "integer", "minimum": 3, "maximum": 5},
                           "quoted_total_cents": {"type": "integer", "minimum": 0, "maximum": 20}})},
        {"arguments": closed({"customer_ref": STRING, "quantity": QUANTITY}),
         "result": closed({"order_id": STRING})},
        {"arguments": closed({"order_id": STRING,
                              "amount_cents": {"type": "integer", "minimum": 0, "maximum": 20}}),
         "result": closed({"invoice_id": STRING})},
    ],
}


def oracle(quantity, unit_price_cents, discount_cents):
    """Independent business specification; never passed to the learner."""
    return quantity * unit_price_cents - discount_cents


class Business:
    def __init__(self, path, *, create=True):
        self.path = Path(path)
        self.faults = {}
        if create:
            with self.connect() as db:
                db.executescript("""
                    CREATE TABLE prices(customer_ref TEXT PRIMARY KEY, unit_price_cents INTEGER NOT NULL,
                                        quoted_total_cents INTEGER NOT NULL);
                    CREATE TABLE orders(order_id TEXT PRIMARY KEY, customer_ref TEXT NOT NULL REFERENCES prices,
                                        quantity INTEGER NOT NULL);
                    CREATE TABLE invoices(invoice_id TEXT PRIMARY KEY, order_id TEXT NOT NULL UNIQUE REFERENCES orders,
                                          amount_cents INTEGER NOT NULL);
                    CREATE TABLE attempts(sequence INTEGER PRIMARY KEY AUTOINCREMENT, tool TEXT NOT NULL,
                                          arguments TEXT NOT NULL);
                """)

    def connect(self):
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA foreign_keys=ON")
        db.row_factory = sqlite3.Row
        return db

    def rows(self, table):
        assert table in {"prices", "orders", "invoices", "attempts"}
        with self.connect() as db:
            return [dict(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def seed(self, tag, quantity, price, discount, quote):
        customer = "customer-" + tag
        with self.connect() as db:
            db.execute("INSERT INTO prices VALUES(?,?,?)", (customer, price, quote))
        return {"customer_ref": customer, "quantity": quantity, "discount_cents": discount}

    def dispatch(self, tool, args):
        with self.connect() as db:
            db.execute("INSERT INTO attempts(tool, arguments) VALUES(?,?)", (tool, json.dumps(args, sort_keys=True)))
        expected = ({"customer_ref": str} if tool == LOOKUP else
                    {"customer_ref": str, "quantity": int} if tool == ORDER else
                    {"order_id": str, "amount_cents": int})
        assert set(args) == set(expected)
        assert all(type(args[key]) is kind for key, kind in expected.items())
        with self.connect() as db:
            if tool == LOOKUP:
                row = db.execute("SELECT unit_price_cents, quoted_total_cents FROM prices WHERE customer_ref=?",
                                 (args["customer_ref"],)).fetchone()
                assert row is not None
                result = dict(row)
            elif tool == ORDER:
                result = {"order_id": "order-" + uuid.uuid4().hex}
                db.execute("INSERT INTO orders VALUES(?,?,?)",
                           (result["order_id"], args["customer_ref"], args["quantity"]))
            else:
                result = {"invoice_id": "invoice-" + uuid.uuid4().hex}
                db.execute("INSERT INTO invoices VALUES(?,?,?)",
                           (result["invoice_id"], args["order_id"], args["amount_cents"]))
        if self.faults.get(tool) == "lost_ack":
            raise ConnectionError("local fixture lost acknowledgement after SQLite commit")
        return json.dumps(result, sort_keys=True)

    def assert_invoice(self, inputs, result):
        with self.connect() as db:
            row = db.execute("""SELECT i.invoice_id,i.order_id,i.amount_cents,o.customer_ref,o.quantity,
                                       p.unit_price_cents FROM invoices i JOIN orders o USING(order_id)
                                       JOIN prices p USING(customer_ref) WHERE i.invoice_id=?""",
                             (result["invoice_id"],)).fetchone()
        assert row is not None
        assert row["customer_ref"] == inputs["customer_ref"] and row["quantity"] == inputs["quantity"]
        assert row["amount_cents"] == oracle(inputs["quantity"], row["unit_price_cents"], inputs["discount_cents"])
        assert type(row["amount_cents"]) is int
        return dict(row)


def registry_for(business):
    registry = tools.ToolRegistry(principal=OWNER)
    for index, name in enumerate(TOOLS):
        registry.register(tools.Tool(
            name=name, description="Local SQLite business fixture connector",
            input_schema=copy.deepcopy(DOMAIN["steps"][index]["arguments"]),
            fn=lambda args, tool=name: business.dispatch(tool, args), parallel_safe=name == LOOKUP,
        ))
    return registry


def no_agent(*args, **kwargs):
    raise AssertionError("a learned action recipe must not call an agent or restart a completed prefix")


class Harness:
    def __init__(self, business):
        self.business = business
        self.native = execution.default_action_runner(None, channel="test", user_id=OWNER)
        self.approvals = []

    def demonstrate(self, tag, quantity, price, discount, *, quote=None):
        inputs = self.business.seed(tag, quantity, price, discount,
                                    oracle(quantity, price, discount) if quote is None else quote)
        steps = []

        def observed(tool, args, data):
            before = copy.deepcopy(args)
            raw, outcome = self.native(tool, args, data)
            assert outcome == 1.0
            result = action_recipe.parse_result(raw)
            steps.append({"tool": tool, "arguments": before, "result": result})
            return raw, outcome

        def approved(node, _data):
            self.approvals.append(node.id)
            return "approved"

        def teacher_action(index, arguments):
            # Each teacher action is a real reviewed saved Flow. The teacher
            # consumes the preceding actual result to prepare the next action.
            source = Flow("teacher-" + uuid.uuid4().hex, "Reviewed teacher action", "review", owner=OWNER,
                          nodes={"review": FlowNode("review", "approval", next="work", prompt="Review fixture action"),
                                 "work": FlowNode("work", "action", tool=TOOLS[index], params=arguments, output="result")})
            store.save_flow(source)
            run = execution.execute(
                source, owner=OWNER, data={"input": copy.deepcopy(inputs)},
                agent_runner=no_agent, action_runner=observed, approve_fn=approved,
            )
            assert run.status == "completed", run.error
            return action_recipe.parse_result(run.data["result"])

        looked_up = teacher_action(0, {"customer_ref": inputs["customer_ref"]})
        order = teacher_action(1, {"customer_ref": inputs["customer_ref"], "quantity": quantity})
        invoice = teacher_action(2, {"order_id": order["order_id"],
                                     "amount_cents": oracle(quantity, looked_up["unit_price_cents"], discount)})
        self.business.assert_invoice(inputs, invoice)
        return {"id": "reviewed-" + tag, "inputs": inputs, "steps": steps}

    def coincident_episodes(self):
        return [self.demonstrate(f"training-{i}", *row) for i, row in enumerate(COINCIDENT)]

    def counterexamples(self):
        return [self.demonstrate(f"counterexample-{i}", q, p, d, quote=(oracle(q, p, d) + 7) % 21)
                for i, (q, p, d) in enumerate(COUNTEREXAMPLES)]

    def learn(self, episodes):
        from maverick.flow.action_recipe_transforms import synthesize_transformed

        return synthesize_transformed(episodes, allowed_tools=TOOLS, domain=copy.deepcopy(DOMAIN),
                                      max_operations=2, operators=["add", "sub", "mul"], constants=[])

    def draft(self, artifact, suffix):
        flow = recipe_flow.make_flow(artifact, flow_id="transformed-" + suffix, name="Learned invoice sequence")
        flow.owner = OWNER
        assert flow.validate() == []
        store.save_flow(flow)
        return flow

    def execute(self, flow, inputs, run_id):
        def approved(node, _data):
            self.approvals.append(node.id)
            return "approved"

        return execution.execute(flow, owner=OWNER, run_id=run_id, data={"input": copy.deepcopy(inputs)},
                                 agent_runner=no_agent, action_runner=self.native, approve_fn=approved)


@pytest.fixture
def transformed_business(tmp_path, monkeypatch):
    configuration = tmp_path / "transformed-fixture.toml"
    configuration.write_text(
        '[flows]\nenable=true\naction_recipes=true\naction_recipe_transforms=true\n'
        '[security.tool_risk]\ntransforms_lookup_price="low"\n'
        'transforms_create_order="high"\ntransforms_create_invoice="high"\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(configuration))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    # The receipts these tests verify are signed; pin signing so they hold under
    # the suite's ordinary posture as well as the secure one.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    from test_support.audit_child_process import configure_test_audit_signer

    configure_test_audit_signer(monkeypatch)
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "0")
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    config.reset_config_cache()
    business = Business(tmp_path / "transforms-business.sqlite")
    registry = registry_for(business)
    monkeypatch.setattr(tools, "base_registry", lambda *args, **kwargs: registry)
    yield Harness(business)
    config.reset_config_cache()


def replay_in_fresh_worker(path, run_id):
    """A new interpreter redelivers the durable run ID, without a Python artifact."""
    from unittest.mock import patch

    config.reset_config_cache()
    business = Business(path, create=False)
    registry = registry_for(business)
    with patch.object(tools, "base_registry", lambda *args, **kwargs: registry):
        run = store.load_run(run_id)
        flow = store.load_flow_snapshot(run.definition_digest)
        returned = Harness(business).execute(flow, run.input_data["input"], run_id)
        assert returned.status == "indeterminate"
