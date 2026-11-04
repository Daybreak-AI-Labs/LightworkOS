"""Imported routing is checked through the real flow interpreter, offline."""
from __future__ import annotations

import itertools
import json

import pytest
from maverick.automation_import import n8n, power_automate
from maverick.automation_import.ir import ImportedAutomation, ImportedStep, ImportedTrigger
from maverick.automation_import.to_flow import to_flow_with_report
from maverick.flow.runner import run_flow


def pa(expression):
    return power_automate.translate({"name": "routing", "actions": {
        "Check": {"type": "If", "expression": expression,
                  "actions": {"Accept": {"type": "Compose", "inputs": "accept"}},
                  "else": {"actions": {"Reject": {"type": "Compose", "inputs": "reject"}}}},
    }})


def routed(automation, data):
    flow, report = to_flow_with_report(automation)
    assert flow.validate() == []
    calls = []

    def agent(node, brief, _data):
        calls.append((node.label, brief))
        return "fixture success", 1.0

    def action(*_args):
        raise AssertionError("routing fixture must never dispatch an external action")

    result = run_flow(flow, data=data, agent_fn=agent, action_fn=action)
    assert result.status == "completed", result
    return [name for name, _ in calls], calls, report


def test_nested_boolean_truth_table_preserves_every_arm_and_not():
    expression = {"and": [
        {"or": [{"equals": ["@triggerBody()?['a']", True]},
                {"equals": ["@triggerBody()?['b']", True]}]},
        {"not": {"greater": ["@triggerBody()?['amount']", 100]}},
    ]}
    for a, b, amount in itertools.product((False, True), (False, True), (5, 150, None)):
        names, _, _ = routed(pa(expression), {"a": a, "b": b, "amount": amount})
        expected = (a or b) and not (amount is not None and amount > 100)
        assert names == ["Accept" if expected else "Reject"]


@pytest.mark.parametrize(("expression", "data", "accepted"), [
    ("@and(equals(triggerBody()?['status'], 'yes'), greater(triggerBody()?['amount'], 100))",
     {"status": "yes", "amount": 5}, False),
    ("@not(greater(triggerBody()?['amount'], 100))", {"amount": 5}, True),
    ("@equals(triggerBody()?['name'], 'Jane, Doe')", {"name": "Jane, Doe"}, True),
    ("@equals(triggerBody()?['name'], 'O''Brien')", {"name": "O'Brien"}, True),
    ({"equals": ["@triggerBody()?['customer']?['status']", "true"]},
     {"customer": {"status": "true"}, "status": False}, True),
    ({"equals": ["@triggerBody()?['status']", "true"]}, {"status": True}, False),
    ({"equals": ["@triggerBody()?['status']", "a and b or c"]},
     {"status": "a and b or c"}, True),
])
def test_wdl_string_parser_nested_fields_and_literal_types(expression, data, accepted):
    assert routed(pa(expression), data)[0] == ["Accept" if accepted else "Reject"]


def n8n_flow(conditions, **parameters):
    return n8n.translate({"id": "routing", "name": "Route", "nodes": [
        {"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}},
        {"name": "Check", "type": "n8n-nodes-base.if", "parameters": {
            "conditions": conditions, **parameters}},
        {"name": "Accept", "type": "n8n-nodes-base.noOp", "parameters": {}},
        {"name": "Reject", "type": "n8n-nodes-base.noOp", "parameters": {}},
    ], "connections": {"Hook": {"main": [[{"node": "Check"}]]},
                       "Check": {"main": [[{"node": "Accept"}], [{"node": "Reject"}]]}}})


@pytest.mark.parametrize("reference", ["={{ $json.amount }}", "{{$json.amount}}", "$json['amount']"])
def test_n8n_json_reference_executes_correct_arm(reference):
    automation = n8n_flow({"conditions": [{"leftValue": reference,
        "operator": {"operation": "gt", "type": "number"}, "rightValue": 100}]})
    assert routed(automation, {"amount": 150})[0] == ["Accept"]
    assert routed(automation, {"amount": 5})[0] == ["Reject"]


@pytest.mark.parametrize("combination", ["all", "any"])
def test_n8n_v1_multiple_groups_and_v2_combinations(combination):
    v1 = {"number": [{"value1": "={{$json.amount}}", "operation": "larger", "value2": 100}],
          "string": [{"value1": "={{$json.status}}", "operation": "equal", "value2": "yes"}]}
    v2 = {"combinator": "and" if combination == "all" else "or", "conditions": [
        {"leftValue": "={{$json.amount}}", "operator": {"operation": "gt"}, "rightValue": 100},
        {"leftValue": "={{$json.status}}", "operator": {"operation": "equals"}, "rightValue": "yes"}]}
    for amount, status in itertools.product((5, 150), ("no", "yes")):
        outcomes = [amount > 100, status == "yes"]
        accepted = all(outcomes) if combination == "all" else any(outcomes)
        for automation in (n8n_flow(v1, combineOperation=combination), n8n_flow(v2)):
            assert routed(automation, {"amount": amount, "status": status})[0] == [
                "Accept" if accepted else "Reject"]


@pytest.mark.parametrize("expression", [
    {"equals": ["@outputs('Earlier')?['status']", "ready"]},
    {"startsWith": ["@triggerBody()?['status']", "yes"]},
    {"equals": ["@triggerBody()?['a']", "@triggerBody()?['b']"]},
    {"and": []}, {"equals": ["a", None]},
])
def test_unsupported_wdl_is_repair_required_not_a_runnable_guess(expression):
    with pytest.raises(ValueError, match="requires repair before execution"):
        to_flow_with_report(pa(expression))


@pytest.mark.parametrize("expression", [
    {"equals": ["yes", "yes"]},
    {"equals": ["@triggerBody()?['customer.status']", "ready"]},
])
def test_wdl_literal_and_dotted_key_are_not_reinterpreted_as_nested_data(expression):
    with pytest.raises(ValueError, match="requires repair before execution"):
        to_flow_with_report(pa(expression))


@pytest.mark.parametrize("conditions", [
    {"conditions": [{"leftValue": "={{ $json.amount + 1 }}", "operator": "gt", "rightValue": 100}]},
    {"conditions": [{"leftValue": "amount", "operator": "unknown", "rightValue": 100}]},
    {"conditions": [{"leftValue": "amount", "operator": "gt", "rightValue": "={{$json.limit}}"}]},
    {},
])
def test_unsupported_n8n_is_repair_required(conditions):
    with pytest.raises(ValueError, match="requires repair before execution"):
        to_flow_with_report(n8n_flow(conditions))


def test_agent_fallback_retains_operational_inputs_and_redacts_credentials():
    def automation(url):
        return ImportedAutomation("n8n", "http", "HTTP", ImportedTrigger(), steps=[ImportedStep(
            "Fetch", app="http", params={"method": "POST", "url": url,
                "body": {"customer_id": "customer-77", "description": "line one\nline two"},
                "authorization": "private-bearer-value", "headers": {"api_key": "private-api-key"}},  # pragma: allowlist secret -- synthetic redaction fixture
        )])
    first, _ = to_flow_with_report(automation("https://example.invalid/customer/a"))
    second, _ = to_flow_with_report(automation("https://example.invalid/customer/b"))
    text = first.nodes[first.start].brief
    assert first.to_dict() != second.to_dict()
    for required in ("POST", "example.invalid/customer/a", "customer-77", "line one\\nline two"):
        assert required in text
    assert "private-bearer-value" not in text and "private-api-key" not in text
    assert "REDACTED" in text
    assert json.dumps(first.to_dict())


def test_fallback_does_not_silently_truncate_inputs():
    imported = ImportedAutomation("n8n", "big", "Big", ImportedTrigger(), steps=[ImportedStep(
        "Fetch", params={"url": "x" * 16385},
    )])
    with pytest.raises(ValueError, match="inputs require repair"):
        to_flow_with_report(imported)


def test_direct_action_retains_full_operational_inputs_through_execution():
    params = {"channel": "general", "text": "First line\n" + "Message text. " * 30,
              "metadata": {f"field_{index}": index for index in range(16)},
              "items": list(range(16)), "api_key": "private-api-key"}
    imported = ImportedAutomation("n8n", "post", "Post", ImportedTrigger(), steps=[ImportedStep(
        "Post", operation="post", tools_hint=["slack"], params=params,
    )])
    flow, _ = to_flow_with_report(imported)
    calls = []
    result = run_flow(
        flow, data={}, agent_fn=lambda *_: pytest.fail("deterministic action expected"),
        action_fn=lambda _node, inputs, _data: (calls.append(inputs), None),
        approve_fn=lambda *_: "approved",
    )
    assert result.status == "completed"
    assert len(calls) == 1
    assert calls[0]["text"] == params["text"]
    assert calls[0]["metadata"] == params["metadata"]
    assert calls[0]["items"] == params["items"]
    assert calls[0]["op"] == "post"
    assert calls[0]["api_key"] == "[REDACTED:automation_import_secret]"


def test_direct_action_requires_repair_instead_of_truncating_oversized_inputs():
    imported = ImportedAutomation("n8n", "big", "Big", ImportedTrigger(), steps=[ImportedStep(
        "Post", operation="post", tools_hint=["slack"], params={"text": "x" * 16385},
    )])
    with pytest.raises(ValueError, match="inputs require repair"):
        to_flow_with_report(imported)


def test_n8n_references_parse_in_linear_time():
    import time

    from maverick.automation_import import predicates
    start = time.perf_counter()
    for n in (4_000, 60_000):
        with pytest.raises(ValueError):
            predicates.n8n_key("{{" + " " * n + "x")
    assert time.perf_counter() - start < 1.0          # was 30 s at 4,000 characters
    assert predicates.n8n_key("={{ $json.status }}") == "status"


@pytest.mark.parametrize("ref", ["{{ $json.or }}", "{{ $json.and }}", "OR"])
def test_reserved_words_cannot_be_data_paths(ref):
    from maverick.automation_import import predicates
    with pytest.raises(ValueError, match="repair"):
        predicates.n8n_key(ref)
    with pytest.raises(ValueError, match="repair"):
        predicates.wdl_key("triggerBody()?['and']")
