"""Imported control flow must not silently change the source's execution."""
from __future__ import annotations

import pytest
from maverick.automation_import import make, n8n, power_automate, workato
from maverick.automation_import.ir import ImportedAutomation, ImportedTrigger
from maverick.automation_import.materialize import materialize
from maverick.automation_import.to_flow import to_flow_with_report
from maverick.flow.expressions import eval_condition
from maverick.flow.ir import NODE_BRANCH, NODE_SWITCH


def _pa(actions):
    return power_automate.translate({"name": "repair", "actions": actions})


def _wk(block):
    return workato.translate({"name": "repair", "code": {
        "provider": "salesforce", "name": "new_record", "block": block,
    }})


@pytest.mark.parametrize("dependencies", [
    {"First": ["Failed", "TimedOut"]}, {}, {"Missing": ["Succeeded"]},
])
def test_power_automate_non_chain_dependencies_require_repair(dependencies):
    with pytest.raises(ValueError, match="repair"):
        to_flow_with_report(_pa({
            "First": {"type": "Compose"},
            "Second": {"type": "Compose", "runAfter": dependencies},
        }))


def test_imported_output_references_require_explicit_binding():
    for automation in [
        _pa({"Each": {"type": "Foreach", "foreach": "@outputs('Get_rows')?['body/value']",
                      "actions": {"Body": {"type": "Compose"}}}}),
        _pa({"Switch": {"type": "Switch", "expression": "@outputs('Get_rows')?['body/value']",
                        "cases": {"A": {"case": "a", "actions": {"Body": {"type": "Compose"}}}}}}),
        _wk([{"keyword": "foreach", "input": {"source": "#{_('data.step1.rows')}"},
              "block": [{"keyword": "action", "name": "Body"}]}]),
    ]:
        with pytest.raises(ValueError, match="repair"):
            to_flow_with_report(automation)


def test_power_automate_switch_case_ids_do_not_collide():
    cases = {}
    expected = set()
    for case in range(12):
        actions = {}
        previous = None
        for step in range(11 if case == 1 else 1):
            name = f"case{case}_step{step}"
            expected.add(name.replace("_", " "))
            actions[name] = {"type": "Compose", "runAfter": (
                {previous: ["Succeeded"]} if previous else {})}
            previous = name
        cases[str(case)] = {"case": str(case), "actions": actions}
    flow, _ = to_flow_with_report(_pa({"Route": {
        "type": "Switch", "expression": "@triggerBody()?['kind']", "cases": cases,
    }}))
    assert expected <= {node.label for node in flow.nodes.values()}
    switch = next(node for node in flow.nodes.values() if node.kind == NODE_SWITCH)
    assert len({case["to"] for case in switch.cases}) == 12


@pytest.mark.parametrize("keyword", ["else", "elsif", "try", "catch"])
def test_workato_unsupported_blocks_require_repair(keyword):
    with pytest.raises(ValueError, match="repair"):
        to_flow_with_report(_wk([{"keyword": keyword, "block": [
            {"keyword": "action", "name": "Required child"},
        ]}]))


def test_workato_conditions_preserve_literals_and_refuse_unknown_comparisons():
    def imported(inp):
        return _wk([{"keyword": "if", "input": inp, "block": [
            {"keyword": "action", "name": "Body"},
        ]}])

    for inp in [{"a": "Dept", "operation": "not_contains", "b": "x"},
                {"operation": "equals_to", "b": True},
                {"a": "Dept", "operation": "equals_to", "b": "sk-" + "a" * 48}]:
        with pytest.raises(ValueError, match="repair"):
            to_flow_with_report(imported(inp))
    for right in ["Research and Development", False, 0]:
        flow, _ = to_flow_with_report(imported({"a": "Dept", "operation": "equals_to", "b": right}))
        branch = next(node for node in flow.nodes.values() if node.kind == NODE_BRANCH)
        assert eval_condition(branch.condition, {"Dept": right})


def test_make_module_filter_guards_the_remaining_route():
    from maverick.flow.runner import run_flow

    automation = make.translate({"name": "filtered", "flow": [
        {"module": "gateway:CustomWebHook"},
        {"module": "audit:Log", "filter": {"conditions": [[
            {"a": "amount", "o": "number:greater", "b": "100"},
        ]]}},
        {"module": "audit:Log"},
    ]})
    flow, report = to_flow_with_report(automation)
    assert any(row["kind"] == NODE_BRANCH and row["fidelity"] == "preserved" for row in report)
    for amount, expected in [(50, 0), (200, 2)]:
        calls = []
        result = run_flow(flow, data={"amount": amount},
                          agent_fn=lambda *args: ("ok", None),
                          action_fn=lambda *args, calls=calls: (calls.append("sent"), None),
                          approve_fn=lambda *args: "approved")
        assert result.status == "completed"
        assert len(calls) == expected


def test_make_invalid_router_route_is_not_dropped():
    with pytest.raises(ValueError, match="repair"):
        to_flow_with_report(make.translate({"name": "unsafe route", "flow": [
            {"module": "gateway:CustomWebHook"},
            {"module": "builtin:BasicRouter", "routes": [
                {"flow": [{"module": "memory:Write"}]},
                {"flow": [{"module": "audit:Log"}]},
            ]},
        ]}))


def test_make_filter_refuses_credentials_without_changing_literal_semantics():
    def imported(left, right):
        return make.translate({"name": "filter", "flow": [
            {"module": "gateway:CustomWebHook"},
            {"module": "audit:Log", "filter": {"conditions": [[
                {"a": left, "o": "text:equal", "b": right},
            ]]}},
        ]})

    for left, right in [("status", "sk-" + "a" * 48), ("AKIA" + "A" * 16, "ready")]:
        with pytest.raises(ValueError, match="repair") as error:
            to_flow_with_report(imported(left, right))
        assert left not in str(error.value) and right not in str(error.value)
    value = "Research and Development"
    flow, _ = to_flow_with_report(imported("status", value))
    branch = next(node for node in flow.nodes.values() if node.kind == NODE_BRANCH)
    assert eval_condition(branch.condition, {"status": value})


def test_uipath_conditions_are_single_complete_comparisons():
    def imported(condition):
        return ImportedAutomation("uipath", "1", "condition", ImportedTrigger(), raw={
            "workflow": {"activities": [{"type": "If", "condition": condition,
                                           "then": {"activities": [{"type": "WriteLine"}]}}]},
        })

    for condition in [
        'invoiceTotal > 1000 AndAlso customerRegion = "EU" AndAlso approved = True',
        'Dept = "sk-' + "a" * 48 + '"',
        'amount = threshold', 'amount <> threshold', 'amount > threshold',
    ]:
        with pytest.raises(ValueError, match="repair"):
            to_flow_with_report(imported(condition))
    value = "Research and Development " * 5
    flow, _ = to_flow_with_report(imported(f'Dept = "{value}"'))
    branch = next(node for node in flow.nodes.values() if node.kind == NODE_BRANCH)
    assert eval_condition(branch.condition, {"Dept": value})
    for condition, data in [("amount = 10", {"amount": 10}),
                            ("approved = True", {"approved": True}),
                            ("done != yes", {"done": "no"})]:
        flow, _ = to_flow_with_report(imported(condition))
        branch = next(node for node in flow.nodes.values() if node.kind == NODE_BRANCH)
        assert eval_condition(branch.condition, data)


@pytest.mark.parametrize("interval", [
    {"field": "weeks", "weeksInterval": 2, "triggerAtDay": [1]},
    {"field": "days", "daysInterval": 2},
    {"field": "hours", "hoursInterval": 5},
    {"field": "months", "monthsInterval": 5},
    {"field": "minutes", "minutesInterval": 7},
    [{"field": "minutes", "minutesInterval": 15}, {"field": "weeks", "weeksInterval": 2}],
    [{"field": "weeks", "weeksInterval": 2}, {"field": "minutes", "minutesInterval": 15}],
    [{"field": "minutes", "minutesInterval": 15}, {"field": "days", "triggerAtHour": 9}],
])
def test_n8n_inexact_intervals_require_repair(interval):
    rules = interval if isinstance(interval, list) else [interval]
    for extra in ({}, {"cronExpression": "0 9 * * *"}):
        with pytest.raises(ValueError, match="repair"):
            n8n.translate({"name": "cadence", "nodes": [{
                "name": "Schedule", "type": "n8n-nodes-base.scheduleTrigger",
                "parameters": {"rule": {"interval": rules}, **extra},
            }]})


def test_wdl_contains_fidelity_reports_runtime_approximation():
    flow, report = to_flow_with_report(_pa({"Check": {
        "type": "If", "expression": {"contains": ["@triggerBody()?['tags']", "a"]},
        "actions": {"Body": {"type": "Compose"}},
    }}))
    branch = next(node for node in flow.nodes.values() if node.kind == NODE_BRANCH)
    assert eval_condition(branch.condition, {"tags": ["abc"]})
    assert next(row for row in report if row["step"] == "Check")["fidelity"] == "approximated"


def test_imported_schedule_carries_explicit_run_budgets(monkeypatch):
    captured = []
    monkeypatch.setattr("maverick.catalog_trust.shield_scan", lambda *args, **kwargs: None)
    monkeypatch.setattr("maverick.templates.save_user_template", lambda *args, **kwargs: None)
    monkeypatch.setattr("maverick.scheduler.schedule_cron", lambda queue, cron, kind, payload:
                        (captured.append(payload) or "job", 123))
    automation = ImportedAutomation("manual", "1", "budget", ImportedTrigger(kind="schedule", cron="0 9 * * *"))
    materialize(automation, queue=object(), budget_dollars=0.5, budget_wall_seconds=30)
    assert captured[0]["max_dollars"] == 0.5
    assert captured[0]["max_wall_seconds"] == 30


def test_workato_action_output_pill_is_not_read_as_trigger_data():
    def imported(pill, *, action_alias="f00dbabe", trigger_alias=None):
        tree = {"provider": "salesforce", "name": "new_record", "block": [
            {"keyword": "action", "provider": "salesforce", "name": "search_records",
             **({"as": action_alias} if action_alias else {})},
            {"keyword": "if", "input": {"a": pill, "operation": "greater_than", "b": "100"},
             "block": [{"keyword": "action", "name": "Body"}]},
        ]}
        if trigger_alias:
            tree["as"] = trigger_alias
        return workato.translate({"name": "pill", "code": tree})

    for automation in [
        imported("#{_('data.salesforce.f00dbabe.Amount')}"),
        imported("#{_('data.salesforce.f00dbabe.Amount')}", action_alias=None),
        imported("#{_('data.salesforce.f00dbabe.Amount')}", trigger_alias="1a2b3c4d"),
        imported("#{_('data.salesforce.Amount')}", trigger_alias="1a2b3c4d"),
    ]:
        with pytest.raises(ValueError, match="repair"):
            to_flow_with_report(automation)
    for pill, alias in [("#{_('data.salesforce.1a2b3c4d.Amount')}", "1a2b3c4d"),
                        ("#{_('data.salesforce.Amount')}", None)]:
        flow, _ = to_flow_with_report(imported(pill, trigger_alias=alias))
        branch = next(node for node in flow.nodes.values() if node.kind == NODE_BRANCH)
        assert branch.condition == "Amount > 100"
