"""Import fidelity: lowering an n8n workflow to a flow preserves IF/Filter
branches as real branch nodes instead of flattening the graph; a Power
Automate (WDL) definition preserves If/Foreach; every path emits a per-step
fidelity report."""
from __future__ import annotations

import pytest
from maverick.automation_import import n8n, power_automate
from maverick.automation_import.to_flow import to_flow, to_flow_with_report
from maverick.flow.ir import (
    NODE_ACTION,
    NODE_AGENT,
    NODE_APPROVAL,
    NODE_BRANCH,
    NODE_FOREACH,
    NODE_PARALLEL,
    partition_draft_validation_errors,
)


def _assert_preview_valid(flow):
    """Imported drafts may await tool classification, but nothing else."""
    blocking, unclassified = partition_draft_validation_errors(flow.validate())
    assert blocking == [], blocking
    return unclassified

_IF_WF = {
    "id": "7", "name": "Route by amount", "active": True,
    "nodes": [
        {"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}},
        {"name": "Check", "type": "n8n-nodes-base.if", "parameters": {"conditions": {
            "conditions": [{"leftValue": "{{amount}}", "operator": {"operation": "gt"},
                            "rightValue": "100"}]}}},
        {"name": "Escalate", "type": "n8n-nodes-base.slack", "parameters": {"operation": "post"}},
        {"name": "AutoApprove", "type": "n8n-nodes-base.noOp", "parameters": {}},
    ],
    "connections": {
        "Hook": {"main": [[{"node": "Check", "type": "main", "index": 0}]]},
        "Check": {"main": [[{"node": "Escalate", "type": "main", "index": 0}],
                           [{"node": "AutoApprove", "type": "main", "index": 0}]]},
    },
}


def test_if_node_becomes_a_branch_with_wired_arms():
    f = to_flow(n8n.translate(_IF_WF))
    unclassified = _assert_preview_valid(f)
    assert unclassified == []
    branch = next(n for n in f.nodes.values() if n.kind == NODE_BRANCH)
    assert branch.condition == "amount > '100'"  # reference normalized, operator mapped
    # The supported Slack post contract binds to the classified Lightwork tool
    # behind a human gate; the false arm remains the no-op agent approximation.
    true_gate = f.nodes[branch.if_true]
    assert true_gate.kind == NODE_APPROVAL
    true_action = f.nodes[true_gate.next]
    assert true_action.kind == NODE_ACTION
    assert true_action.tool == "slack_bot"
    assert true_action.params["op"] == "post"
    assert f.nodes[branch.if_false].kind == NODE_AGENT
    assert f.start == branch.id                          # trigger -> the IF first


def test_linear_workflow_still_lowers_linearly():
    wf = {
        "id": "1", "name": "Linear", "active": True,
        "nodes": [
            {"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}},
            {"name": "A", "type": "n8n-nodes-base.slack", "parameters": {"operation": "post"}},
            {"name": "B", "type": "n8n-nodes-base.hubspot", "parameters": {"operation": "create"}},
        ],
        "connections": {
            "Hook": {"main": [[{"node": "A", "type": "main", "index": 0}]]},
            "A": {"main": [[{"node": "B", "type": "main", "index": 0}]]},
        },
    }
    f = to_flow(n8n.translate(wf))
    _assert_preview_valid(f)
    assert not any(n.kind == NODE_BRANCH for n in f.nodes.values())
    assert f.nodes[f.start].next is not None            # chained


def _n8n_fanout(connections):
    return n8n.translate({
        "id": "fanout", "name": "Welcome a lead", "active": True,
        "nodes": [
            {"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}},
            {"name": "Prepare", "type": "n8n-nodes-base.noOp", "parameters": {}},
            {"name": "CRM", "type": "n8n-nodes-base.noOp", "parameters": {}},
            {"name": "Notify", "type": "n8n-nodes-base.noOp", "parameters": {}},
            {"name": "Welcome", "type": "n8n-nodes-base.noOp", "parameters": {}},
        ],
        "connections": connections,
    })


def _edges(*names):
    return [{"node": name, "type": "main", "index": 0} for name in names]


def test_n8n_fanout_runs_every_connected_path_and_reports_the_approximation(
    tmp_path, monkeypatch,
):
    from maverick.flow import store
    from maverick.flow.runner import STATUS_COMPLETED, run_flow

    imported = _n8n_fanout({
        "Hook": {"main": [_edges("Prepare")]},
        "Prepare": {"main": [_edges("CRM", "Notify", "Welcome")]},
    })
    flow, report = to_flow_with_report(imported)
    _assert_preview_valid(flow)
    assert not flow.reachability_errors()
    first = flow.nodes[flow.start]
    fork = flow.nodes[first.next]
    assert fork.kind == NODE_PARALLEL
    assert len(fork.branches) == 3
    assert {e["step"] for e in report if e["kind"] == NODE_AGENT} == {
        "Prepare", "CRM", "Notify", "Welcome",
    }
    fork_entry = next(e for e in report if e["kind"] == NODE_PARALLEL)
    assert fork_entry["fidelity"] == "approximated"
    assert "order" in fork_entry["note"]

    # An imported draft must remain publishable, then execute all three paths.
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
    saved = store.save_flow(flow)
    store.publish_flow(saved.id, expected_version=saved.version,
                       expected_revision=saved.revision)
    seen = []
    result = run_flow(
        flow, agent_fn=lambda node, brief, data: seen.append(node.label) or ("ok", None),
        action_fn=lambda node, params, data: ({"ok": True}, None),
        data={},
    )
    assert result.status == STATUS_COMPLETED
    assert sorted(seen) == ["CRM", "Notify", "Prepare", "Welcome"]


def test_n8n_trigger_fanout_keeps_each_root_path():
    imported = _n8n_fanout({
        "Hook": {"main": [_edges("Prepare", "CRM", "Notify", "Welcome")]},
    })
    flow, report = to_flow_with_report(imported)
    _assert_preview_valid(flow)
    assert flow.nodes[flow.start].kind == NODE_PARALLEL
    assert len(flow.nodes[flow.start].branches) == 4
    assert len([r for r in report if r["kind"] == NODE_AGENT]) == 4


def test_n8n_decision_fanout_preserves_each_true_connection_and_false_arm():
    from maverick.flow.runner import STATUS_COMPLETED, run_flow

    imported = _n8n_fanout({
        "Hook": {"main": [_edges("Prepare")]},
        "Prepare": {"main": [_edges("CRM", "Notify"), _edges("Welcome")]},
    })
    raw = imported.raw
    raw["nodes"][1]["type"] = "n8n-nodes-base.if"
    raw["nodes"][1]["parameters"] = {"conditions": {"conditions": [
        {"leftValue": "{{amount}}", "operator": {"operation": "gt"},
         "rightValue": "100"},
    ]}}
    flow = to_flow(n8n.translate(raw))
    _assert_preview_valid(flow)
    choice = flow.nodes[flow.start]
    assert choice.kind == NODE_BRANCH
    assert flow.nodes[choice.if_true].kind == NODE_PARALLEL
    assert flow.nodes[choice.if_false].label == "Welcome"
    for amount, expected in [(200, ["CRM", "Notify"]), (50, ["Welcome"])]:
        seen = []
        result = run_flow(
            flow,
            agent_fn=lambda node, brief, data, seen=seen: seen.append(node.label) or ("ok", None),
            action_fn=lambda node, params, data: ({"ok": True}, None),
            data={"amount": amount},
        )
        assert result.status == STATUS_COMPLETED
        assert sorted(seen) == expected


def test_n8n_fanout_with_risky_action_uses_a_durable_parent_approval():
    from maverick.flow.runner import STATUS_COMPLETED, run_flow

    raw = _n8n_fanout({
        "Hook": {"main": [_edges("Prepare")]},
        "Prepare": {"main": [_edges("CRM", "Notify", "Welcome")]},
    }).raw
    raw["nodes"][3]["type"] = "n8n-nodes-base.slack"
    raw["nodes"][3]["parameters"] = {"operation": "post", "text": "hello"}
    flow = to_flow(n8n.translate(raw))
    _assert_preview_valid(flow)
    assert not flow.reachability_errors()
    gate = next(node for node in flow.nodes.values() if node.kind == NODE_APPROVAL)
    fork = flow.nodes[gate.next]
    assert fork.kind == NODE_PARALLEL
    assert all(all(node.kind != NODE_APPROVAL for node in branch.nodes.values())
               for branch in fork.branches)
    seen = []
    result = run_flow(
        flow,
        agent_fn=lambda node, brief, data: seen.append(node.label) or ("ok", None),
        action_fn=lambda node, params, data: seen.append(node.label) or ({"ok": True}, None),
        approve_fn=lambda node, data: "approved",
        data={},
    )
    assert result.status == STATUS_COMPLETED
    assert sorted(seen) == ["CRM", "Notify", "Prepare", "Welcome"]


def test_n8n_fanout_with_shared_downstream_step_requires_repair():
    imported = _n8n_fanout({
        "Hook": {"main": [_edges("Prepare")]},
        "Prepare": {"main": [_edges("CRM", "Notify")]},
        "CRM": {"main": [_edges("Welcome")]},
        "Notify": {"main": [_edges("Welcome")]},
    })
    with pytest.raises(ValueError, match="paths rejoin or loop"):
        to_flow_with_report(imported)


def test_n8n_disconnected_step_requires_repair_instead_of_a_false_preserved_report():
    imported = _n8n_fanout({
        "Hook": {"main": [_edges("Prepare")]},
        "Prepare": {"main": [_edges("CRM", "Notify")]},
    })
    with pytest.raises(ValueError, match="disconnected steps"):
        to_flow_with_report(imported)


@pytest.mark.parametrize("extra, message", [
    ({"main": [_edges("CRM")], "error": [_edges("Notify")]}, "non-main output"),
    ({"main": [_edges("CRM"), _edges("Notify")]}, "unsupported output sockets"),
])
def test_n8n_unsupported_sockets_are_refused(extra, message):
    imported = _n8n_fanout({
        "Hook": {"main": [_edges("Prepare")]},
        "Prepare": extra,
    })
    with pytest.raises(ValueError, match=message):
        to_flow_with_report(imported)


def test_graphless_import_falls_back_to_linear():
    # a Make/manual automation (no n8n raw graph) still lowers via the linear path
    from maverick.automation_import import ir as iir
    a = iir.ImportedAutomation("make", "9", "x", iir.ImportedTrigger(kind=iir.TRIGGER_WEBHOOK),
                               steps=[iir.ImportedStep(name="s1"), iir.ImportedStep(name="s2")])
    f = to_flow(a)
    _assert_preview_valid(f)
    assert len(f.nodes) == 2


# ---- Power Automate (WDL) structural capture ---------------------------------

_PA_WF = {
    "name": "flow-1",
    "properties": {
        "displayName": "Escalate blocked orders",
        "definition": {
            "triggers": {"When_a_row_is_added": {
                "type": "OpenApiConnection",
                "inputs": {"host": {"apiId": ".../apis/shared_commondataservice",
                                    "operationId": "OnNewRow"}}}},
            "actions": {
                "Check_status": {
                    "type": "If",
                    "runAfter": {},
                    "expression": {"and": [
                        {"equals": ["@triggerBody()?['status']", "blocked"]}]},
                    "actions": {"Post_alert": {
                        "type": "OpenApiConnection", "runAfter": {},
                        "inputs": {"host": {"apiId": ".../apis/shared_slack",
                                            "operationId": "PostMessage"},
                                   "parameters": {"text": "blocked!"}}}},
                    "else": {"actions": {"Log_ok": {
                        "type": "Compose", "runAfter": {}, "inputs": "ok"}}},
                },
                "Wrap_up": {
                    "type": "OpenApiConnection",
                    "runAfter": {"Check_status": ["Succeeded"]},
                    "inputs": {"host": {"apiId": ".../apis/shared_teams",
                                        "operationId": "PostReply"},
                               "parameters": {"text": "done"}},
                },
            },
        },
    },
}


def test_power_automate_if_becomes_branch_with_rejoining_arms():
    f, report = to_flow_with_report(power_automate.translate(_PA_WF))
    assert _assert_preview_valid(f) == []
    assert not any("risk-classify" in entry["note"] for entry in report)
    branch = next(n for n in f.nodes.values() if n.kind == NODE_BRANCH)
    assert branch.condition == "status == 'blocked'"  # literal type is preserved
    assert f.start == branch.id
    then_gate = f.nodes[branch.if_true]
    then_node = f.nodes[then_gate.next]
    else_node = f.nodes[branch.if_false]
    assert then_gate.kind == NODE_APPROVAL
    assert then_node.kind == NODE_ACTION and then_node.tool == "slack_bot"
    assert then_node.params["op"] == "post"
    assert else_node.kind == NODE_AGENT                  # Compose -> agent approximation
    # Both arms rejoin at a mandatory human gate before the high-risk action.
    wrap = next(n for n in f.nodes.values() if n.tool == "teams")
    gate = f.nodes[then_node.next]
    assert gate.kind == NODE_APPROVAL and gate.next == wrap.id
    assert else_node.next == gate.id
    fidelity = {r["step"]: r["fidelity"] for r in report}
    assert fidelity["Check_status"] == "preserved"
    assert fidelity["Post_alert"] == "preserved"
    assert fidelity["Log_ok"] == "approximated"


def test_power_automate_foreach_becomes_a_loop_with_a_body():
    wf = {
        "properties": {"displayName": "Digest rows", "definition": {
            "triggers": {"Manual": {"type": "Request"}},
            "actions": {"For_each_row": {
                "type": "Foreach", "runAfter": {},
                "foreach": "@triggerBody()?['rows']",
                "actions": {"Summarize": {"type": "Compose", "runAfter": {},
                                          "inputs": "@item()"}},
            }},
        }},
    }
    f, report = to_flow_with_report(power_automate.translate(wf))
    _assert_preview_valid(f)
    loop = next(n for n in f.nodes.values() if n.kind == NODE_FOREACH)
    assert loop.items == "rows"
    assert loop.body is not None and len(loop.body.nodes) == 1
    assert {r["fidelity"] for r in report if r["step"] == "For_each_row"} == {"preserved"}


def test_power_automate_switch_approximates_with_report():
    wf = {
        "properties": {"displayName": "Route", "definition": {
            "triggers": {"Manual": {"type": "Request"}},
            "actions": {"Route_by_type": {
                "type": "Switch", "runAfter": {}, "expression": "@triggerBody()?['t']",
                "cases": {}, "default": {}},
            },
        }},
    }
    f, report = to_flow_with_report(power_automate.translate(wf))
    _assert_preview_valid(f)
    only = next(iter(f.nodes.values()))
    assert only.kind == NODE_AGENT                       # runs, but approximated
    r = next(r for r in report if r["step"] == "Route_by_type")
    assert r["fidelity"] == "approximated" and "Switch" in r["note"]


def test_power_automate_switch_with_cases_becomes_switch_node():
    wf = {
        "properties": {"displayName": "Route by tier", "definition": {
            "triggers": {"Manual": {"type": "Request"}},
            "actions": {
                "Route": {
                    "type": "Switch", "runAfter": {},
                    "expression": "@triggerBody()?['tier']",
                    "cases": {
                        "Gold": {"case": "gold", "actions": {
                            "VIP": {"type": "OpenApiConnection", "runAfter": {},
                                    "inputs": {"host": {"apiId": ".../apis/shared_slack",
                                                        "operationId": "PostMessage"},
                                               "parameters": {"text": "vip"}}}}},
                        "Free": {"case": "free", "actions": {}},
                    },
                    "default": {"actions": {
                        "Log": {"type": "Compose", "runAfter": {}, "inputs": "meh"}}},
                },
                "Done": {"type": "Compose", "runAfter": {"Route": ["Succeeded"]},
                         "inputs": "done"},
            },
        }},
    }
    from maverick.flow.ir import NODE_SWITCH
    f, report = to_flow_with_report(power_automate.translate(wf))
    _assert_preview_valid(f)
    sw = next(n for n in f.nodes.values() if n.kind == NODE_SWITCH)
    assert sw.condition == "tier"
    values = {c["value"] for c in sw.cases}
    assert values == {"gold", "free"}
    # The gold arm gates the classified Slack action, then rejoins after it.
    gold_to = next(c["to"] for c in sw.cases if c["value"] == "gold")
    done = next(n for n in f.nodes.values() if (n.label or "") == "Done")
    gold_gate = f.nodes[gold_to]
    gold_action = f.nodes[gold_gate.next]
    assert gold_gate.kind == NODE_APPROVAL
    assert gold_action.tool == "slack_bot" and gold_action.next == done.id
    assert gold_action.params["op"] == "post"
    # an empty case arm falls straight through to the join
    free_to = next(c["to"] for c in sw.cases if c["value"] == "free")
    assert free_to == done.id
    # the default arm is the switch's next
    assert f.nodes[sw.next].label == "Log"
    assert next(r for r in report if r["step"] == "Route")["fidelity"] == "preserved"


def test_power_automate_until_becomes_while_with_negated_exit():
    wf = {
        "properties": {"displayName": "Poll until done", "definition": {
            "triggers": {"Manual": {"type": "Request"}},
            "actions": {"Keep_checking": {
                "type": "Until", "runAfter": {},
                "expression": {"equals": ["@triggerBody()?['status']", "done"]},
                "limit": {"count": 12},
                "actions": {"Check": {"type": "Compose", "runAfter": {},
                                      "inputs": "@body('poll')"}},
            }},
        }},
    }
    from maverick.flow.ir import NODE_WHILE
    f, report = to_flow_with_report(power_automate.translate(wf))
    _assert_preview_valid(f)
    loop = next(n for n in f.nodes.values() if n.kind == NODE_WHILE)
    assert loop.condition == "status != 'done'"       # exit condition negated
    assert loop.limit == 12 and loop.body is not None
    assert next(r for r in report if r["step"] == "Keep_checking")["fidelity"] == "approximated"


def test_power_automate_scope_becomes_scope_node():
    wf = {
        "properties": {"displayName": "Grouped", "definition": {
            "triggers": {"Manual": {"type": "Request"}},
            "actions": {"Try_block": {
                "type": "Scope", "runAfter": {},
                "actions": {"Step": {"type": "Compose", "runAfter": {}, "inputs": "x"}},
            }},
        }},
    }
    from maverick.flow.ir import NODE_SCOPE
    f, report = to_flow_with_report(power_automate.translate(wf))
    _assert_preview_valid(f)
    sc = next(n for n in f.nodes.values() if n.kind == NODE_SCOPE)
    assert sc.body is not None and len(sc.body.nodes) == 1
    assert next(r for r in report if r["step"] == "Try_block")["fidelity"] == "preserved"


def test_workato_if_and_repeat_are_captured_structurally():
    import json as _json

    from maverick.automation_import import workato
    from maverick.flow.ir import NODE_FOREACH
    recipe = {
        "id": 7, "name": "Escalate big deals", "running": True,
        "code": _json.dumps({
            "provider": "salesforce", "name": "new_opportunity",
            "block": [
                {"keyword": "if", "description": "Big deal?",
                 "input": {"a": "#{_('data.salesforce.amount')}",
                           "operation": "greater_than", "b": "10000"},
                 "block": [
                     {"keyword": "action", "provider": "slack", "name": "post_message",
                      "input": {"text": "big deal!"}},
                 ]},
                {"keyword": "foreach", "description": "Per line item",
                 "input": {"source": "#{_('data.salesforce.line_items')}"},
                 "block": [
                     {"keyword": "action", "provider": "quickbooks", "name": "create_invoice_line",
                      "input": {}},
                 ]},
                {"keyword": "action", "provider": "gmail", "name": "send_email",
                 "input": {"to": "sales@x.com"}},
            ],
        }),
    }
    f, report = to_flow_with_report(workato.translate(recipe))
    _assert_preview_valid(f)
    branch = next(n for n in f.nodes.values() if n.kind == NODE_BRANCH)
    assert branch.condition == "amount > 10000"
    then_gate = f.nodes[branch.if_true]
    then_node = f.nodes[then_gate.next]
    loop = next(n for n in f.nodes.values() if n.kind == NODE_FOREACH)
    assert then_gate.kind == NODE_APPROVAL
    assert then_node.tool == "slack_bot"
    assert then_node.params["op"] == "post"
    gate = f.nodes[then_node.next]
    assert gate.kind == NODE_APPROVAL and gate.next == loop.id
    assert branch.if_false == gate.id         # no-match falls through to gate
    assert loop.items == "line_items" and loop.body is not None
    assert all(n.kind != NODE_APPROVAL for n in loop.body.nodes.values())
    fidelity = {r["step"]: r["fidelity"] for r in report}
    assert fidelity["Big deal?"] == "preserved"
    assert fidelity["Per line item"] == "preserved"


def test_uipath_release_stays_one_imported_step_behind_a_gate():
    # A UiPath Release has no exposed graph: one process action plus governance.
    from maverick.automation_import import uipath
    rel = {"Name": "Invoice bot", "ProcessKey": "InvoiceBot", "Key": "k1"}
    f, report = to_flow_with_report(uipath.translate(rel))
    _assert_preview_valid(f)
    assert len(f.nodes) == 2
    gate = f.nodes[f.start]
    assert gate.kind == NODE_APPROVAL and f.nodes[gate.next].tool == "uipath"


def test_uipath_exported_activity_tree_is_captured_structurally():
    from maverick.automation_import import ir as iir
    from maverick.flow.ir import NODE_FOREACH, NODE_SCOPE, NODE_WHILE
    # a raw carrying an exported activity tree (Sequence with If/ForEach/While/TryCatch)
    raw = {
        "Name": "Process invoices",
        "workflow": {"type": "Sequence", "activities": [
            {"type": "If", "displayName": "High value?",
             "condition": "amount > 1000",
             "then": {"activities": [
                 {"type": "InvokeWorkflow", "displayName": "Escalate"}]},
             "else": {"activities": [
                 {"type": "WriteLine", "displayName": "Log"}]}},
            {"type": "ForEach", "displayName": "Per line", "values": "lines",
             "activities": [{"type": "InvokeWorkflow", "displayName": "Post line"}]},
            {"type": "While", "displayName": "Retry", "condition": "done != yes",
             "activities": [{"type": "InvokeWorkflow", "displayName": "Attempt"}]},
            {"type": "TryCatch", "displayName": "Guarded",
             "try": {"activities": [{"type": "InvokeWorkflow", "displayName": "Risky"}]}},
        ]},
    }
    a = iir.ImportedAutomation("uipath", "1", "Process invoices",
                               iir.ImportedTrigger(kind=iir.TRIGGER_MANUAL),
                               steps=[iir.ImportedStep(name="x")], raw=raw)
    f, report = to_flow_with_report(a)
    _assert_preview_valid(f)
    kinds = {n.kind for n in f.nodes.values()}
    assert NODE_BRANCH in kinds and NODE_FOREACH in kinds
    assert NODE_WHILE in kinds and NODE_SCOPE in kinds
    branch = next(n for n in f.nodes.values() if n.kind == NODE_BRANCH)
    assert branch.condition == "amount > 1000"
    assert {r["fidelity"] for r in report if r["kind"] == NODE_BRANCH} == {"preserved"}


def test_uipath_trycatch_wrapping_a_loop_keeps_the_loop_node():
    # A TryCatch whose Try is a single container activity (a While) must keep
    # the While inside the scope body -- lowering Try AS an activity, not its
    # children (which would drop the loop and run its steps once).
    from maverick.automation_import import ir as iir
    from maverick.flow.ir import NODE_SCOPE, NODE_WHILE
    raw = {
        "Name": "Guarded loop",
        "workflow": {"type": "Sequence", "activities": [
            {"type": "TryCatch", "displayName": "Guarded",
             "try": {"type": "While", "displayName": "Retry", "condition": "done != yes",
                     "activities": [{"type": "InvokeWorkflow", "displayName": "Attempt"}]}},
        ]},
    }
    a = iir.ImportedAutomation("uipath", "1", "Guarded loop",
                               iir.ImportedTrigger(kind=iir.TRIGGER_MANUAL),
                               steps=[iir.ImportedStep(name="x")], raw=raw)
    f, _report = to_flow_with_report(a)
    _assert_preview_valid(f)
    scope = next(n for n in f.nodes.values() if n.kind == NODE_SCOPE)
    assert scope.body is not None
    body_kinds = {n.kind for n in scope.body.nodes.values()}
    assert NODE_WHILE in body_kinds   # the loop survived, not unwrapped to its steps


def test_every_lowering_path_emits_a_report():
    from maverick.automation_import import ir as iir
    a = iir.ImportedAutomation("make", "9", "x", iir.ImportedTrigger(kind=iir.TRIGGER_WEBHOOK),
                               steps=[iir.ImportedStep(name="s1")])
    _, report = to_flow_with_report(a)
    assert report and report[0]["fidelity"] in ("preserved", "approximated")
    _, n8n_report = to_flow_with_report(n8n.translate(_IF_WF))
    assert any(r["kind"] == NODE_BRANCH and r["fidelity"] == "preserved" for r in n8n_report)


# ---- Make (Integromat) router structural capture -----------------------------

_MAKE_ROUTER = {
    "name": "Route lead",
    "flow": [
        {"id": 1, "module": "gateway:CustomWebHook", "mapper": {}},
        {"id": 2, "module": "slack:CreateMessage", "mapper": {"text": "hi"},
         "metadata": {"designer": {"name": "Greet"}}},
        {"id": 3, "module": "builtin:BasicRouter", "routes": [
            {"filter": {"name": "hot", "conditions": [[
                {"a": "score", "o": "number:greater", "b": "80"}]]},
             "flow": [{"id": 4, "module": "hubspot:createDeal", "mapper": {}}]},
            {"flow": [{"id": 5, "module": "slack:CreateMessage", "mapper": {"text": "later"},
                       "metadata": {"designer": {"name": "Nurture"}}}]},
        ]},
    ],
}


def test_make_router_becomes_parallel_fan_out():
    from maverick.automation_import import make
    f, report = to_flow_with_report(make.translate(_MAKE_ROUTER))
    _assert_preview_valid(f)
    router = next(n for n in f.nodes.values() if n.kind == NODE_PARALLEL)
    assert len(router.branches) == 2
    guarded = router.branches[0]
    branch = next(n for n in guarded.nodes.values() if n.kind == NODE_BRANCH)
    assert branch.condition.endswith("> 80")             # filter operator mapped
    assert guarded.nodes[branch.if_true].kind == NODE_ACTION
    assert router.branches[1].nodes[router.branches[1].start].kind == NODE_ACTION
    # The pre-router connector and the risky parallel container each have a
    # durable root gate; no unresumable gate is placed inside either branch.
    first_gate = f.nodes[f.start]
    first = f.nodes[first_gate.next]
    router_gate = f.nodes[first.next]
    assert first_gate.kind == NODE_APPROVAL and first.kind == NODE_ACTION
    assert router_gate.kind == NODE_APPROVAL and router_gate.next == router.id
    assert all(all(n.kind != NODE_APPROVAL for n in b.nodes.values())
               for b in router.branches)
    assert any(e["kind"] == NODE_PARALLEL and e["fidelity"] == "preserved" for e in report)


def test_make_router_runs_all_matching_routes():
    from maverick.automation_import import make
    from maverick.flow.runner import STATUS_COMPLETED, run_flow

    bp = {"name": "fanout", "flow": [
        {"id": 1, "module": "gateway:CustomWebHook"},
        {"id": 2, "module": "builtin:BasicRouter", "routes": [
            {"filter": {"conditions": [[{"a": "amount", "o": "number:greater", "b": "100"}]]},
             "flow": [{"id": 3, "module": "audit:Log", "mapper": {}}]},
            {"filter": {"conditions": [[{"a": "amount", "o": "number:greater", "b": "50"}]]},
             "flow": [{"id": 4, "module": "approval:Request", "mapper": {}}]},
        ]},
    ]}
    f = to_flow(make.translate(bp))
    seen = []
    result = run_flow(
        f,
        agent_fn=lambda node, brief, data: (brief, None),
        action_fn=lambda node, params, data: seen.append(node.tool) or ({"ok": True}, None),
        approve_fn=lambda node, data: "approved",
        data={"amount": 200},
    )
    assert result.status == STATUS_COMPLETED
    assert sorted(seen) == ["approval", "audit"]


def test_make_without_a_router_still_lowers_linearly():
    from maverick.automation_import import make
    bp = {"name": "flat", "flow": [
        {"id": 1, "module": "gateway:CustomWebHook"},
        {"id": 2, "module": "slack:CreateMessage", "mapper": {"text": "hi"}},
        {"id": 3, "module": "hubspot:createContact", "mapper": {}},
    ]}
    f = to_flow(make.translate(bp))
    _assert_preview_valid(f)
    assert not any(n.kind == NODE_BRANCH for n in f.nodes.values())


def test_uipath_invocation_is_reported_approximated():
    # A UiPath process is imported as a single start_job action, but its internal
    # If/Switch/While/ForEach live in .xaml the Orchestrator API doesn't return --
    # so the report must say "approximated", not falsely claim the branches survived.
    from maverick.automation_import import uipath
    f, report = to_flow_with_report(uipath.translate({"Name": "Invoice bot", "Key": "k1"}))
    _assert_preview_valid(f)
    action_entry = next(e for e in report if e["kind"] == NODE_ACTION)
    gate_entry = next(e for e in report if e["kind"] == NODE_APPROVAL)
    assert action_entry["fidelity"] == "approximated"
    assert "Orchestrator" in action_entry["note"]
    assert "approval gate" in gate_entry["note"]
