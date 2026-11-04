"""The extended node vocabulary: switch, while, wait_event, scope (try/catch),
concurrent foreach, and choice/expiring approvals."""
from __future__ import annotations

from maverick.flow.ir import Flow
from maverick.flow.runner import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PAUSED_EVENT,
    STATUS_REJECTED,
    run_flow,
)


def _noop_agent(node, brief, data):
    return (f"ran:{brief}", 1.0)


def _run(flow_dict, data=None, **kw):
    flow = Flow.from_dict(flow_dict)
    assert flow.validate() == [], flow.validate()
    return run_flow(flow, agent_fn=_noop_agent,
                    action_fn=lambda n, p, d: ("", 1.0), data=data, **kw)


def test_switch_routes_on_case_value_and_defaults():
    f = {
        "id": "sw", "name": "sw", "start": "s",
        "nodes": [
            {"id": "s", "kind": "switch", "condition": "kind",
             "cases": [{"value": "bug", "to": "b"}, {"value": "sales", "to": "c"}],
             "next": "d"},
            {"id": "b", "kind": "agent", "brief": "triage bug", "output": "r"},
            {"id": "c", "kind": "agent", "brief": "route to sales", "output": "r"},
            {"id": "d", "kind": "agent", "brief": "default lane", "output": "r"},
        ],
    }
    assert _run(f, {"kind": "bug"}).data["r"] == "ran:triage bug"
    assert _run(f, {"kind": "sales"}).data["r"] == "ran:route to sales"
    assert _run(f, {"kind": "other"}).data["r"] == "ran:default lane"


def test_switch_case_to_unknown_node_fails_validation():
    f = Flow.from_dict({
        "id": "sw", "name": "sw", "start": "s",
        "nodes": [{"id": "s", "kind": "switch", "condition": "k",
                   "cases": [{"value": "x", "to": "nope"}]}],
    })
    assert any("unknown node" in e for e in f.validate())


def test_while_loops_until_condition_flips_and_respects_cap():
    f = {
        "id": "wh", "name": "wh", "start": "w",
        "nodes": [{"id": "w", "kind": "while", "condition": "done != yes",
                   "limit": 50, "output": "passes",
                   "body": {"id": "", "name": "b", "start": "step",
                            "nodes": [{"id": "step", "kind": "action",
                                       "tool": "web_search", "output": "n"}]}}],
    }
    ticks = []

    def action(node, params, d):
        ticks.append(1)
        if len(ticks) >= 3:
            d["done"] = "yes"          # body flips the condition
        return ("t", 1.0)
    flow = Flow.from_dict(f)
    res = run_flow(flow, agent_fn=_noop_agent, action_fn=action, data={"done": "no"})
    assert res.status == STATUS_COMPLETED
    # 3rd pass sets done=yes; the while re-checks and stops
    assert len(ticks) == 3 and res.data["passes"] == 3


def test_while_default_cap_stops_a_runaway_loop():
    f = {
        "id": "wh2", "name": "wh", "start": "w",
        "nodes": [{"id": "w", "kind": "while", "condition": "x == 1",
                   "output": "passes",
                   "body": {"id": "", "name": "b", "start": "a",
                            "nodes": [{"id": "a", "kind": "agent", "brief": "spin"}]}}],
    }
    res = _run(f, {"x": 1})            # condition never flips
    assert res.status == STATUS_COMPLETED and res.data["passes"] == 100


def test_wait_event_pauses_and_resumes_with_merged_data():
    f = {
        "id": "we", "name": "we", "start": "w",
        "nodes": [
            {"id": "w", "kind": "wait_event", "prompt": "waiting for the callback",
             "next": "a"},
            {"id": "a", "kind": "agent", "brief": "handle {{payload}}", "output": "r"},
        ],
    }
    res = _run(f)
    assert res.status == STATUS_PAUSED_EVENT and res.cursor == "w"
    assert res.prompt == "waiting for the callback"
    resumed = _run(f, resume={"node_id": "w",
                              "data": dict(res.data, payload="evt-9")})
    assert resumed.status == STATUS_COMPLETED
    assert resumed.data["r"] == "ran:handle evt-9"


def test_scope_catches_a_body_failure_and_routes_on_error():
    f = {
        "id": "sc", "name": "sc", "start": "s",
        "nodes": [
            {"id": "s", "kind": "scope", "on_error": "h", "next": "ok",
             "body": {"id": "", "name": "b", "start": "boom",
                      "nodes": [{"id": "boom", "kind": "action",
                                 "tool": "web_search"}]}},
            {"id": "h", "kind": "agent", "brief": "recover from {{_error}}", "output": "r"},
            {"id": "ok", "kind": "agent", "brief": "all good", "output": "r"},
        ],
    }

    def broken(node, params, d):
        raise RuntimeError("connector down")
    flow = Flow.from_dict(f)
    res = run_flow(flow, agent_fn=_noop_agent, action_fn=broken)
    assert res.status == STATUS_COMPLETED
    assert res.data["r"].startswith("ran:recover from")
    assert "connector down" in res.data["_error"]


def test_scope_redacts_executor_secrets_before_catch_branch():
    secret = "ghp_" + "Z" * 36  # pragma: allowlist secret
    flow = Flow.from_dict({
        "id": "safe-catch", "name": "safe-catch", "start": "scope",
        "nodes": [
            {
                "id": "scope", "kind": "scope", "on_error": "recover",
                "body": {
                    "id": "", "name": "body", "start": "boom",
                    "nodes": [{"id": "boom", "kind": "action", "tool": "web_search"}],
                },
            },
            {"id": "recover", "kind": "agent", "brief": "recover {{_error}}"},
        ],
    })

    def broken(node, params, data):
        raise RuntimeError(f"Authorization: Bearer {secret}")

    result = run_flow(flow, agent_fn=_noop_agent, action_fn=broken)

    assert result.status == STATUS_COMPLETED
    assert secret not in result.data["_error"]
    assert "redacted" in result.data["_error"].lower()


def test_nested_wait_event_fails_closed_not_open():
    # A wait_event buried in a foreach body cannot pause; it must fail closed
    # with an actionable error rather than silently continue before the event's data arrives.
    f = {
        "id": "nw", "name": "nw", "start": "l",
        "nodes": [{"id": "l", "kind": "foreach", "items": "rows", "var": "row",
                   "next": "after",
                   "body": {"id": "", "name": "b", "start": "w",
                            "nodes": [
                                {"id": "w", "kind": "wait_event", "prompt": "cb", "next": "x"},
                                {"id": "x", "kind": "agent", "brief": "should NOT run", "output": "r"},
                            ]}},
                  {"id": "after", "kind": "agent", "brief": "downstream", "output": "done"}],
    }
    ran = []
    res = run_flow(Flow.from_dict(f),
                   agent_fn=lambda n, b, d: (ran.append(b) or ("x", 1.0)),
                   action_fn=lambda n, p, d: ("", 1.0), data={"rows": ["a"]})
    assert res.status == STATUS_FAILED
    assert "Move it to the main flow" in res.error
    assert "should NOT run" not in ran and "downstream" not in ran


def test_resume_with_missing_node_fails_closed_not_restart():
    # If the paused node no longer exists in the (edited) flow, resuming must
    # fail closed, never silently restart the whole flow from the top.
    f = {
        "id": "re", "name": "re", "start": "a",
        "nodes": [{"id": "a", "kind": "agent", "brief": "step", "output": "r"}],
    }
    ran = []
    res = run_flow(Flow.from_dict(f),
                   agent_fn=lambda n, b, d: (ran.append(b) or ("x", 1.0)),
                   action_fn=lambda n, p, d: ("", 1.0),
                   resume={"node_id": "ghost", "data": {}})
    assert res.status == STATUS_FAILED and res.cursor == "ghost"
    assert "no longer exists" in res.error
    assert ran == []                       # nothing re-executed from the top


def test_resume_plain_approval_rejects_any_non_approved_string():
    # A no-choices approval resumed with a bogus verdict must NOT be treated as
    # approved (the human-gate-bypass fix).
    f = {
        "id": "ap", "name": "ap", "start": "a",
        "nodes": [
            {"id": "a", "kind": "approval", "prompt": "ok?", "next": "b"},
            {"id": "b", "kind": "agent", "brief": "gated action", "output": "r"},
        ],
    }
    ran = []

    def agent(n, b, d):
        ran.append(b)
        return ("x", 1.0)
    for bogus in ("banana", "approve", "ok", "yes", "deny"):
        res = run_flow(Flow.from_dict(f), agent_fn=agent,
                       action_fn=lambda n, p, d: ("", 1.0),
                       resume={"node_id": "a", "data": {}, "decision": bogus})
        assert res.status == STATUS_REJECTED, bogus
    assert ran == []                       # the gated action never ran
    # only the literal "approved" continues
    ok = run_flow(Flow.from_dict(f), agent_fn=agent,
                  action_fn=lambda n, p, d: ("", 1.0),
                  resume={"node_id": "a", "data": {}, "decision": "approved"})
    assert ok.status == STATUS_COMPLETED and ran == ["gated action"]


def test_approval_expires_after_sets_resume_at_over_timeout():
    # expires_after is the approval's expiry; a bare execution `timeout` still
    # works as a fallback for flows saved before the field existed.
    f = {"id": "ax", "name": "ax", "start": "a",
         "nodes": [{"id": "a", "kind": "approval", "prompt": "ok?", "expires_after": 90}]}
    now = [1000.0]
    res = run_flow(Flow.from_dict(f), agent_fn=_noop_agent,
                   action_fn=lambda n, p, d: ("", 1.0), now=lambda: now[0])
    assert res.status == "paused_approval" and res.resume_at == 1090.0
    f2 = {"id": "ax2", "name": "ax", "start": "a",
          "nodes": [{"id": "a", "kind": "approval", "prompt": "ok?", "timeout": 60}]}
    res2 = run_flow(Flow.from_dict(f2), agent_fn=_noop_agent,
                    action_fn=lambda n, p, d: ("", 1.0), now=lambda: now[0])
    assert res2.resume_at == 1060.0                 # legacy timeout still honored


def test_approval_expiry_routes_to_on_expire_escalation():
    f = {
        "id": "esc", "name": "esc", "start": "a",
        "nodes": [
            {"id": "a", "kind": "approval", "prompt": "sign off?", "expires_after": 60,
             "on_expire": "esc", "output": "verdict", "next": "ok"},
            {"id": "esc", "kind": "agent", "brief": "escalate to manager", "output": "r"},
            {"id": "ok", "kind": "agent", "brief": "proceed", "output": "r"},
        ],
    }
    # the sweep resumes an expired approval with the out-of-band expired flag
    res = run_flow(Flow.from_dict(f), agent_fn=_noop_agent,
                   action_fn=lambda n, p, d: ("", 1.0),
                   resume={"node_id": "a", "data": {}, "expired": True})
    assert res.status == STATUS_COMPLETED
    assert res.data["verdict"] == "expired" and res.data["r"] == "ran:escalate to manager"


def test_approval_expiry_without_on_expire_rejects():
    f = {"id": "ex2", "name": "ex", "start": "a",
         "nodes": [{"id": "a", "kind": "approval", "prompt": "ok?", "expires_after": 60, "next": "b"},
                   {"id": "b", "kind": "agent", "brief": "go", "output": "r"}]}
    res = run_flow(Flow.from_dict(f), agent_fn=_noop_agent,
                   action_fn=lambda n, p, d: ("", 1.0),
                   resume={"node_id": "a", "data": {}, "expired": True})
    assert res.status == STATUS_REJECTED           # fail closed, no on_expire


def test_forged_expired_decision_string_is_not_an_expiry():
    # A caller CANNOT trigger the escalation lane through the verdict channel:
    # an unlisted decision string (e.g. the old in-band marker) fails closed.
    f = {
        "id": "esc2", "name": "esc2", "start": "a",
        "nodes": [
            {"id": "a", "kind": "approval", "prompt": "sign off?", "expires_after": 60,
             "on_expire": "esc", "output": "verdict", "next": "ok"},
            {"id": "esc", "kind": "agent", "brief": "escalate to manager", "output": "r"},
            {"id": "ok", "kind": "agent", "brief": "proceed", "output": "r"},
        ],
    }
    res = run_flow(Flow.from_dict(f), agent_fn=_noop_agent,
                   action_fn=lambda n, p, d: ("", 1.0),
                   resume={"node_id": "a", "data": {}, "decision": "expired"})
    assert res.status == STATUS_REJECTED


def test_scope_without_catch_still_fails_the_run():
    f = {
        "id": "sc2", "name": "sc", "start": "s",
        "nodes": [{"id": "s", "kind": "scope",
                   "body": {"id": "", "name": "b", "start": "boom",
                            "nodes": [{"id": "boom", "kind": "action",
                                       "tool": "web_search"}]}}],
    }

    def broken(node, params, d):
        raise RuntimeError("nope")
    res = run_flow(Flow.from_dict(f), agent_fn=_noop_agent, action_fn=broken)
    assert res.status == "failed" and "nope" in res.error


def test_concurrent_foreach_preserves_item_order():
    f = {
        "id": "cf", "name": "cf", "start": "l",
        "nodes": [{"id": "l", "kind": "foreach", "items": "rows", "var": "row",
                   "concurrent": True, "output": "out",
                   "body": {"id": "", "name": "b", "start": "a",
                            "nodes": [{"id": "a", "kind": "agent",
                                       "brief": "handle {{row}}", "output": "r"}]}}],
    }
    res = _run(f, {"rows": ["x", "y", "z"]})
    assert res.status == STATUS_COMPLETED
    assert [s["r"] for s in res.data["out"]] == ["ran:handle x", "ran:handle y", "ran:handle z"]


def test_approval_choice_verdict_continues_and_records():
    f = {
        "id": "ap", "name": "ap", "start": "a",
        "nodes": [
            {"id": "a", "kind": "approval", "prompt": "ship, hold, or escalate?",
             "choices": ["ship", "hold"], "output": "verdict", "next": "s"},
            {"id": "s", "kind": "switch", "condition": "verdict",
             "cases": [{"value": "ship", "to": "go"}], "next": "stop"},
            {"id": "go", "kind": "agent", "brief": "shipping", "output": "r"},
            {"id": "stop", "kind": "agent", "brief": "holding", "output": "r"},
        ],
    }
    flow = Flow.from_dict(f)
    res = run_flow(flow, agent_fn=_noop_agent, action_fn=lambda n, p, d: ("", 1.0),
                   approve_fn=lambda node, d: "ship")
    assert res.status == STATUS_COMPLETED
    assert res.data["verdict"] == "ship" and res.data["r"] == "ran:shipping"


def test_approval_expiry_sets_resume_at():
    f = {
        "id": "ax", "name": "ax", "start": "a",
        "nodes": [{"id": "a", "kind": "approval", "prompt": "ok?", "timeout": 60}],
    }
    now = [1000.0]
    res = run_flow(Flow.from_dict(f), agent_fn=_noop_agent,
                   action_fn=lambda n, p, d: ("", 1.0), now=lambda: now[0])
    assert res.status == "paused_approval" and res.resume_at == 1060.0


def test_new_kinds_round_trip_serialization():
    d = {
        "id": "rt", "name": "rt", "start": "s",
        "nodes": [
            {"id": "s", "kind": "switch", "condition": "k",
             "cases": [{"value": "a", "to": "w"}], "next": "w"},
            {"id": "w", "kind": "while", "condition": "x == 1", "limit": 5,
             "body": {"id": "", "name": "b", "start": "n",
                      "nodes": [{"id": "n", "kind": "agent", "brief": "b"}]},
             "next": "e"},
            {"id": "e", "kind": "wait_event", "prompt": "cb", "next": "f"},
            {"id": "f", "kind": "foreach", "items": "r", "concurrent": True,
             "body": {"id": "", "name": "b", "start": "n",
                      "nodes": [{"id": "n", "kind": "agent", "brief": "b"}]}},
        ],
    }
    flow = Flow.from_dict(d)
    again = Flow.from_dict(flow.to_dict())
    assert again.nodes["s"].cases == [{"value": "a", "to": "w"}]
    assert again.nodes["w"].limit == 5 and again.nodes["w"].body is not None
    assert again.nodes["f"].concurrent is True
    assert again.validate() == []
