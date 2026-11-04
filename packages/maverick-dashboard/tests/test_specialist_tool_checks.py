"""Saved answer checks that say which tools a specialist calls, run against recording stubs only."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

API = "/api/v1/workforce-ops/test-suite"
DRAFTS = "/api/v1/specialist-drafts"
PACK = "proc_po_chaser"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import learning_jobs

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.config.dashboard_overrides_path", lambda: tmp_path / "dashboard.toml")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    config.reset_config_cache()
    dash_app._world_cache.clear()
    learning_jobs.clear_for_tests()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), tmp_path
    learning_jobs.clear_for_tests()
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: rows.append(payload) or True)
    return rows


@pytest.fixture
def no_real_tools(monkeypatch):
    """Any touch of the real tool registry, its sandbox or a subprocess fails the test."""
    import subprocess

    import maverick.tools as tools

    def boom(*_args, **_kwargs):
        raise AssertionError("a real tool or process was reached during a tool check")

    monkeypatch.setattr(tools.ToolRegistry, "run", boom)
    monkeypatch.setattr(tools.ToolRegistry, "get", boom)
    monkeypatch.setattr(tools, "base_registry", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    return boom


def _case(specialist="finance_ap", **extra):
    row = {"specialist": specialist,
           "task": "Two invoices have the same purchase order. What would you do?",
           "includes": ["duplicate"], "excludes": ["payment sent"],
           "refusal": False, "citation": False}
    row.update(extra)
    return row


def _tool_case(**extra):
    row = _case(with_tools=True, tools_called=[{"name": "send_email", "contains": "Acme"}],
                tools_not_called=["delete_record"], tool_results=[])
    row.update(extra)
    return row


def _knob(tmp, text):
    from maverick import config

    (tmp / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


def _wait(client, response):
    assert response.status_code == 200, response.text
    job = response.json()["job"]
    deadline = time.time() + 15
    while job["state"] in {"admitted", "running", "stopping"}:
        assert time.time() < deadline, job
        time.sleep(.05)
        job = client.get("/api/v1/learning-ops/jobs/" + job["id"]).json()["job"]
    return job


def _revisions(app, specialist="finance_ap"):
    rows = app.get(API + "/customer", params={"specialist": specialist}).json()["cases"]
    return {row["id"]: row["revision"] for row in rows}


def _scripted_llm(monkeypatch, script):
    """Replay ``script`` (LLMResponse objects) and record every provider call."""
    from maverick import llm

    calls = []

    def answer(self, system, messages, **kwargs):
        calls.append({"system": system, "messages": [dict(m) for m in messages], "kwargs": kwargs})
        return script.pop(0) if script else llm.LLMResponse(
            text="FINAL: (script exhausted)", thinking=None, tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(llm.LLM, "complete", answer)
    return calls


def _use(name, args, call_id="call-1"):
    from maverick import llm

    return llm.LLMResponse(text="", thinking=None, stop_reason="tool_use",
                           tool_calls=[llm.ToolCall(id=call_id, name=name, input=args)])


def _say(text):
    from maverick import llm

    return llm.LLMResponse(text=text, thinking=None, tool_calls=[], stop_reason="end_turn")


# ---- pure checks ----------------------------------------------------------------

def test_a_tool_check_cannot_be_created_while_the_switch_is_off():
    from maverick_dashboard import specialist_tool_checks as tools

    with pytest.raises(ValueError, match="turned off"):
        tools.normalized(enabled=False, with_tools=True, called=[{"name": "send_email", "contains": ""}],
                         not_called=[], results=[])
    # A check without tools keeps today's shape whatever the switch says.
    plain = tools.normalized(enabled=False, with_tools=False, called=[], not_called=[], results=[])
    assert plain == {"with_tools": False, "tools_called": [], "tools_not_called": [], "tool_results": []}


def test_tool_fields_reject_empty_contradictory_and_malformed_entries():
    from maverick_dashboard import specialist_tool_checks as tools

    def build(**kwargs):
        base = {"enabled": True, "with_tools": True, "called": [], "not_called": [], "results": []}
        base.update(kwargs)
        return tools.normalized(**base)

    with pytest.raises(ValueError, match="at least one tool"):
        build()
    with pytest.raises(ValueError, match="both required and forbidden"):
        build(called=[{"name": "send_email", "contains": ""}], not_called=["send_email"])
    with pytest.raises(ValueError, match="tool name"):
        build(not_called=["rm -rf /"])
    with pytest.raises(ValueError, match="canned result"):
        build(not_called=["send_email"], results=[{"name": "send_email", "text": "   "}])
    with pytest.raises(ValueError, match="tool lines|Turn on"):
        tools.normalized(enabled=True, with_tools=False, called=[{"name": "x", "contains": ""}],
                         not_called=[], results=[])
    clean = build(called=[{"name": " send_email ", "contains": " Acme "}], not_called=["delete_record"],
                  results=[{"name": "send_email", "text": "Sent."}])
    assert clean["tools_called"] == [{"name": "send_email", "contains": "Acme"}]
    assert clean["tools_not_called"] == ["delete_record"]
    assert clean["tool_results"] == [{"name": "send_email", "text": "Sent."}]


def test_each_expectation_passes_only_for_the_right_call_with_the_text():
    from maverick_dashboard import specialist_tool_checks as tools

    case = _tool_case()
    right = [{"name": "send_email", "arguments": '{"to": "Acme"}', "answer": "canned"}]
    results = tools.tool_check_results(case, right)
    assert [r["passed"] for r in results] == [True, True]
    assert "Called send_email" in results[0]["result"] and "Did not call delete_record" in results[1]["result"]

    wrong_text = [{"name": "send_email", "arguments": '{"to": "Other"}', "answer": "canned"}]
    results = tools.tool_check_results(case, wrong_text)
    assert results[0]["passed"] is False and "no call included" in results[0]["result"]

    forbidden = right + [{"name": "delete_record", "arguments": "{}", "answer": "not_available"}]
    results = tools.tool_check_results(case, forbidden)
    assert results[1]["passed"] is False and "must not call" in results[1]["result"]

    missing = tools.tool_check_results(case, [])
    assert missing[0]["passed"] is False and "Did not call send_email" in missing[0]["result"]


def test_the_stubs_record_each_call_and_answer_with_the_canned_text_or_a_fixed_refusal():
    from maverick_dashboard import specialist_tool_checks as tools

    stubs = tools.ToolStubs(["lookup_invoice", "send_email"], {"lookup_invoice": "Invoice 77 is a duplicate."})
    assert stubs.answer("lookup_invoice", {"id": 77}) == "Invoice 77 is a duplicate."
    assert stubs.answer("send_email", {"to": "Acme"}) == tools._NOT_AVAILABLE
    assert stubs.answer("format_disk", {"path": "/"}) == tools._NOT_AVAILABLE
    assert [c["answer"] for c in stubs.calls] == ["canned", "not_available", "not_offered"]
    assert stubs.calls[0]["arguments"] == '{"id": 77}'
    stubs.answer("send_email", {"blob": "a" * 5000})
    assert len(stubs.calls[-1]["arguments"]) <= tools._RECORD_LIMIT
    assert len(tools._bounded("y" * 5000, tools._RECORD_LIMIT)) <= tools._RECORD_LIMIT


def test_the_text_a_call_must_include_is_matched_against_the_whole_argument_values():
    from maverick_dashboard import specialist_test_sets as saved
    from maverick_dashboard import specialist_tool_checks as tools

    quoted = tools.ToolStubs(["send_email"], {})
    quoted.answer("send_email", {"to": 'Acme "Ltd"'})
    quoted_case = _tool_case(tools_called=[{"name": "send_email", "contains": 'Acme "Ltd"'}])
    assert tools.tool_check_results(quoted_case, quoted.calls)[0]["passed"] is True

    # The text sits after the first characters kept for the run record, so it must still count.
    long = tools.ToolStubs(["send_email"], {})
    long.answer("send_email", {"body": "x" * 1200 + " END"})
    long_case = _tool_case(tools_called=[{"name": "send_email", "contains": "END"}])
    assert tools.tool_check_results(long_case, long.calls)[0]["passed"] is True

    # The record keeps only the bounded arguments, never the matching text.
    stored = saved.grade({**long_case, "id": "d" * 32, "revision": 1, "task": "Late. What now?", "includes": ["chase"],
                          "excludes": [], "refusal": False, "citation": False}, "Chase the supplier now.", tool_calls=long.calls)
    assert stored["passed"] is True and set(stored["tool_calls"][0]) == {"name", "arguments", "answer"}
    assert len(stored["tool_calls"][0]["arguments"]) <= tools._RECORD_LIMIT


def test_each_tool_step_gets_an_equal_share_of_the_run_output_allowance():
    from maverick_dashboard import specialist_tool_checks as tools

    assert tools.tool_step_tokens(512) == 128  # a tool check's four steps share its four-question allowance
    assert tools.tool_step_tokens(None) == 256
    assert tools.tool_step_tokens(10) == 32
    assert tools.tool_step_tokens(10_000) == 256


def test_offered_tools_are_the_named_ones_plus_the_allowed_ones_minus_the_denied():
    from maverick_dashboard import specialist_tool_checks as tools

    case = _tool_case(tool_results=[{"name": "lookup_invoice", "text": "Found."}])
    offered = tools.offered_tools(case, allow=["summarize", "delete_record"], deny=["delete_record", "shell"])
    assert offered[:3] == ["send_email", "delete_record", "lookup_invoice"]  # named checks always stay offered
    assert "summarize" in offered and "shell" not in offered
    assert len(offered) <= tools.MAX_TOOLS_OFFERED


def test_grading_combines_the_answer_with_the_tool_checks():
    from maverick_dashboard import specialist_test_sets as saved

    case = _tool_case(id="c" * 32, revision=1, task="Two invoices are duplicates. What now?",
                      includes=["duplicate"], excludes=["payment sent"], refusal=False, citation=False)
    good_calls = [{"name": "send_email", "arguments": '{"to": "Acme"}', "answer": "canned"}]
    passed = saved.grade(case, "This is a duplicate; I emailed Acme.", tool_calls=good_calls)
    assert passed["passed"] is True and [c["passed"] for c in passed["tool_checks"]] == [True, True]
    assert passed["tool_calls"] == good_calls
    # A good answer with a missing call still fails.
    failed = saved.grade(case, "This is a duplicate; I emailed Acme.", tool_calls=[])
    assert failed["passed"] is False and failed["checks"]["includes"] == 1
    # Cases without tools grade exactly as before.
    plain = saved.grade({**case, "with_tools": False}, "This is a duplicate.")
    assert "tool_checks" not in plain and plain["passed"] is True


# ---- the answer run ----------------------------------------------------------------

def test_the_check_calls_the_expected_tool_with_the_text_and_no_real_tool_runs(
        client, monkeypatch, audit_rows, no_real_tools):
    app, tmp = client
    _knob(tmp, "[models]\ncapability_tests = true\n[agent_tests]\ntool_checks = true\n")
    created = app.post(API + "/customer", json={**_tool_case(), "with_tools": True,
                                              "tools_called": [{"name": "send_email", "contains": "Acme"}],
                                              "tools_not_called": ["delete_record"],
                                              "tool_results": [{"name": "lookup_invoice",
                                                                "text": "Invoice 77 is a duplicate."}]})
    assert created.status_code == 200, created.text
    assert created.json()["case"]["with_tools"] is True
    calls = _scripted_llm(monkeypatch, [
        _use("lookup_invoice", {"id": 77}, "call-a"),
        _use("send_email", {"to": "Acme", "body": "Duplicate invoice, no payment sent."}, "call-b"),
        _say("This is a duplicate; nothing was paid. I emailed Acme."),
    ])
    job = _wait(app, app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                        "operation_id": "e" * 32,
                                                        "case_revisions": _revisions(app)}))
    assert job["state"] == "done", job
    run = job["result"]["run"]
    assert run["state"] == "done" and run["passed"] == 1 and run["total"] == 1
    result = run["results"][0]
    assert result["passed"] is True
    assert [c["passed"] for c in result["tool_checks"]] == [True, True]
    assert [c["answer"] for c in result["tool_calls"]] == ["canned", "not_available"]
    # The model was offered stubs only: the named tools plus the pack's allowed tools, never the denied ones.
    offered = {tool["name"] for tool in calls[0]["kwargs"]["tools"]}
    assert {"send_email", "delete_record", "lookup_invoice"} <= offered
    assert "release_payment" not in offered and "shell" not in offered  # the pack's denied tools
    assert all(tool["input_schema"] == {"type": "object", "additionalProperties": True}
               for tool in calls[0]["kwargs"]["tools"])
    # The canned answer went back to the model as the tool result.
    tool_results = calls[1]["messages"][-1]["content"]
    assert tool_results[0]["content"] == "Invoice 77 is a duplicate."
    assert calls[0]["kwargs"]["_no_failover"] is True
    assert {call["kwargs"]["max_tokens"] for call in calls} == {128}  # the run's output allowance, shared by four steps
    run_audit = [row for row in audit_rows if row.get("verb") == "specialist_test_run"]
    assert run_audit and run_audit[-1]["tool_checks"] == 1 and "task" not in run_audit[-1]


def test_a_forbidden_call_or_a_missing_expected_call_fails_the_check(client, monkeypatch, no_real_tools):
    app, tmp = client
    _knob(tmp, "[models]\ncapability_tests = true\n[agent_tests]\ntool_checks = true\n")
    assert app.post(API + "/customer", json={**_tool_case(), "with_tools": True,
                                            "tools_called": [{"name": "send_email", "contains": ""}],
                                            "tools_not_called": ["delete_record"]}).status_code == 200
    _scripted_llm(monkeypatch, [_use("delete_record", {"id": 1}), _say("This is a duplicate; nothing was paid.")])
    job = _wait(app, app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                        "operation_id": "f" * 32,
                                                        "case_revisions": _revisions(app)}))
    result = job["result"]["run"]["results"][0]
    assert result["passed"] is False
    assert [c["passed"] for c in result["tool_checks"]] == [False, False]
    assert "must not call" in result["tool_checks"][1]["result"]
    assert "Did not call send_email" in result["tool_checks"][0]["result"]
    assert job["result"]["run"]["passed"] == 0


def test_a_budget_refusal_stops_the_check_cleanly(client, monkeypatch, no_real_tools):
    from maverick import budget as budget_module

    app, tmp = client
    _knob(tmp, "[models]\ncapability_tests = true\n[agent_tests]\ntool_checks = true\n")
    assert app.post(API + "/customer", json={**_tool_case(), "with_tools": True,
                                            "tools_called": [{"name": "send_email", "contains": ""}]}).status_code == 200

    def refuse(self):
        raise budget_module.BudgetExceeded("tool calls over the limit")

    monkeypatch.setattr(budget_module.Budget, "record_tool_call", refuse)
    calls = _scripted_llm(monkeypatch, [_use("send_email", {"to": "Acme"})])
    job = _wait(app, app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                        "operation_id": "1" * 32,
                                                        "case_revisions": _revisions(app)}))
    assert job["state"] == "done", job
    run = job["result"]["run"]
    assert run["state"] == "stopped" and run["passed"] == 0 and run["results"] == []
    assert "allowance" in run["message"] and len(calls) == 1


def test_the_knob_off_skips_existing_tool_checks_without_any_provider_call(client, monkeypatch, no_real_tools):
    app, tmp = client
    _knob(tmp, "[models]\ncapability_tests = true\n[agent_tests]\ntool_checks = true\n")
    assert app.post(API + "/customer", json={**_tool_case(), "with_tools": True,
                                            "tools_called": [{"name": "send_email", "contains": ""}]}).status_code == 200
    _knob(tmp, "[models]\ncapability_tests = true\n")
    calls = _scripted_llm(monkeypatch, [_say("This is a duplicate; nothing was paid.")])
    job = _wait(app, app.post(API + "/customer/run", json={"specialist": "finance_ap",
                                                        "operation_id": "2" * 32,
                                                        "case_revisions": _revisions(app)}))
    run = job["result"]["run"]
    assert calls == []
    assert run["state"] == "done" and run["passed"] == 0 and run["total"] == 1
    assert "turned off" in run["results"][0]["note"] and run["results"][0]["passed"] is False


def test_creating_a_tool_check_is_refused_while_the_switch_is_off(client, audit_rows):
    app, tmp = client
    _knob(tmp, "[models]\ncapability_tests = true\n")
    refused = app.post(API + "/customer", json={**_tool_case(), "with_tools": True,
                                              "tools_called": [{"name": "send_email", "contains": ""}]})
    assert refused.status_code == 422 and "turned off" in refused.text
    assert app.get(API + "/customer", params={"specialist": "finance_ap"}).json()["cases"] == []
    # Plain checks still save while the switch is off.
    assert app.post(API + "/customer", json=_case()).status_code == 200


def test_the_publish_summary_counts_a_failed_tool_check_as_not_passing():
    from maverick_dashboard import agent_publish_gate as gate
    from maverick_dashboard import specialist_test_sets as saved

    case = _tool_case(id="a" * 32, revision=1, task="Two invoices are duplicates. What now?",
                      includes=["duplicate"], excludes=[], refusal=False, citation=False)
    # A correct answer with no tool call: the answer check passes, the tool check fails.
    result = saved.grade(case, "This is a duplicate.", tool_calls=[])
    run = {"id": "r" * 32, "state": "done", "case_revisions": [{"id": "a" * 32, "revision": 1}],
           "results": [result]}
    summary = gate._summary(run, "current", {"a" * 32: 1})
    assert result["checks"]["includes"] == 1 and summary["passed"] == 0 and summary["passing"] is False


def test_the_workforce_page_says_whether_tool_checks_are_on(client):
    app, tmp = client
    _knob(tmp, "[models]\ncapability_tests = true\n")
    assert app.get(API + "/customer", params={"specialist": "finance_ap"}).json()["tool_checks_enabled"] is False
    _knob(tmp, "[models]\ncapability_tests = true\n[agent_tests]\ntool_checks = true\n")
    assert app.get(API + "/customer", params={"specialist": "finance_ap"}).json()["tool_checks_enabled"] is True


# ---- a complete draft's publication check -------------------------------------------

def _decide(app, name, action, **fields):
    """Review, then confirm, one Agent Factory decision on a complete draft."""
    context = app.get(DRAFTS + "/history").json()["context"]
    review = app.post(DRAFTS + "/review", json={"name": name, "action": action, "context": context, **fields})
    if review.status_code != 200:
        return review
    return app.post(DRAFTS + "/apply", json={"token": review.json()["token"], "confirmed": True})


def _original_when_finished(app, operation):
    deadline = time.time() + 20
    original = app.get(DRAFTS + "/originals/" + operation).json()
    while not (original["confirmed"] and (original.get("run") or {}).get("state") in {"done", "failed", "stopped", "unknown"}):
        assert time.time() < deadline, original
        time.sleep(.05)
        original = app.get(DRAFTS + "/originals/" + operation).json()
    return original


def _tool_check_draft(app, monkeypatch, new):
    """A saved tool check, then a retained complete draft that changes the specialist's instructions."""
    created = app.post(API + "/customer", json={
        "specialist": PACK, "task": "The supplier is late. Who should we chase?", "includes": ["chase"],
        "excludes": [], "refusal": False, "citation": False, "with_tools": True,
        "tools_called": [{"name": "send_email", "contains": "Acme"}], "tools_not_called": [], "tool_results": []})
    assert created.status_code == 200, created.text
    saved = _decide(app, PACK, "save", entered={"persona": new})
    assert saved.status_code == 200 and saved.json()["confirmed"], saved.text
    return "SPD-" + saved.json()["operation"]


def test_a_complete_draft_with_a_tool_check_can_pass_the_publication_gate(client, monkeypatch, no_real_tools):
    app, tmp = client
    _knob(tmp, "[models]\ncapability_tests = true\n[agent_tests]\ntool_checks = true\n")
    new = "You chase overdue purchase orders and always say which supplier to chase first."
    draft = _tool_check_draft(app, monkeypatch, new)
    calls = _scripted_llm(monkeypatch, [
        _use("send_email", {"to": "Acme", "body": "Chasing the late delivery."}),
        _say("We should chase the supplier first; I emailed Acme."),
    ])
    checked = _decide(app, PACK, "check", selected=draft)
    assert checked.status_code == 200, checked.text
    run = _original_when_finished(app, checked.json()["operation"])["run"]
    assert run["state"] == "done" and run["passed"] == 1 and run["total"] == 1, run
    assert [c["passed"] for c in run["results"][0]["tool_checks"]] == [True]
    assert len(calls) == 2
    published = _decide(app, PACK, "publish", selected=draft)
    assert published.status_code == 200 and published.json()["confirmed"], published.text
    assert app.get("/api/v1/agents/" + PACK).json()["persona"] == new


def test_a_complete_draft_with_a_tool_check_is_not_publishable_while_the_switch_is_off(client, monkeypatch, no_real_tools):
    app, tmp = client
    _knob(tmp, "[models]\ncapability_tests = true\n[agent_tests]\ntool_checks = true\n")
    new = "You chase overdue purchase orders and always say which supplier to chase first."
    draft = _tool_check_draft(app, monkeypatch, new)
    _knob(tmp, "[models]\ncapability_tests = true\n")
    calls = _scripted_llm(monkeypatch, [_say("We should chase the supplier first; I emailed Acme.")])
    checked = _decide(app, PACK, "check", selected=draft)
    assert checked.status_code == 200, checked.text
    run = _original_when_finished(app, checked.json()["operation"])["run"]
    assert calls == []
    assert run["state"] == "done" and run["passed"] == 0
    assert "turned off" in run["results"][0]["note"] and run["results"][0]["passed"] is False
    refused = _decide(app, PACK, "publish", selected=draft)
    assert refused.status_code == 409, refused.text
    assert app.get("/api/v1/agents/" + PACK).json()["persona"] != new


def test_the_draft_notice_and_the_agents_page_describe_tool_checks_as_recording_stubs():
    from pathlib import Path

    from maverick_dashboard import specialist_drafts

    page = (Path(specialist_drafts.__file__).parent / "templates" / "agents.html").read_text(encoding="utf-8")
    for text in (specialist_drafts.NOTICE, page):
        assert "no real tools" in text and "recording test stubs" in text
        assert "with no tools" not in text and "They use no tools" not in text


def test_the_authority_check_runs_before_every_tool_check_provider_call_and_a_refusal_sends_nothing_more(no_real_tools):
    from maverick import budget as budget_module
    from maverick_dashboard import specialist_tool_checks as tools

    class Provider:
        def __init__(self, replies):
            self.replies, self.sent = list(replies), []

        def complete(self, system, messages, **kwargs):
            self.sent.append(kwargs)
            return self.replies.pop(0)

    def run(provider, before_call):
        return tools.run_tool_check(provider, system="s", task="Late delivery?", case=_tool_case(),
                                    names=["send_email"], budget=budget_module.Budget(max_tool_calls=4, max_output_tokens=512),
                                    before_call=before_call, max_tokens=128)

    # Every provider call is preceded by the authority check; the stub answers the call with its fixed refusal.
    checks = []
    provider = Provider([_use("send_email", {"to": "Acme"}), _say("I emailed Acme.")])
    text, calls = run(provider, lambda: checks.append(1))
    assert text == "I emailed Acme." and [c["answer"] for c in calls] == ["not_available"]
    assert len(checks) == len(provider.sent) == 2

    # A refusal at the second check stops the loop before the second provider call is sent.
    class Refused(Exception):
        pass

    seen = []

    def refuse_after_first() -> None:
        seen.append(1)
        if len(seen) > 1:
            raise Refused("authority withdrawn")

    provider = Provider([_use("send_email", {"to": "Acme"}), _say("I emailed Acme.")])
    with pytest.raises(Refused):
        run(provider, refuse_after_first)
    assert len(provider.sent) == 1
