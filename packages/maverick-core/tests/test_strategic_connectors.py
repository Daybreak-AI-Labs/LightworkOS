"""Strategic-fit connectors: ServiceNow, Snowflake, Databricks, OneTrust, Vertex.

Network-free: ``httpx`` is faked so we exercise registration, auth-config
errors, the confirm gate, request routing, and response shaping with no real
API call.
"""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest
from maverick.budget import Budget


def _fake_httpx(monkeypatch, **methods):
    mod = types.ModuleType("httpx")
    for name, value in methods.items():
        setattr(mod, name, value)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status, body):
    r = MagicMock()
    r.status_code = status
    r.json = MagicMock(return_value=body)
    r.text = str(body)
    return r


# --------------------------- registration smoke ---------------------------

def test_connectors_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    names = {t.name for t in base_registry(_W(), LocalBackend(workdir=tmp_path)).all()}
    for n in ("servicenow", "snowflake", "databricks", "onetrust", "vertex"):
        assert n in names, n


# --------------------------------- ServiceNow ------------------------------

def test_servicenow_requires_config(monkeypatch):
    monkeypatch.delenv("SERVICENOW_INSTANCE_URL", raising=False)
    monkeypatch.delenv("SERVICENOW_TOKEN", raising=False)
    _fake_httpx(monkeypatch, request=MagicMock())
    from maverick.tools.servicenow_tool import servicenow_tool
    out = servicenow_tool().fn({"op": "query", "table": "incident"})
    assert "ERROR" in out and "SERVICENOW" in out


def test_servicenow_query_hits_table_api(monkeypatch):
    monkeypatch.setenv("SERVICENOW_INSTANCE_URL", "https://x.service-now.com")
    monkeypatch.setenv("SERVICENOW_TOKEN", "t")
    req = MagicMock(return_value=_resp(200, {"result": [{"number": "INC001"}]}))
    _fake_httpx(monkeypatch, request=req)
    from maverick.tools.servicenow_tool import servicenow_tool
    out = servicenow_tool().fn({"op": "query", "table": "incident", "query": "active=true"})
    assert "INC001" in out
    assert req.call_args.args[0] == "GET"
    assert req.call_args.args[1].endswith("/api/now/table/incident")


def test_servicenow_rejects_dot_sys_id():
    from maverick.tools.servicenow_tool import _safe_seg
    assert not _safe_seg(".") and not _safe_seg("..") and _safe_seg("abc.1")


def test_servicenow_create_needs_confirm(monkeypatch):
    monkeypatch.setenv("SERVICENOW_INSTANCE_URL", "https://x.service-now.com")
    monkeypatch.setenv("SERVICENOW_TOKEN", "t")
    req = MagicMock()
    _fake_httpx(monkeypatch, request=req)
    from maverick.tools.servicenow_tool import servicenow_tool
    out = servicenow_tool().fn({"op": "create", "table": "incident",
                                "fields": {"short_description": "x"}})
    assert "DRY RUN" in out
    req.assert_not_called()


# ---------------------------------- Snowflake ------------------------------

def test_snowflake_requires_config(monkeypatch):
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    monkeypatch.delenv("SNOWFLAKE_TOKEN", raising=False)
    _fake_httpx(monkeypatch)
    from maverick.tools.snowflake_tool import snowflake_tool
    out = snowflake_tool().fn({"op": "query", "statement": "select 1"})
    assert "ERROR" in out and "SNOWFLAKE" in out


def test_snowflake_select_runs(monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct")
    monkeypatch.setenv("SNOWFLAKE_TOKEN", "t")
    post = MagicMock(return_value=_resp(200, {
        "resultSetMetaData": {"numRows": 1, "rowType": [{"name": "N"}]},
        "data": [["42"]],
    }))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.snowflake_tool import snowflake_tool
    out = snowflake_tool().fn({"op": "query", "statement": "SELECT 42 AS N"})
    assert "42" in out and "N" in out
    assert post.call_args.args[0].endswith("/api/v2/statements")


def test_snowflake_write_needs_confirm(monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct")
    monkeypatch.setenv("SNOWFLAKE_TOKEN", "t")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.snowflake_tool import snowflake_tool
    out = snowflake_tool().fn({"op": "query", "statement": "INSERT INTO t VALUES (1)"})
    assert "DRY RUN" in out
    post.assert_not_called()


def test_snowflake_still_running_statement_is_not_reported_as_done(monkeypatch):
    # The SQL API answers 202 with only a handle when the statement outlives
    # the server-side wait; that is not "ok (0 rows)".
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct")
    monkeypatch.setenv("SNOWFLAKE_TOKEN", "t")
    post = MagicMock(return_value=_resp(202, {
        "code": "333334", "message": "Asynchronous execution in progress.",
        "statementHandle": "01b2-handle",
    }))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.snowflake_tool import snowflake_tool
    out = snowflake_tool().fn({"op": "query", "statement": "SELECT 1"})
    assert out.startswith("ERROR") and "01b2-handle" in out and "ok (" not in out


# --------------------------------- Databricks ------------------------------

def test_databricks_requires_config(monkeypatch):
    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.delenv("DATABRICKS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, request=MagicMock())
    from maverick.tools.databricks_tool import databricks_tool
    out = databricks_tool().fn({"op": "jobs_list"})
    assert "ERROR" in out and "DATABRICKS" in out


def test_databricks_unfinished_or_failed_statement_is_not_success(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", "https://w.cloud.databricks.com")
    monkeypatch.setenv("DATABRICKS_TOKEN", "t")
    from maverick.tool_results import ToolResultState, classify_tool_result
    from maverick.tools import databricks_tool as mod
    for state, err, want in (
        ("PENDING", None, ToolResultState.INDETERMINATE),
        ("FAILED", {"message": "boom"}, ToolResultState.FAILED),
        ("CANCELED", None, ToolResultState.FAILED),
    ):
        status = {"state": state, **({"error": err} if err else {})}
        monkeypatch.setattr(mod, "_req", lambda *a, _s=status, **k: (
            200, {"statement_id": "st_1", "status": _s}))
        out = mod.databricks_tool().fn({"op": "sql", "statement": "DELETE FROM t",
                                        "warehouse_id": "wh", "confirm": True})
        assert classify_tool_result(out) is want and "st_1" in out, (state, out)


def test_databricks_jobs_list(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", "https://w.cloud.databricks.com")
    monkeypatch.setenv("DATABRICKS_TOKEN", "t")
    req = MagicMock(return_value=_resp(200, {"jobs": [{"job_id": 7, "settings": {"name": "etl"}}]}))
    _fake_httpx(monkeypatch, request=req)
    from maverick.tools.databricks_tool import databricks_tool
    out = databricks_tool().fn({"op": "jobs_list"})
    assert "7" in out and "etl" in out


def test_databricks_job_run_needs_confirm(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", "https://w.cloud.databricks.com")
    monkeypatch.setenv("DATABRICKS_TOKEN", "t")
    req = MagicMock()
    _fake_httpx(monkeypatch, request=req)
    from maverick.tools.databricks_tool import databricks_tool
    out = databricks_tool().fn({"op": "job_run", "job_id": 7})
    assert "DRY RUN" in out
    req.assert_not_called()


# ---------------------------------- OneTrust -------------------------------

def test_onetrust_requires_config(monkeypatch):
    monkeypatch.delenv("ONETRUST_HOSTNAME", raising=False)
    monkeypatch.delenv("ONETRUST_TOKEN", raising=False)
    _fake_httpx(monkeypatch)
    from maverick.tools.onetrust_tool import onetrust_tool
    out = onetrust_tool().fn({"op": "get", "path": "/api/assessment/v2/assessments"})
    assert "ERROR" in out and "ONETRUST" in out


def test_onetrust_get(monkeypatch):
    monkeypatch.setenv("ONETRUST_HOSTNAME", "https://app.onetrust.com")
    monkeypatch.setenv("ONETRUST_TOKEN", "t")
    get = MagicMock(return_value=_resp(200, {"content": [{"name": "DPIA"}]}))
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.onetrust_tool import onetrust_tool
    out = onetrust_tool().fn({"op": "get", "path": "/api/assessment/v2/assessments"})
    assert "DPIA" in out
    assert get.call_args.args[0].endswith("/api/assessment/v2/assessments")


def test_onetrust_post_needs_confirm(monkeypatch):
    monkeypatch.setenv("ONETRUST_HOSTNAME", "https://app.onetrust.com")
    monkeypatch.setenv("ONETRUST_TOKEN", "t")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.onetrust_tool import onetrust_tool
    out = onetrust_tool().fn({"op": "post", "path": "/api/x", "body": {"a": 1}})
    assert "DRY RUN" in out
    post.assert_not_called()


# ----------------------------------- Vertex --------------------------------

def test_vertex_requires_config(monkeypatch):
    monkeypatch.delenv("VERTEX_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("VERTEX_PROJECT", raising=False)
    _fake_httpx(monkeypatch)
    from maverick.tools.vertex_tool import vertex_tool
    out = vertex_tool().fn({"op": "generate", "model": "m", "prompt": "hi"})
    assert "ERROR" in out and "VERTEX" in out


def _vertex(monkeypatch, body, *, budget=None, status=200):
    """A vertex tool bound to a run budget, with a fake Vertex endpoint."""
    monkeypatch.setenv("VERTEX_ACCESS_TOKEN", "t")
    monkeypatch.setenv("VERTEX_PROJECT", "proj")
    # The output allowance each call holds; small, so a hold fits these runs.
    monkeypatch.setenv("MAVERICK_AGENT_MAX_TOKENS", "1000")
    post = MagicMock(return_value=_resp(status, body))
    _fake_httpx(monkeypatch, post=post)
    from maverick.budget import Budget
    from maverick.tools.vertex_tool import vertex_tool
    budget = Budget() if budget is None else budget
    return vertex_tool(budget=budget), post, budget


def _generated(text="ok", **usage):
    body = {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    if usage:
        body["usageMetadata"] = usage
    return body


def test_vertex_generate(monkeypatch):
    tool, post, _budget = _vertex(monkeypatch, _generated("hello from vertex"))
    out = tool.fn({"op": "generate", "model": "gemini-2.5-pro", "prompt": "hi"})
    assert out == "hello from vertex"
    assert ":generateContent" in post.call_args.args[0]


def test_vertex_generate_obeys_the_model_allow_list_and_has_no_built_in_model(monkeypatch):
    # Users own model choice: the tool names no model of its own, and a model
    # outside [access] allowed_models is refused before any request is sent.
    monkeypatch.setattr("maverick.runtime_overrides.allowed_models",
                        lambda: {"vertex:approved-model"})
    tool, post, _budget = _vertex(monkeypatch, _generated())
    out = tool.fn({"op": "generate", "prompt": "hi"})
    assert out.startswith("ERROR") and "model" in out
    out = tool.fn({"op": "generate", "model": "other-model", "prompt": "hi"})
    assert out.startswith("ERROR") and "allowed_models" in out
    assert post.call_count == 0
    assert tool.fn({"op": "generate", "model": "approved-model", "prompt": "hi"}) == "ok"
    # Product text names no model either; it says how the allow-list spells one.
    description = tool.input_schema["properties"]["model"]["description"]
    assert "gemini" not in description.lower() and "vertex:<model id>" in description


def test_vertex_calls_are_metered_against_provider_spend(monkeypatch):
    # Each Vertex request is a paid provider call, so it goes through the same
    # provider spend accounting (and caps) as web_search.
    tool, post, _budget = _vertex(monkeypatch, {"predictions": [1]})
    import maverick.tools.vertex_tool as vt
    from maverick.provider_cost_cap import ProviderCapExceeded
    metered = []

    def meter(provider, callback, **metadata):
        metered.append((provider, metadata.get("category")))
        return callback()

    monkeypatch.setattr(vt, "metered_provider_call", meter)
    tool.fn({"op": "predict", "endpoint_id": "7", "instances": [1]})
    tool.fn({"op": "generate", "model": "m", "prompt": "hi"})
    assert metered == [("vertex", "inference"), ("vertex", "generation")]

    def refuse(provider, callback, **metadata):
        raise ProviderCapExceeded(provider, 5.0, 5.0, "2026-11")

    monkeypatch.setattr(vt, "metered_provider_call", refuse)
    with pytest.raises(ProviderCapExceeded):
        tool.fn({"op": "generate", "model": "m", "prompt": "hi"})
    assert post.call_count == 2


def _vertex_ledger(monkeypatch, tmp_path, caps=None):
    from maverick import provider_cost_cap as cap
    monkeypatch.setattr(cap, "caps_from_config", lambda: dict(caps or {}))
    monkeypatch.setattr(cap, "_ledger_path", lambda: tmp_path / "provider_spend.json")
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    return cap


def test_vertex_call_is_charged_to_the_run_budget_at_the_operator_rate(monkeypatch, tmp_path):
    # Kernel rule 3: a Vertex call is model spend, so it is charged to the run
    # like any other call. The price an operator set for the exact route wins,
    # and the spend receipt carries that charge and how it was priced.
    from datetime import datetime, timedelta, timezone

    from maverick import runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    today = datetime.now(timezone.utc).date()
    ro.set_model_rate(
        "vertex:contract-model", input_per_mtok=2.0, output_per_mtok=8.0,
        source="Contract R1", as_of=today.isoformat(),
        valid_until=(today + timedelta(days=30)).isoformat(), approved_by="operator@example.com",
    )
    cap = _vertex_ledger(monkeypatch, tmp_path)
    from maverick.budget import Budget
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry
    _tool, post, budget = _vertex(
        monkeypatch,
        _generated(promptTokenCount=1_000_000, candidatesTokenCount=400_000,
                   thoughtsTokenCount=100_000, totalTokenCount=1_500_000),
        budget=Budget(max_dollars=20.0),
    )

    class _W:
        def open_questions(self, gid):
            return []

    # The tool an agent run gets: the registry binds it to the run's budget.
    registry = base_registry(_W(), LocalBackend(workdir=tmp_path), budget=budget)
    tool = next(t for t in registry.all() if t.name == "vertex")
    with cap.work_item_scope("goal:VX-1"):
        assert tool.fn({"op": "generate", "model": "contract-model", "prompt": "hi"}) == "ok"
        receipt = cap.reservation_catalogue_for_work_item("goal:VX-1").receipts[0]
    assert post.call_count == 1
    # Thinking tokens are billed as output: 1M in at $2 + 0.5M out at $8.
    assert (budget.input_tokens, budget.output_tokens) == (1_000_000, 500_000)
    assert budget.dollars == pytest.approx(6.0)
    assert budget.estimated_usage_calls == 0
    assert budget.pricing_snapshot()["vertex:contract-model"]["rate_card_version"] == "operator-ceiling-v1"
    assert receipt.state == "settled" and receipt.actual == pytest.approx(6.0)
    assert receipt.cost_basis == "estimated"
    assert receipt.pricing_evidence["rate_card_version"] == "operator-ceiling-v1"


def test_vertex_model_with_no_price_is_charged_the_safety_ceiling_and_says_so(monkeypatch, tmp_path):
    # No rate set and no tracked price for the route: charge the safety ceiling
    # rather than nothing, and name the fix where the limit is reported.
    import maverick.budget as budget_mod
    cap = _vertex_ledger(monkeypatch, tmp_path)
    tool, post, budget = _vertex(
        monkeypatch, _generated(promptTokenCount=10_000, candidatesTokenCount=10_000),
        budget=budget_mod.Budget(max_dollars=1.0),
    )
    args = {"op": "generate", "model": "some-model", "prompt": "hi"}
    with cap.work_item_scope("goal:VX-2"):
        assert tool.fn(args) == "ok"
        receipt = cap.reservation_catalogue_for_work_item("goal:VX-2").receipts[0]
    ceiling_in, ceiling_out = budget_mod._SELF_HOSTED_PUBLIC_CEILING
    assert budget.dollars == pytest.approx(0.01 * ceiling_in + 0.01 * ceiling_out)
    assert receipt.state == "settled" and receipt.actual == pytest.approx(budget.dollars)
    assert receipt.pricing_evidence["rate_card_version"] == "unpriced-model-ceiling-v1"
    with pytest.raises(budget_mod.BudgetExceeded) as exceeded:
        tool.fn(args)
    assert post.call_count == 2
    for text in (str(exceeded.value), budget.summary()):
        assert "safety ceiling" in text and "vertex:some-model" in text
        assert "Set the model's price in Settings > Models" in text


def test_vertex_reply_without_token_counts_is_charged_an_estimate(monkeypatch, tmp_path):
    # A custom endpoint reports no token counts, and a generate reply may omit
    # them: charge an estimate from the text length and mark it estimated.
    import json
    import math
    _vertex_ledger(monkeypatch, tmp_path)
    reply = {"predictions": ["p" * 400]}
    tool, post, budget = _vertex(monkeypatch, reply)
    instances = [{"text": "i" * 800}]
    assert "pppp" in tool.fn({"op": "predict", "endpoint_id": "7", "instances": instances})
    sent = json.dumps(post.call_args.kwargs["json"], default=str)
    assert budget.input_tokens == math.ceil(len(sent) / 4)
    assert budget.output_tokens == math.ceil(len(str(reply)) / 4)
    assert budget.dollars > 0 and "vertex:endpoints/7" in budget.pricing_snapshot()
    assert budget.estimated_usage_calls == 1 and "estimated" in budget.summary()
    post.return_value = _resp(200, _generated("no counts"))
    assert tool.fn({"op": "generate", "model": "m", "prompt": "hi"}) == "no counts"
    assert budget.estimated_usage_calls == 2


def test_vertex_is_refused_before_any_request_without_budget_left(monkeypatch, tmp_path):
    # budget.check() runs before the request: a run with nothing left must not
    # reach Vertex, and nothing more is charged.
    from maverick.budget import Budget, BudgetExceeded
    _vertex_ledger(monkeypatch, tmp_path)
    spent = Budget(max_dollars=1.0)
    spent.dollars = 1.5
    tool, post, _budget = _vertex(monkeypatch, _generated(), budget=spent)
    for args in ({"op": "generate", "model": "m", "prompt": "hi"},
                 {"op": "predict", "endpoint_id": "7", "instances": [1]}):
        with pytest.raises(BudgetExceeded):
            tool.fn(args)
    assert post.call_count == 0
    assert spent.dollars == 1.5


def test_vertex_without_a_run_budget_is_refused_before_any_request(monkeypatch, tmp_path):
    # A caller with no run budget (a flow's tool step) cannot be charged, so
    # nothing is sent and the reply says where to call Vertex instead.
    from maverick.tools.vertex_tool import vertex_tool
    _vertex_ledger(monkeypatch, tmp_path)
    _tool, post, _budget = _vertex(monkeypatch, _generated())
    for args in ({"op": "generate", "model": "m", "prompt": "hi"},
                 {"op": "predict", "endpoint_id": "7", "instances": [1]}):
        out = vertex_tool().fn(args)
        assert out.startswith("ERROR") and "spending limit" in out and "nothing was sent" in out
    assert post.call_count == 0


def test_vertex_spending_cap_is_enforced_from_the_charges(monkeypatch, tmp_path):
    # With every call charged, [budget.provider_caps] vertex holds like any
    # other provider's cap: calls run until the cap is reached, then stop.
    from maverick.provider_cost_cap import ProviderCapExceeded
    cap = _vertex_ledger(monkeypatch, tmp_path, caps={"vertex": 1.0})
    tool, post, budget = _vertex(
        monkeypatch, _generated(promptTokenCount=10_000, candidatesTokenCount=10_000))
    args = {"op": "generate", "model": "m", "prompt": "hi"}
    assert tool.fn(args) == "ok" and tool.fn(args) == "ok"
    assert cap.check("vertex").spent == pytest.approx(budget.dollars) == pytest.approx(1.2)
    with pytest.raises(ProviderCapExceeded):
        tool.fn(args)
    with pytest.raises(ProviderCapExceeded):
        tool.fn({"op": "predict", "endpoint_id": "7", "instances": [1]})
    assert post.call_count == 2


def test_vertex_holds_its_largest_reply_before_sending(monkeypatch, tmp_path):
    # The hold covers the longest reply a call may return, so a call whose
    # largest reply would not fit is never sent. generate asks for at most the
    # output allowance ([context] max_output_tokens) or the caller's smaller
    # limit; predict cannot limit its reply, so it holds the same allowance.
    from maverick.budget import Budget, BudgetExceeded
    _vertex_ledger(monkeypatch, tmp_path)
    tool, post, _budget = _vertex(monkeypatch, _generated(), budget=Budget(max_dollars=1.0))
    monkeypatch.setenv("MAVERICK_AGENT_MAX_TOKENS", "20000")  # $1.00 at the ceiling
    for args in ({"op": "generate", "model": "m", "prompt": "hi"},
                 {"op": "predict", "endpoint_id": "7", "instances": [1]}):
        with pytest.raises(BudgetExceeded):
            tool.fn(args)
    assert post.call_count == 0
    assert tool.fn({"op": "generate", "model": "m", "prompt": "hi", "max_output_tokens": 1000}) == "ok"
    assert post.call_args.kwargs["json"]["generationConfig"] == {"maxOutputTokens": 1000}
    with pytest.raises(BudgetExceeded):  # 50000 is cut to the allowance: no fit
        tool.fn({"op": "generate", "model": "m", "prompt": "hi", "max_output_tokens": 50000})
    assert post.call_count == 1
    assert tool.fn({"op": "generate", "model": "m", "prompt": "hi",
                    "max_output_tokens": "lots"}).startswith("ERROR")


@pytest.mark.parametrize("limit", ["run", "provider_cap"])
def test_vertex_parallel_calls_cannot_pass_the_spending_limits(monkeypatch, tmp_path, limit):
    # Four generate calls at once, each replying with all it asked for: only
    # the calls whose largest reply fits are sent, so neither the run limit
    # nor the vertex cap is passed.
    import concurrent.futures
    import time

    from maverick.budget import Budget, BudgetExceeded
    from maverick.provider_cost_cap import ProviderCapExceeded
    cap = _vertex_ledger(monkeypatch, tmp_path,
                         caps={"vertex": 1.0} if limit == "provider_cap" else None)
    tool, post, budget = _vertex(
        monkeypatch, _generated(),
        budget=Budget(max_dollars=1.0) if limit == "run" else None)
    monkeypatch.setenv("MAVERICK_AGENT_MAX_TOKENS", "8192")  # $0.41 at the ceiling

    def reply(url, *, json, **_kw):
        time.sleep(0.2)
        wanted = json["generationConfig"]["maxOutputTokens"]
        return _resp(200, _generated(promptTokenCount=10, candidatesTokenCount=wanted))

    post.side_effect = reply
    with cap.work_item_scope("goal:VX-3"), concurrent.futures.ThreadPoolExecutor(4) as pool:
        calls = [pool.submit(tool.fn, {"op": "generate", "model": "m", "prompt": "hi"})
                 for _ in range(4)]
        refused = [c for c in calls
                   if isinstance(c.exception(), (BudgetExceeded, ProviderCapExceeded))]
    assert post.call_count == 2 and len(refused) == 2
    assert budget.dollars <= 1.0
    if limit == "provider_cap":
        assert cap.check("vertex").spent == pytest.approx(budget.dollars)


def test_vertex_ids_cannot_leave_their_path_segment(monkeypatch):
    tool, post, _budget = _vertex(monkeypatch, {"predictions": []})
    tool.fn({"op": "generate", "model": "../../../endpoints/777:predict#", "prompt": "hi"})
    assert "/models/..%2F..%2F..%2Fendpoints%2F777%3Apredict%23:generateContent" in post.call_args.args[0]
    tool.fn({"op": "predict", "endpoint_id": "../x", "instances": [1]})
    assert post.call_args.args[0].endswith("/endpoints/..%2Fx:predict")
    assert tool.fn({"op": "predict", "endpoint_id": "..", "instances": [1]}).startswith("ERROR")


def test_erp_and_analytics_connectors_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    names = {t.name for t in base_registry(_W(), LocalBackend(workdir=tmp_path)).all()}
    for n in ("oracle", "sap", "workday", "bigquery", "dynamics"):
        assert n in names, n


# ----------------------------------- Oracle --------------------------------

def test_oracle_requires_config(monkeypatch):
    monkeypatch.delenv("ORACLE_ORDS_URL", raising=False)
    monkeypatch.delenv("ORACLE_ORDS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.oracle_tool import oracle_tool
    out = oracle_tool().fn({"op": "sql", "statement": "select 1 from dual"})
    assert "ERROR" in out and "ORACLE" in out


def test_oracle_select_runs(monkeypatch):
    monkeypatch.setenv("ORACLE_ORDS_URL", "https://h/ords/me")
    monkeypatch.setenv("ORACLE_ORDS_TOKEN", "t")
    post = MagicMock(return_value=_resp(200, {"items": [{"resultSet": {"items": [{"N": 1}]}}]}))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.oracle_tool import oracle_tool
    out = oracle_tool().fn({"op": "sql", "statement": "SELECT 1 AS N FROM dual"})
    assert "\"N\"" in out or "N" in out
    assert post.call_args.args[0].endswith("/_/sql")
    assert post.call_args.kwargs["content"] == "SELECT 1 AS N FROM dual"


def test_oracle_write_needs_confirm(monkeypatch):
    monkeypatch.setenv("ORACLE_ORDS_URL", "https://h/ords/me")
    monkeypatch.setenv("ORACLE_ORDS_TOKEN", "t")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.oracle_tool import oracle_tool
    out = oracle_tool().fn({"op": "sql", "statement": "DELETE FROM t"})
    assert "DRY RUN" in out
    post.assert_not_called()


def test_oracle_multistatement_read_needs_confirm(monkeypatch):
    monkeypatch.setenv("ORACLE_ORDS_URL", "https://h/ords/me")
    monkeypatch.setenv("ORACLE_ORDS_TOKEN", "t")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.oracle_tool import oracle_tool
    out = oracle_tool().fn({
        "op": "sql",
        "statement": "SELECT 1 FROM dual; DELETE FROM t WHERE 1=1",
    })
    assert "DRY RUN" in out
    post.assert_not_called()


@pytest.mark.parametrize("statement", [
    # Oracle q-quoting hides the semicolon from a plain quote scanner.
    "select q'[a'b]' from dual; delete from t",
    # ORDS runs a script: a SQL*Plus command ends at its line, and a lone "/"
    # line ends a SQL statement, so no semicolon is needed for a second one.
    "show user\ndelete from t",
    "select 1 from dual\n/\ndelete from t",
    # SQL*Plus (SQLBLANKLINES OFF, the default) also ends a statement at a
    # blank line or at a line holding only ".".
    "select 1 from dual\n\ndelete from t;",
    "select 1 from dual\n.\ndelete from t",
    "select 1 from dual\n   \ndelete from t",
])
def test_oracle_script_tricks_cannot_pass_as_a_read(monkeypatch, statement):
    monkeypatch.setenv("ORACLE_ORDS_URL", "https://h/ords/me")
    monkeypatch.setenv("ORACLE_ORDS_TOKEN", "t")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.oracle_tool import oracle_tool
    out = oracle_tool().fn({"op": "sql", "statement": statement})
    assert "DRY RUN" in out
    post.assert_not_called()
    if "delete" in statement and "q'" not in statement and "show" not in statement:
        # A read with a blank line inside is legitimate SQL elsewhere, so say why.
        assert "ends a statement" in out


def test_oracle_backslash_quote_multistatement_read_needs_confirm(monkeypatch):
    monkeypatch.setenv("ORACLE_ORDS_URL", "https://h/ords/me")
    monkeypatch.setenv("ORACLE_ORDS_TOKEN", "t")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.oracle_tool import oracle_tool
    out = oracle_tool().fn({
        "op": "sql",
        "statement": "SELECT 'x\\' FROM dual; DELETE FROM t WHERE 1=1; --'",
    })
    assert "DRY RUN" in out
    post.assert_not_called()


# ------------------------------------- SAP ---------------------------------

def test_sap_requires_config(monkeypatch):
    monkeypatch.delenv("SAP_BASE_URL", raising=False)
    monkeypatch.delenv("SAP_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.sap_tool import sap_tool
    out = sap_tool().fn({"op": "get", "path": "/sap/opu/odata/x"})
    assert "ERROR" in out and "SAP" in out


def test_sap_get_adds_json_format(monkeypatch):
    monkeypatch.setenv("SAP_BASE_URL", "https://s4.example.com")
    monkeypatch.setenv("SAP_TOKEN", "t")
    get = MagicMock(return_value=_resp(200, {"d": {"results": [{"BusinessPartner": "1"}]}}))
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.sap_tool import sap_tool
    out = sap_tool().fn({"op": "get", "path": "/sap/opu/odata/sap/SVC/Entity"})
    assert "BusinessPartner" in out
    assert get.call_args.kwargs["params"]["$format"] == "json"


def test_sap_post_needs_confirm(monkeypatch):
    monkeypatch.setenv("SAP_BASE_URL", "https://s4.example.com")
    monkeypatch.setenv("SAP_TOKEN", "t")
    post = MagicMock()
    _fake_httpx(monkeypatch, get=MagicMock(), post=post)
    from maverick.tools.sap_tool import sap_tool
    out = sap_tool().fn({"op": "post", "path": "/sap/opu/odata/x", "body": {"a": 1}})
    assert "DRY RUN" in out
    post.assert_not_called()


def test_sap_csrf_cookie_header_keeps_every_session_cookie():
    import httpx
    from maverick.tools.sap_tool import _cookie_header
    headers = httpx.Headers([("set-cookie", "a=1; path=/"),
                             ("set-cookie", "SID=abc; path=/; secure; HttpOnly")])
    assert _cookie_header(headers) == "a=1; SID=abc"


# ----------------------------------- Workday -------------------------------

def test_workday_requires_config(monkeypatch):
    monkeypatch.delenv("WORKDAY_BASE_URL", raising=False)
    monkeypatch.delenv("WORKDAY_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.workday_tool import workday_tool
    out = workday_tool().fn({"op": "get", "path": "/workers"})
    assert "ERROR" in out and "WORKDAY" in out


def test_workday_get(monkeypatch):
    monkeypatch.setenv("WORKDAY_BASE_URL", "https://wd.example.com/ccx/api/v1/T")
    monkeypatch.setenv("WORKDAY_TOKEN", "t")
    get = MagicMock(return_value=_resp(200, {"data": [{"id": "w1"}]}))
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.workday_tool import workday_tool
    out = workday_tool().fn({"op": "get", "path": "/workers"})
    assert "w1" in out
    assert get.call_args.args[0].endswith("/workers")


def test_workday_path_cannot_climb_out_of_base_url(monkeypatch):
    monkeypatch.setenv("WORKDAY_BASE_URL", "https://wd.example.com/ccx/api/v1/T")
    monkeypatch.setenv("WORKDAY_TOKEN", "t")
    get = MagicMock()
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.workday_tool import workday_tool
    for path in ("/../../staffing/v6/OTHER/workers", "/%2e%2e/x", "a/./b"):
        out = workday_tool().fn({"op": "get", "path": path})
        assert out.startswith("ERROR") and "WORKDAY_BASE_URL" in out, path
    get.assert_not_called()


def test_workday_post_needs_confirm(monkeypatch):
    monkeypatch.setenv("WORKDAY_BASE_URL", "https://wd.example.com/ccx/api/v1/T")
    monkeypatch.setenv("WORKDAY_TOKEN", "t")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.workday_tool import workday_tool
    out = workday_tool().fn({"op": "post", "path": "/workers", "body": {"x": 1}})
    assert "DRY RUN" in out
    post.assert_not_called()


# ---------------------------------- BigQuery -------------------------------

def test_bigquery_requires_config(monkeypatch):
    monkeypatch.delenv("BIGQUERY_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("BIGQUERY_PROJECT", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.bigquery_tool import bigquery_tool
    out = bigquery_tool(budget=Budget()).fn({"op": "query", "sql": "select 1"})
    assert "ERROR" in out and "BIGQUERY" in out


def test_bigquery_select_runs(monkeypatch):
    monkeypatch.setenv("BIGQUERY_ACCESS_TOKEN", "t")
    monkeypatch.setenv("BIGQUERY_PROJECT", "proj")
    post = MagicMock(return_value=_resp(200, {
        "schema": {"fields": [{"name": "n"}]},
        "rows": [{"f": [{"v": "42"}]}],
        "totalRows": "1",
    }))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.bigquery_tool import bigquery_tool
    out = bigquery_tool(budget=Budget()).fn({"op": "query", "sql": "SELECT 42 AS n"})
    assert "42" in out
    assert post.call_args.args[0].endswith("/projects/proj/queries")


def test_bigquery_write_needs_confirm(monkeypatch):
    monkeypatch.setenv("BIGQUERY_ACCESS_TOKEN", "t")
    monkeypatch.setenv("BIGQUERY_PROJECT", "proj")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.bigquery_tool import bigquery_tool
    out = bigquery_tool(budget=Budget()).fn({"op": "query", "sql": "DELETE FROM d.t WHERE 1=1"})
    assert "DRY RUN" in out
    post.assert_not_called()


def test_bigquery_multistatement_read_needs_confirm(monkeypatch):
    monkeypatch.setenv("BIGQUERY_ACCESS_TOKEN", "t")
    monkeypatch.setenv("BIGQUERY_PROJECT", "proj")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.bigquery_tool import bigquery_tool
    out = bigquery_tool(budget=Budget()).fn({
        "op": "query",
        "sql": "SELECT 1; DELETE FROM d.t WHERE 1=1",
    })
    assert "DRY RUN" in out
    post.assert_not_called()


def test_bigquery_trailing_semicolon_read_runs(monkeypatch):
    monkeypatch.setenv("BIGQUERY_ACCESS_TOKEN", "t")
    monkeypatch.setenv("BIGQUERY_PROJECT", "proj")
    post = MagicMock(return_value=_resp(200, {"totalRows": "0"}))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.bigquery_tool import bigquery_tool
    out = bigquery_tool(budget=Budget()).fn({"op": "query", "sql": "SELECT ';' AS semi;"})
    assert "ok" in out
    assert post.call_args.kwargs["json"]["query"] == "SELECT ';' AS semi;"


def test_bigquery_incomplete_job_is_not_reported_as_empty(monkeypatch):
    monkeypatch.setenv("BIGQUERY_ACCESS_TOKEN", "t")
    monkeypatch.setenv("BIGQUERY_PROJECT", "proj")
    post = MagicMock(return_value=_resp(200, {
        "jobComplete": False,
        "jobReference": {"projectId": "proj", "jobId": "job_123", "location": "US"},
    }))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.bigquery_tool import bigquery_tool
    out = bigquery_tool(budget=Budget()).fn({"op": "query", "sql": "SELECT * FROM d.big"})
    assert out.startswith("INDETERMINATE:")
    assert "still running" in out and "job_123" in out


# ---------------------------------- Dynamics -------------------------------

def test_dynamics_requires_config(monkeypatch):
    monkeypatch.delenv("DYNAMICS_RESOURCE_URL", raising=False)
    monkeypatch.delenv("DYNAMICS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.dynamics_tool import dynamics_tool
    out = dynamics_tool().fn({"op": "query", "entity": "accounts"})
    assert "ERROR" in out and "DYNAMICS" in out


def test_dynamics_query(monkeypatch):
    monkeypatch.setenv("DYNAMICS_RESOURCE_URL", "https://org.crm.dynamics.com")
    monkeypatch.setenv("DYNAMICS_TOKEN", "t")
    get = MagicMock(return_value=_resp(200, {"value": [{"name": "Acme"}]}))
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.dynamics_tool import dynamics_tool
    out = dynamics_tool().fn({"op": "query", "entity": "accounts", "params": {"$top": 5}})
    assert "Acme" in out
    assert get.call_args.args[0].endswith("/api/data/v9.2/accounts")


def test_dynamics_create_needs_confirm(monkeypatch):
    monkeypatch.setenv("DYNAMICS_RESOURCE_URL", "https://org.crm.dynamics.com")
    monkeypatch.setenv("DYNAMICS_TOKEN", "t")
    post = MagicMock()
    _fake_httpx(monkeypatch, get=MagicMock(), post=post)
    from maverick.tools.dynamics_tool import dynamics_tool
    out = dynamics_tool().fn({"op": "create", "entity": "accounts", "fields": {"name": "x"}})
    assert "DRY RUN" in out
    post.assert_not_called()


def test_bigquery_is_charged_by_terabytes_scanned_within_what_is_left(monkeypatch):
    # Priced per terabyte, a query is charged for the bytes the reply says it
    # scanned, and asks BigQuery to refuse a scan the run could not pay for.
    # A reply without byte counts is charged the per-call safety ceiling.
    import os

    from maverick import config
    from maverick.budget import Budget
    from maverick.tools.bigquery_tool import bigquery_tool

    home = os.environ["MAVERICK_HOME"]
    os.makedirs(home, exist_ok=True)
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as f:
        f.write('[budget.tool_prices]\nbigquery = { dollars = 5.0, per = "terabyte" }\n')
    config.reset_config_cache()
    monkeypatch.setenv("BIGQUERY_ACCESS_TOKEN", "t")
    monkeypatch.setenv("BIGQUERY_PROJECT", "proj")
    post = MagicMock(return_value=_resp(200, {"totalRows": "0", "totalBytesProcessed": "200000000000"}))
    _fake_httpx(monkeypatch, post=post)
    budget = Budget(max_dollars=2.0)
    tool = bigquery_tool(budget=budget)
    assert tool.fn({"op": "query", "sql": "select 1"}).startswith("ok")
    assert post.call_args.kwargs["json"]["maximumBytesBilled"] == str(int(2.0 / 5.0 * 1e12))
    assert budget.dollars == pytest.approx(1.0)
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as f:
        f.write("")
    config.reset_config_cache()
    post.return_value = _resp(200, {"totalRows": "0"})
    assert tool.fn({"op": "query", "sql": "select 1"}).startswith("ok")
    assert "maximumBytesBilled" not in post.call_args.kwargs["json"]
    assert budget.dollars == pytest.approx(1.10)
    assert bigquery_tool().fn({"op": "query", "sql": "select 1"}).startswith("ERROR")
