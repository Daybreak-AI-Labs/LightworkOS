"""Strategic-fit connectors: ServiceNow, Snowflake, Databricks, OneTrust, Vertex.

Network-free: ``httpx`` is faked so we exercise registration, auth-config
errors, the confirm gate, request routing, and response shaping with no real
API call.
"""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


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
    out = vertex_tool().fn({"op": "generate", "prompt": "hi"})
    assert "ERROR" in out and "VERTEX" in out


def test_vertex_generate(monkeypatch):
    monkeypatch.setenv("VERTEX_ACCESS_TOKEN", "t")
    monkeypatch.setenv("VERTEX_PROJECT", "proj")
    post = MagicMock(return_value=_resp(200, {
        "candidates": [{"content": {"parts": [{"text": "hello from vertex"}]}}]
    }))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.vertex_tool import vertex_tool
    out = vertex_tool().fn({"op": "generate", "model": "gemini-2.5-pro", "prompt": "hi"})
    assert out == "hello from vertex"
    assert ":generateContent" in post.call_args.args[0]


def test_vertex_ids_cannot_leave_their_path_segment(monkeypatch):
    monkeypatch.setenv("VERTEX_ACCESS_TOKEN", "t")
    monkeypatch.setenv("VERTEX_PROJECT", "proj")
    post = MagicMock(return_value=_resp(200, {"predictions": []}))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.vertex_tool import vertex_tool
    vertex_tool().fn({"op": "generate", "model": "../../../endpoints/777:predict#", "prompt": "hi"})
    assert "/models/..%2F..%2F..%2Fendpoints%2F777%3Apredict%23:generateContent" in post.call_args.args[0]
    vertex_tool().fn({"op": "predict", "endpoint_id": "../x", "instances": [1]})
    assert post.call_args.args[0].endswith("/endpoints/..%2Fx:predict")
    assert vertex_tool().fn({"op": "predict", "endpoint_id": "..", "instances": [1]}).startswith("ERROR")


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
    out = bigquery_tool().fn({"op": "query", "sql": "select 1"})
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
    out = bigquery_tool().fn({"op": "query", "sql": "SELECT 42 AS n"})
    assert "42" in out
    assert post.call_args.args[0].endswith("/projects/proj/queries")


def test_bigquery_write_needs_confirm(monkeypatch):
    monkeypatch.setenv("BIGQUERY_ACCESS_TOKEN", "t")
    monkeypatch.setenv("BIGQUERY_PROJECT", "proj")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.bigquery_tool import bigquery_tool
    out = bigquery_tool().fn({"op": "query", "sql": "DELETE FROM d.t WHERE 1=1"})
    assert "DRY RUN" in out
    post.assert_not_called()


def test_bigquery_multistatement_read_needs_confirm(monkeypatch):
    monkeypatch.setenv("BIGQUERY_ACCESS_TOKEN", "t")
    monkeypatch.setenv("BIGQUERY_PROJECT", "proj")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.bigquery_tool import bigquery_tool
    out = bigquery_tool().fn({
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
    out = bigquery_tool().fn({"op": "query", "sql": "SELECT ';' AS semi;"})
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
    out = bigquery_tool().fn({"op": "query", "sql": "SELECT * FROM d.big"})
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
