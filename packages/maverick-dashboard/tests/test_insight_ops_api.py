"""Task questions, task health and recorded steps: the buttons that replace
``maverick analytics``, ``diag health`` and ``diag replay``. Each person sees
only the tasks they may see; raw analytics questions are for installation
administrators, read-only and time-limited."""
from __future__ import annotations

import datetime as dt
import sys

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT", "MAVERICK_TRACE_DIR"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()
    try:
        yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    finally:
        config.reset_config_cache()
        audit_writer._default = None
        audit_writer._defaults.clear()
        dash_app._world_cache.clear()


def _as(monkeypatch, role: str, who: str) -> None:
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _world():
    from maverick_dashboard._shared import _world as shared
    return shared()


def _task(owner: str, title: str, cost: float, status: str = "done") -> int:
    w = _world()
    gid = w.create_goal(title, "", owner=owner)
    ep = w.start_episode(gid)
    w.end_episode(ep, "summary", "success", cost_dollars=cost, input_tokens=100, output_tokens=50)
    w.set_goal_status(gid, status)
    return gid


# ---- task questions (analytics) -------------------------------------------------

def test_questions_are_answered_from_the_tasks_a_person_may_see(client, monkeypatch):
    pytest.importorskip("duckdb")
    _task("user:ada", "Ada's report", 2.5)
    _task("user:bob", "Bob's report", 4.0, status="failed")
    unidentified = client.post("/api/v1/analytics/ask", json={"metric": "spend", "group": "none"}).json()
    assert unidentified["rows"] == []
    _as(monkeypatch, "admin", "user:ada")
    whole = client.post("/api/v1/analytics/ask", json={"metric": "spend", "group": "none"}).json()
    assert whole["rows"] == [{"group": "all", "value": 2.5}]
    by_status = client.post("/api/v1/analytics/ask", json={"metric": "tasks", "group": "status"}).json()
    assert {r["group"]: r["value"] for r in by_status["rows"]} == {"done": 1}
    _as(monkeypatch, "operator", "user:bob")
    mine = client.post("/api/v1/analytics/ask", json={"metric": "spend", "group": "task"}).json()
    assert len(mine["rows"]) == 1 and "Bob's report" in mine["rows"][0]["group"] and mine["rows"][0]["value"] == 4.0
    today = dt.date.today().isoformat()
    ranged = client.post("/api/v1/analytics/ask", json={"metric": "runs", "group": "day", "since": today, "until": today}).json()
    assert ranged["rows"] == [{"group": today, "value": 1.0}] or ranged["rows"][0]["value"] == 1.0
    old = client.post("/api/v1/analytics/ask", json={"metric": "runs", "group": "none", "until": "2001-01-01"}).json()
    assert old["rows"] == [] or old["rows"][0]["value"] == 0


def test_questions_accept_only_the_listed_choices(client):
    for bad in ({"metric": "password", "group": "none"}, {"metric": "spend", "group": "owner"},
                {"metric": "spend", "since": "yesterday"}, {"metric": "spend", "since": "2026-02-01", "until": "2026-01-01"},
                {"metric": "spend", "extra": 1}):
        assert client.post("/api/v1/analytics/ask", json=bad).status_code == 422, bad


@pytest.mark.parametrize("principal, title, spend", [
    (None, None, None),
    ("user:ada", "Ada's report", "2.5"),
    ("user:bob", "Bob's report", "4.0"),
])
def test_admin_sql_keeps_the_same_employee_content_scope(client, monkeypatch, principal, title, spend):
    pytest.importorskip("duckdb")
    _task("user:ada", "Ada's report", 2.5)
    _task("user:bob", "Bob's report", 4.0, status="failed")
    if principal is not None:
        _as(monkeypatch, "admin", principal)
    response = client.post("/api/v1/analytics/query", json={
        "query": "SELECT g.title, sum(e.cost) AS spend FROM goals g JOIN episodes e ON e.goal_id=g.id GROUP BY g.title ORDER BY g.title",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["rows"] == ([[title, spend]] if title is not None else [])
    if title is not None:
        assert data["columns"] == ["title", "spend"]
    assert data["more"] is False


def test_questions_say_plainly_when_the_add_on_is_missing(client, monkeypatch):
    monkeypatch.setitem(sys.modules, "duckdb", None)
    r = client.post("/api/v1/analytics/ask", json={"metric": "spend", "group": "none"})
    assert r.status_code == 503 and "not installed" in r.json()["detail"]
    assert client.get("/api/v1/analytics/choices").status_code == 200


def test_typed_questions_are_for_installation_administrators_and_read_only(client, monkeypatch):
    pytest.importorskip("duckdb")
    _task("user:ada", "Ada's report", 1.0)
    _as(monkeypatch, "admin", "user:ada")
    choices = client.get("/api/v1/analytics/choices").json()
    assert choices["can_write_queries"] is True
    r = client.post("/api/v1/analytics/query", json={"query": "SELECT count(*) AS n FROM goals"})
    assert r.json() == {"columns": ["n"], "rows": [["1"]], "more": False}
    for bad in ("DELETE FROM goals", "COPY goals TO '/tmp/x.csv'", "SELECT * FROM read_csv('/etc/passwd')"):
        r = client.post("/api/v1/analytics/query", json={"query": bad})
        assert r.status_code == 422, bad
        assert "SELECT" in r.json()["detail"]
    assert client.post("/api/v1/analytics/query", json={"query": "x" * 4001}).status_code == 422
    _as(monkeypatch, "operator", "user:bob")
    assert client.get("/api/v1/analytics/choices").json()["can_write_queries"] is False
    assert client.post("/api/v1/analytics/query", json={"query": "SELECT 1"}).status_code == 403


def test_typed_questions_cannot_smuggle_a_second_statement(client):
    pytest.importorskip("duckdb")
    _task("user:ada", "Ada's report", 1.0)
    for bad in ("SELECT 1) AS x; DROP TABLE goals; SELECT * FROM (SELECT 1",
                "SELECT 1) AS x; SELECT ?::INT AS lim, range AS r FROM range(5000) --"):
        r = client.post("/api/v1/analytics/query", json={"query": bad})
        assert r.status_code == 422, (bad, r.json())
        assert "SELECT" in r.json()["detail"]


def test_typed_questions_are_stopped_at_the_time_limit(client, monkeypatch):
    pytest.importorskip("duckdb")
    from maverick_dashboard import insight_ops_api
    monkeypatch.setattr(insight_ops_api, "_SQL_SECONDS", 0.2)
    r = client.post("/api/v1/analytics/query", json={
        "query": "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t) SELECT count(*) FROM t"})
    assert r.status_code == 503 and "too long" in r.json()["detail"]


# ---- task health (diag health) ----------------------------------------------------

def test_health_uses_the_kernel_score_and_the_task_access_check(client, monkeypatch):
    gid = _task("user:ada", "Ada's report", 1.0)
    assert client.get(f"/api/v1/goals/{gid}/health").status_code == 404
    _as(monkeypatch, "operator", "user:ada")
    response = client.get(f"/api/v1/goals/{gid}/health")
    assert response.status_code == 200, response.text
    h = response.json()
    from maverick.health_score import goal_health
    _goal, kernel = goal_health(_world(), gid)
    assert h["score"] == kernel.score and h["grade"] == kernel.grade and h["finished"] is True
    assert h["tokens_used"] == 150 and h["parts"][0]["points"] == 100
    _as(monkeypatch, "operator", "user:bob")
    assert client.get(f"/api/v1/goals/{gid}/health").status_code == 404
    assert client.get("/api/v1/goals/999999/health").status_code == 404


# ---- recorded steps (diag replay) -------------------------------------------------

def test_recorded_steps_are_read_through_the_verified_reader(client, monkeypatch, tmp_path):
    gid = _task("user:ada", "Ada's report", 1.0)
    assert client.get(f"/api/v1/goals/{gid}/recorded-steps").status_code == 404
    _as(monkeypatch, "operator", "user:ada")
    off = client.get(f"/api/v1/goals/{gid}/recorded-steps").json()
    assert off["recording"] is False
    traces = tmp_path / "traces"
    traces.mkdir(mode=0o700)
    monkeypatch.setenv("MAVERICK_TRACE_DIR", str(traces))
    assert client.get(f"/api/v1/goals/{gid}/recorded-steps").json() == {
        "recording": True, "damaged": False, "kinds": [], "total": 0, "matching": 0, "steps": []}
    from maverick.replay.trace import TraceWriter, goal_trace_path
    writer = TraceWriter(str(goal_trace_path(gid)))
    writer.record("plan", agent="planner", content="Split the report into three parts")
    writer.record("tool", agent="worker", content="Fetched the sales figures")
    writer.close()
    data = client.get(f"/api/v1/goals/{gid}/recorded-steps").json()
    assert data["kinds"] == ["plan", "tool"] and data["total"] == 2
    assert [s["text"] for s in data["steps"]] == ["Split the report into three parts", "Fetched the sales figures"]
    only = client.get(f"/api/v1/goals/{gid}/recorded-steps?kind=tool").json()
    assert only["matching"] == 1 and only["steps"][0]["who"] == "worker"
    path = goal_trace_path(gid)
    path.write_text(path.read_text().replace("sales", "SALES"))  # tampered
    assert client.get(f"/api/v1/goals/{gid}/recorded-steps").json()["damaged"] is True
    _as(monkeypatch, "operator", "user:bob")
    assert client.get(f"/api/v1/goals/{gid}/recorded-steps").status_code == 404


# ---- pages ---------------------------------------------------------------------

def test_spend_replay_and_task_pages_carry_the_new_controls(client):
    from test_support.plain_language import developer_terms, visible_text
    gid = _task("", "Weekly report", 1.0)
    spend = client.get("/spend").text
    assert "Questions about your tasks" in visible_text(spend) and 'id="io-ask-form"' in spend
    replay = client.get(f"/replay?goal={gid}").text
    assert "Recorded steps" in visible_text(replay) and 'id="io-steps-show"' in replay
    task = client.get(f"/chat/goal/{gid}").text
    text = visible_text(task)
    assert "Check this task's health" in text and "Run code for this task" in text
    assert "lightwork-insight-ops.js" in task and "lightwork-code-sandbox.js" in task
    for page, marker, end in ((spend, 'id="io-ask-title"', "</section>"), (replay, 'id="io-steps-title"', "</section>"),
                              # The task controls (health check, code sandbox) now sit after the
                              # stop card, just before the reply composer.
                              (task, '<div class="task-ops">', 'id="composer"')):
        start = page.index(marker)
        assert developer_terms("<main>" + page[start:page.index(end, start)] + "</main>") == []
