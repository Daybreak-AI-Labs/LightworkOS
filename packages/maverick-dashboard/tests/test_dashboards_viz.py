"""Executive boards on Overview / Spend / Workforce: the board API returns
windowed, owner-scoped payloads, and the pages ship the board skeleton
(slicer + stamp + card containers + board.js). Charts render client-side;
the API payload is the contract these tests pin."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def _seed_world():
    from maverick.world_model import WorldModel
    w = WorldModel()
    done = w.create_goal("Vendor DPA review", domain="legal_privacy")
    eid = w.start_episode(done)
    w.end_episode(eid, "ok", "success", cost_dollars=1.25,
                  input_tokens=10_000, output_tokens=1_500, tool_calls=6)
    w.set_goal_status(done, "done")
    blocked = w.create_goal("Access recert", domain="sec_access_review")
    w.set_goal_status(blocked, "blocked")
    return w


def test_overview_board_payload(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_world()
    d = _client().get("/api/v1/dashboards/overview?days=30").json()
    assert d["board"] == "overview" and d["days"] == 30
    assert d["totals"] == {"total": 2, "active": 0, "done": 1, "blocked": 1}
    assert len(d["daily"]) == 30
    # Both goals were created today — the last daily bucket carries them.
    assert d["daily"][-1]["started"] == 2 and d["daily"][-1]["delivered"] == 1
    assert d["window"]["started"] == 2 and d["window"]["delivered"] == 1
    # legal_privacy rolls up to its business suite; titles decrypt.
    assert any(r["total"] for r in d["domains"])
    assert d["recent"][0]["title"] in ("Vendor DPA review", "Access recert")


def test_overview_board_reports_every_status_not_just_the_headline_four(monkeypatch, tmp_path):
    """Deriving "Queued" as total - done - active - blocked would count failed,
    cancelled and draft goals as queued. The payload carries the real count
    per status so the page can show each one on its own."""
    _isolate(monkeypatch, tmp_path)
    w = _seed_world()
    for title, status in (("Waiting", "pending"), ("Broke", "failed"),
                          ("Stopped", "cancelled"), ("Half-written", "draft")):
        w.set_goal_status(w.create_goal(title, domain="legal_privacy"), status)
    d = _client().get("/api/v1/dashboards/overview?days=30").json()
    assert d["by_status"] == {
        "done": 1, "blocked": 1, "pending": 1, "failed": 1, "cancelled": 1, "draft": 1,
    }
    # The headline totals keep their meaning.
    assert d["totals"] == {"total": 6, "active": 0, "done": 1, "blocked": 1}


def test_spend_board_payload(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_world()
    d = _client().get("/api/v1/dashboards/spend?days=30").json()
    assert len(d["daily"]) == 30
    assert d["totals"]["runs"] == 1
    assert abs(d["totals"]["dollars"] - 1.25) < 1e-6
    assert d["totals"]["input_tokens"] == 10_000
    assert d["outcomes"] == {"success": 1, "failed": 0, "running": 0}
    assert d["top_goals"][0]["title"] == "Vendor DPA review"
    assert d["per_run"][0]["cost"] == 1.25


def test_workforce_board_payload(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_world()
    d = _client().get("/api/v1/dashboards/workforce?days=90").json()
    assert d["kpis"]["goals_completed"] == 1
    assert d["kpis"]["delivered_window"] == 1
    assert d["depts"] and d["depts"][0]["completed"] == 1
    assert d["leaders"]


def test_board_days_clamped_and_unknown_board_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    assert c.get("/api/v1/dashboards/overview?days=7").json()["days"] == 90
    assert c.get("/api/v1/dashboards/nope").status_code == 404


def test_department_scoped_user_cannot_read_unfiltered_company_boards(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_world()
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "caller_suites", lambda request: frozenset({"finance"}))
    client = _client()
    for board in ("overview", "spend", "workforce", "savings", "oversight"):
        api = client.get(f"/api/v1/dashboards/{board}")
        page = client.get(f"/{board}", headers={"Accept": "text/html"})
        assert api.status_code == 200, board
        assert page.status_code == 200, board
        assert api.json()["scope"] == "permitted_own"
        assert "Vendor DPA review" not in api.text
        assert "Access recert" not in api.text
        assert "not company totals" in page.text
    assert client.get("/api/v1/dashboards/overview").json()["totals"]["total"] == 0
    assert client.get("/api/v1/spend").json()["total"]["runs"] == 0
    # Department-specific boards retain their existing permission checks.
    assert client.get("/api/v1/dashboards/finance").status_code == 200
    monkeypatch.setattr(auth, "caller_suites", lambda request: None)
    assert client.get("/api/v1/dashboards/overview").status_code == 200
    assert client.get("/overview", headers={"Accept": "text/html"}).status_code == 200


def test_board_payloads_survive_empty_world(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    for board in ("overview", "spend", "workforce", "savings", "oversight",
                  "privacy", "finance", "security"):
        r = c.get(f"/api/v1/dashboards/{board}")
        assert r.status_code == 200, board
        assert r.json()["days"] == 90


def test_pages_ship_the_board_skeleton(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_world()
    c = _client()
    for path, marker in (("/overview", "bd-momentum"),
                         ("/spend", "bd-burn"),
                         ("/workforce", "bd-depts")):
        t = c.get(path).text
        assert "/static/board.js" in t, path
        assert 'aria-label="Time range"' in t and 'data-days="90"' in t and 'id="bd-stamp"' in t, path
        assert marker in t, path


def test_overview_empty_still_offers_first_goal(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/overview").text
    assert "Start your first task" in t
    assert "bd-momentum" not in t   # no board over an empty record


def test_department_boards_show_practice_cost_apart_from_the_real_totals(monkeypatch, tmp_path):
    """Practice AI calls cost real provider money: a department board shows
    them on their own line, scoped like its real figures (this person's tasks
    in their departments), and never inside the department's totals."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    w = _seed_world()
    real = w.create_goal("Pay the March invoices", domain="finance_ap")
    w.end_episode(w.start_episode(real), "ok", "success", cost_dollars=2.0)
    from maverick import practice
    from maverick.world_model import open_world

    with practice.scope():
        pw = open_world()
        for title, domain, cost in (("Practice: pay invoices", "finance_ap", 0.42),
                                    ("Practice: privacy review", "legal_privacy", 0.30)):
            pw.end_episode(pw.start_episode(pw.create_goal(title, domain=domain)), "ok", "success", cost_dollars=cost)
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "caller_suites", lambda request: frozenset({"finance"}))
    client = _client()
    for board in ("spend", "workforce", "savings"):
        data = client.get(f"/api/v1/dashboards/{board}?days=30").json()
        line = data["practice"]
        # Only the finance practice run: the legal one is outside this person's departments.
        assert line["dollars"] == 0.42 and line["runs"] == 1 and line["counted_against_limits"] is False, board
        assert line["text"] == "Practice: $0.42 in the last 30 days (not counted against limits)", board
    spend = client.get("/api/v1/dashboards/spend?days=30").json()
    assert spend["totals"]["dollars"] == 2.0 and spend["all_time"]["dollars"] == 2.0  # real totals unchanged
    for board in ("overview", "oversight"):
        assert "practice" not in client.get(f"/api/v1/dashboards/{board}").json(), board


def test_board_refuses_a_non_ascii_context_header_like_any_other_wrong_one(monkeypatch, tmp_path):
    from maverick import world_model

    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    client = _client()
    # Header text arrives decoded as latin-1, so e-acute is a non-ASCII str.
    for value in ("0" * 64, b"caf\xe9"):
        refused = client.get("/api/v1/dashboards/overview?days=30", headers={"X-Lightwork-Board-Context": value})
        assert refused.status_code == 409, (value, refused.status_code, refused.text)
