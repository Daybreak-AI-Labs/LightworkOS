"""Functional robustness: audit `day` path-traversal + bounded params.

The audit log resolves ``day`` to ``audit_dir/{day}.ndjson``; the
dashboard passed the raw ``?day=`` query value straight through, so a
crafted value could escape the audit directory. The day is now validated
to YYYY-MM-DD at the HTTP boundary, a non-numeric ``n`` no longer 500s,
and the events endpoints cap ``limit``.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _env(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(
        "maverick.audit.writer.DEFAULT_AUDIT_DIR", tmp_path / "audit",
    )
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    import maverick.audit.writer as aw
    aw._default = None
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_safe_audit_day_validation():
    from maverick_dashboard.app import safe_audit_day
    assert safe_audit_day("2026-05-28") == "2026-05-28"
    assert safe_audit_day("../../etc/passwd") is None
    assert safe_audit_day("../secret") is None
    assert safe_audit_day("2026-05-28/../../x") is None
    assert safe_audit_day("") is None
    assert safe_audit_day(None) is None


def test_audit_page_survives_non_numeric_n(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    r = _client().get("/audit?n=not-a-number")
    assert r.status_code == 200  # was an unguarded int() -> 500


def test_audit_page_rejects_invalid_day_with_actionable_error(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    r = _client().get("/audit?day=../../../etc/passwd")
    assert r.status_code == 400
    assert "YYYY-MM-DD" in r.text
    assert "../../../etc/passwd" not in r.text


def test_audit_apis_reject_invalid_day_instead_of_silently_using_today(
    monkeypatch, tmp_path
):
    _env(monkeypatch, tmp_path)
    c = _client()
    for path in (
        "/api/v1/audit/grep?pattern=x&day=../../../etc/passwd",
        "/api/v1/audit/tail?day=2026-02-31",
    ):
        response = c.get(path)
        assert response.status_code == 400
        assert "YYYY-MM-DD" in response.json()["detail"]


def test_goal_events_endpoint_caps_limit(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    from maverick import world_model
    gid = world_model.WorldModel(tmp_path / "world.db").create_goal("g", "d")
    r = _client().get(f"/api/v1/goals/{gid}/events?limit=999999999")
    assert r.status_code == 200


def test_wrong_content_type_returns_422_not_500(monkeypatch, tmp_path):
    # A client POSTing a non-JSON body with a wrong Content-Type triggered a
    # RequestValidationError whose 'input' was raw bytes; json.dumps couldn't
    # serialize it, turning the 422 into an opaque 500.
    _env(monkeypatch, tmp_path)
    from maverick_dashboard.app import app
    c = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"},
                   raise_server_exceptions=False)
    r = c.post("/api/v1/goals", content=b"hello world",
               headers={"Content-Type": "text/garbage"})
    assert r.status_code == 422, r.status_code


def test_overflow_goal_id_returns_404_not_500(monkeypatch, tmp_path):
    # A goal_id beyond SQLite's signed-64-bit range raised OverflowError ->
    # uncaught -> 500. It can't be a real row, so it must be 404.
    _env(monkeypatch, tmp_path)
    from maverick_dashboard.app import app
    c = TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False)
    big = 2 ** 63 + 1
    for path in (f"/api/v1/goals/{big}", f"/api/v1/goals/{big}/events"):
        r = c.get(path)
        assert r.status_code == 404, (path, r.status_code)
