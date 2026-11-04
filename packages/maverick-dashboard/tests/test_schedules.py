"""Dashboard scheduling: arm a saved template (or a prompt) to run on a cron.

Hermetic like the other dashboard tests: HOME is isolated to tmp so JobQueue
uses a tmp jobs.db and templates resolve under tmp. Nothing here runs a goal —
the worker is out of scope; these cover the REST surface that arms/lists/cancels
schedules, plus the [features] scheduling gate.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    # Mutating /api/v1 requests in no-token mode must pass the same-origin CSRF check.
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    import maverick.templates as tpl
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tmp_path / ".maverick" / "templates")


def _retire(client, job_id, *, headers=None):
    listing = client.get("/api/v1/schedules", headers=headers).json()["schedules"]
    selected = next(row for row in listing if row["id"] == job_id)
    response = client.post(f"/api/v1/schedules/definitions/{selected['definition_id']}",
                           headers=headers, json={"expected_revision": selected["revision"],
                                                  "state": "retired", "confirm": True})
    assert response.status_code == 200, response.text
    return response.json()


def test_create_list_cancel_text_schedule(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    r = c.post("/api/v1/schedules", json={
        "cron": "0 9 * * 1-5", "text": "Summarize overnight emails", "title": "AM digest"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["cron"] == "0 9 * * 1-5" and body["kind"] == "start_goal"
    assert body["title"] == "AM digest" and body["next_run"] > 0
    sid = body["id"]
    # it appears in the list
    listed = c.get("/api/v1/schedules").json()["schedules"]
    assert any(s["id"] == sid and s["cron"] == "0 9 * * 1-5" for s in listed)
    # Durable definitions retire through a reviewed revision and retain history.
    assert c.delete(f"/api/v1/schedules/{sid}").status_code == 409
    retired = _retire(c, sid)
    assert retired["state"] == "retired" and retired["next_run"] == 0
    assert retired["owner"] == ""
    assert retired["history"][0]["status"] == "cancelled"
    assert any(row["definition_id"] == retired["definition_id"]
               for row in c.get("/api/v1/schedules").json()["schedules"])


def test_create_schedule_preserves_proxy_identity(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick_dashboard.auth as auth
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")

    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: True)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)

    c = _client()
    r = c.post(
        "/api/v1/schedules",
        headers={"X-Forwarded-User": "alice"},
        json={"cron": "0 9 * * *", "text": "Run restricted task", "title": "Restricted"},
    )
    assert r.status_code == 201, r.text

    from maverick.job_queue import JobQueue

    job = JobQueue().get(r.json()["id"])
    assert job is not None
    assert job.payload["owner"] == "user:alice"
    assert job.payload["channel"] == "api"
    assert job.payload["user_id"] == "alice"


def test_create_schedule_returns_stable_schedule_id(monkeypatch, tmp_path):
    # v2 provenance: a stable schedule_id is minted, carried in the job payload
    # (so it survives cron re-arms), surfaced by the API, and used to group runs.
    _isolate(monkeypatch, tmp_path)
    c = _client()
    r = c.post("/api/v1/schedules", json={"cron": "0 9 * * *", "text": "x", "title": "t"})
    assert r.status_code == 201, r.text
    sid = r.json()["schedule_id"]
    assert sid
    from maverick.job_queue import JobQueue
    assert JobQueue().get(r.json()["id"]).payload["schedule_id"] == sid
    listed = c.get("/api/v1/schedules").json()["schedules"]
    assert any(s["schedule_id"] == sid for s in listed)


def test_create_schedule_from_template_renders_params(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    tdir = tmp_path / ".maverick" / "templates"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "weekly-report.md").write_text(
        "---\nowner: local\ntitle: Weekly {{topic}} report\nparams:\n  - topic\n---\n"
        "Research {{topic}} and email the team.\n", encoding="utf-8")
    c = _client()
    r = c.post("/api/v1/schedules", json={
        "cron": "0 9 * * 1", "template": "weekly-report", "params": {"topic": "rivals"}})
    assert r.status_code == 201, r.text
    assert r.json()["title"] == "Weekly rivals report"   # title rendered from the template
    # a missing required param is a 400 (render raises ValueError)
    assert c.post("/api/v1/schedules", json={
        "cron": "0 9 * * 1", "template": "weekly-report"}).status_code == 400
    # an unknown template is a 404
    assert c.post("/api/v1/schedules", json={
        "cron": "0 9 * * 1", "template": "nope"}).status_code == 404


def test_bad_cron_and_empty_body_are_400(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    assert c.post("/api/v1/schedules",
                  json={"cron": "not a cron", "text": "x"}).status_code == 400
    # neither a template nor text to run
    assert c.post("/api/v1/schedules",
                  json={"cron": "0 9 * * *"}).status_code == 400


def _enable_oidc_principal_map(monkeypatch):
    """OIDC on; the bearer token string *is* the subject (no real JWT).

    ``Bearer alice`` -> principal ``user:alice`` — the same seam
    ``test_authz_owner_scoping.py`` uses.
    """
    import maverick_dashboard.auth as auth
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    rbac.set_role("user:mallory", "operator")

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    def _verify(token, **_kw):
        return VerifiedPrincipal(
            sub=token, issuer="https://issuer.example", audience="maverick",
            claims={"sub": token},
        )

    monkeypatch.setattr(auth, "verify_oidc_token", _verify)


def test_delete_schedule_cross_user_404(monkeypatch, tmp_path):
    """An authenticated non-admin cannot cancel another user's schedule (IDOR)."""
    _isolate(monkeypatch, tmp_path)
    import maverick.job_queue as jq
    monkeypatch.setattr(jq, "DEFAULT_DB", tmp_path / "jobs.db")
    _enable_oidc_principal_map(monkeypatch)
    c = _client()
    r = c.post("/api/v1/schedules",
               headers={"Authorization": "Bearer alice"},
               json={"cron": "0 9 * * *", "text": "alice's digest", "title": "AM"})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    # mallory (default operator role, owns nothing) may not cancel alice's schedule
    denied = c.delete(f"/api/v1/schedules/{sid}",
                      headers={"Authorization": "Bearer mallory"})
    assert denied.status_code == 404
    job = jq.JobQueue().get(sid)
    assert job is not None and job.status == "pending"  # still armed
    # a legacy unowned pending job is likewise not cancellable by a non-admin
    legacy = jq.JobQueue().enqueue("start_goal", {"text": "legacy", "__cron__": "0 9 * * *"})
    assert c.delete(f"/api/v1/schedules/{legacy}",
                    headers={"Authorization": "Bearer mallory"}).status_code == 404
    assert jq.JobQueue().get(legacy).status == "pending"
    # The owner retires their own reviewed definition; history remains intact.
    assert c.delete(f"/api/v1/schedules/{sid}",
                    headers={"Authorization": "Bearer alice"}).status_code == 409
    assert _retire(c, sid, headers={"Authorization": "Bearer alice"})["state"] == "retired"
    assert jq.JobQueue().get(sid).status == "cancelled"


def test_delete_schedule_admin_has_no_employee_content_authority(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.job_queue as jq
    monkeypatch.setattr(jq, "DEFAULT_DB", tmp_path / "jobs.db")
    _enable_oidc_principal_map(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    c = _client()
    r = c.post("/api/v1/schedules",
               headers={"Authorization": "Bearer alice"},
               json={"cron": "0 9 * * *", "text": "x", "title": "t"})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert c.delete(f"/api/v1/schedules/{sid}",
                    headers={"Authorization": "Bearer root"}).status_code == 404
    assert jq.JobQueue().get(sid).status == "pending"
    assert c.get("/api/v1/schedules", headers={"Authorization": "Bearer root"}).json()["schedules"] == []


def test_scheduling_feature_off_403(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import config
    real = config.get_features
    monkeypatch.setattr(config, "get_features", lambda: {**real(), "scheduling": False})
    c = _client()
    # the mutating route 403s; the read-only list stays available
    assert c.post("/api/v1/schedules",
                  json={"cron": "0 9 * * *", "text": "x"}).status_code == 403
    assert c.get("/api/v1/schedules").status_code == 200


def test_legacy_missing_owner_schedule_is_visible_only_to_local_caller(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.job_queue import JobQueue
    from maverick.scheduler import schedule_cron
    job_id, _ = schedule_cron(JobQueue(), "0 9 * * *", "start_goal", {"text": "legacy local", "__cron__": "0 9 * * *"})
    client = _client()
    own = client.get("/api/v1/schedules").json()["schedules"]
    assert [row["id"] for row in own] == [job_id]
    assert own[0]["owner"] == ""
    retired = _retire(client, job_id)
    assert retired["state"] == "retired"
    _enable_oidc_principal_map(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    headers = {"Authorization": "Bearer root"}
    assert client.get("/api/v1/schedules", headers=headers).json()["schedules"] == []
    refused = client.post(f"/api/v1/schedules/definitions/{retired['definition_id']}",
                          headers=headers, json={"expected_revision": retired["revision"],
                                                 "state": "retired", "confirm": True})
    assert refused.status_code == 404
