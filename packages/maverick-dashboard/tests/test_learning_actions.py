"""Learning buttons on the Learned and Learning pages: global-admin only,
kernel functions underneath, plain answers."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
REVISION = "a" * 64


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, dreaming, world_model
    from maverick_dashboard import app as dash_app
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(dreaming, "snapshots_dir", lambda: tmp_path / "snapshots")
    monkeypatch.setattr(dreaming, "_live_stores", lambda: {"guardrails.json": tmp_path / "guardrails.json"})
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash_app._world_cache.clear()


@pytest.fixture
def saved_point(monkeypatch):
    from maverick import dreaming

    coverage = {"revision": REVISION, "labels": ["Learned skills"], "notice": "Checked",
                "source_notice": "Current account", "preserved": "Customer work stays current"}

    def read(name):
        if name not in dreaming.list_snapshots():
            raise ValueError("Saved point missing")
        return coverage

    monkeypatch.setattr(dreaming, "snapshot_coverage", read)
    return coverage


def _operator(monkeypatch):
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:op1", "operator")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:op1")


def test_every_learning_action_needs_a_global_admin(client, monkeypatch):
    _operator(monkeypatch)
    for method, path, body in (
        ("post", "/api/v1/learned/guidance/remove", {"model_id": "m", "line": "x"}),
        ("post", "/api/v1/learned/guidance/retire", {"older_than_days": 90}),
        ("post", "/api/v1/learned/guidance/probation-review", {"model_id": "m"}),
        ("get", "/api/v1/learning/snapshots", None),
        ("get", "/api/v1/learning/snapshots/20260101T000000Z/coverage", None),
        ("post", "/api/v1/learning/dream", {"preview": True}),
        ("post", "/api/v1/learning/rollback", {"snapshot": "20260101T000000Z", "revision": REVISION}),
        ("post", "/api/v1/learning/hindsight", {}),
        ("post", "/api/v1/learning/prove", {"baseline": [1], "treatment": [1]}),
    ):
        kwargs = {"json": body} if body is not None else {}
        assert getattr(client, method)(path, **kwargs).status_code == 403, path


def test_remove_one_lesson(client, monkeypatch, tmp_path):
    from maverick import self_harness as sh
    store = tmp_path / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: store)
    sh._write_addenda({"claude-x": "Operating guidance learned for this model:\n"
                                   "- keep this\n- drop this\n- retained legacy lesson"}, store)
    meta = {}
    for line in ("keep this", "drop this"):
        sh._upsert_line_meta(meta, "claude-x", line, {"source_goal_ids": [0]}, now=1)
    sh._write_line_meta(meta, store)
    assert sh.list_learned(store)["claude-x"] == ["keep this", "drop this"]
    r = client.post("/api/v1/learned/guidance/remove", json={"model_id": "claude-x", "line": "drop this"})
    assert r.json() == {"removed": True}
    assert sh.list_learned(store)["claude-x"] == ["keep this"]
    # Removing a shared lesson neither exposes nor discards quarantined content.
    assert "retained legacy lesson" in sh.load_addenda(store)["claude-x"]
    again = client.post("/api/v1/learned/guidance/remove", json={"model_id": "claude-x", "line": "drop this"})
    assert again.status_code == 404 and "already removed" in again.json()["detail"]


def test_retire_takes_only_the_offered_choices(client, monkeypatch):
    from maverick import self_harness as sh
    seen = []
    monkeypatch.setattr(sh, "retire_stale", lambda **kw: seen.append(kw) or 2)
    assert client.post("/api/v1/learned/guidance/retire", json={"older_than_days": 7}).status_code == 422
    assert client.post("/api/v1/learned/guidance/retire", json={"older_than_days": 90}).json() == {"retired": 2}
    assert seen == [{"older_than_days": 90.0}]


def test_snapshots_rollback_and_hindsight(client, monkeypatch, saved_point):
    from maverick import dreaming
    from maverick_dashboard.learning_actions_api import snapshot_label
    assert snapshot_label("20260927T101500Z") == "27 Sep 2026, 10:15 UTC"
    monkeypatch.setattr(dreaming, "list_snapshots", list)
    assert client.get("/api/v1/learning/snapshots").json() == {"snapshots": []}
    r = client.post("/api/v1/learning/hindsight", json={})
    assert r.status_code == 409 and "saved point" in r.json()["detail"]
    r = client.post("/api/v1/learning/rollback", json={"snapshot": "20260101T000000Z", "revision": REVISION})
    assert r.status_code == 404
    assert client.post("/api/v1/learning/rollback", json={"snapshot": "../etc", "revision": REVISION}).status_code == 422
    assert client.post("/api/v1/learning/rollback", json={"snapshot": "latest", "revision": REVISION}).status_code == 422
    monkeypatch.setattr(dreaming, "list_snapshots", lambda: ["20260101T000000Z"])
    def restore(name, *, expected_revision):
        assert name == "20260101T000000Z" and expected_revision == REVISION
        return ["skills", "insights"]

    monkeypatch.setattr(dreaming, "rollback_learning_state", restore)
    result = client.post("/api/v1/learning/rollback", json={"snapshot": "20260101T000000Z", "revision": REVISION})
    assert result.json() == {"restored": 2, "coverage": saved_point}
    assert client.post("/api/v1/learning/rollback", json={"snapshot": "20260101T000000Z", "revision": "b" * 64}).status_code == 409


@pytest.mark.parametrize("has_report", [True, False])
def test_failed_rollback_warns_that_learning_may_have_changed(client, monkeypatch,
                                                               tmp_path, has_report, saved_point):
    from maverick import dreaming

    snapshot = "20260101T000000Z"
    live = tmp_path / "learned-guidance.txt"
    live.write_text("current guidance", encoding="utf-8")
    monkeypatch.setattr(dreaming, "list_snapshots", lambda: [snapshot])

    def fail_after_restoring_guidance(name, *, expected_revision):
        assert name == snapshot and expected_revision == REVISION
        if has_report:
            live.write_text("saved guidance", encoding="utf-8")
            report = dreaming.LearningRollbackReport(
                snapshot=snapshot, required=("guidance", "skills"),
                restored=("guidance",), failures={"skills": "simulated write failure"},
            )
            raise dreaming.LearningRollbackError(report)
        raise OSError("simulated pre-effect integrity refusal")

    monkeypatch.setattr(dreaming, "rollback_learning_state", fail_after_restoring_guidance)
    response = client.post("/api/v1/learning/rollback", json={"snapshot": snapshot, "revision": REVISION})

    detail = response.json()["detail"]
    if has_report:
        assert live.read_text(encoding="utf-8") == "saved guidance"
        assert response.status_code == 503 and "may have changed" in detail
        assert "Review the Learned and Learning pages" in detail
        assert "Nothing was restored" not in detail
    else:
        assert live.read_text(encoding="utf-8") == "current guidance"
        assert response.status_code == 409 and "Nothing was restored" in detail


def test_dream_preview_and_run_respect_the_switch(client, monkeypatch):
    from maverick import dreaming
    report = dreaming.DreamReport(goals_replayed=4, insights_written=1, skills_distilled=2)
    monkeypatch.setattr(dreaming, "dream_cycle_dry", lambda world: report)
    out = client.post("/api/v1/learning/dream", json={"preview": True}).json()
    assert out["preview"] is True and out["tasks_reviewed"] == 4 and out["skills_learned"] == 2
    monkeypatch.setattr(dreaming, "enabled", lambda: False)
    r = client.post("/api/v1/learning/dream", json={"preview": False})
    assert r.status_code == 409 and "Turn on Dreaming" in r.json()["detail"]


def test_prove_learning_verdict(client):
    r = client.post("/api/v1/learning/prove", json={"baseline": [0, 0, 0, 0, 0, 0],
                                                    "treatment": [1, 1, 1, 1, 1, 1]})
    assert r.json()["verdict"] == "improved" and r.json()["better"] == 6
    assert client.post("/api/v1/learning/prove", json={"baseline": [0, 1], "treatment": [1]}).status_code == 422
    assert client.post("/api/v1/learning/prove", json={"baseline": [2], "treatment": [1]}).status_code == 422


def test_learning_page_offers_run_now_to_admins(client):
    from test_support.plain_language import developer_terms, visible_text
    page = client.get("/learning").text
    assert developer_terms(page) == []
    text = visible_text(page)
    for label in ("Run learning now", "Preview what would change", "Learn now",
                  "Go back to this point", "Check now", "Check the results"):
        assert label in text, label
    assert "HTTP" not in page and "flip it" not in page


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _admin(monkeypatch):
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:ada", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:ada")


def test_rollback_is_recorded_with_who_did_it(client, monkeypatch, audit_rows, saved_point):
    from maverick import dreaming
    from maverick.audit import EventKind
    _admin(monkeypatch)
    audit_rows.clear()
    monkeypatch.setattr(dreaming, "list_snapshots", lambda: ["20260101T000000Z"])
    monkeypatch.setattr(dreaming, "rollback_learning_state", lambda name, **kw: ["skills", "insights"])
    r = client.post("/api/v1/learning/rollback", json={"snapshot": "20260101T000000Z", "revision": REVISION})
    assert r.status_code == 200
    rows = [row for row in audit_rows if row.get("action") == "rollback"]
    assert len(rows) == 1
    row = rows[0]
    assert row["kind"] == EventKind.LEARNING_UPDATE and row["actor"] == "user:ada"
    assert row["snapshot"] == "20260101T000000Z" and row["restored"] == ["skills", "insights"]


def test_a_learning_run_is_recorded_with_who_started_it(client, monkeypatch, audit_rows):
    from maverick import dreaming
    from maverick.audit import EventKind
    _admin(monkeypatch)
    audit_rows.clear()
    report = dreaming.DreamReport(goals_replayed=4, insights_written=1, skills_distilled=2, activity_recorded=True)
    monkeypatch.setattr(dreaming, "enabled", lambda: True)
    monkeypatch.setattr(dreaming, "settings", lambda: {"snapshots": True})
    monkeypatch.setattr(dreaming, "dream_cycle", lambda world: report)
    monkeypatch.setattr(dreaming, "dream_cycle_dry", lambda world: report)
    assert client.post("/api/v1/learning/dream", json={"preview": True}).status_code == 200
    assert [row for row in audit_rows if row.get("action") == "dream_run"] == []
    assert client.post("/api/v1/learning/dream", json={"preview": False}).status_code == 200
    rows = [row for row in audit_rows if row.get("action") == "dream_run"]
    assert len(rows) == 1
    assert rows[0]["kind"] == EventKind.LEARNING_UPDATE and rows[0]["actor"] == "user:ada"
    assert rows[0]["lessons_written"] == 1 and rows[0]["skills_learned"] == 2
