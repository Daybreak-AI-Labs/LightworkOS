"""Dashboard control surface.

Adds halt button, consent / answer-question UI, audit log page,
plugins / MCP / tools / channels list pages, skill install form, and
goal cancel. Each requires a backing route or page render here.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


# ---------- halt ----------

def test_halt_status_when_clear(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/api/v1/halt")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is False
    assert body["file"].endswith("HALT")
    assert body["file_present"] is False


def test_halt_post_then_status_then_delete(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    # Arm.
    r = client.post(
        "/api/v1/halt",
        json={"reason": "test"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 204
    assert (tmp_path / "HALT").exists()
    # Status reflects file presence.
    s = client.get("/api/v1/halt").json()
    assert s["file_present"] is True
    # Clear.
    r = client.delete(
        "/api/v1/halt",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 204
    assert not (tmp_path / "HALT").exists()


# ---------- cancel goal ----------

def test_cancel_goal_marks_status(monkeypatch, tmp_path: Path):
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)

    wm = world_model.WorldModel(db)
    gid = wm.create_goal("test", "desc")
    wm.close() if hasattr(wm, "close") else None

    client = _client()
    r = client.post(
        f"/api/v1/goals/{gid}/cancel",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 204

    wm2 = world_model.WorldModel(db)
    g = wm2.get_goal(gid)
    assert g.status == "cancelled"


def test_cancel_unknown_goal_404(monkeypatch, tmp_path: Path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.post(
        "/api/v1/goals/99999/cancel",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 404


def test_cancel_already_done_goal_noop(monkeypatch, tmp_path: Path):
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    wm = world_model.WorldModel(db)
    gid = wm.create_goal("test", "desc")
    wm.set_goal_status(gid, "done", result="ok")
    client = _client()
    r = client.post(
        f"/api/v1/goals/{gid}/cancel",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 204
    g = world_model.WorldModel(db).get_goal(gid)
    assert g.status == "done"  # untouched


# ---------- open questions ----------

def test_open_questions_empty(monkeypatch, tmp_path: Path):
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    wm = world_model.WorldModel(db)
    gid = wm.create_goal("test", "desc")
    client = _client()
    r = client.get(f"/api/v1/goals/{gid}/open_questions")
    assert r.status_code == 200
    assert r.json() == {"open_questions": [], "last_answer": None}


def test_open_questions_returns_unanswered(monkeypatch, tmp_path: Path):
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    wm = world_model.WorldModel(db)
    gid = wm.create_goal("test", "desc")
    wm.ask("Which dates?", goal_id=gid)
    client = _client()
    r = client.get(f"/api/v1/goals/{gid}/open_questions")
    body = r.json()
    assert len(body["open_questions"]) == 1
    assert body["open_questions"][0]["question"] == "Which dates?"


# ---------- list endpoints ----------

def test_list_plugins_returns_groups(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/api/v1/plugins")
    assert r.status_code == 200
    body = r.json()
    assert "plugins" in body
    for kind in ("tools", "channels", "skills", "personas"):
        assert kind in body["plugins"]
        assert isinstance(body["plugins"][kind], list)


def test_list_mcp_servers(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/api/v1/mcp")
    assert r.status_code == 200
    assert "servers" in r.json()


def test_list_channels(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/api/v1/channels")
    assert r.status_code == 200
    assert "channels" in r.json()


def test_audit_tail_empty(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    # AuditLog's default arg was bound at class-def time, so patching
    # DEFAULT_AUDIT_DIR on the module is ineffective. Inject a fresh
    # singleton with the explicit tmp dir.
    import maverick.audit.writer as w
    w._default = w.AuditLog(audit_dir=tmp_path / "audit")
    client = _client()
    r = client.get("/api/v1/audit/tail")
    assert r.status_code == 200
    assert r.json()["events"] == []


# ---------- HTML pages render ----------

def test_audit_page_renders(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(
        "maverick.audit.writer.DEFAULT_AUDIT_DIR", tmp_path / "audit",
    )
    import maverick.audit.writer as w
    w._default = None
    client = _client()
    r = client.get("/audit")
    assert r.status_code == 200
    assert "activity log" in r.text.lower()


def test_plugins_page_renders(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/plugins")
    assert r.status_code == 200
    assert "plugins" in r.text.lower()


def test_mcp_page_renders(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/mcp")
    assert r.status_code == 200
    assert "mcp" in r.text.lower()


def test_tools_page_renders(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/tools")
    assert r.status_code == 200
    assert "tool" in r.text.lower()


def test_channels_page_renders(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/channels")
    assert r.status_code == 200
    assert "channel" in r.text.lower()


def test_channels_page_redacts_sensitive_values(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    import maverick.config as _cfg
    monkeypatch.setattr(
        _cfg,
        "load_config",
        lambda: {
            "channels": {
                "slack": {
                    "enabled": True,
                    "bot_token": "xoxb-real-secret",
                    "app_token": "xapp-real-secret",
                    "workspace": "ops",
                }
            }
        },
    )
    client = _client()
    r = client.get("/channels")
    assert r.status_code == 200
    # The page no longer dumps raw configuration at all, and secrets never render.
    assert "bot_token=" not in r.text and "workspace=ops" not in r.text
    assert "xoxb-real-secret" not in r.text
    assert "xapp-real-secret" not in r.text


# ---------- nav + halt UI present in base.html ----------

def test_base_nav_includes_new_pages(monkeypatch, tmp_path):
    """Every new page is reachable via the header nav."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/")
    text = r.text
    # /tools is folded out of the sidebar in the moderate declutter (reached
    # in-page); the rest remain first-class nav entries.
    for href in ("/audit", "/plugins", "/mcp", "/channels"):
        assert href in text, f'nav missing link to {href}'


def test_base_renders_halt_pill(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/overview")
    assert "halt-pill" in r.text


def test_footer_no_longer_leaks_world_db_path(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/")
    assert "~/.maverick/world.db" not in r.text


# ---------- index hero empty state ----------

def test_index_empty_state_shows_hero(monkeypatch, tmp_path):
    """The overview shows the hero CTA on a fresh install, not 4 zeros + 3 'No X yet' rows."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/overview")
    text = r.text
    assert "Start your first task" in text
    # The 4-zeros graveyard should be absent on a fresh install.
    assert text.count('class="num"') == 0


def test_halt_status_includes_reason_and_armed_at(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    # Arm with a reason.
    r = client.post(
        "/api/v1/halt",
        json={"reason": "test arm"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 204
    s = client.get("/api/v1/halt").json()
    assert s["file_present"] is True
    assert s["reason"] == "test arm"
    assert isinstance(s["armed_at"], (int, float))
    assert s["armed_at"] > 0


def test_halt_status_when_clear_has_no_reason(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    s = client.get("/api/v1/halt").json()
    assert s["file_present"] is False
    assert s["reason"] is None
    assert s["armed_at"] is None


def test_cache_stats_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/api/v1/cache/stats")
    assert r.status_code == 200
    body = r.json()
    assert "files" in body
    assert "max_entries" in body["files"]


def test_cache_purge_endpoint_default_all(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.post(
        "/api/v1/cache/purge",
        json={"scopes": ["all"]},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 200
    report = r.json()
    assert {"files", "repo_map"}.issubset(report.keys())


def test_cache_purge_targeted_scope(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick.cache.file import read_cache_stats, read_file_cached
    f = tmp_path / "x.txt"
    f.write_text("data")
    read_file_cached(f)
    assert read_cache_stats()["entries"] >= 1

    client = _client()
    r = client.post(
        "/api/v1/cache/purge",
        json={"scopes": ["files"]},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 200
    assert read_cache_stats()["entries"] == 0


def test_cache_html_page_renders(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.get("/cache")
    assert r.status_code == 200
    text = r.text
    assert "Clear everything" in text
    assert "Recently read files" in text
    # (Cache is folded out of the sidebar in the moderate declutter; still
    # reachable at /cache and rendered above.)


def test_audit_grep_requires_pattern(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    import maverick.audit.writer as w
    w._default = w.AuditLog(audit_dir=tmp_path / "audit")
    client = _client()
    r = client.get("/api/v1/audit/grep?pattern=")
    assert r.status_code == 422 or r.status_code == 400  # required arg either way


def test_audit_grep_treats_regex_tokens_as_literal_text(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog
    al = AuditLog(audit_dir=tmp_path / "audit")
    al.record(AuditEvent(
        ts=1.0, kind=EventKind.TOOL_CALL,
        payload={"name": "has-parens", "principal": "user:(unclosed", "input_summary": "private-reason"}))
    import maverick.audit.writer as w
    w._default = al
    client = _client()
    # A regex metacharacter that would be an invalid pattern is now matched
    # literally (no ReDoS surface), so this returns the event, not a 400.
    r = client.get("/api/v1/audit/grep?pattern=(unclosed")
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) == 1
    assert events[0]["principal"] == "user:(unclosed"
    assert "name" not in events[0] and "input_summary" not in events[0]
    assert client.get("/api/v1/audit/grep?pattern=private-reason").json()["events"] == []


def test_audit_grep_finds_matching_events(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog
    al = AuditLog(audit_dir=tmp_path / "audit")
    al.record(AuditEvent(
        ts=1.0, kind=EventKind.TOOL_CALL,
        payload={"name": "shell", "principal": "user:alice", "input_summary": "ls"}))
    al.record(AuditEvent(
        ts=2.0, kind=EventKind.TOOL_CALL,
        payload={"name": "web_search", "principal": "user:bob", "input_summary": "x"}))
    import maverick.audit.writer as w
    w._default = al
    client = _client()
    r = client.get("/api/v1/audit/grep?pattern=user:alice")
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) == 1
    assert events[0]["principal"] == "user:alice"
    assert "name" not in events[0] and "input_summary" not in events[0]


def test_audit_grep_scans_complete_day_and_reports_result_cap(monkeypatch, tmp_path):
    """A match outside the old 1,000-row tail remains discoverable, while a
    capped response says exactly how much evidence was scanned and omitted."""
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    import maverick.audit.writer as writer
    from maverick.audit.writer import AuditLog

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    day = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    rows = []
    for index in range(1_205):
        rows.append(
            {
                "v": 1,
                "ts": float(index),
                "kind": "tool_result",
                "agent": "qa",
                "goal_id": None,
                "principal": "user:complete-day-needle" if index < 205 else "user:other",
                "detail": "private context",
            }
        )
    (audit_dir / f"{day}.ndjson").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    writer._default = AuditLog(audit_dir=audit_dir, sign=False)

    response = _client().get("/api/v1/audit/grep?pattern=complete-day-needle")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scanned"] == 1_205
    # Exactly 205 seeded control identifiers match. A request URL is private
    # payload and never creates an extra content-search result.
    assert body["total_matches"] == 205
    assert body["returned"] == 200
    assert body["truncated"] is True
    assert body["scan_complete"] is True
    assert body["scope"] == {"day": day}


def test_resume_404_for_unknown_goal(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    r = client.post(
        "/api/v1/goals/9999/resume",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 404


def test_resume_conflicts_when_goal_not_paused(monkeypatch, tmp_path):
    """Only blocked / cancelled / failed goals are resumable."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    wm = world_model.WorldModel(tmp_path / "world.db")
    gid = wm.create_goal("g", "x")
    wm.set_goal_status(gid, "active")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    r = client.post(
        f"/api/v1/goals/{gid}/resume",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "restart_changed"
    assert r.json()["detail"]["next_action"]["href"] == f"/chat/goal/{gid}"


def test_resume_flips_cancelled_to_pending(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    wm = world_model.WorldModel(tmp_path / "world.db")
    gid = wm.create_goal("g", "x")
    wm.set_goal_status(gid, "cancelled", result="cancelled via dashboard")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    # Stub the dispatcher-facing async seam so the background task doesn't
    # actually start the agent (all launch surfaces now route through it).
    from maverick import runner
    captured = []

    async def _queued(*args, **kwargs):
        captured.append(("called", args, kwargs))
        return "queued"

    monkeypatch.setattr(runner, "run_goal_in_background_async", _queued)
    client = _client()
    r = client.post(
        f"/api/v1/goals/{gid}/resume",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 204
    # The world.db row flipped.
    g = world_model.WorldModel(tmp_path / "world.db").get_goal(gid)
    assert g.status == "pending"
    # The runner was scheduled.
    assert captured, "runner was not scheduled"


def test_resume_blocked_goal(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    wm = world_model.WorldModel(tmp_path / "world.db")
    gid = wm.create_goal("g", "x")
    wm.set_goal_status(gid, "blocked")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    from maverick import runner

    async def _queued(*_args, **_kwargs):
        return "queued"

    monkeypatch.setattr(runner, "run_goal_in_background_async", _queued)
    client = _client()
    r = client.post(
        f"/api/v1/goals/{gid}/resume",
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 204
