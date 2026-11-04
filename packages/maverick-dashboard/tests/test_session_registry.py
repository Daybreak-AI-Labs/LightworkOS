"""Server-side session record: register, list, end one, end all, prune."""
from __future__ import annotations

import os
import time

import pytest
from maverick import config
from maverick_dashboard import session_registry as sr


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    config.reset_config_cache()
    # The throttle and the open store connection are process-wide: one test's
    # refresh must not throttle the next test's touch, nor keep its file open.
    sr._TOUCHED.clear()
    yield
    sr._drop_shared()
    sr._TOUCHED.clear()
    config.reset_config_cache()


def _register(sid, principal="user:alice", **over):
    now = time.time()
    fields = dict(sid=sid, principal=principal, via="session", mfa=True, mfa_at=now,
                  issued_at=now, expires_at=now + 3600, ip="203.0.113.9",
                  user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36")
    fields.update(over)
    sr.register(**fields)


def test_register_status_and_listing():
    _register("s1")
    _register("s2", mfa=False, mfa_at=None, via="invite")
    _register("s3", principal="user:bob")
    assert sr.status("s1") is True
    assert sr.status("nope") is None
    mine = sr.list_for("user:alice")
    assert [r.sid for r in mine] == ["s2", "s1"] or {r.sid for r in mine} == {"s1", "s2"}
    record = sr.get("s1")
    assert record.mfa is True and record.user_agent == "Chrome on Windows"
    assert record.ip == "203.0.113.9" and record.active
    assert {r.sid for r in sr.list_all()} == {"s1", "s2", "s3"}


def test_revoke_one_and_everywhere():
    _register("s1")
    _register("s2")
    _register("s3", principal="user:bob")
    ended = sr.revoke("s1", by="user:alice")
    assert ended.revoked_at is not None and ended.revoked_by == "user:alice"
    assert sr.status("s1") is False
    assert sr.revoke("missing", by="x") is None
    assert sr.revoke_all("user:alice", by="admin") == 1  # s2 only; s1 already ended
    assert sr.status("s2") is False and sr.status("s3") is True
    assert sr.list_for("user:alice") == []
    assert len(sr.list_for("user:alice", include_ended=True)) == 2


def test_revoke_all_can_keep_the_current_device():
    _register("s1")
    _register("s2")
    assert sr.revoke_all("user:alice", by="user:alice", keep_sid="s1") == 1
    assert sr.status("s1") is True and sr.status("s2") is False


def test_expired_sessions_are_inactive_and_pruned_after_retention():
    yesterday = time.time() - 86400
    _register("old", issued_at=yesterday - 60, expires_at=yesterday)
    assert sr.status("old") is False
    assert sr.list_for("user:alice") == []
    long_ago = time.time() - 40 * 86400
    _register("ancient", issued_at=long_ago, expires_at=long_ago + 60)
    _register("fresh")  # registering prunes rows past retention (30 days)
    assert sr.status("ancient") is None and sr.status("old") is False


def test_touch_updates_last_seen_at_most_once_a_minute():
    _register("s1", issued_at=time.time() - 120)
    before = sr.get("s1").last_seen
    sr.touch("s1", ip="198.51.100.4", user_agent="curl/8.0")
    after = sr.get("s1")
    assert after.last_seen > before and after.ip == "198.51.100.4"
    assert after.user_agent == "curl"
    sr.touch("s1", ip="198.51.100.5")
    assert sr.get("s1").ip == "198.51.100.4"  # throttled


def test_unreadable_store_fails_closed(tmp_path):
    path = sr._path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not a database", encoding="utf-8")
    with pytest.raises(sr.SessionStoreError):
        sr.status("s1")
    with pytest.raises(sr.SessionStoreError):
        sr.list_all()


@pytest.mark.parametrize("ua, expected", [
    ("", "Unknown device"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1", "Safari on iPhone"),
    ("Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0", "Firefox on Linux"),
    ("python-httpx/0.27", "Program"),
])
def test_user_agent_summary(ua, expected):
    assert sr.user_agent_summary(ua) == expected


def test_a_bearer_key_cannot_end_sessions_and_a_late_audit_refusal_is_reported_honestly(monkeypatch):
    from fastapi import HTTPException
    from maverick.audit import AuditRefused
    from maverick_dashboard import auth, sessions_page

    monkeypatch.setattr(auth, "api_key_permissions", lambda request: {"view"})
    for call in (lambda: sessions_page._revoke_one(object(), "a" * 32),
                 lambda: sessions_page._revoke_everywhere(object(), None)):
        with pytest.raises(HTTPException) as refused:
            call()
        assert refused.value.status_code == 403 and "API key" in refused.value.detail

    def refuse(*args, **kwargs):
        raise AuditRefused("custody unavailable")

    monkeypatch.setattr("maverick.audit.audit_event", refuse)
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:admin")
    with pytest.raises(HTTPException) as late:
        sessions_page._audit_revoke(object(), target="user:x", sid="", count=1, everywhere=True)
    assert late.value.status_code == 503 and "were signed out" in late.value.detail


@pytest.mark.skipif(os.name == "nt", reason="Windows keeps no store handle between calls (_KEEP_OPEN)")
def test_the_store_connection_is_reused_until_the_file_is_replaced():
    with sr._connect() as first:
        pass
    with sr._connect() as second:
        pass
    assert second is first
    sr._path().unlink()
    with sr._connect() as third:
        pass
    assert third is not first
    _register("after-replace")
    assert sr.status("after-replace") is True
    assert sr.status("never-registered") is None


def test_no_store_handle_outlives_a_call_where_the_file_cannot_be_replaced(monkeypatch):
    # Windows: an open store file cannot be removed or swapped by an operator,
    # so nothing may keep it open between calls.
    monkeypatch.setattr(sr, "_KEEP_OPEN", False)
    _register("s1")
    assert sr._SHARED["conn"] is None
    assert sr.status("s1") is True
    assert sr._SHARED["conn"] is None
    sr._path().unlink()
    assert sr.status("s1") is None
    _register("s2")
    assert sr.status("s2") is True and sr._SHARED["conn"] is None


def test_a_refresh_inside_the_window_does_not_reach_the_store(monkeypatch):
    sr._TOUCHED.clear()
    _register("s1", issued_at=time.time() - 120)
    sr.touch("s1", ip="203.0.113.10", activity=True)   # this process's first refresh writes
    assert sr.get("s1").ip == "203.0.113.10"
    calls = []
    real_connect = sr._connect

    def counting_connect():
        calls.append(1)
        return real_connect()

    monkeypatch.setattr(sr, "_connect", counting_connect)
    sr.touch("s1", activity=True)
    sr.touch("s1", activity=True)
    assert calls == []
    sr._TOUCHED.clear()
    sr.touch("s1", ip="203.0.113.11", activity=True)
    assert calls == [1]
    assert sr.get("s1").ip == "203.0.113.10"   # last_seen is recent, so the UPDATE matches nothing, as before


def test_a_refresh_another_process_wrote_does_not_throttle_this_one(monkeypatch):
    # A touch whose UPDATE matched nothing (another process refreshed the row
    # inside the window) must not start this process's window: the row's time
    # is unknown here, so the next touch asks the store again.
    start = time.time()
    _register("s1", issued_at=start - 30)        # refreshed 30 s ago elsewhere
    clock = [start]
    monkeypatch.setattr(sr.time, "time", lambda: clock[0])
    sr.touch("s1", ip="198.51.100.4", activity=True)
    assert sr.get("s1").ip == "203.0.113.9"      # inside that window: no write
    assert "s1" not in sr._TOUCHED
    clock[0] = start + 40                         # 70 s after the other refresh
    sr.touch("s1", ip="198.51.100.5", activity=True)
    record = sr.get("s1")
    assert record.ip == "198.51.100.5" and record.last_seen == start + 40

