"""Tests for the notify tool (maverick.tools.notify)."""
from __future__ import annotations

# ---------- notify tool ----------

def test_notify_requires_title():
    from maverick.tools.notify import notify_tool
    out = notify_tool().fn({"body": "msg"})
    assert "requires title" in out


def test_notify_sanitizes_priority(monkeypatch):
    # notify() returns an int (backends fired) and takes a title kwarg.
    captured = {"prio": None, "title": None}

    def fake_notify(body, *, title="Lightwork", priority="default",
                    category="agent", **_):
        captured["prio"] = priority
        captured["title"] = title
        return 1

    monkeypatch.setattr("maverick.notifications.notify", fake_notify)
    from maverick.tools.notify import notify_tool
    out = notify_tool().fn({"title": "hi", "priority": "BOGUS"})
    assert out == "queued; delivery not yet confirmed (1 backend)"
    assert captured["prio"] == "default"
    # Title is forwarded as a distinct field, not jammed into the body.
    assert captured["title"] == "hi"


def test_notify_no_backend_configured(monkeypatch):
    # notify() returns 0 when no backend fires.
    monkeypatch.setattr(
        "maverick.notifications.notify",
        lambda *a, **k: 0,
    )
    from maverick.tools.notify import notify_tool
    out = notify_tool().fn({"title": "hello"})
    assert "no notification backend" in out


def test_notify_reports_count(monkeypatch):
    # notify() returns an int count of backends fired; the tool must format
    # that int, not call len() on it (which raised TypeError -> every
    # successful send was reported to the agent as an error).
    monkeypatch.setattr(
        "maverick.notifications.notify",
        lambda *a, **k: 2,
    )
    from maverick.tools.notify import notify_tool
    out = notify_tool().fn({"title": "hello", "body": "body"})
    assert out == "queued; delivery not yet confirmed (2 backends)"


def test_notify_urgent_maps_to_max(monkeypatch):
    # The tool exposes "urgent"; notify() backends use "max".
    captured = {}
    monkeypatch.setattr(
        "maverick.notifications.notify",
        lambda body, *, title="Lightwork", priority="default", **k:
        captured.__setitem__("prio", priority) or 1,
    )
    from maverick.tools.notify import notify_tool
    notify_tool().fn({"title": "x", "priority": "urgent"})
    assert captured["prio"] == "max"
