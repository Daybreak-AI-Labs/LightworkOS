"""Tests for the notify tool (maverick.tools.notify)."""
from __future__ import annotations

import pytest

# ---------- notify tool ----------


@pytest.fixture(autouse=True)
def _a_backend_is_configured(monkeypatch):
    monkeypatch.setattr("maverick.notifications.configured_backends", lambda *a, **k: ["ntfy"])


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
    # notify() counts a queued backend even when it has no destination, so the
    # tool asks whether one is configured instead of reading the count.
    monkeypatch.setattr("maverick.notifications.configured_backends", lambda *a, **k: [])
    monkeypatch.setattr(
        "maverick.notifications.notify",
        lambda *a, **k: 1,
    )
    from maverick.tools.notify import notify_tool
    out = notify_tool().fn({"title": "hello"})
    assert "no notification backend" in out


def test_notify_held_for_a_batch_is_not_reported_as_unconfigured(monkeypatch):
    # With batching on, notify() returns 0 while the item waits in the batcher.
    monkeypatch.setattr(
        "maverick.notifications.notify",
        lambda *a, outcomes=None, **k: outcomes.append("batched") or 0,
    )
    from maverick.tools.notify import notify_tool
    out = notify_tool().fn({"title": "hello"})
    assert out == "held for the next batched digest; delivery not yet confirmed"


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
