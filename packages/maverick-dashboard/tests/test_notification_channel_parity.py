"""NOT-1 across every channel: each kind of notification says why the person
gets it, what is needed, by when, and links to the exact item -- in the app,
in a private Slack or Telegram message, and in the daily summary by email
(text and HTML) and in Slack. One of each kind goes through every formatter.

This is the buildable part of the 50-notification sample; delivery through
live Slack, Teams and email workspaces still needs connected accounts."""
from __future__ import annotations

import re
import sys
import time
from types import SimpleNamespace

import pytest
from maverick import daily_digest
from maverick.personal_notifications import alert_brief, explain, validate_preferences
from maverick.slack_interactive import digest_blocks

BASE = "https://lw.example.test"
DUE = time.time() + 3 * 3600

ALERTS = [
    {"category": "needs-decision", "label": "Needs your decision", "href": "/approvals#approval-7",
     "reason": "You were assigned to decide this request", "action": "Approve or reject the request", "due_at": DUE},
    {"category": "blocked", "label": "Needs attention", "href": "/chat/goal/1", "goal_id": 1},
    {"category": "failed", "label": "Did not finish", "href": "/chat/goal/2", "goal_id": 2},
    {"category": "completed", "label": "Finished", "href": "/chat/goal/3", "goal_id": 3},
    {"category": "changed-result", "label": "Result changed", "href": "/chat/goal/4", "goal_id": 4},
    {"category": "deadline", "label": "Deadline approaching or overdue", "href": "/chat/goal/5", "goal_id": 5,
     "due_at": DUE},
    {"category": "mention", "label": "Mentioned you", "href": "/permissions#comment-9",
     "reason": "Dana mentioned you in a comment", "action": "Read the comment and reply"},
]


@pytest.mark.parametrize("alert", ALERTS, ids=[a["category"] for a in ALERTS])
def test_in_app_alerts_say_why_what_by_when_and_link(alert):
    shown = explain(dict(alert))
    assert shown["reason"] and shown["action"]
    assert shown["due_at"] or shown["no_due"]
    assert shown["href"].startswith("/") and not shown["href"].startswith("//")


@pytest.mark.parametrize("alert", ALERTS, ids=[a["category"] for a in ALERTS])
def test_private_messages_say_why_what_by_when_and_link(alert, tmp_path, monkeypatch):
    from maverick import personal_notification_delivery as delivery

    brief = alert_brief(alert)
    assert re.search(r"Why: .+\.$", brief), brief
    explained = explain(dict(alert))
    assert explained["action"] in brief
    assert ("Due " in brief or "Decide by " in brief) if alert.get("due_at") else explained["no_due"] in brief
    monkeypatch.setattr(delivery, "seal", lambda value: value)
    monkeypatch.setattr(delivery, "unseal", lambda value: value)
    monkeypatch.setattr(delivery, "data_dir", lambda *parts: tmp_path.joinpath(*parts))
    monkeypatch.setattr(delivery, "_settings", lambda: {"personal_dashboard_url": BASE})
    link = {"id": "a" * 32, "verified_at": 1, "channel": "telegram", "sender_id": "123"}
    monkeypatch.setitem(sys.modules, "maverick.personal_identity", SimpleNamespace(
        linked_channels=lambda _: [link], principal_current=lambda _: True))
    sent = []
    monkeypatch.setattr(delivery, "send_private", lambda target, text, *rest: sent.append(text))
    delivery.dispatch("user:ana", {"items": [{**alert, "id": "b" * 64, "seen_at": None}]},
                      validate_preferences({"external_links": [link["id"]]}))
    assert sent and brief in sent[0] and BASE + alert["href"] in sent[0]


def _digest():
    return {
        "principal": "", "date_label": "Tuesday 06 October 2026", "time_zone": "UTC", "empty": False,
        "approvals": [{"id": 7, "action": "Send email", "risk_label": "High risk", "decide_by": DUE}],
        "questions": [{"goal_id": 2, "question": "Which vendor?"}],
        "results": [{"id": 3, "title": "Vendor spend", "status": "done", "status_label": "Finished",
                     "href": "/chat/goal/3"},
                    {"id": 4, "title": "Close books", "status": "failed", "status_label": "Did not finish",
                     "href": "/chat/goal/4"}],
        "expiring_keys": [{"label": "deploy", "prefix": "lw_dep", "days_left": 2, "href": "/api-keys"}],
        "spending": {"dollars": 0, "limit_dollars": 0}, "counts": {},
    }


def test_every_summary_line_says_what_is_needed_by_when_and_links_in_every_format():
    digest = _digest()
    text = daily_digest.render_text(digest, dashboard_url=BASE)
    html = daily_digest.render_html(digest, dashboard_url=BASE)
    slack = " ".join(str(block) for block in digest_blocks(digest, dashboard_url=BASE))
    for rendered in (text, html, slack):
        assert "You get this because you turned on the daily summary" in rendered  # why
        assert "Approve or reject it" in rendered and "Decide by" in rendered  # approval: what, by when
        assert "Answer it so the task can continue. The task waits until you answer." in rendered
        assert "Vendor spend (Finished). Review the result. Nothing is due." in rendered
        assert "Close books (Did not finish). Open the task to see why it stopped, then run it again. Nothing is due." in rendered
        assert "deploy stops working in 2 day(s). Replace it before then" in rendered
        for href in ("/approvals#approval-7", "/chat/goal/2#question-panel", "/chat/goal/3", "/chat/goal/4", "/api-keys"):
            assert BASE + href in rendered, href
