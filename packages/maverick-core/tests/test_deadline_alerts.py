"""Deadline alerts: each (record, state, deadline) alerts exactly once, restarts
never re-send, lead times come from config, quiet hours hold non-urgent
alerts, and routing prefers the assignee over the workspace owner."""
from __future__ import annotations

import time
from pathlib import Path

import pytest
from maverick import deadline_alerts as da
from maverick.world_model import WorldModel

DAY = 86_400.0
HOUR = 3_600.0
# A fixed "now" at 10:00 local so due_today / quiet-hour maths is stable.
NOW = time.mktime((2026, 10, 5, 10, 0, 0, 0, 0, -1))


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_PUBLIC_URL", raising=False)
    # A channel exported in the developer's shell must not turn a test into a real send.
    for name in ("MAVERICK_NTFY_TOPIC", "PUSHOVER_USER_KEY", "PUSHOVER_APP_TOKEN",
                 "DISCORD_NOTIFY_WEBHOOK_URL", "SLACK_NOTIFY_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)
    from maverick import config
    config.reset_config_cache()
    # Webhook emission is exercised on its own; keep it out of the alert tests.
    monkeypatch.setattr(da, "_emit_webhook", lambda alert, world: None)


@pytest.fixture
def world(tmp_path: Path):
    return WorldModel(path=tmp_path / "world.db")


def _config(**overrides):
    section = {"enabled": True, "owner": "Dana (privacy owner)"}
    section.update(overrides)
    return {"deadline_alerts": section}


def _deadline(record_type="dsar", record_id="R1", due_in=2 * DAY, assignee="", title="access request from a@b.com"):
    return da.Deadline(record_type, record_id, title, NOW + due_in, "/privacy/dsar/" + record_id, assignee)


def _run(world, deadlines, *, now=NOW, config=None, sent=None):
    sent = [] if sent is None else sent

    def notify(body, **kw):
        sent.append((kw.get("title"), body, kw.get("priority")))
        return 1

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(da, "collect", lambda **kw: list(deadlines))
        summary = da.run_cycle(now=now, world=world, config=config or _config(), notify=notify)
    return summary, sent


def test_due_soon_alert_goes_out_once(world):
    d = _deadline(due_in=2 * DAY - 60)  # inside the 2-day lead
    summary, sent = _run(world, [d])
    assert summary["sent"] == 1 and summary["alerts"][0]["state"] == "due_soon_2d"
    assert len(sent) == 1
    title, body, priority = sent[0]
    assert title.startswith("Due soon:") and "a@b.com" in body and "/privacy/dsar/R1" in body
    assert "For: Dana (privacy owner)" in body and priority == "default"
    # The same cycle again: nothing new.
    summary, sent = _run(world, [d], sent=sent)
    assert summary["sent"] == 0 and summary["already_sent"] == 1 and len(sent) == 1


def test_overdue_alert_goes_out_once_and_is_urgent(world):
    d = _deadline(due_in=-3 * DAY)
    summary, sent = _run(world, [d])
    assert summary["alerts"][0]["state"] == "overdue" and sent[0][2] == "high"
    assert "Overdue" in sent[0][0] and "was due 3 day(s) ago" in sent[0][1]
    summary, sent = _run(world, [d], now=NOW + HOUR, sent=sent)
    assert summary["sent"] == 0 and len(sent) == 1


def test_restart_does_not_resend(world, tmp_path):
    d = _deadline(due_in=DAY)
    _run(world, [d])
    # A fresh process opens the same database: the ledger, not memory, decides.
    again = WorldModel(path=tmp_path / "world.db")
    summary, sent = _run(again, [d])
    assert summary["sent"] == 0 and summary["already_sent"] == 1 and sent == []


def test_each_state_transition_alerts_once(world):
    d = _deadline(due_in=6 * DAY)
    s1, sent = _run(world, [d])                          # 7-day warning
    s2, sent = _run(world, [d], now=NOW + 5 * DAY, sent=sent)   # 2-day warning
    s3, sent = _run(world, [d], now=NOW + 6 * DAY - HOUR, sent=sent)  # due today (same local day)
    s4, sent = _run(world, [d], now=NOW + 7 * DAY, sent=sent)     # overdue
    assert [s["alerts"][0]["state"] for s in (s1, s2, s3, s4)] == [
        "due_soon_7d", "due_soon_2d", "due_today", "overdue"]
    assert len(sent) == 4


def test_extended_deadline_starts_over(world):
    d = _deadline(due_in=DAY)
    _run(world, [d])
    extended = da.Deadline(d.record_type, d.record_id, d.title, d.due_at + 10 * DAY, d.link)
    summary, sent = _run(world, [extended], now=NOW + 9 * DAY)
    assert summary["sent"] == 1 and summary["alerts"][0]["state"] == "due_soon_2d"


def test_lead_times_come_from_config(world):
    d = _deadline(due_in=13 * DAY)
    summary, _ = _run(world, [d])
    assert summary["sent"] == 0  # default leads are 7 and 2 days
    summary, sent = _run(world, [d], config=_config(lead_days={"dsar": [14, 3]}))
    assert summary["alerts"][0]["state"] == "due_soon_14d"


def test_incident_uses_hour_leads_and_ignores_quiet_hours(world):
    inc = da.Deadline("incident", "I1", "lost laptop", NOW + 3 * HOUR, "/privacy#incidents")
    dsar = _deadline(due_in=DAY)
    cfg = _config(quiet_hours="09:00-11:00")  # NOW is 10:00 local
    assert da.in_quiet_hours(NOW, da.settings(cfg))
    summary, sent = _run(world, [inc, dsar], config=cfg)
    assert summary["sent"] == 1 and summary["held_quiet"] == 1
    assert summary["alerts"][0]["state"] == "due_soon_4h" and sent[0][2] == "high"
    # Once quiet hours end the held alert goes out, still exactly once.
    summary, sent = _run(world, [inc, dsar], now=NOW + 2 * HOUR, config=cfg, sent=sent)
    assert summary["sent"] == 1 and summary["alerts"][0]["record_type"] == "dsar"


def test_quiet_hours_window_crossing_midnight():
    cfg = da.settings(_config(quiet_hours="22:00-07:00"))
    at_23 = time.mktime((2026, 10, 5, 23, 30, 0, 0, 0, -1))
    at_06 = time.mktime((2026, 10, 6, 6, 30, 0, 0, 0, -1))
    at_12 = time.mktime((2026, 10, 6, 12, 0, 0, 0, 0, -1))
    assert da.in_quiet_hours(at_23, cfg) and da.in_quiet_hours(at_06, cfg)
    assert not da.in_quiet_hours(at_12, cfg)


def test_assignee_routes_before_owner(world):
    mine = _deadline(record_id="A", due_in=DAY, assignee="Priya")
    nobody = _deadline(record_id="B", due_in=DAY)
    summary, sent = _run(world, [mine, nobody])
    by_id = {a["record_id"]: a for a in summary["alerts"]}
    assert by_id["A"]["recipient"] == "Priya" and by_id["A"]["recipient_kind"] == "assignee"
    assert by_id["B"]["recipient"] == "Dana (privacy owner)" and by_id["B"]["recipient_kind"] == "owner"
    assert any("For: Priya" in body for _t, body, _p in sent)


def test_digest_mode_sends_one_message_per_recipient(world):
    deadlines = [_deadline(record_id="A", due_in=DAY, assignee="Priya"),
                 _deadline(record_id="B", due_in=DAY, assignee="Priya"),
                 _deadline(record_id="C", due_in=-DAY)]
    summary, sent = _run(world, deadlines, config=_config(mode="digest"))
    assert summary["sent"] == 3 and len(sent) == 2
    priya = next(m for m in sent if m[0] == "Deadlines for Priya")
    assert "2 deadline(s)" in priya[1] and priya[1].count("\n- ") == 2
    assert all(row["mode"] == "digest" for row in da.alerts_for("dsar", "A", world=world))


def test_alerts_for_record_and_recent(world):
    _run(world, [_deadline(record_id="Z", due_in=DAY)])
    rows = da.alerts_for("dsar", "Z", world=world)
    assert len(rows) == 1 and rows[0]["state"] == "due_soon_2d" and rows[0]["backends"] == 1
    assert da.recent_alerts(world=world)[0]["record_id"] == "Z"
    assert da.alerts_for("dsar", "other", world=world) == []


def test_disabled_sends_nothing(world):
    summary, sent = _run(world, [_deadline(due_in=-DAY)], config=_config(enabled=False))
    assert summary == {"evaluated": 0, "sent": 0, "held_quiet": 0, "already_sent": 0,
                       "not_sent": 0, "unconfirmed": 0, "backing_off": 0, "alerts": [], "enabled": False} and sent == []


def test_settings_defaults_and_bounds(monkeypatch):
    cfg = da.settings({"deadline_alerts": {"poll_seconds": 5, "mode": "weird",
                                           "lead_days": {"dsar": ["9", "x", "3"]},
                                           "lead_hours": {"incident": [48]}}})
    assert cfg["poll_seconds"] == 60 and cfg["mode"] == "immediate"
    assert cfg["lead_days"]["dsar"] == [9, 3] and cfg["lead_days"]["vendor"] == [30, 7]
    assert cfg["lead_hours"]["incident"] == [48] and cfg["lead_hours"]["approval"] == [24, 4]
    # Enabled follows the privacy register when unset.
    monkeypatch.setattr("maverick.privacy_ops.enabled", lambda: False)
    assert da.settings({})["enabled"] is False


def test_collects_real_dsar_and_incident_deadlines(monkeypatch):
    from maverick import audit, privacy_ops
    monkeypatch.setattr(audit, "record", lambda *a, **k: True)
    from maverick import webhook_events
    monkeypatch.setattr(webhook_events, "emit", lambda *a, **k: 0)
    req = privacy_ops.open_dsar("a@b.com", "access", opened_by="t")
    inc = privacy_ops.open_incident("laptop", severity="high", reported_by="t")
    found = {(d.record_type, d.record_id): d for d in da.collect(now=time.time())}
    assert found[("dsar", req["id"])].due_at == pytest.approx(req["due_at"])
    assert found[("dsar", req["id"])].link == "/privacy/dsar/" + req["id"]
    assert found[("incident", inc["id"])].due_at == pytest.approx(inc["notify_deadline_at"])
    privacy_ops.close_dsar(req["id"], closed_by="t")
    privacy_ops.decide_incident_notification(inc["id"], False, rationale="no personal data", decided_by="t")
    assert not [d for d in da.collect(now=time.time()) if d.record_type in ("dsar", "incident")]


def test_webhook_events_fire_for_due_and_overdue(world, monkeypatch):
    monkeypatch.undo()  # restore the real _emit_webhook
    from maverick import webhook_events
    events = []
    monkeypatch.setattr(webhook_events, "emit", lambda ev, **kw: events.append((ev, kw["payload"]["state"])) or 1)
    monkeypatch.setattr(da, "collect", lambda **kw: [_deadline(record_id="A", due_in=DAY),
                                                     _deadline(record_id="B", due_in=-DAY),
                                                     da.Deadline("approval", "9", "deploy", NOW - 1, "/approvals")])
    da.run_cycle(now=NOW, world=world, config=_config(), notify=lambda *a, **k: 1)
    assert ("dsar.due_soon", "due_soon_2d") in events
    assert ("dsar.overdue", "overdue") in events
    assert ("approval.expired", "overdue") in events


@pytest.mark.parametrize("record_type,action", [
    ("dsar", "Respond to the data request"),
    ("dsar_acknowledgement", "Acknowledge the data request"),
    ("incident", "Decide whether to notify the regulator and the people affected"),
    ("assessment_renewal", "Renew the assessment or retire it"),
    ("assessment_review", "Review the assessment"),
    ("vendor_contract", "Renew the contract or end it"),
    ("approval", "Approve or reject the request"),
])
def test_every_deadline_alert_says_why_what_is_needed_and_by_when(record_type, action):
    """NOT-1: the reason, the action and its due time travel in every alert."""
    assigned = da.Alert(_deadline(record_type=record_type, assignee="Priya"), "due_soon_2d",
                        "Priya", "assignee", False)
    _title, body = da.message_for(assigned, NOW)
    assert f"Needed: {action}." in body
    assert "is due in 2 days" in body
    assert "For: Priya, because this record is assigned to them." in body
    owner = da.Alert(_deadline(record_type=record_type), "due_soon_2d", "Dana (privacy owner)", "owner", False)
    assert ("For: Dana (privacy owner), because no one is assigned to this record."
            in da.message_for(owner, NOW)[1])


def test_approval_deadline_opens_that_approval_card(monkeypatch):
    from maverick import approval_cards

    monkeypatch.setattr(approval_cards, "decode_approval_detail", lambda detail: {"expires_at": NOW + HOUR})
    world = type("World", (), {"pending_approvals": lambda self: [
        type("Approval", (), {"id": 41, "detail": "card", "action": "deploy", "risk": "high"})()]})()
    [deadline] = da._approval_deadlines(NOW, world)
    assert deadline.link.endswith("/approvals#approval-41")


# ---- only an accepted delivery suppresses the next cycle -------------------

def _cycle(world, deadlines, notify, *, now=NOW, mode="immediate"):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(da, "collect", lambda **kw: list(deadlines))
        return da.run_cycle(now=now, world=world, config=_config(mode=mode), notify=notify)


def _real_notify_config(tmp_path, monkeypatch, backend):
    """Route the cycle through the real notification layer with ``backend``."""
    from maverick import config, notifications
    (tmp_path / "config.toml").write_text(
        f'[notifications]\nbackend = "{backend}"\nntfy_topic = "deadlines"\n', encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(notifications, "_load_config",
                        lambda: {"backend": backend, "ntfy_topic": "deadlines", "delivery_receipts": False})
    return notifications


def test_no_notification_backend_keeps_the_alert_due_until_repaired(world, tmp_path, monkeypatch):
    notifications = _real_notify_config(tmp_path, monkeypatch, "none")
    d = _deadline(record_type="incident", record_id="I1", due_in=-HOUR)
    first = _cycle(world, [d], None)
    assert first["sent"] == 0 and first["not_sent"] == 1 and first["alerts"] == []
    assert da.recent_alerts(world=world) == []
    # The next cycle tries again rather than reporting it as already sent.
    second = _cycle(world, [d], None, now=NOW + 900)
    assert second["already_sent"] == 0 and second["not_sent"] == 1
    # Once a backend is configured and accepts, the overdue alert goes out once.
    monkeypatch.setattr(notifications, "_load_config",
                        lambda: {"backend": "ntfy", "ntfy_topic": "deadlines", "delivery_receipts": False})
    posted = []
    monkeypatch.setattr(notifications, "_send_ntfy",
                        lambda title, body, priority, server, topic: posted.append(title) or True)
    third = _cycle(world, [d], None, now=NOW + 1800)
    assert third["sent"] == 1 and len(posted) == 1 and posted[0].startswith("Overdue")
    assert third["alerts"][0]["delivery"] == "accepted" and third["alerts"][0]["backends"] == 1
    fourth = _cycle(world, [d], None, now=NOW + 2700)
    assert fourth["already_sent"] == 1 and fourth["sent"] == 0 and len(posted) == 1


def test_every_backend_refusing_is_retried_and_one_accepting_is_enough(world):
    d = _deadline(record_type="dsar", record_id="D1", due_in=-DAY)
    refused = _cycle(world, [d], lambda body, **kw: 0)
    assert refused["not_sent"] == 1 and refused["sent"] == 0
    assert da.recent_alerts(world=world) == []
    accepted = _cycle(world, [d], lambda body, **kw: 1, now=NOW + 900)
    assert accepted["sent"] == 1 and accepted["alerts"][0]["backends"] == 1
    assert _cycle(world, [d], lambda body, **kw: 1, now=NOW + 1800)["already_sent"] == 1


def test_one_of_several_backends_accepting_records_it_sent(world, tmp_path, monkeypatch):
    notifications = _real_notify_config(tmp_path, monkeypatch, "ntfy")
    monkeypatch.setattr(notifications, "_load_config",
                        lambda: {"backend": "ntfy", "ntfy_topic": "deadlines", "slack_webhook": "",
                                 "delivery_receipts": False})
    monkeypatch.setattr(notifications, "_send_ntfy", lambda *a: True)
    outcome = da.deliver("t", "b", urgent=True, recipient="x", notify=None)
    assert outcome.status == "accepted" and outcome.accepted == 1
    # Several backends: one refuses (no Slack address), one accepts.
    monkeypatch.setattr(notifications, "_dispatch",
                        lambda backend, **kw: backend == "ntfy")
    real = notifications.notify
    monkeypatch.setattr(notifications, "notify",
                        lambda body, **kw: real(body, backends=["slack", "ntfy"], **kw))
    d = _deadline(record_id="M1", due_in=-DAY)
    summary = _cycle(world, [d], None)
    assert summary["sent"] == 1 and summary["alerts"][0]["backends"] == 1


def test_an_uncertain_send_is_recorded_unconfirmed_and_never_replayed(world, tmp_path, monkeypatch):
    notifications = _real_notify_config(tmp_path, monkeypatch, "ntfy")
    attempts = []

    def lost_reply(title, body, priority, server, topic):
        attempts.append(title)
        notifications._network_unknown()  # the service may have received it
        return False
    monkeypatch.setattr(notifications, "_send_ntfy", lost_reply)
    d = _deadline(record_type="incident", record_id="I2", due_in=-HOUR)
    first = _cycle(world, [d], None)
    assert first["unconfirmed"] == 1 and first["sent"] == 0 and len(attempts) == 1
    row = da.recent_alerts(world=world)[0]
    assert row["mode"] == "immediate-unconfirmed" and row["backends"] == 0
    assert first["alerts"][0]["delivery"] == "unconfirmed"
    # Not replayed blindly on the next cycle.
    again = _cycle(world, [d], None, now=NOW + 900)
    assert again["already_sent"] == 1 and len(attempts) == 1


def test_a_sender_failing_mid_send_is_unconfirmed_not_retried(world):
    calls = []

    def broken(body, **kw):
        calls.append(body)
        raise ConnectionError("reset after the request was written")
    d = _deadline(record_id="X1", due_in=-DAY)
    first = _cycle(world, [d], broken)
    assert first["unconfirmed"] == 1 and first["not_sent"] == 0
    assert _cycle(world, [d], broken, now=NOW + 900)["already_sent"] == 1 and len(calls) == 1


def test_digest_mode_retries_a_refused_digest_for_every_alert_in_it(world):
    ds = [_deadline(record_id="G1", due_in=-DAY), _deadline(record_id="G2", due_in=-DAY)]
    refused = _cycle(world, ds, lambda body, **kw: 0, mode="digest")
    assert refused["not_sent"] == 2 and refused["sent"] == 0
    sent = _cycle(world, ds, lambda body, **kw: 1, now=NOW + 900, mode="digest")
    assert sent["sent"] == 2 and {a["record_id"] for a in sent["alerts"]} == {"G1", "G2"}


def test_a_legacy_unsent_row_no_longer_suppresses_the_alert(world):
    """Rows written by the old cycle when nothing accepted are retried once."""
    d = _deadline(record_type="incident", record_id="L1", due_in=-HOUR)
    alert = da.Alert(d, "overdue", "Dana (privacy owner)", "owner", True)
    da._write(world, "INSERT INTO deadline_alerts(id, workspace, record_type, record_id, state, due_at,"
                     " recipient, recipient_kind, title, message, link, sent_at, backends, mode)"
                     " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              ("dla_legacy", da._workspace(), "incident", "L1", "overdue", float(d.due_at),
               alert.recipient, "owner", d.title, "old", d.link, NOW - DAY, 0, "immediate"))
    assert not da.already_sent(world, alert)
    summary = _cycle(world, [d], lambda body, **kw: 1)
    assert summary["sent"] == 1
    rows = da.alerts_for("incident", "L1", world=world)
    assert len(rows) == 1 and rows[0]["backends"] == 1


def test_a_subscribed_webhook_counts_as_delivery(world, monkeypatch):
    monkeypatch.setattr(da, "_emit_webhook", lambda alert, world: 1)
    d = _deadline(record_id="W1", due_in=-DAY)
    summary = _cycle(world, [d], lambda body, **kw: 0)
    assert summary["sent"] == 1 and summary["alerts"][0]["backends"] == 1
    assert _cycle(world, [d], lambda body, **kw: 0, now=NOW + 900)["already_sent"] == 1


def test_email_that_never_reached_the_server_is_retried_not_marked_unconfirmed(world, tmp_path, monkeypatch):
    import smtplib

    from maverick import notifications

    monkeypatch.setattr(notifications, "_load_config", lambda: {
        "backend": "email", "delivery_receipts": False,
        "email": {"host": "smtp.example.test", "from_address": "lw@example.test", "user": "lw",
                  "password": "expired", "tls": "ssl", "to": "ops@example.test"}})  # pragma: allowlist secret

    class Session:
        def __init__(self, login=None, send=None):
            self._login, self._send = login, send

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def login(self, user, password):
            if self._login:
                raise self._login

        def send_message(self, message):
            if self._send:
                raise self._send
            return {}
    d = _deadline(record_type="incident", record_id="I9", due_in=-HOUR)
    monkeypatch.setattr(notifications, "_smtp_session",
                        lambda mail: Session(login=smtplib.SMTPAuthenticationError(535, b"bad credentials")))
    refused = _cycle(world, [d], None)
    assert refused["not_sent"] == 1 and refused["unconfirmed"] == 0 and da.recent_alerts(world=world) == []
    # The password is fixed; the statutory-clock alert goes out.
    monkeypatch.setattr(notifications, "_smtp_session", lambda mail: Session())
    assert _cycle(world, [d], None, now=NOW + 3600)["sent"] == 1
    # A timeout once the message was handed over may have delivered it: never replayed.
    other = _deadline(record_type="incident", record_id="I10", due_in=-HOUR)
    monkeypatch.setattr(notifications, "_smtp_session",
                        lambda mail: Session(send=TimeoutError("no reply after the message body")))
    lost = _cycle(world, [other], None)
    assert lost["unconfirmed"] == 1 and lost["not_sent"] == 0
    assert _cycle(world, [other], None, now=NOW + 3600)["already_sent"] == 1


# ---- a channel that never works cannot flood or block the notification layer

def _receipt_rows():
    from maverick.notification_receipts import DeliveryReceipts

    return DeliveryReceipts()._load()


def _configure_ntfy(tmp_path, monkeypatch, *, accepts):
    """The admin sets an ntfy topic in config.toml; the server accepts or refuses."""
    from maverick import config, notifications

    (tmp_path / "config.toml").write_text('[notifications]\nbackend = "ntfy"\nntfy_topic = "deadlines"\n',
                                          encoding="utf-8")
    config.reset_config_cache()
    posted = []
    monkeypatch.setattr(notifications, "_send_ntfy",
                        lambda title, body, priority, server, topic: posted.append(title) or accepts)
    return posted


def test_400_cycles_with_no_backend_leave_the_delivery_history_alone_then_everything_goes_out(
        world, tmp_path, monkeypatch):
    from maverick import notifications

    # A default install: no [notifications] section (ntfy without a topic), receipts on, 3 overdue records.
    deadlines = [_deadline(record_id=f"D{i}", due_in=-DAY) for i in range(3)]
    for i in range(400):  # about 4 days of 15-minute cycles
        assert _cycle(world, deadlines, None, now=NOW + 900 * i)["sent"] == 0
    assert _receipt_rows() == []
    assert da.recent_alerts(world=world) == []
    # The admin configures a working topic: an unrelated notification and all three alerts go out.
    posted = _configure_ntfy(tmp_path, monkeypatch, accepts=True)
    assert notifications.notify("hello", async_dispatch=False, batch=False) == 1
    recovered = _cycle(world, deadlines, None, now=NOW + 900 * 400)
    assert recovered["sent"] == 3 and recovered["not_sent"] == 0 and len(posted) == 4
    assert len(_receipt_rows()) == 4
    assert _cycle(world, deadlines, None, now=NOW + 900 * 401)["already_sent"] == 3


def test_a_channel_that_refuses_is_retried_with_a_growing_wait_and_a_bounded_history(world, tmp_path, monkeypatch):
    from maverick import notifications

    posted = _configure_ntfy(tmp_path, monkeypatch, accepts=False)
    deadlines = [_deadline(record_id=f"D{i}", due_in=-DAY) for i in range(3)]
    for i in range(400):
        _cycle(world, deadlines, None, now=NOW + 900 * i)
    # 5, 10, 20, 40 minutes, then hourly: about 100 attempts per alert, not 400.
    assert 3 * 90 <= len(posted) <= 3 * 110
    assert len(_receipt_rows()) == len(posted) < 400
    # The topic is fixed later that day: other notifications were never blocked, and the alerts follow.
    monkeypatch.setattr(notifications, "_send_ntfy", lambda *a: True)
    assert notifications.notify("hello", async_dispatch=False, batch=False) == 1
    assert _cycle(world, deadlines, None, now=NOW + 900 * 400 + 3600)["sent"] == 3


def test_definite_failures_back_off_5_10_20_40_60_minutes_then_hourly(world):
    d = _deadline(record_id="B1", due_in=-DAY)
    attempts = [m for m in range(0, 256, 5)
                if _cycle(world, [d], lambda body, **kw: 0, now=NOW + 60 * m)["not_sent"]]
    assert attempts == [0, 5, 15, 35, 75, 135, 195, 255]
    waiting = _cycle(world, [d], lambda body, **kw: 0, now=NOW + 60 * 260)
    assert waiting["backing_off"] == 1 and waiting["not_sent"] == 0 and waiting["already_sent"] == 0


def test_overlapping_cycles_send_each_alert_once(world, monkeypatch):
    """The scheduler and a manual "run now" can overlap: neither may send an
    alert the other is sending, or fail on the ledger row the other wrote."""
    import threading

    monkeypatch.setattr(da, "collect", lambda **kw: [_deadline(record_id="R1", due_in=DAY),
                                                      _deadline(record_id="R2", due_in=DAY)])
    sent, outcomes, errors = [], [], []
    start = threading.Barrier(2)

    def notify(body, **kw):
        time.sleep(0.15)
        sent.append(kw.get("title"))
        return 1

    def cycle():
        try:
            start.wait(10)
            outcomes.append(da.run_cycle(now=NOW, world=world, config=_config(), notify=notify))
        except Exception as exc:  # noqa: BLE001 -- the test reports it
            errors.append(exc)

    threads = [threading.Thread(target=cycle) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert errors == []
    assert len(sent) == 2
    assert sum(o["sent"] for o in outcomes) == 2 and sum(o["already_sent"] for o in outcomes) == 2


def test_a_wait_recorded_by_a_wrong_clock_does_not_hold_back_the_retry(world):
    d = _deadline(record_id="C1", due_in=-DAY)
    year = 365 * DAY
    assert _cycle(world, [d], lambda body, **kw: 0, now=NOW + year)["not_sent"] == 1  # clock a year ahead
    # The clock is corrected and the channel works: the alert goes out now, not in a year.
    fixed = _cycle(world, [d], lambda body, **kw: 1, now=NOW + 60)
    assert fixed["sent"] == 1 and fixed["backing_off"] == 0


def test_changing_the_notification_setup_ends_the_wait_at_once(world, tmp_path):
    d = _deadline(record_id="B2", due_in=-DAY)
    for m in (0, 5, 15, 35):
        assert _cycle(world, [d], lambda body, **kw: 0, now=NOW + 60 * m)["not_sent"] == 1
    assert _cycle(world, [d], lambda body, **kw: 0, now=NOW + 60 * 40)["backing_off"] == 1  # next try at 75
    (tmp_path / "config.toml").write_text('[notifications]\nbackend = "ntfy"\nntfy_topic = "fixed"\n',
                                          encoding="utf-8")
    from maverick import config
    config.reset_config_cache()
    sent = _cycle(world, [d], lambda body, **kw: 1, now=NOW + 60 * 45)
    assert sent["sent"] == 1 and sent["backing_off"] == 0


def test_a_recovered_alert_leaves_no_retry_state_and_an_unconfirmed_one_is_not_retried(world, tmp_path):
    import json

    path = tmp_path / "deadline-alert-retries.json"
    d = _deadline(record_id="B3", due_in=-DAY)
    assert _cycle(world, [d], lambda body, **kw: 0)["not_sent"] == 1
    entries = json.loads(path.read_text(encoding="utf-8"))
    assert len(entries) == 1 and "B3" not in path.read_text(encoding="utf-8")  # hashed, no record ids
    assert _cycle(world, [d], lambda body, **kw: 1, now=NOW + 600)["sent"] == 1
    assert json.loads(path.read_text(encoding="utf-8")) == {}
    lost = _deadline(record_id="B4", due_in=-DAY)

    def broken(body, **kw):
        raise ConnectionError("reset after the request was written")
    assert _cycle(world, [lost], lambda body, **kw: 0)["not_sent"] == 1
    assert _cycle(world, [lost], broken, now=NOW + 600)["unconfirmed"] == 1
    assert json.loads(path.read_text(encoding="utf-8")) == {}
    assert _cycle(world, [lost], lambda body, **kw: 1, now=NOW + 7200)["already_sent"] == 1


def test_no_destination_means_no_attempt_and_no_receipt(world, monkeypatch):
    from maverick import notifications

    monkeypatch.setattr(notifications, "notify", lambda *a, **kw: pytest.fail("nothing is set up to receive it"))
    outcome = da.deliver("t", "b", urgent=True, recipient="x", notify=None)
    assert outcome.status == "not_sent" and _receipt_rows() == []


def test_the_retry_store_prunes_old_entries_and_stays_bounded(world, tmp_path, monkeypatch):
    import json

    path = tmp_path / "deadline-alert-retries.json"
    path.write_text(json.dumps({"old": {"failures": 3, "next_at": 1.0, "setup": "x", "at": NOW - 40 * DAY}}),
                    encoding="utf-8")
    assert _cycle(world, [_deadline(record_id="B5", due_in=-DAY)], lambda body, **kw: 0)["not_sent"] == 1
    entries = json.loads(path.read_text(encoding="utf-8"))
    assert "old" not in entries and len(entries) == 1
    monkeypatch.setattr(da, "_RETRY_MAX_ENTRIES", 2)
    ds = [_deadline(record_id=f"C{i}", due_in=-DAY) for i in range(4)]
    _cycle(world, ds, lambda body, **kw: 0, now=NOW + 3600)
    assert len(json.loads(path.read_text(encoding="utf-8"))) == 2


# ---- the cycle survives one bad record, one bad write, one bad lock -------------

def test_one_malformed_record_does_not_hide_the_rest_of_its_source(monkeypatch):
    from maverick import privacy_ops
    monkeypatch.setattr(privacy_ops, "enabled", lambda: True)
    monkeypatch.setattr(privacy_ops, "list_dsars", lambda: [
        {"id": "bad", "status": "open", "due_at": "2026-11-01", "kind": "access", "subject_id": "x"},
        {"id": "nan", "status": "open", "due_at": float("nan"), "kind": "access", "subject_id": "x"},
        {"id": "good", "status": "open", "due_at": NOW + DAY, "kind": "access", "subject_id": "y"},
    ])
    assert [d.record_id for d in da._dsar_deadlines(NOW)] == ["good"]
    monkeypatch.setattr(privacy_ops, "list_incidents", lambda: [
        {"id": "i1", "status": "open", "notify_deadline_at": "soon"},
        {"id": "i2", "status": "open", "notify_deadline_at": NOW + HOUR, "title": "breach"},
    ])
    assert [d.record_id for d in da._incident_deadlines(NOW)] == ["i2"]


def test_malformed_assessments_and_vendor_contracts_are_skipped_individually(monkeypatch):
    from maverick import assessment
    from maverick import vendor_management as vm
    monkeypatch.setattr(assessment, "list_saved", lambda: [
        {"id": "a1", "renewal_at": "never", "status": "approved", "next_review_at": NOW + DAY},
        {"id": "a2", "renewal_at": NOW + DAY, "status": "approved"},
    ])
    found = {(d.record_type, d.record_id) for d in da._assessment_deadlines(NOW)}
    assert found == {("assessment_review", "a1"), ("assessment_renewal", "a2")}
    monkeypatch.setattr(vm, "enabled", lambda: True)
    monkeypatch.setattr(vm, "list_vendors", lambda: [
        {"id": "v1", "name": "Acme", "contracts": ["not-a-dict", {"kind": "dpa", "renews_at": "x"},
                                                   {"kind": "msa", "renews_at": NOW + DAY}]}])
    assert [d.record_id for d in da._vendor_deadlines(NOW)] == ["v1:msa"]


def test_an_alert_that_cannot_be_recorded_does_not_stop_the_others(world, monkeypatch):
    real = da._record_sent

    def flaky(world_, alert, *args, **kwargs):
        if alert.deadline.record_id == "R1":
            raise RuntimeError("database is locked")
        return real(world_, alert, *args, **kwargs)

    monkeypatch.setattr(da, "_record_sent", flaky)
    first, second = _deadline(record_id="R1", due_in=DAY), _deadline(record_id="R2", due_in=DAY)
    summary, sent = _run(world, [first, second])
    assert len(sent) == 2                                      # both went out
    assert [a["record_id"] for a in summary["alerts"]] == ["R2"]   # the second is on record
    assert summary["unconfirmed"] == 1
    monkeypatch.setattr(da, "_record_sent", real)
    again, sent = _run(world, [first, second], sent=sent)
    # The unrecorded alert went out: the next cycle writes its ledger row and
    # never sends it again (an uncertain send is never replayed).
    assert len(sent) == 2
    assert [a["record_id"] for a in again["alerts"]] == ["R1"] and again["already_sent"] == 2
    third, sent = _run(world, [first, second], sent=sent)
    assert len(sent) == 2 and third["already_sent"] == 2


def test_an_alert_whose_ledger_stays_unwritable_is_never_resent(world, monkeypatch):
    def locked(*_args, **_kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(da, "_record_sent", locked)
    alert = _deadline(record_id="L1", due_in=DAY)
    summary, sent = _run(world, [alert])
    assert len(sent) == 1 and summary["unconfirmed"] == 1
    for hours in (1, 2, 6, 12):  # past every retry back-off, still the same "due soon" alert
        later, sent = _run(world, [alert], sent=sent, now=NOW + hours * 3600)
        assert len(sent) == 1 and later["unconfirmed"] == 1


def test_a_lock_that_cannot_be_taken_does_not_stop_alerts(world, monkeypatch):
    import contextlib

    from maverick import file_lock

    @contextlib.contextmanager
    def refusing(path, **kwargs):
        raise OSError("lock directory is read-only")
        yield

    monkeypatch.setattr(file_lock, "cross_process_lock", refusing)
    summary, sent = _run(world, [_deadline(due_in=DAY)])
    assert summary["sent"] == 1 and len(sent) == 1


def test_a_failure_inside_the_cycle_is_not_hidden_by_the_lock_fallback(world, monkeypatch):
    monkeypatch.setattr(da, "evaluate", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="boom"):
        _run(world, [_deadline(due_in=DAY)])


def test_a_big_digest_is_sent_in_parts_each_small_enough_for_the_smallest_backend(world):
    deadlines = [_deadline(record_id=f"R{i}", due_in=DAY, title="access request " + "x" * 120) for i in range(12)]
    summary, sent = _run(world, deadlines, config=_config(mode="digest"))
    assert len(sent) > 1
    assert all(len(body) <= da._DIGEST_LIMIT + 400 for _, body, _ in sent)     # one long line may overshoot, once
    assert all(len(body) <= 1024 for _, body, _ in sent)
    assert sent[0][0] == f"Deadlines for Dana (privacy owner) (1/{len(sent)})"
    assert summary["sent"] == 12 and len(summary["alerts"]) == 12              # every alert is on record once
    assert sum(body.count("\n- ") for _, body, _ in sent) == 12


def test_a_small_digest_keeps_its_single_message_and_plain_title(world):
    summary, sent = _run(world, [_deadline(record_id="A", due_in=DAY), _deadline(record_id="B", due_in=DAY)],
                         config=_config(mode="digest"))
    assert len(sent) == 1 and sent[0][0] == "Deadlines for Dana (privacy owner)"


def test_a_deadline_two_calendar_days_away_is_not_called_tomorrow():
    monday_23 = time.mktime((2026, 10, 5, 23, 0, 0, 0, 0, -1))
    wednesday_04 = time.mktime((2026, 10, 7, 4, 0, 0, 0, 0, -1))          # 29 hours later
    assert "is due in 2 days" in da._when(wednesday_04, monday_23, time.localtime)
    tuesday_22 = time.mktime((2026, 10, 6, 22, 0, 0, 0, 0, -1))           # 23 hours later
    assert da._when(tuesday_22, monday_23, time.localtime).startswith("is due in 23 hour")
    tuesday_23_30 = monday_23 + 24.5 * HOUR
    assert da._when(tuesday_23_30, monday_23, time.localtime).startswith("is due tomorrow")


def test_a_world_opened_for_a_read_is_closed_again(monkeypatch, tmp_path):
    from maverick import world_model
    opened = []

    class Tracked(WorldModel):
        def close(self):
            opened.append("closed")
            super().close()

    monkeypatch.setattr(world_model, "open_world", lambda *a, **k: Tracked(path=tmp_path / "w.db"))
    assert da.recent_alerts() == []
    assert da.alerts_for("dsar", "R1") == []
    assert opened == ["closed", "closed"]


def test_the_ledger_reads_back_on_postgres(postgres_test_dsn):
    # PostgresWorldModel has no _read_all: the "already sent" check and the
    # record page's alert list must read through a cursor there.
    from maverick.world_model_backends.postgres import PostgresWorldModel

    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        d = _deadline(record_id="PG1", due_in=2 * DAY - 60)
        summary, sent = _run(world, [d])
        assert summary["sent"] == 1 and len(sent) == 1
        summary, sent = _run(world, [d], sent=sent)
        assert summary["sent"] == 0 and summary["already_sent"] == 1 and len(sent) == 1
        rows = da.alerts_for("dsar", "PG1", world=world)
        assert len(rows) == 1 and rows[0]["state"] == "due_soon_2d" and rows[0]["backends"] == 1
        assert da.recent_alerts(world=world)[0]["record_id"] == "PG1"
