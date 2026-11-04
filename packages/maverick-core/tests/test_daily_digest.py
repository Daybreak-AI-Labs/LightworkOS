"""The daily summary: composition per person, time zones, empty-skip, opt-out,
send audit and the sender hook."""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DAILY_DIGEST", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture
def recorded(monkeypatch):
    import maverick.audit as audit

    rows: list[tuple[str, dict]] = []
    monkeypatch.setattr(audit, "record", lambda kind, **p: rows.append((kind, p)) or True)
    return rows


def _world(tmp_path):
    from maverick.world_model import WorldModel

    return WorldModel(tmp_path / "world.db")


def _seed(world):
    """Alice owns a finished goal with a question and spend; Bob owns another."""
    mine = world.create_goal("Weekly forecast", owner="user:alice")
    theirs = world.create_goal("Bob's audit", owner="user:bob")
    for goal in (mine, theirs):
        world.set_goal_status(goal, "done", result="All good.")
    ep = world.start_episode(mine)
    world.end_episode(ep, summary="s", outcome="ok", cost_dollars=1.25, input_tokens=10)
    world.ask("Which quarter?", goal_id=mine)
    world.ask("Which vendor?", goal_id=theirs)
    approved_by_me = world.create_approval("wire_funds", risk="high", detail="d",
                                          requested_by="user:alice")
    other = world.create_approval("delete_files", risk="medium", detail="d",
                                  requested_by="user:bob")
    return {"mine": mine, "theirs": theirs, "requested": approved_by_me, "other": other}


def test_compose_for_a_person_who_may_decide(tmp_path):
    from maverick.daily_digest import compose_digest

    world = _world(tmp_path)
    ids = _seed(world)
    digest = compose_digest(world, "user:alice", can_decide=True)
    assert [a["id"] for a in digest["approvals"]] == [ids["requested"], ids["other"]]
    assert [a["waiting_on"] for a in digest["approvals"]] == ["someone else", "you"]
    assert [r["id"] for r in digest["results"]] == [ids["mine"]]
    assert [q["question"] for q in digest["questions"]] == ["Which quarter?"]
    assert digest["spending"]["dollars"] == pytest.approx(1.25)
    assert digest["counts"] == {"approvals": 2, "results": 1, "questions": 1, "expiring_keys": 0}
    assert digest["empty"] is False


def test_compose_for_a_viewer_and_an_administrator(tmp_path):
    from maverick.daily_digest import compose_digest

    world = _world(tmp_path)
    ids = _seed(world)
    viewer = compose_digest(world, "user:alice", can_decide=False)
    assert [a["id"] for a in viewer["approvals"]] == [ids["requested"]]
    assert viewer["approvals"][0]["waiting_on"] == "someone else"
    admin = compose_digest(world, "user:root", can_decide=True, sees_everything=True)
    assert {r["id"] for r in admin["results"]} == {ids["mine"], ids["theirs"]}
    assert len(admin["questions"]) == 2
    nobody = compose_digest(world, "user:carol", can_decide=False)
    assert nobody["empty"] is True


def test_spending_this_month_follows_the_persons_time_zone(tmp_path):
    from maverick.daily_digest import compose_digest, month_start

    world = _world(tmp_path)
    goal = world.create_goal("Old", owner="user:alice")
    world.set_goal_status(goal, "done")
    # 1 Oct 2026 00:30 in Auckland is still 30 Sep in UTC.
    now = datetime(2026, 9, 30, 12, 30, tzinfo=timezone.utc).timestamp()
    old = world.start_episode(goal)
    world.end_episode(old, summary="s", outcome="ok", cost_dollars=3.0)
    with world._writing() as conn:  # backdate the run to 30 Sep 10:00 UTC
        conn.execute("UPDATE episodes SET started_at = ? WHERE id = ?",
                     (datetime(2026, 9, 30, 10, tzinfo=timezone.utc).timestamp(), old))
    utc = compose_digest(world, "user:alice", can_decide=False, now=now, time_zone="UTC",
                         spend_limit=2.0)
    assert utc["spending"]["dollars"] == pytest.approx(3.0) and utc["spending"]["over_limit"]
    nz = compose_digest(world, "user:alice", can_decide=False, now=now,
                        time_zone="Pacific/Auckland", spend_limit=2.0)
    assert nz["spending"]["dollars"] == 0 and nz["spending"]["month_label"] == "October 2026"
    assert datetime.fromtimestamp(month_start(now, "Pacific/Auckland"),
                                  tz=ZoneInfo("Pacific/Auckland")).day == 1


def test_spend_limit_comes_from_config(tmp_path):
    from maverick.config import get_my_work
    from maverick.daily_digest import compose_digest

    (tmp_path / "config.toml").write_text(
        "[my_work]\ndigest_enable = true\ndigest_hour = 7\nmonthly_spend_limit_dollars = 42\n")
    section = get_my_work()
    assert section["digest_enable"] is True and section["digest_hour"] == 7
    assert section["digest_poll_seconds"] == 300
    digest = compose_digest(_world(tmp_path), "user:a", can_decide=False)
    assert digest["spending"]["limit_dollars"] == 42


def test_render_text_and_html(tmp_path):
    from maverick.daily_digest import compose_digest, render_html, render_text

    world = _world(tmp_path)
    _seed(world)
    world.ask("<b>Which</b> quarter?", goal_id=world.create_goal("X", owner="user:alice"))
    digest = compose_digest(world, "user:alice", can_decide=True, spend_limit=10)
    text = render_text(digest, dashboard_url="https://lw.test/")
    assert "waiting for your decision" in text and "https://lw.test/me" in text
    assert "$1.25 of your $10.00 monthly limit" in text
    html = render_html(digest, dashboard_url="https://lw.test/")
    assert "&lt;b&gt;Which&lt;/b&gt;" in html and "<b>Which</b>" not in html
    empty = compose_digest(world, "user:nobody", can_decide=False)
    assert "Nothing is waiting" in render_text(empty)


def test_due_now_respects_hour_time_zone_and_opt_out():
    from maverick.daily_digest import due_now

    # 07:30 UTC = 08:30 in Berlin (CEST): due in Berlin, not yet in Reykjavik (UTC).
    now = datetime(2026, 7, 1, 7, 30, tzinfo=timezone.utc).timestamp()
    berlin = {"time_zone": "Europe/Berlin", "digest_hour": 8, "digest_enabled": True}
    london = {"time_zone": "Atlantic/Reykjavik", "digest_hour": 8, "digest_enabled": True}
    assert due_now(berlin, now=now) == (True, "2026-07-01")
    assert due_now(london, now=now) == (False, "2026-07-01")
    assert due_now({**berlin, "last_digest_date": "2026-07-01"}, now=now)[0] is False
    assert due_now({**berlin, "digest_enabled": False}, now=now)[0] is False
    late = datetime(2026, 7, 1, 20, 0, tzinfo=timezone.utc).timestamp()
    assert due_now(berlin, now=late)[0] is True  # a paused scheduler still sends today


def test_run_cycle_sends_once_skips_empty_and_audits(tmp_path, recorded, monkeypatch):
    from maverick import channel_identities, daily_digest, user_preferences

    world = _world(tmp_path)
    _seed(world)
    sent = []
    daily_digest.register_digest_sender("teams", lambda p, d, links, prefs: sent.append(("teams", p, d["counts"])) or True)
    monkeypatch.setattr(daily_digest, "_send_slack",
                        lambda p, d, links, prefs: sent.append(("slack", p, d["counts"])) or True)
    try:
        channel_identities.link("slack", "U1", "user:alice", actor="admin")
        channel_identities.link("teams", "T-1", "user:alice", actor="admin")
        channel_identities.link("slack", "U2", "user:carol", actor="admin")  # nothing waiting
        user_preferences.set_preferences("user:dave", digest_enabled=False)
        now = datetime(2026, 7, 1, 9, 0, tzinfo=timezone.utc).timestamp()
        people = ["user:alice", "user:carol", "user:dave", "user:erin"]
        summary = daily_digest.run_digest_cycle(
            world, principals=people, can_decide=lambda p: p == "user:alice", now=now)
        assert summary == {"checked": 4, "sent": 1, "skipped_empty": 1,
                           "skipped_unlinked": 1, "failed": 0, "unconfirmed": 0, "backing_off": 0}
        assert sorted(s[0] for s in sent) == ["slack", "teams"]
        assert all(s[1] == "user:alice" for s in sent)
        notes = [p for k, p in recorded if k == "digest_sent"]
        assert {n["channel"] for n in notes} == {"slack", "teams"}
        assert all(n["recipient"] == "user:alice" and n["ok"] and n["approvals"] == 2 for n in notes)
        assert not any("wire" in str(n).lower() for n in notes)  # no content in the audit
        again = daily_digest.run_digest_cycle(
            world, principals=people, can_decide=lambda p: True, now=now + 60)
        assert again["sent"] == 0 and len(sent) == 2  # once a day
        user_preferences.set_preferences("user:carol", send_when_empty=True)
        user_preferences.mark_digest_sent("user:carol", "")
        third = daily_digest.run_digest_cycle(
            world, principals=["user:carol"], can_decide=lambda p: False, now=now + 120)
        assert third["sent"] == 1 and sent[-1][1] == "user:carol"
    finally:
        daily_digest.register_digest_sender("teams", None)


def test_email_digest_uses_linked_address_or_profile_email(tmp_path, recorded, monkeypatch):
    from maverick import daily_digest, notifications, user_preferences

    world = _world(tmp_path)
    _seed(world)
    mails = []
    monkeypatch.setattr(notifications, "send_email",
                        lambda to, subject, text, html_body=None, cfg=None: mails.append((to, subject, html_body is not None)) or True)
    user_preferences.set_preferences("user:alice", email="alice@example.com")
    prefs = user_preferences.get_preferences("user:alice")
    digest = daily_digest.compose_digest(world, "user:alice", can_decide=True)
    outcomes = daily_digest.send_digest("user:alice", digest, links=[], prefs=prefs)
    assert outcomes == [{"channel": "email", "ok": True, "delivery": "accepted"}]
    assert mails[0][0] == "alice@example.com" and mails[0][2] is True
    assert "summary" in mails[0][1].lower()
    outcomes = daily_digest.send_digest(
        "user:alice", digest, links=[{"channel": "email", "external_id": "work@example.com"}],
        prefs={"email": ""})
    assert mails[-1][0] == "work@example.com" and outcomes[0]["ok"]


def test_slack_digest_sends_a_dm_with_blocks(tmp_path, monkeypatch):
    from maverick import daily_digest, slack_interactive

    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-not-a-real-token")
    dms = []
    monkeypatch.setattr(slack_interactive, "send_dm",
                        lambda token, user, text, blocks=None: dms.append((token, user, blocks)) or True)
    digest = daily_digest.compose_digest(_world(tmp_path), "user:a", can_decide=False)
    ok = daily_digest._send_slack("user:a", digest, [{"channel": "slack", "external_id": "U7"}], {})
    assert ok and dms[0][1] == "U7" and dms[0][2][0]["type"] == "header"
    monkeypatch.delenv("SLACK_BOT_TOKEN")
    assert daily_digest._send_slack("user:a", digest, [{"channel": "slack", "external_id": "U7"}], {}) is False


def test_expiring_access_keys_section_is_optional(tmp_path, monkeypatch):
    import sys
    import types

    from maverick import daily_digest
    from maverick.slack_interactive import digest_blocks

    world = _world(tmp_path)
    now = 1_800_000_000.0
    assert daily_digest.compose_digest(world, "user:a", can_decide=False, now=now)["expiring_keys"] == []

    class Key:
        def __init__(self, label, owner, days):
            self.id, self.label, self.owner, self.prefix = label, label, owner, "lw_" + label[:3]
            self.expires_at = now + days * 86400

        def usable(self, at):
            return at < self.expires_at

    keys = [Key("deploy", "user:a", 2), Key("later", "user:a", 20), Key("bobs", "user:b", 1)]
    fake = types.ModuleType("maverick_dashboard.api_keys")
    fake.list_keys = lambda owner=None: [k for k in keys if owner is None or k.owner == owner]
    fake.expiring_soon = lambda rows, within_days=7, now=None: [
        k for k in rows if k.usable(now) and k.expires_at <= now + within_days * 86400]
    monkeypatch.setitem(sys.modules, "maverick_dashboard.api_keys", fake)
    mine = daily_digest.compose_digest(world, "user:a", can_decide=False, now=now)
    assert [k["label"] for k in mine["expiring_keys"]] == ["deploy"]
    assert mine["expiring_keys"][0]["days_left"] == 2 and mine["counts"]["expiring_keys"] == 1
    assert mine["empty"] is False
    everyone = daily_digest.compose_digest(world, "user:root", can_decide=True,
                                           sees_everything=True, now=now)
    assert [k["label"] for k in everyone["expiring_keys"]] == ["bobs", "deploy"]
    text = daily_digest.render_text(mine)
    # NOT-1: each line also says what to do and by when.
    assert "access key(s) stop working within 7 days" in text
    assert "deploy stops working in 2 day(s). Replace it before then" in text
    assert "deploy" in daily_digest.render_html(mine)
    assert "stop working within 7 days" in digest_blocks(mine)[1]["text"]["text"]
    fake.list_keys = lambda owner=None: (_ for _ in ()).throw(RuntimeError("store down"))
    assert daily_digest.compose_digest(world, "user:a", can_decide=False, now=now)["expiring_keys"] == []


def test_expiring_access_keys_come_from_the_real_api_keys_module(tmp_path, monkeypatch):
    """With the dashboard installed the guarded import resolves to
    ``maverick_dashboard.api_keys.expiring_soon`` (no fake module needed)."""
    import importlib

    from maverick import daily_digest

    api_keys = importlib.import_module("maverick_dashboard.api_keys")
    assert callable(api_keys.expiring_soon) and callable(api_keys.list_keys)
    calls = []

    def expiring_soon(keys, *, within_days=7, now=None):
        calls.append((list(keys), within_days))
        return []

    monkeypatch.setattr(api_keys, "expiring_soon", expiring_soon)
    monkeypatch.setattr(api_keys, "list_keys", lambda owner=None: [])
    now = 1_800_000_000.0
    world = _world(tmp_path)
    assert daily_digest.compose_digest(world, "user:a", can_decide=False, now=now)["expiring_keys"] == []
    assert calls == [([], daily_digest.KEY_EXPIRY_DAYS)]


def _rendered_digest():
    """A summary with one of each item, in a fixed time zone."""
    return {
        "date_label": "Sunday 04 October 2026", "time_zone": "Europe/London", "empty": False,
        "approvals": [
            {"id": 12, "action": "Run a shell command", "risk_label": "High risk",
             "decide_by": 1791147900.0, "waiting_on": "you"},
            {"id": 13, "action": "Delete old drafts", "risk_label": "Medium risk",
             "decide_by": None, "waiting_on": "someone else"},
        ],
        "questions": [{"id": 7, "goal_id": 5, "goal_title": "Forecast", "question": "Which quarter?",
                       "asked_at": 1791140000.0, "href": "/chat/goal/5"}],
        "results": [{"id": 9, "title": "Board pack", "status": "done", "status_label": "Finished",
                     "summary": "PRIVATE RESULT TEXT", "href": "/chat/goal/9"}],
        "expiring_keys": [],
        "spending": {"dollars": 1.5, "limit_dollars": 10, "over_limit": False},
        "counts": {"approvals": 2, "questions": 1, "results": 1, "expiring_keys": 0},
    }


def test_summary_says_why_what_and_by_when_and_links_each_item():
    """NOT-1 for email and Slack: a reason, the action and its due time, and an
    exact link per item; never the result text."""
    from maverick.daily_digest import render_html, render_text
    from maverick.slack_interactive import digest_blocks

    digest = _rendered_digest()
    text = render_text(digest, dashboard_url="https://lw.test/")
    assert "You get this because you turned on the daily summary in My work." in text
    assert "Decide by Sun 04 Oct 2026, 22:05 (Europe/London)" in text
    assert "https://lw.test/approvals#approval-12" in text
    assert "Waiting on someone else's decision" in text and "No expiry is set" in text
    assert "The task waits until you answer" in text
    assert "https://lw.test/chat/goal/5#question-panel" in text
    assert "https://lw.test/chat/goal/9" in text
    assert "Change or stop this summary: https://lw.test/me#daily-summary" in text
    html = render_html(digest, dashboard_url="https://lw.test/")
    assert 'href="https://lw.test/approvals#approval-12"' in html
    assert "Decide by Sun 04 Oct 2026, 22:05 (Europe/London)" in html
    assert "You get this because you turned on the daily summary in My work." in html
    blocks = digest_blocks(digest, dashboard_url="https://lw.test")
    joined = " ".join(str(block) for block in blocks)
    assert "<https://lw.test/approvals#approval-12|Open 1>" in joined
    assert "Decide by Sun 04 Oct 2026, 22:05 (Europe/London)" in joined
    assert "You get this because you turned on the daily summary in My work." in joined
    for rendered in (text, html, joined):
        assert "PRIVATE RESULT TEXT" not in rendered


def test_results_already_seen_in_the_app_are_left_out_of_the_summary(tmp_path, monkeypatch):
    from maverick import daily_digest
    from maverick import personal_notifications as alerts

    world = _world(tmp_path)
    ids = _seed(world)
    everything = daily_digest.compose_digest(world, "user:alice", can_decide=True)
    assert [row["id"] for row in everything["results"]] == [ids["mine"]]
    trimmed = daily_digest.compose_digest(world, "user:alice", can_decide=True,
                                          seen_goal_ids={ids["mine"]})
    assert trimmed["results"] == [] and trimmed["left_out_seen"] == 1
    # The questions it still waits on stay: they need an answer, seen or not.
    assert trimmed["questions"] == everything["questions"]
    monkeypatch.setattr(alerts.PersonalInbox, "seen_goal_ids", lambda self: {ids["mine"]})
    prepared = daily_digest.prepare_digest(world, "user:alice", can_decide=True,
                                           prefs={"time_zone": "UTC"})
    assert prepared["results"] == [] and prepared["left_out_seen"] == 1


# ---- the day counts as done only once a channel accepted the summary ------

NOON = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc).timestamp()


def _cycle(world, now):
    from maverick import daily_digest

    return daily_digest.run_digest_cycle(world, principals=["user:alice"], can_decide=lambda p: True, now=now)


def _last_sent():
    from maverick import user_preferences

    return user_preferences.get_preferences("user:alice").get("last_digest_date")


def _deliveries(recorded):
    return [(n["channel"], n["delivery"]) for k, n in recorded if k == "digest_sent"]


def test_no_working_channel_is_retried_until_the_channel_is_set_up(tmp_path, recorded, monkeypatch):
    from maverick import channel_identities, slack_interactive

    world = _world(tmp_path)
    _seed(world)
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    channel_identities.link("slack", "U1", "user:alice", actor="admin")
    first = _cycle(world, NOON)
    assert first["failed"] == 1 and first["sent"] == 0 and _last_sent() == ""
    assert _deliveries(recorded) == [("slack", "not_sent")]
    assert _cycle(world, NOON + 300)["failed"] == 1 and _last_sent() == ""
    # The Slack app gets connected: the next poll still delivers today's summary, once.
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-not-a-real-token")
    dms = []
    monkeypatch.setattr(slack_interactive, "send_dm",
                        lambda token, user, text, blocks=None: dms.append(user) or True)
    fixed = _cycle(world, NOON + 600)
    assert fixed["sent"] == 1 and fixed["failed"] == 0 and dms == ["U1"]
    assert _last_sent() == "2026-07-01"
    assert _cycle(world, NOON + 900)["sent"] == 0 and dms == ["U1"]


def test_every_channel_refusing_keeps_the_day_open_and_one_accepting_closes_it(tmp_path, recorded, monkeypatch):
    from maverick import channel_identities, daily_digest

    world = _world(tmp_path)
    _seed(world)
    answers = {"slack": False, "teams": False}
    tried = []

    def sender(channel):
        return lambda p, d, links, prefs: tried.append(channel) or answers[channel]
    monkeypatch.setattr(daily_digest, "_send_slack", sender("slack"))
    daily_digest.register_digest_sender("teams", sender("teams"))
    try:
        channel_identities.link("slack", "U1", "user:alice", actor="admin")
        channel_identities.link("teams", "T-1", "user:alice", actor="admin")
        refused = _cycle(world, NOON)
        assert refused["failed"] == 1 and sorted(tried) == ["slack", "teams"] and _last_sent() == ""
        assert {d for _, d in _deliveries(recorded)} == {"not_sent"}
        answers["teams"] = True
        one = _cycle(world, NOON + 300)
        assert one["sent"] == 1 and one["failed"] == 0 and len(tried) == 4
        assert _last_sent() == "2026-07-01"
        assert ("teams", "accepted") in _deliveries(recorded)
        assert _cycle(world, NOON + 600)["sent"] == 0 and len(tried) == 4
    finally:
        daily_digest.register_digest_sender("teams", None)


def test_a_channel_failing_mid_send_is_unconfirmed_and_not_resent(tmp_path, recorded, monkeypatch):
    from maverick import channel_identities, daily_digest

    world = _world(tmp_path)
    _seed(world)
    tried = []

    def broken(p, d, links, prefs):
        tried.append("teams")
        raise ConnectionError("reset after the message was written")
    monkeypatch.setattr(daily_digest, "_send_slack", lambda p, d, links, prefs: tried.append("slack") and False)
    daily_digest.register_digest_sender("teams", broken)
    try:
        channel_identities.link("slack", "U1", "user:alice", actor="admin")
        channel_identities.link("teams", "T-1", "user:alice", actor="admin")
        first = _cycle(world, NOON)
        assert first["unconfirmed"] == 1 and first["failed"] == 0 and first["sent"] == 0
        assert sorted(_deliveries(recorded)) == [("slack", "not_sent"), ("teams", "unconfirmed")]
        assert _last_sent() == "2026-07-01"
        assert _cycle(world, NOON + 300)["unconfirmed"] == 0 and len(tried) == 2
    finally:
        daily_digest.register_digest_sender("teams", None)


def test_an_audit_refusal_after_the_send_neither_replays_nor_stops_the_cycle(tmp_path, recorded, monkeypatch):
    import maverick.audit as audit
    from maverick import channel_identities, daily_digest, user_preferences
    from maverick.audit.errors import AuditRefused

    world = _world(tmp_path)
    _seed(world)
    sent = []
    monkeypatch.setattr(daily_digest, "_send_slack",
                        lambda p, d, links, prefs: sent.append(p) or True)

    channel_identities.link("slack", "U1", "user:alice", actor="admin")
    channel_identities.link("slack", "U2", "user:bob", actor="admin")

    def refuse(kind, **fields):
        raise AuditRefused("the audit sink refuses writes")
    monkeypatch.setattr(audit, "audit_event", refuse)
    people = ["user:alice", "user:bob"]

    def cycle(now):
        return daily_digest.run_digest_cycle(world, principals=people, can_decide=lambda p: True, now=now)
    first = cycle(NOON)
    assert first["sent"] == 2 and sent == ["user:alice", "user:bob"]
    for person in people:
        assert user_preferences.get_preferences(person)["last_digest_date"] == "2026-07-01"
    assert cycle(NOON + 300)["sent"] == 0 and len(sent) == 2  # no copy on the next poll


class _Smtp:
    def __init__(self, refused):
        self.refused = refused

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, **kwargs):
        return None

    def login(self, user, password):
        return None

    def send_message(self, message):
        return self.refused


def test_email_the_server_refused_is_retried_and_one_it_may_have_taken_is_not(tmp_path, recorded, monkeypatch):
    from maverick import notifications, user_preferences

    world = _world(tmp_path)
    _seed(world)
    user_preferences.set_preferences("user:alice", email="alice@example.com")
    monkeypatch.setattr(notifications, "_load_config",
                        lambda: {"email": {"host": "smtp.example.test", "from_address": "lw@example.test"}})
    monkeypatch.setattr(notifications, "_smtp_session",
                        lambda mail: _Smtp({"alice@example.com": (550, b"mailbox unavailable")}))
    refused = _cycle(world, NOON)
    assert refused["failed"] == 1 and _last_sent() == ""
    attempts = []

    class NoReplyAfterData(_Smtp):
        def send_message(self, message):
            attempts.append("data")
            raise TimeoutError("no reply after the message was sent")
    monkeypatch.setattr(notifications, "_smtp_session", lambda mail: NoReplyAfterData({}))
    lost = _cycle(world, NOON + 300)
    assert lost["unconfirmed"] == 1 and lost["failed"] == 0 and _last_sent() == "2026-07-01"
    assert _deliveries(recorded) == [("email", "not_sent"), ("email", "unconfirmed")]
    assert _cycle(world, NOON + 600)["unconfirmed"] == 0 and len(attempts) == 1
    # The server accepts tomorrow's summary as usual.
    monkeypatch.setattr(notifications, "_smtp_session", lambda mail: _Smtp({}))
    assert _cycle(world, NOON + 86_400)["sent"] == 1 and _last_sent() == "2026-07-02"


# ---- a channel that keeps refusing is retried after a growing wait --------

@pytest.fixture
def teams(tmp_path):
    """Alice has only a Teams account; ``answer`` decides what the sender does."""
    from maverick import channel_identities, daily_digest

    state = {"answer": False, "tried": []}

    def sender(p, d, links, prefs):
        state["tried"].append(p)
        if isinstance(state["answer"], Exception):
            raise state["answer"]
        return state["answer"]
    daily_digest.register_digest_sender("teams", sender)
    channel_identities.link("teams", "T-1", "user:alice", actor="admin")
    world = _world(tmp_path)
    _seed(world)
    state["world"] = world
    yield state
    daily_digest.register_digest_sender("teams", None)


def _at(minutes):
    return NOON + 60 * minutes


def test_definite_failures_back_off_5_10_20_40_60_minutes_then_hourly(teams, recorded):
    from maverick import daily_digest, user_preferences

    assert [daily_digest.retry_delay(n) / 60 for n in range(1, 9)] == [5, 10, 20, 40, 60, 60, 60, 60]
    attempts = [m for m in range(0, 256, 5) if _cycle(teams["world"], _at(m))["failed"]]
    assert attempts == [0, 5, 15, 35, 75, 135, 195, 255]
    retry = user_preferences.digest_retry("user:alice")
    assert retry["date"] == "2026-07-01" and retry["failures"] == 8 and retry["next_at"] == _at(315)
    assert _last_sent() == ""


def test_polls_inside_the_wait_write_no_audit_rows(teams, recorded):
    summaries = [_cycle(teams["world"], _at(m)) for m in range(0, 61, 5)]  # 13 polls in an hour
    assert sum(s["failed"] for s in summaries) == 4  # minutes 0, 5, 15 and 35
    assert sum(s["backing_off"] for s in summaries) == 9
    assert _deliveries(recorded) == [("teams", "not_sent")] * 4
    assert len(teams["tried"]) == 4


def test_a_send_accepted_after_backing_off_closes_the_day(teams, recorded):
    from maverick import user_preferences

    for m in (0, 5, 10, 15):
        _cycle(teams["world"], _at(m))
    assert len(teams["tried"]) == 3  # minute 10 waited
    teams["answer"] = True
    assert _cycle(teams["world"], _at(20))["backing_off"] == 1 and len(teams["tried"]) == 3
    done = _cycle(teams["world"], _at(35))
    assert done["sent"] == 1 and len(teams["tried"]) == 4 and _last_sent() == "2026-07-01"
    assert user_preferences.digest_retry("user:alice") == {}
    assert _cycle(teams["world"], _at(95))["sent"] == 0 and len(teams["tried"]) == 4
    # The next day starts without a wait.
    assert _cycle(teams["world"], _at(24 * 60))["sent"] == 1 and len(teams["tried"]) == 5


def test_an_unconfirmed_send_after_backing_off_is_still_not_resent(teams, recorded):
    from maverick import user_preferences

    assert _cycle(teams["world"], _at(0))["failed"] == 1
    teams["answer"] = ConnectionError("reset after the message was written")
    assert _cycle(teams["world"], _at(3))["backing_off"] == 1
    lost = _cycle(teams["world"], _at(5))
    assert lost["unconfirmed"] == 1 and lost["failed"] == 0 and _last_sent() == "2026-07-01"
    assert user_preferences.digest_retry("user:alice") == {}
    for m in (10, 60, 180):
        assert _cycle(teams["world"], _at(m))["unconfirmed"] == 0
    assert len(teams["tried"]) == 2
    assert _deliveries(recorded) == [("teams", "not_sent"), ("teams", "unconfirmed")]


def test_changing_the_channel_settings_ends_the_wait_at_once(teams, recorded, tmp_path):
    from maverick import channel_identities, user_preferences

    for m in (0, 5, 15, 35):
        assert _cycle(teams["world"], _at(m))["failed"] == 1
    assert _cycle(teams["world"], _at(40))["backing_off"] == 1  # next try at minute 75
    (tmp_path / "config.toml").write_text("[my_work]\ndigest_enable = true\n", encoding="utf-8")
    assert _cycle(teams["world"], _at(45))["failed"] == 1  # tried at once
    assert user_preferences.digest_retry("user:alice")["failures"] == 1  # a fresh wait: 5 minutes
    assert _cycle(teams["world"], _at(50))["failed"] == 1
    assert _cycle(teams["world"], _at(55))["backing_off"] == 1
    # Linking another account is a change too.
    channel_identities.link("slack", "U9", "user:alice", actor="admin")
    linked = _cycle(teams["world"], _at(56))
    assert linked["backing_off"] == 0 and linked["failed"] == 1


def test_a_mail_login_failure_is_retried_once_the_password_is_fixed(tmp_path, recorded, monkeypatch):
    import smtplib

    from maverick import notifications, user_preferences

    world = _world(tmp_path)
    _seed(world)
    user_preferences.set_preferences("user:alice", email="alice@example.com")
    monkeypatch.setattr(notifications, "_load_config", lambda: {"email": {
        "host": "smtp.example.test", "from_address": "lw@example.test", "user": "lw",
        "password": "expired", "tls": "ssl"}})  # pragma: allowlist secret

    class ExpiredPassword(_Smtp):
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")
    monkeypatch.setattr(notifications, "_smtp_session", lambda mail: ExpiredPassword({}))
    first = _cycle(world, NOON)
    # Nothing was handed to the server: a definite failure with a back-off, not "unconfirmed".
    assert first["failed"] == 1 and first["unconfirmed"] == 0 and _last_sent() == ""
    assert _deliveries(recorded) == [("email", "not_sent")]
    monkeypatch.setattr(notifications, "_smtp_session", lambda mail: _Smtp({}))
    fixed = _cycle(world, NOON + 300)
    assert fixed["sent"] == 1 and _last_sent() == "2026-07-01"


def test_a_decider_sees_only_approvals_in_their_departments(tmp_path):
    # The bell and the reminders skip approvals outside the person's
    # departments; the summary (and /me and Slack status) did not.
    from maverick.daily_digest import compose_digest

    world = _world(tmp_path)
    finance = world.create_approval("pay.invoice", requested_by="user:bob")
    general = world.create_approval("send.email", requested_by="user:bob")
    with world._writing() as conn:
        conn.execute("UPDATE approvals SET department='finance' WHERE id=?", (finance,))
    hr = compose_digest(world, "user:hr-lead", can_decide=True, suites=frozenset({"hr"}))
    assert [row["id"] for row in hr["approvals"]] == [general]
    finance_lead = compose_digest(world, "user:fin", can_decide=True, suites=frozenset({"finance"}))
    assert {row["id"] for row in finance_lead["approvals"]} == {finance, general}
    unrestricted = compose_digest(world, "user:root", can_decide=True)
    assert {row["id"] for row in unrestricted["approvals"]} == {finance, general}
    # A person's own request always shows, whatever its department.
    own = compose_digest(world, "user:bob", can_decide=True, suites=frozenset({"hr"}))
    assert {row["id"] for row in own["approvals"]} == {finance, general}
