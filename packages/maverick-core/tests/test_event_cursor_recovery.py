"""Offline protocol and real-filesystem coverage for durable source positions."""
from __future__ import annotations

import os

import pytest
from maverick import automation_events as ev


def test_empty_feed_baseline_survives_restart_and_first_burst(monkeypatch):
    items = []
    monkeypatch.setattr(ev, "_http_get_json", lambda *a, **k: items)
    config = {"url": "https://feed.invalid", "id_field": "order.key"}
    cursor = ev.HttpJsonSource().poll(config, "").cursor
    assert cursor
    assert ev.HttpJsonSource().poll(config, cursor).cursor == cursor
    # IDs resembling cursor syntax and long IDs must remain exact, not sentinels
    # or the flattened 2,000-character display value.
    ids = [0, cursor, "x" * 2500 + "a", "x" * 2500 + "b"]
    items.extend({"order": {"key": item}} for item in reversed(ids))
    result = ev.HttpJsonSource().poll(config, cursor)
    assert result.event_ids == list(map(str, ids))
    assert ev.HttpJsonSource().poll(config, result.cursor).events == []


def test_empty_baseline_drains_first_burst_beyond_limit():
    cursor = ev.diff_new_items([], "", "id").cursor
    items = [{"id": str(i)} for i in reversed(range(60))]
    received = []
    for _ in range(4):
        result = ev.diff_new_items(items, cursor, "id")
        received.extend(item["id"] for item in result.events)
        cursor = result.cursor
    assert received == list(map(str, range(60)))


@pytest.mark.parametrize("legacy", ["lightwork:cursor:v1:provider-item-123",
                                     'lightwork:cursor:v1:["feed","other"]'])
def test_explicit_legacy_format_preserves_arbitrary_old_provider_ids(legacy):
    result = ev.diff_new_items([{"id": "new"}, {"id": legacy}], legacy, "id", cursor_format=0)
    assert result.event_ids == ["new"]
    assert ev.diff_new_items([{"id": "new"}, {"id": legacy}], result.cursor, "id", cursor_format=1).events == []


def test_form_admission_identity_cannot_be_overridden_by_submitted_fields():
    from maverick import form_store
    source = ev.FormSource()
    config = {"token": "synthetic-form"}
    cursor = source.poll(config, "").cursor
    for _ in range(2):
        form_store.append("synthetic-form", {"id": "same", "_lightwork_event_id": "same", "_seq": "same"})
    result = source.poll(config, cursor)
    assert result.event_ids == ["1", "2"]
    assert [event["id"] for event in result.events] == ["same", "same"]


@pytest.mark.parametrize("items", [[{}], [{"id": "a"}, {"id": "a"}]])
def test_feed_without_unique_identity_refuses_cursor_advance(items):
    with pytest.raises(ev.EventSourceError, match="unique IDs"):
        ev.diff_new_items(items, "legacy-id", "id")


def test_tied_files_drain_restart_and_late_tie_without_loss(tmp_path):
    config = {"path": str(tmp_path), "glob": "*.csv"}
    cursor = ev.FileDirSource().poll(config, "").cursor
    stamp = 1_800_000_000_123_456_789
    for i in range(30):
        path = tmp_path / f"row-{i:02}.csv"
        path.write_text("synthetic", encoding="utf-8")
        os.utime(path, ns=(stamp, stamp))
    first = ev.FileDirSource().poll(config, cursor)
    assert len(first.events) == 25
    # Sorts BEFORE already admitted files; a mere (timestamp,last_path) cursor
    # would lose this new arrival even without advancing to a later timestamp.
    late = tmp_path / "aaa-late.csv"
    late.write_text("late", encoding="utf-8")
    os.utime(late, ns=(stamp, stamp))
    second = ev.FileDirSource().poll(config, first.cursor)
    names = [item["name"] for item in first.events + second.events]
    assert len(names) == len(set(names)) == 31
    assert "aaa-late.csv" in names
    assert ev.FileDirSource().poll(config, second.cursor).events == []
    late.unlink()
    assert ev.FileDirSource().poll(config, second.cursor).cursor == second.cursor


def test_file_boundary_capacity_refuses_instead_of_dropping(tmp_path, monkeypatch):
    monkeypatch.setattr(ev, "_MAX_FILE_BOUNDARY_IDS", 2)
    config = {"path": str(tmp_path)}
    cursor = ev.FileDirSource().poll(config, "").cursor
    for i in range(3):
        p = tmp_path / str(i)
        p.write_text("x", encoding="utf-8")
        os.utime(p, ns=(100, 100))
    with pytest.raises(ev.EventSourceError, match="capacity"):
        ev.FileDirSource().poll(config, cursor)


def test_legacy_file_highwater_does_not_replay_equal_timestamp(tmp_path):
    p = tmp_path / "old.csv"
    p.write_text("x", encoding="utf-8")
    os.utime(p, (1000, 1000))
    result = ev.FileDirSource().poll({"path": str(tmp_path)}, "1000.0")
    assert result.events == [] and result.cursor == "1000.0"


def test_legacy_fractional_file_cursor_uses_original_float_and_preserves_migration_key(tmp_path):
    p = tmp_path / "old.csv"
    p.write_text("x", encoding="utf-8")
    stamp = 1_800_000_000_123_456_789
    os.utime(p, ns=(stamp, stamp))
    cursor = str(p.stat().st_mtime)
    assert ev.FileDirSource().poll({"path": str(tmp_path)}, cursor).events == []
    new = tmp_path / "new.csv"
    new.write_text("new", encoding="utf-8")
    os.utime(new, ns=(stamp + 1_000_000_000, stamp + 1_000_000_000))
    first = ev.FileDirSource().poll({"path": str(tmp_path)}, cursor)
    assert first.events[0]["id"] == str(new)
    assert first.event_ids[0] != str(new)
    # A lost cursor commit repeats the legacy key; publishing it ends migration.
    retry = ev.FileDirSource().poll({"path": str(tmp_path)}, cursor)
    assert first == retry
    assert ev.FileDirSource().poll({"path": str(tmp_path)}, first.cursor).events == []


class Mailbox:
    def __init__(self):
        self.uids = list(range(1, 31))
        self.validity = "800"
        self.fetched = []
        self.fetch_error = False

    def login(self, user, password):
        return "OK", []

    def select(self, mailbox, readonly):
        assert readonly is True
        return "OK", [str(len(self.uids)).encode()]

    def response(self, kind):
        assert kind == "UIDVALIDITY"
        return kind, [self.validity.encode()]

    def uid(self, operation, *args):
        if operation == "search":
            since = int(args[1].split()[1].split(":")[0])
            return "OK", [b" ".join(str(uid).encode() for uid in self.uids if uid >= since)]
        assert operation == "fetch"
        self.fetched.append(int(args[0]))
        if self.fetch_error:
            return "NO", [None]
        return "OK", [(b"header", b"From: synthetic@example.invalid\r\n"
                       b"Authentication-Results: mx.example.invalid; dmarc=pass header.from=example.invalid\r\n"
                       b"Subject: Order\r\n\r\nbody")]

    def logout(self):
        return "BYE", []


@pytest.fixture
def mailbox(monkeypatch):
    box = Mailbox()
    monkeypatch.setattr("imaplib.IMAP4_SSL", lambda *a, **k: box)
    monkeypatch.setenv("SYNTHETIC_IMAP_PASSWORD", "synthetic-offline")
    return box


IMAP_CONFIG = {"host": "mail.invalid", "username": "synthetic",
               "password_env": "SYNTHETIC_IMAP_PASSWORD", "include_body": True,  # pragma: allowlist secret
               "trusted_authserv_id": "mx.example.invalid",
               "allowed_senders": "synthetic@example.invalid"}  # pragma: allowlist secret - synthetic environment-variable name


def test_imap_password_name_cannot_point_at_another_process_secret(mailbox, monkeypatch):
    """A saved source must not send an unrelated process secret (a provider key)
    to the mail host it names."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-provider-key")  # pragma: allowlist secret
    attempts = []
    monkeypatch.setattr("imaplib.IMAP4_SSL", lambda *a, **k: attempts.append(a) or mailbox)
    refused = ("ANTHROPIC_API_KEY", "MAVERICK_DASHBOARD_TOKEN", "DATABASE_PASSWORD",
               "MAVERICK_EMAIL_PASSWORD", "MAIL_TOKEN", "mail_password", "EMAIL_APP_PASSWORD",
               "SMTP_PASSWORD", "DATABASE_PASSWORD_MAIL", "OPENAI_API_KEY_MAIL_PASS",
               "GMAIL_CLIENT_SECRET", "OUTLOOK_CLIENT_SECRET", "MAIL_SECRET_KEY",
               "AWS_SECRET_ACCESS_KEY_MAIL", "OUTLOOK_SECRET", "IMAPPASSWORD")
    for name in refused:
        assert ev.imap_password_name_problem(name), name
        with pytest.raises(ev.EventSourceError, match="mail password name"):
            ev.ImapEmailSource().poll({**IMAP_CONFIG, "password_env": name}, "")
    assert attempts == []
    # Working mail setups keep their existing variable names.
    for name in ("MAIL_PASSWORD", "GMAIL_APP_PASSWORD", "SYNTHETIC_IMAP_PASSWORD", "IMAP_PW",
                 "ICLOUD_APP_PASSWORD", "YAHOO_APP_PASSWORD", "SYNTHETIC_MAIL_PASSWORD"):
        assert ev.imap_password_name_problem(name) is None, name
    monkeypatch.setenv("GMAIL_APP_PASSWORD", "synthetic-offline")  # pragma: allowlist secret
    ev.ImapEmailSource().poll({**IMAP_CONFIG, "password_env": "GMAIL_APP_PASSWORD"}, "")  # pragma: allowlist secret
    assert len(attempts) == 1


def test_imap_requires_sender_verification_and_an_explicit_people_list(mailbox):
    source = ev.ImapEmailSource()
    with pytest.raises(ev.EventSourceError, match="server that checks"):
        source.poll({k: v for k, v in IMAP_CONFIG.items() if k != "trusted_authserv_id"}, "")
    with pytest.raises(ev.EventSourceError, match="permitted email senders"):
        source.poll({k: v for k, v in IMAP_CONFIG.items() if k != "allowed_senders"}, "")
    with pytest.raises(ev.EventSourceError, match="encrypted mail connection"):
        source.poll({**IMAP_CONFIG, "use_ssl": False}, "")
    baseline = source.poll(IMAP_CONFIG, "")
    mailbox.uids.append(31)
    original_uid = mailbox.uid

    def forged_uid(operation, *args):
        if operation == "fetch":
            return "OK", [(b"header", b"From: synthetic@example.invalid\r\n"
                           b"Authentication-Results: relay.evil.invalid; dmarc=pass header.from=example.invalid\r\n"
                           b"Subject: Forged\r\n\r\nbody")]
        return original_uid(operation, *args)

    mailbox.uid = forged_uid
    rejected = source.poll(IMAP_CONFIG, baseline.cursor)
    assert rejected.events == []
    assert ev._decode_cursor(rejected.cursor, "imap") == ["800", 31]
    mailbox.uid = original_uid
    mailbox.uids.append(32)
    assert [row["uid"] for row in source.poll(IMAP_CONFIG, rejected.cursor).events] == ["32"]


def test_imap_rejects_forged_dmarc_pass_inside_server_comment(mailbox):
    source = ev.ImapEmailSource()
    baseline = source.poll(IMAP_CONFIG, "")
    mailbox.uids.append(31)
    original_uid = mailbox.uid

    def forged_uid(operation, *args):
        if operation == "fetch":
            return "OK", [(b"header", b"From: synthetic@example.invalid\r\n"
                           b"Authentication-Results: mx.example.invalid; spf=pass "
                           b"(sender; dmarc=pass header.from=example.invalid); "
                           b"dmarc=fail header.from=example.invalid\r\n\r\n")]
        return original_uid(operation, *args)

    mailbox.uid = forged_uid
    rejected = source.poll(IMAP_CONFIG, baseline.cursor)
    assert rejected.events == []
    assert ev._decode_cursor(rejected.cursor, "imap") == ["800", 31]


def test_imap_authenticated_but_unlisted_sender_does_not_start_work(mailbox):
    source = ev.ImapEmailSource()
    baseline = source.poll(IMAP_CONFIG, "")
    mailbox.uids.append(31)
    other = {**IMAP_CONFIG, "allowed_senders": "someone-else@example.invalid"}
    rejected = source.poll(other, baseline.cursor)
    assert rejected.events == []
    assert ev._decode_cursor(rejected.cursor, "imap") == ["800", 31]


def test_imap_initial_highwater_fetches_no_history_and_reset_rebaselines(mailbox):
    source = ev.ImapEmailSource()
    baseline = source.poll(IMAP_CONFIG, "")
    assert baseline.events == [] and mailbox.fetched == []
    assert ev._decode_cursor(baseline.cursor, "imap") == ["800", 30]
    assert source.poll(IMAP_CONFIG, baseline.cursor).events == []
    mailbox.uids.extend([31, 32])
    result = source.poll(IMAP_CONFIG, baseline.cursor)
    assert [event["id"] for event in result.events] == ["800:31", "800:32"]
    assert mailbox.fetched == [31, 32]
    mailbox.validity = "801"
    mailbox.uids = [1, 2, 3]
    reset = source.poll(IMAP_CONFIG, result.cursor)
    assert reset.events == [] and mailbox.fetched == [31, 32]
    mailbox.uids.append(4)
    assert source.poll(IMAP_CONFIG, reset.cursor).events[0]["id"] == "801:4"


def test_imap_empty_mailbox_first_new_message_fires_and_fetch_failure_retains_cursor(mailbox):
    mailbox.uids = []
    cursor = ev.ImapEmailSource().poll(IMAP_CONFIG, "").cursor
    mailbox.uids = [1]
    mailbox.fetch_error = True
    with pytest.raises(ev.EventSourceError, match="cursor retained"):
        ev.ImapEmailSource().poll(IMAP_CONFIG, cursor)
    mailbox.fetch_error = False
    assert ev.ImapEmailSource().poll(IMAP_CONFIG, cursor).events[0]["uid"] == "1"


def test_imap_legacy_cursor_preserves_existing_highwater(mailbox):
    result = ev.ImapEmailSource().poll(IMAP_CONFIG, "25")
    assert [event["uid"] for event in result.events] == list(map(str, range(26, 31)))
    assert mailbox.fetched == list(range(26, 31))
    assert [event["id"] for event in result.events] == list(map(str, range(26, 31)))
    assert result.event_ids == [f"800:{uid}" for uid in range(26, 31)]
    assert ev.ImapEmailSource().poll(IMAP_CONFIG, "25") == result
