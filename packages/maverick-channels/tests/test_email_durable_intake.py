"""Local fake IMAP/SMTP transports over the actual channel journal."""
from __future__ import annotations

import asyncio
import email.message

import pytest
from maverick import world_model
from maverick_channels import delivery
from maverick_channels.email import EmailChannel


@pytest.fixture
def environment(monkeypatch, tmp_path):
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    runs = []
    async def handler(msg):
        runs.append(msg.text)
        return "saved answer"
    channel = EmailChannel(handler, "imap.example.test", "bot@example.test", "fixture",
                           "smtp.example.test", "bot@example.test", "fixture",
                           allowed_user_ids=["alice@example.test"],
                           trusted_authserv_id="mx.example.test")
    return channel, runs


def _mail():
    msg = email.message.EmailMessage()
    msg["From"], msg["Subject"] = "alice@example.test", "Review"
    msg["Authentication-Results"] = "mx.example.test; dmarc=pass header.from=example.test"
    msg.set_content("Question")
    return msg.as_bytes()


def _imap(monkeypatch, on_seen, message=_mail):
    class IMAP:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def login(self, *args):
            pass
        def select(self, *args):
            return "OK", [b"1"]
        def response(self, *args):
            return "UIDVALIDITY", [b"42"]
        def uid(self, command, *args):
            if command == "search":
                return "OK", [b"7"]
            if command == "fetch":
                return "OK", [(b"7", message())]
            assert command == "store" and args == (b"7", "+FLAGS", "\\Seen")
            on_seen()
            return "OK", []
    monkeypatch.setattr("maverick_channels.email.imaplib.IMAP4_SSL", IMAP)


def test_unauthenticated_sender_never_enters_durable_work(environment, monkeypatch):
    channel, runs = environment
    seen = []
    def unverified_mail():
        msg = email.message.EmailMessage()
        msg["From"] = "alice@example.test"
        msg.set_content("Start work")
        return msg.as_bytes()
    _imap(monkeypatch, lambda: seen.append(True), unverified_mail)
    assert channel._fetch_unseen() == []
    assert seen == [True]
    assert delivery.DeliveryJournal().store.list(limit=2) == []
    assert runs == []


def test_pre_upgrade_email_receipt_is_held_before_recovery(environment, monkeypatch):
    channel, runs = environment
    journal = delivery.DeliveryJournal()
    message = delivery.IncomingMessage(
        user_id="alice@example.test", text="Old request", channel="email", message_id="legacy-1",
    )
    old = journal.admit(message, external_id="legacy-1", account=channel._account(),
                        route={"subject": "Old reply"})
    monkeypatch.setattr(channel, "_fetch_unseen", list)
    async def no_sleep(*args):
        channel._stop = True
    monkeypatch.setattr("maverick_channels.email.asyncio.sleep", no_sleep)
    asyncio.run(channel.start())
    held = journal.get(old["id"])
    assert held["restore_hold"] is True
    assert held["execution"] == "received"
    assert runs == []


def test_seen_ack_occurs_after_durable_intake_and_restart_recovers(environment, monkeypatch):
    channel, runs = environment
    def seen():
        rows = delivery.DeliveryJournal().store.list(limit=2)
        assert len(rows) == 1 and rows[0]["execution"] == "received"
        assert not runs
    _imap(monkeypatch, seen)
    rows = channel._fetch_unseen()
    assert rows[0]["external_id"] == "42:7" and not runs
    sent = []
    async def send(user_id, text, subject):
        sent.append((user_id, text, subject))
        channel._stop = True
    monkeypatch.setattr(channel, "send", send)
    monkeypatch.setattr(channel, "_fetch_unseen", list)
    async def no_sleep(*args):
        channel._stop = True
    monkeypatch.setattr("maverick_channels.email.asyncio.sleep", no_sleep)
    asyncio.run(channel.start())
    assert len(runs) == 1 and sent == [("alice@example.test", "saved answer", "Re: Review")]
    assert delivery.DeliveryJournal().get(rows[0]["id"])["delivery"] == "delivered"


def test_queued_email_question_is_sent_after_ack_from_saved_sender(environment, monkeypatch):
    from maverick import server as server_mod

    channel, _ = environment

    async def handler(msg):
        msg._channel_question_watch = {
            "goal_id": 4, "conversation_id": 8, "tenant": None,
            "owner": "user:email:alice@example.test",
            "execution_principal": "user:email:alice@example.test",
        }
        return "Task queued"

    channel.handler = handler
    journal = delivery.DeliveryJournal()
    message = delivery.IncomingMessage(
        user_id="alice@example.test", text="Prepare report", channel="email",
        message_id="42:7",
    )
    row = journal.admit(message, external_id="42:7", account=channel._account(),
                        route={"subject": "Re: Review", "sender_auth": "trusted_dmarc_pass"})
    monkeypatch.setattr(channel, "_fetch_unseen", list)
    monkeypatch.setattr(server_mod, "queued_channel_question",
                        lambda *a: ("Question #9 for task #4: Which customer?", False))
    sent = []

    async def send(user_id, text, subject):
        sent.append((user_id, text, subject))

    monkeypatch.setattr(channel, "send", send)

    async def no_sleep(*args):
        channel._stop = True

    monkeypatch.setattr("maverick_channels.email.asyncio.sleep", no_sleep)
    asyncio.run(channel.start())
    assert sent == [
        ("alice@example.test", "Task queued", "Re: Review"),
        ("alice@example.test", "Question #9 for task #4: Which customer?", "Re: Review"),
    ]
    assert journal.get(row["id"])["question_watch"] is None


def test_failed_intake_does_not_ack_seen(environment, monkeypatch):
    channel, runs = environment
    _imap(monkeypatch, lambda: pytest.fail("Acknowledged before durable intake"))
    monkeypatch.setattr(delivery.DeliveryJournal, "admit", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        channel._fetch_unseen()
    assert not runs


def test_folded_subject_is_unfolded_before_saving_reply_route(environment, monkeypatch):
    channel, _ = environment
    _imap(monkeypatch, lambda: None,
          lambda: _mail().replace(b"Subject: Review", b"Subject: Review\r\n\tthis quarter"))
    row, = channel._fetch_unseen()
    assert row["route"]["subject"] == "Re: Review this quarter"
    message = email.message.EmailMessage()
    message["Subject"] = row["route"]["subject"]
    assert "Subject: Review this quarter" in row["message"]["text"]


def test_invalid_intake_configuration_leaves_mail_unread(environment, monkeypatch):
    from maverick import config

    channel, _ = environment
    seen = []
    _imap(monkeypatch, lambda: seen.append(True))
    monkeypatch.setattr(config, "load_config", lambda: {"channels": {"max_intake_records": 0}})
    with pytest.raises(ValueError, match="intake capacity"):
        channel._fetch_unseen()
    assert seen == []


@pytest.mark.parametrize("phase", ["connect", "accepted_then_disconnect", "explicit_rejection"])
def test_smtp_failure_classification_retains_ambiguity(environment, monkeypatch, phase):
    channel, _ = environment
    import smtplib
    class SMTP:
        def __init__(self, *args, **kwargs):
            if phase == "connect":
                raise OSError("no connection")
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def login(self, *args):
            pass
        def send_message(self, message):
            assert message["Message-ID"] == "<stable@fixture>"
            if phase == "explicit_rejection":
                raise smtplib.SMTPDataError(550, b"rejected")
            raise smtplib.SMTPServerDisconnected("lost after possible acceptance")
    monkeypatch.setattr("maverick_channels.email.smtplib.SMTP_SSL", SMTP)
    expected = smtplib.SMTPServerDisconnected if phase == "accepted_then_disconnect" else delivery.DeliveryNotSent
    with pytest.raises(expected):
        channel._send_sync("alice@example.test", "reply", "subject", message_id="<stable@fixture>")


def test_port_587_uses_tls_before_sign_in_or_sending(environment, monkeypatch):
    channel, _ = environment
    channel.smtp_port = 587
    steps = []
    class SMTP:
        def __init__(self, *args, **kwargs):
            assert args == ("smtp.example.test", 587)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def starttls(self, *, context):
            assert context is not None
            steps.append("tls")
        def login(self, *args):
            steps.append("login")
        def send_message(self, message):
            steps.append("send")
            return {}
    monkeypatch.setattr("maverick_channels.email.smtplib.SMTP", SMTP)
    monkeypatch.setattr("maverick_channels.email.smtplib.SMTP_SSL", lambda *a, **kw: pytest.fail("wrong TLS mode"))
    channel._send_sync("alice@example.test", "reply", "subject")
    assert steps == ["tls", "login", "send"]


def test_rotating_recovery_window_finds_later_records_and_preserves_failed_cursor(environment):
    channel, _ = environment
    journal = delivery.DeliveryJournal()
    for i in range(8):
        msg = delivery.IncomingMessage(user_id="alice@example.test", text=str(i), channel="email", message_id=str(i))
        journal.admit(msg, external_id=str(i), account=channel._account(), route={"subject": "Review"})
    first, checkpoint = journal.recovery_window(channel="email", account=channel._account(), limit=2)
    repeated, _ = journal.recovery_window(channel="email", account=channel._account(), limit=2)
    assert [row["id"] for row in first] == [row["id"] for row in repeated]
    found = set()
    for _ in range(4):
        rows, checkpoint = journal.recovery_window(channel="email", account=channel._account(), limit=2)
        found.update(row["id"] for row in rows)
        journal.finish_recovery_window(checkpoint)
    assert len(found) == 8


def test_one_recovery_pass_looks_past_finished_receipts(environment):
    """Before, a pass inspected only ``limit`` receipts, so on a store full of
    finished work a stranded message waited hours for its turn."""
    channel, _ = environment
    journal = delivery.DeliveryJournal()
    admitted = []
    for i in range(40):
        msg = delivery.IncomingMessage(user_id="alice@example.test", text=str(i), channel="email", message_id=str(i))
        admitted.append(journal.admit(msg, external_id=str(i), account=channel._account(), route={"subject": "Review"}))
    waiting = admitted.pop(17)
    for row in admitted:
        journal.change(row, execution="completed", delivery="delivered")
    rows, _ = journal.recovery_window(channel="email", account=channel._account(), limit=2)
    assert [row["id"] for row in rows] == [waiting["id"]]
    # The scan still has a hard bound on receipts inspected per pass.
    rows, _ = journal.recovery_window(channel="email", account=channel._account(), limit=2, scan_limit=2)
    assert len(rows) <= 2


def test_a_refused_attachment_never_stops_the_mailbox(environment, monkeypatch):
    # A file type the store refuses raised inside the poll before the email was
    # marked read, so it stayed first among the unread and every later poll
    # stopped at it: no newer email was ever taken in.
    channel, _ = environment
    def with_program():
        msg = email.message.EmailMessage()
        msg["From"], msg["Subject"] = "alice@example.test", "Tool"
        msg["Authentication-Results"] = "mx.example.test; dmarc=pass header.from=example.test"
        msg.set_content("Please look at this")
        msg.add_attachment(b"MZ\x90\x00binary", maintype="application", subtype="x-msdownload",
                           filename="tool.exe")
        return msg.as_bytes()
    seen = []
    _imap(monkeypatch, lambda: seen.append(True), with_program)
    rows = channel._fetch_unseen()
    assert seen == [True]
    assert len(rows) == 1 and rows[0]["message"]["attachments"] == []
    assert rows[0]["message"]["text"].startswith("Subject: Tool\n\nPlease look at this")
    assert "attached files were not accepted" in rows[0]["message"]["text"]


def test_an_email_admitted_differently_before_is_marked_read_not_retried_forever(environment, monkeypatch):
    # An email admitted by an earlier build (a different intake fingerprint)
    # and marked unread again: the earlier admission stands and the poll moves on.
    channel, _ = environment
    old = delivery.IncomingMessage(user_id="alice@example.test", text="Earlier text", channel="email",
                                   message_id="42:7")
    delivery.DeliveryJournal().admit(old, external_id="42:7", account=channel._account(),
                                     route={"subject": "Re: Review"})
    seen = []
    _imap(monkeypatch, lambda: seen.append(True))
    assert channel._fetch_unseen() == []
    assert seen == [True]
    assert len(delivery.DeliveryJournal().store.list(limit=5)) == 1


def test_a_full_intake_still_leaves_the_email_unread_for_later(environment, monkeypatch):
    from maverick.governed_records import GovernedRecordCapacityError

    channel, _ = environment
    def full(*args, **kwargs):
        raise GovernedRecordCapacityError("full")
    monkeypatch.setattr(delivery.DeliveryJournal, "admit", full)
    seen = []
    _imap(monkeypatch, lambda: seen.append(True))
    with pytest.raises(GovernedRecordCapacityError):
        channel._fetch_unseen()
    assert seen == []


def test_one_failing_row_does_not_pin_the_email_recovery_window(environment, monkeypatch):
    # The email loop wrapped the whole batch in one try: a row that raised on
    # every pass (an unconfirmed question send, say) skipped the rows after it
    # and never advanced the window, so they were never handled.
    channel, _ = environment
    journal = delivery.DeliveryJournal()
    for n in (1, 2):
        message = delivery.IncomingMessage(user_id="alice@example.test", text=f"Request {n}",
                                           channel="email", message_id=f"42:{n}")
        journal.admit(message, external_id=f"42:{n}", account=channel._account(),
                      route={"subject": "Re: Review", "sender_auth": "trusted_dmarc_pass"})
    handled, finished = [], []

    async def process(incoming, **kwargs):
        if incoming.message_id == "42:1":
            raise delivery.DeliveryUnknown("Prior channel send has no confirmed receipt")
        handled.append(incoming.message_id)

    monkeypatch.setattr(channel, "process_message", process)
    monkeypatch.setattr(channel, "_fetch_unseen", list)
    monkeypatch.setattr(delivery.DeliveryJournal, "finish_recovery_window",
                        lambda self, checkpoint: finished.append(checkpoint))
    async def no_sleep(*args):
        channel._stop = True
    monkeypatch.setattr("maverick_channels.email.asyncio.sleep", no_sleep)
    asyncio.run(channel.start())
    assert handled == ["42:2"] and len(finished) == 1
