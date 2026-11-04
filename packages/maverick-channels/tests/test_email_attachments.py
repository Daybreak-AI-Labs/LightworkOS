"""Inbound email file parts become IncomingMessage.attachments dicts."""
from __future__ import annotations

import email.message

from maverick_channels.email import EmailChannel


def test_multipart_file_part_captured():
    m = email.message.EmailMessage()
    m["From"] = "a@b.com"
    m["Subject"] = "numbers"
    m.set_content("see attached")
    m.add_attachment(b"col1,col2\n1,2\n", maintype="text", subtype="csv",
                     filename="data.csv")
    out = EmailChannel._extract_attachments(m)
    assert len(out) == 1
    assert out[0]["filename"] == "data.csv"
    assert out[0]["mime"] == "text/csv"
    assert out[0]["data"].startswith(b"col1")


def test_plain_email_has_no_attachments():
    m = email.message.EmailMessage()
    m.set_content("just words")
    assert EmailChannel._extract_attachments(m) == []


def test_attachment_count_is_bounded():
    m = email.message.EmailMessage()
    m.set_content("many files")
    for i in range(15):
        m.add_attachment(b"x", maintype="text", subtype="plain",
                         filename=f"f{i}.txt")
    assert len(EmailChannel._extract_attachments(m)) == 10
