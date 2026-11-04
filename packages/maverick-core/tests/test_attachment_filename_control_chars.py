"""Attachment filenames must reject control characters (incl. null byte).

Regression: validation rejected '/', '\\', and a leading '.', but a null
byte ("evil\\x00.jpg") slipped through -- and a null byte truncates the
path at the C layer in downstream consumers (and other control chars
enable log/terminal injection).
"""
import pytest
from maverick.attachments import AttachmentRejected, store


def test_rejects_null_byte_in_filename():
    with pytest.raises(AttachmentRejected, match="control character"):
        store(1, "evil\x00.jpg", "image/jpeg", b"data")


def test_rejects_newline_in_filename():
    with pytest.raises(AttachmentRejected, match="control character"):
        store(1, "evil\n.jpg", "image/jpeg", b"data")
