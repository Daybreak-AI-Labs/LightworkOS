"""Tests for the s3_attachments tool. No network calls."""
from __future__ import annotations

from maverick.tools import s3_attachments as s3a


def test_missing_op_errors():
    assert s3a.s3_attachments().fn({}).startswith("ERROR: op is required")


def test_unknown_op_errors():
    assert s3a.s3_attachments().fn({"op": "nope"}).startswith("ERROR: unknown op")


def test_key_for_requires_filename():
    out = s3a.s3_attachments().fn({"op": "key_for", "filename": "  "})
    assert out.startswith("ERROR")
    assert "requires filename" in out


def test_put_get_url_require_bucket_and_key():
    out = s3a.s3_attachments().fn({"op": "put_url", "bucket": "b"})
    assert out.startswith("ERROR")
    assert "bucket and key" in out


def test_key_for_is_deterministic_and_keeps_ext():
    k1 = s3a.key_for("Report.PDF")
    k2 = s3a.key_for("Report.PDF")
    assert k1 == k2
    assert k1.startswith("attachments/")
    assert k1.endswith(".pdf")
    # Different names -> different keys.
    assert s3a.key_for("a.txt") != s3a.key_for("b.txt")
    # No extension -> no trailing dot.
    assert not s3a.key_for("README").endswith(".")


def test_build_url_virtual_hosted(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    out = s3a.s3_attachments().fn(
        {"op": "get_url", "bucket": "mybucket", "key": "attachments/abc.txt"}
    )
    assert out == "https://mybucket.s3.eu-west-1.amazonaws.com/attachments/abc.txt"


def test_build_url_default_region_and_encoding(monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    url = s3a.build_url("b", "dir/name with space.txt", s3a._region())
    assert url.startswith("https://b.s3.us-east-1.amazonaws.com/")
    # Path separators preserved, the space within a segment is encoded.
    assert "dir/name%20with%20space.txt" in url


def test_put_url_op_roundtrip(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    key = s3a.key_for("photo.png")
    out = s3a.s3_attachments().fn({"op": "put_url", "bucket": "b", "key": key})
    assert out == f"https://b.s3.us-east-1.amazonaws.com/{key}"
