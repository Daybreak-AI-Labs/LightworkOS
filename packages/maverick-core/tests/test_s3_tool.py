"""Tests for the S3 tool (maverick.tools.s3_tool)."""
from __future__ import annotations

import sys
import types


def _install_fake_boto3(monkeypatch, *, buckets=None, list_objects=None,
                        get_body=None, get_size=None, presigned_url="https://x"):
    boto3 = types.ModuleType("boto3")

    class _Body:
        def __init__(self, data):
            self._data = data

        def read(self, n):
            return self._data[:n]

    class _Client:
        def list_buckets(self):
            return {"Buckets": buckets or []}

        def list_objects_v2(self, **kwargs):
            return {"Contents": list_objects or []}

        def get_object(self, Bucket, Key):
            return {
                "Body": _Body((get_body or "hello").encode("utf-8")),
                "ContentLength": get_size if get_size is not None else 5,
                "ContentType": "text/plain",
            }

        def put_object(self, **kwargs):
            return {}

        def delete_object(self, **kwargs):
            return {}

        def generate_presigned_url(self, *a, **k):
            return presigned_url

    boto3.client = lambda *a, **k: _Client()
    monkeypatch.setitem(sys.modules, "boto3", boto3)


# ---------- S3 ----------

def test_s3_requires_op():
    from maverick.tools.s3_tool import s3_tool
    assert "op is required" in s3_tool().fn({})


def test_s3_missing_boto3(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)
    from maverick.tools.s3_tool import s3_tool
    out = s3_tool().fn({"op": "list_buckets"})
    assert "boto3 not installed" in out


def test_s3_list_buckets(monkeypatch):
    import datetime as _dt
    _install_fake_boto3(monkeypatch, buckets=[
        {"Name": "b1", "CreationDate": _dt.datetime(2026, 1, 1)},
    ])
    from maverick.tools.s3_tool import s3_tool
    out = s3_tool().fn({"op": "list_buckets"})
    assert "b1" in out


def test_s3_put_dry_run(monkeypatch):
    _install_fake_boto3(monkeypatch)
    from maverick.tools.s3_tool import s3_tool
    out = s3_tool().fn({
        "op": "put", "bucket": "b", "key": "k", "body": "hi",
    })
    assert "DRY RUN" in out


def test_s3_put_confirmed(monkeypatch):
    _install_fake_boto3(monkeypatch)
    from maverick.tools.s3_tool import s3_tool
    out = s3_tool().fn({
        "op": "put", "bucket": "b", "key": "k", "body": "hi",
        "confirm": True,
    })
    assert "put s3://b/k" in out


def test_s3_presign_returns_url(monkeypatch):
    _install_fake_boto3(monkeypatch, presigned_url="https://x.example/k?sig=abc")
    from maverick.tools.s3_tool import s3_tool
    out = s3_tool().fn({"op": "presign", "bucket": "b", "key": "k"})
    assert "https://x.example/k?sig=abc" in out
