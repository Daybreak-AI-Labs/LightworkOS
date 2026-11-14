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
        meta = types.SimpleNamespace(endpoint_url="https://s3.us-east-1.amazonaws.com")
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

    created = []
    boto3.client = lambda *a, **k: created.append(k) or _Client()
    boto3.created = created
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    botocore = types.ModuleType("botocore")
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = lambda **k: k
    botocore.config = botocore_config
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)


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


def test_s3_endpoint_is_checked_against_enterprise_egress(monkeypatch, tmp_path):
    # botocore is outside the process egress guard, so the tool checks the
    # client's endpoint itself: enterprise mode with no allowed host refuses.
    _install_fake_boto3(monkeypatch, buckets=[{"Name": "b1"}])
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "absent.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    from maverick import config
    config.reset_config_cache()
    from maverick.tools.s3_tool import s3_tool
    out = s3_tool().fn({"op": "list_buckets"})
    config.reset_config_cache()
    assert out.startswith("ERROR") and "s3.us-east-1.amazonaws.com" in out
    assert "b1" not in out
    # Only the probe (static placeholder keys, so no credential provider
    # runs) was built; it uses path-style addressing, so requests stay on the
    # checked host instead of <bucket>.<host>.
    created = sys.modules["boto3"].created
    assert len(created) == 1 and created[0]["aws_access_key_id"] == "egress-probe"
    assert created[0]["config"] == {"s3": {"addressing_style": "path"}}
