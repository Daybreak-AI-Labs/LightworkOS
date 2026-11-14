"""WORM export of closed audit day-files (audit/worm.py).

Orchestration is exercised against a fake/local sink + a tmp audit dir (no S3),
the way the rest of the audit suite avoids live infra.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick.audit import worm
from maverick.audit.signing import (
    AuditSigner,
    ensure_anchors,
    reanchor_day_after_erase,
    verify_chain,
)

_REAL_SEALING_ACTIVE = worm._at_rest_sealing_active


@pytest.fixture(autouse=True)
def _plaintext_worm_path(monkeypatch):
    """These tests exercise WORM push/verify MECHANICS over plaintext
    day-files (a supported configuration). The at-rest sealing interlock
    is pinned off here so the mechanics run under the secure posture
    too; the interlock itself has its own test below, which re-pins it
    on explicitly."""
    monkeypatch.setattr(worm, "_at_rest_sealing_active", lambda: False)


class FakeSink:
    def __init__(self):
        self.puts = []
        self._objects = {}

    def put(self, name, data, *, retain_until):
        self.puts.append((name, data, retain_until))
        self._objects[name] = data
        return {
            "target": "fake", "name": name,
            "retain_until": retain_until.isoformat(),
        }

    def verify(self, locator, expected_sha256):
        data = self._objects.get(locator.get("name"))
        return data is not None and worm._sha256(data) == expected_sha256


def _audit_dir(tmp_path, files: dict[str, str]) -> Path:
    ad = tmp_path / "audit"
    ad.mkdir()
    for name, content in files.items():
        if worm._valid_day_name(name):
            signer = AuditSigner(ad / name)
            assert signer.write({"kind": "test", "content": content})
        elif name != "anchors.ndjson":
            (ad / name).write_text(content, encoding="utf-8")
    ensure_anchors(ad)
    return ad


def _append_signed_and_reanchor(ad: Path, name: str, content: str) -> None:
    path = ad / name
    signer = AuditSigner(path)
    assert signer.write({"kind": "test_update", "content": content})
    reanchor_day_after_erase(ad, path)


# --- push -------------------------------------------------------------------

def test_push_ships_closed_skips_today_and_anchors(tmp_path):
    ad = _audit_dir(tmp_path, {
        "2020-01-01.ndjson": "a\n",
        "2020-01-02.ndjson": "b\n",
        "2099-01-01.ndjson": "future\n",   # >= today -> not closed
        "anchors.ndjson": "anchor\n",      # not a date-named day-file
    })
    sink = FakeSink()
    rep = worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert rep == {"2020-01-01.ndjson": "pushed", "2020-01-02.ndjson": "pushed"}
    assert {n for n, _, _ in sink.puts} == {"2020-01-01.ndjson", "2020-01-02.ndjson"}
    # retain-until is in the future (the lock duration).
    assert all(ru > worm._utcnow() for _, _, ru in sink.puts)


def test_push_is_idempotent(tmp_path):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "a\n"})
    sink = FakeSink()
    worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    rep = worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert rep == {"2020-01-01.ndjson": "already pushed"}
    assert len(sink.puts) == 1   # no second shipment


def test_failed_upload_holds_only_that_file(tmp_path):
    # An upload with an unknown result is held for review, but it must not
    # stop every later day from being exported.
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "a\n"})

    class _Flaky(FakeSink):
        def put(self, name, data, *, retain_until):
            raise ConnectionRefusedError("collector down")

    rep = worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=_Flaky())
    assert rep == {"2020-01-01.ndjson": "error (ConnectionRefusedError)"}

    signer = AuditSigner(ad / "2020-01-02.ndjson")
    assert signer.write({"kind": "test", "content": "b"})
    ensure_anchors(ad)
    sink = FakeSink()
    rep = worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert rep["2020-01-01.ndjson"].startswith("refused: held")
    assert rep["2020-01-02.ndjson"] == "pushed"
    assert [n for n, _, _ in sink.puts] == ["2020-01-02.ndjson"]


def test_changed_file_is_repushed(tmp_path):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "a\n"})
    f = ad / "2020-01-01.ndjson"
    sink = FakeSink()
    worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    _append_signed_and_reanchor(ad, f.name, "authorized changed version")
    rep = worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert rep == {"2020-01-01.ndjson": "re-pushed (changed)"}
    assert len(sink.puts) == 2


def test_dry_run_writes_nothing(tmp_path):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "a\n"})
    rep = worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", dry_run=True)
    assert rep == {"2020-01-01.ndjson": "would push"}
    assert not (ad / "worm").exists()   # no manifest, no sink built


def test_push_unconfigured_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(worm, "_worm_cfg", dict)
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "a\n"})
    with pytest.raises(worm.WormUnavailable):
        worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01")


# --- verify -----------------------------------------------------------------

def test_verify_reports_ok_changed_and_unpushed(tmp_path):
    ad = _audit_dir(tmp_path, {
        "2020-01-01.ndjson": "a\n",
        "2020-01-02.ndjson": "b\n",
    })
    sink = worm.LocalWormSink(ad / "worm" / "store")
    worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    _append_signed_and_reanchor(ad, "2020-01-02.ndjson", "changed")
    signer = AuditSigner(ad / "2020-01-03.ndjson")
    assert signer.write({"kind": "test", "content": "never pushed"})
    ensure_anchors(ad)
    rep = worm.verify(audit_dir=ad)
    assert rep["2020-01-01.ndjson"] == "ok"
    assert rep["2020-01-02.ndjson"] == "changed since push"
    assert rep["2020-01-03.ndjson"] == "NOT pushed"


def test_forged_manifest_does_not_verify_or_suppress_push(tmp_path):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "a\n"})
    digest = worm._sha256((ad / "2020-01-01.ndjson").read_bytes())
    missing = ad / "worm" / "store" / "missing-copy"
    (ad / "worm").mkdir()
    (ad / "worm" / "manifest.ndjson").write_text(
        json.dumps({
            "name": "2020-01-01.ndjson",
            "sha256": digest,
            "locator": {"target": "local", "path": str(missing)},
        }) + "\n",
        encoding="utf-8",
    )

    assert worm.verify(audit_dir=ad) == {"2020-01-01.ndjson": "manifest invalid"}

    sink = worm.LocalWormSink(ad / "worm" / "store")
    with pytest.raises(worm.WormUnavailable, match="manifest"):
        worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    # Recovery is explicit: quarantine the untrusted legacy/forged manifest,
    # then create a fresh signed chain by pushing the source again.
    (ad / "worm" / "manifest.ndjson").unlink()
    rep = worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert rep == {"2020-01-01.ndjson": "pushed"}
    assert worm.verify(audit_dir=ad) == {"2020-01-01.ndjson": "ok"}


def test_tampered_signed_source_is_never_shipped(tmp_path):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "original"})
    path = ad / "2020-01-01.ndjson"
    path.write_bytes(path.read_bytes().replace(b"original", b"forged!!"))
    sink = FakeSink()

    with pytest.raises(worm.WormUnavailable, match="signed chain"):
        worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert sink.puts == []


def test_exact_source_bytes_are_authenticated_before_shipping(tmp_path, monkeypatch):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "original"})
    source = ad / "2020-01-01.ndjson"
    original_read = worm._read_custodied_file

    def swapped_read(path, **kwargs):
        if Path(path) == source:
            return b'{"unsigned":"attacker snapshot"}\n'
        return original_read(path, **kwargs)

    monkeypatch.setattr(worm, "_read_custodied_file", swapped_read)
    sink = FakeSink()
    with pytest.raises(worm.WormUnavailable, match="intact signed chain"):
        worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert sink.puts == []


def test_every_closed_source_requires_signed_anchor_coverage(tmp_path):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "anchored"})
    assert AuditSigner(ad / "2020-01-02.ndjson").write(
        {"kind": "test", "content": "signed but not anchored"}
    )
    sink = FakeSink()

    with pytest.raises(worm.WormUnavailable, match="intact signed chain"):
        worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert sink.puts == []


def test_tampered_signed_manifest_fails_closed(tmp_path):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "original"})
    sink = worm.LocalWormSink(ad / "worm" / "store")
    worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    manifest = ad / "worm" / "manifest.ndjson"
    manifest.write_bytes(manifest.read_bytes().replace(b'"schema": 1', b'"schema": 9'))

    assert worm.verify(audit_dir=ad) == {"2020-01-01.ndjson": "manifest invalid"}
    with pytest.raises(worm.WormUnavailable, match="manifest signature"):
        worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)


def test_exact_manifest_bytes_must_carry_valid_signatures(tmp_path, monkeypatch):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "original"})
    sink = worm.LocalWormSink(ad / "worm" / "store")
    worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    manifest = ad / "worm" / "manifest.ndjson"
    signed = json.loads(manifest.read_text(encoding="utf-8").splitlines()[-1])
    forged = {
        key: value
        for key, value in signed.items()
        if key not in {"prev_hash", "key_id", "hash", "sig"}
    }
    forged["sha256"] = "f" * 64
    forged_bytes = (json.dumps(forged) + "\n").encode()
    original_read = worm._read_custodied_file

    def swapped_read(path, **kwargs):
        if Path(path) == manifest:
            return forged_bytes
        return original_read(path, **kwargs)

    monkeypatch.setattr(worm, "_read_custodied_file", swapped_read)
    with pytest.raises(worm.WormUnavailable, match="manifest signature"):
        worm._load_manifest(ad)


def test_concurrent_manifest_appends_form_one_verified_chain(tmp_path):
    ad = tmp_path / "audit"
    ad.mkdir()
    retain = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc).isoformat()

    def append(i: int) -> None:
        name = f"2020-01-{i + 1:02d}.ndjson"
        worm._append_manifest(ad, {
            "name": name,
            "sha256": worm._sha256(name.encode()),
            "pushed_at": "2026-01-01T00:00:00+00:00",
            "retain_until": retain,
            "locator": {
                "target": "fake", "name": name, "retain_until": retain,
            },
        })

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(20)))

    manifest = ad / "worm" / "manifest.ndjson"
    assert verify_chain(manifest) == []
    assert len(worm._load_manifest(ad)) == 20


# --- local sink -------------------------------------------------------------

def test_local_sink_writes_readonly_versioned(tmp_path):
    sink = worm.LocalWormSink(tmp_path / "worm")
    ru = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
    loc1 = sink.put("2020-01-01.ndjson", b"a", retain_until=ru)
    loc2 = sink.put("2020-01-01.ndjson", b"a2", retain_until=ru)
    p1, p2 = Path(loc1["path"]), Path(loc2["path"])
    assert p1 != p2 and p1.exists() and p2.exists()   # re-push kept the prior copy
    mode = stat.S_IMODE(p1.stat().st_mode)
    # Windows exposes chmod's DOS read-only bit as 0444; the protected DACL is
    # the confidentiality boundary there. POSIX can express owner-read only.
    assert mode == (0o444 if os.name == "nt" else 0o400)
    assert p1.read_bytes() == b"a" and p2.read_bytes() == b"a2"


def test_local_sink_rejects_symlinked_signed_locator(tmp_path):
    sink = worm.LocalWormSink(tmp_path / "worm")
    ru = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
    locator = sink.put("2020-01-01.ndjson", b"evidence", retain_until=ru)
    original = Path(locator["path"])
    replacement = original.with_name(
        "2020-01-01.ndjson.1234567890-" + "a" * 32
    )
    replacement.write_bytes(b"evidence")
    os.chmod(original, 0o600)
    original.unlink()
    try:
        original.symlink_to(replacement)
    except OSError:
        pytest.skip("symlink creation is unavailable to this Windows account")

    assert not sink.verify(locator, worm._sha256(b"evidence"))


def test_push_then_verify_through_local_sink(tmp_path):
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "a\n"})
    sink = worm.LocalWormSink(ad / "worm" / "store")
    worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert worm.verify(audit_dir=ad) == {"2020-01-01.ndjson": "ok"}


# --- s3 sink (boto3 mocked) -------------------------------------------------

def test_s3_sink_put_uses_object_lock(monkeypatch):
    calls = {}

    class _FakeS3:
        def put_object(self, **kw):
            calls.update(kw)
            return {"VersionId": "version-1"}

    class _FakeBoto3:
        @staticmethod
        def client(*a, **k):
            return _FakeS3()

    monkeypatch.setitem(__import__("sys").modules, "boto3", _FakeBoto3)
    sink = worm.S3WormSink(bucket="b", prefix="audit/", mode="compliance")
    ru = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
    loc = sink.put("2020-01-01.ndjson", b"data", retain_until=ru)
    assert calls["Bucket"] == "b"
    assert calls["Key"] == "audit/2020-01-01.ndjson"
    assert calls["ObjectLockMode"] == "COMPLIANCE"
    assert calls["ObjectLockRetainUntilDate"] == ru
    assert loc["target"] == "s3" and loc["mode"] == "COMPLIANCE"
    assert loc["version_id"] == "version-1"
    assert loc["authority_id"] == sink._authority_id()


def test_s3_sink_requires_versioned_object_lock_response(monkeypatch):
    class _FakeS3:
        @staticmethod
        def put_object(**kw):
            return {}

    class _FakeBoto3:
        @staticmethod
        def client(*a, **k):
            return _FakeS3()

    monkeypatch.setitem(__import__("sys").modules, "boto3", _FakeBoto3)
    sink = worm.S3WormSink(bucket="b")
    with pytest.raises(worm.WormUnavailable, match="VersionId"):
        sink.put(
            "2020-01-01.ndjson", b"data",
            retain_until=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc),
        )


def test_s3_verification_binds_version_mode_and_retention():
    until = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
    data = b"immutable"

    class _Body:
        @staticmethod
        def read():
            return data

    class _FakeS3:
        @staticmethod
        def get_object(**kw):
            return {"Body": _Body(), "VersionId": kw["VersionId"]}

        @staticmethod
        def get_object_retention(**kw):
            return {
                "Retention": {"Mode": "COMPLIANCE", "RetainUntilDate": until}
            }

    sink = worm.S3WormSink(bucket="trusted", prefix="audit/", mode="COMPLIANCE")
    sink._client = _FakeS3()
    locator = {
        "target": "s3", "bucket": "trusted",
        "key": "audit/2020-01-01.ndjson", "mode": "COMPLIANCE",
        "version_id": "v1", "retain_until": until.isoformat(),
        "authority_id": sink._authority_id(),
    }
    assert sink.verify(locator, worm._sha256(data))
    assert not sink.verify({**locator, "bucket": "redirected"}, worm._sha256(data))
    assert not sink.verify({**locator, "version_id": ""}, worm._sha256(data))
    assert not sink.verify({**locator, "authority_id": "0" * 64}, worm._sha256(data))


def test_s3_verification_requires_returned_version_identity():
    until = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
    data = b"immutable"

    class _Body:
        @staticmethod
        def read():
            return data

    class _FakeS3:
        @staticmethod
        def get_object(**kw):
            return {"Body": _Body()}  # endpoint ignored requested VersionId

        @staticmethod
        def get_object_retention(**kw):
            return {
                "Retention": {"Mode": "COMPLIANCE", "RetainUntilDate": until}
            }

    sink = worm.S3WormSink(bucket="trusted", prefix="audit/", mode="COMPLIANCE")
    sink._client = _FakeS3()
    locator = {
        "target": "s3", "bucket": "trusted",
        "key": "audit/2020-01-01.ndjson", "mode": "COMPLIANCE",
        "version_id": "v1", "retain_until": until.isoformat(),
        "authority_id": sink._authority_id(),
    }
    assert not sink.verify(locator, worm._sha256(data))


def test_local_sink_rejects_path_forming_object_name(tmp_path):
    sink = worm.LocalWormSink(tmp_path / "worm")
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        sink.put(
            "../2020-01-01.ndjson", b"data",
            retain_until=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc),
        )


def test_s3_sink_rejects_bad_mode():
    with pytest.raises(worm.WormUnavailable):
        worm.S3WormSink(bucket="b", mode="whenever")


def test_worm_enabled_env_and_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_AUDIT_WORM", raising=False)
    monkeypatch.setattr(worm, "_worm_cfg", dict)
    assert worm.worm_enabled() is False
    monkeypatch.setattr(worm, "_worm_cfg", lambda: {"provider": "s3"})
    assert worm.worm_enabled() is True
    monkeypatch.setenv("MAVERICK_AUDIT_WORM", "0")
    assert worm.worm_enabled() is False   # env wins


def test_push_refuses_unsealed_plaintext_when_sealing_active(tmp_path, monkeypatch):
    # WORM must never lock PLAINTEXT audit data under a multi-year
    # immutable retention. When sealing is active (at-rest on + key present) an
    # unsealed closed day-file is refused until `audit seal` runs.
    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "plaintext event\n"})
    monkeypatch.setattr(worm, "_at_rest_sealing_active", lambda: True)
    sink = FakeSink()
    rep = worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert "refused: unsealed plaintext" in rep["2020-01-01.ndjson"]
    assert sink.puts == []   # nothing shipped


def test_push_allows_when_sealing_inactive(tmp_path, monkeypatch):
    # An explicit encryption opt-out permits plaintext WORM export.
    from maverick import crypto_at_rest

    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "plaintext event\n"})
    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: False)

    def _must_not_probe(_data):  # pragma: no cover - assertion is the test
        raise AssertionError("disabled sealing must not resolve a key or crypto backend")

    monkeypatch.setattr(crypto_at_rest, "seal", _must_not_probe)
    sink = FakeSink()
    rep = worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)
    assert rep["2020-01-01.ndjson"] == "pushed"
    assert len(sink.puts) == 1


def test_push_refuses_plaintext_when_configured_sealing_is_unavailable(
    tmp_path, monkeypatch,
):
    """A key/KMS/crypto outage must not be interpreted as an encryption opt-out."""
    from maverick import crypto_at_rest

    ad = _audit_dir(tmp_path, {"2020-01-01.ndjson": "sensitive plaintext\n"})
    # This test needs the REAL sealing-active logic (the autouse fixture
    # pins it off for the plaintext-mechanics tests).
    monkeypatch.setattr(worm, "_at_rest_sealing_active", _REAL_SEALING_ACTIVE)
    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: True)

    def _outage(_data):
        raise crypto_at_rest.EncryptionUnavailable("kms unavailable")

    monkeypatch.setattr(crypto_at_rest, "seal", _outage)
    sink = FakeSink()

    with pytest.raises(worm.WormUnavailable, match="sealing is unavailable"):
        worm.push_closed_dayfiles(audit_dir=ad, today="2025-01-01", sink=sink)

    assert sink.puts == []
    assert not (ad / "worm").exists()
