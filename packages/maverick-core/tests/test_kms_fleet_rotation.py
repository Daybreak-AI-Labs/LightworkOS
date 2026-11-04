"""Operable, resumable fleet KEK rotation."""
from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from maverick.crypto_at_rest import EncryptionUnavailable  # noqa: E402
from maverick.tenant import kms as K  # noqa: E402
from maverick.tenant import kms_fleet as F  # noqa: E402

_OLD = "ab" * 32  # hex KEKs
_NEW = "cd" * 32


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setenv("MAVERICK_KMS_KEK", _OLD)  # seal under the OLD kek
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    K._clear_cache()
    yield
    K._clear_cache()


def _provision(*tenant_ids: str) -> None:
    from maverick.tenant import registry
    old_kms = K.LocalKMS(bytes.fromhex(_OLD))
    for tid in tenant_ids:
        registry.create_tenant(tid)
        K.seal_for_tenant(tid, b"data-" + tid.encode(), kms=old_kms)  # mints a DEK
    K._clear_cache()


def test_rotates_all_provisioned_tenants():
    _provision("a", "b")
    rep = F.rotate_local_fleet(_OLD, _NEW)
    assert set(rep["rotated"]) == {"a", "b"}
    assert rep["failed"] == {}
    # Data is now readable under the NEW kek; the OLD kek can no longer unwrap.
    new_kms = K.LocalKMS(bytes.fromhex(_NEW))
    K._clear_cache()
    assert K.unseal_for_tenant("a", K.seal_for_tenant("a", b"x", kms=new_kms), kms=new_kms)
    K._clear_cache()
    with pytest.raises(EncryptionUnavailable):
        K.tenant_dek("a", kms=K.LocalKMS(bytes.fromhex(_OLD)))


def test_idempotent_resumable_second_run_skips():
    _provision("a", "b")
    F.rotate_local_fleet(_OLD, _NEW)        # full rotation
    K._clear_cache()
    rep2 = F.rotate_local_fleet(_OLD, _NEW)  # re-run
    assert rep2["rotated"] == []
    assert set(rep2["skipped"]) == {"a", "b"}   # already on new -> skipped
    assert rep2["failed"] == {}


def test_resumes_after_partial_rotation():
    # Simulate an interruption: rotate only 'a' by hand, then run the fleet --
    # 'a' is skipped (already new), 'b' is rotated.
    _provision("a", "b")
    K.rotate_kek_idempotent(
        "a", old_kms=K.LocalKMS(bytes.fromhex(_OLD)),
        new_kms=K.LocalKMS(bytes.fromhex(_NEW)))
    K._clear_cache()
    rep = F.rotate_local_fleet(_OLD, _NEW)
    assert rep["skipped"] == ["a"]
    assert rep["rotated"] == ["b"]


def test_dry_run_writes_nothing_but_projects_outcomes():
    _provision("a", "b")
    rep = F.rotate_local_fleet(_OLD, _NEW, dry_run=True)
    assert rep["dry_run"] is True
    assert set(rep["rotated"]) == {"a", "b"}     # WOULD rotate
    # Nothing actually changed: OLD kek still opens the DEKs.
    K._clear_cache()
    assert K.tenant_dek("a", kms=K.LocalKMS(bytes.fromhex(_OLD)))


def test_wrong_old_kek_is_isolated_failure_not_crash():
    _provision("a")
    bogus = "11" * 32
    rep = F.rotate_local_fleet(bogus, _NEW)   # neither old(bogus) nor new opens it
    assert "a" in rep["failed"]
    assert rep["rotated"] == []


def test_bad_kek_length_raises():
    _provision("a")
    with pytest.raises(EncryptionUnavailable):
        F.rotate_local_fleet("00", _NEW)      # 1 byte -> not a 32-byte KEK


def test_cli_kms_rotate_reads_keks_from_files(tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main

    _provision("a")
    old_file = tmp_path / "old-kek"
    new_file = tmp_path / "new-kek"
    old_file.write_text(_OLD + "\n", encoding="utf-8")
    new_file.write_text(_NEW + "\n", encoding="utf-8")

    res = CliRunner().invoke(main, [
        "tenant", "kms-rotate",
        "--old-kek-file", str(old_file),
        "--new-kek-file", str(new_file),
        "--dry-run",
    ])

    assert res.exit_code == 0, res.output
    assert "fleet KEK rotation (dry run): 1 tenant(s) with a DEK" in res.output


def test_cli_kms_rotate_rejects_raw_kek_argv():
    from click.testing import CliRunner
    from maverick.cli import main

    res = CliRunner().invoke(main, [
        "tenant", "kms-rotate",
        "--old-kek", _OLD,
        "--new-kek", _NEW,
        "--dry-run",
    ])

    assert res.exit_code != 0
    # The raw KEK option is rejected (only --old-kek-file is accepted, so secrets
    # never land in argv). Match on the option name, not click's exact phrasing,
    # which varies by version ("No such option: --old-kek" vs. "No such option
    # '--old-kek'. Did you mean '--old-kek-file'?").
    assert "No such option" in res.output and "--old-kek" in res.output
