"""Offline repair trust regressions; no native inspector or provider executes."""
import contextlib
import json

import pytest
from maverick import installation_offline as offline


def metadata(tmp_path, **changes):
    release = dict(version="1.2.3", signature="signed", runtime_sha256="a" * 64, installer_sha256="b" * 64)
    release.update(changes)
    (tmp_path / "downloads.json").write_text(json.dumps({"public_key": "pinned", "new": release}))


def test_wrong_version_refused_before_inspection(tmp_path, monkeypatch):
    metadata(tmp_path, version="1.2.2")
    monkeypatch.setattr(offline.recovery.workspace_recovery, "version", lambda: "1.2.3")
    monkeypatch.setattr(offline.recovery, "repair_capability", lambda **kwargs: pytest.fail("must reject first"))
    with pytest.raises(offline.recovery.MaintenanceError, match="exact installed version"):
        offline.review(str(tmp_path), public_key="pinned")


def test_wrong_key_refused_before_inspection(tmp_path):
    metadata(tmp_path)
    with pytest.raises(offline.recovery.MaintenanceError, match="cannot change"):
        offline.review(str(tmp_path), public_key="different")


def test_a_key_holding_a_lone_surrogate_is_refused_not_a_crash(tmp_path):
    release = dict(version="1.2.3", signature="signed", runtime_sha256="a" * 64, installer_sha256="b" * 64)
    # json.dumps writes the escape "\\ud800"; reading it back yields an unencodable character.
    (tmp_path / "downloads.json").write_text(json.dumps({"public_key": "\ud800", "new": release}))
    with pytest.raises(offline.recovery.MaintenanceError, match="cannot change"):
        offline.review(str(tmp_path), public_key="pinned")


def test_changed_cached_package_cannot_authorize(tmp_path, monkeypatch):
    monkeypatch.setattr(offline.recovery, "_locked", contextlib.nullcontext)
    monkeypatch.setattr(offline, "_directory", lambda identifier: tmp_path)
    monkeypatch.setattr(offline.recovery, "_read", lambda path: {"kind": "offline-repair-review", "expires_at": 99999999999, "release": {"installer_sha256": "b" * 64}})
    monkeypatch.setattr(offline.backup, "_sha256", lambda path: "c" * 64)
    monkeypatch.setattr(offline.recovery, "authorize_repair", lambda **kwargs: pytest.fail("changed bytes cannot authorize"))
    with pytest.raises(offline.recovery.MaintenanceError, match="installer changed"):
        offline.authorize("a" * 32, confirm=True)


# ---- review(): the folder, the key, the cache and the publisher check ----------

def review_ready(tmp_path, monkeypatch, *, thumbprint="A" * 40, cache=None):
    """Everything review() needs, with only the Windows trust engine replaced."""
    folder = tmp_path / "selected"
    folder.mkdir()
    metadata(folder)
    (folder / "new.msi").write_bytes(b"msi")
    cache = cache or tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    recovery = offline.recovery
    monkeypatch.setattr(recovery, "_locked", contextlib.nullcontext)
    monkeypatch.setattr(offline, "_root", lambda: cache)
    monkeypatch.setattr(offline, "_directory", lambda identifier: cache / identifier)
    monkeypatch.setattr(recovery.workspace_recovery, "version", lambda: "1.2.3")
    monkeypatch.setattr(recovery, "_target", lambda: "installation-a")
    monkeypatch.setattr(recovery, "_write", lambda path, record: path.write_text(json.dumps(record)))
    monkeypatch.setattr(recovery, "_read", lambda path: json.loads(path.read_text()))
    monkeypatch.setattr(recovery, "_copy_retained_source", lambda source, target, digest: target.write_bytes(b"msi"))
    monkeypatch.setattr(recovery, "repair_capability", lambda **kwargs: {
        "product_code": "P", "package_code": "K", "publisher_thumbprint": thumbprint, "runtime_role": "primary"})
    monkeypatch.setattr(recovery, "_installer", lambda directory, meta, label: {
        "sha256": "b" * 64, "product_code": "P", "package_code": "K", "publisher_thumbprint": "A" * 40})
    return folder, cache


def test_review_succeeds_when_no_install_time_package_supplies_a_publisher(tmp_path, monkeypatch):
    # Offline repair exists for the installation whose retained package is gone;
    # the core repair path compares a publisher only when both sides have one.
    folder, _ = review_ready(tmp_path, monkeypatch, thumbprint=None)
    assert offline.review(str(folder), public_key="pinned")["verified"] is True


def test_review_still_refuses_a_different_publisher(tmp_path, monkeypatch):
    folder, _ = review_ready(tmp_path, monkeypatch, thumbprint="B" * 40)
    with pytest.raises(offline.recovery.MaintenanceError, match="does not match the installed Windows product"):
        offline.review(str(folder), public_key="pinned")


def test_an_interrupted_review_directory_does_not_block_every_later_review(tmp_path, monkeypatch):
    folder, cache = review_ready(tmp_path, monkeypatch)
    (cache / ("a" * 32)).mkdir()            # the helper stopped before writing review.json
    unreadable = cache / ("b" * 32)
    unreadable.mkdir()
    (unreadable / "review.json").write_text("{not json")
    assert offline.review(str(folder), public_key="pinned")["verified"] is True
    assert not (cache / ("a" * 32)).exists() and not unreadable.exists()


@pytest.mark.parametrize("folder", ["//server/share/package", "\\\\server\\share\\package"])
def test_network_shares_are_refused_in_either_slash_style(folder):
    with pytest.raises(offline.recovery.MaintenanceError, match="network shares"):
        offline.review(folder, public_key="pinned")


def test_a_folder_that_is_gone_gets_the_plain_instruction_not_an_operating_system_error(tmp_path):
    with pytest.raises(offline.recovery.MaintenanceError, match="Select the local folder"):
        offline.review(str(tmp_path / "ejected-drive"), public_key="pinned")
    with pytest.raises(offline.recovery.MaintenanceError, match="Select the local folder"):
        offline.review(str(tmp_path) + "\x00", public_key="pinned")


def test_a_non_ascii_key_is_a_refusal_not_a_type_error(tmp_path):
    (tmp_path / "downloads.json").write_text(json.dumps({"public_key": "clé", "new": {}}), encoding="utf-8")
    with pytest.raises(offline.recovery.MaintenanceError, match="cannot change"):
        offline.review(str(tmp_path), public_key="cle")


def test_a_failed_review_reports_its_own_error_even_if_cleanup_also_fails(tmp_path, monkeypatch):
    folder, _ = review_ready(tmp_path, monkeypatch)
    monkeypatch.setattr(offline.recovery, "_installer", lambda *args: (_ for _ in ()).throw(
        offline.recovery.MaintenanceError("signature rejected")))
    def blocked(directory):
        raise offline.recovery.MaintenanceError("The private offline cache needs administrator inspection.")
    monkeypatch.setattr(offline, "_cleanup", blocked)
    with pytest.raises(offline.recovery.MaintenanceError, match="signature rejected"):
        offline.review(str(folder), public_key="pinned")


# ---- authorize(): a grant that cannot be staged must not stay behind ------------

def test_a_grant_that_cannot_be_staged_is_retired_and_the_review_stays_unused(tmp_path, monkeypatch):
    recovery = offline.recovery
    review_directory = tmp_path / "review"
    review_directory.mkdir()
    (review_directory / "new.msi").write_bytes(b"msi")
    row = {"kind": "offline-repair-review", "expires_at": 99999999999, "used": False, "public_key": "pinned",
           "release": {"version": "1.2.3", "runtime_sha256": "a" * 64, "installer_sha256": "b" * 64, "signature": "s"}}
    saved = []
    monkeypatch.setattr(recovery, "_locked", contextlib.nullcontext)
    monkeypatch.setattr(offline, "_review", lambda identifier: (review_directory, dict(row)))
    monkeypatch.setattr(recovery, "authorize_repair", lambda **kwargs: {
        "directory": str(tmp_path / "grant"), "authorization": "g" * 32 + ":" + "n" * 64})
    monkeypatch.setattr(recovery, "_write", lambda path, record: saved.append(record))
    monkeypatch.setattr(recovery, "_copy_retained_source", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    discarded = []
    monkeypatch.setattr(recovery, "discard_authorization", lambda token, *, actor: discarded.append((token, actor)))
    with pytest.raises(OSError, match="disk full"):
        offline.authorize("c" * 32, confirm=True)
    assert discarded == [("g" * 32 + ":" + "n" * 64, "native-offline-repair")]
    assert saved == []                                  # the review was not marked used


def test_a_used_review_releases_its_private_copy_of_the_installer(tmp_path, monkeypatch):
    recovery = offline.recovery
    review_directory = tmp_path / "review"
    grant_directory = tmp_path / "grant"
    review_directory.mkdir()
    grant_directory.mkdir()
    (review_directory / "new.msi").write_bytes(b"msi")
    row = {"kind": "offline-repair-review", "expires_at": 99999999999, "used": False, "public_key": "pinned",
           "release": {"version": "1.2.3", "runtime_sha256": "a" * 64, "installer_sha256": "b" * 64, "signature": "s"}}
    saved = []
    monkeypatch.setattr(recovery, "_locked", contextlib.nullcontext)
    monkeypatch.setattr(offline, "_review", lambda identifier: (review_directory, dict(row)))
    monkeypatch.setattr(recovery, "authorize_repair", lambda **kwargs: {
        "directory": str(grant_directory), "authorization": "g" * 32 + ":" + "n" * 64})
    monkeypatch.setattr(recovery, "_write", lambda path, record: saved.append(record))
    monkeypatch.setattr(recovery, "_copy_retained_source", lambda source, target, digest: target.write_bytes(b"msi"))
    monkeypatch.setattr(recovery, "discard_authorization", lambda *args, **kwargs: pytest.fail("a staged grant is kept"))
    offline.authorize("c" * 32, confirm=True)
    assert saved[0]["used"] is True
    assert (grant_directory / "new.msi").exists() and (grant_directory / "downloads.json").exists()
    assert not (review_directory / "new.msi").exists()
