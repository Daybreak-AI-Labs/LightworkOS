"""Workspace snapshot / restore."""
from __future__ import annotations

import errno
import os
import tarfile

import pytest
from maverick.workspace_snapshot import (
    create_snapshot,
    list_snapshots,
    restore_snapshot,
    workspace_snapshot,
)


class _SB:
    """Minimal sandbox stub exposing a workdir confinement root."""

    def __init__(self, workdir):
        self.workdir = str(workdir)


def _symlink_or_skip(link, target, *, target_is_directory=False):
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except NotImplementedError as exc:
        if os.name == "nt":
            pytest.skip(f"symlinks are unavailable on this Windows host: {exc}")
        raise
    except OSError as exc:
        # Windows may require Developer Mode or SeCreateSymbolicLinkPrivilege.
        # Never hide an unexpected POSIX path/filesystem regression as a
        # capability skip.
        if os.name == "nt" and (
            getattr(exc, "winerror", None) == 1314
            or exc.errno in {errno.EPERM, errno.EACCES}
        ):
            pytest.skip(f"Windows symlink privilege is unavailable: {exc}")
        raise


def _src(tmp_path):
    src = tmp_path / "work"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("alpha", encoding="utf-8")
    (src / "sub" / "b.txt").write_text("beta", encoding="utf-8")
    return src


def test_snapshot_then_restore_roundtrip(tmp_path):
    src = _src(tmp_path)
    store = tmp_path / "snaps"
    man = create_snapshot(src, store, label="before edit")
    assert man["id"] == "snap-0001"
    assert man["files"] == 2

    dest = tmp_path / "restored"
    res = restore_snapshot(store, "snap-0001", dest)
    assert res["restored"] == 2
    assert (dest / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert (dest / "sub" / "b.txt").read_text(encoding="utf-8") == "beta"


def test_restore_removes_files_added_after_snapshot(tmp_path):
    """Reverting an ADDITIVE change must delete files the patch created.
    Regression: restore only extracted members, so an added file survived the
    rollback while restore still reported success -- the revert silently
    no-op'd the add."""
    src = _src(tmp_path)                       # state A: a.txt, sub/b.txt
    store = tmp_path / "snaps"
    man = create_snapshot(src, store, label="state-A")

    # State B: a patch ADDS a new file and a whole new subdir, and edits an
    # existing file (to prove restore still overwrites the edit).
    (src / "added.txt").write_text("NEW", encoding="utf-8")
    (src / "newdir").mkdir()
    (src / "newdir" / "nested.txt").write_text("NEW2", encoding="utf-8")
    (src / "a.txt").write_text("EDITED", encoding="utf-8")

    res = restore_snapshot(store, man["id"], src)   # in-place rollback

    # The added file and added subdir are GONE.
    assert not (src / "added.txt").exists()
    assert not (src / "newdir").exists()
    # The edited file is back to its snapshot content.
    assert (src / "a.txt").read_text(encoding="utf-8") == "alpha"
    # The untouched snapshot file survives.
    assert (src / "sub" / "b.txt").read_text(encoding="utf-8") == "beta"
    assert res["restored"] == 2
    assert res["removed"] == 3   # added.txt + newdir/nested.txt + empty newdir


def test_ids_increment_and_list_newest_first(tmp_path):
    src = _src(tmp_path)
    store = tmp_path / "snaps"
    create_snapshot(src, store, label="one")
    create_snapshot(src, store, label="two")
    snaps = list_snapshots(store)
    assert [s["id"] for s in snaps] == ["snap-0002", "snap-0001"]
    assert snaps[0]["label"] == "two"


def test_snapshot_rejects_missing_dir(tmp_path):
    with pytest.raises(ValueError):
        create_snapshot(tmp_path / "nope", tmp_path / "snaps")


def test_failed_archive_leaves_no_corrupt_snapshot(tmp_path, monkeypatch):
    # State-corruption-on-error guard: if archiving fails partway, the store
    # must NOT be left with a truncated snap-*.tar.gz that list_snapshots
    # surfaces and a later restore chokes on. The build goes to a temp file
    # that is atomically renamed only on success.
    src = _src(tmp_path)
    store = tmp_path / "snaps"

    real_add = tarfile.TarFile.add

    def boom_add(self, *a, **k):
        # Let the tar header start, then fail mid-archive (e.g. disk full).
        raise OSError("simulated write failure mid-archive")

    monkeypatch.setattr(tarfile.TarFile, "add", boom_add)
    with pytest.raises(OSError):
        create_snapshot(src, store, label="doomed")
    monkeypatch.setattr(tarfile.TarFile, "add", real_add)

    # No snapshot (corrupt or otherwise) and no leftover temp file.
    assert list_snapshots(store) == []
    assert list(store.glob("snap-*")) == []
    assert list(store.glob("*.tmp")) == []

    # The store is still usable: a subsequent snapshot succeeds and reuses id 1
    # (the failed attempt never claimed a discoverable name).
    man = create_snapshot(src, store, label="recovered")
    assert man["id"] == "snap-0001"
    assert list_snapshots(store)[0]["label"] == "recovered"


def test_restore_unknown_id_errors(tmp_path):
    store = tmp_path / "snaps"
    store.mkdir()
    with pytest.raises(ValueError):
        restore_snapshot(store, "snap-0009", tmp_path / "out")


def test_restore_blocks_path_traversal(tmp_path):
    """A tarbomb member with ../ must not escape the destination."""
    store = tmp_path / "snaps"
    store.mkdir()
    evil = store / "snap-0001-evil.tar.gz"
    payload = tmp_path / "payload"
    payload.write_text("pwned", encoding="utf-8")
    with tarfile.open(evil, "w:gz") as tar:
        tar.add(payload, arcname="../escape.txt")
    with pytest.raises(ValueError):
        restore_snapshot(store, "snap-0001", tmp_path / "dest")
    assert not (tmp_path / "escape.txt").exists()


def test_rollback_in_place_with_outward_symlink_completes(tmp_path):
    """A workspace containing an outward-pointing symlink must still roll back
    fully. Regression: the containment check .resolve()'d the pre-existing
    symlink out of dest and raised, aborting the restore and leaving members
    that sorted after the symlink (the very file being rolled back) unrestored."""
    src = tmp_path / "work"
    src.mkdir()
    (src / "z_important.txt").write_text("ORIGINAL", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    _symlink_or_skip(src / "00_current", outside)  # outward, sorts first
    store = tmp_path / "snaps"
    man = create_snapshot(src, store, label="cp")
    # symlink is not restorable, so it must not be counted in the manifest
    assert man["files"] == 1

    (src / "z_important.txt").write_text("CORRUPTED", encoding="utf-8")
    res = restore_snapshot(store, man["id"], src)  # rollback in place
    assert res["restored"] == 1
    assert res["skipped_links"] == 1
    assert (src / "z_important.txt").read_text(encoding="utf-8") == "ORIGINAL"


def test_restore_still_blocks_traversal_through_symlinked_subdir(tmp_path):
    """Skipping link members and lexical containment must not weaken the
    traversal guard: a regular-file member with ../ still escapes-> rejected."""
    store = tmp_path / "snaps"
    store.mkdir()
    evil = store / "snap-0001-evil.tar.gz"
    payload = tmp_path / "payload"
    payload.write_text("pwned", encoding="utf-8")
    with tarfile.open(evil, "w:gz") as tar:
        tar.add(payload, arcname="../escape.txt")
    with pytest.raises(ValueError):
        restore_snapshot(store, "snap-0001", tmp_path / "dest")
    assert not (tmp_path / "escape.txt").exists()


def test_restore_blocks_legacy_extract_through_preexisting_symlink(tmp_path, monkeypatch):
    src = tmp_path / "src"
    (src / "cache").mkdir(parents=True)
    (src / "cache" / "pwn.txt").write_text("owned", encoding="utf-8")
    store = tmp_path / "snaps"
    man = create_snapshot(src, store, label="safe")

    dest = tmp_path / "dest"
    outside = tmp_path / "outside"
    dest.mkdir()
    outside.mkdir()
    _symlink_or_skip(dest / "cache", outside, target_is_directory=True)

    real_extract = tarfile.TarFile.extract

    def legacy_extract(self, member, path="", set_attrs=True, *, numeric_owner=False,
                       filter=None):
        if filter is not None:
            raise TypeError("legacy tarfile has no filter kwarg")
        return real_extract(
            self, member, path, set_attrs=set_attrs, numeric_owner=numeric_owner)

    monkeypatch.setattr(tarfile.TarFile, "extract", legacy_extract)
    with pytest.raises(ValueError, match="follows a link outside destination"):
        restore_snapshot(store, man["id"], dest)
    assert not (outside / "pwn.txt").exists()

def test_tool_snapshot_confined_to_workspace(tmp_path):
    # HOME is isolated by the autouse conftest, so the store lands under tmp.
    work = tmp_path / "work"
    work.mkdir()
    (work / "f.txt").write_text("x", encoding="utf-8")
    out = workspace_snapshot(_SB(work)).fn({"op": "snapshot", "path": "."})
    assert out.startswith("created snap-")


def test_tool_snapshot_rejects_source_escape(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    out = workspace_snapshot(_SB(work)).fn({"op": "snapshot", "path": "../../"})
    assert out.startswith("ERROR") and "escape" in out.lower()


def test_tool_restore_rejects_dest_escape(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    out = workspace_snapshot(_SB(work)).fn(
        {"op": "restore", "id": "snap-0001", "dest": "/tmp/evil-restore"})
    assert out.startswith("ERROR") and "escape" in out.lower()


def test_store_dir_is_resolved_per_tenant(tmp_path, monkeypatch):
    """Regression: the store was fixed at import time and shared by every
    tenant, so one tenant could list and restore another tenant's archives."""
    from maverick.paths import tenant_scope
    from maverick.workspace_snapshot import store_dir

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    with tenant_scope(tenant="acme"):
        acme = store_dir()
    with tenant_scope(tenant="globex"):
        globex = store_dir()
    assert acme != globex
    assert "tenants" in acme.parts and "tenants" in globex.parts


def test_restore_into_other_directory_never_deletes(tmp_path):
    """Regression: restoring a snapshot of ``ws/sub`` into ``ws`` deleted every
    file in ``ws`` the archive did not contain."""
    ws = tmp_path / "ws"
    (ws / "sub").mkdir(parents=True)
    (ws / "sub" / "s.txt").write_text("s", encoding="utf-8")
    (ws / "important.txt").write_text("keep", encoding="utf-8")
    store = tmp_path / "snaps"
    man = create_snapshot(ws / "sub", store)

    res = restore_snapshot(store, man["id"], ws)

    assert (ws / "important.txt").read_text(encoding="utf-8") == "keep"
    assert (ws / "sub" / "s.txt").exists()
    assert res["removed"] == 0 and res["reconciled"] is False


def test_ids_past_9999_stay_unique_and_store_is_capped(tmp_path, monkeypatch):
    """Regression: ids overflowed into a repeated ``snap-10000`` that was
    silently overwritten and never listed; and nothing capped the store."""
    import maverick.workspace_snapshot as mod

    src = _src(tmp_path)
    store = tmp_path / "snaps"
    store.mkdir()
    (store / "snap-9999.tar.gz").write_bytes(b"")
    first = create_snapshot(src, store)
    second = create_snapshot(src, store)
    assert (first["id"], second["id"]) == ("snap-10000", "snap-10001")
    assert [s["id"] for s in list_snapshots(store)] == [
        "snap-10001", "snap-10000", "snap-9999"]
    assert restore_snapshot(store, "snap-10000", tmp_path / "r")["id"] == "snap-10000"

    monkeypatch.setattr(mod, "_MAX_SNAPSHOTS", 3)
    with pytest.raises(ValueError, match="store is full"):
        create_snapshot(src, store)
    # The tool reply tells the model that an operator must act, and where.
    monkeypatch.setattr(mod, "store_dir", lambda: store)
    out = workspace_snapshot(_SB(src)).fn({"op": "snapshot", "path": "."})
    assert "store is full" in out and "operator must remove" in out
    assert str(store) in out


def _legacy_archive(src, store, num="0001"):
    """An archive as written before the source directory was recorded."""
    store.mkdir(parents=True, exist_ok=True)
    path = store / f"snap-{num}.tar.gz"
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        tar.add(src, arcname=".", recursive=True)
    return path


def test_legacy_archive_keeps_added_files_unless_caller_opts_in(tmp_path, monkeypatch):
    """An archive without a recorded source keeps added files (and the tool
    says so) unless the caller states the restore is in place."""
    import maverick.workspace_snapshot as mod

    src = _src(tmp_path)
    store = tmp_path / "snaps"
    _legacy_archive(src, store)
    (src / "added.txt").write_text("NEW", encoding="utf-8")
    monkeypatch.setattr(mod, "store_dir", lambda: store)

    reply = workspace_snapshot(_SB(src)).fn(
        {"op": "restore", "id": "snap-0001", "dest": "."})
    assert "were KEPT" in reply
    assert (src / "added.txt").exists()

    res = restore_snapshot(store, "snap-0001", src, legacy_in_place=True)
    assert res["reconciled"] is True
    assert not (src / "added.txt").exists()


def test_client_bound_store_warns_about_legacy_archives(tmp_path, monkeypatch, caplog):
    """Binding a client id moves the store; archives left in the shared store
    are named in a warning and in list output, never listed or served."""
    import maverick.workspace_snapshot as mod
    from maverick import paths

    home = tmp_path / "home"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    _legacy_archive(_src(tmp_path), home / "snapshots")
    monkeypatch.setattr(mod, "current_tenant", lambda: "acme")
    monkeypatch.setattr(mod, "explicit_tenant_id", lambda: None)
    monkeypatch.setattr(paths, "current_tenant", lambda: "acme")

    with caplog.at_level("WARNING"):
        out = workspace_snapshot(_SB(tmp_path)).fn({"op": "list"})
    assert out.startswith("(no snapshots)")
    assert str(home / "snapshots") in out
    assert str(home / "snapshots") in caplog.text

    # An explicitly scoped tenant on a multi-tenant host is never told.
    monkeypatch.setattr(mod, "explicit_tenant_id", lambda: "acme")
    assert workspace_snapshot(_SB(tmp_path)).fn({"op": "list"}) == "(no snapshots)"
