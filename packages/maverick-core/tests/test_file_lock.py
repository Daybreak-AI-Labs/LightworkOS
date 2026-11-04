"""Shared cross-process lock + atomic write helper (maverick.file_lock).

These back the file-race fixes across the state stores: atomic_write_text must
never leave a torn file for a concurrent reader, and cross_process_lock must
serialize a read-modify-write so concurrent writers don't lose updates.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from maverick.file_lock import (
    atomic_create_text,
    atomic_read_bytes,
    atomic_read_text,
    atomic_write_bytes,
    atomic_write_bytes_chunks,
    atomic_write_text,
    atomic_write_text_chunks,
    cross_process_lock,
    ensure_private_file,
    open_private_append,
    private_path_is_restricted,
)


def _make_shared_directory(path):
    path.mkdir(mode=0o777)
    if os.name == "nt":
        subprocess.run(
            [
                "icacls",
                str(path),
                "/grant",
                "*S-1-1-0:(OI)(CI)RX",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        path.chmod(0o755)
    assert not private_path_is_restricted(path, 0o700)


def _directory_security_snapshot(path):
    if os.name == "nt":
        import maverick.file_lock as file_lock

        return file_lock._windows_private_sddl(path)[0]
    return path.stat().st_mode & 0o777


def test_atomic_write_replaces_whole_file(tmp_path):
    p = tmp_path / "s.json"
    atomic_write_text(p, json.dumps({"a": 1}))
    assert json.loads(p.read_text()) == {"a": 1}
    atomic_write_text(p, json.dumps({"a": 2}))
    assert json.loads(p.read_text()) == {"a": 2}


def test_atomic_write_creates_parent_dirs(tmp_path):
    p = tmp_path / "nested" / "deep" / "s.txt"
    atomic_write_text(p, "hello")
    assert p.read_text() == "hello"


def test_private_file_helpers_do_not_claim_existing_shared_parent(tmp_path):
    shared = tmp_path / "shared"
    _make_shared_directory(shared)
    unrelated = shared / "unrelated.txt"
    unrelated.write_text("keep-access", encoding="utf-8")
    parent_security = _directory_security_snapshot(shared)
    unrelated_security = (
        _directory_security_snapshot(unrelated)
        if os.name == "nt"
        else unrelated.stat().st_mode & 0o777
    )

    created = shared / "created.txt"
    appended = shared / "events.jsonl"
    atomic_create_text(created, "secret")
    fd = open_private_append(appended)
    try:
        os.write(fd, b'{"event":"ok"}\n')
    finally:
        os.close(fd)

    assert _directory_security_snapshot(shared) == parent_security
    assert not private_path_is_restricted(shared, 0o700)
    assert unrelated.read_text(encoding="utf-8") == "keep-access"
    if os.name == "nt":
        assert _directory_security_snapshot(unrelated) == unrelated_security
    else:
        assert unrelated.stat().st_mode & 0o777 == unrelated_security
    assert private_path_is_restricted(created)
    assert private_path_is_restricted(appended)


def test_private_file_helper_owns_and_hardens_missing_parent(tmp_path):
    parent = tmp_path / "owned-state"
    target = parent / "secret.txt"
    atomic_create_text(target, "secret")
    assert private_path_is_restricted(parent, 0o700)
    assert private_path_is_restricted(target)


def test_atomic_write_supports_non_bmp_windows_path(tmp_path):
    p = tmp_path / "rocket-U0001f680U0001f680" / "state.json"
    atomic_write_text(p, '{"ok": true}')
    assert json.loads(p.read_text())["ok"] is True


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length paths")
def test_windows_secure_temp_and_atomic_write_beyond_max_path(tmp_path):
    """Direct Win32 calls must not regress to the legacy 260-char ceiling."""
    import maverick.file_lock as file_lock

    parent = tmp_path
    index = 0
    while len(os.path.abspath(parent)) < 220:
        remaining = 220 - len(os.path.abspath(parent)) - 1
        parent /= f"s{index}-" + ("x" * min(35, remaining - 3))
        parent.mkdir()
        index += 1
    target = parent / "state.json"

    expected_temp_length = len(os.path.abspath(parent / ".state.json-")) + 36
    assert len(os.path.abspath(target)) < 260
    assert expected_temp_length > 260
    assert file_lock._windows_extended_path(target).startswith("\\\\?\\")
    assert file_lock._windows_extended_path(
        r"\\server\share\folder\state.json"
    ) == r"\\?\UNC\server\share\folder\state.json"

    fd, temporary = file_lock._windows_secure_mkstemp(
        parent,
        prefix=".state.json-",
        suffix=".tmp",
    )
    try:
        os.write(fd, b"private")
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        assert len(temporary) > 260
        assert temporary.startswith("\\\\?\\")
        assert private_path_is_restricted(temporary)
    finally:
        os.unlink(temporary)

    atomic_write_text(target, '{"long_path": true}')
    assert json.loads(atomic_read_text(target))["long_path"] is True
    assert private_path_is_restricted(target)
    assert [entry.name for entry in parent.iterdir()] == ["state.json"]


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length paths")
def test_windows_atomic_reads_beyond_max_path(tmp_path):
    """A published file must remain readable when its final path exceeds MAX_PATH."""
    parent = tmp_path
    index = 0
    while len(os.path.abspath(parent)) < 230:
        remaining = 230 - len(os.path.abspath(parent)) - 1
        parent /= f"s{index}-" + ("x" * min(35, remaining - 3))
        parent.mkdir()
        index += 1

    text_path = parent / ("state-" + "x" * 40 + ".json")
    bytes_path = parent / ("state-" + "y" * 40 + ".bin")
    missing_path = parent / ("missing-" + "z" * 40 + ".json")
    assert len(os.path.abspath(text_path)) > 260
    assert len(os.path.abspath(bytes_path)) > 260

    atomic_write_text(text_path, '{"state": "published"}')
    atomic_write_bytes(bytes_path, b"\x00published\xff")
    assert json.loads(atomic_read_text(text_path)) == {"state": "published"}
    assert atomic_read_bytes(bytes_path) == b"\x00published\xff"
    with pytest.raises(FileNotFoundError):
        atomic_read_text(missing_path)
    with pytest.raises(FileNotFoundError):
        atomic_read_bytes(missing_path)


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length paths")
def test_windows_private_directory_helpers_create_and_verify_deep_paths(tmp_path):
    import maverick.file_lock as file_lock

    parent = tmp_path / ("s0-" + "x" * 35)
    index = 1
    while len(os.path.abspath(parent)) < 285:
        parent /= f"s{index}-" + "x" * 35
        index += 1
    assert file_lock.ensure_private_directory(parent) == parent
    assert file_lock.require_private_directory(parent) == parent
    assert file_lock.prepare_private_directory(parent) == parent
    assert private_path_is_restricted(Path(file_lock._windows_extended_path(parent)), 0o700)

    target = parent / ("r" * 64) / ("p" * 64 + ".bin")
    file_lock.atomic_create_bytes(target, b"deep private payload")
    assert atomic_read_bytes(target) == b"deep private payload"
    assert private_path_is_restricted(
        Path(file_lock._windows_extended_path(target.parent)), 0o700,
    )


def test_atomic_write_bytes_round_trips_privately_without_temp_files(tmp_path):
    p = tmp_path / "payload.bin"
    payload = bytes(range(256)) + b"\x00\xffaudit"
    atomic_write_bytes(p, payload)
    assert atomic_read_bytes(p) == payload
    assert private_path_is_restricted(p)
    assert [f.name for f in tmp_path.iterdir()] == ["payload.bin"]


def test_atomic_write_text_chunks_streams_privately(tmp_path):
    p = tmp_path / "export.jsonl"
    count = atomic_write_text_chunks(p, (f'{{"n":{i}}}\n' for i in range(3)))
    assert count == 3
    assert p.read_text(encoding="utf-8").splitlines() == [
        '{"n":0}',
        '{"n":1}',
        '{"n":2}',
    ]
    assert private_path_is_restricted(p)
    assert [f.name for f in tmp_path.iterdir()] == ["export.jsonl"]


@pytest.mark.parametrize("fail", [False, True])
def test_binary_stream_stays_private_and_unpublished_until_complete(tmp_path, fail):
    path = tmp_path / "segment.bin"
    atomic_write_bytes(path, b"original")
    class Interrupted(BaseException):
        pass
    def chunks():
        for payload in (b"\x00\xff", b"exact signed row\n"):
            assert path.read_bytes() == b"original"
            temporary = list(tmp_path.glob(".segment.bin-*.tmp"))
            assert len(temporary) == 1
            assert private_path_is_restricted(temporary[0])
            yield payload
        if fail:
            raise Interrupted
    if fail:
        with pytest.raises(Interrupted):
            atomic_write_bytes_chunks(path, chunks())
        assert path.read_bytes() == b"original"
    else:
        assert atomic_write_bytes_chunks(path, chunks()) == 2
        assert path.read_bytes() == b"\x00\xffexact signed row\n"
    assert private_path_is_restricted(path)
    assert [entry.name for entry in tmp_path.iterdir()] == ["segment.bin"]


def test_atomic_write_replaces_symlink_not_referent(tmp_path):
    referent = tmp_path / "referent.txt"
    link = tmp_path / "state.txt"
    referent.write_text("do-not-overwrite", encoding="utf-8")
    try:
        link.symlink_to(referent)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise
    atomic_write_text(link, "new-state")
    assert referent.read_text(encoding="utf-8") == "do-not-overwrite"
    assert not link.is_symlink()
    assert link.read_text(encoding="utf-8") == "new-state"


def test_atomic_write_sets_mode_0600(tmp_path):
    p = tmp_path / "s.txt"
    atomic_write_text(p, "x")
    assert private_path_is_restricted(p)


def test_ensure_private_file_hardens_existing_file(tmp_path):
    p = tmp_path / "legacy-secret.txt"
    p.write_text("secret", encoding="utf-8")
    if os.name != "nt":
        p.chmod(0o644)
    ensure_private_file(p)
    assert private_path_is_restricted(p)
    assert p.read_text(encoding="utf-8") == "secret"


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL fast path")
def test_ensure_private_file_does_not_reharden_already_private_file(
    tmp_path, monkeypatch,
):
    """A verified private live database must not receive chmod/DACL churn."""
    import maverick.file_lock as file_lock

    path = tmp_path / "already-private.db"
    atomic_create_text(path, "private")
    assert private_path_is_restricted(path)

    def _unexpected_hardening(*_args, **_kwargs):
        raise AssertionError("already-private file was hardened again")

    monkeypatch.setattr(file_lock, "harden_path_permissions", _unexpected_hardening)
    assert ensure_private_file(path) == path
    assert path.read_text(encoding="utf-8") == "private"


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode fast path")
def test_ensure_private_file_leaves_an_already_private_posix_file_unchanged(tmp_path):
    """Re-applying the same mode still moves ctime, which reads as a change."""
    path = tmp_path / "already-private.txt"
    atomic_create_text(path, "private")
    before = path.stat()
    ensure_private_file(path)
    after = path.stat()
    assert after.st_ctime_ns == before.st_ctime_ns
    assert private_path_is_restricted(path)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-bound DACL fast path")
def test_ensure_private_file_rejects_aba_swap_during_private_fast_path(
    tmp_path, monkeypatch,
):
    import maverick.file_lock as file_lock

    path = tmp_path / "sensitive.txt"
    displaced = tmp_path / "displaced.txt"
    replacement = tmp_path / "replacement.txt"
    replacement_displaced = tmp_path / "replacement-displaced.txt"
    atomic_create_text(path, "original")
    atomic_create_text(replacement, "attacker replacement")
    real_open = file_lock._windows_open_security_handle

    def _open_during_aba(candidate):
        os.replace(candidate, displaced)
        os.replace(replacement, candidate)
        fd, handle = real_open(candidate)
        # Restore the initial object before the verifier's final lstat. A
        # path-based ACL query would see a private file and accept this ABA.
        os.replace(candidate, replacement_displaced)
        os.replace(displaced, candidate)
        return fd, handle

    monkeypatch.setattr(file_lock, "_windows_open_security_handle", _open_during_aba)
    with pytest.raises(PermissionError, match="identity changed"):
        ensure_private_file(path)

    assert path.read_text(encoding="utf-8") == "original"
    assert replacement_displaced.read_text(encoding="utf-8") == "attacker replacement"


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-bound DACL fast path")
def test_ensure_private_file_repairs_acl_broadened_during_fast_path(
    tmp_path, monkeypatch,
):
    import maverick.file_lock as file_lock

    path = tmp_path / "sensitive.txt"
    atomic_create_text(path, "original")
    real_query = file_lock._windows_handle_private_sddl
    real_harden = file_lock.harden_path_permissions
    queries = 0
    harden_calls = 0

    def _broaden_after_first_query(handle):
        nonlocal queries
        result = real_query(handle)
        queries += 1
        if queries == 1:
            subprocess.run(
                ["icacls", str(path), "/grant", "*S-1-1-0:R"],
                check=True,
                capture_output=True,
                text=True,
            )
        return result

    def _record_hardening(candidate, mode=0o600):
        nonlocal harden_calls
        harden_calls += 1
        return real_harden(candidate, mode)

    monkeypatch.setattr(
        file_lock,
        "_windows_handle_private_sddl",
        _broaden_after_first_query,
    )
    monkeypatch.setattr(file_lock, "harden_path_permissions", _record_hardening)
    assert ensure_private_file(path) == path

    assert queries == 2
    assert harden_calls == 1
    assert private_path_is_restricted(path)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-bound DACL fast path")
def test_ensure_private_file_rejects_hardlink_added_during_fast_path(
    tmp_path, monkeypatch,
):
    import maverick.file_lock as file_lock

    path = tmp_path / "sensitive.txt"
    alias = tmp_path / "late-hardlink.txt"
    atomic_create_text(path, "original")
    real_query = file_lock._windows_handle_private_sddl
    queries = 0

    def _link_after_first_query(handle):
        nonlocal queries
        result = real_query(handle)
        queries += 1
        if queries == 1:
            os.link(path, alias)
        return result

    monkeypatch.setattr(
        file_lock,
        "_windows_handle_private_sddl",
        _link_after_first_query,
    )
    with pytest.raises(PermissionError, match="identity changed"):
        ensure_private_file(path)

    assert path.stat().st_nlink == 2


@pytest.mark.skipif(os.name != "nt", reason="Windows DOS write posture")
def test_ensure_private_file_does_not_fast_return_for_wrong_windows_mode(tmp_path):
    path = tmp_path / "read-only.txt"
    atomic_create_text(path, "private", mode=0o600)

    assert ensure_private_file(path, mode=0o400) == path
    assert not path.stat().st_mode & stat.S_IWRITE
    assert private_path_is_restricted(path, mode=0o400)


def test_windows_restricted_acl_requires_trusted_owner_and_allow_only(monkeypatch):
    import maverick.file_lock as file_lock

    current = "S-1-5-21-1-2-3-1001"
    monkeypatch.setattr(file_lock, "_windows_current_user_sid", lambda: current)

    private = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
    assert file_lock._windows_acl_is_restricted(private, current)
    assert not file_lock._windows_acl_is_restricted(
        private,
        "S-1-5-21-9-9-9-1002",
    )
    assert not file_lock._windows_acl_is_restricted(
        "D:P(A;;FA;;;OW)(A;;FR;;;WD)",
        current,
    )
    assert not file_lock._windows_acl_is_restricted(
        "D:P(D;;FA;;;OW)(A;;FA;;;SY)",
        current,
    )


def test_ensure_private_file_rejects_identity_swap_during_hardening(
    tmp_path, monkeypatch,
):
    import maverick.file_lock as file_lock

    path = tmp_path / "sensitive.txt"
    replacement = tmp_path / "replacement.txt"
    displaced = tmp_path / "displaced.txt"
    path.write_text("original", encoding="utf-8")
    replacement.write_text("attacker replacement", encoding="utf-8")
    # Force the branch under test even when the process umask makes new files
    # private. Windows ACL posture cannot be broadened with chmod, so bypass
    # its already-private fast path while retaining the real hardening call.
    if os.name == "nt":
        monkeypatch.setattr(file_lock, "_windows_open_private_file_is_restricted", lambda *_: False)
    else:
        path.chmod(0o644)
    real_harden = file_lock.harden_path_permissions

    def _swap_after_hardening(candidate, mode=0o600):
        real_harden(candidate, mode)
        os.replace(candidate, displaced)
        os.replace(replacement, candidate)

    monkeypatch.setattr(file_lock, "harden_path_permissions", _swap_after_hardening)
    with pytest.raises(PermissionError, match="identity changed"):
        ensure_private_file(path)

    assert path.read_text(encoding="utf-8") == "attacker replacement"
    assert displaced.read_text(encoding="utf-8") == "original"


def test_ensure_private_file_rejects_non_regular_path(tmp_path):
    with pytest.raises(PermissionError, match="not a regular file"):
        ensure_private_file(tmp_path)


def test_ensure_private_file_rejects_symlink(tmp_path):
    referent = tmp_path / "referent.txt"
    link = tmp_path / "secret-link.txt"
    referent.write_text("secret", encoding="utf-8")
    try:
        link.symlink_to(referent)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise
    with pytest.raises(PermissionError, match="not a regular file"):
        ensure_private_file(link)


@pytest.mark.skipif(os.name == "nt", reason="POSIX link/unlink publication window")
def test_ensure_private_file_waits_for_atomic_create_publication(tmp_path):
    """A verifier may observe link(temp, target) before unlink(temp)."""
    target = tmp_path / "world.db"
    temp = tmp_path / ".world.db-publication.tmp"
    temp.write_bytes(b"")
    temp.chmod(0o600)
    os.link(temp, target, follow_symlinks=False)

    removed = threading.Event()

    def _finish_publication():
        time.sleep(0.02)
        temp.unlink()
        removed.set()

    publisher = threading.Thread(target=_finish_publication)
    publisher.start()
    try:
        assert ensure_private_file(target) == target
    finally:
        publisher.join(timeout=2)

    assert removed.is_set()
    assert target.stat().st_nlink == 1
    assert private_path_is_restricted(target)


@pytest.mark.skipif(os.name == "nt", reason="POSIX link/unlink publication window")
def test_ensure_private_file_never_accepts_persistent_publication_hardlink(
    tmp_path,
    monkeypatch,
):
    import maverick.file_lock as file_lock

    target = tmp_path / "world.db"
    temp = tmp_path / ".world.db-attacker.tmp"
    temp.write_bytes(b"sensitive")
    temp.chmod(0o600)
    os.link(temp, target, follow_symlinks=False)
    monkeypatch.setattr(file_lock, "_PRIVATE_FILE_PUBLICATION_RETRY_SECONDS", 0)

    with pytest.raises(PermissionError, match="not a regular file"):
        ensure_private_file(target)

    assert target.stat().st_nlink == 2


def test_atomic_write_leaves_no_temp_files(tmp_path):
    p = tmp_path / "s.txt"
    atomic_write_text(p, "x")
    # Only the target file remains -- the unique temp was replaced into place.
    assert [f.name for f in tmp_path.iterdir()] == ["s.txt"]


def test_atomic_write_creates_private_empty_temp_before_writing(tmp_path, monkeypatch):
    import maverick.file_lock as file_lock

    seen: list[tuple[int, bool]] = []
    real_create = file_lock._secure_mkstemp

    def _record_create(directory, *, prefix, suffix, mode):
        fd, path = real_create(
            directory,
            prefix=prefix,
            suffix=suffix,
            mode=mode,
        )
        seen.append((os.stat(path).st_size, file_lock.private_path_is_restricted(path)))
        return fd, path

    monkeypatch.setattr(file_lock, "_secure_mkstemp", _record_create)
    file_lock.atomic_write_text(tmp_path / "secret.txt", "sensitive")
    assert seen == [(0, True)]


def test_atomic_write_no_torn_read_under_concurrency(tmp_path):
    p = tmp_path / "s.json"
    atomic_write_text(p, json.dumps({"n": 0}))
    errors: list[Exception] = []
    successful_reads = 0
    stop = threading.Event()

    def writer():
        for i in range(300):
            atomic_write_text(p, json.dumps({"n": i, "pad": "y" * 200}))

    def reader():
        nonlocal successful_reads
        while not stop.is_set():
            try:
                json.loads(p.read_text())
                successful_reads += 1
            except PermissionError as e:
                # Windows opens do not request FILE_SHARE_DELETE. A reader can
                # lose the race with MoveFileEx and receive a transient access
                # denial; successful reads must still be complete documents.
                if os.name != "nt":
                    errors.append(e)
            except (ValueError, OSError) as e:
                errors.append(e)

    rt = threading.Thread(target=reader)
    wt = threading.Thread(target=writer)
    rt.start()
    wt.start()
    wt.join()
    stop.set()
    rt.join()
    assert not errors, errors[:3]
    assert successful_reads > 0
    assert json.loads(p.read_text())["n"] == 299


@pytest.mark.skipif(os.name != "nt", reason="Windows rename sharing semantics")
def test_atomic_read_retries_transient_windows_access_denial(
    tmp_path, monkeypatch,
):
    p = tmp_path / "state.json"
    p.write_text('{"ok": true}', encoding="utf-8")
    real_read = type(p).read_text
    attempts = 0

    def _flaky_read(self, *args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError("simulated MoveFileEx race")
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(type(p), "read_text", _flaky_read)
    assert json.loads(atomic_read_text(p))["ok"] is True
    assert attempts == 3


@pytest.mark.skipif(os.name != "nt", reason="Windows rename sharing semantics")
def test_atomic_write_waits_for_real_windows_sharing_denial(tmp_path):
    """A real handle without FILE_SHARE_DELETE pins the old destination.

    The atomic publisher must retry until that handle closes, rather than
    exposing a transient Windows sharing violation to normal callers.
    """
    import ctypes
    from ctypes import wintypes

    p = tmp_path / "shared.txt"
    atomic_write_text(p, "old")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    handle = create_file(
        str(p),
        0x80000000,  # GENERIC_READ
        0x00000001 | 0x00000002,  # share READ|WRITE, deliberately not DELETE
        None,
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    assert handle != invalid_handle, ctypes.WinError(ctypes.get_last_error())

    started = threading.Event()
    errors: list[BaseException] = []

    def writer():
        started.set()
        try:
            atomic_write_text(p, "new")
        except BaseException as exc:  # surfaced below with thread context
            errors.append(exc)

    thread = threading.Thread(target=writer)
    thread.start()
    assert started.wait(timeout=2)
    try:
        time.sleep(0.15)
        assert thread.is_alive(), "write unexpectedly bypassed sharing denial"
    finally:
        assert close_handle(handle)
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert not errors
    assert p.read_text(encoding="utf-8") == "new"


def test_cross_process_lock_serializes_writers(tmp_path):
    """The lock must serialize a load-modify-save so concurrent increments of a
    shared counter don't lose updates."""
    p = tmp_path / "counter.json"
    atomic_write_text(p, json.dumps({"c": 0}))
    n, per = 12, 50

    def worker():
        for _ in range(per):
            with cross_process_lock(p):
                cur = json.loads(p.read_text())["c"]
                atomic_write_text(p, json.dumps({"c": cur + 1}))

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert json.loads(p.read_text())["c"] == n * per


def test_cross_process_lock_creates_sidecar(tmp_path):
    p = tmp_path / "x.json"
    with cross_process_lock(p):
        pass
    lock_path = tmp_path / "x.json.lock"
    assert lock_path.exists()
    assert private_path_is_restricted(lock_path)
    # The lock sidecar is separate from the target (os.replace swaps the inode).
    assert not p.exists()


def test_cross_process_lock_is_reentrant_for_same_thread(tmp_path):
    p = tmp_path / "nested.json"
    with cross_process_lock(p), cross_process_lock(p):
        atomic_write_text(p, "nested")
    assert p.read_text() == "nested"


def test_strict_cross_process_lock_uses_platform_backend(tmp_path):
    p = tmp_path / "strict.json"
    with cross_process_lock(p, strict=True):
        atomic_write_text(p, "strict")
    assert p.read_text() == "strict"


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length paths")
def test_windows_lock_accepts_maximum_tenant_segment_without_splitting_identity(tmp_path):
    import maverick.file_lock as file_lock
    from maverick.paths import MAX_TENANT_SEGMENT_LENGTH

    tenant = "t" * MAX_TENANT_SEGMENT_LENGTH
    target = tmp_path / "tenants" / tenant / "flows" / "runs" / ("." + "a" * 32 + ".checkpoint")
    lock_path = target.parent / (target.name + ".lock")
    extended_target = Path(file_lock._windows_extended_path(target))
    extended_lock = Path(file_lock._windows_extended_path(lock_path))
    assert len(os.path.abspath(lock_path)) > 260
    assert file_lock._canonical_lock_path(lock_path) == file_lock._canonical_lock_path(extended_lock)

    with cross_process_lock(target, strict=True):
        with cross_process_lock(extended_target, strict=True):
            assert private_path_is_restricted(extended_lock)
    assert extended_lock.read_bytes() == b"\0"


def test_strict_nested_lock_refuses_degraded_outer_scope(tmp_path):
    import maverick.file_lock as file_lock

    p = tmp_path / "degraded.json"
    lock_path = p.parent / (p.name + ".lock")
    canonical = file_lock._canonical_lock_path(lock_path)
    prior = getattr(file_lock._THREAD_LOCK_STATE, "held", None)
    file_lock._THREAD_LOCK_STATE.held = {canonical: (1, False)}
    try:
        with pytest.raises(RuntimeError, match="backend is unavailable"):
            with cross_process_lock(p, strict=True):
                pytest.fail("strict lock unexpectedly inherited a degraded scope")
    finally:
        if prior is None:
            delattr(file_lock._THREAD_LOCK_STATE, "held")
        else:
            file_lock._THREAD_LOCK_STATE.held = prior


def test_cross_process_lock_serializes_processes(tmp_path):
    p = tmp_path / "process-counter.json"
    atomic_write_text(p, json.dumps({"c": 0}))
    code = """
import json
import sys
from pathlib import Path
from maverick.file_lock import atomic_write_text, cross_process_lock

path = Path(sys.argv[1])
for _ in range(20):
    with cross_process_lock(path):
        current = json.loads(path.read_text())["c"]
        atomic_write_text(path, json.dumps({"c": current + 1}))
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(p)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    for process in processes:
        stdout, stderr = process.communicate(timeout=60)
        assert process.returncode == 0, (stdout, stderr)
    assert json.loads(p.read_text())["c"] == 80


@pytest.mark.skipif(os.name != "nt", reason="Windows byte-range lock regression")
def test_windows_lock_creator_alone_initializes_byte(tmp_path):
    """A contender waits for the O_EXCL creator; it never writes the lock byte."""
    target = tmp_path / "creator-race.json"
    creator_ready = tmp_path / "creator-ready"
    contender_ready = tmp_path / "contender-ready"
    release = tmp_path / "release-creator"
    code = r"""
import sys
import time
from pathlib import Path
import maverick.file_lock as file_lock

mode, target_raw, marker_raw, release_raw = sys.argv[1:]
target = Path(target_raw)
marker = Path(marker_raw)
release = Path(release_raw)
if mode == "creator":
    real_write = file_lock.os.write
    def delayed_creator_write(fd, data):
        marker.write_text("ready", encoding="utf-8")
        deadline = time.monotonic() + 10.0
        while not release.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("creator was not released")
            time.sleep(0.005)
        return real_write(fd, data)
    file_lock.os.write = delayed_creator_write
else:
    real_wait = file_lock._wait_for_windows_lock_initialization
    def marked_wait(path, fd):
        marker.write_text("ready", encoding="utf-8")
        return real_wait(path, fd)
    file_lock._wait_for_windows_lock_initialization = marked_wait

with file_lock.cross_process_lock(target, strict=True):
    pass
"""

    def wait_for(path):
        deadline = time.monotonic() + 10.0
        while not path.exists():
            if time.monotonic() >= deadline:
                pytest.fail(f"subprocess did not reach marker {path.name}")
            time.sleep(0.005)

    creator = subprocess.Popen(
        [
            sys.executable, "-c", code, "creator", str(target),
            str(creator_ready), str(release),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_for(creator_ready)
    contender = subprocess.Popen(
        [
            sys.executable, "-c", code, "contender", str(target),
            str(contender_ready), str(release),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_for(contender_ready)
    assert contender.poll() is None
    release.write_text("go", encoding="utf-8")

    for process in (creator, contender):
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, (stdout, stderr)
    assert (tmp_path / "creator-race.json.lock").read_bytes() == b"\0"


def test_cross_process_lock_fails_closed_when_dir_unwritable(tmp_path):
    # An impossible lock dir must raise rather than silently running an
    # unserialized security-sensitive read-modify-write.
    bogus = tmp_path / "missing-parent-file" / "child.json"
    # Create a *file* where a directory is expected so mkdir/open fail.
    (tmp_path / "missing-parent-file").write_text("not a dir")
    with pytest.raises(OSError), cross_process_lock(bogus):
        pytest.fail("lock acquisition unexpectedly succeeded")
    assert not os.path.exists(str(bogus) + ".lock")


def test_cross_process_lock_rejects_dangling_sidecar_symlink(tmp_path):
    target = tmp_path / "state.json"
    lock_path = tmp_path / "state.json.lock"
    outside = tmp_path / "outside" / "created-by-followed-link"
    try:
        lock_path.symlink_to(outside)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise

    with pytest.raises((OSError, PermissionError)):
        with cross_process_lock(target, strict=True):
            pytest.fail("a dangling lock alias was followed")

    # In particular, Windows O_CREAT must not follow the dangling sidecar and
    # create its outside referent before post-open validation can run.
    assert not outside.exists()
    assert lock_path.is_symlink()


def test_cross_process_lock_rejects_hardlinked_sidecar(tmp_path):
    target = tmp_path / "state.json"
    lock_path = tmp_path / "state.json.lock"
    outside = tmp_path / "outside-lock"
    outside.write_bytes(b"do-not-lock-or-mutate")
    try:
        lock_path.hardlink_to(outside)
    except OSError:
        pytest.skip("hardlinks are unavailable on this host")

    with pytest.raises(PermissionError, match="single-link regular file"):
        with cross_process_lock(target, strict=True):
            pytest.fail("a hardlinked lock sidecar was accepted")

    assert outside.read_bytes() == b"do-not-lock-or-mutate"


# --- per-path in-process locking: the stripe-collision deadlock class -------

def test_distinct_paths_never_share_the_in_process_lock(tmp_path):
    """Regression: the in-process side of cross_process_lock was 64 hash-shared
    stripes, held for the whole critical section. Two UNRELATED lock files
    landing on one stripe deadlocked any nested acquisition (observed: the
    self-harness promotion path vs the audit writer, ~1 run in 64). A thread
    holding path A must never block a different path B -- for every B."""
    import threading

    from maverick.file_lock import cross_process_lock

    inside = threading.Event()
    release = threading.Event()

    def hold_a():
        with cross_process_lock(tmp_path / "a.state"):
            inside.set()
            release.wait(timeout=30)

    t = threading.Thread(target=hold_a, daemon=True)
    t.start()
    assert inside.wait(timeout=10)
    try:
        # With 64 stripes, ~16 of 1000 distinct paths would share A's stripe
        # and block forever; per-path locks must sail through all of them.
        for i in range(1000):
            with cross_process_lock(tmp_path / f"b{i}.state"):
                pass
    finally:
        release.set()
        t.join(timeout=10)
    assert not t.is_alive()


def test_nested_cross_path_locks_cannot_abba_deadlock(tmp_path):
    """The exact shape that wedged self-harness: thread 1 audits from inside a
    store lock (store file-lock -> writer lock -> audit file-lock) while
    thread 2 audits directly (writer lock -> audit file-lock)."""
    import threading

    from maverick.file_lock import cross_process_lock

    writer_lock = threading.Lock()
    store, audit = tmp_path / "store.state", tmp_path / "audit.log"
    done = []

    def promoter():
        for _ in range(50):
            with cross_process_lock(store):
                with writer_lock, cross_process_lock(audit):
                    pass
        done.append("promoter")

    def auditor():
        for _ in range(50):
            with writer_lock, cross_process_lock(audit):
                pass
        done.append("auditor")

    threads = [threading.Thread(target=promoter, daemon=True),
               threading.Thread(target=auditor, daemon=True)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert done.count("promoter") == 1 and done.count("auditor") == 1


def test_same_path_contenders_still_serialize(tmp_path):
    """Same-path exclusion holds: two threads bumping a counter under the
    same lock lose no update."""
    import json
    import threading

    from maverick.file_lock import atomic_write_text, cross_process_lock

    target = tmp_path / "counter.json"
    atomic_write_text(target, json.dumps({"n": 0}))

    def bump():
        for _ in range(50):
            with cross_process_lock(target):
                n = json.loads(target.read_text())["n"]
                atomic_write_text(target, json.dumps({"n": n + 1}))

    threads = [threading.Thread(target=bump, daemon=True) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert json.loads(target.read_text())["n"] == 200


def test_lock_registry_does_not_accumulate(tmp_path):
    """Entries live only while someone holds or waits -- the bounded-memory
    property the old stripe table existed to provide."""
    from maverick.file_lock import _LOCAL_PATH_LOCKS, cross_process_lock

    for i in range(200):
        with cross_process_lock(tmp_path / f"f{i}.state"):
            assert _LOCAL_PATH_LOCKS          # live while held
    assert not _LOCAL_PATH_LOCKS              # empty once released


def test_empty_lock_sidecar_self_heals(tmp_path, monkeypatch):
    """An orphaned EMPTY sidecar (the creator died -- or AV/backup tooling
    recreated the file empty -- before the lock byte was published) used to
    wedge the lock FOREVER: every later opener took the existing-file path,
    waited out the initialization timeout, and raised "lock file was never
    initialized"; no process could ever become the O_EXCL creator again.
    Observed in the field on a dashboard-config.toml.lock the user had to
    delete by hand. A timed-out waiter now adopts the orphan instead."""
    import maverick.file_lock as file_lock

    lock_path = tmp_path / "state.json.lock"
    lock_path.write_bytes(b"")
    fd = os.open(str(lock_path), os.O_RDWR)
    try:
        with monkeypatch.context() as mp:
            mp.setattr(file_lock, "_WINDOWS_LOCK_INITIALIZATION_SECONDS", 0.05)
            mp.setattr(file_lock.os, "name", "nt")
            file_lock._wait_for_windows_lock_initialization(lock_path, fd)
            # Adoption published the byte; a second waiter sees an
            # initialized lock immediately (no timeout, no error).
            file_lock._wait_for_windows_lock_initialization(lock_path, fd)
    finally:
        os.close(fd)
    assert lock_path.read_bytes() == b"\0"


def test_orphan_adoption_failure_keeps_the_classic_error(tmp_path, monkeypatch):
    """When the adoption write fails (e.g. a live creator already holds the
    mandatory byte-range lock), the waiter reports the classic timeout error
    with the underlying cause chained -- never a silent success."""
    import maverick.file_lock as file_lock

    lock_path = tmp_path / "state.json.lock"
    lock_path.write_bytes(b"")
    fd = os.open(str(lock_path), os.O_RDWR)
    try:
        with monkeypatch.context() as mp:
            mp.setattr(file_lock, "_WINDOWS_LOCK_INITIALIZATION_SECONDS", 0.05)
            mp.setattr(file_lock.os, "name", "nt")

            def denied(_fd, _data):
                raise PermissionError("byte-range lock held")

            mp.setattr(file_lock.os, "write", denied)
            with pytest.raises(PermissionError, match="never initialized"):
                file_lock._wait_for_windows_lock_initialization(lock_path, fd)
    finally:
        os.close(fd)
    assert lock_path.read_bytes() == b""
