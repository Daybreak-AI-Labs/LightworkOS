"""Real file publication with a synthetic kubectl transport; no live cluster."""
from __future__ import annotations

import io
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest
from maverick.sandbox import workspace_transfer as transfer
from maverick.sandbox.kubernetes import KubernetesBackend


def _capture_using_fake_run(args, archive, timeout):
    with archive.open("xb") as destination:
        return subprocess.run(args, stdout=destination, stderr=subprocess.PIPE,
                              timeout=timeout).returncode


def _backend(monkeypatch, tmp_path, operation, *, export_fails=False):
    local = tmp_path / "workspace"
    local.mkdir()
    remote = tmp_path / "remote"
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if "run" in args:
            remote.mkdir()
        elif "cp" in args:
            shutil.copytree(kwargs["cwd"], remote, dirs_exist_ok=True)
        elif "exec" in args:
            if "tar" in args:
                if export_fails:
                    return SimpleNamespace(returncode=1, stderr=b"connection lost")
                with tarfile.open(fileobj=kwargs["stdout"], mode="w") as archive:
                    archive.add(remote, arcname=".")
            else:
                operation(remote, local)
                return SimpleNamespace(returncode=0, stdout="completed", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.setattr(transfer, "capture_archive", _capture_using_fake_run)
    return KubernetesBackend(workdir=local, allow_network=True), local, calls


def test_failed_pod_cleanup_is_visible_without_masking_execution(monkeypatch, tmp_path, caplog):
    backend, _, _ = _backend(monkeypatch, tmp_path, lambda remote, local: None)
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: SimpleNamespace(returncode=1))

    assert backend._delete_pod("sandbox-pod") is None
    assert "failed to delete pod sandbox-pod" in caplog.text


def test_archive_capture_limits_bytes_before_disk_grows(tmp_path, monkeypatch):
    monkeypatch.setattr(transfer, "MAX_ARCHIVE_BYTES", 128 * 1024)
    archive = tmp_path / "archive.tar"
    with pytest.raises(transfer.WorkspaceTransferError, match="output limits"):
        transfer.capture_archive([sys.executable, "-c",
                                  "import sys; sys.stdout.buffer.write(b'x' * 1024 * 1024)"], archive, 10)
    assert archive.stat().st_size <= 128 * 1024


def test_archive_capture_timeout_retains_bounded_partial_output(tmp_path):
    archive = tmp_path / "archive.tar"
    with pytest.raises(subprocess.TimeoutExpired):
        transfer.capture_archive([sys.executable, "-c", "import time; time.sleep(10)"], archive, .1)
    assert archive.exists()


def test_archive_capture_drains_both_pipes(tmp_path):
    archive = tmp_path / "archive.tar"
    assert transfer.capture_archive([sys.executable, "-c",
        "import sys; sys.stderr.write('d' * 100000); sys.stdout.buffer.write(b'archive')"], archive, 10) == 0
    assert archive.read_bytes() == b"archive"


def test_end_to_end_rename_deletion_and_new_files(monkeypatch, tmp_path):
    def operation(remote, local):
        (remote / "old.txt").rename(remote / "renamed.txt")
        (remote / "delete.txt").unlink()
        (remote / "reports").mkdir()
        (remote / "reports" / "result.txt").write_text("finished")
        (local / "concurrent.txt").write_text("local work")

    backend, local, calls = _backend(monkeypatch, tmp_path, operation)
    (local / "old.txt").write_text("original")
    (local / "delete.txt").write_text("obsolete")
    result = backend.exec("fixture")
    assert result.exit_code == 0, result.stderr
    assert not (local / "old.txt").exists() and not (local / "delete.txt").exists()
    assert (local / "renamed.txt").read_text() == "original"
    assert (local / "reports" / "result.txt").read_text() == "finished"
    assert (local / "concurrent.txt").read_text() == "local work"
    assert any("delete" in call for call in calls)


def test_first_run_with_empty_workspace_receives_output_without_copying_volume_root(monkeypatch, tmp_path):
    backend, local, calls = _backend(monkeypatch, tmp_path,
        lambda remote, local: (remote / "first.txt").write_text("first deliverable"))
    result = backend.exec("create first deliverable")
    assert result.exit_code == 0, result.stderr
    assert (local / "first.txt").read_text() == "first deliverable"
    assert not any("cp" in call for call in calls)


def test_conflict_keeps_local_edit_and_exported_output(monkeypatch, tmp_path):
    def operation(remote, local):
        (remote / "report.txt").write_text("remote result")
        (local / "report.txt").write_text("concurrent edit")

    backend, local, calls = _backend(monkeypatch, tmp_path, operation)
    (local / "report.txt").write_text("before")
    result = backend.exec("fixture")
    assert result.exit_code == 74 and result.stdout == "completed"
    assert (local / "report.txt").read_text() == "concurrent edit"
    from maverick.paths import data_dir
    [recovery] = list(data_dir("sandbox-recovery").iterdir())
    assert (recovery / "exported" / "report.txt").read_text() == "remote result"
    assert (recovery / "input" / "report.txt").read_text() == "before"
    assert (recovery / "export.tar").is_file()
    assert any("delete" in call for call in calls), "validated local export is recoverable without the pod"


def test_failed_export_retains_pod_and_original_workspace(monkeypatch, tmp_path):
    backend, local, calls = _backend(monkeypatch, tmp_path,
                                    lambda remote, local: (remote / "result.txt").write_text("result"),
                                    export_fails=True)
    (local / "original.txt").write_text("unchanged")
    result = backend.exec("fixture")
    assert result.exit_code == 74 and result.stdout == "completed"
    assert not any("delete" in call for call in calls)
    assert "within one hour" in result.stderr
    assert (local / "original.txt").read_text() == "unchanged"


@pytest.mark.parametrize("name,kind", [("../escape", tarfile.REGTYPE),
                                      ("/absolute", tarfile.REGTYPE),
                                      ("C:/escape", tarfile.REGTYPE),
                                      ("link", tarfile.SYMTYPE),
                                      ("hardlink", tarfile.LNKTYPE),
                                      ("device", tarfile.CHRTYPE),
                                      ("a/../b", tarfile.REGTYPE),
                                      ("file:stream", tarfile.REGTYPE)])
def test_untrusted_archive_rejects_escapes_and_special_entries(tmp_path, name, kind):
    archive = tmp_path / "export.tar"
    with tarfile.open(archive, "w") as stream:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = "../../outside"
        member.size = 1 if kind == tarfile.REGTYPE else 0
        stream.addfile(member, io.BytesIO(b"x") if member.size else None)
    with pytest.raises(transfer.WorkspaceTransferError):
        transfer.extract_archive(archive, tmp_path / "staged")
    assert not (tmp_path / "escape").exists()


def test_directory_deletion_refuses_concurrently_added_child(tmp_path):
    local, exported = tmp_path / "local", tmp_path / "exported"
    (local / "folder").mkdir(parents=True)
    exported.mkdir()
    baseline = transfer.snapshot(local)
    (local / "folder" / "new.txt").write_text("new local file")
    with pytest.raises(transfer.WorkspaceTransferError, match="changed locally"):
        transfer.publish(local, baseline, exported, tmp_path / "backup")
    assert (local / "folder" / "new.txt").read_text() == "new local file"


def test_file_bound_refuses_before_pod_is_started(monkeypatch, tmp_path):
    backend, local, calls = _backend(monkeypatch, tmp_path, lambda remote, local: None)
    monkeypatch.setattr(transfer, "MAX_FILE_BYTES", 3)
    (local / "large").write_bytes(b"1234")
    assert backend.exec("fixture").exit_code == 74
    assert not any("run" in call for call in calls)


def test_interrupted_publication_retains_originals_and_export(tmp_path, monkeypatch):
    local, exported = tmp_path / "local", tmp_path / "exported"
    local.mkdir()
    exported.mkdir()
    (local / "a").write_text("original a")
    (local / "b").write_text("original b")
    baseline = transfer.snapshot(local)
    (exported / "a").write_text("new a")
    (exported / "b").write_text("new b")
    original_write = transfer._write

    def fail_second(root, relative, raw, mode):
        if root == local and relative == "b":
            raise OSError("simulated disk failure")
        return original_write(root, relative, raw, mode)

    monkeypatch.setattr(transfer, "_write", fail_second)
    with pytest.raises(OSError, match="disk failure"):
        transfer.publish(local, baseline, exported, tmp_path / "backup")
    assert (tmp_path / "backup" / "a").read_text() == "original a"
    assert (tmp_path / "backup" / "b").read_text() == "original b"
    assert (exported / "a").read_text() == "new a"
    assert (local / "b").read_text() == "original b"
