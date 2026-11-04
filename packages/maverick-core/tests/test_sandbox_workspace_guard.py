"""Container mounts must not include the operator's private data."""
import os

import pytest
from maverick.sandbox.workspace_guard import validate_container_workspace


def test_rejects_workspace_containing_lightwork_data(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    with pytest.raises(ValueError, match="dedicated workspace"):
        validate_container_workspace(tmp_path)
    with pytest.raises(ValueError, match="dedicated workspace"):
        validate_container_workspace(tmp_path / "state" / "audit")
    validate_container_workspace(tmp_path / "state" / "workspace")
    validate_container_workspace(tmp_path / "project")


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks requires Windows privileges")
def test_rejects_resolved_private_directory(tmp_path, monkeypatch):
    from pathlib import Path

    home = tmp_path / "home"
    home.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    (home / ".ssh").symlink_to(private, target_is_directory=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("MAVERICK_HOME", str(home / ".maverick"))
    with pytest.raises(ValueError, match="dedicated workspace"):
        validate_container_workspace(private)


def test_private_document_stage_is_exact_scoped_and_identity_bound(tmp_path, monkeypatch):
    from maverick.file_lock import ensure_private_directory
    from maverick.sandbox.workspace_guard import _document_stage_scope

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    parent = ensure_private_directory(tmp_path / "state" / "document-processing")
    stage = ensure_private_directory(parent / "job-example")
    other = ensure_private_directory(parent / "job-other")
    with pytest.raises(ValueError, match="dedicated workspace"):
        validate_container_workspace(stage)
    with _document_stage_scope(stage):
        validate_container_workspace(stage)
        with pytest.raises(ValueError, match="dedicated workspace"):
            validate_container_workspace(parent)
        with pytest.raises(ValueError, match="dedicated workspace"):
            validate_container_workspace(other)
        stage.rename(parent / "old-job")
        ensure_private_directory(stage)
        with pytest.raises(ValueError, match="dedicated workspace"):
            validate_container_workspace(stage)
    with pytest.raises(ValueError, match="dedicated workspace"):
        validate_container_workspace(stage)


def test_document_stage_permission_is_reset_after_an_error(tmp_path, monkeypatch):
    from maverick.file_lock import ensure_private_directory
    from maverick.sandbox.workspace_guard import _document_stage_scope

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    parent = ensure_private_directory(tmp_path / "state" / "document-processing")
    stage = ensure_private_directory(parent / "job-example")
    with pytest.raises(RuntimeError, match="interrupted"):
        with _document_stage_scope(stage):
            validate_container_workspace(stage)
            raise RuntimeError("interrupted")
    with pytest.raises(ValueError, match="dedicated workspace"):
        validate_container_workspace(stage)


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks requires Windows privileges")
def test_document_stage_scope_rejects_a_symlink(tmp_path, monkeypatch):
    from maverick.file_lock import ensure_private_directory
    from maverick.sandbox.workspace_guard import _document_stage_scope

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    parent = ensure_private_directory(tmp_path / "state" / "document-processing")
    target = ensure_private_directory(parent / "actual")
    link = parent / "job-link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="not private"):
        with _document_stage_scope(link):
            pytest.fail("a symlink must not receive a document-stage capability")
