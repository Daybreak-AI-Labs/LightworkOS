"""Reject container mounts that would expose the operator's private home."""
import contextvars
import os
import stat
from contextlib import contextmanager
from pathlib import Path

# Only the synchronous, trusted document worker establishes this scope. It is
# exact-directory and inode bound; it does not grant general access to state.
# Context propagation is not a boundary against untrusted in-process Python.
_DOCUMENT_STAGE = contextvars.ContextVar("document_stage", default=None)


def _private_directory_identity(path: Path) -> tuple[int, int, int, int]:
    from ..file_lock import private_path_is_restricted

    before = path.lstat()
    if (not stat.S_ISDIR(before.st_mode)
            or (os.name != "nt" and before.st_uid != os.geteuid())
            or not private_path_is_restricted(path, 0o700)):
        raise ValueError("Document staging directory is not private and owner-controlled.")
    after = path.lstat()
    before_id = (before.st_dev, before.st_ino, before.st_mode, before.st_uid)
    after_id = (after.st_dev, after.st_ino, after.st_mode, after.st_uid)
    if before_id != after_id:
        raise ValueError("Document staging directory changed during verification.")
    return after_id


@contextmanager
def _document_stage_scope(stage: Path):
    """Permit one freshly created private document job, only in this context."""
    from ..paths import data_dir

    stage = Path(stage)
    parent = data_dir("document-processing")
    if stage.parent.resolve() != parent.resolve() or not stage.name.startswith("job-"):
        raise ValueError("Document stage is outside its private staging directory.")
    parent_id = _private_directory_identity(parent)
    stage_id = _private_directory_identity(stage)
    token = _DOCUMENT_STAGE.set((stage.resolve(), parent, parent_id, stage_id))
    try:
        yield
    finally:
        _DOCUMENT_STAGE.reset(token)


def _permitted_document_stage(workspace: Path) -> bool:
    permit = _DOCUMENT_STAGE.get()
    if permit is None:
        return False
    stage, parent, parent_id, stage_id = permit
    if workspace != stage:
        return False
    try:
        return (_private_directory_identity(parent) == parent_id
                and _private_directory_identity(stage) == stage_id)
    except (OSError, ValueError):
        return False


def validate_container_workspace(workdir: Path) -> None:
    from ..paths import maverick_home

    workspace = Path(workdir).resolve()
    home = Path.home().resolve()
    state = maverick_home().resolve()
    private_dirs = tuple((home / name).resolve() for name in (
        ".ssh", ".aws", ".config", ".gnupg", ".docker", ".kube",
    ))
    private_files = tuple((home / name).resolve() for name in (
        ".bashrc", ".zshrc", ".npmrc", ".pypirc", ".netrc", ".gitconfig",
    ))
    sensitive = (state, *private_dirs, *private_files)
    # The shipped workspace is deliberately below the state root; other state
    # descendants include databases, audit evidence and credentials.
    allowed_workspace = state / "workspace"
    if (any(path.is_relative_to(workspace) for path in sensitive)
            or any(workspace.is_relative_to(path) for path in private_dirs)
            or (workspace.is_relative_to(state)
                and not workspace.is_relative_to(allowed_workspace)
                and not _permitted_document_stage(workspace))):
        raise ValueError("Choose a dedicated workspace outside the operator's private data directories.")
