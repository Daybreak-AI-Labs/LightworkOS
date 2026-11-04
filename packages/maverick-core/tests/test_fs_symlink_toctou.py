"""Symlink TOCTOU guard for the filesystem tools.

``_safe_resolve`` resolves + range-checks a path, but the tool then opens it a
moment later — a window in which a symlink swapped into the path can redirect
the open outside the workspace. The tool verifies, THROUGH the opened descriptor
(``/proc/self/fd``), that the inode actually opened is still inside the
workspace. These tests prove (a) legitimate in-workspace symlinks still work and
(b) an escape detected only after the open is refused with no data leak / no
truncation of the outside file.

Linux-only: the fd->realpath check relies on ``/proc/self/fd``. Elsewhere the
guard degrades to the (unchanged) resolve-time check, so there's nothing new to
assert.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from maverick.tools import fs

pytestmark = pytest.mark.skipif(
    not Path("/proc/self/fd").exists() or os.name == "nt",
    reason="fd->realpath containment check requires /proc (Linux)",
)


class _SB:
    def __init__(self, workdir: Path):
        self.workdir = str(workdir)


@pytest.fixture
def workdir(tmp_path) -> Path:
    return tmp_path.resolve()


# ---- helper: _open_contained -------------------------------------------------

def test_open_contained_allows_inside_symlink(workdir):
    (workdir / "real.txt").write_text("inside")
    (workdir / "link.txt").symlink_to(workdir / "real.txt")
    fd = fs._open_contained(workdir, workdir / "link.txt", os.O_RDONLY)
    try:
        assert os.read(fd, 64) == b"inside"  # legit symlink-following preserved
    finally:
        os.close(fd)


def test_open_contained_rejects_outside_symlink(workdir):
    outside = Path(tempfile.mkdtemp()).resolve() / "secret"
    outside.write_text("TOPSECRET")
    (workdir / "escape").symlink_to(outside)
    with pytest.raises(ValueError, match="outside the workspace"):
        fs._open_contained(workdir, workdir / "escape", os.O_RDONLY)


def test_open_contained_rejects_outside_path_with_deleted_suffix(workdir):
    """A live outside path may legitimately end in " (deleted)".

    Linux appends the same text to /proc fd links for unlinked files, but the
    containment guard must not strip it blindly: doing so can turn an outside
    sibling named like "<workdir> (deleted)" into the workspace path.
    """
    outside = workdir.parent / f"{workdir.name} (deleted)"
    outside.write_text("SECRET")
    swapped = workdir / "escape"
    swapped.symlink_to(outside)

    with pytest.raises(ValueError, match="outside the workspace"):
        fs._open_contained(workdir, swapped, os.O_RDONLY)


def test_read_file_rejects_swapped_symlink_to_deleted_suffix_sibling(workdir, monkeypatch):
    outside = workdir.parent / f"{workdir.name} (deleted)"
    outside.write_text("SECRET_OUTSIDE_READ")
    swapped = workdir / "looks-fine.txt"
    swapped.symlink_to(outside)
    monkeypatch.setattr(fs, "_safe_resolve", lambda _sb, _p: swapped)

    out = fs.read_file(_SB(workdir)).fn({"path": "looks-fine.txt"})
    assert "symlink race" in out
    assert "SECRET_OUTSIDE_READ" not in out


def test_write_file_rejects_swapped_symlink_to_deleted_suffix_sibling(workdir, monkeypatch):
    outside = workdir.parent / f"{workdir.name} (deleted)"
    outside.write_text("ORIGINAL-MUST-SURVIVE")
    swapped = workdir / "out.txt"
    swapped.symlink_to(outside)
    monkeypatch.setattr(fs, "_safe_resolve", lambda _sb, _p: swapped)

    out = fs.write_file(_SB(workdir)).fn({"path": "out.txt", "content": "HACKED"})
    assert "symlink race" in out
    assert outside.read_text() == "ORIGINAL-MUST-SURVIVE"


# ---- read_file: post-check swap can't leak ----------------------------------

def test_read_file_toctou_guard_blocks_swapped_symlink(workdir, monkeypatch):
    """Simulate a symlink swapped in AFTER the resolve check: _safe_resolve
    returns a contained-looking path that is actually a symlink to an outside
    file. The fd containment check must catch it — no outside content leaks."""
    outside = Path(tempfile.mkdtemp()).resolve() / "passwd"
    outside.write_text("root:x:0:0:SECRET")
    swapped = workdir / "looks-fine.txt"
    swapped.symlink_to(outside)
    # Pretend the path passed the resolve-time containment check.
    monkeypatch.setattr(fs, "_safe_resolve", lambda _sb, _p: swapped)

    out = fs.read_file(_SB(workdir)).fn({"path": "looks-fine.txt"})
    assert "symlink race" in out
    assert "SECRET" not in out  # nothing from the outside file leaked


def test_read_file_inside_symlink_end_to_end(workdir):
    (workdir / "data.txt").write_text("legit-content")
    (workdir / "alias.txt").symlink_to(workdir / "data.txt")
    out = fs.read_file(_SB(workdir)).fn({"path": "alias.txt"})
    assert out == "legit-content"


# ---- write_file: never truncates / writes an escaped file -------------------

def test_write_file_toctou_guard_does_not_truncate_outside(workdir, monkeypatch):
    outside = Path(tempfile.mkdtemp()).resolve() / "important"
    outside.write_text("ORIGINAL-MUST-SURVIVE")
    swapped = workdir / "out.txt"
    swapped.symlink_to(outside)
    monkeypatch.setattr(fs, "_safe_resolve", lambda _sb, _p: swapped)

    out = fs.write_file(_SB(workdir)).fn({"path": "out.txt", "content": "HACKED"})
    assert "symlink race" in out
    # The outside file was neither truncated nor overwritten.
    assert outside.read_text() == "ORIGINAL-MUST-SURVIVE"


def test_write_file_inside_symlink_end_to_end(workdir):
    (workdir / "target.txt").write_text("old")
    (workdir / "w-alias.txt").symlink_to(workdir / "target.txt")
    out = fs.write_file(_SB(workdir)).fn({"path": "w-alias.txt", "content": "new"})
    assert "wrote" in out
    assert (workdir / "target.txt").read_text() == "new"  # legit symlink write


# ---- list_dir: post-check swap can't list outside ---------------------------

def test_list_dir_toctou_guard_blocks_swapped_symlink(workdir, monkeypatch):
    outside_dir = Path(tempfile.mkdtemp()).resolve()
    (outside_dir / "secret-file").write_text("x")
    swapped = workdir / "subdir"
    swapped.symlink_to(outside_dir)
    monkeypatch.setattr(fs, "_safe_resolve", lambda _sb, _p: swapped)

    out = fs.list_dir(_SB(workdir)).fn({"path": "subdir"})
    assert "symlink race" in out
    assert "secret-file" not in out


def test_list_dir_inside_symlink_end_to_end(workdir):
    sub = workdir / "real_sub"
    sub.mkdir()
    (sub / "a.txt").write_text("1")
    (workdir / "sub_alias").symlink_to(sub)
    out = fs.list_dir(_SB(workdir)).fn({"path": "sub_alias"})
    assert "a.txt" in out
