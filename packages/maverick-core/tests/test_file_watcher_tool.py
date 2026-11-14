"""Tests for the file_watcher tool."""
from __future__ import annotations

import os
import time
from pathlib import Path


def _sandbox(tmp_path: Path):
    class _Sandbox:
        workdir = tmp_path
    return _Sandbox()

def test_file_watcher_requires_path(tmp_path: Path):
    from maverick.tools.file_watcher import file_watcher
    out = file_watcher(_sandbox(tmp_path)).fn({})
    assert "ERROR" in out and "path" in out


def test_file_watcher_path_missing(tmp_path: Path):
    from maverick.tools.file_watcher import file_watcher
    out = file_watcher(_sandbox(tmp_path)).fn({"path": str(tmp_path / "nope")})
    assert "ERROR" in out


def test_file_watcher_baseline_then_diff(tmp_path: Path):
    from maverick.tools.file_watcher import file_watcher
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    # Native file mtimes can round above time.time() on Windows. Make these
    # existing files clearly older than the baseline; keep later changes real.
    old_ts = time.time() - 60
    for name in ("a.txt", "b.txt"):
        os.utime(tmp_path / name, (old_ts, old_ts))
    tool = file_watcher(_sandbox(tmp_path))

    baseline_out = tool.fn({"path": str(tmp_path)})
    assert "baseline" in baseline_out
    assert "2 files" in baseline_out
    baseline_ts = float(baseline_out.split()[1])

    # No new changes -> empty diff.
    diff_out = tool.fn({"path": str(tmp_path), "since": baseline_ts})
    assert "no changes" in diff_out

    # Wait a moment, then modify one file.
    time.sleep(0.05)
    new_ts = time.time()
    (tmp_path / "a.txt").write_text("a-changed")
    os.utime(tmp_path / "a.txt", (new_ts + 1, new_ts + 1))

    diff2 = tool.fn({"path": str(tmp_path), "since": baseline_ts})
    assert "1 file(s) changed" in diff2
    assert "a.txt" in diff2
    assert "b.txt" not in diff2


def test_file_watcher_pattern(tmp_path: Path):
    from maverick.tools.file_watcher import file_watcher
    (tmp_path / "keep.py").write_text("x")
    (tmp_path / "skip.txt").write_text("x")
    # Force mtimes into the future so they're > since.
    future = time.time() + 60
    os.utime(tmp_path / "keep.py", (future, future))
    os.utime(tmp_path / "skip.txt", (future, future))

    tool = file_watcher(_sandbox(tmp_path))
    out = tool.fn({"path": str(tmp_path), "since": 0, "pattern": "*.py"})
    assert "keep.py" in out
    assert "skip.txt" not in out


def test_file_watcher_skips_noise_dirs(tmp_path: Path):
    """Skip .git, node_modules, __pycache__ etc. (and dot-files by default)."""
    from maverick.tools.file_watcher import file_watcher
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("x")
    (tmp_path / "real.py").write_text("x")
    future = time.time() + 60
    for p in tmp_path.rglob("*"):
        if p.is_file():
            os.utime(p, (future, future))

    out = file_watcher(_sandbox(tmp_path)).fn({"path": str(tmp_path), "since": 0})
    assert "real.py" in out
    assert "HEAD" not in out
    assert "junk.js" not in out


def test_file_watcher_bad_since_value(tmp_path: Path):
    from maverick.tools.file_watcher import file_watcher
    out = file_watcher(_sandbox(tmp_path)).fn({"path": str(tmp_path), "since": "yesterday"})
    assert "ERROR" in out and "since" in out


def test_file_watcher_blocks_paths_outside_workspace(tmp_path: Path):
    from maverick.tools.file_watcher import file_watcher

    outside = tmp_path.parent / "outside-watch"
    outside.mkdir(exist_ok=True)
    (outside / "x.txt").write_text("x")

    out = file_watcher(_sandbox(tmp_path)).fn({"path": str(outside), "since": 0})
    assert "ERROR" in out and "escapes the workspace" in out


def test_file_watcher_does_not_stat_symlink_targets(tmp_path: Path):
    from maverick.tools.file_watcher import file_watcher
    ws = tmp_path / "ws"
    ws.mkdir()
    secret = tmp_path / "outside.txt"
    secret.write_text("x" * 12345)
    (ws / "link.txt").symlink_to(secret)
    out = file_watcher(_sandbox(ws)).fn({"path": str(ws), "since": 0})
    assert "link.txt" in out and "12345" not in out
