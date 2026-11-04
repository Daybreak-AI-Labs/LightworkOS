"""Repo-map cache signature is content-aware (catches nested edits)."""
from __future__ import annotations

from maverick.cache.file import _workdir_signature, repo_map_cached


def test_nested_file_change_invalidates_signature(tmp_path):
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    f = sub / "mod.py"
    f.write_text("x = 1\n", encoding="utf-8")
    sig1 = _workdir_signature(tmp_path)
    # Edit a NESTED file (append -> size changes, so it's mtime-resolution
    # independent). The old immediate-children-only signature missed this.
    f.write_text("x = 1\ny = 2\n", encoding="utf-8")
    sig2 = _workdir_signature(tmp_path)
    assert sig1 and sig2 and sig1 != sig2


def test_new_nested_file_invalidates_signature(tmp_path):
    (tmp_path / "a.py").write_text("a\n", encoding="utf-8")
    sig1 = _workdir_signature(tmp_path)
    nested = tmp_path / "deep" / "deeper"
    nested.mkdir(parents=True)
    (nested / "new.py").write_text("new\n", encoding="utf-8")
    assert _workdir_signature(tmp_path) != sig1


def test_empty_top_level_directory_invalidates_signature(tmp_path):
    (tmp_path / "a.py").write_text("a\n", encoding="utf-8")
    sig1 = _workdir_signature(tmp_path)
    (tmp_path / "empty_top").mkdir()
    assert _workdir_signature(tmp_path) != sig1


def test_empty_nested_directory_invalidates_signature(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.py").write_text("x = 1\n", encoding="utf-8")
    sig1 = _workdir_signature(tmp_path)
    (pkg / "nested_empty").mkdir()
    assert _workdir_signature(tmp_path) != sig1


def test_skip_dirs_do_not_affect_signature(tmp_path):
    (tmp_path / "a.py").write_text("a\n", encoding="utf-8")
    sig1 = _workdir_signature(tmp_path)
    # Changes under a skipped dir (e.g. node_modules) must not bust the cache.
    nm = tmp_path / "node_modules" / "lib"
    nm.mkdir(parents=True)
    (nm / "huge.js").write_text("// vendored\n", encoding="utf-8")
    assert _workdir_signature(tmp_path) == sig1


def test_repo_map_cached_rebuilds_on_nested_change(tmp_path):
    f = tmp_path / "src" / "mod.py"
    f.parent.mkdir(parents=True)
    f.write_text("v1\n", encoding="utf-8")
    calls = {"n": 0}

    def _builder():
        calls["n"] += 1
        return f"map-{calls['n']}"

    assert repo_map_cached(tmp_path, _builder) == "map-1"
    assert repo_map_cached(tmp_path, _builder) == "map-1"  # cache hit, no rebuild
    f.write_text("v1\nv2\n", encoding="utf-8")              # nested edit
    assert repo_map_cached(tmp_path, _builder) == "map-2"   # rebuilt
    assert calls["n"] == 2


def test_repo_map_cached_rebuilds_on_empty_directory_change(tmp_path):
    (tmp_path / "pkg").mkdir()
    calls = {"n": 0}

    def _builder():
        calls["n"] += 1
        return f"map-{calls['n']}"

    assert repo_map_cached(tmp_path, _builder) == "map-1"
    assert repo_map_cached(tmp_path, _builder) == "map-1"  # cache hit
    (tmp_path / "pkg" / "nested_empty").mkdir()
    assert repo_map_cached(tmp_path, _builder) == "map-2"
    assert calls["n"] == 2
