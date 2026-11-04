"""Tests for the cache purge module."""
from __future__ import annotations

from pathlib import Path


def test_cache_stats_shape(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import cache
    from maverick.cache.file import clear_read_cache, read_file_cached
    clear_read_cache()
    f = tmp_path / "x.txt"
    f.write_text("hello")
    read_file_cached(f)  # warm

    s = cache.stats()
    assert "files" in s
    assert s["files"]["entries"] >= 1
    assert s["files"]["bytes"] >= 5
    assert "skill_embeddings" in s


def test_cache_purge_files(tmp_path: Path):
    from maverick import cache
    from maverick.cache.file import clear_read_cache, read_cache_stats, read_file_cached
    clear_read_cache()
    f = tmp_path / "x.txt"
    f.write_text("hello world")
    read_file_cached(f)
    assert read_cache_stats()["entries"] >= 1

    report = cache.purge(["files"])
    assert "files" in report
    assert report["files"]["cleared_entries"] >= 1
    assert read_cache_stats()["entries"] == 0


def test_cache_purge_repo_map(tmp_path: Path):
    from maverick import cache
    from maverick.cache.file import clear_repo_cache, repo_map_cached
    clear_repo_cache()
    (tmp_path / "f.py").write_text("x")
    repo_map_cached(tmp_path, lambda: "MAP")

    report = cache.purge(["repo_map"])
    assert report["repo_map"]["cleared"]


def test_cache_purge_skill_embeddings(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import cache
    skill_dir = tmp_path / ".maverick"
    skill_dir.mkdir()
    skill_path = skill_dir / "skill_embeddings.json"
    skill_path.write_text('{"a": [0.1, 0.2]}')

    report = cache.purge(["skill_embeddings"])
    assert report["skill_embeddings"]["cleared"]
    assert not skill_path.exists()


def test_cache_purge_all(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import cache
    from maverick.cache.file import clear_read_cache, read_cache_stats, read_file_cached
    clear_read_cache()
    f = tmp_path / "y.txt"
    f.write_text("data")
    read_file_cached(f)

    report = cache.purge(["all"])
    assert {"files", "repo_map", "skill_embeddings"}.issubset(report.keys())
    assert read_cache_stats()["entries"] == 0


def test_cache_purge_unknown_scope_ignored(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import cache
    report = cache.purge(["nope", "files"])
    assert "files" in report
    assert "nope" not in report


def test_cache_purge_default_is_all(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import cache
    report = cache.purge([])
    assert {"files", "repo_map", "skill_embeddings"}.issubset(report.keys())
