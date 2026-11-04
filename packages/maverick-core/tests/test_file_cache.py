"""Tests for the file cache (maverick.cache.file)."""
from __future__ import annotations

from maverick.cache import file as file_cache

# ---------- file_cache byte accounting ----------

def test_read_cache_counts_encoded_bytes(tmp_path):
    file_cache.clear_read_cache()
    # A multi-byte char: 'é' is 1 code point but 2 UTF-8 bytes.
    f = tmp_path / "u.txt"
    f.write_text("é" * 100, encoding="utf-8")
    text = file_cache.read_file_cached(f)
    assert text == "é" * 100
    stats = file_cache.read_cache_stats()
    # 100 chars -> 200 UTF-8 bytes, not 100.
    assert stats["bytes"] == 200
    file_cache.clear_read_cache()


def test_read_cache_byte_accounting_balances_on_evict(tmp_path):
    file_cache.clear_read_cache()
    f = tmp_path / "a.txt"
    f.write_text("ünïcödé", encoding="utf-8")
    file_cache.read_file_cached(f)
    # Re-reading the same key must not double-count (replace, not append).
    f.write_text("ünïcödé!", encoding="utf-8")
    file_cache.read_file_cached(f)
    stats = file_cache.read_cache_stats()
    assert stats["entries"] == 1
    assert stats["bytes"] == len("ünïcödé!".encode())
    file_cache.clear_read_cache()


# ---------- file_cache ----------

def test_file_cache_read_round_trip(tmp_path):
    from maverick.cache.file import (
        clear_read_cache,
        read_cache_stats,
        read_file_cached,
    )
    clear_read_cache()
    f = tmp_path / "f.txt"
    f.write_text("hello world")
    out = read_file_cached(f)
    assert out == "hello world"
    # Cache hit on second read.
    out2 = read_file_cached(f)
    assert out2 == "hello world"
    stats = read_cache_stats()
    assert stats["entries"] == 1
    clear_read_cache()


def test_file_cache_invalidates_on_mtime_change(tmp_path):
    import time as _time

    from maverick.cache.file import clear_read_cache, read_file_cached
    clear_read_cache()
    f = tmp_path / "f.txt"
    f.write_text("v1")
    assert read_file_cached(f) == "v1"
    # Bump mtime + content.
    _time.sleep(0.02)
    f.write_text("v2")
    assert read_file_cached(f) == "v2"
    clear_read_cache()


def test_file_cache_missing_file_returns_none(tmp_path):
    from maverick.cache.file import read_file_cached
    assert read_file_cached(tmp_path / "nope") is None


def test_repo_map_cache_invalidates_on_workdir_change(tmp_path):
    from maverick.cache.file import clear_repo_cache, repo_map_cached
    clear_repo_cache()
    workdir = tmp_path / "wd"
    workdir.mkdir()
    (workdir / "a.py").write_text("hi")
    calls = {"n": 0}

    def build():
        calls["n"] += 1
        return f"map-{calls['n']}"

    assert repo_map_cached(workdir, build) == "map-1"
    assert repo_map_cached(workdir, build) == "map-1"  # cached
    # Modify workdir -- new file changes signature.
    import time as _time
    _time.sleep(0.02)
    (workdir / "b.py").write_text("hi")
    assert repo_map_cached(workdir, build) == "map-2"
    clear_repo_cache()
