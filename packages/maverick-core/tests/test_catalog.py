"""Federated catalog client + hash-pinned skill install."""
from __future__ import annotations

import hashlib
import json
import os
import time

import pytest
from maverick import catalog

_SKILL_BODY = """---
name: summarize-url
triggers: ["summarize this url"]
tools_needed: ["http_fetch"]
---
# Summarize a URL

Fetch with http_fetch, write 3 sentences.
"""
_SKILL_SHA = hashlib.sha256(_SKILL_BODY.encode()).hexdigest()


def _index(entries: list[dict]) -> dict:
    return {"schema_version": 1, "kind": "skills", "entries": entries}


def _entry(**over) -> dict:
    e = {
        "name": "summarize-url",
        "version": "1.0.0",
        "summary": "Fetch a URL and summarise.",
        "source": "gh:org/repo:SKILL.md",
        "sha256": _SKILL_SHA,
        "author": "org",
        "verified": True,
    }
    e.update(over)
    return e


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch, tmp_path):
    # Point the catalog cache at a tmp dir so tests don't read ~/.maverick.
    monkeypatch.setattr(catalog, "_CACHE_DIR", tmp_path / "catalog-cache")


def _stub_fetch(monkeypatch, mapping: dict[str, dict]):
    """Replace _fetch_index_raw with an in-memory map of url -> index dict."""
    monkeypatch.setattr(catalog, "_fetch_index_raw", lambda url: mapping.get(url))


# ---------- entry parsing ----------

def test_entry_from_dict_requires_name_and_source():
    with pytest.raises(catalog.CatalogError):
        catalog.CatalogEntry.from_dict("skills", {"name": "x"})  # no source
    with pytest.raises(catalog.CatalogError):
        catalog.CatalogEntry.from_dict("skills", {"source": "gh:x/y"})  # no name


def test_entry_round_trips():
    e = catalog.CatalogEntry.from_dict("skills", _entry())
    d = e.to_dict()
    assert d["name"] == "summarize-url"
    assert d["sha256"] == _SKILL_SHA
    assert d["verified"] is False  # index claims are not independent verification


def test_malformed_statistics_and_entries_do_not_hide_valid_catalog(monkeypatch):
    indexes = {
        "https://broken.example/skills/index.json": ["invalid index"],
        "https://valid.example/skills/index.json": _index([
            None, _entry(install_count="1.2k"), _entry(name="second-skill", install_count=float("inf")),
        ]),
    }
    monkeypatch.setattr(catalog, "_fetch_index_raw", indexes.get)
    entries = catalog.load_catalog("skills", indexes=["https://broken.example", "https://valid.example"])
    assert {entry.name for entry in entries} == {"summarize-url", "second-skill"}
    assert all(entry.install_count == 0 for entry in entries)


# ---------- load_catalog ----------

def test_load_catalog_unknown_kind_raises():
    with pytest.raises(catalog.CatalogError):
        catalog.load_catalog("widgets")


def test_load_catalog_merges_indexes_earlier_wins(monkeypatch):
    _stub_fetch(monkeypatch, {
        "https://a/skills/index.json": _index([_entry(version="2.0.0")]),
        "https://b/skills/index.json": _index([_entry(version="9.9.9")]),
    })
    out = catalog.load_catalog("skills", indexes=["https://a", "https://b"])
    assert len(out) == 1
    assert out[0].version == "2.0.0"  # index a wins


def test_load_catalog_skips_malformed_entries(monkeypatch):
    _stub_fetch(monkeypatch, {
        "https://a/skills/index.json": _index([
            {"name": "good", "source": "gh:x/y", "sha256": "abc"},
            {"name": "bad-no-source"},  # malformed → skipped
        ]),
    })
    out = catalog.load_catalog("skills", indexes=["https://a"])
    assert [e.name for e in out] == ["good"]


def test_load_catalog_unreachable_index_returns_empty(monkeypatch):
    _stub_fetch(monkeypatch, {})  # every url -> None
    assert catalog.load_catalog("skills", indexes=["https://nope"]) == []


def test_resolve_finds_by_name(monkeypatch):
    _stub_fetch(monkeypatch, {
        "https://a/skills/index.json": _index([_entry()]),
    })
    e = catalog.resolve("summarize-url", "skills", indexes=["https://a"])
    assert e is not None and e.name == "summarize-url"
    assert catalog.resolve("missing", "skills", indexes=["https://a"]) is None


# ---------- verify_sha256 ----------

def test_verify_sha256_matches():
    assert catalog.verify_sha256(_SKILL_BODY, _SKILL_SHA) is True


def test_verify_sha256_rejects_mismatch():
    assert catalog.verify_sha256("tampered", _SKILL_SHA) is False


def test_verify_sha256_rejects_empty_hash():
    # An unpinned entry is not installable without the opt-in gate.
    assert catalog.verify_sha256(_SKILL_BODY, "") is False


# ---------- cache behaviour ----------

def test_fetch_index_caches(monkeypatch, tmp_path):
    calls = {"n": 0}

    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, _n=-1): return json.dumps(_index([_entry()])).encode()

    def _open(self, url, timeout=0):
        calls["n"] += 1
        return _Resp()

    # catalog now fetches through maverick.tools.http_fetch.guarded_urlopen
    # (shared SSRF guard), which uses a custom opener that revalidates every
    # redirect hop; patch the opener's open() and neutralize the host check so
    # the test stays hermetic.
    import urllib.request

    from maverick.tools import http_fetch
    monkeypatch.setattr(http_fetch, "is_blocked_host", lambda _h: False)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", _open)
    url = "https://a/skills/index.json"
    catalog._fetch_index_raw(url)
    catalog._fetch_index_raw(url)  # second call should hit the cache
    assert calls["n"] == 1


def test_fetch_index_refuses_non_https(monkeypatch):
    assert catalog._fetch_index_raw("http://insecure/skills/index.json") is None


# ---------- negative cache + page timeout ----------

@pytest.fixture(autouse=True)
def _fresh_negative_cache(monkeypatch):
    monkeypatch.setattr(catalog, "_NEGATIVE", {})


def _patch_failing_opener(monkeypatch, calls: dict):
    import urllib.request

    from maverick.tools import http_fetch

    def _open(self, url, timeout=0):
        calls["n"] += 1
        calls["timeout"] = timeout
        raise OSError("offline")

    monkeypatch.setattr(http_fetch, "is_blocked_host", lambda _h: False)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", _open)


def test_failed_fetch_is_not_retried_within_negative_ttl(monkeypatch):
    calls = {"n": 0}
    _patch_failing_opener(monkeypatch, calls)
    url = "https://down/skills/index.json"
    assert catalog._fetch_index_raw(url) is None
    assert catalog._fetch_index_raw(url) is None
    assert catalog._fetch_index_raw(url) is None
    assert calls["n"] == 1  # the two later calls never touched the network


def test_negative_cache_expires(monkeypatch):
    calls = {"n": 0}
    _patch_failing_opener(monkeypatch, calls)
    url = "https://down/skills/index.json"
    now = [1000.0]
    monkeypatch.setattr(catalog.time, "monotonic", lambda: now[0])
    catalog._fetch_index_raw(url)
    now[0] += catalog.NEGATIVE_CACHE_TTL - 1
    catalog._fetch_index_raw(url)
    assert calls["n"] == 1
    now[0] += 2
    catalog._fetch_index_raw(url)
    assert calls["n"] == 2


def test_negative_cache_serves_stale_disk_cache(monkeypatch, tmp_path):
    calls = {"n": 0}
    _patch_failing_opener(monkeypatch, calls)
    url = "https://down/skills/index.json"
    cache = catalog._cache_path(url)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(_index([_entry(name="stale")])))
    old = time.time() - catalog._CACHE_TTL - 10
    os.utime(cache, (old, old))
    first = catalog._fetch_index_raw(url)
    second = catalog._fetch_index_raw(url)
    assert first["entries"][0]["name"] == "stale"
    assert second == first
    assert calls["n"] == 1


def test_successful_fetch_clears_negative_cache(monkeypatch):
    calls = {"n": 0}
    _patch_failing_opener(monkeypatch, calls)
    url = "https://flaky/skills/index.json"
    catalog._fetch_index_raw(url)
    assert url in catalog._NEGATIVE
    catalog._NEGATIVE.clear()  # TTL elapsed

    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, _n=-1): return json.dumps(_index([_entry()])).encode()

    import urllib.request
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", lambda self, url, timeout=0: _Resp())
    assert catalog._fetch_index_raw(url)["entries"]
    assert url not in catalog._NEGATIVE


def test_load_catalog_timeout_bounds_the_fetch(monkeypatch):
    calls = {"n": 0}
    _patch_failing_opener(monkeypatch, calls)
    catalog.load_catalog("skills", indexes=["https://down"], timeout=catalog.PAGE_FETCH_TIMEOUT)
    assert calls["timeout"] == catalog.PAGE_FETCH_TIMEOUT
    catalog._NEGATIVE.clear()
    catalog.load_catalog("skills", indexes=["https://down"])
    assert calls["timeout"] == catalog.FETCH_TIMEOUT
    assert catalog._FETCH_TIMEOUT.get() is None  # reset after the call


def test_verify_sha256_refuses_a_lone_surrogate_pin_without_raising():
    # Catalog JSON can carry a lone surrogate; it is a mismatch, not an exception.
    assert catalog.verify_sha256(b"content", "\ud800") is False
