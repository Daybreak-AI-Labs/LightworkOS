"""Tests for the web_archive tool. No network calls."""
from __future__ import annotations

from maverick.tools import web_archive as wa


def test_snapshot_missing_url_errors():
    out = wa.web_archive().fn({"op": "snapshot", "url": ""})
    assert out.startswith("ERROR")
    assert "url is required" in out


def test_save_missing_url_errors():
    out = wa.web_archive().fn({"op": "save", "url": "  "})
    assert out.startswith("ERROR")
    assert "url is required" in out


def test_unknown_op_errors():
    assert wa.web_archive().fn({"op": "nope", "url": "x"}).startswith(
        "ERROR: unknown op"
    )


def test_avail_url_builder():
    url = wa._avail_url("http://example.com", "20200101")
    assert url.startswith("https://archive.org/wayback/available?")
    assert "url=http%3A%2F%2Fexample.com" in url
    assert "timestamp=20200101" in url
    # Without a timestamp the param is omitted.
    assert "timestamp" not in wa._avail_url("http://example.com")


def test_save_url_builder_and_op():
    assert wa._save_url("http://example.com") == (
        "https://web.archive.org/save/http://example.com"
    )
    out = wa.web_archive().fn({"op": "save", "url": "http://example.com"})
    assert "save endpoint:" in out
    assert "https://web.archive.org/save/http://example.com" in out


def test_parse_availability_present_and_absent():
    present = {
        "archived_snapshots": {
            "closest": {
                "available": True,
                "url": "http://web.archive.org/web/2020/http://example.com",
                "timestamp": "20200101000000",
                "status": "200",
            }
        }
    }
    out = wa._parse_availability(present)
    assert "snapshot:" in out
    assert "20200101000000" in out
    assert "status: 200" in out
    assert wa._parse_availability({"archived_snapshots": {}}) == "no snapshot found"
    assert wa._parse_availability({}) == "no snapshot found"


def test_snapshot_op_uses_helper(monkeypatch):
    captured = {}

    def fake_get(url):
        captured["url"] = url
        return 200, {
            "archived_snapshots": {
                "closest": {"available": True, "url": "U", "timestamp": "T",
                            "status": "200"}
            }
        }

    monkeypatch.setattr(wa, "_http_get_json", fake_get)
    out = wa.web_archive().fn({"op": "snapshot", "url": "http://example.com"})
    assert "snapshot:" in out
    assert captured["url"].startswith("https://archive.org/wayback/available?")
