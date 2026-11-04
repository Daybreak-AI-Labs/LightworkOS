"""error_patterns: normalize + cluster error lines by signature."""
from __future__ import annotations

from maverick.tools.error_patterns import error_patterns


def test_clusters_near_identical_errors():
    t = error_patterns()
    out = t.fn({"op": "analyze", "errors": [
        "connection to 10.0.0.4:5432 failed",
        "connection to 10.0.0.9:5454 failed",
        "connection to 192.168.1.1:5432 failed",
        "timeout after 30s",
        "timeout after 45s",
    ]})
    assert "2 distinct pattern(s) across 5 line(s)" in out
    # the 3 connection errors collapse to one bucket, ranked first
    assert "3x  connection to <ip>:<n> failed" in out
    assert "2x  timeout after <n>s" in out


def test_normalizes_uuid_path_hex_ts():
    t = error_patterns()
    out = t.fn({"op": "analyze", "errors": [
        "2026-06-09T04:00:00Z ERROR job 550e8400-e29b-41d4-a716-446655440000 at /var/log/app.log failed 0xdeadbeef",
    ]})
    assert "<ts>" in out and "<uuid>" in out and "<addr>" in out
    assert "ERROR job <uuid> at <path> failed <addr>" in out.replace("<ts> ", "")


def test_text_blob_input_and_top():
    t = error_patterns()
    blob = "err 1\nerr 2\nerr 3\nother\n"
    out = t.fn({"op": "analyze", "text": blob, "top": 1})
    assert "distinct pattern(s) across 4 line(s)" in out
    # top=1 -> only the most frequent bucket ("err <n>", count 3) shown
    assert "3x  err <n>" in out


def test_errors_and_empty():
    t = error_patterns()
    assert t.fn({"op": "analyze"}).startswith("ERROR")
    assert t.fn({"op": "analyze", "errors": []}).startswith("ERROR")
    # whitespace-only text has no usable input -> ERROR
    assert t.fn({"op": "analyze", "text": "   \n  \n"}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "error_patterns" in names
