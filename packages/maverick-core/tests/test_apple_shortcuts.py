"""apple_shortcuts: shortcuts:// URL builder. No network."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from maverick.tools.apple_shortcuts import apple_shortcuts


def _run(**kw):
    return apple_shortcuts().fn(kw)


def test_run_url_basic():
    out = _run(op="run_url", name="My Shortcut")
    assert out.startswith("shortcuts://run-shortcut?")
    q = parse_qs(urlsplit(out).query)
    assert q["name"] == ["My Shortcut"]
    assert "input" not in q


def test_run_url_encodes_spaces_and_specials():
    out = _run(op="run_url", name="Make Note", input="a & b / c?d")
    # Spaces are percent-encoded (not '+'); special chars are escaped.
    assert "Make%20Note" in out
    assert " " not in out and "+" not in out
    q = parse_qs(urlsplit(out).query)
    assert q["name"] == ["Make Note"]
    assert q["input"] == ["a & b / c?d"]


def test_xcallback_url_with_success():
    out = _run(
        op="xcallback",
        name="Run It",
        input="hello world",
        x_success="myapp://done",
    )
    assert out.startswith("shortcuts://x-callback-url/run-shortcut?")
    q = parse_qs(urlsplit(out).query)
    assert q["name"] == ["Run It"]
    assert q["input"] == ["hello world"]
    assert q["x-success"] == ["myapp://done"]


def test_xcallback_without_optionals():
    out = _run(op="xcallback", name="Solo")
    q = parse_qs(urlsplit(out).query)
    assert q["name"] == ["Solo"]
    assert "input" not in q and "x-success" not in q


def test_errors():
    t = apple_shortcuts()
    assert t.fn({"op": "run_url"}).startswith("ERROR")  # no name
    assert t.fn({"op": "xcallback", "name": "  "}).startswith("ERROR")
    assert t.fn({"op": "nope", "name": "x"}).startswith("ERROR")
