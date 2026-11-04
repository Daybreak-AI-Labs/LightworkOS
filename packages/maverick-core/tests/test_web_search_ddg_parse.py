"""DDG lite HTML parsing: correct extraction + bounded (ReDoS-safe) regex.

The matcher must not catastrophically backtrack on a large/hostile page -- the
old unbounded `(.+?) ... .*? ... (.+?)` with DOTALL was quadratic over many
result anchors."""
from __future__ import annotations

from maverick.tools.web_search import _parse_ddg_results

_SAMPLE = (
    '<a class="result__a" href="/l/?uddg=https%3A%2F%2Fexample.com%2Fa&rut=x">'
    "First <b>Title</b></a>\n"
    '<span class="result__url">example.com</span>\n'
    '<a class="result__snippet">First snippet text.</a>\n'
    '<a class="result__a" href="/l/?uddg=https%3A%2F%2Fexample.org%2Fb">Second</a>\n'
    '<a class="result__snippet">Second snippet.</a>\n'
)


def test_parses_title_url_and_snippet():
    out = _parse_ddg_results(_SAMPLE, num=10)
    assert len(out) == 2
    assert out[0] == {
        "title": "First Title",
        "url": "https://example.com/a",
        "snippet": "First snippet text.",
    }
    assert out[1]["url"] == "https://example.org/b"
    assert out[1]["title"] == "Second"


def test_respects_num_limit():
    assert len(_parse_ddg_results(_SAMPLE, num=1)) == 1


def test_drops_non_http_target():
    html = (
        '<a class="result__a" href="javascript:alert(1)">x</a>'
        '<a class="result__snippet">s</a>'
    )
    assert _parse_ddg_results(html, num=10) == []


def test_bounded_against_pathological_input():
    # Many result anchors, each followed by junk and NO snippet: the old
    # unbounded regex scanned to EOF per anchor (quadratic); the bounded one
    # gives up after the cap and returns quickly. The test completing is the
    # assertion -- a quadratic matcher would hang on this ~300KB input.
    evil = ('<a class="result__a" href="https://x/">t</a>' + "Z" * 6000) * 50
    assert _parse_ddg_results(evil, num=10) == []
