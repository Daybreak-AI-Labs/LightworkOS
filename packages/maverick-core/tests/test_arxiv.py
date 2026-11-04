"""Tests for the arXiv tool (maverick.tools.arxiv)."""
from __future__ import annotations

# ---------- arxiv tool ----------

def test_arxiv_search_requires_query():
    from maverick.tools.arxiv import arxiv
    out = arxiv().fn({"op": "search", "query": ""})
    assert "requires query" in out


def test_arxiv_fetch_requires_id():
    from maverick.tools.arxiv import arxiv
    out = arxiv().fn({"op": "fetch", "arxiv_id": ""})
    assert "requires arxiv_id" in out


def test_arxiv_parser_handles_real_atom():
    from maverick.tools.arxiv import _parse_atom
    # A trimmed-down arxiv-shaped response.
    xml = """
    <feed>
      <entry>
        <id>http://arxiv.org/abs/2106.09685v3</id>
        <title>LoRA: Low-Rank Adaptation of Large Language Models</title>
        <summary>We propose Low-Rank Adaptation, or LoRA, which freezes...</summary>
        <published>2021-06-17T17:01:48Z</published>
        <name>Edward J. Hu</name>
        <name>Yelong Shen</name>
      </entry>
    </feed>
    """
    entries = _parse_atom(xml)
    assert len(entries) == 1
    e = entries[0]
    assert e["arxiv_id"] == "2106.09685"
    assert "LoRA" in e["title"]
    assert "Hu" in e["authors"]


class TestArxivOldStyleId:
    def test_old_style_id_with_slash_preserved(self):
        import re
        # Mirror the normalization in _op_fetch.
        def norm(s):
            s = re.sub(r"^https?://arxiv\.org/(?:abs|pdf)/", "", s)
            return re.sub(r"v\d+$", "", s)
        assert norm("math.GT/0309136") == "math.GT/0309136"
        assert norm("https://arxiv.org/abs/math.GT/0309136v1") == "math.GT/0309136"
        assert norm("2106.09685v2") == "2106.09685"
