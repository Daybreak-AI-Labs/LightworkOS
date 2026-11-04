"""Graph-structured compaction (v8): history -> triples + rendered digest."""
from __future__ import annotations

from maverick.compaction import compact_messages
from maverick.compaction.graph import (
    compact_graph,
    extract_triples,
    render_digest,
)

_PROSE = (
    "parser-service depends on redis. "
    "deploy requires green CI. "
    "release v2 contains the parser fix."
)


def _msgs() -> list[dict]:
    return [
        {"role": "user", "content": "GOAL: ship parser-service."},
        {"role": "assistant", "content": "parser-service depends on redis."},
        {"role": "user", "content": "deploy requires green CI."},
        {"role": "assistant", "content": [
            {"type": "text", "text": "release v2 contains the parser fix."},
        ]},
        {"role": "user", "content": "recent question"},
        {"role": "assistant", "content": "recent answer"},
    ]


class TestExtractTriples:
    def test_heuristic_prose_extraction_is_deterministic(self):
        triples = extract_triples(_PROSE)
        assert ["parser-service", "depends_on", "redis"] in triples
        assert ["deploy", "requires", "green CI"] in triples
        assert triples == extract_triples(_PROSE)

    def test_structured_lines_parsed(self):
        triples = extract_triples("alpha | uses | beta")
        assert triples == [["alpha", "uses", "beta"]]

    def test_dedupe_case_insensitive_and_cap(self):
        text = "alpha | uses | beta. Alpha | Uses | Beta. gamma | uses | delta"
        assert len(extract_triples(text)) == 2
        assert extract_triples(text, max_triples=1) == [["alpha", "uses", "beta"]]

    def test_llm_adds_triples_after_heuristic_ones(
        self, fake_llm, make_llm_response,
    ):
        fake_llm.scripted = [make_llm_response("omega | produces | sigma")]
        triples = extract_triples(_PROSE, llm=fake_llm)
        assert triples[0] == ["parser-service", "depends_on", "redis"]
        assert ["omega", "produces", "sigma"] in triples

    def test_llm_uses_configured_summarizer_role_model(
        self, monkeypatch, fake_llm, make_llm_response,
    ):
        monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE_SUMMARIZER", "testprov:tiny-sum")
        fake_llm.scripted = [make_llm_response("")]
        extract_triples(_PROSE, llm=fake_llm)
        assert fake_llm.calls[0]["model"] == "testprov:tiny-sum"

    def test_llm_failure_keeps_heuristic_triples(self):
        class Boom:
            def complete(self, *a, **kw):
                raise RuntimeError("api down")

        triples = extract_triples(_PROSE, llm=Boom())
        assert ["parser-service", "depends_on", "redis"] in triples


class TestRenderDigest:
    def test_counts_and_arrow_lines(self):
        digest = render_digest(
            [["a", "uses", "b"], ["b", "requires", "c"]], turns=7)
        assert digest.startswith('<graph-digest turns="7" entities="3" triples="2">')
        assert "a --uses--> b" in digest
        assert "b --requires--> c" in digest
        assert digest.endswith("</graph-digest>")


class TestCompactGraph:
    def test_short_list_passes_through(self):
        msgs = [{"role": "user", "content": "hi"}]
        assert compact_graph(msgs) == msgs

    def test_middle_replaced_by_graph_digest(self):
        msgs = _msgs()
        out = compact_graph(msgs, keep_recent=2)
        assert out[0] == msgs[0]
        assert out[-2:] == msgs[-2:]
        assert len(out) == 4  # brief + digest + 2-message tail
        body = out[1]["content"]
        assert '<graph-digest turns="3"' in body
        assert "parser-service --depends_on--> redis" in body
        assert "deploy --requires--> green CI" in body
        assert "release v2 --contains--> parser fix" in body

    def test_no_triples_falls_back_to_default(self):
        msgs = [
            {"role": "user", "content": "GOAL"},
            {"role": "assistant", "content": "zxqv"},
            {"role": "user", "content": "wibble"},
            {"role": "user", "content": "recent q"},
            {"role": "assistant", "content": "recent a"},
        ]
        assert compact_graph(msgs, keep_recent=2) == compact_messages(msgs, keep_recent=2)

    def test_llm_backed_triples_land_in_digest(self, fake_llm, make_llm_response):
        fake_llm.scripted = [make_llm_response("omega | produces | sigma")]
        out = compact_graph(_msgs(), keep_recent=2, llm=fake_llm)
        assert "omega --produces--> sigma" in out[1]["content"]

    def test_input_not_mutated(self):
        msgs = _msgs()
        import json
        snapshot = json.dumps(msgs)
        compact_graph(msgs, keep_recent=2)
        assert json.dumps(msgs) == snapshot
