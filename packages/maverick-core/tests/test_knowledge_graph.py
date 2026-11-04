"""Tests for the knowledge_graph tool (maverick.tools.knowledge_graph)."""
from __future__ import annotations

from maverick.tools.knowledge_graph import knowledge_graph

# ---- knowledge_graph ----

def test_kg_extract_structured_and_heuristic():
    t = knowledge_graph()
    out = t.fn({
        "op": "extract",
        "text": "Lightwork uses Postgres. Orchestrator | spawns | sub-agents. "
                "The shield depends on the kernel.",
    })
    assert "Lightwork | uses | Postgres" in out
    assert "Orchestrator | spawns | sub-agents" in out
    assert "shield | depends_on | kernel" in out


def test_kg_query_and_neighbors():
    t = knowledge_graph()
    triples = [["a", "uses", "b"], ["b", "uses", "c"], ["d", "is_a", "a"]]
    q = t.fn({"op": "query", "triples": triples, "relation": "uses"})
    assert "a --uses--> b" in q and "b --uses--> c" in q and "d --is_a--> a" not in q
    n = t.fn({"op": "neighbors", "triples": triples, "node": "a"})
    assert "a --uses--> b" in n and "d --is_a--> a" in n


def test_kg_dot_render():
    t = knowledge_graph()
    out = t.fn({"op": "dot", "triples": [["a", "uses", "b"]]})
    assert out.startswith("digraph knowledge {") and "'a' -> 'b'" in out
