"""chaos_gameday: chaos game-day script generator."""
from __future__ import annotations

from maverick.tools.chaos_gameday import chaos_gameday

_GRAPH = [
    {"name": "web", "deps": ["api"]},
    {"name": "api", "deps": ["db", "cache"]},
    {"name": "db", "deps": []},
    {"name": "cache", "deps": []},
]


def _plan(components, fault):
    return chaos_gameday().fn({"op": "plan", "components": components, "fault": fault})


def test_topological_order_dependencies_first():
    out = _plan(_GRAPH, "kill")
    # Leaves (db, cache) before api before web.
    assert out.index("kill db") < out.index("kill api") < out.index("kill web")
    assert out.index("kill cache") < out.index("kill api")
    assert out.startswith("PLAN fault=kill steps=4 components=4")


def test_blast_radius_is_transitive_downstream():
    out = _plan(_GRAPH, "latency")
    # db's blast radius = everything that (transitively) depends on it.
    assert "latency db (inject artificial latency); blast_radius=[api, web]" in out
    # web is a sink: nothing downstream.
    assert "latency web (inject artificial latency); blast_radius=[(none — leaf-facing)]" in out


def test_rollback_note_matches_fault():
    out = _plan(_GRAPH, "netsplit")
    assert "rollback: heal the partition" in out
    assert "reverse step order" in out


def test_cycle_detected_but_not_fatal():
    out = _plan([
        {"name": "a", "deps": ["b"]},
        {"name": "b", "deps": ["a"]},
    ], "kill")
    assert out.startswith("PLAN") and "cycle detected among: a, b" in out
    # Both still appear as steps.
    assert "kill a" in out and "kill b" in out


def test_deterministic_tie_break_by_name():
    out1 = _plan(_GRAPH, "kill")
    out2 = _plan(list(reversed(_GRAPH)), "kill")
    # Order independent of input ordering (ties broken by name).
    assert out1 == out2


def test_errors():
    t = chaos_gameday()
    assert t.fn({"op": "plan", "fault": "kill"}).startswith("ERROR")  # no components
    assert t.fn({"op": "plan", "components": [{"name": "a"}], "fault": "boom"}).startswith("ERROR")
    assert t.fn({"op": "nope", "components": [{"name": "a"}], "fault": "kill"}).startswith("ERROR")
    assert t.fn(
        {"op": "plan", "components": [{"name": "a"}, {"name": "a"}], "fault": "kill"}
    ).startswith("ERROR")  # duplicate name
