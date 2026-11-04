"""Critical-path-aware scheduling: ready frontier ordered by remaining tail."""
from __future__ import annotations

from maverick.task_graph import TaskGraph


def _diamond():
    # a -> b -> d ; a -> c -> d, plus a long tail off b: b -> e -> f
    g = TaskGraph()
    for t in ("a", "b", "c", "d", "e", "f"):
        g.add_task(t, t)
    g.tasks["b"]["deps"] = ["a"]
    g.tasks["c"]["deps"] = ["a"]
    g.tasks["d"]["deps"] = ["b", "c"]
    g.tasks["e"]["deps"] = ["b"]
    g.tasks["f"]["deps"] = ["e"]
    return g


def test_remaining_weight_counts_longest_tail():
    g = _diamond()
    tail = g.remaining_critical_weight()
    # a's tail: a->b->e->f = 4 (the heaviest chain from a)
    assert tail["a"] == 4.0
    # b's tail: b->e->f = 3 ; c's tail: c->d = 2
    assert tail["b"] == 3.0 and tail["c"] == 2.0
    assert tail["f"] == 1.0  # leaf


def test_done_task_contributes_zero_own_weight():
    g = _diamond()
    # a done LEAF contributes nothing to the tail.
    g.set_status("f", "done")
    tail = g.remaining_critical_weight()
    assert tail["f"] == 0.0
    # e -> f, with f done: e's tail is just its own weight (1).
    assert tail["e"] == 1.0


def test_ready_prioritized_orders_by_tail():
    g = _diamond()
    g.set_status("a", "done")  # now b and c are ready
    order = g.ready_prioritized()
    # b (tail 3, on the long chain) must be dispatched before c (tail 2)
    assert order == ["b", "c"]


def test_ready_prioritized_uses_weights():
    g = TaskGraph()
    for t in ("root", "cheap", "expensive"):
        g.add_task(t)
    g.tasks["cheap"]["deps"] = ["root"]
    g.tasks["expensive"]["deps"] = ["root"]
    g.set_status("root", "done")
    # equal task counts, but `expensive` is heavier -> it goes first
    order = g.ready_prioritized(weights={"expensive": 10.0, "cheap": 1.0})
    assert order == ["expensive", "cheap"]


def test_schedule_op_renders_order(tmp_path, monkeypatch):
    import maverick.task_graph as tg
    from maverick.task_graph import _run
    g = _diamond()
    g.set_status("a", "done")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    g.save(tg._graph_path("sched"))
    res = _run({"op": "schedule", "graph": "sched"})
    assert "dispatch order" in res
    lines = [ln.strip() for ln in res.splitlines() if ln.strip().startswith(("b", "c"))]
    assert lines[0].startswith("b") and lines[1].startswith("c")
