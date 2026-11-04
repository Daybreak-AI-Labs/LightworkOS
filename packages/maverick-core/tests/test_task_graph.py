"""Persistent task graph."""
from __future__ import annotations

import pytest
from maverick.task_graph import TaskGraph


def _g():
    g = TaskGraph()
    g.add_task("a", "first")
    g.add_task("b", "second", deps=["a"])
    g.add_task("c", "third", deps=["a"])
    g.add_task("d", "fourth", deps=["b", "c"])
    return g


def test_ready_is_the_frontier():
    g = _g()
    assert g.ready() == ["a"]  # only a has no deps
    g.set_status("a", "done")
    assert g.ready() == ["b", "c"]  # both unblocked
    g.set_status("b", "done")
    assert g.ready() == ["c"]  # d still waits on c


def test_topo_order_respects_deps():
    order = _g().topo_order()
    assert order.index("a") < order.index("b")
    assert order.index("a") < order.index("c")
    assert order.index("b") < order.index("d")
    assert order.index("c") < order.index("d")


def test_cycle_detected_and_rejected():
    g = TaskGraph()
    g.add_task("x", deps=["y"])
    g.add_task("y", deps=["x"])
    assert g.has_cycle()
    with pytest.raises(ValueError):
        g.topo_order()


def test_self_dependency_rejected():
    g = TaskGraph()
    with pytest.raises(ValueError):
        g.add_task("a", deps=["a"])


def test_set_status_validates():
    g = _g()
    with pytest.raises(ValueError):
        g.set_status("a", "bogus")
    with pytest.raises(KeyError):
        g.set_status("zzz", "done")


def test_persist_roundtrip(tmp_path):
    g = _g()
    g.set_status("a", "done")
    path = tmp_path / "graph.json"
    g.save(path)
    g2 = TaskGraph.load(path)
    assert g2.tasks["a"]["status"] == "done"
    assert g2.tasks["d"]["deps"] == ["b", "c"]
    assert g2.ready() == ["b", "c"]


def test_load_missing_is_empty(tmp_path):
    assert TaskGraph.load(tmp_path / "nope.json").tasks == {}


# ---- critical path ----

def test_critical_path_linear_chain():
    g = TaskGraph()
    g.add_task("a")
    g.add_task("b", deps=["a"])
    g.add_task("c", deps=["b"])
    path, length = g.critical_path()
    assert path == ["a", "b", "c"] and length == 3.0


def test_critical_path_diamond():
    # a -> {b, c} -> d ; longest chain is length 3 (a, b|c, d)
    path, length = _g().critical_path()
    assert length == 3.0
    assert path[0] == "a" and path[-1] == "d" and len(path) == 3


def test_critical_path_weighted():
    g = TaskGraph()
    g.add_task("a")
    g.add_task("b", deps=["a"])   # heavy
    g.add_task("c", deps=["a"])   # light
    path, length = g.critical_path(weights={"a": 1, "b": 5, "c": 2})
    assert path == ["a", "b"] and length == 6.0


def test_critical_path_empty_and_cycle():
    assert TaskGraph().critical_path() == ([], 0.0)
    g = TaskGraph()
    g.add_task("a", deps=["b"])
    g.tasks["b"] = {"title": "", "deps": ["a"], "status": "todo"}  # cycle
    assert g.critical_path() == ([], 0.0)


def test_tool_critical_op(tmp_path, monkeypatch):
    import maverick.task_graph as tg
    monkeypatch.setattr(tg, "_STORE", tmp_path)
    t = tg.task_graph()
    t.fn({"op": "add", "task": "a"})
    t.fn({"op": "add", "task": "b", "deps": ["a"]})
    out = t.fn({"op": "critical"})
    assert "critical path" in out and "a -> b" in out


# ---- concurrency: atomic save + lock-guarded load-modify-save ----

def test_save_is_atomic_under_concurrent_reads(tmp_path):
    """A bare write_text truncates in place, so a reader mid-write sees a
    half-written file and json.load raises -> the whole DAG is lost. With the
    atomic temp+replace, a concurrent reader only ever sees a whole file."""
    import threading

    path = tmp_path / "graph.json"
    g = _g()
    g.save(path)  # seed a valid file
    errors: list[Exception] = []
    stop = threading.Event()

    def writer():
        for i in range(200):
            gg = TaskGraph()
            for j in range(i + 1):
                gg.add_task(f"t{j}", "x" * 50)
            gg.save(path)

    def reader():
        while not stop.is_set():
            try:
                TaskGraph.load(path)  # must never see a torn file
            except (ValueError, OSError) as e:  # json torn read / mid-replace
                errors.append(e)

    rt = threading.Thread(target=reader)
    rt.start()
    wt = threading.Thread(target=writer)
    wt.start()
    wt.join()
    stop.set()
    rt.join()
    assert not errors, f"torn read(s): {errors[:3]}"


def test_tool_add_is_concurrency_safe(tmp_path, monkeypatch):
    """Concurrent add ops do a load-modify-save; without the cross-process lock
    the second save clobbers the first's task -> tasks silently vanish. Each of
    N writers adds a distinct task id; all N must survive."""
    import threading

    import maverick.task_graph as tg
    monkeypatch.setattr(tg, "_STORE", tmp_path)
    t = tg.task_graph()

    n = 40

    def add(i: int):
        t.fn({"op": "add", "task": f"task{i:03d}", "title": "t"})

    threads = [threading.Thread(target=add, args=(i,)) for i in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    g = TaskGraph.load(tmp_path / "default.json")
    assert len(g.tasks) == n, f"lost updates: only {len(g.tasks)} of {n} survived"


def test_tool_graphs_are_principal_scoped(tmp_path, monkeypatch):
    import maverick.task_graph as tg
    from maverick.connections import bind_principal

    monkeypatch.setattr(tg, "_STORE", tmp_path)
    tool = tg.task_graph()
    with bind_principal("user:alice"):
        assert "added" in tool.fn({"op": "add", "task": "alice-only"})
        assert "alice-only" in tool.fn({"op": "list"})
    with bind_principal("user:bob"):
        assert tool.fn({"op": "list"}) == "(empty)"
    with bind_principal("user:alice"):
        assert "alice-only" in tool.fn({"op": "list"})


def test_tool_principal_resolution_failure_never_uses_shared_graph(
    tmp_path, monkeypatch,
):
    import maverick.connections as connections
    import maverick.task_graph as tg

    monkeypatch.setattr(tg, "_STORE", tmp_path)

    def _broken_authority():
        raise RuntimeError("authority unavailable")

    monkeypatch.setattr(connections, "current_principal", _broken_authority)
    with pytest.raises(RuntimeError, match="authority unavailable"):
        tg.task_graph().fn({"op": "add", "task": "must-not-land"})
    assert not list(tmp_path.rglob("*.json"))


def test_tool_store_resolves_active_tenant_per_call(tmp_path, monkeypatch):
    import maverick.task_graph as tg
    from maverick.paths import tenant_scope

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(tg, "_STORE", tg._INITIAL_STORE)
    tool = tg.task_graph()
    with tenant_scope(tenant="acme"):
        tool.fn({"op": "add", "task": "acme-only"})
        assert "acme-only" in tool.fn({"op": "list"})
    with tenant_scope(tenant="globex"):
        assert tool.fn({"op": "list"}) == "(empty)"


# ---- DoS: deep chains must not blow the Python stack ----

def test_deep_chain_does_not_recurse_or_crash():
    """has_cycle/topo_order use an explicit stack, not recursion. A linear
    chain far deeper than sys.getrecursionlimit() (an agent can build it via
    repeated `add` ops on the persisted, tool-callable graph) must not raise
    RecursionError."""
    g = TaskGraph()
    n = 2500  # comfortably past the default recursion limit (~1000)
    for i in range(n):
        g.add_task(f"t{i}", deps=[f"t{i + 1}"] if i + 1 < n else [])
    assert g.has_cycle() is False
    order = g.topo_order()
    assert len(order) == n
    # A deep cycle is still detected (no false negative from the rewrite).
    g.add_task(f"t{n - 1}", deps=["t0"])
    assert g.has_cycle() is True


def test_node_count_is_capped():
    """The persisted, agent-built graph is bounded so it can't grow without
    limit (O(V^2) topo_order + on-disk bloat)."""
    import maverick.task_graph as tg
    g = TaskGraph()
    for i in range(tg._MAX_TASKS):
        g.add_task(f"t{i}")
    assert len(g.tasks) == tg._MAX_TASKS
    with pytest.raises(ValueError, match="full"):
        g.add_task("one-too-many")
    # Updating an EXISTING task at the cap still works (not a new node).
    g.add_task("t0", title="updated")
    assert g.tasks["t0"]["title"] == "updated"


def test_tool_op_survives_a_deep_chain(tmp_path, monkeypatch):
    """The `order` op over a deep persisted graph returns a result instead of
    crashing the tool call with an uncaught RecursionError."""
    import maverick.task_graph as tg
    monkeypatch.setattr(tg, "_STORE", tmp_path)
    t = tg.task_graph()
    n = 1500  # past the recursion limit
    # Persist the deep chain once. Building it through 1,500 tool "add" calls
    # rewrote and fsynced the whole growing file each time (about 3,000
    # fsyncs), which passed in seconds alone but hit the 180 s limit on a
    # loaded disk; the op under test is "order", not "add".
    g = tg.TaskGraph()
    for i in range(n):
        g.add_task(f"t{i}", "", [f"t{i + 1}"] if i + 1 < n else [])
    g.save(tg._graph_path("default"))
    out = t.fn({"op": "order"})
    assert "t0" in out and "ERROR" not in out
