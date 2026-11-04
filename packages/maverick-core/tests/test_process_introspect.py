"""process_introspect: offline analysis of a caller-supplied snapshot."""
from __future__ import annotations

from maverick.tools.process_introspect import process_introspect

_SNAP = [
    {"pid": 1, "ppid": 0, "name": "init", "rss_kb": 100, "cpu_pct": 0.1},
    {"pid": 2, "ppid": 1, "name": "big", "rss_kb": 5000, "cpu_pct": 2.0},
    {"pid": 3, "ppid": 1, "name": "hot", "rss_kb": 2000, "cpu_pct": 90.0},
]


def _run(**kw):
    return process_introspect().fn({"op": "parse", **kw})


def test_top_by_rss_orders_descending():
    out = _run(snapshot=_SNAP, top=2, by="rss")
    lines = out.splitlines()
    assert lines[0] == "OK: 3 process(es); top 2 by rss"
    assert lines[1].startswith("pid=2 big rss_kb=5000")
    assert lines[2].startswith("pid=3 hot rss_kb=2000")
    assert "orphans: 0" in out  # ppid=0 is a root, not an orphan


def test_top_by_cpu():
    out = _run(snapshot=_SNAP, top=1, by="cpu")
    assert "top 1 by cpu" in out
    assert "pid=3 hot cpu_pct=90" in out
    assert "pid=2" not in out.split("orphans")[0]  # only top-1 ranked


def test_orphan_detection():
    out = _run(snapshot=[
        {"pid": 10, "ppid": 999, "name": "lost", "rss_kb": 10, "cpu_pct": 0},
        {"pid": 11, "ppid": 10, "name": "child", "rss_kb": 5, "cpu_pct": 0},
    ])
    assert "orphans: 1 (ppid not in snapshot)" in out
    assert "orphan pid=10 lost ppid=999" in out
    assert "pid=11" not in out.split("orphans:")[1]  # parent present, not orphan


def test_default_top_is_five():
    out = _run(snapshot=_SNAP)
    assert "top 3 by rss" in out  # only 3 procs though default top=5


def test_empty_snapshot():
    out = _run(snapshot=[])
    assert out.startswith("OK: 0 process(es)")
    assert "orphans: 0" in out


def test_errors():
    t = process_introspect()
    assert t.fn({"op": "parse"}).startswith("ERROR")  # no snapshot
    assert _run(snapshot=_SNAP, by="mem").startswith("ERROR")  # bad metric
    assert _run(snapshot=_SNAP, top=0).startswith("ERROR")  # top < 1
    assert _run(snapshot=[{"ppid": 1}]).startswith("ERROR")  # missing pid
    assert t.fn({"op": "nope", "snapshot": []}).startswith("ERROR")
