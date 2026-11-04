"""comparative_replay: step-aligned divergence diff of two run traces."""
from __future__ import annotations

from maverick.tools.comparative_replay import comparative_replay


def _run(**kw):
    return comparative_replay().fn({"op": "compare", **kw})


def test_identical_traces():
    trace = [{"step": 1, "action": "read", "result": "ok"},
             {"step": 2, "action": "write", "result": "ok"}]
    out = _run(run_a=trace, run_b=[dict(e) for e in trace])
    assert out.startswith("IDENTICAL")
    assert "similarity=100.0%" in out
    assert "matched 2/2" in out


def test_first_divergence_on_action():
    a = [{"step": 1, "action": "read", "result": "ok"},
         {"step": 2, "action": "write", "result": "ok"}]
    b = [{"step": 1, "action": "read", "result": "ok"},
         {"step": 2, "action": "delete", "result": "ok"}]
    out = _run(run_a=a, run_b=b)
    assert out.startswith("DIVERGES at step 2")
    assert "MISMATCH action 'write' != 'delete'" in out


def test_divergence_on_result_same_action():
    a = [{"step": 1, "action": "read", "result": "found"}]
    b = [{"step": 1, "action": "read", "result": "missing"}]
    out = _run(run_a=a, run_b=b)
    assert "DIVERGES at step 1" in out
    assert "MISMATCH result" in out


def test_step_only_in_one_run():
    a = [{"step": 1, "action": "read", "result": "ok"}]
    b = [{"step": 1, "action": "read", "result": "ok"},
         {"step": 2, "action": "write", "result": "ok"}]
    out = _run(run_a=a, run_b=b)
    assert "only in B" in out
    assert "matched 1/2" in out


def test_similarity_percentage_partial():
    a = [{"step": 1, "action": "a", "result": ""},
         {"step": 2, "action": "b", "result": ""}]
    b = [{"step": 1, "action": "a", "result": ""},
         {"step": 2, "action": "c", "result": ""}]
    out = _run(run_a=a, run_b=b)
    # SequenceMatcher over ["a","b"] vs ["a","c"] -> 1 common of 4 = 50%.
    assert "similarity=50.0%" in out


def test_errors():
    t = comparative_replay()
    assert t.fn({"op": "compare", "run_a": "x", "run_b": []}).startswith("ERROR")
    assert t.fn({"op": "compare", "run_a": [], "run_b": []}).startswith("ERROR")
    assert t.fn({"op": "nope", "run_a": [], "run_b": []}).startswith("ERROR")
