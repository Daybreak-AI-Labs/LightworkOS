"""collusion_detector: voting-collusion bloc detection across agents."""
from __future__ import annotations

from maverick.tools.collusion_detector import collusion_detector


def _d(votes, threshold=None, quorum=None):
    args = {"op": "detect", "votes": votes}
    if threshold is not None:
        args["threshold"] = threshold
    if quorum is not None:
        args["quorum"] = quorum
    return collusion_detector().fn(args)


def test_clear_when_independent():
    out = _d({
        "a": ["y", "n", "y"],
        "b": ["n", "y", "n"],
        "c": ["y", "y", "n"],
    })
    assert out.startswith("CLEAR")
    assert "3 agents, 3 rounds, threshold 1" in out


def test_identical_bloc_flagged():
    out = _d({
        "a": ["y", "n", "y"],
        "b": ["y", "n", "y"],  # identical to a
        "c": ["n", "y", "n"],
    })
    assert out.startswith("SUSPECT")
    assert "{a, b} cohesion 1" in out


def test_threshold_below_one_links_near_matches():
    # a and b agree 2/3; default threshold 1.0 -> clear, 0.6 -> linked
    votes = {"a": ["y", "y", "y"], "b": ["y", "y", "n"]}
    assert _d(votes).startswith("CLEAR")
    out = _d(votes, threshold=0.6)
    assert out.startswith("SUSPECT") and "cohesion 0.6" in out


def test_transitive_bloc():
    out = _d({
        "a": ["y", "y"],
        "b": ["y", "y"],
        "c": ["y", "y"],
    })
    assert "{a, b, c}" in out


def test_quorum_defeating():
    out = _d({
        "a": ["y", "y", "y"],
        "b": ["y", "y", "y"],
        "c": ["y", "y", "y"],
        "d": ["n", "n", "n"],
    }, quorum=3)
    assert out.startswith("COLLUSION")
    assert "quorum-defeating (>= 3)" in out


def test_quorum_not_reached_is_suspect():
    out = _d({
        "a": ["y", "y"],
        "b": ["y", "y"],
        "c": ["n", "n"],
    }, quorum=3)
    assert out.startswith("SUSPECT")
    assert "quorum-defeating" not in out


def test_blocs_sorted_largest_first():
    out = _d({
        "a": ["y", "y"], "b": ["y", "y"], "c": ["y", "y"],  # bloc of 3
        "x": ["n", "n"], "z": ["n", "n"],                    # bloc of 2
    })
    lines = out.splitlines()
    assert "{a, b, c}" in lines[1] and "{x, z}" in lines[2]


def test_errors():
    t = collusion_detector()
    assert t.fn({"op": "detect", "votes": {"a": ["y"]}}).startswith("ERROR")  # <2 agents
    assert t.fn({"op": "detect", "votes": {"a": ["y"], "b": ["y", "n"]}}).startswith("ERROR")  # ragged
    assert t.fn({"op": "detect", "votes": {"a": [], "b": []}}).startswith("ERROR")  # empty
    assert t.fn({"op": "detect", "votes": {"a": ["y"], "b": ["y"]}, "threshold": 2}).startswith("ERROR")
    assert t.fn({"op": "detect", "votes": {"a": ["y"], "b": ["y"]}, "quorum": 1}).startswith("ERROR")
    assert t.fn({"op": "nope", "votes": {}}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "collusion_detector" in names


# ---- collusion_detector ----

def test_collusion_echoed_reasoning():
    t = collusion_detector()
    out = t.fn({"messages": [
        {"agent": "proposer", "text": "the migration is safe because the lock is held"},
        {"agent": "verifier", "text": "the migration is safe because the lock is held"},
    ]})
    assert "COLLUSION SIGNALS" in out
    assert "echoed reasoning" in out


def test_collusion_rubber_stamp():
    t = collusion_detector()
    out = t.fn({"messages": [
        {"agent": "verifier", "text": "looks fine a", "verdict": "approve"},
        {"agent": "verifier", "text": "looks fine b", "verdict": "approved"},
        {"agent": "verifier", "text": "looks fine c", "verdict": "lgtm"},
    ]})
    assert "rubber-stamp" in out and "approved all 3" in out


def test_collusion_clean():
    t = collusion_detector()
    out = t.fn({"messages": [
        {"agent": "proposer", "text": "use a hash join here for the big table"},
        {"agent": "verifier", "text": "I disagree, a nested loop wins on this cardinality", "verdict": "reject"},
    ]})
    assert "CLEAN" in out


def test_collusion_validation():
    t = collusion_detector()
    assert t.fn({"messages": []}).startswith("ERROR")
    assert t.fn({"messages": [{"agent": "x"}]}).startswith("ERROR")
    assert t.fn({"messages": [{"agent": "x", "text": "y"}], "threshold": 2}).startswith("ERROR")
