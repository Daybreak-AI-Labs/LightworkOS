"""quorum_approval: M-of-N sign-off check."""
from __future__ import annotations

from maverick.tools.quorum_approval import quorum_approval


def _run(**kw):
    return quorum_approval().fn({"op": "check", **kw})


def test_satisfied():
    out = _run(approvals=[{"approver": "alice"}, {"approver": "bob"}], required=2)
    assert out.startswith("SATISFIED") and "2 distinct approver" in out


def test_blocked_insufficient():
    out = _run(approvals=[{"approver": "alice"}], required=2)
    assert out.startswith("BLOCKED") and "need 2" in out


def test_dedupe_case_insensitive():
    out = _run(approvals=[{"approver": "Alice"}, {"approver": "alice"}], required=2)
    assert out.startswith("BLOCKED")  # same person twice counts once


def test_distinct_roles():
    same = _run(approvals=[{"approver": "a", "role": "ops"},
                           {"approver": "b", "role": "ops"}],
                required=2, require_distinct_roles=True)
    assert same.startswith("BLOCKED") and "distinct role" in same
    diff = _run(approvals=[{"approver": "a", "role": "ops"},
                           {"approver": "b", "role": "security"}],
                required=2, require_distinct_roles=True)
    assert diff.startswith("SATISFIED")


def test_three_of_three():
    out = _run(approvals=[{"approver": "a"}, {"approver": "b"}, {"approver": "c"}],
               required=3)
    assert out.startswith("SATISFIED")


def test_errors():
    t = quorum_approval()
    assert t.fn({"op": "check"}).startswith("ERROR")  # no approvals
    assert t.fn({"op": "check", "approvals": []}).startswith("ERROR")  # no required
    assert t.fn({"op": "check", "approvals": [], "required": 0}).startswith("ERROR")
    assert t.fn({"op": "nope", "approvals": [], "required": 1}).startswith("ERROR")


def test_non_finite_required_does_not_crash():
    # Regression: int(args["required"]) raised OverflowError on a non-finite value.
    t = quorum_approval()
    for bad in (float("inf"), float("-inf")):
        out = t.fn({"op": "check", "approvals": [{"approver": "a"}], "required": bad})
        assert out.startswith("ERROR")
