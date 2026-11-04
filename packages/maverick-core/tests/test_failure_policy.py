"""Tests for the failure-policy classification lint (maverick.failure_policy).

The lint requires every broad exception handler in the scoped audit-integrity
subsystem to declare its failure mode via a `# failure-policy: <class>` marker.
"""
from __future__ import annotations

from pathlib import Path

from maverick import failure_policy as fp


def test_real_audit_tree_is_fully_classified():
    """The shipped audit subsystem has every broad except marked (the gate)."""
    assert fp.scan() == {}
    assert fp.main([]) == 0


def test_flow_approval_authority_is_in_scope():
    """Changes to approval authority handlers must receive a classification."""
    approval_file = fp._PKG / "flow" / "approvals.py"
    assert approval_file in fp.SCOPED_FILES
    assert fp.scan_file(approval_file) == []


def test_egress_guard_is_in_scope():
    """The network boundary's broad error paths need a declared policy."""
    guard_file = fp._PKG / "egress_guard.py"
    assert guard_file in fp.SCOPED_FILES
    assert fp.scan_file(guard_file) == []


def test_sandbox_lifecycle_files_are_in_scope():
    for name in ("local.py", "kubernetes.py"):
        path = fp._PKG / "sandbox" / name
        assert path in fp.SCOPED_FILES
        assert fp.scan_file(path) == []


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "mod.py"
    p.write_text(body, encoding="utf-8")
    return p


def test_unmarked_broad_except_is_flagged(tmp_path):
    p = _write(tmp_path, "try:\n    x = 1\nexcept Exception:\n    pass\n")
    probs = fp.scan_file(p)
    assert len(probs) == 1
    assert "without a # failure-policy" in probs[0][1]


def test_marker_on_except_line_passes(tmp_path):
    p = _write(
        tmp_path,
        "try:\n    x = 1\nexcept Exception:  # failure-policy: best_effort\n    pass\n",
    )
    assert fp.scan_file(p) == []


def test_marker_on_line_above_passes(tmp_path):
    p = _write(
        tmp_path,
        "try:\n    x = 1\n    # failure-policy: fail_closed\nexcept Exception:\n    raise\n",
    )
    assert fp.scan_file(p) == []


def test_invalid_class_is_flagged(tmp_path):
    p = _write(
        tmp_path,
        "try:\n    x = 1\n    # failure-policy: oops\nexcept Exception:\n    pass\n",
    )
    probs = fp.scan_file(p)
    assert len(probs) == 1
    assert "invalid failure-policy class" in probs[0][1]


def test_bare_baseexception_and_tuple_are_broad(tmp_path):
    src = (
        "try:\n    x = 1\nexcept:\n    pass\n"
        "try:\n    x = 1\nexcept BaseException:\n    pass\n"
        "try:\n    x = 1\nexcept (ValueError, Exception):\n    pass\n"
    )
    p = _write(tmp_path, src)
    # All three are broad + unmarked -> three problems.
    assert len(fp.scan_file(p)) == 3


def test_narrow_except_needs_no_marker(tmp_path):
    p = _write(tmp_path, "try:\n    x = 1\nexcept ValueError:\n    pass\n")
    assert fp.scan_file(p) == []


def test_sibling_handlers_trailing_comment_not_misattributed(tmp_path):
    # A `# failure-policy:` comment trailing a PRIOR sibling handler's body
    # must not be credited to the NEXT handler just because it's the
    # physically preceding line -- that would let an unmarked broad handler
    # slip through unflagged.
    p = _write(
        tmp_path,
        "try:\n"
        "    risky_a()\n"
        "except ValueError:\n"
        "    pass\n"
        "    # failure-policy: best_effort\n"
        "except Exception:\n"
        "    swallow_silently()\n",
    )
    probs = fp.scan_file(p)
    assert len(probs) == 1
    assert probs[0][0] == 6  # the `except Exception:` line
    assert "without a # failure-policy" in probs[0][1]


def test_standalone_comment_between_sibling_handlers_passes(tmp_path):
    # Unlike the previous case, a marker indented to match the `except`
    # clauses themselves (not nested inside the previous handler's body) is a
    # legitimate, unambiguous annotation of the next handler.
    p = _write(
        tmp_path,
        "try:\n"
        "    risky_a()\n"
        "except ValueError:\n"
        "    pass\n"
        "# failure-policy: fail_soft_with_audit\n"
        "except Exception:\n"
        "    log_and_continue()\n",
    )
    assert fp.scan_file(p) == []


def test_all_classes_accepted(tmp_path):
    for cls in fp.CLASSES:
        p = _write(
            tmp_path,
            f"try:\n    x = 1\nexcept Exception:  # failure-policy: {cls}\n    pass\n",
        )
        assert fp.scan_file(p) == [], cls
