"""The production-posture ratchet, at its designed endgame.

The register started at **91 failures** under the real posture (audit
signing on, at-rest encryption on, consent fail-closed, tool-risk ceiling
applied) — none a product bug, all tests asserting a legacy default or
fixtures that never granted consent because consent used to auto-approve.
The debt has been paid down to **zero**, so the baseline is empty and the
gate is fully blocking: any posture failure is "new" by definition.
"""

from __future__ import annotations

import json

import pytest
from maverick import posture_gate as gate

_REPORT = """
FAILED packages/maverick-core/tests/test_a.py::test_one - AssertionError: boom
FAILED packages/maverick-core/tests/test_b.py::test_two[a b] - TypeError
ERROR packages/maverick-core/tests/test_c.py::test_three
91 failed, 15778 passed, 197 skipped in 819.93s
"""


def test_it_parses_node_ids() -> None:
    assert gate.parse_report(_REPORT) == {
        "packages/maverick-core/tests/test_a.py::test_one",
        "packages/maverick-core/tests/test_b.py::test_two[a b]",
        "packages/maverick-core/tests/test_c.py::test_three",
    }


def test_a_parametrized_id_with_spaces_survives() -> None:
    """The bug that undercounted the first baseline by 16 of 91.

    A ``\\S+`` capture stops at the space inside ``[a b]``, so those entries
    were dropped. An undercounted baseline is worse than none: it looks like a
    ratchet while letting the missing entries through as "new" forever.
    """
    ids = gate.parse_report("FAILED tests/t.py::test_x[first second] - E")
    assert ids == {"tests/t.py::test_x[first second]"}


def test_the_committed_baseline_is_paid_off() -> None:
    """The register's endgame: zero recorded debt, so the gate blocks on ANY
    posture failure. (Report-vacuity is guarded separately below — an empty
    baseline never lets a truncated report read as success.)"""
    assert gate.load_baseline() == set()


def test_the_baseline_file_shape() -> None:
    data = json.loads(gate.BASELINE.read_text(encoding="utf-8"))
    assert data["count"] == len(data["failures"])
    assert data["failures"] == sorted(data["failures"])


# -- the ratchet -----------------------------------------------------------

def test_a_new_failure_is_drift() -> None:
    new, fixed = gate.drift({"a::b", "c::d"}, {"a::b"})
    assert new == ["c::d"] and fixed == []


def test_a_fixed_failure_must_be_removed_from_the_baseline() -> None:
    """Otherwise the register becomes an exemption list instead of debt."""
    new, fixed = gate.drift({"a::b"}, {"a::b", "c::d"})
    assert new == [] and fixed == ["c::d"]


def test_no_drift_is_clean() -> None:
    assert gate.drift({"a::b"}, {"a::b"}) == ([], [])


# -- vacuity: the gate must not pass on a report that never ran ------------

def test_a_truncated_report_is_an_error_not_a_pass(tmp_path, capsys) -> None:
    """The failure mode this repo has been closing everywhere.

    A killed or empty posture run produces a report with no summary. Reading
    that as "zero failures" would turn the whole job into a green check that
    inspected nothing.
    """
    report = tmp_path / "posture.txt"
    report.write_text("", encoding="utf-8")
    assert gate.main(["--ci", "--report", str(report)]) == 2
    assert "no pytest summary" in capsys.readouterr().err


def test_a_missing_report_is_an_error(tmp_path, capsys) -> None:
    assert gate.main(["--ci", "--report", str(tmp_path / "nope.txt")]) == 2
    assert "no report at" in capsys.readouterr().err


def test_a_completed_run_with_zero_failures_is_accepted(tmp_path) -> None:
    """Positive control: refusing every report would also pass the tests above."""
    report = tmp_path / "posture.txt"
    report.write_text("17080 passed in 800s\n", encoding="utf-8")
    # Zero failures against the empty baseline: clean pass.
    assert gate.main(["--ci", "--report", str(report)]) == 0


def test_any_failure_blocks_against_the_empty_baseline(tmp_path) -> None:
    """The flip this register existed to earn: with zero recorded debt, a
    single posture failure fails the build as new drift."""
    report = tmp_path / "posture.txt"
    report.write_text(
        "FAILED packages/maverick-core/tests/test_a.py::test_one - boom\n"
        "1 failed, 17079 passed in 800s\n", encoding="utf-8")
    assert gate.main(["--ci", "--report", str(report)]) == 1


@pytest.mark.parametrize("summary", ["1 failed, 2 passed", "3 error", "9 passed"])
def test_summary_detection(tmp_path, summary) -> None:
    report = tmp_path / "posture.txt"
    report.write_text(summary + "\n", encoding="utf-8")
    assert gate.main(["--report", str(report)]) in (0, 1)
