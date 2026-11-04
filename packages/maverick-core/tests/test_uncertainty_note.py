"""Honest-uncertainty caveat on un-verified orchestrator FINALs.

When the orchestrator returns an answer it could not cleanly verify
(self-check rejected after the one-revision cap, or verification ran out
of budget), the user-facing answer should say so instead of being handed
over as if it were confirmed. Coding-mode finals are never wrapped (they
may be patches). High swarm-disagreement is added only as extra colour
when we are already flagging uncertainty.
"""
from maverick.agent import (
    _final_uncertainty_reasons,
    _final_with_uncertainty_note,
)


def test_clean_verification_has_no_reasons():
    assert _final_uncertainty_reasons(
        verifier_rejected=False, verifier_incomplete=False,
        disagreement=0.0, coding=False,
    ) == []


def test_coding_mode_never_caveats():
    # Even with everything wrong, coding-mode finals are left untouched --
    # they may be patches and prose would corrupt them.
    assert _final_uncertainty_reasons(
        verifier_rejected=True, verifier_incomplete=True,
        disagreement=1.0, coding=True,
    ) == []


def test_verifier_rejected_flags():
    reasons = _final_uncertainty_reasons(
        verifier_rejected=True, verifier_incomplete=False,
        disagreement=0.0, coding=False,
    )
    assert any("self-check" in r for r in reasons)


def test_budget_incomplete_flags():
    reasons = _final_uncertainty_reasons(
        verifier_rejected=False, verifier_incomplete=True,
        disagreement=0.0, coding=False,
    )
    assert any("budget" in r for r in reasons)


def test_disagreement_only_added_when_already_flagging():
    # High disagreement but clean verification -> no caveat at all.
    assert _final_uncertainty_reasons(
        verifier_rejected=False, verifier_incomplete=False,
        disagreement=0.95, coding=False,
    ) == []
    # High disagreement on top of a real reason -> add the colour.
    reasons = _final_uncertainty_reasons(
        verifier_rejected=True, verifier_incomplete=False,
        disagreement=0.95, coding=False,
    )
    assert any("disagreed" in r for r in reasons)


def test_low_disagreement_not_added():
    reasons = _final_uncertainty_reasons(
        verifier_rejected=True, verifier_incomplete=False,
        disagreement=0.3, coding=False,
    )
    assert not any("disagreed" in r for r in reasons)


def test_note_prepended_and_body_preserved():
    out = _final_with_uncertainty_note(
        "The answer is 42.", ["an internal self-check did not pass"],
    )
    assert out.endswith("The answer is 42.")
    assert "could not fully verify" in out


def test_note_noop_without_reasons():
    assert _final_with_uncertainty_note("hi", []) == "hi"


def test_note_noop_on_empty_or_missing_final():
    assert _final_with_uncertainty_note("", ["x"]) == ""
    assert _final_with_uncertainty_note(None, ["x"]) is None
