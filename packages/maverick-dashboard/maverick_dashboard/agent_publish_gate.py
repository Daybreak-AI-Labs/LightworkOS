"""The test result an agent or specialist's instructions must have before they are published.

A run counts for a set of instructions when it tested exactly that text with
the agent's current model, covered every saved test at its current version,
and finished with every answer passing. Plain runs test the current
instructions; a comparison tests the proposed ones.
"""
from __future__ import annotations

import hashlib

from . import specialist_test_sets as saved


def instructions_key(model: str, instructions: str) -> str:
    """One identity for "these words, answered by this model"."""
    text = " ".join(str(instructions or "").split())
    return hashlib.sha256((str(model) + "\n" + text).encode("utf-8")).hexdigest()


def _tested(run: dict) -> tuple[str | None, str]:
    """The instructions a finished run tested, and which answers belong to them."""
    comparison = run.get("comparison")
    if comparison:
        return instructions_key(run.get("model", ""), comparison.get("proposed_instructions", "")), "proposed"
    return run.get("instructions_key"), "current"


def _summary(run: dict, variant: str, current: dict[str, int]) -> dict:
    answers = [row for row in run.get("results", []) if row.get("variant", "current") == variant]
    tested = {row["id"]: row["revision"] for row in run.get("case_revisions", [])}
    covers = bool(current) and tested == current
    passed = sum(bool(row.get("passed")) for row in answers)
    return {"run": run["id"], "started_at": run.get("started_at"), "passed": passed,
            "total": len(tested), "covers_all_tests": covers,
            "passing": covers and run.get("state") == "done" and len(answers) == len(current)
            and passed == len(current)}


def latest_for(specialist: str, model: str, instructions: str) -> dict | None:
    """The newest finished run of exactly these instructions, or ``None``."""
    key = instructions_key(model, instructions)
    current = {row["id"]: row["revision"] for row in saved.cases_for(specialist)}
    for run in saved.runs_for(specialist):
        if run.get("state") not in {"done", "stopped"}:
            continue
        tested, variant = _tested(run)
        if tested == key:
            return _summary(run, variant, current)
    return None


def check(specialist: str, *, model: str, current_instructions: str, new_instructions: str | None,
          creating: bool, required: bool) -> dict:
    """Whether publishing ``new_instructions`` needs a passing run, and whether one exists."""
    tests = len(saved.cases_for(specialist)) if not creating else 0
    changed = (not creating and new_instructions is not None
               and " ".join(new_instructions.split()) != " ".join((current_instructions or "").split()))
    target = new_instructions if changed else current_instructions
    latest = None if creating else latest_for(specialist, model, target or "")
    passing = bool(latest and latest["passing"])
    needed = bool(required and changed)
    if creating:
        message = "New agents start under supervision. Add tests after creating it."
    elif not tests:
        message = "No saved tests yet. Add tests in Workforce and run them on these instructions."
    elif latest is None:
        message = "These instructions have not been tested yet."
    elif passing:
        message = f"All {latest['total']} saved tests passed on these instructions."
    elif not latest["covers_all_tests"]:
        message = "The last test run on these instructions did not include every saved test at its current version."
    else:
        message = f"{latest['passed']} of {latest['total']} saved tests passed on these instructions."
    return {"required": needed, "instructions_changed": changed, "passing": passing,
            "tests": tests, "latest": latest, "message": message,
            "blocked": needed and not passing}


__all__ = ["check", "instructions_key", "latest_for"]
