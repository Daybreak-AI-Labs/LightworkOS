"""Customer-owned, tool-free answer checks for the current specialist instructions.

The cases and each run's result are tenant-scoped durable records. A started
provider call is never retried after an interruption: a missing final receipt
is reported as unknown, not quietly counted as a failure or a free call.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from contextlib import nullcontext
from typing import Any

from maverick.agent_tests_policy import max_cases_per_specialist
from maverick.file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from maverick.paths import data_dir

from .specialist_tool_checks import tool_check_results

# A Copilot-reviewed run picks at most this many; a person can run the whole set.
MAX_CASES_PER_RUN = 5
_MAX_RUNS = 500


def _max_all_cases() -> int:
    """Every specialist's saved checks together: 50 full sets at the configured limit, never below 1,000."""
    return max(1000, 50 * max_cases_per_specialist())


def draft_answer_limits(questions: int) -> dict:
    """The spending and size ceilings for one complete-draft check, before the configured caps apply.

    Five questions keep the original $0.25 run. Each further question adds the same allowance a
    saved-test run gets, so a set the limit allows can finish inside its budget.
    """
    count = max(5, int(questions))
    return {"max_dollars": round(.05 * count, 2), "max_input_tokens": 2000 * count,
            "max_output_tokens": 128 * count, "max_wall_seconds": max(120, 24 * count)}


def _path():
    return data_dir("specialist-tests", "cases-and-runs.json")


def _read(path) -> dict:
    if not path.exists():
        return {"schema": 1, "cases": {}, "runs": {}}
    value = json.loads(atomic_read_text(path, encoding="utf-8"))
    if (not isinstance(value, dict) or value.get("schema") != 1
            or not isinstance(value.get("cases"), dict)
            or not isinstance(value.get("runs"), dict)):
        raise ValueError("The saved answer checks cannot be read. Nothing was changed.")
    return value


def _with_store(fn, *, effect_guard=None):
    from maverick.authority_effects import authority_effect_fence

    path = _path()
    ensure_private_directory(path.parent)
    with (authority_effect_fence() if effect_guard is not None else nullcontext()), cross_process_lock(path.with_suffix(".lock"), strict=True):
        value = _read(path)
        if effect_guard is not None:
            effect_guard()
        result, changed = fn(value)
        if changed:
            atomic_write_text(path, json.dumps(value, ensure_ascii=False, allow_nan=False), encoding="utf-8", effect_guard=effect_guard)
        return result


def cases_for(specialist: str) -> list[dict]:
    return _with_store(lambda db: (
        sorted((dict(row) for row in db["cases"].values() if row["specialist"] == specialist),
               key=lambda row: (row["created_at"], row["id"])), False))


def cases_for_specialists(specialists: set[str]) -> dict[str, list[dict]]:
    """Read named choices once, within the current tenant's native store."""
    rows = _with_store(lambda db: (
        sorted((dict(row) for row in db["cases"].values() if row["specialist"] in specialists),
               key=lambda row: (row["created_at"], row["id"])), False))
    result: dict[str, list[dict]] = {}
    for row in rows:
        result.setdefault(row["specialist"], []).append(row)
    return result


def save_case(specialist: str, fields: dict, *, identity: str | None = None,
              expected_revision: int | None = None) -> dict:
    limit, total = max_cases_per_specialist(), _max_all_cases()

    def mutate(db):
        cases = db["cases"]
        prior = cases.get(identity) if identity else None
        if identity and (prior is None or prior["specialist"] != specialist):
            raise ValueError("This test no longer exists. Refresh the list.")
        if prior and prior["revision"] != expected_revision:
            raise ValueError("This test changed. Refresh it before saving again.")
        if not prior and (len(cases) >= total or sum(
                c["specialist"] == specialist for c in cases.values()) >= limit):
            raise ValueError("This test list is full. Remove an old test before adding another.")
        now = time.time()
        row = {"id": identity or uuid.uuid4().hex, "specialist": specialist,
               **fields, "revision": (prior["revision"] + 1 if prior else 1),
               "created_at": prior["created_at"] if prior else now, "updated_at": now}
        cases[row["id"]] = row
        return dict(row), True
    return _with_store(mutate)


def save_once(specialist: str, fields: dict, identity: str) -> dict:
    """Copilot's sealed operation ID is the case ID, so a retry cannot add two."""
    limit, total = max_cases_per_specialist(), _max_all_cases()

    def mutate(db):
        prior = db["cases"].get(identity)
        if prior is not None:
            if prior["specialist"] != specialist or any(prior.get(key) != value for key, value in fields.items()):
                raise ValueError("This reviewed operation already belongs to a different test.")
            return dict(prior), False
        if len(db["cases"]) >= total or sum(
                c["specialist"] == specialist for c in db["cases"].values()) >= limit:
            raise ValueError("This test list is full. Remove an old test before adding another.")
        now = time.time()
        row = {"id": identity, "specialist": specialist, **fields,
               "revision": 1, "created_at": now, "updated_at": now}
        db["cases"][identity] = row
        return dict(row), True
    return _with_store(mutate)


def case_by_id(identity: str) -> dict | None:
    return _with_store(lambda db: (dict(db["cases"][identity]) if identity in db["cases"] else None, False))


def delete_case(specialist: str, identity: str, expected_revision: int) -> None:
    def mutate(db):
        row = db["cases"].get(identity)
        if row is None or row["specialist"] != specialist:
            raise ValueError("This test no longer exists. Refresh the list.")
        if row["revision"] != expected_revision:
            raise ValueError("This test changed. Refresh it before removing it.")
        del db["cases"][identity]
        return None, True
    _with_store(mutate)


def snapshot(specialist: str, selected_ids: list[str] | None = None) -> list[dict]:
    rows = cases_for(specialist)
    if not rows:
        raise ValueError("Add at least one test before running the checks.")
    limit = max_cases_per_specialist()
    if selected_ids:
        if len(selected_ids) > limit or len(set(selected_ids)) != len(selected_ids):
            raise ValueError(f"Choose between 1 and {limit} different checks.")
        selected = set(selected_ids)
        rows = [row for row in rows if row["id"] in selected]
        if len(rows) != len(selected):
            raise ValueError("One selected check changed or was removed. Refresh the list.")
    elif len(rows) > limit:
        raise ValueError(f"Choose at most {limit} checks for one run.")
    return rows


def reserve_run(specialist: str, model: str, instruction_hash: str, cases: list[dict],
                actor: str, identity: str, *, comparison: dict | None = None,
                instructions_key: str | None = None, instructions: str | None = None,
                single_variant: bool = False, effect_guard=None) -> dict:
    """Persist a reviewed operation before starting a background worker."""
    def mutate(db):
        prior = db["runs"].get(identity)
        revisions = [{"id": c["id"], "revision": c["revision"]} for c in cases]
        if prior is not None:
            if (prior["specialist"] != specialist or prior["model"] != model
                    or prior["instruction_hash"] != instruction_hash
                    or prior["case_revisions"] != revisions or prior.get("comparison") != comparison
                    or prior["actor"] != actor):
                raise ValueError("This reviewed operation no longer matches its original test run.")
            return dict(prior), False
        if len(db["runs"]) >= _MAX_RUNS:
            finished = sorted((r for r in db["runs"].values()
                               if r["state"] not in {"running", "prepared"}
                               and not r.get("comparison", {}).get("draft_profile")
                               and time.time() - r["started_at"] > 600),
                              key=lambda r: r["started_at"])
            if effect_guard is not None or not finished:
                raise ValueError("Test history is full. No new test was started.")
            del db["runs"][finished[0]["id"]]
        row = {"id": identity, "specialist": specialist, "model": model,
               "instruction_hash": instruction_hash, "actor": actor, "started_at": time.time(),
               "finished_at": None, "state": "prepared", "results": [], "total": len(cases),
               "passed": 0, "spent_dollars": 0.0, "case_revisions": revisions,
               "case_snapshots": [dict(c) for c in cases]}
        if instructions_key:
            # The exact words tested, so each answer can point back to them.
            row.update(instructions_key=instructions_key, instructions=(instructions or "")[:6000])
        if comparison:
            row.update(comparison=dict(comparison), total=len(cases) if single_variant else len(cases) * 2)
        db["runs"][identity] = row
        return dict(row), True
    return _with_store(mutate, effect_guard=effect_guard)


def begin_run(specialist: str, model: str, instruction_hash: str, cases: list[dict], actor: str,
              identity: str | None = None, *, instructions_key: str | None = None,
              instructions: str | None = None, effect_guard=None) -> tuple[dict, bool]:
    def mutate(db):
        if identity and identity in db["runs"]:
            prior = db["runs"][identity]
            if prior["specialist"] != specialist:
                raise ValueError("This reviewed request already belongs to another agent or specialist.")
            if prior["state"] == "prepared":
                prior.update(state="running", started_at=time.time())
                return (dict(prior), True), True
            return (dict(prior), False), False
        if len(db["runs"]) >= _MAX_RUNS:
            # Retain the newest history, including every unfinished operation.
            finished = sorted((r for r in db["runs"].values()
                               if r["state"] not in {"running", "prepared"}
                               and not r.get("comparison", {}).get("draft_profile")
                               and time.time() - r["started_at"] > 600),
                              key=lambda r: r["started_at"])
            if not finished:
                raise ValueError("Test history is full. No new test was started.")
            del db["runs"][finished[0]["id"]]
        row = {"id": identity or uuid.uuid4().hex, "specialist": specialist, "model": model,
               "instruction_hash": instruction_hash, "actor": actor, "started_at": time.time(),
               "finished_at": None, "state": "running", "results": [],
               "total": len(cases), "passed": 0, "spent_dollars": 0.0,
               "case_revisions": [{"id": c["id"], "revision": c["revision"]} for c in cases],
               "case_snapshots": [dict(c) for c in cases]}
        if instructions_key:
            # The exact words tested, so each answer can point back to them.
            row.update(instructions_key=instructions_key, instructions=(instructions or "")[:6000])
        db["runs"][row["id"]] = row
        return (dict(row), True), True
    return _with_store(mutate, effect_guard=effect_guard)


def run_by_id(identity: str) -> dict | None:
    return _with_store(lambda db: (dict(db["runs"][identity]) if identity in db["runs"] else None, False))


def append_result(run_id: str, result: dict, spent_dollars: float, *, effect_guard=None) -> None:
    def mutate(db):
        row = db["runs"].get(run_id)
        if row is None or row["state"] != "running":
            raise ValueError("The original test run is no longer available. No call was replayed.")
        if any((r["case_id"], r.get("variant", "current")) == (result["case_id"], result.get("variant", "current")) for r in row["results"]):
            raise ValueError("This answer already has a result. No call was replayed.")
        row["results"].append(result)
        row["passed"] = sum(bool(r.get("passed")) for r in row["results"])
        row["spent_dollars"] = round(max(0.0, spent_dollars), 6)
        return None, True
    _with_store(mutate, effect_guard=effect_guard)


def finish_run(run_id: str, state: str, spent_dollars: float, message: str = "", *, effect_guard=None) -> dict:
    if state not in {"done", "stopped", "unknown"}:
        raise ValueError("Invalid test result")
    def mutate(db):
        row = db["runs"].get(run_id)
        if row is None:
            raise ValueError("The original test run is no longer available.")
        if row["state"] != "running":
            return dict(row), False
        row.update(state=state, finished_at=time.time(), message=message[:240],
                   spent_dollars=round(max(0.0, spent_dollars), 6))
        return dict(row), True
    return _with_store(mutate, effect_guard=effect_guard)


def all_runs_for(specialist: str) -> list[dict]:
    """Every retained run of one specialist, newest first (``runs_for`` shows only the latest 20)."""
    rows = _with_store(lambda db: (
        sorted((dict(row) for row in db["runs"].values() if row["specialist"] == specialist),
               key=lambda row: row["started_at"], reverse=True), False))
    return [public_run(row) for row in rows]


def runs_for(specialist: str) -> list[dict]:
    return all_runs_for(specialist)[:20]


def _stale_after(row: dict) -> float:
    """A whole set takes longer than a few checks; allow 30 s per answer."""
    return max(180.0, 30.0 * float(row.get("total") or 0))


def public_run(row: dict) -> dict:
    result = dict(row)
    if result["state"] == "running" and time.time() - result["started_at"] > _stale_after(result):
        result["state"] = "unknown"
        result["message"] = "No final result arrived. A provider call may still have been billed. Nothing was retried."
    if result["state"] == "prepared" and time.time() - result["started_at"] > 180:
        if result.get("comparison", {}).get("draft_profile"):
            result["state"] = "unknown"
            result["message"] = "No confirmed worker outcome arrived. Read the original decision; this answer request will not be repeated automatically."
        else:
            result["message"] = "This request was prepared, but no provider call started. Use its original request reference to start it."
    return result


def instruction_digest(system: str, model: str) -> str:
    return hashlib.sha256((model + "\n" + system).encode("utf-8")).hexdigest()


def specialist_instructions(profile) -> str:
    """The specialist's own instructions, shared by answer checks and public chat."""
    from maverick.agent_autonomy import default_profile_for, render_autonomy_prompt
    from maverick.domain import render_workflow_prompt
    from maverick.domain_discipline import augment_persona
    from maverick.domain_refusals import render_refusals

    return (augment_persona(profile.name, profile.persona)
            + render_refusals(profile.name, profile.refuse)
            + render_autonomy_prompt(profile.name, profile.autonomy or default_profile_for(profile.name))
            + render_workflow_prompt(profile.workflow))


def answer_system(profile) -> str:
    """Use the current specialist's answer instructions with every action disabled."""
    return (specialist_instructions(profile)
            + "\nThis is an answer check using fictional test material. No tools, files, knowledge sources "
              "or outside systems are connected. Answer the question directly. Never claim to have "
              "taken an action or checked a source you cannot access.")


SKIPPED_TOOL_CHECK_NOTE = ("Skipped: tool checks are turned off in All settings, so this check did not run "
                           "and does not count as passing.")


def skipped_tool_check(case: dict, *, variant: str | None = None) -> dict[str, Any]:
    """A tool check that did not run while its switch is off. It never counts as passing."""
    row = {"case_id": case["id"], "task": case["task"], "passed": False, "score": 0.0, "checks": {},
           "answer": "", "tool_checks": [], "tool_calls": [], "note": SKIPPED_TOOL_CHECK_NOTE}
    if variant is not None:
        row["variant"] = variant
    return row


def _tool_outcome(case: dict, tool_calls: list[dict] | None) -> tuple[dict[str, Any], bool]:
    if not case.get("with_tools"):
        return {}, True
    calls = list(tool_calls or [])
    checks = tool_check_results(case, calls)
    stored = [{key: value for key, value in call.items() if key != "match"} for call in calls]
    return {"tool_checks": checks, "tool_calls": stored}, all(row["passed"] for row in checks)


def grade(case: dict, output: str, *, retain_full: bool = False,
          tool_calls: list[dict] | None = None) -> dict[str, Any]:
    from maverick.domain_eval import EvalCase, score_output
    if retain_full and len(output.encode("utf-8")) > 64000:
        raise ValueError("The complete answer exceeds the supported result limit. Nothing was shortened or counted as passing.")
    tools, tools_passed = _tool_outcome(case, tool_calls)
    if not output or not output.strip():
        return {"case_id": case["id"], "task": case["task"], "passed": False,
                "score": 0.0, "checks": {"empty_answer": 0.0}, "answer": "", **tools}
    rubric = EvalCase(case["specialist"], case["task"],
                      expect_includes=tuple(case["includes"]),
                      expect_excludes=tuple(case["excludes"]),
                      expect_refusal=case["refusal"], expect_citation=case["citation"])
    result = score_output(rubric, output, pass_threshold=1.0)
    return {"case_id": case["id"], "task": case["task"], "passed": result.passed and tools_passed,
            "score": result.score, "checks": result.checks, "answer": output if retain_full else output[:2000],
            **tools}
