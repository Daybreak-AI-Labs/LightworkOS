"""Reviewed check-only question usefulness through the native learning pass."""
from __future__ import annotations

import base64
import json
import time
from typing import Literal

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick import self_harness_eval as evaluation
from maverick import self_improvement_runner as runner
from maverick.governed_operations import digest
from pydantic import BaseModel, ConfigDict, Field

from . import learning_passes as passes
from . import learning_task_examples as examples
from . import learning_test_cases_api as questions
from .auth import require_page_permission
from .plain_labels import model_label

PURPOSE = "question_quality"
PAGE = "/learned#learning-question-checks"
NOTICE = ("Ask the selected model to answer each selected saved question without a new lesson, then ask the current answer checker whether each response answers the question. "
          "The answering service receives the complete question. The independent checker receives the question and response; the saved expected answer is retained as your reported reference, not revealed to the checker. Their judgments can be wrong or unavailable. "
          "This check changes no question, lesson, instruction or model. Removing a question needs a separate current review in Learning questions.")


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    model: str = Field(min_length=1, max_length=200)
    references: list[str] = Field(min_length=1, max_length=16)
    samples: Literal[2, 4] = 2


def authority(request, context=None):
    from .app import require_page_visible

    require_page_permission(request, "/learned")
    require_page_visible(request, "/learned")
    return questions._authority(request, context)


def catalog(request):
    context = authority(request)
    actor, workspace = passes.native._actor(request), passes.native._workspace()
    rows = [row for row in passes._requests().list(limit=10001)
            if row.get("purpose") == PURPOSE and (row["actor"], row["context"], row["workspace"]) == (actor, context, workspace)]
    value = {"context": context, "notice": NOTICE, "available": False, "models": [],
             "requests": [{"value": row["id"][4:], "label": "Question check / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))}
                          for row in sorted(rows, key=lambda row: row["created_at"], reverse=True)[:20]]}
    try:
        state = passes._state(request, context=context)
        value.update(available=state["egress"], revision=state["revision"], ceiling=state["ceiling"], checker=model_label(state["checker"]),
                     models=[{"value": model, "label": model_label(model)} for model in state["models"]])
        if not state["egress"]:
            value["problem"] = "AI learning tests are off. Original checks remain readable. Review learning testing in All settings before a new check."
    except HTTPException as exc:
        if exc.status_code != 409:
            raise
        value["problem"] = exc.detail
    authority(request, context)
    return value


def browse(request, model, offset=0):
    authority(request)
    return questions.browse(request, model, offset=offset)


def _selected(request, state, model, references):
    if len(set(references)) != len(references):
        raise HTTPException(422, "Choose each question once.")
    rows = []
    for reference in references:
        if len(reference) != 64 or any(char not in "abcdef0123456789" for char in reference):
            raise HTTPException(422, "Choose current named questions from the list.")
        try:
            _, _, row = evaluation._selected_case(state["corpus"], model, reference,
                                                  authorize=lambda case: examples.case_access(request, case))
        except ValueError as exc:
            raise HTTPException(409, "A selected question changed or is unavailable to you. Choose current questions again; nothing was started.") from exc
        evaluation.require_cases_current([row])
        rows.append(dict(row))
    return rows


def prepare(request, values, *, context, revision):
    authority(request, context)
    body = Choices.model_validate(values)
    state = passes._state(request, context=context, write=True)
    if state["revision"] != revision:
        raise HTTPException(409, "The questions, models, permissions or learning settings changed. Refresh and review again; your choices are kept.")
    if not state["egress"] or body.model not in state["models"]:
        raise HTTPException(409, "Choose a current model with AI learning tests enabled before reviewing.")
    cases = _selected(request, state, body.model, body.references)
    authority(request, context)
    return {"context": context, "revision": revision, "source_revision": state["source_revision"], "artifact": state["artifact"],
            "body": body.model_dump(), "models": [body.model], "checker": state["checker"], "ceiling": state["ceiling"],
            "cases": cases, "quality_sources": {"model": body.model, "references": body.references, "source": questions._scope(request)["source"]}}


def review_rows(prepared):
    return [{"label": "What this check does", "after": NOTICE},
            {"label": "Answering model", "after": model_label(prepared["models"][0])},
            {"label": "Answer checker", "after": model_label(prepared["checker"])},
            {"label": "Complete selected questions", "after": [{"Question": row["goal"], "Expected answer": row.get("expected", "")} for row in prepared["cases"]]},
            {"label": "Repeated answers", "after": str(prepared["body"]["samples"]) + " answers per question. Every requested answer and judgment must complete before a question is described as consistently passed in this check."},
            {"label": "Instructions used", "after": "The model answers as a general assistant, without a proposed lesson or your saved specialist instructions. This check does not repeat your original task."},
            {"label": "Spending", "after": f"One shared spending ceiling: ${prepared['ceiling']:g}. Current provider, organization and time limits also apply." if prepared["ceiling"] is not None else "Current provider, organization and time limits apply; no extra dollar ceiling is set."},
            {"label": "Storage and later use", "after": "The existing encrypted original learning request retains these checked responses. Current source permission is required to read them. Questions and lessons are kept, including when some checks are unavailable. Past exposure to an AI service cannot be undone."}]


def _report(row):
    with crypto_at_rest.deployment_key_scope():
        return json.loads(crypto_at_rest.unseal_bound(base64.b64decode(row["quality_report"], validate=True), row["id"]))


def _readable_sources(request, binding):
    scope = questions._scope(request)
    if scope["source"] != binding["source"]:
        raise HTTPException(409, "The original question collection is no longer available in this view.")
    for reference in binding["references"]:
        questions.selected_case(request, binding["model"], reference)
    return scope


def original(request, operation, prepared=None):
    context = authority(request)
    value = passes.original(request, operation, prepared, purpose=PURPOSE, notice=NOTICE)
    value["message"] = value["message"].replace("learning pass", "question check").replace("pass", "question check")
    row = passes.owned(request, operation, prepared, purpose=PURPOSE)
    if row and row.get("quality_report") and not row.get("_audit_pending") and value["confirmed"]:
        try:
            scope = _readable_sources(request, row["quality_sources"])
            report = _report(row)
            if questions._scope(request, context) != scope:
                raise HTTPException(409, "Current source access changed.")
        except (HTTPException, ValueError, TypeError, KeyError, crypto_at_rest.EncryptionUnavailable):
            value["private_report_unavailable"] = "The original outcome is retained, but its private questions and responses are unavailable under current source access. Nothing was repeated."
        else:
            value["checks"] = report
    authority(request, context)
    return value


def start(request, prepared, operation, *, expires):
    authority(request, prepared["context"])

    def current_sources():
        authority(request, prepared["context"])
        state = passes._state(request, context=prepared["context"])
        current = _selected(request, state, prepared["body"]["model"], prepared["body"]["references"])
        if digest(current) != digest(prepared["cases"]) or state["checker"] != prepared["checker"]:
            raise HTTPException(409, "The selected questions or answer checker changed. No further check was admitted.")

    def work(_job, budget, guard, effect_scope, _state):
        guard()
        answer = evaluation.llm_runner(runner._evaluator_llm(prepared["models"][0], guard), budget=budget,
                                      work_item_id="question-quality:" + operation)
        judge = evaluation.llm_judge(runner._evaluator_llm(prepared["checker"], guard), budget=budget,
                                    samples=1, strict=True, work_item_id="question-quality:" + operation,
                                    verdict_observer=lambda *_args: None)
        rows = evaluation.corpus_quality(prepared["cases"], run_fn=answer, judge_fn=judge,
                                         samples=prepared["body"]["samples"], dispatch_guard=guard, retain_responses=True)
        guard()
        requested = len(prepared["cases"]) * prepared["body"]["samples"]
        judged = sum(row["samples"] for row in rows)
        complete = len(rows) == len(prepared["cases"]) and judged == requested
        consistent = sum(row["complete"] and not row["discriminative"] for row in rows)
        with crypto_at_rest.deployment_key_scope():
            protected = base64.b64encode(crypto_at_rest.seal_bound(json.dumps(rows, ensure_ascii=False).encode(), "LPR-" + operation)).decode()
        with effect_scope():
            store = passes._requests()
            row = store.get("LPR-" + operation)
            saved = store.update(row["id"], lambda record: record.update(quality_report=protected), expected_revision=row["revision"],
                                 action="learning.question.check.result", actor=passes.native._actor(request), effect_guard=guard)
            if not saved or saved.get("_audit_pending"):
                raise HTTPException(503, "The checked responses could not be confirmed as saved. Read the original outcome; do not repeat automatically.")
        guard()
        result = passes._pass_result([{"Requested checks": requested, "Completed judgments": judged,
                                      "Checks not completed": requested - judged, "Questions consistently passed in this check": consistent,
                                      "Completion": "Complete" if complete else "Partial; some checks are unavailable",
                                      "Questions removed": 0}], budget, False)
        result["meaning"] = "These results cover this check only. No questions were removed; they do not prove better results in your team’s work."
        return result

    passes.start(request, prepared, operation, expires=expires, run_work=work,
                 check_current=current_sources, purpose=PURPOSE, notice=NOTICE)
    return original(request, operation, prepared)
