"""Selected-target lesson testing through the existing reviewed learning pass."""
from __future__ import annotations

import json
import time
from contextlib import contextmanager

from fastapi import HTTPException
from maverick import self_harness
from maverick import self_harness_eval as evaluation
from maverick import self_improvement_runner as runner
from maverick.governed_operations import digest
from maverick.learning_store import guidance_fence
from maverick.llm import model_for_role
from pydantic import BaseModel, ConfigDict, Field

from . import learning_passes as passes
from .auth import require_page_permission
from .plain_labels import model_label

PAGE = "/learned#learning-transfers"
PURPOSE = "lesson_transfer"
NOTICE = ("Test currently shareable lessons from one model on another model's current questions and the standing instructions you supply. "
          "Lessons that pass the existing approval checks start on trial. Testing can spend money and keep judged-attempt records. "
          "A safety copy is required first. These checks do not establish performance on customer work.")


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=200)
    retry_judged: bool = False
    instructions: str = Field(min_length=1, max_length=1024 * 1024)


def authority(request, context=None):
    require_page_permission(request, "/learned")
    return passes.questions._authority(request, context)


def _source(source):
    with guidance_fence():
        store = self_harness.load_addenda()
        meta = self_harness.load_line_meta()
        lines = self_harness.transferable_lines(source, store=store, meta=meta)
        tried = self_harness._load_transfer_tried(strict=True)
    return lines, digest(tried)


def _history(request, context):
    rows = passes._requests().list(limit=10001)
    actor, workspace = passes.native._actor(request), passes.native._workspace()
    owned = [row for row in rows if row.get("purpose") == PURPOSE
             and (row["actor"], row["context"], row["workspace"]) == (actor, context, workspace)]
    return [{"value": row["id"][4:], "label": "Lesson test / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))}
            for row in sorted(owned, key=lambda row: row["created_at"], reverse=True)[:20]]


def catalog(request):
    context = authority(request)
    result = {"context": context, "notice": NOTICE, "requests": _history(request, context), "models": [], "available": False}
    try:
        state = passes._state(request, context=context)
        result.update(available=True, revision=state["revision"], models=[{"value": model, "label": model_label(model)} for model in state["models"]])
    except HTTPException as exc:
        if exc.status_code != 409:
            raise
        result["problem"] = exc.detail
    authority(request, context)
    return result


def prepare(request, values, *, context, revision):
    authority(request, context)
    body = Choices.model_validate(values)
    body.instructions = passes.loop._instructions(body.instructions) or ""
    state = passes._state(request, context=context, write=True)
    if state["revision"] != revision:
        raise HTTPException(409, "The current lessons, questions, models or settings changed. Refresh and review again; your entered instructions are kept.")
    if body.source == body.target or any(model not in state["models"] for model in (body.source, body.target)):
        raise HTTPException(409, "Choose two different models currently in use.")
    if not state["egress"]:
        raise HTTPException(409, "AI learning tests are off. Review the learning testing setting in All settings before starting.")
    lines, tried = _source(body.source)
    cases = evaluation.corpus_cases(runner._normalize_eval_manifest(state["corpus"]), body.target)
    if not lines or not cases:
        raise HTTPException(409, "This choice needs currently shareable, accepted lessons and current questions for the receiving model. Set them up on the Learned page first.")
    prepared = {"context": context, "revision": state["revision"], "source_revision": state["source_revision"],
                "artifact": state["artifact"], "body": body.model_dump(), "models": [body.target], "ceiling": state["ceiling"],
                "lessons": lines, "tried": tried, "questions": [{"Question": row["goal"], "Expected answer": row.get("expected", "")} for row in cases],
                "checker": model_label(state["checker"]), "careful": state["careful"]}
    if len(json.dumps(prepared, ensure_ascii=False).encode("utf-8")) > 2 * 1024 * 1024:
        raise HTTPException(413, "This complete review exceeds 2 MB. Choose a smaller current question set or instructions copy; nothing was started.")
    if passes._state(request, context=context)["revision"] != state["revision"]:
        raise HTTPException(409, "The source changed while preparing the complete review. Refresh and review again.")
    authority(request, context)
    return prepared


def review_rows(prepared):
    body = prepared["body"]
    return [{"label": "What can change", "after": NOTICE},
            {"label": "From model", "after": model_label(body["source"])},
            {"label": "Receiving model", "after": model_label(body["target"])},
            {"label": "Complete lessons included", "after": prepared["lessons"]},
            {"label": "Complete current questions and expected answers", "after": prepared["questions"]},
            {"label": "Current standing instructions supplied for the receiving model", "after": body["instructions"]},
            {"label": "Already judged lessons", "after": "Test them again. This can spend money again." if body["retry_judged"] else "Keep their recorded judgments; do not test them again."},
            {"label": "Approval checks", "after": "Current careful testing, sealed final-question allowance and answer-checker calibration remain required." if prepared["careful"] else "Current native learning approval checks remain required."},
            {"label": "Answer checker", "after": prepared["checker"]},
            {"label": "Spending", "after": f"One shared test ceiling: ${prepared['ceiling']:g}; all current provider and organization limits also apply." if prepared["ceiling"] is not None else "Current provider and organization limits apply. No per-test dollar ceiling is set; review All settings if needed."}]


def original(request, operation, prepared=None):
    context = authority(request)
    row = passes.original(request, operation, prepared, purpose=PURPOSE, notice=NOTICE)
    row["message"] = row["message"].replace("learning pass", "lesson test").replace("pass", "lesson test")
    authority(request, context)
    return row


def _evaluation_context(prepared, state, budget, guard, effect_scope):
    body, settings = prepared["body"], self_harness.settings()
    envelope = runner._eval_budget(settings)
    for name, fallback in (("max_input_tokens", 10**9), ("max_output_tokens", 10**9), ("max_wall_seconds", 3600.0)):
        limit = getattr(envelope, name, fallback)
        current = getattr(budget, name)
        setattr(budget, name, limit if current is None else min(current, limit))
    corpus_path = settings["eval_corpus"]
    verifier, paraphraser = model_for_role("verifier"), model_for_role("summarizer")
    evaluator_id = evaluation.judge_evaluator_identity(verifier, samples=int(settings.get("judge_samples", 1)), strict=True)
    reason, calibration = runner._risk_calibration_boundary(settings, scoring=True, evaluator_id=evaluator_id)
    if reason:
        raise HTTPException(409, "The answer checker needs current calibration before lessons can be changed. Review the calibration controls on the Learned page.")
    floors = runner._validation_floors(settings)
    holdout = None
    if settings.get("risk_limited"):
        holdout = runner._build_holdout_authorizer(settings, corpus_path=corpus_path, model_id=body["target"],
            evaluation_system=body["instructions"], verifier_model=verifier, metamorphic_model=paraphraser,
            corpus_manifest=state["corpus"], evaluation_budget=budget, dispatch_guard=guard, effect_scope=effect_scope)
        floors["holdout_authorize"] = holdout
    if settings.get("metamorphic"):
        cases = [row for rows in runner._normalize_eval_manifest(state["corpus"]).values() for row in rows]
        floors["metamorphic_fn"] = runner._memo_paraphraser(evaluation.llm_paraphraser(
            runner._evaluator_llm(paraphraser, guard), budget=budget,
            authorize_sources=lambda: evaluation.require_cases_current(cases)))
    cache = {}

    def evaluator(model):
        if model != body["target"]:
            raise ValueError("unreviewed transfer target")
        guard()
        if model not in cache:
            cache[model] = runner._auto_evaluator(model, corpus_path=corpus_path, system_prefix=body["instructions"],
                verifier_model=verifier, strict_judge=bool(settings.get("risk_limited")), calibration_evaluator_id=evaluator_id,
                judge_samples=settings.get("judge_samples", 1), judge_unknown=bool(settings.get("metamorphic")),
                corpus_manifest=state["corpus"], budget=budget, dispatch_guard=guard)
        return cache[model]

    def promotion():
        guard()
        if holdout is not None and not holdout.finalize_for_promotion():
            return False
        return calibration is None or calibration() is True

    return (evaluator, floors), promotion, holdout


def start(request, prepared, operation, *, expires):
    authority(request, prepared["context"])
    expected_tried = [prepared["tried"]]

    def source_current():
        authority(request, prepared["context"])
        lessons, tried = _source(prepared["body"]["source"])
        if lessons != prepared["lessons"] or tried != expected_tried[0]:
            raise HTTPException(409, "The reviewed lessons or their earlier judgments changed. No further test or learning change was admitted.")

    def work(_job, budget, guard, effect_scope, state):
        @contextmanager
        def scope():
            with effect_scope() as advance:
                def accepted():
                    advance()
                    expected_tried[0] = _source(prepared["body"]["source"])[1]
                accepted.retirement_guard = advance.retirement_guard
                accepted.lifecycle_guard = advance.lifecycle_guard
                yield accepted
        context, promotion, holdout = _evaluation_context(prepared, state, budget, guard, scope)
        completed = False
        try:
            report = runner.run_self_harness_transfer(prepared["body"]["source"], targets=prepared["models"],
                force=prepared["body"]["retry_judged"], _context=context, raise_errors=True,
                dispatch_guard=guard, effect_scope=scope, promotion_authorize=promotion,
                work_item_id="lesson-transfer:" + operation)
            completed = True
        finally:
            if holdout is not None and not holdout.finalize_remaining() and completed:
                raise HTTPException(503, "Final-question evidence could not be confirmed. Earlier learning changes may remain; read the original task and current lessons.")
        guard()
        reports = [{"Model": model_label(model), "Lessons tried": len(row["attempted"]),
                    "Started on trial": len(row["promoted"]), "Not adopted": len(row["skipped"]),
                    "Checks not completed": sum(item == "no evaluator/corpus for target" or item.startswith("gate refused")
                        or "sealed holdout authorization failed" in item or self_harness._INDETERMINATE_REASON in item
                        for item in row["skipped"])} for model, row in report.items()]
        return passes._pass_result(reports, budget, False)

    passes.start(request, prepared, operation, expires=expires, run_work=work,
                 check_current=source_current, purpose=PURPOSE, notice=NOTICE)
    return original(request, operation, prepared)
