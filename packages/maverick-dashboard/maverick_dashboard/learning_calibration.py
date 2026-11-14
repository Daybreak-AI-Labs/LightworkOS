"""Actual current answer-checker judgments through native reviewed learning custody."""
from __future__ import annotations

import math
import time
from typing import Literal

from fastapi import HTTPException
from maverick import calibration, self_harness
from maverick import self_harness_eval as evaluation
from maverick import self_improvement_runner as runner
from maverick.governed_operations import digest
from maverick.llm import model_for_role
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import learning_passes as passes
from . import learning_test_cases_api as questions
from .auth import require_page_permission
from .plain_labels import model_label

PAGE = "/learned#learning-calibration"
PURPOSE = "checker_calibration"
NOTICE = ("Check the current answer checker against saved questions, responses you supply and your independent correct or incorrect labels. "
          "The checker sees the question and response; your label and its basis stay private. Actual AI judgments can spend money. "
          "Only this reviewed check's completed checks are assessed. Existing reliability floors remain unchanged; a check may stay insufficient or held.")


class LabelledCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    reference: str = Field(pattern=r"^[a-f0-9]{64}$")
    answer: str = Field(min_length=1, max_length=8000)
    correct: bool
    basis: str = Field(min_length=1, max_length=2000)

    @field_validator("answer", "basis")
    @classmethod
    def complete(cls, value):
        if not value.strip() or "\x00" in value:
            raise ValueError("Complete the response and the independent basis for its label.")
        return value


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["judge", "assess"] = "judge"
    model: str = Field(default="", max_length=200)
    cases: list[LabelledCase] = Field(default_factory=list, max_length=64)
    original_operation: str = Field(default="", pattern=r"^(?:[a-f0-9]{32})?$")


def authority(request, context=None):
    require_page_permission(request, "/learned")
    return questions._authority(request, context)


def _checker():
    settings = self_harness.settings()
    model = model_for_role("verifier")
    samples = int(settings.get("judge_samples", 1))
    return model, samples, evaluation.judge_evaluator_identity(model, samples=samples, strict=True)


def _sample_source(operation):
    return "dashboard_checker:" + operation


def _read_samples():
    try:
        return calibration.load_samples(strict=True)
    except (OSError, ValueError, TypeError) as exc:
        raise HTTPException(503, "The complete answer-checker record cannot be read. Its current reliability is unconfirmed; no check was started.") from exc


def _history(request, context):
    actor, workspace = passes.native._actor(request), passes.native._workspace()
    rows = [row for row in passes._requests().list(limit=10001)
            if row.get("purpose") == PURPOSE and (row["actor"], row["context"], row["workspace"]) == (actor, context, workspace)]
    return [{"value": row["id"][4:], "label": ("Answer assessment / " if row.get("checker_action") == "assess" else "Answer check / ") + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))}
            for row in sorted(rows, key=lambda row: row["created_at"], reverse=True)[:20]]


def _current_assessment(verdict, checker, settings, policy):
    """Read actual adequacy even when risk-limited enforcement is off."""
    if not isinstance(verdict, dict) or verdict.get("adequate") is not True or verdict.get("evaluator_id") != checker:
        return False
    careful = bool(settings.get("risk_limited"))
    minimum = max(20, int(policy["min_samples"])) if careful else int(policy["min_samples"])
    separation = max(.15, float(policy["min_discrimination"])) if careful else float(policy["min_discrimination"])
    try:
        stamp, gap = float(verdict["ts"]), float(verdict["discrimination"])
        age = float(settings.get("calibration_max_age_hours", 24)) * 3600
        counts = [verdict[name] for name in ("n", "n_correct", "n_incorrect")]
        return (all(type(value) is int for value in counts) and counts[0] >= minimum
                and counts[1] > 0 and counts[2] > 0 and counts[1] + counts[2] <= counts[0]
                and all(math.isfinite(value) for value in (stamp, gap, age))
                and age > 0 and 0 <= time.time() - stamp <= age and gap >= separation)
    except (KeyError, ValueError, TypeError, OverflowError):
        return False


def catalog(request):
    context = authority(request)
    model, draws, checker = _checker()
    retained = [sample for sample in _read_samples() if sample.evaluator_id == checker]
    # The checker assessment below writes the evaluator-bound receipt, not the
    # general learning-freeze verdict (calibration.run_assessment).
    receipt = calibration._risk_verdict_path()
    verdict = calibration._load_verdict(receipt)
    if receipt.exists() and verdict is None:
        raise HTTPException(503, "The current checker assessment cannot be verified. Refresh after its saved record is available; no check was started.")
    settings, policy = self_harness.settings(), calibration._settings()
    minimum = max(20, int(policy["min_samples"])) if settings.get("risk_limited") else int(policy["min_samples"])
    value = {"context": context, "notice": NOTICE, "available": False, "models": [], "requests": _history(request, context),
             "checker": model_label(model), "draws": draws, "retained_current_checker_samples": len(retained),
             "current_receipt": _current_assessment(verdict, checker, settings, policy),
             "minimum_samples": minimum,
             "scope": "Recent original choices show at most your newest 20 retained requests. Sample count includes retained records for this exact current checker; it does not establish adequacy."}
    try:
        state = passes._state(request, context=context)
        value.update(available=True, revision=state["revision"], models=[{"value": name, "label": model_label(name)} for name in state["models"]], ceiling=state["ceiling"], egress=state["egress"])
    except HTTPException as exc:
        if exc.status_code != 409:
            raise
        value["problem"] = exc.detail
    authority(request, context)
    return value


def browse(request, model, offset=0):
    authority(request)
    return questions.browse(request, model, offset=offset)


def _owned_samples(request, operation, checker):
    row = passes.owned(request, operation, purpose=PURPOSE)
    if row is None:
        raise HTTPException(404, "Choose one of your retained original answer checks.")
    binding = row.get("checker_sources")
    scope = questions._scope(request)
    if (not isinstance(binding, dict) or set(binding) != {"model", "references", "source"}
            or binding["source"] != scope["source"] or binding["model"] not in scope["models"]
            or not isinstance(binding["references"], list) or not 1 <= len(binding["references"]) <= 64):
        raise HTTPException(409, "The original's question source cannot currently be verified. Its historical outcome remains readable; no new assessment was admitted.")
    state = passes._state(request, context=row["context"])
    for reference in binding["references"]:
        try:
            _, _, case = evaluation._selected_case(state["corpus"], binding["model"], reference)
        except ValueError as exc:
            raise HTTPException(409, "An original question changed or was removed. Read its historical check; a new assessment needs current permitted questions.") from exc
        evaluation.require_cases_current([case])
    measured = row.get("checker_measurements_operation", operation)
    questions._request_id(measured)
    if measured != operation and passes.owned(request, measured, purpose=PURPOSE) is None:
        raise HTTPException(409, "The original measurements cannot be attributed to your retained check. No new assessment was admitted.")
    samples = [sample for sample in _read_samples() if sample.source == _sample_source(measured) and sample.evaluator_id == checker]
    if not samples:
        raise HTTPException(409, "This original has no clean retained judgments for the current checker. Run a separately reviewed current check first.")
    return samples, measured


def prepare(request, values, *, context, revision):
    authority(request, context)
    body = Choices.model_validate(values)
    state = passes._state(request, context=context, write=True)
    if state["revision"] != revision:
        raise HTTPException(409, "The current questions, checker, sources or settings changed. Refresh and review again; your entered work is kept.")
    checker_model, draws, checker = _checker()
    cases = []
    if body.action == "judge":
        if not state["egress"]:
            raise HTTPException(409, "AI learning tests are off. Review the learning testing setting in All settings before starting.")
        if body.model not in state["models"] or not body.cases or body.original_operation:
            raise HTTPException(422, "Choose current saved questions and complete at least one independently labelled response.")
        seen = set()
        for selected in body.cases:
            try:
                _, _, source = evaluation._selected_case(state["corpus"], body.model, selected.reference)
            except ValueError as exc:
                raise HTTPException(409, "A selected question changed. Choose it again from the current collection.") from exc
            if not evaluation.case_current(source):
                raise HTTPException(403, "A selected question is no longer permitted for learning. No check was started.")
            key = (selected.reference, selected.answer)
            if key in seen:
                raise HTTPException(422, "Do not repeat the same question and response in this check.")
            seen.add(key)
            cases.append({"source": dict(source), **selected.model_dump()})
    else:
        if body.cases or body.model or not body.original_operation:
            raise HTTPException(422, "Choose one original check to assess; do not add new responses to an assessment.")
        samples, measured = _owned_samples(request, body.original_operation, checker)
    prepared = {key: state[key] for key in ("context", "revision", "source_revision", "artifact", "ceiling")}
    prepared.update(body=body.model_dump(), models=[checker_model], checker=checker, draws=draws, cases=cases)
    policy = calibration._settings()
    careful = self_harness.settings().get("risk_limited")
    prepared["minimum_samples"] = max(20, int(policy["min_samples"])) if careful else int(policy["min_samples"])
    prepared["minimum_separation"] = max(0.15, float(policy["min_discrimination"])) if careful else float(policy["min_discrimination"])
    prepared["checker_sources"] = {"model": body.model, "references": [row["reference"] for row in cases],
                                   "source": questions._scope(request, context)["source"]} if body.action == "judge" else passes.owned(request, body.original_operation, purpose=PURPOSE)["checker_sources"]
    if body.action == "assess":
        prepared["sample_revision"] = digest([sample.__dict__ for sample in samples])
        prepared["sample_operation"] = measured
    if passes._state(request, context=context)["revision"] != state["revision"]:
        raise HTTPException(409, "The current source changed during review. Refresh before continuing.")
    authority(request, context)
    return prepared


def review_rows(prepared):
    assess = prepared["body"]["action"] == "assess"
    cases = [{"Question": row["source"]["goal"], "Saved expected answer": row["source"].get("expected", ""),
              "Response supplied": row["answer"], "Your independent label": "Correct" if row["correct"] else "Incorrect", "Label basis": row["basis"]}
             for row in prepared["cases"]]
    return [{"label": "Effect", "after": "Reassess only the retained completed checks from your selected original check. No AI is called." if assess else NOTICE},
            {"label": "Current answer checker", "after": model_label(prepared["models"][0])},
            {"label": "Complete independently labelled responses", "after": cases if not assess else "Only the selected original's exact current-checker sample records; no unrelated or older checker is mixed in."},
            {"label": "Checker judgments", "after": "No new judgment" if assess else f"{prepared['draws']} AI votes per response. Every vote must be completed and readable to count."},
            {"label": "Reliability decision", "after": "The existing assessment may stay insufficient or held. A saved assessment is not a promise that learning will be allowed, and does not establish business accuracy."},
            {"label": "Current reliability floors", "after": f"At least {prepared['minimum_samples']} actual completed checks, both independently labelled correct and incorrect responses, and at least {prepared['minimum_separation'] * 100:g} percentage points between confidence in correct and incorrect responses. Existing adversarial-resistance rules also apply."},
            {"label": "Storage and recovery", "after": "Append only completed checks to the existing checker record and save its actual assessment. This does not modify lessons or the separate checks needed before a lesson can be adopted. Read the original task after an interrupted reply; nothing is automatically repeated."},
            {"label": "Spending", "after": "No AI spending for this assessment." if assess else f"Spending limit for this complete check: ${prepared['ceiling']:g}; current provider and organization limits also apply." if prepared["ceiling"] is not None else "Current provider and organization limits apply; no additional check ceiling is set."}]


def original(request, operation, prepared=None):
    context = authority(request)
    value = passes.original(request, operation, prepared, purpose=PURPOSE, notice=NOTICE)
    value["message"] = value["message"].replace("learning pass", "answer check").replace("pass", "answer check")
    authority(request, context)
    return value


def start(request, prepared, operation, *, expires):
    authority(request, prepared["context"])

    def current_sources():
        authority(request, prepared["context"])
        if _checker()[2] != prepared["checker"]:
            raise HTTPException(409, "The selected checker changed. No further call or checker record was admitted.")
        evaluation.require_cases_current([row["source"] for row in prepared["cases"]])
        if prepared["body"]["action"] == "assess":
            samples, measured = _owned_samples(request, prepared["body"]["original_operation"], prepared["checker"])
            if measured != prepared["sample_operation"] or digest([sample.__dict__ for sample in samples]) != prepared["sample_revision"]:
                raise HTTPException(409, "The original checker evidence changed. Review its complete assessment again.")

    def work(job, budget, guard, effect_scope, _state):
        source = _sample_source(operation if prepared["body"]["action"] == "judge" else prepared["sample_operation"])
        saved = 0
        if prepared["body"]["action"] == "judge":
            for row in prepared["cases"]:
                guard()
                recorded = []

                def observe(verdict, confidence, evaluator_id, *, truth=row["correct"], measurements=recorded):
                    guard()
                    if evaluator_id != prepared["checker"] or not math.isfinite(confidence):
                        raise HTTPException(409, "The actual checker evidence did not match this complete review.")
                    with effect_scope():
                        # Native calibration assesses confidence that the
                        # RESPONSE is correct, not confidence in either vote.
                        answer_confidence = confidence if verdict else 1 - confidence
                        if not calibration.record_sample(answer_confidence, truth, source=source,
                                evaluator_id=evaluator_id, before_effect=guard):
                            raise HTTPException(503, "The checker measurement could not be retained. Read its original task; do not repeat it automatically.")
                    measurements.append(True)

                judge = evaluation.llm_judge(runner._evaluator_llm(prepared["models"][0], guard), budget=budget,
                    samples=prepared["draws"], strict=True, evaluator_id=prepared["checker"],
                    work_item_id="checker-calibration:" + operation, verdict_observer=observe)
                judge(row["source"]["goal"], row["answer"], "")
                guard()
                if not recorded:
                    raise HTTPException(409, "The checker did not return every clean judgment. Earlier completed checks may remain; read the original task.")
                saved += 1
        guard()
        with effect_scope():
            report = calibration.run_assessment(evaluator_id=prepared["checker"], sources={source}, strict=True, before_effect=guard,
                min_samples=prepared["minimum_samples"], min_discrimination=prepared["minimum_separation"])
        guard()
        result = passes._pass_result([{"Model": model_label(prepared["models"][0]), "Actual completed checks saved": saved,
            "Samples assessed": report.n, "Labelled correct responses": report.n_correct, "Labelled incorrect responses": report.n_incorrect,
            "Reliability decision": "Meets current reliability checks" if report.adequate else "Held; current reliability checks were not met",
            "Difference in confidence": round(report.discrimination, 4), "Checks not completed": 0,
            "Scope": "Only this selected original's actual completed checks and your independent labels. Labels are operator reports, not independently verified business truth."}], budget, False)
        result["meaning"] = "Completed answer checks using your independent labels; this does not establish customer-work performance."
        return result

    passes.start(request, prepared, operation, expires=expires, run_work=work,
                 check_current=current_sources, purpose=PURPOSE, notice=NOTICE)
    return original(request, operation, prepared)
