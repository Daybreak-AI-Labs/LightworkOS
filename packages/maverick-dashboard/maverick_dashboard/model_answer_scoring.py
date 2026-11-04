"""Reviewed ordinary answers for the packaged deterministic task sets."""
from __future__ import annotations

import copy
import math
import os
import re
import time
from typing import Literal

from fastapi import HTTPException
from maverick import config
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.training import environments
from pydantic import BaseModel, ConfigDict, Field

from . import learning_jobs as jobs
from . import learning_ops_api as native
from .auth import require_global_permission
from .draft_api import context_for
from .plain_labels import model_label

PAGE = "/learning#lo-mi-answer-h"
NOTICE = ("These are published sample questions. This checks the answers you enter against fixed rules, "
          "without contacting an AI service. It does not verify who produced the answers or change which AI handles your work. "
          "A high score here does not establish performance on real work.")
TITLES = {"dsar_routing_v1": "Recognize and route personal-data requests",
          "article28_clause_v1": "Review a processor's privacy commitments",
          "privacy_assessment_v1": "Review privacy risks and safeguards"}
CLAUSES = {"instructions": "Written instructions", "confidentiality": "Confidentiality",
           "security": "Security safeguards", "subprocessors": "Other processors",
           "assistance": "Help with personal-data requests", "breach": "Breach reporting",
           "deletion": "Delete or return data", "audit": "Audit access",
           "transfers": "International transfers", "retention": "How long data is kept"}
PIA = {"necessity": "Necessity", "lawful_basis": "Lawful basis", "special_category": "Sensitive information",
       "transparency": "Transparency", "rights": "People's rights", "retention": "Retention",
       "security": "Security safeguards", "transfers": "International transfers",
       "processors": "Other processors", "automated": "Automated decisions"}
SPLITS = {"holdout": "Kept-aside questions", "validation": "Check questions", "train": "Practice questions"}


def _pia_passage(value):
    key, answer = value.removesuffix(".").split("=", 1)
    return PIA.get(key.removeprefix("pia_"), "Privacy safeguard") + ": " + {
        "yes": "Yes", "no": "No", "unknown": "Not known"}.get(answer, "Not known")


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    reference: str = Field(min_length=1, max_length=128)
    values: dict[str, str] = Field(max_length=12)
    quotes: list[str] = Field(default_factory=list, max_length=16)


class Answers(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    task_set: str = Field(min_length=1, max_length=120)
    split: Literal["holdout", "validation", "train"]
    model: str = Field(default="", max_length=200)
    answers: list[Answer] = Field(min_length=1, max_length=24)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


def authority(request, context=None, *, write=False, current_settings=True):
    require_global_permission(request, "admin")
    current = context_for(request)
    if context is not None and current != context:
        raise HTTPException(409, "Your account or workspace changed. Refresh before continuing.")
    if current_settings and config.config_source_errors(include_tenant=True):
        raise HTTPException(409, "Current settings could not be checked. Your entered answers are kept.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
        native._halt_preflight("model-answer-score")
    return current


def _models():
    from maverick.self_improvement_runner import harness_fleet_models
    return harness_fleet_models()[:50]


def _fields(task_set):
    def choice(name, label, options):
        return {"name": name, "label": label, "choices": [{"value": key, "label": text} for key, text in options]}
    if task_set == "dsar_routing_v1":
        return [choice("is_dsar", "Is this a personal-data request?", [("true", "Yes"), ("false", "No")]),
                choice("kind", "Request type", [("", "No personal-data request"), ("access", "Access or a copy"),
                       ("erasure", "Deletion"), ("portability", "Move data elsewhere"), ("rectification", "Correction"),
                       ("restriction", "Restrict use"), ("objection", "Object to use")]),
                choice("route", "Team to handle it", [("privacy_review", "Privacy review"), ("ordinary_support", "Customer support")]),
                {"name": "deadline_days", "label": "Days to respond (leave empty when no deadline applies)", "kind": "number"}]
    if task_set == "article28_clause_v1":
        return [choice(key, label, [("present", "Provided"), ("missing", "Missing"), ("unclear", "Unclear")])
                for key, label in CLAUSES.items()]
    if task_set == "privacy_assessment_v1":
        risks = [("minimal", "Minimal"), ("low", "Low"), ("medium", "Medium"), ("high", "High")]
        return [choice("inherent_risk", "Risk before safeguards", risks), choice("residual_risk", "Risk after safeguards", risks)] + [
            choice("pia_" + key, label, [("", "No finding"), ("risk", "Risk"), ("unverified", "Not verified")])
            for key, label in PIA.items()]
    raise HTTPException(409, "This task set does not have an ordinary answer form yet. Your other answers are kept.")


def current(request, task_set, split):
    context = authority(request)
    if task_set not in TITLES or split not in SPLITS:
        raise HTTPException(422, "Choose a task set and questions from the lists.")
    try:
        pack = environments.load_environment(task_set)
        cases = pack.split(split)
    except environments.EnvironmentError as exc:
        raise HTTPException(409, "The task questions changed or could not be verified. Your entered answers are kept.") from exc
    if not cases or len(cases) > 24 or any(c.data_classification != "public" or c.provenance != "synthetic"
            or c.answer_visibility != "published" or c.consent is not None for c in cases):
        raise HTTPException(409, "Only the supported published example questions can use this form. Private answers remain protected.")
    models = _models()
    source = digest([os.path.normcase(str(environments.environment_pack_dir().resolve())), pack.digest])
    revision = digest([context, source, models, split])
    rows = []
    for index, case in enumerate(cases):
        evidence = case.evidence_text
        shown = evidence
        if task_set == "privacy_assessment_v1":
            shown = "\n".join(_pia_passage(item.strip()) for item in evidence.split(";") if "=" in item)
        rows.append({"reference": case.case_id, "title": "Question " + str(index + 1) + ": " +
                     ("Privacy safeguards" if task_set == "privacy_assessment_v1" else shown[:90]), "evidence": shown,
                     "quotes": [{"value": item.strip().removesuffix("."), "label": _pia_passage(item.strip())}
                                for item in evidence.split(";") if "=" in item] if task_set == "privacy_assessment_v1" else []})
    authority(request, context)
    if models != _models():
        raise HTTPException(409, "The available model labels changed. Refresh; your entered answers are kept.")
    return {"context": context, "revision": revision, "source": source, "task_set": task_set, "split": split,
            "title": TITLES[task_set], "questions_label": SPLITS[split], "notice": NOTICE,
            "models": [{"value": value, "label": model_label(value)} for value in models],
            "questions": rows, "fields": _fields(task_set)}, pack


def _output(task_set, case, answer):
    fields = _fields(task_set)
    if set(answer.values) != {field["name"] for field in fields}:
        raise HTTPException(422, "Complete the displayed answer fields for every question.")
    for field in fields:
        value = answer.values[field["name"]]
        if len(value) > 200 or field.get("choices") and value not in {c["value"] for c in field["choices"]}:
            raise HTTPException(422, "Choose from the displayed answer options.")
    values = answer.values
    if task_set == "dsar_routing_v1":
        days = values["deadline_days"]
        if days and (not days.isdecimal() or not 0 <= int(days) <= 3650):
            raise HTTPException(422, "Use a whole number of days, or leave the deadline empty.")
        output = {**values, "is_dsar": values["is_dsar"] == "true", "deadline_days": int(days) if days else None}
    elif task_set == "article28_clause_v1":
        output = {value: [key for key in CLAUSES if values[key] == value] for value in ("present", "missing", "unclear")}
    else:
        output = {"inherent_risk": values["inherent_risk"], "residual_risk": values["residual_risk"],
                  "findings": [{"id": "pia_" + key, "kind": values["pia_" + key]} for key in PIA if values["pia_" + key]]}
    citations = []
    for quote in answer.quotes:
        if not quote or len(quote) > 4000 or case.evidence_text.find(quote) < 0:
            raise HTTPException(422, "Each supporting passage must appear exactly in its question's information.")
        if quote in [row["quote"] for row in citations]:
            raise HTTPException(422, "Keep each supporting passage once.")
        if task_set == "privacy_assessment_v1" and quote not in {item.strip().removesuffix(".") for item in case.evidence_text.split(";") if "=" in item}:
            raise HTTPException(422, "Choose supporting information from the displayed privacy safeguards.")
        start = case.evidence_text.index(quote)
        citations.append({"source_id": case.source_id, "quote": quote, "start": start, "end": start + len(quote)})
    reasons = [kind + ":" + key for kind in ("missing", "unclear") for key in output.get(kind, [])]
    return {**output, "citations": citations, "reason_codes": reasons}


def prepare(request, values):
    body = Answers.model_validate(values)
    state, pack = current(request, body.task_set, body.split)
    authority(request, body.context, write=True)
    if body.context != state["context"] or body.revision != state["revision"]:
        raise HTTPException(409, "The questions or settings changed. Refresh their review; your entered answers are kept.")
    if body.model and body.model not in {row["value"] for row in state["models"]}:
        raise HTTPException(409, "The reported model is no longer available. Review its label again.")
    cases = {case.case_id: case for case in pack.split(body.split)}
    if [a.reference for a in body.answers] != list(cases):
        raise HTTPException(422, "Supply one answer for every displayed question.")
    outputs = {a.reference: _output(body.task_set, cases[a.reference], a) for a in body.answers}
    return {"body": body.model_dump(), "source": state["source"], "pack": pack.digest, "outputs": outputs,
            "model_label": model_label(body.model) if body.model else "Not specified", "title": state["title"],
            "questions_label": state["questions_label"], "questions": state["questions"]}


def review_rows(prepared):
    body = prepared["body"]
    fields = _fields(body["task_set"])
    rows = [{"label": "Task set", "after": prepared["title"]}, {"label": "Questions", "after": prepared["questions_label"]},
            {"label": "Reported answer model (not verified)", "after": prepared["model_label"]}]
    for index, answer in enumerate(body["answers"]):
        question = prepared["questions"][index]
        lines = ["Question information:", question["evidence"], "", "Supplied answer:"]
        for field in fields:
            value = answer["values"][field["name"]]
            shown = next((c["label"] for c in field.get("choices", []) if c["value"] == value), value or "No deadline")
            lines.append(field["label"] + ": " + shown)
        quotes = answer["quotes"]
        if body["task_set"] == "privacy_assessment_v1":
            quotes = [_pia_passage(q) for q in quotes]
        rows.append({"label": question["title"], "after": "\n".join(lines + ["Supporting passages:"] + (quotes or ["None supplied"]))})
    return rows


def _store():
    return GovernedRecordStore("model-answer-score-requests", "MAS", "model_answer_score_request")


def _owned(request, operation):
    context = authority(request, current_settings=False)
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "That original scoring request is unavailable.")
    row = _store().get("MAS-" + operation)
    if row and (row["actor"] != native._actor(request) or row["context"] != context):
        raise HTTPException(404, "That original scoring request is unavailable to your account.")
    return row


def original(request, operation):
    context = authority(request, current_settings=False)
    row = _owned(request, operation)
    if row is None:
        return {"operation": operation, "context": context, "confirmed": False,
                "message": "The original scoring record is unavailable. Absence does not mean it failed. No work was repeated."}
    body = row["prepared"]["body"]
    job = jobs.get(row["job_id"]) if row.get("job_id") else None
    if job is not None and (job.started_by != native._actor(request) or job.workspace != native._workspace() or job.kind != "model_improvement_score"):
        raise HTTPException(404, "The original scoring task is unavailable to your account.")
    result = {"operation": operation, "context": context, "confirmed": bool(row.get("job_id")),
              "message": "Your check was accepted. Its saved progress or result is shown below." if row.get("job_id") else
                         "The original start is unconfirmed. This check was not started again; check its saved request later.",
              "task_set": row["prepared"]["title"], "questions": row["prepared"]["questions_label"],
              "reported_model": row["prepared"]["model_label"], "notice": NOTICE, "job": copy.deepcopy(job.view()) if job else None,
              "review": review_rows(row["prepared"]), "selection": {"task_set": body["task_set"], "split": body["split"]}}
    if row.get("job_id") and job is None:
        result["message"] = ("The original check was accepted, but its detailed result is no longer saved. "
            "This does not establish whether it finished. Nothing was repeated. If another local check is needed, prepare and confirm a separate new review.")
    elif job is not None and not job.view()["worker_available"] and job.active:
        result["message"] = ("The original check was accepted; its last saved progress is shown below, but the process that ran it is no longer available. "
            "Completion is unconfirmed. Nothing was restarted. A new local check requires a separate review and confirmation.")
    authority(request, context, current_settings=False)
    return result


def start(request, prepared, operation, *, expires):
    body = prepared["body"]
    context = authority(request, body["context"], write=True)
    actor = native._actor(request)
    binding = digest({"operation": operation, "prepared": prepared, "actor": actor})
    with authority_effect_fence():
        authority(request, context, write=True)
        existing = _owned(request, operation)
        if existing:
            if existing["binding"] != binding:
                raise HTTPException(409, "Read the original scoring request; it belongs to a different review.")
            return original(request, operation)
        if not isinstance(expires, (float, int)) or not math.isfinite(expires) or expires <= time.time():
            raise HTTPException(409, "This review expired before the check was admitted. Your answers are kept; prepare a fresh review.")
        if prepare(request, body) != prepared:
            raise HTTPException(409, "The reviewed question source changed. Your entered answers are kept.")
        native._record(request, "model_answer_score", phase="prepared", operation=operation, reviewed_revision=body["revision"])
        claim = _store().create({"id": "MAS-" + operation, "actor": actor, "context": context,
                                "binding": binding, "prepared": prepared, "state": "admitting"},
                               action="learning.answers.prepare", actor=actor, max_records=10000)
        def run(job):
            # Bind the real native worker before scoring. Neither a lost reply nor
            # matching answers can establish a different job as this request.
            with authority_effect_fence():
                if prepare(request, body) != prepared:
                    raise HTTPException(409, "The questions or access changed before scoring. No answers were checked.")
                _store().update(claim["id"], lambda row: row.update(state="admitted", job_id=job.id),
                    expected_revision=claim["revision"], action="learning.answers.admitted", actor=actor)
                state, pack = current(request, body["task_set"], body["split"])
                if state["revision"] != body["revision"] or pack.digest != prepared["pack"]:
                    raise HTTPException(409, "The question source changed before scoring. No answers were checked.")
                evaluated = environments.evaluate_outputs(pack, prepared["outputs"], split=body["split"])
                labels = {c.case_id: "Question " + str(i + 1) for i, c in enumerate(pack.split(body["split"]))}
                return {"provided_answers_only": True, "task_set": prepared["title"], "reported_model": prepared["model_label"],
                        "questions": len(evaluated.results), "passed": sum(r.passed for r in evaluated.results),
                        "score": round(evaluated.score, 4), "pass_rate": round(evaluated.pass_rate, 4), "notice": NOTICE,
                        "answers": [{"question": labels[r.case_id], "passed": r.passed,
                            "answer_match": round(r.correctness, 4), "evidence_match": round(r.citation_score, 4),
                            "evidence_valid": r.parsed and not any("span" in reason for reason in r.reasons)} for r in evaluated.results]}
        try:
            native.start_job(request, "model_improvement_score", "Checking supplied example answers", run)
        except Exception:
            # A claimed admission is never dispatched again, even when the worker
            # could not start or its original receipt was interrupted.
            return original(request, operation)
    return original(request, operation)
