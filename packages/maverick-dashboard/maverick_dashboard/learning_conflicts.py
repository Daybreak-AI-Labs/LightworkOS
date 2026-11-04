"""Reviewed native meaning checks; interrupted requests never dispatch twice."""
from __future__ import annotations

import math
import time

from fastapi import HTTPException
from maverick import config, self_harness
from maverick.authority_effects import authority_effect_fence
from maverick.budget import resolve_budget_caps
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore, RecordConflict

from . import learning_jobs as jobs
from . import learning_ops_api as native
from . import learning_test_cases_api as questions

PAGE = "/learned#lpo-clash-h"
TTL = 600
NOTICE = ("This advisory check compares only currently shareable learned guidance within each model and area. "
          "It changes no instructions. AI judgments may be wrong or unavailable; a clear result is not proof that guidance is correct. "
          "Original requests stay on this installation; detailed job observations are retained among its recent tasks.")


def _requests():
    return GovernedRecordStore("learning-conflict-requests", "LCC", "learning_conflict_request", authority_scope="deployment_global")


def _state(request, model=None, *, context=None, write=False):
    current = questions._authority(request, context, write=write)
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current learning settings cannot be read. No check was started.")
    model = native._offered(model)
    checked = self_harness.conflict_review(model)
    from maverick.llm import model_for_role

    from .learning_loop_api import _scope_label
    from .plain_labels import model_label
    verifier = model_for_role("verifier")
    caps = resolve_budget_caps(task_class="self_harness")
    cap = self_harness.settings().get("eval_budget_dollars")
    limits = [value for value in (caps.get("max_dollars"), cap) if value is not None]
    if any(type(value) not in {int, float} or not math.isfinite(value) or value < 0 for value in limits):
        raise HTTPException(409, "The learning spending limit needs attention in All settings. No check was started.")
    ceiling = min(limits) if limits else None
    sections, pair_count = [], 0
    for key, block in checked["blocks"].items():
        mid, scope = self_harness._split_key(key)
        lines = self_harness._bullets(block)
        pair_count += sum(self_harness._norm_line(a) != self_harness._norm_line(b)
                          for index, a in enumerate(lines) for b in lines[index + 1:])
        sections.append({"label": model_label(mid) + " / " + _scope_label(scope), "lines": lines})
    if pair_count > 256 or sum(len(line) for section in sections for line in section["lines"]) > 24000:
        raise HTTPException(409, "This selection is too large for one complete review. Choose one model and review again; nothing was started.")
    revision = digest([current, model, checked["revision"], caps, cap, verifier, native._fleet()])
    questions._authority(request, current)
    return {"context": current, "revision": revision, "model": model, "sections": sections, "pairs": pair_count,
            "withheld": checked["withheld"], "ceiling": ceiling, "verifier": verifier, "verifier_label": model_label(verifier),
            "blocks": checked["blocks"]}


def catalog(request):
    context = questions._authority(request)
    from .plain_labels import model_label
    rows = [row for row in _requests().list(limit=10001) if row["actor"] == native._actor(request) and row["context"] == context]
    recent = sorted(rows, key=lambda row: row["created_at"], reverse=True)[:20]
    questions._authority(request, context)
    return {"context": context, "models": [{"value": model, "label": model_label(model)} for model in native._fleet()],
            "requests": [{"value": row["id"][4:], "label": "Meaning check / " + (model_label(row["model"]) if row["model"] else "Every model") +
                          " / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))} for row in recent], "notice": NOTICE}


def prepare(request, model=None, *, context=None):
    state = _state(request, model, context=context, write=True)
    if not state["pairs"]:
        raise HTTPException(409, "There are no pairs of currently shareable lessons to compare in this selection. Withheld or unavailable guidance is not a clear result.")
    return {key: state[key] for key in ("context", "revision", "model")} | {"expires": time.time() + TTL}


def changes(request, prepared):
    state = _state(request, prepared["model"], context=prepared["context"])
    if state["revision"] != prepared["revision"]:
        raise HTTPException(409, "The guidance, sources, model or spending settings changed. Review the current selection again.")
    return [{"label": "What will run", "after": f"{state['pairs']} pair comparisons using {state['verifier_label']}. {NOTICE}"},
            {"label": "Spending", "after": f"Current per-run ceiling: ${state['ceiling']:g}. Other provider and organization limits still apply. Actual use is recorded; this is not a price quote." if state["ceiling"] is not None else
             "No per-run dollar ceiling is configured. Current provider and organization limits still apply. Set a limit in All settings before proceeding if needed."},
            {"label": "Unavailable guidance", "after": f"{state['withheld']} stored lines are withheld because their shared sources or safety checks could not be confirmed. Their contents are not sent."},
            *[{"label": section["label"], "after": section["lines"]} for section in state["sections"]]]


def _deadline(prepared):
    expires = prepared.get("expires")
    if type(expires) not in {int, float} or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
        raise HTTPException(409, "This review expired. Review the current guidance again; no new AI call was made.")


def owned(request, operation, *, prepared=None):
    context = questions._authority(request)
    questions._request_id(operation)
    row = _requests().get("LCC-" + operation)
    if row and (row["context"] != context or row["actor"] != native._actor(request) or row["workspace"] != native._workspace()):
        raise HTTPException(404, "This original check is not available to this account and workspace.")
    if row and prepared is not None and row["request_digest"] != digest([operation, prepared, native._actor(request)]):
        raise HTTPException(409, "This original request belongs to another reviewed check.")
    questions._authority(request, context)
    return row


def original(request, operation, *, prepared=None):
    row = owned(request, operation, prepared=prepared)
    result = {"context": questions._authority(request), "operation": operation, "confirmed": False, "active": False,
              "message": "Whether the original check started is unconfirmed. Nothing was repeated; a missing result does not prove that work failed.", "notice": NOTICE}
    if not row or not row.get("job_id"):
        return result
    job = jobs.get(row["job_id"])
    if not job or (job.kind, job.started_by, job.workspace) != ("self_harness_clash", row["actor"], row["workspace"]):
        result["message"] = "The original task observation is no longer available. Its request remains recorded. No AI work was repeated."
        return result
    view = jobs.current_view(job)
    result.update(confirmed=bool(view["observation_saved"]), active=job.active,
                  message="The original meaning-check task is recorded. This lookup made no AI call." if view["observation_saved"] else
                  "The original task is known, but its latest progress is not confirmed as saved. No AI work was repeated.",
                  state=view["state"] if view["observation_saved"] else "unconfirmed", problem=view.get("problem", ""), job_id=job.id,
                  task_href="/learned?learning_task=" + job.id + "#learning-job-history")
    report = view.get("result")
    if report and view["result_retained"] and view["observation_saved"]:
        result.update({key: report[key] for key in ("checked", "unknown", "flagged", "wording_flags", "total", "spent", "stopped")})
        try:
            state = _state(request, row["model"], context=row["context"])
        except HTTPException:
            state = None
        if state and state["revision"] == row["source_revision"]:
            sections = state["sections"]
            result["pairs"] = [{"area": sections[item["section"]]["label"], "first": sections[item["section"]]["lines"][item["first"]],
                                "second": sections[item["section"]]["lines"][item["second"]],
                                "basis": "AI flagged a possible conflict" if item["verdict"] is True else "Wording flag; AI judgment unavailable"}
                               for item in report["comparisons"] if item["verdict"] is True or item["fallback"]]
        else:
            result["message"] += " Guidance or its permissions changed; original pair text is withheld. Counts describe the original check, not current guidance."
    questions._authority(request, row["context"])
    return result


def start(request, prepared, operation):
    questions._request_id(operation)
    with authority_effect_fence():
        questions._authority(request, prepared["context"], write=True)
        if owned(request, operation, prepared=prepared):
            return original(request, operation, prepared=prepared)
        _deadline(prepared)
        state = _state(request, prepared["model"], context=prepared["context"], write=True)
        if state["revision"] != prepared["revision"]:
            raise HTTPException(409, "The reviewed guidance, sources or spending settings changed. Review again; no task was started.")
        store, actor = _requests(), native._actor(request)
        native._record(request, "self_harness_semantic_conflicts", phase="reviewed", operation=operation,
                       reviewed_revision=prepared["revision"], comparisons=state["pairs"])
        try:
            claim = store.create({"id": "LCC-" + operation, "actor": actor, "context": prepared["context"],
                                  "workspace": native._workspace(), "model": prepared["model"],
                                  "request_digest": digest([operation, prepared, actor]), "source_revision": prepared["revision"],
                                  "state": "admitting"}, action="learning.conflict.prepare", actor=actor, max_records=10000)
        except RecordConflict:
            return original(request, operation, prepared=prepared)
        if claim.get("_audit_pending"):
            return original(request, operation, prepared=prepared)
        _deadline(prepared)
        questions._authority(request, prepared["context"], write=True)

    budget_box = []

    def guard(*, deadline=False):
        questions._authority(request, prepared["context"], write=True)
        if deadline:
            _deadline(prepared)
        if _state(request, prepared["model"], context=prepared["context"])["revision"] != prepared["revision"]:
            raise HTTPException(409, "The reviewed shared guidance or its access changed. No further AI call was made.")

    class Stopped(Exception):
        pass

    def run(job):
        from maverick.llm import LLM
        # Publish the ACTUAL admitted native job, before any physical AI call.
        with authority_effect_fence():
            accepted = store.update(claim["id"], lambda row: row.update(job_id=job.id, state="admitted"),
                                    expected_revision=claim["revision"], action="learning.conflict.admitted", actor=actor)
            if not accepted or accepted.get("_audit_pending"):
                raise HTTPException(503, "The original task identity could not be confirmed. No AI call was made.")
            guard(deadline=True)
        budget = native._budget("self_harness")
        if state["ceiling"] is not None:
            budget.max_dollars = min(budget.max_dollars, state["ceiling"]) if budget.max_dollars is not None else state["ceiling"]
        budget_box.append(budget)
        comparisons = []
        keys = list(state["blocks"])

        def dispatch():
            guard()
            if job.cancelled:
                raise Stopped

        def before_pair(_key, _a, _b):
            dispatch()

        def observe(key, a, b, verdict, fallback):
            section = keys.index(key)
            lines = state["sections"][section]["lines"]
            comparisons.append({"section": section, "first": lines.index(a), "second": lines.index(b), "verdict": verdict, "fallback": fallback})

        classifier = self_harness.llm_conflict_classifier(LLM(state["verifier"]), budget=budget,
                         dispatch_guard=dispatch, max_physical_attempts=1)
        try:
            self_harness.detect_store_conflicts(model_id=prepared["model"], reviewed_blocks=state["blocks"],
                        classifier_fn=classifier, before_pair=before_pair, observe_pair=observe)
        except Stopped:
            pass
        guard()
        checked = sum(item["verdict"] is not None for item in comparisons)
        return {"comparisons": comparisons, "total": state["pairs"], "checked": checked,
                "unknown": state["pairs"] - checked, "flagged": sum(item["verdict"] is True for item in comparisons),
                "wording_flags": sum(item["fallback"] for item in comparisons), "spent": round(float(budget.dollars), 6),
                "stopped": bool(job.cancelled)}

    def cancel():
        if budget_box:
            jobs.stop_budget(budget_box[0])()

    try:
        native.start_job(request, "self_harness_clash", "Checking lessons for possible conflicts by meaning", run,
                         cancellable=True, on_cancel=cancel)
    except HTTPException:
        # A response/admission gap must not create a second paid worker.
        return original(request, operation, prepared=prepared)
    return original(request, operation, prepared=prepared)
