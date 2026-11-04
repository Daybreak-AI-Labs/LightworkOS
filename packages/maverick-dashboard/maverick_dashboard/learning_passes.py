"""Reviewed native self-coaching passes with durable original admission custody."""
from __future__ import annotations

import json
import math
import os
import time
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from fastapi import HTTPException
from maverick import config, dreaming, learning_store, reflexion, self_harness
from maverick import self_harness_eval as evaluation
from maverick import self_improvement_runner as runner
from maverick.authority_effects import authority_effect_fence
from maverick.budget import resolve_budget_caps
from maverick.file_lock import _windows_extended_path, cross_process_lock, open_private_read
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore, RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import learning_jobs as jobs
from . import learning_loop_api as loop
from . import learning_ops_api as native
from . import learning_test_cases_api as questions
from .plain_labels import model_label

PAGE = "/learned#learning-passes"
TTL = 600
NOTICE = ("This pass looks for repeated mistakes in currently shareable work, tests possible lessons when AI testing is permitted, "
          "and uses the existing learning approval rules. It can change shared lessons and retire old ones. A safety copy is required first. "
          "AI testing can spend money. Test results do not establish performance on customer work.")


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scope: Literal["main", "all", "chosen"] = "main"
    model_id: str = Field(default="", max_length=200)
    trial: bool = False
    retire: bool = True
    instructions: str = Field(default="", max_length=1024 * 1024)


def _requests():
    return GovernedRecordStore("learning-pass-requests", "LPR", "learning_pass_request", authority_scope="deployment_global")


def _recent(models):
    """Strictly read the native recent window; never authorize tolerant-empty."""
    path = reflexion.default_path()
    io_path = _windows_extended_path(path) if os.name == "nt" else path
    fields = tuple(reflexion.Reflexion.__dataclass_fields__)
    try:
        with reflexion._lock, cross_process_lock(path, strict=True):
            try:
                named_before = os.stat(io_path)
                with open(io_path, "rb") as handle:
                    before = os.fstat(handle.fileno())
                    # The existing miner scans the final 2,000 lines then uses
                    # the latest 500 by recorded time. Bound that exact window.
                    start = max(0, before.st_size - 32 * 1024 * 1024)
                    handle.seek(start)
                    data = handle.read(32 * 1024 * 1024 + 1)
                    after = os.fstat(handle.fileno())
            except FileNotFoundError:
                return [], os.path.normcase(str(path.resolve()))
            def identity(st):
                return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns
            current = os.stat(io_path)
            # Windows reports change-time on fstat but creation-time on stat.
            # Compare each clock within its own API; both must retain the same
            # physical file, size and modification time as the named source.
            if (identity(before) != identity(after) or identity(named_before) != identity(current)
                    or identity(before)[:4] != identity(current)[:4]):
                raise ValueError("source changed during review")
            lines = data.splitlines()
            if start:
                lines = lines[1:]
                if len(lines) < 2000:
                    raise ValueError("recent source exceeds readable window")
            tail = deque(lines, maxlen=2000)
            rows = []
            for line in tail:
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("unreadable source record")
                row = {key: value.get(key) for key in fields}
                ts = row["ts"]
                if ts is not None and (type(ts) not in {int, float} or not math.isfinite(ts)):
                    raise ValueError("unreadable source time")
                for name in fields:
                    if name not in {"ts", "goal_id", "tools_used"} and row[name] is not None and not isinstance(row[name], str):
                        raise ValueError("unreadable source field")
                rows.append(row)
            rows.sort(key=lambda row: row["ts"] or 0, reverse=True)
            shared = [row for row in rows[:500] if any(self_harness._is_minable(row, model_id=model) for model in models)]
            return shared, os.path.normcase(str(path.resolve()))
    except (OSError, ValueError, TypeError) as exc:
        raise HTTPException(409, "Recent learning work cannot be completely checked. No pass was started; refresh when its saved history is available.") from exc


def _strict_object(path):
    try:
        with os.fdopen(open_private_read(path), "rb") as handle:
            raw = handle.read(32 * 1024 * 1024 + 1)
        if len(raw) > 32 * 1024 * 1024:
            raise ValueError("guidance bound")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("guidance shape")
        json.dumps(value, allow_nan=False)
        return value
    except FileNotFoundError:
        return {}


def _artifact():
    """The native writer's whole generation, including current source custody."""
    with learning_store.guidance_fence():
        source = learning_store.guidance_source()
        if source["mode"] == "world":
            saved = learning_store.export_guidance_snapshot()
            raw = {row[0]: row[1] for row in saved["addenda"]}
            meta = {row[0]: json.loads(row[1]) for row in saved["line_meta"]}
        else:
            path = self_harness._store_path()
            raw = _strict_object(path)
            meta = _strict_object(self_harness._meta_path(path))
        if any(not isinstance(value, str) for value in raw.values()) or any(not isinstance(value, dict) for value in meta.values()):
            raise HTTPException(409, "Current learned instructions cannot be checked safely. Review and restore a verified learning copy before continuing.")
        return _artifact_identity(source, raw, meta)


def _artifact_identity(source, raw, meta):
    # Runtime recall/outcome counters are intentionally live. Publication
    # identity, trial state, provenance and current source access are pinned.
    incidental = {"recall_notes", "last_recalled_at", "recent_outcomes", "recall_success", "recall_failure"}
    stable_meta = {key: {name: value for name, value in row.items() if name not in incidental} for key, row in meta.items()}
    permissions = [[key, line, self_harness._shared_line_current(key, line, meta)]
                   for key, block in raw.items() for line in self_harness._bullets(block)]
    return digest([source, raw, stable_meta, permissions])


def _state(request, *, context=None, write=False):
    current = questions._authority(request, context, write=write)
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "The current learning settings cannot be read. No pass was started.")
    settings = self_harness.settings()
    if not self_harness.enabled() or settings.get("_config_valid") is not True:
        raise HTTPException(409, "Self-coaching is off or its settings need attention. Open Learning systems before continuing.")
    from maverick.llm import model_for_role, require_model_allowed
    models = runner.harness_fleet_models()
    main = model_for_role("orchestrator")
    if not models or main not in models or len(models) > 20:
        raise HTTPException(409, "The models currently in use cannot be completely reviewed. Check the model settings before continuing.")
    for model in models:
        require_model_allowed(model)
    path = str(settings.get("eval_corpus") or "")
    corpus = {}
    if path:
        with evaluation._corpus_lock, cross_process_lock(Path(path)), evaluation._corpus_rmw_lock(Path(path)):
            corpus = evaluation._authoring_raw(path)
    normalized = runner._normalize_eval_manifest(corpus)
    # Native mining accepts only explicitly shared, currently permitted sources.
    shared, source_path = _recent(models)
    caps = resolve_budget_caps(task_class="self_harness")
    limits = [v for v in (caps.get("max_dollars"), settings.get("eval_budget_dollars")) if v is not None]
    if any(type(v) not in {int, float} or not math.isfinite(v) or v < 0 for v in limits):
        raise HTTPException(409, "The learning spending limit needs attention in All settings.")
    cfg = config.load_config()
    source_revision = digest([current, cfg, models, main, corpus, normalized, shared, caps,
                       source_path,
                       questions._scope(request)["source"] if path else "no-questions"])
    try:
        artifact = _artifact()
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(409, "Current learned instructions cannot be checked safely. Review and restore a verified learning copy before continuing.") from exc
    revision = digest([source_revision, artifact])
    questions._authority(request, current)
    return {"context": current, "revision": revision, "source_revision": source_revision, "artifact": artifact, "models": models, "main": main, "rows": shared,
            "corpus": corpus, "counts": {m: sum(self_harness._is_minable(row, model_id=m) for row in shared) for m in models},
            "questions": {m: len(evaluation.corpus_cases(normalized, m)) for m in models},
            "ceiling": min(limits) if limits else None, "egress": runner._learning_provider_egress_enabled(),
            "checker": model_for_role("verifier"), "careful": bool(settings.get("risk_limited"))}


def catalog(request):
    state = _state(request)
    rows = [row for row in _requests().list(limit=10001)
            if row.get("purpose", "learning_pass") == "learning_pass" and row["actor"] == native._actor(request) and row["context"] == state["context"] and row["workspace"] == native._workspace()]
    questions._authority(request, state["context"])
    return {"context": state["context"], "revision": state["revision"], "notice": NOTICE,
            "models": [{"value": m, "label": model_label(m)} for m in state["models"]],
            "requests": [{"value": row["id"][4:], "label": "Learning pass / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))}
                         for row in sorted(rows, key=lambda row: row["created_at"], reverse=True)[:20]]}


def prepare(request, values, *, context=None, revision=None):
    body = Choices.model_validate(values)
    body.instructions = loop._instructions(body.instructions) or ""
    state = _state(request, context=context, write=True)
    if revision is not None and revision != state["revision"]:
        raise HTTPException(409, "The work, questions, models or settings changed. Refresh and review again; nothing was started.")
    selected = state["models"] if body.scope == "all" else [state["main"] if body.scope == "main" else body.model_id]
    if not selected or any(model not in state["models"] for model in selected):
        raise HTTPException(409, "Choose a model currently in use before reviewing.")
    if state["careful"] and state["egress"] and any(state["questions"][m] for m in selected) and not body.instructions:
        raise HTTPException(409, "Careful testing needs the current standing instructions. Enter them or review a recorded copy first.")
    return {"context": state["context"], "revision": state["revision"], "source_revision": state["source_revision"], "artifact": state["artifact"], "body": body.model_dump(),
            "models": selected, "summary": [{"Model": model_label(m), "Shareable recent mistakes": state["counts"][m],
                                             "Currently usable named questions": state["questions"][m]} for m in selected],
            "ceiling": state["ceiling"], "egress": state["egress"], "checker": model_label(state["checker"])}


def review_rows(prepared):
    body = prepared["body"]
    return [{"label": "What can change", "after": NOTICE},
            {"label": "Included models and source", "after": prepared["summary"]},
            {"label": "Testing", "after": "AI testing is permitted; answers are checked by " + prepared["checker"] if prepared["egress"] else
             "AI testing is off. The pass can inspect work, review recorded trial outcomes and retire old lessons. It will make no AI testing calls; current learning approval rules still apply."},
            {"label": "Spending", "after": f"One shared per-pass ceiling: ${prepared['ceiling']:g}. Current provider and organization limits also apply." if prepared["ceiling"] is not None else
             "No per-pass dollar ceiling is set. Current provider and organization limits apply; set a ceiling in All settings if needed."},
            {"label": "New lessons", "after": "Put on trial first; stronger current safety settings still apply." if body["trial"] else "Use current learning approval and trial settings."},
            {"label": "Old lessons", "after": "Review and retire lessons not confirmed lately, using the current retirement settings." if body["retire"] else "Do not run stale-lesson retirement."},
            {"label": "Standing instructions supplied for this test", "after": body["instructions"] or "None supplied. No verified production instruction snapshot is claimed."}]


def owned(request, operation, prepared=None, *, purpose="learning_pass"):
    context = questions._authority(request)
    questions._request_id(operation)
    row = _requests().get("LPR-" + operation)
    if row and row.get("purpose", "learning_pass") != purpose:
        raise HTTPException(404, "This original request belongs to a different learning operation.")
    if row and (row["actor"], row["context"], row["workspace"]) != (native._actor(request), context, native._workspace()):
        raise HTTPException(404, "This original learning pass is unavailable to your account and workspace.")
    if row and prepared is not None and row["binding"] != digest([operation, native._actor(request), prepared]):
        raise HTTPException(409, "This original request belongs to another reviewed pass.")
    questions._authority(request, context)
    return row


def original(request, operation, prepared=None, *, purpose="learning_pass", notice=NOTICE):
    row = owned(request, operation, prepared, purpose=purpose)
    result = {"context": questions._authority(request), "operation": operation, "recorded": bool(row), "confirmed": False,
              "message": "Whether the original pass started is unconfirmed. Nothing was repeated; a missing task does not prove failure.", "notice": notice}
    if row and row.get("job_id"):
        job = jobs.get(row["job_id"])
        if job and (job.kind, job.started_by, job.workspace) == ("self_harness_run", row["actor"], row["workspace"]):
            view = jobs.current_view(job)
            result.update(confirmed=bool(view["observation_saved"]), job={k: view[k] for k in ("state", "worker_available", "problem", "result_retained")},
                          task_href="/learned?learning_task=" + job.id + "#learning-job-history")
            result["message"] = ("The original learning task is recorded. Read its current progress and stop controls below; no new pass was started." if view["observation_saved"] else
                                 "The original task is known, but its latest progress is not confirmed as saved. No pass was repeated.")
            if view["result_retained"] and view["observation_saved"] and isinstance(view["result"], dict):
                # Historical aggregate evidence stays readable after withdrawal;
                # learned/source text belongs to current authorized native views.
                result["result"] = view["result"]
        else:
            result["message"] = "The original admission is retained, but its detailed task observation is unavailable. No pass was repeated. A new pass needs a separate current review."
    questions._authority(request, result["context"])
    return result


def _cooperative_stop(job, exc):
    from maverick.budget import BudgetExceeded
    from maverick.learning_guard import Halted

    return job.cancelled and isinstance(exc, (Halted, BudgetExceeded))


def _pass_result(reports, budget, stopped_early):
    return {"reports": reports, "spent": round(float(budget.dollars), 6), "stopped_early": stopped_early,
            "meaning": "Work completed before the stop may have been kept; an unfinished model has no complete report." if stopped_early else
                       "Recorded native learning checks; no customer-performance claim."}


def _deadline(expires):
    if type(expires) not in {int, float} or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
        raise HTTPException(409, "This review expired. Review current work again; no new pass was admitted.")


def _retirement_write_guard_factory(guard, expected_artifact):
    def reviewed_stages(after, before_meta, after_meta):
        # Only native planned states are eligible inside the still-held fences.
        # A partial write never advances the accepted pass generation.
        guard()
        source = learning_store.guidance_source()
        allowed = {expected_artifact[0],
                   _artifact_identity(source, after, before_meta),
                   _artifact_identity(source, after, after_meta)}
        return lambda: guard(allowed_artifacts=allowed)
    return reviewed_stages


def _check_current_budget(budget):
    if budget is not None:
        budget.check()


def _model_report(model, report, retired):
    result = {"Model": model_label(model), "Repeated mistakes": report.mined,
              "Lessons tried": report.proposed, "Passed testing": report.validated,
              "Adopted": report.promoted, "Retired": retired,
              "Trial lessons accepted": len(report.graduated),
              "Trial lessons removed": len(report.demoted),
              "Lessons returned to trial": len(report.relapsed),
              "Approval gate off": not report.gate_enabled,
              "Paused for calibration": report.frozen,
              "Checks not completed": len(report.skipped)}
    if report.qualification_held:
        result.update({"AI checks": "Held; testing prerequisites are incomplete.",
                       "Trial lesson decisions": "Held. Trial acceptance and failure checks were not run."})
    return result


def _review_guard(request, prepared, expires, check_current):
    def current_review():
        questions._authority(request, prepared["context"], write=True)
        _deadline(expires)
        current = _state(request, context=prepared["context"], write=True)
        if current["revision"] != prepared["revision"]:
            raise HTTPException(409, "The reviewed work, questions, models or settings changed. No pass was started.")
        if check_current is not None:
            check_current()
        questions._authority(request, prepared["context"], write=True)
        _deadline(expires)
        return current
    return current_review


def _reviewed_work(prepared, operation, job, budget, guard, effect_scope, state, run_work):
    if run_work is not None:
        return run_work(job, budget, guard, effect_scope, state)
    reports, stopped_early = [], False
    try:
        for model in prepared["models"]:
            guard()
            report, retired = runner.run_self_harness_cycle(state["rows"], model_id=model, retire=prepared["body"]["retire"],
                canary=True if prepared["body"]["trial"] else None, evaluation_system=prepared["body"]["instructions"] or None,
                evaluation_budget=budget, evaluation_corpus_manifest=state["corpus"], dispatch_guard=guard, effect_scope=effect_scope,
                work_item_id="learning-pass:" + operation, raise_errors=True)
            guard()
            reports.append(_model_report(model, report, retired))
    except Exception as exc:
        if not _cooperative_stop(job, exc):
            raise
        stopped_early = True
    return _pass_result(reports, budget, stopped_early)


def _purpose_metadata(purpose, prepared, operation):
    if purpose == "question_quality":
        return {"quality_sources": prepared["quality_sources"]}
    if purpose == "checker_calibration":
        return {"checker_sources": prepared["checker_sources"],
                "checker_action": prepared["body"]["action"],
                "checker_measurements_operation": operation if prepared["body"]["action"] == "judge" else prepared["sample_operation"]}
    return {}


def start(request, prepared, operation, *, expires, run_work=None, check_current=None,
          purpose="learning_pass", notice=NOTICE):
    questions._request_id(operation)
    if purpose not in {"learning_pass", "lesson_transfer", "checker_calibration", "question_quality"} or (purpose != "learning_pass") != (run_work is not None):
        raise ValueError("unsupported native learning operation")

    def read_original():
        return original(request, operation, prepared, purpose=purpose, notice=notice)

    current_review = _review_guard(request, prepared, expires, check_current)

    with authority_effect_fence():
        questions._authority(request, prepared["context"], write=True)
        if owned(request, operation, prepared, purpose=purpose):
            return read_original()
        state = current_review()
        native._record(request, "self_harness_run", phase="prepared", operation=operation, reviewed_revision=prepared["revision"], models=len(prepared["models"]))
        store, actor = _requests(), native._actor(request)
        try:
            record = {"id": "LPR-" + operation, "actor": actor, "context": prepared["context"], "workspace": native._workspace(),
                      "binding": digest([operation, actor, prepared]), "state": "admitting"}
            guarded = {}
            if run_work is not None:
                record["purpose"] = purpose
                guarded["effect_guard"] = current_review
                # Reference-only custody permits current source-right checks
                # on reassessment without storing private responses/labels.
                record.update(_purpose_metadata(purpose, prepared, operation))
            claim = store.create(record, action="learning.pass.prepare", actor=actor, max_records=10000, **guarded)
        except RecordConflict:
            return read_original()
        if claim.get("_audit_pending"):
            return read_original()

    budget_box = []

    def run(job):
        expected_artifact = [prepared["artifact"]]
        budget = None

        def guard(*, allowed_artifacts=()):
            questions._authority(request, prepared["context"], write=True)
            if job.cancelled:
                from maverick.learning_guard import Halted
                raise Halted("self-harness", "dashboard-stop")
            current = _state(request, context=prepared["context"])
            if current["source_revision"] != prepared["source_revision"] or current["artifact"] not in {expected_artifact[0], *allowed_artifacts}:
                raise HTTPException(409, "The reviewed sources, models, settings or access changed. No further call or learning change was admitted.")
            if check_current is not None:
                check_current()
            _check_current_budget(budget)

        @contextmanager
        def admission_scope():
            with authority_effect_fence():
                guard()
                yield

        @contextmanager
        def effect_scope():
            with authority_effect_fence(), learning_store.guidance_fence():
                guard()

                def advance():
                    # Called only after a successful native mutation/readback,
                    # while the same writer locks still exclude other writers.
                    expected_artifact[0] = _artifact()

                advance.retirement_guard = _retirement_write_guard_factory(guard, expected_artifact)
                advance.lifecycle_guard = _retirement_write_guard_factory(guard, expected_artifact)
                yield advance

        with admission_scope():
            accepted = store.update(claim["id"], lambda row: row.update(job_id=job.id, state="admitted"), expected_revision=claim["revision"],
                                    action="learning.pass.admitted", actor=actor, **guarded)
            if not accepted or accepted.get("_audit_pending"):
                raise HTTPException(503, "The original task could not be recorded. No AI call was made.")
            _deadline(expires)
        budget = native._budget("self_harness")
        if prepared["ceiling"] is not None:
            budget.max_dollars = min(budget.max_dollars, prepared["ceiling"]) if budget.max_dollars is not None else prepared["ceiling"]
        budget_box.append(budget)
        # Only local snapshot preparation holds the authority fence. The native
        # scope then retains that safety boundary without locking network work.
        with admission_scope():
            scope = dreaming.learning_mutation_scope()
            scope.__enter__()
        try:
            with admission_scope():
                _deadline(expires)
            return _reviewed_work(prepared, operation, job, budget, guard, effect_scope, state, run_work)
        finally:
            scope.__exit__(None, None, None)

    def cancel():
        if budget_box:
            jobs.stop_budget(budget_box[0])()

    try:
        label = {"lesson_transfer": "Reviewed lesson transfer", "checker_calibration": "Reviewed answer check", "question_quality": "Reviewed question check"}.get(purpose, "Reviewed learning pass")
        native.start_job(request, "self_harness_run", label, run,
                         cancellable=True, on_cancel=cancel)
    except Exception:  # noqa: BLE001 -- a lost admission must never replay work
        return read_original()
    return read_original()
