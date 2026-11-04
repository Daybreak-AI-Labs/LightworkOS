"""Reviewed paired intake checks and one exact native factory adoption.

Uses the existing encrypted task observations and governed promotion journal.
No generated specialist is saved, provisioned or run by a comparison.
"""
from __future__ import annotations

import copy
import json
import math
import re
import secrets
import time
from dataclasses import asdict

from fastapi import HTTPException
from maverick import config, crypto_at_rest, domain, intake
from maverick import factory_learning as factory
from maverick.authority_effects import authority_effect_fence
from maverick.file_lock import cross_process_lock
from maverick.governed_operations import digest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import auth
from . import learning_jobs as jobs
from .draft_api import context_for
from .plain_labels import CAPABILITY_LABELS, capability_label, model_label

PAGE = "/learning#lo-factory"
TTL = 600
KINDS = {"compare": "factory_guidance_check", "adopt": "factory_guidance_adopt", "restore": "factory_guidance_restore"}
RESTORE_NOTICE = "Restores earlier guidance for future agent building only. It does not change saved or running agents, grant actions or call an AI service. Later guidance is never overwritten. A separate review is required before any restoration or receipt completion."
NOTICE = ("This compares unsaved agent setups built with current guidance and with one selected addition. "
          "The local check only asks whether the expected tool remains allowed after normal safety checks. "
          "The recurring problem and expected tool are reported premises, not independently verified business facts. "
          "This does not establish overall answer quality, causal business improvement or working connected actions. "
          "It never saves, provisions or runs an agent. Adoption separately changes guidance used to build future agents.")


class CompareIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    min_support: int = Field(default=3, ge=2, le=1000)
    correction: str = Field(min_length=1, max_length=256)
    packs: list[str] = Field(min_length=2, max_length=64)
    dollars: float = Field(ge=0, le=5)
    seconds: int = Field(ge=15, le=300)
    authorize_input_use: bool


class AdoptIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")


def authority(request, context=None, *, write=False, restoring=False):
    from . import learning_ops_api as native
    auth.require_global_permission(request, "admin")
    auth.require_page_permission(request, "/learning")
    auth.require_permission(request, "operate")
    current = context_for(request)
    if context is not None and context != current:
        raise HTTPException(409, "Your account or workspace changed. Refresh the comparison; entered work is kept.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
        if not restoring:
            native._factory_on()
            native._halt_preflight("factory-learning")
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current learning settings are unavailable. No new check or adoption was admitted.")
    return current


def _connection():
    from maverick.llm import LLM, _parse_spec, model_for_role
    model = model_for_role("orchestrator")
    provider, _ = _parse_spec(model)
    client = LLM(model)
    return {"model": str(model), "connection": client._provider_client_config(provider).fingerprint,
            "settings": digest(config.load_config())}


def _outcomes():
    # Strict current reads refuse damaged records; a skipped row is not complete evidence.
    rows = factory.load_outcomes(strict=True)
    if len(rows) > 56250:
        raise HTTPException(409, "There is too much retained setup history for one complete review. No history was shortened.")
    return rows, digest([str(factory.outcomes_path().resolve()), [asdict(row) for row in rows]])


def _artifact():
    path = factory.corrections_path()
    with cross_process_lock(path, strict=True):
        state = factory._load_correction_artifact(path, strict=True)
    return factory._artifact_revision(path, state).sha256, state


def _pack(request, name, profiles):
    from maverick import domain_edit
    profile = profiles.get(name)
    if profile is None:
        raise HTTPException(409, "A selected agent's current setup is unavailable. Refresh the source choices.")
    allowed = auth.caller_suites(request)
    if allowed is not None and not domain.suites_for_domain(name, profile) <= allowed:
        raise HTTPException(403, "Your current access does not include a selected agent's department.")
    value = asdict(profile)
    goals = [profile.output.deliverable] if profile.output.deliverable else []
    if len(profile.description) > 1000 or any(len(goal) > 300 for goal in goals):
        raise HTTPException(409, "A selected request exceeds this comparison's complete input limit. Its text was not shortened.")
    generation = domain_edit._override_generation(name, domain.user_dir() / (name + ".toml"))
    return {"name": name, "description": profile.description, "goals": goals, "source": digest([value, generation])}


def _guidance(state, scope):
    items = [factory._entry_correction(row) for row in state.entries.values()]
    items = [item for item in items if item is not None and (item.scope == "*" or item.scope == scope)]
    items.sort(key=lambda item: -item.support)
    if not items:
        return ""
    return "\nLearned from packs this factory has already produced (apply when relevant):\n" + "\n".join("- " + item.guidance for item in items[:factory._MAX_GUIDANCE_ITEMS])


def catalog(request, min_support=3):
    context = authority(request)
    with auth.fresh_configuration():
        rows, source = _outcomes()
        corrections = factory.mine_corrections(rows, min_support=min_support)
        if len(corrections) > 1000:
            raise HTTPException(409, "The complete suggestion list exceeds this form's limit. Nothing was hidden or adopted.")
        artifact, state = _artifact()
        connection = _connection()
        suggestions = []
        for item in corrections:
            packs = sorted({row.pack for row in rows if (row.suite or "*", row.signal, row.detail) == (item.scope, item.signal, item.detail)})
            ready = item.signal == factory.SIGNAL_TOOL_MISSING and item.key() not in state.entries
            suggestions.append({**asdict(item), "key": item.key(), "packs": packs, "supported": ready,
                "why": "Already adopted" if item.key() in state.entries else "This check supports missing-tool suggestions only." if not ready else ""})
        revision = digest([context, source, artifact, connection, min_support, suggestions])
        authority(request, context)
        return {"context": context, "revision": revision, "corrections": suggestions, "requests": history(request)["requests"],
                "model": model_label(connection["model"]), "notice": NOTICE, "enabled": factory.enabled()}


def history(request):
    """Recent original choices need no current AI connection or source body."""
    from . import learning_ops_api as native
    context = authority(request)
    rows = [{"value": job.result["operation"], "label": {"factory_guidance_check": "Agent-building comparison", "factory_guidance_adopt": "Agent-building adoption", "factory_guidance_restore": "Earlier guidance restoration"}[job.kind] + " / " + time.strftime("%b %d, %H:%M", time.localtime(job.started_at))}
            for job in jobs.listed() if job.kind in KINDS.values() and job.started_by == native._actor(request)
            and job.workspace == native._workspace() and isinstance(job.result, dict) and job.result.get("operation")]
    authority(request, context)
    return {"context": context, "requests": rows}


def prepare_compare(request, values):
    body = CompareIn.model_validate(values)
    authority(request, body.context, write=True)
    if not body.authorize_input_use or len(set(body.packs)) != len(body.packs) or not math.isfinite(body.dollars):
        raise HTTPException(422, "Choose each request once and explicitly allow its complete description to be sent for this comparison.")
    state = catalog(request, body.min_support)
    if (state["context"], state["revision"]) != (body.context, body.revision):
        raise HTTPException(409, "The current suggestions, account, guidance or AI connection changed. Refresh and review again.")
    correction = next((row for row in state["corrections"] if row["key"] == body.correction), None)
    if correction is None or not correction["supported"] or not set(body.packs) <= set(correction["packs"]):
        raise HTTPException(409, "Choose a current supported suggestion and its named reported requests.")
    from maverick.tools import base_tool_names
    tools = base_tool_names(configured_optional=True, include_plugins=False)
    if tools is None or correction["detail"] not in tools:
        raise HTTPException(409, "The expected tool is not available in the native tool catalog. This suggestion cannot be qualified here.")
    profiles = domain.available_domains()
    cases = [_pack(request, name, profiles) for name in body.packs]
    artifact, artifact_state = _artifact()
    connection = _connection()
    # A suite correction must include existing suite guidance, not just global guidance.
    scope = None if correction["scope"] == "*" else correction["scope"]
    guidance = _guidance(artifact_state, scope)
    baseline = intake._PROPOSER_SYSTEM + ("\n" + guidance if guidance else "")
    candidate = baseline + "\nAdditional reviewed guidance:\n- " + correction["guidance"]
    prepared = {"action": "compare", "body": body.model_dump(), "correction": correction, "cases": cases,
                "artifact": artifact, "connection": connection, "baseline": baseline, "candidate": candidate,
                "source": _outcomes()[1], "current_guidance": guidance or "No previously adopted guidance for this area."}
    _bounded(prepared)
    _guard(request, prepared, float("inf"))
    return prepared


def _bounded(value):
    if len(json.dumps(value, allow_nan=False).encode("utf-8")) > 100000:
        raise HTTPException(422, "This complete comparison exceeds the retained result limit. Nothing was shortened or admitted.")


def _guard(request, prepared, expires, budget=None, *, adopted=False):
    if time.time() >= expires:
        raise HTTPException(409, "This review expired before the next protected step. Read its original result; do not repeat it automatically.")
    with auth.fresh_configuration():
        body = prepared["body"]
        authority(request, body["context"], write=True)
        if _connection() != prepared["connection"]:
            raise HTTPException(409, "The AI connection or current settings changed. Read the original comparison before another review.")
        rows, source = _outcomes()
        if source != prepared["source"]:
            raise HTTPException(409, "The retained setup history changed. Prepare a separate current comparison review.")
        corrections = factory.mine_corrections(rows, min_support=body["min_support"])
        current = next((row for row in corrections if row.key() == body["correction"]), None)
        if current is None or asdict(current) != {key: prepared["correction"][key] for key in asdict(current)}:
            raise HTTPException(409, "The selected reported problem changed. No further generation or adoption was admitted.")
        profiles = domain.available_domains()
        if [_pack(request, row["name"], profiles) for row in prepared["cases"]] != prepared["cases"]:
            raise HTTPException(409, "A selected agent's source or permission changed. No further generation or adoption was admitted.")
        if not adopted and _artifact()[0] != prepared["artifact"]:
            raise HTTPException(409, "The factory guidance changed. Read the original result and prepare a separate current review.")
        if budget is not None:
            budget.check()
        if time.time() >= expires:
            raise HTTPException(409, "This review expired while checking current sources. No further protected step was admitted.")
        authority(request, body["context"], write=True)
        return source


def review_rows(prepared):
    rows = [{"label": "Meaning and limits", "after": NOTICE},
            {"label": "Guidance used today", "after": prepared.get("current_guidance", "The current saved guidance remains in both comparisons.")},
            {"label": "Selected additional guidance", "after": prepared["correction"]["guidance"]},
            {"label": "Expected result (reported)", "after": "The generated setup allows this action: " + _action_name(prepared["correction"]["detail"]) + ". The usual safety checks still apply."},
            {"label": "AI service", "after": model_label(prepared["connection"]["model"])},
            {"label": "Spending and time limits", "after": "$" + str(prepared["body"]["dollars"]) + "; " + str(prepared["body"]["seconds"]) + " seconds, or tighter current organization limits."}]
    for index, case in enumerate(prepared["cases"], 1):
        rows.append({"label": "Request " + str(index) + ": " + case["name"],
                     "after": case["description"] + ("\nGoals:\n" + "\n".join(case["goals"]) if case["goals"] else "\nNo additional goals.")})
    if prepared["action"] == "adopt":
        rows.extend(prepared["comparison_rows"])
        rows.append({"label": "What adopting changes", "after": "Adds this one piece of guidance for future agent building. It grants no actions and changes no saved or running agent. Existing approval and safety requirements still apply."})
    else:
        rows.append({"label": "Work admitted", "after": str(len(prepared["cases"]) * 2) + " AI generations. Generated setups are checked locally and never activated. A stopped or incomplete comparison cannot qualify adoption."})
    return rows


def review(request, action, values):
    authority(request)
    try:
        if action == "compare":
            CompareIn.model_validate(values)
        elif action == "adopt":
            operation = AdoptIn.model_validate(values).operation
        elif action == "restore":
            RestoreIn.model_validate(values)
        else:
            raise HTTPException(422, "Choose a supported guidance decision.")
    except ValidationError as exc:
        raise HTTPException(422, "Check the guidance decision details and try again.") from exc
    if action == "compare":
        prepared = prepare_compare(request, values)
    elif action == "adopt":
        prepared = prepare_adopt(request, operation)
    else:
        prepared = prepare_restore(request, values)
    expires = time.time() + TTL
    from . import learning_ops_api as native
    operation = secrets.token_hex(16)
    envelope = {"purpose": "factory-guidance-v1", "operation": operation, "actor": native._actor(request),
                "workspace": native._workspace(), "expires": expires, "prepared": prepared}
    token = crypto_at_rest.seal_to_str(json.dumps(envelope, allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "The complete private review could not be protected. Nothing was admitted.")
    return {"token": token, "operation": operation, "expires": expires, "action": action,
            "context": prepared["body"]["context"], "changes": restore_rows(prepared) if action == "restore" else review_rows(prepared),
            "notice": RESTORE_NOTICE if action == "restore" else NOTICE}


def _open(request, token):
    from . import learning_ops_api as native
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        envelope = json.loads(crypto_at_rest.unseal_from_str(token))
        if set(envelope) != {"purpose", "operation", "actor", "workspace", "expires", "prepared"} or envelope["purpose"] != "factory-guidance-v1":
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This protected review is unavailable. Read its original result before a new decision.") from exc
    authority(request, envelope["prepared"]["body"]["context"], write=True, restoring=envelope["prepared"]["action"] == "restore")
    if (envelope["actor"], envelope["workspace"]) != (native._actor(request), native._workspace()):
        raise HTTPException(404, "This review is unavailable to the current account.")
    return envelope


def _job(request, operation):
    from . import learning_ops_api as native
    authority(request)
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "This original request is unavailable.")
    job = jobs.get(operation[:16])
    if job is not None and (job.kind not in KINDS.values() or job.started_by != native._actor(request)
            or job.workspace != native._workspace() or not isinstance(job.result, dict) or job.result.get("operation") != operation):
        raise HTTPException(404, "This original request is unavailable to the current account.")
    return job


def original(request, operation):
    context = authority(request)
    job = _job(request, operation)
    if job is None:
        restored = _restore_receipt(request, operation)
        if restored is not None:
            authority(request, context)
            return {"operation": operation, "confirmed": True, "state": "done", "source_visible": False,
                    "result": restored, "message": "The original restoration receipt is confirmed. Its complete review is no longer in recent task history. Nothing was repeated."}
        historical = _adoption_receipt(request, operation)
        if historical is not None:
            authority(request, context)
            return {"operation": operation, "confirmed": historical.state in {"committed", "aborted"},
                    "state": historical.state, "source_visible": False,
                    "result": {"adopted": historical.state == "committed"},
                    "message": "The original adoption decision is retained. Its complete comparison is no longer in recent task history. Nothing was repeated." if historical.state in {"committed", "aborted"} else "The original adoption remains unconfirmed. Nothing was repeated."}
        return {"operation": operation, "confirmed": False, "message": "The original task is not currently retained. This does not mean it failed. Nothing was repeated."}
    view = jobs.current_view(job)
    if job.kind == KINDS["restore"]:
        return _restore_original(request, operation, view)
    result = copy.deepcopy(view.get("result") or {})
    complete = job._durable and view["result_retained"] and result.get("complete") is True and job.state == "done"
    if job.kind == KINDS["compare"]:
        complete = job._durable and view["observation_saved"] and view["result_retained"] and job.state in {"done", "failed", "stopped", "not_started"}
    if job.kind == KINDS["adopt"]:
        tx = _adoption_receipt(request, operation)
        if tx is not None:
            result["adopted"] = tx.state == "committed"
            complete = tx.state in {"committed", "aborted"}
    prepared = result.get("prepared")
    # Source withdrawal never grants access to retained private request bodies.
    private = False
    if prepared:
        try:
            _guard(request, prepared, float("inf"), adopted=job.kind == KINDS["adopt"])
            private = True
        except HTTPException as exc:
            if exc.status_code in {401, 403}:
                authority(request, context)
        except (OSError, ValueError, RuntimeError):
            # Missing/damaged current sources cannot reveal an old private body.
            # The retained decision metadata remains usable under current access.
            private = False
    safe = {key: result[key] for key in ("baseline_score", "candidate_score", "samples", "effect_ci_low", "adopted", "gate_reasons", "complete") if key in result}
    if private:
        safe.update({key: result[key] for key in ("pairs", "guidance", "prepared") if key in result})
        if "pairs" in result:
            safe["comparison_rows"] = _comparison_rows(result["pairs"])
    authority(request, context)
    return {"operation": operation, "confirmed": complete, "state": job.state,
            "message": "The original result is confirmed; no work was repeated." if complete else "The original start or completion is unconfirmed. Read saved progress; do not start it again automatically.",
            "job": {key: view[key] for key in ("state", "can_stop", "problem", "worker_available", "observation_saved", "retention_problem")},
            "result": safe, "source_visible": private,
            "task_href": "/learned?learning_task=" + job.id + "#learning-job-history"}


def _adoption_receipt(request, operation):
    from maverick import self_improvement as si

    from . import learning_ops_api as native
    tx = si.shared().ledger.transaction("factory:" + operation)
    if tx is not None and (tx.record.provenance.get("factory_actor"), tx.record.provenance.get("factory_workspace"), tx.record.provenance.get("factory_operation")) != (native._actor(request), native._workspace(), operation):
        raise HTTPException(404, "This original adoption receipt is unavailable to the current account.")
    return tx



class RestoreIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    adoption: str = Field(pattern=r"^[a-f0-9]{32}$")


def _restore_plan(request, adoption=None):
    from . import learning_ops_api as native
    return factory.restoration_plan(actor=native._actor(request), workspace=native._workspace(), adoption=adoption)


def restore_options(request):
    context = authority(request)
    try:
        plan = _restore_plan(request)
        choices = [{"value": plan["adoption"], "label": "Your most recent guidance change / " + time.strftime("%b %d, %H:%M", time.localtime(plan["adopted_at"]))}]
        notice = RESTORE_NOTICE
    except (OSError, RuntimeError, ValueError) as exc:
        choices = []
        notice = "Current guidance history could not be read. Nothing was restored." if isinstance(exc, OSError) else str(exc)
    authority(request, context)
    return {"context": context, "choices": choices, "notice": notice, "requests": history(request)["requests"]}


def prepare_restore(request, values):
    body = RestoreIn.model_validate(values)
    context = authority(request, write=True, restoring=True)
    try:
        plan = _restore_plan(request, body.adoption)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(409, "Current guidance could not be verified. Nothing was restored." if isinstance(exc, OSError) else str(exc)) from exc
    prepared = {"action": "restore", "body": {"context": context, "dollars": 0, "seconds": 15}, "plan": plan}
    _bounded(prepared)
    _restore_guard(request, prepared, float("inf"))
    return prepared


def _restore_guard(request, prepared, expires, budget=None):
    with auth.fresh_configuration():
        authority(request, prepared["body"]["context"], write=True, restoring=True)
        if budget is not None:
            budget.check()
        if time.time() >= expires:
            raise HTTPException(409, "This restoration review expired. Read the original before a separate current review.")


def _guidance_text(values):
    text = "\n\n".join(values) or "No adopted agent-building guidance."
    return re.sub(r"(['`])([A-Za-z0-9_.:-]{1,256})\1", lambda match: _action_name(match.group(2)), text).replace("packs ", "agents ")


def restore_rows(prepared):
    plan = prepared["plan"]
    return [{"label": "Meaning and limits", "after": RESTORE_NOTICE},
            {"label": "Complete agent-building guidance", "before": _guidance_text(plan["current"]), "after": _guidance_text(plan["earlier"])},
            {"label": "What this decision does", "after": "Restores the exact earlier guidance and records this separate decision." if plan["mode"] == "restore" else "The earlier guidance is already present. This records a separately reviewed restoration receipt without rewriting guidance. It does not confirm any earlier uncertain attempt."},
            {"label": "Limits", "after": "No AI calls or spending. Up to 15 seconds of local verification and recording."},
            {"label": "Future work", "after": "Future agent building uses the earlier guidance when relevant. Existing saved and running agents keep their own setup, approval and safety requirements."},
            {"label": "Changes during the wait", "after": "Current account, workspace and administrator authority are checked again at the protected write. Any later guidance change refuses this restoration."},
            {"label": "Interrupted reply", "after": "Read this exact original decision. It is never repeated automatically. If guidance was restored but its receipt is missing, a new explicit review can complete the receipt without rewriting guidance."}]


def _restore_receipt(request, operation):
    from . import learning_ops_api as native
    try:
        return factory.restoration_receipt(actor=native._actor(request), workspace=native._workspace(), operation=operation)
    except PermissionError as exc:
        raise HTTPException(404, "This original restoration is unavailable to the current account.") from exc


def _restore_original(request, operation, view):
    context = authority(request)
    receipt = _restore_receipt(request, operation)
    prepared = (view.get("result") or {}).get("prepared")
    safe = dict(receipt or {})
    private = False
    if prepared:
        try:
            _restore_guard(request, prepared, float("inf"))
            path = factory.corrections_path()
            _, state = _artifact()
            current = factory._artifact_revision(path, state).to_dict()
            private = current in [prepared["plan"]["artifact"], prepared["plan"]["before"]]
            if private:
                safe["restoration_rows"] = restore_rows(prepared)
        except (HTTPException, OSError, RuntimeError, ValueError):
            private = False
    authority(request, context)
    return {"operation": operation, "confirmed": receipt is not None and receipt["complete"], "state": view["state"],
            "message": ("The separate restoration receipt is confirmed. Earlier guidance was already present; nothing was rewritten and no earlier uncertain attempt was confirmed."
                        if receipt and receipt["mode"] == "acknowledge" else
                        "Earlier guidance restored; the original receipt is confirmed. Nothing was repeated." if receipt else
                        "This restoration remains unconfirmed. Earlier guidance may already be present; read the original before a separately reviewed receipt completion. Nothing was repeated."),
            "result": safe, "source_visible": private,
            "job": {key: view[key] for key in ("state", "can_stop", "problem", "worker_available", "observation_saved", "retention_problem")},
            "task_href": "/learned?learning_task=" + operation[:16] + "#learning-job-history"}


def _run_restore(request, prepared, operation, expires, budget):
    from . import learning_ops_api as native
    with authority_effect_fence():
        _restore_guard(request, prepared, expires, budget)
        result = factory.restore_reviewed_correction(actor=native._actor(request), workspace=native._workspace(),
            adoption=prepared["plan"]["adoption"], operation=operation, expected_plan=prepared["plan"],
            effect_guard=lambda: _restore_guard(request, prepared, expires, budget))
        return {"operation": operation, "binding": digest(prepared), "original_until": expires, "prepared": prepared, **result}


def _proposal(client, prepared, case, system, budget, guard):
    errors = []
    spec = intake.IntakeSpec(case["name"], case["description"], goals=case["goals"])
    def dispatch():
        # The fence covers only this authority check, never the provider call.
        with authority_effect_fence():
            guard()

    def propose(_spec):
        try:
            dispatch()
            answer = client.complete(system=system, messages=[{"role": "user", "content": intake._intake_prompt(spec)}],
                                     budget=budget, max_tokens=1500, dispatch_guard=dispatch)
            parsed = intake._parse_proposal(answer.text)
            if not parsed:
                raise ValueError("The AI service did not return a usable agent setup. The safe fallback is not comparison evidence.")
            return parsed
        except Exception as exc:
            errors.append(exc)
            raise
    profile = intake.generate_profile(spec, propose=propose)
    if errors:
        raise errors[0]
    value = {"allowed_tools": profile.allow_tools, "denied_tools": profile.deny_tools, "maximum_risk": profile.max_risk}
    if len(json.dumps(value, allow_nan=False).encode()) > 2048:
        raise ValueError("The complete checked capabilities exceed this comparison's retained limit. Nothing was shortened.")
    value["passed"] = prepared["correction"]["detail"] in profile.allow_tools and prepared["correction"]["detail"] not in profile.deny_tools
    return value


def _comparison(request, prepared, operation, expires, job, budget):
    from maverick.llm import LLM
    def guard():
        return _guard(request, prepared, expires, budget)
    guard()
    client = LLM(prepared["connection"]["model"])
    pairs = []
    for index, case in enumerate(prepared["cases"]):
        if job.cancelled:
            raise HTTPException(409, "This comparison was stopped. A partial comparison cannot qualify adoption.")
        order = ("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")
        pair = {"request": case["name"]}
        for arm in order:
            pair[arm] = _proposal(client, prepared, case, prepared[arm], budget, guard)
        pairs.append(pair)
        _bounded({"prepared": prepared, "pairs": pairs, "operation": operation, "original_until": expires})
    guard()
    baseline = [float(row["baseline"]["passed"]) for row in pairs]
    candidate = [float(row["candidate"]["passed"]) for row in pairs]
    effect = factory._paired_effect_lcb(baseline, candidate)
    result = {"operation": operation, "binding": digest(prepared), "original_until": expires, "prepared": prepared, "complete": True,
            "guidance": prepared["correction"]["guidance"], "pairs": pairs, "samples": len(pairs),
            "baseline_score": sum(baseline) / len(pairs), "candidate_score": sum(candidate) / len(pairs), "effect_ci_low": effect}
    _bounded(result)
    return result


def prepare_adopt(request, operation):
    row = original(request, operation)
    if not row["confirmed"] or not row["source_visible"] or row.get("result", {}).get("complete") is not True or "pairs" not in row.get("result", {}):
        raise HTTPException(409, "Choose a complete retained native comparison with current source permission. An unavailable or supplied score cannot qualify adoption.")
    result = row["result"]
    prepared = copy.deepcopy(result["prepared"])
    authority(request, prepared["body"]["context"], write=True)
    _guard(request, prepared, float("inf"))
    prepared.update(action="adopt", comparison=operation, result={key: result[key] for key in ("baseline_score", "candidate_score", "samples", "effect_ci_low")},
                    comparison_rows=_comparison_rows(result["pairs"]))
    from maverick import self_improvement as si
    correction = factory.ProposerCorrection(**{key: prepared["correction"][key] for key in ("scope", "signal", "detail", "support", "guidance")})
    evidence = _evidence(prepared)
    artifact, state = _artifact()
    after = factory._next_artifact(state, correction, evidence)
    candidate = factory._factory_candidate(correction, evidence, before_revision=factory._artifact_revision(factory.corrections_path(), state),
                                          after_revision=factory._artifact_revision(factory.corrections_path(), after), si=si)
    verdict = si.shared().evaluate(candidate)
    if not verdict.promote:
        reasons = "; ".join(g.reason for g in verdict.gates if not g.ok)
        raise HTTPException(409, "The current adoption checks did not pass: " + reasons + ". The comparison remains saved; no guidance was adopted.")
    prepared["artifact"] = artifact
    _bounded(prepared)
    return prepared


def _action_name(name):
    from .permission_requests_api import action_label
    return capability_label(name) if name in CAPABILITY_LABELS else action_label("tool", name)


def _capability_text(value):
    return "Expected action: " + ("Allowed" if value["passed"] else "Not allowed") + "\nAllowed actions: " + ", ".join(_action_name(name) for name in value["allowed_tools"]) + "\nActions it cannot use: " + ", ".join(_action_name(name) for name in value["denied_tools"]) + "\nMaximum risk: " + str(value["maximum_risk"])


def _comparison_rows(pairs):
    return [{"label": "Request " + str(i + 1) + ": " + pair["request"].replace("_", " "),
             "before": _capability_text(pair["baseline"]), "after": _capability_text(pair["candidate"])} for i, pair in enumerate(pairs)]


def _evidence(prepared):
    value = prepared["result"]
    return factory.FactoryEvidenceResult(**value, evidence_sha256=digest([prepared["comparison"], value]), source_sha256=digest(prepared),
        provenance={"source": "Native paired intake capability checks; reported request/expected-tool premises; no business or general accuracy claim",
                    "dataset_sha256": digest(prepared["cases"]), "split_sha256": digest([row["name"] for row in prepared["cases"]]),
                    "evaluator_sha256": digest(["native-intake-allowed-tool-v1", prepared["correction"]["detail"]]),
                    "model_sha256": digest(prepared["connection"]), "prompt_sha256": digest([prepared["baseline"], prepared["candidate"]]),
                    "baseline_prompt_sha256": digest(prepared["baseline"]), "candidate_prompt_sha256": digest(prepared["candidate"])})


def apply(request, token, *, confirmed):
    if confirmed is not True:
        raise HTTPException(422, "Confirm the complete review before continuing.")
    envelope = _open(request, token)
    prepared, operation, expires = envelope["prepared"], envelope["operation"], envelope["expires"]
    existing = _job(request, operation)
    if (existing is not None or prepared["action"] == "adopt" and _adoption_receipt(request, operation) is not None
            or prepared["action"] == "restore" and _restore_receipt(request, operation) is not None):
        return original(request, operation)
    if time.time() >= expires:
        raise HTTPException(409, "This review expired. No new work was admitted; prepare a fresh review.")
    from . import learning_ops_api as native
    if prepared["action"] == "restore":
        from maverick.budget import Budget
        budget = Budget(max_dollars=0, max_wall_seconds=15, max_tool_calls=0)
    else:
        budget = native._budget("eval")
    budget.max_dollars = min(budget.max_dollars if budget.max_dollars is not None else math.inf, prepared["body"]["dollars"])
    budget.max_wall_seconds = min(budget.max_wall_seconds if budget.max_wall_seconds is not None else math.inf, prepared["body"]["seconds"])
    budget.max_tool_calls = 0
    with authority_effect_fence():
        if prepared["action"] == "restore":
            _restore_guard(request, prepared, expires, budget)
            if prepare_restore(request, {"adoption": prepared["plan"]["adoption"]}) != prepared:
                raise HTTPException(409, "The restoration changed. Review current guidance again.")
        else:
            _guard(request, prepared, expires, budget)
        if prepared["action"] == "adopt" and prepare_adopt(request, prepared["comparison"]) != prepared:
            raise HTTPException(409, "The exact comparison or adoption checks changed. Review it again.")
        def run(job):
            if prepared["action"] == "compare":
                return _comparison(request, prepared, operation, expires, job, budget)
            if prepared["action"] == "restore":
                return _run_restore(request, prepared, operation, expires, budget)
            with authority_effect_fence():
                _guard(request, prepared, expires, budget)
                correction = factory.ProposerCorrection(**{key: prepared["correction"][key] for key in ("scope", "signal", "detail", "support", "guidance")})
                value = factory.promote_reviewed_correction(correction, _evidence(prepared), expected_sha256=prepared["artifact"], operation=operation,
                    provenance={"factory_actor": native._actor(request), "factory_workspace": native._workspace(), "factory_operation": operation,
                                "factory_comparison": prepared["comparison"], "factory_review": digest(prepared)},
                    effect_guard=lambda: _guard(request, prepared, expires, budget, adopted=True))
                result = {"operation": operation, "binding": digest(prepared), "original_until": expires, "prepared": prepared, "complete": value["transaction_state"] in {"committed", "aborted"} or value["disposition"] == "skipped", **value}
                _bounded(result)
                return result
        try:
            jobs.start(KINDS[prepared["action"]], {"compare": "Compare agent-building guidance", "adopt": "Adopt reviewed agent-building guidance", "restore": "Restore earlier agent-building guidance"}[prepared["action"]], run,
                started_by=native._actor(request), workspace=native._workspace(), cancellable=prepared["action"] == "compare",
                on_cancel=lambda: setattr(budget, "max_dollars", 0), requested_id=operation[:16],
                initial_result={"operation": operation, "binding": digest(prepared), "original_until": expires, "prepared": prepared, "complete": False},
                problem=lambda exc: exc.detail if isinstance(exc, HTTPException) else "The comparison or adoption could not be completed. Earlier work may remain; read this original before a separate decision.")
        except jobs.JobRefused as exc:
            raise HTTPException(503, str(exc)) from exc
    return original(request, operation)
