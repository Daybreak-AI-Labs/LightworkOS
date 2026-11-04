"""Reviewed local preference training with one atomic model/result publication."""
from __future__ import annotations

import copy
import json
import math
import os
import re
import time

from fastapi import HTTPException
from maverick import config
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.memory_ownership import source_allowed
from maverick.paths import data_dir
from maverick.training import ingest
from maverick.training.identity import record_trajectory_id
from maverick.training.reward_model import (
    FEATURES,
    PreferenceRewardModel,
    train_reward_model,
    training_comparisons,
)
from pydantic import BaseModel, ConfigDict, Field

from . import learning_jobs, learning_ops_api
from .auth import require_global_permission
from .draft_api import context_for

PAGE = "/learning#lo-rm-h"
MAX_OUTLINES = 200
NOTICE = ("This learns a small ranking model from the first 200 permitted task outlines kept here. "
          "Both attempts need recorded steps and a distinguishable pattern to be used. "
          "Answer drafts without recorded steps stay available for answer training, but are skipped here. "
          "It uses recorded ratings and step patterns, without sending work to an AI service. "
          "Agreement on those training comparisons does not prove better results on new work. "
          "Private employee work and tasks excluded from learning are not admitted. Nothing is shared or enabled.")


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    min_margin: str = Field(default="0.5", pattern=r"^(0\.25|0\.5|1\.0)$")
    max_pairs: int = Field(default=64)
    epochs: int = Field(default=200)
    lr: str = Field(default="0.1", pattern=r"^(0\.05|0\.1|0\.2)$")


class Reviewed(Choices):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


def authority(request, context=None, *, write=False, historical=False):
    require_global_permission(request, "admin")
    current = context_for(request)
    if context is not None and context != current:
        raise HTTPException(409, "Your account or workspace changed. Refresh before continuing.")
    if not historical and config.config_source_errors(include_tenant=True):
        raise HTTPException(409, "Current learning settings could not be checked. Nothing was started.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
        learning_ops_api._halt_preflight("reward_model_train")
    return current


def _options(values):
    body = Choices.model_validate(values)
    learning_ops_api._choice(body.max_pairs, (32, 64, 128))
    learning_ops_api._choice(body.epochs, (100, 200, 500))
    return body


def fields():
    return [{"name": "min_margin", "label": "Smallest difference to learn from", "kind": "select", "value": "0.5",
             "choices": [{"value": v, "label": label} for v, label in (("0.25", "Small"), ("0.5", "Medium"), ("1.0", "Large"))]},
            {"name": "max_pairs", "label": "Comparisons per task", "kind": "select", "value": 64,
             "choices": [{"value": v, "label": "Up to " + str(v)} for v in (32, 64, 128)]},
            {"name": "epochs", "label": "Training rounds", "kind": "select", "value": 200,
             "choices": [{"value": v, "label": str(v)} for v in (100, 200, 500)]},
            {"name": "lr", "label": "Learning speed", "kind": "select", "value": "0.1",
             "choices": [{"value": v, "label": label} for v, label in (("0.05", "Slow"), ("0.1", "Normal"), ("0.2", "Fast"))]}]


def _events(world, goal_id):
    # The compatibility ingest reader tolerates DB failures and returns a
    # partial outline. A reviewed training source must be complete or refused.
    if not source_allowed(goal_id, "", world=world):
        raise ValueError("source permission")
    result, since = [], 0
    for _ in range(11):
        batch = world.goal_events(goal_id, since_id=since, limit=500)
        result.extend({"agent": item.agent, "kind": item.kind, "content": item.content, "ts": item.ts} for item in batch)
        if len(result) > 5000:
            raise ValueError("outline step bound")
        if len(batch) < 500:
            if not source_allowed(goal_id, "", world=world):
                raise ValueError("source permission changed")
            return result
        if batch[-1].id <= since:
            raise ValueError("outline pagination")
        since = batch[-1].id
    raise ValueError("outline step bound")


def _source():
    world = learning_ops_api._world()
    outbox = data_dir("outbox")
    rows, sources, shown = [], [], []
    try:
        for record in ingest.load_donations(outbox, world=world):
            identifier = record_trajectory_id(record)
            goal_id = record.get("goal_id", 0)
            if type(goal_id) is not int or goal_id < 0:
                raise ValueError("source identity")
            events = _events(world, goal_id)
            candidates = [ingest.build_trajectory(record, events), *ingest.build_rejected_trajectories(record),
                          *ingest.build_candidate_trajectories(record)]
            remaining = MAX_OUTLINES - len(rows)
            if remaining <= 0:
                break
            accepted = [ingest.to_klear_jsonl(candidate) for candidate in candidates[:remaining]]
            for row in accepted:
                value = float(row.get("terminal_reward", 0))
                if not math.isfinite(value) or not 0 <= value <= 1:
                    raise ValueError("outline rating")
                if len(row.get("messages", [])) > 5000:
                    raise ValueError("outline size")
                # The native featurizer must be able to consume every selected row.
                from maverick.training.reward_model import featurize
                featurize(row)
            goal = world.get_goal(goal_id) if goal_id else None
            title = str(getattr(goal, "title", "") or "Saved task outline")[:160]
            shown.append({"Task": title, "Attempts": len(accepted), "Recorded steps": len(events),
                          "Recorded rating": round(float(record.get("reward", 0)), 4)})
            rows.extend(accepted)
            sources.append({"identity": identifier, "goal": goal_id, "record": digest(record)})
            if len(rows) >= MAX_OUTLINES:
                break
    except Exception as exc:  # noqa: BLE001 -- incomplete source cannot authorize training
        raise HTTPException(409, "The task outlines could not be checked safely. Refresh the current source before training.") from exc
    storage = digest(os.path.normcase(str(outbox.resolve())))
    return rows, sources, shown, digest([storage, rows, sources, shown]), storage


def current(request, values=None):
    context = authority(request)
    body = _options(values or {})
    rows, sources, shown, source, storage = _source()
    pairs, evidence = training_comparisons(rows, min_margin=float(body.min_margin), max_pairs_per_group=body.max_pairs)
    available, _counts = training_comparisons(rows, min_margin=0.25, max_pairs_per_group=128)
    authority(request, context)
    return {"context": context, "revision": digest([context, source]), "source": source, "storage": storage,
            "outlines": len(rows), "comparisons": len(pairs), "evidence": evidence, "tasks": shown, "sources": sources,
            "notice": NOTICE, "choices": fields(), "ready": bool(pairs), "can_review": bool(available)}, rows


def prepare(request, values):
    body = Reviewed.model_validate(values)
    options = _options(body.model_dump(exclude={"context", "revision"}))
    state, _rows = current(request, options.model_dump())
    authority(request, body.context, write=True)
    if body.context != state["context"] or body.revision != state["revision"]:
        raise HTTPException(409, "The reviewed task outlines changed. Refresh the source and review again; nothing was started.")
    if not state["ready"]:
        raise HTTPException(409, "There are no usable comparisons with recorded, distinguishable steps on both attempts. Missing steps and indistinguishable patterns cannot train this ranking model. Nothing was trained or shared.")
    return {"body": body.model_dump(), "source": state["source"], "storage": state["storage"],
            "outlines": state["outlines"], "comparisons": state["comparisons"], "evidence": state["evidence"],
            "tasks": state["tasks"], "sources": state["sources"]}


def evidence_counts(evidence):
    """Readable counts for reviewed training and compatible older receipts."""
    if not evidence:
        return {}
    return {"Candidate comparisons": evidence["candidates"], "Usable comparisons": evidence["eligible"],
            "Skipped because steps are missing": evidence["missing_steps"],
            "Skipped because confidence is unavailable": evidence["no_confidence"],
            "Unresolved because step patterns are identical": evidence["unresolved"]}


def review_rows(prepared):
    body = prepared["body"]
    rows = [{"label": "Learning source", "after": "Eligible task outlines currently kept in this workspace"},
            {"label": "Work included", "after": str(prepared["outlines"]) + " attempts; " + str(prepared["comparisons"]) + " comparisons"},
            {"label": "Effect", "after": "Save a separate local ranking model. No current model is replaced; no AI is contacted or sharing enabled."}]
    rows.extend({"label": label, "after": str(count)} for label, count in evidence_counts(prepared.get("evidence")).items())
    for field in fields():
        shown = next(c["label"] for c in field["choices"] if c["value"] == body[field["name"]])
        rows.append({"label": field["label"], "after": shown})
    for index, task in enumerate(prepared["tasks"]):
        rows.append({"label": "Task group " + str(index + 1), "after": "\n".join(str(key) + ": " + str(value) for key, value in task.items())})
    return rows


def _store():
    return GovernedRecordStore("reward-training-requests", "RMT", "reward_training_request")


def _owned(request, operation):
    context = authority(request, historical=True)
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "That saved training request is unavailable.")
    row = _store().get("RMT-" + operation)
    if row and (row["actor"] != learning_ops_api._actor(request) or row["context"] != context):
        raise HTTPException(404, "That saved training request is unavailable to your account.")
    return row


def original(request, operation):
    context = authority(request, historical=True)
    row = _owned(request, operation)
    if row is None:
        return {"operation": operation, "context": context, "published": False,
                "message": "This original training record is unavailable. Absence does not establish failure. Nothing was started again.", "notice": NOTICE}
    job = learning_jobs.get(row["job_id"]) if row.get("job_id") else None
    if job and (job.started_by != row["actor"] or job.workspace != learning_ops_api._workspace() or job.kind != "reward_model_train"):
        raise HTTPException(404, "That original training task is unavailable to your account.")
    published = row["state"] == "published"
    source_visible = all(source_allowed(source["goal"], "") for source in row["prepared"]["sources"])
    safe_review = copy.deepcopy(row["prepared"])
    if not source_visible:
        safe_review["tasks"] = []
    result = {"operation": operation, "context": context, "published": published, "notice": NOTICE,
              "message": "The ranking model and its result were saved together." if published else
                         "The original training result is unconfirmed. Read its saved progress; nothing was started again.",
              "job": copy.deepcopy(job.view()) if job else None, "result": copy.deepcopy(row.get("result")),
              "review": review_rows(safe_review), "source_details_withheld": not source_visible}
    if not source_visible:
        result["message"] += " Original task details are withheld because their current sharing permission could not be confirmed."
    if row.get("job_id") and not job and not published:
        result["message"] = "The original training start was accepted, but its detailed progress is no longer available. Completion is unconfirmed. Nothing was repeated."
    authority(request, context, historical=True)
    if source_visible and not all(source_allowed(source["goal"], "") for source in row["prepared"]["sources"]):
        safe_review["tasks"] = []
        result["review"] = review_rows(safe_review)
        result["source_details_withheld"] = True
        result["message"] += " Original task details are withheld because their current sharing permission changed."
    return result


def _deadline(expires):
    if type(expires) not in {float, int} or not math.isfinite(expires) or not time.time() < expires <= time.time() + 600:
        raise HTTPException(409, "The training review expired before work could start. Review current outlines again.")


def start(request, prepared, operation, *, expires):
    body = prepared["body"]
    actor = learning_ops_api._actor(request)
    context = authority(request, body["context"], write=True)
    binding = digest([actor, context, operation, prepared])
    with authority_effect_fence():
        authority(request, context, write=True)
        existing = _owned(request, operation)
        if existing:
            if existing["binding"] != binding:
                raise HTTPException(409, "Read the original request; it belongs to a different training review.")
            return original(request, operation)
        _deadline(expires)
        if prepare(request, body) != prepared:
            raise HTTPException(409, "The source changed before training could start. Review it again.")
        learning_ops_api._record(request, "reward_model_train", phase="prepared", operation=operation, reviewed_revision=body["revision"])
        authority(request, context, write=True)
        _deadline(expires)
        claim = _store().create({"id": "RMT-" + operation, "actor": actor, "context": context, "binding": binding,
                                "prepared": prepared, "state": "admitting"}, action="learning.reward.prepare", actor=actor, max_records=1000)

        def run(job):
            with authority_effect_fence():
                authority(request, context, write=True)
                if prepare(request, body) != prepared:
                    raise HTTPException(409, "The outlines or access changed before training. No model was saved.")
                admitted = _store().update(claim["id"], lambda row: row.update(state="training", job_id=job.id),
                    expected_revision=claim["revision"], action="learning.reward.admitted", actor=actor)
                state, rows = current(request, {key: body[key] for key in ("min_margin", "max_pairs", "epochs", "lr")})
                if state["source"] != prepared["source"]:
                    raise HTTPException(409, "The source changed before training. No model was saved.")
                # Retaining the actual worker identity and reading its source
                # can wait on native writers. Recheck at the final admission.
                authority(request, context, write=True)
                _deadline(expires)
            model, report = train_reward_model(rows, min_margin=float(body["min_margin"]), max_pairs_per_group=body["max_pairs"],
                                               epochs=body["epochs"], lr=float(body["lr"]))
            if report["pairs"] < 1 or any(not math.isfinite(float(w)) for w in model.weights.values()):
                raise HTTPException(409, "Training did not produce a usable ranking model. No model was saved.")
            result = {"name": "rm-reviewed-" + operation, "created_at": time.time(), "pairs": int(report["pairs"]),
                      "accuracy": round(float(report["accuracy"]), 4), "outlines": len(rows), "source": "reviewed_outbox",
                      "evidence": {key: report[key] for key in prepared["evidence"]}}
            with authority_effect_fence():
                authority(request, context, write=True)
                if prepare(request, body) != prepared:
                    raise HTTPException(409, "The outlines or access changed during training. Its new model was not saved.")
                _store().update(claim["id"], lambda row: row.update(state="published", model=model.to_dict(), result=result),
                    expected_revision=admitted["revision"], action="learning.reward.published", actor=actor)
            return {"trained": True, **result, "notice": NOTICE}

        try:
            learning_ops_api.start_job(request, "reward_model_train", "Learning a local ranking model", run)
        except Exception:
            return original(request, operation)
    return original(request, operation)


def models():
    rows = [r for r in _store().list(limit=1000) if r.get("state") == "published"]
    return [copy.deepcopy(row["result"]) for row in sorted(rows, key=lambda r: r["result"]["created_at"], reverse=True)[:50]]


def model_bytes(request, name):
    match = re.fullmatch(r"rm-reviewed-([a-f0-9]{32})", name)
    if not match:
        return None
    context = authority(request)
    row = _store().get("RMT-" + match.group(1))
    if row is None or row.get("state") != "published" or row["result"]["name"] != name:
        raise HTTPException(404, "That saved ranking model is no longer available.")
    if row["prepared"]["storage"] != digest(os.path.normcase(str(data_dir("outbox").resolve()))):
        raise HTTPException(409, "The model's original outline storage changed. Choose a model trained from the current source.")
    expected = {s["identity"]: s for s in row["prepared"]["sources"]}
    world = learning_ops_api._world()
    found = set()
    for index, source in enumerate(ingest.load_donations(data_dir("outbox"), world=world)):
        if index >= 2000:
            break
        identifier = record_trajectory_id(source)
        retained = expected.get(identifier)
        if retained:
            if digest(source) != retained["record"] or not source_allowed(retained["goal"], "", world=world):
                raise HTTPException(409, "A task used to train this model changed or no longer permits learning. Train a new model from current eligible outlines.")
            found.add(identifier)
        if found == set(expected):
            break
    if found != set(expected):
        raise HTTPException(409, "The original training sources cannot all be verified now. This model was not used. Review current outlines before training a new one.")
    model = row["model"]
    if model.get("type") != "bradley_terry_linear" or model.get("features") != list(FEATURES) or set(model.get("weights", {})) != set(FEATURES):
        raise HTTPException(409, "This saved model could not be checked. It was not used.")
    PreferenceRewardModel(model["weights"])
    authority(request, context)
    return json.dumps(model, allow_nan=False, ensure_ascii=False).encode("utf-8")


__all__ = ["Choices", "Reviewed", "current", "prepare", "review_rows", "original", "start", "models", "model_bytes"]
