"""Learning-page buttons for the training and research commands that were
terminal-only: ``model-improvement status/models/score``, ``reward-model
train/score`` and the coordination shorthand (``codebook``, ``codec-learn``,
``codec-probe``).

Reads need ``view``. Anything that trains, scores, learns or stores needs a
global administrator and runs as a background job the page polls. None of
these calls a model to generate text: model-improvement scoring is
deterministic, the reward model is a small local model trained on this
server, and the shorthand is learned from recorded messages. The only
provider call is the optional Anthropic token-count estimate, offered only
for its direct configured connection while learning may contact it. It uses the main
assistant model (``model_for_role("orchestrator")``).
"""
from __future__ import annotations

import json
import re
import tempfile
import time
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission
from .learning_ops_api import _choice, _clip, _record, _upload, _world, start_job

router = APIRouter(prefix="/training-ops", tags=["training-ops"])

_OUTPUTS_LIMIT = 5 * 1024 * 1024
_TRAJECTORY_LIMIT = 20 * 1024 * 1024
_MAX_ROWS = 20_000
_MODEL_NAME = re.compile(r"rm-\d{8}-\d{6}\Z")
_SPLITS = {"holdout": "Kept-aside questions", "validation": "Check questions", "train": "Practice questions"}
_MEMORY = (8, 16, 24, 32, 48, 64, 80, 128, 192)
_CONTEXT = (4096, 8192, 16384, 32768, 65536, 131072)
_CONCURRENCY = (1, 2, 4, 8)


class CodecIn(BaseModel):
    how_many: Literal[500, 2000, 5000] = 5000
    exact: bool = False


# ---- model improvement --------------------------------------------------------

def _planning_context(request: Request) -> str:
    from . import auth
    from .app import require_page_visible
    from .draft_api import context_for

    with auth.fresh_configuration():
        principal = getattr(request.state, "principal", None)
        if principal is not None:
            via = (principal.claims or {}).get("via")
            resolver = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                        "proxy": auth._proxy_principal}.get(via)
            fresh = resolver(request) if resolver else principal
            if fresh is None or fresh.principal != principal.principal:
                raise HTTPException(401, "Sign in again before reading learning controls.")
            request.state.principal = fresh
            auth._enforce_scim_active(fresh)
            auth._enforce_workspace_policies(request, fresh)
        require_permission(request, "view")
        auth.require_page_permission(request, "/learning")
        require_page_visible(request, "/learning")
        return context_for(request)


def _readiness_reason(text: str) -> str:
    low = text.lower()
    if "need" in low and "train" in low:
        return "Needs more independent practice task groups."
    if "need" in low and "holdout" in low:
        return "Needs more independent kept-aside task groups."
    if "published seed" in low:
        return "Its kept-aside answers are published examples, so they cannot prove a model is ready."
    if "both train and holdout" in low:
        return "The same task appears in both practice and kept-aside groups."
    if "repeat identical" in low:
        return "Some task groups are copies of each other."
    return "Not ready yet."


def _status() -> dict:
    from maverick.training.improvement_report import status_report
    from maverick.training.specialist_models import load_catalog
    doc = status_report()
    cfg = doc["config"]
    roles = sorted({r for m in load_catalog().models for r in m.roles})
    return {
        "on": bool(cfg.get("enable")), "hosted_allowed": bool(cfg.get("allow_hosted")),
        "signed_receipt_required": bool(cfg.get("require_signed_receipt")),
        "catalog": {"as_of": doc["catalog"]["as_of"], "candidates": int(doc["catalog"]["candidates"])},
        "task_sets": [{"value": e["environment_id"], "label": e["environment_id"].replace("_", " ").replace("-", " ").capitalize(),
                       "ready": bool(e["ready"]), "practice_groups": int(e["train_families"]),
                       "kept_aside_groups": int(e["holdout_families"]),
                       "why_not": sorted({_readiness_reason(r) for r in e["reasons"]})}
                      for e in doc["environments"]][:50],
        "choices": {"roles": [{"value": r, "label": r.replace("_", " ").capitalize()} for r in roles],
                    "memory_gib": list(_MEMORY), "context_tokens": list(_CONTEXT),
                    "concurrency": list(_CONCURRENCY),
                    "splits": [{"value": k, "label": v} for k, v in _SPLITS.items()]},
    }


@router.get("/model-improvement")
async def model_improvement(request: Request) -> dict:
    context = _planning_context(request)
    try:
        status = await run_in_threadpool(_status)
    except Exception as exc:  # noqa: BLE001 -- plain message, no internals
        raise HTTPException(status_code=503, detail="Model planning details are not available right now.") from exc
    if _planning_context(request) != context:
        raise HTTPException(409, "Your account or workspace changed. Reload Learning before reading model choices.")
    return {**status, "context": context}


@router.get("/model-improvement/models")
async def planning_models(request: Request, role: str = Query(min_length=1, max_length=64),
                          memory_gib: int = Query(), context_tokens: int = 16384,
                          concurrency: int = 1) -> dict:
    context = _planning_context(request)
    if memory_gib not in _MEMORY or context_tokens not in _CONTEXT or concurrency not in _CONCURRENCY:
        raise HTTPException(status_code=422, detail="Choose from the lists.")
    from maverick.training.improvement_report import candidates_report
    from maverick.training.specialist_models import SpecialistModelError
    try:
        doc = await run_in_threadpool(lambda: candidates_report(
            role, memory_gib=float(memory_gib), context_tokens=context_tokens, concurrency=concurrency))
    except (SpecialistModelError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Choose a role from the list.") from exc
    if _planning_context(request) != context:
        raise HTTPException(409, "Your account or workspace changed. Reload Learning before reading model choices.")
    return {"planning_only": True, "context": context,
        "query": {"role": role, "memory_gib": memory_gib, "context_tokens": context_tokens, "concurrency": concurrency}, "models": [
        {"name": c["model_id"], "licence": _clip(c["license"], 80), "status": str(c["status"]).replace("_", " "),
         "priority": int(c["planning_priority"]), "fits": bool(c["estimate"].get("fits")),
         "memory_needed_gib": round(float(c["estimate"].get("minimum_memory_gib") or 0.0), 1)}
        for c in doc["candidates"][:100]]}


@router.post("/model-improvement/score")
async def score_task_set(request: Request, task_set: str = Query(min_length=1, max_length=120),
                         split: Literal["holdout", "validation", "train"] = "holdout") -> dict:
    """``model-improvement score``: score an answers file against one task set
    without a model judge, as a background job."""
    require_global_permission(request, "admin")
    from maverick.training.environments import list_environment_ids
    from maverick.training.improvement_report import score_report, strict_json_object
    if task_set not in await run_in_threadpool(list_environment_ids):
        raise HTTPException(status_code=422, detail="Choose a task set from the list.")
    raw = await _upload(request, _OUTPUTS_LIMIT)
    try:
        outputs = strict_json_object(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=(
            "That answers file must list one answer per question, with no repeated questions.")) from exc

    def _run(job) -> dict:
        doc = score_report(task_set, outputs, split=split)
        results = doc["results"]
        return {"task_set": task_set, "questions": len(results),
                "passed": sum(1 for r in results if r.get("passed")),
                "score": round(float(doc["score"]), 4), "pass_rate": round(float(doc["pass_rate"]), 4),
                "unanswered": len(doc["missing_case_ids"]), "not_in_set": len(doc["extra_case_ids"])}
    return start_job(request, "model_improvement_score", "Scoring answers against a task set", _run)


# ---- ordinary supplied-answer scoring --------------------------------------------

@router.get("/model-improvement/questions")
async def ordinary_model_questions(request: Request, task_set: str = Query(min_length=1, max_length=120),
                                   split: Literal["holdout", "validation", "train"] = "holdout"):
    from . import model_answer_scoring as scoring
    state, _pack = await run_in_threadpool(scoring.current, request, task_set, split)
    return Response(json.dumps(state), media_type="application/json", headers={"Cache-Control": "private, no-store"})


@router.post("/model-improvement/answer-review")
async def ordinary_answer_review(request: Request):
    import secrets

    from maverick import crypto_at_rest

    from . import model_answer_scoring as scoring
    raw = await _upload(request, 96 * 1024)
    try:
        values = json.loads(raw)
        prepared = await run_in_threadpool(scoring.prepare, request, values)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, "Complete the displayed answer fields before reviewing.") from exc
    material = {"purpose": "lightwork.provided-answer-scoring.v1", "prepared": prepared,
                "operation": secrets.token_hex(16), "expires": time.time() + 600}
    token = crypto_at_rest.seal_to_str(json.dumps(material, ensure_ascii=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 262144:
        raise HTTPException(409, "This answer review could not be protected. Your entered work is kept.")
    return Response(json.dumps({"token": token, "operation": material["operation"], "context": prepared["body"]["context"],
                               "review": scoring.review_rows(prepared), "notice": scoring.NOTICE}),
                    media_type="application/json", headers={"Cache-Control": "private, no-store"})


class OrdinaryScoreIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=262144)
    confirmed: Literal[True]


@router.post("/model-improvement/answer-score")
async def ordinary_answer_score(request: Request, body: OrdinaryScoreIn):
    from maverick import crypto_at_rest

    from . import model_answer_scoring as scoring
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if (set(material) != {"purpose", "prepared", "operation", "expires"}
                or material["purpose"] != "lightwork.provided-answer-scoring.v1" or material["expires"] <= time.time()):
            raise ValueError
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(409, "This answer review expired or could not be checked. Read any original request before preparing another.") from exc
    row = await run_in_threadpool(scoring.start, request, material["prepared"], material["operation"], expires=material["expires"])
    return Response(json.dumps(row), media_type="application/json", headers={"Cache-Control": "private, no-store"})


@router.get("/model-improvement/answer-requests/{operation}")
async def original_answer_score(request: Request, operation: str):
    from . import model_answer_scoring as scoring
    row = await run_in_threadpool(scoring.original, request, operation)
    return Response(json.dumps(row), media_type="application/json", headers={"Cache-Control": "private, no-store"})


# ---- reward model ----------------------------------------------------------------

def _store() -> Path:
    from maverick.paths import data_dir
    return data_dir("reward-models")


def _index() -> list[dict]:
    try:
        rows = json.loads((_store() / "index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [r for r in rows if isinstance(r, dict) and _MODEL_NAME.fullmatch(str(r.get("name")))] \
        if isinstance(rows, list) else []


def _outbox_rows() -> list[dict]:
    from maverick.paths import data_dir
    from maverick.training.ingest import klear_rows
    world = None
    try:
        world = _world()
    except HTTPException:
        world = None
    rows: list[dict] = []
    for row in klear_rows(data_dir("outbox"), world):
        rows.append(row)
        if len(rows) >= _MAX_ROWS:
            break
    return rows


def _file_rows(raw: bytes) -> list[dict]:
    from maverick.training.rlaif import load_klear
    with tempfile.TemporaryDirectory(prefix="lw-trajectories-") as folder:
        path = Path(folder) / "trajectories.jsonl"
        path.write_bytes(raw)
        rows = load_klear(path)
    return [r for r in rows if isinstance(r, dict)][:_MAX_ROWS]


async def _rows(request: Request, source: str) -> bytes:
    if source == "file":
        return await _upload(request, _TRAJECTORY_LIMIT)
    return b""


@router.get("/reward-models")
async def reward_models(request: Request) -> dict:
    require_permission(request, "view")

    def _read() -> dict:
        from maverick.donation import list_pending

        from .reward_model_training import models
        combined = list(reversed(_index())) + models()
        return {"models": sorted(combined, key=lambda row: row["created_at"], reverse=True)[:50], "waiting_outlines": len(list_pending())}
    return await run_in_threadpool(_read)


@router.get("/reward-models/current-outlines")
async def current_reward_outlines(request: Request, min_margin: Literal["0.25", "0.5", "1.0"] = "0.5",
                                 max_pairs: int = 64, epochs: int = 200,
                                 lr: Literal["0.05", "0.1", "0.2"] = "0.1") -> Response:
    from . import reward_model_training as reward
    state, _rows = await run_in_threadpool(reward.current, request,
        {"min_margin": min_margin, "max_pairs": max_pairs, "epochs": epochs, "lr": lr})
    public = {key: value for key, value in state.items() if key not in {"source", "storage", "sources"}}
    return Response(json.dumps(public), media_type="application/json", headers={"Cache-Control": "private, no-store"})


@router.post("/reward-models/review")
async def review_reward_training(request: Request) -> Response:
    import secrets

    from maverick import crypto_at_rest

    from . import reward_model_training as reward
    try:
        prepared = await run_in_threadpool(reward.prepare, request, json.loads(await _upload(request, 8192)))
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, "Choose the displayed training options before reviewing.") from exc
    value = {"purpose": "lightwork.reward-training.v1", "operation": secrets.token_hex(16),
             "expires": time.time() + 600, "prepared": prepared}
    token = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 262144:
        raise HTTPException(409, "The training review could not be protected. Nothing was started.")
    return Response(json.dumps({"token": token, "operation": value["operation"], "context": prepared["body"]["context"],
                               "review": reward.review_rows(prepared), "notice": reward.NOTICE}),
                    media_type="application/json", headers={"Cache-Control": "private, no-store"})


@router.post("/reward-models/train-reviewed")
async def train_reviewed_reward_model(request: Request, body: OrdinaryScoreIn) -> Response:
    from maverick import crypto_at_rest

    from . import reward_model_training as reward
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if (set(value) != {"purpose", "operation", "expires", "prepared"}
                or value["purpose"] != "lightwork.reward-training.v1" or value["expires"] <= time.time()):
            raise ValueError
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(409, "This training review expired or could not be checked. Read any original request before preparing another.") from exc
    result = await run_in_threadpool(reward.start, request, value["prepared"], value["operation"], expires=value["expires"])
    return Response(json.dumps(result), media_type="application/json", headers={"Cache-Control": "private, no-store"})


@router.get("/reward-models/requests/{operation}")
async def original_reward_training(request: Request, operation: str) -> Response:
    from . import reward_model_training as reward
    result = await run_in_threadpool(reward.original, request, operation)
    return Response(json.dumps(result), media_type="application/json", headers={"Cache-Control": "private, no-store"})


@router.post("/reward-models/train")
async def train_reward_model(request: Request, source: Literal["outbox", "file"] = "outbox",
                             min_margin: Literal["0.25", "0.5", "1.0"] = "0.5",
                             max_pairs: int = 64, epochs: int = 200,
                             lr: Literal["0.05", "0.1", "0.2"] = "0.1") -> dict:
    """``reward-model train``: learns on this server from task outlines (the
    donated outlines, or an uploaded outline file) and keeps the result."""
    require_global_permission(request, "admin")
    _choice(max_pairs, (32, 64, 128))
    _choice(epochs, (100, 200, 500))
    from maverick.file_lock import atomic_write_text
    from maverick.training.reward_model import train_reward_model as train
    raw = await _rows(request, source)
    await run_in_threadpool(lambda: _record(request, "reward_model_train", source=source))

    def _run(job) -> dict:
        rows = _file_rows(raw) if source == "file" else _outbox_rows()
        if not rows:
            return {"trained": False, "why": "There are no task outlines to learn from yet."}
        model, report = train(rows, min_margin=float(min_margin), max_pairs_per_group=max_pairs,
                              epochs=epochs, lr=float(lr))
        if report["pairs"] == 0:
            return {"trained": False, "why": ("There are no usable comparisons with recorded, distinguishable "
                                              "steps on both attempts. No ranking model was saved."),
                    "evidence": {key: report[key] for key in ("candidates", "eligible", "skipped", "unresolved",
                                                              "missing_steps", "indistinguishable", "no_confidence")}}
        name = time.strftime("rm-%Y%m%d-%H%M%S", time.gmtime())
        store = _store()
        store.mkdir(parents=True, exist_ok=True)
        atomic_write_text(store / f"{name}.json", json.dumps(model.to_dict(), indent=2, sort_keys=True))
        entry = {"name": name, "created_at": time.time(), "pairs": int(report["pairs"]),
                 "accuracy": round(float(report["accuracy"]), 4), "outlines": len(rows), "source": source,
                 "evidence": {key: report[key] for key in ("candidates", "eligible", "skipped", "unresolved",
                                                           "missing_steps", "indistinguishable", "no_confidence")}}
        atomic_write_text(store / "index.json", json.dumps((_index() + [entry])[-200:], indent=2))
        return {"trained": True, **entry}
    return start_job(request, "reward_model_train", "Training the reward model", _run)


def _model_path(name: str) -> Path:
    if not _MODEL_NAME.fullmatch(name) or name not in {r["name"] for r in _index()}:
        raise HTTPException(status_code=404, detail="That reward model is no longer kept. Refresh the page.")
    return _store() / f"{name}.json"


@router.post("/reward-models/{name}/score")
async def score_with_reward_model(request: Request, name: str,
                                  source: Literal["outbox", "file"] = "outbox") -> dict:
    require_global_permission(request, "admin")
    from maverick.training.reward_model import PreferenceRewardModel, has_recorded_steps

    from .reward_model_training import model_bytes
    guided = await run_in_threadpool(model_bytes, request, name)
    path = await run_in_threadpool(_model_path, name) if guided is None else None
    raw = await _rows(request, source)

    def _run(job) -> dict:
        require_global_permission(request, "admin")
        latest = model_bytes(request, name) if guided is not None else None
        model = PreferenceRewardModel(json.loads(latest)["weights"]) if latest is not None else PreferenceRewardModel.load(path)
        rows = _file_rows(raw) if source == "file" else _outbox_rows()
        scored = sorted(({"outcome": str(r.get("outcome") or "").replace("_", " "),
                          "steps": len(r.get("messages") or []), "score": round(model.score(r), 4),
                          "reference": str(r.get("id") or "")[:80]} for r in rows if has_recorded_steps(r)),
                        key=lambda x: x["score"], reverse=True)
        return {"scored": len(scored), "top": scored[:50], "skipped": len(rows) - len(scored),
                "notice": "Attempts without recorded steps were not scored. These scores describe step patterns, not answer quality."}
    return start_job(request, "reward_model_score", "Scoring task outlines with the reward model", _run)


@router.get("/reward-models/{name}/download")
async def download_reward_model(request: Request, name: str) -> Response:
    require_global_permission(request, "admin")
    from .reward_model_training import model_bytes
    data = await run_in_threadpool(model_bytes, request, name)
    if data is None:
        path = await run_in_threadpool(_model_path, name)
        data = await run_in_threadpool(path.read_bytes)
    require_global_permission(request, "admin")
    await run_in_threadpool(lambda: _record(request, "reward_model_download", model=name))
    return Response(data, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="Lightwork-reward-model-{name[3:]}.json"',
        "Cache-Control": "private, no-store"})


# ---- coordination shorthand (codebook / codec) --------------------------------------

def _exact_allowed() -> bool:
    try:
        from maverick.self_learning import provider_egress_enabled
        return bool(provider_egress_enabled())
    except Exception:  # noqa: BLE001 -- uncertainty cannot authorize egress
        return False


def _counter(exact: bool, request: Request | None = None):
    from maverick.codec_probe import resolve_counter
    if not exact:
        return resolve_counter()
    if not _exact_allowed():
        raise HTTPException(status_code=409, detail=(
            "Learning may not contact your AI provider, so only the free estimate is available."))
    from maverick.llm import model_for_role, require_model_allowed
    model = model_for_role("orchestrator")
    require_model_allowed(model)
    from .draft_api import context_for
    from .learning_ops_api import _halt_preflight
    context = context_for(request) if request is not None else None

    def check_current():
        if request is not None:
            require_global_permission(request, "admin")
            if context_for(request) != context:
                raise HTTPException(409, "Your account, workspace or access changed. No further messages were sent.")
        _halt_preflight("codec-count")
        if not _exact_allowed() or model_for_role("orchestrator") != model:
            raise HTTPException(409, "Learning access or the selected model changed. No further messages were sent.")

    check_current()
    return resolve_counter(model=model, official_only=True, before_count=check_current)


def _codec_view() -> dict:
    from maverick import emergent_protocol, emergent_tokens
    book = emergent_protocol.shared().book()
    tokens = emergent_tokens.shared().book()
    available = False
    if _exact_allowed():
        try:
            from maverick.codec_probe import anthropic_counting_available
            from maverick.llm import model_for_role
            available = anthropic_counting_available(model_for_role("orchestrator"))
        except (HTTPException, ValueError, RuntimeError, ImportError, OSError, TypeError):
            pass
    return {"shorthand": {"codes": int(book.size), "on": bool(emergent_protocol.enabled()),
                          "phrases": [_clip(p, 160) for p in list(book.forward)[:10]]},
            "token_codes": {"codes": int(tokens.size), "on": bool(emergent_tokens.enabled())},
            "exact_count_available": available}


@router.get("/codec")
async def codec(request: Request) -> dict:
    require_permission(request, "view")
    return await run_in_threadpool(_codec_view)


def _messages(how_many: int) -> list[str]:
    return list(_world().recent_event_contents(limit=how_many))


@router.post("/codec/shorthand/learn")
async def learn_shorthand(request: Request, body: CodecIn) -> dict:
    """``codebook``: relearn the shorthand from recent coordination and keep it."""
    require_global_permission(request, "admin")
    await run_in_threadpool(lambda: _record(request, "codebook_learn", messages=body.how_many))

    def _run(job) -> dict:
        from maverick.emergent_protocol import compression_ratio, learn, shared
        msgs = _messages(body.how_many)
        book = learn(msgs)
        shared().update(book)
        return {"codes": int(book.size), "messages": len(msgs),
                "smaller_pct": round((1 - compression_ratio(msgs, book)) * 100) if msgs else 0,
                "phrases": [_clip(p, 160) for p in list(book.forward)[:10]]}
    return start_job(request, "codebook_learn", "Learning the shorthand", _run)


@router.post("/codec/token-codes/learn")
async def learn_token_codes(request: Request, body: CodecIn) -> dict:
    """``codec-learn``: learn the token-saving codes and keep them."""
    require_global_permission(request, "admin")
    counter = await run_in_threadpool(_safe_counter, body.exact, request)
    await run_in_threadpool(lambda: _record(request, "codec_learn", messages=body.how_many, exact=body.exact))

    def _run(job) -> dict:
        from maverick import emergent_tokens as et
        msgs = _messages(body.how_many)
        if not msgs:
            return {"learned": False, "why": "There are no recorded messages between agents to learn from yet."}
        learned = et.learn_from_messages(msgs, count_tokens=counter)
        if learned is None:
            return {"learned": False, "why": "This way of counting offers no cheap codes, so it would not help."}
        book, saved = learned
        return {"learned": True, "codes": int(book.size), "messages": len(msgs), "saved_pct": round(saved, 1)}
    return start_job(request, "codec_learn", "Learning token-saving codes", _run)


@router.post("/codec/measure")
async def measure_codec(request: Request, body: CodecIn) -> dict:
    """``codec-probe``: does the shorthand save tokens, not just characters?"""
    require_global_permission(request, "admin")
    counter = await run_in_threadpool(_safe_counter, body.exact, request)

    def _run(job) -> dict:
        from maverick.codec_probe import measure
        from maverick.emergent_protocol import learn
        msgs = _messages(body.how_many)
        if not msgs:
            return {"measured": False, "why": "There are no recorded messages between agents to measure yet."}
        book = learn(msgs)
        d = measure(msgs, book, count_tokens=counter).to_dict()
        be = d["breakeven_messages"]
        return {"measured": True, "messages": int(d["n_messages"]), "codes": int(book.size),
                "characters_saved_pct": d["byte_savings_pct"], "tokens_saved_pct": d["token_savings_pct"],
                "pays_off": bool(d["pays_off"]), "codebook_tokens": int(d["codebook_tokens"]),
                "break_even_after": None if be == float("inf") else round(float(be))}
    return start_job(request, "codec_probe", "Measuring the shorthand", _run)


def _safe_counter(exact: bool, request: Request | None = None):
    try:
        return _counter(exact, request)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 -- counter unavailable (no tokenizer / blocked model)
        raise HTTPException(status_code=409, detail=(
            "Lightwork cannot count tokens on this server right now.")) from exc


__all__ = ["router"]
