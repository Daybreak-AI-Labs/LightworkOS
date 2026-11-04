"""Ordinary reviewed questions in the existing shared self-coaching corpus."""
from __future__ import annotations

import base64
import json
import math
import os
import secrets
import time
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from maverick import config, crypto_at_rest, self_harness
from maverick import self_harness_eval as corpus
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import learning_ops_api as native
from .auth import require_global_permission
from .draft_api import context_for
from .plain_labels import model_label

router = APIRouter(prefix="/learning-test-cases", tags=["learning-test-cases"])
PAGE = "/learned#learning-test-questions"
PURPOSE = "lightwork.learning-test-question.v1"
SETUP_PURPOSE = "lightwork.learning-test-question-setup.v1"
TTL = 600
SCOPE = ("These questions are shared self-coaching information, available to administrators who manage this learning storage. "
         "Future checks can send them to the configured AI providers. Saving a question uses no AI and spends nothing.")


class CaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    model: str = Field(min_length=1, max_length=200)
    question: str = Field(min_length=1, max_length=4000)
    expected: str = Field(min_length=1, max_length=4000)

    @field_validator("question", "expected")
    @classmethod
    def complete(cls, value):
        if not value.strip():
            raise ValueError("Complete the question and expected answer.")
        return value


class ReviewIn(CaseIn):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_reference: str = Field(default="", max_length=65536)


class SelectedIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    model: str = Field(min_length=1, max_length=200)
    reference: str = Field(pattern=r"^[a-f0-9]{64}$")


class CorrectionIn(SelectedIn):
    question: str = Field(min_length=1, max_length=4000)
    expected: str = Field(min_length=1, max_length=4000)


class ChangeReviewIn(SelectedIn):
    action: Literal["correct", "retire"]
    question: str = Field(default="", max_length=4000)
    expected: str = Field(default="", max_length=4000)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class SaveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=262144)
    confirmed: Literal[True]


class SetupIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


def _authority(request, context=None, *, write=False):
    require_global_permission(request, "admin")
    current = context_for(request)
    if context is not None and current != context:
        raise HTTPException(409, "Your account or workspace changed. Refresh before continuing.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
        native._halt_preflight("self-harness")
    return current


def _scope(request, context=None, *, write=False):
    current = _authority(request, context, write=write)
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "The current learning settings could not be read. Open All settings before continuing.")
    path = native._corpus_path()
    settings = self_harness.settings()
    mode = str(settings.get("store") or "files").strip().lower()
    if mode not in {"files", "world"}:
        raise HTTPException(409, "Choose a supported learning storage option in All settings.")
    models = native._fleet()
    material = {"context": current, "path": os.path.normcase(str(Path(path).resolve())), "mode": mode}
    if mode == "world":
        from maverick import learning_store
        material["world"] = digest(learning_store._pg_dsn()) if learning_store._postgres() else os.path.normcase(str(learning_store._sqlite_path().resolve()))
    return {"context": current, "path": path, "source": digest(material), "models": models}


def _call(function):
    try:
        return function()
    except HTTPException:
        raise
    except (ValueError, OSError, RecursionError) as exc:
        raise HTTPException(409, "The current test questions could not be changed safely. Refresh and review them again.") from exc


def current(request):
    if not self_harness.settings().get("eval_corpus"):
        setup = setup_state(request)
        return {"context": setup["context"], "revision": setup["revision"], "models": [], "total": 0,
                "scope": SCOPE, "setup_required": True, "setup_blocked": setup["blocked"],
                "blocked": setup["blocked"] or "Set up learning questions before adding the first question."}
    scope = _scope(request)
    state = _call(lambda: corpus.corpus_authoring_state(scope["path"]))
    checked = _scope(request, scope["context"])
    if checked != scope:
        raise HTTPException(409, "Learning storage or the available models changed. Refresh before continuing.")
    blocked = ""
    try:
        native._halt_preflight("self-harness")
    except HTTPException as exc:
        blocked = exc.detail
    return {"context": scope["context"], "revision": digest([scope["source"], state["revision"], scope["models"]]),
            "models": [{"value": model, "label": model_label(model), "questions": state["counts"].get(model, 0)} for model in scope["models"]],
            "total": state["total_cases"], "scope": SCOPE, "blocked": blocked}


def setup_state(request):
    """Guide the existing global setting; never choose a new learner or activate it."""
    from maverick.paths import data_dir

    from . import settings_all_page as settings_page
    from . import settings_catalog, settings_store

    context = _authority(request)
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "The current learning settings could not be read. Refresh after they are available again.")
    with settings_store._locked(strict=True):
        layers = settings_page._sources()
        setting = settings_catalog.BY_ID["self_harness.eval_corpus"]
        resolved = settings_page._resolve(setting, layers)
        tenant_owned = settings_catalog.lookup(layers["tenant"], setting.path)[0]
        values = self_harness.settings()
        mode = str(values.get("store") or "files").strip().lower()
        path = str(data_dir("self-coaching-questions.json", tenant=None).resolve())
        blocked = ""
        if values.get("eval_corpus"):
            blocked = "Learning questions are already set up. Refresh the current collection; its existing location will be kept."
        elif resolved["locked"] or tenant_owned:
            blocked = "Your installation or workspace controls where learning questions are kept. This guided setup cannot replace that choice. Ask its administrator to make this setting available in Lightwork."
        elif mode not in {"files", "world"}:
            blocked = "Choose a supported learning storage option in All settings before setting up questions."
        else:
            try:
                settings_catalog.coerce(setting, path)
                native._halt_preflight("self-harness")
            except Exception as exc:
                if isinstance(exc, HTTPException):
                    blocked = str(exc.detail)
                else:
                    blocked = "Lightwork's managed learning location is not available under this installation's storage rules. Ask its administrator to restore access; no location was changed."
        binding = {"context": context, "path": os.path.normcase(path), "settings_file": os.path.normcase(str(config.dashboard_overrides_path().resolve())), "mode": mode}
        if mode == "world":
            from maverick import learning_store
            binding["world"] = digest(learning_store._pg_dsn()) if learning_store._postgres() else os.path.normcase(str(learning_store._sqlite_path().resolve()))
        state = {"context": context, "settings_revision": settings_page._revision(layers), "source": digest(binding),
                 "path": path, "storage": "In the existing shared learning database" if mode == "world" else "In Lightwork's managed data on this server",
                 "blocked": blocked, "ready": bool(values.get("eval_corpus"))}
        state["revision"] = digest(state)
        _authority(request, context)
        return state


def setup_changes(prepared):
    return [{"label": "Learning questions", "before": "Not set up", "after": prepared["storage"]},
            {"label": "Location", "after": "Lightwork chooses its own managed learning location. You do not need to enter a file location. Any existing information there is kept."},
            {"label": "Who can use it", "after": SCOPE},
            {"label": "Future checks", "after": "Existing learning settings still control future checks. Setting up a collection does not establish an improvement or qualify an empty collection."},
            {"label": "Effect", "after": "Save only the existing learning-question location setting. No learning switch, model, schedule or storage option changes. No AI runs and nothing is spent. Lightwork saves the collection when you add its first question."}]


def prepare_setup(request, *, context=None, revision=None):
    from . import settings_all_page as settings_page
    from . import settings_experience, settings_store

    with settings_store._locked(strict=True):
        state = setup_state(request)
        _authority(request, context or state["context"], write=True)
        if state["blocked"]:
            raise HTTPException(409, state["blocked"])
        if revision is not None and revision != state["revision"]:
            raise HTTPException(409, "Learning settings changed. Refresh before reviewing setup again.")
        body = settings_page.CatalogUpdate(expected_revision=state["settings_revision"], confirm=True,
                    changes=[settings_page.SettingChange(id="self_harness.eval_corpus", value=state["path"])])
        review = settings_experience.review(request, body)
        if review.status_code != 200 or [item["id"] for item in json.loads(review.body)["items"]] != ["self_harness.eval_corpus"]:
            raise HTTPException(409, "This learning setting changed. Refresh and review setup again.")
        if setup_state(request) != state:
            raise HTTPException(409, "Learning storage changed during review. Refresh before continuing.")
        return {key: state[key] for key in ("context", "settings_revision", "source", "path", "storage", "revision")}


def _setup_store():
    return GovernedRecordStore("learning-case-setup-requests", "LCS", "learning_case_setup_request")


def setup_original(request, operation, *, prepared=None):
    context = _authority(request)
    _request_id(operation)
    row = _setup_store().get("LCS-" + operation)
    if row and (row["context"] != context or row["actor"] != native._actor(request)):
        raise HTTPException(404, "This original learning setup request is not available to this account.")
    if row and prepared is not None and row["request_digest"] != digest({"operation": operation, "prepared": prepared, "actor": native._actor(request)}):
        raise HTTPException(409, "This original request belongs to another reviewed setup.")
    try:
        state = setup_state(request)
        current = "A learning-question location is currently configured. Refresh the collection before adding a question." if state["ready"] else state["blocked"] or "Learning questions are not currently set up."
    except (HTTPException, ValueError, OSError):
        state = {"ready": False}
        current = "Current learning readiness could not be read. The original receipt is kept; nothing was repeated."
    confirmed = bool(row and row["state"] == "saved")
    message = ("The original learning-question setup was saved. No setup was repeated." if confirmed else
               row.get("message") if row and row["state"] in {"refused", "queued"} else
               "The original setup is unconfirmed. Current readiness is shown separately; matching settings do not prove this request succeeded. Nothing was repeated.")
    _authority(request, context)
    return {"operation": operation, "context": context, "confirmed": confirmed, "message": message,
            "ready": state["ready"], "current": current, "scope": SCOPE}


def save_setup(request, prepared, operation):
    from . import settings_all_page as settings_page
    from . import settings_store

    _request_id(operation)
    context, actor = prepared["context"], native._actor(request)
    with settings_store._locked(strict=True):
        _authority(request, context, write=True)
        if _setup_store().get("LCS-" + operation) is not None:
            return setup_original(request, operation, prepared=prepared)
        checked = prepare_setup(request, context=context, revision=prepared["revision"])
        if checked != prepared:
            raise HTTPException(409, "Learning settings or storage changed. Review setup again.")
        native._record(request, "self_harness_case_setup", phase="prepared", operation=operation,
                       reviewed_revision=prepared["settings_revision"])
        store = _setup_store()
        claim = store.create({"id": "LCS-" + operation, "context": context, "actor": actor, "state": "writing",
                             "request_digest": digest({"operation": operation, "prepared": prepared, "actor": actor})},
                             action="learning.case.setup.prepare", actor=actor, max_records=10000)
        try:
            _authority(request, context, write=True)
            result = settings_page._catalog_update_locked(request, settings_page.CatalogUpdate(
                expected_revision=prepared["settings_revision"], confirm=True,
                changes=[settings_page.SettingChange(id="self_harness.eval_corpus", value=prepared["path"])]))
            if result.status_code == 200 and json.loads(result.body).get("changed") == ["self_harness.eval_corpus"]:
                outcome, message = "saved", ""
            elif result.status_code == 202:
                outcome, message = "queued", "This setup is waiting for the installation's independent approval. Open Approvals, then review the current learning setup. No setup was repeated."
            else:
                outcome, message = "refused", "This setup was not applied by the settings service. Refresh the current settings and review again."
            store.update(claim["id"], lambda row: row.update(state=outcome, message=message), expected_revision=claim["revision"],
                         action="learning.case.setup.result", actor=actor)
        except Exception:
            # A prepared claim is not proof of a completed setting write. Never
            # call the writer again or infer attribution from equal settings.
            return setup_original(request, operation, prepared=prepared)
        return setup_original(request, operation, prepared=prepared)


def prepare_case(request, values, *, context=None, revision=None, source_reference=""):
    from . import learning_task_examples as examples

    body = CaseIn.model_validate(values)
    state = current(request)
    _authority(request, context or state["context"], write=True)
    if revision is not None and state["revision"] != revision:
        raise HTTPException(409, "The test questions or available models changed. Refresh and review again.")
    scope = _scope(request, state["context"], write=True)
    if body.model not in scope["models"]:
        raise HTTPException(409, "This model is no longer offered. Choose a current model and review again.")
    try:
        reviewed = corpus.review_corpus_case(scope["path"], body.model, body.question, body.expected)
    except ValueError as exc:
        # Native validation sentences are bounded business copy, never file/parser errors.
        if str(exc).startswith(("This model", "The test-question collection")):
            raise HTTPException(409, str(exc)) from exc
        raise HTTPException(409, "The current test questions could not be read safely. Nothing was saved.") from exc
    checked = current(request)
    if checked["revision"] != state["revision"]:
        raise HTTPException(409, "The test questions changed during review. Refresh before saving.")
    prepared = {"context": scope["context"], "source": scope["source"], "corpus_revision": reviewed["revision"],
            "models": scope["models"], "case": body.model_dump(), "model_label": model_label(body.model),
            "questions_before": reviewed["model_cases"], "total_before": reviewed["total_cases"]}
    if source_reference:
        selected = examples.reviewed_source(request, source_reference, scope["context"])
        prepared.update(task_source=selected["source"], task_review={key: selected[key] for key in ("title", "question", "answer")},
                        source_expires=selected["expires"])
    return prepared


def changes(prepared):
    from .learning_task_examples import USE

    if prepared.get("action"):
        before = prepared["before"]
        return [{"label": "Model", "after": prepared["model_label"]},
                {"label": "Question", "before": before["question"], "after": prepared["case"]["question"] if prepared["action"] == "correct" else "Retire this question"},
                {"label": "Expected answer", "before": before["expected"], "after": prepared["case"]["expected"] if prepared["action"] == "correct" else "Remove from future checks"},
                {"label": "Other saved information", "after": "Original learning permissions and other information stay with a corrected question. Unrelated questions and past check results remain unchanged."},
                {"label": "Who can use it", "after": SCOPE},
                {"label": "Effect", "after": "Correct only this exact question. No check runs." if prepared["action"] == "correct" else "Remove only this exact question from the collection used by future checks. Its original saved receipts remain available. No check runs."}]
    source = prepared.get("task_review")
    source_rows = ([{"label": "Completed task", "after": source["title"]},
                    {"label": "Full task text", "after": source["question"]},
                    {"label": "Full recorded answer", "after": source["answer"]},
                    {"label": "Permission for this task", "after": USE}] if source else [])
    return source_rows + [{"label": "Model", "after": prepared["model_label"]},
            {"label": "Question", "after": prepared["case"]["question"]},
            {"label": "Expected answer", "after": prepared["case"]["expected"]},
            {"label": "Questions for this model", "before": prepared["questions_before"], "after": prepared["questions_before"] + 1},
            {"label": "Who can use it", "after": SCOPE},
            {"label": "Effect", "after": "Add this one question. Existing questions and lessons stay in place. No checks run and no improvement is established."}]


def _store():
    return GovernedRecordStore("learning-case-requests", "LCA", "learning_case_request")


def _request_id(operation):
    if len(operation) != 32 or any(char not in "0123456789abcdef" for char in operation):
        raise HTTPException(404, "This original question-saving request is not available.")
    return "LCA-" + operation


def _owned(request, operation):
    context = _authority(request)
    row = _store().get(_request_id(operation))
    if row and (row.get("context") != context or row.get("actor") != native._actor(request)):
        raise HTTPException(404, "This original question-saving request is not available to this account.")
    if row and row.get("protected_prepared"):
        try:
            row["prepared"] = json.loads(crypto_at_rest.unseal_bound(base64.b64decode(row["protected_prepared"], validate=True), row["id"]))
        except Exception as exc:
            raise HTTPException(503, "This original request's private review could not be opened. Its outcome remains unconfirmed; nothing was repeated.") from exc
    _authority(request, context)
    return row


def _protected_prepared(prepared, operation):
    binding = prepared.get("task_source") or prepared.get("before", {}).get("task_source")
    if not binding:
        return {"prepared": prepared}
    payload = base64.b64encode(crypto_at_rest.seal_bound(json.dumps(prepared, ensure_ascii=False).encode(), _request_id(operation))).decode()
    return {"prepared": {"task_source": binding}, "protected_prepared": payload}


def _project(request, row):
    if row["prepared"].get("action"):
        return _change_project(request, row)
    confirmed = row["state"] == "saved"
    current_state = "The original save is recorded. This receipt does not promise the question is still in the current collection."
    try:
        scope = _scope(request, row["context"])
        if scope["source"] == row["prepared"]["source"]:
            case = row["prepared"]["case"]
            original = corpus.authored_corpus_case(scope["path"], case["model"], row["binding"])
            if original is not None:
                if original.get("goal") != case["question"] or original.get("expected") != case["expected"]:
                    raise HTTPException(409, "The saved question changed. No work was repeated.")
                confirmed = True
                current_state = "This exact originally saved question is present in the current collection."
            else:
                current_state = "The originally saved question is not present now. Its absence does not establish whether earlier work succeeded."
    except (HTTPException, ValueError, OSError):
        # Retain the original receipt; a changed/unavailable current source never authorizes replay.
        current_state = "The current collection could not be matched to this original request. Nothing was repeated."
    _authority(request, row["context"])
    value = {"operation": row["id"][4:], "context": row["context"], "confirmed": confirmed,
            "message": "The original question was saved. No duplicate was added and no check was run." if confirmed else
                       "The original save is unconfirmed. Read the current collection before deciding what to do next; nothing is repeated automatically.",
            "model": row["prepared"]["model_label"], "question": row["prepared"]["case"]["question"],
            "expected": row["prepared"]["case"]["expected"], "recorded_at": row["created_at"], "current": current_state, "scope": SCOPE}
    return _source_projection(request, row["prepared"], value)


def _source_projection(request, prepared, value):
    from .learning_task_examples import case_access

    binding = prepared.get("task_source") or prepared.get("before", {}).get("task_source")
    if binding and not case_access(request, {"task_source": binding}):
        value.pop("question", None)
        value.pop("expected", None)
        value.pop("before", None)
        value["current"] = "The original recorded outcome is retained, but the source or its current permission is unavailable. Private question and answer text is withheld. Nothing was repeated."
    return value


def original_request(request, operation):
    row = _owned(request, operation)
    if row is None:
        return {"operation": operation, "context": _authority(request), "confirmed": False,
                "message": "No original saved-request record is available. Absence does not mean a save failed. Nothing was repeated."}
    return _project(request, row)


def save_case(request, prepared, operation):
    if prepared.get("action"):
        return save_change(request, prepared, operation)
    context = _authority(request, prepared["context"], write=True)
    case = CaseIn.model_validate(prepared["case"])
    actor = native._actor(request)
    request_digest = digest({"operation": operation, "prepared": prepared, "actor": actor})
    with authority_effect_fence():
        _authority(request, context, write=True)
        existing = _owned(request, operation)
        if existing is not None:
            if existing["request_digest"] != request_digest:
                raise HTTPException(409, "This request belongs to another reviewed question. Read its original result.")
            return _project(request, existing)

        def authorize():
            scope = _scope(request, context, write=True)
            if scope["source"] != prepared["source"] or scope["models"] != prepared["models"] or case.model not in scope["models"]:
                raise HTTPException(409, "Learning storage or the available models changed. Review again before saving.")
            if prepared.get("task_source"):
                from .learning_task_examples import case_access
                if not case_access(request, prepared) or time.time() >= prepared["source_expires"]:
                    raise HTTPException(409, "The selected task, permission or review deadline changed. Review the current source again. Nothing was added.")
        authorize()
        store = _store()
        claim = None
        # Secret until committed with the case; a legacy import cannot manufacture it.
        binding = secrets.token_hex(32)

        def claim_request():
            nonlocal claim
            native._record(request, "self_harness_case_append", phase="prepared", operation=operation,
                           reviewed_revision=prepared["corpus_revision"], model_sha256=digest(case.model))
            claim = store.create({"id": _request_id(operation), "context": context, "actor": actor,
                                  "binding": binding, "request_digest": request_digest, **_protected_prepared(prepared, operation), "state": "writing"},
                                 action="learning.case.prepare", actor=actor, max_records=10000)
        try:
            scope = _scope(request, context, write=True)
            options = {"task_source": prepared["task_source"]} if prepared.get("task_source") else {}
            corpus.append_reviewed_corpus_case(scope["path"], case.model, case.question, case.expected,
                expected_revision=prepared["corpus_revision"], binding=binding, authorize=authorize, before_write=claim_request, **options)
            store.update(claim["id"], lambda row: row.update(state="saved"), expected_revision=claim["revision"],
                         action="learning.case.saved", actor=actor)
        except Exception as exc:
            # A durable claim or native marker means effects may exist: recover by reads, never retry writes.
            retained = _owned(request, operation)
            if retained is not None:
                if retained["request_digest"] != request_digest:
                    raise HTTPException(409, "This request belongs to another reviewed question. Read its original result.") from exc
                return _project(request, retained)
            if isinstance(exc, HTTPException):
                raise
            if isinstance(exc, ValueError) and str(exc).startswith(("The test questions changed", "This model", "The test-question collection")):
                raise HTTPException(409, str(exc)) from exc
            raise HTTPException(503, "The reviewed question could not be saved. Check its original outcome before another attempt.") from exc
        return _project(request, _owned(request, operation))


def browse(request, model, *, offset=0):
    from .learning_task_examples import case_access

    scope = _scope(request)
    if model not in scope["models"]:
        raise HTTPException(409, "Choose a currently available model.")
    try:
        page = corpus.browse_corpus_cases(scope["path"], model, offset=offset, authorize=lambda row: case_access(request, row))
    except ValueError as exc:
        if str(exc).startswith("This model's imported collection"):
            raise HTTPException(409, str(exc)) from exc
        raise HTTPException(409, "The current question collection could not be read safely. It remains unchanged.") from exc
    if _scope(request, scope["context"]) != scope:
        raise HTTPException(409, "Your access, models or learning storage changed. Refresh current questions.")
    return {**page, "context": scope["context"], "model": model, "model_label": model_label(model),
            "revision": digest([scope["source"], page["revision"], scope["models"]])}


def selected_case(request, model, reference):
    from .learning_task_examples import case_access

    scope = _scope(request)
    if model not in scope["models"]:
        raise HTTPException(409, "Choose a currently available model.")
    value = _call(lambda: corpus.review_corpus_change(scope["path"], model, reference, "retire", authorize=lambda row: case_access(request, row)))
    if _scope(request, scope["context"]) != scope:
        raise HTTPException(409, "Your access, models or learning storage changed. Refresh current questions.")
    return {"context": scope["context"], "model": model, "reference": reference, "model_label": model_label(model),
            "revision": digest([scope["source"], value["revision"], scope["models"]]), **value["before"]}


def prepare_change(request, values, action, *, context=None, revision=None):
    from .learning_task_examples import case_access

    body = (CorrectionIn if action == "correct" else SelectedIn).model_validate(values)
    state = current(request)
    scope = _scope(request, context or state["context"], write=True)
    if revision is not None and state["revision"] != revision or body.model not in scope["models"]:
        raise HTTPException(409, "The collection or available models changed. Refresh and select the question again.")
    reviewed = _call(lambda: corpus.review_corpus_change(scope["path"], body.model, body.reference, action,
                    getattr(body, "question", None), getattr(body, "expected", None), authorize=lambda row: case_access(request, row)))
    if current(request)["revision"] != state["revision"]:
        raise HTTPException(409, "The questions changed during review. Select the current question again.")
    return {"action": action, "context": scope["context"], "source": scope["source"], "models": scope["models"],
            "corpus_revision": reviewed["revision"], "before_digest": reviewed["before_digest"], "after_digest": reviewed["after_digest"],
            "before": reviewed["before"], "case": {"model": body.model, "reference": body.reference,
              "question": body.question if action == "correct" else reviewed["before"]["question"],
              "expected": body.expected if action == "correct" else reviewed["before"]["expected"]},
            "model_label": model_label(body.model), "questions_before": reviewed["questions_before"]}


def _change_project(request, row):
    prepared = row["prepared"]
    confirmed = row["state"] == "saved"
    observation = "The receipt records the original change. It does not promise the current collection has stayed unchanged."
    try:
        scope = _scope(request, row["context"])
        if scope["source"] == prepared["source"]:
            effect = corpus.authored_corpus_effect(scope["path"], row["binding"])
            expected = {"action": prepared["action"], "model": prepared["case"]["model"],
                        "before_digest": prepared["before_digest"], "after_digest": prepared["after_digest"]}
            if effect == expected:
                confirmed = True
                observation = "The collection retains the exact original change receipt. Nothing was repeated."
            elif not confirmed:
                observation = "No matching original effect is available. Equal answers or a missing question cannot prove this request succeeded."
    except (HTTPException, ValueError, OSError):
        observation = "Current learning storage could not be checked. The original recorded outcome is kept; nothing was repeated."
    _authority(request, row["context"])
    value = {"operation": row["id"][4:], "context": row["context"], "confirmed": confirmed,
            "action": prepared["action"], "message": ("The original question correction was saved." if prepared["action"] == "correct" else "The original question retirement was saved.") + " No change was repeated and no check was run." if confirmed else
                       "The original change is unconfirmed. Read the current collection before deciding what to do next; nothing is repeated automatically.",
            "model": prepared["model_label"], "question": prepared["case"]["question"], "expected": prepared["case"]["expected"],
            "before": prepared["before"], "current": observation, "recorded_at": row["created_at"], "scope": SCOPE}
    return _source_projection(request, prepared, value)


def save_change(request, prepared, operation):
    context = _authority(request, prepared["context"], write=True)
    actor = native._actor(request)
    request_digest = digest({"operation": operation, "prepared": prepared, "actor": actor})
    with authority_effect_fence():
        _authority(request, context, write=True)
        previous = _owned(request, operation)
        if previous is not None:
            if previous["request_digest"] != request_digest:
                raise HTTPException(409, "This request belongs to another reviewed question change.")
            return _project(request, previous)
        def authorize():
            scope = _scope(request, context, write=True)
            if scope["source"] != prepared["source"] or scope["models"] != prepared["models"] or prepared["case"]["model"] not in scope["models"]:
                raise HTTPException(409, "Learning storage or models changed. Review the current question again.")
            if prepared["before"].get("task_source"):
                from .learning_task_examples import case_access
                if not case_access(request, prepared["before"]):
                    raise HTTPException(409, "The task source or permission changed. Its private question cannot be changed here.")
        authorize()
        binding, store, claim = secrets.token_hex(32), _store(), None
        def claim_request():
            nonlocal claim
            native._record(request, "self_harness_case_" + prepared["action"], phase="prepared", operation=operation,
                           reviewed_revision=prepared["corpus_revision"], model_sha256=digest(prepared["case"]["model"]))
            claim = store.create({"id": _request_id(operation), "context": context, "actor": actor, "binding": binding,
                                  "request_digest": request_digest, **_protected_prepared(prepared, operation), "state": "writing"},
                                 action="learning.case.prepare", actor=actor, max_records=10000)
        try:
            scope, case = _scope(request, context, write=True), prepared["case"]
            corpus.change_reviewed_corpus_case(scope["path"], case["model"], case["reference"], prepared["action"],
                    case["question"], case["expected"], expected_revision=prepared["corpus_revision"],
                    before_digest=prepared["before_digest"], binding=binding, authorize=authorize, before_write=claim_request)
            store.update(claim["id"], lambda row: row.update(state="saved"), expected_revision=claim["revision"],
                         action="learning.case.saved", actor=actor)
        except Exception as exc:
            retained = _owned(request, operation)
            if retained is not None:
                if retained["request_digest"] != request_digest:
                    raise HTTPException(409, "This request belongs to another reviewed question change.") from exc
                return _project(request, retained)
            if isinstance(exc, HTTPException):
                raise
            if isinstance(exc, (ValueError, PermissionError)):
                raise HTTPException(409, "The selected question or its learning permissions changed. Refresh and review again. Nothing was changed.") from exc
            raise HTTPException(503, "The original change is unconfirmed. Check its saved outcome before another attempt.") from exc
        return _project(request, _owned(request, operation))


def _response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.get("")
def state(request: Request):
    return _response(current(request))


@router.get("/context")
def recovery_context(request: Request):
    # Original receipts remain reachable even when corpus setup needs repair.
    return _response({"context": _authority(request)})


@router.get("/task-sources")
def task_sources(request: Request, offset: int = Query(0, ge=0, le=1000000)):
    from .learning_task_examples import catalog
    return _response(catalog(request, offset=offset))


@router.get("/task-source")
def task_source(request: Request, goal: int = Query(ge=1), context: str = Query(pattern=r"^[a-f0-9]{64}$")):
    from .learning_task_examples import selected
    return _response(selected(request, goal, context))


@router.get("/cases")
def cases(request: Request, model: str = Query(min_length=1, max_length=200), offset: int = Query(0, ge=0, le=1000000)):
    return _response(browse(request, model, offset=offset))


@router.get("/case")
def case(request: Request, model: str = Query(min_length=1, max_length=200), reference: str = Query(pattern=r"^[a-f0-9]{64}$")):
    return _response(selected_case(request, model, reference))


@router.get("/requests/{operation}")
def receipt(request: Request, operation: str):
    return _response(original_request(request, operation))


@router.get("/setup/requests/{operation}")
def setup_receipt(request: Request, operation: str):
    return _response(setup_original(request, operation))


@router.post("/setup/review")
def setup_review(request: Request, body: SetupIn):
    prepared = prepare_setup(request, context=body.context, revision=body.revision)
    material = {"purpose": SETUP_PURPOSE, "prepared": prepared, "operation": secrets.token_hex(16), "expires": time.time() + TTL}
    token = crypto_at_rest.seal_to_str(json.dumps(material, allow_nan=False, ensure_ascii=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 262144:
        raise HTTPException(503, "This setup could not be prepared securely. Nothing was changed.")
    return _response({"token": token, "operation": material["operation"], "context": prepared["context"], "changes": setup_changes(prepared)})


@router.post("/review")
def review(request: Request, body: ReviewIn):
    prepared = prepare_case(request, {key: getattr(body, key) for key in ("model", "question", "expected")}, context=body.context,
                            revision=body.revision, source_reference=body.source_reference)
    material = {"purpose": PURPOSE, "prepared": prepared, "operation": secrets.token_hex(16), "expires": time.time() + TTL}
    token = crypto_at_rest.seal_to_str(json.dumps(material, allow_nan=False, ensure_ascii=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 262144:
        raise HTTPException(503, "This question could not be prepared securely. Nothing was saved.")
    return _response({"token": token, "operation": material["operation"], "context": prepared["context"], "changes": changes(prepared)})


@router.post("/change-review")
def change_review(request: Request, body: ChangeReviewIn):
    values = body.model_dump(exclude={"action", "context", "revision"})
    if body.action == "retire":
        values = {key: values[key] for key in ("model", "reference")}
    prepared = prepare_change(request, values, body.action, context=body.context, revision=body.revision)
    material = {"purpose": PURPOSE, "prepared": prepared, "operation": secrets.token_hex(16), "expires": time.time() + TTL}
    token = crypto_at_rest.seal_to_str(json.dumps(material, allow_nan=False, ensure_ascii=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 262144:
        raise HTTPException(503, "This question change could not be prepared securely. Nothing was changed.")
    return _response({"token": token, "operation": material["operation"], "context": prepared["context"], "changes": changes(prepared)})


@router.post("/save")
def save(request: Request, body: SaveIn):
    _authority(request, write=True)
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if (set(material) != {"purpose", "prepared", "operation", "expires"} or material["purpose"] not in {PURPOSE, SETUP_PURPOSE}
                or type(material["expires"]) not in (int, float) or not math.isfinite(material["expires"])):
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This review changed. Prepare the question again.") from exc
    is_setup = material["purpose"] == SETUP_PURPOSE
    existing = _setup_store().get("LCS-" + material["operation"]) if is_setup else _owned(request, material["operation"])
    if existing is None and not time.time() < material["expires"] <= time.time() + TTL:
        raise HTTPException(409, "This review expired. Prepare the question again.")
    return _response(save_setup(request, material["prepared"], material["operation"]) if is_setup else save_case(request, material["prepared"], material["operation"]))
