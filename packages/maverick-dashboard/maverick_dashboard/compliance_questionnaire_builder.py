"""Ordinary questionnaire design bound to native immutable versions and receipts."""
from __future__ import annotations

import json
import secrets
import time
from contextlib import nullcontext
from functools import wraps
from typing import Literal

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from pydantic import Field

from . import auth
from .compliance_scoping_api import authority
from .department_team_updates import context
from .product_operations import StrictInput

TTL = 600
PURPOSE = "lightwork.questionnaire-design.v1"
DOMAINS = {"organization": "Your organization", "industry": "Industry", "jurisdiction": "Where you operate",
           "data": "Data you handle", "system": "Your systems", "vendor": "Vendors", "ai": "AI use", "operational": "Operations"}


class Condition(StrictInput):
    question: int = Field(ge=0, le=255)
    operator: Literal["equals", "not_equals", "contains", "in", "greater_or_equal", "less_or_equal"]
    value: bool | int | list[int]


class Question(StrictInput):
    name: str = Field(min_length=1, max_length=120)
    domain: Literal["organization", "industry", "jurisdiction", "data", "system", "vendor", "ai", "operational"]
    kind: Literal["boolean", "integer", "single_choice", "multi_choice"]
    options: list[str] = Field(default_factory=list, max_length=64)
    required: bool = True
    condition: Condition | None = None


class Rule(StrictInput):
    framework: str = Field(min_length=1, max_length=120)
    controls: list[str] = Field(min_length=1, max_length=256)
    overlaps: list[str] = Field(default_factory=list, max_length=256)
    reason: str = Field(min_length=1, max_length=120)
    conditions: list[Condition] = Field(default_factory=list, max_length=32)


class Design(StrictInput):
    name: str = Field(min_length=1, max_length=120)
    questions: list[Question] = Field(min_length=8, max_length=256)
    rules: list[Rule] = Field(min_length=1, max_length=512)


class StudioSource(StrictInput):
    studio: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    form: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    pointer: str = Field(pattern=r"^[a-f0-9]{64}$")
    blueprint: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReviewInput(StrictInput):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: str = Field(default="", max_length=128)
    source_revision: str = Field(default="", pattern=r"^(?:[a-f0-9]{64})?$")
    design: Design
    studio_source: StudioSource | None = None


def native_errors(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        from maverick import compliance_scoping as core
        from maverick import no_code_grc_studio as studio
        try:
            return function(*args, **kwargs)
        except studio.GRCStudioError as exc:
            code = (404 if isinstance(exc, studio.GRCStudioNotFound) else
                    403 if isinstance(exc, (studio.GRCStudioPermissionDenied, studio.GRCStudioConfigError)) else
                    409 if isinstance(exc, studio.GRCStudioConflict) else 503)
            raise HTTPException(code, "The live studio form changed or is unavailable. Your draft is kept; check its current version before saving.") from exc
        except core.ComplianceScopingError as exc:
            code = (404 if isinstance(exc, core.ComplianceScopingNotFound) else
                    403 if isinstance(exc, (core.ComplianceScopingPermissionDenied, core.ComplianceScopingConfigError)) else
                    409 if isinstance(exc, core.ComplianceScopingConflict) else
                    422 if isinstance(exc, core.ComplianceScopingValidationError) else 503)
            detail = ("These saved questionnaire details could not be verified. No questionnaire was changed." if code == 503 else
                      "The selected questionnaire changed before the save. Keep your draft and review the current starting version." if code == 409 else
                      "Check all eight topics, named choices, typed conditions and at least one control in every scope rule. Your draft has been kept." if code == 422 else str(exc))
            raise HTTPException(code, detail) from exc
    return wrapped


def bound(request, expected=None):
    auth.require_permission(request, "operate")
    if expected is not None and context(request) != expected:
        raise HTTPException(409, "Your account, workspace or access changed. Return to the original account before reviewing or checking this request.")
    return authority(request)


def name_for(names, ref):
    return names.get(ref) or ref.removeprefix("ref:").replace("-", " ").replace("_", " ").strip().capitalize()


def _studio(request, tenant):
    from . import no_code_grc_studio_composition as composition
    auth.require_permission(request, "view")
    if not composition.grc_studio_enabled(tenant):
        raise HTTPException(403, "Turn on Compliance studio before choosing a live form.")
    factory = getattr(request.app.state, "grc_studio_store_factory", None)
    if not callable(factory):
        raise HTTPException(503, "Compliance studio is unavailable. Your questionnaire draft is kept.")
    return factory(tenant_id=tenant, principal_ref=composition.principal_ref(request, tenant), request=request)


def _form(version, form_id):
    form = next((row for row in version.blueprint["forms"] if row["form_id"] == form_id), None)
    if form is None:
        raise HTTPException(404, "Choose a current live studio form.")
    record = next(row for row in version.blueprint["objects"] if row["object_id"] == form["object_id"])
    fields = {row["field_id"]: row for row in record["fields"]}
    questions, issues = [], []
    for section in form["sections"]:
        for identity in section["field_ids"]:
            item = fields[identity]
            label = name_for({}, item["label_ref"])
            choices = [name_for({}, option) for option in item["options"]]
            if len(label) > 120 or any(len(choice) > 120 for choice in choices):
                issues.append(label + ": use question and choice names of no more than 120 characters.")
            if len(set(choices)) != len(choices):
                issues.append(label + ": give each choice a different readable name before importing.")
            if item["field_type"] not in {"boolean", "integer", "single_choice", "multi_choice"}:
                issues.append(label + ": this answer format is not supported by compliance questionnaires.")
            if item["default"] is not None:
                issues.append(label + ": automatic answers are not supported; answers must be supplied by the respondent.")
            if len(item["options"]) > 64:
                issues.append(label + ": compliance questionnaires allow up to 64 choices per question.")
            questions.append({"name": label, "domain": section["section_id"] if section["section_id"] in DOMAINS else "",
                              "kind": item["field_type"], "options": choices,
                              "required": item["required"], "condition": None})
    if not 8 <= len(questions) <= 256:
        issues.append("This form must contain between 8 and 256 questions to cover all eight compliance topics.")
    for rule in version.blueprint["rules"]:
        if rule["object_id"] == record["object_id"]:
            issues.append(name_for({}, rule["rule_id"]) + ": studio record actions cannot be translated into compliance applicability rules. Remove this rule from the form’s record type before importing.")
    return {"name": name_for({}, form["title_ref"]), "questions": questions, "incompatibilities": issues}


@native_errors
def studio_sources(request):
    original = context(request)
    _core, tenant, _store = bound(request, original)
    store = _studio(request, tenant)
    versions = store.list_versions(tenant, state="published", limit=1000)
    output = []
    for version in versions:
        pointer, active = store.get_active(tenant, version.studio_id)
        if active.version != version.version:
            continue
        for form in active.blueprint["forms"]:
            output.append({"studio": version.studio_id, "form": form["form_id"],
                           "name": name_for({}, active.blueprint["name_ref"]) + " · " + name_for({}, form["title_ref"]),
                           "version": active.version})
            if len(output) >= 1000:
                break
        if len(output) >= 1000:
            break
    bound(request, original)
    return {"context": original, "forms": output,
            "notice": "Choose an independently approved live form. Up to 1,000 forms from the most recent 1,000 published studio versions are listed; the exact live source is checked again before saving."}


@native_errors
def studio_form(request, studio_id, form_id):
    original = context(request)
    _core, tenant, _store = bound(request, original)
    pointer, version = _studio(request, tenant).get_active(tenant, studio_id)
    result = _form(version, form_id)
    bound(request, original)
    return {"context": original, "source_version": version.version, "studio_source": {"studio": studio_id, "form": form_id,
            "pointer": pointer.integrity_sha256, "blueprint": version.blueprint_sha256}, **result,
            "notice": "Import keeps every question, answer format and choice. Assign a topic to each question and supply your team’s real framework and control rules. Saving creates a separate immutable questionnaire awaiting independent approval; it does not change the studio."}


def _checked_studio(request, tenant, pin, design=None, store=None):
    pointer, version = (store or _studio(request, tenant)).get_active(tenant, pin.studio)
    if pointer.integrity_sha256 != pin.pointer or version.blueprint_sha256 != pin.blueprint:
        raise HTTPException(409, "The live studio form changed. Your draft is kept. Check the current form before another review.")
    form = _form(version, pin.form)
    if form["incompatibilities"]:
        raise HTTPException(422, "This form is not compatible: " + " ".join(form["incompatibilities"]))
    if design is not None:
        exact = [{key: value for key, value in question.model_dump().items() if key != "domain"} for question in design.questions]
        source_questions = [{key: value for key, value in question.items() if key != "domain"} for question in form["questions"]]
        if exact != source_questions:
            raise HTTPException(409, "Keep the imported questions, choices and answer formats intact. Assign topics and scope rules in this builder; change the source questions in Compliance studio.")
    return version


def public(q):
    return {"name": name_for(q.display_names, q.questionnaire_id), "version": q.version,
            "status": "Ready to use" if q.status == "published" else "Waiting for independent approval",
            "questions": len(q.questions), "rules": len(q.rules)}


@native_errors
def catalog(request):
    original = context(request)
    _core, tenant, store = bound(request, original)
    rows = store.list_records(tenant, limit=1000)["questionnaires"]
    latest = {}
    for row in rows:
        if row.questionnaire_id not in latest:
            latest[row.questionnaire_id] = row
    bound(request, original)
    return {"context": original, "sources": [{"id": q.questionnaire_id, **public(q)} for q in latest.values()],
            "notice": "Up to 1,000 saved versions are listed. Each selection is checked against its actual latest version before review."}


def _condition_to_design(condition, indices, questions):
    if condition is None:
        return None
    index = indices[condition["question_id"]]
    source = questions[index]
    value = condition["value"]
    if source["answer_type"] in {"single_choice", "multi_choice"}:
        options = list(source["options"])
        value = [options.index(item) for item in value] if isinstance(value, list) else options.index(value)
    return {"question": index, "operator": condition["operator"], "value": value}


@native_errors
def source(request, identity=""):
    original = context(request)
    _core, tenant, store = bound(request, original)
    if not identity:
        return {"context": original, "source": "", "source_revision": "", "source_version": 0, "design": {
            "name": "", "questions": [{"name": "", "domain": domain, "kind": "boolean", "options": [], "required": True, "condition": None} for domain in DOMAINS],
            "rules": [{"framework": "", "controls": [""], "overlaps": [], "reason": "", "conditions": []}]}}
    q = store.latest_questionnaire(tenant, identity)
    if q is None:
        raise HTTPException(404, "This questionnaire is unavailable. Choose a current questionnaire.")
    if any(item["answer_type"] == "opaque_ref" for item in q.questions):
        raise HTTPException(409, "This imported questionnaire uses named-item answers that the builder does not yet support. Its current version remains available for assessments; create a separate questionnaire with Yes/No, number or choice answers.")
    indices = {item["question_id"]: i for i, item in enumerate(q.questions)}
    names = q.display_names
    design = {"name": name_for(names, q.questionnaire_id), "questions": [{
        "name": name_for(names, item["question_ref"]), "domain": item["domain"], "kind": item["answer_type"],
        "options": [name_for(names, option) for option in item["options"]], "required": item["required"],
        "condition": _condition_to_design(item["condition"], indices, q.questions)} for item in q.questions],
        "rules": [{"framework": name_for(names, item["framework_ref"]), "controls": [name_for(names, ref) for ref in item["control_refs"]],
                   "overlaps": [name_for(names, ref) for ref in item["overlap_refs"]], "reason": name_for(names, item["reason_code"]),
                   "conditions": [_condition_to_design(item, indices, q.questions) for item in item["conditions"]]} for item in q.rules]}
    bound(request, original)
    return {"context": original, "source": identity, "source_revision": q.integrity_sha256, "source_version": q.version, "design": design}


def _compile(design, questionnaire, previous=None):
    names = {questionnaire: design.name.strip()}
    refs = {}
    if previous:
        refs = {(ref.split("-")[0], label): ref for ref, label in previous.display_names.items()}
    def named(kind, label):
        label = label.strip()
        if not label or len(label) > 120 or any(ord(char) < 32 or ord(char) == 127 for char in label):
            raise HTTPException(422, "Use short names on one line for each question, choice, framework, control and reason.")
        key = (kind, label)
        value = refs.setdefault(key, kind + "-" + secrets.token_hex(12))
        names[value] = label
        return value
    questions = []
    for item in design.questions:
        if len(set(option.strip() for option in item.options)) != len(item.options):
            raise HTTPException(422, "Give each choice within a question a different name.")
        question_id = "question-" + secrets.token_hex(12)
        ref = "ref:" + question_id
        names[ref] = item.name.strip()
        options = [named("choice", option) for option in item.options]
        questions.append({"question_id": question_id, "question_ref": ref, "domain": item.domain,
                          "answer_type": item.kind, "options": options, "required": item.required, "condition": None})
    def condition(item, before):
        if item.question >= before:
            raise HTTPException(422, "A question condition must refer to an earlier question. Rule conditions can use any question.")
        q = questions[item.question]
        value = item.value
        if q["answer_type"] in {"single_choice", "multi_choice"}:
            values = value if isinstance(value, list) else [value]
            if any(type(index) is not int or not 0 <= index < len(q["options"]) for index in values):
                raise HTTPException(422, "Choose a current answer for each condition.")
            mapped = [q["options"][index] for index in values]
            value = mapped if isinstance(value, list) else mapped[0]
        return {"question_id": q["question_id"], "operator": item.operator, "value": value}
    for i, item in enumerate(design.questions):
        if item.condition:
            questions[i]["condition"] = condition(item.condition, i)
    rules = [{"rule_id": "rule-" + secrets.token_hex(12), "framework_ref": named("framework", rule.framework),
              "control_refs": [named("control", label) for label in rule.controls],
              "overlap_refs": [named("overlap", label) for label in rule.overlaps], "reason_code": named("reason", rule.reason),
              "conditions": [condition(item, len(questions)) for item in rule.conditions]} for rule in design.rules]
    return questions, rules, names


@native_errors
def review(request, data: ReviewInput):
    with authority_effect_fence():
        core, tenant, store = bound(request, data.context)
        studio_version = None
        if data.studio_source is not None:
            studio_version = _checked_studio(request, tenant, data.studio_source, data.design)
        previous = store.latest_questionnaire(tenant, data.source) if data.source else None
        if data.source and (previous is None or previous.integrity_sha256 != data.source_revision):
            raise HTTPException(409, "The selected questionnaire changed after you opened it. Keep your draft and open the current version before reviewing again.")
        if not data.source and data.source_revision:
            raise HTTPException(422, "Choose a current questionnaire or start a new one.")
        identity = data.source or "questionnaire-" + secrets.token_hex(12)
        questions, rules, names = _compile(data.design, identity, previous)
        material = {"questionnaire_id": identity, "questions": questions, "rules": rules,
                    "display_names": names, "expected_latest_version": previous.version if previous else 0,
                    "expected_latest_integrity": previous.integrity_sha256 if previous else None,
                    "idempotency_key": "design-" + secrets.token_hex(16)}
        if studio_version is not None:
            material["studio_source"] = {"studio_id": data.studio_source.studio, "form_id": data.studio_source.form,
                "version": studio_version.version, "pointer_sha256": data.studio_source.pointer,
                "blueprint_sha256": data.studio_source.blueprint}
        # Use the same closed validation now; the native transaction rechecks source at save.
        core._creation_material(identity, questions, rules, material["expected_latest_version"], store._actor(), names,
                               material["expected_latest_integrity"], material.get("studio_source"))
        bound(request, data.context)
        token = crypto_at_rest.seal_to_str(json.dumps({"purpose": PURPOSE, "context": data.context,
                "expires_at": time.time() + TTL, "material": material,
                "studio_source": data.studio_source.model_dump() if data.studio_source else None}, sort_keys=True, allow_nan=False))
        if not crypto_at_rest.is_sealed_str(token):
            raise HTTPException(503, "Secure review is unavailable. Nothing was saved.")
    return {"token": token, "context": data.context, "preview": data.design.model_dump(),
            "version": material["expected_latest_version"] + 1, "studio_form": data.studio_source is not None,
            "message": "This creates an immutable version waiting for approval by a different administrator. Existing assessments keep their original version. Names and rules are supplied by your team; Lightwork does not verify framework coverage or legal correctness."}


def open_token(token, recovery=False):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if (set(value) not in ({"purpose", "context", "expires_at", "material"}, {"purpose", "context", "expires_at", "material", "studio_source"}) or value["purpose"] != PURPOSE
                or not isinstance(value["expires_at"], float) or (not recovery and not time.time() < value["expires_at"] <= time.time() + TTL)):
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This review expired or could not be verified. Keep your draft and prepare another review.") from exc


@native_errors
def receipt(request, token):
    value = open_token(token, recovery=True)
    _core, tenant, store = bound(request, value["context"])
    q = store.questionnaire_creation_receipt(tenant, **value["material"])
    bound(request, value["context"])
    return {"confirmed": q is not None, "result": public(q) if q else None,
            "message": "The original saved version is confirmed. No save was repeated." if q else "No original acceptance was found. This check does not save or retry; keep your draft and review again only after confirming the original request is no longer running."}


@native_errors
def apply(request, token):
    value = open_token(token, recovery=True)
    with authority_effect_fence():
        _core, tenant, store = bound(request, value["context"])
        prior = store.questionnaire_creation_receipt(tenant, **value["material"])
        if prior is not None:
            return {"confirmed": True, "result": public(prior), "message": "Read the original accepted version; no new version was created."}
        open_token(token)
        pin = StudioSource.model_validate(value["studio_source"]) if value.get("studio_source") else None
        source_store = _studio(request, tenant) if pin else None
        fence = (source_store.active_source_fence(tenant, pin.studio, expected_pointer_integrity=pin.pointer,
                 expected_blueprint_sha256=pin.blueprint) if pin else nullcontext())
        with fence:
            def guard():
                # Do not reopen/initialize the target store inside its held
                # SQLite transaction. Recheck current authority without a writer.
                auth.require_permission(request, "operate")
                if context(request) != value["context"]:
                    raise HTTPException(409, "Your account, workspace or access changed. No questionnaire was saved.")
                if not _core.enabled():
                    raise HTTPException(403, "Compliance questionnaires were turned off before saving. No questionnaire was changed.")
                open_token(token)
                if pin:
                    auth.require_permission(request, "view")
                    _checked_studio(request, tenant, pin, store=source_store)
            q = store.create_questionnaire_version(tenant, **value["material"], effect_guard=guard)
        bound(request, value["context"])
        return {"confirmed": True, "result": public(q), "message": "Saved for independent approval. A different administrator must review it before any new assessment can use it."}
