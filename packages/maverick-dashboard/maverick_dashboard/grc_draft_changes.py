"""Reviewed native GRC draft saves and exact original receipts; no publication."""
from __future__ import annotations

import math
import time
from dataclasses import asdict

from fastapi import HTTPException
from maverick import no_code_grc_studio as core
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest

from . import auth
from . import no_code_grc_studio_api as native
from . import no_code_grc_studio_composition as composition
from .draft_api import context_for

PAGE = "/compliance/grc-studio"
TTL = 600
NOTICE = "Save only the complete reviewed blueprint as a draft. Sending it for independent review, approving it and publishing it remain separate actions. Connected destinations are not changed by this save."


def context(request):
    suites, scopes = auth.caller_suites(request), auth.api_key_scopes(request)
    from .api_flow_operator_review import _workspace_authority
    try:
        workspace = _workspace_authority(request, auth.caller_principal(request) or "", native._tenant_id())
    except HTTPException as exc:
        if exc.status_code == 409:
            raise HTTPException(409, "Your account, workspace or access changed. Refresh this page before using private draft details.") from exc
        raise
    return digest([context_for(request), workspace, auth.caller_role(request), sorted(suites) if suites is not None else None,
                   sorted(scopes) if scopes is not None else None])


def authority(request, expected=None, *, write=False):
    with auth.fresh_configuration():
        return _current_authority(request, expected, write=write)


def _current_authority(request, expected=None, *, write=False):
    # Refresh named session claims before checking a retained review or a
    # physical writer callback; its earlier request may have waited on a lock.
    principal = getattr(request.state, "principal", None)
    via = (getattr(principal, "claims", None) or {}).get("via")
    refresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
               "proxy": auth._proxy_principal}.get(via)
    if refresh is not None:
        fresh = refresh(request)
        if fresh is None or fresh.principal != principal.principal:
            raise HTTPException(401, "Sign in again before reviewing or saving this blueprint.")
        request.state.principal = principal = fresh
    if principal is not None:
        auth._enforce_scim_active(principal)
        auth._enforce_workspace_policies(request, principal)
    auth.require_permission(request, "operate")
    current = context(request)
    if expected is not None and current != expected:
        raise HTTPException(409, "Your account, workspace or access changed. Private draft details cannot be reused; refresh this page.")
    tenant = native._tenant_id()
    actor = native._principal(request, tenant)
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
    return tenant, actor, current


def call(function):
    try:
        return function()
    except HTTPException:
        raise
    except core.GRCStudioNotFound as exc:
        raise HTTPException(404, "This saved blueprint or original draft result is unavailable.") from exc
    except core.GRCStudioPermissionDenied as exc:
        raise HTTPException(403, "Your current access does not permit this draft operation.") from exc
    except core.GRCStudioConflict as exc:
        raise HTTPException(409, "This blueprint changed. Keep your entered work and review the current saved version before deciding again.") from exc
    except core.GRCStudioValidationError as exc:
        raise HTTPException(422, "The complete blueprint contains unsupported or incomplete choices. Your entered work is kept.") from exc
    except (core.GRCStudioConfigError, core.GRCStudioIntegrityError, OSError) as exc:
        raise HTTPException(503, "The studio or its original records could not be verified. Nothing was repeated.") from exc
    except Exception as exc:
        raise HTTPException(503, "The original save could not be confirmed. Check its original result; nothing will be repeated automatically.") from exc


def store(request):
    tenant, actor, current = authority(request)
    state = request.app.state
    enabled = getattr(state, "grc_studio_enabled_probe", None)
    ready = getattr(state, "grc_studio_readiness_probe", None)
    factory = getattr(state, "grc_studio_store_factory", None)
    if not callable(enabled) or enabled(tenant) is not True:
        raise HTTPException(403, "This workspace's GRC studio is turned off.")
    if not callable(ready) or ready(tenant) is not True or not callable(factory):
        raise HTTPException(503, "The studio is not ready. Finish its setup in Settings before saving.")
    selected = call(lambda: factory(tenant_id=tenant, principal_ref=actor, request=request))
    if getattr(selected, "tenant_id", None) != tenant or not callable(getattr(selected, "draft_result", None)):
        raise HTTPException(503, "This installation cannot verify original draft saves. Nothing was repeated.")
    authority(request, current)
    return selected


def _source(request, selected):
    tenant, actor, _current = authority(request)
    return digest([str(selected.path.resolve()), asdict(composition.settings_for_tenant(tenant)), tenant, actor])


def catalog(request):
    tenant, actor, current = authority(request)
    selected = store(request)
    authority(request, current)
    return {"context": current, "notice": NOTICE,
            "source": _source(request, selected)}


def _human(value):
    return str(value).replace("_", " ").replace("-", " ").replace(".", " ").strip().capitalize()


LABELS = {"name_ref": "Name", "description_ref": "Description", "objects": "Record types", "object_id": "Record type",
    "label_ref": "Name", "field_id": "Field", "field_type": "Answer type", "forms": "Forms", "form_id": "Form",
    "title_ref": "Title", "field_ids": "Fields", "options": "Choices", "record_ref": "Linked record type",
    "evidence_ref": "Linked evidence", "rules": "Rules", "rule_id": "Rule", "when": "When", "then": "Do",
    "operator": "Comparison", "collector_bindings": "Evidence links", "binding_id": "Evidence link",
    "collector_id": "Saved evidence source", "collector_version": "Evidence source version",
    "collector_integrity_sha256": "Exact evidence source fingerprint", "source_path": "Evidence value location",
    "target_field_id": "Field to fill", "control_refs": "Supported controls", "report_views": "Reports",
    "view_id": "Report", "group_by": "Group results by", "sort_by": "Order results by", "schema": "Blueprint format",
    "studio_id": "Blueprint", "section_id": "Section", "field_mappings": "Fields to fill", "value": "Answer",
    "mode": "Matching rule", "conditions": "Conditions", "action": "Action", "actions": "Actions"}
VALUES = {"single_choice": "Pick one", "multi_choice": "Pick several", "boolean": "Yes or no", "integer": "Whole number",
    "decimal": "Number", "text_ref": "Short text", "record_ref": "Link to a record", "evidence_ref": "Link to evidence",
    "digest": "File fingerprint", "equals": "is", "not_equals": "is not", "greater_than": "is more than",
    "greater_or_equal": "is at least", "less_than": "is less than", "less_or_equal": "is at most",
    "contains": "includes", "is_set": "is answered", "set_value": "Set an answer", "require_evidence": "Require evidence"}


def _fields(blueprint, sources=()):
    # Human labels are a review projection only. The sealed request and writer
    # keep the exact native definition, field paths and control identities.
    projected = dict(blueprint)
    if "collector_bindings" in blueprint:
        projected["collector_bindings"] = []
    for original in blueprint.get("collector_bindings", ()):
        source = next((row for row in sources if row["collector_id"] == original["collector_id"] and
                       row["collector_version"] == original["collector_version"] and
                       row["collector_integrity_sha256"] == original["collector_integrity_sha256"]), None)
        item = dict(original)
        if source:
            item["collector_id"] = source["label"]
            controls = {row["value"]: row["label"] for row in source["controls"]}
            item["control_refs"] = [controls.get(value, value) for value in original["control_refs"]]
            item["field_mappings"] = [{**mapping, "source_path": [next((row["label"] for row in source["outputs"]
                                      if row["path"] == mapping["source_path"]), ", ".join(mapping["source_path"]))]}
                                      for mapping in original["field_mappings"]]
        projected["collector_bindings"].append(item)
    return _project_fields(projected)


def _project_fields(blueprint):
    result = {}
    def visit(value, path, technical=False, literal=False):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "schema":
                    continue  # Fixed validated format, never an editable business choice.
                visit(item, path + (LABELS.get(key, _human(key)),), technical or key == "collector_integrity_sha256",
                      literal or key in {"value", "source_path"})
        elif isinstance(value, list) and value:
            for index, item in enumerate(value):
                visit(item, path + (str(index + 1),), technical, literal)
        else:
            text = "None" if value is None or value == [] else "Yes" if value is True else "No" if value is False else VALUES.get(value, _human(value)) if isinstance(value, str) and not (technical or literal) else str(value)
            result[path] = (text, technical)
    visit(blueprint, ())
    return result


def prepare(request, kind, studio, body, expected):
    tenant, actor, current = authority(request, expected, write=True)
    if kind not in {"create", "replace"}:
        raise HTTPException(422, "Choose a new draft or an existing editable draft.")
    version = body.get("version") if kind == "replace" else None
    inputs = {key: item for key, item in body.items() if kind != "replace" or key != "version"}
    model = native.CreateVersionIn if kind == "create" else native.ReplaceDraftIn
    try:
        inputs = model.model_validate({**inputs, "operation_id": "review-only"}).model_dump(mode="python")
    except ValueError as exc:
        raise HTTPException(422, "Choose supported complete draft inputs. Your entered work is kept.") from exc
    inputs.pop("operation_id")
    normalized = call(lambda: core.validate_blueprint(inputs["blueprint"], expected_studio_id=studio))
    inputs["blueprint"] = normalized
    selected = store(request)
    before = None
    if kind == "replace":
        if type(version) is not int or not 1 <= version <= 2_147_483_647:
            raise HTTPException(422, "Choose the exact draft version before reviewing it.")
        before = call(lambda: selected.get_version(tenant, studio, version))
        if (before.state != "draft" or before.created_by_ref != actor or before.revision != inputs["expected_revision"]
                or before.integrity_sha256 != inputs["expected_integrity_sha256"]):
            raise HTTPException(409, "This draft or its author changed. Your entered work is kept; review the current version.")
        inputs["version"] = version
    elif inputs["expected_latest_version"]:
        before = call(lambda: selected.get_version(tenant, studio, inputs["expected_latest_version"]))
    sources = native.validate_collector_bindings(request, normalized, before.blueprint if before else None)
    value = {"kind": kind, "studio": studio, "inputs": inputs, "tenant": tenant, "actor": actor,
        "context": current, "source": _source(request, selected), "before": before.integrity_sha256 if before else None,
        "deadline": time.time() + TTL}
    changes = review_rows(before.blueprint if before else {}, normalized, sources)
    if before:
        changes[0]["before"] = _human(before.blueprint["name_ref"]) + " / version " + str(before.version) + " / recorded change " + str(before.revision) + " / " + _human(before.state)
    changes[0]["after"] = ("Create version " + str(inputs["expected_latest_version"] + 1) if kind == "create" else "Update draft version " + str(version)) + ". " + NOTICE
    authority(request, current)
    return value, changes


def review_rows(before, after, sources=()):
    left, right = _fields(before, sources), _fields(after, sources)
    rows = [{"label": "Save effect", "before": "Current saved blueprint" if before else "No saved blueprint",
             "after": NOTICE}]
    for path in dict.fromkeys([*left, *right]):
        old, new = left.get(path), right.get(path)
        rows.append({"label": " · ".join(path), "before": old[0] if old else "Not included", "after": new[0] if new else "Removed",
                     "technical": bool(old and old[1] or new and new[1])})
    if len(rows) > 512 or len(str(rows).encode("utf-8")) > 131072:
        raise HTTPException(413, "This full blueprint exceeds the protected review limit. Keep your entered work and use a smaller blueprint; unseen choices cannot be approved.")
    return rows


def draft_request(value):
    return {"action": "create_version" if value["kind"] == "create" else "replace_draft", "studio_id": value["studio"],
            **value["inputs"], "actor_ref": value["actor"]}


def original(request, value, operation):
    tenant, actor, current = authority(request, value["context"])
    if tenant != value["tenant"] or actor != value["actor"]:
        raise HTTPException(404, "This original draft save belongs to another account or workspace.")
    selected = store(request)
    result = call(lambda: selected.draft_result(tenant, operation, draft_request(value)))
    response = {"context": current, "operation": operation, "confirmed": result is not None, "notice": NOTICE,
        "message": "The original save is unconfirmed. Nothing was repeated. A matching current blueprint is not proof of this request."}
    if result:
        response.update(message="Your original reviewed draft was saved. Nothing was repeated.", name=_human(result.blueprint["name_ref"]),
                        studio=result.studio_id, version=result.version, revision=result.revision, recorded_at=result.updated_at)
        try:
            saved = selected.get_version(tenant, result.studio_id, result.version)
            response["current"] = "That exact saved draft is still current." if saved.integrity_sha256 == result.integrity_sha256 else "This version has changed since your original save. Your original receipt remains historical."
        except core.GRCStudioNotFound:
            response["current"] = "This version is no longer retained. Its original receipt remains historical."
    authority(request, current)
    return response


def _guard(request, value, selected):
    tenant, actor, _current = authority(request, value["context"], write=True)
    deadline = value.get("deadline")
    if (tenant != value["tenant"] or actor != value["actor"] or type(deadline) not in {int, float}
            or not math.isfinite(deadline) or not time.time() < deadline <= time.time() + TTL):
        raise HTTPException(409, "This review expired before saving. Your entered work is kept; review current choices again.")
    if _source(request, selected) != value["source"]:
        raise HTTPException(409, "The current studio setup changed. Review your entered choices again.")
    version = value["inputs"].get("version", value["inputs"].get("expected_latest_version", 0))
    if version:
        before = selected.get_version(tenant, value["studio"], version)
        if before.integrity_sha256 != value["before"]:
            raise HTTPException(409, "The saved blueprint changed after your full review. Your entered work is kept; review it against the current saved version.")
    native.validate_collector_bindings(request, value["inputs"]["blueprint"], before.blueprint if version else None)


def apply(request, value, operation):
    authority(request, value["context"], write=True)
    with authority_effect_fence():
        existing = original(request, value, operation)
        if existing["confirmed"]:
            return existing
        selected = store(request)
        def guard():
            _guard(request, value, selected)
        if not call(lambda: selected.admit_draft_save(value["tenant"], operation, draft_request(value), before_write=guard)):
            return original(request, value, operation)
        arguments = {**value["inputs"], "operation_id": operation, "before_write": guard}
        if value["kind"] == "create":
            call(lambda: selected.create_version(value["tenant"], value["studio"], **arguments))
        else:
            version = arguments.pop("version")
            call(lambda: selected.replace_draft(value["tenant"], value["studio"], version, **arguments))
        return original(request, value, operation)


def legacy_save(request, selected, kind, tenant, studio, inputs, expected_context, *, version=None):
    """Keep headless input compatibility; recheck native authority after writer waits."""
    with authority_effect_fence():
        authority(request, expected_context, write=True)
        source = _source(request, selected)
        prior_version = version if kind == "replace" else inputs.get("expected_latest_version", 0)
        previous = selected.get_version(tenant, studio, prior_version).blueprint if prior_version else None
        def guard():
            authority(request, expected_context, write=True)
            if _source(request, selected) != source:
                raise HTTPException(409, "Studio setup changed during draft admission. No draft was saved.")
            native.validate_collector_bindings(request, inputs["blueprint"], previous)
        if kind == "create":
            return selected.create_version(tenant, studio, **inputs, before_write=guard)
        return selected.replace_draft(tenant, studio, version, **inputs, before_write=guard)
