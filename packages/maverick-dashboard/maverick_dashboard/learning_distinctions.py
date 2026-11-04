"""Source-bound native discovery; no new consent, AI calls or publication."""
from __future__ import annotations

import copy
import json
import math
import re
import time
from contextlib import ExitStack

from fastapi import HTTPException, Response
from maverick import crypto_at_rest
from maverick.audit.errors import AuditRefused
from maverick.authority_effects import authority_effect_fence
from maverick.flow import operational_distinctions as discovery
from maverick.flow import recipe_lineage, store
from maverick.flow.action_episode_review import _episode
from maverick.flow.recipe_domain import domain_from_contract
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore, RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import flow_teach_ops_api as teach
from . import local_flow_comparisons as comparisons
from .candidate_promotion_api import _binding
from .plain_labels import datetime_text

PAGE = "/learning/distinctions"
TTL = 600
NOTICE = ("Use only your selected accepted examples and their existing learning permissions. Find the smallest additional available observations "
          "that distinguish the two demonstrated actions, then check them through the existing local teaching rules. "
          "No permission is widened, AI is called, action is repeated or workflow is published. A draft remains subject to its original sources.")
MEANING = ("These known examples are not proof of future accuracy or business value. The comparison uses the same examples and every available field. "
           "A smaller set of observations cannot explain more of these examples than all available information. Missing information and identical observations with different actions remain unresolved.")


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    flow_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    run_ids: list[str] = Field(min_length=4, max_length=32)
    base_fields: list[str] = Field(default_factory=list, max_length=6)


def records():
    return GovernedRecordStore("learning-distinction-requests", "LDR", "learning_distinction_request")


def authority(request, context=None, *, write=False):
    tenant, owner, current = _binding(request, Response())
    teach._gate(request)
    if context is not None and current != context:
        raise HTTPException(409, "Your account or workspace changed. Refresh before continuing.")
    if write:
        from maverick.learning_guard import check_learning_halt

        from .app import _require_same_origin
        _require_same_origin(request)
        check_learning_halt("flow_recipe_lineage", "operational_distinctions")
    return tenant, owner, current


def flows(request):
    tenant, owner, context = authority(request)
    rows = store.list_flow_summaries(owner=owner, bounded=True)
    if len(rows) > 100:
        raise HTTPException(409, "Open this page from a named workflow; the workspace is larger than this 100-workflow picker.")
    authority(request, context)
    return {"context": context, "flows": [{"value": row["id"], "label": row["name"]} for row in rows]}


def options(request, flow_id):
    tenant, owner, context = authority(request)
    flow = teach._flow(request, flow_id)
    if flow.owner != owner:
        raise HTTPException(403, "Choose a workflow that belongs to your account.")
    overview = teach.flow_teach_overview(request, flow_id)
    available = teach.reviewed_examples(request, flow_id)
    ready = [row for row in available["runs"] if row["can_learn"]]
    history = [row for row in records().list(limit=1000) if row["owner"] == owner and row["tenant"] == tenant and row["flow_id"] == flow_id]
    authority(request, context)
    return {"context": context, "flow": overview["flow"], "revision": digest([context, overview, available]), "runs": [
                {"value": row["run_id"], "label": "Accepted example / " + datetime_text(row["started"], seconds=True),
                 "revision": row["revision"], "episode": row["episode"], "grant": row["grant"]} for row in ready],
            "requests": [{"value": row["id"][4:], "label": "Distinction review / " + datetime_text(row["created_at"], seconds=True)} for row in history[-20:]],
            "notice": NOTICE, "meaning": MEANING}


def source(request, choices, *, context=None):
    body = Choices.model_validate(choices)
    tenant, owner, current = authority(request, context)
    from maverick.config import get_flows
    flags = get_flows()
    if not teach._signed_ready(flags) or flags.get("action_recipe_choices") is not True:
        raise HTTPException(409, "Signed teaching and choosing between actions must be enabled in Learning settings before preparing distinctions.")
    selected = options(request, body.flow_id)
    if len(set(body.run_ids)) != len(body.run_ids):
        raise HTTPException(422, "Choose each accepted example once.")
    ready = {row["value"]: row for row in selected["runs"]}
    if not set(body.run_ids) <= ready.keys():
        raise HTTPException(409, "A chosen example is no longer permitted for learning. Check its Learning example card.")
    service, ctx = teach._episode_service(request, body.flow_id, human=True)
    episodes, contracts, bindings = [], [], {}
    for run_id in sorted(body.run_ids):
        row = service.get(ctx, body.flow_id, run_id, detail=True)
        if row.get("training_available") is not True or not row.get("evidence"):
            raise HTTPException(409, "A chosen example is unavailable or its learning permission expired.")
        episodes.append(_episode(row, row["evidence"]))
        contracts.append(copy.deepcopy(row["evidence"]["contract"]))
        bindings[run_id] = {"revision": row["revision"], "episode": row["episode_sha256"], "grant": row["grant_sha256"]}
    if any(contract != contracts[0] for contract in contracts):
        raise HTTPException(409, "Choose accepted examples with the same reviewed inputs and action contracts. Different contracts require separate teaching reviews.")
    tools = contracts[0]["allowed_tools"]
    domain = domain_from_contract("choices", contracts[0], episodes)
    analysis = discovery.analyze(episodes, domain, tools, body.base_fields)
    fields, artifact = discovery.qualified_fields(episodes, domain, tools, analysis)
    final = options(request, body.flow_id)
    if final["revision"] != selected["revision"]:
        raise HTTPException(409, "The workflow or examples changed while reading. Your selection is kept; refresh and review again.")
    authority(request, current)
    material = {"context": current, "tenant": tenant, "owner": owner, "body": body.model_dump(), "flow": selected["flow"],
                "runs": bindings, "episodes": episodes, "domain": domain, "tools": tools, "analysis": analysis, "fields": fields,
                "settings": digest(flags),
                "artifact": artifact}
    material["revision"] = digest(material)
    return material


def preview(material):
    analysis = material["analysis"]
    names = {field["name"]: discovery.field_label(field) for field in analysis["catalog"]}
    field_values = [{names[name]: value for name, value in row.items()} for row in analysis["rows"]]
    return {"workflow": material["flow"]["name"], "version": material["flow"]["version"], "observations": [{"value": field["name"], "label": names[field["name"]]} for field in analysis["catalog"]],
            "examples": [{"label": "Example " + str(index + 1), "values": values, "action": teach_label(analysis["labels"][index]),
                          "initial_values": material["episodes"][index]["inputs"],
                          "recorded_work": [{"action": teach_label(step["tool"]), "details": step["arguments"], "result": step["result"]}
                                            for step in material["episodes"][index]["steps"]]} for index, values in enumerate(field_values)],
            "currently_used": [names[name] for name in analysis["base"]], "proposed": [names[name] for name in material["fields"] or []],
            "aliases": [{"examples": [left + 1, right + 1], "unresolved": [left, right] in analysis["unresolved"]} for left, right in analysis["pairs"]],
            "matched_bound": {"Selected observations": analysis["projection_maximum_matches"], "All available observations": analysis["whole_information_maximum_matches"], "Examples": analysis["cases"]},
            "ready": material["fields"] is not None,
            "qualification": "The proposed extra observations help tell these examples apart and pass the supported teaching rules." if material["fields"] is not None else
                             "These examples remain unresolved under the supported teaching rules. Identical observations with different actions or missing information can prevent a draft. No answer is invented.",
            "notice": NOTICE, "meaning": MEANING}


def teach_label(value):
    from .identity_format import humanize
    return humanize(value)


def changes(material):
    review = preview(material)
    return [{"label": "Workflow and saved version", "after": review["workflow"] + " / version " + str(review["version"])},
            {"label": "Current observations", "after": review["currently_used"] or ["No observations selected"]},
            {"label": "Proposed smallest qualified observations", "after": review["proposed"]},
            {"label": "Complete accepted examples", "after": review["examples"]},
            {"label": "Observed conflicts", "after": review["aliases"]},
            {"label": "Comparison using all available information", "after": review["matched_bound"]},
            {"label": "Scope and consequence", "after": NOTICE + " " + MEANING}]


def owned(request, operation, prepared=None):
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(422, "Choose an original distinction review.")
    tenant, owner, context = authority(request)
    row = records().get("LDR-" + operation)
    if row and (row["tenant"], row["owner"], row["context"]) != (tenant, owner, context):
        raise HTTPException(404, "This original review is unavailable to your account.")
    if row and prepared is not None and row["binding"] != digest([operation, owner, prepared]):
        raise HTTPException(409, "This request belongs to another reviewed selection.")
    authority(request, context)
    return row


def package(request, row):
    payload = json.loads(crypto_at_rest.unseal_from_str(row["payload"]))
    if payload["binding"] != row["binding"]:
        raise HTTPException(409, "The retained result cannot be verified.")
    service, ctx = teach._episode_service(request, row["flow_id"], human=True)
    for bundle in payload["package"]["bundles"]:
        service.assert_bundle_current(ctx, bundle)
    trust, tenant = teach._workspace_trust()
    recipe_lineage.validate_package(payload["package"], trust=trust, expected_tenant=tenant, now=time.time())
    authority(request, row["context"])
    return payload


def original(request, operation, prepared=None):
    row = owned(request, operation, prepared)
    result = {"operation": operation, "confirmed": False, "message": "The original package is unconfirmed. Nothing was repeated; a missing result does not prove failure."}
    if row and row["state"] == "saved" and not row.get("_audit_pending"):
        result.update(confirmed=True, message="The original unpublished package was saved. Nothing was published or repeated.", flow_id=row["flow_id"],
                      teach_href="/flows/" + row["flow_id"] + "/teach", download_href="/api/v1/learning/distinctions/original/" + operation + "/package")
        try:
            payload = package(request, row)
            result.update(review=payload["review"], currently_usable=True)
        except (PermissionError, LookupError, ValueError, HTTPException, RecordConflict, AuditRefused):
            authority(request, row["context"])
            result.update(currently_usable=False, message="The original package was saved, but its sources are no longer currently eligible. No package contents are returned or reused.")
            result.pop("download_href", None)
    authority(request)
    return result


def build(request, prepared, operation, *, expires):
    body = Choices.model_validate(prepared["body"])
    with authority_effect_fence():
        authority(request, prepared["context"], write=True)
        if owned(request, operation, prepared):
            return original(request, operation, prepared)
        if type(expires) not in (int, float) or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
            raise HTTPException(409, "This review expired. Review current examples again.")
        current = source(request, body.model_dump(), context=prepared["context"])
        if current["revision"] != prepared["revision"] or current["fields"] is None:
            raise HTTPException(409, "The reviewed sources or rule checks changed. No new package was prepared.")
        service = records()
        try:
            claim = service.create({"id": "LDR-" + operation, "tenant": prepared["tenant"], "owner": prepared["owner"], "context": prepared["context"],
                                    "flow_id": body.flow_id, "binding": digest([operation, prepared["owner"], prepared]), "state": "preparing"},
                                   action="learning.distinctions.prepare", actor=prepared["owner"], max_records=1000)
        except RecordConflict:
            return original(request, operation, prepared)
        if claim.get("_audit_pending"):
            return original(request, operation, prepared)
    # Actual signed issuance is bounded native custody, not synthetic attestation.
    bundles = teach._gather_signed(request, body.flow_id, sorted(body.run_ids), expected_runs=prepared["runs"])
    trust, tenant = teach._workspace_trust()
    learned = recipe_lineage.learn_choice_from_verified_bundles(bundles, trust=trust, expected_tenant=tenant, now=time.time(),
                allowed_tools=prepared["tools"], domain={**prepared["domain"], "guard_fields": prepared["fields"]}, max_operations=1)
    payload = crypto_at_rest.seal_to_str(discovery.canonical({"binding": claim["binding"], "package": learned, "review": preview(prepared)}))
    if not crypto_at_rest.is_sealed_str(payload):
        raise HTTPException(503, "The package could not be retained securely. Check the original request; nothing will repeat automatically.")
    with authority_effect_fence(), ExitStack() as locks:
        for run_id in sorted(body.run_ids):
            locks.enter_context(store.run_lock(run_id))
        locks.enter_context(store._definitions_lock())
        authority(request, prepared["context"], write=True)
        flow = teach._flow(request, body.flow_id)
        if (flow.version, flow.revision, flow.owner) != (prepared["flow"]["version"], prepared["flow"]["revision"], prepared["owner"]):
            raise HTTPException(409, "The source workflow changed. The original request remains unconfirmed; no package was published.")
        if time.time() >= expires:
            raise HTTPException(409, "The review expired before the package could be saved. Check the original request; nothing was published.")
        native, ctx = teach._episode_service(request, body.flow_id, human=True)
        for bundle in bundles:
            native.assert_bundle_current(ctx, bundle)
        authority(request, prepared["context"], write=True)
        def save(row):
            from maverick.config import get_flows

            authority(request, prepared["context"], write=True)
            if time.time() >= expires:
                raise HTTPException(409, "The review expired before the package could be saved. Check the original request; nothing was published.")
            current_flow = teach._flow(request, body.flow_id)
            if (current_flow.version, current_flow.revision, current_flow.owner) != (prepared["flow"]["version"], prepared["flow"]["revision"], prepared["owner"]):
                raise HTTPException(409, "The source workflow changed before saving. Check the original request.")
            if digest(get_flows()) != prepared["settings"]:
                raise HTTPException(409, "The learning settings changed before saving. Check the original request.")
            for bundle in bundles:
                native.assert_bundle_current(ctx, bundle)
            authority(request, prepared["context"], write=True)
            if time.time() >= expires:
                raise HTTPException(409, "The review expired before saving. Check the original request; no package was published.")
            row.update(state="saved", payload=payload)

        service.update(claim["id"], save, expected_revision=claim["revision"],
                       action="learning.distinctions.saved", actor=prepared["owner"])
    return original(request, operation, prepared)


def regions(request, flow_id, identifiers):
    tenant, owner, context = authority(request)
    if len(set(identifiers)) != len(identifiers) or not 1 <= len(identifiers) <= 20:
        raise HTTPException(422, "Choose one to twenty different native comparisons.")
    selected = []
    for identifier in identifiers:
        comparisons.view(request, identifier)
        row = comparisons.records().get(identifier)
        if row is None or (row["tenant"], row["owner"], row["flow_id"]) != (tenant, owner, flow_id):
            raise HTTPException(404, "A comparison is unavailable to this account and workflow.")
        comparisons._check(row)
        selected.append(row)
    cells = discovery.observed_cells(selected)
    by_id = {row["id"]: row for row in selected}
    for cell in cells:
        for evidence in cell["evidence"]:
            row = by_id[evidence["comparison"]]
            baseline = store.load_flow_snapshot(row["baseline"]["definition_digest"])
            evidence.update(baseline_version=baseline.version, source_when=next(case["created"] for case in row["cases"] if case["run_id"] == evidence["source_run"]))
    for row in selected:
        comparisons._check(row)
    authority(request, context)
    return {"context": context, "cells": cells, "scope": "Exact full-input observations, kept separate for each immutable published/proposed version pair. Unobserved values remain unknown. No new training use is granted.",
            "meaning": "Your expected answers are customer labels. These observations support only the selected known cases; they do not establish generalization, causal lift or business value."}
