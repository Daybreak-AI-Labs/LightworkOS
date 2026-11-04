"""Reviewed Copilot controls call the same work-value authorization and CAS APIs."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import intent_value_api as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class MetricInput(StrictInput):
    scope: Literal["own", "company"] = "own"
    start: str = ""
    end: str = ""


class WorkInput(StrictInput):
    identifier: str = Field(pattern=r"^IVW-[a-f0-9]{32}$")


class CorrectInput(WorkInput):
    intents: str = Field(max_length=300)
    additional_activity: str = Field(default="", max_length=100)
    deliverables: int = Field(default=1, ge=1, le=50)
    size: Literal["standard", "large"] = "standard"
    reason: str = Field(min_length=1, max_length=1000)


class ProposalInput(StrictInput):
    identifier: str = Field(pattern=r"^IVR-[a-f0-9]{32}$")


class DecisionInput(ProposalInput):
    decision: Literal["defer", "decline", "reopen", "adjust"]
    keep_preparation_manual: bool = False


def metric_snapshot(request, _selection):
    result = native.synced_report(request)
    return Snapshot(digest(result["totals"]), "Shared authorized work-value service",
        result["notice"], fields=[{"name": "scope", "label": "Scope", "kind": "select", "required": True,
            "choices": [{"value": "own", "label": "My work"}, {"value": "company", "label": "Company totals"}]},
            {"name": "start", "label": "Start date (YYYY-MM-DD; empty means this month)", "kind": "text"},
            {"name": "end", "label": "End date (YYYY-MM-DD; empty means today)", "kind": "text"}])


def metric_prepare(request, _selection, arguments):
    result = native.synced_report(request, **arguments)
    return Preview("Audit-backed work and economic estimates for the selected UTC period.", native={
        "Metrics": result["totals"], "Scope": result["scope"], "Assumptions": result["notice"],
        "Evidence": {"href": "/work-value", "label": "Inspect contributing work and calculations"}})


def snapshot_for(kind):
    def snapshot(request, _selection):
        native.authority(request, write=True)
        native.settings.retry_pending()
        if kind in {"correct", "recalculate", "confirm"}:
            rows = native.records(request)
        else:
            rows = native.synced_opportunities(request, include_decided=True)["opportunities"]
        fields = [{"name": "identifier", "label": "Work item" if kind in {"correct", "recalculate", "confirm"} else "Opportunity",
            "kind": "select", "required": True, "choices": [{"value": row["id"], "label": row["label"] + " · " + row["id"][-8:]} for row in rows]}]
        if kind == "correct":
            activities = [{"value": "", "label": "Unknown / no additional activity"}] + [
                {"value": item["id"], "label": item["label"]} for item in native.taxonomy.catalog()]
            fields += [{"name": "intents", "label": "Business activity", "kind": "select", "choices": activities},
                {"name": "additional_activity", "label": "Additional activity, if any", "kind": "select", "choices": activities},
                {"name": "deliverables", "label": "Number of deliverables for each selected activity", "kind": "number", "value": 1, "required": True},
                {"name": "size", "label": "Scope", "kind": "select", "required": True, "choices": [
                    {"value": "standard", "label": "Fits the benchmark component"}, {"value": "large", "label": "Larger/uncertain; leave unvalued"}]},
                {"name": "reason", "label": "Correction reason", "kind": "text", "required": True}]
        if kind == "decision":
            fields += [{"name": "decision", "label": "Your decision", "kind": "select", "required": True,
                "choices": [{"value": value, "label": label} for value, label in (("defer", "Defer"), ("decline", "Keep current process"), ("reopen", "Reopen"), ("adjust", "Adjust manual steps"))]},
                {"name": "keep_preparation_manual", "label": "Also retain preparation as a manual step", "kind": "checkbox"}]
        disabled = kind == "confirm" and not native.settings.settings()["completion_confirmation"]
        return Snapshot(digest([(row["id"], row["revision"]) for row in rows]), "Current owned work and opportunity records",
            "Inspect and confirm this change. Source evidence is preserved; drafts never activate themselves.",
            fields=fields, blocked="Optional completion confirmation is turned off." if disabled else "No authorized records are available." if not rows else "")
    return snapshot


def prepare_for(kind):
    def prepare(request, _selection, arguments):
        identifier = arguments["identifier"]
        row = (native.work(request, identifier, write=True) if kind in {"correct", "recalculate", "confirm"}
               else native.recommendation(request, identifier, write=True))
        changes = [{"label": "Record", "before": row["label"], "after": kind}]
        if kind == "correct":
            selected = [item for item in (arguments["intents"], arguments["additional_activity"]) if item]
            if any(native.taxonomy.definition(item) is None for item in selected):
                raise HTTPException(422, "Choose a known business activity.")
            changes.append({"label": "Business activities", "before": row["label"], "after": ", ".join(native.taxonomy.definition(item)["label"] for item in selected) or "Unknown"})
            changes.append({"label": "Deliverables per activity", "after": str(arguments["deliverables"])})
        return Preview("Review the selected record and requested change. No execution will start.", changes=changes,
            native={"revision": row["revision"], "arguments": arguments})
    return prepare


def execute_for(kind):
    def execute(request, _selection, arguments, prepared, _operation):
        identifier, revision = arguments["identifier"], prepared["revision"]
        if kind == "correct":
            intents = [item for item in (arguments["intents"], arguments["additional_activity"]) if item]
            body = native.CorrectionIn(revision=revision, intents=intents,
                                      units={item.split(".")[0]: arguments["deliverables"] for item in intents},
                                      size=arguments["size"], reason=arguments["reason"])
            result = native.correct_endpoint(request, identifier, body)
        elif kind == "recalculate":
            result = native.recalculate_endpoint(request, identifier, native.RevisionIn(revision=revision))
        elif kind == "confirm":
            result = native.confirm_endpoint(request, identifier, native.RevisionIn(revision=revision))
        elif kind == "decision":
            manual = ["inputs", "review"] + (["prepare"] if arguments["keep_preparation_manual"] else [])
            result = native.decision_endpoint(request, identifier, native.DecisionIn(revision=revision, decision=arguments["decision"], manual_steps=manual))
        elif kind == "use":
            result = native.use_endpoint(request, identifier, native.RevisionIn(revision=revision))
        else:
            result = native.build_endpoint(request, identifier, native.RevisionIn(revision=revision))
        pending = result.get("state") == "audit_pending"
        return Outcome("unconfirmed" if pending else "confirmed",
            "Audit delivery is pending. Refresh before continuing." if pending else result.get("message", "Change saved with history; source execution evidence is unchanged."),
            {"Inspect": {"href": result.get("href", "/work-value"), "label": "Inspect the result"}})
    return execute


def entries():
    common = {"family": "learning", "direct_ui": "/work-value", "pages": ("/work-value",)}
    rows = [Adapter("learning.work_value_read", "Read work value and costs", input_model=MetricInput,
        snapshot=metric_snapshot, prepare=metric_prepare, **common)]
    for kind, label, model in (("correct", "Correct detected business activity", CorrectInput),
            ("recalculate", "Recalculate a work estimate", WorkInput), ("confirm", "Record optional completion opinion", WorkInput), ("decision", "Decide on a work opportunity", DecisionInput),
            ("use", "Use an existing capability for an opportunity", ProposalInput), ("build", "Create a reviewable workflow draft", ProposalInput)):
        rows.append(Adapter("learning.work_value_" + kind, label, input_model=model,
            snapshot=snapshot_for(kind), prepare=prepare_for(kind), execute=execute_for(kind), **common))
    from .product_operations_intent_value_settings import entries as settings_entries
    return (*rows, *settings_entries(common))
