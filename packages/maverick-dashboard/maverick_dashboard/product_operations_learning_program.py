"""Reviewed instruction activation and exact whole-restore control for Copilot.

The native Learned page and Copilot use the same current-state decision. The
model selects a control only: people choose a proposal, review every affected
instruction and confirm. Recovery reads the exact original native receipt
without applying a second time. An instruction change is not evidence of improved results.
"""
from __future__ import annotations

from fastapi import HTTPException
from maverick import harness_refine
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import learning_loop_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class DecisionInput(StrictInput):
    proposal: str = Field(pattern=r"^[0-9a-f]{16}$")


def _code_practice_state(request):
    from maverick import config

    from . import learning_ops_api, training_ops_api

    context = training_ops_api._planning_context(request)
    auth.require_global_permission(request, "admin")
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current practice settings are unavailable. Review All settings before continuing.")
    try:
        status = learning_ops_api._modify_status()
    except Exception as exc:
        raise HTTPException(503, "Current practice controls could not be checked. Refresh Learning before continuing.") from exc
    if training_ops_api._planning_context(request) != context:
        raise HTTPException(409, "Your account or workspace changed. Reload Learning before continuing.")
    auth.require_global_permission(request, "admin")
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current practice settings are unavailable. Review All settings before continuing.")
    return {"context": context, "status": status}


def code_practice_snapshot(request, _selection):
    state = _code_practice_state(request)
    return Snapshot(digest(state), "Current access and settings for code practice",
                    "Open the complete practice controls. Your entered objective and rounds stay private and are kept. Opening starts no work and installs no change.",
                    details={"learning_code_practice_form": {"context": state["context"]}})


def code_practice_prepare(request, _selection, _arguments):
    state = _code_practice_state(request)
    return Preview("Review the current practice status, spending allowance and blockers, then choose an objective and rounds. A separate confirmation is required to start; opening starts nothing.",
                   native={"learning_code_practice_form": {"context": state["context"]}})


def _suggestion_state(request):
    from maverick import config

    from .app import require_page_visible
    from .draft_api import context_for

    auth.require_global_permission(request, "admin")
    require_page_visible(request, "/learned")
    context = context_for(request)
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current learning settings are unavailable. Review All settings before suggesting a change.")
    settings = harness_refine._settings()
    auth.require_global_permission(request, "admin")
    require_page_visible(request, "/learned")
    if context_for(request) != context:
        raise HTTPException(409, "Your account or workspace changed. Reload Learned before continuing.")
    return {"context": context, "enabled": settings["enable"], "approval_required": settings["require_approval"]}


def suggestion_snapshot(request, _selection):
    state = _suggestion_state(request)
    return Snapshot(digest(state), "Current instruction-suggestion access and settings",
                    "Open the existing Suggest a change form. Your entered text stays private and is kept; opening makes no suggestion or AI call.",
                    details={"instruction_suggestion_form": {"context": state["context"]}},
                    blocked="Suggested instruction changes are off. Turn them on in All settings first." if not state["enabled"] else "")


def suggestion_prepare(request, _selection, _arguments):
    state = _suggestion_state(request)
    if not state["enabled"]:
        raise HTTPException(409, "Suggested instruction changes are off. Turn them on in All settings first.")
    if _suggestion_state(request) != state:
        raise HTTPException(409, "Instruction settings changed during this check. Refresh before opening the form.")
    return Preview("Open Suggest a change and enter what went wrong, the proposed instructions and why they may help. Sending a suggestion does not apply it.",
                   native={"instruction_suggestion_form": {"context": state["context"]}})


def _state(request):
    auth.require_global_permission(request, "admin")
    rows = harness_refine.list_proposals()
    rows = native.visible_instruction_rows(request, rows)
    current = harness_refine.refinements()
    visible = {row["id"] for row in rows}
    current = [row for row in current if row.get("proposal_id") in visible]
    settings = harness_refine._settings()
    return rows, current, settings


def review_snapshot(request, _selection):
    rows, current, settings = _state(request)
    proposals = [native._proposal_view(row) for row in rows[:100]]
    details = {"instruction_changes": [{"title": row["title"], "where_used": row["target"],
                                       "instructions": row["change"], "why": row["rationale"],
                                       "decision": row["approval"] or {"pending": "Waiting to apply",
                                                                 "applied": "Applied", "reverted": "Restored",
                                                                 "reconciled_absent": "Not in use after review"}.get(row["status"], "Needs review")}
                                      for row in proposals],
               "changes_in_use": [{"title": str(row["name"]).replace("-", " "),
                                   "instructions": row["change"]} for row in current[:100]],
               "more_changes": len(rows) > 100 or len(current) > 100,
               "open_learning": {"href": "/learned", "label": "Open instruction decisions"}}
    return Snapshot(digest([rows, current, settings]), "Current instruction decisions and instructions in use",
                    "Review suggestions, approvals and the instructions currently used. Applying instructions does not establish that results improved.",
                    details=details)


def review_prepare(request, selection, _arguments):
    state = review_snapshot(request, selection)
    return Preview(state.summary, native=state.details)


def decision_snapshot(request, _selection, *, undo):
    rows, current, settings = _state(request)
    candidates = [row for row in rows if row.get("status") == ("applied" if undo else "pending")]
    if not undo:
        actor = native._actor(request)
        candidates = [row for row in candidates if row.get("proposed_by") == actor
                      and (not settings["require_approval"] or native._approval_state(row.get("approval_id")) == "Approved")]
    choices = [{"value": row["id"], "label": str(row["name"]).replace("-", " ")}
               for row in candidates[:100]]
    approval_states = [(row["id"], native._approval_state(row.get("approval_id"))) for row in candidates]
    blocked = ("No applied instruction change has a restore point to review." if undo else
               "No suggestion from your account is ready to apply. Review approvals on the Learned page.") if not choices else ""
    if not undo and not settings["enable"]:
        blocked = "Suggested instruction changes are turned off. Open Learning settings before applying."
    return Snapshot(digest([rows, current, settings, approval_states]),
                    "Current instruction proposals, approvals and instructions in use",
                    "Restore the complete earlier instruction set. The review names every instruction removed or brought back." if undo else
                    "Apply one exact approved suggestion from your account. A restore point is saved first.",
                    fields=[{"name": "proposal", "label": "Instruction change", "kind": "select",
                             "required": True, "choices": choices}], blocked=blocked)


def decision_prepare(request, selection, arguments, *, undo):
    offered = decision_snapshot(request, selection, undo=undo)
    if offered.blocked:
        raise HTTPException(409, offered.blocked)
    if arguments["proposal"] not in {choice["value"] for choice in offered.fields[0]["choices"]}:
        raise HTTPException(409, "This change is no longer available to decide. Refresh current instructions.")
    review = harness_refine.change_review(arguments["proposal"])
    plain = native.instruction_review(request, arguments["proposal"])
    if plain["revision"] != review["revision"]:
        raise HTTPException(409, "The instructions changed while preparing this review. Refresh and review again.")
    summary = ("Restore these exact reviewed instructions. Every listed removal and return is part of this decision." if undo else
               "Apply this exact reviewed instruction change. Approval is checked again, and agents use the change on new tasks.")
    return Preview(summary, changes=[{"label": change["title"],
                                     "before": change["before"] or "No instructions for this change",
                                     "after": change["after"] or "Removed"} for change in plain["changes"]],
                   native={"proposal": arguments["proposal"], "revision": review["revision"],
                           "context": plain["context"], "source_revision": plain["source_revision"],
                           "review_expires_at": plain["review_expires_at"],
                           "change": review["proposal"]["digest"], "after": digest(review["after"])})


def decision_execute(request, selection, arguments, prepared, _operation, *, undo):
    if prepared.get("proposal") != arguments["proposal"]:
        raise HTTPException(409, "The selected instruction change changed. Review it again.")
    if not prepared.get("context") or not prepared.get("source_revision"):
        raise HTTPException(409, "Open a fresh full instruction review before deciding.")
    result = native.change_current_refinement(request, arguments["proposal"], prepared["revision"], undo=undo,
                                              operation_id=_operation, context=prepared["context"],
                                              source_revision=prepared["source_revision"],
                                              review_expires_at=prepared.get("review_expires_at"))
    receipt = result.get("receipt")
    return Outcome(receipt["status"] if receipt else "unconfirmed",
                   receipt["message"] if receipt else "The original result needs checking. No decision was repeated.",
                   {"result": receipt, "current_instructions": {"href": "/learned#llp-original", "label": "Check the original decision and review current instructions"}})


def decision_recover(request, _selection, arguments, prepared, _operation, *, undo):
    if prepared.get("proposal") != arguments["proposal"]:
        raise HTTPException(409, "The selected instruction change changed. Review it again.")
    if not prepared.get("context"):
        return None
    receipt = native.original_instruction_result(request, arguments["proposal"], prepared["revision"],
                                                _operation, prepared["context"], undo=undo)
    if receipt is None:
        return None
    # A confirmed original read back here was not repeated: report it as replayed.
    return Outcome("replayed" if receipt["status"] == "confirmed" else receipt["status"], receipt["message"],
                   {"result": receipt, "current_instructions": {"href": "/learned#llp-original", "label": "Check the original decision and review current instructions"}})


def entries():
    common = {"family": "learning", "direct_ui": "/learned", "pages": ("/learned",)}
    result = [Adapter("learning.code_practice_form", "Review code-practice controls", input_model=EmptyInput,
                      snapshot=code_practice_snapshot, prepare=code_practice_prepare,
                      direct_ui="/learning#lo-modify", family="learning", pages=("/learning",),
                      aliases=("open code practice", "practice improvements to Lightwork", "review self improvement practice")),
              Adapter("learning.instruction_suggestion_form", "Suggest an instruction change", input_model=EmptyInput,
                      snapshot=suggestion_snapshot, prepare=suggestion_prepare,
                      direct_ui="/learned#llp-propose-box", family="learning", pages=("/learned",),
                      aliases=("suggest a learning improvement", "open instruction suggestion", "suggest a change")),
              Adapter("learning.instruction_decisions", "Review instruction changes", input_model=EmptyInput,
                      snapshot=review_snapshot, prepare=review_prepare,
                      aliases=("show instruction changes", "review improvement decisions"), **common)]
    for undo, identifier, label in ((False, "apply", "Apply an approved instruction change"),
                                    (True, "restore", "Restore earlier instructions")):
        result.append(Adapter("learning.instructions_" + identifier, label, input_model=DecisionInput,
                              snapshot=lambda request, selection, undo=undo: decision_snapshot(request, selection, undo=undo),
                              prepare=lambda request, selection, arguments, undo=undo: decision_prepare(request, selection, arguments, undo=undo),
                              execute=lambda request, selection, arguments, prepared, operation, undo=undo: decision_execute(request, selection, arguments, prepared, operation, undo=undo),
                              recover=lambda request, selection, arguments, prepared, operation, undo=undo: decision_recover(request, selection, arguments, prepared, operation, undo=undo),
                              read_recovery=lambda request, selection, arguments, prepared, operation, undo=undo: decision_recover(request, selection, arguments, prepared, operation, undo=undo),
                              **common))
    return tuple(result)
