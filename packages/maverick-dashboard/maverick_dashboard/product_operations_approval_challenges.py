"""Copilot uses the same reviewed local challenge controls as the native page."""
from __future__ import annotations

from functools import partial
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import approval_challenges_api as native
from . import auth
from .draft_api import context_for
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput

_PAGE = "/learning/approval-challenges"


def _report(plain):
    result = plain["result"]
    return {"source": plain["source"], "fictional_change": plain["title"], "required_sign_offs": plain["quorum"],
            "when": plain["when"], "saved_result": plain["status"], "practice_steps": plain["steps"], "declared_limits": plain["bounds"],
            "local_check": "Selected sign-off blocked; no final vote retained" if result["current"] and result["blocked"] and not result["vote_recorded"] else "Review the saved local outcome before relying on it",
            "explanation": plain["explanation"], "limits": plain["limitations"],
            "open": {"label": "Review challenge and file controls", "href": _PAGE + "?record=" + plain["id"]}}


class GenerateInput(StrictInput):
    family: Literal["claim_changed", "card_changed", "round_changed", "expired"]
    quorum: int = Field(ge=1, le=2)


class RecordInput(StrictInput):
    record: str = Field(pattern=r"^ACP-[a-f0-9]{32}$")


class SetupInput(StrictInput):
    enabled: bool


def snapshot(request, selection, *, action):
    if selection:
        raise HTTPException(422, "Choose this local challenge in the review.")
    value = native._call(lambda: native.choices(request))
    fields, blocked = [], ""
    if action == "generate":
        fields = [{"name": "family", "label": "Fictional approval change", "kind": "select", "required": True, "choices": value["patterns"]},
                  {"name": "quorum", "label": "Required sign-offs", "kind": "select", "required": True, "choices": [{"value": 1, "label": "One reviewer"}, {"value": 2, "label": "Two reviewers"}]}]
        if not value["enabled"]:
            blocked = "An installation administrator can turn on local approval challenges here."
    elif action == "setup":
        auth.require_global_permission(request, "admin")
        fields = [{"name": "enabled", "label": "Allow local approval challenges", "kind": "boolean", "value": value["enabled"]}]
    else:
        offered = [row for row in value["records"] if action == "review" or row.get("can_" + action)]
        fields = [{"name": "record", "label": "Saved practice challenge", "kind": "select", "required": True,
                   "choices": [{"value": row["id"], "label": row["title"] + " · " + row["when"] + " · " + row["status"]} for row in offered]}]
        if not offered:
            blocked = "No recently saved challenge offers this action. Open Approval challenges to browse earlier records or import a file."
    details = {"permission": "On" if value["enabled"] else "Off", "source": "Practice scenario; no customer incident",
               "recent_records": [{"pattern": row["title"], "when": row["when"], "status": row["status"]} for row in value["records"][:20]],
               "open": {"label": "Open Approval challenges and file import", "href": _PAGE}}
    return Snapshot(digest([value["context"], value["enabled"], value["records"], native.source.adapter_version()]),
                    "Current local challenge permission and your saved practice results",
                    "Generate or receive a fictional approval scenario, check the this installation’s approval safeguards in a disposable local copy, and explicitly review export. This does not install a live safeguard or establish complete protection.",
                    details, fields, blocked)


def prepare(request, selection, arguments, *, action):
    snapshot(request, selection, action=action)
    value = native.choices(request)
    if action == "generate":
        native._allowed()
        artifact = native.source.compile_challenge(arguments["family"], arguments["quorum"])
        return Preview("Build the selected small fictional approval scenario and check it against this installation’s approval safeguards in a fresh disposable copy. No customer settings, credentials or requests are copied. No AI call, live safeguard activation or export occurs.",
                       [{"label": "Fictional change", "after": native.source.FAMILIES[arguments["family"]]}, {"label": "Required sign-offs", "after": arguments["quorum"]},
                        {"label": "Execution allowance", "after": "One local check, at most 10 seconds; one request and two reviewers"}],
                       {"artifact": artifact})
    if action == "setup":
        return Preview("Allow fictional approval challenges and isolated local checks on this installation. Every check and export remains separately reviewed." if arguments["enabled"] else "Stop creating and checking local challenges. Existing records remain reviewable.",
                       [{"label": "Local approval challenges", "before": "On" if value["enabled"] else "Off", "after": "On" if arguments["enabled"] else "Off"}], {"previous": value["enabled"]})
    row = native._call(lambda: native.visible(request, arguments["record"]))
    plain = native._plain(row)
    if action != "review" and not plain.get("can_" + action):
        raise HTTPException(409, "This challenge no longer offers that action. Refresh and review its current state.")
    if action == "review":
        return Preview("This is a practice scenario and an earlier local result. Check the source and limits, what the check covers and whether this installation has changed here; import and download use the controls on this page.", native=_report(plain))
    summary = {"check": "Run this exact imported supported practice file against this installation’s approval safeguards in a fresh disposable copy. No customer settings, credentials, live requests or AI calls are used.",
               "export": "Authorize only this exact practice scenario and sign-off count for sharing. The shared file includes its declared limits and checks that refuse outdated sign-offs; it contains no customer incident, private values, account or request identity, local timing or software details. A recipient must review and check it separately. Nothing is activated in production.",
               "resolve": "Record the interrupted original check as unknown. No check is repeated and no protection is claimed.",
               "remove": "Remove this inactive saved practice and its local result, freeing a saved-record slot. Its decision receipt stays in the activity history. Previously shared files are not recalled. A check in progress cannot be removed."}[action]
    return Preview(summary, [{"label": "Fictional change", "after": plain["title"]}, {"label": "Required sign-offs", "after": plain["quorum"]},
                             {"label": "Current result", "after": plain["status"]}], {"record": row["id"], "revision": row["revision"],
                             **({"original_removal": row["remove_operation"]} if action == "remove" and row["state"] == "removing" else {})})


def execute(request, _selection, arguments, prepared, operation, *, action):
    context = context_for(request)
    if action == "generate":
        if prepared != {"artifact": native.source.compile_challenge(arguments["family"], arguments["quorum"])}:
            raise HTTPException(409, "This practice scenario changed. Review it again.")
        result = native._call(lambda: native.generate(request, native.Generate(context=context, confirm=True, operation=operation, **arguments)))
    elif action == "setup":
        result = native.setup(request, native.Setup(context=context, confirm=True, previous=prepared["previous"], enabled=arguments["enabled"]))
    else:
        if prepared["record"] != arguments["record"]:
            raise HTTPException(409, "The selected practice challenge changed. Review it again.")
        result = native._call(lambda: getattr(native, action)(request, arguments["record"], native.ActionReview(context=context, confirm=True, revision=prepared["revision"], operation=prepared.get("original_removal", operation))))
    link = {"label": "Review current practice challenge", "href": _PAGE + ("?record=" + result["record"]["id"] if "record" in result else "")}
    return Outcome("confirmed", result["detail"], {**(_report(result["record"]) if "record" in result else {}), "open": link})


def recover(request, _selection, arguments, prepared, operation, *, action):
    if action == "setup":
        native._bound(request)
        auth.require_global_permission(request, "admin")
        if native.source.enabled() == arguments["enabled"]:
            return Outcome("unconfirmed", "The current practice setting matches this review. The original change is not confirmed. No change was repeated.")
        return None
    identity = "ACP-" + operation if action == "generate" else arguments["record"]
    if action == "remove":
        retired = native.removal(request, identity)
        if (retired and retired["operation"] == prepared.get("original_removal", operation)
                and prepared["revision"] in {retired["reviewed_revision"], retired["source_revision"]}
                and not retired.get("_audit_pending") and native.records().get(identity) is None):
            return Outcome("replayed", "The original saved practice removal is confirmed. Its decision receipt is retained; nothing was removed again.",
                           {"open": {"label": "Open current practice records", "href": _PAGE}})
        return None
    try:
        row = native.visible(request, identity)
    except HTTPException as exc:
        if exc.status_code == 404:
            return None
        raise
    if action == "generate" and (row["artifact"]["family"] != arguments["family"] or row["artifact"]["quorum"] != arguments["quorum"]):
        return None
    if action in {"check", "export", "resolve"}:
        if action == "check" and row["state"] == "prepared" and row["revision"] == prepared["revision"]:
            return None
        if row.get(action + "_operation") != operation or row.get(action + "_review_revision") != prepared["revision"]:
            return None
    plain = native._plain(row)
    return Outcome("replayed", plain["status"] + ". The original saved state was read; no check or export was repeated.",
                   _report(plain))


def entries():
    return tuple(Adapter("learning.approval_challenges_" + action, label, "learning", _PAGE, (_PAGE, "/learning"), model,
                         partial(snapshot, action=action), partial(prepare, action=action),
                         None if action == "review" else partial(execute, action=action), None if action == "review" else partial(recover, action=action), aliases)
                 for action, label, model, aliases in (
                     ("generate", "Build and check an approval challenge", GenerateInput, ("test approval race locally", "build executable approval challenge")),
                     ("review", "Review a practice approval challenge", RecordInput, ("review local approval check", "import approval challenge file")),
                     ("check", "Check an imported approval challenge", RecordInput, ("check approval challenge locally",)),
                     ("export", "Authorize a practice challenge export", RecordInput, ("share approval challenge",)),
                     ("resolve", "Resolve an interrupted local approval check", RecordInput, ("resolve approval challenge check",)),
                     ("remove", "Remove an inactive approval practice record", RecordInput, ("remove saved approval challenge", "make space for approval practice")),
                     ("setup", "Change local approval challenge permission", SetupInput, ("turn local approval challenges on", "turn local approval challenges off"))))
