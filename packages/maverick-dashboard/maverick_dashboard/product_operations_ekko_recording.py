"""Read-only Copilot handoff to the ordinary consented Ekko recorder controls."""
from __future__ import annotations

from fastapi import HTTPException

from . import ekko_ops_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Open Ekko to choose your device and recording permissions.")
    state = native.recording_options(request)
    return Snapshot(state["context"], "Open the complete activity recording controls",
        "Choose this enrolled device and confirm what Ekko may record before starting. "
        "Opening the controls never records activity or changes your choices.",
        {"automatic_recording_available": state["active_app"],
         "availability": state["availability_message"], "computer": state["platform"]})


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    return Preview(current.summary, native={"ekko_recording_review": {
        "scope": "current_page", "context": current.revision}})


def discovery_snapshot(request, selection):
    current = snapshot(request, selection)
    return Snapshot(current.revision, "Review Ekko's automation opportunities",
        "Open the current device's evidence, describe the job, and review a workflow or assistant draft. "
        "Recorded activity stays in the protected page; it is not sent to Copilot. "
        "Opening this review does not record activity, save a draft, or run work.")


def discovery_prepare(request, selection, _arguments):
    current = discovery_snapshot(request, selection)
    return Preview(current.summary, native={"ekko_discovery_review": {
        "scope": "current_page", "context": current.revision}})


def planning_snapshot(request, selection):
    current = snapshot(request, selection)
    return Snapshot(current.revision, "Open your private opportunity workspace",
        "Review saved plans, benefit assumptions and owner-reported pilot results on the protected Ekko page. "
        "Task notes and recorded activity stay outside this conversation. Opening the workspace does not save or start work.")


def planning_prepare(request, selection, _arguments):
    current = planning_snapshot(request, selection)
    return Preview(current.summary, native={"ekko_planning_review": {
        "scope": "current_page", "context": current.revision}})


def entries():
    from .product_operations_ekko_factory import entries as factory_entries

    return (*factory_entries(), Adapter("learning.ekko_recording_controls", "Open activity recording controls", "learning",
        "/ekko#ekko-recording", ("/ekko",), EmptyInput, snapshot, prepare,
        aliases=("record the apps I use", "open activity recording controls",
                 "start recording activity", "how can Ekko record activity")),
        Adapter("learning.ekko_discovery_review", "Review repeated work with Ekko", "learning",
            "/ekko#ekko-opportunities-heading", ("/ekko",), EmptyInput, discovery_snapshot, discovery_prepare,
            aliases=("find work to automate", "review Ekko suggestions", "turn repeated work into a workflow")),
        Adapter("learning.ekko_planning_review", "Open private opportunity plans", "learning",
            "/ekko#ekko-planning", ("/ekko",), EmptyInput, planning_snapshot, planning_prepare,
            aliases=("review my automation shortlist", "record an Ekko pilot result", "estimate automation benefit")))
