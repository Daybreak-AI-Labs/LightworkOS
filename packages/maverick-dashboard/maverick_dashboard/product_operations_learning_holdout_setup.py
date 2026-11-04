"""The native location/initialization reviews, with pure original readback."""
from __future__ import annotations

from . import learning_holdout_setup_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot


def _details(state):
    return {"Current readiness": state.get("current", state.get("message")), "Scope": native.SCOPE,
            "Open record controls": {"href": native.PAGE, "label": "Open record controls"}}


def snapshot(request, _selection, *, action=None):
    state = native.current(request)
    return Snapshot(state["revision"], "Current learning location, record check and retained initialization request",
                    native.SCOPE, details=_details(state), blocked=state[action + "_blocked"] if action else "")


def prepare(request, _selection, _arguments, *, action):
    reviewed = native.prepare(request, action)
    return Preview("Initialize this exact selected record once." if action == "initialize" else "Choose the managed location; initialization stays a separate reviewed step.",
                   changes=native.changes(reviewed), native=reviewed)


def execute(request, _selection, _arguments, prepared, operation):
    result = native.save(request, prepared, operation)
    return Outcome("confirmed" if result["confirmed"] else "unconfirmed", result["message"], _result_details(result))


def _result_details(result):
    return {**_details(result), "Open original setup": {"href": "/learned?holdout_request=" + result["operation"] + "#learning-holdout-setup", "label": "Open original setup"}}


def recover(request, _selection, _arguments, prepared, operation, *, read_only=False):
    if native._owned(request, operation) is None and not read_only:
        return None
    result = native.original(request, operation, prepared=prepared)
    return Outcome("replayed" if result["confirmed"] else "unconfirmed", result["message"], _result_details(result))


def entries():
    common = {"family": "learning", "direct_ui": native.PAGE, "pages": ("/learning", "/learned"), "input_model": EmptyInput}
    return (
        Adapter("learning.read_holdout_record", "Read the unseen-question record", snapshot=snapshot,
                prepare=lambda r, s, a: Preview("Read the current record check. No question is used or work repeated.", native=_details(native.current(r))), **common),
        *(Adapter(identifier, label, snapshot=lambda r, s, action=action: snapshot(r, s, action=action),
                   prepare=lambda r, s, a, action=action: prepare(r, s, a, action=action), execute=execute, recover=recover,
                   read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common)
          for action, identifier, label in (
              ("location", "learning.setup_holdout_location", "Choose the unseen-question record location"),
              ("initialize", "learning.initialize_holdout_record", "Initialize the unseen-question record"))),
    )
