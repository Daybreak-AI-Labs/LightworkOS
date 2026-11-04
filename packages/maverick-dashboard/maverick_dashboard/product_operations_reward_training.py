"""Current-source local training and original-result Copilot controls."""
import time

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import BaseModel, ConfigDict

from . import reward_model_training as native
from .product_operations import TTL, Adapter, Outcome, Preview, Snapshot


class Empty(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def snapshot(request, _selection):
    state, _rows = native.current(request)
    return Snapshot(state["revision"], "Current eligible local task outlines", native.NOTICE,
                    native.evidence_counts(state["evidence"]), fields=state["choices"],
                    blocked="There are no usable comparisons with recorded, distinguishable steps on both attempts. Missing steps cannot establish which attempt is better." if not state["can_review"] else "")


def prepare(request, _selection, arguments):
    state, _rows = native.current(request)
    reviewed = native.prepare(request, {**arguments, "context": state["context"], "revision": state["revision"]})
    return Preview(native.NOTICE, changes=native.review_rows(reviewed),
                   native={"prepared": reviewed, "expires": time.time() + min(600, TTL)})


def _checked(arguments, prepared):
    body = prepared["prepared"]["body"]
    if arguments != {key: body[key] for key in ("min_margin", "max_pairs", "epochs", "lr")}:
        raise HTTPException(409, "The training options changed after review. Review them again.")


def execute(request, selection, arguments, prepared, operation):
    _checked(arguments, prepared)
    row = native.start(request, prepared["prepared"], operation, expires=prepared["expires"])
    return _outcome(row)


def _outcome(row):
    state = "confirmed" if row["published"] else "queued" if row.get("job") and row["job"]["worker_available"] else "unconfirmed"
    details = {"Meaning": native.NOTICE, "Saved result": row.get("result") or "Not confirmed", "Request status": row["message"],
               "Open saved result": {"href": "/learning?reward_request=" + row["operation"] + "#lo-rm-h", "label": "Check original training result"}}
    if isinstance(details["Saved result"], dict):
        result = details["Saved result"]
        details["Saved result"] = {"Comparisons": result["pairs"], "Outlines": result["outlines"],
                                  "Agreement on training comparisons": str(round(result["accuracy"] * 100)) + "%",
                                  **native.evidence_counts(result.get("evidence"))}
    return Outcome(state, row["message"], details=details)


def recover(request, selection, arguments, prepared, operation, *, read_only=False):
    _checked(arguments, prepared)
    existing = native._owned(request, operation)
    if existing is None and not read_only:
        return None
    if existing is not None:
        actor = native.learning_ops_api._actor(request)
        if existing["binding"] != digest([actor, prepared["prepared"]["body"]["context"], operation, prepared["prepared"]]):
            raise HTTPException(409, "This request belongs to a different training review. Read its original result.")
    return _outcome(native.original(request, operation))


def read_snapshot(request, selection):
    native.authority(request, historical=True)
    if selection.get("kind") != "reward_training" or not selection.get("operation"):
        return Snapshot(digest([native.authority(request, historical=True), "none"]), "Saved original local training request",
                        native.NOTICE, blocked="Choose Check original training result in Learning first.")
    row = native.original(request, selection["operation"])
    return Snapshot(digest(row), "Saved original local training request", row["message"])


def read_prepare(request, selection, _arguments):
    row = native.original(request, selection["operation"])
    outcome = _outcome(row)
    return Preview(row["message"], native=outcome.details)


def entries():
    common = {"family": "learning", "pages": ("/learning",), "direct_ui": native.PAGE}
    return (Adapter("learning.train_local_ranking", "Train a local ranking model", input_model=native.Choices,
                    snapshot=snapshot, prepare=prepare, execute=execute, recover=recover,
                    read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
            Adapter("learning.read_local_ranking", "Read the selected original ranking training", input_model=Empty,
                    snapshot=read_snapshot, prepare=read_prepare, **common))
