"""Read-only protected opening of the actual independent history controls."""
from fastapi import HTTPException
from maverick.governed_operations import digest

from . import audit_checkpoint_custody_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def _current(request, selection):
    if selection:
        raise HTTPException(422, "Choose checkpoint copies in the Activity log's ordinary controls.")
    return native.state(request)


def snapshot(request, selection):
    state = _current(request, selection)
    return Snapshot(digest(state), "Independent history protection",
        "Open the complete current checkpoint copy, independent approval, Apply, Original and remote history verification controls. Opening sends and changes nothing.",
        details={"Saved Amazon accounts": len(state["accounts"]), "Saved copy requests": state["request_count"],
                 "Signed checkpoint available": state["source"] is not None})


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    state = _current(request, selection)
    if digest(state) != current.revision:
        raise HTTPException(409, "Your history protection setup or access changed. Read the current controls again.")
    return Preview(current.summary, native={"audit_checkpoint_custody_form": {"context": state["context"]}})


def entries():
    return (Adapter("audit.checkpoints.custody_controls", "Open independent history protection", "reviews",
        "/audit#independent-checkpoint-custody", ("/audit",), EmptyInput, snapshot, prepare,
        aliases=("retain audit checkpoints independently", "check independently retained audit history", "read original checkpoint copy",
                 "open independent audit history protection")),)
