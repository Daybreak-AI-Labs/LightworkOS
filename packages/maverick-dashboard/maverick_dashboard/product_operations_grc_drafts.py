"""Protected native GRC draft review and original-result handoffs."""
from __future__ import annotations

from maverick.governed_operations import digest

from . import grc_draft_changes as native
from .product_operations import Adapter, Preview, Snapshot, StrictInput


class EmptyIn(StrictInput):
    pass


def snapshot(request, _selection):
    value = native.catalog(request)
    return Snapshot(digest(value), "Current authorized blueprint studio", native.NOTICE)


def prepare(request, _selection, _arguments, *, original=False):
    value = native.catalog(request)
    return Preview("Open the protected original-save lookup without repeating a write. A retained original review is required in this browser." if original else "Choose ordinary blueprint controls, review every saved choice and confirm the draft in the protected studio. This handoff saves nothing.",
        native={"Scope": native.NOTICE, "grc_draft_form": {"context": value["context"], "original": original},
                "open": {"label": "Read original draft save" if original else "Review a blueprint draft", "href": native.PAGE + ("#grcs-save-original" if original else "#grcs-builder-panel")}})


def entries():
    common = {"family": "artifacts", "pages": (native.PAGE,), "direct_ui": native.PAGE, "input_model": EmptyIn, "snapshot": snapshot}
    return (Adapter("grc.draft.review", "Review and save a blueprint draft", prepare=prepare, **common),
            Adapter("grc.draft.original", "Read an original blueprint draft save", prepare=lambda r, s, a: prepare(r, s, a, original=True), **common))
