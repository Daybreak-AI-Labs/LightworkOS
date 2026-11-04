"""Copilot opens the same complete private lesson-test review and originals."""
from __future__ import annotations

from maverick.governed_operations import digest

from . import learning_transfers as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, _selection):
    value = native.catalog(request)
    return Snapshot(digest([value["context"], value.get("revision"), value["available"]]),
        "Test lessons on another model", native.NOTICE,
        blocked=value.get("problem", "") if not value["available"] else "")


def prepare(request, _selection, _arguments):
    value = native.catalog(request)
    return Preview("Choose the two models and read every current lesson, test question, supplied instruction and spending limit in the complete native form. This opens the form without starting any AI test.",
        native={"learning_transfer_form": {"context": value["context"], "original": False},
                "open": {"label": "Review a lesson test", "href": native.PAGE}})


def original_snapshot(request, selection):
    context = native.authority(request)
    selected = selection.get("kind") == "learning_transfer" and selection.get("operation")
    if not selected:
        return Snapshot(digest([context, "none"]), "Your original lesson test", "Read the accepted original request without repeating work.",
                        blocked="Choose one of your original lesson tests on the Learned page first.")
    row = native.original(request, selection["operation"])
    return Snapshot(digest(row), "Your original lesson test", row["message"])


def original_prepare(request, selection, _arguments):
    row = native.original(request, selection["operation"])
    return Preview(row["message"], native={"learning_transfer_form": {"context": row["context"], "original": True},
        "open": {"label": "Read this original lesson test", "href": "/learned?learning_transfer=" + row["operation"] + "#learning-transfers"}})


def entries():
    common = {"family": "learning", "pages": ("/learned",), "direct_ui": native.PAGE}
    return (Adapter("learning.lesson_transfer_form", "Test lessons on another model", input_model=EmptyInput,
                    snapshot=snapshot, prepare=prepare, **common),
            Adapter("learning.read_original_transfer", "Read the selected original lesson test", input_model=EmptyInput,
                    snapshot=original_snapshot, prepare=original_prepare, **common))
