"""Copilot opens the same read-only ordinary walkthrough."""
from fastapi import HTTPException

from .product_operations import Adapter, EmptyInput, Preview, Snapshot
from .product_tour import PAGES, state


def _read(request, selection):
    if selection:
        raise HTTPException(422, "Open a supported main page to take its tour.")
    page = getattr(request.state, "product_operations_page", None)
    if page not in PAGES:
        raise HTTPException(404, "Open a supported main page to take its tour.")
    return state(request, page)


def snapshot(request, selection):
    value = _read(request, selection)
    return Snapshot(value["revision"], "A quick tour of this page",
        "Point to the real controls and explain the next step. Your draft stays intact. Nothing is sent, started or changed.",
        blocked="" if value["available"] else value["detail"])


def prepare(request, selection, _arguments):
    value = _read(request, selection)
    return Preview("Open the same ordinary page tour. Opening help starts nothing.", native={
        "product_tour_review": {"scope": "current_page", "context": value["context"]}})


def entries():
    return (Adapter("help.product_tour", "Take a quick tour", "artifacts", "/start", PAGES,
        EmptyInput, snapshot, prepare, aliases=("take a quick tour", "show me how to use Lightwork",
        "show me this page", "walk me through this page")),)
