"""Copilot opens complete native assessment reads and human review controls."""
from __future__ import annotations

from functools import partial

from maverick.governed_operations import digest

from . import capability_assessment_controls as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, selection, *, review):
    authority = native.authority(request, review=review)
    if not selection:
        return Snapshot(digest(authority), "Native specialist and workflow assessments",
            "Choose an assessment from the register to inspect its full findings or open its review controls.",
            blocked="Open an assessment in the register first.")
    kind, subject = native.selected(selection)
    value = native.current(request, kind, subject, review=review)
    handoff = {key: value[key] for key in ("context", "kind", "subject", "revision", "source")}
    handoff["review"] = review
    return Snapshot(digest([authority, handoff]), "Current selected native assessment",
        "Open the complete assessment in its protected native form. A person makes any decision there; opening it saves nothing.",
        details={"capability_assessment": handoff})


def prepare(request, selection, _arguments, *, review):
    value = snapshot(request, selection, review=review)
    return Preview(value.summary, native=value.details)


def entries():
    return tuple(Adapter(identifier, label, "reviews", "/assessments", ("/assessments",), EmptyInput,
        partial(snapshot, review=review), partial(prepare, review=review), aliases=aliases)
        for identifier, label, review, aliases in (
            ("reviews.capability_assessment.read", "Read selected specialist or workflow assessment", False,
             ("read this assessment", "show these assessment findings")),
            ("reviews.capability_assessment.review", "Open selected assessment review controls", True,
             ("review this assessment", "approve this privacy review", "assessment needs work")),
        ))
