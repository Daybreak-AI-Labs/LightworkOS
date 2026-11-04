"""Copilot opens the same protected ordinary questionnaire builder."""
from fastapi import HTTPException
from maverick.governed_operations import digest

from . import compliance_questionnaire_builder as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

_PAGE = "/compliance/scoping#cs-questionnaire-design"


def snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Choose a questionnaire in the protected design form.")
    value = native.catalog(request)
    return Snapshot(digest(value), "Questionnaire design", "Create a questionnaire or review a new version in the ordinary protected form. Your draft questions and conditions stay outside the model guide.",
                    {"Saved questionnaires": len(value["sources"]), "open": {"label": "Open questionnaire design", "href": _PAGE}}, [])


def prepare(request, selection, _arguments):
    snapshot(request, selection)
    return Preview("Choose and review your questions and scope rules in Lightwork. The full form saves through the native independent-approval process.",
                   native={"form_handoff": "compliance-questionnaire", "context": native.context(request), "open": {"label": "Open questionnaire design", "href": _PAGE}})


def entries():
    return (Adapter("compliance.questionnaire.build", "Build or update a compliance questionnaire", "preferences", _PAGE,
                    ("/compliance/scoping",), EmptyInput, snapshot, prepare,
                    aliases=("create questionnaire", "edit questionnaire", "design compliance questions")),)
