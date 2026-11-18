"""Plain answers for single-computer features on a shared deployment.

Some features keep their records only on a single-computer installation: their
record collections are pinned with ``required_backend="local"``. On a
deployment whose saved records live in shared Postgres, such a collection
refuses before any I/O with ``GovernedRecordLocalOnly``. That refusal is the
deployment's shape, not an outage:

- a read the page loads on open answers 200 with ``available: false`` and
  :data:`MESSAGE` (:func:`read`);
- every other request answers 409 with :data:`REFUSAL` (the app's exception
  handler, :func:`refusal_response`);
- a page renders :data:`MESSAGE` instead of its controls (:func:`page`).

A real store failure is not this refusal. It stays 503 (or 500) and is logged
with its cause by :mod:`.store_failures`.
"""
from __future__ import annotations

from maverick.candidate_promotion import CandidatePromotionUnavailable
from maverick.governed_records import GovernedRecordLocalOnly

MESSAGE = ("This feature needs a single-computer installation of Lightwork, "
           "so it is not available on this shared deployment.")
REFUSAL = MESSAGE + " Nothing was saved or changed."


class LocalReleaseOnly(CandidatePromotionUnavailable, GovernedRecordLocalOnly):
    """Installed local workflow-release records were opened on a shared deployment.

    Release callers that already refuse ``CandidatePromotionUnavailable`` keep
    doing so; every ``GovernedRecordLocalOnly`` handler now recognises it too.
    """


def shared_deployment() -> bool:
    """Whether saved records are confirmed to live in a shared database.

    A selector that cannot be read is not answered here: the stores themselves
    report that failure, and it must not be shown as "not available here".
    """
    from maverick.governed_records import configured_governed_records_backend

    try:
        return configured_governed_records_backend() != "local"
    except Exception:  # noqa: BLE001 - the store reports a real selector failure
        return False


def unavailable(**empty) -> dict:
    """A read's answer when the feature is not available on this deployment."""
    return {**empty, "available": False, "message": MESSAGE}


def read(function, **empty):
    """Run a page's opening read; a single-computer refusal reads as unavailable."""
    try:
        return function()
    except GovernedRecordLocalOnly:
        return unavailable(**empty)


def refusal_response(request):
    """409 for a single-computer refusal that no route answered itself."""
    from fastapi.responses import JSONResponse

    from .app import _wants_html, templates

    headers = {"Cache-Control": "private, no-store"}
    if _wants_html(request):
        return templates.TemplateResponse(request, "error.html", {
            "status": 409, "title": "Not available on this deployment", "message": MESSAGE,
            "path": request.url.path, "gate": "", "reauthenticate": "", "feature": {},
        }, status_code=409, headers=headers)
    return JSONResponse({"detail": REFUSAL, "available": False, "code": "single_computer_only"},
                        status_code=409, headers=headers)


def page(request, title: str, *, section: str = "Learning", back: tuple[str, str] = ("/learning", "Back to Learning")):
    """The notice page for a single-computer feature, or None where it can run."""
    if not shared_deployment():
        return None
    from .app import templates

    return templates.TemplateResponse(request, "single_computer_only.html", {
        "section": section, "title": title, "message": MESSAGE, "back_href": back[0], "back_label": back[1],
    }, headers={"Cache-Control": "private, no-store"})
