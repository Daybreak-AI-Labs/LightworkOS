"""Agent Factory's reviewed draft flow for dashboard tests.

Shared by the Agent Factory, effective-access and changelog tests, so none of
them imports another test module (which breaks whenever that module is not
collected alongside it).
"""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app as dashboard_app

# Mutating /api/v1 requests carry a same-origin Origin (the CSRF contract).
client = TestClient(dashboard_app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

DRAFTS = "/api/v1/specialist-drafts"
PUBLISH_REASON = "Reviewed specialist change approved for this test"


def review_draft(name, action, *, app=None, **fields):
    """Review one Agent Factory decision on a specialist's complete draft."""
    app = app or client
    context = app.get(DRAFTS + "/history").json()["context"]
    return app.post(DRAFTS + "/review", json={"name": name, "action": action, "context": context, **fields})


def apply_draft(review, *, app=None):
    app = app or client
    return app.post(DRAFTS + "/apply", json={"token": review.json()["token"], "confirmed": True})


def publish_review(name, entered, *, reason=PUBLISH_REASON, app=None):
    """Save the complete draft, then prepare (not apply) its Publish review.

    Direct live saves are retired: a definition changes only by publishing a
    retained complete draft. Returns the first refusal, or the publish review."""
    saved = review_draft(name, "save", app=app, entered=entered)
    if saved.status_code != 200:
        return saved
    applied = apply_draft(saved, app=app)
    if applied.status_code != 200 or not applied.json().get("confirmed"):
        return applied
    # The retained draft is the saved original itself (a brand-new agent has no
    # active definition yet, so its original does not echo a draft link).
    return review_draft(name, "publish", app=app, selected="SPD-" + applied.json()["operation"], reason=reason)


def publish(name, entered, *, reason=PUBLISH_REASON, app=None):
    """Save and publish a complete draft through Agent Factory's reviewed flow."""
    review = publish_review(name, entered, reason=reason, app=app)
    if review.status_code != 200 or "token" not in review.json():
        return review
    return apply_draft(review, app=app)
