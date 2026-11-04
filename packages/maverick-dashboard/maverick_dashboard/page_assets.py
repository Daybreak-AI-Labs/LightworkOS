"""Static scripts for the administration pages rebuilt in plain language.

Each file gets an explicit route (the dashboard serves only registered
assets); unknown names are never matched here.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, Response

router = APIRouter()
_STATIC = Path(__file__).parent / "static"
ASSETS = (
    "cytoscape-3.30.2.min.js",
    "lightwork-settings-catalog-requests.js",
    "lightwork-runtime-policy-recovery.js",
    "lightwork-today.js",
    "lightwork-department-board.js",
    "lightwork-department-team-updates.js",
    "lightwork-starter-teams.js",
    "lightwork-starter-team-schedules.js",
    "lightwork-employee-activation.js",
    "lightwork-budget-guidance.js",
    "lightwork-task-diagnostics.js",
    "lightwork-devices.js",
    "lightwork-read-aloud.js",
    "lightwork-run-status.js",
    "lightwork-session.js",
    "lightwork-approvals-count.js",
    "lightwork-theme-preview.js",
    "lightwork-i18n.js",
    "lightwork-model-guidance.js",
    "lightwork-flow-retirement.js",
    "lightwork-model-tests.js",
    "lightwork-notification-health.js",
    "lightwork-notification-badge.js",
    "lightwork-personal-notifications.js",
    "lightwork-comments.js",
    "lightwork-policy-suggestions.js",
    "lightwork-digest-preview.js",
    "lightwork-result-feedback.js",
    "lightwork-help-menu.js",
    "lightwork-practice.js",
    "lightwork-usage-measures.js",
    "lightwork-settings-admin.js",
    "lightwork-tenants.js",
    "lightwork-typeahead.js",
    "lightwork-compliance.js",
    "lightwork-retention-maintenance.js",
    "lightwork-compliance-scoping.js",
    "lightwork-compliance-questionnaire-builder.js",
    "lightwork-plugin-practice.js",
    "lightwork-compliance-scope-actions.js",
    "lightwork-dsar-detail.js",
    "lightwork-dsar-handoff.js",
    "lightwork-privacy-notice-governance.js",
    "lightwork-privacy-notice-proposals.js",
    "lightwork-privacy-rights-form.js",
    "lightwork-privacy-regulatory-intelligence.js",
    "lightwork-privacy-rights-consumer-delivery.js",
    "lightwork-privacy-rights-orchestration.js",
    "lightwork-red-team-schedules.js",
    "lightwork-learning-loop.js",
    "lightwork-learning-acquisition.js",
    "lightwork-learning-flywheel.js",
    "lightwork-learning-jobs.js",
    "lightwork-learning-test-cases.js",
    "lightwork-learning-holdout-setup.js",
    "lightwork-model-answer-scoring.js",
    "lightwork-reward-model-training.js",
    "lightwork-manual-skill-removal.js",
    "lightwork-learning-passes.js",
    "lightwork-learning-transfers.js",
    "lightwork-learning-calibration.js",
    "lightwork-audit-actions.js",
    "lightwork-decision-evidence.js",
    "lightwork-commitment-capability.js",
    "lightwork-work-restructuring.js",
    "lightwork-competence-transport.js",
    "lightwork-private-task-computation.js",
    "lightwork-recovery-visibility.js",
    "lightwork-procedure-interactions.js",
    "lightwork-request-program.js",
    "lightwork-operator-acquisition.js",
    "lightwork-governed-rule-evolution.js",
    "lightwork-applicability-regions.js",
    "lightwork-agent-override-changes.js",
    "lightwork-access-key-requests.js",
    "lightwork-automation-imports.js",
    "lightwork-report-downloads.js",
    "lightwork-capability-assessments.js",
    "lightwork-generated-tool-removal.js",
    "lightwork-workflow-step-checks.js",
    "lightwork-commitment-economic-alternatives.js",
    "lightwork-flow-requalification.js",
    "lightwork-learning-distinctions.js",
    "lightwork-learning-pending-cases.js",
    "lightwork-value-proof.js",
    "lightwork-assurance-forms.js",
    "lightwork-feature-actions.js",
    "lightwork-ops-panels.js",
    "lightwork-tax.js",
    "lightwork-task-changes.js",
    "lightwork-viewpoints.js",
    "lightwork-usability-survey.js",
    "lightwork-web-vitals.js",
    "lightwork-assessment-review.js",
    "lightwork-policy-exceptions.js",
    "lightwork-schedule-setup.js",
)
# Page stylesheets served next to their scripts (the shell itself is one
# stylesheet, lightwork.css; its translation rules live there).
STYLES: tuple[str, ...] = ("lightwork-schedule-management.css",)


@router.get("/static/lightwork-i18n-catalog/{language}/{revision}.js", include_in_schema=False)
def journey_catalog(language: str, revision: str, request: Request) -> Response:
    """Serve only shipped public copy, independently of session preferences."""
    from .i18n import LANGS
    from .i18n_journeys import browser_catalog_asset

    if language not in LANGS or len(revision) != 64:
        raise HTTPException(404, "No such product catalog")
    current, content = browser_catalog_asset(language)
    if revision != current:
        raise HTTPException(404, "No such product catalog")
    # GZip middleware can choose a different encoding of the same catalog.
    etag = f'W/"{current}"'
    headers = {"Cache-Control": "public, max-age=31536000, immutable",
               "ETag": etag, "X-Content-Type-Options": "nosniff"}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(content, media_type="application/javascript; charset=utf-8", headers=headers)


def _route(name: str):
    async def serve() -> FileResponse:
        return FileResponse(_STATIC / name, media_type="application/javascript; charset=utf-8",
                            headers={"Cache-Control": "public, max-age=300"})
    serve.__name__ = "asset_" + name.replace("-", "_").replace(".", "_")
    return serve


for _name in ASSETS:
    router.add_api_route("/static/" + _name, _route(_name), methods=["GET"], include_in_schema=False)


def _style_route(name: str):
    async def serve() -> FileResponse:
        return FileResponse(_STATIC / name, media_type="text/css; charset=utf-8",
                            headers={"Cache-Control": "public, max-age=300"})
    serve.__name__ = "asset_" + name.replace("-", "_").replace(".", "_")
    return serve


for _name in STYLES:
    router.add_api_route("/static/" + _name, _style_route(_name), methods=["GET"], include_in_schema=False)
