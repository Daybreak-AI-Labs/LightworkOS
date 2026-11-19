"""Pages that froze or stalled the hosted demo render in the worker pool.

Each page reads its settings and permissions and renders the shared shell, all
file reads (about 290 per page on the demo's network volume). As ``async def``
handlers they ran on the event loop, where every other request waited behind
them; FastAPI runs a plain ``def`` handler in its worker pool.
"""
from __future__ import annotations

import inspect

import pytest
from maverick_dashboard import (
    ai_evidence_analysis_page,
    assessment_evidence_autopopulation_page,
    consent_custom_index_page,
    regulatory_obligations_page,
)
from maverick_dashboard.app import app, templates

APP_PAGES = (
    "/third-party/intelligence",
    "/compliance/continuous-evidence",
    "/third-party/lifecycle",
    "/privacy/rights-orchestration",
    "/privacy/data-discovery",
    "/privacy/rights-consumer-delivery",
    "/consent/profile-data",
    "/privacy/regulatory-intelligence",
)
ROUTER_PAGES = (
    (ai_evidence_analysis_page.create_ai_evidence_analysis_page_router, "/ai-evidence-analysis"),
    (assessment_evidence_autopopulation_page.create_assessment_evidence_autopopulation_page_router,
     "/assess/evidence-autopopulation"),
    (consent_custom_index_page.create_consent_custom_index_page_router, "/consent/custom-indexes"),
    (regulatory_obligations_page.create_regulatory_obligations_page_router, "/compliance/obligations"),
)


def _endpoints(routes, path: str) -> list:
    return [
        route.endpoint for route in routes
        if getattr(route, "path", None) == path and "GET" in getattr(route, "methods", ())
    ]


@pytest.mark.parametrize("path", APP_PAGES)
def test_page_renders_in_the_worker_pool_not_on_the_event_loop(path: str) -> None:
    endpoints = _endpoints(app.routes, path)
    assert endpoints, path
    assert not any(inspect.iscoroutinefunction(endpoint) for endpoint in endpoints), path


@pytest.mark.parametrize(("create", "path"), ROUTER_PAGES)
def test_workbench_renders_in_the_worker_pool_not_on_the_event_loop(create, path: str) -> None:
    endpoints = _endpoints(create(templates).routes, path)
    assert endpoints, path
    assert not any(inspect.iscoroutinefunction(endpoint) for endpoint in endpoints), path
