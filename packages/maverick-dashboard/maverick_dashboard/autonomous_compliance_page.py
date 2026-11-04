"""Autonomous Compliance product landing page (Govern -> Autonomous Compliance).

The six compliance suites already ship as separate dashboard pages scattered
across several nav groups. This page presents them as ONE product -- the
compliance platform run by governed agents -- each module carrying an honest
shipped / preview / external status badge and a link to the real module page.
Status is read from ``maverick.compliance_catalog``,
the single source of truth, so the product surface can never claim more than
the capability review supports.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from .auth import require_permission

PAGE_PATH = "/autonomous-compliance"


#: One plain sentence per module, shown on its card instead of the page address.
MODULE_SUMMARIES: dict[str, str] = {
    "/governance-agents": "Ready-made agents that keep your AI inventory and reviews up to date.",
    "/ai-entity-tasks": "Review and fix-up tasks for each AI system you use.",
    "/ai-evidence-analysis": "Read uploaded documents and pull out evidence about your AI systems.",
    "/privacy": "Assessments, vendors, data requests, breaches and consent in one place.",
    "/privacy/rights-orchestration": "Handle requests from people to see, correct or delete their data.",
    "/privacy/data-discovery": "Scan your storage to find where personal data lives.",
    "/privacy/notice-governance": "Approve and publish new versions of your privacy notices.",
    "/privacy/drop": "Handle California deletion and opt-out requests.",
    "/privacy/rights-form": "Let people submit privacy requests from your website.",
    "/consent": "Record and honour what each person agreed to.",
    "/consent/publishing": "Publish your consent banner and preference center.",
    "/consent/global-opt-out": "Honour browser opt-out signals such as Global Privacy Control.",
    "/consent/scan-inventory": "Scan your websites for cookies and trackers.",
    "/compliance": "See which regulations you meet and what still needs doing.",
    "/compliance/continuous-evidence": "Collect proof that your controls keep working.",
    "/security/governance": "Prepare for the EU AI Act and train your people.",
    "/assess/evidence-autopopulation": "Fill in assessment answers from evidence you already have.",
    "/third-party/intelligence": "Watch your vendors for risk signals.",
    "/third-party/lifecycle": "Onboard, review and offboard vendors step by step.",
    "/third-party/contracts": "Keep vendor contracts and engagements on record.",
    "/data-use": "Decide what data may be used for which purpose.",
    "/data-use/providers": "Apply your data-use rules inside your data platforms.",
}

#: Plain meanings for the three status labels (the catalog's own wording is
#: written for reviewers).
STATUS_MEANINGS: dict[str, str] = {
    "shipped": "Ready to use today.",
    "preview": "Works, but is still being expanded. Try it and tell us what you need.",
    "external": "Needs an outside service, licence or certification before it can be used.",
}


def visible_suites(suites, not_ready) -> list:
    """The catalog with every module held back from users removed, and any
    suite left empty dropped: the landing must never link a visitor into a
    workbench the sidebar and finder deliberately do not offer."""
    from dataclasses import replace

    out = []
    for suite in suites:
        modules = tuple(m for m in suite.modules if m.path not in not_ready)
        if modules:
            out.append(suite if len(modules) == len(suite.modules) else replace(suite, modules=modules))
    return out


def landing_context() -> dict:
    """The landing's suites, cards and labels (the page, and the Compliance
    page's Overview tab)."""
    from maverick import compliance_catalog as catalog

    from . import ui_visibility

    catalog_suites = visible_suites(catalog.suites(), ui_visibility.not_ready_paths())
    return {
        "suites": catalog_suites,
        "module_count": sum(len(s.modules) for s in catalog_suites),
        "status_order": catalog.STATUS_ORDER,
        "status_labels": catalog.STATUS_LABELS,
        "status_meanings": {**catalog.STATUS_MEANINGS, **STATUS_MEANINGS},
        "module_summaries": MODULE_SUMMARIES,
        # Each card names its page exactly as the sidebar and heading do.
        "page_names": {page["path"]: page["label"] for page in ui_visibility.PAGES},
        "status_badge_class": catalog.STATUS_BADGE_CLASS,
    }


def create_autonomous_compliance_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    """Create the store-free Autonomous Compliance product landing router."""

    if not isinstance(templates, Jinja2Templates):
        raise TypeError(
            "Autonomous compliance page requires a Jinja template authority"
        )
    router = APIRouter(tags=["autonomous-compliance"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def landing(request: Request) -> Response:
        require_permission(request, "view")
        if any(
            key not in {"theme", "density", "font", "lang"}
            for key in request.query_params
        ):
            raise HTTPException(
                status_code=404, detail="Autonomous compliance unavailable"
            )
        # In areas navigation the landing is the Compliance page's Overview tab.
        from .navigation_api import areas_redirect

        moved = areas_redirect(request)
        if moved is not None:
            return moved
        response = templates.TemplateResponse(
            request, "autonomous_compliance.html", landing_context()
        )
        return with_landing_headers(response)

    return router


def with_landing_headers(response: Response) -> Response:
    """The landing's own caching and indexing headers, wherever it renders."""
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return response


__all__ = ["MODULE_SUMMARIES", "PAGE_PATH", "create_autonomous_compliance_page_router",
           "landing_context", "with_landing_headers"]
