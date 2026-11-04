"""Links from dashboard pages to the public documentation site.

``DOCS_HOME`` is the site in ``mkdocs.yml`` (``site_url``). ``PAGE_DOCS`` maps
a dashboard path (or path prefix) to the public docs page that explains it;
pages without a match fall back to the docs home. Only pages listed in
``mkdocs.public.yml`` belong here: a private engineering note must never be
linked from the product.
"""
from __future__ import annotations

DOCS_HOME = "https://daybreak-ai-labs.github.io/LightworkOS/"

# path prefix -> (label shown in "Learn more about <label>", docs page slug)
PAGE_DOCS: dict[str, tuple[str, str]] = {
    "/start": ("getting started", "getting-started"),
    "/chat": ("tasks", "starter-goals"),
    "/goals": ("tasks", "starter-goals"),
    "/goal-builder": ("tasks", "starter-goals"),
    "/deliverables": ("results", "starter-goals"),
    "/approvals": ("approvals", "governed-execution"),
    "/audit": ("the activity log", "audit-checkpoints"),
    "/spending-limits": ("spending limits", "task-limits"),
    "/spend": ("spending", "provider-spending"),
    "/billing": ("billing", "pricing-governance"),
    "/settings": ("settings", "configuration"),
    "/providers": ("AI providers", "configuration"),
    "/connections": ("connections", "connectors"),
    "/plugins": ("plugins", "plugins"),
    "/safety": ("safety", "safety"),
    "/oversight": ("oversight", "safety"),
    "/permissions": ("permissions", "safety"),
    "/external-agents": ("external agents", "external-agents"),
    "/mcp": ("agent connections", "a2a"),
    "/security/assurance": ("model assurance", "MODEL_RISK_ASSURANCE"),
    "/security": ("security", "SECURITY_GRC"),
    "/compliance": ("compliance", "compliance-assessments"),
    "/benchmarks": ("benchmarks", "benchmarks/governance-frontier"),
    "/learning": ("learning", "MODEL_IMPROVEMENT_PLATFORM"),
    "/learned": ("learning", "MODEL_IMPROVEMENT_PLATFORM"),
    "/tenants": ("workspaces", "enterprise/architecture"),
}


def docs_url(slug: str = "") -> str:
    slug = slug.strip("/")
    return DOCS_HOME + (slug + "/" if slug else "")


def learn_more_for(path: str) -> dict | None:
    """The docs link for a dashboard path, or None when no page matches.

    The longest matching prefix wins, so ``/security/assurance`` beats
    ``/security``. A prefix matches whole path segments only.
    """
    path = (path or "").rstrip("/") or "/"
    best: tuple[str, tuple[str, str]] | None = None
    for prefix, target in PAGE_DOCS.items():
        if path == prefix or path.startswith(prefix + "/"):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, target)
    if best is None:
        return None
    label, slug = best[1]
    return {"label": label, "url": docs_url(slug)}
