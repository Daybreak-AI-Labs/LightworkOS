"""Storefront: the buyer-facing browse view over packs and connectors.

The rest of this package is the marketplace *backend* (federation, moderation,
ratings, donations, stats). This submodule is the *front* of the store: two
discoverable catalogs over capabilities that already ship, so depth reads as
something you can browse instead of a flat list.

* :func:`pack_marketplace` — the specialist packs, grouped into department
  bundles (:mod:`maverick.departments`). A buyer browses teams and the
  specialists inside them, not a thousand-row table.
* :func:`connector_marketplace` — the enterprise connectors
  (:func:`maverick.tools.enterprise_connectors.connector_catalog`), with a total
  count and substring search, so integration breadth is countable and findable.

Read-only and dependency-free: presentation over the pack registry and the
connector catalog. Respects ``[suites]`` config via the departments layer.
"""
from __future__ import annotations

from .. import departments
from ..domain import enabled_domains


def _pack_entry(profile) -> dict:
    """One specialist's marketplace card."""
    return {
        "name": profile.name,
        "description": profile.description or "",
        "max_risk": profile.max_risk or "low",
        "authoring": profile.authoring,
        "deliverable": getattr(profile.output, "deliverable", "") or "",
    }


def pack_marketplace(cfg: dict | None = None) -> list[dict]:
    """Every enabled department with its specialist roster, sorted by title.

    Shape: ``[{key, title, charter, headcount, packs: [{name, description,
    max_risk, authoring, deliverable}, ...]}, ...]``."""
    domains = enabled_domains(cfg)
    out: list[dict] = []
    for dept in departments.list_departments(cfg):
        packs = [_pack_entry(domains[n]) for n in dept.members if n in domains]
        out.append({
            "key": dept.key,
            "title": dept.title,
            "charter": dept.charter,
            "headcount": dept.headcount,
            "packs": packs,
        })
    return out


def search_packs(query: str, cfg: dict | None = None) -> list[dict]:
    """Flat specialist matches across all departments (name/description match).

    Each result carries its department for context. Empty query returns []."""
    needle = (query or "").strip().lower()
    if not needle:
        return []
    domains = enabled_domains(cfg)
    out: list[dict] = []
    for dept in departments.list_departments(cfg):
        for name in dept.members:
            prof = domains.get(name)
            if prof is None:
                continue
            if needle in f"{prof.name} {prof.description}".lower():
                entry = _pack_entry(prof)
                entry["department"] = dept.title
                entry["suite"] = dept.key
                out.append(entry)
    return out


def connector_marketplace(query: str | None = None) -> dict:
    """The connector catalog with a total and optional substring search.

    Shape: ``{"total": N, "connectors": [{name, label, env_count}, ...]}``.
    ``query`` filters on name/label; ``total`` always reflects the full catalog
    so the headline count is honest regardless of the active filter."""
    from ..tools.enterprise_connectors import connector_catalog

    catalog = connector_catalog()
    needle = (query or "").strip().lower()
    connectors = []
    for c in catalog:
        if needle and needle not in f"{c['name']} {c['label']}".lower():
            continue
        connectors.append({
            "name": c["name"],
            "label": c["label"],
            "env_count": len(c.get("env") or []),
        })
    return {"total": len(catalog), "connectors": connectors}
