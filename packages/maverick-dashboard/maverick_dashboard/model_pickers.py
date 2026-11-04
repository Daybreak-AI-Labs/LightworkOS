"""Grouped model choices for Settings > Models.

Builds, from the shipped catalog plus the cached live discovery, one group per
provider: what the saved connection can reach (live), what the catalog knows
(catalog), and the discovery status the admin sees. The pickers offer the
configured providers plus whatever the admin allow-listed; every provider is
listed in the allow-list so an admin can approve models before setting it up.
"""
from __future__ import annotations

import os
import re
import time

CUSTOM = "__custom__"
_VALID_SPEC = re.compile(r"[A-Za-z0-9_.:/@-]{1,128}")
_STATUS_TEXT = {
    "pending": "Not checked yet. Refresh to list the models this connection can reach.",
    "unconfigured": "Set up this service under Provider keys to use it.",
    "disabled": "Live discovery is switched off; showing the shipped catalog.",
    "unsupported": "No model-list endpoint; pick from the catalog or type a model id.",
    "configured": "Using the model saved in your connection.",
}


def age(seconds: float | None) -> str | None:
    """A short 'refreshed …' phrase, or None when never refreshed."""
    if seconds is None:
        return None
    seconds = max(0.0, float(seconds))
    if seconds < 90:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} d ago"


def config_catalog() -> list[str]:
    """Admin additions from ``[models] catalog`` in config.toml (validated)."""
    try:
        from maverick.config import load_config
        raw = (load_config().get("models", {}) or {}).get("catalog") or []
    except Exception:  # pragma: no cover -- config read fails soft
        return []
    out: list[str] = []
    for spec in raw:
        s = str(spec).strip()
        if s and s not in out and _VALID_SPEC.fullmatch(s):
            out.append(s)
    return out


def _configured_cloud_model(name: str) -> str:
    """Offer the exact customer deployment/model selected in provider setup."""
    fields = {"azure": ("deployment", "AZURE_OPENAI_DEPLOYMENT"),
              "bedrock": ("model_id", "BEDROCK_MODEL_ID"),
              "vertex": ("model_id", "VERTEX_MODEL_ID")}
    if name not in fields:
        return ""
    try:
        from maverick.config import get_provider_config

        table = get_provider_config(name) or {}
        field, env = fields[name]
        env_value = str(os.environ.get(env, "") or "").strip()
        saved = str(table.get(field) or "").strip()
        # The Vertex client takes the saved model over the environment, so the
        # picker offers that one; Azure and Bedrock take the environment first.
        value = (saved or env_value) if name == "vertex" else (env_value or saved)
        return value if _VALID_SPEC.fullmatch(f"{name}:{value}") else ""
    except Exception:
        return ""


def _group(name: str, label: str, row: dict | None, entry: dict, enabled: bool, now: float) -> dict:
    from maverick.llm import MODEL_CATALOG
    from maverick.model_discovery import DISCOVERABLE, UNSUPPORTED, spec_for

    configured = bool(row and row.get("configured"))
    supported = name in DISCOVERABLE
    status = entry.get("status")
    if supported and not enabled:
        status = "disabled"
    elif not status:
        status = "unsupported" if not supported else ("pending" if configured else "unconfigured")
    reported = list(entry.get("models") or []) if enabled and configured and status in {"live", "unavailable"} else []
    live = reported if status == "live" and not entry.get("stale", True) else []
    live_set = set(live)
    catalog = list(MODEL_CATALOG.get(name, []))
    customer_model = _configured_cloud_model(name)
    if customer_model and customer_model not in catalog:
        catalog.append(customer_model)
    if customer_model and configured and status in {"unsupported", "disabled"}:
        status = "configured"
    catalog_set = set(catalog)
    ids = list(dict.fromkeys(reported + catalog))
    fetched_at = entry.get("fetched_at")
    if status == "live":
        detail = entry.get("detail") or f"{len(live)} models reachable with the configured connection"
    elif status == "unavailable":
        detail = entry.get("detail") or "the model list could not be read"
    else:
        detail = UNSUPPORTED.get(name) or _STATUS_TEXT.get(status, "")
    if status == "unconfigured" and name == "ollama":
        detail = "Add your model server's address under Provider keys. Ollama does not require an API key."
    return {
        "name": name,
        "label": label,
        "configured": configured,
        "supported": supported,
        "status": status,
        "detail": detail,
        "fetched_ago": age(now - fetched_at) if isinstance(fetched_at, (int, float)) else None,
        "stale": bool(entry.get("stale")),
        "live_count": len(live),
        "previous_count": len(reported) if not live else 0,
        "last_attempt_ago": age(now - entry["last_attempt_at"]) if isinstance(entry.get("last_attempt_at"), (int, float)) else None,
        "models": [
            {"spec": spec_for(name, m), "id": m, "live": m in live_set, "catalog": m in catalog_set,
             "last_known": m in reported and m not in live_set}
            for m in ids
        ],
    }


def build(providers: list[dict], allow: set[str]) -> dict:
    """Template context: provider groups, picker optgroups and discovery summary.

    ``providers`` are the settings-store rows (name, label, configured); ``allow``
    is the admin allow-list, which caps what the pickers offer.
    """
    from maverick import model_discovery
    from maverick.llm import MODEL_CATALOG, PROVIDER_LABELS

    discovered = model_discovery.snapshot()
    enabled = model_discovery.discovery_enabled()
    now = time.time()
    rows = {p["name"]: p for p in providers}
    order = list(rows) + [n for n in MODEL_CATALOG if n not in rows]
    groups = [
        _group(name, rows.get(name, {}).get("label") or PROVIDER_LABELS.get(name) or name,
               rows.get(name), discovered.get(name) or {}, enabled, now)
        for name in order
    ]
    from maverick.model_guidance import describe
    from maverick.model_guidance import enabled as model_guidance_enabled
    guidance_enabled = model_guidance_enabled()
    metadata = {}
    if guidance_enabled:
        for group in groups:
            entry = discovered.get(group["name"]) or {}
            for model in group["models"]:
                metadata[model["spec"]] = describe(model["spec"], provider=group["name"],
                    capability=(entry.get("capabilities") or {}).get(model["id"]),
                    fetched_at=entry.get("fetched_at"), stale=bool(entry.get("stale", True)))
    known = {m["spec"] for g in groups for m in g["models"]}
    custom = [s for s in config_catalog() if s not in known]
    if custom:
        groups.append({
            "name": "custom", "label": "Custom (config)", "configured": True, "supported": False,
            "status": "catalog", "detail": "Added by [models] catalog in config.toml.",
            "fetched_ago": None, "stale": False, "live_count": 0,
            "models": [{"spec": s, "id": s, "live": False, "catalog": True} for s in custom],
        })
    picker_groups = []
    for g in groups:
        options = [m for m in g["models"] if not allow or m["spec"] in allow]
        if not options:
            continue
        if g["configured"]:
            picker_groups.append({"label": g["label"], "options": options})
        elif allow:
            # The admin approved these explicitly: the pickers mirror the
            # allow-list even before that provider is set up.
            picker_groups.append({"label": g["label"] + " (not set up)", "options": options})
    offered = {m["spec"] for pg in picker_groups for m in pg["options"]}
    leftovers = sorted(allow - known - set(custom)) if allow else []
    if leftovers:
        picker_groups.append({"label": "Allowed", "options": [
            {"spec": s, "id": s, "live": False, "catalog": False} for s in leftovers]})
        offered.update(leftovers)
    fetched = [e.get("fetched_at") for e in discovered.values()
               if isinstance(e.get("fetched_at"), (int, float))]
    return {
        "model_groups": groups,
        "model_guidance": metadata,
        "model_guidance_enabled": guidance_enabled,
        "picker_groups": picker_groups,
        "offered_specs": sorted(offered),
        "discovery_enabled": enabled,
        "configured_count": sum(1 for g in groups if g["configured"] and g["name"] != "custom"),
        "live_count": sum(1 for g in groups if g["status"] == "live" and not g["stale"]),
        "last_refresh_ago": age(now - max(fetched)) if fetched else None,
        "custom_marker": CUSTOM,
    }


def chosen(form, field: str) -> str:
    """The submitted model for ``field``: the picker value, or the typed id when
    the picker says custom. Whitespace-trimmed; empty means 'clear'."""
    value = (form.get(field) or "").strip()
    if value == CUSTOM:
        value = (form.get(field + "_custom") or "").strip()
    return value
