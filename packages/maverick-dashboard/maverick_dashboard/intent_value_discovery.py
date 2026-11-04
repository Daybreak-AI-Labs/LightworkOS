"""Owner-only consented Ekko observations, queried live without copying content."""
from __future__ import annotations

from urllib.parse import urlencode

from maverick.config import get_ekko
from maverick.work_discovery_store import EnrollmentRequired

from . import auth


def read(request, device_id="local-device"):
    from .ekko_routes import _store

    if not auth.has_permission(request, "operate") or not get_ekko().get("enable"):
        return {"state": "off", "patterns": [], "notice": "Consented external observations are available through Ekko when enabled and enrolled."}
    store = _store(request, device_id)
    if not store.path.exists():
        return {"state": "not_enrolled", "patterns": [], "notice": "Enroll a device in Ekko to review its permitted activity patterns."}
    try:
        result = store.governed_candidate_projection()
    except EnrollmentRequired:
        return {"state": "consent_unavailable", "patterns": [], "notice": "Current device consent is unavailable; prior observations are not disclosed."}
    except Exception:
        return {"state": "unavailable", "patterns": [], "notice": "Consented observations could not be read completely. This does not mean there is no opportunity."}
    return {"state": "available", "device_id": device_id,
        "notice": "These permitted external activity patterns are observations only. Application actions do not reliably establish business intent or Lightwork execution. Inspect them in Ekko; they receive no executed labor value.",
        "patterns": [{"id": item["opportunity_id"], "label": item["title"],
            "occurrences": item["occurrences"], "distinct_days": item["distinct_days"],
            "steps": item["pattern"], "evidence": item["evidence"], "intent": "unknown",
            "href": "/ekko?" + urlencode({"device_id": device_id})}
            for item in result["candidates"]]}
