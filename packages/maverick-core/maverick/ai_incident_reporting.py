"""EU AI Act Article 73 serious-incident reporting: clocks, drafts, routing.

The AI Act's serious-incident regime is NOT the GDPR breach regime, and this
module deliberately shares nothing with the Article 33 72-hour clock in the
privacy register. Under Regulation (EU) 2024/1689 (consolidated 2026-07-27),
providers of high-risk AI systems report serious incidents to the **market
surveillance authority of the Member State where the incident occurred**
(Art. 73(1)), on a tiered clock anchored to *awareness*:

  * **15 days** — the default for a serious incident (Art. 73(2));
  * **2 days**  — for a widespread infringement (Art. 3(61)) or a serious
    incident that is a serious and irreversible disruption of critical
    infrastructure (Art. 3(49)(b)) (Art. 73(3));
  * **10 days** — in the event of the death of a person (Art. 73(4)).

An incomplete *initial* report may be submitted first and followed by a
*complete* report (Art. 73(5)), which is why the lifecycle here separates the
two. When more than one window applies, the strictest one binds.

The module layers on the Model Risk & AI Assurance Officer's incident
register: a serious-incident declaration cites an existing assurance incident
and never duplicates its content. Everything consequential is a **human
assertion** — the category classification, the causal-link status, and every
submission carry a named actor and timestamp, and this module never contacts
an authority itself. The clock math and the report draft are operational
aids, not legal advice, and no output of this module is a conformity claim.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from . import model_risk_assurance as mra
from .governed_records import GovernedRecordStore

SCHEMA = "lightwork.ai-serious-incident.v1"

#: Versioned advisory metadata, mirroring the assurance officer's convention:
#: citations are data with a basis version, never bare strings in prose.
REGULATION_METADATA = {
    "regulation": "Regulation (EU) 2024/1689",
    "consolidated": "2026-07-27",
    "source": "https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng",
    "articles": ("Art. 3(49)", "Art. 3(61)", "Art. 73"),
}

REPORTING_NOTICE = (
    "Deadline calculations and report drafts are operational aids prepared "
    "from operator assertions. They are not legal advice, not a conformity "
    "assessment, and not a submission; a named human classifies the incident "
    "and files with the market surveillance authority."
)

_DAY_SECONDS = 86_400

#: Art. 3(49) categories. ``window_days``/``deadline_citation`` carry the
#: paragraph of Art. 73 that binds when the category applies on its own.
SERIOUS_INCIDENT_CATEGORIES: dict[str, dict[str, Any]] = {
    "death": {
        "label": "Death of a person",
        "category_citation": "Art. 3(49)(a)",
        "window_days": 10,
        "deadline_citation": "Art. 73(4)",
    },
    "serious_health_harm": {
        "label": "Serious harm to a person's health",
        "category_citation": "Art. 3(49)(a)",
        "window_days": 15,
        "deadline_citation": "Art. 73(2)",
    },
    "critical_infrastructure_disruption": {
        "label": (
            "Serious and irreversible disruption of the management or "
            "operation of critical infrastructure"
        ),
        "category_citation": "Art. 3(49)(b)",
        "window_days": 2,
        "deadline_citation": "Art. 73(3)",
    },
    "fundamental_rights_infringement": {
        "label": (
            "Infringement of obligations under Union law intended to "
            "protect fundamental rights"
        ),
        "category_citation": "Art. 3(49)(c)",
        "window_days": 15,
        "deadline_citation": "Art. 73(2)",
    },
    "serious_property_or_environment_harm": {
        "label": "Serious harm to property or the environment",
        "category_citation": "Art. 3(49)(d)",
        "window_days": 15,
        "deadline_citation": "Art. 73(2)",
    },
}

CAUSAL_LINK_STATUSES = ("established", "reasonably_likely", "under_investigation")

#: Lifecycle. Art. 73(5) allows a complete report without an initial one, so
#: ``declared`` may go straight to ``complete_reported``. Withdrawal is the
#: human-gated exit for a declaration that review found not to be a serious
#: incident; terminal states accept nothing further.
_TRANSITIONS = {
    "declared": frozenset({"initial_reported", "complete_reported", "withdrawn"}),
    "initial_reported": frozenset({"complete_reported", "withdrawn"}),
    "complete_reported": frozenset(),
    "withdrawn": frozenset(),
}

#: EU-27 Member State codes for Art. 73(1) routing. A code outside this set is
#: refused rather than guessed at — mis-routing a statutory report is worse
#: than asking the operator to pick again.
EU_MEMBER_STATES = frozenset({
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE",
})

_MAX_RECORDS = 5_000
_MAX_TEXT = 4_000
_MAX_NAME = 256

_STORE = GovernedRecordStore(
    "ai_serious_incidents", "ASI", "ai_serious_incident"
)


class AIIncidentReportingConfigError(RuntimeError):
    """The [ai_incident_reporting] section is missing, off, or unreadable."""


def get_reporting_config() -> dict[str, Any]:
    """Read and validate the closed, default-off global configuration."""

    try:
        from .config import config_source_errors, load_global_config

        config = load_global_config()
        if config_source_errors(include_tenant=False) or not isinstance(config, dict):
            raise AIIncidentReportingConfigError(
                "ai-incident-reporting configuration is unreadable"
            )
    except AIIncidentReportingConfigError:
        raise
    except Exception as exc:
        raise AIIncidentReportingConfigError(
            "ai-incident-reporting configuration is unavailable"
        ) from exc
    section = config.get("ai_incident_reporting") or {}
    if not isinstance(section, dict):
        raise AIIncidentReportingConfigError("ai_incident_reporting must be a table")
    unknown = set(section) - {"enable"}
    if unknown:
        raise AIIncidentReportingConfigError(
            f"unknown ai_incident_reporting keys: {', '.join(sorted(unknown))}"
        )
    enable = section.get("enable", False)
    if not isinstance(enable, bool):
        raise AIIncidentReportingConfigError(
            "ai_incident_reporting.enable must be a boolean"
        )
    return {"enable": enable}


def enabled() -> bool:
    try:
        return bool(get_reporting_config()["enable"] is True and mra.enabled())
    except Exception:
        return False


def _require_enabled() -> None:
    if not enabled():
        raise AIIncidentReportingConfigError(
            "AI Act incident reporting is off; set [ai_incident_reporting] "
            "enable = true (requires [model_risk_assurance])"
        )


def _text(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ValueError(f"{label} must be between 1 and {limit} characters")
    return text


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a numeric timestamp")
    stamp = float(value)
    if stamp <= 0:
        raise ValueError(f"{label} must be positive")
    return stamp


def classify_deadline(category: str, *, widespread: bool = False) -> dict[str, Any]:
    """The binding Art. 73 window for one classification. Pure.

    ``widespread`` (Art. 3(61)) forces the 2-day clock of Art. 73(3); when a
    category carries its own shorter window the strictest applies.
    """

    token = str(category or "").strip().lower()
    entry = SERIOUS_INCIDENT_CATEGORIES.get(token)
    if entry is None:
        raise ValueError(
            "category must be one of: "
            + ", ".join(sorted(SERIOUS_INCIDENT_CATEGORIES))
        )
    if not isinstance(widespread, bool):
        raise ValueError("widespread must be a boolean")
    window = int(entry["window_days"])
    citation = str(entry["deadline_citation"])
    if widespread and window > 2:
        window, citation = 2, "Art. 73(3)"
    return {
        "category": token,
        "category_citation": entry["category_citation"],
        "window_days": window,
        "window_seconds": window * _DAY_SECONDS,
        "deadline_citation": citation,
        "widespread": widespread,
    }


def _declaration_id(incident_id: str) -> str:
    """A fresh ASI id per declaration; a withdrawn one never blocks a redo."""

    seed = json.dumps([incident_id, uuid.uuid4().hex], separators=(",", ":"))
    return "ASI-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def _find_assurance_incident(incident_id: str) -> dict[str, Any]:
    wanted = _text(incident_id, "incident_id", _MAX_NAME)
    for row in mra.list_incidents():
        if row.get("id") == wanted:
            return row
    raise KeyError(f"assurance incident {wanted!r} is not recorded")


def declare_serious_incident(
    incident_id: str,
    *,
    category: str,
    widespread: bool = False,
    became_aware_at: float,
    causal_link: str,
    member_state: str,
    authority: str,
    declared_by: str,
    notes: str = "",
) -> dict[str, Any]:
    """Classify one assurance incident as an Art. 3(49) serious incident.

    The declaration is a human assertion: it cites the existing incident, the
    named Member State whose market surveillance authority receives the report
    (Art. 73(1)), and starts the binding clock from ``became_aware_at``.
    Nothing is transmitted anywhere.
    """

    _require_enabled()
    incident = _find_assurance_incident(incident_id)
    deadline = classify_deadline(category, widespread=widespread)
    link = str(causal_link or "").strip().lower()
    if link not in CAUSAL_LINK_STATUSES:
        raise ValueError(
            "causal_link must be one of: " + ", ".join(CAUSAL_LINK_STATUSES)
        )
    state = str(member_state or "").strip().upper()
    if state not in EU_MEMBER_STATES:
        raise ValueError(
            "member_state must be an EU-27 country code for Art. 73(1) routing"
        )
    aware = _timestamp(became_aware_at, "became_aware_at")
    occurred = float(incident.get("occurred_at") or 0.0)
    if occurred and aware + 1e-6 < occurred:
        raise ValueError("became_aware_at cannot precede the incident itself")
    operator = _text(declared_by, "declared_by", _MAX_NAME)
    note = str(notes or "").strip()[:_MAX_TEXT]

    for row in _STORE.list(limit=_MAX_RECORDS):
        if (
            row.get("incident_id") == incident["id"]
            and row.get("status") != "withdrawn"
        ):
            raise ValueError(
                f"incident {incident['id']} already has an active "
                "serious-incident declaration"
            )

    record = {
        "id": _declaration_id(incident["id"]),
        "schema": SCHEMA,
        "incident_id": incident["id"],
        "asset_id": incident.get("asset_id"),
        "incident_revision": incident.get("revision"),
        **deadline,
        "occurred_at": occurred or None,
        "became_aware_at": aware,
        "report_due_at": aware + deadline["window_seconds"],
        "causal_link": link,
        "member_state": state,
        "authority": _text(authority, "authority", _MAX_NAME),
        "declared_by": operator,
        "notes": note,
        "status": "declared",
        "submissions": [],
        "regulation": dict(REGULATION_METADATA),
        "legal_certification": False,
    }
    return _STORE.create(
        record,
        action="declare_serious_incident",
        actor=operator,
        max_records=_MAX_RECORDS,
    )


def _transition(record: dict[str, Any], target: str) -> None:
    current = str(record.get("status") or "")
    if target not in _TRANSITIONS.get(current, frozenset()):
        raise ValueError(
            f"serious-incident transition {current} -> {target} is invalid"
        )
    record["status"] = target


def record_submission(
    record_id: str,
    *,
    kind: str,
    submitted_by: str,
    submitted_at: float,
    reference: str,
    expected_revision: int,
) -> dict[str, Any] | None:
    """Record that a named human filed the Art. 73 report with the authority.

    ``kind`` is ``initial`` (an incomplete report to stop the clock, Art.
    73(5)) or ``complete``. A submission after the deadline is still recorded
    — the register must reflect what happened — but is flagged ``late``.
    """

    _require_enabled()
    report_kind = str(kind or "").strip().lower()
    if report_kind not in ("initial", "complete"):
        raise ValueError("kind must be 'initial' or 'complete'")
    operator = _text(submitted_by, "submitted_by", _MAX_NAME)
    stamp = _timestamp(submitted_at, "submitted_at")
    proof = _text(reference, "reference", _MAX_NAME)

    def _mutate(record: dict[str, Any]) -> None:
        target = (
            "initial_reported" if report_kind == "initial" else "complete_reported"
        )
        _transition(record, target)
        record["submissions"] = [
            *record.get("submissions", []),
            {
                "kind": report_kind,
                "submitted_by": operator,
                "submitted_at": stamp,
                "reference": proof,
                "late": stamp > float(record.get("report_due_at") or 0.0),
                "recorded_at": time.time(),
            },
        ]

    return _STORE.update(
        str(record_id or ""),
        _mutate,
        expected_revision=expected_revision,
        action="record_serious_incident_submission",
        actor=operator,
    )


def withdraw_declaration(
    record_id: str,
    *,
    rationale: str,
    reviewer: str,
    expected_revision: int,
) -> dict[str, Any] | None:
    """Human-gated exit for a declaration review found not serious."""

    _require_enabled()
    reason = _text(rationale, "rationale", _MAX_TEXT)
    operator = _text(reviewer, "reviewer", _MAX_NAME)

    def _mutate(record: dict[str, Any]) -> None:
        _transition(record, "withdrawn")
        record["withdrawal"] = {
            "rationale": reason,
            "reviewer": operator,
            "withdrawn_at": time.time(),
        }

    return _STORE.update(
        str(record_id or ""),
        _mutate,
        expected_revision=expected_revision,
        action="withdraw_serious_incident_declaration",
        actor=operator,
    )


def report_clock(record: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    """The live clock for one declaration. Terminal states have no clock."""

    current = time.time() if now is None else _timestamp(now, "now")
    due = float(record.get("report_due_at") or 0.0)
    status = str(record.get("status") or "")
    running = status == "declared"
    return {
        "status": status,
        "report_due_at": due,
        "deadline_citation": record.get("deadline_citation"),
        "seconds_remaining": max(0.0, due - current) if running else 0.0,
        "overdue": bool(running and current > due),
    }


def list_declarations(
    *,
    status: str | None = None,
    now: float | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Declarations with their clocks, most urgent first."""

    _require_enabled()
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")
    wanted = str(status or "").strip().lower() or None
    if wanted is not None and wanted not in _TRANSITIONS:
        raise ValueError(
            "status must be one of: " + ", ".join(sorted(_TRANSITIONS))
        )
    records = _STORE.list(limit=_MAX_RECORDS + 1)
    if len(records) > _MAX_RECORDS:
        raise ValueError("serious-incident inventory exceeds its supported capacity")
    rows = []
    for record in records:
        if wanted is not None and record.get("status") != wanted:
            continue
        rows.append({**record, "clock": report_clock(record, now=now)})
    rows.sort(key=lambda row: (not row["clock"]["overdue"], row["report_due_at"]))
    return rows[:limit]


def overdue_declarations(*, now: float | None = None) -> list[dict[str, Any]]:
    """Unreported declarations past their Art. 73 deadline."""

    return [
        row
        for row in list_declarations(now=now)
        if row["clock"]["overdue"]
    ]


def get_declaration(record_id: str) -> dict[str, Any] | None:
    _require_enabled()
    return _STORE.get(str(record_id or ""))


def render_report(record_id: str, *, now: float | None = None) -> str:
    """A bounded Art. 73 report draft for the routed authority.

    Drafted from recorded assertions only; carries citations and the
    non-certification notice, and never any content beyond the bounded
    incident summary already held by the assurance register.
    """

    _require_enabled()
    record = _STORE.get(str(record_id or ""))
    if record is None:
        raise KeyError(f"serious-incident declaration {record_id!r} is not recorded")
    incident = _find_assurance_incident(str(record.get("incident_id")))
    clock = report_clock(record, now=now)
    submissions = record.get("submissions") or []
    lines = [
        "# Serious-incident report (draft)",
        "",
        f"Prepared under {REGULATION_METADATA['regulation']} Art. 73, "
        f"consolidated {REGULATION_METADATA['consolidated']}.",
        "",
        "## 1. Routing (Art. 73(1))",
        f"- Member State where the incident occurred: {record['member_state']}",
        f"- Market surveillance authority: {record['authority']}",
        "",
        "## 2. AI system",
        f"- Assurance asset: {record.get('asset_id')}",
        f"- Assurance incident: {record['incident_id']} "
        f"(revision {record.get('incident_revision')})",
        "",
        "## 3. Classification",
        f"- Category: {SERIOUS_INCIDENT_CATEGORIES[record['category']]['label']} "
        f"({record['category_citation']})",
        f"- Widespread infringement (Art. 3(61)): "
        f"{'yes' if record.get('widespread') else 'no'}",
        f"- Binding deadline: {record['window_days']} day(s) from awareness "
        f"({record['deadline_citation']})",
        "",
        "## 4. Timeline",
        f"- Occurred at: {record.get('occurred_at')}",
        f"- Provider became aware at: {record['became_aware_at']}",
        f"- Report due at: {record['report_due_at']}"
        + (" — OVERDUE" if clock["overdue"] else ""),
        f"- Causal link: {record['causal_link']}",
        "",
        "## 5. Incident description",
        str(incident.get("summary") or "")[:_MAX_TEXT],
        "",
        "## 6. Evidence citations",
    ]
    citations = incident.get("evidence_citations") or []
    if citations:
        lines.extend(
            f"- {citation.get('record_id')} (revision {citation.get('revision')})"
            for citation in citations
        )
    else:
        lines.append("- none recorded")
    lines.extend([
        "",
        "## 7. Submissions recorded",
    ])
    if submissions:
        lines.extend(
            f"- {row['kind']} filed by {row['submitted_by']} at "
            f"{row['submitted_at']}"
            + (" (late)" if row.get("late") else "")
            for row in submissions
        )
    else:
        lines.append("- none recorded")
    if record.get("notes"):
        lines.extend(["", "## 8. Operator notes", record["notes"]])
    lines.extend(["", "---", REPORTING_NOTICE])
    return "\n".join(lines)


__all__ = [
    "AIIncidentReportingConfigError",
    "CAUSAL_LINK_STATUSES",
    "EU_MEMBER_STATES",
    "REGULATION_METADATA",
    "REPORTING_NOTICE",
    "SCHEMA",
    "SERIOUS_INCIDENT_CATEGORIES",
    "classify_deadline",
    "declare_serious_incident",
    "enabled",
    "get_declaration",
    "get_reporting_config",
    "list_declarations",
    "overdue_declarations",
    "record_submission",
    "render_report",
    "report_clock",
    "withdraw_declaration",
]
