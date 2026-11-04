"""Jurisdiction-aware breach-notification obligations, verified at source.

Fifteen regimes' who/when/whether rules as data, every deadline checked
against the primary source or the regulator's own guidance on the
verification date below — the discipline that already caught a repealed
statute elsewhere in this platform. :func:`assess_breach` turns one
incident's facts (jurisdictions, subjects affected, sensitivity, malice,
discovery time) into concrete per-regime obligations with computed due
timestamps where the law fixes a clock, and the statute's own words where
it does not.

Honest boundaries, stated plainly: this is DECISION SUPPORT for the
operator's counsel, never legal advice or a notification service — the
platform transmits nothing. Business-day math skips weekends plus the
FIXED-date national holidays of jurisdictions with a verified calendar;
movable and optional holidays stay working days, so a computed date can
only fall at or before the true deadline, never after it. Regimes not yet
verified against primary sources (e.g. India's DPDP rules, whose official
sources were unreachable from this build environment) are deliberately
absent rather than guessed at.
"""
from __future__ import annotations

import datetime
import time
from typing import Any

SCHEMA = "lightwork.breach-plan.v1"
#: The date every deadline below was checked against its source.
VERIFIED_AT = "2026-08-25"
NON_LEGAL_ADVICE = (
    "Deterministic decision support for the operator's own counsel; not "
    "legal advice, and never a notification transmitted on your behalf."
)

_DAY = 86_400.0


def _fixed(unit: str, value: int, anchor: str, *, condition: str = "") -> dict:
    return {"basis": "fixed", "unit": unit, "value": value,
            "anchor": anchor, "condition": condition}


def _standard(text: str) -> dict:
    return {"basis": "standard", "text": text}


#: regime id -> verified rule set. ``authority``/``subjects`` each carry a
#: deadline spec plus the trigger condition in the law's own terms.
REGIMES: dict[str, dict[str, Any]] = {
    "eu_gdpr": {
        "name": "EU — GDPR",
        "authority": "Competent supervisory authority",
        "authority_deadline": _fixed(
            "hours", 72, "discovery",
            condition="without undue delay and, where feasible, not later "
                      "than 72 hours after awareness; reasons required if "
                      "later. Not required if unlikely to result in a risk.",
        ),
        "subjects_deadline": _standard(
            "Without undue delay when the breach is likely to result in a "
            "HIGH risk to rights and freedoms (Art. 34)."),
        "records_duty": "Document every breach, notified or not (Art. 33(5)).",
        "notification_contents": {
            "audience": "supervisory authority",
            "basis": "GDPR Art. 33(3)",
            "elements": [
                "Nature of the breach: categories and approximate numbers "
                "of data subjects and records concerned",
                "Name and contact details of the DPO or other contact point",
                "Likely consequences of the breach",
                "Measures taken or proposed, including mitigation",
            ],
        },
        "citations": ["GDPR Art. 33", "GDPR Art. 34"],
    },
    "uk_gdpr": {
        "name": "UK — UK GDPR",
        "authority": "Information Commissioner's Office (ICO)",
        "authority_deadline": _fixed(
            "hours", 72, "discovery",
            condition="Same 72-hour standard as EU GDPR Art. 33 (retained "
                      "law); risk threshold identical.",
        ),
        "subjects_deadline": _standard(
            "Without undue delay when likely to result in a high risk "
            "(UK GDPR Art. 34)."),
        "records_duty": "Document every breach (UK GDPR Art. 33(5)).",
        "notification_contents": {
            "audience": "ICO",
            "basis": "UK GDPR Art. 33(3)",
            "elements": [
                "Nature of the breach: categories and approximate numbers "
                "of data subjects and records concerned",
                "DPO / contact point details",
                "Likely consequences",
                "Measures taken or proposed, including mitigation",
            ],
        },
        "citations": ["UK GDPR Art. 33", "UK GDPR Art. 34"],
    },
    "us_hipaa": {
        "name": "US — HIPAA Breach Notification Rule",
        "authority": "HHS Secretary",
        "authority_deadline": _fixed(
            "days", 60, "discovery",
            condition="500+ individuals: without unreasonable delay, no "
                      "later than 60 days. Under 500: annual log due 60 "
                      "days after calendar year end.",
        ),
        "subjects_deadline": _fixed(
            "days", 60, "discovery",
            condition="Individual notice without unreasonable delay, no "
                      "later than 60 days after discovery.",
        ),
        "media_rule": "Prominent media outlets in the state when 500+ "
                      "residents of one state/jurisdiction are affected.",
        "notification_contents": {
            "audience": "individuals",
            "basis": "45 CFR § 164.404(c)(1)",
            "elements": [
                "Brief description of what happened, with breach and "
                "discovery dates where known",
                "Types of unsecured PHI involved (name, SSN, DOB, "
                "address, account number, diagnosis, ...)",
                "Steps individuals should take to protect themselves",
                "What the covered entity is doing to investigate, "
                "mitigate, and prevent recurrence",
                "Contact procedures: toll-free number, email, website, "
                "or postal address",
            ],
        },
        "citations": ["45 CFR §§ 164.400–414"],
    },
    "us_ca": {
        "name": "US — California",
        "authority": "California Attorney General",
        "authority_deadline": _standard(
            "Sample notice to the AG when a single breach requires "
            "notifying more than 500 California residents."),
        "authority_min_subjects": 501,
        "subjects_deadline": _standard(
            "In the most expedient time possible and without unreasonable "
            "delay."),
        "notification_contents": {
            "audience": "individuals",
            "basis": "Cal. Civ. Code § 1798.82(d)",
            "elements": [
                "Titled 'Notice of Data Breach', plain language, >=10pt, "
                "with the five prescribed headings (What Happened? / What "
                "Information Was Involved? / What We Are Doing / What You "
                "Can Do / For More Information)",
                "Name and contact information of the reporting entity",
                "Types of personal information involved",
                "Breach date, estimated date, or range, when determinable",
                "Whether notification was delayed by a law-enforcement "
                "investigation",
                "General description of the incident, when available",
                "Toll-free numbers and addresses of the major credit "
                "reporting agencies when SSN or ID numbers were exposed "
                "(and no-cost identity-theft services >=12 months where "
                "(d)(2)(G) applies)",
            ],
        },
        "citations": ["Cal. Civ. Code §§ 1798.29, 1798.82"],
    },
    "us_tx": {
        "name": "US — Texas",
        "authority": "Texas Attorney General",
        "authority_deadline": _fixed(
            "days", 30, "determination",
            condition="As soon as practicable and not later than 30 days "
                      "when 250+ Texas residents are affected (SB 768, "
                      "eff. 2023-09-01); electronic OAG form required.",
        ),
        "authority_min_subjects": 250,
        "subjects_deadline": _fixed(
            "days", 60, "determination",
            condition="Individuals without unreasonable delay, no later "
                      "than 60 days after determining the breach occurred.",
        ),
        "citations": ["Tex. Bus. & Com. Code § 521.053"],
    },
    "us_co": {
        "name": "US — Colorado",
        "authority": "Colorado Attorney General",
        "authority_deadline": _fixed(
            "days", 30, "determination",
            condition="Within the same 30-day window when 500+ Colorado "
                      "residents are affected.",
        ),
        "authority_min_subjects": 500,
        "subjects_deadline": _fixed(
            "days", 30, "determination",
            condition="Residents within 30 days of determining a breach "
                      "with misuse or likely misuse.",
        ),
        "citations": ["Colo. Rev. Stat. § 6-1-716"],
    },
    "us_fl": {
        "name": "US — Florida (FIPA)",
        "authority": "Florida Department of Legal Affairs",
        "authority_deadline": _fixed(
            "days", 30, "determination",
            condition="Within 30 days when 500+ individuals in Florida are "
                      "affected (15-day extension for good cause).",
        ),
        "authority_min_subjects": 500,
        "subjects_deadline": _fixed(
            "days", 30, "determination",
            condition="Individuals within 30 days of determination "
                      "(15-day good-cause extension possible).",
        ),
        "citations": ["Fla. Stat. § 501.171"],
    },
    "us_ny": {
        "name": "US — New York (SHIELD Act)",
        "authority": "NY Attorney General, Dept. of State, State Police",
        "authority_deadline": _standard(
            "State regulators are notified when residents are notified; "
            "consumer reporting agencies when 5,000+ NY residents are "
            "affected."),
        "subjects_deadline": _fixed(
            "days", 30, "discovery",
            condition="Residents within 30 days of discovery (2025 "
                      "amendment to GBL § 899-aa).",
        ),
        "citations": ["N.Y. Gen. Bus. Law § 899-aa (as amended 2025)"],
    },
    "br_lgpd": {
        "name": "Brazil — LGPD",
        "authority": "ANPD",
        "authority_deadline": _fixed(
            "business_days", 3, "discovery",
            condition="3 business days for breaches with relevant risk or "
                      "damage (doubled for small-scale agents); supplement "
                      "within 20 business days.",
        ),
        "subjects_deadline": _fixed(
            "business_days", 3, "discovery",
            condition="Affected subjects on the same 3-business-day clock "
                      "as the ANPD notice.",
        ),
        "holiday_calendar": "BR",
        "citations": ["LGPD Art. 48", "ANPD Resolution CD/ANPD 15/2024",
                      "Lei 662/1949 (as amended by Lei 10.607/2002), "
                      "Lei 6.802/1980, Lei 14.759/2023 — feriados nacionais"],
    },
    "ca_pipeda": {
        "name": "Canada — PIPEDA",
        "authority": "Office of the Privacy Commissioner (OPC)",
        "authority_deadline": _standard(
            "Report as soon as feasible after determining a real risk of "
            "significant harm (RROSH)."),
        "subjects_deadline": _standard(
            "Notify affected individuals as soon as feasible after the "
            "RROSH determination."),
        "records_duty": "Keep records of ALL breaches (RROSH or not) for "
                        "24 months.",
        "citations": ["PIPEDA ss. 10.1–10.3", "Breach of Security "
                      "Safeguards Regulations"],
    },
    "ca_quebec": {
        "name": "Canada (Quebec) — Law 25",
        "authority": "Commission d'acces a l'information (CAI)",
        "authority_deadline": _standard(
            "Promptly -- the Commission's own wording is \"s'empresser d'en "
            "aviser la Commission\" -- once the incident presents a risk "
            "that serious injury be caused. No fixed clock in the text."),
        "subjects_deadline": _standard(
            "Every person whose personal information is concerned must be "
            "notified; the Commission may ORDER the enterprise to do so. "
            "Notice may be withheld where it would hinder an investigation "
            "to prevent, detect or repress crime or statutory offences."),
        "records_duty": (
            "Maintain a register of confidentiality incidents; each entry "
            "is kept for at least FIVE years after the date, or the period, "
            "the incident became known."),
        "citations": [
            "Act respecting the protection of personal information in the "
            "private sector (Law 25) -- confidentiality incidents",
            "Reglement sur les incidents de confidentialite",
            "CAI guidance for enterprises, 'Incidents de confidentialite et "
            "mesures de securite', verified 2026-08-25",
        ],
    },
    "au_ndb": {
        "name": "Australia — Notifiable Data Breaches",
        "authority": "OAIC",
        "authority_deadline": _standard(
            "As soon as practicable after forming reasonable grounds to "
            "believe an eligible breach occurred (likely serious harm, "
            "not remediated)."),
        "subjects_deadline": _standard(
            "Individuals at likely risk of serious harm, promptly, with "
            "the OAIC statement."),
        "assessment_window": _fixed(
            "days", 30, "discovery",
            condition="Suspected breaches must be assessed within 30 days "
                      "(Privacy Act s 26WH).",
        ),
        "citations": ["Privacy Act 1988 (Cth) Part IIIC", "s 26WH"],
    },
    "sg_pdpa": {
        "name": "Singapore — PDPA",
        "authority": "PDPC",
        "authority_deadline": _fixed(
            "days", 3, "determination",
            condition="3 calendar days after assessing the breach as "
                      "notifiable (likely significant harm, OR significant "
                      "scale: 500+ individuals).",
        ),
        "subjects_deadline": _standard(
            "Affected individuals when likely significant harm, unless an "
            "exception applies."),
        "assessment_window": _fixed(
            "days", 30, "discovery",
            condition="PDPC expects the notifiability assessment done "
                      "expeditiously — ~30 days from discovery overall.",
        ),
        "citations": ["PDPA ss. 26A–26D"],
    },
    "jp_appi": {
        "name": "Japan — APPI",
        "authority": "Personal Information Protection Commission (PPC)",
        "authority_deadline": _fixed(
            "days", 30, "discovery",
            condition="Two-stage: preliminary report promptly (guidance: "
                      "3–5 days), final report within 30 days — 60 days "
                      "for likely-malicious breaches (cyberattack). "
                      "Triggers: sensitive data, property-damage risk, "
                      "improper purpose, or 1,000+ subjects.",
        ),
        "malicious_deadline_days": 60,
        "authority_min_subjects": 1000,
        "subjects_deadline": _standard(
            "Affected individuals promptly for the same trigger "
            "categories."),
        "citations": ["APPI Art. 26 (amended)", "PPC Enforcement Rules"],
    },
    "kr_pipa": {
        "name": "South Korea — PIPA",
        "authority": "PIPC / KISA",
        "authority_deadline": _fixed(
            "hours", 72, "discovery",
            condition="Report within 72 hours when 1,000+ subjects, "
                      "sensitive or unique identifiers, or external "
                      "unauthorized access (2023 amendment standardized "
                      "the clock).",
        ),
        "authority_min_subjects": 1000,
        "subjects_deadline": _fixed(
            "hours", 72, "discovery",
            condition="Affected data subjects within 72 hours (Art. 34(1)).",
        ),
        "citations": ["PIPA Art. 34", "Enforcement Decree (2023)"],
    },
}

#: Verified-but-absent regimes, stated so the gap is a decision, not a hole.
UNVERIFIED_REGIMES = {
    "in_dpdp": "India DPDP Act 2023 — rules not yet verified at source here",
    "qc_law25": "Quebec Law 25 — CAI timing not yet verified at source here",
}


class BreachNotificationError(RuntimeError):
    """Base failure for the breach-notification planner."""


class BreachNotificationConfigError(BreachNotificationError):
    """The feature is not enabled."""


def get_breach_notification_config() -> dict[str, Any]:
    from .config import load_global_config

    try:
        config = load_global_config()
    except Exception as exc:
        raise BreachNotificationConfigError(
            "breach_notification configuration is unavailable"
        ) from exc
    section = (config or {}).get("breach_notification") or {}
    if not isinstance(section, dict):
        raise BreachNotificationConfigError(
            "breach_notification must be a table")
    flag = section.get("enable", False)
    if not isinstance(flag, bool):
        raise BreachNotificationConfigError(
            "breach_notification.enable must be a boolean")
    return {"enable": flag}


def enabled() -> bool:
    try:
        return get_breach_notification_config()["enable"] is True
    except Exception:
        return False


def _require_enabled() -> None:
    if not enabled():
        raise BreachNotificationConfigError(
            "the breach planner requires [breach_notification] enable = true"
        )


#: Fixed-date national holidays, per jurisdiction, verified at the primary
#: source. Only statutory FIXED dates are modelled: movable religious
#: observances and optional "pontos facultativos" (Carnival, Corpus Christi)
#: are not national holidays by statute, so they are left in as working
#: days. That errs in the safe direction -- a computed deadline can only
#: land at or BEFORE the true one, never after it.
_FIXED_HOLIDAYS: dict[str, frozenset[tuple[int, int]]] = {
    # Brazil: Lei 662/1949 (as amended by Lei 10.607/2002), Lei 6.802/1980
    # (12 Oct), Lei 14.759/2023 (20 Nov). Verified 2026-08-25 at planalto.gov.br.
    "BR": frozenset({
        (1, 1), (4, 21), (5, 1), (9, 7), (10, 12),
        (11, 2), (11, 15), (11, 20), (12, 25),
    }),
}


def _is_working_day(stamp: float, calendar: str) -> bool:
    """Monday-Friday, minus the jurisdiction's fixed national holidays."""

    # Epoch day 0 (1970-01-01) was a Thursday: weekday = (day + 3) % 7 with
    # Monday = 0, so Monday-Friday is < 5.
    if (int(stamp // _DAY) + 3) % 7 >= 5:
        return False
    holidays = _FIXED_HOLIDAYS.get(calendar)
    if not holidays:
        return True
    moment = datetime.datetime.fromtimestamp(stamp, tz=datetime.timezone.utc)
    return (moment.month, moment.day) not in holidays


def _add_business_days(start: float, count: int, *, calendar: str = "") -> float:
    """Business-day math over weekends and fixed national holidays.

    ``calendar`` selects a verified holiday set; an unknown or empty one
    skips weekends only, which is what every regime without a modelled
    calendar honestly gets.
    """

    stamp = start
    remaining = count
    while remaining > 0:
        stamp += _DAY
        if _is_working_day(stamp, calendar):
            remaining -= 1
    return stamp


def _due_at(spec: dict, *, discovered_at: float, determined_at: float,
            calendar: str = "") -> float | None:
    if spec.get("basis") != "fixed":
        return None
    anchor = determined_at if spec["anchor"] == "determination" else discovered_at
    unit, value = spec["unit"], spec["value"]
    if unit == "hours":
        return anchor + value * 3600.0
    if unit == "days":
        return anchor + value * _DAY
    if unit == "business_days":
        return _add_business_days(anchor, value, calendar=calendar)
    raise ValueError(f"unknown deadline unit: {unit}")


def list_regimes() -> list[dict[str, Any]]:
    """The verified matrix, citations included, for the UI and the CLI."""

    _require_enabled()
    return [
        {
            "regime": regime_id,
            "name": rule["name"],
            "authority": rule["authority"],
            "citations": list(rule["citations"]),
        }
        for regime_id, rule in sorted(REGIMES.items())
    ]


def assess_breach(
    jurisdictions: list[str],
    *,
    subjects_affected: int | None = None,
    sensitive: bool = False,
    malicious: bool = False,
    discovered_at: float | None = None,
    determined_at: float | None = None,
) -> dict[str, Any]:
    """Per-regime obligations for one incident's facts.

    ``discovered_at`` anchors awareness clocks; ``determined_at`` (default:
    discovery) anchors determination clocks. Unknown jurisdiction ids are
    refused, never guessed. Threshold notes state when a regulator notice
    is below its trigger rather than silently dropping the row.
    """

    _require_enabled()
    wanted = [str(j).strip().lower() for j in jurisdictions if str(j).strip()]
    if not wanted or len(wanted) > 32:
        raise ValueError("jurisdictions must name 1-32 regimes")
    unknown = sorted(set(wanted) - set(REGIMES))
    if unknown:
        known = ", ".join(sorted(REGIMES))
        raise ValueError(
            f"unknown regime(s): {', '.join(unknown)}. Verified regimes: "
            f"{known}. Absent by design: "
            + "; ".join(f"{k} ({v})" for k, v in UNVERIFIED_REGIMES.items())
        )
    if subjects_affected is not None and (
        not isinstance(subjects_affected, int)
        or isinstance(subjects_affected, bool)
        or subjects_affected < 0
    ):
        raise ValueError("subjects_affected must be a non-negative integer or None")
    now = time.time()
    discovery = float(discovered_at) if discovered_at is not None else now
    determination = (
        float(determined_at) if determined_at is not None else discovery
    )
    if determination < discovery:
        raise ValueError("determined_at cannot precede discovered_at")

    obligations: list[dict[str, Any]] = []
    for regime_id in dict.fromkeys(wanted):
        rule = REGIMES[regime_id]
        authority_spec = dict(rule["authority_deadline"])
        if regime_id == "jp_appi" and malicious:
            authority_spec = _fixed(
                "days", rule["malicious_deadline_days"], "discovery",
                condition=authority_spec["condition"],
            )
        minimum = rule.get("authority_min_subjects")
        below_threshold = (
            minimum is not None and subjects_affected is not None
            and subjects_affected < minimum
        )
        calendar = str(rule.get("holiday_calendar") or "")
        entry: dict[str, Any] = {
            "regime": regime_id,
            "name": rule["name"],
            "authority": rule["authority"],
            "authority_deadline": authority_spec,
            "authority_due_at": _due_at(
                authority_spec, calendar=calendar,
                discovered_at=discovery, determined_at=determination,
            ),
            "authority_below_threshold": (
                None if minimum is not None and subjects_affected is None
                else bool(below_threshold)
            ),
            "subjects_deadline": rule["subjects_deadline"],
            "subjects_due_at": _due_at(
                rule["subjects_deadline"], calendar=calendar,
                discovered_at=discovery, determined_at=determination,
            ),
            "citations": list(rule["citations"]),
        }
        if calendar in _FIXED_HOLIDAYS:
            entry["holiday_calendar"] = calendar
        if below_threshold:
            entry["threshold_note"] = (
                f"Reported subject count ({subjects_affected}) is below "
                f"this regulator's {minimum}-subject trigger; other "
                f"triggers (e.g. sensitivity) may still apply."
            )
        elif minimum is not None and subjects_affected is None:
            entry["threshold_note"] = (
                "Affected-person count not provided; this regulator's "
                f"{minimum}-subject trigger cannot be assessed. Other "
                "triggers (e.g. sensitivity) may still apply."
            )
        if sensitive and regime_id in {"jp_appi", "kr_pipa"}:
            entry["sensitivity_note"] = (
                "Sensitive data is an independent reporting trigger here "
                "regardless of subject count."
            )
        for key in ("assessment_window", "records_duty", "media_rule",
                    "notification_contents"):
            if key in rule:
                entry[key] = rule[key]
        if "notification_contents" not in rule:
            entry["notification_contents"] = None  # not yet encoded here
        if "assessment_window" in rule:
            entry["assessment_due_at"] = _due_at(
                rule["assessment_window"], calendar=calendar,
                discovered_at=discovery, determined_at=determination,
            )
        obligations.append(entry)

    obligations.sort(
        key=lambda row: (
            row["authority_due_at"] is None,
            row["authority_due_at"] or 0.0,
            row["regime"],
        )
    )
    return {
        "schema": SCHEMA,
        "verified_at": VERIFIED_AT,
        "discovered_at": discovery,
        "determined_at": determination,
        "subjects_affected": subjects_affected,
        "sensitive": bool(sensitive),
        "malicious": bool(malicious),
        "obligations": obligations,
        "business_day_note": (
            "Business-day math skips weekends, plus the FIXED-date national "
            "holidays of the jurisdictions with a verified calendar "
            f"({', '.join(sorted(_FIXED_HOLIDAYS))}). Movable religious "
            "observances and optional/municipal holidays are treated as "
            "working days, so a computed date can only fall at or before "
            "the true deadline, never after it."
        ),
        "notice": NON_LEGAL_ADVICE,
    }


__all__ = [
    "NON_LEGAL_ADVICE",
    "REGIMES",
    "SCHEMA",
    "UNVERIFIED_REGIMES",
    "VERIFIED_AT",
    "BreachNotificationConfigError",
    "BreachNotificationError",
    "assess_breach",
    "enabled",
    "get_breach_notification_config",
    "list_regimes",
]
