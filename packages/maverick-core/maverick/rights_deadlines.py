"""Per-jurisdiction clocks for people's privacy-rights requests, verified at source.

Rather than one constant (30 days) for every request, each regime carries the period the law actually fixes, the
extension it allows, whether it counts calendar or business days, and the
statute section or regulator page the numbers were read from on
``verified_at`` -- the same discipline :mod:`maverick.breach_notification`
applies to breach clocks.

Honest boundaries: decision support for the operator's privacy team, never
legal advice. Business-day maths skips weekends only (no holiday calendar is
modelled for these regimes), so a computed date can only land at or before
the true deadline. A regime whose primary source could not be fetched from
this build environment is listed in :data:`UNVERIFIED` with the addresses
tried and is NOT offered on the public form until someone verifies it --
absent rather than guessed.
"""
from __future__ import annotations

import calendar
import datetime
from typing import Any

#: The date every number below was checked against its source.
VERIFIED_AT = "2026-09-30"
NON_LEGAL_ADVICE = (
    "Deterministic decision support for the operator's own privacy team; "
    "not legal advice."
)

_DAY = 86_400.0

#: The request types the public form can offer. ``deletion`` is what a
#: member of the public sees; the tracker stores it as ``erasure``.
REQUEST_TYPES = (
    "access", "deletion", "correction", "portability", "opt_out",
    "limit_sensitive", "objection", "restriction", "withdraw_consent",
)
#: Tracker kind for each public request type.
TRACKER_KIND = {kind: kind for kind in REQUEST_TYPES} | {"deletion": "erasure"}
#: Public request type for each tracker kind.
PUBLIC_TYPE = {kind: public for public, kind in TRACKER_KIND.items()}

#: Template families: regimes that share wording and structure.
FAMILIES = ("gdpr", "us_state", "lgpd", "pipeda", "australia", "japan")

_GDPR_RIGHTS = (
    "access", "deletion", "correction", "portability", "objection",
    "restriction", "withdraw_consent",
)
_US_STATE_RIGHTS = ("access", "deletion", "correction", "portability", "opt_out")
_US_45_45 = {
    "unit": "days", "value": 45,
    "extension": {"unit": "days", "value": 45, "notice": "within_initial_period"},
}


def _regime(
    name: str, family: str, rights: tuple[str, ...], *, response: dict | None,
    source: str, citation: str, text: str, acknowledge: dict | None = None,
    per_type: dict[str, dict] | None = None,
) -> dict[str, Any]:
    return {
        "name": name, "family": family, "rights": rights,
        "response": response, "acknowledge": acknowledge,
        "per_type": per_type or {}, "source": source, "citation": citation,
        "statutory_text": text, "verified_at": VERIFIED_AT,
    }


#: regime id -> verified rule set. ``response`` is the default clock for the
#: regime; ``per_type`` overrides it for one request type; ``None`` means the
#: law fixes no period (the tracker then uses the property's internal target
#: and says so).
REGIMES: dict[str, dict[str, Any]] = {
    "eu_gdpr": _regime(
        "European Union (GDPR)", "gdpr", _GDPR_RIGHTS,
        response={
            "unit": "months", "value": 1,
            "extension": {"unit": "months", "value": 2,
                          "notice": "within_initial_period"},
        },
        source="https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32016R0679",
        citation="GDPR Art. 12(3)",
        text="Information on action taken on a request under Articles 15 to "
             "22 without undue delay and in any event within one month of "
             "receipt of the request; extendable by two further months where "
             "necessary, with the data subject informed of the extension and "
             "the reasons within one month of receipt.",
    ),
    "uk_gdpr": _regime(
        "United Kingdom (UK GDPR)", "gdpr", _GDPR_RIGHTS,
        response={
            "unit": "months", "value": 1,
            "extension": {"unit": "months", "value": 2,
                          "notice": "within_initial_period"},
        },
        source="https://www.legislation.gov.uk/ukpga/2025/18/section/76",
        citation="UK GDPR Art. 12A (inserted by Data (Use and Access) Act 2025 s. 76)",
        text="The applicable time period is one month beginning with the "
             "relevant time (the latest of receipt of the request, receipt of "
             "identity information requested under Art. 12(6), or payment of "
             "any fee); extendable by two further months for complex or "
             "numerous requests, by notice given before the end of the first "
             "month stating the reasons.",
    ),
    "us_ca_ccpa": _regime(
        "California (CCPA/CPRA)", "us_state",
        ("access", "deletion", "correction", "portability", "opt_out",
         "limit_sensitive"),
        response=_US_45_45,
        acknowledge={"unit": "business_days", "value": 10},
        per_type={
            "opt_out": {"unit": "business_days", "value": 15, "extension": None},
        },
        source="https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.130",
        citation="Cal. Civ. Code 1798.130(a)(2)(A); 11 CCR 7021(a); 11 CCR 7026(f)(1)",
        text="Respond within 45 days of receiving a verifiable consumer request, "
             "extendable once by an additional 45 days with notice within the "
             "first 45 days (Civ. Code 1798.130(a)(2)(A)); confirm receipt "
             "within 10 business days (11 CCR 7021(a)); honour an opt-out of "
             "sale/sharing no later than 15 business days from receipt (11 CCR "
             "7026(f)(1), read at law.cornell.edu). Limit-use requests use the "
             "45-day clock here; 11 CCR 7027 was not fetched in this build.",
    ),
    "us_va": _regime(
        "Virginia (VCDPA)", "us_state", _US_STATE_RIGHTS, response=_US_45_45,
        source="https://law.lis.virginia.gov/vacode/title59.1/chapter53/section59.1-577/",
        citation="Va. Code 59.1-577(B)(1)",
        text="Respond without undue delay, but in all cases within 45 days of "
             "receipt; extendable once by 45 additional days when reasonably "
             "necessary, informing the consumer within the initial 45-day "
             "period together with the reason.",
    ),
    "us_co": _regime(
        "Colorado (CPA)", "us_state", _US_STATE_RIGHTS, response=_US_45_45,
        source="https://colorado.public.law/statutes/crs_6-1-1306",
        citation="C.R.S. 6-1-1306(2)(a)",
        text="Inform the consumer of action taken without undue delay and, in "
             "any event, within 45 days after receipt; extendable by 45 "
             "additional days where reasonably necessary, informing the "
             "consumer within the first 45 days with the reasons.",
    ),
    "us_ct": _regime(
        "Connecticut (CTDPA)", "us_state", _US_STATE_RIGHTS, response=_US_45_45,
        source="https://portal.ct.gov/ag/sections/privacy/the-connecticut-data-privacy-act",
        citation="Conn. Gen. Stat. 42-522(b) (per the Attorney General's summary)",
        text="A controller must respond no later than 45 days after receipt "
             "of the request; under certain conditions the response period "
             "may be extended by 45 days. (Statute text at cga.ct.gov was "
             "unreachable in this build; the AG page was fetched.)",
    ),
    "us_ut": _regime(
        "Utah (UCPA)", "us_state", _US_STATE_RIGHTS, response=_US_45_45,
        source="https://le.utah.gov/~2022/bills/sbillenr/SB0227.pdf",
        citation="Utah Code 13-61-203 (S.B. 227, 2022, enrolled)",
        text="Respond to a verifiable consumer request within 45 days after "
             "receipt; extendable once by 45 additional days with notice to "
             "the consumer and the reasons.",
    ),
    "us_tx": _regime(
        "Texas (TDPSA)", "us_state", _US_STATE_RIGHTS, response=_US_45_45,
        source="https://texas.public.law/statutes/tex._bus._and_com._code_section_541.052",
        citation="Tex. Bus. & Com. Code 541.052(b)",
        text="Respond without undue delay, not later than the 45th day after "
             "receipt; extendable once by up to 45 days when reasonably "
             "necessary, informing the consumer within the initial period "
             "together with the reason.",
    ),
    "us_or": _regime(
        "Oregon (OCPA)", "us_state", _US_STATE_RIGHTS, response=_US_45_45,
        source="https://oregon.public.law/statutes/ors_646a.576",
        citation="ORS 646A.576(5)(a)",
        text="Respond without undue delay and not later than 45 days after "
             "receiving the request; extendable by an additional 45 days if "
             "reasonably necessary, notifying the consumer within the initial "
             "45-day period with the reason.",
    ),
    "br_lgpd": _regime(
        "Brazil (LGPD)", "lgpd",
        ("access", "deletion", "correction", "portability", "withdraw_consent",
         "objection"),
        response=None,
        per_type={"access": {"unit": "days", "value": 15, "extension": None}},
        source="https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-publicacaooriginal-156212-pl.html",
        citation="Lei 13.709/2018 Art. 19 I-II",
        text="Access: in simplified form immediately, or as a clear and complete "
             "declaration within 15 days of the request (Art. 19 II). The Act "
             "fixes no period for the other Art. 18 rights; the tracker uses "
             "the property's internal target for those.",
    ),
    "ca_pipeda": _regime(
        "Canada (PIPEDA)", "pipeda", ("access", "correction", "withdraw_consent"),
        response={
            "unit": "days", "value": 30,
            "extension": {"unit": "days", "value": 30, "notice": "within_initial_period"},
        },
        source="https://laws-lois.justice.gc.ca/eng/acts/P-8.6/page-2.html",
        citation="PIPEDA s. 8(3)-(5)",
        text="Respond not later than thirty days after receipt (s. 8(3)); "
             "extendable for a maximum of thirty additional days on the s. 8(4) "
             "grounds, with a notice of extension sent within the first thirty "
             "days stating the new limit, the reasons and the right to "
             "complain; failure to respond in time is a deemed refusal (s. 8(5)).",
    ),
    "au_privacy": _regime(
        "Australia (Privacy Act, APP 12)", "australia", ("access", "correction"),
        response={"unit": "days", "value": 30, "extension": None,
                  "basis": "regulator_guidance"},
        source="https://www.oaic.gov.au/privacy/australian-privacy-principles/australian-privacy-principles-guidelines/chapter-12-app-12-access-to-personal-information",
        citation="APP 12.4(a)(ii); OAIC APP Guidelines ch. 12",
        text="An organisation must respond within a reasonable period after the "
             "request is made; the OAIC's guidance is that a reasonable period "
             "should not exceed 30 calendar days. No statutory extension.",
    ),
    "jp_appi": _regime(
        "Japan (APPI)", "japan", ("access", "correction", "deletion", "restriction"),
        response=None,
        source="https://www.ppc.go.jp/files/pdf/APPI_english.pdf",
        citation="APPI Art. 28(2) in the PPC's June 2020 English translation "
                 "(renumbered Art. 33 by the 2020 amendment)",
        text="Disclose retained personal data to the principal without delay; "
             "no fixed number of days is prescribed for disclosure, correction "
             "or cease-of-use requests. The tracker uses the property's "
             "internal target.",
    ),
}

#: Regimes the brief asked for whose primary source could not be fetched from
#: this build environment. They are not computed and not offered on the
#: public form until someone verifies them and moves them into REGIMES.
UNVERIFIED: dict[str, dict[str, Any]] = {
    "ca_quebec": {
        "name": "Quebec (Law 25 / P-39.1 s. 32)",
        "attempted_sources": (
            "https://www.legisquebec.gouv.qc.ca/en/document/cs/P-39.1",
            "https://www.legisquebec.gouv.qc.ca/en/pdf/cs/P-39.1.pdf",
            "https://www.canlii.org/en/qc/laws/stat/cqlr-c-p-39.1/latest/",
        ),
        "reason": "HTTP 403 from legisquebec.gouv.qc.ca and canlii.org on "
                  + VERIFIED_AT,
    },
    "sg_pdpa": {
        "name": "Singapore (PDPA s. 21; PDP Regulations 2021 reg. 4)",
        "attempted_sources": (
            "https://sso.agc.gov.sg/Act/PDPA2012",
            "https://sso.agc.gov.sg/SL/PDPA2012-S63-2021",
            "https://www.pdpc.gov.sg/overview-of-pdpa/the-legislation/personal-data-protection-act",
        ),
        "reason": "HTTP 403 from sso.agc.gov.sg; pdpc.gov.sg pages render "
                  "no static text, on " + VERIFIED_AT,
    },
}


# --------------------------------------------------------------------------- #
# Date arithmetic
# --------------------------------------------------------------------------- #

def _is_weekday(stamp: float) -> bool:
    # Epoch day 0 (1970-01-01) was a Thursday: weekday = (day + 3) % 7, Mon = 0.
    return (int(stamp // _DAY) + 3) % 7 < 5


def add_business_days(start: float, count: int) -> float:
    """Skip weekends only; no holiday calendar is modelled for these regimes."""
    stamp = start
    remaining = int(count)
    while remaining > 0:
        stamp += _DAY
        if _is_weekday(stamp):
            remaining -= 1
    return stamp


def add_months(start: float, months: int) -> float:
    """The corresponding date ``months`` later (UTC); when that month has no
    such day, its last day -- the way the ICO reads GDPR's "one month"."""
    moment = datetime.datetime.fromtimestamp(start, tz=datetime.timezone.utc)
    index = moment.year * 12 + (moment.month - 1) + int(months)
    year, month = divmod(index, 12)
    month += 1
    day = min(moment.day, calendar.monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day).timestamp()


def _advance(start: float, spec: dict) -> float:
    unit, value = spec["unit"], int(spec["value"])
    if unit == "days":
        return start + value * _DAY
    if unit == "business_days":
        return add_business_days(start, value)
    if unit == "months":
        return add_months(start, value)
    raise ValueError(f"unknown deadline unit: {unit}")


# --------------------------------------------------------------------------- #
# Clocks
# --------------------------------------------------------------------------- #

def regime(regime_id: str) -> dict[str, Any]:
    return REGIMES[str(regime_id or "")]


def family_for(regime_id: str) -> str:
    """The template family of a regime; ``gdpr`` wording for an unknown one."""
    entry = REGIMES.get(str(regime_id or ""))
    return str(entry["family"]) if entry else "gdpr"


def compute_clock(
    regime_id: str, request_type: str, received_at: float, *,
    internal_target_days: int = 30,
) -> dict[str, Any]:
    """The clock for one request: ``due_at``, ``acknowledge_by`` and the
    extension the law allows, with the source that says so.

    ``request_type`` is a public request type (``deletion``, not ``erasure``);
    a type the regime does not grant is a ``ValueError``. ``due_basis`` says
    where the date comes from: ``statutory``, ``regulator_guidance`` or
    ``internal_target`` (the law fixes no period, the operator's own target
    is used and shown as such)."""
    entry = regime(regime_id)
    public_type = PUBLIC_TYPE.get(request_type, request_type)
    if public_type not in entry["rights"]:
        raise ValueError(
            f"{entry['name']} does not grant a {public_type} request on this form"
        )
    received = float(received_at)
    spec = entry["per_type"].get(public_type, entry["response"])
    target = max(1, int(internal_target_days))
    if spec is None:
        due_at = received + target * _DAY
        basis = "internal_target"
        extension: dict | None = None
    else:
        due_at = _advance(received, spec)
        basis = str(spec.get("basis") or "statutory")
        extension = spec.get("extension")
    acknowledge = entry["acknowledge"]
    return {
        "jurisdiction": regime_id,
        "jurisdiction_name": entry["name"],
        "family": entry["family"],
        "request_type": public_type,
        "received_at": received,
        "due_at": due_at,
        "due_basis": basis,
        "acknowledge_by": _advance(received, acknowledge) if acknowledge else None,
        "extension_max_days": (
            0 if extension is None else
            None if extension["unit"] == "months" else int(extension["value"])
        ),
        "extension_months": (
            int(extension["value"]) if extension and extension["unit"] == "months"
            else None
        ),
        "extension_notice_by": due_at if extension else None,
        "citation": entry["citation"],
        "source": entry["source"],
        "verified_at": entry["verified_at"],
        "statutory_text": entry["statutory_text"],
        "non_legal_advice": NON_LEGAL_ADVICE,
    }


def extension_for(clock: dict, *, days: int | None, now: float) -> dict[str, Any]:
    """Validate a recorded extension against the regime's rule.

    ``days`` may be ``None`` for a month-based regime (take the full "two
    further months"); for a day-based regime it is required and capped at the
    statutory maximum. The notice must be given before the first period ends
    -- every regime above says so."""
    if clock.get("extension_max_days") == 0:
        raise ValueError("this regime allows no extension of the response period")
    due_at = float(clock["due_at"])
    if float(now) > due_at:
        raise ValueError(
            "an extension must be notified before the first response period ends"
        )
    months = clock.get("extension_months")
    if months:
        if days is not None and (int(days) < 1 or int(days) > 62):
            raise ValueError("extension days must be 1-62 for a two-month regime")
        received = float(clock["received_at"])
        maximum = add_months(received, 1 + int(months))
        extended_until = maximum if days is None else min(maximum, due_at + int(days) * _DAY)
        return {"extended_until": extended_until, "maximum_until": maximum}
    if days is None:
        raise ValueError("extension days are required for this regime")
    limit = int(clock.get("extension_max_days") or 0)
    if int(days) < 1 or int(days) > limit:
        raise ValueError(f"extension days must be 1-{limit} for this regime")
    return {
        "extended_until": due_at + int(days) * _DAY,
        "maximum_until": due_at + limit * _DAY,
    }


def form_choices() -> list[dict[str, Any]]:
    """The jurisdictions the public form may offer, with the rights each grants."""
    return [
        {"id": regime_id, "name": entry["name"], "family": entry["family"],
         "rights": list(entry["rights"]), "citation": entry["citation"]}
        for regime_id, entry in REGIMES.items()
    ]


__all__ = [
    "FAMILIES", "NON_LEGAL_ADVICE", "PUBLIC_TYPE", "REGIMES", "REQUEST_TYPES",
    "TRACKER_KIND", "UNVERIFIED", "VERIFIED_AT", "add_business_days",
    "add_months", "compute_clock", "extension_for", "family_for",
    "form_choices", "regime",
]
