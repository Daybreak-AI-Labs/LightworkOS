"""Firm onboarding: a profile in, a pilot-readiness verdict out.

"Intake the firm's process and start testing in days" needs one thing up
front: an honest, mechanical answer to *what will the first-pass engine
actually cover for THIS firm's book of business, and what must they hand to
their tax engine?* This module is that answer.

A firm describes itself in a small profile (the states it serves, the names it
gives its source documents, whether the signed-constants channel is wired) and
:func:`assess_readiness` turns it into a :class:`ReadinessReport`:

* every state the firm serves is sorted into **computed** (no-tax / flat,
  drafted first-pass) or **handed off** (graduated/credit-structured -- the
  firm's tax engine owns it), or flagged as an invalid code;
* every document alias is resolved to a canonical form the extractor knows,
  or flagged so the firm fixes the mapping before client files arrive;
* a clear **ready-to-pilot** verdict with the blockers (must fix) separated
  from the warnings (fine to pilot, worth knowing).

Pure and deterministic: profile in, report out, no IO. The thin TOML loader
and the ``maverick tax onboard`` command wire it to a file. Pair it with
``maverick tax backtest`` -- onboarding says what's in scope, the back-test
proves the accuracy on the firm's own prior returns.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .tax_prep import DOC_TYPES, STATE_CODES, STATE_TY2025


@dataclass
class FirmProfile:
    """A firm's intake profile -- the minimum needed to scope a pilot."""
    name: str
    states: list[str] = field(default_factory=list)
    # firm's own document label -> a canonical DOC_TYPES value
    doc_aliases: dict[str, str] = field(default_factory=dict)
    constants_channel_configured: bool = False
    roster_size: int = 0
    # the document labels the firm actually works with (their words) -- used to
    # check coverage: which the engine recognizes vs. which need a manual touch.
    forms_handled: list[str] = field(default_factory=list)


# Document types whose figures the engine actually extracts (vs. classified-
# but-flagged-for-the-preparer). Mirrors tax_prep's extraction coverage.
_EXTRACTED_TYPES = frozenset({
    "W-2", "1099-INT", "1099-DIV", "1099-NEC", "1098", "1099-R", "SSA-1099",
    "1099-G", "1098-E", "1098-T", "1099-B",
})


@dataclass
class ReadinessReport:
    firm: str
    computed_states: list[str] = field(default_factory=list)
    handoff_states: list[str] = field(default_factory=list)
    invalid_states: list[str] = field(default_factory=list)
    resolved_aliases: dict[str, str] = field(default_factory=dict)
    unresolved_aliases: dict[str, str] = field(default_factory=dict)
    forms_extracted: list[str] = field(default_factory=list)
    forms_flagged: list[str] = field(default_factory=list)
    forms_unrecognized: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ready_to_pilot(self) -> bool:
        return not self.blockers


def resolve_doc_type(label: str, aliases: dict[str, str] | None = None) -> str:
    """A firm's document label -> a canonical DOC_TYPES value, or "UNKNOWN".

    Checks the firm's explicit aliases first (case-insensitively), then an
    exact canonical match, so a firm can map "Wage Statement" -> "W-2" once and
    have the whole pipeline speak its vocabulary."""
    low = (label or "").strip().lower()
    for firm_label, canonical in (aliases or {}).items():
        if firm_label.strip().lower() == low and canonical in DOC_TYPES:
            return canonical
    for canonical in DOC_TYPES:
        if canonical.lower() == low:
            return canonical
    return "UNKNOWN"


def assess_readiness(profile: FirmProfile) -> ReadinessReport:
    """Scope a firm's pilot: which states compute, which hand off, whether the
    document taxonomy resolves, and a blockers-vs-warnings verdict."""
    rep = ReadinessReport(firm=profile.name)
    computed = STATE_TY2025["no_tax"] | set(STATE_TY2025["flat"])
    for raw in profile.states:
        code = (raw or "").strip().upper()
        if code not in STATE_CODES:
            rep.invalid_states.append(code or raw)
        elif code in computed:
            rep.computed_states.append(code)
        else:
            rep.handoff_states.append(code)
    rep.computed_states.sort()
    rep.handoff_states.sort()

    for firm_label, canonical in profile.doc_aliases.items():
        if canonical in DOC_TYPES:
            rep.resolved_aliases[firm_label] = canonical
        else:
            rep.unresolved_aliases[firm_label] = canonical

    # Coverage: classify each form the firm handles by what the engine does
    # with it -- extract its figures, classify-and-flag it, or not recognize it.
    for form in profile.forms_handled:
        canonical = resolve_doc_type(form, profile.doc_aliases)
        if canonical in _EXTRACTED_TYPES:
            rep.forms_extracted.append(form)
        elif canonical != "UNKNOWN":
            rep.forms_flagged.append(form)
        else:
            rep.forms_unrecognized.append(form)

    if rep.invalid_states:
        rep.blockers.append(
            "invalid state code(s): " + ", ".join(rep.invalid_states)
            + " -- fix the profile before intake")
    if rep.unresolved_aliases:
        rep.blockers.append(
            "document alias(es) map to an unknown type: "
            + ", ".join(f"{k}->{v}" for k, v in rep.unresolved_aliases.items())
            + f" (valid types: {', '.join(DOC_TYPES)})")
    if rep.handoff_states:
        rep.warnings.append(
            "graduated/credit-structured state(s) " + ", ".join(rep.handoff_states)
            + " are NOT drafted first-pass -- the firm's tax engine (CCH "
            "Axcess / GoSystem) owns those state returns")
    if not profile.constants_channel_configured:
        rep.warnings.append(
            "no signed-constants channel configured -- runs on the built-in "
            "TY tables; wire [tax] trusted_constants_pubkeys + update_url to "
            "auto-apply in-season law changes")
    if profile.roster_size <= 0:
        rep.warnings.append(
            "no client roster size given -- supply prior filed returns to "
            "`maverick tax backtest` to measure accuracy before going live")
    if rep.forms_unrecognized:
        rep.warnings.append(
            "form(s) the firm handles are not recognized: "
            + ", ".join(rep.forms_unrecognized)
            + " -- add a [firm.doc_aliases] mapping or expect manual handling")
    if rep.forms_flagged:
        rep.warnings.append(
            "form(s) classified but not auto-computed (carried/flagged for the "
            "preparer): " + ", ".join(rep.forms_flagged))
    return rep


def render_readiness(rep: ReadinessReport) -> str:
    verdict = "READY TO PILOT" if rep.ready_to_pilot else "NOT READY (blockers)"
    out = [
        f"TAX ONBOARDING READINESS — {rep.firm}",
        "=" * 52,
        f"Verdict             : {verdict}",
        f"States computed     : {', '.join(rep.computed_states) or '(none)'}",
        f"States handed off   : {', '.join(rep.handoff_states) or '(none)'}",
        f"Doc aliases resolved: {len(rep.resolved_aliases)}"
        + (f"  (unresolved {len(rep.unresolved_aliases)})"
           if rep.unresolved_aliases else ""),
    ]
    if rep.forms_extracted or rep.forms_flagged or rep.forms_unrecognized:
        out.append(
            f"Forms coverage      : {len(rep.forms_extracted)} extracted, "
            f"{len(rep.forms_flagged)} flagged, "
            f"{len(rep.forms_unrecognized)} unrecognized")
    if rep.blockers:
        out += ["", "BLOCKERS (must fix before intake):", "-" * 52]
        out += [f"  - {b}" for b in rep.blockers]
    if rep.warnings:
        out += ["", "WARNINGS (fine to pilot, worth knowing):", "-" * 52]
        out += [f"  - {w}" for w in rep.warnings]
    out += ["", "NEXT: `maverick tax backtest <prior-returns>` to measure "
            "accuracy on the firm's own filed returns."]
    return "\n".join(out)


def load_profile(path) -> FirmProfile:
    """Load a firm profile from TOML.

    Shape::

        [firm]
        name = "Smith & Co CPAs"
        states = ["PA", "NJ", "TX"]
        roster_size = 1200
        constants_channel_configured = true
        [firm.doc_aliases]
        "Wage Statement" = "W-2"
    """
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover -- 3.10 fallback
        import tomli as tomllib
    from pathlib import Path
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    firm = data.get("firm") or {}
    return FirmProfile(
        name=str(firm.get("name") or "(unnamed firm)"),
        states=[str(s) for s in (firm.get("states") or [])],
        doc_aliases={str(k): str(v)
                     for k, v in (firm.get("doc_aliases") or {}).items()},
        constants_channel_configured=bool(
            firm.get("constants_channel_configured", False)),
        roster_size=int(firm.get("roster_size", 0) or 0),
        forms_handled=[str(f) for f in (firm.get("forms_handled") or [])],
    )


__all__ = [
    "FirmProfile", "ReadinessReport", "resolve_doc_type", "assess_readiness",
    "render_readiness", "load_profile",
]
