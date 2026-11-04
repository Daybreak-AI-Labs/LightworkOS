"""Vendor-paper review: is it a DPA or an Addendum, where does it depart from
our standard position, and what exact language fixes it.

When a vendor insists on *their* paper, a privacy reviewer does three things by
hand: work out which instrument they actually sent, read it against our
template, and mark up the clauses that fall short. This module does all three,
with a deliberate split of authority:

* **Deterministic finds the gaps.** Which clauses are missing, weak, or
  contradicted is decided by pattern checks against a fixed checklist -- the
  Art. 28 list in :mod:`maverick.privacy_ops` for a DPA, and the CCPA/CPRA
  service-provider list here for an Addendum. A model never gets to invent a
  finding, and never gets to clear one.
* **The model only drafts prose.** Opus (via ``get_role_model("reviewer")``,
  never a hard-coded id) is asked to tailor our standard clause to the
  vendor's defined terms and numbering so the redline reads like their
  document. If it is unavailable, unaffordable, or returns something that
  drifts from our position, we fall back to our template language verbatim.
  The gap list is identical either way.
* **The instrument choice defers to the jurisdiction guard.** Classification
  here reads the document; when intake facts are known, the caller passes them
  and the deterministic jurisdiction table wins, mirroring the concierge's
  existing contract guard.

Output is a set of :class:`~maverick.docx_redline.ClauseEdit` objects plus a
reviewer-facing concern list, so the same result drives both the analysis
report and the tracked-changes document.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

INSTRUMENTS = ("dpa", "addendum")
INSTRUMENT_LABELS = {"dpa": "Data Processing Agreement",
                     "addendum": "Privacy Addendum"}

# --- classification -------------------------------------------------------

# Signals that the document IS a GDPR Art. 28 processing agreement.
_DPA_SIGNALS = (
    (r"\bdata processing agreement\b", 5),
    (r"\bdata processing addendum\b", 4),
    (r"\barticle 28\b|\bart\.? ?28\b", 5),
    (r"\bgdpr\b|\bgeneral data protection regulation\b", 3),
    (r"\bdata (?:controller|exporter)\b", 2),
    (r"\bdata (?:processor|importer)\b", 2),
    (r"\bstandard contractual clauses\b|\bsccs?\b", 3),
    (r"\bsub-?processor", 2),
    (r"\bsupervisory authority\b", 2),
    (r"\bdata subject\b", 1),
)

# Signals that it is a US state-privacy addendum (service-provider terms).
_ADDENDUM_SIGNALS = (
    (r"\bprivacy addendum\b", 5),
    (r"\bccpa\b|\bcpra\b", 5),
    (r"\bcalifornia consumer privacy act\b", 5),
    (r"\bservice provider\b", 3),
    (r"\bbusiness purpose\b", 3),
    (r"\bsell\b.{0,30}\bpersonal information\b|\bsale of personal information\b", 3),
    (r"\bshare\b.{0,30}\bcross-context\b|\bcross-context behavio", 3),
    (r"\bconsumer\b", 1),
    (r"\bpersonal information\b", 1),
)


def _score(text_low: str, signals: tuple[tuple[str, int], ...]) -> tuple[int, list[str]]:
    total = 0
    hits: list[str] = []
    for pattern, weight in signals:
        if re.search(pattern, text_low):
            total += weight
            hits.append(pattern)
    return total, hits


def classify_instrument(text: str, *, filename: str = "") -> dict:
    """Which instrument the vendor actually sent.

    Scores GDPR/Art. 28 signals against US service-provider signals across the
    document *and* the filename. Ties and thin documents resolve to the
    stronger instrument (DPA) and say so, because under-classifying a DPA as an
    addendum drops the Art. 28 obligations entirely."""
    body = (text or "")[:400_000]
    low = f"{filename} \n {body}".lower()
    dpa_score, dpa_hits = _score(low, _DPA_SIGNALS)
    add_score, add_hits = _score(low, _ADDENDUM_SIGNALS)

    if dpa_score == 0 and add_score == 0:
        return {"instrument": "dpa", "confidence": "low",
                "dpa_score": 0, "addendum_score": 0, "signals": [],
                "reason": ("no recognisable processing-agreement language was "
                           "found — defaulting to the stronger instrument "
                           "(DPA); a human must confirm what this document is")}
    if add_score > dpa_score:
        margin = add_score - dpa_score
        return {"instrument": "addendum",
                "confidence": "high" if margin >= 4 else "medium",
                "dpa_score": dpa_score, "addendum_score": add_score,
                "signals": add_hits,
                "reason": ("US state-privacy service-provider language "
                           f"predominates (score {add_score} vs {dpa_score})")}
    margin = dpa_score - add_score
    return {"instrument": "dpa",
            "confidence": "high" if margin >= 4 else "medium",
            "dpa_score": dpa_score, "addendum_score": add_score,
            "signals": dpa_hits,
            "reason": ("GDPR Art. 28 processing language predominates "
                       f"(score {dpa_score} vs {add_score})"
                       if margin else
                       "signals are evenly balanced — defaulting to the "
                       "stronger instrument (DPA)")}


# --- our standard positions ----------------------------------------------

# The CCPA/CPRA service-provider contract requirements, in the same shape as
# privacy_ops.DPA_CHECKLIST: (key, requirement, citation, severity, patterns).
ADDENDUM_CHECKLIST: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    ("limited_purpose", "Processing limited to specified business purposes",
     "Cal. Civ. Code 1798.100(d)(1)", "high",
     (r"business purpose", r"specified purpose", r"limited purpose")),
    ("no_sale", "Prohibition on selling or sharing personal information",
     "Cal. Civ. Code 1798.140(ag)(1)(A)", "high",
     (r"not sell", r"shall not sell", r"no sale of personal",
      r"not .{0,20}share")),
    ("no_retention_outside", "No retention, use, or disclosure outside the "
     "direct business relationship",
     "Cal. Civ. Code 1798.140(ag)(1)(B)", "high",
     (r"outside .{0,30}direct business relationship",
      r"not retain.{0,40}(?:use|disclos)")),
    ("no_combining", "No combining with personal information from other sources",
     "11 CCR 7051(a)(4)", "medium",
     (r"not combine", r"shall not combine", r"combin\w+ .{0,30}other source")),
    ("compliance_obligations", "Service provider complies with applicable "
     "obligations and provides the same protections",
     "Cal. Civ. Code 1798.100(d)(2)", "high",
     (r"comply with .{0,40}(?:ccpa|cpra|applicable privacy)",
      r"same level of privacy protection")),
    ("remediation_rights", "Business may take reasonable steps to stop and "
     "remediate unauthorised use", "Cal. Civ. Code 1798.100(d)(4)", "medium",
     (r"remediat", r"stop and remediate", r"reasonable steps")),
    ("noncompliance_notice", "Notice to the business on inability to comply",
     "Cal. Civ. Code 1798.100(d)(3)", "medium",
     (r"notify .{0,40}(?:no longer|unable to) (?:meet|comply)",
      r"inability to comply")),
    ("monitoring", "Business may monitor compliance",
     "11 CCR 7051(a)(7)", "medium",
     (r"monitor", r"audit", r"assess.{0,20}compliance")),
    ("deletion", "Deletion or return of personal information on termination",
     "Cal. Civ. Code 1798.105", "high",
     (r"delete", r"return .{0,30}personal information", r"destro")),
    ("subcontractors", "Flow-down of equivalent terms to subcontractors",
     "11 CCR 7051(c)", "medium",
     (r"subcontractor", r"sub-?processor", r"flow.?down")),
)

# Our standard clause language, per checklist key. This is the fallback that
# ships in the redline when no model is available -- so the deliverable is
# always complete, never a stub.
OUR_POSITIONS: dict[str, str] = {
    # GDPR Art. 28 (keys mirror privacy_ops.DPA_CHECKLIST)
    "instructions": (
        "Processor shall process personal data only on documented instructions "
        "from Controller, including with regard to transfers, unless required "
        "to do so by applicable law, in which case Processor shall inform "
        "Controller of that legal requirement before processing unless that law "
        "prohibits such information on important grounds of public interest."),
    "confidentiality": (
        "Processor shall ensure that persons authorised to process the personal "
        "data have committed themselves to confidentiality or are under an "
        "appropriate statutory obligation of confidentiality."),
    "security": (
        "Processor shall implement and maintain appropriate technical and "
        "organisational measures to ensure a level of security appropriate to "
        "the risk, including encryption of personal data in transit and at "
        "rest, ongoing confidentiality, integrity, availability and resilience "
        "of processing systems, and regular testing of those measures."),
    "subprocessors": (
        "Processor shall not engage another processor without Controller's "
        "prior specific or general written authorisation. Where general "
        "authorisation applies, Processor shall inform Controller of any "
        "intended addition or replacement of sub-processors at least thirty "
        "(30) days in advance and shall give Controller the opportunity to "
        "object. Processor shall impose on each sub-processor data protection "
        "obligations equivalent to those set out in this Agreement and remains "
        "fully liable for the sub-processor's performance."),
    "assistance": (
        "Taking into account the nature of the processing, Processor shall "
        "assist Controller by appropriate technical and organisational measures "
        "for the fulfilment of Controller's obligation to respond to requests "
        "for exercising the data subject's rights, and shall assist Controller "
        "in ensuring compliance with the obligations under Articles 32 to 36."),
    "breach": (
        "Processor shall notify Controller without undue delay and in any event "
        "within seventy-two (72) hours after becoming aware of a personal data "
        "breach, and shall provide sufficient information to allow Controller "
        "to meet its own notification obligations."),
    "deletion": (
        "At Controller's election, Processor shall delete or return all personal "
        "data to Controller after the end of the provision of services relating "
        "to processing, and shall delete existing copies unless applicable law "
        "requires storage of the personal data. Processor shall certify "
        "deletion in writing on request."),
    "audit": (
        "Processor shall make available to Controller all information necessary "
        "to demonstrate compliance with the obligations laid down in Article 28 "
        "and shall allow for and contribute to audits, including inspections, "
        "conducted by Controller or another auditor mandated by Controller."),
    "transfers": (
        "Processor shall not transfer personal data outside the European "
        "Economic Area or the United Kingdom without implementing a valid "
        "Chapter V transfer mechanism, including the Standard Contractual "
        "Clauses together with a documented transfer impact assessment and any "
        "supplementary measures the assessment identifies as necessary."),
    "retention": (
        "Processor shall retain personal data only for as long as necessary to "
        "provide the services or as required by applicable law, and shall apply "
        "the documented retention periods agreed with Controller."),
    # CCPA / CPRA service-provider positions
    "limited_purpose": (
        "Service Provider shall process personal information solely for the "
        "specified business purposes set out in the Agreement and for no other "
        "purpose, and shall not process it for its own commercial purposes."),
    "no_sale": (
        "Service Provider shall not sell or share personal information as those "
        "terms are defined under the California Consumer Privacy Act, as "
        "amended."),
    "no_retention_outside": (
        "Service Provider shall not retain, use, or disclose personal "
        "information outside the direct business relationship with Business or "
        "for any purpose other than the specified business purposes."),
    "no_combining": (
        "Service Provider shall not combine personal information received from "
        "Business with personal information received from or on behalf of any "
        "other person, or collected from its own interaction with the consumer, "
        "except as permitted by applicable law."),
    "compliance_obligations": (
        "Service Provider shall comply with all applicable obligations under "
        "the California Consumer Privacy Act and shall provide the same level "
        "of privacy protection as required of Business."),
    "remediation_rights": (
        "Business may take reasonable and appropriate steps to stop and "
        "remediate any unauthorised use of personal information by Service "
        "Provider."),
    "noncompliance_notice": (
        "Service Provider shall notify Business promptly, and in any event "
        "within five (5) business days, if it determines that it can no longer "
        "meet its obligations under applicable privacy law."),
    "monitoring": (
        "Business may take reasonable and appropriate steps to monitor Service "
        "Provider's compliance with this Addendum, including through manual "
        "review, automated scanning, or independent assessment."),
    "subcontractors": (
        "Service Provider shall impose obligations equivalent to those in this "
        "Addendum on any subcontractor that processes personal information, and "
        "remains responsible for the subcontractor's performance."),
}


# --- the operator's playbook ---------------------------------------------

PLAYBOOK_FILENAME = "clause_playbook.json"


def playbook_path():
    """Where the operator's clause playbook lives.

    ``[paper_review] playbook_path`` wins; otherwise it sits beside the other
    governed data under the Lightwork home."""
    from pathlib import Path
    try:
        from .config import load_config
        configured = ((load_config() or {}).get("paper_review") or {}).get(
            "playbook_path")
        if configured:
            return Path(str(configured)).expanduser()
    except Exception:  # pragma: no cover -- config read never breaks a review
        pass
    from .paths import data_dir
    return data_dir("privacy") / PLAYBOOK_FILENAME


def default_playbook() -> dict:
    """The shipped positions, as a plain dict an operator can edit."""
    return dict(OUR_POSITIONS)


def write_playbook(positions: dict | None = None, *, path=None):
    """Write a starter playbook the operator can edit. Returns the path.

    This is the setup step for a real engagement: the shipped clauses are OUR
    standard positions, and a customer's are their own."""
    import json
    from pathlib import Path
    target = Path(path) if path else playbook_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_comment": ("Your standard clause positions. Each key is a clause id "
                     "from the Art. 28 or CCPA checklist; the value is the "
                     "exact language a vendor's paper must be redlined to. "
                     "Keys you omit fall back to the shipped position."),
        "positions": dict(positions if positions is not None
                          else default_playbook()),
    }
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    try:
        target.chmod(0o600)
    except OSError:  # pragma: no cover -- best effort on odd filesystems
        pass
    return target


def load_playbook() -> dict:
    """Our positions with the operator's playbook layered on top.

    Falls back to the shipped positions entirely -- a missing, unreadable, or
    malformed playbook must never leave a redline with empty clauses."""
    import json
    positions = default_playbook()
    try:
        path = playbook_path()
        if not path.exists():
            return positions
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # pragma: no cover -- a bad file degrades, never raises
        log.warning("paper_review: playbook unreadable (%s); using the shipped "
                    "positions", e)
        return positions
    body = raw.get("positions") if isinstance(raw, dict) else None
    if not isinstance(body, dict):
        log.warning("paper_review: playbook has no 'positions' object; using "
                    "the shipped positions")
        return positions
    for key, text in body.items():
        if isinstance(key, str) and isinstance(text, str) and text.strip():
            positions[key] = text.strip()
    return positions


@dataclass
class Concern:
    """One departure from our standard position, for the analysis report."""

    clause_key: str
    requirement: str
    citation: str
    severity: str
    status: str                 # missing | unclear | present
    their_language: str = ""
    our_position: str = ""
    proposed: str = ""
    drafted_by: str = "template"   # "template" | "model"

    def to_dict(self) -> dict:
        return {
            "clause_key": self.clause_key, "requirement": self.requirement,
            "citation": self.citation, "severity": self.severity,
            "status": self.status,
            "their_language": self.their_language[:600],
            "our_position": self.our_position,
            "proposed": self.proposed, "drafted_by": self.drafted_by,
        }


@dataclass
class PaperReview:
    """The full result: what it is, where it falls short, and the edits."""

    vendor: str
    instrument: str
    classification: dict = field(default_factory=dict)
    concerns: list[Concern] = field(default_factory=list)
    clauses_total: int = 0
    clauses_present: int = 0
    document_name: str = ""
    drafted_with_model: bool = False
    # The paragraphs the analysis actually read. The reconstructed-redline path
    # (PDF uploads) rebuilds from exactly these, so the document we mark up and
    # the document we reasoned about can never diverge.
    source_paragraphs: list[str] = field(default_factory=list, repr=False)

    @property
    def gaps(self) -> list[Concern]:
        return [c for c in self.concerns if c.status != "present"]

    @property
    def high_severity_gaps(self) -> int:
        return sum(1 for c in self.gaps if c.severity == "high")

    @property
    def recommendation(self) -> str:
        """Deterministic: never a model's opinion on whether to sign."""
        if self.high_severity_gaps:
            return "do_not_sign_without_changes"
        return "acceptable_with_changes" if self.gaps else "acceptable"

    def edits(self) -> list:
        """The tracked-changes edit list for :mod:`maverick.docx_redline`."""
        from .docx_redline import ClauseEdit
        out = []
        for c in self.gaps:
            out.append(ClauseEdit(find=c.their_language, replace=c.proposed,
                                  note=c.requirement, clause_key=c.clause_key,
                                  scope="paragraph"))
        return out

    def to_dict(self) -> dict:
        return {
            "vendor": self.vendor, "instrument": self.instrument,
            "instrument_label": INSTRUMENT_LABELS.get(self.instrument,
                                                      self.instrument),
            "document_name": self.document_name,
            "classification": self.classification,
            "clauses_total": self.clauses_total,
            "clauses_present": self.clauses_present,
            "gaps": len(self.gaps),
            "high_severity_gaps": self.high_severity_gaps,
            "recommendation": self.recommendation,
            "drafted_with_model": self.drafted_with_model,
            "concerns": [c.to_dict() for c in self.concerns],
        }


def _checklist_for(instrument: str):
    if instrument == "addendum":
        return ADDENDUM_CHECKLIST
    from .privacy_ops import DPA_CHECKLIST
    return DPA_CHECKLIST


def _paragraphs(text: str) -> list[str]:
    """Document paragraphs, in original case. The docx extractor separates
    paragraphs with newlines; PDFs come through the same way."""
    return [p.strip() for p in re.split(r"\n+", text or "") if p.strip()]


def _locate_paragraph(paragraphs: list[str], patterns: tuple[str, ...]) -> str:
    """The vendor's own paragraph that a clause pattern matches, in original
    case -- the anchor a tracked change replaces. Empty when nothing matches
    (the clause is simply absent, so the edit becomes an insertion)."""
    for pattern in patterns:
        for para in paragraphs:
            if re.search(pattern, para.lower()):
                return para
    return ""


_NEGATED = re.compile(r"\b(?:not|no|without|never|excluded?)\b[^.;]{0,20}$")

# Language that affirmatively contracts for the OPPOSITE of our position.
#
# The shipped checklists detect *presence* -- "does the paper mention
# sub-processors" -- which is the right question for a completeness review but
# the wrong one here. A vendor paper that says "Processor may engage
# sub-processors at its sole discretion" mentions them and would score as
# satisfied, while actually granting itself the exact right our template
# withholds. These patterns catch that inversion, and a clause they hit is
# reported as ``conflicting``: worse than an omission, because the vendor has
# bargained for the opposite, so it escalates to high severity regardless of
# the checklist's default.
_ADVERSE: dict[str, tuple[str, ...]] = {
    # GDPR Art. 28
    "instructions": (r"for its own (?:commercial|business|internal) purposes",
                     r"any (?:lawful )?purpose it determines"),
    "subprocessors": (r"sole discretion", r"without (?:prior )?notice",
                      r"without (?:the )?(?:controller'?s? )?(?:prior )?"
                      r"(?:written )?(?:consent|authoris|authoriz|approval)",
                      r"no obligation to (?:notify|inform)"),
    "breach": (r"no obligation to notify",
               r"sole discretion .{0,40}(?:notify|breach)"),
    "deletion": (r"shall not (?:delete|return)",
                 r"no obligation to (?:delete|return)",
                 r"may retain .{0,60}indefinitely"),
    "audit": (r"no (?:audit|inspection) rights?", r"no right to (?:audit|inspect)",
              r"shall not (?:permit|allow) .{0,40}(?:audit|inspection)"),
    "transfers": (r"(?:processor'?s?|its) (?:sole )?discretion",
                  r"any (?:third )?countr\w+ (?:it|processor) (?:selects|chooses)",
                  r"without .{0,40}(?:safeguard|transfer mechanism)"),
    "assistance": (r"no obligation to assist",),
    "retention": (r"indefinitely", r"as long as .{0,20}deems"),
    # CCPA / CPRA
    "limited_purpose": (r"for its own (?:commercial|business) purposes",),
    "no_sale": (r"may sell", r"reserves the right to sell",
                r"may share .{0,40}(?:third part|cross-context)"),
    "no_combining": (r"may combine", r"combine[sd]? .{0,60}other sources?"),
    "no_retention_outside": (r"may (?:retain|use|disclose) .{0,40}"
                             r"(?:its own|other) purpose",),
    "subcontractors": (r"sole discretion", r"without (?:prior )?notice"),
}


# What each clause is ABOUT. Adverse phrases like "sole discretion" are
# generic and appear in many clauses, so an unscoped scan lets one clause
# anchor onto another's paragraph -- e.g. the transfers clause claiming the
# sub-processor sentence, which then leaves a real edit unapplied. A paragraph
# only counts as adverse for a clause when it is on that clause's subject.
_TOPIC: dict[str, str] = {
    "instructions": r"instruction|process(?:es|ing)? .{0,30}personal data",
    "confidentiality": r"confidential",
    "security": r"secur|encrypt|technical and organisational",
    "subprocessors": r"sub-?processor|subcontract",
    "assistance": r"assist|data subject|dsar",
    "breach": r"breach|security incident",
    "deletion": r"delet|destro|return .{0,30}(?:data|information)",
    "audit": r"audit|inspect",
    "transfers": r"transfer|third countr|outside the (?:eu|eea|european)|"
                 r"international",
    "retention": r"retain|retention|storage period",
    "limited_purpose": r"purpose",
    "no_sale": r"sell|sale|shar",
    "no_retention_outside": r"retain|use|disclos",
    "no_combining": r"combin",
    "compliance_obligations": r"compl(?:y|iance)",
    "remediation_rights": r"remediat|reasonable steps",
    "noncompliance_notice": r"notif|unable to|no longer",
    "monitoring": r"monitor|audit|assess",
    "subcontractors": r"subcontractor|sub-?processor",
}


def _adverse_paragraph(paragraphs: list[str], key: str) -> str:
    """The vendor paragraph that contracts against our position, if any.

    Requires the paragraph to be on this clause's subject AND to carry adverse
    language, so a generic phrase cannot drag an unrelated paragraph in."""
    adverse = _ADVERSE.get(key, ())
    if not adverse:
        return ""
    topic = _TOPIC.get(key)
    for para in paragraphs:
        low = para.lower()
        if topic and not re.search(topic, low):
            continue
        if any(re.search(pattern, low) for pattern in adverse):
            return para
    return ""


def _clause_status(para: str, pattern_hit: bool, patterns: tuple[str, ...]) -> str:
    if not pattern_hit:
        return "missing"
    low = para.lower()
    for pattern in patterns:
        m = re.search(pattern, low)
        if m and _NEGATED.search(low[max(0, m.start() - 30):m.start()]):
            return "unclear"
    return "present"


def analyze(text: str, *, vendor: str = "", instrument: str = "",
            document_name: str = "") -> PaperReview:
    """Deterministic comparison of vendor paper against our standard positions.

    No model is consulted: this is the authoritative gap list."""
    classification = classify_instrument(text, filename=document_name)
    chosen = instrument if instrument in INSTRUMENTS else classification["instrument"]
    paragraphs = _paragraphs(text)
    positions = load_playbook()
    concerns: list[Concern] = []
    present = 0
    for key, requirement, citation, severity, patterns in _checklist_for(chosen):
        # Adverse language wins over presence: a paper that grants the vendor
        # the opposite right still "mentions" the topic, so checking presence
        # first would score it satisfied.
        adverse = _adverse_paragraph(paragraphs, key)
        if adverse:
            para, status, severity = adverse, "conflicting", "high"
        else:
            para = _locate_paragraph(paragraphs, patterns)
            status = _clause_status(para, bool(para), patterns)
        if status == "present":
            present += 1
        concerns.append(Concern(
            clause_key=key, requirement=requirement, citation=citation,
            severity=severity, status=status,
            their_language=para if status != "missing" else "",
            our_position=positions.get(key, ""),
            proposed=positions.get(key, ""),
        ))
    return PaperReview(
        vendor=vendor, instrument=chosen, classification=classification,
        concerns=concerns, clauses_total=len(concerns), clauses_present=present,
        document_name=document_name, source_paragraphs=paragraphs)


_DRAFT_SYSTEM = (
    "You are a privacy counsel redlining a vendor's contract. You will be given "
    "our REQUIRED position for one clause and, if present, the vendor's current "
    "wording. Rewrite our required position so it fits the vendor's defined "
    "terms, numbering and drafting style.\n"
    "Hard rules: never weaken, qualify, or add exceptions to our position; "
    "never add commentary, headings, quotes or markdown; return ONLY the clause "
    "text as a single paragraph. If you cannot preserve our position exactly, "
    "return our position unchanged."
)

# Substantive terms whose loss would silently weaken our position. If the model
# drops one that our template had, we keep the template language instead.
_LOAD_BEARING = ("shall", "not", "without", "prior", "written", "notify",
                 "delete", "encrypt", "audit", "72", "seventy-two", "equivalent")


def _acceptable_draft(drafted: str, ours: str) -> bool:
    """A model draft is accepted only if it stays recognisably our clause: a
    real sentence, similar length, and it must not drop a load-bearing term
    that our own language relies on."""
    text = (drafted or "").strip()
    if len(text) < 40 or len(text) > max(1200, len(ours) * 3):
        return False
    if "\n" in text.strip() or text.lstrip().startswith(("#", "-", "*", "`")):
        return False
    low, ours_low = text.lower(), ours.lower()
    for term in _LOAD_BEARING:
        if term in ours_low and term not in low:
            return False
    return True


def draft_language(review: PaperReview, *, budget_dollars: float = 2.0) -> PaperReview:
    """Tailor each proposed clause to the vendor's drafting, using the reviewer
    role model (Opus by configuration, never hard-coded).

    Degrades silently and completely: with no provider key, no budget, or a
    draft that drifts from our position, the template language stands. The gap
    list is never altered here -- only the prose."""
    gaps = review.gaps
    if not gaps:
        return review
    try:
        from .budget import Budget
        from .llm import LLM, model_for_role
    except Exception:  # pragma: no cover -- kernel always ships these
        return review
    try:
        llm = LLM(model_for_role("reviewer"))
    except Exception as e:  # pragma: no cover -- provider/config variance
        log.debug("paper_review: model unavailable, using template text: %s", e)
        return review

    # One budget across the whole redline: caps are enforced at record time, so
    # every dimension we will cross has to be raised together.
    budget = Budget(max_dollars=budget_dollars, max_output_tokens=60_000,
                    max_tool_calls=0)
    for concern in gaps:
        ours = concern.our_position
        if not ours:
            continue
        theirs = concern.their_language
        prompt = (f"Clause: {concern.requirement} ({concern.citation})\n\n"
                  f"OUR REQUIRED POSITION:\n{ours}\n\n"
                  + (f"VENDOR'S CURRENT WORDING:\n{theirs[:1500]}\n\n"
                     if theirs else "The vendor's paper omits this clause "
                                    "entirely.\n\n")
                  + "Return only the clause text to insert.")
        try:
            resp = llm.complete(
                system=_DRAFT_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
                budget=budget, max_tokens=700)
            drafted = (getattr(resp, "text", "") or "").strip()
        except Exception as e:  # pragma: no cover -- network/budget variance
            log.debug("paper_review: draft failed for %s: %s",
                      concern.clause_key, e)
            break
        if _acceptable_draft(drafted, ours):
            concern.proposed = drafted
            concern.drafted_by = "model"
            review.drafted_with_model = True
    return review


_STATUS_LABEL = {
    "missing": "MISSING",
    "conflicting": "CONFLICTS WITH OUR POSITION",
    "unclear": "UNCLEAR / NEGATED",
    "present": "meets our position",
}

_RECOMMENDATION_LABEL = {
    "do_not_sign_without_changes":
        "DO NOT SIGN as drafted — high-severity gaps must be closed first.",
    "acceptable_with_changes":
        "Acceptable once the attached tracked changes are accepted.",
    "acceptable": "Acceptable — no departures from our standard position.",
}


def analysis_memo(review: PaperReview, *, version: int = 1,
                  reviewed_by: str = "", redline_filename: str = "",
                  redline_result=None, now: float | None = None,
                  closed_from_previous: list | None = None,
                  previous_version: int = 0) -> str:
    """The reviewer-facing memo that accompanies the redline.

    Plain text on purpose: it has to stay readable in a document preview
    (OneTrust's, a dashboard's), and it must state what was NOT done as
    plainly as what was."""
    import time as _time
    d = review.to_dict()
    stamp = _time.strftime("%Y-%m-%dT%H:%M:%SZ",
                           _time.gmtime(now if now is not None else _time.time()))
    lines = [
        f"VENDOR PAPER REVIEW — {review.vendor}  (v{version})",
        "=" * 68,
        f"Document reviewed : {review.document_name}",
        f"Instrument        : {d['instrument_label']} "
        f"({d['classification'].get('confidence', 'unknown')} confidence)",
        f"                    {d['classification'].get('reason', '')}",
        f"Reviewed by       : {reviewed_by}",
        f"Reviewed at       : {stamp}",
        f"Clause coverage   : {d['clauses_present']} of {d['clauses_total']} "
        "meet our standard position",
        f"Departures        : {d['gaps']} "
        f"({d['high_severity_gaps']} high severity)",
        "",
        "RECOMMENDATION",
        "-" * 68,
        _RECOMMENDATION_LABEL.get(d["recommendation"], d["recommendation"]),
        "",
    ]
    if closed_from_previous is not None and previous_version:
        lines += ["NEGOTIATION PROGRESS", "-" * 68]
        if closed_from_previous:
            lines.append(
                f"This draft closes {len(closed_from_previous)} of the "
                f"change(s) we demanded in v{previous_version}:")
            lines += [f"   + {c}" for c in closed_from_previous]
        else:
            lines.append(
                f"None of the changes we demanded in v{previous_version} "
                "were accepted in this draft.")
        if d["gaps"]:
            lines.append(f"{d['gaps']} demand(s) remain open — see CONCERNS.")
        lines.append("")
    lines += [
        "CONCERNS",
        "-" * 68,
    ]
    gaps = review.gaps
    if not gaps:
        lines.append("None. Every checked clause meets our standard position.")
    for i, c in enumerate(gaps, start=1):
        lines += [
            f"{i}. [{c.severity.upper()}] {c.requirement}",
            f"   Basis          : {c.citation}",
            f"   Status         : {_STATUS_LABEL.get(c.status, c.status)}",
        ]
        if c.their_language:
            lines.append(f"   Their wording  : {c.their_language[:300]}")
        source = ("model-tailored to their drafting"
                  if c.drafted_by == "model" else "our standard template")
        lines += [
            f"   Required change: {c.proposed[:600]}",
            f"   Language source: {source}",
            "",
        ]
    if redline_filename:
        lines += ["TRACKED-CHANGES DOCUMENT", "-" * 68,
                  f"Attached as: {redline_filename}"]
    if redline_result is not None:
        r = redline_result.to_dict()
        lines.append(
            f"{r['applied']} full paragraph(s) marked up in place, "
            f"{r['inserted']} clause(s) proposed as additions.")
        if r["synthesized"]:
            lines.append(
                "The vendor supplied a PDF, so the redline is a reconstruction "
                "of the text we could read; their original file was not "
                "modified.")
        if r["unmatched"]:
            lines.append(
                f"{len(r['unmatched'])} required change(s) could NOT be "
                "safely applied to a full paragraph and require manual review:")
            lines += [f"   - {u}" for u in r["unmatched"]]
            explanations = {
                "scope_mismatch": "The anchor covers only part of a paragraph or a different paragraph. Supply the complete paragraph and replacement.",
                "ambiguous_match": "The same text appears in multiple paragraphs. Select an exact location in the original source.",
                "unsupported_inline_structure": "The target contains formatting, links, bookmarks, fields or revisions this editor cannot safely preserve.",
                "stale_source": "The selected location belongs to a different source version.",
                "invalid_location": "The selected source location is invalid.",
                "conflicting_edit": "Another proposed change already targets this paragraph.",
                "unsupported_scope": "Only complete paragraph replacements are supported.",
                "not_found": "The full paragraph was not found in this source.",
                "empty_edit": "The proposal contains no replacement or insertion.",
            }
            for outcome in r.get("edit_results", []):
                if outcome.get("status") == "needs_review":
                    reason = explanations.get(outcome.get("reason"), "Manual review required.")
                    lines.append(f"   Edit {outcome['edit_index'] + 1}: {reason}")
    lines += [
        "",
        "HOW TO READ THIS",
        "-" * 68,
        "Gap findings are produced deterministically from our clause "
        "checklists — a model cannot create or clear a finding. Where a model "
        "was available it only re-drafted our required language to match the "
        "vendor's defined terms, and any draft that weakened our position was "
        "discarded in favour of the template wording.",
    ]
    return "\n".join(lines)


def requirement_labels(instrument: str) -> dict:
    """Clause key -> human requirement, for reporting on clauses that are no
    longer gaps (their concern objects don't exist in the current review)."""
    return {row[0]: row[1] for row in _checklist_for(instrument)}


# --- drafting OUR paper ----------------------------------------------------

_PARTY_TERMS = {"dpa": ("Controller", "Processor"),
                "addendum": ("Business", "Service Provider")}

_DRAFT_TITLES = {"dpa": "DATA PROCESSING AGREEMENT",
                 "addendum": "CCPA/CPRA SERVICE-PROVIDER ADDENDUM"}


@dataclass
class OurPaperDraft:
    """Our template instrument, filled for one vendor. ``filled`` names every
    value that was auto-inserted -- exactly the runs rendered in red."""

    vendor: str
    instrument: str
    content: bytes
    filled: list = field(default_factory=list)
    clause_count: int = 0

    def to_dict(self) -> dict:
        return {"vendor": self.vendor, "instrument": self.instrument,
                "instrument_label": INSTRUMENT_LABELS.get(self.instrument,
                                                          self.instrument),
                "filled": list(self.filled),
                "clause_count": self.clause_count,
                "bytes": len(self.content)}


def draft_our_paper(vendor: str, *, instrument: str = "dpa",
                    org: str = "", effective_date: str = "") -> OurPaperDraft:
    """When the vendor signs OUR paper: our template instrument as a real
    ``.docx``, with every vendor-specific value auto-filled **in red** so
    counsel sees at a glance what the machine inserted and what is template.

    Entirely deterministic -- the clause language is the operator's playbook
    (shipped positions underneath), never a model's drafting. A missing org
    name or date becomes a red bracketed placeholder rather than a guess."""
    if instrument not in _PARTY_TERMS:
        raise ValueError(f"unknown instrument {instrument!r}")
    from .docx_redline import build_docx
    us, them = _PARTY_TERMS[instrument]
    org = (org or "").strip() or str(_config().get("org_name", "")).strip()
    positions = load_playbook()
    checklist = _checklist_for(instrument)

    filled: list[str] = []

    def fill(value: str, placeholder: str, label: str) -> tuple:
        shown = value or placeholder
        filled.append(f"{label}: {shown}")
        return (shown, True)

    vendor_run = fill((vendor or "").strip(), f"[{them.upper()} LEGAL ENTITY]",
                      them.lower())
    org_run = fill(org, f"[{us.upper()} LEGAL ENTITY]", us.lower())
    date_run = fill((effective_date or "").strip(), "[EFFECTIVE DATE]",
                    "effective date")

    blocks: list[tuple] = [
        ("title", [(_DRAFT_TITLES[instrument], False)]),
        ("para", []),
        ("para", [
            ("This agreement is entered into between ", False), org_run,
            (f' (the "{us}") and ', False), vendor_run,
            (f' (the "{them}"), effective as of ', False), date_run,
            (". Values shown in red were inserted for this vendor and must "
             "be verified before signature; all other language is our "
             "standard position.", False)]),
        ("para", []),
    ]
    for i, row in enumerate(checklist, start=1):
        key, requirement, citation = row[0], row[1], row[2]
        blocks.append(("heading", [(f"{i}. {requirement} ({citation})",
                                    False)]))
        blocks.append(("para", [(positions.get(key, OUR_POSITIONS.get(
            key, "")), False)]))
        blocks.append(("para", []))
    blocks += [
        ("heading", [("Signatures", False)]),
        ("para", [(f"For the {us}: ", False),
                  ("[name, title, date]", True)]),
        ("para", [(f"For the {them}: ", False),
                  ("[name, title, date]", True)]),
    ]
    return OurPaperDraft(vendor=(vendor or "").strip(), instrument=instrument,
                         content=build_docx(blocks, footer_title=_DRAFT_TITLES[instrument]), filled=filled,
                         clause_count=len(checklist))


def _config() -> dict:
    try:
        from .config import load_config
        return (load_config() or {}).get("paper_review") or {}
    except Exception:  # pragma: no cover -- config read never breaks a review
        return {}


def review_paper(text: str, *, vendor: str = "", instrument: str = "",
                 document_name: str = "",
                 use_model: bool | None = None) -> PaperReview:
    """Classify, compare against our template, and draft the clause edits.

    ``use_model=None`` defers to ``[paper_review] use_model`` in config, which
    an operator can set to false so no model ever sees a vendor contract. The
    gap findings are identical either way -- only the wording of the proposed
    clauses changes."""
    review = analyze(text, vendor=vendor, instrument=instrument,
                     document_name=document_name)
    cfg = _config()
    if use_model is None:
        use_model = bool(cfg.get("use_model", True))
    if use_model:
        review = draft_language(
            review, budget_dollars=float(cfg.get("draft_budget_dollars", 2.0)))
    return review


__all__ = ["INSTRUMENTS", "INSTRUMENT_LABELS", "ADDENDUM_CHECKLIST",
           "OUR_POSITIONS", "PLAYBOOK_FILENAME", "Concern", "PaperReview",
           "OurPaperDraft", "classify_instrument", "analyze",
           "draft_language", "review_paper", "analysis_memo",
           "draft_our_paper", "requirement_labels", "playbook_path",
           "default_playbook", "write_playbook", "load_playbook"]
