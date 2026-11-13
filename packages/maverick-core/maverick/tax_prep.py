"""Tax preparation pipeline: uploaded documents -> first-pass draft return.

The flagship professional-services workflow. A client uploads source
documents; the ``tax_`` suite's agents classify and extract them; this
module is the DETERMINISTIC core they feed: typed source documents in,
standardized workpaper out, first-pass Form 1040 + state computation on
top, and a review package where **every number cites the document it came
from**.

Division of labor (the architecture's spine):

* **Agents** (tax_ packs) do the unstructured work at runtime -- chasing
  missing documents, OCR/extraction from PDFs, client communications --
  and feed structured :class:`SourceDoc` records into this module. The
  firm's professional tax engine (CCH Axcess / GoSystem, via the
  ``cch_axcess`` / ``gosystem_tax`` connectors) remains the authoritative
  computation and filing system; this first pass is the prep accelerant
  and cross-check in front of it.
* **This module** does everything that must be exactly right and provable:
  classification schemas, workpaper assembly, completeness checks, the
  TY2025 federal computation, the flat/no-tax state computation, and the
  review package. Pure functions, no LLM, unit-tested against
  hand-computed returns.
* **The CPA** reviews and signs. The draft is labeled as a first pass for
  preparer review; filing and certification are human acts (the same
  "agents draft; humans file and certify" discipline as the finance suite).

Scope of the v1 computation (stated, not hidden): Form 1040 with W-2 wages,
1099-INT interest, ordinary 1099-DIV dividends (all taxed at ordinary rates;
box 1b qualified dividends are read and flagged for the preparer, who applies
the preferential rates), the standard deduction, the child tax credit, and
federal withholding; plus state returns for no-tax
and flat-rate states (graduated states are flagged for the preparer / the
tax engine). Itemizing, Schedules C/D/E, retirement and benefit taxability,
and credits beyond the CTC are workpaper line items flagged FOR PREPARER
REVIEW rather than computed. Tax-year constants live in two tables
(``TY2025`` federal per the One Big Beautiful Bill Act; ``STATE_TY2025``)
and ship as content updates each season.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

DISCLAIMER = (
    "FIRST-PASS DRAFT prepared by Lightwork tax agents for preparer review. "
    "Not a filed return and not tax advice. A credentialed preparer must "
    "review, complete, and sign before filing."
)

DOC_TYPES = ("W-2", "1099-INT", "1099-DIV", "1099-NEC", "1099-B", "1099-R",
             "SSA-1099", "1099-G", "1098-T", "1098-E", "1098", "K-1",
             "PRIOR-RETURN", "UNKNOWN")

# Lexical signatures for deterministic classification of extracted text.
# Order matters: specific variants (1098-T/-E) before their generic prefix.
_DOC_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("W-2", ("w-2", "wage and tax statement", "wages, tips")),
    ("1099-INT", ("1099-int", "interest income")),
    ("1099-DIV", ("1099-div", "ordinary dividends")),
    ("1099-NEC", ("1099-nec", "nonemployee compensation")),
    ("1099-B", ("1099-b", "proceeds from broker")),
    ("1099-R", ("1099-r", "distributions from pensions")),
    ("SSA-1099", ("ssa-1099", "social security benefit")),
    ("1099-G", ("1099-g", "unemployment compensation",
                "certain government payments")),
    ("1098-T", ("1098-t", "tuition statement")),
    ("1098-E", ("1098-e", "student loan interest")),
    ("1098", ("1098", "mortgage interest")),
    ("K-1", ("schedule k-1", "k-1", "partner's share")),
    ("PRIOR-RETURN", ("form 1040", "u.s. individual income tax return")),
]

_MONEY_RE = re.compile(r"(-?)\$?\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)")
_STATE_TOKEN_RE = re.compile(r"\b([A-Z]{2})\b")
_REPORT_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_REPORT_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_REPORT_WHITESPACE_RE = re.compile(r"\s+")

# TY2025 federal constants (One Big Beautiful Bill Act, enacted July 2025).
# One table per tax year; updating next season is a content release.
TY2025 = {
    "year": 2025,
    "standard_deduction": {"single": 15750.0, "mfj": 31500.0, "hoh": 23625.0},
    "brackets": {  # (top of bracket, rate); top bracket open-ended
        "single": [(11925, .10), (48475, .12), (103350, .22), (197300, .24),
                   (250525, .32), (626350, .35), (None, .37)],
        "mfj": [(23850, .10), (96950, .12), (206700, .22), (394600, .24),
                (501050, .32), (751600, .35), (None, .37)],
        "hoh": [(17000, .10), (64850, .12), (103350, .22), (197300, .24),
                (250525, .32), (626350, .35), (None, .37)],
    },
    "ctc_per_child": 2200.0,
    "ctc_phaseout_start": {"single": 200000.0, "mfj": 400000.0,
                           "hoh": 200000.0},
    # Additional standard deduction per 65+/blind box (TY2025). SEASON
    # CONTENT: verify against the published Rev. Proc. figures each year.
    # Single/HoH: $2,000 per box; Married: $1,600 per box per spouse.
    "additional_standard_deduction": {"single": 2000.0, "mfj": 1600.0,
                                      "hoh": 2000.0},
}

FILING_STATUSES = ("single", "mfj", "hoh")

STATE_CODES = frozenset({
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA", "HI",
    "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN",
    "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH",
    "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA",
    "WV", "WI", "WY",
})

# TY2025 state constants for the states whose individual income tax is
# absent or a flat rate with a simple base. SEASON CONTENT: verify against
# each state's published TY2025 figures before a production season -- the
# preparer reviews every draft, and graduated/credit-structured states are
# deliberately NOT computed here (the professional tax engine owns those).
# "basis": what the flat rate applies to before the state deduction --
# federal AGI or federal taxable income.
STATE_TY2025: dict = {
    "year": 2025,
    "no_tax": frozenset({"AK", "FL", "NV", "NH", "SD", "TN", "TX", "WA", "WY"}),
    "flat": {
        "AZ": {"rate": .025, "basis": "agi",
               "deduction": {"single": 15750.0, "mfj": 31500.0, "hoh": 23625.0}},
        "CO": {"rate": .044, "basis": "federal_taxable",
               "deduction": {"single": 0.0, "mfj": 0.0, "hoh": 0.0}},
        "GA": {"rate": .0519, "basis": "agi",
               "deduction": {"single": 12000.0, "mfj": 24000.0, "hoh": 12000.0}},
        "ID": {"rate": .05695, "basis": "federal_taxable",
               "deduction": {"single": 0.0, "mfj": 0.0, "hoh": 0.0}},
        "IL": {"rate": .0495, "basis": "agi",
               "deduction": {"single": 2850.0, "mfj": 5700.0, "hoh": 2850.0}},
        "IN": {"rate": .03, "basis": "agi",
               "deduction": {"single": 1000.0, "mfj": 2000.0, "hoh": 1000.0}},
        "KY": {"rate": .04, "basis": "agi",
               "deduction": {"single": 3270.0, "mfj": 6540.0, "hoh": 3270.0}},
        "LA": {"rate": .03, "basis": "agi",
               "deduction": {"single": 12500.0, "mfj": 25000.0, "hoh": 12500.0}},
        "MI": {"rate": .0425, "basis": "agi",
               "deduction": {"single": 5800.0, "mfj": 11600.0, "hoh": 5800.0}},
        "NC": {"rate": .0425, "basis": "agi",
               "deduction": {"single": 12750.0, "mfj": 25500.0, "hoh": 19125.0}},
        "PA": {"rate": .0307, "basis": "agi",
               "deduction": {"single": 0.0, "mfj": 0.0, "hoh": 0.0}},
    },
    # Graduated states: same shape as "flat" but with a marginal "brackets"
    # list ([(top_of_bracket, rate), ..., (None, top_rate)]) instead of a
    # single rate. Deliberately empty in the built-in tables -- graduated
    # bracket tables are verified tax data that ships through the SIGNED
    # constants channel (maverick.tax_constants), not hard-coded here; until a
    # bundle supplies a state's brackets it is handed off to the preparer /
    # tax engine. The computation machinery (compute_state_first_pass) is ready.
    "graduated": {},
}


@dataclass
class SourceDoc:
    """One classified source document with its extracted figures.

    Figures split into two tiers: those the v1 computation consumes (wages,
    interest, ordinary dividends, withholding) and CARRIED figures from the
    broader document set (mortgage interest, retirement, social security,
    ...) -- extracted onto the workpaper for the preparer but never guessed
    into the return. ``confidence`` (0..1) and ``review_required`` surface a
    weak extraction so a misread is caught instead of flowing through.
    """
    doc_type: str
    label: str                       # e.g. "W-2 — Acme Corp"
    wages: float = 0.0               # W-2 box 1
    federal_withholding: float = 0.0  # W-2 box 2 / 1099 box 4
    interest: float = 0.0            # 1099-INT box 1
    ordinary_dividends: float = 0.0  # 1099-DIV box 1a
    # 1099-DIV box 1b: part of box 1a. NOT used to compute -- the draft taxes
    # all of box 1a at ordinary rates -- but read so the preparer is told.
    qualified_dividends: float = 0.0
    nonemployee_comp: float = 0.0    # 1099-NEC box 1 (flagged, not computed)
    state: str = ""                  # W-2 box 15 state code
    state_withholding: float = 0.0   # W-2 box 17
    # Carried figures: extracted for the preparer, NOT in the v1 computation.
    mortgage_interest: float = 0.0   # 1098 box 1
    retirement_gross: float = 0.0    # 1099-R box 1
    retirement_taxable: float = 0.0  # 1099-R box 2a
    social_security: float = 0.0     # SSA-1099 box 5
    unemployment: float = 0.0        # 1099-G box 1
    student_loan_interest: float = 0.0  # 1098-E box 1
    tuition: float = 0.0             # 1098-T box 1
    broker_proceeds: float = 0.0     # 1099-B proceeds (basis work flagged)
    confidence: float = 1.0          # 0..1 extraction confidence
    review_required: bool = False    # forced human review of this doc
    raw_excerpt: str = ""            # provenance snippet (bounded)


@dataclass
class Workpaper:
    """The standardized prep workpaper the agents assemble."""
    filing_status: str = "single"
    dependents_under_17: int = 0
    state: str = ""                  # resident state; "" = infer from docs
    docs: list[SourceDoc] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Age / blindness drive the additional standard deduction (65+/blind).
    # For single/HoH only the taxpayer's flags apply; spouse flags are MFJ.
    taxpayer_65_or_older: bool = False
    spouse_65_or_older: bool = False
    taxpayer_blind: bool = False
    spouse_blind: bool = False
    # Quarterly estimated tax already paid (Form 1040-ES) -- a payment, like
    # withholding, that reduces the balance due. Not on any W-2/1099, so it is
    # an explicit workpaper input the preparer/organizer supplies.
    estimated_payments: float = 0.0
    # Prior-year overpayment the client elected to apply to this year (a
    # 1040 payment line), also supplied from the organizer / prior return.
    prior_year_overpayment: float = 0.0

    @property
    def additional_standard_boxes(self) -> int:
        """Count of additional-standard-deduction conditions (65+ / blind).

        Single/HoH count only the taxpayer (max 2); MFJ counts both spouses
        (max 4). Each box adds one unit of the per-status additional amount."""
        boxes = int(self.taxpayer_65_or_older) + int(self.taxpayer_blind)
        if normalize_filing_status(self.filing_status) == "mfj":
            boxes += int(self.spouse_65_or_older) + int(self.spouse_blind)
        return boxes

    @property
    def total_wages(self) -> float:
        return sum(d.wages for d in self.docs)

    @property
    def total_interest(self) -> float:
        return sum(d.interest for d in self.docs)

    @property
    def total_dividends(self) -> float:
        return sum(d.ordinary_dividends for d in self.docs)

    @property
    def total_withholding(self) -> float:
        return sum(d.federal_withholding for d in self.docs)

    @property
    def total_payments(self) -> float:
        """Federal tax already paid: withholding + estimated payments + any
        prior-year overpayment applied to this year."""
        return (self.total_withholding + self.estimated_payments
                + self.prior_year_overpayment)

    @property
    def total_state_withholding(self) -> float:
        return sum(d.state_withholding for d in self.docs)


@dataclass
class Draft1040:
    """First-pass federal return: line values + provenance + open items."""
    filing_status: str
    total_income: float
    standard_deduction: float
    taxable_income: float
    tax_before_credits: float
    child_tax_credit: float
    tax_after_credits: float
    federal_withholding: float
    balance: float                   # negative = refund
    estimated_payments: float = 0.0  # 1040-ES already paid
    prior_year_overpayment: float = 0.0  # prior-year refund applied here
    open_items: list[str] = field(default_factory=list)
    lines: list[tuple[str, float, str]] = field(default_factory=list)
    # (line description, amount, source citation)
    carried: list[tuple[str, float, str]] = field(default_factory=list)
    # carried figures (mortgage interest, retirement, ...) -- extracted for
    # the preparer, NOT summed into the computation above
    # the year of the constants that computed this draft (a signed bundle can
    # carry another year than the built-in table)
    tax_year: int = TY2025["year"]


@dataclass
class StateDraft:
    """First-pass state computation (no-tax and flat-rate states only)."""
    state: str
    filing_status: str
    computed: bool                   # False = preparer/tax-engine completes
    rate: float = 0.0
    state_taxable: float = 0.0
    tax: float = 0.0
    withholding: float = 0.0
    balance: float = 0.0             # negative = refund (computed states only)
    open_items: list[str] = field(default_factory=list)
    tax_year: int = STATE_TY2025["year"]  # year of the constants used


def classify(text: str) -> str:
    """Deterministic doc-type classification from extracted text."""
    t = (text or "").lower()
    for doc_type, needles in _DOC_SIGNATURES:
        if any(n in t for n in needles):
            return doc_type
    return "UNKNOWN"


def _looks_like_year(token: str, value: float) -> bool:
    """A bare 4-digit integer in a plausible tax-year range, with no currency
    marker, is almost certainly the form's tax year printed on a title/header
    line (e.g. "Form 1099-INT Interest Income 2025") -- not a dollar amount."""
    return ("$" not in token and "," not in token and "." not in token
            and value == int(value) and 1900 <= value <= 2100)


def _looks_like_money(token: str) -> bool:
    """A matched token carries a currency marker ($, thousands comma, or
    cents) -- used to gate the next-line fallback so a bare box number or
    label digit on the following line is never mistaken for the amount."""
    return "$" in token or "," in token or "." in token


def _signed(m) -> float:
    value = float(m.group(2).replace(",", ""))
    return -value if m.group(1) == "-" else value


def _amount_after(text: str, *labels: str) -> float:
    """First dollar amount AFTER a label, scanning every line.

    Extraction agents normally supply structured figures; this parser covers
    cleanly formatted text exports so the pipeline runs end to end without
    an LLM (and so the demo/tests are deterministic). Searching after the
    label keeps "Box 1 Wages: $85,000.00" from yielding the box number.

    Hardened against the real failure modes that would otherwise produce a
    SILENT WRONG NUMBER on a tax return:
      * a label that is the prefix of a longer token -- "box 1" must not match
        "box 10".."box 19" (a word boundary is required after the label, so
        the box-2 federal-withholding probe can't latch onto "box 20" either);
      * a bare tax year on a title line ("... Interest Income 2025") being read
        as the amount -- year-like bare integers are skipped, and the scan
        continues to the real box line;
      * a leading minus sign being dropped -- the sign is preserved;
      * a box label and its value on SEPARATE lines (common in PDF text
        exports): when the label line carries no digits at all, the amount is
        taken from the next line, but only when it is clearly money-formatted
        ($/comma/cents) so a following box number is never grabbed.
    The first VALID money after any label wins; labels are tried in order per
    line. Bare unformatted integers in the 1900-2100 range are the one input
    this intentionally skips; real exports carry a $, comma, or cents.
    """
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        low = line.lower()
        for lbl in labels:
            pos = 0
            while True:
                idx = low.find(lbl, pos)
                if idx < 0:
                    break
                after = idx + len(lbl)
                pos = after
                # Word boundary: reject "box 1" sitting inside "box 10" so the
                # following digit can't be mistaken for (part of) the amount.
                if after < len(low) and low[after].isalnum():
                    continue
                rest = line[after:]
                m = _MONEY_RE.search(rest)
                if m:
                    if not _looks_like_year(m.group(0), _signed(m)):
                        return _signed(m)
                    continue  # year-like: keep scanning this line
                # No usable amount on this line. A bare label line (no digits
                # at all in the remainder) falls back to the next line, but
                # only for a clearly money-formatted value.
                if not any(c.isdigit() for c in rest) and i + 1 < len(lines):
                    nm = _MONEY_RE.search(lines[i + 1])
                    if (nm and _looks_like_money(nm.group(0))
                            and not _looks_like_year(nm.group(0), _signed(nm))):
                        return _signed(nm)
    return 0.0


def normalize_filing_status(status: str) -> str:
    """Filing status, case- and whitespace-normalized.

    A supported status returns its canonical lowercase form ("MFJ" -> "mfj");
    anything else returns lowercased-as-given so callers flag it rather than
    silently miscomputing as single. Guards every programmatic/agent caller
    that builds a Workpaper directly (the CLI already gates --filing-status)."""
    return (status or "").strip().lower()


def _state_code(text: str) -> str:
    """W-2 box 15 state code from a labeled line, validated against the
    real state-code set so an EIN fragment or stray initials never pass."""
    for line in (text or "").splitlines():
        low = line.lower()
        if "box 15" not in low and not low.lstrip().startswith("state"):
            continue
        for token in _STATE_TOKEN_RE.findall(line):
            if token in STATE_CODES:
                return token
    return ""


def _report_safe(value: object, *, fallback: str = "document") -> str:
    """Normalize untrusted text for one-line report fields.

    Source labels can originate from uploaded filenames. Unix filenames may
    contain newlines and terminal control bytes, so citations and open items
    must never render them verbatim into a preparer-facing package.
    """
    cleaned = _REPORT_ANSI_RE.sub(" ", str(value))
    cleaned = _REPORT_CONTROL_RE.sub(" ", cleaned)
    cleaned = _REPORT_WHITESPACE_RE.sub(" ", cleaned).strip()
    return cleaned or fallback


# The primary figure each classified doc type must yield; a zero here means
# the extractor could not read the document's headline number, which forces
# human review rather than a silently-empty line. K-1 has no single headline
# figure (multi-box pass-through) so it is always preparer work.
_PRIMARY_FIELD: dict[str, str] = {
    "W-2": "wages", "1099-INT": "interest", "1099-DIV": "ordinary_dividends",
    "1099-NEC": "nonemployee_comp", "1098": "mortgage_interest",
    "1099-R": "retirement_gross", "SSA-1099": "social_security",
    "1099-G": "unemployment", "1098-E": "student_loan_interest",
    "1098-T": "tuition", "1099-B": "broker_proceeds",
}


def _score_confidence(doc: SourceDoc) -> None:
    """Deterministic extraction confidence + forced-review flag.

    1.0 when the doc's headline figure was read; 0.3 (review) when a
    classified doc yielded nothing; 0.0 (review) for an unclassified doc;
    0.6 (review) for K-1 / prior-return which carry no single computed
    figure. Conservative on purpose -- a weak read is surfaced, never hidden.
    """
    if doc.doc_type == "UNKNOWN":
        doc.confidence, doc.review_required = 0.0, True
        return
    if doc.doc_type in ("K-1", "PRIOR-RETURN"):
        doc.confidence, doc.review_required = 0.6, True
        return
    field = _PRIMARY_FIELD.get(doc.doc_type)
    if field and getattr(doc, field) == 0.0:
        doc.confidence, doc.review_required = 0.3, True
        return
    doc.confidence, doc.review_required = 1.0, False


def extract(text: str, *, label: str = "") -> SourceDoc:
    """Classify + pull the standard boxes from one document's text."""
    doc_type = classify(text)
    doc = SourceDoc(doc_type=doc_type,
                    label=_report_safe(label or doc_type, fallback=doc_type),
                    raw_excerpt=(text or "")[:160])
    if doc_type == "W-2":
        doc.wages = _amount_after(text, "wages, tips", "box 1")
        doc.federal_withholding = _amount_after(
            text, "federal income tax withheld", "box 2")
        doc.state = _state_code(text)
        doc.state_withholding = _amount_after(
            text, "state income tax", "box 17")
    elif doc_type == "1099-INT":
        doc.interest = _amount_after(text, "interest income", "box 1")
        doc.federal_withholding = _amount_after(
            text, "federal income tax withheld", "box 4")
    elif doc_type == "1099-DIV":
        doc.ordinary_dividends = _amount_after(
            text, "ordinary dividends", "box 1a")
        doc.qualified_dividends = _amount_after(
            text, "qualified dividends", "box 1b")
        doc.federal_withholding = _amount_after(
            text, "federal income tax withheld", "box 4")
    elif doc_type == "1099-NEC":
        doc.nonemployee_comp = _amount_after(
            text, "nonemployee compensation", "box 1")
    elif doc_type == "1098":
        doc.mortgage_interest = _amount_after(
            text, "mortgage interest received", "mortgage interest", "box 1")
    elif doc_type == "1099-R":
        doc.retirement_gross = _amount_after(
            text, "gross distribution", "box 1")
        doc.retirement_taxable = _amount_after(
            text, "taxable amount", "box 2a")
        doc.federal_withholding = _amount_after(
            text, "federal income tax withheld", "box 4")
    elif doc_type == "SSA-1099":
        doc.social_security = _amount_after(
            text, "net benefits", "box 5", "social security benefit")
    elif doc_type == "1099-G":
        doc.unemployment = _amount_after(
            text, "unemployment compensation", "box 1")
        doc.federal_withholding = _amount_after(
            text, "federal income tax withheld", "box 4")
    elif doc_type == "1098-E":
        doc.student_loan_interest = _amount_after(
            text, "student loan interest", "box 1")
    elif doc_type == "1098-T":
        doc.tuition = _amount_after(
            text, "payments received", "box 1")
    elif doc_type == "1099-B":
        doc.broker_proceeds = _amount_after(text, "proceeds", "box 1d")
    _score_confidence(doc)
    return doc


# Doc types whose tax treatment needs preparer judgment: classified and
# carried on the workpaper, never guessed into the computation.
_PREPARER_DOC_ITEMS = {
    "1099-NEC": "self-employment income requires Schedule C + SE tax "
                "-- PREPARER MUST COMPLETE",
    "K-1": "K-1 pass-through requires Schedule E -- PREPARER MUST COMPLETE",
    "1099-B": "broker proceeds require Schedule D / Form 8949 basis work "
              "-- PREPARER MUST COMPLETE",
    "1099-R": "retirement distribution: taxable amount and rollover "
              "treatment -- PREPARER MUST COMPLETE",
    "SSA-1099": "social security benefits: taxability worksheet "
                "-- PREPARER MUST COMPLETE",
    "1099-G": "government payments (unemployment / state refund): "
              "taxability -- PREPARER MUST COMPLETE",
    "1098": "mortgage interest -- evaluate itemizing vs the standard "
            "deduction",
    "1098-T": "tuition statement -- evaluate education credits",
    "1098-E": "student loan interest -- evaluate the deduction",
}


# Carried figures: (SourceDoc field, review-package description). Extracted
# and shown to the preparer, never summed into the v1 computation.
_CARRIED_FIELDS: list[tuple[str, str]] = [
    ("nonemployee_comp", "Nonemployee comp (1099-NEC box 1)"),
    ("mortgage_interest", "Mortgage interest (1098 box 1)"),
    ("retirement_gross", "Retirement gross distribution (1099-R box 1)"),
    ("retirement_taxable", "Retirement taxable amount (1099-R box 2a)"),
    ("social_security", "Social security benefits (SSA-1099 box 5)"),
    ("unemployment", "Unemployment compensation (1099-G box 1)"),
    ("student_loan_interest", "Student loan interest (1098-E box 1)"),
    ("tuition", "Tuition paid (1098-T box 1)"),
    ("broker_proceeds", "Broker proceeds (1099-B)"),
]


def carried_figures(wp: Workpaper) -> list[tuple[str, float, str]]:
    """Non-zero carried figures across the workpaper's docs, each cited.

    These are extracted for the preparer's eyes -- they are NOT income in the
    v1 computation (their tax treatment needs judgment: itemizing, SE tax,
    taxability worksheets), and the matching open items say so."""
    out: list[tuple[str, float, str]] = []
    for d in wp.docs:
        for fld, desc in _CARRIED_FIELDS:
            val = getattr(d, fld, 0.0)
            if val:
                out.append((desc, val, d.label))
    return out


def _money_fingerprint(d: SourceDoc) -> tuple:
    """A document's identity for duplicate detection: type + every extracted
    money figure (rounded). Two of a client's documents with the same type and
    byte-identical figures are almost certainly the same form uploaded twice --
    two real jobs would not share identical wages AND withholding."""
    return (d.doc_type, round(d.wages, 2), round(d.interest, 2),
            round(d.ordinary_dividends, 2), round(d.federal_withholding, 2),
            round(d.nonemployee_comp, 2), round(d.mortgage_interest, 2),
            round(d.retirement_gross, 2), round(d.retirement_taxable, 2),
            round(d.social_security, 2), round(d.unemployment, 2),
            round(d.student_loan_interest, 2), round(d.tuition, 2),
            round(d.broker_proceeds, 2), round(d.state_withholding, 2),
            round(d.qualified_dividends, 2))


def duplicate_groups(wp: Workpaper) -> list[list[str]]:
    """Groups of labels that look like the same document uploaded more than
    once (same type, identical figures, and a non-zero headline figure so two
    empty/unparsed docs don't count). Detection only -- the preparer decides
    whether a match is a true duplicate or a coincidence."""
    seen: dict[tuple, list[str]] = {}
    for d in wp.docs:
        fp = _money_fingerprint(d)
        # Ignore all-zero fingerprints (UNKNOWN / unparsed): they would group
        # unrelated empty docs together.
        if any(fp[i] for i in range(1, len(fp))):
            seen.setdefault(fp, []).append(_report_safe(d.label))
    return [labels for labels in seen.values() if len(labels) > 1]


def _dividend_rate_item(d: SourceDoc, label: str) -> str | None:
    """Flag that the first pass taxes box 1a at ordinary rates.

    This may overstate tax when any dividends qualify; the exact effect depends
    on taxable income, credits, and the preparer's completed worksheet.
    """
    if d.ordinary_dividends <= 0 and d.qualified_dividends <= 0:
        return None
    if d.qualified_dividends > 0:
        return (f"{label}: qualified dividends of ${d.qualified_dividends:,.2f} "
                "(box 1b) are taxed at ordinary rates in this draft, so the "
                "estimate may be too high -- apply the Qualified Dividends and "
                "Capital Gain Tax Worksheet -- PREPARER MUST COMPLETE")
    return (f"{label}: no box 1b qualified dividends read -- if any of these "
            "dividends are qualified, this draft taxes them at ordinary rates "
            "and may overstate the estimate (the Qualified Dividends and Capital "
            "Gain Tax Worksheet is not applied) -- PREPARER MUST EVALUATE")


def missing_items(wp: Workpaper) -> list[str]:
    """Completeness check: what a preparer would chase before computing."""
    items: list[str] = []
    if normalize_filing_status(wp.filing_status) not in FILING_STATUSES:
        items.append(f"filing status {wp.filing_status!r} is not supported "
                     f"(supported: {', '.join(FILING_STATUSES)})")
    if not wp.docs:
        items.append("no source documents provided")
    for group in duplicate_groups(wp):
        items.append(
            "POSSIBLE DUPLICATE upload (same type, identical figures): "
            + ", ".join(group) + " -- confirm whether to include both; a "
            "re-upload double-counts income")
    for d in wp.docs:
        label = _report_safe(d.label)
        if d.doc_type == "UNKNOWN":
            items.append(f"unclassified document: {label} -- needs "
                         "preparer identification")
        flag = _PREPARER_DOC_ITEMS.get(d.doc_type)
        if flag:
            items.append(f"{label}: {flag}")
        if dividend_item := _dividend_rate_item(d, label):
            items.append(dividend_item)
        if d.doc_type == "W-2" and d.wages <= 0:
            items.append(f"{label}: W-2 with no box-1 wages extracted -- "
                         "verify the document")
        # A classified doc whose headline figure did not read (confidence
        # 0.3) is surfaced for verification rather than carried as a silent
        # zero. UNKNOWN docs are already named above.
        elif d.doc_type != "UNKNOWN" and d.confidence <= 0.3:
            items.append(f"{label} ({d.doc_type}): LOW EXTRACTION "
                         "CONFIDENCE -- headline figure not read; verify the "
                         "document before relying on it")
        # A negative income / withholding figure is almost always an
        # extraction error (a stray minus, a bracketed loss); never let it
        # flow into the totals as a silent reducer.
        if min(d.wages, d.interest, d.ordinary_dividends, d.nonemployee_comp,
               d.federal_withholding, d.state_withholding) < 0:
            items.append(f"{label}: NEGATIVE figure extracted -- verify the "
                         "document (likely an extraction error)")
    return items


def _bracket_tax(taxable: float, brackets: list[tuple]) -> float:
    tax, lower = 0.0, 0.0
    for top, rate in brackets:
        if top is None or taxable <= top:
            tax += (taxable - lower) * rate
            return max(0.0, tax)
        tax += (top - lower) * rate
        lower = float(top)
    return max(0.0, tax)  # pragma: no cover -- open bracket returns above


def compute_first_pass(wp: Workpaper, *, constants: dict = TY2025) -> Draft1040:
    """The first-pass federal computation, every line cited to its source.

    Deterministic and intentionally conservative: anything outside the
    supported scope lands in ``open_items`` for the preparer instead of
    being guessed at.
    """
    status = normalize_filing_status(wp.filing_status)
    status = status if status in FILING_STATUSES else "single"
    lines: list[tuple[str, float, str]] = []
    for d in wp.docs:
        if d.wages:
            lines.append(("Wages (1040 line 1a)", d.wages,
                          _report_safe(d.label)))
        if d.interest:
            lines.append(("Taxable interest (line 2b)", d.interest,
                          _report_safe(d.label)))
        if d.ordinary_dividends:
            lines.append(("Ordinary dividends (line 3b)",
                          d.ordinary_dividends, _report_safe(d.label)))
    total_income = wp.total_wages + wp.total_interest + wp.total_dividends
    # Standard deduction + the additional amount for 65+/blind (each checked
    # box adds one per-status unit). Fall back to the built-in additional
    # table when an applied bundle predates this field, so the senior
    # deduction is never silently dropped.
    base_std = constants["standard_deduction"][status]
    add_table = (constants.get("additional_standard_deduction")
                 or TY2025["additional_standard_deduction"])
    boxes = wp.additional_standard_boxes
    additional = boxes * add_table[status]
    std = base_std + additional
    taxable = max(0.0, total_income - std)
    tax = round(_bracket_tax(taxable, constants["brackets"][status]), 2)

    # Child tax credit with the 5% phaseout, capped at tax (nonrefundable
    # portion only -- the additional CTC is an open item for the preparer).
    # Dependents are clamped at 0 so a bad input can never invent a negative
    # credit (which would otherwise inflate the tax).
    ctc = constants["ctc_per_child"] * max(0, wp.dependents_under_17)
    over = max(0.0, total_income - constants["ctc_phaseout_start"][status])
    if over:
        ctc = max(0.0, ctc - (int((over + 999) // 1000) * 50.0))
    ctc = min(ctc, tax)

    payments = wp.total_payments
    after_credits = max(0.0, tax - ctc)
    open_items = missing_items(wp) + _payment_and_deduction_flags(wp, boxes,
                                                                  total_income)
    draft = Draft1040(
        filing_status=status,
        total_income=round(total_income, 2),
        standard_deduction=round(std, 2),
        taxable_income=round(taxable, 2),
        tax_before_credits=tax,
        child_tax_credit=round(ctc, 2),
        tax_after_credits=round(after_credits, 2),
        federal_withholding=round(wp.total_withholding, 2),
        estimated_payments=round(wp.estimated_payments, 2),
        prior_year_overpayment=round(wp.prior_year_overpayment, 2),
        balance=round(after_credits - payments, 2),
        open_items=open_items + list(wp.notes),
        lines=lines,
        carried=carried_figures(wp),
        tax_year=int(constants["year"]),
    )
    return draft


def _payment_and_deduction_flags(wp: Workpaper, add_boxes: int,
                                 total_income: float) -> list[str]:
    """Open items the computation should surface to the preparer: the senior
    bonus deduction it does NOT compute, an input-confirmation for the
    additional standard deduction, and a payments-exceed-income sanity check."""
    flags: list[str] = []
    if add_boxes:
        flags.append(
            f"standard deduction includes the additional amount for "
            f"{add_boxes} 65+/blind box(es) -- confirm the age/blindness inputs")
    if wp.taxpayer_65_or_older or wp.spouse_65_or_older:
        flags.append(
            "taxpayer/spouse is 65+: the OBBBA senior deduction (up to "
            "$6,000/person, MAGI phaseout) is NOT computed here -- PREPARER "
            "MUST EVALUATE")
    payments = wp.total_payments
    if payments > total_income > 0:
        flags.append(
            f"federal payments ${payments:,.2f} exceed total income "
            f"${total_income:,.2f} -- verify withholding/estimated figures "
            "(possible extraction error)")
    return flags


def infer_state(wp: Workpaper) -> str:
    """Resident state: the workpaper's explicit state, else the single state
    on the W-2s (multiple states = preparer call, so return "")."""
    if wp.state:
        return wp.state.upper()
    seen = {d.state for d in wp.docs if d.state}
    return next(iter(seen)) if len(seen) == 1 else ""


def compute_state_first_pass(wp: Workpaper, state: str, *,
                             federal: Draft1040 | None = None,
                             constants: dict = STATE_TY2025) -> StateDraft:
    """First-pass state computation for no-tax and flat-rate states.

    Graduated and credit-structured states are NOT estimated here -- a wrong
    state estimate is worse than an explicit handoff, so those come back
    ``computed=False`` with the withholding tallied and the open item naming
    the authoritative path (the preparer / the firm's tax engine via the
    CCH Axcess / GoSystem connectors).
    """
    state = (state or "").upper()
    year = int(constants["year"])
    status = normalize_filing_status(wp.filing_status)
    status = status if status in FILING_STATUSES else "single"
    withholding = round(sum(
        d.state_withholding for d in wp.docs if d.state == state), 2)
    open_items: list[str] = []
    blank_state = round(sum(
        d.state_withholding for d in wp.docs if not d.state), 2)
    if blank_state:
        open_items.append(
            f"state withholding ${blank_state:,.2f} reported on document(s) "
            "with no state -- PREPARER MUST CONFIRM the state before crediting "
            f"it (not assumed to be {state or 'the resident state'})")
    other = sorted({d.state for d in wp.docs if d.state and d.state != state})
    if other:
        open_items.append(
            f"withholding reported for other state(s) {', '.join(other)} -- "
            "multi-state allocation PREPARER MUST COMPLETE")

    if state not in STATE_CODES:
        return StateDraft(
            state=state or "??", filing_status=status, computed=False,
            withholding=withholding, tax_year=year,
            open_items=open_items + [
                "resident state not determined -- set it on the workpaper "
                "(or --state) so the state return can be drafted"])

    if state in constants["no_tax"]:
        return StateDraft(state=state, filing_status=status, computed=True,
                          withholding=withholding, tax_year=year,
                          balance=round(-withholding, 2),
                          open_items=open_items)

    flat = constants["flat"].get(state)
    graduated = (constants.get("graduated") or {}).get(state)
    if flat is None and graduated is None:
        return StateDraft(
            state=state, filing_status=status, computed=False,
            withholding=withholding, tax_year=year,
            open_items=open_items + [
                f"{state} has a graduated/credit-structured income tax with no "
                "bracket table loaded -- first pass not computed; PREPARER MUST "
                "COMPLETE (or compute in the firm's tax engine via the "
                "cch_axcess / gosystem_tax connector, or load a signed "
                "constants bundle that includes this state's brackets)"])

    # Flat and graduated states share the same base/deduction handling; only
    # the tax function differs (a single rate vs. the marginal bracket table).
    spec = flat if flat is not None else graduated
    if spec["basis"] == "federal_taxable":
        if federal is None:
            federal = compute_first_pass(wp)
        base = federal.taxable_income
    else:  # "agi" -- equal to total income in the v1 scope (no adjustments)
        base = wp.total_wages + wp.total_interest + wp.total_dividends
    taxable = max(0.0, base - spec["deduction"][status])
    if flat is not None:
        rate = flat["rate"]
        tax = round(taxable * rate, 2)
    else:
        rate = 0.0  # marginal; the bracket table, not a single rate
        tax = round(_bracket_tax(taxable, graduated["brackets"]), 2)
    open_items.append(
        f"{state} credits, exemptions beyond the standard amount, and any "
        "local/municipal tax are not computed -- PREPARER MUST REVIEW")
    return StateDraft(
        state=state, filing_status=status, computed=True,
        rate=rate, state_taxable=round(taxable, 2), tax=tax,
        withholding=withholding, balance=round(tax - withholding, 2),
        open_items=open_items, tax_year=year,
    )


def _render_state(out: list[str], sd: StateDraft) -> None:
    out += ["", f"DRAFT {sd.state} STATE RETURN (TY{sd.tax_year}) "
                "— first pass",
            "-" * 52]
    if not sd.computed:
        out.append("  Not computed in the first pass (see open items).")
        out.append(f"State withholding    : ${sd.withholding:,.2f}")
        return
    if sd.rate:
        out.append(f"State taxable income : ${sd.state_taxable:,.2f}")
        out.append(f"State tax (flat {sd.rate * 100:.2f}%)"
                   f" : ${sd.tax:,.2f}")
    elif sd.state_taxable or sd.tax:
        # graduated brackets: marginal, so there is no single rate to show
        out.append(f"State taxable income : ${sd.state_taxable:,.2f}")
        out.append(f"State tax (graduated): ${sd.tax:,.2f}")
    else:
        out.append("  No state individual income tax.")
    out.append(f"State withholding    : ${sd.withholding:,.2f}")
    if sd.balance < 0:
        out.append(f"EST. STATE REFUND    : ${-sd.balance:,.2f}")
    else:
        out.append(f"EST. STATE BALANCE   : ${sd.balance:,.2f}")


def render_review_package(draft: Draft1040,
                          state: StateDraft | None = None) -> str:
    """The preparer-facing review package: draft + provenance + open items."""
    n_open = len(draft.open_items) + (len(state.open_items) if state else 0)
    triage = (f"REVIEW SUMMARY: {n_open} open item(s) for the preparer"
              if n_open else "REVIEW SUMMARY: no open items flagged")
    out = [DISCLAIMER, "", triage, "",
           f"DRAFT FORM 1040 (TY{draft.tax_year}) — first pass",
           "=" * 52,
           f"Filing status        : {draft.filing_status.upper()}"]
    for desc, amount, source in draft.lines:
        desc = _report_safe(desc, fallback="line")
        source = _report_safe(source)
        out.append(f"  {desc:<34} ${amount:>12,.2f}   [{source}]")
    out += [
        f"Total income         : ${draft.total_income:,.2f}",
        f"Standard deduction   : ${draft.standard_deduction:,.2f}",
        f"Taxable income       : ${draft.taxable_income:,.2f}",
        f"Tax (before credits) : ${draft.tax_before_credits:,.2f}",
        f"Child tax credit     : ${draft.child_tax_credit:,.2f}",
        f"Tax after credits    : ${draft.tax_after_credits:,.2f}",
        f"Federal withholding  : ${draft.federal_withholding:,.2f}",
    ]
    if draft.estimated_payments:
        out.append(f"Estimated payments   : ${draft.estimated_payments:,.2f}")
    if draft.prior_year_overpayment:
        out.append("Prior-yr overpayment : "
                   f"${draft.prior_year_overpayment:,.2f}")
    if draft.balance < 0:
        out.append(f"ESTIMATED REFUND     : ${-draft.balance:,.2f}")
    else:
        out.append(f"ESTIMATED BALANCE DUE: ${draft.balance:,.2f}")
    if draft.carried:
        out += ["",
                "CARRIED FIGURES (preparer review — NOT in the computation "
                "above):",
                "-" * 52]
        for desc, amount, source in draft.carried:
            out.append(f"  {desc:<40} ${amount:>12,.2f}   [{source}]")
    if state is not None:
        _render_state(out, state)
    open_items = list(draft.open_items)
    if state is not None:
        open_items += [f"[{state.state}] {i}" for i in state.open_items]
    if open_items:
        out.append("")
        out.append("OPEN ITEMS FOR PREPARER (must be resolved before filing):")
        out += [f"  - {_report_safe(item, fallback='open item')}"
                for item in open_items]
    return "\n".join(out)


def review_package_dict(draft: Draft1040,
                        state: StateDraft | None = None) -> dict:
    """The review package as a structured dict for programmatic intake.

    Stable schema for a firm wiring the first pass into its own systems:
    every federal line with its source citation, the carried figures, the
    combined open items, and the state block. Money stays as floats (cents);
    the text package remains the human-facing artifact."""
    data: dict = {
        "disclaimer": DISCLAIMER,
        "tax_year": draft.tax_year,
        "filing_status": draft.filing_status,
        "is_draft": True,
        "federal": {
            "lines": [{"description": desc, "amount": amt, "source": src}
                      for desc, amt, src in draft.lines],
            "total_income": draft.total_income,
            "standard_deduction": draft.standard_deduction,
            "taxable_income": draft.taxable_income,
            "tax_before_credits": draft.tax_before_credits,
            "child_tax_credit": draft.child_tax_credit,
            "tax_after_credits": draft.tax_after_credits,
            "federal_withholding": draft.federal_withholding,
            "estimated_payments": draft.estimated_payments,
            "prior_year_overpayment": draft.prior_year_overpayment,
            "balance": draft.balance,
            "is_refund": draft.balance < 0,
        },
        "carried_figures": [{"description": desc, "amount": amt, "source": src}
                            for desc, amt, src in draft.carried],
        "open_items": list(draft.open_items),
    }
    if state is not None:
        data["state"] = {
            "state": state.state,
            "computed": state.computed,
            "rate": state.rate,
            "state_taxable": state.state_taxable,
            "tax": state.tax,
            "withholding": state.withholding,
            "balance": state.balance,
            "open_items": list(state.open_items),
        }
        data["open_items"] += [f"[{state.state}] {i}" for i in state.open_items]
    return data


__all__ = [
    "DISCLAIMER", "DOC_TYPES", "TY2025", "STATE_TY2025", "STATE_CODES",
    "FILING_STATUSES",
    "SourceDoc", "Workpaper", "Draft1040", "StateDraft",
    "classify", "extract", "missing_items", "compute_first_pass",
    "infer_state", "compute_state_first_pass", "render_review_package",
    "normalize_filing_status", "carried_figures", "duplicate_groups",
    "review_package_dict",
]
