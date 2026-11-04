"""Versioned business objects and requested actions, with provisional effort ranges.

The local classifier deliberately abstains. It parses the instruction before
quoted/source material, composes an action with a business object, and carries
context only for explicit follow-ups. No customer text is retained or sent away.
The confidence vocabulary describes rule support, never a model probability.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

VERSION = "2026-10-08.1"
CLASSIFIER_VERSION = "2026-10-09.1"
EFFECTIVE_DATE = "2026-10-08"
PROVENANCE = (
    "Provisional Lightwork planning assumption, not a validated industry average. "
    "One bounded deliverable using supplied material; excludes research, approval, "
    "implementation and whole-project effort unless explicitly included."
)


@dataclass(frozen=True)
class BusinessObject:
    id: str
    family: str
    label: str
    terms: tuple[str, ...]
    actions: tuple[str, ...]
    # A deliberately broad range for the drafting/analysis component, minutes.
    effort: tuple[int, int]
    scope: str
    dimensions: tuple[str, ...]
    specialist: str = ""


OBJECTS = (
    BusinessObject("rfp", "Sales & proposals", "RFP", ("rfp", "request for proposal"),
                   ("draft", "review", "summarize", "extract"), (60, 240),
                   "One initial RFP document, up to 10 pages; not the entire bid cycle",
                   ("pages", "requirements", "reviewers")),
    BusinessObject("proposal", "Sales & proposals", "sales proposal", ("proposal", "bid response", "sales pitch"),
                   ("draft", "review", "summarize"), (45, 180), "One proposal section or short proposal", ("pages", "requirements")),
    BusinessObject("sales_email", "Sales & proposals", "sales outreach", ("sales email", "outreach email", "follow-up email"),
                   ("draft", "review"), (10, 40), "One tailored outreach message", ("recipients", "personalization")),
    BusinessObject("financial_analysis", "Finance", "financial analysis", ("financial analysis", "financial model", "budget variance", "cash flow", "profitability"),
                   ("analyze", "review", "summarize", "extract"), (45, 180), "One analysis of supplied financial data", ("periods", "entities", "rows")),
    BusinessObject("financial_report", "Finance", "financial report", ("financial report", "management accounts", "earnings report"),
                   ("draft", "review", "summarize", "extract"), (45, 180), "One report from supplied figures", ("pages", "periods")),
    BusinessObject("invoice", "Finance", "invoice", ("invoice", "expense report"),
                   ("review", "extract", "reconcile"), (10, 40), "One invoice or expense document; no payment execution", ("documents", "line_items")),
    BusinessObject("vendor", "Procurement", "vendor evaluation", ("vendor evaluation", "supplier evaluation", "vendor comparison", "supplier comparison"),
                   ("draft", "analyze", "review", "summarize"), (30, 120), "One comparison of up to three supplied vendor profiles", ("vendors", "criteria")),
    BusinessObject("contract", "Procurement", "contract", ("contract", "agreement", "purchase order"),
                   ("draft", "review", "summarize", "extract"), (45, 180), "One document component; professional approval retained", ("pages", "clauses")),
    BusinessObject("meeting", "Operations", "meeting record", ("meeting notes", "meeting minutes", "meeting transcript", "action items"),
                   ("draft", "summarize", "extract"), (15, 60), "One meeting record from supplied notes", ("pages", "participants")),
    BusinessObject("procedure", "Operations", "operating procedure", ("sop", "operating procedure", "process document", "checklist"),
                   ("draft", "review", "summarize"), (30, 120), "One procedure for an established process", ("steps", "exceptions")),
    BusinessObject("data", "Operations", "structured data", ("spreadsheet", "csv", "data table", "dataset"),
                   ("analyze", "extract", "reconcile", "summarize"), (20, 90), "One bounded supplied table; no data acquisition", ("rows", "columns", "sources")),
    BusinessObject("support", "Customer support", "support response", ("support ticket", "customer complaint", "support response", "customer reply"),
                   ("draft", "review", "summarize", "extract"), (10, 40), "One customer issue using existing knowledge", ("issues", "systems")),
    BusinessObject("knowledge", "Customer support", "knowledge article", ("knowledge article", "help article", "faq", "knowledge base"),
                   ("draft", "review", "summarize"), (30, 120), "One short knowledge article", ("pages", "sources")),
    BusinessObject("marketing", "Marketing", "marketing content", ("blog post", "marketing copy", "social post", "press release", "newsletter"),
                   ("draft", "review", "summarize"), (30, 120), "One initial content asset; campaign strategy excluded", ("words", "channels", "audiences")),
    BusinessObject("campaign", "Marketing", "campaign analysis", ("campaign results", "campaign performance", "marketing performance"),
                   ("analyze", "review", "summarize"), (30, 120), "One supplied campaign result set", ("channels", "periods")),
    BusinessObject("code", "Engineering & product", "code change", ("code", "function", "pull request", "bug", "unit test"),
                   ("draft", "review", "analyze", "summarize"), (30, 120), "One bounded code component; integration and deployment excluded", ("files", "interfaces", "test_cases")),
    BusinessObject("product", "Engineering & product", "product specification", ("product spec", "product requirement", "user story", "acceptance criteria", "release notes"),
                   ("draft", "review", "summarize", "extract"), (30, 120), "One feature or release document", ("requirements", "stakeholders")),
    BusinessObject("hiring", "HR & communications", "hiring document", ("job description", "interview guide", "onboarding plan"),
                   ("draft", "review", "summarize"), (30, 90), "One role document; candidate decisions remain human", ("roles", "competencies")),
    BusinessObject("communication", "HR & communications", "internal communication", ("internal memo", "staff announcement", "employee communication", "weekly update"),
                   ("draft", "review", "summarize"), (15, 60), "One internal message from supplied facts", ("audiences", "words")),
    BusinessObject("research", "Research & compliance", "research brief", ("research brief", "research report", "literature review", "market research"),
                   ("draft", "analyze", "review", "summarize", "extract"), (45, 180), "One synthesis of supplied sources; primary research excluded", ("sources", "pages")),
    BusinessObject("compliance", "Research & compliance", "compliance assessment", ("compliance assessment", "risk assessment", "policy", "audit evidence", "regulatory requirements"),
                   ("draft", "review", "summarize", "extract", "analyze"), (30, 180), "One assessment component; legal judgment and approval retained", ("controls", "pages", "jurisdictions")),
    BusinessObject("document", "Research & compliance", "document", ("document", "report", "pdf", "attachment"),
                   ("review", "summarize", "extract", "translate"), (15, 60), "One supplied document up to 10 pages", ("pages", "languages")),
)

# Actions compose with objects. A quoted occurrence of an object alone never
# classifies a task. Narrow object matches take precedence over "document".
ACTIONS = {
    "draft": ("Draft", r"draft|write|create|compose|prepare|generate|implement|fix", 1.0),
    "review": ("Review", r"review|check|critique|proofread|evaluate|assess", 0.5),
    "summarize": ("Summarize", r"summari[sz]e|summari[sz]ing|summar(?:y|ies)|condense", 0.25),
    "extract": ("Extract from", r"extract|identify|list|pull out", 0.25),
    "analyze": ("Analyze", r"analy[sz]e|compare|explain|calculate|forecast|model|perform analysis", 1.0),
    "reconcile": ("Reconcile", r"reconcile|match|deduplicate|clean", 0.5),
    "translate": ("Translate", r"translate|locali[sz]e", 0.5),
}
BY_OBJECT = {obj.id: obj for obj in OBJECTS}
COUNTS = {word: index for index, word in enumerate(
    ("one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"), start=1)}


@lru_cache(maxsize=128)
def _object_pattern(obj):
    terms = {*obj.terms, obj.label.casefold()}
    for term in tuple(terms):
        if term.endswith("analysis"):
            terms.add(term[:-2] + "es")
        elif term.endswith("y") and not term.endswith(("ay", "ey")):
            terms.add(term[:-1] + "ies")
        elif not term.endswith("s"):
            terms.add(term + "s")
    return r"(?:" + "|".join(re.escape(term) for term in sorted(terms, key=len, reverse=True)) + r")"


# Cache taxonomy rules only; customer requests/classifications are never cached.
NEW_WORK = re.compile(r"\b(?:another|separate|new|different|second|third)\s+(?:" +
                      "|".join(_object_pattern(obj) for obj in OBJECTS) + r"|task|project)\b")
GUIDANCE = re.compile(
    r"\b(?:how\s+(?:to|(?:can|do|should|would)\s+(?:i|we))\b|"
    r"(?:explain|describe|teach|show)\s+(?:(?:me|us)\s+)?(?:how|whether)\b|"
    r"what\s+does\b.*\bmean\b|(?:classify|categorize|label)\s+(?:this|that|the|my)\b)"
)


def _units(request, intents):
    units = {}
    count = r"(\d{1,6}|" + "|".join(COUNTS) + r")"
    for identifier in intents:
        obj = BY_OBJECT[identifier.split(".")[0]]
        matches = re.findall(r"\b" + count + r"\s+(?:(?:separate|distinct|new|different)\s+)?" + _object_pattern(obj) + r"\b", request)
        units[obj.id] = max([int(value) if value.isdigit() else COUNTS[value] for value in matches] or [1])
    return units


def definition(identifier: str) -> dict | None:
    parts = identifier.split(".")
    if len(parts) != 2 or parts[0] not in BY_OBJECT:
        return None
    obj, action = BY_OBJECT[parts[0]], parts[1]
    if action not in obj.actions:
        return None
    verb, _, fraction = ACTIONS[action]
    lo, hi = (round(n * fraction) for n in obj.effort)
    return {"id": identifier, "family": obj.family, "object": obj.id, "action": action,
            "label": f"{verb} {obj.label}", "description": obj.scope,
            "examples": [f"{verb} this {obj.label} using the supplied information"],
            "effort_dimensions": list(obj.dimensions), "benchmark_id": identifier,
            "benchmark": {"id": identifier, "version": VERSION, "effective_date": EFFECTIVE_DATE,
                          "low_minutes": lo, "high_minutes": hi, "minutes": (lo + hi) / 2,
                          "unit": "one bounded deliverable component", "scope": obj.scope,
                          "provenance": PROVENANCE, "provisional": True, "override": False,
                          "attributable_share": 0.5, "review_minutes": (lo + hi) / 10,
                          "review_basis": "Provisional retained review effort, 20% of baseline",
                          "size": "standard", "size_multiplier": 1.0}}


def catalog() -> list[dict]:
    return [definition(f"{obj.id}.{action}") for obj in OBJECTS for action in obj.actions]


def instruction(text: str) -> str:
    """Quoted documents are data; keep only the leading, bounded request."""
    text = str(text or "")[:8000]
    text = re.split(r"```|\n\s*>|\n\s*(?:source|document|context|transcript|attachment)\s*:",
                    text, maxsplit=1, flags=re.IGNORECASE)[0]
    text = re.sub(r'"[^"\n]*"|“[^”\n]*”|<[^>]*>.*?</[^>]*>', " quoted material ", text, flags=re.DOTALL)
    text = re.sub(r"(?<!\w)'[^'\n]+'(?!\w)|‘[^’\n]*’", " quoted material ", text)
    return text[:1200].strip().casefold()


def _clause_intents(request):
    matches = []
    for clause in re.split(r"[;\n]|\b(?:and|then)\s+(?=(?:draft|write|review|check|summari[sz]e|extract|analy[sz]e|reconcile|translate)\b)", request):
        # Advice about doing a task is not a request for that deliverable.
        # We have no guidance-effort benchmark, so leave it unvalued.
        if GUIDANCE.search(clause):
            continue
        clause = re.sub(r"\b(?:perform|conduct|do|provide|run)\s+(?:an?\s+)?(?=(?:financial\s+|data\s+)?analysis\b)", "analyze ", clause)
        found = []
        for obj in OBJECTS:
            if not re.search(r"\b" + _object_pattern(obj) + r"\b", clause):
                continue
            if obj.id == "document" and found:
                continue
            for action in obj.actions:
                if re.search(r"\b(?:" + ACTIONS[action][1] + r")\b", clause):
                    found.append(f"{obj.id}.{action}")
        # A following pronoun with an explicit action can refer to the previous
        # business object; it does not create another deliverable.
        if not found and matches and re.search(r"\b(?:it|that|them)\b", clause):
            for identifier in matches[-1:]:
                obj = BY_OBJECT[identifier.split(".")[0]]
                found.extend(f"{obj.id}.{action}" for action in obj.actions if re.search(r"\b(?:" + ACTIONS[action][1] + r")\b", clause))
        matches.extend(found)
    return matches


def classify(text: str, *, previous: list[str] | None = None) -> dict:
    request = instruction(text)
    new_work = bool(NEW_WORK.search(request))
    followup = bool(re.match(r"(?:please\s+)?(?:revise|update|change|shorten|expand|fix that|try again|make it|add |remove |continue|actually|instead|also )", request))
    matches = _clause_intents(request)
    # A follow-up action can change intent without treating ten revisions as
    # ten deliverables. Explicit negation is not a request for the negated work.
    negated = re.findall(r"(?:do not|don't|not|rather than|instead of)\s+(\w+)", request)
    matches = [item for item in matches if not any(
        re.fullmatch(ACTIONS[item.split('.')[1]][1], word) for word in negated)]
    if not matches and previous and followup and not new_work:
        matches = list(previous)
        confidence, reason = "contextual", "Explicit follow-up to the same work; intent inherited."
    else:
        confidence = "supported" if matches else "unknown"
        reason = "Requested action and business object matched; confirm if inaccurate." if matches else "No sufficiently specific requested business activity was recognized."
    if len(matches) > 4:
        matches, confidence, reason = [], "ambiguous", "Too many plausible activities; choose the intended work."
    units = _units(request, matches)
    size = "large" if (re.search(r"\b(?:complex|comprehensive|extensive)\b|\b(?:1[1-9]|[2-9]\d|\d{3,})[- ]pages?", request)
                       or any(value > 50 for value in units.values())) else "standard"
    return {"intents": list(dict.fromkeys(matches)), "confidence": confidence, "reason": reason,
            "new_work": new_work, "size": size, "units": units, "version": CLASSIFIER_VERSION}
