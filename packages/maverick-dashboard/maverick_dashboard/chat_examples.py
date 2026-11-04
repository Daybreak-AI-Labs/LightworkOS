"""What the empty chat offers: example requests for the person's department and one true limit.

Departments come from the same catalogue as the sample tasks
(:mod:`maverick.sample_outcomes`), matched to the person's department access
(their granted suites) or, for someone with access to every department, to the
department picked during setup. The examples work in a plain chat without
attached files; the department's sample task stays one link away on Get
started, where it runs on made-up files.
"""
from __future__ import annotations

# The one limit the empty state states. It is true in code: the shell tool
# demands a fresh human decision for every command (allow_auto_approve=False,
# consult_ledger=False), whatever the workspace's approval mode; the test
# suite pins that. Nothing here claims more than that.
# What it is and can do, how reliable it is, and two limits that are
# true in code (shell consent; the tool registry and its access list).
CAPABILITY = ("Lightwork is an AI assistant. It plans and carries out multi-step work with "
              "Lightwork's specialists, then hands you the result to review.")
LIMITS = ("Lightwork can make mistakes, so check important facts before you rely on them. "
          "It never runs a command without a person's approval, and it only reaches the tools "
          "and connected systems your administrator allows.")

EXAMPLES: dict[str, tuple[str, ...]] = {
    "finance": (
        "Explain the difference between accrued and prepaid expenses with a short example.",
        "Draft a polite reminder to a customer whose invoice is 30 days overdue.",
        "Build a month-end close checklist for a small finance team.",
    ),
    "privacy": (
        "Explain what a data subject access request is and how long we have to answer one.",
        "Draft a plain-language notice telling customers what personal data we keep and why.",
        "List the questions to ask a new vendor before it handles customer data.",
    ),
    "security": (
        "List the signs that an email is a phishing attempt, with an example of each.",
        "Draft a short message warning staff about a phishing email that is going around.",
        "Make a checklist for the first hour after a suspected security incident.",
    ),
    "legal": (
        "Explain the usual clauses in a mutual NDA in plain words.",
        "List the points counsel should check before a supplier contract renews.",
        "Draft a polite email asking the other side for a signed copy of our NDA.",
    ),
    "hr": (
        "Draft a warm welcome email for a new starter's first day.",
        "Build a first-week onboarding plan for a new warehouse coordinator.",
        "Write five fair interview questions for a customer support role.",
    ),
    "procurement": (
        "Draft a polite email asking a supplier to confirm a late order's delivery date.",
        "List what to compare when choosing between two quotes for the same item.",
        "Explain three-way matching of invoices, purchase orders and receipts in plain words.",
    ),
    "customer_support": (
        "Draft a friendly reply to a customer whose order arrived damaged.",
        "Suggest five tags for sorting support tickets by what customers need.",
        "Write a short help article on how to reset a password.",
    ),
    "tax": (
        "Explain the difference between a tax deduction and a tax credit with an example.",
        "Draft a short cover letter to send with our reply to a tax notice.",
        "List the records to keep for a business expense claim.",
    ),
}
GENERAL = (
    "Summarize the key points of a long email I paste in.",
    "Turn my rough notes into a clear project update for my manager.",
    "Draft an agenda for a 30-minute team meeting.",
    "Explain a term I don't understand in plain words.",
)
# Department access (suite keys) each catalogue department serves, besides the
# suite of its sample task's own specialist.
_SUITES = {
    "finance": {"finance"}, "privacy": {"data_analytics"}, "security": {"security_ops", "it_grc"},
    "legal": {"legal"}, "hr": {"hr"}, "procurement": {"procurement"},
    "customer_support": {"customer_experience"}, "tax": {"tax"},
}
_MOST = 5


def _departments(request) -> list[str]:
    """The person's catalogue departments, best match first."""
    from maverick import sample_outcomes
    from maverick.config import get_first_outcome
    from maverick.domain import suite_for

    from . import auth

    suites = auth.caller_suites(request)
    if suites is None:
        recorded = get_first_outcome().get("department")
        return [recorded] if recorded in sample_outcomes.FIRST_OUTCOMES else []
    named = [slug for slug in sample_outcomes.FIRST_OUTCOMES if _SUITES.get(slug, set()) & suites]
    by_specialist = [slug for slug, outcome in sample_outcomes.FIRST_OUTCOMES.items()
                     if slug not in named and suite_for(outcome.pack) in suites]
    return named + by_specialist


def _sample(request, department: str) -> dict | None:
    """The department's sample task, when Get started can offer it to this person."""
    try:
        from .guided_outcome import first_outcomes_for

        offered = first_outcomes_for(request)
    except Exception:  # the examples never depend on the sample catalogue loading
        return None
    for row in offered.get("outcomes") or []:
        if row.get("department") == department:
            return {"label": row.get("label", ""), "href": "/start#first-outcome-title"}
    return None


def examples_for(request) -> dict:
    """4-6 example requests, their department's name, and its sample task."""
    from maverick import sample_outcomes

    departments = [slug for slug in _departments(request) if slug in EXAMPLES]
    picked: list[str] = []
    for slug in departments[:2]:
        picked.extend(EXAMPLES[slug][: 3 if len(departments) == 1 else 2])
    for text in GENERAL:
        if len(picked) >= (_MOST if departments else len(GENERAL)):
            break
        picked.append(text)
    first = departments[0] if departments else None
    return {"department": sample_outcomes.get(first).label if first else None,
            "examples": picked[:6], "sample": _sample(request, first) if first else None}


__all__ = ["CAPABILITY", "EXAMPLES", "GENERAL", "LIMITS", "examples_for"]
