"""Every word a member of the public reads on the rights-request pages.

One place, keyed by language, so a translation is a new dict entry rather
than a template edit. ``strings(lang)`` falls back to English key by key, so
a partial translation never blanks the page. Plain language throughout:
these pages are read by people who are not privacy specialists.
"""
from __future__ import annotations

STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "page_title": "Privacy request",
        "heading": "Make a privacy request to {organisation}",
        "intro": (
            "Use this form to ask {organisation} about the personal data it "
            "holds about you. Tell us which law applies to you and what you "
            "would like us to do. We will email you a link to confirm your "
            "address before we start."
        ),
        "jurisdiction_label": "Which law applies to you?",
        "jurisdiction_help": (
            "Choose where you live. This decides which requests you can make "
            "and how long we have to answer."
        ),
        "request_type_label": "What would you like us to do?",
        "name_label": "Your name (optional)",
        "email_label": "Your email address",
        "email_help": "We send the confirmation link and our answer here.",
        "relationship_label": "How do you know {organisation}?",
        "relationship_customer": "I am or was a customer",
        "relationship_employee": "I am or was an employee or contractor",
        "relationship_other": "Something else",
        "message_label": "Anything that helps us find your data (optional)",
        "message_help": "For example an account number or the email you used with us.",
        "agent_label": "I am making this request on behalf of someone else as their authorised agent",
        "agent_help": "We may ask for proof that you are allowed to act for them.",
        "challenge_label": "Quick check: {question}",
        "challenge_help": "This helps us keep automated submissions out.",
        "submit": "Send my request",
        "sending": "Sending…",
        "privacy_policy": "How we handle your data",
        "contact": "Questions? Email {contact_email}.",
        "not_available": (
            "This request form is not available. If you need to make a "
            "privacy request, please contact the organisation directly."
        ),
        "error_generic": "Something went wrong. Please check the form and try again.",
        "error_summary_title": "There is a problem",
        "error_title_prefix": "Error: ",
        "error_email_missing": "Enter your email address, so we can send you the confirmation link.",
        "error_email_format": "Enter an email address like name@example.com.",
        "error_answer_missing": "Answer the quick check, using numbers.",
        "error_answer_format": "Answer the quick check using numbers only.",
        "error_challenge": "That answer was not right. Please try the new sum.",
        "error_rate": "Too many requests right now. Please wait a while and try again.",
        "verify_title": "Confirm your privacy request",
        "verify_intro": (
            "Press the button to confirm that this email address is yours. "
            "Your request will then be opened and the clock starts."
        ),
        "verify_button": "Confirm my request",
        "verify_invalid": (
            "This link is not valid. It may have expired or already been used. "
            "If you still need to make a request, please submit the form again."
        ),
        "status_title": "Your privacy request",
        "status_reference": "Reference",
        "status_type": "What you asked for",
        "status_law": "Law that applies",
        "status_state": "Where it stands",
        "status_received": "Received on",
        "status_due": "Answer due by",
        "status_extended": "We have extended the response time and told you why by email.",
        "status_unverified": (
            "We are waiting for you to confirm your email address. Open the "
            "link we sent you to start your request."
        ),
        "status_invalid": "This link is not valid or has expired.",
        "non_legal_advice": (
            "The dates shown come from the law you chose and are provided for "
            "information; they are not legal advice."
        ),
    },
}


def strings(lang: str = "en") -> dict[str, str]:
    """The catalog for ``lang`` over the English one, key by key."""
    base = dict(STRINGS["en"])
    base.update(STRINGS.get(lang or "en", {}))
    return base
