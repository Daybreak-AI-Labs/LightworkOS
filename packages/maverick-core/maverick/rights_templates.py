"""Email templates for answering privacy-rights requests, per regime family.

Six kinds of notice (acknowledgement, verification, identity follow-up,
extension, completion, refusal) for each template family in
:data:`maverick.rights_deadlines.FAMILIES`. Defaults ship in code and are
written for a member of the public; an administrator may replace any of
them from the settings page. Each save gets a version number and the last
20 versions of a template are kept, so recent wording can be shown later;
the text of older versions is discarded.

Placeholders are ``{name}`` tokens from :data:`PLACEHOLDERS` only -- a saved
template naming an unknown one is refused, so a typo never ships a literal
``{due_dat}`` to a requester. Rendering never raises on a missing value; it
leaves the field empty, because a notice with one blank is better than no
notice when a deadline is running.
"""
from __future__ import annotations

import re
import time
from typing import Any

from .governed_records import GovernedRecordStore
from .rights_deadlines import FAMILIES

KINDS = (
    "acknowledgement", "verification", "identity_followup", "extension",
    "completion", "refusal",
)
KIND_LABELS = {
    "acknowledgement": "We received your request",
    "verification": "Please confirm your email address",
    "identity_followup": "We need more information to confirm who you are",
    "extension": "We need more time to answer your request",
    "completion": "Your request has been answered",
    "refusal": "We cannot carry out your request",
}
#: Every placeholder a template may use, with what it becomes.
PLACEHOLDERS: dict[str, str] = {
    "organisation": "The organisation's name, from the property settings.",
    "property_name": "The website or app the request came through.",
    "requester_name": "The name the requester typed (may be empty).",
    "reference": "The request reference, e.g. DSAR-1a2b3c4d5e.",
    "request_type": "The request type in plain words, e.g. 'a copy of your data'.",
    "jurisdiction": "The law the requester chose, e.g. 'California (CCPA/CPRA)'.",
    "received_date": "The date the request was received (YYYY-MM-DD).",
    "due_date": "The date the answer is due (YYYY-MM-DD).",
    "extended_until_date": "The new due date after an extension (YYYY-MM-DD).",
    "extension_reason": "The reason recorded for the extension.",
    "verify_link": "The single-use link that confirms the email address.",
    "status_link": "The link where the requester can follow progress.",
    "secure_link": "The secure download link for the answer.",
    "secure_link_expires": "When the secure link stops working (YYYY-MM-DD).",
    "lawful_basis": "The legal ground for refusing, written by the operator.",
    "contact_email": "The privacy contact address from the property settings.",
}
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_MAX_SUBJECT = 200
_MAX_BODY = 8000
_MAX_VERSIONS = 20
_MAX_RECORDS = 200

_STORE = GovernedRecordStore("rights_templates", "RTPL", "rights_template")


class RightsTemplateError(ValueError):
    """A template could not be saved as written."""


# --------------------------------------------------------------------------- #
# Defaults -- plain language, numbers come from the clock, never from text
# --------------------------------------------------------------------------- #

_COMMON: dict[str, dict[str, str]] = {
    "verification": {
        "subject": "Confirm your privacy request to {organisation} ({reference})",
        "body": (
            "Hello{requester_name},\n\n"
            "We received a request through {property_name} asking for "
            "{request_type}.\n\n"
            "To confirm that this email address is yours, please open this "
            "link. It works once and expires soon:\n{verify_link}\n\n"
            "You can follow the progress of your request here at any time:\n"
            "{status_link}\n\n"
            "If you did not make this request, you can ignore this email and "
            "nothing further will happen.\n\n"
            "{organisation}\n{contact_email}"
        ),
    },
    "identity_followup": {
        "subject": "Your privacy request {reference}: we need to confirm who you are",
        "body": (
            "Hello{requester_name},\n\n"
            "Before we can act on your request for {request_type}, we need "
            "to make sure we are dealing with the right person. Please reply "
            "to this email with the information our team has asked for. We "
            "only use it to check your identity and then delete it.\n\n"
            "Reference: {reference}\n{organisation}\n{contact_email}"
        ),
    },
    "completion": {
        "subject": "Your privacy request {reference} has been answered",
        "body": (
            "Hello{requester_name},\n\n"
            "We have finished your request for {request_type}.\n\n"
            "Where there is something to send you, it is available at this "
            "secure link until {secure_link_expires}:\n{secure_link}\n\n"
            "The link is personal to you. Please do not forward it.\n\n"
            "If you have questions, reply to this email.\n\n"
            "{organisation}\n{contact_email}"
        ),
    },
}


def _family_defaults(
    ack_body: str, ext_body: str, refusal_body: str,
) -> dict[str, dict[str, str]]:
    return {
        **_COMMON,
        "acknowledgement": {
            "subject": "We received your privacy request ({reference})",
            "body": ack_body,
        },
        "extension": {
            "subject": "Your privacy request {reference}: we need more time",
            "body": ext_body,
        },
        "refusal": {
            "subject": "Your privacy request {reference}: our decision",
            "body": refusal_body,
        },
    }


_SIGN = "\n\n{organisation}\n{contact_email}"

DEFAULTS: dict[str, dict[str, dict[str, str]]] = {
    "gdpr": _family_defaults(
        "Hello{requester_name},\n\n"
        "Thank you. We received your request for {request_type} on "
        "{received_date} (reference {reference}).\n\n"
        "We will answer by {due_date}. If your request is complex we may "
        "need up to two more months; if so we will tell you before "
        "{due_date} and explain why.\n\n"
        "You can follow progress here:\n{status_link}" + _SIGN,
        "Hello{requester_name},\n\n"
        "We are still working on your request for {request_type} "
        "(reference {reference}). We need more time because: "
        "{extension_reason}\n\n"
        "We will answer by {extended_until_date} at the latest. You have the "
        "right to complain to your data protection authority if you are "
        "unhappy with this." + _SIGN,
        "Hello{requester_name},\n\n"
        "We have looked carefully at your request for {request_type} "
        "(reference {reference}) and we are not able to carry it out.\n\n"
        "The reason is: {lawful_basis}\n\n"
        "You have the right to complain to your data protection authority "
        "and to seek a judicial remedy." + _SIGN,
    ),
    "us_state": _family_defaults(
        "Hello{requester_name},\n\n"
        "This confirms we received your request for {request_type} on "
        "{received_date} (reference {reference}).\n\n"
        "We will respond by {due_date}. If we need more time we may take "
        "up to 45 additional days; if so we will tell you before {due_date} "
        "and explain why.\n\n"
        "You can follow progress here:\n{status_link}" + _SIGN,
        "Hello{requester_name},\n\n"
        "We are still working on your request for {request_type} "
        "(reference {reference}). We are extending our response time "
        "because: {extension_reason}\n\n"
        "We will respond by {extended_until_date} at the latest." + _SIGN,
        "Hello{requester_name},\n\n"
        "We have reviewed your request for {request_type} (reference "
        "{reference}) and we are declining to act on it.\n\n"
        "The reason is: {lawful_basis}\n\n"
        "You may appeal this decision by replying to this email. If your "
        "appeal is denied, you may contact your state Attorney General." + _SIGN,
    ),
    "lgpd": _family_defaults(
        "Hello{requester_name},\n\n"
        "We received your request for {request_type} on {received_date} "
        "(reference {reference}).\n\n"
        "We will answer by {due_date}.\n\n"
        "You can follow progress here:\n{status_link}" + _SIGN,
        "Hello{requester_name},\n\n"
        "We are still working on your request for {request_type} "
        "(reference {reference}). Reason: {extension_reason}\n\n"
        "We now expect to answer by {extended_until_date}." + _SIGN,
        "Hello{requester_name},\n\n"
        "We have reviewed your request for {request_type} (reference "
        "{reference}) and we are unable to carry it out.\n\n"
        "The reason is: {lawful_basis}\n\n"
        "You may file a complaint with the Autoridade Nacional de Proteção "
        "de Dados (ANPD)." + _SIGN,
    ),
    "pipeda": _family_defaults(
        "Hello{requester_name},\n\n"
        "We received your request for {request_type} on {received_date} "
        "(reference {reference}).\n\n"
        "We will respond by {due_date}. If we need more time we will tell "
        "you before then, with the reasons and your right to complain to "
        "the Privacy Commissioner of Canada.\n\n"
        "You can follow progress here:\n{status_link}" + _SIGN,
        "Hello{requester_name},\n\n"
        "We are extending the time to respond to your request for "
        "{request_type} (reference {reference}). Reason: {extension_reason}\n\n"
        "We will respond by {extended_until_date}. You have the right to "
        "make a complaint to the Privacy Commissioner of Canada about this "
        "extension." + _SIGN,
        "Hello{requester_name},\n\n"
        "We have reviewed your request for {request_type} (reference "
        "{reference}) and we are unable to carry it out.\n\n"
        "The reason is: {lawful_basis}\n\n"
        "You have the right to make a complaint to the Privacy Commissioner "
        "of Canada." + _SIGN,
    ),
    "australia": _family_defaults(
        "Hello{requester_name},\n\n"
        "We received your request for {request_type} on {received_date} "
        "(reference {reference}).\n\n"
        "We aim to respond by {due_date}.\n\n"
        "You can follow progress here:\n{status_link}" + _SIGN,
        "Hello{requester_name},\n\n"
        "We are still working on your request for {request_type} "
        "(reference {reference}). Reason: {extension_reason}\n\n"
        "We now expect to respond by {extended_until_date}." + _SIGN,
        "Hello{requester_name},\n\n"
        "We have reviewed your request for {request_type} (reference "
        "{reference}) and we are unable to carry it out.\n\n"
        "The reason is: {lawful_basis}\n\n"
        "You may complain to the Office of the Australian Information "
        "Commissioner (OAIC)." + _SIGN,
    ),
    "japan": _family_defaults(
        "Hello{requester_name},\n\n"
        "We received your request for {request_type} on {received_date} "
        "(reference {reference}).\n\n"
        "We will respond without delay; our target is {due_date}.\n\n"
        "You can follow progress here:\n{status_link}" + _SIGN,
        "Hello{requester_name},\n\n"
        "We are still working on your request for {request_type} "
        "(reference {reference}). Reason: {extension_reason}\n\n"
        "We now expect to respond by {extended_until_date}." + _SIGN,
        "Hello{requester_name},\n\n"
        "We have reviewed your request for {request_type} (reference "
        "{reference}) and we are unable to carry it out.\n\n"
        "The reason is: {lawful_basis}" + _SIGN,
    ),
}
assert set(DEFAULTS) == set(FAMILIES)


# --------------------------------------------------------------------------- #
# Validation, storage, rendering
# --------------------------------------------------------------------------- #

def _check(family: str, kind: str) -> None:
    if family not in FAMILIES:
        raise RightsTemplateError(f"family must be one of {', '.join(FAMILIES)}")
    if kind not in KINDS:
        raise RightsTemplateError(f"kind must be one of {', '.join(KINDS)}")


def placeholders_in(text: str) -> set[str]:
    return set(_PLACEHOLDER_RE.findall(text or ""))


def validate(subject: str, body: str) -> tuple[str, str]:
    """Bounded text, known placeholders only."""
    subject = (subject or "").strip()
    body = (body or "").strip()
    if not subject or len(subject) > _MAX_SUBJECT:
        raise RightsTemplateError(f"subject must be 1-{_MAX_SUBJECT} characters")
    if "\n" in subject or "\r" in subject:
        raise RightsTemplateError("subject must be a single line")
    if not body or len(body) > _MAX_BODY:
        raise RightsTemplateError(f"body must be 1-{_MAX_BODY} characters")
    unknown = sorted((placeholders_in(subject) | placeholders_in(body)) - set(PLACEHOLDERS))
    if unknown:
        raise RightsTemplateError(
            "unknown placeholder(s): " + ", ".join("{" + p + "}" for p in unknown)
        )
    return subject, body


def _stored(family: str, kind: str) -> dict[str, Any] | None:
    for row in _STORE.list(limit=_MAX_RECORDS + 1):
        if row.get("family") == family and row.get("kind") == kind:
            return row
    return None


def get_template(family: str, kind: str) -> dict[str, Any]:
    """The template in force: the latest saved version, else the default."""
    _check(family, kind)
    row = _stored(family, kind)
    if row and row.get("versions"):
        latest = row["versions"][-1]
        return {
            "family": family, "kind": kind, "subject": latest["subject"],
            "body": latest["body"], "version": int(latest["version"]),
            "source": "custom", "saved_by": latest.get("saved_by", ""),
            "saved_at": latest.get("saved_at"),
        }
    default = DEFAULTS[family][kind]
    return {
        "family": family, "kind": kind, "subject": default["subject"],
        "body": default["body"], "version": 0, "source": "default",
    }


def save_template(
    family: str, kind: str, *, subject: str, body: str, actor: str,
) -> dict[str, Any]:
    """Save a new version of one template (validated; older versions kept)."""
    _check(family, kind)
    subject, body = validate(subject, body)
    who = (actor or "").strip()[:256] or "dashboard"
    row = _stored(family, kind)
    entry = {"subject": subject, "body": body, "saved_by": who, "saved_at": time.time()}
    if row is None:
        entry["version"] = 1
        _STORE.create(
            {"id": _STORE.new_id(), "family": family, "kind": kind,
             "versions": [entry]},
            action="save_template", actor=who, max_records=_MAX_RECORDS,
        )
        return get_template(family, kind)

    def mutate(value: dict[str, Any]) -> None:
        versions = list(value.get("versions") or [])
        entry["version"] = (int(versions[-1]["version"]) if versions else 0) + 1
        versions.append(entry)
        value["versions"] = versions[-_MAX_VERSIONS:]

    _STORE.update(
        str(row["id"]), mutate, expected_revision=int(row.get("revision") or 0),
        action="save_template", actor=who,
    )
    return get_template(family, kind)


def reset_template(family: str, kind: str, *, actor: str) -> dict[str, Any]:
    """Go back to the shipped default (kept as a new version for the trail)."""
    default = DEFAULTS[family][kind]
    return save_template(
        family, kind, subject=default["subject"], body=default["body"], actor=actor,
    )


def history(family: str, kind: str) -> list[dict[str, Any]]:
    _check(family, kind)
    row = _stored(family, kind)
    return [dict(v) for v in (row or {}).get("versions") or []]


def list_templates() -> list[dict[str, Any]]:
    """Every family x kind with the template currently in force."""
    return [get_template(family, kind) for family in FAMILIES for kind in KINDS]


def render(template: dict[str, Any], context: dict[str, Any]) -> dict[str, str]:
    """Fill placeholders; a missing value renders empty, never raises."""
    def fill(text: str) -> str:
        return _PLACEHOLDER_RE.sub(
            lambda m: str(context.get(m.group(1), "") or ""), text or "")

    return {"subject": fill(template["subject"]), "body": fill(template["body"])}


__all__ = [
    "DEFAULTS", "KINDS", "KIND_LABELS", "PLACEHOLDERS", "RightsTemplateError",
    "get_template", "history", "list_templates", "placeholders_in", "render",
    "reset_template", "save_template", "validate",
]
