"""Who did something, in words a person reads.

A sign-in identifier (``user:google-oauth2|1048...``) never reaches a page.
The installation knows a person's name or email from four records: their
company directory (SCIM) entry bound to the sign-in, the name and verified
email their company sign-in reported (:mod:`account_profiles`), the address an
accepted invitation was sent to, and the signed-in person's own verified address.
Without one of them the account kind is shown ("Google account"), as before.
Lightwork's own background workers and AI specialists read as what they are.

The records are read once per :func:`labeler` call, so a list of rows costs
one read; an unreadable record only means fewer names, never an error.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable

from .identity_format import humanize, humanize_principal

log = logging.getLogger(__name__)

# An AI role's or specialist's run name: "<role>-<depth>" ("pe_content_writing-0").
_ROLE_RUN = re.compile(r"(?P<role>[a-z][a-z0-9_]*)-\d{1,3}")


def _principal(sub: str) -> str:
    return sub if sub.startswith("user:") else "user:" + sub


def _directory_names() -> dict[str, str]:
    """Name or email per sign-in, from the company directory and invitations."""
    names: dict[str, str] = {}
    try:
        from . import subject_directory
        from .scim import _load

        users = _load()
        index = subject_directory.load_index() if users else {}
        for record in users.values():
            label = " ".join(str(record.get("displayName") or record.get("email") or "").split())
            if not label:
                continue
            # Bound the way directory access checks bind a record to a sign-in.
            ids = [str(record.get("externalId") or ""), str(record.get("id") or "")]
            for sub in {*ids, *subject_directory.subs_in(index, ids)} - {""}:
                names.setdefault(_principal(sub), label)
    except Exception:  # noqa: BLE001 -- an unreadable directory only means fewer names
        log.debug("company directory names unavailable", exc_info=True)
    try:
        from . import account_profiles

        for principal, label in account_profiles.names().items():
            names.setdefault(principal, label)
    except Exception:  # noqa: BLE001 -- as above
        log.debug("recorded sign-in names unavailable", exc_info=True)
    try:
        from . import invites

        for invite in invites.list_invites():
            if invite.used_by and invite.email:
                names.setdefault(invite.used_by, invite.email)
    except Exception:  # noqa: BLE001 -- as above
        log.debug("invitation addresses unavailable", exc_info=True)
    return names


def _own_name(request) -> tuple[str, str]:
    """The signed-in person's sign-in and the address their sign-in verified."""
    principal = getattr(getattr(request, "state", None), "principal", None)
    claims = getattr(principal, "claims", None) or {}
    address = next((str(claims[key]) for key in ("verified_email", "idp_email") if claims.get(key)), "")
    if not address and claims.get("email") and claims.get("email_verified") is True:
        address = str(claims["email"])
    who = getattr(principal, "principal", "") or ""
    return (who, address) if isinstance(who, str) and who and "@" in address else ("", "")


def _non_person(value: str) -> str:
    """A Lightwork worker or AI specialist, or "" for anything else."""
    kind, _, rest = value.partition(":")
    if kind == "system" and rest:
        return humanize(rest.split(":", 1)[0]) + " (Lightwork)"
    run = _ROLE_RUN.fullmatch(value)
    if run:
        from .plain_labels import AGENT_ROLES

        role = run.group("role")
        try:
            from maverick.domain import available_domains

            known = role in AGENT_ROLES or role in available_domains()
        except Exception:  # noqa: BLE001 -- an unreadable catalog names nothing
            known = role in AGENT_ROLES
        if known:
            from .step_narration import role_title

            return role_title(role) + " (AI)"
    return ""


def labeler(request=None) -> Callable[[object], str]:
    """``label(principal) -> str`` for the people on one page."""
    names = _directory_names()
    own, address = _own_name(request)
    if own:
        names.setdefault(own, address)

    def label(principal: object) -> str:
        value = "" if principal is None else str(principal).strip()
        if not value:
            return "Unknown"
        return names.get(value) or _non_person(value) or humanize_principal(value).name

    return label
