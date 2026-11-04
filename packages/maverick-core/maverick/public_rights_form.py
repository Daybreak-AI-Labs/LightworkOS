"""The public privacy-rights request form: intake, email verification, status.

An anonymous person on the operator's website files a request for one
configured *property* (a website or app), choosing the law that applies to
them; the request enters the DSAR tracker as ``unverified`` and becomes
``open`` when they open the single-use verification link emailed to the
address they gave -- the one identity method this platform performs itself
(``email_challenge``). A separate long-lived status token lets them follow
progress without an account.

Anti-abuse without a third-party service: a signed arithmetic challenge,
a honeypot field, per-address and per-email sliding-window limits, and
bounded field sizes. Answers to the public never confirm or deny whether an
email address is known here: a submission is answered with the request's
reference and says "if the address is valid we sent a link" only when the
confirmation email went out (otherwise it says it could not be sent and who
to contact), and every unknown, expired or used token reads as the same
"not found".

Config (``[privacy_automation.public_rights_form]``): ``enable``,
``verification_ttl_hours``, ``status_ttl_days``, ``requests_per_ip_per_hour``,
``requests_per_email_per_day``, ``internal_target_days``,
``max_message_chars``. Email goes through :mod:`maverick.mailer` (the
platform's one sending account); when none is configured the notice is
logged on the request as not sent, never lost silently.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from typing import Any

from . import rights_deadlines, rights_templates
from .constant_time import text_equals
from .governed_records import GovernedRecordStore

log = logging.getLogger(__name__)

ACTOR = "public-rights-form"
RELATIONSHIPS = ("customer", "employee", "other")
#: What a member of the public reads for each request type.
REQUEST_TYPE_LABELS = {
    "access": "a copy of your data",
    "deletion": "deletion of your data",
    "correction": "correction of your data",
    "portability": "your data in a portable format",
    "opt_out": "opting out of the sale or sharing of your data",
    "limit_sensitive": "limiting the use of your sensitive data",
    "objection": "stopping a use of your data you object to",
    "restriction": "restricting how your data is used",
    "withdraw_consent": "withdrawing your consent",
}
_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,47}\Z")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,24}\Z")
_ORIGIN_RE = re.compile(r"https://[A-Za-z0-9.-]{1,253}(?::\d{1,5})?\Z")
_URL_RE = re.compile(r"https://[^\s<>\"']{1,500}\Z")
_MAX_PROPERTIES = 500
_MAX_ORIGINS = 20
_MAX_SCAN = 10_001
_CHALLENGE_TTL = 15 * 60
_MAX_BURNED = 10_000
_DEFAULTS = {
    "enable": False,
    "verification_ttl_hours": 24,
    "status_ttl_days": 90,
    "requests_per_ip_per_hour": 5,
    "requests_per_email_per_day": 3,
    "internal_target_days": 30,
    "max_message_chars": 4000,
}

_PROPERTIES = GovernedRecordStore("rights_form_properties", "RFP", "rights_form_property", archive_when_full=False)


class PublicRightsFormError(ValueError):
    """The submission cannot be accepted as sent (the message is public-safe)."""


class RateLimited(PublicRightsFormError):
    """Too many requests from this address or for this email."""


class ChallengeFailed(PublicRightsFormError):
    """The arithmetic challenge was wrong, expired or reused."""


class PublicRightsFormConfigError(RuntimeError):
    """The module is off or misconfigured."""


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

def get_config() -> dict[str, Any]:
    from .config import load_global_config

    config = load_global_config() or {}
    privacy = config.get("privacy_automation") or {}
    section = privacy.get("public_rights_form") if isinstance(privacy, Mapping) else None
    if section is None:
        section = {}
    if not isinstance(section, Mapping):
        raise PublicRightsFormConfigError(
            "privacy_automation.public_rights_form must be a table")
    out: dict[str, Any] = {}
    for key, default in _DEFAULTS.items():
        value = section.get(key, default)
        if key == "enable":
            if not isinstance(value, bool):
                raise PublicRightsFormConfigError(
                    "privacy_automation.public_rights_form.enable must be a boolean")
        elif isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise PublicRightsFormConfigError(
                f"privacy_automation.public_rights_form.{key} must be a positive integer")
        out[key] = value
    out["enable"] = bool(out["enable"]) and bool(
        isinstance(privacy, Mapping) and privacy.get("enable", False) is True
    )
    return out


def enabled() -> bool:
    try:
        return get_config()["enable"] is True
    except Exception:
        return False


def _require_enabled() -> dict[str, Any]:
    cfg = get_config()
    if not cfg["enable"]:
        raise PublicRightsFormConfigError(
            "the public rights-request form is off "
            "([privacy_automation.public_rights_form] enable)")
    return cfg


# --------------------------------------------------------------------------- #
# Properties (one per website or app)
# --------------------------------------------------------------------------- #

def _text(value: object, label: str, limit: int, *, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise PublicRightsFormError(f"{label} is required")
    if len(text) > limit:
        raise PublicRightsFormError(f"{label} must be at most {limit} characters")
    return text


def _slug(value: object) -> str:
    slug = str(value or "").strip().lower()
    if not _SLUG_RE.fullmatch(slug):
        raise PublicRightsFormError(
            "the link name must be 2-48 lower-case letters, digits or hyphens")
    return slug


def _property_view(row: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "id", "slug", "name", "organisation", "contact_email", "privacy_policy_url",
        "default_jurisdiction", "jurisdictions", "request_types", "allowed_origins",
        "enabled", "revision", "created_at", "updated_at",
    )
    return {k: row.get(k) for k in keys}


def _validate_property(fields: Mapping[str, Any]) -> dict[str, Any]:
    jurisdictions = [str(j) for j in (fields.get("jurisdictions") or [])]
    unknown = [j for j in jurisdictions if j not in rights_deadlines.REGIMES]
    if unknown or not jurisdictions:
        raise PublicRightsFormError(
            "choose at least one verified jurisdiction"
            + (f"; unknown: {', '.join(unknown)}" if unknown else ""))
    default = str(fields.get("default_jurisdiction") or jurisdictions[0])
    if default not in jurisdictions:
        raise PublicRightsFormError("the default jurisdiction must be one of those offered")
    types = [str(t) for t in (fields.get("request_types") or rights_deadlines.REQUEST_TYPES)]
    bad = [t for t in types if t not in rights_deadlines.REQUEST_TYPES]
    if bad or not types:
        raise PublicRightsFormError("choose at least one known request type")
    origins = [str(o).strip().rstrip("/") for o in (fields.get("allowed_origins") or [])]
    if len(origins) > _MAX_ORIGINS or any(not _ORIGIN_RE.fullmatch(o) for o in origins):
        raise PublicRightsFormError(
            "allowed origins must be https:// addresses without a path (at most 20)")
    contact = _text(fields.get("contact_email"), "contact email", 200)
    if not _EMAIL_RE.fullmatch(contact):
        raise PublicRightsFormError("contact email must be a valid address")
    policy = _text(fields.get("privacy_policy_url"), "privacy policy link", 500, required=False)
    if policy and not _URL_RE.fullmatch(policy):
        raise PublicRightsFormError("the privacy policy link must start with https://")
    return {
        "name": _text(fields.get("name"), "property name", 200),
        "organisation": _text(fields.get("organisation"), "organisation name", 200),
        "contact_email": contact,
        "privacy_policy_url": policy,
        "default_jurisdiction": default,
        "jurisdictions": jurisdictions,
        "request_types": types,
        "allowed_origins": origins,
        "enabled": bool(fields.get("enabled", True)),
    }


def get_property(slug: str) -> dict[str, Any] | None:
    try:
        wanted = _slug(slug)
    except PublicRightsFormError:
        return None
    for row in _PROPERTIES.list(limit=_MAX_PROPERTIES + 1):
        if row.get("slug") == wanted:
            return _property_view(row)
    return None


def list_properties() -> list[dict[str, Any]]:
    return sorted(
        (_property_view(r) for r in _PROPERTIES.list(limit=_MAX_PROPERTIES + 1)),
        key=lambda r: str(r.get("slug") or ""),
    )


def upsert_property(slug: str, fields: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
    """Create or replace the form settings for one property."""
    key = _slug(slug)
    body = _validate_property(fields)
    who = _text(actor, "actor", 256)
    existing = get_property(key)
    if existing is None:
        record = {"id": _PROPERTIES.new_id(), "slug": key, **body}
        return _property_view(_PROPERTIES.create(
            record, action="upsert_property", actor=who, max_records=_MAX_PROPERTIES,
        ))

    def mutate(value: dict[str, Any]) -> None:
        value.update(body)

    saved = _PROPERTIES.update(
        str(existing["id"]), mutate, expected_revision=int(existing["revision"] or 0),
        action="upsert_property", actor=who,
    )
    if saved is None:  # pragma: no cover - raced deletion
        raise PublicRightsFormError("property vanished during update")
    return _property_view(saved)


def delete_property(slug: str, *, actor: str) -> bool:
    existing = get_property(slug)
    if existing is None:
        return False
    _text(actor, "actor", 256)
    return _PROPERTIES.delete(str(existing["id"]), expected_revision=int(existing["revision"] or 0))


# --------------------------------------------------------------------------- #
# Anti-abuse: signed arithmetic challenge, rate limits
# --------------------------------------------------------------------------- #

_secret_lock = threading.Lock()
_secret: bytes | None = None
_burned: deque[str] = deque()
_burned_set: set[str] = set()


def _challenge_secret() -> bytes:
    """HMAC key for challenge tokens: derived from the deployment's
    encryption key when one is set (so every worker agrees), else a random
    per-process key (single-process deployments; a token issued by one
    worker would be refused by another, which only costs a retry)."""
    global _secret
    with _secret_lock:
        if _secret is None:
            seed = os.environ.get("MAVERICK_ENCRYPTION_KEY", "").strip()
            _secret = (
                hashlib.sha256(b"public-rights-form-challenge:" + seed.encode()).digest()
                if seed else secrets.token_bytes(32)
            )
        return _secret


def _sign(answer: int, expires: int, nonce: str) -> str:
    message = f"{answer}|{expires}|{nonce}".encode()
    return hmac.new(_challenge_secret(), message, hashlib.sha256).hexdigest()


def new_challenge(*, now: float | None = None) -> dict[str, Any]:
    """A small sum a person can do in their head, signed so the server keeps
    no state until it is answered."""
    moment = time.time() if now is None else float(now)
    a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
    expires = int(moment) + _CHALLENGE_TTL
    nonce = secrets.token_hex(8)
    return {
        "question": f"What is {a} plus {b}?",
        "token": f"{expires}.{nonce}.{_sign(a + b, expires, nonce)}",
        "expires_at": expires,
    }


def check_challenge(token: str, answer: object, *, now: float | None = None) -> bool:
    """True once per token, for the right answer, before it expires."""
    moment = time.time() if now is None else float(now)
    try:
        expires_text, nonce, signature = str(token or "").split(".")
        expires = int(expires_text)
        value = int(str(answer).strip())
    except (ValueError, AttributeError):
        return False
    if expires < moment or len(nonce) != 16:
        return False
    if not text_equals(_sign(value, expires, nonce), signature):
        return False
    with _secret_lock:
        if nonce in _burned_set:
            return False
        _burned.append(nonce)
        _burned_set.add(nonce)
        while len(_burned) > _MAX_BURNED:
            _burned_set.discard(_burned.popleft())
    return True


class SlidingWindowLimit:
    """Bounded in-process per-key sliding window."""

    def __init__(self, window_seconds: float, *, max_keys: int = 50_000) -> None:
        self.window = float(window_seconds)
        self.max_keys = max_keys
        self._buckets: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, now: float) -> bool:
        """Record one event; False when the key is over its limit."""
        with self._lock:
            if key not in self._buckets and len(self._buckets) >= self.max_keys:
                for candidate, values in tuple(self._buckets.items()):
                    while values and now - values[0] >= self.window:
                        values.popleft()
                    if not values:
                        self._buckets.pop(candidate, None)
                if len(self._buckets) >= self.max_keys:
                    return False
            values = self._buckets.setdefault(key, deque())
            while values and now - values[0] >= self.window:
                values.popleft()
            if len(values) >= int(limit):
                return False
            values.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


_IP_LIMIT = SlidingWindowLimit(3600.0)
_EMAIL_LIMIT = SlidingWindowLimit(86_400.0)


def reset_limits() -> None:
    """Tests only."""
    _IP_LIMIT.reset()
    _EMAIL_LIMIT.reset()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Email
# --------------------------------------------------------------------------- #

MailSender = Callable[[str, str, str], tuple[bool, str]]
_sender: MailSender | None = None


def _default_sender(to: str, subject: str, body: str) -> tuple[bool, str]:
    from . import mailer

    if not mailer.configured():
        return False, "no sending account configured ([email] / EMAIL_USER)"
    try:
        mailer.send(to, subject, body)
    except mailer.MailerError as exc:
        return False, str(exc)[:200]
    return True, ""


def set_mail_sender(sender: MailSender | None) -> None:
    """Swap the transport (tests; a deployment adapter). ``None`` restores
    the platform mailer."""
    global _sender
    _sender = sender


def _send(to: str, subject: str, body: str) -> tuple[bool, str]:
    sender = _sender or _default_sender
    try:
        return sender(to, subject, body)
    except Exception as exc:  # noqa: BLE001 - a failed notice is recorded, never raised
        log.warning("rights-form email failed: %s", type(exc).__name__)
        return False, f"{type(exc).__name__}"


def _date(stamp: object) -> str:
    try:
        value = float(stamp or 0)
    except (TypeError, ValueError):
        return ""
    if value <= 0:
        return ""
    return datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc).strftime("%Y-%m-%d")


def _context(record: Mapping[str, Any], prop: Mapping[str, Any] | None,
             links: Mapping[str, str]) -> dict[str, str]:
    requester = record.get("requester") or {}
    name = str(requester.get("name") or "").strip()
    kind = str(record.get("kind") or "")
    public_type = rights_deadlines.PUBLIC_TYPE.get(kind, kind)
    regime = rights_deadlines.REGIMES.get(str(record.get("jurisdiction") or ""))
    return {
        "organisation": str((prop or {}).get("organisation") or ""),
        "property_name": str((prop or {}).get("name") or ""),
        "requester_name": f" {name}" if name else "",
        "reference": str(record.get("id") or ""),
        "request_type": REQUEST_TYPE_LABELS.get(public_type, public_type),
        "jurisdiction": str(regime["name"]) if regime else "",
        "received_date": _date(record.get("received_at") or record.get("created_at")),
        "due_date": _date(record.get("due_at")),
        "extended_until_date": _date(record.get("extended_until")),
        "extension_reason": str(record.get("extension_reason") or ""),
        "contact_email": str((prop or {}).get("contact_email") or ""),
        **{k: str(v) for k, v in links.items()},
    }


def _log_email(request_id: str, kind: str, sent: bool, reason: str, version: int,
               *, lawful_basis: str = "") -> None:
    from . import privacy_ops

    def mutate(record: dict[str, Any]) -> bool:
        form = dict(record.get("public_form") or {})
        emails = list(form.get("emails") or [])[-49:]
        entry = {
            "kind": kind, "sent": sent, "reason": reason, "at": time.time(),
            "template_version": version,
        }
        if lawful_basis:
            # A sent refusal is the requester's answer; keep its stated reason.
            entry["lawful_basis"] = lawful_basis[:2000]
        emails.append(entry)
        form["emails"] = emails
        record["public_form"] = form
        return True

    privacy_ops.annotate_dsar(request_id, mutate, action=f"email_{kind}", actor=ACTOR)


#: What the privacy team reads for each notice; the same words as the
#: request page's Send buttons.
NOTICE_LABELS = {
    "acknowledgement": "We received it",
    "verification": "Confirm the email address",
    "identity_followup": "Need more identity proof",
    "extension": "Extension notice",
    "completion": "Completed (with secure link)",
    "refusal": "Refusal (with lawful basis)",
}


def notice_problem(reason: str) -> tuple[str, str]:
    """Why a notice was not sent and what to do next, in plain words. The
    raw reason (setting names, server replies) stays technical detail."""
    text = str(reason or "")
    if text.startswith("no sending account configured"):
        return ("Lightwork has no email account to send from.",
                "An administrator can set one up in Settings, under Email account. "
                "Until then, contact the requester another way and note it on the request.")
    if text == "the requester has no email address":
        return ("The request has no email address to send to.",
                "Contact the requester another way and note it on the request.")
    return ("The email could not be sent.",
            "Try again. If it fails again, ask an administrator to check the email settings, "
            "or contact the requester another way.")


def notice_log(record: Mapping[str, Any]) -> dict[str, Any]:
    """The request's notices for the privacy team: only notices that were
    actually sent count as sent; each unsent one says why and what next."""
    emails = (record.get("public_form") or {}).get("emails") or []
    items = []
    for entry in emails if isinstance(emails, list) else ():
        if not isinstance(entry, Mapping):
            continue
        kind = str(entry.get("kind") or "")
        sent = entry.get("sent") is True
        problem, next_step = ("", "") if sent else notice_problem(str(entry.get("reason") or ""))
        technical = f"Template version {entry.get('template_version', 0)}"
        if not sent and entry.get("reason"):
            technical = f"{entry['reason']} · {technical}"
        items.append({
            "kind": kind, "label": NOTICE_LABELS.get(kind, kind.replace("_", " ").capitalize()),
            "sent": sent, "date": _date(entry.get("at")), "problem": problem,
            "next_step": next_step, "technical": technical,
        })
    sent_count = sum(1 for item in items if item["sent"])
    return {"sent": sent_count, "not_sent": len(items) - sent_count, "items": items}


def send_notice(
    request_id: str, kind: str, *, actor: str = ACTOR,
    extra: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Render the request's family template for ``kind`` and send it to the
    requester; the outcome is logged on the request either way.

    ``extra`` supplies the placeholders only the caller knows:
    ``lawful_basis`` (refusal), ``secure_link`` and ``secure_link_expires``
    (completion), ``verify_link`` / ``status_link`` (verification)."""
    from . import privacy_ops

    if kind not in rights_templates.KINDS:
        raise PublicRightsFormError(f"kind must be one of {', '.join(rights_templates.KINDS)}")
    record = privacy_ops.get_dsar(request_id)
    if record is None or "status" not in record:
        raise KeyError(f"no such request: {request_id}")
    extras = dict(extra or {})
    if kind == "refusal" and not str(extras.get("lawful_basis") or "").strip():
        raise PublicRightsFormError("a refusal must state its lawful basis")
    if kind == "completion" and not str(extras.get("secure_link") or "").strip():
        raise PublicRightsFormError("a completion notice needs the secure link")
    if kind == "extension" and not record.get("extended_until"):
        raise PublicRightsFormError("record the extension before sending the notice")
    prop = get_property(str((record.get("requester") or {}).get("property") or ""))
    template = rights_templates.get_template(
        rights_deadlines.family_for(str(record.get("jurisdiction") or "")), kind)
    context = _context(record, prop, extras)
    if kind == "verification":
        # The submitter has not yet proved control of this mailbox; don't let
        # them insert text or links into a notice sent to a third party.
        context["requester_name"] = ""
    rendered = rights_templates.render(template, context)
    to = str(record.get("subject_id") or "")
    sent, reason = (False, "the requester has no email address")
    if _EMAIL_RE.fullmatch(to):
        sent, reason = _send(to, rendered["subject"], rendered["body"])
    _log_email(str(record["id"]), kind, sent, reason, int(template["version"]),
               lawful_basis=str(extras.get("lawful_basis") or "") if kind == "refusal" else "")
    log.info("rights-form notice %s for %s by %s: sent=%s", kind, record["id"], actor, sent)
    problem, next_step = ("", "") if sent else notice_problem(reason)
    return {"request_id": record["id"], "kind": kind, "sent": sent, "reason": reason,
            "problem": problem, "next_step": next_step,
            "subject": rendered["subject"], "template_version": template["version"]}


# --------------------------------------------------------------------------- #
# Public intake
# --------------------------------------------------------------------------- #

def form_definition(slug: str) -> dict[str, Any] | None:
    """What the public page needs: the property's offer and a challenge.
    ``None`` when the module is off or the property is unknown/disabled."""
    if not enabled():
        return None
    prop = get_property(slug)
    if prop is None or not prop.get("enabled"):
        return None
    offered = set(prop["request_types"])
    jurisdictions = [
        {"id": row["id"], "name": row["name"],
         "rights": [r for r in row["rights"] if r in offered]}
        for row in rights_deadlines.form_choices()
        if row["id"] in prop["jurisdictions"]
    ]
    return {
        "property": {
            "slug": prop["slug"], "name": prop["name"],
            "organisation": prop["organisation"],
            "contact_email": prop["contact_email"],
            "privacy_policy_url": prop["privacy_policy_url"],
        },
        "default_jurisdiction": prop["default_jurisdiction"],
        "jurisdictions": jurisdictions,
        "request_type_labels": {t: REQUEST_TYPE_LABELS[t] for t in prop["request_types"]},
        "relationships": list(RELATIONSHIPS),
        "max_message_chars": get_config()["max_message_chars"],
        "challenge": new_challenge(),
        "non_legal_advice": rights_deadlines.NON_LEGAL_ADVICE,
    }


def _validate_submission(payload: Mapping[str, Any], prop: Mapping[str, Any],
                         cfg: Mapping[str, Any]) -> dict[str, Any]:
    email = _text(payload.get("email"), "email", 200).lower()
    if not _EMAIL_RE.fullmatch(email):
        raise PublicRightsFormError("please enter a valid email address")
    request_type = str(payload.get("request_type") or "")
    if request_type not in prop["request_types"]:
        raise PublicRightsFormError("choose what you are asking for")
    jurisdiction = str(payload.get("jurisdiction") or prop["default_jurisdiction"])
    if jurisdiction not in prop["jurisdictions"]:
        raise PublicRightsFormError("choose the law that applies to you")
    if request_type not in rights_deadlines.REGIMES[jurisdiction]["rights"]:
        raise PublicRightsFormError(
            "that request type is not available under the law you chose")
    relationship = str(payload.get("relationship") or "other")
    if relationship not in RELATIONSHIPS:
        raise PublicRightsFormError("tell us your relationship with the organisation")
    message = _text(payload.get("message"), "message", int(cfg["max_message_chars"]),
                    required=False)
    return {
        "email": email, "name": " ".join(_text(payload.get("name"), "name", 200, required=False).split()),
        "request_type": request_type, "jurisdiction": jurisdiction,
        "relationship": relationship, "message": message,
        "authorised_agent": bool(payload.get("authorised_agent")),
    }


def _mail_ready() -> bool:
    """Whether a confirmation email can be attempted at all (a sending
    account, or a transport swapped in by a deployment adapter)."""
    if _sender is not None:
        return True
    from . import mailer

    try:
        return mailer.configured()
    except Exception:  # noqa: BLE001 - unreadable mail settings cannot send
        return False


def _accepted(reference: str, *, email_sent: bool, prop: Mapping[str, Any],
              cfg: Mapping[str, Any]) -> dict[str, Any]:
    """The acceptance the requester reads: always their reference, and an
    email promise only when the confirmation email went out."""
    if email_sent:
        hours = int(cfg["verification_ttl_hours"])
        message = (
            "Thank you. If that email address is valid, we have sent it a link to "
            f"confirm your request. The link works once and expires in {hours} "
            f"hour{'' if hours == 1 else 's'}. Your reference is {reference}."
        )
    else:
        message = (
            "Thank you. We received your request, but we could not send you an "
            f"email to confirm it. Your reference is {reference}. To confirm the "
            f"request, contact {prop.get('organisation') or 'us'} at "
            f"{prop.get('contact_email') or 'the privacy contact on this page'} "
            "and quote your reference."
        )
    return {"accepted": True, "reference": reference, "email_sent": email_sent,
            "message": message}


def submit(
    slug: str, payload: Mapping[str, Any], *, client_ip: str, base_url: str,
    now: float | None = None,
) -> dict[str, Any]:
    """Accept one public submission. Returns the acceptance with the
    request's reference, promising an email only when the confirmation
    email was sent. Honeypot hits are dropped silently with a reply of the
    same shape (an unrecorded reference) so a bot cannot tell; raises
    :class:`RateLimited`, :class:`ChallengeFailed` or
    :class:`PublicRightsFormError` for the public-safe failures."""
    cfg = _require_enabled()
    prop = get_property(slug)
    if prop is None or not prop.get("enabled"):
        raise KeyError("no such form")
    moment = time.time() if now is None else float(now)
    if not isinstance(payload, Mapping) or len(payload) > 20:
        raise PublicRightsFormError("the form was not sent correctly")
    if str(payload.get("website") or "").strip():
        # Honeypot: a bot filled the hidden field. Say nothing different.
        log.info("rights-form honeypot hit for %s", slug)
        return _accepted(f"DSAR-{secrets.token_hex(5)}", email_sent=_mail_ready(),
                         prop=prop, cfg=cfg)
    if not _IP_LIMIT.hit(_digest(f"ip:{client_ip}"), cfg["requests_per_ip_per_hour"], moment):
        raise RateLimited("too many requests from your connection; try again later")
    if not check_challenge(str(payload.get("challenge_token") or ""),
                           payload.get("challenge_answer"), now=moment):
        raise ChallengeFailed("the answer to the sum was wrong or expired; try again")
    fields = _validate_submission(payload, prop, cfg)
    if not _EMAIL_LIMIT.hit(_digest(f"email:{fields['email']}"),
                            cfg["requests_per_email_per_day"], moment):
        raise RateLimited("too many requests for this email address today")
    from . import privacy_ops

    record = privacy_ops.open_dsar(
        fields["email"], rights_deadlines.TRACKER_KIND[fields["request_type"]],
        channel="web_form", opened_by=f"{ACTOR}:{prop['slug']}",
        jurisdiction=fields["jurisdiction"], source="public_form", status="unverified",
        received_at=moment, internal_target_days=int(cfg["internal_target_days"]),
        requester={
            "name": fields["name"], "relationship": fields["relationship"],
            "authorised_agent": fields["authorised_agent"],
            "message": fields["message"], "property": prop["slug"],
        },
    )
    verify_token = secrets.token_urlsafe(32)
    status_token = secrets.token_urlsafe(32)

    def attach(value: dict[str, Any]) -> bool:
        value["public_form"] = {
            "property": prop["slug"],
            "verify_sha256": _digest(verify_token),
            "verify_expires_at": moment + int(cfg["verification_ttl_hours"]) * 3600,
            "verify_used_at": None,
            "status_sha256": _digest(status_token),
            "status_expires_at": moment + int(cfg["status_ttl_days"]) * 86_400,
            "client_ip_sha256": _digest(str(client_ip or "")),
            "emails": [],
        }
        return True

    privacy_ops.annotate_dsar(record["id"], attach, action="public_form_tokens", actor=ACTOR)
    base = str(base_url or "").rstrip("/")
    notice = send_notice(record["id"], "verification", extra={
        "verify_link": f"{base}/rights/verify/{verify_token}",
        "status_link": f"{base}/rights/status/{status_token}",
    })
    return _accepted(str(record["id"]), email_sent=notice["sent"] is True, prop=prop, cfg=cfg)


# --------------------------------------------------------------------------- #
# Tokens: verification (single use) and status (long lived)
# --------------------------------------------------------------------------- #

_STATUS_LABELS = {
    "unverified": "Waiting for you to confirm your email address",
    "open": "Received and being worked on",
    "awaiting_erasure": "Being worked on",
    "fulfilled": "Answered",
    "closed": "Closed",
}


def public_view(record: Mapping[str, Any], *, now: float | None = None) -> dict[str, Any]:
    """What the requester may see: no operator names, no internal notes."""
    from . import privacy_ops

    clock = privacy_ops.dsar_clock(dict(record), now=now)
    kind = str(record.get("kind") or "")
    public_type = rights_deadlines.PUBLIC_TYPE.get(kind, kind)
    regime = rights_deadlines.REGIMES.get(str(record.get("jurisdiction") or ""))
    return {
        "reference": record.get("id"),
        "request_type": public_type,
        "request_type_label": REQUEST_TYPE_LABELS.get(public_type, public_type),
        "jurisdiction": record.get("jurisdiction"),
        "jurisdiction_name": regime["name"] if regime else "",
        "status": record.get("status"),
        "status_label": _STATUS_LABELS.get(str(record.get("status")), "In progress"),
        "verified": (record.get("verification") or {}).get("status") == "verified",
        "received_date": _date(record.get("received_at") or record.get("created_at")),
        "due_date": _date(clock["effective_due_at"]),
        "extended": bool(record.get("extended_until")),
        "acknowledged": bool(record.get("acknowledged_at")),
    }


def _find_by_digest(field: str, token: str) -> dict[str, Any] | None:
    from . import privacy_ops

    raw = str(token or "").strip()
    if not raw or len(raw) > 128:
        return None
    digest = _digest(raw)
    for row in privacy_ops.iter_dsar_records()[:_MAX_SCAN]:
        form = row.get("public_form") or {}
        if hmac.compare_digest(str(form.get(field) or ""), digest):
            return row
    return None


def verify(token: str, *, now: float | None = None) -> dict[str, Any] | None:
    """Consume a verification link: the request becomes ``open`` with
    ``email_challenge`` recorded as the method performed, the fulfillment
    record (when that module is on) gets the same fact, and the
    acknowledgement notice goes out. Unknown, expired and already-used
    tokens all return ``None``."""
    if not enabled():
        return None
    moment = time.time() if now is None else float(now)
    row = _find_by_digest("verify_sha256", token)
    if row is None:
        return None
    form = row.get("public_form") or {}
    if form.get("verify_used_at") or moment > float(form.get("verify_expires_at") or 0):
        return None
    from . import privacy_ops

    def burn(value: dict[str, Any]) -> bool:
        inner = dict(value.get("public_form") or {})
        if inner.get("verify_used_at"):
            return False
        inner["verify_used_at"] = moment
        value["public_form"] = inner
        return True

    # Verify first (a no-op when already verified), then burn: a failure while
    # recording the verification leaves the link usable instead of stranding an
    # unverified request behind a "link not valid" page.
    reference = f"opened the verification link sent to the address given ({_date(moment)})"
    saved = privacy_ops.verify_dsar(
        str(row["id"]), method="email_challenge", reference=reference, verified_by=ACTOR,
    )
    burned = privacy_ops.annotate_dsar(str(row["id"]), burn, action="verify_link", actor=ACTOR)
    if burned is None or (burned.get("public_form") or {}).get("verify_used_at") != moment:
        return None  # a racing use won; the link is single-use
    _record_fulfillment_identity(str(row["id"]), reference)
    try:
        send_notice(str(row["id"]), "acknowledgement")
    except Exception:  # noqa: BLE001 - the person is verified; the notice outcome is logged on the request
        log.warning("could not send the acknowledgement for %s", row["id"], exc_info=True)
    return public_view(saved or row, now=moment)


def _record_fulfillment_identity(request_id: str, reference: str) -> None:
    from . import dsar_fulfillment

    if not dsar_fulfillment.enabled():
        return
    try:
        record = dsar_fulfillment.open_fulfillment(request_id, actor=ACTOR)
        if (record.get("identity") or {}).get("status") != "verified":
            dsar_fulfillment.record_identity_verification(
                str(record["id"]), method="email_challenge", reference=reference,
                actor=ACTOR, expected_revision=int(record.get("revision") or 0),
            )
    except Exception:  # noqa: BLE001 - the tracker already holds the fact
        log.warning("could not mirror email verification into dsar_fulfillment for %s",
                    request_id)


def status(token: str, *, now: float | None = None) -> dict[str, Any] | None:
    """The requester's view of their request; ``None`` for unknown/expired."""
    if not enabled():
        return None
    moment = time.time() if now is None else float(now)
    row = _find_by_digest("status_sha256", token)
    if row is None:
        return None
    if moment > float((row.get("public_form") or {}).get("status_expires_at") or 0):
        return None
    return public_view(row, now=moment)


__all__ = [
    "ACTOR", "ChallengeFailed", "NOTICE_LABELS", "PublicRightsFormConfigError",
    "PublicRightsFormError", "RELATIONSHIPS", "REQUEST_TYPE_LABELS", "RateLimited",
    "SlidingWindowLimit", "check_challenge", "delete_property", "enabled",
    "form_definition", "get_config", "get_property", "list_properties",
    "new_challenge", "notice_log", "notice_problem", "public_view", "reset_limits",
    "send_notice",
    "set_mail_sender", "status", "submit", "upsert_property", "verify",
]
