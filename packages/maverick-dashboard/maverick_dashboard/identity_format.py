"""Human-friendly rendering of identities and roles for the dashboard UI.

Enterprise operators should never have to read a raw OIDC subject like
``user:auth0|000000000000000000000001`` or a lowercase role slug like
``operator`` in the interface. The identity provider only hands us an opaque
``sub`` for federated accounts (there is no email for a break-glass admin
pinned by ``sub``), so we cannot always show a real name -- but we can always
show *what kind of account it is* ("Google account", "Email & password
account") instead of the machine string, keep a short disambiguating tail, and
tuck the exact principal into a tooltip for the operator who still needs it
(matching the audit log, configuring the admin list).

Pure string formatting, no I/O. Exposed to templates as Jinja filters
(``identity``, ``role_label``) registered in :mod:`maverick_dashboard.app`.
"""
from __future__ import annotations

from dataclasses import dataclass

# Auth0 / OIDC connection prefixes -> the provider a person recognizes. The
# ``sub`` is ``<connection>|<id>``; the connection names are Auth0's strategy
# identifiers plus a few common OIDC ``iss``-derived ones.
_PROVIDERS = {
    "auth0": "Email & password",
    "email": "Email & password",
    "google-oauth2": "Google",
    "google-apps": "Google Workspace",
    "windowslive": "Microsoft",
    "microsoft": "Microsoft",
    "waad": "Microsoft Entra ID",
    "adfs": "Microsoft Entra ID",
    "samlp": "SAML single sign-on",
    "oidc": "Single sign-on",
    "github": "GitHub",
    "gitlab": "GitLab",
    "linkedin": "LinkedIn",
    "facebook": "Facebook",
    "apple": "Apple",
    "okta": "Okta",
    "sms": "Phone number",
}

# Principal kind prefixes (the part before the first colon).
_KINDS = {
    "user": "Person",
    "agent": "AI agent",
    "service": "Service account",
    "svc": "Service account",
}

# Built-in role slugs -> the label an operator reads. Unknown (custom) roles
# fall through to a generic title-casing so a "privacy-officer" role still reads
# as "Privacy officer".
_ROLE_LABELS = {
    "admin": "Administrator",
    "operator": "Operator",
    "auditor": "Auditor",
    "viewer": "Viewer",
}

# Permission atoms -> plain verbs, for the custom-role builder.
_PERMISSION_LABELS = {
    "admin": "Administer",
    "audit": "Review audit trail",
    "operate": "Run work",
    "view": "View",
}

# What each built-in role lets a person do. The same sentence is shown wherever
# a role is chosen (invite, role change, workspace member) and on the access
# check, so a role reads the same everywhere.
_ROLE_DESCRIPTIONS = {
    "admin": ("Runs Lightwork. Manages people and roles, settings, provider keys and "
              "secrets, plus everything an operator and an auditor can do."),
    "operator": ("Does the work. Starts and cancels tasks, approves or denies actions "
                 "waiting for a decision, and uses tools. Can't change settings or "
                 "manage people."),
    "auditor": ("Reviews the record. Reads the history of what happened and reports, "
                "and nothing else, so reviews stay independent."),
    "viewer": "Looks but doesn't touch. Sees dashboards and results.",
}

# Each permission atom as the power a person reads, most basic first.
POWERS = (
    ("view", "View work and results"),
    ("operate", "Run and change work, and decide approvals"),
    ("audit", "Read the activity record"),
    ("admin", "Manage people, settings and policy"),
)


def role_description(role: object, permissions=(), description: object = "") -> str:
    """One plain sentence for a built-in or custom role.

    A custom role reads as its administrator's own description (when given)
    followed by the powers its permission atoms grant, so even an undescribed
    role says what it allows."""
    slug = "" if role is None else str(role).strip()
    if slug in _ROLE_DESCRIPTIONS:
        return _ROLE_DESCRIPTIONS[slug]
    held = set(permissions or ())
    powers = [text.lower() for atom, text in POWERS if atom in held]
    if not powers:
        allows = "Allows nothing yet."
    elif len(powers) == 1:
        allows = f"Can {powers[0]}."
    else:
        allows = "Can " + ", ".join(powers[:-1]) + " and " + powers[-1] + "."
    own = " ".join(str(description or "").split()).rstrip(".")
    return f"{own}. {allows}" if own else allows


@dataclass(frozen=True)
class Identity:
    """A principal rendered for people. ``name`` is the human label, ``detail``
    a short disambiguating tail (or empty), ``raw`` the exact principal string
    for a tooltip / copy, ``kind`` the account-kind label."""

    name: str
    detail: str
    raw: str
    kind: str

    def __str__(self) -> str:  # so ``{{ p | identity }}`` alone is still safe
        return self.name


def _short(identifier: str) -> str:
    """A short, stable tail of an opaque id for disambiguation (never the whole
    thing -- that is the machine string we are hiding)."""
    identifier = identifier.strip()
    if len(identifier) <= 10:
        return identifier
    return "…" + identifier[-6:]


def humanize_principal(principal: object) -> Identity:
    """Turn a principal string into an :class:`Identity` for display.

    Accepts the ``kind:subject`` form the platform uses (``user:...``,
    ``agent:...``) as well as a bare subject. Never raises: anything
    unparseable renders as itself.
    """
    raw = "" if principal is None else str(principal).strip()
    if not raw:
        return Identity(name="Unknown", detail="", raw="", kind="")

    kind_prefix, sep, subject = raw.partition(":")
    if sep:
        kind = _KINDS.get(kind_prefix.lower(), kind_prefix.capitalize())
    else:
        kind, subject = "", raw

    subject = subject.strip()

    # An agent/service principal: the subject is already a chosen name.
    if kind_prefix.lower() in ("agent", "service", "svc"):
        return Identity(name=subject or kind, detail=kind, raw=raw, kind=kind)

    # Email-based subject (non-SSO invites store ``user:<email>``): show it.
    if "@" in subject and "|" not in subject:
        return Identity(name=subject, detail="Email", raw=raw, kind=kind or "Person")

    # Federated ``<connection>|<id>`` subject: show the provider + a short tail.
    if "|" in subject:
        connection, _, ident = subject.partition("|")
        provider = _PROVIDERS.get(connection.lower())
        if provider:
            return Identity(
                name=f"{provider} account", detail=_short(ident), raw=raw,
                kind=kind or "Person",
            )
        # Unknown connection: still avoid dumping the whole sub.
        pretty = connection.replace("-", " ").replace("_", " ").strip().capitalize()
        return Identity(
            name=f"{pretty or 'Federated'} account", detail=_short(ident), raw=raw,
            kind=kind or "Person",
        )

    # Loopback / local operator.
    if subject.lower() in ("local", "loopback", "localhost"):
        return Identity(name="Local operator", detail="", raw=raw, kind=kind or "Person")

    # A short, already-readable subject (or anything else): show it as-is.
    return Identity(name=subject or raw, detail="", raw=raw, kind=kind or "Person")


def role_label(role: object) -> str:
    """A built-in or custom role slug rendered as a readable label."""
    slug = "" if role is None else str(role).strip()
    if not slug:
        return ""
    if slug in _ROLE_LABELS:
        return _ROLE_LABELS[slug]
    return slug.replace("-", " ").replace("_", " ").strip().capitalize()


def permission_label(permission: object) -> str:
    """A permission atom (``operate``/``audit``/``admin``/``view``) as a verb."""
    slug = "" if permission is None else str(permission).strip()
    return _PERMISSION_LABELS.get(slug, slug.replace("-", " ").replace("_", " ").capitalize())


# Words a stored value spells in lowercase that a person reads differently.
# Kept in step with ``WORDS`` in static/lightwork-ui.js (mvHuman).
_WORDS = {
    "ai": "AI", "api": "API", "id": "ID", "ids": "IDs", "url": "URL", "sso": "SSO",
    "dsar": "DSAR", "gdpr": "GDPR", "ccpa": "CCPA", "hipaa": "HIPAA", "soc2": "SOC 2",
    "pii": "personal data", "sla": "SLA", "mfa": "MFA", "eu": "EU", "us": "US", "uk": "UK",
    "llm": "AI model", "mcp": "MCP", "sha256": "fingerprint", "csv": "CSV", "pdf": "PDF",
    "iso": "ISO", "nist": "NIST", "dpia": "DPIA", "ropa": "record of processing",
    "cmp": "consent banner", "ok": "OK",
}


def humanize(value: object) -> str:
    """A generic enum/slug (status, risk level, action, kind) rendered as a
    readable label: underscores/hyphens become spaces, the first letter is
    capitalized and known abbreviations read as a person writes them
    (``in_progress`` -> ``In progress``, ``ai_act`` -> ``AI act``). Empty in,
    empty out."""
    words = ("" if value is None else str(value)).replace("-", " ").replace("_", " ").split()
    if not words:
        return ""
    text = " ".join(_WORDS.get(word.lower(), word.lower()) for word in words)
    return text[0].upper() + text[1:]


__all__ = [
    "Identity",
    "POWERS",
    "humanize_principal",
    "role_label",
    "role_description",
    "permission_label",
    "humanize",
]
