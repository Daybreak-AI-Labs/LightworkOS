"""Reviewed Microsoft mail accounts; sealed renewal and one exact mail target."""
from __future__ import annotations

import hmac
import os
import re
import uuid
from contextlib import contextmanager

from . import config, connection_oauth, connections
from .paths import current_tenant_id_strict, tenant_scope

PROFILE = "microsoft-mail"
_EMAIL = re.compile(r"[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+")
_BINDING = ("oauth_account", "oauth_tenant", "oauth_principal")


def verified_identity(response, *, client_id, nonce=""):
    """Verify the ID token, never infer identity from Exchange access bytes."""
    from .oidc import OIDCConfig, _require_pyjwt, verify_oidc_token

    token = response.get("id_token") if isinstance(response, dict) else None
    if not isinstance(token, str) or not 1 <= len(token) <= 32768:
        raise ValueError("Microsoft did not confirm the signed account identity. Reconnect in Connections.")
    jwt_mod = _require_pyjwt()
    # Unverified tid selects only a UUID path on the fixed Microsoft host. The
    # signature, exact resulting issuer, audience and signed tid are checked next.
    raw = jwt_mod.decode(token, options={"verify_signature": False})
    tenant = raw.get("tid")
    if not isinstance(tenant, str) or not re.fullmatch(r"[0-9a-f-]{36}", tenant) or str(uuid.UUID(tenant)) != tenant:
        raise ValueError("Microsoft organization identity was not confirmed.")
    issuer = "https://login.microsoftonline.com/" + tenant + "/v2.0"
    keys = "https://login.microsoftonline.com/" + tenant + "/discovery/v2.0/keys"
    connection_oauth._network_allowed(keys)
    principal = verify_oidc_token(token, config=OIDCConfig(
        issuer=issuer, audience=client_id, jwks_uri=keys, algorithms=["RS256"]))
    claims = principal.claims
    if claims.get("tid") != tenant or claims.get("ver") != "2.0":
        raise ValueError("Microsoft organization identity was not confirmed.")
    # Every Microsoft consent carries a nonce; a request without one (or a
    # token without the matching one) cannot bind this sign-in to it.
    if (not isinstance(nonce, str) or not nonce or not isinstance(claims.get("nonce"), str)
            or not hmac.compare_digest(claims["nonce"], nonce)):
        raise ValueError("Microsoft sign-in did not match this account request. Start again.")
    email = connection_oauth._identity_text(claims.get("email") or claims.get("preferred_username"), maximum=320)
    if not _EMAIL.fullmatch(email):
        raise ValueError("Microsoft did not confirm a mailbox address. Reconnect with the mailbox account.")
    name = connection_oauth._identity_text(claims.get("name"), maximum=512)
    return {"provider": "microsoft", "subject": principal.sub, "tenant_id": tenant,
            "display_name": name or email, "email": email}


def _authority(tenant, actor):
    try:
        from maverick_dashboard import rbac, scim_groups
        from maverick_dashboard.auth import global_role_for_principal
    except ImportError:
        # Administrator access is checked through the dashboard; without it the
        # authority cannot be evaluated, so refuse rather than crash.
        raise PermissionError("Microsoft email requires the Lightwork dashboard to confirm "
                              "administrator access, and it is not installed.") from None

    from .tenant.registry import assert_tenant_active

    if not tenant or not isinstance(actor, str) or not actor.startswith("user:"):
        raise PermissionError("Choose a workspace and sign in with a named administrator to connect Microsoft email.")
    assert_tenant_active(tenant)
    if (current_tenant_id_strict() != tenant or not connection_oauth.enabled()
            or "admin" not in rbac.permissions_for(global_role_for_principal(actor))
            or scim_groups.active_for_principal(actor) is False):
        raise PermissionError("The Microsoft email owner's current administrator access is required. Review Channels.")


def _record(value, actor):
    if not isinstance(value, str) or value.count(":") != 1:
        raise ValueError("Choose a connected Microsoft email account.")
    name, revision = value.split(":")
    if not connections._NAME_RE.fullmatch(name) or not re.fullmatch(r"[a-f0-9]{32}", revision):
        raise ValueError("Choose a connected Microsoft email account.")
    record = connections.get_connection(name)
    if (not record or not record.get("token") or record.get("revision") != revision or record.get("owner") != actor
            or not connections._may_use(record, actor) or record.get("connector") != "microsoft_mail"
            or record.get("base_url") != "https://outlook.office.com"
            or (record.get("oauth") or {}).get("profile") != PROFILE):
        raise PermissionError("This Microsoft email account changed or is no longer yours. Reconnect and choose it again.")
    status = connection_oauth.public_status(record)
    if not status or status.get("available") is not True:
        raise PermissionError("Reconnect the Microsoft email account in Connections before using it.")
    return record


def choices(actor):
    """Only exact owned current mail accounts; no tokens or hidden grants."""
    tenant = current_tenant_id_strict()
    try:
        _authority(tenant, actor)
    except PermissionError:
        return []
    rows = []
    for record in connections.list_connections(owner=actor):
        if (record.get("oauth") or {}).get("profile") != PROFILE:
            continue
        value = record["name"] + ":" + record["revision"]
        try:
            current = _record(value, actor)
        except (PermissionError, ValueError):
            continue
        identity = current["oauth"]["identity"]
        rows.append({"value": value, "label": identity["email"] + " · " + current["name"],
                     "email": identity["email"]})
    return rows


def bind_account(value, *, actor):
    tenant = current_tenant_id_strict()
    _authority(tenant, actor)
    _record(value, actor)
    return {"oauth_account": value, "oauth_tenant": tenant, "oauth_principal": actor}


def configuration_problem(cfg):
    if cfg.get("email_auth", "password") != "microsoft":
        if (str(cfg.get("imap_host", "")).lower() == "outlook.office365.com"
                or str(cfg.get("smtp_host", "")).lower() == "smtp.office365.com"):
            return "Microsoft email needs account sign-in. Connect the mailbox in Connections, then choose it on Channels."
        return ""
    try:
        port = int(cfg.get("smtp_port") or 0)
    except (TypeError, ValueError):
        port = 0
    if (str(cfg.get("imap_host", "")).lower() != "outlook.office365.com"
            or str(cfg.get("smtp_host", "")).lower() != "smtp.office365.com"
            or port != 587):
        return "Microsoft account sign-in can be used only with the Microsoft mail servers shown on Channels."
    if not all(isinstance(cfg.get(key), str) and cfg[key] for key in _BINDING):
        return "Choose and save a connected Microsoft email account on Channels."
    incoming, outgoing = cfg.get("imap_user"), cfg.get("smtp_user")
    if (not isinstance(incoming, str) or not _EMAIL.fullmatch(incoming)
            or incoming != outgoing):
        return "Use the same full mailbox address for incoming and outgoing Microsoft email."
    return ""


@contextmanager
def credential(cfg):
    """Renew and recheck the exact current channel pin before physical login."""
    from .authority_effects import authority_effect_fence

    problem = configuration_problem(cfg)
    if problem or cfg.get("email_auth") != "microsoft":
        raise PermissionError(problem or "Microsoft email account sign-in is not selected.")
    tenant, actor = cfg["oauth_tenant"], cfg["oauth_principal"]
    with tenant_scope(tenant=tenant), authority_effect_fence():
        _authority(tenant, actor)
        _saved_configuration(cfg)
        record = _record(cfg["oauth_account"], actor)
        renewed = connection_oauth.renew(record, actor=actor)
        with connections._mutation_lock():
            _authority(tenant, actor)
            _saved_configuration(cfg)
            latest = _record(cfg["oauth_account"], actor)
            if latest.get("token") != renewed.get("token"):
                raise PermissionError("Microsoft email authorization changed before sign-in.")
            yield latest["token"]


def _saved_configuration(cfg):
    current = (config.load_global_config().get("channels") or {}).get("email") or {}
    keys = (*_BINDING, "email_auth", "imap_host", "smtp_host", "smtp_port", "imap_user", "smtp_user")
    # Resolve both sides the way the email channel does: an unsaved value
    # falls back to its environment variable.
    def people(value):
        if value is None:
            value = os.environ.get("EMAIL_ALLOWED_USER_IDS", "").split(",")
        if not isinstance(value, (list, tuple, set)):
            return None
        return {str(person).strip().lower() for person in value} - {""}
    def server(value):
        return str(value or os.environ.get("EMAIL_TRUSTED_AUTHSERV_ID", "")).strip()
    if (current.get("enabled") is not True or any(current.get(key) != cfg.get(key) for key in keys)
            or server(current.get("trusted_authserv_id")) != server(cfg.get("trusted_authserv_id"))
            or people(current.get("allowed_user_ids")) != people(cfg.get("allowed_user_ids"))):
        raise PermissionError("Microsoft email settings changed. Apply the current settings to the chat service.")


@contextmanager
def mail_effect(cfg):
    """Keep current mailbox authority through a read/admission or physical send."""
    if cfg.get("email_auth") != "microsoft":
        yield
        return
    from .authority_effects import authority_effect_fence

    tenant, actor = cfg["oauth_tenant"], cfg["oauth_principal"]
    with tenant_scope(tenant=tenant), authority_effect_fence(), connections._mutation_lock():
        _authority(tenant, actor)
        _saved_configuration(cfg)
        _record(cfg["oauth_account"], actor)
        yield


def authenticate_imap(inbox, cfg):
    if cfg.get("email_auth") != "microsoft":
        problem = configuration_problem(cfg)
        if problem:
            raise PermissionError(problem)
        return inbox.login(str(cfg.get("imap_user") or ""), str(cfg.get("imap_password") or ""))
    with credential(cfg) as token:
        payload = ("user=" + cfg["imap_user"] + "\x01auth=Bearer " + token + "\x01\x01").encode()
        sent = False

        def reply(_challenge):
            nonlocal sent
            if sent:
                return b""  # Finish a failed challenge without resending access bytes.
            sent = True
            return payload

        return inbox.authenticate("XOAUTH2", reply)


def authenticate_smtp(smtp, cfg):
    if cfg.get("email_auth") != "microsoft":
        problem = configuration_problem(cfg)
        if problem:
            raise PermissionError(problem)
        return smtp.login(str(cfg.get("smtp_user") or ""), str(cfg.get("smtp_password") or ""))
    with credential(cfg) as token:
        payload = "user=" + cfg["smtp_user"] + "\x01auth=Bearer " + token + "\x01\x01"
        # STARTTLS discards the server's EHLO answer; login() greets again on
        # its own, auth() does not.
        smtp.ehlo_or_helo_if_needed()
        return smtp.auth("XOAUTH2", lambda challenge=None: payload if challenge is None else "")
