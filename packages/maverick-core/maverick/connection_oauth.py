"""Renewable named connections with sealed app registrations and consent state.

The existing provider-wide OAuth vault remains a legacy automation contract.
These records belong to an exact named connection, owner, tenant and origin.
Refreshing access bytes preserves the reviewed connection generation; changing
credentials, app registration, sharing, provider or destination does not.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
import uuid
from urllib.parse import parse_qs, urlencode, urlsplit

from . import config, connections, oauth_providers
from .file_lock import (
    atomic_read_bytes,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .paths import current_tenant_id_strict, data_dir
from .tenant.kms import seal_text_for_tenant, unseal_text_for_tenant

PROFILES = {
    "google-drive": {
        "label": "Google Drive evidence", "provider": "google", "connector": "gdrive",
        "origin": "https://www.googleapis.com",
        "scopes": ["openid", "https://www.googleapis.com/auth/userinfo.profile",
                   "https://www.googleapis.com/auth/userinfo.email",
                   "https://www.googleapis.com/auth/drive.readonly"],
    },
    "google-cloud-storage": {
        "label": "Google Cloud Storage discovery", "provider": "google",
        "connector": "google_cloud_storage", "origin": "https://storage.googleapis.com",
        "scopes": ["openid", "https://www.googleapis.com/auth/userinfo.profile",
                   "https://www.googleapis.com/auth/userinfo.email",
                   "https://www.googleapis.com/auth/devstorage.read_only"],
    },
    "jira-cloud": {
        "label": "Jira Cloud reviewed delivery", "provider": "atlassian",
        "connector": "jira", "origin": "https://api.atlassian.com",
        "scopes": ["read:me", "read:jira-work", "write:jira-work", "offline_access"],
    },
    "microsoft-mail": {
        "label": "Microsoft 365 email", "provider": "microsoft", "connector": "microsoft_mail",
        "origin": "https://outlook.office.com",
        "scopes": ["openid", "profile", "email", "offline_access",
                   "https://outlook.office.com/IMAP.AccessAsUser.All",
                   "https://outlook.office.com/SMTP.Send"],
    },
}
_MAX_BYTES = 4 * 1024 * 1024
DESKTOP_CALLBACK = "http://127.0.0.1:8766/connections"
DESKTOP_PROFILE = "desktop-loopback-v1"
_NATIVE_TICKET_ENV = "MAVERICK_DESKTOP_OAUTH_TICKET_KEY"
_NATIVE_TICKET_SCHEMA = "lightwork.native-oauth-ticket.v1"
_NATIVE_TICKET_MAX = 8192
_PENDING_CONSENT_LIMIT = 32
_RETIRED_CONSENT_LIMIT = 64
_RETIRED_CONSENT_TTL = 24 * 60 * 60
_GOOGLE_SCOPE_ALIASES = {
    "email": "https://www.googleapis.com/auth/userinfo.email",
    "profile": "https://www.googleapis.com/auth/userinfo.profile",
}


def _digest(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def _native_ticket_key():
    raw = os.environ.get(_NATIVE_TICKET_ENV, "")
    if not re.fullmatch(r"[a-f0-9]{64}", raw):
        raise PermissionError("Desktop account return requires the dashboard started by this Lightwork app.")
    return bytes.fromhex(raw)


def desktop_instance_id():
    """Public, non-secret fingerprint for the dashboard child of this shell."""
    try:
        return hashlib.sha256(_native_ticket_key()).hexdigest()
    except PermissionError:
        return ""


def _sign_native_ticket(payload):
    key = _native_ticket_key()
    flat = {name: " ".join(value) if isinstance(value, list) else str(value) for name, value in payload.items()}
    body = urlencode(sorted(flat.items())).encode().hex()
    signature = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    return body + "." + signature


def _read_native_ticket(ticket, purpose):
    if not isinstance(ticket, str) or not 100 <= len(ticket) <= _NATIVE_TICKET_MAX or ticket.count(".") != 1:
        raise PermissionError("Desktop account-return authorization could not be verified.")
    body, signature = ticket.split(".")
    if not re.fullmatch(r"(?:[a-f0-9]{2})+", body) or not re.fullmatch(r"[a-f0-9]{64}", signature):
        raise PermissionError("Desktop account-return authorization could not be verified.")
    key = _native_ticket_key()
    expected = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise PermissionError("Desktop account-return authorization could not be verified.")
    try:
        raw = bytes.fromhex(body).decode("ascii")
        fields = parse_qs(raw, keep_blank_values=True, strict_parsing=True)
        if any(len(values) != 1 for values in fields.values()):
            raise ValueError
        flat = {name: values[0] for name, values in fields.items()}
        if urlencode(sorted(flat.items())) != raw:
            raise ValueError
        payload = dict(flat)
        payload["scopes"] = payload.get("scopes", "").split(" ") if payload.get("scopes") else []
        payload["issued_at"] = int(payload.get("issued_at", ""))
        payload["expires_at"] = int(payload.get("expires_at", ""))
    except Exception as exc:
        raise PermissionError("Desktop account-return authorization could not be verified.") from exc
    now = int(time.time())
    if (not isinstance(payload, dict) or payload.get("schema") != _NATIVE_TICKET_SCHEMA
            or payload.get("purpose") != purpose or payload.get("instance") != hashlib.sha256(key).hexdigest()
            or not isinstance(payload.get("issued_at"), int) or not isinstance(payload.get("expires_at"), int)
            or payload["issued_at"] > now + 5 or payload["expires_at"] <= now
            or payload["expires_at"] > payload["issued_at"] + 600
            or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", str(payload.get("jti", "")))):
        raise PermissionError("Desktop account-return authorization expired or could not be verified.")
    return payload


def _ticket_identity(actor, context):
    return {
        "instance": desktop_instance_id(),
        "tenant_sha256": _digest(current_tenant_id_strict()),
        "principal_sha256": _digest(actor),
        "context": context,
    }


def desktop_return_enabled():
    override = config.env_flag("MAVERICK_OAUTH_DESKTOP_RETURN")
    if override is None:
        override = config.env_flag("LIGHTWORK_OAUTH_DESKTOP_RETURN")
    loaded = config.load_global_config()
    return enabled() and (override if override is not None else (loaded.get("oauth") or {}).get("desktop_return") is True)


def enabled():
    override = config.env_flag("MAVERICK_OAUTH_VAULT")
    if override is None:
        override = config.env_flag("LIGHTWORK_OAUTH_VAULT")
    loaded = config.load_global_config()
    return connections.enabled() and not config.config_source_errors(include_tenant=True) and (override if override is not None else (loaded.get("oauth") or {}).get("vault") is True)


def _authority(actor):
    tenant = current_tenant_id_strict()
    if not tenant or not isinstance(actor, str) or not actor.startswith("user:") or not enabled():
        raise PermissionError("Named account authorization requires an enabled workspace connection vault.")
    return tenant


def _path():
    return data_dir("connections", "oauth-setup.sealed")


def _load():
    try:
        path = _path()
        # App registrations and connection credentials share one mutation
        # transaction. Use its same sidecar while verifying and reading setup,
        # including for metadata readers outside a mutation transaction.
        with cross_process_lock(connections._path(), strict=True):
            ensure_private_file(path)
            if path.stat().st_size > _MAX_BYTES:
                raise ValueError("setup exceeds its bound")
            raw = unseal_text_for_tenant(current_tenant_id_strict(), atomic_read_bytes(path))
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"applications", "consents"} or any(not isinstance(value[k], dict) for k in value):
            raise ValueError("invalid setup")
        return value
    except FileNotFoundError:
        return {"applications": {}, "consents": {}}
    except Exception as exc:
        raise connections.ConnectionStoreUnavailable("Account authorization setup is unavailable.") from exc


def _save(value):
    raw = json.dumps(value, sort_keys=True)
    if len(raw.encode()) > _MAX_BYTES - 4096:
        raise ValueError("Account authorization setup capacity reached.")
    ensure_private_directory(_path().parent)
    atomic_write_bytes(_path(), seal_text_for_tenant(current_tenant_id_strict(), raw), mode=0o600)


def _app_key(actor, provider):
    return hashlib.sha256(json.dumps([actor, provider]).encode()).hexdigest()


def _workspace_app_key(provider):
    # A distinct namespace in the existing tenant-sealed store. Owner keys
    # remain private legacy registrations and are never migrated implicitly.
    return "workspace:" + hashlib.sha256(provider.encode()).hexdigest()


def _bound_application(store, actor, provider, binding):
    key = binding.get("application_key", _app_key(actor, provider))
    if key not in (_app_key(actor, provider), _workspace_app_key(provider)):
        return None
    row = store["applications"].get(key)
    if not isinstance(row, dict) or row.get("provider") != provider:
        return None
    if key == _workspace_app_key(provider):
        if row.get("scope") != "workspace":
            return None
    elif row.get("owner") != actor or row.get("scope", "owner") != "owner":
        return None
    return row


def _selected_application(store, actor, provider):
    for key in (_workspace_app_key(provider), _app_key(actor, provider)):
        row = _bound_application(store, actor, provider, {"application_key": key})
        if row:
            return key, row
    return None, None


def applications(actor):
    """Legacy owner registrations; callers must authorize metadata access."""
    _authority(actor)
    value = _load()["applications"]
    return [{"provider": row["provider"], "client_id": row["client_id"], "revision": row["revision"], "has_secret": bool(row["client_secret"])} for row in value.values() if row.get("owner") == actor and row.get("scope", "owner") == "owner"]


def managed_applications(actor):
    """Workspace registration metadata for the authorized installation operator."""
    _authority(actor)
    store = _load()
    result = []
    for provider in ("google", "atlassian", "microsoft"):
        row = _bound_application(store, actor, provider, {"application_key": _workspace_app_key(provider)})
        if row:
            result.append({"provider": provider, "client_id": row["client_id"], "revision": row["revision"],
                "has_secret": bool(row["client_secret"]), "configured": True, "registration_scope": "workspace",
                **({"desktop_return": True} if row.get("desktop_return") is True else {})})
    return result


def available_applications(actor):
    """Customer availability without operator registration identifiers or secrets."""
    _authority(actor)
    store = _load()
    result = []
    for provider in ("google", "atlassian", "microsoft"):
        key, row = _selected_application(store, actor, provider)
        if row:
            result.append({"provider": provider, "configured": True,
                "registration_scope": "workspace" if key == _workspace_app_key(provider) else "legacy_owner",
                **({"desktop_return": True} if key == _workspace_app_key(provider) and row.get("desktop_return") is True else {})})
    return result


def save_application(actor, *, provider, client_id, client_secret, expected_revision):
    """Retain the owner-only registration contract for explicit legacy callers."""
    _save_application(actor, provider=provider, client_id=client_id, client_secret=client_secret,
        expected_revision=expected_revision, workspace=False)
    return applications(actor)


def save_workspace_application(actor, *, provider, client_id, client_secret, expected_revision, desktop_return=False):
    """Save operator-managed registration; the API enforces global admin authority."""
    _save_application(actor, provider=provider, client_id=client_id, client_secret=client_secret,
        expected_revision=expected_revision, workspace=True, desktop_return=desktop_return)
    return managed_applications(actor)


def _save_application(actor, *, provider, client_id, client_secret, expected_revision, workspace, desktop_return=False):
    _authority(actor)
    if not isinstance(desktop_return, bool) or desktop_return and (not workspace or not desktop_return_enabled()):
        raise PermissionError("Desktop account return is not enabled for this installation.")
    if provider not in {"google", "atlassian", "microsoft"}:
        raise ValueError("Select a supported account provider.")
    if not isinstance(client_id, str) or not 1 <= len(client_id) <= 1024 or any(ord(c) < 33 for c in client_id):
        raise ValueError("Enter the provider's application client ID.")
    if client_secret is not None and (not isinstance(client_secret, str) or not 1 <= len(client_secret) <= 4096 or any(ord(c) < 32 for c in client_secret)):
        raise ValueError("Enter the application's client secret, or leave it unchanged.")
    with connections._mutation_lock():
        store = _load()
        key = _workspace_app_key(provider) if workspace else _app_key(actor, provider)
        previous = store["applications"].get(key)
        if (previous or {}).get("revision", "") != expected_revision:
            raise connections.ConnectionVersionConflict("Application registration changed. Reload before saving.")
        secret = client_secret if client_secret is not None else (previous or {}).get("client_secret", "")
        if not secret:
            raise ValueError("This authorization flow requires the application's client secret.")
        if not previous and len(store["applications"]) >= 1000:
            raise ValueError("Application registration capacity reached.")
        store["applications"][key] = {"provider": provider, "owner": actor, "client_id": client_id,
            "client_secret": secret, "revision": uuid.uuid4().hex, "saved_at": time.time(),
            "scope": "workspace" if workspace else "owner", "desktop_return": desktop_return}
        _save(store)


def _network_allowed(url):
    from .enterprise import deployment_enterprise_enabled, enterprise_egress_denial
    loaded = config.load_global_config()
    if config.config_source_errors(include_tenant=True):
        raise PermissionError("Network policy is unavailable.")
    hosts = (loaded.get("enterprise") or {}).get("allowed_hosts") or []
    if deployment_enterprise_enabled() and urlsplit(url).hostname not in hosts:
        raise PermissionError("Deployment network policy blocks this authorization provider.")
    if enterprise_egress_denial(url, tool="connection_oauth"):
        raise PermissionError("Workspace network policy blocks this authorization provider.")


def _post_token(provider, payload):
    from .tools.oauth_helper import _post_form
    url = oauth_providers.get_provider(provider).token_url
    _network_allowed(url)
    # HTTPS, public-address pinning, no redirects, bounded response; the
    # surrounding application egress guard remains active as well.
    if provider != "atlassian":
        return _post_form(url, payload)
    from .tools._ssrf import safe_client
    chunks, size = [], 0
    with safe_client(url, timeout=30.0) as client:
        with client.stream("POST", url, json=payload, headers={"Accept": "application/json"}) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 100000:
                    raise ValueError("Provider authorization response exceeds its supported bound.")
                chunks.append(chunk)
    return json.loads(b"".join(chunks))


def _bearer_json(url, token, *, label):
    from .tools._ssrf import safe_client
    _network_allowed(url)
    chunks, size = [], 0
    with safe_client(url, timeout=30.0) as client:
        with client.stream("GET", url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"}) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 100000:
                    raise ValueError(f"{label} exceeds its supported bound.")
                chunks.append(chunk)
    return json.loads(b"".join(chunks))


def _jira_sites(token):
    return _bearer_json(
        "https://api.atlassian.com/oauth/token/accessible-resources", token,
        label="Authorized site list",
    )


def _identity_text(value, *, maximum, required=False):
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError("Provider account identity was incomplete.")
    result = value.strip()
    if (required and not result) or len(result) > maximum or any(
        ord(char) < 32 or ord(char) == 127 for char in result
    ):
        raise ValueError("Provider account identity was incomplete.")
    return result


def _provider_identity(provider, token, *, response=None, client_id="", nonce=""):
    if provider == "microsoft":
        from .microsoft_mail import verified_identity
        return verified_identity(response, client_id=client_id, nonce=nonce)
    if provider == "google":
        raw = _bearer_json(
            "https://openidconnect.googleapis.com/v1/userinfo", token,
            label="Provider account identity",
        )
        subject_field = "sub"
    elif provider == "atlassian":
        raw = _bearer_json(
            "https://api.atlassian.com/me", token,
            label="Provider account identity",
        )
        subject_field = "account_id"
    else:
        raise ValueError("Provider account identity is unsupported.")
    if not isinstance(raw, dict):
        raise ValueError("Provider account identity was incomplete.")
    subject = _identity_text(raw.get(subject_field), maximum=255, required=True)
    display_name = _identity_text(raw.get("name"), maximum=512)
    email = _identity_text(raw.get("email"), maximum=320)
    result = {"provider": provider, "subject": subject,
              "display_name": display_name or email or subject, "email": email}
    if provider == "google":
        result["email_verified"] = raw.get("email_verified") is True
        result["hosted_domain"] = _identity_text(raw.get("hd"), maximum=255)
    else:
        result["account_status"] = _identity_text(raw.get("account_status"), maximum=64)
    return result


def _stored_identity(value, provider):
    if not isinstance(value, dict) or value.get("provider") != provider:
        raise ValueError("Saved provider account identity is unavailable.")
    result = {
        "provider": provider,
        "subject": _identity_text(value.get("subject"), maximum=255, required=True),
        "display_name": _identity_text(value.get("display_name"), maximum=512, required=True),
        "email": _identity_text(value.get("email"), maximum=320),
    }
    if provider == "google":
        result["email_verified"] = value.get("email_verified") is True
        result["hosted_domain"] = _identity_text(value.get("hosted_domain"), maximum=255)
    elif provider == "microsoft":
        tenant = _identity_text(value.get("tenant_id"), maximum=36, required=True)
        if not re.fullmatch(r"[0-9a-f-]{36}", tenant) or str(uuid.UUID(tenant)) != tenant:
            raise ValueError("Saved Microsoft account identity is unavailable.")
        result["tenant_id"] = tenant
    else:
        result["account_status"] = _identity_text(value.get("account_status"), maximum=64)
    return result


def _normalize_scope(provider, value):
    if not isinstance(value, str) or not value or len(value) > 512 or any(
        ord(char) < 33 for char in value
    ):
        raise ValueError("Provider granted access was invalid.")
    if provider == "microsoft" and value in {"IMAP.AccessAsUser.All", "SMTP.Send"}:
        return "https://outlook.office.com/" + value
    return _GOOGLE_SCOPE_ALIASES.get(value, value) if provider == "google" else value


def _required_token_scopes(provider, requested):
    # Microsoft reports resource permissions on its access token. Identity is
    # verified separately from the signed ID token; refresh bytes prove renewal.
    return set(requested) - ({"openid", "profile", "email", "offline_access"}
                             if provider == "microsoft" else set())


def _scope_snapshot(provider, response, requested, *, prior=None):
    returned = response.get("scope")
    if returned is None:
        if provider == "microsoft" and prior is None:
            raise ValueError("Microsoft did not confirm the requested mailbox access. Reconnect in Connections.")
        if prior is not None:
            return list(prior), "preserved_on_refresh"
        return [], "provider_omitted"
    if not isinstance(returned, str) or len(returned) > 8192:
        raise ValueError("Provider granted access was invalid.")
    granted = sorted({_normalize_scope(provider, value) for value in returned.split()})
    required = {_normalize_scope(provider, value) for value in _required_token_scopes(provider, requested)}
    if not required <= set(granted):
        raise ValueError("Provider did not grant the requested access. Review consent and reconnect.")
    return granted, "token_response"


def _stored_scopes(provider, values):
    if not isinstance(values, list) or len(values) > 64:
        raise ValueError("Saved provider scope status is unavailable.")
    return sorted({_normalize_scope(provider, value) for value in values})


def _redirect_uri(value, return_profile="browser"):
    if return_profile != "browser":
        if return_profile != DESKTOP_PROFILE or value != DESKTOP_CALLBACK or not desktop_return_enabled():
            raise ValueError("Desktop authorization requires the enabled registered app return address.")
        return value
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path != "/connections"):
        raise ValueError("Authorization must return to this app's Connections page.")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Remote account authorization requires HTTPS.")
    return value


def _intent(profile, name, site_url):
    if profile not in PROFILES or not connections._NAME_RE.fullmatch(name):
        raise ValueError("Choose a supported account and connection name.")
    selected = PROFILES[profile]
    if profile == "jira-cloud":
        site = urlsplit(site_url)
        if (site.scheme != "https" or not site.hostname or not site.hostname.endswith(".atlassian.net")
                or site.username or site.password or site.port not in (None, 443)
                or site.path not in ("", "/") or site.query or site.fragment):
            raise ValueError("Enter the exact HTTPS address of the Jira Cloud site to authorize.")
        site_url = "https://" + site.hostname
    elif site_url:
        raise ValueError("A site address is needed only for Jira Cloud.")
    return selected, site_url


def _native_ticket_fields(actor, *, profile, selected, application, name, site_url,
                          expected_revision, context):
    return {
        **_ticket_identity(actor, context),
        "profile": profile,
        "provider": selected["provider"],
        "client_id_sha256": _digest(application["client_id"]),
        "callback_uri": DESKTOP_CALLBACK,
        "scopes": list(selected["scopes"]),
        "name_sha256": _digest(name),
        "site_url_sha256": _digest(site_url),
        "expected_revision_sha256": _digest(expected_revision),
    }


def native_prepare_ticket(actor, *, profile, name, context, expected_revision="", site_url=""):
    """Issue a short-lived preflight grant without creating a provider consent."""
    _authority(actor)
    if not desktop_return_enabled():
        raise PermissionError("Desktop account return is not enabled for this installation.")
    _native_ticket_key()
    selected, site_url = _intent(profile, name, site_url)
    _redirect_uri(DESKTOP_CALLBACK, DESKTOP_PROFILE)
    _network_allowed(oauth_providers.get_provider(selected["provider"]).token_url)
    with connections._mutation_lock():
        store = _load()
        application_key, application = _selected_application(store, actor, selected["provider"])
        if not application:
            raise ValueError("Ask your installation administrator to enable this account provider, then try again.")
        if application_key != _workspace_app_key(selected["provider"]) or application.get("desktop_return") is not True:
            raise PermissionError("Ask your installation administrator to register and confirm the desktop return address for this provider.")
        current = connections.get_connection(name)
        if current and current.get("owner") != actor:
            raise PermissionError("This connection name is already owned by another account.")
        if (current or {}).get("revision", "") != expected_revision:
            raise connections.ConnectionVersionConflict("Connection changed. Reload before authorizing.")
        now = int(time.time())
        payload = {
            "schema": _NATIVE_TICKET_SCHEMA,
            "purpose": "prepare",
            **_native_ticket_fields(actor, profile=profile, selected=selected, application=application,
                name=name, site_url=site_url, expected_revision=expected_revision, context=context),
            "jti": secrets.token_urlsafe(32),
            "issued_at": now,
            "expires_at": now + 600,
        }
    return {"prepare_ticket": _sign_native_ticket(payload), "expires_in": 600}


def _validated_prepare_ticket(actor, ticket, *, profile, selected, application, name,
                              site_url, expected_revision, context):
    payload = _read_native_ticket(ticket, "prepare")
    exact = {
        "schema": _NATIVE_TICKET_SCHEMA,
        "purpose": "prepare",
        **_native_ticket_fields(actor, profile=profile, selected=selected, application=application,
            name=name, site_url=site_url, expected_revision=expected_revision, context=context),
        "jti": payload.get("jti"),
        "issued_at": payload.get("issued_at"),
        "expires_at": payload.get("expires_at"),
    }
    if set(payload) != set(exact) or any(payload.get(key) != value for key, value in exact.items()):
        raise PermissionError("Desktop account-return authorization does not match this account connection.")
    return payload


def self_connect_profiles() -> frozenset[str]:
    """Administrator-approved fixed OAuth profiles; unavailable config fails closed."""
    if config.config_source_errors(include_tenant=True):
        return frozenset()
    settings = config.load_config().get("connections") or {}
    if settings.get("allow_self_connect") is not True:
        return frozenset()
    raw = settings.get("self_connect_profiles", "google-drive")
    if not isinstance(raw, str):
        return frozenset()
    return frozenset(item.strip() for item in raw.split(",") if item.strip() in PROFILES)


def _self_connect_allowed(profile):
    if profile not in self_connect_profiles():
        raise PermissionError("Your administrator no longer permits connecting this account profile.")


def begin(actor, *, profile, name, redirect_uri, context, expected_revision="", site_url="", return_profile="browser",
          native_handle="", prepare_ticket="", self_connect=False):
    _authority(actor)
    if self_connect:
        _self_connect_allowed(profile)
    selected, site_url = _intent(profile, name, site_url)
    redirect_uri = _redirect_uri(redirect_uri, return_profile)
    _network_allowed(oauth_providers.get_provider(selected["provider"]).token_url)
    with connections._mutation_lock():
        store = _load()
        application_key, application = _selected_application(store, actor, selected["provider"])
        if self_connect and application_key != _workspace_app_key(selected["provider"]):
            raise PermissionError("An administrator must approve the workspace application before you connect your own account.")
        if not application:
            raise ValueError("Ask your installation administrator to enable this account provider, then try again.")
        if return_profile == DESKTOP_PROFILE and (application_key != _workspace_app_key(selected["provider"]) or application.get("desktop_return") is not True):
            raise PermissionError("Ask your installation administrator to register and confirm the desktop return address for this provider.")
        current = connections.get_connection(name)
        if current and current.get("owner") != actor:
            raise PermissionError("This connection name is already owned by another account.")
        if self_connect and current and (current.get("access") != "owner" or current.get("allowed_principals")):
            raise PermissionError("An administrator must review reconnection of a shared account.")
        if (current or {}).get("revision", "") != expected_revision:
            raise connections.ConnectionVersionConflict("Connection changed. Reload before authorizing.")
        prepared = None
        if return_profile == DESKTOP_PROFILE:
            if not re.fullmatch(r"[a-f0-9]{64}", native_handle or ""):
                raise PermissionError("Desktop account-return receiver could not be verified.")
            prepared = _validated_prepare_ticket(actor, prepare_ticket, profile=profile, selected=selected,
                application=application, name=name, site_url=site_url,
                expected_revision=expected_revision, context=context)
        elif native_handle or prepare_ticket:
            raise ValueError("Native account-return fields require the desktop return profile.")
        state = secrets.token_urlsafe(32)
        key = hashlib.sha256(state.encode()).hexdigest()
        built, verifier = oauth_providers.build_authorize_url(selected["provider"], client_id=application["client_id"], redirect_uri=redirect_uri, state=state, scopes=selected["scopes"])
        nonce = secrets.token_urlsafe(32) if selected["provider"] == "microsoft" else ""
        if nonce:
            built += "&nonce=" + nonce
        # Retain only bounded, current pending consent. Consumed requests cannot
        # be retried after an uncertain token exchange.
        now = time.time()
        store["consents"] = {
            key: value for key, value in store["consents"].items()
            if value["expires_at"] > now
        }
        pending_count = sum(
            value.get("retired") is not True
            for value in store["consents"].values()
        )
        if pending_count >= _PENDING_CONSENT_LIMIT:
            raise ValueError("Too many account authorizations are pending. Wait ten minutes.")
        store["consents"][key] = {"owner": actor, "profile": profile, "name": name, "context": context, "self_connect": self_connect,
            "application_key": application_key, "application_revision": application["revision"], "expected_revision": expected_revision,
            "redirect_uri": redirect_uri, "return_profile": return_profile,
            "site_url": site_url, "verifier": verifier, "expires_at": now + 600,
            **({"nonce": nonce} if nonce else {}),
            **({"native_prepare_jti": prepared["jti"], "native_handle_sha256": _digest(native_handle)} if prepared else {})}
        launch_ticket = ""
        if prepared:
            fields = parse_qs(urlsplit(built).query, strict_parsing=True)
            challenge = fields.get("code_challenge", [""])
            if len(challenge) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", challenge[0]):
                raise ValueError("The provider PKCE request could not be verified.")
            issued_at = int(now)
            launch_ticket = _sign_native_ticket({
                "schema": _NATIVE_TICKET_SCHEMA,
                "purpose": "launch",
                **_native_ticket_fields(actor, profile=profile, selected=selected, application=application,
                    name=name, site_url=site_url, expected_revision=expected_revision, context=context),
                "consent_sha256": key,
                "state": state,
                "pkce_challenge": challenge[0],
                "authorize_url_sha256": _digest(built),
                "native_handle_sha256": _digest(native_handle),
                "prepare_ticket_sha256": _digest(prepare_ticket),
                "prepare_jti": prepared["jti"],
                "jti": secrets.token_urlsafe(32),
                "issued_at": issued_at,
                "expires_at": issued_at + 600,
            })
        _save(store)
    return {"authorize_url": built, "state": state, "expires_in": 600,
        **({"native_launch_ticket": launch_ticket} if launch_ticket else {})}


def _tokens(response, scopes, *, provider="", prior_refresh="", prior_granted=None):
    if not isinstance(response, dict):
        raise ValueError("Provider authorization response was incomplete.")
    if "token_type" in response and (not isinstance(response["token_type"], str) or response["token_type"].lower() != "bearer"):
        raise ValueError("Provider did not return a supported Bearer authorization.")
    access, refresh = response.get("access_token"), response.get("refresh_token") or prior_refresh
    if any(not isinstance(v, str) or not 1 <= len(v) <= 32768 or any(ord(c) < 32 for c in v) for v in (access, refresh)):
        raise ValueError("Provider did not supply renewable authorization. Reconnect with offline access.")
    seconds = response.get("expires_in")
    if isinstance(seconds, bool):
        raise ValueError("Provider authorization expiry was invalid.")
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        raise ValueError("Provider authorization expiry was absent.") from None
    if not math.isfinite(seconds) or not 60 < seconds <= 366 * 86400:
        raise ValueError("Provider authorization expiry was outside supported limits.")
    granted_scopes, scope_status = _scope_snapshot(
        provider, response, scopes, prior=prior_granted,
    )
    return access, refresh, time.time() + seconds, granted_scopes, scope_status


def finish(actor, *, state, code, context, redirect_uri, return_profile="browser"):
    _authority(actor)
    _redirect_uri(redirect_uri, return_profile)
    if (not isinstance(state, str) or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", state)
            or not isinstance(code, str) or not 1 <= len(code) <= 8192 or any(ord(c) < 32 for c in code)):
        raise ValueError("Authorization response was invalid.")
    key = hashlib.sha256(state.encode()).hexdigest()
    with connections._mutation_lock():
        store = _load()
        consent = store["consents"].get(key)
        if (not consent or consent.get("retired") is True
                or consent["owner"] != actor or consent["context"] != context
                or consent["redirect_uri"] != redirect_uri or consent.get("return_profile", "browser") != return_profile
                or consent["expires_at"] <= time.time()):
            raise PermissionError("Authorization expired or belongs to a different account or workspace. Start again.")
        if consent.get("self_connect"):
            _self_connect_allowed(consent["profile"])
        selected = PROFILES[consent["profile"]]
        application = _bound_application(store, actor, selected["provider"], consent)
        records = connections._load()
        previous = records.get(consent["name"])
        if (not application or application["revision"] != consent["application_revision"]
                or (previous or {}).get("revision", "") != consent["expected_revision"]
                or previous and previous.get("owner") != actor):
            raise connections.ConnectionVersionConflict("Connection or application changed during consent. Start again.")
        del store["consents"][key]
        _save(store)
        token_response = _post_token(selected["provider"], {"grant_type": "authorization_code", "client_id": application["client_id"], "client_secret": application["client_secret"], "code": code, "redirect_uri": redirect_uri, "code_verifier": consent["verifier"],
            **({"scope": " ".join(selected["scopes"])} if selected["provider"] == "microsoft" else {})})
        access, refresh, expires, granted_scopes, scope_status = _tokens(
            token_response, selected["scopes"], provider=selected["provider"],
        )
        identity = _provider_identity(selected["provider"], access, response=token_response,
            client_id=application["client_id"], nonce=consent.get("nonce", ""))
        prefix = ""
        workspace = {}
        if consent["profile"] == "jira-cloud":
            sites = _jira_sites(access)
            if not isinstance(sites, list):
                raise ValueError("Authorized Jira sites were unavailable.")
            matches = [row for row in sites if isinstance(row, dict) and str(row.get("url", "")).rstrip("/") == consent["site_url"]]
            if len(matches) != 1 or not re.fullmatch(r"[0-9a-fA-F-]{36}", str(matches[0].get("id", ""))):
                raise ValueError("Consent did not authorize the selected Jira site. No connection was saved.")
            resource_scopes = matches[0].get("scopes")
            if (not isinstance(resource_scopes, list) or any(not isinstance(value, str) for value in resource_scopes)
                    or not (set(selected["scopes"]) - {"offline_access", "read:me"}) <= set(resource_scopes)):
                raise ValueError("The selected Jira site did not grant the required read and write access.")
            cloud_id = str(uuid.UUID(matches[0]["id"]))
            prefix = "/ex/jira/" + cloud_id
            workspace = {"provider_id": cloud_id,
                         "name": _identity_text(matches[0].get("name"), maximum=512),
                         "url": consent["site_url"]}
        _authority(actor)
        if consent.get("self_connect"):
            _self_connect_allowed(consent["profile"])
        records[consent["name"]] = {"name": consent["name"], "connector": selected["connector"], "base_url": selected["origin"], "token": access,
            "created": (previous or {}).get("created", time.time()), "owner": actor,
            "access": (previous or {}).get("access", "owner"), "allowed_principals": (previous or {}).get("allowed_principals", []),
            "revision": uuid.uuid4().hex,
            "oauth": {"profile": consent["profile"], "self_connect": consent.get("self_connect", False), "application_key": consent.get("application_key", _app_key(actor, selected["provider"])),
                "application_revision": application["revision"], "refresh_token": refresh,
                "expires_at": expires, "refresh_state": "ready", "api_prefix": prefix,
                "site_url": consent["site_url"], "identity": identity,
                "workspace": workspace, "requested_scopes": list(selected["scopes"]),
                "granted_scopes": granted_scopes, "scope_status": scope_status}}
        connections._save(records)
        return connections._public(records[consent["name"]])


def cancel_consent(actor, *, state, context, redirect_uri, return_profile="browser"):
    """Idempotently retire the caller's exact consent; never change credentials."""
    _authority(actor)
    if not isinstance(state, str) or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", state):
        raise ValueError("Authorization cancellation could not be matched.")
    key = hashlib.sha256(state.encode()).hexdigest()
    with connections._mutation_lock():
        store = _load()
        consent = store["consents"].get(key)
        binding = (actor, context, redirect_uri, return_profile)
        if not consent or (
            consent.get("owner"), consent.get("context"), consent.get("redirect_uri"),
            consent.get("return_profile", "browser"),
        ) != binding:
            return False
        if consent.get("retired") is True:
            return True
        now = time.time()
        store["consents"][key] = {
            "owner": actor, "context": context, "redirect_uri": redirect_uri,
            "return_profile": return_profile, "retired": True,
            "retired_at": now, "expires_at": now + _RETIRED_CONSENT_TTL,
        }
        retired = sorted(
            (
                (retired_key, float(value.get("retired_at", 0)))
                for retired_key, value in store["consents"].items()
                if value.get("retired") is True
            ),
            key=lambda item: item[1],
        )
        for retired_key, _ in retired[:-_RETIRED_CONSENT_LIMIT]:
            del store["consents"][retired_key]
        _save(store)
        return True


def renew(record, *, actor):
    """Resolve refreshed bytes only after callers validated origin and grants."""
    if not record.get("oauth"):
        return record
    _authority(actor)
    # The record lock spans provider I/O, not the shared credential-store lock.
    # OS ownership releases on process death; persisted pending state does not.
    # A later caller must never replay a possibly consumed rotating token.
    target = connections._path().parent / ("refresh-" + _digest(record.get("name")))
    with cross_process_lock(target, strict=True):
        return _renew_owned(record, actor=actor)


def _refresh_binding(record):
    """Freeze credentials and authority, allowing only a concurrent test receipt."""
    return hashlib.sha256(json.dumps(
        {key: value for key, value in record.items() if key != "last_test"},
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


def _renew_owned(record, *, actor):
    with connections._mutation_lock():
        _authority(actor)
        records = connections._load()
        current = records.get(record["name"])
        if (not current or current.get("revision") != record.get("revision")
                or not connections._may_use(current, actor)):
            raise connections.ConnectionVersionConflict("Connection authority changed. Reload before continuing.")
        oauth = current.get("oauth") or {}
        if oauth.get("self_connect"):
            _self_connect_allowed(oauth.get("profile"))
        selected = PROFILES.get(oauth.get("profile"))
        if (not selected or current.get("connector") != selected["connector"] or current.get("base_url") != selected["origin"]):
            raise PermissionError("Renewable connection destination does not match its authorization.")
        try:
            prior_identity = _stored_identity(oauth.get("identity"), selected["provider"])
            prior_granted = _stored_scopes(selected["provider"], oauth.get("granted_scopes"))
            if oauth.get("requested_scopes") != selected["scopes"]:
                raise ValueError
        except ValueError as exc:
            raise PermissionError(
                "Account identity or access status is unavailable. Reconnect in Connections."
            ) from exc
        application = _bound_application(_load(), current["owner"], selected["provider"], oauth)
        if not application or application["revision"] != oauth.get("application_revision"):
            raise connections.ConnectionVersionConflict("App registration changed. Reconnect this account in Connections.")
        if oauth.get("refresh_state") != "ready":
            raise PermissionError("Account renewal was interrupted. Reconnect in Connections before continuing.")
        if float(oauth.get("expires_at", 0)) > time.time() + 60:
            return dict(current)
        _network_allowed(oauth_providers.get_provider(selected["provider"]).token_url)
        # A crash/lost reply during rotating-token exchange is ambiguous. Mark
        # before sending and refuse automatic replay of the old refresh token.
        oauth["refresh_state"] = "pending"
        oauth["refresh_lease"] = uuid.uuid4().hex
        frozen = _refresh_binding(current)
        app_binding = _refresh_binding(application)
        connections._save(records)
    try:
        result = _post_token(selected["provider"], {"grant_type": "refresh_token", "client_id": application["client_id"], "client_secret": application["client_secret"], "refresh_token": oauth["refresh_token"],
            **({"scope": " ".join(selected["scopes"])} if selected["provider"] == "microsoft" else {})})
        access, refresh, expires, granted_scopes, scope_status = _tokens(
            result, selected["scopes"], provider=selected["provider"],
            prior_refresh=oauth["refresh_token"], prior_granted=prior_granted,
        )
        identity = _provider_identity(selected["provider"], access, response=result, client_id=application["client_id"])
        if (identity["subject"] != prior_identity["subject"]
                or identity.get("tenant_id") != prior_identity.get("tenant_id")):
            raise PermissionError(
                "The provider returned a different account. Reconnect in Connections."
            )
        workspace = oauth.get("workspace") or {}
        if selected["provider"] == "atlassian":
            sites = _jira_sites(access)
            if not isinstance(sites, list):
                raise ValueError("Authorized Jira sites were unavailable.")
            matches = [row for row in sites if isinstance(row, dict)
                       and str(row.get("url", "")).rstrip("/") == oauth.get("site_url")
                       and str(row.get("id", "")) == workspace.get("provider_id")]
            required = set(selected["scopes"]) - {"offline_access", "read:me"}
            if (len(matches) != 1 or not isinstance(matches[0].get("scopes"), list)
                    or not required <= set(matches[0]["scopes"])):
                raise PermissionError(
                    "Jira site access changed. Reconnect in Connections."
                )
            workspace = dict(workspace)
            workspace["name"] = _identity_text(matches[0].get("name"), maximum=512)
        with connections._mutation_lock():
            _authority(actor)
            records = connections._load()
            latest = records.get(record["name"])
            if (not latest or not connections._may_use(latest, actor)
                    or _refresh_binding(latest) != frozen):
                raise connections.ConnectionVersionConflict("Connection changed during renewal.")
            bound_app = _bound_application(_load(), latest["owner"], selected["provider"], latest["oauth"])
            if not bound_app or _refresh_binding(bound_app) != app_binding:
                raise connections.ConnectionVersionConflict("App registration changed during renewal.")
            if latest["oauth"].get("self_connect"):
                _self_connect_allowed(latest["oauth"].get("profile"))
            latest["token"] = access
            latest["oauth"].update(refresh_token=refresh, expires_at=expires, refresh_state="ready",
                                   identity=identity, workspace=workspace,
                                   granted_scopes=granted_scopes, scope_status=scope_status)
            latest["oauth"].pop("refresh_lease", None)
            connections._save(records)
            return dict(latest)
    except Exception as exc:
        raise PermissionError("Account renewal could not be confirmed. Reconnect in Connections before continuing.") from exc


def public_status(record):
    value = record.get("oauth")
    if not isinstance(value, dict):
        return None
    state = value.get("refresh_state")
    action = "" if state == "ready" else "Reconnect this account in Connections before continuing."
    identity = None
    requested_scopes = []
    granted_scopes = []
    scope_status = "unavailable"
    workspace = {}
    provider = ""
    try:
        selected = PROFILES.get(value.get("profile"))
        if not enabled() or not current_tenant_id_strict():
            state, action = "unavailable", "Ask your administrator to check saved account authorization settings."
        elif (not selected or record.get("connector") != selected["connector"]
                or record.get("base_url") != selected["origin"]):
            state, action = "reconnect_required", "Reconnect this account in Connections before continuing."
        else:
            provider = selected["provider"]
            identity = _stored_identity(value.get("identity"), provider)
            requested_scopes = _stored_scopes(provider, value.get("requested_scopes"))
            granted_scopes = _stored_scopes(provider, value.get("granted_scopes"))
            scope_status = value.get("scope_status")
            if (requested_scopes != sorted(selected["scopes"])
                    or scope_status not in {"token_response", "provider_omitted", "preserved_on_refresh"}
                    or scope_status == "token_response" and not _required_token_scopes(provider, requested_scopes) <= set(granted_scopes)):
                raise ValueError("Saved provider scope status changed")
            if provider == "atlassian":
                stored_workspace = value.get("workspace")
                if (not isinstance(stored_workspace, dict)
                        or not re.fullmatch(r"[0-9a-f-]{36}", str(stored_workspace.get("provider_id", "")))
                        or stored_workspace.get("url") != value.get("site_url")):
                    raise ValueError("Saved Jira workspace identity changed")
                workspace = {"provider_id": str(uuid.UUID(stored_workspace["provider_id"])),
                             "name": _identity_text(stored_workspace.get("name"), maximum=512),
                             "url": value.get("site_url", "")}
            application = _bound_application(_load(), record.get("owner"), selected["provider"], value)
            if not application or application.get("revision") != value.get("application_revision"):
                state, action = "reconnect_required", "Reconnect this account in Connections; its application registration changed."
    except Exception:
        state, action = "unavailable", "Ask your administrator to restore account authorization settings, then reconnect."
    return {"profile": value.get("profile"), "expires_at": value.get("expires_at"),
        "renewal_state": state, "available": state == "ready", "recovery_action": action,
        "site_url": value.get("site_url", ""), "provider": provider,
        "identity": identity, "workspace": workspace,
        "requested_scopes": requested_scopes, "granted_scopes": granted_scopes,
        "scope_status": scope_status}
