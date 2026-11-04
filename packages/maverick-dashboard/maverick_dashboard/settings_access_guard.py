"""Lock-out guard for sign-in, administrator and key settings.

Settings > All settings can change how people sign in, who is an
administrator, and which key service unlocks stored data. A careless change
there can lock everyone out -- including the administrator making it -- or
leave saved records unreadable. Before such a save is written this module:

* works out how the person saving is signed in right now (the server's
  access token, a company sign-in session, an invitation session, the
  company proxy, or this computer without sign-in);
* evaluates the settings as they would be after the save (the same layers
  and precedence the kernel uses, environment still winning);
* refuses the save with one plain sentence when that person would lose their
  way in or their administrator role and no working replacement is proven,
  or when Lightwork would refuse to start;
* otherwise asks for confirmation (the page shows the sentence) whenever the
  person will be signed out or must sign in a new way. A provider connection
  check is not proof that a person can sign in again.

The server's access token set in the environment is the break-glass way in:
a person using it can never be locked out by a change here, because nothing
on this page can change it.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

SIGN_IN_PREFIXES = ("auth.",)
SIGN_IN_IDS = frozenset({
    "dashboard.token", "dashboard.invites", "dashboard.require_auth", "dashboard.admins",
    "dashboard.default_role", "dashboard.session_secret", "dashboard.group_roles",
    "client.enforce", "enterprise.mode", "profile.name",
})
KEY_PREFIXES = ("kms.",)
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class Refused(Exception):
    """A change the guard will not write, with the sentence the page shows."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


# ------------------------------------------------------------ after the save
def _deep_merge(base: dict, overlay: dict) -> dict:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def merged_config(layers: dict[str, Any], writes: dict | None = None) -> dict:
    """The configuration the kernel reads once ``writes`` land in the overlay."""
    here = copy.deepcopy(layers.get("here") or {})
    for path, value in (writes or {}).items():
        node = here
        for part in path[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        if value is None:
            node.pop(path[-1], None)
        else:
            node[path[-1]] = value
    from maverick.config_resets import merge_dashboard
    cfg = merge_dashboard(layers.get("base") or {}, here, _deep_merge)
    return _deep_merge(cfg, layers.get("operator") or {})


def _env_flag(*names: str) -> bool | None:
    for name in names:
        raw = os.environ.get(name, "").strip().lower()
        if raw in _TRUE:
            return True
        if raw in _FALSE:
            return False
        if raw:
            return True  # an unreadable security switch counts as on
    return None


def _table(cfg: dict, *path: str) -> dict:
    node: object = cfg
    for part in path:
        node = node.get(part) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else {}


def _text(env: str, table: dict, key: str) -> str:
    return (os.environ.get(env, "") or str(table.get(key) or "")).strip()


def _secret(env: str, table: dict, key: str) -> str:
    try:
        from maverick.secret_provider import get_secret

        value = get_secret(env) or ""
    except Exception:
        value = os.environ.get(env, "")
    return (value or str(table.get(key) or "")).strip()


@dataclass(frozen=True)
class Access:
    """Every way into the dashboard, as one configuration would allow it."""

    token_env: bool  # the server's access token (environment or these settings)
    token_value: str
    oidc: bool
    oidc_login: bool
    oidc_secret: str
    oidc_issuer: str
    saml_policy: bool
    saml_login: bool
    proxy: bool
    proxy_header: str
    proxy_table: dict
    invites: bool
    local_owner_login_open: bool
    invite_secret: str
    auth_policy_fingerprint: str
    require_auth: bool
    client_enforced: bool
    claimed: bool
    admins: frozenset[str]
    default_role: str
    group_roles: dict

    @property
    def anonymous_ok(self) -> bool:
        """This computer may use the dashboard without signing in."""
        return not (self.token_env or self.require_auth or self.oidc or self.proxy
                    or self.invites or self.saml_policy or self.claimed
                    or self.client_enforced)

    @property
    def any_method(self) -> bool:
        """Lightwork's own start-up check for "require sign-in" passes."""
        return (self.token_env or self.oidc or self.proxy or self.invites
                or (self.saml_login and bool(self.oidc_secret)))


def _oidc(cfg: dict) -> dict:
    table = _table(cfg, "auth", "oidc")
    flag = _env_flag("MAVERICK_OIDC_ENABLED")
    enabled = flag if flag is not None else bool(table.get("enabled", False))
    issuer = _text("MAVERICK_OIDC_ISSUER", table, "issuer")
    client_id = _text("MAVERICK_OIDC_CLIENT_ID", table, "client_id")
    secret = _secret("MAVERICK_OIDC_SESSION_SECRET", table, "session_secret")
    client_secret = _secret("MAVERICK_OIDC_CLIENT_SECRET", table, "client_secret")
    redirect_uri = _text("MAVERICK_OIDC_REDIRECT_URI", table, "redirect_uri")
    audience = _text("MAVERICK_OIDC_AUDIENCE", table, "audience")
    return {"enabled": enabled, "issuer": issuer, "secret": secret,
            "login": bool(enabled and client_id and client_secret and redirect_uri
                          and audience and secret and issuer)}


def _saml(cfg: dict, oidc_secret: str) -> tuple[bool, bool]:
    auth = cfg.get("auth") if isinstance(cfg.get("auth"), dict) else {}
    raw = auth.get("saml") if isinstance(auth, dict) else None
    if isinstance(raw, dict) and raw.get("enabled") is False:
        return False, False
    policy = bool(raw) if isinstance(raw, dict) else raw is not None
    table = raw if isinstance(raw, dict) else {}
    login = bool(str(table.get("sp_entity_id") or "").strip()
                 and str(table.get("acs_url") or "").strip()
                 and (str(table.get("idp_metadata_url") or "").strip()
                      or str(table.get("idp_metadata_file") or "").strip())
                 and oidc_secret)
    return policy, login


def _admins(cfg: dict) -> frozenset[str]:
    env = (os.environ.get("MAVERICK_DASHBOARD_ADMINS") or "").strip()
    if env:
        return frozenset(a.strip() for a in env.split(",") if a.strip())
    raw = _table(cfg, "dashboard").get("admins") or []
    if isinstance(raw, str):
        raw = [raw]
    return frozenset(str(a).strip() for a in raw if str(a).strip()) \
        if isinstance(raw, (list, tuple)) else frozenset()


def _token(cfg: dict) -> str:
    env = os.environ.get("MAVERICK_DASHBOARD_TOKEN", "")
    if env:
        return env
    value = _table(cfg, "dashboard").get("token")
    return value.strip() if isinstance(value, str) else ""


def _client_enforced(cfg: dict) -> bool:
    flag = _env_flag("MAVERICK_CLIENT_ENFORCE")
    if flag is not None:
        return flag
    try:
        from maverick.enterprise import deployment_enterprise_enabled

        if deployment_enterprise_enabled(config=cfg, source_errors=()):
            return True
    except Exception:
        return True
    return _table(cfg, "client").get("enforce") is True


def access_for(cfg: dict) -> Access:
    """Evaluate every way in for one configuration (environment wins)."""
    from . import local_owner

    dashboard = _table(cfg, "dashboard")
    oidc = _oidc(cfg)
    saml_policy, saml_login = _saml(cfg, oidc["secret"])
    proxy_table = _table(cfg, "auth", "proxy")
    proxy_flag = _env_flag("MAVERICK_PROXY_AUTH")
    claimed = bool(local_owner.claimed())
    invites_flag = _env_flag("MAVERICK_DASHBOARD_INVITES", "LIGHTWORK_DASHBOARD_INVITES")
    if invites_flag is None:
        invites_flag = dashboard["invites"] is True if "invites" in dashboard else claimed
    require = _env_flag("MAVERICK_DASHBOARD_REQUIRE_AUTH")
    if require is None:
        raw = dashboard.get("require_auth", False)
        require = raw if isinstance(raw, bool) else True
    return Access(
        token_env=bool(_token(cfg)), token_value=_token(cfg),
        oidc=oidc["enabled"], oidc_login=oidc["login"], oidc_secret=oidc["secret"],
        oidc_issuer=oidc["issuer"], saml_policy=saml_policy, saml_login=saml_login,
        proxy=proxy_flag if proxy_flag is not None else proxy_table.get("enabled") is True,
        proxy_header=(os.environ.get("MAVERICK_PROXY_AUTH_HEADER")
                      or str(proxy_table.get("header") or "") or "X-Forwarded-User").strip(),
        proxy_table=proxy_table, invites=bool(invites_flag),
        local_owner_login_open=local_owner.sign_in_available_for(cfg),
        invite_secret=_secret("MAVERICK_DASHBOARD_SESSION_SECRET", dashboard, "session_secret"),
        auth_policy_fingerprint=hashlib.sha256(
            json.dumps(cfg.get("auth"), sort_keys=True, default=str).encode("utf-8")
        ).hexdigest(),
        require_auth=bool(require), client_enforced=_client_enforced(cfg), claimed=claimed,
        admins=_admins(cfg), default_role=str(dashboard.get("default_role") or "viewer"),
        group_roles={str(k).strip().casefold(): str(v).strip().lower()
                     for k, v in (dashboard.get("group_roles") or {}).items()
                     if isinstance(v, str)} if isinstance(dashboard.get("group_roles"), dict)
        else {},
    )


# ----------------------------------------------------------------- the caller
def caller_route(request) -> tuple[str, str | None]:
    """``(route, principal)``: how the person saving got in right now."""
    from . import auth

    try:
        if auth._dashboard_token_authenticated(request):
            return "token", None
    except Exception:
        pass
    principal = getattr(getattr(request, "state", None), "principal", None)
    if principal is None:
        return "local", None
    via = str((getattr(principal, "claims", None) or {}).get("via") or "bearer")
    name = str(getattr(principal, "principal", "") or "")
    return via, name or None


def _proxy_trusts(table: dict, host: str) -> bool:
    import ipaddress

    from maverick import proxy_auth

    trusted = table.get("trusted_proxies")
    if isinstance(trusted, (list, tuple)) and trusted:
        peer = proxy_auth._normalized_peer(host)
        if peer is None:
            return False
        return any(peer in net for net in proxy_auth._parse_trusted_networks(trusted))
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    return table.get("trust_loopback") is True and loopback


def _route_survives(route: str, request, before: Access, after: Access) -> bool:
    if route == "token":
        # The environment's token can't be changed here; a token set on this
        # page keeps working only if it is still the one the caller sent.
        if os.environ.get("MAVERICK_DASHBOARD_TOKEN"):
            return True
        import hmac

        authorization = request.headers.get("authorization", "") if request else ""
        supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
        return bool(supplied and after.token_value) and hmac.compare_digest(
            supplied.encode(), after.token_value.encode())
    if route == "local":
        return after.anonymous_ok
    if route == "proxy":
        host = request.client.host if getattr(request, "client", None) else ""
        return (after.proxy and bool(request.headers.get(after.proxy_header))
                and _proxy_trusts(after.proxy_table, host))
    if route == "invite":
        # Existing local sessions are not a recovery path when the owner
        # passphrase route would refuse the next sign-in.
        return (after.invites and after.local_owner_login_open and not after.oidc_login
                and after.invite_secret == before.invite_secret)
    if route == "session":
        return ((after.oidc_login or after.saml_login)
                and after.oidc_secret == before.oidc_secret
                and after.auth_policy_fingerprint == before.auth_policy_fingerprint)
    # A sign-in token presented by a program.
    return (after.oidc and after.oidc_issuer == before.oidc_issuer
            and after.auth_policy_fingerprint == before.auth_policy_fingerprint)


def _owner_can_return(request, principal: str | None, after_cfg: dict, after: Access) -> bool:
    """The person is this computer's owner and can sign in again with the
    owner passphrase after the save (owner sign-in works only on this
    computer, with invitations on and no other sign-in set up)."""
    if not principal or not _is_this_computer(request) or after.token_env:
        return False
    if not _owner_sign_in_open(after_cfg) or not after.invites \
            or after.oidc or after.proxy or after.saml_policy:
        return False
    return _is_owner(principal)


def _is_admin_role(role: str | None) -> bool:
    from . import rbac

    try:
        return "admin" in rbac.permissions_for(role)
    except Exception:
        return False


def _stays_admin(principal: str, after: Access) -> bool:
    """The person keeps an installation-wide administrator role after the save."""
    if principal in after.admins:
        return True
    from . import rbac, scim_groups

    try:
        stored = rbac.get_stored_role(principal)
        if stored:
            return _is_admin_role(stored)
        names = scim_groups.group_names_for_principal(principal)
        mapped = {after.group_roles[n.casefold()] for n in names
                  if n.casefold() in after.group_roles}
        if mapped:
            return _is_admin_role(rbac.most_privileged(mapped))
    except Exception:
        return False
    return _is_admin_role(after.default_role)


def _someone_is_admin(after: Access) -> bool:
    if after.admins:
        return True
    from . import rbac

    try:
        return any(_is_admin_role(rbac.get_stored_role(p)) for p in rbac.list_users())
    except Exception:
        return False


# ------------------------------------------------------------------- review
def _proven_sign_in(after: Access, values: dict) -> tuple[bool, str]:
    """Provider checks cannot prove that a human can sign in after this save."""
    from . import settings_tests

    failure = ""
    if after.oidc_login:
        outcome = settings_tests.check_oidc_login(values)
        failure = ("Provider details are reachable, but no person has completed a sign-in "
                   "through this configuration yet." if outcome.ok else outcome.message)
    if after.saml_login:
        outcome = settings_tests.check_saml_login(values)
        failure = failure or ("Provider metadata is reachable, but no person has completed a "
                              "sign-in through this configuration yet." if outcome.ok else outcome.message)
    return False, failure


def _unproven_message(route: str, after: Access, failure: str) -> str:
    if failure:
        return (f"{failure} This change would lock you out before a verified sign-in or "
                "recovery route is available, so nothing was changed.")
    if route == "token":
        return ("This change would stop the access token you are using from working, and you "
                "would have no other working way back in. Set up and test a sign-in method "
                "first.")
    if route != "local":
        return ("This change would sign you out, and you would have no working way back in. "
                "Set up and test another sign-in method first, or make this change on the "
                "computer Lightwork runs on.")
    if after.proxy and not (after.oidc or after.saml_policy):
        return ("Lightwork can't check sign-in through your company proxy from this session. "
                "Sign in another way first (for example with this computer's owner account), "
                "then turn this on.")
    if after.invites and not (after.oidc or after.saml_policy or after.proxy):
        return ("Invitations need someone who can already sign in. Set up this computer's "
                "owner account first, then turn on invitations.")
    if after.oidc or after.saml_policy:
        return ("Your company sign-in isn't fully set up yet, so this change would lock you "
                "out. Fill in its details and use Test connection first.")
    return ("Nobody can sign in to Lightwork yet, so this would lock you out. Set up and test "
            "a sign-in method first, then change this.")


def _way_back(request, route: str, principal: str | None, after_cfg: dict, after: Access,
              values: dict) -> str:
    """How the person gets back in once their current way in ends ("" = none)."""
    if route != "local" and after.anonymous_ok and _is_this_computer(request):
        return ("You will be signed out. On this computer Lightwork will open again without "
                "sign-in.")
    if _owner_can_return(request, principal, after_cfg, after):
        return ("You will be signed out and will need to sign in again with the owner "
                "account's email and passphrase.")
    from .company_signin_migration import guarded_transition

    migration = guarded_transition(request, after_cfg)
    if migration:
        return migration
    proven, failure = _proven_sign_in(after, values)
    if proven:
        if not (principal and _stays_admin(principal, after)) and not _someone_is_admin(after):
            raise Refused("After this change nobody would be an administrator. Add yourself to "
                          "the administrators list first.")
        return ("You will be signed out of Lightwork and will need to sign in again with your "
                "company sign-in. Make sure you are on the administrators list.")
    raise Refused(_unproven_message(route, after, failure))


def review_sign_in(request, changes: list[dict], layers: dict[str, Any], writes: dict,
                   prospective: dict[str, object]) -> list[dict]:
    """Confirmations a sign-in change needs; raises :class:`Refused` when unsafe."""
    touched = [c["setting"] for c in changes
               if c["setting"].id in SIGN_IN_IDS or c["setting"].id.startswith(SIGN_IN_PREFIXES)]
    if not touched:
        return []
    before_cfg, after_cfg = merged_config(layers), merged_config(layers, writes)
    before, after = access_for(before_cfg), access_for(after_cfg)
    if after.require_auth and not after.any_method:
        raise Refused("With sign-in required, Lightwork would refuse to start, because no way "
                      "to sign in is set up. Set up a sign-in method first.")
    route, principal = caller_route(request)
    confirms: list[dict] = []
    if not _route_survives(route, request, before, after):
        warning = _way_back(request, route, principal, after_cfg, after, prospective)
        confirms.append({"id": touched[0].id, "label": "Your access", "kind": "access",
                         "warning": warning})
    elif route == "invite" and _is_owner(principal) and _owner_sign_in_open(before_cfg) \
            and not _owner_sign_in_open(after_cfg):
        # Still signed in, but the owner's passphrase sign-in pauses while any
        # company sign-in details are saved: say so before it matters.
        confirms.append({
            "id": touched[0].id, "label": "Your access", "kind": "access",
            "warning": ("Signing in with the owner account's email and passphrase is paused "
                        "while company sign-in details or a server access token are saved. Stay "
                        "signed in until the new way in works, or remove them to use the "
                        "passphrase again."),
        })
    if principal and route != "token" and not _stays_admin(principal, after):
        raise Refused("This would remove your own administrator access. Ask another "
                      "administrator to make this change.")
    return confirms


def _owner_sign_in_open(cfg: dict) -> bool:
    """Disabled OIDC details are drafts; they do not pause local owner login."""
    from .local_owner import sign_in_available_for

    return sign_in_available_for(cfg)


def _is_owner(principal: str | None) -> bool:
    from . import local_owner

    if not principal:
        return False
    try:
        row = local_owner._read()
    except Exception:
        return False
    return bool(row) and principal == "user:" + str(row.get("email") or "")


def _is_this_computer(request) -> bool:
    import ipaddress

    host = request.client.host if getattr(request, "client", None) else ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def review_keys(changes: list[dict], prospective: dict[str, object]) -> list[dict]:
    """Key-service changes must still open the data keys already in use."""
    changed = [c["setting"] for c in changes if c["setting"].id.startswith(KEY_PREFIXES)
               and c["setting"].id != "kms.dek_cache_ttl"]
    if not changed:
        return []
    from . import settings_tests

    outcome = settings_tests.check_kms(prospective)
    if not outcome.ok:
        raise Refused(f"{outcome.message} Nothing was changed.")
    return [{
        "id": changed[0].id, "label": "Stored records", "kind": "access",
        "warning": "Lightwork will lock and unlock its data keys with this key service from now on.",
    }]


def _prerequisites(changed: set[str], values: dict[str, object]) -> None:
    """Refuse choices Lightwork could not start or keep working with."""
    def filled(setting_id: str) -> bool:
        return bool(str(values.get(setting_id) or "").strip())

    if changed & {"queue.backend", "queue.signing_key", "queue.redis_dsn", "queue.namespace",
                  "world_model.backend"} and values.get("queue.backend") == "arq":
        if not (filled("queue.redis_dsn") and filled("queue.namespace")
                and len(str(values.get("queue.signing_key") or "").encode("utf-8")) >= 32):
            raise Refused("A shared queue needs the queue address, a queue key of at least 32 "
                          "characters and a queue name. Fill those in first.")
        if str(values.get("world_model.backend") or "").lower() != "postgres":
            raise Refused("A shared queue needs Lightwork's records in the shared PostgreSQL "
                          "database. Choose that first.")
    postgres = (values.get("world_model.backend") == "postgres"
                or values.get("governed_records.backend") == "postgres")
    if changed & {"world_model.backend", "governed_records.backend", "world_model.dsn"} \
            and postgres and not filled("world_model.dsn"):
        raise Refused("The shared PostgreSQL database needs its connection filled in first.")
    if "client.enforce" in changed and values.get("client.enforce") is True:
        from maverick import client

        try:
            bound = client.strict_client_id()
        except Exception:
            bound = None
        if not bound:
            raise Refused("This installation has no client name, so requiring one would stop "
                          "Lightwork from starting. The client name is chosen when Lightwork is "
                          "installed.")
    if "kms.provider" in changed and values.get("kms.provider") not in (None, "", "local") \
            and not filled("kms.key_id"):
        raise Refused("Fill in the key name at the key service first.")
    if "audit.require_offhost_key" in changed and values.get("audit.require_offhost_key") is True:
        from maverick.audit import signing

        if not signing.active_key_is_offhost():
            raise Refused("The activity record is not signed with a key kept off this server "
                          "yet, so turning this on would stop the record from being written. "
                          "Set up that key first.")
    if "enterprise.require" in changed and values.get("enterprise.require") is True:
        from maverick import deployment

        checks = deployment.verify_deployment()
        failing = sum(1 for check in checks if not check.passed)
        if failing:
            raise Refused(f"{failing} of {len(checks)} regulated-deployment protections do not "
                          "hold yet, so Lightwork would refuse to start. Fix those first.")


def review_allowed_addresses(request, changes: list[dict],
                             prospective: dict[str, object]) -> None:
    """The request that saves the allowed-address list must itself match it,
    or the person saving would be locked out the moment it is written."""
    if not any(c["setting"].id == "auth.ip_allowlist.cidrs" for c in changes):
        return
    from . import ip_allowlist

    entries = prospective.get("auth.ip_allowlist.cidrs") or []
    if not isinstance(entries, list) or not entries:
        return
    networks, rejected = ip_allowlist.parse_networks(entries)
    if rejected:
        raise Refused("These entries are not network addresses or ranges: "
                      + ", ".join(rejected) + ". Nothing was changed.")
    address = ip_allowlist.client_ip(request)
    shown = str(address) if address is not None else "unknown"
    if address is None or not any(address in network for network in networks):
        raise Refused(f"The address you are using now ({shown}) is not in that list, so "
                      "saving it would lock you out. Add it, or the range it belongs to, "
                      "first.")


def review_second_factor(request, changes: list[dict],
                         prospective: dict[str, object]) -> None:
    """Turning on "Require a second factor" from a session that has none
    would end that session at the next request: refuse, and say why."""
    if not any(c["setting"].id == "auth.mfa.require" and c["new"] is True
               for c in changes):
        return
    route, principal = caller_route(request)
    if route in {"token", "local"} or not principal:
        return
    from .mfa_policy import principal_mfa

    proved, _when = principal_mfa(getattr(request.state, "principal", None))
    if not proved:
        raise Refused("Your current sign-in didn't include a second factor, so requiring "
                      "one now would sign you out. Sign in again with your authenticator "
                      "first, then turn this on.")


def review(request, changes: list[dict], layers: dict[str, Any], writes: dict,
           prospective: dict[str, object]) -> list[dict]:
    """Every confirmation the save needs; :class:`Refused` when it must not happen."""
    _prerequisites({c["setting"].id for c in changes}, prospective)
    review_allowed_addresses(request, changes, prospective)
    review_second_factor(request, changes, prospective)
    return (review_sign_in(request, changes, layers, writes, prospective)
            + review_keys(changes, prospective))


__all__ = ["Access", "Refused", "access_for", "caller_route", "merged_config", "review",
           "review_allowed_addresses", "review_keys", "review_second_factor",
           "review_sign_in"]
