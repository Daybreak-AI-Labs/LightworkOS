"""Microsoft Teams channel via the Azure Bot Framework (Bot Connector REST v3).

Teams delivers Activities to the bot's messaging endpoint (``/webhook/teams``)
with a JWT signed by the Bot Connector service. This adapter:

- verifies every request against Microsoft's OpenID metadata and signing keys
  (issuer ``https://api.botframework.com``, audience = the app id, RS256,
  5-minute clock skew), fails closed and caches keys for at most 24 hours
  (https://learn.microsoft.com/azure/bot-service/rest-api/bot-framework-rest-connector-authentication);
- handles ``message`` activities in personal chat, group chat and channel (the
  bot @mention is stripped, as Microsoft's own SDKs do), ``conversationUpdate``
  (welcome text when the bot is added) and ``invoke`` for Adaptive Card
  ``Action.Execute`` buttons (``adaptiveCard/action``);
- replies through the ``serviceUrl`` carried by the activity, with a
  client-credentials token from ``login.microsoftonline.com`` (the tenant when
  the app registration is single-tenant, ``botframework.com`` when it is
  multi-tenant), scope ``https://api.botframework.com/.default``;
- posts approval requests as Adaptive Cards to linked approvers and decides
  them through the dashboard's own decision path (``approval_decisions``).

Security: the token proves the Bot Connector relayed the activity, not who
wrote it. The sender's Microsoft Entra object id must be on ``allowed_users``
and the tenant on ``allowed_tenants`` (or equal to ``tenant_id``); both are
default-deny. Message ids are claimed durably before processing so a
redelivery cannot run (and bill) a goal twice. Outbound HTTP uses the
SSRF-safe pinned client shared with the rest of the kernel.

Config::

    [channels.teams]
    enabled = true
    app_id = "00000000-0000-0000-0000-000000000000"
    app_password = "${TEAMS_APP_PASSWORD}"      # or the secret provider
    tenant_id = "11111111-1111-1111-1111-111111111111"   # blank for multi-tenant
    allowed_tenants = []                        # defaults to [tenant_id]
    allowed_users = ["<Entra object id>"]
    approvals_enabled = true
    port = 8771

Requires::

    python -m pip install -e './packages/maverick-channels[teams]'
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

from .base import (
    Channel,
    IncomingMessage,
    add_webhook_body_limit,
    is_allowed,
    normalize_allowlist,
)
from .delivery import DeliveryNotSent, DeliveryUnknown, send_chunk
from .formatting import split_for_discord

log = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, HTTPException, Request
    _HAVE_DEPS = True
except ImportError:
    _HAVE_DEPS = False
    FastAPI = HTTPException = Request = None  # type: ignore

BOT_OPENID_METADATA = "https://login.botframework.com/v1/.well-known/openidconfiguration"
BOT_ISSUER = "https://api.botframework.com"
TOKEN_SCOPE = "https://api.botframework.com/.default"
LOGIN_HOST = "https://login.microsoftonline.com"
DEFAULT_SERVICE_URL = "https://smba.trafficmanager.net/teams/"
ALGORITHMS = ("RS256",)
CLOCK_SKEW_SECONDS = 300
KEYS_TTL_SECONDS = 24 * 3600
KEYS_REFRESH_COOLDOWN = 60.0
TEXT_LIMIT = 4000
DEFAULT_PORT = 8771
_CONFIRM_RISKS = frozenset({"high", "critical"})
# Teams expects an invoke answer within a few seconds; the in-place update of
# the card is a courtesy that must not make the answer late.
_INVOKE_UPDATE_SECONDS = 3.0
_LINK_CODE = re.compile(r"[0-9A-Fa-f]{6,16}")  # what teams_identity.issue_link_code produces
_TRUTHY = {"1", "true", "yes", "on"}


class TeamsAuthError(PermissionError):
    """The incoming request is not a verified Bot Connector call."""


# ----------------------------------------------------------------- tokens


def token_endpoint(tenant_id: str | None) -> str:
    """Single-tenant registrations use their tenant; multi-tenant use botframework.com."""
    tenant = (tenant_id or "").strip() or "botframework.com"
    return f"{LOGIN_HOST}/{quote(tenant, safe='')}/oauth2/v2.0/token"


def explain_token_failure(status: int, body: object) -> str:
    """Turn Microsoft's token error into a plain sentence (no secrets echoed)."""
    error = str((body or {}).get("error") or "") if isinstance(body, dict) else ""
    description = str((body or {}).get("error_description") or "") if isinstance(body, dict) else ""
    if error == "invalid_client" or "AADSTS7000215" in description:
        return "Microsoft did not accept the app secret. Check the client secret value (not its id) and that it has not expired."
    if error == "unauthorized_client" or "AADSTS700016" in description:
        return "Microsoft does not know this app id in that tenant. Check the app id and the tenant id, or leave the tenant blank for a multi-tenant registration."
    if "AADSTS90002" in description or error == "invalid_request" and "tenant" in description.lower():
        return "Microsoft could not find that tenant. Check the tenant id."
    if error == "invalid_scope":
        return "Microsoft refused the Bot Framework scope. Make sure the registration is an Azure Bot app registration."
    if status >= 500:
        return "Microsoft's sign-in service returned a server error. Try again in a minute."
    return f"Microsoft refused the sign-in ({error or status})."


async def default_transport(method: str, url: str, *, headers: dict | None = None,
                            json_body: object = None, data: dict | None = None,
                            timeout: float = 30.0) -> tuple[int, object]:
    """POST/PUT/GET through the kernel's SSRF-safe pinned client."""
    from maverick.tools._ssrf import safe_async_client

    if urlsplit(url).scheme != "https":
        raise DeliveryNotSent("Teams service URLs must be https")
    async with safe_async_client(url, timeout=timeout) as client:
        response = await client.request(method, url, headers=headers or {}, json=json_body,
                                        data=data)
    try:
        body = response.json() if response.content else {}
    except ValueError:
        body = {"text": response.text[:500]}
    return response.status_code, body


class TokenProvider:
    """Client-credentials token, cached until a minute before it expires."""

    def __init__(self, app_id: str, app_password: str, tenant_id: str | None = None,
                 transport=None):
        self.app_id, self.app_password, self.tenant_id = app_id, app_password, tenant_id
        self._transport = transport or default_transport
        self._token = ""
        self._expires = 0.0
        self._lock = asyncio.Lock()

    async def token(self) -> str:
        async with self._lock:
            if self._token and time.monotonic() < self._expires - 60:
                return self._token
            status, body = await self._transport(
                "POST", token_endpoint(self.tenant_id),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"grant_type": "client_credentials", "client_id": self.app_id,
                      "client_secret": self.app_password, "scope": TOKEN_SCOPE})
            if status != 200 or not isinstance(body, dict) or not body.get("access_token"):
                raise DeliveryNotSent(explain_token_failure(status, body))
            self._token = str(body["access_token"])
            self._expires = time.monotonic() + float(body.get("expires_in") or 3600)
            return self._token


# ------------------------------------------------------- inbound token check


class SigningKeys:
    """Bot Connector signing keys from the OpenID metadata; refreshed on an
    unknown ``kid`` at most once a minute, and at least daily."""

    def __init__(self, fetch_json=None, *, metadata_url: str = BOT_OPENID_METADATA,
                 jwks: dict | None = None):
        self._fetch = fetch_json or self._default_fetch
        self._metadata_url = metadata_url
        self._keys: dict[str, dict] = {}
        self._fetched = float("-inf")
        self._last_attempt = float("-inf")
        self._lock = threading.Lock()
        if jwks:
            self._store(jwks)

    @staticmethod
    def _default_fetch(url: str) -> dict:
        from maverick.tools._ssrf import safe_get

        response = safe_get(url, timeout=5.0)
        response.raise_for_status()
        return response.json()

    def _store(self, jwks: dict) -> None:
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list) or not 1 <= len(keys) <= 128:
            raise TeamsAuthError("Bot Framework signing key set is invalid")
        self._keys = {str(k.get("kid")): k for k in keys if isinstance(k, dict) and k.get("kid")}
        self._fetched = time.monotonic()

    def _refresh(self) -> None:
        now = time.monotonic()
        if now < self._last_attempt + KEYS_REFRESH_COOLDOWN:
            raise TeamsAuthError("signing key refresh is temporarily unavailable")
        self._last_attempt = now
        try:
            metadata = self._fetch(self._metadata_url)
            uri = str((metadata or {}).get("jwks_uri") or "")
            if urlsplit(uri).scheme != "https":
                raise TeamsAuthError("Bot Framework OpenID metadata has no https jwks_uri")
            self._store(self._fetch(uri))
        except TeamsAuthError:
            raise
        except Exception as exc:
            # A network failure, an error status or a malformed document: the
            # request cannot be verified now and is refused, as during the
            # refresh cooldown, never left as an unhandled server error.
            raise TeamsAuthError(f"signing keys could not be fetched ({type(exc).__name__})") from exc

    def key_for(self, kid: str, *, required_endorsement: str | None = None):
        import jwt

        with self._lock:
            stale = time.monotonic() - self._fetched > KEYS_TTL_SECONDS
            if stale or kid not in self._keys:
                self._refresh()
            jwk = self._keys.get(kid)
            if jwk is None:
                raise TeamsAuthError("signing key is unknown")
            if required_endorsement:
                endorsements = jwk.get("endorsements")
                if (not isinstance(endorsements, list)
                        or required_endorsement not in endorsements):
                    raise TeamsAuthError("signing key is not endorsed for this channel")
            try:
                return jwt.PyJWK(jwk).key
            except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
                raise TeamsAuthError("signing key is unusable") from exc


def verify_bot_token(token: str, *, app_id: str, keys: SigningKeys,
                     required_endorsement: str | None = None) -> dict:
    """Return the verified claims of a Bot Connector JWT or raise TeamsAuthError.

    Checks (from Microsoft's Bot Connector authentication page): Bearer JWT,
    issuer ``https://api.botframework.com``, audience = the app id, within its
    validity period with 5 minutes of skew, and a signature by a key from the
    published signing-key document using RS256.
    """
    try:
        import jwt
    except ImportError as exc:
        raise TeamsAuthError("pyjwt[crypto] is required to verify Teams requests") from exc
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise TeamsAuthError("missing token")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TeamsAuthError("malformed token") from exc
    if header.get("alg") not in ALGORITHMS:
        raise TeamsAuthError("unaccepted signing algorithm")
    kid = header.get("kid")
    if not isinstance(kid, str) or not 1 <= len(kid) <= 256:
        raise TeamsAuthError("invalid signing key identifier")
    key = keys.key_for(kid, required_endorsement=required_endorsement)
    try:
        claims = jwt.decode(token, key, algorithms=list(ALGORITHMS), audience=app_id,
                            leeway=CLOCK_SKEW_SECONDS,
                            options={"require": ["exp", "iss", "aud"], "verify_iss": False})
    except jwt.ExpiredSignatureError as exc:
        raise TeamsAuthError("token expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise TeamsAuthError("token audience is not this app") from exc
    except jwt.PyJWTError as exc:
        raise TeamsAuthError("token signature or claims invalid") from exc
    if claims.get("iss") != BOT_ISSUER:
        raise TeamsAuthError("token issuer is not the Bot Connector")
    return claims


# ------------------------------------------------------------- activities


@dataclass
class ParsedActivity:
    kind: str
    text: str = ""
    sender_id: str = ""
    sender_aad: str = ""
    sender_name: str = ""
    conversation_id: str = ""
    conversation_type: str = "personal"
    service_url: str = ""
    tenant_id: str = ""
    activity_id: str = ""
    reply_to_id: str = ""
    bot_added: bool = False
    raw: dict = field(default_factory=dict)

    @property
    def principal_key(self) -> str:
        """The Entra object id is stable across chats; fall back to the bot-scoped id."""
        return self.sender_aad or self.sender_id


def strip_bot_mentions(text: str, entities: object, bot_id: str) -> str:
    """Remove the bot's own ``<at>Name</at>`` mention(s); keep other mentions."""
    out = text or ""
    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, dict) or entity.get("type") != "mention":
            continue
        mentioned = entity.get("mentioned") if isinstance(entity.get("mentioned"), dict) else {}
        if str(mentioned.get("id") or "").lower() == bot_id.lower() and entity.get("text"):
            out = out.replace(str(entity["text"]), "")
    return " ".join(out.split())


def parse_activity(activity: object, *, bot_id: str) -> ParsedActivity | None:
    """Normalize one Bot Framework Activity; ``None`` for shapes we ignore."""
    if not isinstance(activity, dict):
        return None
    kind = str(activity.get("type") or "")
    if kind not in {"message", "conversationUpdate", "invoke"}:
        return None
    sender = activity.get("from") if isinstance(activity.get("from"), dict) else {}
    conversation = (activity.get("conversation")
                    if isinstance(activity.get("conversation"), dict) else {})
    channel_data = (activity.get("channelData")
                    if isinstance(activity.get("channelData"), dict) else {})
    tenant = channel_data.get("tenant") if isinstance(channel_data.get("tenant"), dict) else {}
    recipient = activity.get("recipient") if isinstance(activity.get("recipient"), dict) else {}
    parsed = ParsedActivity(
        kind=kind,
        sender_id=str(sender.get("id") or ""),
        sender_aad=str(sender.get("aadObjectId") or "").lower(),
        sender_name=str(sender.get("name") or "")[:200],
        conversation_id=str(conversation.get("id") or ""),
        conversation_type=str(conversation.get("conversationType") or "personal"),
        service_url=str(activity.get("serviceUrl") or ""),
        tenant_id=str(tenant.get("id") or conversation.get("tenantId") or "").lower(),
        activity_id=str(activity.get("id") or ""),
        reply_to_id=str(activity.get("replyToId") or ""),
        raw=activity,
    )
    if kind == "message":
        text = strip_bot_mentions(str(activity.get("text") or ""), activity.get("entities"),
                                  str(recipient.get("id") or bot_id))
        from .teams_cards import strip_mentions_text, unescape

        parsed.text = unescape(strip_mentions_text(text)) if parsed.conversation_type != "personal" \
            else unescape(text)
    elif kind == "conversationUpdate":
        added = activity.get("membersAdded") if isinstance(activity.get("membersAdded"), list) else []
        me = str(recipient.get("id") or bot_id)
        parsed.bot_added = any(isinstance(m, dict) and str(m.get("id") or "") == me for m in added)
    return parsed


# ------------------------------------------------------------- connector


class TeamsConnector:
    """Bot Connector REST calls with a cached bot token (shared by the channel
    and the proactive approval poster)."""

    def __init__(self, app_id: str, app_password: str, tenant_id: str | None = None,
                 transport=None):
        self.app_id = app_id
        self.bot_id = f"28:{app_id}"
        self._transport = transport or default_transport
        self.tokens = TokenProvider(app_id, app_password, tenant_id, transport=self._transport)

    @staticmethod
    def _base(service_url: str) -> str:
        parts = urlsplit(service_url or "")
        if parts.scheme != "https" or not parts.netloc:
            raise DeliveryNotSent("Teams service URL is not https")
        return service_url.rstrip("/")

    async def _call(self, method: str, url: str, payload: dict) -> dict:
        headers = {"Authorization": f"Bearer {await self.tokens.token()}",
                   "Content-Type": "application/json"}
        status, body = await self._transport(method, url, headers=headers, json_body=payload)
        if status in (401, 403, 404, 400, 413):
            raise DeliveryNotSent(f"Teams rejected the message ({status})")
        if status == 429:
            # Throttled before processing: nothing was posted, so it can be retried.
            raise DeliveryNotSent("Teams is throttling this bot; the message was not sent")
        if status >= 500:
            raise DeliveryUnknown(f"Teams did not confirm the message ({status})")
        if status >= 400:
            raise DeliveryNotSent(f"Teams rejected the message ({status})")
        return body if isinstance(body, dict) else {}

    async def send_activity(self, service_url: str, conversation_id: str, activity: dict, *,
                            reply_to: str | None = None) -> str:
        base = self._base(service_url)
        url = f"{base}/v3/conversations/{quote(conversation_id, safe='')}/activities"
        if reply_to:
            url += "/" + quote(reply_to, safe="")
        body = await self._call("POST", url, {"type": "message", **activity})
        return str(body.get("id") or "")[:512]

    async def update_activity(self, service_url: str, conversation_id: str, activity_id: str,
                              activity: dict) -> str:
        base = self._base(service_url)
        url = (f"{base}/v3/conversations/{quote(conversation_id, safe='')}/activities/"
               f"{quote(activity_id, safe='')}")
        body = await self._call("PUT", url, {"type": "message", "id": activity_id, **activity})
        return str(body.get("id") or activity_id)[:512]

    async def create_personal_conversation(self, service_url: str, *, member_id: str,
                                           tenant_id: str) -> str:
        """Start a 1:1 chat (proactive message). ``member_id`` is the person's
        Entra object id or bot-scoped user id; Teams does not accept a UPN here."""
        base = self._base(service_url)
        body = await self._call("POST", f"{base}/v3/conversations", {
            "bot": {"id": self.bot_id}, "isGroup": False,
            "members": [{"id": member_id}], "tenantId": tenant_id,
            "channelData": {"tenant": {"id": tenant_id}},
        })
        return str(body.get("id") or "")


# ---------------------------------------------------------------- config


def channel_config(cfg: dict | None = None) -> dict:
    """The effective ``[channels.teams]`` table with the secret resolved.

    ``app_password`` comes from the secret provider (``TEAMS_APP_PASSWORD`` in
    the environment or a mounted secret file) first, then the saved value.
    """
    if cfg is None:
        try:
            from maverick.config import load_config

            cfg = ((load_config() or {}).get("channels") or {}).get("teams") or {}
        except Exception:  # noqa: BLE001 -- an unreadable config disables the channel
            cfg = {}
    cfg = cfg if isinstance(cfg, dict) else {}
    try:
        from maverick.secret_provider import get_secret_or_saved

        password = get_secret_or_saved("TEAMS_APP_PASSWORD", cfg.get("app_password"))
    except Exception:  # noqa: BLE001
        password = os.environ.get("TEAMS_APP_PASSWORD") or cfg.get("app_password")

    def flag(value: object) -> bool:
        return str(value).strip().lower() in _TRUTHY if isinstance(value, str) else bool(value)

    return {
        "enabled": flag(cfg.get("enabled")),
        "app_id": str(cfg.get("app_id") or os.environ.get("TEAMS_APP_ID") or "").strip(),
        "app_password": str(password or ""),
        "tenant_id": str(cfg.get("tenant_id") or os.environ.get("TEAMS_TENANT_ID") or "").strip().lower(),
        "allowed_tenants": normalize_allowlist(cfg.get("allowed_tenants"), "TEAMS_ALLOWED_TENANTS"),
        "allowed_users": normalize_allowlist(cfg.get("allowed_users") if "allowed_users" in cfg else cfg.get("allowed_user_ids"),
                                             "TEAMS_ALLOWED_USERS"),
        "approvals_enabled": flag(cfg.get("approvals_enabled")),
        "port": int(cfg.get("port") or DEFAULT_PORT),
        "service_url": str(cfg.get("service_url") or DEFAULT_SERVICE_URL),
        "bot_name": str(cfg.get("bot_name") or "Lightwork")[:100],
    }


def _decisions():
    """The dashboard's approval decision module, or ``None`` when absent."""
    try:
        from maverick_dashboard import approval_decisions
    except Exception:  # noqa: BLE001 -- the kernel runs without the dashboard
        return None
    return approval_decisions


def _approval_world():
    from maverick_dashboard._shared import _world

    return _world()


def _may_see_approval(module, approval_id: int, principal: str) -> bool:
    """Whether ``principal`` may see and decide this request now, by the
    dashboard's own rule (``approval_decisions.eligible_approvers``: holds
    ``operate``, is not deprovisioned, and can open the card or is a linked
    approver it is posted to). Anything that cannot be checked counts as no."""
    try:
        world = _approval_world()
        approval = world.get_approval(int(approval_id))
        return approval is not None and principal in module.eligible_approvers(world, approval)
    except Exception:  # noqa: BLE001 -- an unreadable rule shows nothing
        log.warning("teams: could not check who may see approval #%s", approval_id, exc_info=True)
        return False


# --------------------------------------------------------------- channel


class TeamsChannel(Channel):
    name = "teams"

    def __init__(
        self,
        handler,
        app_id: str | None = None,
        app_password: str | None = None,
        tenant_id: str | None = None,
        allowed_tenants=None,
        allowed_user_ids=None,
        approvals_enabled: bool = False,
        port: int = DEFAULT_PORT,
        bind_host: str | None = None,
        transport=None,
        keys: SigningKeys | None = None,
        decisions=None,
        bot_name: str = "Lightwork",
        service_url: str = DEFAULT_SERVICE_URL,
    ):
        super().__init__(handler)
        if not _HAVE_DEPS:
            raise ImportError(
                "fastapi not installed. From the reviewed checkout run: "
                "python -m pip install -e './packages/maverick-channels[teams]'"
            )
        self.app_id = (app_id or os.environ.get("TEAMS_APP_ID") or "").strip()
        password = app_password or os.environ.get("TEAMS_APP_PASSWORD") or ""
        if not self.app_id or not password:
            raise ValueError("Teams credentials missing. Set app_id and app_password "
                             "([channels.teams] or TEAMS_APP_ID / TEAMS_APP_PASSWORD).")
        self.tenant_id = (tenant_id or os.environ.get("TEAMS_TENANT_ID") or "").strip().lower()
        self.allowed_tenants = {t.lower() for t in normalize_allowlist(allowed_tenants, "TEAMS_ALLOWED_TENANTS")}
        if not self.allowed_tenants and self.tenant_id:
            self.allowed_tenants = {self.tenant_id}
        if not self.allowed_tenants:
            raise ValueError("Set tenant_id or allowed_tenants so only your organisation can reach the bot")
        self.allowed_user_ids = {u.lower() for u in normalize_allowlist(allowed_user_ids, "TEAMS_ALLOWED_USERS")}
        if not self.allowed_user_ids:
            raise ValueError("Set TEAMS_ALLOWED_USERS (Microsoft Entra object ids) to restrict who can drive the agent")
        self.approvals_enabled = bool(approvals_enabled)
        self.port = int(port)
        self.bind_host = bind_host or os.environ.get("TEAMS_BIND_HOST", "127.0.0.1")
        self.bot_name = bot_name
        self.default_service_url = service_url
        self.connector = TeamsConnector(self.app_id, password, self.tenant_id or None, transport=transport)
        self.keys = keys or SigningKeys()
        self._decisions = decisions
        self._service_urls: dict[str, str] = {}
        self._app = FastAPI()
        add_webhook_body_limit(self._app)
        self._app.post("/webhook/teams")(self._handle_webhook)
        self._uvicorn_server = None

    # -- authorization -------------------------------------------------------

    def _tenant_allowed(self, parsed: ParsedActivity) -> bool:
        return bool(parsed.tenant_id) and parsed.tenant_id in self.allowed_tenants

    def _sender_allowed(self, parsed: ParsedActivity) -> bool:
        from maverick.oidc import oidc_enabled

        return (self._tenant_allowed(parsed)
                and (not oidc_enabled() or bool(parsed.sender_aad))
                and is_allowed(parsed.principal_key.lower(), self.allowed_user_ids))

    def _authorized(self, msg: IncomingMessage, account: str) -> bool:
        from maverick.oidc import oidc_enabled

        if not (account == self.app_id
                and is_allowed(str(msg.principal_id).lower(), self.allowed_user_ids)):
            return False
        if (not oidc_enabled() and msg.provider_tenant_id is None
                and msg.provider_sender_id is None):
            # Pre-upgrade receipts retain the original account and allowlist
            # policy. Missing fields can never authorize OIDC identity.
            return True
        return bool(msg.provider_tenant_id in self.allowed_tenants
                    and msg.provider_sender_id == msg.principal_id)

    async def _verify(self, request) -> dict:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise TeamsAuthError("missing bearer token")
        return await asyncio.to_thread(
            verify_bot_token, header[7:], app_id=self.app_id, keys=self.keys,
            required_endorsement="msteams",
        )

    # -- webhook -------------------------------------------------------------

    async def _handle_webhook(self, request: Request):
        from starlette.responses import JSONResponse

        body = await request.body()
        try:
            claims = await self._verify(request)
        except TeamsAuthError as exc:
            log.warning("teams: request refused: %s", exc)
            raise HTTPException(status_code=403, detail="not a verified Bot Connector request") from None
        try:
            activity = json.loads(body or b"{}")
        except ValueError:
            raise HTTPException(status_code=400, detail="bad JSON") from None
        if not isinstance(activity, dict) or activity.get("channelId") != "msteams":
            raise HTTPException(status_code=403, detail="not a verified Microsoft Teams activity")
        parsed = parse_activity(activity, bot_id=self.connector.bot_id)
        if parsed is None:
            return JSONResponse({})
        claimed_url = str(claims.get("serviceurl") or "")
        if not claimed_url or claimed_url != parsed.service_url:
            raise HTTPException(status_code=403, detail="service URL does not match the token")
        if not self._tenant_allowed(parsed):
            log.warning("teams: activity from a tenant that is not allowed; ignoring")
            return JSONResponse({})
        if parsed.service_url:
            self._service_urls[parsed.conversation_id] = parsed.service_url
        if parsed.kind == "conversationUpdate":
            return await self._on_conversation_update(parsed)
        if parsed.kind == "invoke":
            return JSONResponse(await self.handle_invoke(parsed))
        return await self._on_message(parsed)

    async def _on_conversation_update(self, parsed: ParsedActivity):
        from starlette.responses import JSONResponse

        from .teams_cards import welcome_text

        if parsed.bot_added and parsed.conversation_id:
            try:
                await self.connector.send_activity(parsed.service_url, parsed.conversation_id,
                                                   {"text": welcome_text(self.bot_name)})
            except Exception:  # noqa: BLE001 -- a welcome is best-effort
                log.warning("teams: welcome message failed", exc_info=True)
        return JSONResponse({})

    def _remember(self, parsed: ParsedActivity) -> None:
        if parsed.conversation_type != "personal":
            return
        try:
            from maverick.teams_identity import remember_conversation

            remember_conversation(parsed.principal_key, {
                "service_url": parsed.service_url, "conversation_id": parsed.conversation_id,
                "tenant_id": parsed.tenant_id, "user_id": parsed.sender_id})
        except Exception:  # noqa: BLE001 -- never blocks a message
            log.debug("teams: could not remember conversation", exc_info=True)

    async def _maybe_link(self, parsed: ParsedActivity) -> str | None:
        """``link <code>`` in chat redeems an administrator's one-time code."""
        words = parsed.text.split()
        if len(words) != 2 or words[0].lower() != "link" or not _LINK_CODE.fullmatch(words[1]):
            return None  # "link pricing" is a request, not a code
        from maverick.oidc import oidc_enabled

        if oidc_enabled():
            return None  # with company sign-in the legacy link store is not trusted
        from maverick.teams_identity import redeem_link_code

        conversation = None
        if parsed.conversation_type == "personal":
            conversation = {"service_url": parsed.service_url, "conversation_id": parsed.conversation_id,
                            "tenant_id": parsed.tenant_id, "user_id": parsed.sender_id}
        principal = await asyncio.to_thread(redeem_link_code, words[1], parsed.principal_key,
                                            conversation=conversation)
        if principal:
            return f"Done. This Teams account is now linked to {principal}."
        return "That code isn't valid or has expired. Ask an administrator for a new one."

    async def _on_message(self, parsed: ParsedActivity):
        from starlette.background import BackgroundTasks
        from starlette.responses import JSONResponse

        if not self._sender_allowed(parsed):
            log.warning("teams: sender not on the allowlist; ignoring")
            return JSONResponse({})
        if not parsed.conversation_id or not parsed.activity_id:
            raise HTTPException(status_code=400, detail="message identity required")
        await asyncio.to_thread(self._remember, parsed)
        linked = await self._maybe_link(parsed)
        if linked is not None:
            await self.connector.send_activity(parsed.service_url, parsed.conversation_id,
                                               {"text": linked}, reply_to=parsed.activity_id)
            return JSONResponse({})
        if not parsed.text:
            return JSONResponse({})
        msg = IncomingMessage(user_id=parsed.conversation_id, text=parsed.text, channel=self.name,
                              sender_id=parsed.principal_key, message_id=parsed.activity_id,
                              provider_tenant_id=parsed.tenant_id,
                              # The identity _sender_allowed admitted: the
                              # Entra id, or the bot-scoped id when company
                              # sign-in is off and the activity has none.
                              provider_sender_id=parsed.principal_key)
        account = self.app_id
        route = {"service_url": parsed.service_url, "reply_to": parsed.activity_id}
        if (parsed.conversation_type == "personal"
                and (parsed.raw.get("conversation") or {}).get("conversationType") == "personal"):
            route["private_destination"] = {"service_url": parsed.service_url, "conversation_id": parsed.conversation_id,
                                            "tenant_id": parsed.tenant_id, "sender_id": parsed.principal_key, "app_id": self.app_id}
        external_id = parsed.conversation_id + ":" + parsed.activity_id
        try:
            receipt = await self.admit_message(msg, external_id=external_id, account=account,
                                               authorize=lambda: self._authorized(msg, account), route=route)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="message intake unavailable") from exc

        async def process():
            try:
                await self.process_message(msg, external_id=external_id, account=account,
                                           authorize=lambda: self._authorized(msg, account), route=route,
                                           receipt=receipt, send=lambda reply: self._send_saved(msg, reply, route))
            except Exception:  # noqa: BLE001
                log.warning("teams: durable processing requires review: %s", receipt["id"])
        background = BackgroundTasks()
        background.add_task(process)
        return JSONResponse({"status": "ok", "receipt": receipt["id"]}, background=background)

    async def _send_saved(self, msg, reply, route):
        if reply.text:
            return await self.send_threaded(msg.user_id, reply.text, reply_to=reply.thread_ref or route.get("reply_to"),
                                            service_url=route.get("service_url"))

    # -- outbound ------------------------------------------------------------

    def _service_url(self, conversation_id: str, service_url: str | None) -> str:
        return service_url or self._service_urls.get(conversation_id) or self.default_service_url

    async def send(self, user_id: str, text: str) -> None:
        return await self.send_threaded(user_id, text)

    async def send_threaded(self, user_id: str, text: str, *, reply_to: str | None = None,
                            service_url: str | None = None) -> None:
        """Reply in the conversation; long replies go as several messages.

        Native saved replies carry explicit file-availability wording when this
        connector cannot upload files. Text uses Teams' markdown rendering.
        """
        from .teams_cards import attachment, fits_message, result_card

        base = self._service_url(user_id, service_url)
        receipt = None
        for index, chunk in enumerate(split_for_discord(text, limit=TEXT_LIMIT)):
            payload = {"text": chunk, "textFormat": "markdown"}
            if index == 0 and len(text) <= TEXT_LIMIT and "\n" in text.strip():
                # The card keeps every line, one block each; many short lines
                # can outgrow what Teams accepts, so such a reply goes as text.
                card = {"attachments": [attachment(result_card(chunk))], "text": ""}
                if fits_message(card):
                    payload = card

            async def post(payload=payload):
                return await self.connector.send_activity(base, user_id, payload, reply_to=reply_to)
            receipt = await send_chunk("text-" + str(index), payload, post)
        return receipt

    # -- approvals -----------------------------------------------------------

    def _approval_module(self):
        module = self._decisions if self._decisions is not None else _decisions()
        if module is None:
            raise RuntimeError("Approvals from Teams need the Lightwork dashboard package on this server.")
        return module

    async def _approval_principal(self, parsed: ParsedActivity) -> str | None:
        from maverick.oidc import oidc_enabled

        if oidc_enabled():
            from maverick.channel_oidc_bridge import BridgeError, resolve

            from .delivery import _digest

            try:
                return await asyncio.to_thread(
                    resolve, "teams", _digest(self.app_id), parsed.tenant_id,
                    parsed.sender_aad,
                )
            except BridgeError:
                return None
        from maverick.teams_identity import principal_for

        return await asyncio.to_thread(principal_for, parsed.sender_aad, parsed.sender_id)

    async def handle_invoke(self, parsed: ParsedActivity) -> dict:
        """Decide an approval card action through the dashboard's decision path."""
        from .teams_cards import (
            approval_card,
            attachment,
            card_response,
            confirm_card,
            message_response,
        )

        activity = parsed.raw
        if activity.get("name") != "adaptiveCard/action":
            return message_response("That action isn't supported.")
        if not self.approvals_enabled:
            return message_response("Approvals from Teams are turned off on this server.")
        if not self._sender_allowed(parsed):
            return message_response("You're not allowed to use this bot.")
        value = activity.get("value") if isinstance(activity.get("value"), dict) else {}
        action = value.get("action") if isinstance(value.get("action"), dict) else {}
        data = action.get("data") if isinstance(action.get("data"), dict) else {}
        verb = str(action.get("verb") or "")
        try:
            approval_id = int(data.get("approval_id"))
        except (TypeError, ValueError):
            return message_response("This card is missing its request number.")
        binding = str(data.get("binding") or "")
        try:
            module = self._approval_module()
        except RuntimeError as exc:
            return message_response(str(exc))
        await asyncio.to_thread(self._remember, parsed)
        principal = await self._approval_principal(parsed)
        if not principal:
            return message_response("Your Teams account isn't linked for this request. Connect it from My work.")
        # Every card below shows the request, so first apply the dashboard's
        # role and content-access rule; a missing request gets the same answer.
        if not await asyncio.to_thread(_may_see_approval, module, approval_id, principal):
            return message_response("Your Lightwork account can't open this request. Ask an administrator "
                                    "for the operator role or for access to it.")
        view = await asyncio.to_thread(module.approval_view, approval_id)
        if view is None:
            return message_response("This request no longer exists.")
        if verb == "undo":
            return await self._undo(module, parsed, approval_id, principal)
        if view["approval"]["status"] != "pending":
            return message_response("This request was already decided or has expired.")
        if view["card"] is None and verb in ("approve", "approve_confirm"):
            return message_response("This request can't be approved from here because its details "
                                    "could not be checked. Reject it and ask for a new request.")
        if verb == "cancel":
            return card_response(approval_card(view["approval"], view["card"], source_label=view["source_label"]))
        if verb == "approve" and str(view["approval"]["risk"] or "").strip().lower() in _CONFIRM_RISKS:
            return card_response(confirm_card(view["approval"], binding=binding))
        try:
            if verb in ("approve", "approve_confirm"):
                # The confirm card's inputs arrive merged into the action data
                # (Universal Actions): the acknowledgement toggle and, for
                # critical risk, the typed word — the dashboard's own rule.
                acknowledgement = {
                    "acknowledged": str(data.get("acknowledged", "")).lower() == "true"
                    or data.get("acknowledged") is True,
                    "confirmation": str(data.get("confirmation") or ""),
                }
                result = await asyncio.to_thread(
                    module.decide_from_channel, approval_id=approval_id, status="approved",
                    principal=principal, binding=binding, channel=self.name,
                    channel_user=parsed.principal_key, confirmed=verb == "approve_confirm",
                    acknowledgement=acknowledgement)
            elif verb == "reject":
                result = await asyncio.to_thread(
                    module.decide_from_channel, approval_id=approval_id, status="denied",
                    principal=principal, binding=binding, channel=self.name,
                    channel_user=parsed.principal_key)
            elif verb == "ask":
                result = await asyncio.to_thread(
                    module.send_back_from_channel, approval_id=approval_id, principal=principal,
                    rationale=str(data.get("question") or ""), channel=self.name,
                    channel_user=parsed.principal_key)
            else:
                return message_response("That button isn't recognised.")
        except module.ApprovalDecisionRefused as exc:
            return message_response(exc.detail)
        decided = approval_card(view["approval"], view["card"], source_label=view["source_label"],
                                decided=result)
        if parsed.reply_to_id:
            try:
                await asyncio.wait_for(
                    self.connector.update_activity(parsed.service_url, parsed.conversation_id,
                                                   parsed.reply_to_id,
                                                   {"attachments": [attachment(decided)]}),
                    _INVOKE_UPDATE_SECONDS)
            except Exception:  # noqa: BLE001 -- the invoke response still updates the presser's view
                log.warning("teams: could not update the approval card in place", exc_info=True)
        return card_response(decided)

    async def _undo(self, module, parsed: ParsedActivity, approval_id: int, principal: str) -> dict:
        """Undo a decision from the updated card while the grace window is open,
        through the same undo logic as the dashboard; the card returns to its
        pending form so the next decision is a new audit round."""
        from .teams_cards import approval_card, attachment, card_response, message_response

        try:
            await asyncio.to_thread(module.undo_from_channel, approval_id=approval_id,
                                    principal=principal, channel=self.name,
                                    channel_user=parsed.principal_key)
        except module.ApprovalDecisionRefused as exc:
            return message_response(exc.detail)
        view = await asyncio.to_thread(module.approval_view, approval_id)
        card = approval_card(view["approval"], view["card"], source_label=view["source_label"],
                             note="The earlier decision was undone; please decide again.")
        if parsed.reply_to_id:
            try:
                await asyncio.wait_for(
                    self.connector.update_activity(parsed.service_url, parsed.conversation_id,
                                                   parsed.reply_to_id, {"attachments": [attachment(card)]}),
                    _INVOKE_UPDATE_SECONDS)
            except Exception:  # noqa: BLE001
                log.warning("teams: could not restore the approval card in place", exc_info=True)
        return card_response(card)

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        import uvicorn

        config = uvicorn.Config(self._app, host=self.bind_host, port=self.port, log_level="warning")
        self._uvicorn_server = uvicorn.Server(config)
        log.info("Teams webhook on %s:%d", self.bind_host, self.port)
        account = self.app_id

        async def send_saved(message, reply, route):
            return await self._send_saved(message, reply, route)
        async with self.recovery_worker(account=account,
                                        authorize=lambda message: self._authorized(message, account),
                                        send=send_saved):
            await self._uvicorn_server.serve()

    async def stop(self) -> None:
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True


# ------------------------------------------------- proactive approval cards


async def post_approval_card(connector: TeamsConnector, approval_id: int, *, links: list[dict],
                             default_service_url: str, tenant_id: str, decisions=None) -> list[str]:
    """Post the approval card to each linked approver; returns posted activity ids."""
    from .teams_cards import approval_card, attachment

    module = decisions if decisions is not None else _decisions()
    if module is None:
        raise RuntimeError("Approvals from Teams need the Lightwork dashboard package on this server.")
    view = module.approval_view(approval_id)
    if view is None or view["approval"]["status"] != "pending":
        return []
    from maverick.daily_digest import dashboard_url

    card = approval_card(view["approval"], view["card"], source_label=view["source_label"],
                         dashboard_url=dashboard_url())
    posted = []
    for link in links:
        conversation = link.get("conversation") if isinstance(link.get("conversation"), dict) else {}
        service_url = conversation.get("service_url") or default_service_url
        conversation_id = conversation.get("conversation_id")
        try:
            if not conversation_id:
                if not tenant_id:
                    log.info("teams: %s has never chatted with the bot and no tenant_id is set; skipping",
                             link.get("teams_id"))
                    continue
                conversation_id = await connector.create_personal_conversation(
                    service_url, member_id=str(link.get("teams_id") or ""), tenant_id=tenant_id)
            activity_id = await connector.send_activity(service_url, conversation_id,
                                                        {"attachments": [attachment(card)]})
            posted.append(activity_id)
        except Exception:  # noqa: BLE001 -- one unreachable approver never blocks the others
            log.warning("teams: could not post approval #%s to %s", approval_id, link.get("teams_id"),
                        exc_info=True)
    return posted


def post_approval_to_linked_users(approval_id: int, *, cfg: dict | None = None, transport=None,
                                  decisions=None) -> list[str]:
    """Synchronous entry point used by :mod:`maverick.approval_notify`."""
    from maverick.oidc import oidc_enabled
    from maverick.teams_identity import approver_links

    settings = channel_config(cfg)
    if not (settings["enabled"] and settings["approvals_enabled"] and settings["app_id"]
            and settings["app_password"]):
        return []
    if oidc_enabled():
        # Decisions resolve through the sign-in bridge, which these legacy links
        # do not feed; a card posted to them shows the request to people who
        # then cannot act on it.
        return []
    links = approver_links()
    if not links:
        return []
    connector = TeamsConnector(settings["app_id"], settings["app_password"],
                               settings["tenant_id"] or None, transport=transport)
    return asyncio.run(post_approval_card(connector, int(approval_id), links=links,
                                          default_service_url=settings["service_url"],
                                          tenant_id=settings["tenant_id"], decisions=decisions))


__all__ = ["BOT_ISSUER", "BOT_OPENID_METADATA", "DEFAULT_PORT", "DEFAULT_SERVICE_URL", "TOKEN_SCOPE",
           "ParsedActivity", "SigningKeys", "TeamsAuthError", "TeamsChannel", "TeamsConnector",
           "TokenProvider", "channel_config", "explain_token_failure", "parse_activity",
           "post_approval_card", "post_approval_to_linked_users", "strip_bot_mentions",
           "token_endpoint", "verify_bot_token"]
