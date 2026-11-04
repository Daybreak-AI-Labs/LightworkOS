"""Provider function calls backed by the existing durable channel original.

Vapi tool-calls and Retell custom functions use ``lightwork_request(request)``.
Transcript/status notifications are informational and never start work. Caller
numbers are a coarse restriction, not company identity; native task authority
and spending limits still apply. Returning a result does not prove it was heard.
Bland retains its outbound implementation; inbound conversations are unsupported.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re

from .base import (
    Channel,
    IncomingMessage,
    add_webhook_body_limit,
    is_allowed,
    normalize_allowlist,
)

log = logging.getLogger(__name__)

# Which env var holds the API key for each provider. Used both to resolve
# the key at construction and by the installer wizard to prompt for the
# right secret.
PROVIDER_KEY_ENV = {
    "vapi": "VAPI_API_KEY",
    "retell": "RETELL_API_KEY",
    "bland": "BLAND_API_KEY",
}


_E164 = re.compile(r"\+[1-9][0-9]{5,14}\Z")
FUNCTION_NAME = "lightwork_request"
INBOUND_PROVIDERS = frozenset({"vapi", "retell"})


def _identity(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 33 for c in value):
        raise ValueError("A current call and function identity are required.")
    return value


def _arguments(value):
    from .base import _max_inbound_chars

    if not isinstance(value, dict) or set(value) != {"request"}:
        raise ValueError("Use the supported request field for this function.")
    text = value["request"]
    limit = _max_inbound_chars()
    if not isinstance(text, str) or not text.strip() or len(text) > min(30_000, limit if limit > 0 else 30_000):
        raise ValueError("The spoken request is empty or too long.")
    return text


def _retell_request(payload):
    if payload.get("name") != FUNCTION_NAME:
        if "event" in payload:
            return None  # Retell call lifecycle webhooks are informational.
        raise ValueError("This function is not supported.")
    call = payload.get("call")
    if not isinstance(call, dict) or call.get("call_type") != "phone_call" or call.get("direction") != "inbound":
        raise ValueError("A supported incoming phone call is required.")
    call_id, source_assistant = _identity(call.get("call_id")), call.get("agent_id")
    caller = call.get("from_number")
    text = _arguments(payload.get("args"))
    history = call.get("transcript_with_tool_calls")
    if not isinstance(history, list) or not 1 <= len(history) <= 2048:
        raise ValueError("The current function identity is unavailable.")
    invocation = next((item for item in reversed(history) if isinstance(item, dict)
                       and item.get("role") == "tool_call_invocation"), None)
    if not invocation or invocation.get("name") != FUNCTION_NAME:
        raise ValueError("The current function identity is unavailable.")
    arguments = invocation.get("arguments")
    if not isinstance(arguments, str) or len(arguments) > 200_000:
        raise ValueError("The recorded function request is unavailable.")
    try:
        recorded = json.loads(arguments)
    except (ValueError, RecursionError):
        raise ValueError("The recorded function request is unavailable.") from None
    if recorded != payload["args"]:
        raise ValueError("The recorded function request changed.")
    requests = [(_identity(invocation.get("tool_call_id")), text)]
    return call_id, caller, source_assistant, requests


def _vapi_call(item, nested):
    """``(call id, spoken request)`` from one Vapi tool call: the nested
    ``{id, function: {name, arguments}}`` shape of its custom-tools reference
    or the flat ``{id, name, parameters}`` shape of its events page."""
    if not isinstance(item, dict):
        raise ValueError("This function is not supported.")
    native = item.get("toolCall") if nested else item
    if not isinstance(native, dict):
        raise ValueError("The function details are missing.")
    function = native.get("function")
    if isinstance(function, dict):
        name, arguments = function.get("name"), function.get("arguments")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                raise ValueError("Use the supported request field for this function.") from None
    else:
        name, arguments = item.get("name"), native.get("parameters")
    if name != FUNCTION_NAME:
        raise ValueError("This function is not supported.")
    return _identity(native.get("id")), _arguments(arguments)


def parse_request(payload, *, provider, assistant_id, callers):
    """Pure, bounded provider parsing; no caller-authored invocation fallback."""
    if not isinstance(payload, dict):
        raise ValueError("A supported call message is required.")
    if provider not in INBOUND_PROVIDERS:
        raise ValueError("This service supports outgoing calls only.")
    if provider == "vapi":
        message = payload.get("message")
        if not isinstance(message, dict):
            raise ValueError("A supported call message is required.")
        if message.get("type") != "tool-calls":
            return None  # Transcript/status notifications never authorize work.
        call = message.get("call")
        if not isinstance(call, dict):
            raise ValueError("The call details are missing.")
        customer = call.get("customer")
        caller = customer.get("number") if isinstance(customer, dict) else None
        call_id, source_assistant = _identity(call.get("id")), call.get("assistantId")
        source = message.get("assistant")
        if isinstance(source, dict) and source.get("id"):
            if source_assistant and source_assistant != source["id"]:
                raise ValueError("The call assistant details disagree.")
            source_assistant = source["id"]
        flat, wrapped = message.get("toolCallList"), message.get("toolWithToolCallList")
        def unpack(items, nested=False):
            if not isinstance(items, list) or not 1 <= len(items) <= 8:
                raise ValueError("The call must contain one to eight supported requests.")
            output = [_vapi_call(item, nested) for item in items]
            if len({item[0] for item in output}) != len(output):
                raise ValueError("The call repeats a function identity.")
            return output
        requests = unpack(flat) if flat is not None else unpack(wrapped, True)
        if flat is not None and wrapped is not None and requests != unpack(wrapped, True):
            raise ValueError("The call function details disagree.")
    else:
        result = _retell_request(payload)
        if result is None:
            return None
        call_id, caller, source_assistant, requests = result
    if not assistant_id or source_assistant != assistant_id:
        raise PermissionError("The call assistant is not the currently configured assistant.")
    if not isinstance(caller, str) or not _E164.fullmatch(caller) or not is_allowed(caller, callers):
        raise PermissionError("This caller number is not permitted to start work.")
    return call_id, caller, requests


def configured_callers(values=None) -> set[str]:
    """Resolve and validate the effective list of callers allowed to start work.

    An explicit empty list overrides the environment. A missing list remains
    empty so the webhook and listener can refuse inbound work safely.
    """
    if values is not None and not isinstance(values, (list, tuple, set, frozenset)):
        raise ValueError("voice channel: caller list must contain phone numbers")
    callers = normalize_allowlist(values, "VOICE_ALLOWED_CALLERS")
    if any(not _E164.fullmatch(number) for number in callers):
        raise ValueError("voice channel: caller list needs phone numbers in +countrycode format")
    return callers


def configuration_identity(settings):
    """Hash the effective installation channel, including current secret sources."""
    if not isinstance(settings, dict):
        raise ValueError("Phone call settings are unavailable.")
    provider = settings.get("provider") or "vapi"
    material = {**settings, "provider": provider,
                "api_key": settings.get("api_key") or os.environ.get(PROVIDER_KEY_ENV.get(provider, "")),
                "webhook_token": settings.get("webhook_token") or os.environ.get("VAPI_WEBHOOK_TOKEN"),
                "allowed_callers": sorted(configured_callers(settings.get("allowed_callers")))}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_saved_source(source):
    """The current native saved result and external-release gate remain required."""
    from maverick.channel_reply_results import require_source
    from maverick.domain import available_domains, deliverable_release_allowed
    from maverick.world_model import close_world_if_owned, open_world

    require_source(source)
    world = open_world()
    try:
        goal = world.get_goal(source["goal_id"])
        if (goal is None or goal.status != "done" or
                hashlib.sha256((goal.result or "").encode()).hexdigest() != source["voice_result_sha256"]):
            raise PermissionError("The saved answer changed or is no longer available.")
        if goal.domain:
            profile = available_domains().get(goal.domain)
            if profile is None or not deliverable_release_allowed(profile, world.signoff_for(goal.id)):
                raise PermissionError("The saved answer is not approved for release.")
    finally:
        close_world_if_owned(world)


try:
    import httpx
    from fastapi import FastAPI, Header, HTTPException, Request, Response
    _HAVE_DEPS = True
except ImportError:
    _HAVE_DEPS = False
    FastAPI = Header = HTTPException = Request = Response = httpx = None  # type: ignore


class VoiceChannel(Channel):
    """Supported provider functions; HTTP results never prove spoken delivery."""

    name = "voice"

    def __init__(
        self,
        handler,
        api_key: str | None = None,
        phone_number: str | None = None,
        port: int = 8770,
        assistant_id: str | None = None,
        provider: str = "vapi",
        webhook_token: str | None = None,
        allowed_callers=None,
        current_authority=None,
    ):
        super().__init__(handler)
        if not _HAVE_DEPS:
            raise ImportError(
                "Phone call support is missing from this installation. "
                "An installation administrator can update the installed channel support."
            )
        self.provider = provider
        # Each provider keeps its key in its own env var; fall back to the
        # Vapi var for an unknown provider so the error message is sensible.
        key_env = PROVIDER_KEY_ENV.get(provider, "VAPI_API_KEY")
        self.api_key = api_key or os.environ.get(key_env)
        if not self.api_key:
            raise ValueError(f"voice channel: {key_env} not set")
        self.phone_number = phone_number
        self.port = port
        self.assistant_id = assistant_id
        self.webhook_token = webhook_token or os.environ.get("VAPI_WEBHOOK_TOKEN")
        # The bearer authenticates the webhook service, not the phone caller.
        # A caller list is required before any transcript can start work.
        self.allowed_callers = configured_callers(allowed_callers)
        self.current_authority = current_authority

        self._app = FastAPI()
        add_webhook_body_limit(self._app)
        self._app.post("/webhook/voice")(self._handle_webhook)
        self._uvicorn_server = None

    def _check_webhook_auth(self, authorization: str | None) -> bool:
        """Require bearer auth for inbound webhook events."""
        expected = self.webhook_token
        if not expected:
            return False
        if not authorization or not authorization.startswith("Bearer "):
            return False
        given = authorization[len("Bearer "):].strip()
        return hmac.compare_digest(expected.encode("utf-8"), given.encode("utf-8"))

    async def _handle_webhook(
        self,
        request: Request,
        authorization: str | None = Header(None),
    ):
        if not self._check_webhook_auth(authorization):
            raise HTTPException(status_code=401, detail="invalid webhook bearer")
        if not self.allowed_callers:
            raise HTTPException(status_code=403, detail="voice caller list is not configured")

        try:
            payload = await request.json()
            parsed = parse_request(payload, provider=self.provider, assistant_id=self.assistant_id,
                                   callers=self.allowed_callers)
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from None
        except (ValueError, RecursionError):
            raise HTTPException(400, "The phone call request is missing or unsupported.") from None
        if parsed is None:
            return Response(content="{}", media_type="application/json")
        call_id, caller, requests = parsed
        results, originals = [], []
        from maverick.paths import TenantPolicyError, tenant_by_user_enabled, tenant_scope

        # Exactly the same native phone principal/tenant as Server; no body or
        # browser-selected workspace may choose a different delivery original.
        try:
            voice_tenant = f"voice:{caller}" if tenant_by_user_enabled() else None
        except TenantPolicyError:
            raise HTTPException(503, "The phone call account settings are unavailable. No request was started.") from None
        for invocation, text in requests:
            with tenant_scope(tenant=voice_tenant):
                result, row, authorize = await self._answer_function(call_id, caller, invocation, text, authorization)
            results.append({"name": FUNCTION_NAME, "toolCallId": invocation, "result": result})
            originals.append((row, authorize))
        from maverick.authority_effects import authority_effect_fence

        from .delivery import _require_reply_source

        with tenant_scope(tenant=voice_tenant), authority_effect_fence():
            for row, authorize in originals:
                if not authorize():
                    raise HTTPException(403, "Current access to this call or its saved answer is unavailable.")
                try:
                    _require_reply_source(row)
                    if row.get("reply_source"):
                        require_saved_source(row["reply_source"])
                except PermissionError:
                    raise HTTPException(403, "Current access to this saved answer is unavailable.") from None
            body = {"results": results} if self.provider == "vapi" else {"result": results[0]["result"]}
            return Response(json.dumps(body), media_type="application/json", headers={"Cache-Control": "no-store"})

    async def _answer_function(self, call_id, caller, invocation, text, authorization):
        from maverick.authority_effects import authority_effect_fence

        from .delivery import (
            DeliveryJournal,
            DeliveryUnknown,
            _digest,
            _earlier_fingerprint,
            _payload,
            _record_id,
            _require_reply_source,
        )

        identity = f"{len(call_id)}:{call_id}:{invocation}"
        account = self._delivery_account()
        message = IncomingMessage(user_id=caller, sender_id=caller, text=text, channel=self.name,
                                  message_id=identity, conversation_ref=call_id)
        route = {"response_transport": "http", "function": FUNCTION_NAME}
        def authorize():
            return (account == self._delivery_account() and self._check_webhook_auth(authorization)
                    and is_allowed(caller, self.allowed_callers)
                    and (self.current_authority is None or self.current_authority()))
        async def offered(reply):
            raise DeliveryUnknown("Voice HTTP response acceptance is unconfirmed")
        try:
            if not authorize():
                raise PermissionError("Current phone call settings changed.")
            journal = DeliveryJournal()
            row = journal.get(_record_id(self.name, account, identity))
            if row is not None:
                # An original read never resumes a received, running or unknown
                # execution. Changed input cannot borrow its retained identity.
                material, _ = _payload(message, row["id"])
                if row["fingerprint"] not in (_digest([material, route]), _earlier_fingerprint(material, route)):
                    raise ValueError("The function identity belongs to a different request.")
            else:
                row = await self.process_message(message, external_id=identity, account=account,
                                                 authorize=authorize, send=offered, route=route,
                                                 journal=journal)
            with authority_effect_fence():
                if not authorize():
                    raise PermissionError("Current phone call settings changed.")
                _require_reply_source(row)
                if row.get("reply_source"):
                    require_saved_source(row["reply_source"])
                if row["execution"] == "completed" and row.get("reply"):
                    return row["reply"]["text"], row, authorize
                if row["execution"] in {"received", "staging", "execution_started_unconfirmed"}:
                    return "Your earlier request is still processing. It has not been started again.", row, authorize
                return ("Your earlier request has no confirmed result. Changes may already have happened. "
                        "Check the original request in Lightwork before starting another request."), row, authorize
        except PermissionError:
            raise HTTPException(403, "Current access to this call or its saved answer is unavailable.") from None
        except ValueError:
            raise HTTPException(409, "This call identity already belongs to a different request.") from None
        except Exception:
            raise HTTPException(503, "The phone call result is unavailable. Work may already have started; "
                                     "check the original request before starting another request.") from None

    def _delivery_account(self):
        # Provider-issued assistant identity is stable through key rotation.
        # A changed credential must not give an old invocation a new original.
        return json.dumps([self.provider, self.assistant_id or ""], separators=(",", ":"))

    async def start(self) -> None:
        if self.provider not in INBOUND_PROVIDERS:
            raise ValueError("This phone service supports outgoing calls only.")
        if not self.assistant_id:
            raise ValueError("Choose the saved call assistant in All settings before receiving calls.")
        if not self.allowed_callers:
            raise ValueError("Add permitted caller numbers in All settings before receiving calls.")
        import uvicorn
        if not self.webhook_token:
            # Inbound webhook auth rejects every request without a token, so the
            # listener would accept nothing. Fail loudly rather than run inert.
            raise ValueError(
                "Save a call check key in All settings before receiving calls."
            )
        log.info("Voice channel listening on :%d (provider=%s)",
                 self.port, self.provider)
        config = uvicorn.Config(
            self._app, host="127.0.0.1", port=self.port,
            log_level="info",
        )
        self._uvicorn_server = uvicorn.Server(config)
        await self._uvicorn_server.serve()

    def _outbound_request(self, user_id: str, text: str) -> dict:
        """Build the provider-specific outbound-call HTTP request.

        Returns a dict with ``url`` / ``headers`` / ``json``. Contracts
        come from the existing provider integrations. Local transport fixtures
        verify request construction; live provider acceptance needs separate
        qualification. Raises ValueError for an unknown provider so ``send()``
        can report definitive nonacceptance.
        """
        if self.provider == "vapi":
            return {
                "url": "https://api.vapi.ai/call",
                "headers": {"Authorization": f"Bearer {self.api_key}"},
                "json": {
                    "assistantId": self.assistant_id,
                    "customer": {"number": user_id},
                    "phoneNumber": {"number": self.phone_number},
                    "assistantOverrides": {"firstMessage": text},
                },
            }
        if self.provider == "retell":
            # https://docs.retellai.com/api-references/create-phone-call
            return {
                "url": "https://api.retellai.com/v2/create-phone-call",
                "headers": {"Authorization": f"Bearer {self.api_key}"},
                "json": {
                    "from_number": self.phone_number,
                    "to_number": user_id,
                    "override_agent_id": self.assistant_id,
                    "retell_llm_dynamic_variables": {"first_message": text},
                },
            }
        if self.provider == "bland":
            # https://docs.bland.ai/api-v1/post/calls
            return {
                "url": "https://api.bland.ai/v1/calls",
                "headers": {"authorization": self.api_key or ""},
                "json": {
                    "phone_number": user_id,
                    "from": self.phone_number,
                    "task": text,
                    "pathway_id": self.assistant_id,
                },
            }
        raise ValueError(f"unsupported voice provider {self.provider!r}")

    async def send(self, user_id: str, text: str) -> str:
        """Outbound: place a call to `user_id` (a phone number) via the
        configured provider and have the assistant deliver `text`."""
        from .delivery import DeliveryNotSent, DeliveryUnknown, send_chunk

        if not self.assistant_id:
            raise DeliveryNotSent("Voice outbound assistant is not configured")
        try:
            req = self._outbound_request(user_id, text)
        except ValueError as exc:
            raise DeliveryNotSent("Voice outbound provider is unsupported") from exc
        async def create():
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(req["url"], headers=req["headers"], json=req["json"])
            if 400 <= response.status_code < 500 and response.status_code != 408:
                raise DeliveryNotSent("Voice provider rejected the outbound call")
            if response.status_code >= 300:
                raise DeliveryUnknown("Voice outbound acceptance is unconfirmed")
            result = response.json()
            identity = result.get("id") or result.get("call_id")
            if not identity:
                raise DeliveryUnknown("Voice provider returned no call identity")
            return str(identity)
        return await send_chunk("voice-call-0", {"provider": self.provider, "to": user_id,
                                "text": text, "assistant": self.assistant_id}, create)

    async def stop(self) -> None:
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True
