"""Channel interface.

Normalize every platform (CLI, Telegram, iMessage, ...) to the same shape
so the agent loop doesn't have to care where a message came from.
"""
from __future__ import annotations

import logging
import math
import os
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field


def normalize_allowlist(values, env_name: str) -> set:
    """Build an access allowlist from an explicit arg or a comma-separated
    env var (e.g. ``DISCORD_ALLOWED_USER_IDS``). Shared so every channel
    enforces access the same way instead of each rolling its own."""
    if values is not None:
        return {str(v).strip() for v in values if str(v).strip()}
    raw = os.environ.get(env_name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def is_allowed(user_id, allowlist) -> bool:
    """True only if ``user_id`` is an explicit allowlist member. A missing
    id or the ``"anonymous"`` fallback NEVER passes — treat unknown as deny
    so a channel that can't identify the sender can't be driven by anyone."""
    if not allowlist:
        return False
    uid = str(user_id or "").strip()
    if not uid or uid == "anonymous":
        return False
    return uid in allowlist


def claim_processed_message(channel: str, external_id: str) -> bool:
    """Atomically claim an inbound id in the canonical world backend.

    Channel dedup is part of the same control plane as goal execution. Going
    through ``open_world`` keeps it on Postgres when configured and on the
    active tenant's SQLite world otherwise. The ownership-aware close leaves
    process-cached tenant worlds alive while releasing per-call backends.
    """
    from maverick.world_model import close_world_if_owned, open_world

    world = open_world()
    try:
        return bool(world.mark_message_processed(channel, external_id))
    finally:
        try:
            close_world_if_owned(world)
        except Exception:  # pragma: no cover -- claim result remains authoritative
            logging.getLogger(__name__).exception(
                "channel dedup world teardown failed after claim"
            )


def release_processed_message(channel: str, external_id: str) -> None:
    """Release a failed inbound claim through the canonical world backend."""
    from maverick.world_model import close_world_if_owned, open_world

    world = open_world()
    try:
        world.release_processed_message(channel, external_id)
    finally:
        try:
            close_world_if_owned(world)
        except Exception:  # pragma: no cover -- release result remains authoritative
            logging.getLogger(__name__).exception(
                "channel dedup world teardown failed after release"
            )


def public_url_for(request) -> str:
    """Reconstruct the PUBLIC URL Twilio signed, not the loopback URL the
    reverse proxy forwarded to. Twilio signs the https URL it was configured
    with; behind a proxy ``request.url`` is the internal http://127.0.0.1 URL,
    so validating against it 403s every legitimate webhook.

    Prefer ``MAVERICK_PUBLIC_BASE_URL`` (e.g. ``https://bot.example.com``) when
    set, else ``[channels] public_base_url`` (the dashboard's All settings
    page); otherwise rebuild from the ``X-Forwarded-Proto``/``X-Forwarded-Host``
    headers the proxy adds (Caddy/nginx set both). Falls back to the raw
    request URL when neither is available (direct-bind deploys)."""
    try:
        from maverick.env_setting import env_or_config

        base = env_or_config("MAVERICK_PUBLIC_BASE_URL", "channels", "public_base_url", "") or ""
    except Exception:  # an unreadable setting keeps the proxy-header fallback
        base = os.environ.get("MAVERICK_PUBLIC_BASE_URL", "")
    base = base.strip().rstrip("/")
    if base:
        return base + request.url.path

    proto = request.headers.get("X-Forwarded-Proto")
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host")
    if proto and host:
        return f"{proto}://{host}{request.url.path}"
    return str(request.url)


def _max_inbound_chars() -> int:
    """Cap on inbound text fed to the swarm. A single oversized inbound
    message (a 200KB email, an attacker-crafted mention) would otherwise
    drive an uncapped-context, uncapped-cost agent run. Override with
    MAVERICK_MAX_INBOUND_CHARS; 0 disables the cap."""
    try:
        from maverick.env_setting import env_or_config

        return int(env_or_config("MAVERICK_MAX_INBOUND_CHARS", "chat", "max_inbound_chars",
                                 "30000") or "30000")
    except ValueError:
        return 30000


def backoff_delay(base_interval: float, consecutive_errors: int, *, cap: float = 300.0) -> float:
    """Poll-loop sleep after ``consecutive_errors`` consecutive failures.

    No failures -> the normal ``base_interval``. After each consecutive failure
    the delay doubles (base*2, base*4, ...) up to ``cap`` seconds, so a
    persistently failing upstream (API down, token revoked, instance
    unreachable) is polled progressively less often instead of hammered every
    ``base_interval`` -- which otherwise burns CPU, floods the logs, and can get
    the account rate-limited or banned. Callers reset ``consecutive_errors`` to
    0 on the first successful poll, which returns to ``base_interval``."""
    if consecutive_errors <= 0:
        return base_interval
    if base_interval == 0:
        return min(cap, base_interval)
    try:
        delay = math.ldexp(base_interval, consecutive_errors)
    except OverflowError:
        # Even an exponent too large for ldexp has a well-defined limit.
        delay = math.copysign(math.inf, base_interval)
    return min(cap, delay)


def webhook_body_limit() -> int:
    """Max inbound webhook body in bytes. Webhook listeners read the body
    *before* the HMAC/signature check (they must, to compute it), so without a
    cap an unauthenticated POST to an exposed webhook port can buffer arbitrary
    memory. Override with MAVERICK_WEBHOOK_BODY_LIMIT (0 disables the cap), or,
    when that is unset, ``[webhooks] body_limit`` (a positive byte count; the
    All settings page cannot remove the cap). Default 1 MiB -- comfortably
    above any real Slack/Twilio/Meta payload."""
    default = 1 << 20
    env = os.environ.get("MAVERICK_WEBHOOK_BODY_LIMIT")
    if env is not None and env.strip():
        try:
            return int(env)
        except ValueError:
            return default
    try:
        from maverick.config import load_config

        value = ((load_config() or {}).get("webhooks") or {}).get("body_limit")
    except Exception:  # pragma: no cover - config never blocks a listener
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return default
    return value


class BodySizeLimitMiddleware:
    """ASGI middleware that bounds the request body of webhook apps.

    Two layers: reject early with 413 when the Content-Length header exceeds the
    cap (the honest/common case, no buffering), and -- for an absent or lying
    Content-Length -- truncate the streamed body at the cap so the downstream
    parser never buffers more than ``max_bytes`` (a truncated body simply fails
    the signature check -> 403). Applied at the ASGI layer so it covers Form,
    JSON and raw-body handlers uniformly, including FastAPI ``Form(...)`` params
    that are parsed before the route function runs."""

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or self.max_bytes <= 0:
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers") or ():
            if name == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        await _send_413(send)
                        return
                except ValueError:
                    pass
                break
        total = 0
        truncated = False

        async def capped_receive():
            nonlocal total, truncated
            if truncated:
                return {"type": "http.request", "body": b"", "more_body": False}
            msg = await receive()
            if msg.get("type") == "http.request":
                body = msg.get("body", b"")
                if total + len(body) > self.max_bytes:
                    body = body[: max(0, self.max_bytes - total)]
                    truncated = True
                    msg = {"type": "http.request", "body": body, "more_body": False}
                total += len(body)
            return msg

        await self.app(scope, capped_receive, send)


async def _send_413(send) -> None:
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"payload too large"})


def add_webhook_body_limit(app) -> None:
    """Attach :class:`BodySizeLimitMiddleware` to a webhook channel's ASGI app."""
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=webhook_body_limit())


@dataclass
class IncomingMessage:
    user_id: str
    text: str
    attachments: list[dict] = field(default_factory=list)
    channel: str = ""
    raw: object = None
    sender_id: str | None = None
    # First-party provider identifiers retained in the sealed durable intake.
    # These fields alone are never proof; the delivery receipt must also match
    # the currently authenticated app account at execution time.
    provider_tenant_id: str | None = None
    provider_sender_id: str | None = None
    # Platform message id of THIS inbound message, when the platform has one
    # (Slack ts, Telegram message_id, ...). Lets the reply thread onto it via
    # Channel.send_threaded; None on platforms without addressable messages.
    message_id: str | None = None
    # Stable platform thread/topic anchor when it differs from the recipient.
    # Kept in the durable intake so a recovered answer cannot jump threads.
    conversation_ref: str | None = None
    # A room thread reply without a bot mention may answer an open question,
    # but must never create an unrelated goal when none is pending.
    question_reply_only: bool = False

    @property
    def principal_id(self) -> str:
        """Stable end-user identity for auth, history, and tenant scoping.

        ``user_id`` remains the channel reply target for room-based adapters
        (Slack channel, Discord channel, Matrix room). Those adapters set
        ``sender_id`` to the authenticated human sender so per-user server state
        is not accidentally shared by everyone in a room. One-to-one channels
        leave ``sender_id`` unset and continue to use ``user_id`` as before.
        """
        return self.sender_id or self.user_id

    def __post_init__(self) -> None:
        cap = _max_inbound_chars()
        if cap and isinstance(self.text, str) and len(self.text) > cap:
            self.text = self.text[:cap] + "\n\n[...truncated by Lightwork inbound cap]"


Handler = Callable[[IncomingMessage], Awaitable[str]]
"""A handler takes a normalized message and returns the agent's reply.

A handler returns a :class:`Reply` (structured text + attachments + thread
ref). A bare ``str`` return is deprecated (see ``maverick.deprecations``,
``channels.str_handler``) and is still wrapped by :func:`as_reply`; adapters
route results through :meth:`Channel.dispatch` / :meth:`Channel.dispatch_text`
so both forms work everywhere.
"""


@dataclass
class Reply:
    """Structured handler reply.

    ``attachments`` are local file paths the adapter may ship when its
    platform can (adapters without a file API drop them with a debug note —
    the text always goes through). ``thread_ref`` overrides the inbound
    ``message_id`` as the threading anchor for ``send_threaded``.
    """

    text: str
    attachments: list[str] = field(default_factory=list)
    thread_ref: str | None = None


def as_reply(result: Reply | str) -> Reply:
    """Normalize a handler result to :class:`Reply`.

    A bare ``str`` is the deprecated form; it is wrapped into a text-only
    Reply until its removal version in ``maverick.deprecations``.
    """
    if isinstance(result, Reply):
        return result
    try:
        from maverick.deprecations import warn_once
        warn_once("channels.str_handler")
    except Exception:  # the kernel may be absent in a channels-only install
        pass
    return Reply(text="" if result is None else str(result))


class Channel(ABC):
    """Abstract channel adapter.

    Lifecycle:
      - ``start()`` blocks (or runs in background) accepting messages.
      - For each message it dispatches to the registered ``Handler``.
      - ``send(user_id, text)`` pushes a reply back to that user.
      - ``stop()`` cleans up.
    """

    name: str

    def __init__(self, handler: Handler):
        self.handler = handler

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def send(self, user_id: str, text: str) -> None: ...

    async def dispatch(self, msg: IncomingMessage) -> Reply:
        """Run the handler and normalize its result to a :class:`Reply`.

        The SDK v2 entry point: handlers may return ``Reply`` or (shimmed)
        bare ``str``. Adapters that can ship files consume
        ``reply.attachments``; ones that can't use :meth:`dispatch_text`.
        """
        return as_reply(await self.handler(msg))

    async def dispatch_text(self, msg: IncomingMessage) -> str:
        """Run the handler and return just the reply text.

        For adapters with no platform file API: structured attachments are
        dropped with a debug note (the text always goes through), so a v2
        handler works unchanged on every adapter.
        """
        reply = await self.dispatch(msg)
        if reply.attachments:
            logging.getLogger(__name__).debug(
                "channel %s has no file API; dropping %d attachment(s)",
                getattr(self, "name", "?"), len(reply.attachments),
            )
        return reply.text

    async def admit_message(self, msg: IncomingMessage, **kwargs):
        """Persist an authorized inbound message before acknowledging intake."""
        from .delivery import admit_message

        return await admit_message(msg, **kwargs)

    async def process_message(self, msg: IncomingMessage, **kwargs):
        """Execute once and deliver only the durable saved reply on retry."""
        from .delivery import process_message

        return await process_message(self, msg, **kwargs)

    async def recover_messages(self, **kwargs):
        """Recover a bounded fair window under adapter-owned current policy."""
        from .delivery import recover_messages

        return await recover_messages(self, **kwargs)

    def recovery_worker(self, **kwargs):
        """Own a periodic recovery task for the surrounding transport lifetime."""
        from .delivery import recovery_worker

        return recovery_worker(self, **kwargs)

    async def send_threaded(
        self, user_id: str, text: str, *, reply_to: str | None = None,
    ) -> None:
        """Send a reply threaded onto ``reply_to`` (a platform message id).

        Default: ignore the thread reference and fall back to a plain
        ``send`` — adapters whose platform supports threading (Slack
        ``thread_ts``, Telegram ``reply_to_message_id``) override this. The
        caller passes ``IncomingMessage.message_id`` so long-running results
        land under the message that asked for them instead of interleaving
        into a busy room.
        """
        await self.send(user_id, text)

    @abstractmethod
    async def stop(self) -> None: ...
