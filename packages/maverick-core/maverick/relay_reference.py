"""Self-hosted relay reference.

A reference implementation of a self-hostable relay that fronts inbound
requests from an external device or client and forwards work to Lightwork. It
ships as framework-agnostic *logic* you run as a small local/edge service OR a
Worker (see ``docs/self-hosted-relay.md``).

The relay's whole job is the **quick-vs-ack-then-run split** for a client that
waits only a short, fixed time for a reply (30 s by default):

  * **Quick query** (a fact, short chat) -> proxied synchronously to the agent
    and answered inside the deadline.
  * **Long task** (``write.*code | research | deploy ...``) -> answered
    *immediately* with an ack ("Got it! ... result will be sent to Telegram"),
    forwarded to the existing inbound ``POST /webhook/start`` to run in the
    background, and the full result later delivered to a **secondary channel**
    (Telegram) via the outbound webhook seam.

Everything here is pure logic with **injected transport** so it unit-tests with
no server, no network, no agent:

  * ``classify_request`` -- regex-configurable QUICK vs ACK_THEN_RUN decision.
  * ``RelayConfig`` -- the deadline, the long-task pattern, the start URL, the
    secondary-channel target, and an optional HMAC secret.
  * ``Relay`` -- orchestrates: it takes an injected ``sync_handler`` (drives the
    agent for quick queries), ``starter`` (POSTs to ``/webhook/start``), and
    ``deliver`` (the outbound-webhook secondary-channel seam). It enforces the
    deadline on the sync path and falls back to an ack if the agent is slow.

The real wiring (FastAPI route, ``httpx`` POST, ``maverick.webhooks.fire`` for
delivery) lives at the edges and is the caller's to plug in; the doc shows both
the Worker and the local-service shapes.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)


class RequestKind(str, Enum):
    """How the relay should handle an inbound request."""

    QUICK = "quick"            # answer synchronously within the deadline
    ACK_THEN_RUN = "ack_then_run"  # ack now, run in background, deliver later


# The default long-task trigger: verbs that imply work that won't finish inside
# a 30 s device budget. Operators override via ``RelayConfig.long_task_pattern``.
DEFAULT_LONG_TASK_PATTERN = r"\b(write|build|create|research|deploy|refactor|generate|analy[sz]e|implement)\b"


@dataclass(frozen=True)
class RelayConfig:
    """Relay policy. All transport/IO is injected into ``Relay``, not here.

    ``deadline_seconds`` is the client's reply deadline. ``long_task_pattern``
    is the configurable regex that classifies a message as a long task. The
    pattern is matched case-insensitively against the message text.
    """

    deadline_seconds: float = 30.0
    long_task_pattern: str = DEFAULT_LONG_TASK_PATTERN
    start_url: str = "http://localhost:8080/webhook/start"
    secondary_channel: str = "telegram"
    ack_template: str = "Got it! Working on it — the result will be sent to {channel}."
    hmac_secret: str | None = None
    inbound_auth_token: str | None = None
    require_inbound_auth: bool = True

    def compiled_pattern(self) -> re.Pattern:
        return re.compile(self.long_task_pattern, re.IGNORECASE)


@dataclass
class RelayResponse:
    """What the relay returns to the device or client for one inbound request.

    ``immediate`` is the text to show the caller right now (either the quick
    answer, or the ack for a long task). ``kind`` records the branch taken.
    ``started`` is True iff a background run was kicked off. ``error`` carries a
    fail-open message when transport raised (the device still gets a reply).
    """

    kind: RequestKind
    immediate: str
    started: bool = False
    meta: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def classify_request(text: str, config: RelayConfig | None = None) -> RequestKind:
    """QUICK vs ACK_THEN_RUN by the configured long-task regex.

    An empty/whitespace message is QUICK (there's nothing long to run). Matching
    is a ``search`` so the trigger verb can appear anywhere in the message.
    """
    cfg = config or RelayConfig()
    if not text or not text.strip():
        return RequestKind.QUICK
    return RequestKind.ACK_THEN_RUN if cfg.compiled_pattern().search(text) else RequestKind.QUICK


def sign_body(body: bytes, secret: str, *, timestamp: str | None = None) -> tuple[str, str | None]:
    """HMAC-SHA256 over the (optionally timestamp-bound) body.

    Mirrors ``maverick.webhooks._sign`` so the relay's forward to
    ``/webhook/start`` carries a signature the existing inbound receiver
    already knows how to verify. Returns ``(signature, timestamp)``.
    """
    ts = timestamp if timestamp is not None else str(int(time.time()))
    material = f"{ts}.".encode() + body
    mac = hmac.new(secret.encode("utf-8"), material, hashlib.sha256)
    return "sha256=" + mac.hexdigest(), ts


# Injected transport seams. Each is pure-ish from the relay's POV:
#   * SyncHandler answers a quick query (drives the agent), returning text. It
#     MAY block; the relay races it against the deadline.
#   * Starter POSTs the task to /webhook/start, returning a run handle/dict.
#   * Deliver pushes a finished result to the secondary channel (the outbound
#     webhook seam), returning anything (ignored).
SyncHandler = Callable[[str], str]
Starter = Callable[..., dict[str, Any]]
Deliver = Callable[..., Any]


@dataclass
class Relay:
    """The relay core. Holds policy + injected transport; no global IO.

    ``now`` is injectable so deadline logic is testable without real clocks.
    """

    config: RelayConfig
    sync_handler: SyncHandler
    starter: Starter
    deliver: Deliver
    now: Callable[[], float] = time.monotonic

    def handle(
        self, text: str, *, context: dict[str, Any] | None = None, auth_token: str | None = None
    ) -> RelayResponse:
        """Route one authenticated inbound request through the quick-vs-ack-then-run split."""
        context = context or {}
        if self.config.require_inbound_auth and not self.verify_inbound_token(auth_token):
            return RelayResponse(
                kind=RequestKind.QUICK,
                immediate="Unauthorized relay request.",
                error="unauthorized inbound relay request",
            )
        kind = classify_request(text, self.config)
        if kind is RequestKind.QUICK:
            return self._handle_quick(text, context)
        return self._start_background(text, context)

    def verify_inbound_token(self, auth_token: str | None) -> bool:
        """Return True when the caller supplied the configured inbound relay token.

        The relay signs outbound starts with ``hmac_secret``. This separate
        token authenticates the device/user to the relay before any quick work
        or signed background start can be triggered.
        """
        expected = self.config.inbound_auth_token
        if not expected or not auth_token:
            return False
        return hmac.compare_digest(auth_token.encode(), expected.encode())

    # -- quick path -----------------------------------------------------------

    def _handle_quick(self, text: str, context: dict[str, Any]) -> RelayResponse:
        """Answer synchronously, but bail to an ack if we blow the deadline.

        The sync handler may run long; we measure wall time around it and, if it
        overran the device budget, DOWNGRADE to ack-then-run (kick off a
        background run and deliver later) rather than returning a stale answer
        the device may have already timed out waiting for.
        """
        start = self.now()
        try:
            answer = self.sync_handler(text)
        except Exception as e:  # the device must always get a reply
            log.warning("relay: sync handler failed: %s", e)
            return self._start_background(
                text, context, reason=f"sync handler error: {type(e).__name__}",
            )
        elapsed = self.now() - start
        if elapsed > self.config.deadline_seconds:
            log.info("relay: quick path overran deadline (%.1fs); downgrading to ack-then-run", elapsed)
            return self._start_background(text, context, reason="deadline exceeded on sync path")
        return RelayResponse(
            kind=RequestKind.QUICK,
            immediate=answer,
            meta={"elapsed_seconds": round(elapsed, 3)},
        )

    # -- ack-then-run path ----------------------------------------------------

    def _start_background(
        self, text: str, context: dict[str, Any], *, reason: str | None = None
    ) -> RelayResponse:
        """Ack immediately, forward to /webhook/start, arrange later delivery.

        The ack is returned to the device first-thing. The background start is
        best-effort: if ``starter`` raises, we STILL return the ack (fail-open)
        but mark ``started=False`` + an error, because the device has already
        been told "working on it" and a thrown exception there would otherwise
        surface as a 500 to a user who got no reply.
        """
        ack = self.config.ack_template.format(channel=self.config.secondary_channel)
        # Protected keys are set AFTER the context spread so inbound data can
        # never override them. Spreading `context` last would let a context
        # carrying `deliver_to`/`goal` overwrite them -- letting inbound request
        # data redirect a finished long-task result to an attacker-chosen channel
        # or decouple the acked goal from what runs.
        _protected = ("goal", "deliver_to", "source")
        payload = {
            **{k: v for k, v in context.items() if k not in _protected},
            "goal": text,
            "deliver_to": self.config.secondary_channel,
            "source": context.get("source", "relay"),
        }
        meta: dict[str, Any] = {"deliver_to": self.config.secondary_channel}
        if reason:
            meta["downgrade_reason"] = reason
        try:
            handle = self.starter(self.config.start_url, payload, secret=self.config.hmac_secret)
        except Exception as e:
            log.warning("relay: failed to start background run: %s", e)
            return RelayResponse(
                kind=RequestKind.ACK_THEN_RUN,
                immediate=ack,
                started=False,
                meta=meta,
                error=f"start failed: {type(e).__name__}",
            )
        if isinstance(handle, dict):
            meta.update({k: handle[k] for k in ("run_id", "goal_id") if k in handle})
        return RelayResponse(
            kind=RequestKind.ACK_THEN_RUN,
            immediate=ack,
            started=True,
            meta=meta,
        )

    def deliver_result(self, result: str, *, context: dict[str, Any] | None = None) -> bool:
        """Push a finished long-task ``result`` to the secondary channel.

        Called by the background run (or its completion webhook) once the task
        finishes. Delegates to the injected ``deliver`` seam (in production:
        ``maverick.webhooks.fire`` -> Telegram). Returns False (never raises) if
        delivery fails, so a delivery hiccup doesn't crash the completion path.
        """
        context = context or {}
        try:
            self.deliver(self.config.secondary_channel, result, context=context)
            return True
        except Exception as e:
            log.warning("relay: failed to deliver result to %s: %s", self.config.secondary_channel, e)
            return False


def build_start_request(
    payload: dict[str, Any], config: RelayConfig, *, encoder: Callable[[dict], bytes] | None = None
) -> tuple[bytes, dict[str, str]]:
    """Build the body + headers for the forward to ``POST /webhook/start``.

    A helper for the real ``starter``: serializes ``payload`` and, when a
    secret is configured, attaches ``X-Lightwork-Signature`` /
    ``X-Lightwork-Timestamp`` and identical legacy aliases, as expected on the
    receiving end. ``encoder`` defaults to compact JSON; injected so a caller
    can pin serialization for signing.
    """
    if encoder is None:
        import json

        def encoder(obj: dict) -> bytes:
            return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

    body = encoder(payload)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Lightwork-Relay/1.0",
    }
    if config.hmac_secret:
        signature, ts = sign_body(body, config.hmac_secret)
        headers["X-Lightwork-Signature"] = signature
        headers["X-Lightwork-Timestamp"] = ts
        headers["X-Maverick-Signature"] = signature
        headers["X-Maverick-Timestamp"] = ts
    return body, headers


__all__ = [
    "RequestKind",
    "RelayConfig",
    "RelayResponse",
    "Relay",
    "SyncHandler",
    "Starter",
    "Deliver",
    "DEFAULT_LONG_TASK_PATTERN",
    "classify_request",
    "sign_body",
    "build_start_request",
]
