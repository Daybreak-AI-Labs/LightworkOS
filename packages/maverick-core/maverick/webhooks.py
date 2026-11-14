"""Outbound webhooks for run events.

Users configure a list of webhook endpoints in ``~/.maverick/config.toml``:

    [webhooks]
    outbound = [
        "https://example.com/maverick-hook",
        "https://hooks.zapier.com/...",
    ]
    secret = "${MAVERICK_WEBHOOK_SECRET}"    # optional HMAC signing

When set, the kernel fires:
  - goal_created       (goal_id, title)
  - goal_finished      (goal_id, status, result), or for a gated unapproved
                       deliverable (goal_id, status, gate, release_status)
  - episode_finished   (goal_id, episode_id, outcome, cost_dollars)
  - final_emitted      (goal_id, patch_size_bytes)

Record events (``dsar.*``, ``incident.*``, ``assessment.*``, ``vendor.*``,
``approval.*``, ``policy.*``; see :mod:`maverick.webhook_events`) use the
same dispatcher. Since subscriptions became records
(:mod:`maverick.webhook_subscriptions`) the config list above is the *legacy
default subscription*: it still receives every event, and every delivery --
to it or to a saved subscription -- is logged and retried.

The HTTP POST body is the JSON envelope from :func:`build_envelope`
(documented in docs/webhooks.md); if ``secret`` is set, an HMAC-SHA256
signature over ``"<timestamp>." + body`` is sent in the
``X-Lightwork-Signature`` header with the timestamp in ``X-Lightwork-Timestamp``.
The original ``X-Maverick-*`` headers carry the same values for existing clients.

Webhook failures are logged but never block the run.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from collections.abc import Mapping
from contextvars import copy_context
from typing import Any

log = logging.getLogger(__name__)


_thread_lock = threading.Lock()
_executor = None  # type: ignore[var-annotated]
_inflight = None  # type: ignore[var-annotated]  # BoundedSemaphore: queue backpressure


def _pool_size() -> int:
    """Webhook dispatch worker count. ``[webhooks] workers`` /
    ``MAVERICK_WEBHOOK_WORKERS`` (default 4)."""
    env = os.environ.get("MAVERICK_WEBHOOK_WORKERS")
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    try:
        from .config import load_config
        val = ((load_config() or {}).get("webhooks") or {}).get("workers")
        if val is not None:
            return max(1, int(val))
    except Exception:
        pass
    return 4


def _max_inflight() -> int:
    """Cap on queued+running dispatches. ``[webhooks] max_inflight`` /
    ``MAVERICK_WEBHOOK_MAX_INFLIGHT`` (default 16x the worker count). Bounds
    memory: ThreadPoolExecutor's work queue is otherwise unbounded, so a slow
    or hung receiver during a burst backs tasks up in RAM without limit."""
    env = os.environ.get("MAVERICK_WEBHOOK_MAX_INFLIGHT")
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    try:
        from .config import load_config
        val = ((load_config() or {}).get("webhooks") or {}).get("max_inflight")
        if val is not None:
            return max(1, int(val))
    except Exception:
        pass
    return max(16, _pool_size() * 16)


def _expand_env(val: object) -> str | None:
    """Reject unresolved references; operator config expands them centrally."""
    if not isinstance(val, str):
        return str(val) if val is not None else None
    if val.startswith("${") and val.endswith("}"):
        log.warning("webhooks: unresolved configuration reference; refusing the value")
        return None
    return val or None


def _load_config_outbound() -> tuple[list[str], str | None]:
    try:
        from .config import load_config
        cfg = load_config()
    except Exception as e:
        log.debug("webhooks: cannot load config: %s", e)
        return [], None
    section = (cfg or {}).get("webhooks") or {}
    raw = section.get("outbound") or []
    # A single URL written as a string must not be split into characters.
    if isinstance(raw, str):
        raw = [raw]
    urls = [u for u in raw if isinstance(u, str) and u.strip()] if isinstance(raw, (list, tuple)) else []
    from .secret_provider import get_secret
    secret = get_secret("MAVERICK_WEBHOOK_SECRET") or _expand_env(section.get("secret"))
    return urls, secret


def _sign(body: bytes, secret: str, *, timestamp: str | None = None) -> str:
    """HMAC-SHA256 of the request body, optionally binding a timestamp.

    When ``timestamp`` is given it is prepended to the signed material
    (``"<ts>.".encode() + body``). This is the Lightwork-CONTROLLED replay
    defence: the sender sends the same ``timestamp`` in an ``X-Lightwork-
    Timestamp`` header, so a captured request can't be replayed past the
    freshness window without breaking the signature. Body-only signing
    (``timestamp=None``) is preserved for the existing receiver round-trip.
    """
    mac = hmac.new(secret.encode("utf-8"), _signed_material(body, timestamp),
                   hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _signed_material(body: bytes, timestamp: str | None) -> bytes:
    if timestamp is None:
        return body
    return f"{timestamp}.".encode() + body


def _default_max_age() -> int:
    """Replay window (seconds) for Lightwork-signed inbound webhooks.

    Config knob: ``[webhooks] max_age_seconds`` in config.toml, overridable by
    ``MAVERICK_WEBHOOK_MAX_AGE_SECONDS``. Defaults to 300s (5 min)."""
    env = os.environ.get("MAVERICK_WEBHOOK_MAX_AGE_SECONDS")
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    try:
        from .config import load_config
        section = (load_config() or {}).get("webhooks") or {}
        val = section.get("max_age_seconds")
        if val is not None:
            return max(1, int(val))
    except Exception:
        pass
    return 300


def _get_executor():
    """Lazy-init the dispatch threadpool + its in-flight backpressure
    semaphore. Daemon threads so we don't block process exit."""
    global _executor, _inflight
    with _thread_lock:
        if _executor is None:
            from concurrent.futures import ThreadPoolExecutor
            _executor = ThreadPoolExecutor(
                max_workers=_pool_size(), thread_name_prefix="mvk-webhook",
            )
            _inflight = threading.BoundedSemaphore(_max_inflight())
    return _executor


def _submit(executor, fn, *args) -> bool:
    """Submit ``fn(*args)`` to the pool unless the in-flight cap is reached.
    Returns False (drop + caller logs) on overflow so a burst against a slow
    receiver can't grow the work queue without bound."""
    sem = _inflight  # capture: a reset must not make us release a different one
    if not sem.acquire(blocking=False):
        return False
    context = copy_context()

    def _runner():
        try:
            context.run(fn, *args)
        finally:
            sem.release()

    try:
        executor.submit(_runner)
        return True
    except Exception:
        sem.release()
        raise


class NotSent(str):
    """The ``error`` of a failed send that provably never reached the receiver
    (nothing connected). The delivery log retries it on its backoff; any other
    failure with no status code may have been received and is not repeated."""


def _post_result(url: str, body: bytes, headers: dict[str, str],
                 timeout: float) -> tuple[int | None, int, str, str]:
    """POST through the SSRF guard and report ``(status_code, latency_ms,
    response_snippet, error)`` -- the delivery log's raw material. A blocked
    host, a missing client or a transport failure gives ``status_code=None``
    and a short error (a :class:`NotSent` one when nothing was sent); nothing
    here raises."""
    from .secrets import scrub
    # Outbound webhook URLs frequently carry credentials in the query string
    # (?token=, ?api_key=, presigned ?sig=); scrub before logging so they don't
    # land in the default-level logs / log aggregator verbatim.
    safe_url = scrub(url)
    try:
        import httpx  # noqa: F401  (presence check; client built via _ssrf)
    except ImportError:
        log.warning("webhooks: httpx not installed; skipping %s", safe_url)
        return None, 0, "", NotSent("httpx is not installed")
    # Route through the SSRF guard: an outbound URL comes from user config, but
    # a config that points at a loopback/metadata/internal host would let the
    # webhook dispatcher be used as an SSRF proxy. safe_client resolves once,
    # rejects any non-public address, and pins the connection (no rebind).
    try:
        from .tools._ssrf import BlockedHost, safe_client
    except Exception:  # pragma: no cover - guard unavailable
        return None, 0, "", NotSent("SSRF guard unavailable")
    try:
        client = safe_client(url, timeout=timeout)
    except BlockedHost as e:
        log.warning("webhooks: %s blocked (SSRF guard): %s", safe_url, e)
        return None, 0, "", NotSent(f"blocked by the address guard: {scrub(str(e))[:120]}")
    started = time.monotonic()
    try:
        with client:
            resp = client.post(url, content=body, headers=headers)
        latency = int((time.monotonic() - started) * 1000)
        snippet = scrub(resp.text[:200])
        if resp.status_code >= 400:
            log.warning("webhooks: %s returned %d: %s", safe_url, resp.status_code, snippet)
            return resp.status_code, latency, snippet, f"HTTP {resp.status_code}"
        return resp.status_code, latency, snippet, ""
    except Exception as e:
        latency = int((time.monotonic() - started) * 1000)
        log.warning("webhooks: %s failed: %s: %s", safe_url, type(e).__name__, scrub(str(e)))
        from .notifications import never_sent

        error = f"{type(e).__name__}: {scrub(str(e))[:120]}"
        return None, latency, "", NotSent(error) if never_sent(e) else error


def _post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> None:
    _post_result(url, body, headers, timeout)


def build_envelope(
    event: str,
    payload: dict[str, Any],
    *,
    record: dict[str, Any] | None = None,
    link: str = "",
    occurred_at: float | None = None,
    event_id: str | None = None,
    workspace: str | None = None,
) -> dict[str, Any]:
    """The JSON body every outbound webhook carries (documented in
    docs/webhooks.md). ``v``/``event``/``ts``/``payload`` are the original
    fields, kept as they were; ``id``, ``type``, ``occurred_at``,
    ``workspace``, ``record`` and ``link`` were added for record events."""
    import uuid

    when = time.time() if occurred_at is None else float(occurred_at)
    if workspace is None:
        try:
            from .paths import current_tenant_id
            workspace = current_tenant_id() or ""
        except Exception:
            workspace = ""
    return {
        "v": 1,
        "id": event_id or ("evt_" + uuid.uuid4().hex),
        "event": event,
        "type": event,
        "ts": when,
        "occurred_at": when,
        "workspace": workspace,
        "record": dict(record) if record else None,
        "link": link or "",
        "payload": payload,
    }


def encode_body(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope, default=str).encode("utf-8")


def read_signature_headers(headers: Mapping[str, str]) -> tuple[str, str]:
    """Read Lightwork or legacy authentication headers without ambiguity.

    Matching aliases (including repeated header fields) are compatible. Any
    conflicting signature or timestamp is refused before authentication, so a
    caller cannot silently choose a different signed request interpretation.
    """
    observed: dict[str, str] = {}
    accepted = {
        "x-lightwork-signature", "x-maverick-signature",
        "x-lightwork-timestamp", "x-maverick-timestamp",
    }
    for key, value in headers.items():
        name = key.lower()
        if name not in accepted:
            continue
        if name in observed and observed[name] != value:
            raise ValueError("Conflicting webhook authentication headers.")
        observed[name] = value
    values = []
    for field in ("signature", "timestamp"):
        current = observed.get(f"x-lightwork-{field}")
        legacy = observed.get(f"x-maverick-{field}")
        if current is not None and legacy is not None and current != legacy:
            raise ValueError("Conflicting webhook authentication headers.")
        values.append(current if current is not None else legacy or "")
    return values[0], values[1]


def build_headers(body: bytes, event: str, secret: str | None, *,
                  event_id: str | None = None) -> dict[str, str]:
    """Request headers for one attempt. The signature binds a fresh timestamp
    each time (see :func:`_sign`), so a retried delivery carries a signature
    that passes the same freshness check as a first attempt."""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Lightwork-Webhook/1.0",
        "X-Lightwork-Event": event,
        "X-Maverick-Event": event,
    }
    if event_id:
        headers["X-Lightwork-Delivery"] = event_id
        headers["X-Maverick-Delivery"] = event_id
    if secret:
        # Bind a timestamp into the signature so a receiver enforcing a max-age
        # (see verify_signature) can reject a replayed capture. The timestamp is
        # sent alongside in X-Lightwork-Timestamp and is part of the signed
        # material -- it can't be altered without breaking the HMAC.
        ts = str(int(time.time()))
        signature = _sign(body, secret, timestamp=ts)
        headers["X-Lightwork-Timestamp"] = ts
        headers["X-Maverick-Timestamp"] = ts
        headers["X-Lightwork-Signature"] = signature
        headers["X-Maverick-Signature"] = signature
    return headers


def _subscriptions_enabled() -> bool:
    """``[webhooks] subscriptions = false`` returns to one-shot config-list
    dispatch with no delivery log (also ``MAVERICK_WEBHOOK_SUBSCRIPTIONS=0``)."""
    env = os.environ.get("MAVERICK_WEBHOOK_SUBSCRIPTIONS", "").strip().lower()
    if env:
        return env not in ("0", "false", "no", "off")
    try:
        from .config import load_config
        val = ((load_config() or {}).get("webhooks") or {}).get("subscriptions")
        if val is not None:
            return bool(val)
    except Exception:
        pass
    return True


def _fire_subscriptions(event: str, envelope: dict[str, Any], body: bytes,
                        world: Any) -> int | None:
    """Record + start deliveries through the subscription store. ``None`` means
    the store was unavailable and the caller should fall back to the one-shot
    config-list path."""
    from . import webhook_subscriptions as subs
    executor = _get_executor()

    def _start(delivery_id: str) -> None:
        # The delivery is already recorded: a submit failure (the pool is
        # shutting down) leaves it for the retry pump, never for the one-shot
        # fallback below, which would send it a second time.
        try:
            started = _submit(executor, subs.attempt_delivery, delivery_id)
        except Exception as exc:
            log.warning("webhooks: could not start delivery %s (%s); it waits for the retry pump",
                        delivery_id, type(exc).__name__)
            return
        if not started:
            log.warning("webhooks: in-flight cap reached; delivery %s waits for the retry pump",
                        delivery_id)

    try:
        return subs.dispatch(event, envelope, body, world=world, submit=_start)
    except Exception as exc:
        log.warning("webhooks: subscription store unavailable (%s); sending once to the "
                    "configured list", type(exc).__name__)
        return None


def fire(
    event: str,
    payload: dict[str, Any],
    *,
    urls: list[str] | None = None,
    secret: str | None = None,
    timeout: float = 5.0,
    record: dict[str, Any] | None = None,
    link: str = "",
    occurred_at: float | None = None,
    world: Any = None,
) -> int:
    """Dispatch ``event`` to every subscriber.

    With ``urls`` given explicitly (the deliverable hand-off, tests) the body is
    posted once to each address, as before. Otherwise the event goes through
    :mod:`maverick.webhook_subscriptions`: every enabled subscription whose
    filter matches, plus the legacy ``[webhooks] outbound`` list, gets a logged,
    retried delivery. Returns the number of deliveries started; 0 when nobody
    is subscribed (silent no-op for users who haven't opted in).
    """
    from . import practice

    if practice.active():  # practice mode: recorded (when someone would get it), never posted
        targets = list(urls) if urls is not None else list(_load_config_outbound()[0] or [])
        if targets:
            practice.record("webhook", event, {"addresses": len(targets)})
        return 0
    envelope = build_envelope(event, payload, record=record, link=link, occurred_at=occurred_at)
    # Serialize defensively: fire() promises never to raise into the run
    # loop, so a non-serializable payload must degrade to a no-op, not
    # crash the caller.
    try:
        body = encode_body(envelope)
    except (TypeError, ValueError) as e:
        log.warning("webhook: payload not serializable, skipping: %s", e)
        return 0
    if urls is None and secret is None:
        if _subscriptions_enabled():
            sent = _fire_subscriptions(event, envelope, body, world)
            if sent is not None:
                return sent
        urls, secret = _load_config_outbound()
    if not urls:
        return 0
    if secret and not separate_webhook_credential(secret, "outbound"):
        log.warning("webhooks: refusing to send with a secret shared with an inbound credential")
        return 0
    headers = build_headers(body, event, secret, event_id=envelope["id"])

    # Enterprise egress lock: outbound webhooks are off-box data egress just like
    # a tool fetch, so hold them to the SAME boundary (default-deny unless the
    # host is in [enterprise] allowed_hosts). No-op when enterprise mode is off
    # (egress_permitted returns True), so existing webhook setups are unchanged.
    from .enterprise import enterprise_egress_denial
    executor = _get_executor()
    sent = 0
    for url in urls:
        deny = enterprise_egress_denial(url, tool="webhook")
        if deny is not None:
            log.warning("webhooks: %s", deny)  # host-only message; audits egress_blocked
            continue
        if _submit(executor, _post, url, body, dict(headers), timeout):
            sent += 1
        else:
            from .secrets import scrub
            log.warning("webhooks: in-flight cap reached; dropping dispatch to %s",
                        scrub(url))
    return sent


def _load_handoff_target() -> tuple[str | None, str | None]:
    """The deliverable hand-off target: ``([deliverables] handoff_webhook, secret)``.

    The URL may be a literal or a ``${VAR}`` env reference; signing reuses the
    existing ``[webhooks] secret`` so a deployment configures one signing key.
    Returns ``(None, ...)`` when no hand-off endpoint is configured."""
    try:
        from .config import load_config
        cfg = load_config() or {}
    except Exception as e:  # pragma: no cover -- config never blocks the hand-off
        log.debug("webhooks: cannot load config for hand-off: %s", e)
        return None, None
    url = _expand_env((cfg.get("deliverables") or {}).get("handoff_webhook"))
    _, secret = _load_config_outbound()
    return url, secret


def fire_deliverable_handoff(payload: dict[str, Any]) -> int:
    """Push an approved deliverable to the configured system-of-record endpoint.

    A thin wrapper over :func:`fire` for the ``deliverable.approved`` event,
    routed to ``[deliverables] handoff_webhook``. Silent no-op (returns 0) when
    no endpoint is configured, and -- like ``fire`` -- never raises into the
    caller, so a sign-off is recorded whether or not the hand-off is wired."""
    url, secret = _load_handoff_target()
    if not url:
        return 0
    return fire("deliverable.approved", payload, urls=[url], secret=secret)


def verify_signature(
    body: bytes,
    signature: str,
    secret: str,
    *,
    timestamp: str | None = None,
    max_age: int | None = None,
) -> bool:
    """Verify an inbound webhook signature (mirror of _sign()).

    Useful for receivers building on Lightwork's webhook format.

    When ``timestamp`` is supplied the signature must cover that timestamp
    (replay defence for the Lightwork-CONTROLLED format) AND the timestamp must
    be within ``max_age`` seconds of now -- a captured-but-stale request is
    rejected even though its HMAC is otherwise valid. ``max_age`` defaults to
    ``_default_max_age()``. With ``timestamp=None`` this is the original
    body-only check, unchanged.
    """
    if not signature or not signature.startswith("sha256="):
        return False
    if timestamp is not None:
        if not _timestamp_fresh(timestamp, max_age):
            return False
    expected = _sign(body, secret, timestamp=timestamp)
    return hmac.compare_digest(signature.encode(), expected.encode())


def _timestamp_fresh(timestamp: str, max_age: int | None) -> bool:
    """True if ``timestamp`` (unix seconds) is within the replay window."""
    try:
        ts = float(timestamp)
    except (TypeError, ValueError):
        return False
    window = _default_max_age() if max_age is None else max_age
    # Reject both stale (replayed) and far-future (clock-skew abuse) stamps.
    return abs(time.time() - ts) <= window


def inbound_secret() -> str | None:
    """Resolve the dedicated inbound control-plane HMAC secret."""
    from .secret_provider import get_secret  # vault-mountable secret
    return get_secret("MAVERICK_INBOUND_WEBHOOK_SECRET") or None


def separate_webhook_credential(value: str | None, purpose: str) -> bool:
    """Reject credentials shared with another externally exposed trust domain."""
    if not value:
        return False
    from .github_app import webhook_secret as github_webhook_secret
    from .issue_webhooks import gitlab_webhook_token
    from .secret_provider import get_secret

    credentials = {
        "control": inbound_secret(),
        "outbound": _load_config_outbound()[1],
        "approval": get_secret("MAVERICK_FLOW_APPROVAL_SECRET"),
        "linear": get_secret("MAVERICK_LINEAR_WEBHOOK_SECRET"),
        "jira": get_secret("MAVERICK_JIRA_WEBHOOK_SECRET"),
        "gitlab": gitlab_webhook_token(),
        "github": github_webhook_secret(),
    }
    if purpose not in credentials:
        return False
    candidate = value.encode("utf-8")
    return not any(other and hmac.compare_digest(candidate, other.encode("utf-8"))
                   for name, other in credentials.items() if name != purpose)


def issue_webhook_secret(provider: str) -> str | None:
    """Resolve a provider-specific secret; never fall back to the control key."""
    from .secret_provider import get_secret
    if provider not in {"linear", "jira"}:
        return None
    secret = get_secret(f"MAVERICK_{provider.upper()}_WEBHOOK_SECRET")
    return secret if separate_webhook_credential(secret, provider) else None


__all__ = ["build_envelope", "build_headers", "encode_body", "fire",
           "verify_signature", "inbound_secret", "read_signature_headers"]
