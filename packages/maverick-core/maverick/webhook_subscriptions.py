"""Webhook subscriptions, the delivery log and retries.

A list of addresses in ``[webhooks] outbound`` posts each event once, with
no retry and no record of what was sent. This module keeps that list working
as a *legacy default subscription* and adds:

* **Subscriptions as records** (``webhook_subscriptions`` table): an address,
  an event filter (``*``, ``dsar.*`` or exact names), a signing secret (sealed
  at rest like other sensitive columns), an on/off switch and a description.
* **A delivery log** (``webhook_deliveries`` table): one row per subscription
  per event, with every attempt's status code, latency and a short response
  snippet, and when the next retry is due.
* **Retries with backoff and jitter**: five attempts over about an hour
  (immediately, then after 1, 5, 15 and 40 minutes, each +/-20 %). A delivery
  that is still failing after the last attempt is ``dead`` (dead-letter) and
  stays in the log until someone presses "Retry now".

Signing is unchanged: ``webhooks.build_headers`` computes the same
``X-Maverick-Signature`` / ``X-Maverick-Timestamp`` pair per attempt, so a
receiver that verifies today's format verifies retried deliveries too.

Addresses are checked with the same SSRF guard the dispatcher already uses
(``tools._ssrf``): a subscription can never point at a loopback, link-local or
private address. Every mutation is written to the audit log first.
"""
from __future__ import annotations

import functools
import json
import logging
import random
import time
import uuid
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

# Seconds to wait before retry N (attempt N+1); the first attempt is immediate.
RETRY_DELAYS: tuple[int, ...] = (60, 300, 900, 2400)
MAX_ATTEMPTS = len(RETRY_DELAYS) + 1
JITTER = 0.2
RESPONSE_SNIPPET_CHARS = 200
LEGACY_SUBSCRIPTION_ID = "legacy-config"
STATUSES = ("pending", "sending", "unknown", "delivered", "dead")
_MAX_URL = 2048
_MAX_DESCRIPTION = 500
_MAX_EVENTS = 64
_MAX_SECRET = 4096

SQLITE_SCHEMA: list[str] = [
    "CREATE TABLE IF NOT EXISTS webhook_subscriptions ("
    " id TEXT PRIMARY KEY, workspace TEXT NOT NULL DEFAULT '',"
    " url TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',"
    " events TEXT NOT NULL DEFAULT '*', secret TEXT NOT NULL DEFAULT '',"
    " enabled INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL DEFAULT '',"
    " created_at REAL NOT NULL, updated_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS webhook_deliveries ("
    " id TEXT PRIMARY KEY, workspace TEXT NOT NULL DEFAULT '',"
    " subscription_id TEXT NOT NULL, event_id TEXT NOT NULL,"
    " event_type TEXT NOT NULL, url TEXT NOT NULL, body TEXT NOT NULL,"
    " status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,"
    " last_status_code INTEGER, last_latency_ms INTEGER,"
    " last_response TEXT NOT NULL DEFAULT '', last_error TEXT NOT NULL DEFAULT '',"
    " attempt_log TEXT NOT NULL DEFAULT '[]', next_attempt_at REAL,"
    " created_at REAL NOT NULL, updated_at REAL NOT NULL, delivered_at REAL)",
    "CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due"
    " ON webhook_deliveries(status, next_attempt_at)",
    "CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_sub"
    " ON webhook_deliveries(subscription_id, created_at DESC)",
]
POSTGRES_SCHEMA: list[str] = [s.replace(" REAL", " DOUBLE PRECISION") for s in SQLITE_SCHEMA]


class SubscriptionError(ValueError):
    """A subscription field was rejected."""


class DeliveryConflict(SubscriptionError):
    """The current original cannot safely be retried."""


class DeliveryUnconfirmed(SubscriptionError):
    """A reserved send's saved outcome could not be confirmed."""


# --------------------------------------------------------------------- store
def _world(world: Any = None) -> Any:
    if world is not None:
        return world
    from .world_model import open_world
    return open_world()


def _with_world(fn):
    """Call ``fn`` with the caller's ``world``, or with one opened for this call
    and closed after it: an unscoped or Postgres ``open_world()`` is a new
    connection every time, so one left open per call accumulates."""
    @functools.wraps(fn)
    def call(*args, world: Any = None, **kwargs):
        if world is not None:
            return fn(*args, world=world, **kwargs)
        from .world_model import close_world_if_owned, open_world

        opened = open_world()
        try:
            return fn(*args, world=opened, **kwargs)
        finally:
            close_world_if_owned(opened)
    return call


def workspace_id() -> str:
    try:
        from .paths import current_tenant_id
        return current_tenant_id() or ""
    except Exception:
        return ""


def _is_sqlite(world: Any) -> bool:
    return hasattr(world, "_writing")


def _cursor_row(cursor: Any, row: Any) -> dict | None:
    if row is None:
        return None
    if hasattr(row, "keys"):
        return dict(row)
    return dict(zip((column.name for column in cursor.description), row, strict=True))


def _rows(world: Any, sql: str, params: tuple = ()) -> list[dict]:
    if not _is_sqlite(world):
        sql = sql.replace("?", "%s")
    if not hasattr(world, "_read_all"):
        with world._tx(snapshot=True) as cursor:
            cursor.execute(sql, params)
            return [_cursor_row(cursor, row) for row in cursor.fetchall()]
    return [dict(r) for r in world._read_all(sql, params)]


def _row(world: Any, sql: str, params: tuple = ()) -> dict | None:
    if not _is_sqlite(world):
        sql = sql.replace("?", "%s")
    if hasattr(world, "_read_one"):
        found = world._read_one(sql, params)
    else:
        with world._tx(snapshot=True) as cursor:
            cursor.execute(sql, params)
            return _cursor_row(cursor, cursor.fetchone())
    return dict(found) if found is not None else None


def _write(world: Any, sql: str, params: tuple = ()) -> None:
    if _is_sqlite(world):
        with world._writing() as conn:
            conn.execute(sql, params)
        return
    with world._tx() as cur:
        cur.execute(sql.replace("?", "%s"), params)


def _write_one(world: Any, sql: str, params: tuple) -> dict | None:
    """Return a conditional write only after its native transaction commits."""
    if _is_sqlite(world):
        with world._writing() as conn:
            row = conn.execute(sql, params).fetchone()
    else:
        with world._tx() as cur:
            cur.execute(sql.replace("?", "%s"), params)
            row = _cursor_row(cur, cur.fetchone())
    return dict(row) if row is not None else None


# ---------------------------------------------------------------- validation
def validate_url(url: object) -> str:
    """An https/http address on a public host, or :class:`SubscriptionError`.

    Reuses the dispatcher's SSRF guard (``tools._ssrf.resolve_pinned_ip``) so
    a saved subscription can never reach an internal address."""
    text = str(url or "").strip()
    if not text or len(text) > _MAX_URL:
        raise SubscriptionError("the address must be between 1 and 2048 characters")
    try:
        parts = urlsplit(text)
        port = parts.port  # a non-numeric or out-of-range port raises ValueError
    except ValueError as exc:
        raise SubscriptionError("the address is not a valid web address") from exc
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise SubscriptionError("the address must start with https:// and name a server")
    if port == 0 or any(c.isspace() or ord(c) < 32 for c in parts.netloc):
        raise SubscriptionError("the address is not a valid web address")
    if parts.username or parts.password:
        raise SubscriptionError("the address must not carry a user name or password")
    try:
        from .tools._ssrf import BlockedHost, resolve_pinned_ip
    except Exception as exc:  # pragma: no cover - guard always ships with the kernel
        raise SubscriptionError("the address could not be checked") from exc
    try:
        resolve_pinned_ip(parts.hostname)
    except BlockedHost as exc:
        raise SubscriptionError(f"the address is not allowed: {exc}") from exc
    except Exception as exc:
        raise SubscriptionError("the address could not be resolved") from exc
    return text


def normalize_events(events: object) -> list[str]:
    """``"*"``, ``["dsar.*", "incident.opened"]`` or a comma list -> clean list."""
    from .webhook_events import EVENT_TYPES

    if events is None or events == "" or events == "*":
        return ["*"]
    if isinstance(events, str):
        items = [e.strip() for e in events.split(",")]
    elif isinstance(events, (list, tuple)):
        items = [str(e).strip() for e in events]
    else:
        raise SubscriptionError("events must be a list of event names")
    out: list[str] = []
    for item in items:
        if not item:
            continue
        if item == "*":
            return ["*"]
        if item.endswith(".*"):
            prefix = item[:-2]
            if not any(t.startswith(prefix + ".") for t in EVENT_TYPES):
                raise SubscriptionError(f"unknown event family: {item}")
        elif item not in EVENT_TYPES:
            raise SubscriptionError(f"unknown event: {item}")
        if item not in out:
            out.append(item)
    if not out:
        return ["*"]
    if len(out) > _MAX_EVENTS:
        raise SubscriptionError(f"at most {_MAX_EVENTS} events per subscription")
    return out


def matches(events: list[str] | str, event_type: str) -> bool:
    """Does a subscription's filter cover ``event_type``?"""
    if isinstance(events, str):
        try:
            events = json.loads(events) if events.startswith("[") else [events]
        except ValueError:
            events = [events]
    for item in events:
        if item == "*" or item == event_type:
            return True
        if item.endswith(".*") and event_type.startswith(item[:-1]):
            return True
    return False


def _audit(action: str, actor: str, **detail: Any) -> None:
    from .audit import audit_event

    audit_event("webhook_subscription_changed", agent="dashboard", action=action,
                actor=actor or "system", **detail)


def _public(row: dict) -> dict:
    from .crypto_at_rest import EncryptionUnavailable
    from .world_model import _UNSEALED_WITHHELD, _dec_field

    out = dict(row)
    secret = out.pop("secret", "")
    try:
        saved_secret = _dec_field(secret)
    except EncryptionUnavailable as exc:
        raise SubscriptionError("The saved signing secret could not be verified. No secret was exposed.") from exc
    if saved_secret == _UNSEALED_WITHHELD:
        raise SubscriptionError("The saved signing secret could not be verified. No secret was exposed.")
    out["secret_set"] = bool(saved_secret)
    out["enabled"] = bool(out.get("enabled"))
    try:
        out["events"] = json.loads(out.get("events") or '["*"]')
    except ValueError:
        out["events"] = ["*"]
    return out


# ------------------------------------------------------------- subscriptions
@_with_world
def create_subscription(
    url: str,
    *,
    events: object = "*",
    secret: str = "",
    description: str = "",
    enabled: bool = True,
    actor: str = "",
    world: Any = None,
    now: float | None = None,
) -> dict:
    from .world_model import _enc_field

    world = _world(world)
    address = validate_url(url)
    filters = normalize_events(events)
    if len(str(secret or "")) > _MAX_SECRET:
        raise SubscriptionError("the secret is too long")
    if secret:
        from .webhooks import separate_webhook_credential
        if not separate_webhook_credential(str(secret), "outbound"):
            raise SubscriptionError("The outbound secret must differ from inbound and approval credentials.")
    stamp = time.time() if now is None else float(now)
    sub_id = "whs_" + uuid.uuid4().hex[:16]
    ws = workspace_id()
    _audit("create", actor, subscription_id=sub_id, host=urlsplit(address).hostname,
           events=filters, enabled=bool(enabled))
    _write(
        world,
        "INSERT INTO webhook_subscriptions(id, workspace, url, description, events, secret,"
        " enabled, created_by, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (sub_id, ws, address, str(description or "")[:_MAX_DESCRIPTION],
         json.dumps(filters), _enc_field(str(secret or "")) or "", 1 if enabled else 0,
         str(actor or "")[:256], stamp, stamp),
    )
    return get_subscription(sub_id, world=world)


@_with_world
def get_subscription(sub_id: str, *, world: Any = None) -> dict | None:
    row = _row(_world(world), "SELECT * FROM webhook_subscriptions WHERE id = ? AND workspace = ?",
               (str(sub_id or "")[:64], workspace_id()))
    return _public(row) if row else None


@_with_world
def list_subscriptions(*, world: Any = None, include_disabled: bool = True) -> list[dict]:
    sql = "SELECT * FROM webhook_subscriptions WHERE workspace = ?"
    if not include_disabled:
        sql += " AND enabled = 1"
    return [_public(r) for r in _rows(_world(world), sql + " ORDER BY created_at", (workspace_id(),))]


@_with_world
def update_subscription(
    sub_id: str,
    *,
    url: str | None = None,
    events: object = None,
    secret: str | None = None,
    description: str | None = None,
    enabled: bool | None = None,
    actor: str = "",
    world: Any = None,
    now: float | None = None,
) -> dict | None:
    from .world_model import _enc_field

    world = _world(world)
    current = get_subscription(sub_id, world=world)
    if current is None:
        return None
    sets: list[str] = []
    values: list[Any] = []
    changed: dict[str, Any] = {}
    if url is not None:
        address = validate_url(url)
        sets.append("url = ?")
        values.append(address)
        changed["host"] = urlsplit(address).hostname
    if events is not None:
        filters = normalize_events(events)
        sets.append("events = ?")
        values.append(json.dumps(filters))
        changed["events"] = filters
    if secret is not None:
        if len(secret) > _MAX_SECRET:
            raise SubscriptionError("the secret is too long")
        if secret:
            from .webhooks import separate_webhook_credential
            if not separate_webhook_credential(secret, "outbound"):
                raise SubscriptionError("The outbound secret must differ from inbound and approval credentials.")
        sets.append("secret = ?")
        values.append(_enc_field(secret) or "")
        changed["secret_set"] = bool(secret)
    if description is not None:
        sets.append("description = ?")
        values.append(str(description)[:_MAX_DESCRIPTION])
    if enabled is not None:
        sets.append("enabled = ?")
        values.append(1 if enabled else 0)
        changed["enabled"] = bool(enabled)
    if not sets:
        return current
    sets.append("updated_at = ?")
    values.append(time.time() if now is None else float(now))
    _audit("update", actor, subscription_id=current["id"], **changed)
    _write(world, f"UPDATE webhook_subscriptions SET {', '.join(sets)} WHERE id = ? AND workspace = ?",
           (*values, current["id"], workspace_id()))
    return get_subscription(sub_id, world=world)


def _subscription_secret(sub_id: str, world: Any) -> str | None:
    from .world_model import _UNSEALED_WITHHELD, _dec_field

    if sub_id == LEGACY_SUBSCRIPTION_ID:
        from .webhooks import _load_config_outbound
        return _load_config_outbound()[1]
    row = _row(world, "SELECT secret FROM webhook_subscriptions WHERE id = ? AND workspace = ?",
               (sub_id, workspace_id()))
    if not row:
        return None
    secret = _dec_field(row.get("secret") or "")
    if secret == _UNSEALED_WITHHELD:
        raise SubscriptionError("The saved signing secret could not be verified. Nothing was sent.")
    return secret or None


def _send_source(delivery: dict, world: Any, *, read: Callable[[], dict | None] | None = None) -> tuple[tuple, str | None]:
    """Check the current destination and key without changing retained history."""
    from .world_model import _UNSEALED_WITHHELD, _dec_field

    if delivery["workspace"] != workspace_id():
        raise SubscriptionError("The current workspace no longer matches this delivery. Nothing was sent.")
    sub_id = delivery["subscription_id"]
    if sub_id == LEGACY_SUBSCRIPTION_ID:
        from .webhooks import _load_config_outbound
        urls, secret = _load_config_outbound()
        if delivery["url"] not in urls:
            raise SubscriptionError("This destination is no longer configured. Nothing was sent.")
        if secret:
            from .webhooks import separate_webhook_credential
            if not separate_webhook_credential(secret, "outbound"):
                raise SubscriptionError("The outbound secret is shared with an inbound credential. Nothing was sent.")
        return (tuple(urls), secret), secret
    source = (read() if read is not None else _row(
        world, "SELECT * FROM webhook_subscriptions WHERE id = ? AND workspace = ?",
        (sub_id, delivery["workspace"])))
    if source is None or not source["enabled"]:
        raise SubscriptionError("This subscription is unavailable or turned off. Nothing was sent.")
    if source["url"] != delivery["url"]:
        raise SubscriptionError("The subscription address changed. Nothing was sent to the previous address.")
    secret = _dec_field(source["secret"] or "")
    if secret == _UNSEALED_WITHHELD:
        raise SubscriptionError("The saved signing secret could not be verified. Nothing was sent.")
    if secret:
        from .webhooks import separate_webhook_credential
        if not separate_webhook_credential(secret, "outbound"):
            raise SubscriptionError("The outbound secret is shared with an inbound credential. Nothing was sent.")
    return (source["id"], source["workspace"], source["url"], source["enabled"],
            source["secret"], source["updated_at"]), secret or None


@_with_world
def targets_for(event_type: str, *, world: Any = None) -> list[dict]:
    """Every place ``event_type`` goes: enabled matching subscriptions plus the
    legacy ``[webhooks] outbound`` list (one virtual subscription per address)."""
    out: list[dict] = []
    # Choosing targets needs no secret, so none is read here: one subscription
    # whose saved secret cannot be verified must not make the whole lookup fail
    # (and every healthy one stop receiving events). Its own delivery is refused
    # and logged at send time instead (``_send_source``).
    for sub in _rows(_world(world), "SELECT id, url, events FROM webhook_subscriptions"
                     " WHERE workspace = ? AND enabled = 1 ORDER BY created_at", (workspace_id(),)):
        try:
            events = json.loads(sub.get("events") or '["*"]')
        except ValueError:
            events = ["*"]
        if matches(events, event_type):
            out.append({"subscription_id": sub["id"], "url": sub["url"]})
    from .webhooks import _load_config_outbound
    urls, _secret = _load_config_outbound()
    for url in urls:
        out.append({"subscription_id": LEGACY_SUBSCRIPTION_ID, "url": url})
    return out


# ---------------------------------------------------------------- deliveries
def retry_delay(attempts_done: int, *, rng: Callable[[], float] = random.random) -> float | None:
    """Seconds until the next attempt after ``attempts_done`` failures, with
    +/-20 % jitter; ``None`` once the schedule is exhausted (dead-letter)."""
    if attempts_done < 1:
        return 0.0
    if attempts_done >= MAX_ATTEMPTS:
        return None
    base = RETRY_DELAYS[attempts_done - 1]
    return base * (1.0 + JITTER * (2.0 * rng() - 1.0))


def _delivery_public(row: dict) -> dict:
    out = dict(row)
    try:
        out["attempt_log"] = json.loads(out.get("attempt_log") or "[]")
    except ValueError:
        out["attempt_log"] = []
    return out


@_with_world
def enqueue(
    event_type: str,
    event_id: str,
    body: bytes,
    *,
    targets: list[dict],
    world: Any = None,
    now: float | None = None,
) -> list[str]:
    """Record one pending delivery per target; returns the delivery ids."""
    world = _world(world)
    stamp = time.time() if now is None else float(now)
    text = body.decode("utf-8")
    ids: list[str] = []
    ws = workspace_id()
    for target in targets:
        delivery_id = "whd_" + uuid.uuid4().hex[:16]
        _write(
            world,
            "INSERT INTO webhook_deliveries(id, workspace, subscription_id, event_id, event_type,"
            " url, body, status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,'pending',0,?,?,?)",
            (delivery_id, ws, target["subscription_id"], event_id, event_type,
             target["url"], text, stamp, stamp, stamp),
        )
        ids.append(delivery_id)
    return ids


@_with_world
def get_delivery(delivery_id: str, *, world: Any = None) -> dict | None:
    row = _row(_world(world), "SELECT * FROM webhook_deliveries WHERE id = ? AND workspace = ?",
               (str(delivery_id or "")[:64], workspace_id()))
    return _delivery_public(row) if row else None


@_with_world
def list_deliveries(
    *, world: Any = None, subscription_id: str | None = None,
    status: str | None = None, limit: int = 100,
) -> list[dict]:
    sql = "SELECT * FROM webhook_deliveries WHERE workspace = ?"
    params: list[Any] = [workspace_id()]
    if subscription_id:
        sql += " AND subscription_id = ?"
        params.append(subscription_id)
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    rows = _rows(_world(world), sql, tuple(params))
    return [_delivery_public(r) for r in rows]


def _history(row: dict) -> list:
    if isinstance(row.get("attempt_log"), list):
        return row["attempt_log"]
    try:
        history = json.loads(row.get("attempt_log") or "[]")
    except ValueError:
        return []
    return history if isinstance(history, list) else []


def _bounded_history(history: list) -> list:
    decisions = [entry for entry in history if isinstance(entry, dict) and entry.get("state") == "reviewed_recovery"]
    attempts = [entry for entry in history if entry not in decisions]
    return decisions + attempts[-MAX_ATTEMPTS * 2:]


def _claim_delivery(world: Any, row: dict, stamp: float, *, retry: bool = False) -> dict | None:
    """Claim the exact current row without holding a transaction during I/O."""
    attempts = 1 if retry else int(row["attempts"] or 0) + 1
    history = _history(row)
    history.append({"attempt": attempts, "at": stamp, "state": "sending",
                    "attempt_id": uuid.uuid4().hex})
    return _write_one(
        world,
        "UPDATE webhook_deliveries SET status = 'sending', attempts = ?, next_attempt_at = NULL,"
        " updated_at = ?, attempt_log = ?, delivered_at = NULL WHERE id = ? AND workspace = ?"
        " AND status = ? AND attempts = ? AND updated_at = ? AND attempt_log = ? RETURNING *",
        (attempts, stamp, json.dumps(_bounded_history(history)), row["id"], workspace_id(),
         row["status"], row["attempts"], row["updated_at"], row["attempt_log"]),
    )


def _delivery_state(code: object, attempts: int, stamp: float, exhausted: bool,
                    rng: Callable[[], float], *, never_sent: bool = False,
                    ) -> tuple[str, float | None, float | None]:
    if type(code) is int and 200 <= code <= 299:
        return "delivered", None, stamp
    if exhausted:
        return "dead", None, None
    # No response normally means the receiver may still have taken it. Only a
    # send that provably never connected (``webhooks.NotSent``) is retried.
    if not never_sent and (type(code) is not int or not 100 <= code <= 599):
        return "unknown", None, None
    delay = retry_delay(attempts, rng=rng)
    return ("dead", None, None) if delay is None else ("pending", stamp + delay, None)


def _finish_delivery(world: Any, row: dict, stamp: float, result: tuple,
                     exhausted: bool, rng: Callable[[], float]) -> dict:
    from .webhooks import NotSent

    code, latency, snippet, error = result
    status, next_at, delivered_at = _delivery_state(code, row["attempts"], stamp, exhausted, rng,
                                                    never_sent=isinstance(error, NotSent))
    code = code if type(code) is int and 100 <= code <= 599 else None
    history = _history(row)
    history[-1].update({"state": status, "status_code": code, "latency_ms": latency,
                        "error": (error or "")[:200],
                        "response": (snippet or "")[:RESPONSE_SNIPPET_CHARS]})
    try:
        saved = _write_one(
            world,
            "UPDATE webhook_deliveries SET status = ?, last_status_code = ?, last_latency_ms = ?,"
            " last_response = ?, last_error = ?, attempt_log = ?, next_attempt_at = ?,"
            " updated_at = ?, delivered_at = ? WHERE id = ? AND workspace = ? AND status = 'sending'"
            " AND attempts = ? AND attempt_log = ? RETURNING *",
            (status, code, int(latency or 0), (snippet or "")[:RESPONSE_SNIPPET_CHARS], (error or "")[:200],
             json.dumps(history), next_at, stamp, delivered_at, row["id"], workspace_id(),
             row["attempts"], row["attempt_log"]),
        )
    except Exception as exc:
        raise DeliveryUnconfirmed(
            "The send may have reached the receiving system, but its saved outcome is unconfirmed. "
            "Refresh this original delivery and check the receiving system before another attempt."
        ) from exc
    if saved is None:
        raise DeliveryUnconfirmed("The original send's saved outcome changed. Refresh this delivery; do not repeat it.")
    if status == "dead":
        log.warning("webhooks: delivery %s to subscription %s is dead after %d attempts",
                    row["id"], row["subscription_id"], row["attempts"])
    return _delivery_public(saved)


def _send_claimed(world: Any, row: dict, stamp: float, transport: Callable[..., tuple] | None,
                  rng: Callable[[], float], *, effect_guard: Callable[[], None] | None = None) -> dict:
    from .enterprise import enterprise_egress_denial
    from .webhooks import _post_result, build_headers

    exhausted = False
    entered_transport = False
    try:
        body = str(row["body"]).encode("utf-8")
        source, secret = _send_source(row, world)
        headers = build_headers(body, row["event_type"], secret, event_id=row["event_id"])
        if enterprise_egress_denial(row["url"], tool="webhook") is not None:
            result = (None, 0, "", "blocked by the enterprise egress lock")
            exhausted = True
        else:
            if _send_source(row, world)[0] != source:
                raise SubscriptionError("The subscription changed while preparing the send. Nothing was sent.")
            if effect_guard is not None:
                effect_guard()
            entered_transport = True
            result = (transport or _post_result)(row["url"], body, headers, 10.0)
            # The legacy transport tuple has no closed send-phase marker.
            # A missing response cannot safely establish that nothing was sent.
            if not isinstance(result, tuple) or len(result) != 4:
                raise ValueError("invalid transport result")
            if (type(result[1]) is not int or result[1] < 0
                    or not isinstance(result[2], str) or not isinstance(result[3], str)):
                raise ValueError("invalid transport result fields")
    except Exception as exc:
        exhausted = not entered_transport
        error = (str(exc) if isinstance(exc, SubscriptionError) else
                 "The send was refused before contacting the receiving system." if exhausted else
                 "Destination acceptance is unconfirmed; check the original delivery and receiving system.")
        result = (None, 0, "", error)
    return _finish_delivery(world, row, stamp, result, exhausted, rng)


@_with_world
def recovery_material(delivery_id: str, *, world: Any = None) -> tuple[dict, str, bool]:
    """The exact unresolved original and current destination, for private review."""
    from .governed_operations import digest

    world = _world(world)
    row = _row(world, "SELECT * FROM webhook_deliveries WHERE id = ? AND workspace = ?",
               (delivery_id, workspace_id()))
    if row is None or row["status"] not in {"unknown", "sending"}:
        raise DeliveryConflict("This original is no longer an unconfirmed send. Refresh its current record.")
    source, secret = _send_source(row, world)
    return row, digest(source), bool(secret)


def recovery_id(value: dict) -> str:
    from .governed_operations import digest

    return "whr_" + digest([value["workspace"], value["actor"], value["context"],
                            value["original"], value["operation"]])[:40]


def _recovery_decision(row: dict) -> dict | None:
    return next((item for item in _history(row) if isinstance(item, dict) and item.get("state") == "reviewed_recovery"), None)


@_with_world
def recovery_original(value: dict, *, world: Any = None) -> dict | None:
    """Pure exact-request read, independent of current destination or review expiry."""
    row = _row(_world(world), "SELECT * FROM webhook_deliveries WHERE id = ? AND workspace = ?",
               (recovery_id(value), workspace_id()))
    if row is None:
        return None
    decision = _recovery_decision(row)
    if decision != {"state": "reviewed_recovery", **value}:
        raise DeliveryConflict("This saved original belongs to another reviewed request. Nothing was repeated.")
    return _delivery_public(row)


def _recovery_insert(writer: Any, world: Any, value: dict, guard: Callable[[], None]) -> tuple[dict, bool]:
    from .governed_operations import digest

    def execute(sql, params):
        if _is_sqlite(world):
            return writer.execute(sql, params)
        writer.execute(sql.replace("?", "%s"), params)
        return writer

    if _is_sqlite(world):
        if not writer.in_transaction:
            writer.execute("BEGIN IMMEDIATE")
    if value["workspace"] != workspace_id():
        raise DeliveryConflict("The current workspace changed. Nothing was sent.")
    found = execute("SELECT * FROM webhook_deliveries WHERE id = ? AND workspace = ?",
                    (recovery_id(value), workspace_id())).fetchone()
    if found is not None:
        row = _cursor_row(writer, found)
        decision = _recovery_decision(row)
        if decision != {"state": "reviewed_recovery", **value}:
            raise DeliveryConflict("This saved identity belongs to another reviewed request. Nothing was repeated.")
        return _delivery_public(row), False
    suffix = "" if _is_sqlite(world) else " FOR UPDATE"
    original = execute("SELECT * FROM webhook_deliveries WHERE id = ? AND workspace = ?" + suffix,
                       (value["original"], workspace_id())).fetchone()
    if original is None:
        raise DeliveryConflict("The reviewed original is unavailable. Nothing was sent.")
    original = _cursor_row(writer, original)
    def source_read():
        found = execute("SELECT * FROM webhook_subscriptions WHERE id = ? AND workspace = ?" + suffix,
                        (original["subscription_id"], workspace_id())).fetchone()
        return _cursor_row(writer, found)

    guard()
    if (original["status"] not in {"sending", "unknown"} or digest(original) != value["before"]
            or digest(_send_source(original, world, read=source_read)[0]) != value["source"]):
        raise DeliveryConflict("The original delivery or subscription changed. Review its current record; nothing was sent.")
    _audit("reviewed_recovery", value["actor"], operation=value["operation"],
           original_delivery=value["original"], new_delivery=recovery_id(value),
           original_sha256=value["before"], source_sha256=value["source"])
    guard()
    if digest(_send_source(original, world, read=source_read)[0]) != value["source"]:
        raise DeliveryConflict("The subscription changed while recording the decision. Nothing was sent.")
    stamp = time.time()
    history = [{"state": "reviewed_recovery", **value},
               {"attempt": 1, "at": stamp, "state": "sending", "attempt_id": value["operation"]}]
    inserted = execute(
        "INSERT INTO webhook_deliveries(id, workspace, subscription_id, event_id, event_type, url, body,"
        " status, attempts, attempt_log, created_at, updated_at) VALUES(?,?,?,?,?,?,?,'sending',1,?,?,?)"
        " ON CONFLICT(id) DO NOTHING RETURNING *",
        (recovery_id(value), workspace_id(), original["subscription_id"], original["event_id"],
         original["event_type"], original["url"], original["body"], json.dumps(history), stamp, stamp),
    ).fetchone()
    if inserted is None:
        raise DeliveryConflict("Another request reserved this identity. Read its original outcome; nothing was repeated.")
    result = _cursor_row(writer, inserted)
    guard()
    return result, True


@_with_world
def recover_delivery(value: dict, *, guard: Callable[[], None], world: Any = None,
                     transport: Callable[..., tuple] | None = None) -> dict:
    """One separately reviewed new send; the unresolved original is never reset."""
    world = _world(world)
    existing = recovery_original(value, world=world)
    if existing is not None:
        return existing
    scope = world._writing() if _is_sqlite(world) else world._tx()
    with scope as writer:
        row, inserted = _recovery_insert(writer, world, value, guard)
    if not inserted:
        return row
    def before_send():
        from .governed_operations import digest

        guard()
        original, source, _signed = recovery_material(value["original"], world=world)
        if digest(original) != value["before"] or source != value["source"]:
            raise DeliveryConflict("The original delivery or subscription changed before the send. Nothing was sent.")
        guard()

    return _send_claimed(world, row, row["created_at"], transport, random.random, effect_guard=before_send)


def _attempt_pending(delivery_id: str, world: Any, stamp: float,
                     transport: Callable[..., tuple] | None, rng: Callable[[], float]) -> tuple[dict | None, bool]:
    row = _row(world, "SELECT * FROM webhook_deliveries WHERE id = ? AND workspace = ?",
               (delivery_id, workspace_id()))
    if (row is None or row["status"] != "pending" or row["next_attempt_at"] is None
            or row["next_attempt_at"] > stamp):
        return (_delivery_public(row) if row else None), False
    claimed = _claim_delivery(world, row, stamp)
    if claimed is None:
        return get_delivery(delivery_id, world=world), False
    return _send_claimed(world, claimed, stamp, transport, rng), True


@_with_world
def attempt_delivery(
    delivery_id: str, *, world: Any = None, now: float | None = None,
    transport: Callable[..., tuple] | None = None, rng: Callable[[], float] = random.random,
) -> dict | None:
    """Claim one due send before I/O; an unconfirmed original is never replayed.

    The transport's existing four-field result is preserved. Only a final 2xx
    response establishes destination acceptance, not downstream completion.
    """
    stamp = time.time() if now is None else float(now)
    return _attempt_pending(delivery_id, _world(world), stamp, transport, rng)[0]


@_with_world
def process_due(
    *, world: Any = None, now: float | None = None, limit: int = 50,
    transport: Callable[..., tuple] | None = None,
) -> int:
    """Attempt every pending delivery whose retry time has come. Returns the
    number attempted."""
    world = _world(world)
    stamp = time.time() if now is None else float(now)
    rows = _rows(
        world,
        "SELECT id FROM webhook_deliveries WHERE workspace = ? AND status = 'pending' AND next_attempt_at <= ?"
        " ORDER BY next_attempt_at LIMIT ?",
        (workspace_id(), stamp, max(1, int(limit))),
    )
    count = 0
    for row in rows:
        _, claimed = _attempt_pending(row["id"], world, stamp, transport, random.random)
        count += int(claimed)
    return count


@_with_world
def retry_now(
    delivery_id: str, *, actor: str = "", world: Any = None, now: float | None = None,
    transport: Callable[..., tuple] | None = None,
) -> dict | None:
    """Explicitly claim a known pending/dead send; never reset an uncertain original."""
    world = _world(world)
    current = _row(world, "SELECT * FROM webhook_deliveries WHERE id = ? AND workspace = ?",
                   (delivery_id, workspace_id()))
    if current is None:
        return None
    if current["status"] not in {"pending", "dead"}:
        raise DeliveryConflict(
            "This original delivery cannot be retried: it was accepted or its send is unconfirmed. "
            "Refresh its current record and check the receiving system."
        )
    stamp = time.time() if now is None else float(now)
    _audit("retry_delivery", actor, delivery_id=current["id"],
           subscription_id=current["subscription_id"], event_type=current["event_type"])
    claimed = _claim_delivery(world, current, stamp, retry=True)
    if claimed is None:
        raise DeliveryConflict("This delivery changed before the retry. Refresh its original record; nothing was sent by this request.")
    return _send_claimed(world, claimed, stamp, transport, random.random)


@_with_world
def dispatch(
    event_type: str, envelope: dict, body: bytes, *, world: Any = None,
    now: float | None = None, submit: Callable[[str], None] | None = None,
) -> int:
    """Record deliveries for every target of ``event_type`` and hand each to
    ``submit(delivery_id)`` (the dispatcher's thread pool) for its first
    attempt. Returns how many deliveries were recorded."""
    world = _world(world)
    targets = targets_for(event_type, world=world)
    if not targets:
        return 0
    ids = enqueue(event_type, str(envelope.get("id") or ""), body, targets=targets,
                  world=world, now=now)
    for delivery_id in ids:
        if submit is not None:
            submit(delivery_id)
        else:
            attempt_delivery(delivery_id, world=world, now=now)
    return len(ids)


@_with_world
def send_test_event(
    sub_id: str, *, actor: str = "", world: Any = None, now: float | None = None,
    transport: Callable[..., tuple] | None = None,
) -> dict | None:
    """Post a ``webhook.test`` event to one subscription right away."""
    from .webhooks import build_envelope, encode_body

    world = _world(world)
    sub = get_subscription(sub_id, world=world)
    if sub is None:
        return None
    stamp = time.time() if now is None else float(now)
    envelope = build_envelope(
        "webhook.test", {"subscription_id": sub["id"], "requested_by": actor or "dashboard"},
        record={"type": "webhook_subscription", "id": sub["id"], "title": sub["description"] or sub["url"]},
        occurred_at=stamp,
    )
    _audit("send_test", actor, subscription_id=sub["id"])
    ids = enqueue("webhook.test", envelope["id"], encode_body(envelope),
                  targets=[{"subscription_id": sub["id"], "url": sub["url"]}],
                  world=world, now=stamp)
    return attempt_delivery(ids[0], world=world, now=stamp, transport=transport)


__all__ = [
    "LEGACY_SUBSCRIPTION_ID", "MAX_ATTEMPTS", "RETRY_DELAYS", "SubscriptionError",
    "attempt_delivery", "create_subscription", "dispatch", "get_delivery",
    "get_subscription", "list_deliveries", "list_subscriptions", "matches",
    "normalize_events", "process_due", "retry_delay", "retry_now",
    "send_test_event", "targets_for", "update_subscription", "validate_url",
]
