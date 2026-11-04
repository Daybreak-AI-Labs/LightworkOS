"""Standard-library client for the Lightwork dashboard REST API (``/api/v1``).

Only ``urllib``, ``json``, ``ssl`` and ``ipaddress`` are used. Writes are never
retried: a submission that timed out may still have been accepted, so recover
it with :meth:`Lightwork.goal_receipt` and the same ``idempotency_key``.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .dashboard_contracts import GoalEventsResponse, GoalOut

DEFAULT_TIMEOUT = 30.0

# (method, url, headers, body, timeout) -> (status, response headers, body bytes).
# Injected by tests; the default sends the request over the network.
Transport = Callable[[str, str, Mapping[str, str], bytes | None, float],
                     tuple[int, Mapping[str, str], bytes]]

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class LightworkError(Exception):
    """A request failed. ``status`` is the HTTP status, or None when no response arrived."""

    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(status, message)
        self.status = status
        self.message = message

    def __str__(self) -> str:
        return f"HTTP {self.status}: {self.message}" if self.status is not None else self.message


@dataclass(frozen=True)
class Health:
    """``/healthz``. A 503 ("degraded") is a real answer, so it is returned, not raised."""

    ok: bool
    http_status: int
    body: dict[str, Any]


@dataclass(frozen=True)
class Decision:
    """The answer to an approve or deny vote, from the ``X-Lightwork-*`` headers.

    ``audit == "pending"`` means the vote is recorded but signed audit delivery
    has not finished, so the action is not effective yet. Read the approval
    again before saying that the action ran.
    """

    http_status: int
    decision_id: str
    audit: str
    approval_state: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return a redirect answer instead of following it, so the token stays put."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _urllib_transport(method: str, url: str, headers: Mapping[str, str],
                      body: bytes | None, timeout: float) -> tuple[int, Mapping[str, str], bytes]:
    handlers: list[Any] = [
        _NoRedirect,
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    ]
    if _is_loopback(urllib.parse.urlsplit(url).hostname):
        # urllib would send a loopback request, bearer token included, through HTTP_PROXY.
        handlers.insert(0, urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, dict(exc.headers.items()), exc.read()
        finally:
            exc.close()


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _scrub(text: str, token: str | None) -> str:
    return text.replace(token, "[redacted]") if token else text


def _error_message(status: int, raw: bytes) -> str:
    """The server's plain ``detail`` text, or a fixed fallback. Never the raw body."""
    try:
        body = json.loads(raw) if raw else None
    except ValueError:
        body = None
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, str) and detail.strip():
        return detail.strip()
    if isinstance(detail, dict) and isinstance(detail.get("message"), str):
        return detail["message"]
    if isinstance(detail, list):
        messages = [item["msg"] for item in detail
                    if isinstance(item, dict) and isinstance(item.get("msg"), str)]
        if messages:
            return "; ".join(messages)
    return f"request failed with HTTP {status}"


def _parse_json(status: int, raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        raise LightworkError(status, "the server sent a response that is not valid JSON") from None


class Lightwork:
    """A client for one dashboard, such as ``http://127.0.0.1:8765``.

    ``token`` is a personal or service-account API key, or the dashboard's
    ``MAVERICK_DASHBOARD_TOKEN``, sent as ``Authorization: Bearer``. Without a
    token the dashboard's loopback mode applies, and writes are accepted only
    with a same-origin ``Origin`` header, which this client always sends on
    writes. The token is never shown in ``repr`` or in an error message.
    """

    def __init__(self, base_url: str, token: str | None = None, *,
                 timeout: float = DEFAULT_TIMEOUT, transport: Transport | None = None) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in {"http", "https"} or not parts.netloc or parts.query or parts.fragment:
            raise ValueError("base_url must be an absolute http:// or https:// URL without a query")
        if parts.username is not None or parts.password is not None:
            # Never echo the URL: it is the thing that carries the secret.
            raise ValueError("base_url must not contain a username or password; pass the key as token")
        if transport is None and token and parts.scheme == "http" and not _is_loopback(parts.hostname):
            raise ValueError("refusing to send a bearer token over plain http to a non-loopback host; use https")
        if not timeout > 0:
            raise ValueError("timeout must be a positive number of seconds")
        self._origin = f"{parts.scheme}://{parts.netloc}"
        self._base = self._origin + parts.path.rstrip("/")
        self._token = token or None
        self._timeout = float(timeout)
        self._transport = transport or _urllib_transport

    def __repr__(self) -> str:
        return f"Lightwork({self._base!r})"

    # ------------------------------------------------------------ transport

    def _send(self, method: str, path: str, *, params: Mapping[str, Any] | None = None,
              body: Any = None, headers: Mapping[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        url = self._base + path
        query = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
        if query:
            url = f"{url}?{query}"
        sent = {"Accept": "application/json", "User-Agent": "lightwork-client/0.1.0"}
        if self._token:
            sent["Authorization"] = f"Bearer {self._token}"
        if method not in _SAFE_METHODS:
            sent["Origin"] = self._origin
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            sent["Content-Type"] = "application/json"
        sent.update(headers or {})
        try:
            status, response_headers, raw = self._transport(method, url, sent, data, self._timeout)
        # URLError and TimeoutError are OSError subclasses; IncompleteRead (a body cut short) is not.
        except (OSError, http.client.HTTPException) as exc:
            reason = getattr(exc, "reason", None) or exc
            raise LightworkError(None, _scrub(
                f"request to {self._origin} failed: {reason}", self._token)) from exc
        lowered = {str(name).lower(): str(value) for name, value in response_headers.items()}
        return status, lowered, raw

    def _call(self, method: str, path: str, *, expect: tuple[int, ...] = (200, 201),
              params: Mapping[str, Any] | None = None, body: Any = None,
              headers: Mapping[str, str] | None = None) -> Any:
        status, _headers, raw = self._send(method, path, params=params, body=body, headers=headers)
        if status not in expect:
            raise LightworkError(status, _scrub(_error_message(status, raw), self._token))
        return _parse_json(status, raw)

    # ------------------------------------------------------------ health

    def health(self) -> Health:
        """``GET /healthz``. Unauthenticated; 200 is ok, 503 is degraded."""
        status, _headers, raw = self._send("GET", "/healthz")
        if status not in (200, 503):
            raise LightworkError(status, _scrub(_error_message(status, raw), self._token))
        body = _parse_json(status, raw)
        return Health(ok=status == 200, http_status=status, body=body if isinstance(body, dict) else {})

    # ------------------------------------------------------------ goals

    def submit_goal(self, title: str, description: str = "", *, max_dollars: float | None = None,
                    max_wall_seconds: float | None = None, max_depth: int | None = None,
                    idempotency_key: str | None = None) -> dict[str, Any]:
        """``POST /api/v1/goals`` (201). Needs the ``tasks:write`` key scope.

        Admission is not proof of execution. Pass a random ``idempotency_key``
        that you persist before sending. After a failure with no answer, a 5xx,
        or a 409, read :meth:`goal_receipt` with the same key before deciding
        anything: a 409 that says "reconcile before retrying" means the request
        was kept under this key, not refused. Never send the same request under
        a new key. Omitted limits use the server's configured defaults.
        """
        payload = {"title": title, "description": description, "max_dollars": max_dollars,
                   "max_wall_seconds": max_wall_seconds, "max_depth": max_depth}
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._call("POST", "/api/v1/goals", expect=(201,), headers=headers,
                          body={k: v for k, v in payload.items() if v is not None})

    def goal_receipt(self, idempotency_key: str, *, kind: str = "api") -> dict[str, Any]:
        """``GET /api/v1/goal-submissions/receipt``. Reads a start without submitting work.

        ``state`` is ``"accepted"`` (the goal exists and is no longer a draft:
        poll it) or ``"not_dispatched"`` (an admitted draft that never started:
        replay :meth:`submit_goal` with the same key and the same inputs to start
        it). ``execution_confirmed`` is always false here. A 404 means no receipt
        is visible for this key yet, and the first request may still be in
        flight; replaying with the same key is safe. Needs the ``tasks:write``
        key scope.
        """
        return self._call("GET", "/api/v1/goal-submissions/receipt", params={"kind": kind},
                          headers={"Idempotency-Key": idempotency_key, "Cache-Control": "no-cache"})

    def get_goal(self, goal_id: int) -> GoalOut:
        """``GET /api/v1/goals/{id}``: status, ``result``, ``reason_code``, ``needs_input``."""
        return self._call("GET", f"/api/v1/goals/{goal_id}")

    def list_goals(self, *, status: str | None = None, limit: int = 50, offset: int = 0) -> list[GoalOut]:
        """``GET /api/v1/goals``, newest first."""
        return self._call("GET", "/api/v1/goals", params={"status": status, "limit": limit, "offset": offset})

    def goal_events(self, goal_id: int, *, since: int = 0, limit: int = 200) -> GoalEventsResponse:
        """One page of ``GET /api/v1/goals/{id}/events`` after cursor ``since``.

        The page has ``events``, ``next_id`` (save it as the next ``since``),
        ``has_more`` and ``terminal``. Stop polling on ``terminal``, not on status.
        """
        return self._call("GET", f"/api/v1/goals/{goal_id}/events", params={"since": since, "limit": limit})

    def answer_question(self, goal_id: int, question_id: int, answer: str) -> None:
        """``POST /api/v1/goals/{id}/answer``. Returns None on the 204 success."""
        self._call("POST", f"/api/v1/goals/{goal_id}/answer", expect=(204,),
                   body={"question_id": question_id, "answer": answer})

    # ------------------------------------------------------------ approvals

    def list_approvals(self) -> dict[str, Any]:
        """``GET /api/v1/approvals``. Needs the ``approvals:decide`` key scope, or the
        operator role when signed in.

        ``approvals`` rows carry ``approval_card.binding_sha256``, which
        :meth:`approve_approval` needs. ``private_requests`` lists requests
        this caller may not read in full.
        """
        return self._call("GET", "/api/v1/approvals")

    def approve_approval(self, approval_id: int, *, binding: str, acknowledged: bool = False,
                         confirmation: str | None = None) -> Decision:
        """``POST /api/v1/approvals/{id}/approve``.

        ``binding`` is the card's ``binding_sha256``, sent as
        ``X-Lightwork-Approval-Binding``. High and critical risk need
        ``acknowledged=True``; critical risk also needs ``confirmation="approve"``.
        Without them the server answers 422 and the approval stays pending. A 409
        means the card is stale or expired, or a competing vote is still being
        audited; a 404 can mean the approval was already decided. Read
        :meth:`list_approvals` again before deciding. Needs the ``approvals:decide``
        key scope.
        """
        if not binding:
            raise ValueError("binding is required: use approval_card.binding_sha256 from list_approvals()")
        body: dict[str, Any] = {}
        if acknowledged:
            body["acknowledged"] = True
        if confirmation is not None:
            body["confirmation"] = confirmation
        status, headers, raw = self._send("POST", f"/api/v1/approvals/{approval_id}/approve",
                                          body=body or None,
                                          headers={"X-Lightwork-Approval-Binding": binding})
        if status not in (202, 204):
            raise LightworkError(status, _scrub(_error_message(status, raw), self._token))
        return _decision(status, headers)

    def deny_approval(self, approval_id: int, *, reason: str | None = None) -> Decision:
        """``POST /api/v1/approvals/{id}/deny``. The optional reason goes to the audit log.

        Needs the ``approvals:decide`` key scope. Like :meth:`approve_approval`,
        a 202 means the vote is recorded but its audit is pending.
        """
        status, headers, raw = self._send("POST", f"/api/v1/approvals/{approval_id}/deny",
                                          body={"reason": reason} if reason else None)
        if status not in (202, 204):
            raise LightworkError(status, _scrub(_error_message(status, raw), self._token))
        return _decision(status, headers)

    # ------------------------------------------------------------ spend

    def spend(self) -> dict[str, Any]:
        """``GET /api/v1/spend``: total spend and the per-run episodes."""
        return self._call("GET", "/api/v1/spend")


def _decision(status: int, headers: Mapping[str, str]) -> Decision:
    return Decision(
        http_status=status,
        decision_id=headers.get("x-lightwork-decision-id", ""),
        audit=headers.get("x-lightwork-approval-audit", ""),
        approval_state=headers.get("x-lightwork-approval-state", ""),
    )
