"""DSAR Concierge — a standalone data-subject-request agent.

The whole request lifecycle on one small surface: subject-facing intake
(web form + message webhook with a deterministic detector), an identity-
verification email loop, the statutory clock with SLA aging, package
assembly for access/portability, the deliberately NON-destructive erasure
handoff, and a counted value ledger. Standalone it is self-contained; with
Lightwork the same agent mirrors into the governed privacy workspace and
the signed audit chain (see capabilities.py / backend.py — the seam).
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import os
import re
import secrets
import threading
import time
from collections import deque
from pathlib import Path

import backend
import dsar_engine as engine
import value_ledger
from capabilities import CAPS, STANDALONE, caps_summary
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from mailsink import INBOX, start_mailsink

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
templates.env.filters["dt"] = (
    lambda ts: _dt.datetime.fromtimestamp(float(ts or 0))
    .strftime("%Y-%m-%d %H:%M") if ts else "—")

AGENT_VERSION = "1.0.0"
BASE_URL = os.environ.get("DSAR_BASE_URL", "http://127.0.0.1:8891")
OPERATOR_USER = os.environ.get("DSAR_OPERATOR_USER", "operator")
OPERATOR_TOKEN = os.environ.get("DSAR_OPERATOR_TOKEN", "")

app = FastAPI(title="DSAR Concierge")


@app.on_event("startup")
async def _boot() -> None:
    if STANDALONE:
        try:
            app.state.mailserver = await start_mailsink(
                "127.0.0.1", int(os.environ.get("EMAIL_SMTP_PORT", "1026")))
        except Exception as exc:  # pragma: no cover - port variance
            print(f"[mailsink] not started: {exc}")


def _page(request: Request, name: str, **ctx) -> HTMLResponse:
    ctx.setdefault("caps", CAPS)
    ctx.setdefault("caps_summary", caps_summary())
    ctx.setdefault("standalone", STANDALONE)
    return templates.TemplateResponse(request, name, ctx)


def _auth_error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=detail,
        headers={"WWW-Authenticate": 'Basic realm="DSAR operator"'})


def _basic_credentials(authorization: str) -> tuple[str, str] | None:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "basic" or not token:
        return None
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    username, sep, password = decoded.partition(":")
    if not sep:
        return None
    return username, password


def _origin(value: str, *, origin_header: bool = False) -> tuple[str, str, int] | None:
    from urllib.parse import urlsplit

    try:
        url = urlsplit(value)
        if (url.scheme.lower() not in {"http", "https"} or not url.hostname
                or url.username is not None or url.password is not None
                or (origin_header and (url.path or url.query or url.fragment))):
            return None
        port = url.port
        return (url.scheme.lower(), url.hostname.lower(),
                port if port is not None else (443 if url.scheme.lower() == "https" else 80))
    except ValueError:
        return None


def require_operator(request: Request, authorization: str = Header("")) -> None:
    """Protect DSAR operator-only screens and state-changing actions."""
    if not OPERATOR_TOKEN:
        raise _auth_error(
            503,
            "DSAR_OPERATOR_TOKEN must be set before using operator routes.")
    creds = _basic_credentials(authorization)
    if creds is None:
        raise _auth_error(401, "Operator authentication required.")
    username, password = creds
    if not (secrets.compare_digest(username.encode("utf-8", "surrogatepass"),
                                   OPERATOR_USER.encode("utf-8", "surrogatepass"))
            and secrets.compare_digest(password.encode("utf-8", "surrogatepass"),
                                       OPERATOR_TOKEN.encode("utf-8", "surrogatepass"))):
        raise _auth_error(401, "Operator authentication required.")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin_header = request.headers.get("origin")
        origin = origin_header or request.headers.get("referer") or ""
        expected = _origin(BASE_URL)
        if (not expected or _origin(origin, origin_header=origin_header is not None) != expected
                or request.headers.get("sec-fetch-site", "").lower() == "cross-site"):
            raise HTTPException(status_code=403, detail="Same-origin operator request required.")


# Public intake can cause platform email. Fail closed until the operator sets
# an explicit recipient-domain policy, and bound per-peer request volume.
_INTAKE_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
_intake_attempts: dict[str, deque[float]] = {}
_intake_lock = threading.Lock()
_intake_recipients: dict[str, float] = {}
_intake_global: deque[float] = deque()


def _intake_subject(subject: str) -> str:
    subject = (subject or "").strip()
    if len(subject) > 200 or not _INTAKE_EMAIL.fullmatch(subject):
        raise ValueError("A valid email address is required.")
    if not STANDALONE:
        domains = {domain.strip().lower() for domain in
                   os.environ.get("DSAR_EMAIL_ALLOWED_DOMAINS", "").split(",")
                   if domain.strip()}
        if subject.rsplit("@", 1)[1].lower() not in domains:
            raise ValueError("This email domain is not enabled for public intake.")
    return subject


def _intake_rate_limit(request: Request) -> None:
    # Use only the socket peer; forwarded headers are untrusted. Reverse proxies
    # must enforce their own shared per-client and global limits as well.
    peer = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _intake_lock:
        for key in list(_intake_attempts):
            timestamps = _intake_attempts[key]
            while timestamps and timestamps[0] <= now - 60:
                timestamps.popleft()
            if not timestamps:
                del _intake_attempts[key]
        if peer not in _intake_attempts and len(_intake_attempts) >= 8192:
            raise HTTPException(status_code=429, detail="Intake rate limit reached.")
        timestamps = _intake_attempts.setdefault(peer, deque())
        if len(timestamps) >= 30:
            raise HTTPException(status_code=429, detail="Intake rate limit reached.")
        timestamps.append(now)


def _reserve_intake_email(subject: str) -> None:
    # These bounded in-process limits supplement, but do not replace, a shared
    # ingress/mail quota when several workers or replicas are deployed.
    recipient = hashlib.sha256(subject.casefold().encode("utf-8")).hexdigest()
    now = time.monotonic()
    with _intake_lock:
        while _intake_global and _intake_global[0] <= now - 3600:
            _intake_global.popleft()
        for key, timestamp in list(_intake_recipients.items()):
            if timestamp <= now - 3600:
                del _intake_recipients[key]
        if recipient in _intake_recipients or len(_intake_global) >= 100:
            raise HTTPException(status_code=429, detail="Intake email limit reached.")
        _intake_recipients[recipient] = now
        _intake_global.append(now)


def _send_verification(rec: dict) -> None:
    link = f"{BASE_URL}/verify/{rec['verify_token']}"
    backend.send_email(
        rec["subject_id"],
        f"Confirm your {rec['kind']} request {rec['id']}",
        f"We received your {rec['kind']} request. To confirm it came from "
        f"you, open this link:\n\n  {link}\n\nThe statutory clock is "
        f"already running — confirming does not delay your deadline.")


def _open_request(subject: str, kind: str, *, channel: str, note: str = "",
                  intake: dict | None = None) -> dict:
    subject = _intake_subject(subject)
    if kind not in engine.KINDS:
        raise ValueError(f"kind must be one of {engine.KINDS}")
    _reserve_intake_email(subject)
    rec = engine.open_request(subject, kind, channel=channel, note=note,
                              intake=intake)
    rec["platform_id"] = backend.mirror_open(rec)
    engine._save(rec)
    backend.audit_record("DSAR_OPENED", request=rec["id"],
                         request_kind=rec["kind"])
    _send_verification(rec)
    return rec


# --------------------------------------------------------------------------- #
# Subject-facing intake
# --------------------------------------------------------------------------- #
@app.get("/request", response_class=HTMLResponse)
async def request_form(request: Request) -> HTMLResponse:
    return _page(request, "request.html", submitted=None, error=None)


@app.post("/request", response_class=HTMLResponse)
async def request_submit(request: Request,
                         subject_id: str = Form(...),
                         kind: str = Form("access"),
                         note: str = Form("")) -> HTMLResponse:
    _intake_rate_limit(request)
    try:
        rec = _open_request(subject_id, kind, channel="web", note=note)
    except ValueError as exc:
        return _page(request, "request.html", submitted=None,
                     error=str(exc))
    return _page(request, "request.html", submitted=rec, error=None)


@app.post("/webhook/message")
async def webhook_message(request: Request) -> JSONResponse:
    """Inbound message triage (email gateway, chat bridge, curl...). A
    message that does not read as a subject request — or names no subject —
    is a 422, never a silently-opened case."""
    _intake_rate_limit(request)
    body = await request.json()
    text = str(body.get("text", ""))
    sender = str(body.get("sender", ""))
    def reserve_subject(subject: str) -> str:
        subject = _intake_subject(subject)
        _reserve_intake_email(subject)
        return subject

    try:
        probe = engine.from_message(text, sender=sender, before_open=reserve_subject)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=422)
    if probe is None:
        return JSONResponse(
            {"ok": False,
             "error": "no data-subject request detected (or no subject "
                      "address found) — open it manually if you disagree"},
            status_code=422)
    probe["platform_id"] = backend.mirror_open(probe)
    engine._save(probe)
    backend.audit_record("DSAR_OPENED", request=probe["id"],
                         request_kind=probe["kind"])
    _send_verification(probe)
    return JSONResponse({"ok": True, "id": probe["id"],
                         "kind": probe["kind"],
                         "signals": (probe.get("intake") or {})
                         .get("signals", [])}, status_code=201)


@app.get("/verify/{token}", response_class=HTMLResponse)
async def verify_token(request: Request, token: str) -> HTMLResponse:
    rec = engine.verify(token)
    if rec is not None:
        backend.audit_record("DSAR_VERIFIED", request=rec["id"])
    return _page(request, "verify.html", rec=rec)


# --------------------------------------------------------------------------- #
# Operator console
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse,
         dependencies=[Depends(require_operator)])
async def queue(request: Request) -> HTMLResponse:
    rows = engine.list_requests()
    done = [engine.get(r["id"]) for r in rows
            if r["status"] in ("fulfilled", "awaiting_erasure", "closed")]
    hours = dollars = 0.0
    for rec in done:
        if rec:
            v = value_ledger.request_value(rec["kind"])
            hours += v["hours"]
            dollars += v["dollars"]
    return _page(request, "queue.html", rows=rows, aging=engine.aging(),
                 value={"handled": len(done), "hours": round(hours, 1),
                        "dollars": round(dollars, 2)},
                 mail=INBOX[:8])


@app.get("/case/{rid}", response_class=HTMLResponse,
         dependencies=[Depends(require_operator)])
async def case_page(request: Request, rid: str) -> HTMLResponse:
    rec = engine.get(rid)
    if rec is None:
        return _page(request, "verify.html", rec=None)
    return _page(request, "case.html", rec=rec)


@app.post("/case/{rid}/fulfill",
          dependencies=[Depends(require_operator)])
async def case_fulfill(rid: str, extracts: str = Form("")):
    """Access/portability: one 'System: extracted data' line per system —
    only what the operator provides goes into the package."""
    parsed: dict[str, str] = {}
    for line in extracts.splitlines():
        if ":" in line:
            system, _, data = line.partition(":")
            if system.strip() and data.strip():
                parsed[system.strip()] = data.strip()
    rec = engine.fulfill_access(rid, parsed)
    if rec is not None:
        backend.audit_record("DSAR_FULFILLED", request=rec["id"],
                             systems=len(parsed))
        backend.send_email(
            rec["subject_id"],
            f"Your {rec['kind']} request {rec['id']} is ready",
            rec["package"]["cover_note"])
    return RedirectResponse(f"/case/{rid}", status_code=303)


@app.post("/case/{rid}/erasure",
          dependencies=[Depends(require_operator)])
async def case_erasure(rid: str, systems: str = Form("")):
    rec = engine.erasure_handoff(
        rid, [s for s in systems.splitlines() if s.strip()])
    if rec is not None:
        backend.audit_record("DSAR_ERASURE_HANDOFF", request=rec["id"])
    return RedirectResponse(f"/case/{rid}", status_code=303)


@app.post("/case/{rid}/close",
          dependencies=[Depends(require_operator)])
async def case_close(rid: str, reason: str = Form("")):
    rec = engine.close(rid, reason=reason)
    if rec is not None:
        backend.mirror_close(rec)
        backend.audit_record("DSAR_CLOSED", request=rec["id"])
    return RedirectResponse(f"/case/{rid}", status_code=303)


@app.get("/case/{rid}/package.json",
         dependencies=[Depends(require_operator)])
async def case_package(rid: str) -> JSONResponse:
    rec = engine.get(rid)
    if rec is None or not rec.get("package"):
        return JSONResponse({"error": "no package"}, status_code=404)
    return JSONResponse(rec["package"],
                        headers={"Content-Disposition":
                                 f'attachment; filename="{rid}-package.json"'})


# --------------------------------------------------------------------------- #
# Ops surface
# --------------------------------------------------------------------------- #
@app.get("/health")
async def health() -> JSONResponse:
    a = engine.aging()
    return JSONResponse({"ok": True, "open": a["open"],
                         "overdue": a["overdue"]})


@app.get("/value.json")
async def value_json() -> JSONResponse:
    hours = dollars = 0.0
    handled = 0
    for r in engine.list_requests():
        if r["status"] in ("fulfilled", "awaiting_erasure", "closed"):
            handled += 1
            v = value_ledger.request_value(r["kind"])
            hours += v["hours"]
            dollars += v["dollars"]
    return JSONResponse({"agent": "dsar-concierge",
                         "version": AGENT_VERSION, "cases": handled,
                         "hours": round(hours, 1),
                         "dollars": round(dollars, 2)})


@app.get("/about", response_class=HTMLResponse)
async def about(request: Request) -> HTMLResponse:
    return _page(request, "about.html")
