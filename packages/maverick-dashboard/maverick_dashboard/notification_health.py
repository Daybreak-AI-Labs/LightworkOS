"""Administrative delivery health; only explicit tests can be retried safely."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth
from .device_pairing_api import router as device_pairing_router
from .personal_notifications_api import router as personal_notifications_router

router = APIRouter()
router.include_router(personal_notifications_router)
router.include_router(device_pairing_router)


class TestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID


class RetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    receipt_id: str = Field(pattern=r"^[0-9a-f]{64}$")


def _config() -> dict:
    from maverick.notifications import _load_config
    return _load_config()


def _enabled() -> dict:
    config = _config()
    if config.get("delivery_receipts", True) is False:
        raise HTTPException(409, "Turn on notification delivery history in All settings before testing delivery.")
    return config


def _guard(request: Request):
    auth.require_global_permission(request, "admin")


def _same_origin(request: Request):
    from .app import _require_same_origin
    _require_same_origin(request)


def _state() -> dict:
    from maverick.notification_receipts import DeliveryReceipts
    config = _config()
    try:
        rows = DeliveryReceipts().recent()
    except (OSError, ValueError, KeyError) as exc:
        raise HTTPException(503, "Delivery history is unavailable. Restore storage access and refresh.") from exc
    successes = [r for r in rows if r["state"] == "delivered"]
    return {"enabled": config.get("delivery_receipts", True) is not False,
            "backend": config.get("backend", "ntfy"), "receipts": rows,
            "last_success_at": successes[0]["updated_at"] if successes else None,
            "seen": "unknown"}


@router.get("/settings/notifications", response_class=HTMLResponse)
def page(request: Request):
    _guard(request)
    from .app import templates
    return templates.TemplateResponse(request, "notification_health.html", {},
                                      headers={"Cache-Control": "private, no-store"})


@router.get("/api/v1/notifications/delivery-status")
def health(request: Request, response: Response):
    _guard(request)
    response.headers["Cache-Control"] = "private, no-store"
    return _state()


def _test(request: Request, event: str, *, retry=False, backend: str | None = None):
    from maverick.notifications import notify
    config = _enabled()
    selected = str(config.get("backend", "ntfy")).strip().lower()
    if selected not in {"ntfy", "pushover", "slack", "discord"}:
        raise HTTPException(409, "Choose and save a notification channel in All settings first.")
    if backend is not None and backend != selected:
        raise HTTPException(409, "The notification channel changed. Send a new test for the current channel.")
    try:
        notify("This is an explicitly requested delivery test. No task content is included.",
               title="Lightwork delivery test", backends=[selected], batch=False,
               async_dispatch=False, delivery_key=event, delivery_kind="test", retry=retry,
               authorize=lambda: _guard(request))
    except RuntimeError as exc:
        raise HTTPException(503, "Delivery history is unavailable; the test was not sent.") from exc
    _guard(request)
    return _state()


@router.post("/api/v1/notifications/test")
async def test(request: Request, response: Response, body: TestRequest):
    _same_origin(request)
    _guard(request)
    response.headers["Cache-Control"] = "private, no-store"
    return await run_in_threadpool(_test, request, str(body.request_id))


@router.post("/api/v1/notifications/retry")
async def retry(request: Request, response: Response, body: RetryRequest):
    _same_origin(request)
    _guard(request)
    response.headers["Cache-Control"] = "private, no-store"
    from maverick.notification_receipts import DeliveryReceipts
    record = next((r for r in DeliveryReceipts().recent() if r["id"] == body.receipt_id), None)
    if (not record or record["kind"] != "test" or record["state"] != "failed"
            or not record["safe_to_retry"] or record["attempts"] >= 3):
        raise HTTPException(409, "This test cannot safely be retried. Refresh delivery status.")
    return await run_in_threadpool(_test, request, record["request_id"], retry=True, backend=record["backend"])
