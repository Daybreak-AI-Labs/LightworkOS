"""Choose where the Skill Store looks for skills ([catalogs] indexes).

Before this, pointing the Store at an organization's own catalog meant editing
the config file by hand. An administrator can now add or remove a catalog web
address, or go back to the built-in catalog, from the Store page. It only
changes what the Store lists: installing still needs the admin role and the
server's skill-install opt-in. Admin + same-origin checked.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool

router = APIRouter()


def current_catalogs() -> tuple[list[str], bool]:
    """(addresses the Store reads, whether that is the built-in default)."""
    try:
        from maverick.catalog import DEFAULT_INDEXES, _configured_indexes

        urls = _configured_indexes()
        return urls, urls == [i.rstrip("/") for i in DEFAULT_INDEXES]
    except Exception:  # pragma: no cover -- the Store still renders
        return [], True


@router.post("/store/catalogs")
async def store_catalogs(request: Request) -> RedirectResponse:
    from . import app as app_module
    from .auth import require_global_permission

    app_module._require_same_origin(request)
    require_global_permission(request, "admin")
    from . import settings_store

    form = await request.form()
    action = str(form.get("action") or "")
    url = str(form.get("url") or "").strip().rstrip("/")
    urls, is_default = current_catalogs()
    if action == "add":
        new = ([] if is_default else list(urls)) + [url]
    elif action == "remove":
        new = [u for u in urls if u != url]
    elif action == "reset":
        new = []
    else:
        raise HTTPException(400, "Choose add, remove or use the built-in catalog.")
    try:
        await run_in_threadpool(settings_store.set_catalog_indexes, new)
    except ValueError as exc:
        if action == "add":
            return RedirectResponse("/store?saved=bad-address", status_code=303)
        raise HTTPException(400, "That catalog list can't be saved.") from exc
    from maverick.audit import AuditRefused
    from maverick.config import reset_config_cache

    from .settings_audit import record_setting_change

    reset_config_cache()
    try:
        await run_in_threadpool(lambda: record_setting_change(
            request, section="catalogs", key="indexes",
            old=_for_record([] if is_default else urls), new=_for_record(new)))
    except AuditRefused as exc:
        # No change without a record of it: put the previous list back.
        await run_in_threadpool(settings_store.set_catalog_indexes, [] if is_default else urls)
        reset_config_cache()
        raise HTTPException(503, "The change could not be recorded, so it was undone.") from exc
    return RedirectResponse(f"/store?saved={action}", status_code=303)


def _for_record(urls: list[str]) -> list[str]:
    """Catalog addresses for the activity record, without any query text
    (which can carry an access token)."""
    from urllib.parse import urlsplit

    if not urls:
        return ["built-in catalog"]
    shown = []
    for url in urls:
        parts = urlsplit(url)
        shown.append(f"{parts.scheme}://{parts.hostname or ''}"
                     f"{':' + str(parts.port) if parts.port else ''}{parts.path}")
    return shown

