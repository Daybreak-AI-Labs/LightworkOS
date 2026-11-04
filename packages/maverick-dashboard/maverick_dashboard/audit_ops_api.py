"""Independent checkpoints for the Activity log (/audit).

The ``maverick audit checkpoint publish / retire / verify`` commands as
buttons. A checkpoint is a signed note of how long one day of the activity
log was and how it ended, kept in a separate folder beside the log, so a
later change to that day can be proven.

* ``GET  /api/v1/audit/checkpoints`` -- the checkpoints kept so far and the
  days that can get one (``audit`` permission, like the page).
* ``POST /api/v1/audit/checkpoints/publish`` -- publish one day's checkpoint
  (workspace ``admin``). After a person's data was erased the day's log
  changes; the page offers a new checkpoint era for that day and the server
  names the superseded checkpoint itself.
* ``POST /api/v1/audit/checkpoints/verify`` -- check every checkpoint against
  the log, optionally against a receipt kept elsewhere (``audit``).
* ``GET  /api/v1/audit/checkpoints/{sequence}/receipt`` -- a small file to
  keep somewhere else, so rolling the checkpoints back can be detected.
* ``POST /api/v1/audit/checkpoints/retire`` -- retire the checkpoint of a
  day the record-keeping policy deleted (workspace ``admin``, confirmed).

Where checkpoints live and which keys they must be signed with (the
commands' ``--checkpoint-dir`` and ``--pubkey``) is chosen once by an
installation administrator:

* ``GET  /api/v1/audit/checkpoints/settings`` -- the folder in use and the
  pinned keys, by fingerprint only (installation ``audit``).
* ``POST /api/v1/audit/checkpoints/settings/folder/check`` -- check a folder
  on the server without saving (installation ``admin``).
* ``POST /api/v1/audit/checkpoints/settings/folder`` -- use another folder,
  or go back to the default (installation ``admin``, always confirmed:
  checks then read a different history).
* ``POST /api/v1/audit/checkpoints/settings/keys`` and ``.../keys/remove`` --
  pin a key from a key file (or this installation's own key) and unpin one
  (installation ``admin``). Widening the pinned set, and removing the last
  pinned key (which falls back to this installation's own key list), need
  confirmation.

A chosen folder is only accepted inside the allowed places (the same
server-side check Settings uses for locations); the log is always the
workspace's own. Fingerprints are looked up on the server from the chosen
row. Every change is recorded in the activity log before it is made; a
refused record changes nothing.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_global_permission, require_permission

router = APIRouter(prefix="/api/v1/audit/checkpoints", tags=["audit-checkpoints"])

_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_MAX_DAYS = 366
_MAX_ROWS = 500
_MAX_RECEIPT_BYTES = 4096
RECEIPT_KIND = "lightwork-activity-log-checkpoint-receipt"

_KIND_LABELS = {
    "checkpoint": "Checkpoint",
    "supersession": "New checkpoint after an erasure",
    "retirement": "Retired (day deleted by policy)",
}

#: Plain wording for each kind of verification problem.
_BREAK_TEXT = {
    "checkpoint_missing": "No checkpoints have been published yet.",
    "checkpoint_store_invalid": "The checkpoint folder could not be trusted: a checkpoint is missing, "
                                "out of order or its signature does not match.",
    "checkpoint_rollback": "Checkpoints newer than your kept receipt are missing. Someone may have "
                           "rolled the checkpoints back.",
    "checkpoint_fork": "The checkpoint your receipt names has been replaced with a different one.",
    "trusted_minimum_invalid": "That receipt file could not be used.",
}


class PublishIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    day: str = Field(min_length=10, max_length=10)
    #: The day's log changed because a person's data was erased: start a new
    #: checkpoint era for it. The superseded checkpoint is found on the server.
    after_erasure: bool = False


class VerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: The receipt file's text, as downloaded from this page (optional).
    receipt: str | None = Field(default=None, max_length=_MAX_RECEIPT_BYTES)


class RetireIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sequence: int = Field(ge=1, le=10**9)
    confirm: bool = False


def _audit_dir() -> Path:
    from maverick.paths import data_dir

    return data_dir("audit")


def _checkpoint_dir() -> Path:
    from .audit_checkpoint_settings import checkpoint_dir

    return checkpoint_dir()


def _pinned() -> list[str] | None:
    """The pinned keys (``--pubkey``), or None for the local key list."""
    from .audit_checkpoint_settings import trusted_pubkeys

    return trusted_pubkeys()


def _record(request: Request, action: str, *, installation: bool = False, **detail: Any) -> None:
    """One activity-log row naming who asked; refused -> nothing happens."""
    from maverick.audit import AuditRefused, audit_event

    extra = {"_global": True} if installation else {}
    try:
        audit_event("control_plane_action", agent="dashboard", action=action,
                    actor=caller_principal(request) or "local administrator", **extra, **detail)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail=(
            "This could not be added to the activity log, so nothing was changed.")) from exc


def _days() -> list[str]:
    from maverick.audit.reader import event_paths

    stems = sorted((p.stem for p in event_paths(all_days=True)), reverse=True)
    return [s for s in stems if _DAY.fullmatch(s)][:_MAX_DAYS]


def _retired_by_policy() -> set[str]:
    from maverick.audit.signing import retention_purged_days, verify_anchors

    root = _audit_dir()
    if not root.is_dir() or verify_anchors(root):
        return set()
    return {str(entry.get("day")) for entry in retention_purged_days(root)}


def _chain() -> list[dict]:
    from maverick.audit.checkpoints import list_checkpoints

    return list_checkpoints(_checkpoint_dir(), trusted_pubkeys=_pinned())


def _overview() -> dict:
    from maverick.audit.checkpoints import AuditCheckpointError

    days = _days()
    problem = ""
    try:
        chain = _chain()
    except (AuditCheckpointError, OSError, ValueError):
        chain = []
        problem = ("The checkpoints could not be read. Run the check below to see what is wrong, "
                   "or turn on tamper-evident records on the Compliance page first.")
    purged = _retired_by_policy()
    rows = []
    for item in reversed(chain[-_MAX_ROWS:]):
        latest = bool(item["latest_for_day"])
        rows.append({
            "sequence": item["sequence"],
            "day": item["day"],
            "kind": _KIND_LABELS.get(item["record_type"], "Checkpoint"),
            "entries": item["row_count"],
            "created_at": item["created_at"],
            "latest": latest,
            "can_retire": latest and item["record_type"] != "retirement" and item["day"] in purged,
        })
    covered = {item["day"] for item in chain}
    return {
        "checkpoints": rows,
        "total": len(chain),
        "days": [{"day": d, "has_checkpoint": d in covered} for d in days],
        "problem": problem,
    }


def _latest_digest_for_day(day: str) -> str:
    for item in reversed(_chain()):
        if item["day"] == day:
            return str(item["sha256"])
    raise HTTPException(status_code=409, detail=(
        "This day has no checkpoint yet, so there is nothing to start again. Publish it normally."))


def _publish(body: PublishIn, supersede: str | None) -> dict:
    from maverick.audit.checkpoints import publish_checkpoint

    path = publish_checkpoint(
        _audit_dir(), _checkpoint_dir(), day=body.day, trusted_pubkeys=_pinned(),
        supersedes_checkpoint_sha256=supersede,
        lifecycle_reason="gdpr_reanchor" if supersede else None,
    )
    sequence = int(path.stem.rsplit("-", 1)[-1])
    return {"published": True, "sequence": sequence, "day": body.day}


def _publish_problem(exc: Exception) -> str:
    text = str(exc).lower()
    if "prefix/count changed" in text:
        return ("The retained prefix of this day's log no longer matches its checkpoint. This can be an erasure, truncation or another change. Check the log first. A new checkpoint after erasure is allowed only when the retained signed erasure evidence confirms it.")
    if "retired" in text:
        return "This day was deleted by your record-keeping policy, so it cannot get a new checkpoint."
    if "missing" in text:
        return "There is no activity recorded for that day."
    if "intact" in text:
        return "Nothing changed on this day, so publish it normally instead."
    if "outside the pinned" in text:
        return ("This installation's own signing key is not one of the pinned keys, so it cannot sign "
                "checkpoints. Pin its key below, or remove the pinned keys.")
    if "key" in text or "sign" in text:
        return "Checkpoints need tamper-evident records. Turn them on on the Compliance page first."
    return "The checkpoint could not be published. Check the log below, then try again."


def _parse_receipt(text: str | None) -> tuple[int | None, str | None]:
    if not text:
        return None, None
    try:
        doc = json.loads(text)
    except ValueError:
        raise HTTPException(status_code=422, detail="That file is not a checkpoint receipt from this page.") from None
    if (not isinstance(doc, dict) or doc.get("kind") != RECEIPT_KIND
            or not isinstance(doc.get("sequence"), int) or isinstance(doc.get("sequence"), bool)
            or doc["sequence"] < 1 or not _SHA.fullmatch(str(doc.get("fingerprint") or ""))):
        raise HTTPException(status_code=422, detail="That file is not a checkpoint receipt from this page.")
    return int(doc["sequence"]), str(doc["fingerprint"])


def _verify(body: VerifyIn) -> dict:
    from maverick.audit.checkpoints import verify_checkpoints

    minimum_sequence, minimum_digest = _parse_receipt(body.receipt)
    pinned = _pinned()
    breaks = verify_checkpoints(_audit_dir(), _checkpoint_dir(), trusted_pubkeys=pinned,
                                minimum_sequence=minimum_sequence,
                                minimum_digest=minimum_digest)
    problems: list[str] = []
    for item in breaks[:50]:
        text = _BREAK_TEXT.get(item.reason)
        if text is None:
            text = (f"Checkpoint {item.sequence}: the activity log for that day no longer matches it."
                    if item.sequence else "A checkpoint does not match the activity log.")
        if text not in problems:
            problems.append(text)
    missing = any(b.reason == "checkpoint_missing" for b in breaks)
    return {
        "intact": not breaks,
        "none_yet": missing,
        "pinned": minimum_sequence is not None,
        "keys_pinned": bool(pinned),
        "problems": problems,
        "technical": [f"{b.sequence}: {b.reason}: {str(b.detail)[:300]}" for b in breaks[:50]],
    }


def _receipt(sequence: int) -> bytes:
    for item in _chain():
        if item["sequence"] == sequence:
            return json.dumps({"kind": RECEIPT_KIND, "sequence": sequence, "day": item["day"],
                               "fingerprint": item["sha256"]}, indent=2).encode("utf-8")
    raise HTTPException(status_code=404, detail="That checkpoint no longer exists. Refresh the list.")


def _retire_target(sequence: int) -> dict:
    target = next((item for item in _chain() if item["sequence"] == sequence), None)
    if target is None or not target["latest_for_day"] or target["record_type"] == "retirement":
        raise HTTPException(status_code=409, detail="That checkpoint changed since the page loaded. Refresh the list.")
    if target["day"] not in _retired_by_policy():
        raise HTTPException(status_code=409, detail=(
            "Only a day your record-keeping policy deleted can be retired. This day is still kept."))
    return target


def _retire(target: dict) -> dict:
    from maverick.audit.checkpoints import retire_checkpoint

    retire_checkpoint(_audit_dir(), _checkpoint_dir(), trusted_pubkeys=_pinned(),
                      supersedes_checkpoint_sha256=str(target["sha256"]),
                      lifecycle_reason="retention_purge")
    return {"retired": True, "day": target["day"]}


async def _run(function, *args):
    from maverick.audit.checkpoints import AuditCheckpointError

    try:
        return await run_in_threadpool(function, *args)
    except HTTPException:
        raise
    except (AuditCheckpointError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=_publish_problem(exc)) from exc
    except (ImportError, OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Checkpoints are not available right now.") from exc


@router.get("")
async def overview(request: Request) -> dict:
    require_permission(request, "audit")
    return await _run(_overview)


@router.post("/publish")
async def publish(request: Request, body: PublishIn) -> dict:
    require_permission(request, "admin")
    if not _DAY.fullmatch(body.day):
        raise HTTPException(status_code=422, detail="Choose a day from the list.")
    def change():
        from maverick.authority_effects import authority_effect_fence
        with authority_effect_fence():
            require_permission(request, "admin")
            if body.day not in _days():
                raise HTTPException(status_code=422, detail="Choose a day from the list.")
            supersede = _latest_digest_for_day(body.day) if body.after_erasure else None
            _record(request, "audit_checkpoint_publish", day=body.day, after_erasure=body.after_erasure)
            return _publish(body, supersede)
    return await _run(change)


@router.post("/verify")
async def verify(request: Request, body: VerifyIn) -> dict:
    require_permission(request, "audit")
    return await _run(_verify, body)


@router.get("/{sequence}/receipt")
async def receipt(request: Request, sequence: int) -> Response:
    require_permission(request, "audit")
    if not 1 <= sequence <= 10**9:
        raise HTTPException(status_code=422, detail="Choose a checkpoint from the list.")
    data = await _run(_receipt, sequence)
    return Response(content=data, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="activity-log-checkpoint-{sequence}.json"',
        "Cache-Control": "no-store",
    })


@router.post("/retire")
async def retire(request: Request, body: RetireIn) -> dict:
    require_permission(request, "admin")
    if body.confirm is not True:
        raise HTTPException(status_code=409, detail="Confirm the retirement to continue. Nothing was changed.")
    def change():
        from maverick.authority_effects import authority_effect_fence
        with authority_effect_fence():
            require_permission(request, "admin")
            target = _retire_target(body.sequence)
            _record(request, "audit_checkpoint_retire", sequence=body.sequence, day=target["day"])
            return _retire(target)
    return await _run(change)


# ---- where checkpoints live and which keys sign them (installation-wide) -------

class FolderIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: A folder on the server; empty means "beside each workspace's log".
    folder: str = Field(default="", max_length=1024)
    confirm: bool = False


class KeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: A public key file's text (uploaded or pasted), in any common form.
    key: str | None = Field(default=None, max_length=4096)
    #: Pin this installation's own signing key instead.
    own_key: bool = False
    confirm: bool = False


class KeyRemoveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str = Field(min_length=4, max_length=40)
    confirm: bool = False


def _fingerprint(hex_key: str) -> str:
    from .settings_catalog import key_fingerprint

    return key_fingerprint(hex_key)


def _own_key() -> str | None:
    """This installation's active signing key, when signing is on."""
    from maverick.audit.writer import _resolve_signing

    if not _resolve_signing(None):
        return None
    try:
        from maverick.attestation import publisher_key

        return publisher_key(create=False)[1]
    except Exception:  # noqa: BLE001 -- no key material reachable
        return None


def _settings_view() -> dict:
    from . import audit_checkpoint_settings as store

    current = store.load()
    own = _own_key()
    return {
        "folder": current["folder"] or "",
        "default_folder": not current["folder"],
        "keys": [{"fingerprint": _fingerprint(k), "own": k == own} for k in current["keys"]],
        "signing_on": own is not None,
        "own_key_pinned": bool(own and own in current["keys"]),
        "max_keys": store.MAX_KEYS,
    }


def _check_folder(folder: str) -> str:
    from . import settings_paths

    try:
        return settings_paths.check(folder, kind="folder", writable=True)
    except settings_paths.PathRefused as exc:
        text = str(exc)
        raise HTTPException(status_code=422, detail=text[:1].upper() + text[1:]) from exc


def _no_overlap(folder: str) -> None:
    """The kernel refuses a checkpoint folder that holds, or sits inside, an
    activity log; refuse such a choice up front in plain words."""
    from maverick.paths import maverick_home

    chosen = Path(folder).resolve()
    home = maverick_home().resolve()
    audit = _audit_dir().resolve()
    holds_logs = chosen == home or chosen in home.parents
    inside_log = chosen == audit or audit in chosen.parents
    if holds_logs or inside_log:
        raise HTTPException(status_code=422, detail=(
            "Choose a folder outside Lightwork's own folder, such as a separate disk or "
            "write-once storage."))


@router.get("/settings")
async def settings(request: Request) -> dict:
    require_global_permission(request, "audit")
    try:
        return await run_in_threadpool(_settings_view)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="The checkpoint settings could not be read.") from exc


@router.post("/settings/folder/check")
async def check_folder(request: Request, body: FolderIn) -> dict:
    require_global_permission(request, "admin")
    if not body.folder.strip():
        return {"ok": True, "message": "Checkpoints will be kept beside each workspace's activity log."}
    stored = await run_in_threadpool(_check_folder, body.folder)
    _no_overlap(stored)
    from . import settings_paths

    return {"ok": True, "message": settings_paths.describe_ok("folder")}


@router.post("/settings/folder")
async def choose_folder(request: Request, body: FolderIn) -> dict:
    require_global_permission(request, "admin")
    from . import audit_checkpoint_settings as store

    stored = None
    if body.folder.strip():
        stored = await run_in_threadpool(_check_folder, body.folder)
        _no_overlap(stored)
    current = await run_in_threadpool(store.load)
    if (current["folder"] or None) == stored:
        return {"saved": False, "message": "That folder is already in use."}
    if body.confirm is not True:
        raise HTTPException(status_code=409, detail=(
            "Confirm the change to continue. Checks will read the checkpoints in the new folder. "
            "Nothing was changed."))
    await run_in_threadpool(_record, request, "audit_checkpoint_folder", installation=True,
                            folder=stored or "default", previous=current["folder"] or "default")
    await run_in_threadpool(store.save, stored, current["keys"])
    return {"saved": True, "message": ("Checkpoints are now kept in the chosen folder." if stored else
                                       "Checkpoints are kept beside each workspace's activity log again.")}


@router.post("/settings/keys")
async def pin_key(request: Request, body: KeyIn) -> dict:
    require_global_permission(request, "admin")
    from . import audit_checkpoint_settings as store
    from .settings_catalog import SettingError, parse_public_key

    if body.own_key:
        key = await run_in_threadpool(_own_key)
        if key is None:
            raise HTTPException(status_code=409, detail=(
                "This installation has no signing key yet. Turn on tamper-evident records first."))
    else:
        try:
            key = parse_public_key(body.key or "")
        except SettingError as exc:
            raise HTTPException(status_code=422, detail=(
                "That file is not a public key this page can read. Ask for the public key file.")) from exc
    current = await run_in_threadpool(store.load)
    if key in current["keys"]:
        return {"saved": False, "message": "That key is already pinned."}
    if len(current["keys"]) >= store.MAX_KEYS:
        raise HTTPException(status_code=422, detail=f"Pin at most {store.MAX_KEYS} keys.")
    # A second key widens who can sign trusted checkpoints: confirm it.
    if current["keys"] and body.confirm is not True:
        raise HTTPException(status_code=409, detail=(
            "Confirm to continue. Checkpoints signed with this key will be trusted too. Nothing was changed."))
    fingerprint = _fingerprint(key)
    await run_in_threadpool(_record, request, "audit_checkpoint_key_pinned", installation=True,
                            fingerprint=fingerprint)
    await run_in_threadpool(store.save, current["folder"], [*current["keys"], key])
    return {"saved": True, "fingerprint": fingerprint,
            "message": f"Pinned the key {fingerprint}. Only pinned keys are trusted from now on."}


@router.post("/settings/keys/remove")
async def unpin_key(request: Request, body: KeyRemoveIn) -> dict:
    require_global_permission(request, "admin")
    from . import audit_checkpoint_settings as store

    current = await run_in_threadpool(store.load)
    match = [k for k in current["keys"] if _fingerprint(k) == body.fingerprint]
    if not match:
        raise HTTPException(status_code=404, detail="That key is no longer pinned. Refresh the page.")
    remaining = [k for k in current["keys"] if k not in match]
    # Removing the last pin falls back to this installation's own key list.
    if not remaining and body.confirm is not True:
        raise HTTPException(status_code=409, detail=(
            "Confirm to continue. With no pinned keys, any key this installation trusts is accepted. "
            "Nothing was changed."))
    await run_in_threadpool(_record, request, "audit_checkpoint_key_unpinned", installation=True,
                            fingerprint=body.fingerprint)
    await run_in_threadpool(store.save, current["folder"], remaining)
    return {"saved": True, "message": ("Unpinned. Checkpoints are trusted when signed by any key this "
                                       "installation trusts." if not remaining else "Unpinned.")}


__all__ = ["RECEIPT_KIND", "router"]
