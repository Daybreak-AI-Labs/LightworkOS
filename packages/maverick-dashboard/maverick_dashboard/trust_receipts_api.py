"""Closed operator API for trust receipts (bearer-verifiable evidence).

Audit-gated end to end: receipts are cut from the audit log and the log is the
who-did-what-when record, so listing rows, minting and verifying all need the
``audit`` permission (admin and the read-only auditor role). Minting is an
evidence export, not an enforcement change: it never touches the chain it
cites, and every issuance is itself an audit row (``trust_receipt_issued``).

Paths never come from the browser. The audit directory is the deployment's
own; anchoring publishes a checkpoint beside it. Verification trusts the
deployment's protected key registry plus any keys the caller pastes -- and
fails closed with none, exactly like the CLI and the standalone verifier.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

STATUS_SCHEMA = "lightwork.trust-receipts-status.v1"
ROWS_SCHEMA = "lightwork.trust-receipts-rows.v1"
VERIFY_SCHEMA = "lightwork.trust-receipts-verify.v1"

_MAX_ROWS = 500
_MAX_DAYS = 366
_MAX_RECEIPT_BYTES = 4 * 1024 * 1024

Day = Annotated[str, StringConstraints(strict=True, pattern=r"^\d{4}-\d{2}-\d{2}$")]
Sha256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
Kind = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64,
                                        pattern=r"^[a-z][a-z0-9_]{0,63}$")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class MintIn(_StrictModel):
    day: Day
    row_hash: Sha256
    include_suffix: bool = True
    #: Publish (or reuse) a signed checkpoint in this deployment's checkpoint
    #: store (beside the audit directory) so the receipt verifies "anchored".
    anchor: bool = False


class VerifyIn(_StrictModel):
    #: The receipt document VERBATIM, as text -- never a re-encoded object. A
    #: receipt is signed over its canonical JSON, and another JSON
    #: implementation re-serialising it changes number formatting (a browser
    #: turns ``1767225600.0`` into ``1767225600``), which is enough to break
    #: the signature. The CLI and the standalone verifier read the file bytes
    #: for the same reason; this endpoint does too.
    receipt: Annotated[str, StringConstraints(strict=True, min_length=2,
                                              max_length=_MAX_RECEIPT_BYTES)]
    keys: list[Sha256] = Field(default_factory=list, max_length=16)
    use_local_keys: bool = True
    anchor_digest: Sha256 | None = None


def _safe_day(day: str) -> str:
    from maverick.audit.reader import is_valid_day

    if not is_valid_day(day):
        raise HTTPException(status_code=422, detail="day must be a real YYYY-MM-DD date")
    return day


def _audit_root() -> Path:
    from maverick.audit.reader import resolve_audit_dir

    return resolve_audit_dir(None)


def _checkpoint_dir() -> Path:
    """Where anchoring publishes checkpoints: beside the audit directory, never
    inside it (the checkpoint store refuses a nested or overlapping path so a
    checkpoint can never be mistaken for, or sealed with, a day-file) -- or
    the folder an installation administrator chose on the Activity log page,
    so receipts and the page's checkpoints share one history."""
    from .audit_checkpoint_settings import checkpoint_dir

    return checkpoint_dir()


def _local_keys() -> dict[str, str]:
    """``key_id -> pubkey`` from the protected registry; a broken registry is
    reported, never silently treated as empty."""
    from maverick.audit.signing import trusted_audit_public_keys

    try:
        return dict(trusted_audit_public_keys())
    except ValueError as exc:
        raise HTTPException(status_code=503,
                            detail="The list of trusted signing keys could not be read.") from exc


def _days() -> list[str]:
    from maverick.audit.reader import event_paths

    stems = sorted((p.stem for p in event_paths(all_days=True)), reverse=True)
    return stems[:_MAX_DAYS]


def _status() -> dict:
    from maverick.audit.signing import active_key_is_offhost
    from maverick.audit.writer import _resolve_signing
    from maverick.trust_receipt import verifier_source

    signing = bool(_resolve_signing(None))
    key_id = pubkey = None
    custody = "offhost" if active_key_is_offhost() else "colocated"
    keys = _local_keys()
    if signing:
        try:
            from maverick.attestation import publisher_key

            key_id, pubkey = publisher_key()
        except Exception:  # signing configured but no key material reachable
            key_id = pubkey = None
    _text, digest = verifier_source()
    return {
        "schema": STATUS_SCHEMA,
        "signing_enabled": signing,
        "key_custody": custody,
        "key_id": key_id,
        "pubkey": pubkey,
        "trusted_keys": [{"key_id": k, "pubkey": v} for k, v in sorted(keys.items())],
        "days": _days(),
        "checkpoint_dir_present": _checkpoint_dir().is_dir(),
        "verifier_sha256": digest,
    }


def _rows(day: str, kind: str | None, limit: int) -> dict:
    from maverick.audit.reader import iter_events
    from maverick.trust_receipt_verify import derive_claim

    items = []
    total = 0
    for position, event in enumerate(iter_events(day=day), start=1):
        total += 1
        if kind and event.get("kind") != kind:
            continue
        row_hash = event.get("hash")
        signed = isinstance(row_hash, str) and len(row_hash) == 64 and bool(event.get("sig"))
        try:
            claim = derive_claim(event)
        except Exception:
            claim = {}
        items.append({
            "position": position,
            "ts": event.get("ts"),
            "kind": event.get("kind"),
            "agent": event.get("agent"),
            "goal_id": event.get("goal_id"),
            "hash": row_hash if signed else None,
            "signed": signed,
            "decision": claim.get("decision"),
            "tool": claim.get("tool"),
        })
    return {
        "schema": ROWS_SCHEMA,
        "day": day,
        "total": total,
        "items": items[-limit:],
        "truncated": len(items) > limit,
    }


def _mint(body: MintIn) -> bytes:
    from maverick.trust_receipt import export

    checkpoint_dir = None
    if body.anchor:
        # A checkpoint commits to the cross-file anchor ledger, so the ledger
        # must cover every completed day first (today's file is still growing
        # and is never anchored). Idempotent: already-anchored days are left
        # alone; tampering is flagged by the checkpoint, never papered over.
        from maverick.audit.signing import ensure_anchors

        ensure_anchors(_audit_root())
        checkpoint_dir = _checkpoint_dir()
    with tempfile.TemporaryDirectory(prefix="trust-receipt-") as tmp:
        out = export(
            Path(tmp) / "receipt.json", audit_dir=_audit_root(), day=body.day,
            row_hash=body.row_hash, checkpoint_dir=checkpoint_dir,
            include_suffix=body.include_suffix,
        )
        return out.read_bytes()


def _verify(body: VerifyIn) -> dict:
    from maverick.trust_receipt_verify import format_report, verify

    if len(body.receipt.encode("utf-8")) > _MAX_RECEIPT_BYTES:
        raise HTTPException(status_code=413, detail="receipt exceeds the size bound")
    try:
        receipt = json.loads(body.receipt)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="receipt is not valid JSON") from exc
    if not isinstance(receipt, dict):
        raise HTTPException(status_code=422, detail="a receipt is a JSON object")
    trusted: dict[str, str] = {}
    if body.use_local_keys:
        trusted.update(_local_keys())
    for hexkey in body.keys:
        trusted[f"pasted-{hexkey[:16]}"] = hexkey
    checkpoint_dir = _checkpoint_dir()
    result = verify(
        receipt, trusted_keys=list(trusted.values()),
        anchor_digest=body.anchor_digest,
        checkpoint_dir=checkpoint_dir if checkpoint_dir.is_dir() else None,
    )
    return {
        "schema": VERIFY_SCHEMA,
        **result.to_dict(),
        "trusted_key_ids": sorted(trusted),
        "report": format_report(result),
    }


class AttestationIn(_StrictModel):
    #: Optional first day of the learning window the proof covers.
    since_day: Day | None = None


class AttestationVerifyIn(_StrictModel):
    #: The bundle document verbatim, as text (see VerifyIn.receipt).
    bundle: Annotated[str, StringConstraints(strict=True, min_length=2,
                                             max_length=_MAX_RECEIPT_BYTES)]
    key: Sha256 | None = None
    #: Trust this installation's own publishing key, and check the bundle's
    #: history against this installation's own records.
    use_own_key: bool = True


def _attest(body: AttestationIn) -> bytes:
    """``maverick attest export``: a signed proof of past behaviour."""
    import calendar
    import time as _time

    from maverick.attestation import export

    since = None
    if body.since_day:
        since = float(calendar.timegm(_time.strptime(_safe_day(body.since_day), "%Y-%m-%d")))
    with tempfile.TemporaryDirectory(prefix="attestation-") as tmp:
        out = export(Path(tmp) / "attestation.json", audit_dir=_audit_root(), since=since)
        return out.read_bytes()


def _attest_verify(body: AttestationVerifyIn) -> dict:
    """``maverick attest verify``: fails closed without a trusted key."""
    from maverick.attestation_verify import format_report, verify

    try:
        bundle = json.loads(body.bundle)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="That file is not a Lightwork proof file.") from exc
    key = body.key
    evidence = None
    if not key and body.use_own_key:
        from maverick.attestation import publisher_key

        _key_id, key = publisher_key()
        evidence = _audit_root()
    if not key:
        raise HTTPException(status_code=422, detail="Choose whose key to trust.")
    result = verify(bundle, trusted_key_hex=key, evidence_root=evidence)
    return {**result.to_dict(), "report": format_report(result)}


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except HTTPException:
        raise
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="Trust receipts are not available right now.") from exc


def create_trust_receipts_router() -> APIRouter:
    router = APIRouter(prefix="/audit/receipts", tags=["trust-receipts"])

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "audit")
        return await _call(_status)

    @router.get("/rows")
    async def rows(request: Request, day: Day, kind: Kind | None = None,
                   limit: int = Query(default=200, ge=1, le=_MAX_ROWS)):
        require_permission(request, "audit")
        return await _call(_rows, _safe_day(day), kind, limit)

    @router.post("/mint")
    async def mint(request: Request, body: MintIn):
        require_permission(request, "audit")
        _safe_day(body.day)
        payload = await _call(_mint, body)
        name = f"trust-receipt-{body.day}-{body.row_hash[:12]}.json"
        return Response(
            content=payload, media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{name}"',
                "Cache-Control": "no-store, private, max-age=0",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.get("/verifier")
    async def verifier(request: Request):
        require_permission(request, "audit")
        from maverick.trust_receipt import verifier_source

        text, digest = await _call(verifier_source)
        return Response(
            content=text, media_type="text/x-python; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="trust_receipt_verify.py"',
                "X-Verifier-SHA256": digest,
                "Cache-Control": "no-store, private, max-age=0",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.post("/verify")
    async def verify_receipt(request: Request, body: VerifyIn):
        require_permission(request, "audit")
        return await _call(_verify, body)

    @router.post("/attestation")
    async def attestation(request: Request, body: AttestationIn):
        require_permission(request, "audit")
        payload = await _call(_attest, body)
        return Response(
            content=payload, media_type="application/json",
            headers={
                "Content-Disposition": 'attachment; filename="lightwork-proof.json"',
                "Cache-Control": "no-store, private, max-age=0",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.post("/attestation/verify")
    async def attestation_verify(request: Request, body: AttestationVerifyIn):
        require_permission(request, "audit")
        return await _call(_attest_verify, body)

    @router.get("/attestation/verifier")
    async def attestation_verifier(request: Request):
        require_permission(request, "audit")
        from maverick.attestation import verifier_source

        text, digest = await _call(verifier_source)
        return Response(
            content=text, media_type="text/x-python; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="attestation_verify.py"',
                "X-Verifier-SHA256": digest,
                "Cache-Control": "no-store, private, max-age=0",
                "X-Content-Type-Options": "nosniff",
            },
        )

    return router


router = create_trust_receipts_router()

__all__ = ["create_trust_receipts_router", "router"]
