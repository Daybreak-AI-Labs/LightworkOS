"""Read-only, digest-only API for the Evolution Ledger dashboard surface.

The underlying learning stores remain their own authorities.  This router reads
only the durable promotion journal through the core's explicit read-only
projection; it does not discover, construct, repair, lock, approve, promote,
rollback, or otherwise mutate a learning source.  Dreaming, hindsight, and
runtime proof sources are deliberately not accepted from the browser and are
reported as outside this dashboard projection.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi import Path as PathParam
from maverick import learning_history_checkpoint as checkpoint
from maverick.evolution_ledger import (
    EVOLUTION_LEDGER_SCHEMA,
    EvolutionLedgerError,
    project_evolution_ledger,
    promotion_receipt_for_entry,
    verify_promotion_receipt,
)
from pydantic import BaseModel, ConfigDict, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

SNAPSHOT_SCHEMA = "lightwork.evolution-ledger-dashboard-snapshot.v1"
RECEIPT_VERIFICATION_SCHEMA = "lightwork.evolution-ledger-receipt-verification.v1"

_MAX_ENTRIES = 500
_MAX_RECEIPT_BYTES = 64 * 1024

ReceiptText = Annotated[
    str,
    StringConstraints(strict=True, min_length=2, max_length=_MAX_RECEIPT_BYTES),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class VerifyReceiptIn(_StrictModel):
    """A caller-supplied *digest-only* core promotion receipt.

    The endpoint intentionally does not accept an approval request, approval
    signature, trusted keys, source path, ledger id, or promotion selector.
    Receipt-byte integrity can be checked locally, while human-approval
    verification remains a separately supplied private binding in the core.
    """

    receipt: ReceiptText


class VerifyCheckpointIn(_StrictModel):
    checkpoint: Annotated[str, StringConstraints(strict=True, min_length=2, max_length=checkpoint.MAX_FILE_BYTES)]


class EvolutionLedgerInputError(ValueError):
    """A bounded browser input is syntactically invalid."""


def _without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvolutionLedgerInputError("receipt contains a duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonfinite_number(value: str) -> None:
    raise EvolutionLedgerInputError(f"receipt contains a non-finite JSON number ({value})")


def _receipt_object(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > _MAX_RECEIPT_BYTES:
        raise EvolutionLedgerInputError("receipt exceeds the byte limit")
    try:
        receipt = json.loads(
            text,
            object_pairs_hook=_without_duplicate_keys,
            parse_constant=_reject_nonfinite_number,
        )
    except (TypeError, UnicodeError, ValueError) as exc:
        if isinstance(exc, EvolutionLedgerInputError):
            raise
        raise EvolutionLedgerInputError("receipt is not strict JSON") from exc
    if not isinstance(receipt, dict):
        raise EvolutionLedgerInputError("receipt must be a JSON object")
    return receipt


def _promotion_ledger_source() -> tuple[Any | None, str]:
    """Return an existing promotion source without invoking its repair path.

    ``PromotionLedger(path=...)`` calls its compatibility-projection refresh in
    ``__post_init__``.  The dashboard must not perform that write merely because
    an auditor opened a page.  Nor may it call ``data_dir``: resolving a newly
    named tenant through that write-oriented helper can create its immutable
    namespace claim.  The resolver below instead requires an already-valid,
    private claim when a named tenant has durable source material.  An in-memory
    instance has no I/O; assigning the trusted server-derived path lets
    ``project_evolution_ledger`` use its read-only journal parser on a shallow
    copy, as intended by the core module.
    """

    from maverick.self_improvement import PromotionLedger

    path = _read_only_promotion_ledger_path()
    journal_path = Path(f"{path}.journal")
    if not _exists_or_link(path) and not _exists_or_link(journal_path):
        return None, "not_present"
    ledger = PromotionLedger()
    ledger.path = path
    return ledger, "available"


def _exists_or_link(path: Path) -> bool:
    """Treat a dangling symlink as a source condition that must not be ignored."""

    try:
        return path.exists() or path.is_symlink()
    except OSError as exc:
        raise EvolutionLedgerError("promotion ledger source cannot be inspected") from exc


def _read_only_promotion_ledger_path() -> Path:
    """Resolve a tenant-aware source path without creating or repairing state.

    ``maverick.paths.data_dir`` is intentionally an admission helper: its named
    tenant resolution writes an immutable namespace claim.  A dashboard audit
    read must never perform that admission.  This conservative counterpart
    reads only an existing claim and requires the same private-directory/file
    posture before it permits the core journal parser to see durable material.
    An unclaimed named source is unavailable rather than adopted on a view.
    """

    from maverick import paths
    from maverick.file_lock import private_path_is_restricted, require_private_directory

    home = paths.maverick_home()
    tenant = paths.current_tenant_id_strict()
    if tenant is None:
        path = home / "self_improvement.json"
        directories = (home,)
    else:
        canonical_tenant = paths.canonical_tenant_id(tenant)
        # These private helpers are pure encoders/claim validators; using them
        # avoids a second tenant-path encoding implementation in the dashboard.
        segment = paths._tenant_segment(canonical_tenant)
        namespace_key = paths._tenant_namespace_key(canonical_tenant)
        claim_path = paths._tenant_claim_path(home, namespace_key)
        path = home / "tenants" / segment / "self_improvement.json"
        if not _exists_or_link(path) and not _exists_or_link(Path(f"{path}.journal")):
            return path
        directories = (
            home,
            home / ".tenant-namespaces",
            claim_path.parent,
            home / "tenants",
            path.parent,
        )
        try:
            for directory in directories:
                require_private_directory(directory)
            if not private_path_is_restricted(claim_path, 0o600):
                raise EvolutionLedgerError("tenant namespace claim is not private")
            claim = json.loads(
                claim_path.read_text(encoding="utf-8"),
                object_pairs_hook=_without_duplicate_keys,
                parse_constant=_reject_nonfinite_number,
            )
            owner = paths._tenant_claim_owner(claim, namespace_key, claim_path)
            if owner != canonical_tenant:
                raise EvolutionLedgerError("tenant namespace claim is mismatched")
        except EvolutionLedgerError:
            raise
        except (OSError, TypeError, ValueError, PermissionError) as exc:
            raise EvolutionLedgerError("tenant namespace claim is unavailable") from exc

    journal_path = Path(f"{path}.journal")
    if not _exists_or_link(path) and not _exists_or_link(journal_path):
        return path
    try:
        for directory in directories:
            require_private_directory(directory)
        for candidate in (path, journal_path):
            if _exists_or_link(candidate) and not private_path_is_restricted(candidate, 0o600):
                raise EvolutionLedgerError("promotion ledger source is not private")
    except EvolutionLedgerError:
        raise
    except (OSError, PermissionError) as exc:
        raise EvolutionLedgerError("promotion ledger source is unavailable") from exc
    return path


def _snapshot() -> dict[str, Any]:
    """Produce one bounded projection without exposing a locator or journal row."""

    promotion_ledger, promotion_state = _promotion_ledger_source()
    projection = project_evolution_ledger(promotion_ledger)
    all_entries = projection.entries
    visible_entries = all_entries[-_MAX_ENTRIES:]
    limitations = set(projection.limitations)
    if promotion_state == "not_present":
        limitations.add("promotion_ledger_not_present")
    limitations.update(
        {
            "dashboard_projects_only_digest_only_promotion_history",
            "dreaming_hindsight_and_runtime_proof_sources_are_not_exposed_here",
            "receipt_integrity_is_not_a_human_approval_verification",
        }
    )
    return {
        "schema": SNAPSHOT_SCHEMA,
        "captured_at": time.time(),
        "sources": {
            "promotion_ledger": promotion_state,
            "dreaming": "not_exposed",
            "hindsight": "not_exposed",
            "proof": "not_exposed",
        },
        "projection": {
            "schema": EVOLUTION_LEDGER_SCHEMA,
            "entries": [entry.to_dict() for entry in visible_entries],
            "entry_count": len(visible_entries),
            "total_entries": len(all_entries),
            "truncated": len(visible_entries) != len(all_entries),
            "limitations": sorted(limitations),
        },
    }


def _verify_receipt(body: VerifyReceiptIn) -> dict[str, Any]:
    receipt = _receipt_object(body.receipt)
    # Deliberately omit the optional private approval binding.  The response
    # reports that limitation rather than treating a receipt digest as proof of
    # human approval.
    result = verify_promotion_receipt(receipt)
    recorded = None
    if result.receipt_valid:
        ledger, state = _promotion_ledger_source()
        # Check the entire native projection, not the newest 500 visible rows.
        # A valid self-contained fingerprint alone is not a recorded change.
        recorded = state == "available" and any(
            entry.promotion_receipt_sha256 == result.receipt_sha256
            for entry in project_evolution_ledger(ledger).entries
        )
    return {
        "schema": RECEIPT_VERIFICATION_SCHEMA,
        **result.to_dict(),
        "recorded_in_current_history": recorded,
        "checked_at": time.time(),
    }


def _recorded_receipt(entry_sha256: str) -> dict[str, Any]:
    ledger, state = _promotion_ledger_source()
    result = promotion_receipt_for_entry(ledger, entry_sha256) if state == "available" else None
    if result is None:
        raise HTTPException(404, "That recorded receipt is unavailable. Refresh Learning history.")
    return result


def _checkpoint_history() -> dict[str, Any]:
    ledger, _state = _promotion_ledger_source()
    return checkpoint.history(ledger)


def _checkpoint_status() -> dict[str, Any]:
    current = _checkpoint_history()
    reference = checkpoint.build(current)
    return {"record_count": reference["record_count"], "checked_at": reference["saved_at"],
            "adopted_changes": current["adopted_changes"], "restorations": current["restorations"],
            "scope": "The complete native record of learning adoption, restoration, and their related recording steps. Other platform activity is outside this checkpoint.",
            "limits": "Up to 4,096 stored records and 16 MB of source history; no partial checkpoint is offered.",
            "trust": "Keep the original downloaded file independently of this installation. A file created after history was replaced cannot reveal that replacement.",
            "revision": reference["prefix_sha256"]}


def _download_checkpoint() -> dict[str, Any]:
    return checkpoint.build(_checkpoint_history())


def _verify_checkpoint(body: VerifyCheckpointIn) -> dict[str, Any]:
    reference = checkpoint.parse(body.checkpoint)
    return checkpoint.compare(reference, _checkpoint_history())


async def _checkpoint_upload(request: Request) -> VerifyCheckpointIn:
    """Bound the JSON envelope before parsing; never echo uploaded file text."""
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > 32 * 1024:
            raise HTTPException(413, "Choose the original downloaded checkpoint, 4 KB or smaller.")
        raw.extend(chunk)
    try:
        value = json.loads(raw, object_pairs_hook=_without_duplicate_keys, parse_constant=_reject_nonfinite_number)
        return VerifyCheckpointIn.model_validate(value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HTTPException(422, "The checkpoint upload could not be read. Choose the original downloaded file, 4 KB or smaller.") from exc


async def _call(function: Callable[..., Any], *args: Any) -> Any:
    try:
        return await run_in_threadpool(function, *args)
    except EvolutionLedgerInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except checkpoint.CheckpointInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except checkpoint.CheckpointUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except EvolutionLedgerError as exc:
        raise HTTPException(
            status_code=503,
            detail="Learning history is unavailable or its stored checks did not match. Select Refresh before relying on it.",
        ) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Learning history is unavailable. Select Refresh; if it keeps failing, ask your administrator to check it.",
        ) from exc


def create_evolution_ledger_router() -> APIRouter:
    """Create the audit-only, read-only Evolution Ledger API."""

    router = APIRouter(prefix="/audit/evolution-ledger", tags=["evolution-ledger"])

    @router.get("/snapshot")
    async def snapshot(request: Request) -> dict[str, Any]:
        require_permission(request, "audit")
        if request.query_params:
            raise HTTPException(status_code=404, detail="evolution ledger unavailable")
        return await _call(_snapshot)

    @router.post("/verify-receipt")
    async def verify_receipt(request: Request, body: VerifyReceiptIn) -> dict[str, Any]:
        require_permission(request, "audit")
        return await _call(_verify_receipt, body)

    @router.get("/checkpoint/status")
    async def checkpoint_status(request: Request) -> dict[str, Any]:
        require_permission(request, "audit")
        if request.query_params:
            raise HTTPException(404, "History checkpoint unavailable")
        return await _call(_checkpoint_status)

    @router.get("/checkpoint/download")
    async def download_checkpoint(request: Request) -> Response:
        require_permission(request, "audit")
        if request.query_params:
            raise HTTPException(404, "History checkpoint unavailable")
        value = await _call(_download_checkpoint)
        return Response(json.dumps(value, sort_keys=True, separators=(",", ":")), media_type="application/json",
                        headers={"Cache-Control": "no-store, private, max-age=0", "Pragma": "no-cache",
                                 "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                                 "Content-Disposition": 'attachment; filename="lightwork-learning-history-checkpoint.json"'})

    @router.post("/checkpoint/check")
    async def verify_checkpoint(request: Request) -> dict[str, Any]:
        require_permission(request, "audit")
        if request.query_params:
            raise HTTPException(404, "History checkpoint unavailable")
        body = await _checkpoint_upload(request)
        return await _call(_verify_checkpoint, body)

    @router.get("/entries/{entry_sha256}/receipt")
    async def download_receipt(
        request: Request, entry_sha256: str = PathParam(pattern=r"^[0-9a-f]{64}$"),
    ) -> Response:
        require_permission(request, "audit")
        if request.query_params:
            raise HTTPException(404, "Recorded receipt unavailable")
        receipt = await _call(_recorded_receipt, entry_sha256)
        return Response(json.dumps(receipt, sort_keys=True, separators=(",", ":")), media_type="application/json",
                        headers={"Cache-Control": "no-store, private, max-age=0", "Pragma": "no-cache",
                                 "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                                 "Content-Disposition": f'attachment; filename="learning-receipt-{entry_sha256[:16]}.json"'})

    return router


router = create_evolution_ledger_router()

__all__ = [
    "RECEIPT_VERIFICATION_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "VerifyReceiptIn",
    "create_evolution_ledger_router",
    "router",
]
