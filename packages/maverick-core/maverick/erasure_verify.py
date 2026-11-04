"""Differential erasure verification.

A right-to-erasure (GDPR Art. 17) run that *says* it deleted a subject's data
is not the same as proving it. This verifies the claim: after an erase, the
subject must have **zero** residual records in every store this module counts,
and every required store must have been checked successfully.

The subject scan comes from :func:`maverick.dsar.export_subject_data`:
conversations, turns, goals, episodes, facts and audit events, plus
user-scoped facts and knowledge chunks added here. Complete goal-graph proof
uses a signed erasure receipt created before mutation. The receipt contains the
exact conversation, transitive descendant-goal, and episode IDs, allowing
strict post-delete counts across every goal-linked table plus live and
historical episode-derived facts even after the rows that originally
attributed those records to the subject are gone.

A bare post-hoc ``(channel, user)`` scan cannot reconstruct orphan goal IDs and
therefore never claims complete erasure: goal-linked stores are marked
indeterminate until a tenant-scoped receipt is supplied. Receipts store no raw
subject or subject-derived hash.

Within its scope the logic is sound: subject-matching is shared with the erase
path by construction ("a row that *would* be erased is a row that *is*
exported"), so a non-zero residual count is definitionally an incomplete
erasure - the same rule, read back. The operation is read-only, but its verdict
is fail-closed: an unreadable required store produces an ``indeterminate``
report, never a clean certificate.

* :func:`verify_erasure` - the post-erasure check: per-store proof status,
  residual counts and a ``clean`` verdict.
* :func:`differential` - the before/after proof: every ``after`` count is zero
  AND the erase actually removed something (some ``before`` count was > 0).
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from .erasure_receipts import GOAL_LINKED_STORES, RECEIPT_STORES

_DSAR_STORES = (
    "conversations",
    "turns",
    "goals",
    "episodes",
    "fact_history",
    "audit_events",
)
_MAX_ERROR_CHARS = 500


def _safe_error(error: BaseException | str) -> str:
    """Return a bounded, single-line operator-facing verification error."""
    if isinstance(error, BaseException):
        label = type(error).__name__
        try:
            detail = str(error)
        except Exception:  # pragma: no cover - hostile exception __str__
            detail = ""
        raw = f"{label}: {detail}" if detail else label
        cause = error.__cause__
        if cause is not None and cause is not error:
            cause_label = type(cause).__name__
            try:
                cause_detail = str(cause)
            except Exception:  # pragma: no cover - hostile exception __str__
                cause_detail = ""
            raw += (
                f"; caused by {cause_label}: {cause_detail}"
                if cause_detail
                else f"; caused by {cause_label}"
            )
    else:
        raw = str(error)
    clean = " ".join(raw.replace("\x00", "").split())
    return clean[:_MAX_ERROR_CHARS] or "verification failed"


def _checked(count: Any) -> dict[str, Any]:
    """Validate a count and return the public per-store proof shape."""
    if not isinstance(count, int) or isinstance(count, bool):
        raise ValueError("count must be a non-negative integer")
    if count < 0:
        raise ValueError("count must be a non-negative integer")
    return {"checked": True, "count": count, "error": None}


def _unchecked(error: BaseException | str) -> dict[str, Any]:
    return {"checked": False, "count": None, "error": _safe_error(error)}


def _capture_count(counter: Callable[[], Any]) -> dict[str, Any]:
    try:
        return _checked(counter())
    except Exception as error:
        return _unchecked(error)


def _fact_subject_token(channel: str, user_id: str) -> str:
    """Stable, delimiter-safe token for explicitly user-scoped facts."""
    return f"{quote(channel, safe='')}:{quote(user_id, safe='')}"


def _count_user_scoped_facts(
    user_id: str,
    *,
    channel: str | None,
    tenant: str | None,
    world: Any = None,
) -> int:
    """Count explicitly user-scoped global facts for the erasure subject."""
    if not channel:
        raise RuntimeError("subject channel is unresolved")
    from .dsar import _resolve_world

    if world is None:
        world = _resolve_world(tenant, strict=True)
    if world is None:
        raise RuntimeError("world-model fact store is unavailable")
    if not hasattr(world, "facts_matching"):
        raise RuntimeError("world-model fact store cannot be queried")
    return len(world.facts_matching(_fact_subject_token(channel, user_id)))


def _count_user_scoped_fact_history(
    user_id: str,
    *,
    channel: str | None,
    tenant: str | None,
    world: Any = None,
) -> int:
    """Count every retained version under the subject's explicit fact prefix."""
    if not channel:
        raise RuntimeError("subject channel is unresolved")
    from .dsar import _resolve_world

    if world is None:
        world = _resolve_world(tenant, strict=True)
    if world is None:
        raise RuntimeError("world-model fact history store is unavailable")
    history = getattr(world, "fact_history_matching", None)
    if not callable(history):
        raise RuntimeError("world-model fact history store cannot be queried")
    matched = history(_fact_subject_token(channel, user_id))
    if not isinstance(matched, Mapping):
        raise RuntimeError("world-model fact history query returned invalid data")
    return sum(len(versions) for versions in matched.values())


def _count_knowledge_chunks(
    user_id: str,
    *,
    channel: str | None,
    tenant: str | None,
) -> int:
    """Count through the same tenant-explicit, fail-closed admin boundary."""
    if not channel:
        raise RuntimeError("subject channel is unresolved")

    from .knowledge_admin import count_subject
    return count_subject(channel, user_id, tenant=tenant)


def _export_store_statuses(
    bundle: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    raw_counts = bundle.get("counts")
    if not isinstance(raw_counts, Mapping):
        error = _unchecked("DSAR export did not return per-store counts")
        return {name: dict(error) for name in _DSAR_STORES}

    stores: dict[str, dict[str, Any]] = {}
    for name in _DSAR_STORES:
        if name not in raw_counts:
            stores[name] = _unchecked(
                f"DSAR export omitted required store {name!r}"
            )
            continue
        stores[name] = _capture_count(lambda name=name: raw_counts[name])
    return stores


def _expected_receipt_tenant(tenant: str | None) -> str:
    if tenant:
        return str(tenant)
    from .paths import current_tenant_id

    return str(current_tenant_id() or "shared")


def _resolve_proof_world(tenant: str | None) -> Any:
    from .dsar import _resolve_world

    world = _resolve_world(tenant, strict=True)
    if world is None:  # pragma: no cover - strict resolver already raises
        raise RuntimeError("world model is unavailable for receipt proof")
    return world


def _verify_auxiliary_closure(
    proof_world: Any,
    manifest: Mapping[str, Any] | None,
    *,
    durable_proof: bool,
    expected_tenant: str,
    receipt_error: BaseException | str | None,
) -> tuple[bool, BaseException | str | None, tuple[str, ...]]:
    """Resolve the durable post-delete proof without inflating scan logic."""
    from .erasure_receipts import (
        AUXILIARY_ERASURE_STORES,
        load_verified_erasure_closure,
    )

    if not durable_proof or manifest is None:
        return (
            False,
            receipt_error
            or "durable erasure receipt is unavailable for closure verification",
            AUXILIARY_ERASURE_STORES,
        )
    try:
        load_verified_erasure_closure(
            proof_world,
            manifest,
            expected_tenant=expected_tenant,
        )
    except Exception as error:
        return False, error, AUXILIARY_ERASURE_STORES
    return True, None, AUXILIARY_ERASURE_STORES


def verify_erasure(
    user_id: str,
    *,
    channel: str | None = None,
    tenant: str | None = None,
    receipt_id: str | None = None,
    receipt: Mapping[str, Any] | None = None,
    world: Any = None,
) -> dict:
    """Confirm no residual data remains for a subject after erasure.

    Returns ``{subject, tenant, stores, counts, residual, errors, clean,
    indeterminate, verified_at}``. Every ``stores`` entry has
    ``{checked, count, error}``; ``clean`` is True iff every required store was
    checked and every count is zero. ``channel`` should be given (it is part of
    subject identity); the export fails closed on an ambiguous bare
    ``user_id``.

    ``receipt_id`` loads a durable, signed pre-delete scope receipt. ``receipt``
    accepts the same object directly for automatic same-process verification.
    A clean certificate also requires the bound, signed post-delete closure
    proving that attachment files, user notes, the LLM cache, and audit-chain
    maintenance all completed. An unsigned in-memory manifest still provides
    exact diagnostic counts, but cannot yield ``clean=True``.

    When the channel cannot be resolved, a receipt is missing/tampered, or any
    required store cannot be read, ``indeterminate`` is True and ``clean`` is
    forced False. A failed count is never represented as zero.
    """
    from .dsar import export_subject_data

    bundle: dict[str, Any]
    try:
        export_kwargs: dict[str, Any] = {
            "channel": channel,
            "tenant": tenant,
            "strict": True,
        }
        if world is not None:
            export_kwargs["world"] = world
        bundle = export_subject_data(user_id, **export_kwargs)
        if not isinstance(bundle, dict):
            raise TypeError("DSAR export returned a non-object result")
        stores = _export_store_statuses(bundle)
        subject = bundle.get("subject") or {}
    except Exception as error:
        bundle = {}
        subject = {"user_id": user_id, "channel": channel}
        failed = _unchecked(error)
        stores = {name: dict(failed) for name in _DSAR_STORES}

    resolved_channel = (
        subject.get("channel") if isinstance(subject, dict) else channel
    )
    if not resolved_channel:
        scope_error = _unchecked(
            "subject channel could not be resolved; pass an explicit channel"
        )
        # The export deliberately returns empty sections for an unresolved
        # subject. Those zeroes are not observations, so mark them unchecked.
        stores.update({name: dict(scope_error) for name in _DSAR_STORES})

    stores["facts"] = _capture_count(
        lambda: _count_user_scoped_facts(
            user_id,
            channel=resolved_channel,
            tenant=tenant,
            world=world,
        )
    )
    stores["fact_history"] = _capture_count(
        lambda: _count_user_scoped_fact_history(
            user_id,
            channel=resolved_channel,
            tenant=tenant,
            world=world,
        )
    )
    stores["knowledge_chunks"] = _capture_count(
        lambda: _count_knowledge_chunks(
            user_id,
            channel=resolved_channel,
            tenant=tenant,
        )
    )

    expected_tenant = _expected_receipt_tenant(tenant)
    manifest: dict[str, Any] | None = None
    durable_proof = False
    durable_closure = False
    receipt_error: BaseException | str | None = None
    closure_error: BaseException | str | None = None
    proof_world = world
    if receipt_id is not None and receipt is not None:
        receipt_error = "pass receipt_id or receipt, not both"
    else:
        try:
            if proof_world is None:
                proof_world = _resolve_proof_world(tenant)
            if receipt_id is not None:
                from .erasure_receipts import load_verified_receipt

                manifest = load_verified_receipt(
                    proof_world,
                    receipt_id,
                    expected_tenant=expected_tenant,
                )
                durable_proof = True
            elif receipt is not None:
                from .erasure_receipts import (
                    receipt_is_durable,
                    validate_manifest,
                    verify_signed_receipt,
                )

                try:
                    manifest = verify_signed_receipt(
                        receipt,
                        expected_tenant=expected_tenant,
                    )
                    durable_proof = receipt_is_durable(
                        proof_world,
                        manifest,
                        expected_tenant=expected_tenant,
                    )
                    if not durable_proof:
                        receipt_error = (
                            "signed erasure receipt is not recoverable from "
                            "durable tenant storage"
                        )
                except Exception:
                    # An unsigned manifest is valid for immediate diagnostics
                    # after assurance infrastructure failed, but never for a
                    # clean certificate. A signed-looking/tampered object has
                    # extra fields and cannot pass this exact-shape fallback.
                    manifest = validate_manifest(
                        receipt,
                        expected_tenant=expected_tenant,
                    )
                    receipt_error = (
                        "erasure manifest is in-memory only; durable signed "
                        "proof was not created"
                    )
            else:
                receipt_error = (
                    "a signed pre-delete erasure receipt is required to prove "
                    "the goal-linked store closure"
                )
        except Exception as error:
            receipt_error = error
            manifest = None

    if manifest is None:
        scope_status = _unchecked(receipt_error or "erasure receipt is unavailable")
        for store in GOAL_LINKED_STORES:
            stores[store] = dict(scope_status)
    else:
        counter = getattr(proof_world, "count_erasure_receipt_store", None)
        if not callable(counter):
            scope_status = _unchecked(
                "world backend cannot count erasure receipt stores"
            )
            for store in RECEIPT_STORES:
                stores[store] = dict(scope_status)
        else:
            conversation_ids = list(manifest["conversation_ids"])
            goal_ids = list(manifest["goal_ids"])
            episode_ids = list(manifest["episode_ids"])
            for store in RECEIPT_STORES:
                stores[store] = _capture_count(
                    lambda store=store: counter(
                        store,
                        conversation_ids,
                        goal_ids,
                        episode_ids,
                    )
                )

    stores["erasure_receipt"] = (
        _checked(0)
        if durable_proof
        else _unchecked(receipt_error or "durable erasure receipt is unavailable")
    )
    (
        durable_closure,
        closure_error,
        auxiliary_stores,
    ) = _verify_auxiliary_closure(
        proof_world,
        manifest,
        durable_proof=durable_proof,
        expected_tenant=expected_tenant,
        receipt_error=receipt_error,
    )
    closure_status = (
        _checked(0)
        if durable_closure
        else _unchecked(
            closure_error or "durable auxiliary erasure closure is unavailable"
        )
    )
    for store in auxiliary_stores:
        stores[store] = dict(closure_status)

    counts = {
        name: int(status["count"])
        for name, status in stores.items()
        if status["checked"]
    }
    residual = {name: count for name, count in counts.items() if count}
    errors = {
        name: str(status["error"])
        for name, status in stores.items()
        if not status["checked"]
    }
    indeterminate = bool(errors)
    result = {
        "subject": subject,
        "tenant": tenant,
        "stores": stores,
        "counts": counts,
        "residual": residual,
        "errors": errors,
        "indeterminate": indeterminate,
        "clean": (not residual) and not indeterminate,
        "durable_proof": durable_proof,
        "durable_closure": durable_closure,
        "receipt_id": (
            manifest.get("receipt_id")
            if isinstance(manifest, dict)
            else receipt_id
        ),
        "proof_scope": (
            "receipt_and_auxiliary_closure"
            if durable_closure
            else (
                "receipt_closure"
                if manifest is not None
                else "subject_scan_only"
            )
        ),
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
    if indeterminate:
        result["reason"] = "one or more required stores could not be verified"
    return result


def differential(before: dict, after: dict) -> dict:
    """Compare pre/post-erasure residual counts into a proof of removal.

    ``before``/``after`` are ``counts`` dicts (e.g. from two
    :func:`verify_erasure` calls). ``verified`` is True iff every ``after``
    count is zero AND at least one ``before`` count was positive - i.e. the
    erase had something to remove and left nothing behind.
    """
    keys = set(before) | set(after)
    removed = {key: int(before.get(key, 0)) - int(after.get(key, 0)) for key in keys}
    after_clean = all(int(after.get(key, 0)) == 0 for key in keys)
    had_data = any(int(before.get(key, 0)) > 0 for key in keys)
    return {
        "removed": removed,
        "after_clean": after_clean,
        "verified": after_clean and had_data,
    }


__all__ = ["verify_erasure", "differential"]
