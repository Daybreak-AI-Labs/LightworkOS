"""Privacy-minimized, integrity-protected erasure scope receipts.

After an Art. 17 erase removes a subject's conversations and turns, the world
model can no longer reconstruct which otherwise-orphaned goals belonged to the
subject. A proof therefore has to preserve the exact pre-delete ID closure.

Receipts intentionally contain no channel, user identifier, or subject-derived
hash. They contain only a random receipt id, tenant boundary, exact
conversation/goal/episode IDs, the complete store scope, issuance/retirement
timestamps, and an Ed25519 signature made with the existing governed
audit-signing key. Numeric IDs remain indirect identifiers, so rows are
tenant-scoped, insert-only, and retire after the signed retention deadline.

Receipt failure must never prevent privacy deletion. Callers may retain an
unsigned manifest in memory to race-check and inspect the deletion, but only a
signed receipt recovered byte-for-byte from durable storage can support a
``clean`` certificate.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

RECEIPT_SCHEMA = "lightwork.erasure-receipt.v2"
ERASURE_CLOSURE_SCHEMA = "lightwork.erasure-closure.v1"
RECEIPT_RETENTION_DAYS = 365 * 7
MAX_RECEIPT_IDS = 100_000

SOURCE_EPISODE_STORES = {
    "episode_facts": "facts",
    "episode_fact_history": "fact_history",
}
GOAL_LINKED_STORES = (
    "goals",
    "turns",
    "episodes",
    *SOURCE_EPISODE_STORES,
    "artifacts",
    "attachments",
    "attachment_submissions",
    "goal_events",
    "goal_origins",
    "goal_mutation_receipts",
    "messages",
    "processed_messages",
    "questions",
    "share_links",
    "signoffs",
)
RECEIPT_STORES = ("conversations", *GOAL_LINKED_STORES)
AUXILIARY_ERASURE_STORES = (
    "attachment_files",
    "user_notes",
    "llm_cache",
    "audit_chain",
)

_RECEIPT_ID_RE = re.compile(r"[0-9a-f]{32}")
_KEY_ID_RE = re.compile(r"[0-9a-f]{16}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")
_BODY_FIELDS = {
    "schema",
    "receipt_id",
    "tenant_id",
    "issued_at",
    "retained_until",
    "conversation_ids",
    "goal_ids",
    "episode_ids",
    "expected_stores",
}
_SIGNED_FIELDS = _BODY_FIELDS | {"payload_sha256", "key_id", "signature"}
_CLOSURE_BODY_FIELDS = {
    "schema",
    "closure_id",
    "receipt_id",
    "tenant_id",
    "completed_at",
    "retained_until",
    "receipt_payload_sha256",
    "stores",
}
_SIGNED_CLOSURE_FIELDS = _CLOSURE_BODY_FIELDS | {
    "payload_sha256",
    "key_id",
    "signature",
}


class ErasureReceiptError(RuntimeError):
    """An erasure manifest or its durable integrity proof is invalid."""


class ErasurePlanChanged(RuntimeError):
    """The goal closure changed after its receipt was prepared."""


def _canonical(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise ErasureReceiptError("erasure receipt is not canonical JSON") from error


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ErasureReceiptError(f"erasure receipt {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ErasureReceiptError(
            f"erasure receipt {field} is invalid"
        ) from error
    if parsed.tzinfo is None:
        raise ErasureReceiptError(f"erasure receipt {field} has no timezone")
    return parsed.astimezone(timezone.utc)


def _ids(value: Any, field: str, *, require_nonempty: bool) -> list[int]:
    if not isinstance(value, list) or len(value) > MAX_RECEIPT_IDS:
        raise ErasureReceiptError(f"erasure receipt {field} is invalid")
    if require_nonempty and not value:
        raise ErasureReceiptError(f"erasure receipt {field} is empty")
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item <= 0
        for item in value
    ):
        raise ErasureReceiptError(
            f"erasure receipt {field} must contain positive integer IDs"
        )
    if value != sorted(set(value)):
        raise ErasureReceiptError(
            f"erasure receipt {field} must be sorted and unique"
        )
    return list(value)


def validate_manifest(
    value: Mapping[str, Any],
    *,
    require_signature: bool = False,
    expected_tenant: str | None = None,
) -> dict[str, Any]:
    """Validate and normalize a subject-free receipt or in-memory manifest."""
    if not isinstance(value, Mapping):
        raise ErasureReceiptError("erasure receipt must be an object")
    expected_fields = _SIGNED_FIELDS if require_signature else _BODY_FIELDS
    if set(value) != expected_fields:
        raise ErasureReceiptError(
            "erasure receipt has missing or unexpected fields"
        )
    receipt_id = value.get("receipt_id")
    tenant_id = value.get("tenant_id")
    if not isinstance(receipt_id, str) or not _RECEIPT_ID_RE.fullmatch(receipt_id):
        raise ErasureReceiptError("erasure receipt id is invalid")
    if (
        not isinstance(tenant_id, str)
        or not tenant_id
        or len(tenant_id) > 256
        or any(ord(char) < 32 for char in tenant_id)
    ):
        raise ErasureReceiptError("erasure receipt tenant is invalid")
    if expected_tenant is not None and tenant_id != expected_tenant:
        raise ErasureReceiptError("erasure receipt belongs to another tenant")
    if value.get("schema") != RECEIPT_SCHEMA:
        raise ErasureReceiptError("erasure receipt schema is unsupported")

    issued_at = _parse_utc(value.get("issued_at"), "issued_at")
    retained_until = _parse_utc(value.get("retained_until"), "retained_until")
    if retained_until != issued_at + timedelta(days=RECEIPT_RETENTION_DAYS):
        raise ErasureReceiptError(
            "erasure receipt retention period is invalid"
        )
    conversation_ids = _ids(
        value.get("conversation_ids"),
        "conversation_ids",
        require_nonempty=True,
    )
    goal_ids = _ids(
        value.get("goal_ids"),
        "goal_ids",
        require_nonempty=False,
    )
    episode_ids = _ids(
        value.get("episode_ids"),
        "episode_ids",
        require_nonempty=False,
    )
    expected_stores = value.get("expected_stores")
    if expected_stores != list(RECEIPT_STORES):
        raise ErasureReceiptError(
            "erasure receipt does not cover the complete store scope"
        )

    normalized = {
        "schema": RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "tenant_id": tenant_id,
        "issued_at": _utc(issued_at),
        "retained_until": _utc(retained_until),
        "conversation_ids": conversation_ids,
        "goal_ids": goal_ids,
        "episode_ids": episode_ids,
        "expected_stores": list(RECEIPT_STORES),
    }
    if require_signature:
        payload_sha256 = value.get("payload_sha256")
        key_id = value.get("key_id")
        signature = value.get("signature")
        if (
            not isinstance(payload_sha256, str)
            or not _SHA256_RE.fullmatch(payload_sha256)
            or not isinstance(key_id, str)
            or not _KEY_ID_RE.fullmatch(key_id)
            or not isinstance(signature, str)
            or not _SIGNATURE_RE.fullmatch(signature)
        ):
            raise ErasureReceiptError(
                "erasure receipt signing fields are invalid"
            )
        normalized.update(
            payload_sha256=payload_sha256,
            key_id=key_id,
            signature=signature,
        )
    return normalized


def build_manifest(
    *,
    tenant_id: str,
    conversation_ids: list[int] | tuple[int, ...] | set[int],
    goal_ids: list[int] | tuple[int, ...] | set[int],
    episode_ids: list[int] | tuple[int, ...] | set[int] = (),
    now: datetime | None = None,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    """Build the unsigned, subject-free closure used before any mutation."""
    issued = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    manifest = {
        "schema": RECEIPT_SCHEMA,
        "receipt_id": receipt_id or secrets.token_hex(16),
        "tenant_id": str(tenant_id or "shared"),
        "issued_at": _utc(issued),
        "retained_until": _utc(
            issued + timedelta(days=RECEIPT_RETENTION_DAYS)
        ),
        "conversation_ids": sorted(set(conversation_ids)),
        "goal_ids": sorted(set(goal_ids)),
        "episode_ids": sorted(set(episode_ids)),
        "expected_stores": list(RECEIPT_STORES),
    }
    return validate_manifest(manifest)


def _sign_body(body: Mapping[str, Any]) -> dict[str, Any]:
    """Attach the active governed audit-key signature to a canonical body."""
    canonical = _canonical(body).encode("utf-8")
    payload_sha256 = hashlib.sha256(canonical).hexdigest()

    from .audit.signing import _load_or_create_keypair

    private_bytes, public_bytes, key_id = _load_or_create_keypair()
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as error:
        raise ErasureReceiptError(
            "cryptography is required for erasure receipts"
        ) from error
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    derived_public = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if derived_public != public_bytes:
        raise ErasureReceiptError("erasure receipt signing keypair is invalid")
    return {
        **dict(body),
        "payload_sha256": payload_sha256,
        "key_id": key_id,
        "signature": signer.sign(bytes.fromhex(payload_sha256)).hex(),
    }


def _verify_signed_body(
    record: Mapping[str, Any],
    body_fields: set[str],
) -> None:
    """Verify the canonical body digest and its trusted-key signature."""
    body = {field: record[field] for field in body_fields}
    digest = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    if not secrets.compare_digest(digest, str(record["payload_sha256"])):
        raise ErasureReceiptError("erasure receipt payload digest is invalid")

    from .audit.signing import trusted_audit_public_keys, verify_ed25519

    try:
        registry = trusted_audit_public_keys()
    except Exception as error:
        raise ErasureReceiptError(
            "erasure receipt trust registry is unavailable"
        ) from error
    public_key = registry.get(str(record["key_id"]))
    if not public_key or not verify_ed25519(
        public_key,
        str(record["signature"]),
        bytes.fromhex(digest),
    ):
        raise ErasureReceiptError("erasure receipt signature is invalid")


def sign_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Bind a manifest to the active governed audit-signing key era."""
    body = validate_manifest(manifest)
    record = _sign_body(body)
    return validate_manifest(record, require_signature=True)


def verify_signed_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_tenant: str,
) -> dict[str, Any]:
    """Return a normalized receipt only if its protected key verifies it."""
    record = validate_manifest(
        receipt,
        require_signature=True,
        expected_tenant=expected_tenant,
    )
    _verify_signed_body(record, _BODY_FIELDS)
    return record


def _closure_storage_id(receipt_id: str) -> str:
    """Derive a subject-free immutable-row id for a receipt's completion proof."""
    return hashlib.sha256(
        f"{ERASURE_CLOSURE_SCHEMA}:{receipt_id}".encode("ascii")
    ).hexdigest()[:32]


def validate_erasure_closure(
    value: Mapping[str, Any],
    *,
    require_signature: bool = False,
    expected_tenant: str | None = None,
    expected_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the signed zero-result proof for non-database erasure stores."""
    if not isinstance(value, Mapping):
        raise ErasureReceiptError("erasure closure must be an object")
    expected_fields = (
        _SIGNED_CLOSURE_FIELDS if require_signature else _CLOSURE_BODY_FIELDS
    )
    if set(value) != expected_fields:
        raise ErasureReceiptError(
            "erasure closure has missing or unexpected fields"
        )

    closure_id = value.get("closure_id")
    receipt_id = value.get("receipt_id")
    tenant_id = value.get("tenant_id")
    if not isinstance(closure_id, str) or not _RECEIPT_ID_RE.fullmatch(closure_id):
        raise ErasureReceiptError("erasure closure id is invalid")
    if not isinstance(receipt_id, str) or not _RECEIPT_ID_RE.fullmatch(receipt_id):
        raise ErasureReceiptError("erasure closure receipt id is invalid")
    if closure_id != _closure_storage_id(receipt_id):
        raise ErasureReceiptError("erasure closure id is not bound to its receipt")
    if (
        not isinstance(tenant_id, str)
        or not tenant_id
        or len(tenant_id) > 256
        or any(ord(char) < 32 for char in tenant_id)
    ):
        raise ErasureReceiptError("erasure closure tenant is invalid")
    if expected_tenant is not None and tenant_id != expected_tenant:
        raise ErasureReceiptError("erasure closure belongs to another tenant")
    if value.get("schema") != ERASURE_CLOSURE_SCHEMA:
        raise ErasureReceiptError("erasure closure schema is unsupported")

    completed_at = _parse_utc(value.get("completed_at"), "completed_at")
    retained_until = _parse_utc(value.get("retained_until"), "retained_until")
    receipt_payload_sha256 = value.get("receipt_payload_sha256")
    if (
        not isinstance(receipt_payload_sha256, str)
        or not _SHA256_RE.fullmatch(receipt_payload_sha256)
    ):
        raise ErasureReceiptError("erasure closure receipt digest is invalid")

    stores = value.get("stores")
    expected_stores = dict.fromkeys(AUXILIARY_ERASURE_STORES, 0)
    if (
        not isinstance(stores, Mapping)
        or dict(stores) != expected_stores
        or any(isinstance(count, bool) for count in stores.values())
    ):
        raise ErasureReceiptError(
            "erasure closure does not prove every auxiliary store is zero"
        )

    normalized = {
        "schema": ERASURE_CLOSURE_SCHEMA,
        "closure_id": closure_id,
        "receipt_id": receipt_id,
        "tenant_id": tenant_id,
        "completed_at": _utc(completed_at),
        "retained_until": _utc(retained_until),
        "receipt_payload_sha256": receipt_payload_sha256,
        "stores": expected_stores,
    }

    if expected_receipt is not None:
        receipt = validate_manifest(
            expected_receipt,
            require_signature=True,
            expected_tenant=tenant_id,
        )
        issued_at = _parse_utc(receipt["issued_at"], "issued_at")
        if receipt_id != receipt["receipt_id"]:
            raise ErasureReceiptError("erasure closure names another receipt")
        if retained_until != _parse_utc(
            receipt["retained_until"],
            "retained_until",
        ):
            raise ErasureReceiptError(
                "erasure closure retention does not match its receipt"
            )
        if not secrets.compare_digest(
            receipt_payload_sha256,
            receipt["payload_sha256"],
        ):
            raise ErasureReceiptError(
                "erasure closure is not bound to its receipt payload"
            )
        if completed_at < issued_at or completed_at >= retained_until:
            raise ErasureReceiptError(
                "erasure closure completion time is outside receipt retention"
            )

    if require_signature:
        payload_sha256 = value.get("payload_sha256")
        key_id = value.get("key_id")
        signature = value.get("signature")
        if (
            not isinstance(payload_sha256, str)
            or not _SHA256_RE.fullmatch(payload_sha256)
            or not isinstance(key_id, str)
            or not _KEY_ID_RE.fullmatch(key_id)
            or not isinstance(signature, str)
            or not _SIGNATURE_RE.fullmatch(signature)
        ):
            raise ErasureReceiptError(
                "erasure closure signing fields are invalid"
            )
        normalized.update(
            payload_sha256=payload_sha256,
            key_id=key_id,
            signature=signature,
        )
    return normalized


def sign_erasure_closure(
    closure: Mapping[str, Any],
    *,
    expected_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind an auxiliary-store completion proof to the governed audit key."""
    receipt = validate_manifest(expected_receipt, require_signature=True)
    body = validate_erasure_closure(
        closure,
        expected_tenant=receipt["tenant_id"],
        expected_receipt=receipt,
    )
    signed = _sign_body(body)
    return validate_erasure_closure(
        signed,
        require_signature=True,
        expected_tenant=receipt["tenant_id"],
        expected_receipt=receipt,
    )


def _parse_canonical_record(raw: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise ErasureReceiptError(f"{label} was not found")
    try:
        parsed = json.loads(
            raw,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid constant {value}")
            ),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ErasureReceiptError(f"stored {label} is malformed") from error
    if not isinstance(parsed, dict) or _canonical(parsed) != raw:
        raise ErasureReceiptError(f"stored {label} is not canonical")
    return parsed


def persist_receipt(world: Any, manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Sign, insert immutably, recover, and self-verify one receipt."""
    signed = sign_manifest(manifest)
    raw = _canonical(signed)
    try:
        world.store_erasure_receipt(
            signed["receipt_id"],
            raw,
            tenant_id=signed["tenant_id"],
            created_at=_parse_utc(signed["issued_at"], "issued_at").timestamp(),
            retained_until=_parse_utc(
                signed["retained_until"],
                "retained_until",
            ).timestamp(),
        )
        recovered_raw = world.get_erasure_receipt(
            signed["receipt_id"],
            tenant_id=signed["tenant_id"],
        )
    except Exception as error:
        raise ErasureReceiptError(
            "erasure receipt could not be durably stored"
        ) from error
    if recovered_raw != raw:
        raise ErasureReceiptError(
            "erasure receipt durable recovery did not match issuance"
        )
    return verify_signed_receipt(signed, expected_tenant=signed["tenant_id"])


def load_verified_receipt(
    world: Any,
    receipt_id: str,
    *,
    expected_tenant: str,
) -> dict[str, Any]:
    """Recover and verify a tenant-scoped receipt from immutable storage."""
    if not isinstance(receipt_id, str) or not _RECEIPT_ID_RE.fullmatch(receipt_id):
        raise ErasureReceiptError("erasure receipt id is invalid")
    try:
        raw = world.get_erasure_receipt(
            receipt_id,
            tenant_id=expected_tenant,
        )
    except Exception as error:
        raise ErasureReceiptError(
            "erasure receipt storage is unavailable"
        ) from error
    parsed = _parse_canonical_record(raw, label="erasure receipt")
    verified = verify_signed_receipt(parsed, expected_tenant=expected_tenant)
    retained_until = _parse_utc(
        verified["retained_until"],
        "retained_until",
    )
    if retained_until <= datetime.now(timezone.utc):
        raise ErasureReceiptError("erasure receipt has expired")
    return verified


def load_verified_erasure_closure(
    world: Any,
    receipt: Mapping[str, Any],
    *,
    expected_tenant: str,
) -> dict[str, Any]:
    """Load a durable signed proof that every auxiliary erase operation ended."""
    verified_receipt = verify_signed_receipt(
        receipt,
        expected_tenant=expected_tenant,
    )
    durable_receipt = load_verified_receipt(
        world,
        verified_receipt["receipt_id"],
        expected_tenant=expected_tenant,
    )
    if not secrets.compare_digest(
        _canonical(verified_receipt),
        _canonical(durable_receipt),
    ):
        raise ErasureReceiptError(
            "erasure closure receipt does not match durable storage"
        )

    closure_id = _closure_storage_id(verified_receipt["receipt_id"])
    try:
        raw = world.get_erasure_receipt(
            closure_id,
            tenant_id=expected_tenant,
        )
    except Exception as error:
        raise ErasureReceiptError(
            "erasure closure storage is unavailable"
        ) from error
    parsed = _parse_canonical_record(raw, label="erasure closure")
    closure = validate_erasure_closure(
        parsed,
        require_signature=True,
        expected_tenant=expected_tenant,
        expected_receipt=verified_receipt,
    )
    _verify_signed_body(closure, _CLOSURE_BODY_FIELDS)
    if _parse_utc(
        closure["retained_until"],
        "retained_until",
    ) <= datetime.now(timezone.utc):
        raise ErasureReceiptError("erasure closure has expired")
    return closure


def persist_erasure_closure(
    world: Any,
    receipt: Mapping[str, Any],
    *,
    expected_tenant: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Persist the auxiliary zero proof only after every caller check succeeds."""
    verified_receipt = verify_signed_receipt(
        receipt,
        expected_tenant=expected_tenant,
    )
    durable_receipt = load_verified_receipt(
        world,
        verified_receipt["receipt_id"],
        expected_tenant=expected_tenant,
    )
    if not secrets.compare_digest(
        _canonical(verified_receipt),
        _canonical(durable_receipt),
    ):
        raise ErasureReceiptError(
            "erasure closure cannot bind a non-durable receipt"
        )

    closure_id = _closure_storage_id(verified_receipt["receipt_id"])
    try:
        existing = world.get_erasure_receipt(
            closure_id,
            tenant_id=expected_tenant,
        )
    except Exception as error:
        raise ErasureReceiptError(
            "erasure closure storage is unavailable"
        ) from error
    if existing is not None:
        return load_verified_erasure_closure(
            world,
            verified_receipt,
            expected_tenant=expected_tenant,
        )

    completed = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    body = {
        "schema": ERASURE_CLOSURE_SCHEMA,
        "closure_id": closure_id,
        "receipt_id": verified_receipt["receipt_id"],
        "tenant_id": expected_tenant,
        "completed_at": _utc(completed),
        "retained_until": verified_receipt["retained_until"],
        "receipt_payload_sha256": verified_receipt["payload_sha256"],
        "stores": dict.fromkeys(AUXILIARY_ERASURE_STORES, 0),
    }
    signed = sign_erasure_closure(
        body,
        expected_receipt=verified_receipt,
    )
    raw = _canonical(signed)
    try:
        world.store_erasure_receipt(
            closure_id,
            raw,
            tenant_id=expected_tenant,
            created_at=completed.timestamp(),
            retained_until=_parse_utc(
                signed["retained_until"],
                "retained_until",
            ).timestamp(),
        )
    except Exception as error:
        # A concurrent identical completion may win the insert. Accept only a
        # fully verified immutable row; never treat a conflicting row as zero.
        try:
            recovered = load_verified_erasure_closure(
                world,
                verified_receipt,
                expected_tenant=expected_tenant,
            )
        except Exception:
            raise ErasureReceiptError(
                "erasure closure could not be durably stored"
            ) from error
        return recovered

    recovered = load_verified_erasure_closure(
        world,
        verified_receipt,
        expected_tenant=expected_tenant,
    )
    if not secrets.compare_digest(_canonical(recovered), raw):
        raise ErasureReceiptError(
            "erasure closure durable recovery did not match issuance"
        )
    return recovered


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def receipt_is_durable(
    world: Any,
    receipt: Mapping[str, Any],
    *,
    expected_tenant: str,
) -> bool:
    """Whether a signed receipt is recoverable byte-for-byte from storage."""
    try:
        verified = verify_signed_receipt(
            receipt,
            expected_tenant=expected_tenant,
        )
        recovered = load_verified_receipt(
            world,
            verified["receipt_id"],
            expected_tenant=expected_tenant,
        )
        return secrets.compare_digest(_canonical(verified), _canonical(recovered))
    except (ErasureReceiptError, OSError, ValueError):
        return False


def retire_expired_receipts(
    world: Any,
    *,
    tenant_id: str,
    now: float | None = None,
) -> int:
    """Delete receipts only after their signed retention deadline."""
    cutoff = float(now if now is not None else datetime.now(timezone.utc).timestamp())
    if not math.isfinite(cutoff) or cutoff < 0:
        raise ValueError("receipt retirement cutoff is invalid")
    return int(
        world.retire_erasure_receipts(
            cutoff,
            tenant_id=tenant_id,
        )
    )


__all__ = [
    "AUXILIARY_ERASURE_STORES",
    "ERASURE_CLOSURE_SCHEMA",
    "ErasurePlanChanged",
    "ErasureReceiptError",
    "GOAL_LINKED_STORES",
    "RECEIPT_SCHEMA",
    "RECEIPT_STORES",
    "RECEIPT_RETENTION_DAYS",
    "SOURCE_EPISODE_STORES",
    "build_manifest",
    "load_verified_erasure_closure",
    "load_verified_receipt",
    "persist_erasure_closure",
    "persist_receipt",
    "receipt_is_durable",
    "retire_expired_receipts",
    "sign_erasure_closure",
    "validate_erasure_closure",
    "validate_manifest",
    "verify_signed_receipt",
]
