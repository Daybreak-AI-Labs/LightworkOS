"""Officer-recorded handoff of an exact collected package; never remote delivery proof."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from . import privacy_ops as ops
from .authority_effects import authority_effect_fence
from .paths import current_tenant_id, data_dir

CHANNELS = {"secure_portal": "Secure requester portal", "encrypted_email": "Encrypted email",
            "approved_transfer": "Approved secure file transfer", "in_person": "Verified in-person handoff"}
SCOPE = ("This is the collected Lightwork package: conversations, work records, personal facts "
         "and matching activity entries. It may contain other people's details inside text. "
         "This step does not redact it, collect data from other systems, send it, or prove "
         "that the requester received it. Review its contents and your identity, recipient "
         "and disclosure checks before sharing it through an approved secure channel.")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _artifact(record):
    """Reuse native custody checks while the request's record lock is held."""
    if record.get("status") != "fulfilled" or record.get("kind") not in {"access", "portability"}:
        raise ops.RecordConflict("Collect this request's data before recording a package handoff.")
    stored = record.get("fulfillment") or {}
    path = Path(os.path.abspath(data_dir("dsar_requests") / "exports" / f"{record['id']}-export.json"))
    if (not isinstance(stored.get("export_path"), str)
            or Path(os.path.abspath(stored["export_path"])) != path
            or stored.get("export_schema") != ops._DSAR_EXPORT_SCHEMA):
        raise ops.PrivacyStateError("The collected package could not be verified.")
    result = ops._load_dsar_export_artifact(path, intent=ops._dsar_export_intent(record))
    if (result is None or not isinstance(stored.get("artifact_sha256"), str)
            or not hmac.compare_digest(result[1], stored["artifact_sha256"])):
        raise ops.PrivacyStateError("The collected package could not be verified.")
    return result


def _binding(record, artifact):
    return _digest({"schema": 1, "tenant": current_tenant_id() or "", "request": record["id"],
                    "revision": record["revision"], "artifact": artifact})


def _receipts(record):
    rows = record.get("package_handoffs") or []
    keys = ("tenant", "request_id", "artifact_sha256", "actor", "channel", "handed_at", "reference")
    if not isinstance(rows, list) or len(rows) > 20:
        raise ops.PrivacyStateError("The package handoff history could not be verified.")
    for row in rows:
        if (not isinstance(row, dict) or any(not isinstance(row.get(key), str) for key in keys)
                or row["tenant"] != (current_tenant_id() or "") or row["request_id"] != record["id"]
                or row["artifact_sha256"] != (record.get("fulfillment") or {}).get("artifact_sha256")
                or row["channel"] not in CHANNELS or row.get("operator_recorded") is not True
                or row.get("requester_receipt_verified") is not False
                or row.get("package_reviewed") is not True or row.get("identity_checked") is not True
                or type(row.get("recorded_at")) not in (int, float)
                or not math.isfinite(row["recorded_at"])
                or not isinstance(row.get("id"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["id"])
                or not hmac.compare_digest(row["id"], _digest({key: row[key] for key in keys}))):
            raise ops.PrivacyStateError("The package handoff history could not be verified.")
    return rows


def state(request_id, *, authorize):
    authorize()
    result = {}

    def inspect(record):
        authorize()
        if record.get("status") == "closed":
            result.update(binding="", counts={}, scope=SCOPE, request_id=record["id"],
                          artifact_sha256=(record.get("fulfillment") or {}).get("artifact_sha256"),
                          collected_at=record.get("fulfilled_at"),
                          receipts=_receipts(record),
                          audit_pending=bool(record.get("_audit_pending")), package_available=False)
            return
        bundle, artifact = _artifact(record)
        result.update(binding=_binding(record, artifact), counts=bundle["counts"], scope=SCOPE,
                      artifact_sha256=artifact,
                      request_id=record["id"], collected_at=record.get("fulfilled_at"),
                      receipts=_receipts(record),
                      audit_pending=bool(record.get("_audit_pending")), package_available=True)

    with authority_effect_fence():
        if ops._DSAR.update(request_id, inspect, metadata_only=True) is None:
            raise KeyError("This privacy request is unavailable.")
    return result


def record_handoff(request_id, *, binding, channel, handed_at, reference, actor,
                   reviewed, identity_checked, sent, authorize):
    """One immutable operator statement, with exact-package replay and durable audit outbox."""
    authorize()
    if channel not in CHANNELS or reviewed is not True or identity_checked is not True or sent is not True:
        raise ValueError("Confirm the package review, recipient checks and completed secure handoff.")
    if (not isinstance(reference, str) or not 3 <= len(reference.strip()) <= 200
            or any(ord(char) < 32 for char in reference)):
        raise ValueError("Enter a short evidence reference without personal data or access links.")
    try:
        stamp = datetime.fromisoformat(handed_at.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("time zone required")
        stamp = stamp.astimezone(timezone.utc)
        handed = stamp.timestamp()
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Choose the time when you handed off this package.") from exc
    if not time.time() - 365 * 86400 <= handed <= time.time() + 60:
        raise ValueError("Choose a handoff time in the past year, not a future time.")
    result = {}

    def apply(record):
        authorize()
        _bundle, artifact = _artifact(record)
        material = {"tenant": current_tenant_id() or "", "request_id": request_id,
                    "artifact_sha256": artifact, "actor": actor, "channel": channel,
                    "handed_at": stamp.isoformat(), "reference": reference.strip()}
        identity = _digest(material)
        receipts = _receipts(record)
        prior = next((row for row in receipts if row.get("id") == identity), None)
        if prior is not None:
            if any(prior.get(key) != value for key, value in material.items()):
                raise ops.PrivacyStateError("The package handoff receipt could not be verified.")
            result.update(receipt=prior, replayed=True)
            return
        if not hmac.compare_digest(str(binding), _binding(record, artifact)):
            raise ops.RecordConflict("The request or collected package changed. Reopen its review before continuing.")
        if handed < float(record.get("fulfilled_at") or 0) - 60:
            raise ValueError("This handoff time is before the package was collected.")
        if len(receipts) >= 20:
            raise ops.RecordConflict("This request already has twenty handoff receipts. Review them before proceeding.")
        receipt = {"id": identity, **material, "recorded_at": time.time(),
                   "package_reviewed": True, "identity_checked": True,
                   "operator_recorded": True, "requester_receipt_verified": False}
        record["package_handoffs"] = [*receipts, receipt]
        # Native signed activity contains actor, request, revision and a record
        # digest only. No package content, subject, destination or reference.
        ops._queue_audit(record, "package_handoff_recorded", actor)
        result.update(receipt=receipt, replayed=False)

    with authority_effect_fence():
        saved = ops._DSAR.update(request_id, apply)
        if saved is None:
            raise KeyError("This privacy request is unavailable.")
        authorize()
        saved = ops._audit_mutation(ops._DSAR, "dsar", saved)
        if saved.get("_audit_pending"):
            raise ops.PrivacyStateError(
                "The handoff statement is saved, but its activity receipt is pending. "
                "Recheck the saved history or retry this exact statement; do not send the package again."
            )
    return result


def confirm_saved(request_id, *, receipt_id, authorize):
    """Finish the signed activity outbox for one existing statement; never resend or re-attest."""
    authorize()
    result = {}

    def inspect(record):
        authorize()
        if record.get("status") != "closed":
            _artifact(record)
        receipt = next((row for row in _receipts(record) if row["id"] == receipt_id), None)
        if receipt is None:
            raise ops.RecordConflict("This saved handoff statement is unavailable. Recheck its history.")
        result.update(receipt=receipt, replayed=True)

    with authority_effect_fence():
        saved = ops._DSAR.update(request_id, inspect, metadata_only=True)
        if saved is None:
            raise KeyError("This privacy request is unavailable.")
        authorize()
        saved = ops._audit_mutation(ops._DSAR, "dsar", saved)
        if saved.get("_audit_pending"):
            raise ops.PrivacyStateError("The statement is saved but its activity confirmation is still pending.")
    return result
