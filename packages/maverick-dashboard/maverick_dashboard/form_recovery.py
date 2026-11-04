"""Owner decisions for accepted public-form rows that cannot start their target.

The received queue is never rewritten. A private append-only decision journal,
bound to the original row and trigger generation, is checked at delivery time.
Each decision also requires a signed audit witness before it takes effect.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager


class FormRecoveryUnavailable(RuntimeError):
    """A decision cannot be proved from durable, intact evidence."""


class FormRecoveryConflict(RuntimeError):
    """The row or binding changed before the owner's decision."""


def _path(token: str):
    from maverick.paths import data_dir

    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return data_dir("form-recovery") / f"{digest}.ndjson"


def _marker(path):
    return path.with_name(path.name + ".accepted")


@contextmanager
def locked(token: str):
    """Serialize a disposition with delivery, including other app processes."""
    from maverick.file_lock import cross_process_lock, ensure_private_directory

    path = _path(token)
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        yield


def fields_digest(fields: dict) -> str:
    encoded = json.dumps(fields, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _row_fields(event: dict) -> dict:
    return {key: value for key, value in event.items() if key not in {"_seq", "_ts"}}


def _signed_receipt(count: int, tip: str, *, pending_decision: dict | None = None) -> bytes:
    from maverick.audit.signing import sign_detached_digest

    state = {"count": count, "last_hash": tip}
    if pending_decision is not None:
        state["pending_decision"] = pending_decision
    state["signature"] = sign_detached_digest(fields_digest(state))
    return (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _row_bytes(row: dict) -> bytes:
    """The one canonical byte representation written to the decision journal."""
    return (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _verified_row(value: dict, previous: str, trusted_keys: dict) -> dict:
    """Verify a signed decision from either the journal or pending marker."""
    from maverick.audit.signing import verify_detached_digest

    if not isinstance(value, dict):
        raise ValueError("decision row is not an object")
    row = dict(value)
    digest = row.pop("hash", "")
    signature = row.pop("signature", None)
    if (row.get("previous_hash") != previous
            or row.get("decision") != "do_not_run"
            or type(row.get("sequence")) is not int
            or row["sequence"] < 1
            or not isinstance(row.get("generation"), str)
            or not isinstance(row.get("fields_sha256"), str)
            or not isinstance(row.get("reason"), str)
            or not isinstance(row.get("actor"), str)
            or type(row.get("at")) not in (int, float)):
        raise ValueError("decision row is malformed")
    expected = fields_digest(row)
    if (digest != expected or not isinstance(signature, dict)
            or signature.get("digest") != digest
            or signature.get("algorithm") != "Ed25519-SHA256"
            or signature.get("message_version") != "maverick-detached-digest/v1"
            or not isinstance(signature.get("key_id"), str)
            or not isinstance(signature.get("signature"), str)
            or not verify_detached_digest(
                trusted_keys.get(signature["key_id"], ""), digest,
                signature["signature"],
            )):
        raise ValueError("decision chain is damaged")
    return {**row, "hash": digest, "signature": signature}


def _read_decisions(token: str, generation: str, *, allow_unsealed_tail: bool = False
                    ) -> tuple[dict[int, dict], dict | None]:
    """Verify the complete chain and, for review only, one interrupted append.

    A signed marker may carry a pending signed row before journal append,
    including an exact prefix left by a short write, or name the previous tip
    when power fails after that row is fsynced. No other mismatch is recoverable.
    Caller holds ``locked``.
    """
    from maverick.audit.signing import trusted_audit_public_keys, verify_detached_digest
    from maverick.file_lock import atomic_read_bytes, ensure_private_file

    path = _path(token)
    if not _marker(path).exists():
        if path.exists():
            raise FormRecoveryUnavailable("form decision marker is unavailable")
        return {}, None
    if path.exists() and path.stat().st_size > 4 * 1024 * 1024:
        raise FormRecoveryUnavailable("form decisions exceed the safety limit")
    previous = "0" * 64
    output: dict[int, dict] = {}
    seen: set[tuple[str, int]] = set()
    try:
        ensure_private_file(_marker(path), 0o600)
        marker = json.loads(atomic_read_bytes(_marker(path)))
        if not isinstance(marker, dict):
            raise ValueError("decision marker is malformed")
        marker_signature = marker.pop("signature", None)
        if (type(marker.get("count")) is not int or marker["count"] < 0
                or not isinstance(marker.get("last_hash"), str)
                or not isinstance(marker_signature, dict)):
            raise ValueError("decision marker is malformed")
        raw = atomic_read_bytes(path) if path.exists() else b""
        partial = b""
        if raw and not raw.endswith(b"\n"):
            boundary = raw.rfind(b"\n") + 1
            partial = raw[boundary:]
            raw = raw[:boundary]
        trusted_keys = trusted_audit_public_keys()
        marker_digest = fields_digest(marker)
        if (marker_signature.get("digest") != marker_digest
                or not verify_detached_digest(
                    trusted_keys.get(str(marker_signature.get("key_id") or ""), ""),
                    marker_digest, str(marker_signature.get("signature") or ""),
                )):
            raise ValueError("decision marker signature is invalid")
        pending = marker.get("pending_decision")
        if pending is not None:
            pending = _verified_row(pending, marker["last_hash"], trusted_keys)
        count = 0
        marker_tip = "0" * 64
        tail = None
        for line in raw.decode("utf-8").splitlines():
            row = _verified_row(json.loads(line), previous, trusted_keys)
            key = (row["generation"], row["sequence"])
            if key in seen:
                raise ValueError("duplicate form decision")
            seen.add(key)
            count += 1
            previous = row["hash"]
            if count == marker["count"]:
                marker_tip = row["hash"]
            if count == marker["count"] + 1:
                tail = row
            if row["generation"] == generation:
                output[row["sequence"]] = row
        sealed = (pending is None and count > 0 and marker["count"] == count
                  and marker["last_hash"] == previous)
        journal_pending = (pending is not None and count == marker["count"]
                           and marker["last_hash"] == previous
                           and (pending["generation"], pending["sequence"]) not in seen)
        partial_pending = (bool(partial) and journal_pending
                           and _row_bytes(pending).startswith(partial)
                           and len(partial) < len(_row_bytes(pending)))
        marker_pending = (not partial and count == marker["count"] + 1
                          and marker["last_hash"] == marker_tip
                          and (pending is None or pending == tail))
        journal_pending = journal_pending and not partial
        sealed = sealed and not partial
        if not sealed and not (allow_unsealed_tail and (
                journal_pending or partial_pending or marker_pending)):
            raise ValueError("decision journal is incomplete")
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise FormRecoveryUnavailable("form decisions cannot be verified") from exc
    if journal_pending:
        return output, {**pending, "_recovery_phase": "journal_pending"}
    if partial_pending:
        return output, {**pending, "_recovery_phase": "partial_journal_pending",
                        "_partial_size": len(partial)}
    if marker_pending:
        return output, {**tail, "_recovery_phase": "marker_pending"}
    return output, None


def decisions(token: str, generation: str) -> dict[int, dict]:
    """Read only fully witnessed decisions; caller holds ``locked``."""
    return _read_decisions(token, generation)[0]


def interrupted_decision(token: str, generation: str) -> dict | None:
    """Describe one signed decision whose durable record is unfinished."""
    _, tail = _read_decisions(token, generation, allow_unsealed_tail=True)
    if tail is not None and tail["generation"] != generation:
        raise FormRecoveryUnavailable("form decision belongs to another binding")
    return tail


def seal_interrupted_decision(token: str, generation: str, event: dict, *,
                              expected_fields_sha256: str,
                              expected_decision_sha256: str, actor: str) -> dict:
    """After an owner's exact review, finish one signed decision record.

    This never edits the received queue, advances a cursor, or starts a
    workflow. Caller holds ``locked``.
    """
    from maverick.audit import record
    from maverick.file_lock import atomic_write_bytes, open_private_append

    tail = interrupted_decision(token, generation)
    if tail is None:
        raise FormRecoveryConflict("This decision is already complete. Refresh it.")
    if (tail["hash"] != expected_decision_sha256
            or tail["sequence"] != event.get("_seq")
            or tail["fields_sha256"] != expected_fields_sha256
            or fields_digest(_row_fields(event)) != expected_fields_sha256):
        raise FormRecoveryConflict("This decision or submission changed. Refresh it.")
    path = _path(token)
    witnessed = record(
        "form_submission_decision_recovery_authorized", agent=actor[:120],
        _require_signed=True, sequence=tail["sequence"], generation=generation,
        form_sha256=hashlib.sha256(token.encode()).hexdigest(),
        fields_sha256=expected_fields_sha256, decision_sha256=tail["hash"],
    )
    if not witnessed:
        raise FormRecoveryUnavailable("A signed recovery record could not be saved.")
    try:
        if tail["_recovery_phase"] in {"journal_pending", "partial_journal_pending"}:
            # The signed marker contains this exact signed row. Finish its
            # append before sealing; a second crash leaves another exact prefix
            # or the complete row one ahead of the marker.
            row = {key: value for key, value in tail.items()
                   if key not in {"_recovery_phase", "_partial_size"}}
            suffix = _row_bytes(row)[tail.get("_partial_size", 0):]
            fd = open_private_append(path, require_private_parent=True)
            with os.fdopen(fd, "ab") as handle:
                handle.write(suffix)
                handle.flush()
                os.fsync(handle.fileno())
        appended = interrupted_decision(token, generation)
        if (appended is None or appended["_recovery_phase"] != "marker_pending"
                or appended["hash"] != tail["hash"]):
            raise FormRecoveryUnavailable("The signed decision append is still incomplete.")
        with path.open(encoding="utf-8") as handle:
            count = sum(1 for _ in handle)
        atomic_write_bytes(_marker(path), _signed_receipt(count, tail["hash"]))
    except (OSError, RuntimeError, ValueError) as exc:
        raise FormRecoveryUnavailable("The decision recovery could not be saved.") from exc
    return tail


def abandon(token: str, generation: str, event: dict, *, expected_fields_sha256: str,
            reason: str, actor: str) -> dict:
    """Witness and append an explicit decision; caller holds ``locked``."""
    from maverick.audit import record
    from maverick.audit.signing import sign_detached_digest
    from maverick.file_lock import atomic_create_bytes, atomic_write_bytes, open_private_append

    sequence = event.get("_seq")
    if type(sequence) is not int or sequence < 1:
        raise FormRecoveryConflict("This submission's position changed. Refresh it.")
    actual_digest = fields_digest(_row_fields(event))
    if actual_digest != expected_fields_sha256:
        raise FormRecoveryConflict("This submission changed. Refresh it before deciding.")
    existing = decisions(token, generation)
    if sequence in existing:
        raise FormRecoveryConflict("This submission already has a decision. Refresh it.")
    reason = reason.strip()
    if len(reason) < 10 or len(reason) > 500:
        raise FormRecoveryConflict("Explain the decision in 10 to 500 characters.")
    path = _path(token)
    previous = "0" * 64
    count = 0
    if path.exists():
        # The complete chain was verified above. Only its final hash is needed.
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                previous = json.loads(line)["hash"]
                count += 1
    row = {
        "decision": "do_not_run", "sequence": sequence,
        "generation": generation, "fields_sha256": actual_digest,
        "reason": reason, "actor": actor[:120], "at": time.time(),
        "previous_hash": previous,
    }
    row["hash"] = fields_digest(row)
    try:
        row["signature"] = sign_detached_digest(row["hash"])
    except (OSError, RuntimeError, ValueError) as exc:
        raise FormRecoveryUnavailable("This decision could not be signed.") from exc
    witnessed = record(
        "form_submission_abandonment_authorized", agent=actor[:120],
        _require_signed=True, sequence=sequence, generation=generation,
        form_sha256=hashlib.sha256(token.encode()).hexdigest(),
        fields_sha256=actual_digest, decision_sha256=row["hash"],
    )
    if not witnessed:
        raise FormRecoveryUnavailable("A signed record of this decision could not be saved.")
    try:
        # Preserve the signed decision in the signed marker before appending
        # it. Both sides of a crash can then be reviewed without replay.
        if count == 0:
            atomic_create_bytes(_marker(path), _signed_receipt(0, previous,
                                                             pending_decision=row))
        else:
            atomic_write_bytes(_marker(path), _signed_receipt(count, previous,
                                                             pending_decision=row))
        fd = open_private_append(path, require_private_parent=True)
        with os.fdopen(fd, "ab") as handle:
            handle.write(_row_bytes(row))
            handle.flush()
            os.fsync(handle.fileno())
        appended = interrupted_decision(token, generation)
        if (appended is None or appended["_recovery_phase"] != "marker_pending"
                or appended["hash"] != row["hash"]):
            raise FormRecoveryUnavailable("The signed decision append is still incomplete.")
        atomic_write_bytes(_marker(path), _signed_receipt(count + 1, row["hash"]))
    except OSError as exc:
        raise FormRecoveryUnavailable("The decision could not be saved.") from exc
    return row


def without_abandoned(token: str, generation: str, events: list[dict],
                      event_ids: list[str] | None) -> tuple[list[dict], list[str] | None, int]:
    """Verify decisions against original rows before suppressing any delivery."""
    recorded = decisions(token, generation)
    if not recorded:
        return events, event_ids, 0
    kept: list[dict] = []
    kept_ids: list[str] | None = [] if event_ids is not None else None
    skipped = 0
    for index, event in enumerate(events):
        raw_seq = event.get("_seq")
        seq = int(raw_seq) if isinstance(raw_seq, str) and raw_seq.isdecimal() else raw_seq
        decision = recorded.get(seq) if type(seq) is int else None
        if decision is not None:
            if (decision["fields_sha256"] != fields_digest(_row_fields(event))
                    or event_ids is None or event_ids[index] != str(seq)):
                raise FormRecoveryUnavailable("A form decision no longer matches its submission.")
            skipped += 1
            continue
        kept.append(event)
        if kept_ids is not None:
            kept_ids.append(event_ids[index])
    return kept, kept_ids, skipped


def already_started(trigger: dict, event: dict, world) -> bool:
    """Refuse a decision if any known admission already owns this submission."""
    from maverick.automation_events import _flatten

    from maverick_dashboard.event_poll import _event_key, _trigger_key

    sequence = event["_seq"]
    generation = _trigger_key(trigger)
    polled_event = _flatten(event)
    keys = {
        _event_key(generation, polled_event, str(sequence)),
        _event_key(generation, polled_event),
    }
    if trigger.get("flow"):
        import hashlib as _hashlib

        from maverick.flow import store as flow_store

        legacy_id = polled_event.get("id") or polled_event.get("guid") or polled_event.get("uid")
        if legacy_id is None:
            legacy_id = _hashlib.sha1(
                json.dumps(polled_event, sort_keys=True, default=str).encode(),
                usedforsecurity=False,
            ).hexdigest()[:16]
        keys.add(f"{trigger['name']}:{legacy_id}")
        return any(
            flow_store.find_run_by_idem(trigger["flow"], key, within=None) is not None
            for key in keys
        )
    from maverick import event_admission

    return any(event_admission.admitted(world, key) for key in keys)
