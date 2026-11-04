"""Exact channel recovery dispositions; restored receipts never replay.

Readback is an explicit authenticated administrator attestation from the
provider/source system, not a claim that this module queried that system.
Original execution and send outcomes remain intact beside the disposition.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from . import crypto_at_rest, file_lock

NAMESPACES = {
    "channel-deliveries": "chd",
    "channel-delivery-cursors": "chc",
    "channel-poll-cursors": "chp",
    "imessage-intake-cursors": "imc",
}
MAX_BYTES = 16 * 1024 * 1024
READBACK_MAX_AGE = 15 * 60


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _require(condition):
    if not condition:
        raise ValueError("Channel recovery readback does not match the exact restored authority")


def _load(path, *, decryptor=None, tenant=None, workspace=None):
    raw = file_lock.atomic_read_bytes(path)
    _require(len(raw) <= MAX_BYTES)
    encrypted = crypto_at_rest.is_sealed(raw)
    plain = raw
    if encrypted:
        _require(decryptor is not None)
        plain = decryptor(raw, tenant, workspace)
    record = json.loads(plain)
    _require(isinstance(record, dict))
    return record, raw, encrypted


def _write(path, record, raw, encrypted, *, decryptor=None, tenant=None, workspace=None):
    rendered = json.dumps(record, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode()
    _require(len(rendered) <= MAX_BYTES)
    if encrypted:
        _require(callable(getattr(decryptor, "reseal", None)))
        rendered = decryptor.reseal(raw, rendered, tenant, workspace)
    file_lock.atomic_write_bytes(path, rendered, mode=0o600)


def _binding(namespace, record):
    prefix = NAMESPACES[namespace]
    _require(isinstance(record.get("id"), str) and re.fullmatch(prefix + r"-[a-f0-9]{56}", record["id"]))
    _require(type(record.get("revision")) is int and record["revision"] >= 1)
    if namespace == "channel-deliveries":
        _require(record.get("execution") in {"staging", "received", "execution_started_unconfirmed", "execution_unknown", "completed"})
        _require(record.get("delivery") in {"not_ready", "ready", "retryable", "sending", "delivery_unknown", "delivered"})
        _require(isinstance(record.get("channel"), str) and 0 < len(record["channel"]) <= 128)
        _require(isinstance(record.get("account_sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", record["account_sha256"]))
        _require(isinstance(record.get("execution_id"), str) and 0 < len(record["execution_id"]) <= 128)
        _require(isinstance(record.get("external_id"), str) and 0 < len(record["external_id"]) <= 4096)
        _require(isinstance(record.get("chunks"), dict) and len(record["chunks"]) <= 512)
        for key, chunk in record["chunks"].items():
            _require(isinstance(key, str) and 0 < len(key) <= 128 and isinstance(chunk, dict))
            _require(chunk.get("state") in {"sending", "retryable", "delivery_unknown", "delivered"})
        return {name: record[name] for name in ("id", "channel", "account_sha256", "execution_id", "execution", "delivery")} | {
            "external_id_sha256": _digest(record["external_id"]), "chunks_sha256": _digest(record["chunks"])}
    if namespace == "channel-delivery-cursors":
        _require(isinstance(record.get("cursor"), str))
    elif namespace == "imessage-intake-cursors":
        _require(type(record.get("last_rowid")) is int and record["last_rowid"] >= 0)
    else:
        _require(record.get("channel") in {"mastodon", "threads", "bluesky"})
        _require(record.get("cursor") is None or isinstance(record["cursor"], str))
        _require(isinstance(record.get("seen_cursors"), list))
    return {"id": record["id"], "checkpoint_sha256": _digest({key: value for key, value in record.items()
            if key not in {"restore_hold", "_audit_pending"}})}


def stage_authorities(stage: Path, *, decryptor, tenant, now, make_item, blocked_item):
    """Authenticate, classify and persist holds before restore publication."""
    items, classified = [], set()
    for namespace in NAMESPACES:
        directory = stage / namespace
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.json")):
            relative = path.relative_to(stage).as_posix()
            classified.add(relative)
            raw = file_lock.atomic_read_bytes(path)
            digest = hashlib.sha256(raw).hexdigest()
            try:
                record, raw, encrypted = _load(path, decryptor=decryptor, tenant=tenant, workspace=stage)
                binding = _binding(namespace, record)
                _require(path.stem == record["id"])
            except (OSError, ValueError, TypeError, KeyError):
                items.append(blocked_item(relative, namespace, digest))
                continue
            hold = {"schema": 1, "namespace": namespace, "source_sha256": digest,
                    "binding_sha256": _digest(binding), "restored_at": now, "state": "unresolved"}
            # Preserve the preceding disposition for subsequent recoveries.
            if "restore_hold" in record:
                hold["previous_disposition_sha256"] = _digest(record["restore_hold"])
            if namespace != "channel-deliveries":
                hold["prior_checkpoint"] = {key: value for key, value in record.items()
                    if key not in {"restore_hold", "_audit_pending"}}
            record["restore_hold"] = hold
            record.pop("_audit_pending", None)
            record["revision"] += 1
            _write(path, record, raw, encrypted, decryptor=decryptor, tenant=tenant, workspace=stage)
            item = make_item("channel_authority", relative, record["id"],
                prior_state=(record.get("execution", "checkpoint") + "/" + record.get("delivery", "held")),
                content_sha256=digest, safe_state="channel_restore_held", requires_external_readback=True)
            item["channel_binding"] = {key: value for key, value in hold.items() if key != "prior_checkpoint"}
            item["channel_binding"]["record_id"] = record["id"]
            item["readback_template"] = {"schema": 1, "namespace": namespace, "record_id": record["id"],
                "source_sha256": digest, "binding_sha256": hold["binding_sha256"], "observed_at": None,
                "evidence_reference": "", "outcome": "unknown"}
            if namespace == "channel-deliveries":
                item["readback_template"].update(execution="unknown", delivery="unknown",
                    chunks={key: {"outcome": "unknown", "provider_id": ""} for key in record["chunks"]})
            else:
                item["readback_template"]["checkpoint"] = (
                    {"cursor": ""} if namespace == "channel-delivery-cursors" else
                    {"last_rowid": None} if namespace == "imessage-intake-cursors" else
                    {"watermark": ""} if record["channel"] == "mastodon" else {"floor": ""})
            items.append(item)
    return items, classified


def _known_outcome(value):
    _require(value in {"absent", "recorded"})


def _checkpoint_updates(namespace, record, checkpoint, observed):
    _require(isinstance(checkpoint, dict))
    if namespace == "channel-delivery-cursors":
        _require(checkpoint == {"cursor": ""})
        return {"cursor": ""}
    if namespace == "imessage-intake-cursors":
        _require(set(checkpoint) == {"last_rowid"} and type(checkpoint["last_rowid"]) is int
                 and checkpoint["last_rowid"] >= record["last_rowid"])
        return checkpoint
    updates = {"cursor": None, "seen_cursors": [], "status": "idle"}
    if record["channel"] == "mastodon":
        _require(set(checkpoint) == {"watermark"} and isinstance(checkpoint["watermark"], str)
                 and re.fullmatch(r"[0-9]{1,40}", checkpoint["watermark"]))
        _require(int(checkpoint["watermark"]) >= int(record.get("candidate") or record["watermark"]))
        return updates | checkpoint | {"candidate": None}
    _require(set(checkpoint) == {"floor"} and isinstance(checkpoint["floor"], str))
    stamp = datetime.fromisoformat(checkpoint["floor"].replace("Z", "+00:00"))
    _require(stamp.tzinfo is not None)
    epoch = stamp.astimezone(timezone.utc).timestamp()
    _require(record["restore_hold"]["restored_at"] <= epoch <= observed + 60)
    return updates | checkpoint | ({"initial_page": False} if record["channel"] == "threads" else {})


def resolve(path, item, readback, *, actor, decryptor, tenant, workspace):
    """Apply exact admin readback. Unknown outcomes are never dispositions."""
    now = time.time()
    _require(isinstance(readback, dict) and len(json.dumps(readback)) <= 262144)
    required = {"schema", "namespace", "record_id", "source_sha256", "binding_sha256", "observed_at", "evidence_reference", "outcome"}
    binding = item["channel_binding"]
    namespace = binding["namespace"]
    expected_fields = required | ({"execution", "delivery", "chunks"} if namespace == "channel-deliveries" else {"checkpoint"})
    _require(set(readback) == expected_fields and readback["schema"] == 1)
    for key in ("namespace", "record_id", "source_sha256", "binding_sha256"):
        _require(readback[key] == binding[key])
    reference = readback["evidence_reference"]
    _require(isinstance(reference, str) and 8 <= len(reference.strip()) <= 512
             and not any(ord(char) < 32 for char in reference))
    observed = readback["observed_at"]
    _require(type(observed) in {int, float} and math.isfinite(observed))
    record, raw, encrypted = _load(path, decryptor=decryptor, tenant=tenant, workspace=workspace)
    hold = record.get("restore_hold")
    _require(isinstance(hold, dict) and hold.get("source_sha256") == binding["source_sha256"]
             and hold.get("binding_sha256") == binding["binding_sha256"])
    readback_digest = _digest(readback)
    if hold.get("state") == "resolved":
        _require(hold.get("readback_sha256") == readback_digest)
        if item.get("state") == "resolved":
            _require(hashlib.sha256(raw).hexdigest() == item["safe_source"]["sha256"])
        return hashlib.sha256(raw).hexdigest(), readback_digest
    _require(binding["restored_at"] <= observed <= now + 60 and now - observed <= READBACK_MAX_AGE)
    _require(hashlib.sha256(raw).hexdigest() == item["safe_source"]["sha256"])
    _require(readback["outcome"] == "confirmed")
    updates = {}
    if namespace == "channel-deliveries":
        _known_outcome(readback["execution"])
        _known_outcome(readback["delivery"])
        if readback["delivery"] == "recorded":
            _require(readback["execution"] == "recorded")
        _require(isinstance(readback["chunks"], dict) and set(readback["chunks"]) == set(record["chunks"]))
        # A readback cannot erase an already confirmed effect in the archive.
        if record["execution"] == "completed":
            _require(readback["execution"] == "recorded")
        if record["delivery"] == "delivered":
            _require(readback["delivery"] == "recorded")
        for key, old in record["chunks"].items():
            chunk = readback["chunks"][key]
            _require(isinstance(chunk, dict) and set(chunk) == {"outcome", "provider_id"})
            _known_outcome(chunk["outcome"])
            _require(isinstance(chunk["provider_id"], str) and len(chunk["provider_id"]) <= 512)
            if old["state"] == "delivered":
                _require(chunk["outcome"] == "recorded" and chunk["provider_id"] == old.get("provider_id", ""))
            if chunk["outcome"] == "recorded":
                _require(readback["delivery"] == "recorded")
    else:
        updates = _checkpoint_updates(namespace, record, readback["checkpoint"], observed)
    record.update(updates)
    record["restore_hold"] = {**hold, "state": "resolved", "readback_sha256": readback_digest,
        "resolved_at": now, "actor_sha256": hashlib.sha256(actor.encode()).hexdigest(),
        "readback": readback, "automatic_replay_blocked": namespace == "channel-deliveries"}
    record["revision"] += 1
    _write(path, record, raw, encrypted, decryptor=decryptor, tenant=tenant, workspace=workspace)
    return hashlib.sha256(file_lock.atomic_read_bytes(path)).hexdigest(), readback_digest


def assert_checkpoint_ready(record):
    hold = record.get("restore_hold")
    if hold and (not isinstance(hold, dict) or hold.get("state") != "resolved"):
        raise RuntimeError("Restored channel checkpoint requires authoritative recovery readback")
