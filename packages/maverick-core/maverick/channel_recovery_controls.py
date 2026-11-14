"""Ordinary recovery forms translated into the existing exact readback contract.

No provider is queried here. Values record an administrator's source review.
Callers must hold the workspace recovery lock and authenticate the bootstrap.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import re
from datetime import datetime, timezone

from . import channel_recovery as channels
from .constant_time import text_equals


def _require(condition, message="Review the connected-service details again."):
    if not condition:
        raise ValueError(message)


def _iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _timestamp(value):
    _require(isinstance(value, str) and len(value) <= 64 and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})", value),
        "Choose a valid date and time with a time zone.")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(stamp.utcoffset() is not None)
    return stamp.timestamp()


def review_token(marker, item):
    """Bind the original review, not mutable publication state or other items."""
    return channels._digest({
        "bootstrap": {key: marker[key] for key in ("bootstrap_id", "actor", "target", "restored_at")},
        "item": {key: item[key] for key in ("id", "category", "channel_binding", "readback_template")},
    })


def _kind(item):
    template = item["readback_template"]
    namespace = template["namespace"]
    if namespace == "channel-deliveries":
        return "message"
    if namespace == "channel-delivery-cursors":
        return "delivery_restart"
    if namespace == "imessage-intake-cursors":
        return "imessage_position"
    _require(namespace == "channel-poll-cursors")
    keys = set(template["checkpoint"])
    _require(keys in ({"watermark"}, {"floor"}))
    return "notification_position" if keys == {"watermark"} else "poll_time"


def _current_record(path, item, **kwargs):
    record, raw, _ = channels._load(path, **kwargs)
    hold = record.get("restore_hold")
    _require(isinstance(hold, dict) and record.get("id") == item["record_id"])
    for key in ("namespace", "source_sha256", "binding_sha256", "restored_at"):
        _require(hold.get(key) == item["channel_binding"][key])
    # The pending-publication path cannot match the old file hash. Still apply
    # native structural checks before projecting or accepting its saved review.
    # Its revision/checkpoint may have changed legitimately; do not compare this
    # new binding digest with the original pre-restore digest.
    channels._binding(item["channel_binding"]["namespace"], record)
    if hold.get("state") == "resolved":
        readback = hold.get("readback")
        _require(isinstance(readback, dict) and hold.get("readback_sha256") == channels._digest(readback))
        for key in ("namespace", "record_id", "source_sha256", "binding_sha256"):
            _require(readback.get(key) == item["channel_binding"][key])
    else:
        _require(hold.get("state") == "unresolved" and item.get("state") == "unresolved")
    if hold["state"] != "resolved" or item.get("state") == "resolved":
        _require(hashlib.sha256(raw).hexdigest() == item["safe_source"]["sha256"],
                 "This restored item changed. Keep recovery open and refresh its details.")
    return record


def _answer_summary(item, readback):
    """Readable projection only; finalization reuses the original readback bytes."""
    kind = _kind(item)
    value = {"kind": kind, "checked_at": _iso(readback["observed_at"]),
             "evidence_reference": readback["evidence_reference"]}
    if kind == "message":
        value.update({key: copy.deepcopy(readback[key]) for key in ("execution", "delivery", "chunks")})
    elif kind in {"imessage_position", "notification_position"}:
        key = "last_rowid" if kind == "imessage_position" else "watermark"
        value["position"] = str(readback["checkpoint"][key])
    elif kind == "poll_time":
        value["resume_time"] = readback["checkpoint"]["floor"]
    return value


def descriptor(marker, item, path, **kwargs):
    record = _current_record(path, item, **kwargs)
    kind = _kind(item)
    source = {"imessage": "iMessage", "mastodon": "Mastodon", "threads": "Threads",
              "bluesky": "Bluesky", "slack": "Slack", "teams": "Microsoft Teams",
              "discord": "Discord", "telegram": "Telegram", "email": "Email"}.get(
                  record.get("channel"), "Connected service")
    if kind == "imessage_position":
        source = "iMessage"
    result = {"schema": 1, "kind": kind, "review_token": review_token(marker, item),
              "title": "Review a held message" if kind == "message" else "Review where collection resumes",
              "source_label": source, "status": "review_required",
              "restored_at": _iso(item["channel_binding"]["restored_at"]), "retry_answers": None}
    if kind == "message":
        result["execution_choices"] = ["recorded"] if record["execution"] == "completed" else ["absent", "recorded"]
        result["delivery_choices"] = ["recorded"] if record["delivery"] == "delivered" else ["absent", "recorded"]
        _require(set(record["chunks"]) == set(item["readback_template"]["chunks"]))
        result["chunks"] = [{"key": key, "label": f"Reply part {index + 1}",
                             "choices": ["recorded"] if chunk["state"] == "delivered" else ["absent", "recorded"],
                             "receipt_locked": chunk["state"] == "delivered",
                             "receipt": chunk.get("provider_id", "") if chunk["state"] == "delivered" else ""}
                            for index, (key, chunk) in enumerate(record["chunks"].items())]
    elif kind == "imessage_position":
        result["minimum_position"] = str(record["last_rowid"])
    elif kind == "notification_position":
        position = record.get("candidate") or record.get("watermark")
        _require(position not in (None, ""), "This source has no saved position. Keep recovery open.")
        result["minimum_position"] = str(position)
    hold = record["restore_hold"]
    if item.get("state") == "resolved":
        result["status"] = "recorded"
    elif hold["state"] == "resolved":
        result.update(status="recording_incomplete",
                      retry_answers={"kind": "finish_recording", "receipt": hold["readback_sha256"]},
                      recorded_review=_answer_summary(item, hold["readback"]))
    return result


def readback(marker, item, answers, expected_token, path, **kwargs):
    """Translate closed forms under the caller's existing recovery lock."""
    _require(isinstance(expected_token, str) and re.fullmatch(r"[a-f0-9]{64}", expected_token)
             and hmac.compare_digest(expected_token, review_token(marker, item)),
             "This recovery review changed. Refresh and review the current item.")
    _require(isinstance(answers, dict))
    record = _current_record(path, item, **kwargs)
    if answers.get("kind") == "finish_recording":
        _require(set(answers) == {"kind", "receipt"})
        hold = record["restore_hold"]
        _require(hold["state"] == "resolved" and isinstance(answers["receipt"], str)
                 and text_equals(answers["receipt"], hold["readback_sha256"]),
                 "The recorded review changed. Refresh before finishing it.")
        return copy.deepcopy(hold["readback"])
    kind = _kind(item)
    fields = {"kind", "checked_at", "evidence_reference"}
    fields |= ({"execution", "delivery", "chunks"} if kind == "message" else
               {"position"} if kind in {"imessage_position", "notification_position"} else
               {"resume_time"} if kind == "poll_time" else set())
    _require(set(answers) == fields and answers["kind"] == kind)
    reference = answers["evidence_reference"]
    _require(isinstance(reference, str) and 8 <= len(reference.strip()) <= 512
             and not any(ord(char) < 32 for char in reference),
             "Enter a short reference to the source you reviewed.")
    result = copy.deepcopy(item["readback_template"])
    result.update(observed_at=_timestamp(answers["checked_at"]), evidence_reference=reference, outcome="confirmed")
    if kind == "message":
        for key in ("execution", "delivery"):
            _require(isinstance(answers[key], str) and answers[key] in {"absent", "recorded"},
                     "Choose a known outcome for the work and its reply.")
            result[key] = answers[key]
        chunks = answers["chunks"]
        _require(isinstance(chunks, dict) and set(chunks) == set(result["chunks"]))
        for chunk in chunks.values():
            _require(isinstance(chunk, dict) and set(chunk) == {"outcome", "provider_id"})
            _require(isinstance(chunk["outcome"], str) and chunk["outcome"] in {"absent", "recorded"})
            _require(isinstance(chunk["provider_id"], str) and len(chunk["provider_id"]) <= 512)
        result["chunks"] = copy.deepcopy(chunks)
    elif kind in {"imessage_position", "notification_position"}:
        position = answers["position"]
        limit = 19 if kind == "imessage_position" else 40  # a row id is a signed 64-bit SQLite INTEGER
        _require(isinstance(position, str) and re.fullmatch(r"[0-9]{1," + str(limit) + "}", position)
                 and (kind != "imessage_position" or int(position) <= 2**63 - 1),
                 "Enter the complete current position shown by the source.")
        result["checkpoint"] = ({"last_rowid": int(position)} if kind == "imessage_position" else {"watermark": position})
    elif kind == "poll_time":
        _timestamp(answers["resume_time"])
        result["checkpoint"] = {"floor": answers["resume_time"]}
    else:
        result["checkpoint"] = {"cursor": ""}
    return result
