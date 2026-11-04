"""Owned preference corrections and durable suppression, separate from training.

Per-channel restrictions are retained and enforced after unlinking/feature
disablement. Cross-channel recall requires a current verified link and explicit
choice of one authoritative channel, so conflicting notes are never blended.
"""
from __future__ import annotations

import hashlib
import json
import time

from . import personal_identity
from .authority_effects import authority_effect_fence
from .crypto_at_rest import seal, unseal
from .file_lock import atomic_write_bytes, cross_process_lock, ensure_private_directory
from .paths import current_tenant_id_strict, data_dir


def scope_key(channel: str, user_id: str) -> str:
    return hashlib.sha256(json.dumps([channel, user_id], separators=(",", ":")).encode()).hexdigest()


def _path(key):
    return data_dir("personal-memory", key + ".enc")


def _read(key, default):
    try:
        result = json.loads(unseal(_path(key).read_bytes()).decode())
    except FileNotFoundError:
        return default
    if (not isinstance(result, dict) or result.get("key") != key
            or result.get("tenant") != current_tenant_id_strict()):
        raise ValueError("Personal memory controls are unavailable.")
    return result


def controls(channel, user_id):
    key = scope_key(channel, user_id)
    return _read(key, {"key": key, "revision": 0, "recall": True, "suppressed": [], "edits": []})


def profile(principal):
    key = "profile-" + hashlib.sha256(principal.encode()).hexdigest()
    return _read(key, {"key": key, "revision": 0, "shared_source": None})


def _write(record, actor, action):
    from .audit import audit_event
    if audit_event("personal_memory_changed", actor=actor, action=action,
                   revision=record["revision"] + 1) is not True:
        raise RuntimeError("The personal memory change could not be recorded. Nothing was changed.")
    record["revision"] += 1
    record["tenant"] = current_tenant_id_strict()
    atomic_write_bytes(_path(record["key"]), seal(json.dumps(record).encode()), mode=0o600)


def owned_scopes(principal):
    personal_identity._require(principal)
    # Dashboard notes are not inferred from an external username. The server
    # constructs this channel/user pair from this verified dashboard subject.
    scopes = [{"id": "dashboard", "channel": "dashboard", "user_id": principal.removeprefix("user:")}]
    return scopes + personal_identity.linked_channels(principal)


def require_scope(principal, channel, user_id):
    if not any(s["channel"] == channel and s["user_id"] == user_id for s in owned_scopes(principal)):
        raise ValueError("Verify this channel identity from My Data before reading or changing its memories.")


def note_id(row):
    return hashlib.sha256(json.dumps([row.get(k) for k in ("channel", "user_id", "note", "conversation_id", "turn_id", "source_revision")], sort_keys=True).encode()).hexdigest()


def _suppressed(note, record):
    from .user_notes import _near_dup
    candidate = suppression(note, topic=True)
    for rule in record["suppressed"]:
        if "note" in rule:  # existing restrictions remain enforced until migrated
            if note == rule["note"] or rule.get("topic") and _near_dup(note, rule["note"]):
                return True
        elif candidate["note_hash"] == rule.get("note_hash"):
            return True
        elif rule.get("topic"):
            left, right = set(candidate["token_hashes"]), set(rule.get("token_hashes", []))
            if left and right and len(left & right) / min(len(left), len(right)) >= 0.8:
                return True
    return False


def suppression(note, *, topic):
    from .user_notes import _tokens
    return {"note_hash": hashlib.sha256(note.encode()).hexdigest(), "topic": topic,
            "token_hashes": sorted(hashlib.sha256(token.encode()).hexdigest() for token in _tokens(note)) if topic else []}


def collection_allowed(channel, user_id, note):
    record = controls(channel, user_id)
    return record["recall"] and not _suppressed(note, record)


def records(channel, user_id, *, path=None):
    from .user_notes import default_path
    rows = []
    try:
        with open(path or default_path(), encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                if row.get("channel") == channel and row.get("user_id") == user_id:
                    rows.append(row)
    except FileNotFoundError:
        pass
    record = controls(channel, user_id)
    rows = [row for row in rows + record["edits"] if not _suppressed(row.get("note", ""), record)]
    return [{**row, "id": note_id(row), "source_state": "personal correction" if row.get("manual") else
             "source recorded" if row.get("conversation_id") and row.get("turn_id") else "legacy source unavailable"}
            for row in rows]


def update(principal, channel, user_id, *, expected_revision, recall=None,
           note=None, operation=None, replacement=None):
    with authority_effect_fence():
        require_scope(principal, channel, user_id)
        key = scope_key(channel, user_id)
        ensure_private_directory(_path(key).parent)
        with cross_process_lock(_path(key), strict=True):
            record = controls(channel, user_id)
            if record["revision"] != expected_revision:
                raise personal_identity.IdentityConflict("Memory controls changed. Refresh and review before saving.")
            if recall is not None:
                if not isinstance(recall, bool):
                    raise ValueError("Choose whether personal recall is enabled.")
                record["recall"] = recall
            if note:
                row = next((r for r in records(channel, user_id) if r["id"] == note), None)
                if row is None:
                    raise personal_identity.IdentityConflict("This note changed. Refresh before correcting it.")
                if operation not in {"delete", "suppress", "edit"}:
                    raise ValueError("Choose edit, delete, or do not remember this topic again.")
                record["suppressed"].append(suppression(row["note"], topic=operation == "suppress"))
                record["edits"] = [r for r in record["edits"] if note_id(r) != note]
                if operation == "edit":
                    from .safety.secret_detector import scan
                    if not isinstance(replacement, str) or not replacement.strip() or len(replacement) > 160 or scan(replacement):
                        raise ValueError("Enter a preference of up to 160 characters without credentials.")
                    if replacement.strip() == row["note"] or _suppressed(replacement.strip(), record):
                        raise ValueError("Choose a different preference outside an existing suppressed topic.")
                    record["edits"].append({"channel": channel, "user_id": user_id, "note": replacement.strip(),
                                            "ts": time.time(), "source_ts": time.time(), "manual": True})
            if len(record["suppressed"]) > 5000 or len(record["edits"]) > 100:
                raise ValueError("Memory correction storage is full; contact your privacy administrator.")
            _write(record, principal, "recall_changed" if recall is not None else operation)
            return record


def share(principal, *, source, expected_revision):
    with authority_effect_fence():
        scopes = owned_scopes(principal)
        if source is not None and not any(s["id"] == source for s in scopes):
            raise ValueError("Choose one currently linked source, or channel-only recall.")
        record = profile(principal)
        ensure_private_directory(_path(record["key"]).parent)
        with cross_process_lock(_path(record["key"]), strict=True):
            record = profile(principal)
            if record["revision"] != expected_revision:
                raise personal_identity.IdentityConflict("Sharing changed. Review its current scope before saving.")
            record["shared_source"] = source
            _write(record, principal, "sharing_changed")
            return record


def shared_principal(channel, user_id):
    principal = personal_identity.principal_for_channel(channel, user_id)
    if principal and any(scope["id"] == profile(principal)["shared_source"] for scope in owned_scopes(principal)):
        return principal
    return None


def recall(channel, user_id, *, path=None, k=8, execution_identity=False):
    from .config import get_dreaming
    if not get_dreaming().get("user_notes"):
        return []
    # Channel execution receives '<adapter>:<sender>'; source conversations
    # retain the exact sender. Strip only at this explicit runner call site.
    if execution_identity and channel in personal_identity.CHANNELS:
        prefix = channel + ":"
        if not user_id.startswith(prefix):
            return []
        user_id = user_id[len(prefix):]
    if not controls(channel, user_id)["recall"]:
        return []
    principal = personal_identity.principal_for_channel(channel, user_id)
    if channel == "dashboard" and personal_identity.enabled():
        candidate = "user:" + user_id
        principal = candidate if personal_identity.principal_current(candidate) else None
    if principal:
        source = profile(principal)["shared_source"]
        target = next((s for s in owned_scopes(principal) if s["id"] == source), None) if source else None
        if target:
            channel, user_id = target["channel"], target["user_id"]
    if not controls(channel, user_id)["recall"]:
        return []
    from .pilot_learning import excluded
    rows = records(channel, user_id, path=path)
    # The person's own corrections come first, so a rebuild that refills the
    # automatic notes can never push them out of the k recalled.
    rows.sort(key=lambda row: not row.get("manual"))
    # Inspection still shows retained source records, but prompt enrichment
    # immediately stops using a source excluded after it was consolidated.
    return [row["note"] for row in rows
            if not row.get("source_goal_id") or not excluded(int(row["source_goal_id"]))][:max(1, k)]
