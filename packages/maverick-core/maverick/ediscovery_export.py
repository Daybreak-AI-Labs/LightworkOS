"""Signed, streamed ZIP export of one legal matter.

The archive holds one JSONL file per selected record kind with only the
records in scope, plus ``manifest.json``.  The manifest records the matter
definition and the SHA-256 and size of every JSONL file, and is signed with the
audit signing identity through :func:`maverick.audit.signing.sign_detached_digest`.
:func:`verify_export` checks the signature against the audit public-key
registry (:func:`maverick.audit.signing.trusted_audit_public_keys`).

Attachment file bytes are not copied into the archive.  Each attachment row
carries its SHA-256 and size; the files stay in their own store.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import time
import zipfile
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

from .ediscovery import MatterExportError, MatterExportTooLarge, build_scope
from .file_lock import ensure_private_directory

EXPORT_SCHEMA = "lightwork.ediscovery-matter-export.v1"
MAX_EXPORT_BYTES = 256 * 1024 * 1024
_CANONICAL = "Lightwork sorted compact JSON v1 (UTF-8, sorted keys)"
_NOT_INCLUDED = (
    "Attachment file bytes are not included; each attachment row carries its SHA-256 and size.",
    "Audit evidence, knowledge copies, model memory and copies held by outside providers are not part of this export.",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _definition(matter: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("id", "name", "description", "custodians", "date_from", "date_to", "record_kinds", "status",
            "revision", "created_by", "created_at", "updated_by", "updated_at", "released_by", "released_at")
    return {key: matter.get(key) for key in keys}


def _rows(kind: str, scope: Any) -> Iterator[dict[str, Any]]:
    if kind == "goals":
        for goal in sorted(scope.goals.values(), key=lambda item: item.id):
            yield {"record_type": "goal", "id": goal.id, "parent_id": goal.parent_id, "title": goal.title,
                   "description": goal.description, "status": goal.status, "owner": goal.owner,
                   "domain": goal.domain, "project_id": goal.project_id, "created_at": goal.created_at,
                   "updated_at": goal.updated_at, "completed_at": getattr(goal, "completed_at", None),
                   "deadline": goal.deadline, "result": goal.result}
        for run in sorted(scope.runs, key=lambda item: item.id):
            yield {"record_type": "run", "id": run.id, "goal_id": run.goal_id, "started_at": run.started_at,
                   "ended_at": run.ended_at, "outcome": run.outcome, "cost_dollars": run.cost_dollars,
                   "input_tokens": run.input_tokens, "output_tokens": run.output_tokens,
                   "tool_calls": run.tool_calls, "cache_read_tokens": run.cache_read_tokens,
                   "cache_write_tokens": run.cache_write_tokens}
    elif kind == "chats":
        for conv_id in sorted(scope.conversations):
            conv, turns = scope.conversations[conv_id]
            for turn in turns:
                yield {"record_type": "turn", "conversation_id": conv.id, "channel": conv.channel,
                       "user_id": conv.user_id, "turn_id": turn.id, "goal_id": turn.goal_id,
                       "role": turn.role, "ts": turn.ts, "content": turn.content}
        for owner, exchange in sorted(scope.companion_exchanges, key=lambda pair: (pair[0], pair[1]["time"])):
            yield {"record_type": "companion_exchange", "owner": owner, **exchange}
        from .conversation_inbox import public_item

        for owner, item in sorted(scope.inbox_items, key=lambda pair: (pair[0], pair[1]["created_at"])):
            yield {"record_type": "conversation_message", "owner": owner, **public_item(item)}
    elif kind == "attachments":
        for att in sorted(scope.attachments, key=lambda item: item.id):
            yield {"record_type": "attachment", "id": att.id, "goal_id": att.goal_id,
                   "filename": att.filename, "mime": att.mime, "size_bytes": att.size_bytes,
                   "sha256": att.sha256, "created_at": att.created_at}
        for meta in sorted(scope.incident_attachments, key=lambda item: item.attachment_id):
            # Register metadata only: the uploader is recorded as the matter's stored reference.
            yield {"record_type": "incident_attachment", "attachment_id": meta.attachment_id,
                   "incident_kind": meta.incident_kind, "incident_id": meta.incident_id,
                   "incident_revision": meta.incident_revision, "document_id": meta.document_id,
                   "document_revision": meta.document_revision, "safe_display_name": meta.safe_display_name,
                   "media_type": meta.media_type, "byte_size": meta.byte_size, "sha256": meta.sha256,
                   "redaction_state": meta.redaction_state, "status": meta.status,
                   "created_at": meta.created_at, "updated_at": meta.updated_at,
                   "tombstoned_at": meta.tombstoned_at, "purged_at": meta.purged_at,
                   "uploader_ref": meta.principal_ref}
    elif kind == "approvals":
        for approval in sorted(scope.approvals, key=lambda item: item.id):
            yield {"record_type": "approval", "id": approval.id, "goal_id": approval.goal_id,
                   "action": approval.action, "risk": approval.risk, "scope": approval.scope,
                   "detail": approval.detail, "status": approval.status,
                   "requested_by": approval.requested_by, "requested_at": approval.requested_at,
                   "decided_by": approval.decided_by, "decided_at": approval.decided_at,
                   "approvals_required": approval.approvals_required}


def _sign(body: Mapping[str, Any]) -> dict[str, Any]:
    from .audit.signing import sign_detached_digest

    try:
        return sign_detached_digest(_digest(_canonical(body)))
    except (RuntimeError, OSError, ValueError) as exc:
        raise MatterExportError("A signed export is unavailable on this installation, so no export was made.") from exc


def export_matter(world: Any, matter: Mapping[str, Any], *, actor: str, out_dir: str | Path,
                  clock: Callable[[], float] = time.time, max_bytes: int = MAX_EXPORT_BYTES) -> dict[str, Any]:
    """Write the signed archive for ``matter`` into ``out_dir`` and return its facts.

    The archive is streamed entry by entry.  Exceeding ``max_bytes`` removes the
    partial file and raises :class:`MatterExportError` with a plain message.
    """
    scope = build_scope(world, matter)
    directory = Path(out_dir)
    ensure_private_directory(directory)
    target = directory / f"{matter['id']}-{secrets.token_hex(8)}.zip"
    files: list[dict[str, Any]] = []
    written = 0
    try:
        with open(target, "xb") as handle, zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED,
                                                           allowZip64=True) as archive:
            for kind in matter["record_kinds"]:
                name = f"{kind}.jsonl"
                digest = hashlib.sha256()
                size = count = 0
                with archive.open(name, "w", force_zip64=True) as stream:
                    for row in _rows(kind, scope):
                        line = _canonical(row) + b"\n"
                        size += len(line)
                        written += len(line)
                        if written > max_bytes:
                            raise MatterExportTooLarge(
                                "This matter is too large to export in one file. Narrow its date range or custodians and try again.")
                        count += 1
                        digest.update(line)
                        stream.write(line)
                files.append({"path": name, "record_kind": kind, "records": count, "bytes": size,
                              "sha256": digest.hexdigest()})
            body = {
                "schema": EXPORT_SCHEMA,
                "generated_at": float(clock()),
                "exported_by": actor,
                "matter": _definition(matter),
                "canonicalization": _CANONICAL,
                "digest_algorithm": "SHA-256",
                "files": files,
                "record_total": sum(item["records"] for item in files),
                "not_included": list(_NOT_INCLUDED),
            }
            manifest = {**body, "signature": _sign(body)}
            archive.writestr("manifest.json", _canonical(manifest) + b"\n")
        size_on_disk = os.path.getsize(target)
        _audit_export(matter, actor=actor, records=body["record_total"], size=size_on_disk,
                      manifest_digest=manifest["signature"]["digest"])
    except BaseException:
        with contextlib.suppress(OSError):
            target.unlink()
        raise
    return {"path": target, "bytes": size_on_disk, "files": files,
            "records": body["record_total"], "manifest_digest": manifest["signature"]["digest"],
            "key_id": manifest["signature"]["key_id"]}


def _audit_export(matter: Mapping[str, Any], *, actor: str, records: int, size: int, manifest_digest: str) -> None:
    from .audit import EventKind, audit_event

    # Fail closed: an export nobody can account for is not handed out.
    written = audit_event(EventKind.CONTROL_PLANE_ACTION, agent="ediscovery", verb="ediscovery_matter_exported",
                          matter_id=matter["id"], actor=actor, revision=matter["revision"],
                          records=records, bytes=size, manifest_sha256=manifest_digest)
    if not written:
        raise MatterExportError("The export was not released because its audit record could not be written.")


def verify_export(path: str | Path, *, trusted_keys: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Check an export offline: the signature, every file's size and SHA-256, and the entry set."""
    from .audit.signing import (
        DETACHED_DIGEST_MESSAGE_VERSION,
        trusted_audit_public_keys,
        verify_detached_digest,
    )

    problems: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                problems.append("archive")
            manifest = json.loads(archive.read("manifest.json"))
            signature = manifest.pop("signature", None)
            digest = _digest(_canonical(manifest))
            keys = dict(trusted_keys) if trusted_keys is not None else trusted_audit_public_keys()
            if (not isinstance(signature, dict) or signature.get("digest") != digest
                    or signature.get("algorithm") != "Ed25519-SHA256"
                    or signature.get("message_version") != DETACHED_DIGEST_MESSAGE_VERSION
                    or not verify_detached_digest(keys.get(str(signature.get("key_id")), ""), digest,
                                                  str(signature.get("signature", "")))):
                problems.append("signature")
            names = set(archive.namelist())
            listed = {item["path"]: item for item in manifest.get("files", [])}
            if names != set(listed) | {"manifest.json"}:
                problems.append("contents")
            for name, item in listed.items():
                if name not in names:
                    continue
                size = 0
                lines = 0
                sha = hashlib.sha256()
                with archive.open(name) as stream:
                    for chunk in iter(lambda: stream.read(1 << 20), b""):
                        size += len(chunk)
                        sha.update(chunk)
                        lines += chunk.count(b"\n")
                if size != item.get("bytes") or sha.hexdigest() != item.get("sha256") or lines != item.get("records"):
                    problems.append(name)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        problems.append(type(exc).__name__)
        manifest = {}
    return {"valid": not problems, "problems": problems, "manifest": manifest}


__all__ = ["EXPORT_SCHEMA", "MAX_EXPORT_BYTES", "export_matter", "verify_export"]
