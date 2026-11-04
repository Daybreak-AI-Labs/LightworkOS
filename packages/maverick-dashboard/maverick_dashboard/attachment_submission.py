"""Bounded multipart staging shared by chat and REST, before visible admission."""
from __future__ import annotations

import hashlib
import json
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import HTTPException
from maverick import attachments
from maverick.attachment_submissions import SubmissionConflict, SubmissionStore
from maverick.file_lock import cross_process_lock, ensure_private_directory
from maverick.paths import data_dir
from starlette.concurrency import run_in_threadpool

_CHUNK_BYTES = 64 * 1024
_MAX_FILES = 128


def _read_staged(record):
    with record.path.open("rb") as stream:
        data = stream.read(attachments.MAX_FILE_BYTES + 1)
    if len(data) != record.size_bytes or hashlib.sha256(data).hexdigest() != record.sha256:
        raise attachments.AttachmentRejected("Staged attachment changed before admission")
    return data


@asynccontextmanager
async def stage_uploads(files):
    """Read in bounded chunks; never trust multipart Content-Length."""
    parent = ensure_private_directory(data_dir("attachment-staging"))
    with tempfile.TemporaryDirectory(prefix="batch-", dir=parent) as directory:
        records, total = [], 0
        try:
            selected = 0
            for upload in files:
                if upload is None or not (upload.filename or "").strip():
                    continue
                selected += 1
                if selected > _MAX_FILES:
                    raise attachments.AttachmentRejected("Too many attachments in one submission")
                path = Path(directory) / uuid.uuid4().hex
                size, digest = 0, hashlib.sha256()
                with path.open("xb") as stream:
                    while chunk := await upload.read(min(_CHUNK_BYTES, attachments.MAX_FILE_BYTES - size + 1,
                                                          attachments.MAX_GOAL_BYTES - total + 1)):
                        size += len(chunk)
                        total += len(chunk)
                        if size > attachments.MAX_FILE_BYTES or total > attachments.MAX_GOAL_BYTES:
                            raise attachments.AttachmentRejected("Attachment size or per-goal quota exceeded")
                        stream.write(chunk)
                        digest.update(chunk)
                if not size:
                    continue
                record = attachments.Stored(upload.filename, upload.content_type or "application/octet-stream",
                                            size, digest.hexdigest(), path)
                await run_in_threadpool(attachments.validate_attachment, record.filename, record.mime,
                                        await run_in_threadpool(_read_staged, record))
                records.append(record)
            yield records
        except attachments.AttachmentRejected as exc:
            raise HTTPException(status_code=400, detail=f"Attachment: {exc}") from exc


def manifest(records):
    return [{"filename": r.filename, "mime": r.mime, "size_bytes": r.size_bytes, "sha256": r.sha256} for r in records]


def publish_batch(world, goal_id, records):
    def publish(record):
        data = _read_staged(record)
        directory = attachments._root_for_goal(goal_id)
        destination = directory / f"{record.sha256[:16]}-{record.filename}"
        # Sealed at rest like store(); staging is a transient private tempdir.
        attachments._publish_attachment(
            destination, attachments._encode_for_disk(data, destination), record.sha256)
        return attachments.Stored(record.filename, record.mime, record.size_bytes, record.sha256, destination)

    # Check the quota first, then write and seal the content-addressed files
    # OUTSIDE the admission transaction: on SQLite that transaction holds the
    # whole world's write lock, and sealing up to a goal's quota of files can
    # take seconds. Publishing is idempotent (no overwrite, digest-verified);
    # admission re-checks quota and inserts only metadata under the lock.
    existing = {(a.filename, a.mime, int(a.size_bytes), a.sha256): int(a.size_bytes)
                for a in world.list_attachments(goal_id)}
    novel = {(r.filename, r.mime, int(r.size_bytes), r.sha256): int(r.size_bytes)
             for r in records}.keys() - existing.keys()
    if (any(not 0 < int(r.size_bytes) <= attachments.MAX_FILE_BYTES for r in records)
            or sum(existing.values()) + sum(item[2] for item in novel) > attachments.MAX_GOAL_BYTES):
        raise attachments.AttachmentRejected("Per-goal attachment quota exceeded")
    published = [publish(record) for record in records]
    ids = SubmissionStore(world).admit(goal_id, published)
    # Mirroring is optional/best-effort and follows authoritative admission.
    if attachments.s3_mirror_enabled():
        for record in records:
            destination = attachments._root_for_goal(goal_id) / f"{record.sha256[:16]}-{record.filename}"
            attachments._s3_mirror(goal_id, destination, record.mime, destination.read_bytes())
    return ids


async def submit(world, files, *, token, owner, title, description, parent_id=None, domain="", project_id=None,
                 chat_text=None, chat_root_id=None, connection_references=None, task_selection=None,
                 specialist_selection=None, effect_guard=None):
    async with stage_uploads(files) as records:
        files_manifest = manifest(records)
        fingerprint_values = [title, description, parent_id, domain, project_id, files_manifest]
        if connection_references:
            fingerprint_values.append(connection_references)
        if task_selection is not None:
            fingerprint_values.append({"task_model_selection": task_selection})
        if specialist_selection is not None:
            fingerprint_values.append({"specialist_selection": specialist_selection})
        fingerprint = hashlib.sha256(json.dumps(fingerprint_values,
                                                sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        store = SubmissionStore(world)
        detail = {"task_model_selection": task_selection} if task_selection is not None else {}
        if specialist_selection is not None:
            detail["specialist_selection"] = specialist_selection
        try:
            receipt = await run_in_threadpool(store.create, token=token, fingerprint=fingerprint, owner=owner,
                                              title=title, description=description, manifest=files_manifest,
                                              parent_id=parent_id, domain=domain, project_id=project_id,
                                              chat_text=chat_text, chat_root_id=chat_root_id,
                                              connection_references=connection_references,
                                              submission_detail=detail or None,
                                              effect_guard=effect_guard)
        except SubmissionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if receipt["state"] in {"dispatching", "dispatched"}:
            return receipt
        try:
            await run_in_threadpool(publish_batch, world, receipt["goal_id"], records)
            updated = await run_in_threadpool(store.update, receipt["key"], state="admitted",
                                               message="All attachments admitted. Preparing evidence before execution.")
            return {**updated, "created": receipt["created"]}
        except Exception as exc:
            await run_in_threadpool(store.update, receipt["key"], state="draft",
                                   message="Attachment admission interrupted. This draft has not run; resubmit the original batch to recover.")
            raise HTTPException(status_code=409, detail=f"Submission retained as draft /chat/goal/{receipt['goal_id']}; no work started.") from exc


def prepare(world, receipt, *, effect_guard=None):
    """Serialize best-effort derivation and make every missing derivative visible."""
    from maverick.attachments import companion_coverage

    goal_id = receipt["goal_id"]
    lock = data_dir("attachment-staging") / ("prepare-" + receipt["key"])
    with cross_process_lock(lock, strict=True):
        store = SubmissionStore(world)
        current = store.for_goal(goal_id)
        if current is None or current["state"] in {"dispatching", "dispatched"}:
            return False
        records = world.list_attachments(goal_id)
        admitted = {(r.filename, r.mime, r.size_bytes, r.sha256) for r in records}
        if any((row["filename"], row["mime"], row["size_bytes"], row["sha256"]) not in admitted
               for row in current["detail"]["manifest"]):
            store.update(receipt["key"], state="draft", message="Attachment batch is incomplete. Resubmit the original files to recover this draft.")
            return False
        try:
            for record in records:
                attachments._verify_stored_attachment(Path(record.path), record.sha256)
        except (OSError, attachments.AttachmentRejected):
            store.update(receipt["key"], state="draft", message="An admitted attachment is missing or changed. Restore or resubmit the original files before running this draft.")
            return False
        try:
            attachments.generate_companions(world, goal_id)
        except Exception:
            pass  # Coverage below makes absent derivatives explicit.
        coverage = companion_coverage(world, goal_id)
        missing = sum(item["status"] != "ready" for item in coverage)
        message = (f"Attachments admitted; {missing} text companion(s) unavailable. Their source text has not been read."
                   if missing else "Attachments and available evidence are ready.")
        store.update(receipt["key"], state="ready", message=message, coverage=coverage)
        return store.claim_dispatch(receipt["key"], **({"effect_guard": effect_guard} if effect_guard is not None else {}))


async def dispatch(world, receipt, run, goal_id, *, effect_guard=None, **kwargs):
    intent = {key: (sorted(value) if isinstance(value, frozenset) else value) for key, value in kwargs.items()}
    store = SubmissionStore(world)
    guard_options = {"effect_guard": effect_guard} if effect_guard is not None else {}
    try:
        await run_in_threadpool(store.record_dispatch_intent, receipt["key"], intent, **guard_options)
        admitted = await run_in_threadpool(prepare, world, receipt, **guard_options)
    except HTTPException as exc:
        if effect_guard is None or exc.status_code not in {401, 403, 409}:
            raise
        await run_in_threadpool(store.update, receipt["key"], state="draft",
            message=f"Work has not started. {exc.detail}")
        return
    if admitted:
        await run(goal_id, **kwargs)
