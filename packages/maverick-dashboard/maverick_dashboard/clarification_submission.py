"""Atomic clarification evidence admission, without a second task or provider retry."""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import uuid
from pathlib import Path

from fastapi import HTTPException
from maverick import attachments
from maverick.attachment_submissions import SubmissionConflict, SubmissionStore
from maverick.chat_threads import ChatThreads
from maverick.file_lock import ensure_private_directory
from maverick.goal_mutations import GoalMutationConflict
from maverick.paths import data_dir
from starlette.concurrency import run_in_threadpool

from .attachment_submission import _read_staged, manifest, stage_uploads
from .auth import assert_goal_access, caller_principal, require_permission
from .product_errors import product_error


def _authority(request, world, goal_id):
    require_permission(request, "operate")
    goal = world.get_goal(goal_id)
    if goal is None:
        raise product_error(404, "task_unavailable", "This task is no longer available.")
    assert_goal_access(request, goal)
    actor = caller_principal(request) or ""
    if actor != (goal.owner or ""):
        raise product_error(403, "task_read_only", "Only this task's owner can answer its questions.")
    return actor


class _PreparedEvidence:
    """Local derivation uses native parsers against a private temporary world view."""
    def __init__(self, records):
        self.records = list(records)

    def list_attachments(self, goal_id):
        return list(self.records)

    def add_attachment(self, goal_id, filename, mime, size_bytes, sha256, path):
        self.records.append(attachments.Stored(filename, mime, size_bytes, sha256, Path(path)))
        return len(self.records)


def _prepare(records, goal_id, directory):
    # Media transcription may spend money. It is not silently started or retried
    # by an answer submission; users receive this limit before selecting files.
    if any(record.mime.startswith(("audio/", "video/")) for record in records):
        raise product_error(400, "clarification_media", "Attach a transcript, document, PDF or image when answering a question. Audio and video need a separately reviewed transcription task.")
    names = {}
    for record in records:
        if record.filename in names and names[record.filename] != record.sha256:
            raise product_error(400, "attachment_name_conflict", "Two different files use the same name. Rename one before answering.")
        names[record.filename] = record.sha256
    # Give the companion generator verified, content-addressed copies inside
    # its own private goal root; staged upload paths use unrelated UUID names.
    copies = [
        attachments.store(goal_id, record.filename, record.mime, _read_staged(record), root=directory, mirror=False)
        for record in records
    ]
    view = _PreparedEvidence(copies)
    attachments.generate_companions(view, goal_id, root=directory, mirror=False)
    missing = [item for item in attachments.companion_coverage(view, goal_id) if item["status"] != "ready"]
    if missing:
        raise product_error(409, "attachment_not_ready", "Some document text could not be prepared. Attach a readable PDF or text copy before answering. Your question has not been answered.")
    ready = list(records)
    for record in view.records[len(records):]:
        data = attachments.read_bytes(record.path)
        path = directory / ("ready-" + uuid.uuid4().hex)
        path.write_bytes(data)
        plain = attachments.Stored(record.filename, record.mime, record.size_bytes, record.sha256, path)
        _read_staged(plain)
        ready.append(plain)
    return ready


def _accept(request, world, goal_id, question_id, answer, expected_question, operation_id, records, digest):
    from .api import _require_goal_restart_admission

    actor = _authority(request, world, goal_id)
    created = []
    def publish(record):
        data = _read_staged(record)
        # Attempt-exclusive stored names permit rollback cleanup without racing
        # an ordinary upload of the same content-addressed file.
        destination = attachments._root_for_goal(goal_id) / (record.sha256[:16] + "-c" + uuid.uuid4().hex[:16] + "-" + record.filename[-80:])
        if attachments._publish_attachment(destination, attachments._encode_for_disk(data, destination), record.sha256):
            created.append((destination, record.sha256))
        return attachments.Stored(record.filename, record.mime, record.size_bytes, record.sha256, destination)
    try:
        outcome = ChatThreads(world).answer_with_evidence(
            goal_id, question_id, answer, expected_question=expected_question, operation_id=operation_id,
            actor=actor, request_hash=digest, records=records, publish=publish,
            require_admission=lambda: _require_goal_restart_admission(goal_id),
            require_authority=lambda: _authority(request, world, goal_id))
        # Keep the install's existing optional mirror behavior; authoritative
        # admission and local evidence are already complete before dispatch.
        if not outcome["replayed"] and attachments.s3_mirror_enabled():
            admitted = set(outcome["attachment_ids"])
            for record in world.list_attachments(goal_id):
                if record.id in admitted:
                    path = Path(record.path)
                    attachments._s3_mirror(goal_id, path, record.mime, path.read_bytes())
        return outcome
    except Exception:
        # A transaction error can be uncertain. Never remove a file when its
        # admission cannot be checked, or after a successful but lost commit.
        try:
            referenced = {Path(row.path).resolve() for row in world.list_attachments(goal_id)}
            directory = attachments._root_for_goal(goal_id).resolve()
            for path, sha256 in created:
                if path.parent.resolve() == directory and path.resolve() not in referenced:
                    attachments._verify_stored_attachment(path, sha256)
                    path.unlink()
        except Exception:
            pass
        raise


def _validate_answer(request, world, goal_id, answer, expected_question, operation_id, expected_context):
    from .app import _require_same_origin

    _require_same_origin(request)
    from .draft_api import context_for
    if expected_context != context_for(request):
        raise product_error(409, "context_changed", "Your signed-in workspace changed. Reopen the task before sending private content.")
    actor = _authority(request, world, goal_id)
    answer = answer.strip()
    if not answer or len(answer) > 100000:
        raise product_error(400, "answer_required", "Enter an answer of at most 100,000 characters.", field_errors={"message": "Review the length of your answer."})
    if not re.fullmatch(r"[A-Za-z0-9_-]{12,100}", operation_id) or not re.fullmatch(r"[a-f0-9]{64}", expected_question):
        raise product_error(409, "question_stale", "Refresh the current question before answering. Your draft has been kept.")
    return actor, answer


def submit_text(request, world, goal_id, *, question_id, answer, expected_question, operation_id, expected_context):
    """Native text-only admission on the current authority-fence owner thread.

    The multipart entry point stages/extracts files asynchronously. Product
    operations already run in a worker thread under an authority fence; moving
    its effect to another thread would deadlock that fence. Both paths use the
    same input checks and atomic admission/receipt implementation.
    """
    _actor, answer = _validate_answer(request, world, goal_id, answer, expected_question, operation_id, expected_context)
    digest = hashlib.sha256(json.dumps([question_id, expected_question, answer, manifest([])],
                                      sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    try:
        return _accept(request, world, goal_id, question_id, answer, expected_question, operation_id, [], digest)
    except (SubmissionConflict, GoalMutationConflict) as exc:
        raise product_error(409, "question_stale", "The question or task changed. Your answer is preserved; review the current question before retrying.") from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise product_error(503, "answer_unconfirmed", "The answer receipt could not be confirmed. Keep your draft and retry the same submission to check whether it was accepted.", retryable=True) from exc


async def submit(request, world, goal_id, *, question_id, answer, expected_question, operation_id, files, expected_context):
    actor, answer = _validate_answer(request, world, goal_id, answer, expected_question, operation_id, expected_context)
    try:
        async with stage_uploads(files) as records:
            selected = sum(bool(upload and (upload.filename or "").strip()) for upload in files)
            if len(records) != selected:
                raise product_error(400, "empty_attachment", "An attached file is empty. Remove it or select a readable copy before answering.")
            digest = hashlib.sha256(json.dumps([question_id, expected_question, answer, manifest(records)],
                                              sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            # Reading a receipt before extraction avoids repeated local preparation
            # on an acknowledged replay; the mutation checks it again under lock.
            from maverick.goal_mutations import _receipt
            store = SubmissionStore(world)
            with store.transaction(f"clarification-receipt:{goal_id}") as connection:
                prior = _receipt(lambda sql, args=(): store.execute(connection, sql, args), store.open,
                                 goal_id, "clarification", operation_id, actor, digest)
            if prior is not None:
                _authority(request, world, goal_id)
                return prior
            parent = ensure_private_directory(data_dir("attachment-staging"))
            with tempfile.TemporaryDirectory(prefix="answer-", dir=parent) as directory:
                prepared = await run_in_threadpool(_prepare, records, goal_id, Path(directory))
                return await run_in_threadpool(_accept, request, world, goal_id, question_id, answer,
                                               expected_question, operation_id, prepared, digest)
    except (SubmissionConflict, GoalMutationConflict) as exc:
        raise product_error(409, "question_stale", "The question, task or selected files changed. Your answer and files have been kept; review the current question before retrying.") from exc
    except attachments.AttachmentRejected as exc:
        raise product_error(400, "attachment_rejected", "The attached files could not be admitted. Review their types, names and sizes, then retry your retained answer.") from exc
    except HTTPException as exc:
        if exc.status_code == 400 and isinstance(exc.detail, str) and exc.detail.startswith("Attachment:"):
            raise product_error(400, "attachment_rejected", "A selected file could not be read or exceeds the allowed type or size. Your answer and files are kept; remove or replace that file before retrying.") from exc
        raise
    except Exception as exc:
        raise product_error(503, "answer_unconfirmed", "The answer receipt could not be confirmed. Keep your draft and retry the same submission to check whether it was accepted.", retryable=True) from exc


def receipt(request, world, goal_id, operation_id):
    actor = _authority(request, world, goal_id)
    if not re.fullmatch(r"[A-Za-z0-9_-]{12,100}", operation_id):
        raise product_error(404, "receipt_unavailable", "This answer receipt is unavailable.")
    store = SubmissionStore(world)
    with store.transaction(f"clarification-receipt:{goal_id}") as connection:
        row = store.execute(connection, "SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind=? AND operation_id=? AND actor=?",
                            (goal_id, "clarification", operation_id, actor)).fetchone()
    if row is None:
        return {"received": False, "state": "unconfirmed"}
    _authority(request, world, goal_id)
    return {**json.loads(store.open(row[0])), "replayed": True}


def latest_receipt(request, world, goal_id):
    actor = caller_principal(request) or ""
    goal = world.get_goal(goal_id)
    if goal is None or actor != (goal.owner or ""):
        return None
    store = SubmissionStore(world)
    with store.transaction(f"clarification-receipt:{goal_id}") as connection:
        row = store.execute(connection, "SELECT receipt,created_at FROM goal_mutation_receipts WHERE goal_id=? AND kind=? AND actor=? ORDER BY created_at DESC LIMIT 1",
                            (goal_id, "clarification", actor)).fetchone()
    if row is None:
        return None
    result = json.loads(store.open(row[0]))
    return {"received": True, "question_id": result["question_id"], "file_count": len(result["attachment_ids"]), "created_at": row[1]}
