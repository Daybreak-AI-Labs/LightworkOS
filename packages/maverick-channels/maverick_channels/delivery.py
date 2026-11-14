"""Durable channel intake, execution claims and individually receipted replies.

Provider adapters own authentication, routing and definitive send-error
classification. Unknown execution/send effects never become automatic retries.
"""
from __future__ import annotations

import asyncio
import contextvars
import errno
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict
from itertools import islice
from pathlib import Path

from .base import IncomingMessage, Reply, as_reply

MAX_RECORDS = 20_000
MAX_CONFIGURED_RECORDS = 100_000
MAINTENANCE_INTERVAL_SECONDS = 60
CAPACITY_RECOVERY_BATCHES = 10
_maintenance_last: OrderedDict[str, float] = OrderedDict()
_maintenance_lock = threading.Lock()
# One recovery pass inspects at most this many receipts, for at most this long.
RECOVERY_SCAN_LIMIT = 1000
RECOVERY_SCAN_SECONDS = 1.0
_monotonic = time.monotonic  # bound once: tests replace this module's ``time``
MAX_TEXT_CHARS = 1_000_000
MAX_CHUNKS = 512
MAX_ATTACHMENTS = 10
RETENTION_SECONDS = 30 * 24 * 3600
# A delivered, compacted receipt is kept as a deduplication tombstone this long
# (well past any provider's redelivery window; the world's processed-message
# claim that also guards re-execution keeps 30 days), then removed so intake
# capacity is not consumed forever by messages long since answered.
TOMBSTONE_SECONDS = 90 * 24 * 3600
# After this bound, an execution claim can be surfaced as unknown only when
# its local activity guard proves no handler still owns it. Never re-run it.
STALE_CLAIM_SECONDS = 24 * 3600
MAX_PROVIDER_ATTEMPTS = 8
PROVIDER_RETRY_SECONDS = 30
_INTERNAL_ERROR_REPLY = "⚠ An internal error occurred."
_ACTIVE = contextvars.ContextVar("channel_delivery", default=None)
log = logging.getLogger(__name__)


class DeliveryNotSent(RuntimeError):
    """Provider definitively rejected this attempt before accepting a message."""


class _DeliveryNotAuthorized(DeliveryNotSent):
    """The provider was not called because the sender's permission changed."""


class IntakeMessageRejected(ValueError):
    """The message's content or identity cannot be admitted."""


class DeliveryWithheld(DeliveryNotSent):
    """The saved reply's task or sources are not available to this person now.

    Nothing was sent and the check may pass again later, so the reply stays
    retryable; the person's newer messages do not wait behind it."""


def reply_withheld(row) -> bool:
    """True when the reply waits only on the source check, not on the provider."""
    return any(chunk.get("state") == "retryable" and chunk.get("withheld") is True
               for chunk in (row.get("chunks") or {}).values())


class DeliveryUnknown(RuntimeError):
    """An execution or send may have happened; unsafe to repeat automatically."""


class _DeliveryOwnedElsewhere(RuntimeError):
    """A concurrent worker owns this send; the observer must not mutate it."""


def intake_record_limit():
    """Use the current bounded customer setting for all intake authorities."""
    from maverick.config import load_config

    channels = load_config().get("channels", {})
    if channels is None:
        channels = {}
    if not isinstance(channels, dict):
        raise ValueError("Chat app intake settings are invalid")
    value = channels.get("max_intake_records")
    if value is None:
        return MAX_RECORDS
    if type(value) is not int or not 1000 <= value <= MAX_CONFIGURED_RECORDS:
        raise ValueError("Chat app intake capacity must be a number from 1000 to 100000")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _activity_scope(*, create=False):
    """Identify the actual private lock workspace, never just a host/path name."""
    from maverick import file_lock
    from maverick.paths import data_dir

    path = data_dir("channels", "receipt-activity", "workspace-id")
    if os.name == "nt":
        path = Path(file_lock._windows_extended_path(path))
    try:
        fd = file_lock.open_private_read(path)
    except FileNotFoundError:
        if not create:
            raise
        try:
            file_lock.atomic_create_bytes(path, uuid.uuid4().hex.encode("ascii"))
        except FileExistsError:
            pass  # Another first admission established this workspace identity.
        fd = file_lock.open_private_read(path)
    try:
        nonce = os.read(fd, 33)
    finally:
        os.close(fd)
    if not re.fullmatch(rb"[a-f0-9]{32}", nonce):
        raise ValueError("Channel activity workspace identity is invalid; retain unresolved receipts for review")
    return _digest(nonce.decode("ascii"))


@contextmanager
def _receipt_activity(record_id, *, blocking=False, purpose="execution"):
    """Bounded private OS locks, held across intake or a live handler.

    A busy or unavailable lock never proves an owner dead. Stripes limit the
    sidecars to 256 per purpose; unrelated busy execution stripes defer work.
    """
    from maverick import file_lock
    from maverick.paths import data_dir

    root = file_lock.ensure_private_directory(data_dir("channels", "receipt-activity"))
    path = root / (purpose + "-" + _digest(record_id)[:2] + ".lock")
    if os.name == "nt":
        path = Path(file_lock._windows_extended_path(path))
    fd = file_lock._open_lock_file(path)
    try:
        file_lock._validate_open_lock_file(path, fd)
        if os.name == "nt":
            file_lock.harden_path_permissions(path)
        else:
            os.fchmod(fd, 0o600)
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except OSError as exc:
            if not blocking and exc.errno in {errno.EACCES, errno.EAGAIN}:
                yield False
                return
            raise  # Unsupported locking cannot authorize work or stale cleanup.
        file_lock._validate_open_lock_file(path, fd)
        yield True
    finally:
        os.close(fd)  # Releasing the descriptor also releases its OS lock.


def retry_delay(row, *, now=None):
    """Persisted provider backoff; source-withheld replies retain their policy."""
    now = time.time() if now is None else now
    return max((max(0, chunk.get("retry_at", 0) - now)
                for chunk in row.get("chunks", {}).values()
                if chunk.get("state") == "retryable" and not chunk.get("withheld")), default=0)


def _assert_work_allowed():
    from maverick.workspace_recovery import assert_bootstrap_start_allowed

    assert_bootstrap_start_allowed()


def _bounded(value, limit, label):
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError(f"Invalid bounded channel {label}")
    return value


def _blob_path(record_id, sha):
    from maverick.file_lock import _windows_extended_path
    from maverick.paths import data_dir

    if not re.fullmatch(r"chd-[a-f0-9]{56}", record_id) or not re.fullmatch(r"[a-f0-9]{64}", sha):
        raise ValueError("Invalid channel attachment binding")
    path = data_dir("channels", "intake-blobs", record_id, sha)
    # Publication already uses Win32 extended paths. Inspection and reopened
    # reads must name the same file when a private workspace exceeds MAX_PATH.
    return Path(_windows_extended_path(path)) if os.name == "nt" else path


def _record_id(channel, account, external_id):
    from maverick.paths import current_tenant_id_strict

    _bounded(external_id, 4096, "message identity")
    _bounded(account, 4096, "configured account identity")
    _bounded(channel, 128, "adapter name")
    return "chd-" + _digest([current_tenant_id_strict(), channel, account, external_id])[:56]


def _cleanup_paths(record_id, digests):
    if (not isinstance(digests, list) or len(digests) > 2 * MAX_ATTACHMENTS
            or any(not isinstance(digest, str) for digest in digests)):
        raise ValueError("Invalid channel attachment cleanup manifest")
    return [_blob_path(record_id, digest) for digest in digests]


def _legacy_cleanup_digests(record_id):
    """Recover only bounded blob names owned by an already compacted receipt."""
    directory = _blob_path(record_id, "0" * 64).parent
    try:
        with os.scandir(directory) as entries:
            retained = list(islice(entries, 2 * MAX_ATTACHMENTS + 1))
    except FileNotFoundError:
        return []
    digests = [entry.name for entry in retained]
    _cleanup_paths(record_id, digests)
    if any(not entry.is_file(follow_symlinks=False) for entry in retained):
        raise ValueError("Invalid channel attachment cleanup entry")
    return digests


def _payload(msg, record_id):
    from maverick.attachments import MAX_GOAL_BYTES, AttachmentRejected, validate_attachment

    if not isinstance(msg.text, str) or len(msg.text) > MAX_TEXT_CHARS or len(msg.attachments) > MAX_ATTACHMENTS:
        raise IntakeMessageRejected("Channel message exceeds its durable intake bound")
    files, publications, total = [], [], 0
    for item in msg.attachments:
        data = item.get("data")
        if not isinstance(data, bytes):
            raise IntakeMessageRejected("Channel attachment requires admitted bytes")
        filename, mime = item.get("filename"), item.get("mime")
        try:
            sha = validate_attachment(filename, mime, data, existing_total=total)
        except AttachmentRejected as exc:
            raise IntakeMessageRejected(str(exc)) from exc
        total += len(data)
        if total > MAX_GOAL_BYTES:
            raise IntakeMessageRejected("Channel attachments exceed aggregate quota")
        files.append({"filename": filename, "mime": mime, "sha256": sha, "size_bytes": len(data)})
        publications.append((_blob_path(record_id, sha), data, sha))
    try:
        recipient = _bounded(msg.user_id, 4096, "recipient")
    except ValueError as exc:
        raise IntakeMessageRejected(str(exc)) from exc
    payload = {"user_id": recipient, "sender_id": msg.sender_id,
               "provider_tenant_id": getattr(msg, "provider_tenant_id", None),
               "provider_sender_id": getattr(msg, "provider_sender_id", None),
               "channel": msg.channel, "message_id": msg.message_id,
               "conversation_ref": getattr(msg, "conversation_ref", None),
               "question_reply_only": getattr(msg, "question_reply_only", False),
               "text": msg.text, "attachments": files}
    return payload, publications


def _materialize(record):
    from maverick.attachments import _verify_stored_attachment, read_bytes

    payload = dict(record["message"])
    files = []
    for item in payload.pop("attachments"):
        path = _blob_path(record["id"], item["sha256"])
        _verify_stored_attachment(path, item["sha256"])
        data = read_bytes(path)  # sealed at rest like goal attachments
        if len(data) != item["size_bytes"]:
            raise DeliveryUnknown("Admitted channel attachment changed size")
        files.append({"filename": item["filename"], "mime": item["mime"], "data": data})
    return IncomingMessage(**payload, attachments=files)


class DeliveryJournal:
    def __init__(self, store=None):
        from maverick.governed_records import GovernedRecordStore

        self.store = store or GovernedRecordStore("channel-deliveries", "chd", "channel_delivery",
                                                   archive_when_full=False)

    def get(self, record_id):
        return self.store.get(record_id)

    def capacity_status(self):
        """Count receipt identities in bounded pages, without reading bodies."""
        limit = intake_record_limit()
        cursor, used = "", 0
        while used <= limit:
            page_size = min(10_000, limit + 1 - used)
            page = list(self.store.iter_record_ids(start_after=cursor, limit=page_size))
            if not page:
                break
            for position, _ in page:
                # The scan wraps back to the start: a position at or before the
                # cursor ends the count, even if compaction removed the first one.
                if cursor and position <= cursor:
                    return self._capacity_result(used, limit, exact=True)
                cursor = position
                used += 1
                if used > limit:
                    return self._capacity_result(used, limit, exact=False)
        return self._capacity_result(used, limit, exact=True)

    @staticmethod
    def _capacity_result(used, limit, *, exact):
        return {"used": used, "limit": limit, "count_exact": exact,
                "warning": used * 5 >= limit * 4, "full": used >= limit,
                "remedy": "Open Settings > All settings > Chat channels to increase message capacity. "
                          "Only delivered messages past retention can be cleared automatically; "
                          "messages needing review remain saved."}

    def _maintenance_tick(self):
        """Advance one retention window per active workspace, at most once/minute."""
        from maverick.paths import current_tenant_id_strict

        key = (current_tenant_id_strict() or "") + "\0" + os.environ.get("MAVERICK_HOME", "")
        now = _monotonic()
        with _maintenance_lock:
            last = _maintenance_last.get(key)
            if last is not None and now - last < MAINTENANCE_INTERVAL_SECONDS:
                return
            _maintenance_last[key] = now
            _maintenance_last.move_to_end(key)
            if len(_maintenance_last) > 1024:
                _maintenance_last.popitem(last=False)
            if last is None:
                return  # The first accepted message starts this process's cadence.
        try:
            self.compact_delivered(limit=25)
        except Exception:  # noqa: BLE001 -- maintenance cannot block a free intake slot
            log.warning("Channel receipt maintenance needs review", exc_info=True)

    def recovery_window(self, *, channel, account, limit=16, scan_limit=RECOVERY_SCAN_LIMIT,
                        scan_seconds=RECOVERY_SCAN_SECONDS, respect_retry_at=True):
        """Fair bounded recovery; one window never proves an empty queue.

        At most ``limit`` rows are returned, but up to ``scan_limit`` receipts
        (within ``scan_seconds``) are inspected to find them: most receipts
        are finished, and inspecting only ``limit`` per 30-second pass took
        hours to come round a full store to a stranded message."""
        from maverick.governed_records import GovernedRecordStore
        from maverick.privacy_ops import RecordConflict

        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("Invalid channel recovery window")
        cursors = GovernedRecordStore("channel-delivery-cursors", "chc", "channel_delivery_cursor")
        cursor_id = "chc-" + _digest([channel, account])[:56]
        cursor = cursors.get(cursor_id)
        if cursor is None:
            try:
                cursor = cursors.create({"id": cursor_id, "cursor": ""}, action="recovery_cursor_created",
                                        actor="system:channel", max_records=1000)
            except RecordConflict:
                cursor = cursors.get(cursor_id)
        rows, next_cursor = [], cursor["cursor"]
        started = _monotonic()
        for position, record_id in self.store.iter_record_ids(start_after=next_cursor,
                                                              limit=max(limit, scan_limit)):
            row = self._surface_stale_claim(self.get(record_id))
            if row and row["execution"] == "staging":
                self._compact_receipt(row, time.time())
                row = self.get(record_id)
            next_cursor = position
            if (row and not row.get("restore_hold") and row["channel"] == channel and row["account_sha256"] == _digest(account)
                    and (row["execution"] == "received" or row["delivery"] in {"ready", "retryable"}
                         or row.get("question_watch"))
                    and (not respect_retry_at or not retry_delay(row))):
                rows.append(row)
            if len(rows) >= limit or _monotonic() - started >= scan_seconds:
                break
        return rows, (cursors, cursor, next_cursor)

    def _surface_stale_claim(self, row):
        from maverick.privacy_ops import RecordConflict

        if (row and not row.get("restore_hold") and row["delivery"] == "sending"
                and row["updated_at"] < time.time() - STALE_CLAIM_SECONDS):
            # A send that never recorded how it ended belongs to a process that
            # stopped mid-send. It may have reached the person, so it becomes
            # an unknown outcome: reviewable, compactable, and never replayed.
            chunks = {key: ({**chunk, "state": "delivery_unknown"} if chunk.get("state") == "sending" else chunk)
                      for key, chunk in row["chunks"].items()}
            try:
                return self.change(row, delivery="delivery_unknown", chunks=chunks,
                                   reason="Delivery began but its process stopped before recording a result; "
                                          "check the destination before sending again")
            except RecordConflict:
                return self.get(row["id"])
        if (row and not row.get("restore_hold") and row["execution"] == "execution_started_unconfirmed"
                and row["updated_at"] < time.time() - STALE_CLAIM_SECONDS):
            return self._surface_stale_execution(row)
        return row

    def _surface_stale_execution(self, row):
        from maverick.privacy_ops import RecordConflict

        # A different-home replica's local lock says nothing about its owner.
        try:
            if row.get("activity_scope") != _activity_scope():
                log.warning("Channel execution has no matching workspace owner; its receipt remains unresolved")
                return row
            with _receipt_activity(row["id"]) as idle:
                current = self.get(row["id"])
                if not idle or not current or current["revision"] != row["revision"]:
                    return current
                return self.change(current, execution="execution_unknown", delivery="ready",
                                   reply=asdict(Reply(_INTERNAL_ERROR_REPLY)),
                                   reason="Execution began but its process stopped before recording a result; "
                                          "review before retrying")
        except RecordConflict:
            return self.get(row["id"])
        except (OSError, ImportError, ValueError):
            log.warning("Channel execution ownership cannot be checked; its receipt remains unresolved")
            return self.get(row["id"])

    def finish_recovery_window(self, checkpoint):
        from maverick.privacy_ops import RecordConflict

        cursors, cursor, next_cursor = checkpoint
        try:
            cursors.update(cursor["id"], lambda row: row.update(cursor=next_cursor),
                           expected_revision=cursor["revision"], action="recovery_window_completed", actor="system:channel")
        except RecordConflict:
            pass  # Another worker advanced; CAS execution/delivery still owns each item.

    def change(self, row, **updates):
        from maverick.privacy_ops import RecordConflict

        changed = self.store.update(row["id"], lambda record: record.update(updates),
                                    expected_revision=row["revision"], action="delivery_transition", actor="system:channel")
        if changed is None:
            raise RecordConflict("Channel receipt no longer exists")
        return changed

    def admit(self, msg, *, external_id, account, route=None):
        _assert_work_allowed()
        record_id = _record_id(msg.channel, account, external_id)
        with _receipt_activity(record_id, blocking=True, purpose="intake"):
            return self._admit(msg, external_id=external_id, account=account, route=route)

    def _admit(self, msg, *, external_id, account, route=None):
        from maverick.attachments import _encode_for_disk, _publish_attachment
        from maverick.file_lock import ensure_private_directory
        from maverick.governed_records import GovernedRecordCapacityError
        from maverick.privacy_ops import RecordConflict

        _assert_work_allowed()
        record_id = _record_id(msg.channel, account, external_id)
        payload, publications = _payload(msg, record_id)
        route = {} if route is None else route
        if len(json.dumps(route).encode()) > 65536:
            raise IntakeMessageRejected("Channel reply routing exceeds its bound")
        fingerprint = _digest([payload, route])
        row = self.get(record_id)
        if row and row.get("staging_retired") and not row.get("restore_hold"):
            if row.get("activity_scope") != _activity_scope():
                raise IntakeMessageRejected("Unfinished message cleanup has no matching workspace owner; review its saved receipt")
            self._retire_staging(row)
            row = self.get(record_id)
        if row is None:
            self._maintenance_tick()
            # Confirm the existing execution-claim authority is readable before
            # accepting intake. No execution claim is taken at this boundary.
            from maverick.world_model import close_world_if_owned, open_world

            world = open_world()
            try:
                world.is_processed_message(msg.channel, external_id)
            finally:
                close_world_if_owned(world)
            record = {"id": record_id, "channel": msg.channel, "account_sha256": _digest(account),
                      "external_id": external_id, "fingerprint": fingerprint, "message": payload,
                      "route": route, "execution": "staging", "delivery": "not_ready", "chunks": {},
                      "execution_id": str(uuid.uuid4()), "activity_scope": _activity_scope(create=True)}
            try:
                row = self.store.create(record, action="intake_admitted", actor="system:channel",
                                        max_records=intake_record_limit())
            except RecordConflict:
                row = self.get(record_id)
            except GovernedRecordCapacityError as exc:
                # A long-idle workspace may have expired tombstones beyond the
                # next cursor window. Scan a bounded portion before refusing.
                deadline = _monotonic() + 1.0
                for attempt in range(CAPACITY_RECOVERY_BATCHES):
                    if attempt and _monotonic() >= deadline:
                        break
                    try:
                        released = self.compact_delivered(limit=100, release_only=True)
                    except Exception:  # noqa: BLE001 -- preserve capacity diagnosis
                        log.warning("Channel receipt cleanup could not free capacity", exc_info=True)
                        break
                    if released:
                        break
                try:
                    row = self.store.create(record, action="intake_admitted", actor="system:channel",
                                            max_records=intake_record_limit())
                except GovernedRecordCapacityError:
                    raise GovernedRecordCapacityError(
                        "Chat app message capacity is full. Open Settings > All settings > Chat channels "
                        "to increase it; delivered messages past retention clear automatically. "
                        "Messages that need review remain saved."
                    ) from exc
                except RecordConflict:
                    row = self.get(record_id)
        if not row or row["fingerprint"] not in (fingerprint, _earlier_fingerprint(payload, route)):
            raise IntakeMessageRejected("Channel message identity already belongs to different content or routing")
        if row.get("restore_hold"):
            return row
        if row["execution"] == "staging":
            for path, data, sha in publications:
                ensure_private_directory(path.parent)
                _publish_attachment(path, _encode_for_disk(data, path), sha)
            try:
                row = self.change(row, execution="received")
            except RecordConflict:
                row = self.get(record_id)
        return row

    def claim_execution(self, row):
        from maverick.privacy_ops import RecordConflict
        from maverick.world_model import close_world_if_owned, open_world

        _assert_work_allowed()
        if row.get("restore_hold") or row["execution"] != "received":
            return None
        # Open/check the legacy authority before claiming execution so a store
        # outage remains safely retryable. Legacy claims are never reopened.
        world = open_world()
        try:
            legacy = world.is_processed_message(row["channel"], row["external_id"])
            try:
                claimed = self.change(row, execution="execution_started_unconfirmed",
                                      activity_scope=_activity_scope(create=row.get("activity_scope") is None))
            except RecordConflict:
                return None
            marked = False
            if not legacy:
                try:
                    marked = world.mark_message_processed("delivery:" + row["channel"], row["id"])
                except Exception:
                    # The handler has not run. Hand the receipt back to recovery;
                    # if the mark did land, the next claim finds it and records
                    # the message as unknown instead of running it twice.
                    self.change(claimed, execution="received")
                    raise
            if legacy or not marked:
                self.change(claimed, execution="execution_unknown", reason="Prior execution claim has no confirmed result")
                return None
            return claimed
        finally:
            close_world_if_owned(world)

    def compact_delivered(self, *, limit=100, release_only=False):
        """Clear expired payloads only; retain dedup tombstones and unknowns.

        Capacity is a hard admission bound, not permission to evict unresolved
        or deduplication identities. Operators can archive the tenant authority
        under their retention policy before provisioning further capacity.
        """
        from maverick.governed_records import GovernedRecordStore
        from maverick.privacy_ops import RecordConflict

        _assert_work_allowed()
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Invalid channel retention batch")
        cursors = GovernedRecordStore("channel-delivery-cursors", "chc", "channel_delivery_cursor")
        cursor_id = "chc-" + _digest(["maintenance", "retention", 1])[:56]
        cursor = cursors.get(cursor_id)
        if cursor is None:
            try:
                cursor = cursors.create({"id": cursor_id, "cursor": "", "purpose": "retention"},
                                        action="retention_cursor_created", actor="system:channel", max_records=1000)
            except RecordConflict:
                cursor = cursors.get(cursor_id)
        now, compacted, released = time.time(), 0, 0
        next_cursor = cursor["cursor"]
        try:
            for position, record_id in self.store.iter_record_ids(start_after=cursor["cursor"], limit=limit):
                next_cursor = position
                outcome = self._compact_receipt(self.get(record_id), now)
                compacted += bool(outcome)
                released += outcome == "deleted"
                if release_only and released:
                    break
        finally:
            # Surface cleanup failures, but do not let one locked or malformed
            # receipt starve every later record. The rotating scan retries it.
            self.finish_recovery_window((cursors, cursor, next_cursor))
        return released if release_only else compacted

    def _retire_staging(self, row):
        """Under the activity lock, persist cleanup intent before deleting blobs."""
        _assert_work_allowed()
        if not row.get("staging_retired"):
            digests = list(dict.fromkeys(item["sha256"] for item in row["message"].get("attachments", [])))
            _cleanup_paths(row["id"], digests)
            row = self.change(row, staging_retired=True, cleanup_pending=digests)
        for path in _cleanup_paths(row["id"], row["cleanup_pending"]):
            _assert_work_allowed()
            path.unlink(missing_ok=True)
        return "deleted" if self.store.delete(row["id"], expected_revision=row["revision"]) else False

    def _compact_staging(self, row, now):
        from maverick.privacy_ops import RecordConflict

        if (row.get("restore_hold")
                or not row.get("staging_retired") and row["updated_at"] > now - STALE_CLAIM_SECONDS):
            return False
        try:
            if row.get("activity_scope") != _activity_scope():
                log.warning("Unfinished channel intake has no matching workspace owner; its receipt remains saved")
                return False
            with _receipt_activity(row["id"], purpose="intake") as idle:
                current = self.get(row["id"])
                if not idle or not current or current["revision"] != row["revision"]:
                    return False
                return self._retire_staging(current)
        except RecordConflict:
            return False
        except (OSError, ImportError, ValueError):
            log.warning("Channel staging cleanup could not confirm idle ownership; its receipt remains saved")
            return False

    def _compact_receipt(self, row, now):
        from maverick.privacy_ops import RecordConflict

        if row and row["execution"] == "staging":
            return self._compact_staging(row, now)
        if (not row or row.get("restore_hold") or row.get("question_watch")
                or row["execution"] != "completed" or not _settled(row)):
            return False
        if row.get("compacted") and row.get("cleanup_pending") == []:
            if row["updated_at"] > now - TOMBSTONE_SECONDS:
                return False
            try:
                return "deleted" if self.store.delete(row["id"], expected_revision=row["revision"]) else False
            except RecordConflict:
                return False
        if ("cleanup_pending" not in row and not row.get("compacted")
                and row["updated_at"] > now - RETENTION_SECONDS):
            return False
        try:
            if "cleanup_pending" not in row:
                digests = (_legacy_cleanup_digests(row["id"]) if row.get("compacted") else
                           list(dict.fromkeys(item["sha256"] for item in [
                               *row["message"].get("attachments", []), *row.get("reply_files", [])])))
                _cleanup_paths(row["id"], digests)
                # CAS establishes durable cleanup intent before any deletion.
                # Retrying this state bypasses the updated_at retention cutoff.
                row = self.change(row, message={}, reply=None, reply_files=[], reply_source=None, chunks={}, route={},
                                  cleanup_pending=digests, compacted=False)
            for path in _cleanup_paths(row["id"], row["cleanup_pending"]):
                _assert_work_allowed()
                path.unlink(missing_ok=True)
            self.change(row, cleanup_pending=[], compacted=True)
        except RecordConflict:
            return False  # Another worker owns/completed the transition.
        return "compacted"


async def admit_message(msg, *, external_id, account, authorize, route=None, journal=None):
    if not authorize():
        raise PermissionError("Channel sender authorization changed")
    journal = journal or DeliveryJournal()
    return await asyncio.to_thread(journal.admit, msg, external_id=external_id, account=account, route=route)


# Fields the saved message gained after its first release; at their defaults
# the message is the one an earlier build saved without them.
_LATER_FIELDS = {"provider_tenant_id": None, "provider_sender_id": None, "conversation_ref": None,
                 "question_reply_only": False}


def _earlier_fingerprint(payload, route):
    """The fingerprint an earlier build gave this message, or None."""
    if any(payload.get(key) != default for key, default in _LATER_FIELDS.items()):
        return None
    return _digest([{key: value for key, value in payload.items() if key not in _LATER_FIELDS}, route])


def _settled(row):
    """Delivered, or fully written through a transport without remote receipts."""
    if row["delivery"] == "delivered":
        return True
    if row["delivery"] != "delivery_unknown":
        return False
    if row["channel"] == "voice":
        return True  # The answer goes back in the call's own HTTP response.
    written = [chunk for key, chunk in row.get("chunks", {}).items() if key != "reply"]
    return (row["channel"] == "irc" and bool(written)
            and all(chunk.get("state") == "delivered" for chunk in written))


def _require_reply_source(row):
    source = row.get("reply_source")
    if source is None:
        return
    from maverick.channel_reply_results import require_source

    if (source.get("channel") != row["channel"]
            or source.get("account_sha256") != row["account_sha256"]):
        raise PermissionError("Saved reply source does not belong to this chat account")
    require_source(source)


def _freeze_reply_files(row, reply, material):
    from maverick.attachments import (
        _seal_context,
        _verify_stored_attachment,
        is_sealed_file,
        validate_attachment,
    )
    from maverick.authority_effects import authority_effect_fence
    from maverick.crypto_at_rest import seal_bound
    from maverick.file_lock import atomic_write_bytes, cross_process_lock, ensure_private_directory

    files = material["files"]
    if (not isinstance(files, list) or len(files) > MAX_ATTACHMENTS
            or reply.attachments != [item["filename"] for item in files]):
        raise ValueError("Native reply file selection changed")
    prepared = {**row, "reply_source": material["source"]}
    saved, total = [], 0
    for item in files:
        data = item["data"]
        sha = validate_attachment(item["filename"], item["mime"], data, existing_total=total)
        if sha != item["sha256"]:
            raise ValueError("Native reply file content changed")
        total += len(data)
        path = _blob_path(row["id"], sha)
        ensure_private_directory(path.parent)
        with authority_effect_fence(), cross_process_lock(path, strict=True):
            _require_reply_source(prepared)
            if path.exists():
                _verify_stored_attachment(path, sha)
            if not path.exists() or not is_sealed_file(path):
                atomic_write_bytes(path, seal_bound(data, _seal_context(path), portable=True),
                                   effect_guard=lambda: _require_reply_source(prepared))
            _require_reply_source(prepared)
        saved.append({"filename": item["filename"], "mime": item["mime"],
                      "sha256": sha, "size_bytes": len(data), "source": item["source"]})
    _require_reply_source(prepared)
    return {"reply_files": saved, "reply_source": material["source"]}


async def saved_reply_files(reply):
    """Only files frozen with this exact encrypted native reply may be shipped."""
    attempt = _ACTIVE.get()
    if not reply.attachments or not isinstance(attempt, _DeliveryAttempt):
        return []
    row = await asyncio.to_thread(attempt.journal.get, attempt.record_id)
    if row.get("reply") != asdict(reply):
        raise DeliveryUnknown("Saved reply changed before file delivery")
    await asyncio.to_thread(_require_reply_source, row)
    return list(row.get("reply_files", []))


def _read_reply_file(row, item):
    from maverick.attachments import (
        _SEAL_OVERHEAD,
        MAX_FILE_BYTES,
        _decode_stored,
        _verify_stored_attachment,
        validate_attachment,
    )

    if item not in row.get("reply_files", []):
        raise DeliveryUnknown("File does not belong to this saved reply")
    _require_reply_source(row)
    path = _blob_path(row["id"], item["sha256"])
    _verify_stored_attachment(path, item["sha256"])
    with path.open("rb") as stream:
        stored = stream.read(MAX_FILE_BYTES + _SEAL_OVERHEAD + 1)
    data = _decode_stored(stored, path, item["sha256"])
    if (len(data) != item["size_bytes"]
            or validate_attachment(item["filename"], item["mime"], data) != item["sha256"]):
        raise DeliveryUnknown("Saved reply file failed its content check")
    _require_reply_source(row)
    return data


async def read_reply_file(item):
    attempt = _ACTIVE.get()
    if not isinstance(attempt, _DeliveryAttempt):
        raise DeliveryNotSent("File delivery requires a saved native reply")
    row = await asyncio.to_thread(attempt.journal.get, attempt.record_id)
    data = await asyncio.to_thread(_read_reply_file, row, item)
    if not attempt.authorize():
        raise DeliveryNotSent("Chat authorization changed before file delivery")
    return data


async def _execute_claimed(channel, inbound, claimed, *, journal, authorize):
    """Run the handler for a claimed receipt and record its outcome. Every exit
    records one: a result, or ``execution_unknown`` with a reply to the sender."""
    try:
        if not authorize():
            raise PermissionError("Channel sender authorization changed")
        _assert_work_allowed()
        # Runtime-only provenance from the verified receipt, never from an
        # inbound body or a restored message field supplied by the sender.
        inbound._verified_channel_account_sha256 = claimed["account_sha256"]
        if claimed["channel"] == "teams":
            inbound._verified_private_destination = claimed["route"].get("private_destination")
        reply = as_reply(await channel.handler(inbound))
        if len(reply.text) > MAX_TEXT_CHARS or len(reply.attachments) > MAX_ATTACHMENTS:
            raise ValueError("Channel reply exceeds durable outbox bound")
        material = getattr(inbound, "_channel_reply_material", None)
        extras = (await asyncio.to_thread(_freeze_reply_files, claimed, reply, material)
                  if material is not None else {})
        return await asyncio.to_thread(
            journal.change, claimed, execution="completed", delivery="ready",
            reply=asdict(reply),
            question_watch=getattr(inbound, "_channel_question_watch", None),
            **extras,
        )
    except asyncio.CancelledError:
        # Recorded synchronously: a second cancellation cannot interrupt it,
        # and the receipt must not stay "started" with no outcome.
        try:
            journal.change(claimed, execution="execution_unknown", delivery="ready",
                           reply=asdict(Reply(_INTERNAL_ERROR_REPLY)),
                           reason="Execution was cancelled before a result was stored; review before retrying")
        except Exception:  # noqa: BLE001 -- recovery surfaces it once stale
            pass
        raise
    except Exception:
        return await asyncio.to_thread(journal.change, claimed, execution="execution_unknown", delivery="ready",
                                       reply=asdict(Reply(_INTERNAL_ERROR_REPLY)),
                                       reason="Execution began without a confirmed stored result; review before retrying")


async def process_message(channel, msg, *, external_id, account, authorize, send, route=None,
                          receipt=None, journal=None, idempotent=False, prepare=None,
                          provider_retry_seconds=PROVIDER_RETRY_SECONDS):
    _assert_work_allowed()
    journal = journal or DeliveryJournal()
    if receipt is not None:
        expected = _record_id(msg.channel, account, external_id)
        if receipt.get("id") != expected:
            raise PermissionError("Channel receipt does not belong to the current tenant and account")
        row = await asyncio.to_thread(journal.get, expected)
        if row is None:
            raise DeliveryUnknown("Admitted channel receipt is unavailable")
    else:
        row = await admit_message(msg, external_id=external_id, account=account,
                                  authorize=authorize, route=route, journal=journal)
    if not authorize():
        raise PermissionError("Channel sender authorization changed")
    # Materialization/downloads do not dispatch the agent. Leave the receipt
    # received if preparation fails so a later recovery can safely try again.
    # CAS publication plus the execution claim still gives one handler owner.
    if row.get("restore_hold"):
        return row  # A recovery disposition never authorizes old work to replay.
    inbound = None
    if row["execution"] == "received":
        inbound = await asyncio.to_thread(_materialize, row)
        if prepare is not None and not row.get("preparation_complete"):
            from maverick.attachments import _encode_for_disk, _publish_attachment
            from maverick.file_lock import ensure_private_directory
            from maverick.privacy_ops import RecordConflict

            inbound = await prepare(inbound)
            payload, publications = await asyncio.to_thread(_payload, inbound, row["id"])
            # A receipt saved before question_reply_only existed lacks the key;
            # it was admitted with that field's default.
            admitted = {"question_reply_only": False, **row["message"]}
            if any(payload.get(key) != admitted.get(key)
                    for key in ("user_id", "sender_id", "channel", "message_id",
                                "conversation_ref", "question_reply_only", "text")):
                raise PermissionError("Prepared channel input changed its admitted identity or text")
            for path, data, sha in publications:
                await asyncio.to_thread(ensure_private_directory, path.parent)
                await asyncio.to_thread(_publish_attachment, path, _encode_for_disk(data, path), sha)
            try:
                row = await asyncio.to_thread(journal.change, row, message=payload, preparation_complete=True)
            except RecordConflict:
                # Another preparer owns the current revision. It alone may
                # claim execution; an observer must not use stale input.
                return await asyncio.to_thread(journal.get, row["id"])
        if not authorize():
            raise PermissionError("Channel sender authorization changed")
    if row["execution"] == "received":
        with _receipt_activity(row["id"]) as idle:
            if not idle:
                return await asyncio.to_thread(journal.get, row["id"])
            claimed = await asyncio.to_thread(journal.claim_execution, row)
            if claimed:
                row = await _execute_claimed(channel, inbound, claimed, journal=journal, authorize=authorize)
            else:
                row = await asyncio.to_thread(journal.get, row["id"])
    else:
        row = await asyncio.to_thread(journal.get, row["id"])
    if not row.get("reply") or row["delivery"] in {"delivered", "delivery_failed"}:
        return row
    if not authorize():
        raise PermissionError("Channel reply authorization changed")
    context = _DeliveryAttempt(journal, row["id"], authorize, retry_seconds=provider_retry_seconds)
    token = _ACTIVE.set(context)
    try:
        reply = Reply(**row["reply"])
        # The outer operation protects adapters whose provider offers no
        # chunk API. Instrumented adapters additionally receipt each chunk.
        payload = ({"reply": row["reply"], "files": row["reply_files"], "source": row["reply_source"]}
                   if "reply_files" in row else row["reply"])
        await context.send_chunk("reply", payload, lambda: send(reply), idempotent=idempotent)
    except Exception:
        # The owning chunk transition records the outcome atomically. A
        # duplicate observer (or failed receipt write) cannot overwrite a
        # live owner's state with an inferred delivery outcome.
        await context.mark_unconfirmed()
    finally:
        _ACTIVE.reset(token)
    return await asyncio.to_thread(journal.get, row["id"])


async def _recover_row(channel, row, *, account, authorize, send, prepare, journal, idempotent):
    """Re-drive one journal row; None when current policy no longer authorizes it."""
    values = {key: value for key, value in row["message"].items() if key != "attachments"}
    incoming = IncomingMessage(**values)
    if not authorize(incoming):
        return None

    async def send_saved(reply):
        return await send(incoming, reply, row["route"])

    async def prepare_saved(message):
        return await prepare(message, row["route"])

    return await process_message(
        channel, incoming, external_id=row["external_id"], account=account,
        authorize=lambda: authorize(incoming), send=send_saved,
        prepare=prepare_saved if prepare else None, receipt=row, journal=journal,
        idempotent=idempotent)


async def notify_queued_question(row, *, authorize, send, journal=None):
    """Deliver one later question through the original sealed intake route."""
    watch = row.get("question_watch")
    if not watch or row.get("restore_hold") or row.get("compacted"):
        return None
    journal = journal or DeliveryJournal()
    values = {key: value for key, value in row["message"].items() if key != "attachments"}
    incoming = IncomingMessage(**values)
    if not authorize(incoming):
        return None
    from maverick.server import queued_channel_question

    text, retire = await asyncio.to_thread(
        queued_channel_question, watch, incoming, row["account_sha256"],
    )
    if retire:
        from maverick.privacy_ops import RecordConflict

        try:
            return await asyncio.to_thread(journal.change, row, question_watch=None)
        except RecordConflict:
            return None
    if not text or row["delivery"] != "delivered":
        return None
    key = "question:" + _digest(text)[:32]
    attempt = _DeliveryAttempt(journal, row["id"], lambda: authorize(incoming))

    async def send_question():
        # Provider chunks and deterministic email Message-IDs need their own
        # namespace; the queued acknowledgement already used text-0/email-0.
        token = _ACTIVE.set(_PrefixedAttempt(attempt, key + ":"))
        try:
            return await send(incoming, Reply(text), row["route"])
        finally:
            _ACTIVE.reset(token)

    await attempt.send_chunk(
        key, {"text": text, "route": row["route"]},
        send_question,
    )
    from maverick.privacy_ops import RecordConflict

    current = await asyncio.to_thread(journal.get, row["id"])
    try:
        return await asyncio.to_thread(journal.change, current, question_watch=None)
    except RecordConflict:
        return None


async def recover_messages(channel, *, account, authorize, send, prepare=None, limit=16,
                           journal=None, idempotent=False, respect_retry_at=False):
    """Recover one fair window with adapter-owned routing and current policy.

    Explicit recovery retains immediate retry; automatic workers respect the
    persisted provider retry deadline.

    authorize(message) -> bool; send(message, saved_reply, route) -> awaitable;
    optional prepare(message, route) -> awaitable[IncomingMessage].
    """
    journal = journal or DeliveryJournal()
    rows, checkpoint = await asyncio.to_thread(journal.recovery_window, channel=channel.name, account=account,
                                             limit=limit, respect_retry_at=respect_retry_at)
    outcomes = []
    for row in rows:
        try:
            outcome = await _recover_row(channel, row, account=account, authorize=authorize,
                                         send=send, prepare=prepare, journal=journal,
                                         idempotent=idempotent)
            current = await asyncio.to_thread(journal.get, row["id"])
            if current and current.get("question_watch"):
                await notify_queued_question(current, authorize=authorize, send=send,
                                             journal=journal)
        except Exception as exc:
            # One unrecoverable row (a malformed record, a missing blob, an
            # unknown outcome) must not pin the cursor: that would starve every
            # later row in the window on every pass. The row keeps its own
            # state; the window still advances.
            logging.getLogger(__name__).warning(
                "delivery recovery: %s row %s deferred: %s",
                channel.name, row.get("external_id"), exc)
            outcome = exc
        if outcome is not None:
            outcomes.append(outcome)
    # Reached only when the whole window was attempted; a cancellation leaves
    # the cursor where it was so unattempted rows are revisited.
    await asyncio.to_thread(journal.finish_recovery_window, checkpoint)
    return outcomes


class _DeliveryAttempt:
    def __init__(self, journal, record_id, authorize, *, retry_seconds=PROVIDER_RETRY_SECONDS):
        self.journal, self.record_id, self.authorize = journal, record_id, authorize
        self.retry_seconds = retry_seconds
        self.outer_attempt_id = None

    async def mark_unconfirmed(self):
        from maverick.privacy_ops import RecordConflict

        if self.outer_attempt_id is None:
            return
        row = await asyncio.to_thread(self.journal.get, self.record_id)
        chunk = row["chunks"].get("reply", {})
        if chunk.get("attempt_id") != self.outer_attempt_id or chunk.get("state") != "sending":
            return
        try:
            await asyncio.to_thread(self.journal.change, row, delivery="delivery_unknown")
        except RecordConflict:
            pass  # A confirmed owner transition always wins over this fallback.

    async def send_chunk(self, key, payload, call, *, idempotent=False):
        from maverick.privacy_ops import RecordConflict

        _assert_work_allowed()
        if not self.authorize():
            raise PermissionError("Channel reply authorization changed")
        key = _bounded(key, 128, "chunk key")
        row = await asyncio.to_thread(self.journal.get, self.record_id)
        if row.get("restore_hold"):
            raise DeliveryUnknown("Restored channel delivery remains retired from automatic replay")
        chunks = dict(row["chunks"])
        old = chunks.get(key)
        digest = _digest(payload)
        if old and old["payload_sha256"] != digest:
            raise DeliveryUnknown("Saved channel chunk changed")
        if old and old["state"] == "delivered":
            return old.get("provider_id")
        if old and old["state"] == "delivery_failed":
            raise DeliveryNotSent("The provider repeatedly refused this reply; review its saved receipt")
        if old and old["state"] == "sending":
            raise _DeliveryOwnedElsewhere("Another worker owns this channel delivery")
        if old and old["state"] == "delivery_unknown" and not idempotent:
            raise DeliveryUnknown("Prior channel send has no confirmed receipt")
        if key not in chunks and len(chunks) >= MAX_CHUNKS:
            raise DeliveryNotSent("Channel reply exceeds chunk bound")
        attempt_id = uuid.uuid4().hex
        chunks[key] = {"state": "sending", "payload_sha256": digest, "attempt_id": attempt_id,
                       "attempts": (old or {}).get("attempts", 0),
                       "idempotency_key": str(uuid.uuid5(uuid.NAMESPACE_URL, self.record_id + ":" + key))}
        try:
            updates = {"chunks": chunks}
            if key == "reply":
                updates["delivery"] = "sending"
            await asyncio.to_thread(self.journal.change, row, **updates)
        except RecordConflict as exc:
            raise _DeliveryOwnedElsewhere("Another worker owns this channel delivery") from exc
        if key == "reply":
            self.outer_attempt_id = attempt_id
        provider_called = False
        try:
            _assert_work_allowed()
            if not self.authorize():
                raise _DeliveryNotAuthorized("Channel sender authorization changed before sending")
            try:
                await asyncio.to_thread(_require_reply_source, row)
            except PermissionError as exc:
                # Refused before the provider is called: nothing was sent, so the
                # chunk stays retryable (recorded unknown, a non-idempotent
                # channel would refuse every replay and the reply never go out).
                raise DeliveryWithheld(str(exc)) from exc
            if not self.authorize():
                raise _DeliveryNotAuthorized("Channel sender authorization changed before sending")
            provider_called = True
            result = await call()
        except DeliveryNotSent as exc:
            withheld = isinstance(exc, DeliveryWithheld)
            await self._finish(key, attempt_id, "retryable", withheld=withheld,
                               rejected=provider_called and not withheld and not isinstance(exc, _DeliveryNotAuthorized))
            raise
        except BaseException:
            await self._finish(key, attempt_id, "delivery_unknown")
            raise
        await self._finish(key, attempt_id, "delivered", str(result or "")[:512])
        return result

    async def _finish(self, key, attempt_id, state, provider_id="", *, withheld=False, rejected=False):
        row = await asyncio.to_thread(self.journal.get, self.record_id)
        chunks = dict(row["chunks"])
        if chunks[key]["attempt_id"] != attempt_id:
            raise DeliveryUnknown("Channel send ownership changed")
        if rejected:
            attempts = chunks[key].get("attempts", 0) + 1
            chunks[key]["attempts"] = attempts
            if attempts >= MAX_PROVIDER_ATTEMPTS:
                state = "delivery_failed"
            else:
                chunks[key]["retry_at"] = time.time() + self.retry_seconds * 2 ** (attempts - 1)
        chunks[key] = {**chunks[key], "state": state, "provider_id": provider_id}
        if withheld:
            chunks[key]["withheld"] = True
        updates = {"chunks": chunks}
        if key == "reply":
            updates["delivery"] = state
            if state == "delivery_failed":
                updates["reason"] = "The provider repeatedly refused this reply. Automatic attempts stopped; review the saved delivery receipt."
                log.warning("Channel %s reply %s was refused repeatedly; automatic attempts stopped and the receipt needs review",
                            row["channel"], self.record_id)
        await asyncio.to_thread(self.journal.change, row, **updates)


class _PrefixedAttempt:
    """Namespace a later question's provider chunks within the intake receipt."""

    def __init__(self, attempt, prefix):
        self.attempt, self.prefix = attempt, prefix
        self.record_id = attempt.record_id + ":" + prefix

    async def send_chunk(self, key, payload, call, *, idempotent=False):
        return await self.attempt.send_chunk(
            self.prefix + key, payload, call, idempotent=idempotent,
        )


async def send_chunk(key, payload, call, *, idempotent=False):
    """Receipt one provider call; standalone Channel.send retains its old API."""
    _assert_work_allowed()
    current = _ACTIVE.get()
    return await call() if current is None else await current.send_chunk(key, payload, call, idempotent=idempotent)


def chunk_idempotency_key(key):
    current = _ACTIVE.get()
    return str(uuid.uuid4()) if current is None else str(uuid.uuid5(uuid.NAMESPACE_URL, current.record_id + ":" + key))


def delivery_active():
    return _ACTIVE.get() is not None


@asynccontextmanager
async def recovery_worker(channel, **kwargs):
    """Own one periodic recovery task for a running transport."""
    kwargs = {**kwargs, "respect_retry_at": True}

    async def run():
        while True:
            try:
                await channel.recover_messages(**kwargs)
            except Exception:
                logging.getLogger(__name__).warning("Channel %s recovery window requires review", channel.name)
            await asyncio.sleep(30)
    task = asyncio.create_task(run(), name="channel-recovery:" + channel.name)
    try:
        yield
    finally:
        task.cancel()
        done, _ = await asyncio.wait([task], timeout=5)
        if task in done:
            try:
                task.result()
            except asyncio.CancelledError:
                pass
        else:
            logging.getLogger(__name__).warning("Channel %s recovery cancellation remains unconfirmed", channel.name)
