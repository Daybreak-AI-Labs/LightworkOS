"""Bounded encrypted observations; OS custody belongs to existing job threads.

Reading a retained observation never claims or restarts its worker. Local locks
qualify processes on one host/data root, not cross-host execution.
"""
from __future__ import annotations

import copy
import json
import os
import re
import time

from maverick import crypto_at_rest
from maverick.control_plane_lease import Holder, Lease, _require_single_replica, _try_lock
from maverick.file_lock import (
    _open_lock_file,
    _validate_open_lock_file,
    atomic_create_text,
    atomic_read_text,
    cross_process_lock,
    ensure_private_directory,
    harden_path_permissions,
)
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import data_dir
from maverick.privacy_ops import RecordConflict

MAX_KEPT = 40
MAX_RESULT_BYTES = 128 * 1024
_ID = "lj-observations"
_STORE = GovernedRecordStore("learning_job_observations", "lj", "learning_task_observations",
                            authority_scope="deployment_global")


class ObservationUnavailable(RuntimeError):
    """Persistence cannot establish an exact retained outcome."""


def _root():
    return data_dir("learning_job_custody", tenant=None)


def _open_custody(name):
    root = _root()
    ensure_private_directory(root)
    path = root / name
    fd = _open_lock_file(path)
    try:
        harden_path_permissions(path)
        _validate_open_lock_file(path, fd)
        if not _try_lock(fd):
            os.close(fd)
            return None
        return Lease(path, fd, Holder(os.getpid(), "local", time.time(), 0, "learning-task"))
    except BaseException:
        os.close(fd)
        raise


class Custody:
    def __init__(self, leases):
        self.leases = leases

    def assert_owned(self):
        for lease in self.leases:
            lease.assert_owned()

    def release(self):
        for lease in reversed(self.leases):
            lease.release()


def acquire(kind, job_id):
    """Keep the existing one-kind/three-worker bounds across local servers."""
    _require_single_replica()
    root = _root()
    ensure_private_directory(root)
    with cross_process_lock(root / "admission", strict=True):
        leases = []
        try:
            kind_lease = _open_custody("kind-" + digest(kind))
            if kind_lease is None:
                raise ObservationUnavailable("This work is already active on this installation. Read its recorded progress before starting it again.")
            leases.append(kind_lease)
            for number in range(3):
                slot = _open_custody("slot-" + str(number))
                if slot is not None:
                    leases.append(slot)
                    break
            else:
                raise ObservationUnavailable("Three tasks are already active on this installation. Wait for a task to finish before starting more.")
            job_lease = _open_custody("job-" + job_id)
            if job_lease is None:
                raise ObservationUnavailable("This task's worker custody could not be established. Nothing was started.")
            leases.append(job_lease)
            return Custody(leases)
        except BaseException:
            Custody(leases).release()
            raise


def _payload(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(raw.encode("utf-8")) > MAX_RESULT_BYTES:
        raise ObservationUnavailable("This task's result is too large to retain in recent tasks. Read the underlying learning records; do not repeat the work automatically.")
    sealed = crypto_at_rest.seal_to_str(raw)
    if not crypto_at_rest.is_sealed_str(sealed):
        raise ObservationUnavailable("This task's private observation could not be protected. Read the last saved records; do not repeat work automatically.")
    return sealed


def _rows(record):
    if record is None:
        return {}
    if record.get("schema") != 1 or not isinstance(record.get("jobs"), dict) or len(record["jobs"]) > MAX_KEPT:
        raise ObservationUnavailable("Recent task records cannot be verified. No work was started or repeated.")
    result = {}
    for job_id, sealed in record["jobs"].items():
        if (not isinstance(job_id, str) or not re.fullmatch(r"[a-f0-9]{16}", job_id)
                or not isinstance(sealed, str) or not crypto_at_rest.is_sealed_str(sealed)):
            raise ObservationUnavailable("Recent task records cannot be verified. No work was started or repeated.")
        raw = crypto_at_rest.unseal_from_str(sealed)
        if len(raw.encode("utf-8")) > MAX_RESULT_BYTES:
            raise ObservationUnavailable("A retained task exceeds its supported size. No work was repeated.")
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get("id") != job_id
                or value.get("state") not in {"admitted", "running", "stopping", "done", "failed", "stopped", "not_started"}):
            raise ObservationUnavailable("Recent task records cannot be verified. No work was repeated.")
        result[job_id] = value
    return result


def _load():
    marker = _root() / "observations-established"
    try:
        if marker.stat().st_size > 32:
            raise ObservationUnavailable("Recent task storage cannot be verified. No work was started or repeated.")
        established = atomic_read_text(marker)
    except FileNotFoundError:
        established = None
    if established is not None and established != "learning-observations-v1":
        raise ObservationUnavailable("Recent task storage cannot be verified. No work was started or repeated.")
    value = _STORE.get(_ID)
    if value is None and established is not None:
        raise ObservationUnavailable("Previously retained task storage is missing. No work was started or repeated. Review installation recovery in Settings.")
    return value


def read():
    return snapshot()[0]


def snapshot():
    try:
        with crypto_at_rest.deployment_key_scope():
            record = _load()
            return _rows(record), digest(record)
    except ObservationUnavailable:
        raise
    except Exception as exc:
        raise ObservationUnavailable("Recent task storage is unavailable or cannot be verified. No work was started or repeated. Check installation records and encryption readiness in Settings.") from exc


def unchanged(version):
    """Recheck native authority without decrypting every private result again."""
    try:
        with crypto_at_rest.deployment_key_scope():
            return digest(_load()) == version
    except Exception as exc:
        raise ObservationUnavailable("Recent task storage could not be rechecked. Read current tasks again; no work was repeated.") from exc


def _retirable(value):
    if value.get("kind") in {"factory_guidance_check", "factory_guidance_adopt", "factory_guidance_restore"}:
        import math
        result = value.get("result")
        until = result.get("original_until") if isinstance(result, dict) else None
        if type(until) not in {int, float} or not math.isfinite(until) or time.time() < until:
            return False
    if value["state"] not in {"admitted", "running", "stopping"}:
        return True
    # A missing worker in this process is not evidence it stopped. Only the
    # original per-task OS custody being free allows observation retirement.
    lease = _open_custody("job-" + value["id"])
    if lease is None:
        return False
    lease.release()
    return True


def write(value, *, action, actor, admit=False):
    """Commit/read back one exact observation; do not recover by dispatching."""
    try:
        with crypto_at_rest.deployment_key_scope():
            sealed = _payload(value)
            for _attempt in range(8):
                old = _load()
                rows = _rows(old)
                if not admit and value["id"] not in rows:
                    raise ObservationUnavailable("This task's retained observation is unavailable. Its current live result is not confirmed as saved.")
                while admit and value["id"] not in rows and len(rows) >= MAX_KEPT:
                    earlier = sorted(rows.values(), key=lambda row: row["started_at"])
                    retire = next((row for row in earlier if _retirable(row)), None)
                    if retire is None:
                        raise ObservationUnavailable("Recent tasks are full while their workers are still held. Read active tasks before starting another one.")
                    rows.pop(retire["id"])
                rows[value["id"]] = copy.deepcopy(value)
                payloads = {key: sealed if key == value["id"] else old["jobs"][key] for key in rows}
                try:
                    if old is None:
                        saved = _STORE.create({"id": _ID, "schema": 1, "jobs": payloads}, action=action, actor=actor, max_records=1)
                    else:
                        saved = _STORE.update(_ID, lambda row, exact=payloads: row.update(jobs=exact), expected_revision=old["revision"], action=action, actor=actor)
                except RecordConflict:
                    continue
                if saved is None or saved.get("_audit_pending"):
                    raise ObservationUnavailable("The task observation or its activity receipt is unconfirmed. Read the original task before trying anything again.")
                try:
                    atomic_create_text(_root() / "observations-established", "learning-observations-v1")
                except FileExistsError:
                    if atomic_read_text(_root() / "observations-established") != "learning-observations-v1":
                        raise ObservationUnavailable("Recent task storage cannot be verified. Its saved outcome remains unconfirmed.") from None
                checked = _rows(_STORE.get(_ID)).get(value["id"])
                if checked != value:
                    raise ObservationUnavailable("The exact task observation could not be read back. Its saved outcome remains unconfirmed.")
                return
            raise ObservationUnavailable("Recent tasks changed repeatedly. Nothing new was dispatched; refresh before reviewing again.")
    except ObservationUnavailable:
        raise
    except Exception as exc:
        raise ObservationUnavailable("The task observation could not be confirmed as saved. No work will be started or repeated automatically. Check installation records and encryption readiness in Settings.") from exc
