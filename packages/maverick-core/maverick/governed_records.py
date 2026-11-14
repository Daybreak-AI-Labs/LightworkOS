"""Reusable CAS record store with a durable at-least-once audit outbox.

Security, privacy, agent-governance, product-security, and evidence records all
need the same persistence contract: tenant scoping, monotonic revisions,
compare-and-swap mutations, and a signed audit event that cannot be lost when
the audit writer is temporarily unavailable.  This module keeps that contract
in one place rather than letting each product invent a weaker variation.

The local backend remains :class:`maverick.privacy_ops._RecordStore` for the
single-replica compatibility posture.  A Postgres backend provides the same
contract across hosts.  Enterprise and multi-replica deployments fail closed
unless that shared backend and an explicit tenant are available.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import math
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from . import runtime_metrics
from .governed_record_lookup import LocalRecordLookup, RecordLookupSpec, RecordLookupUnavailable
from .postgres_transactions import (
    PostgresTransactions,
    validate_pool_min_size,
    validate_pool_settings,
)
from .privacy_ops import (
    AuditOutboxError,
    PrivacyStateError,
    RecordConflict,
    _queue_audit,
    _RecordStore,
    _unsafe_path_alias,
    _validate_document_evidence_record,
    _validated_audit_queue,
)

log = logging.getLogger(__name__)

_EVENT_KIND = "governed_record_changed"
_MAX_DELIVERIES_PER_FLUSH = 16
_MAX_RECORD_JSON_BYTES = 16 * 1024 * 1024
_MAX_STORED_RECORD_BYTES = 24 * 1024 * 1024
_POSTGRES_TABLE = "governed_records"
_POSTGRES_SCHEMA_LOCK = 0x6D766B677276  # ``mvkgrv``
_POSTGRES_COLUMNS = (
    ("tenant_id", "text", "NO"),
    ("namespace", "text", "NO"),
    ("record_id", "text", "NO"),
    ("revision", "bigint", "NO"),
    ("record_json", "text", "NO"),
    ("created_at", "double precision", "NO"),
    ("updated_at", "double precision", "NO"),
)
_POSTGRES_PRIMARY_KEY = ("tenant_id", "namespace", "record_id")
# Valid tenant ids have an encoded path segment of at most 200 characters.
# This 201-character value therefore cannot collide with a real tenant, while
# preserving the legacy unbound root for explicitly non-strict deployments.
_UNBOUND_TENANT_KEY = "_" * 201
# Deployment-global control-plane authorities must not inherit an ambient
# request tenant, but they also must not share the legacy unbound row.  A real
# tenant can never produce a 201-character canonical id: its portable segment
# is bounded to 200 characters by ``paths.MAX_TENANT_SEGMENT_LENGTH``.  Keeping
# this key private and selecting it only through the explicit authority scope
# below makes the row unreachable through ordinary tenant binding.
_DEPLOYMENT_GLOBAL_TENANT_KEY = "G" * 201
_AUTHORITY_SCOPES = frozenset({"tenant", "deployment_global"})
_RECORD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_BACKENDS = frozenset({"auto", "local", "postgres"})
_REQUIRED_BACKENDS = frozenset({"local", "postgres"})
_RESERVED_FIELDS = frozenset({
    "_audit_pending",
    "created_at",
    "updated_at",
    "revision",
})


@dataclass(frozen=True)
class GovernedMutationFence:
    """One authority-document predicate checked inside a target mutation.

    Shared cross-record invariants cannot be protected by a lease pre-check:
    the holder may expire after the check and before its target row commits.
    A Postgres backend evaluates this predicate after locking the authority
    document and before touching the target row, in the *same transaction* as
    the target mutation.  A takeover therefore either waits for that commit or
    makes the stale holder fail before it can write.

    The predicate must be deterministic, side-effect free, and raise on a
    missing, expired, or otherwise invalid permit.  Local callers should keep
    using their strict filesystem critical section instead of this shared-only
    primitive.
    """

    namespace: str
    prefix: str
    record_id: str
    authority_scope: str
    validate: Callable[[dict[str, Any], float], None]

    def __post_init__(self) -> None:
        _required(self.namespace, "fence namespace", 128)
        prefix = _required(self.prefix, "fence prefix", 16)
        _valid_record_id(self.record_id, prefix)
        if self.authority_scope not in _AUTHORITY_SCOPES:
            raise ValueError("fence authority_scope must be tenant or deployment_global")
        if not callable(self.validate):
            raise TypeError("fence validator must be callable")


def _required(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    return text


def _list_limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("list limit must be an integer")
    # One sentinel row beyond a 10,000-record operational ceiling lets callers
    # detect overflow without issuing an unbounded read.
    if value < 1 or value > 10_001:
        raise ValueError("list limit must be between 1 and 10001")
    return value


def _capacity_limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("record capacity must be an integer")
    if value < 1:
        raise ValueError("record capacity must be positive")
    return value


def _archive_namespace(namespace: str) -> str:
    """Where a full namespace moves its oldest delivered records (kept, not counted)."""
    name = f"{namespace}-archive"
    if len(name) <= 128:
        return name
    return namespace[:95] + "-" + hashlib.sha256(namespace.encode("utf-8")).hexdigest()[:24] + "-archive"


# Statuses that end a record's workflow in every store that uses them. Only
# such records, and records with no status or state at all (receipts, logs),
# are archived when a namespace is full: an archived record leaves the store's
# lists, so archiving open work would hide it. A record in any other status,
# including an unknown one, stays; a namespace full of open work refuses new
# records instead. Deliberately absent because a store uses them for open work:
# "sent" (a questionnaire awaiting its answer), "approved", "accepted", and
# "failed" / "dead_letter" (may still need someone's attention).
_SETTLED_STATUSES = frozenset({
    "archived", "canceled", "cancelled", "closed", "complete", "completed",
    "confirmed", "declined", "delivered", "denied", "done", "erased", "expired",
    "finished", "invalidated", "passed", "purged", "refused", "rejected",
    "replaced", "replayed", "request_denied", "resolved", "retired", "revoked",
    "rolled_back", "settled", "succeeded", "superseded", "waived", "withdrawn",
})


def _settled(record: dict[str, Any]) -> bool:
    for key in ("status", "state"):
        value = record.get(key)
        if isinstance(value, str) and value.strip().lower() not in _SETTLED_STATUSES:
            return False
    return True


class GovernedRecordBackendError(RuntimeError):
    """A governed-record backend cannot preserve its persistence contract."""


class GovernedRecordCapacityError(GovernedRecordBackendError):
    """A bounded governed namespace has no admission slot for a new identity."""


class _GovernedRecordValidationError(ValueError):
    """Controlled validation diagnostic safe to cross the provider boundary."""


def _local_effect_guard(backend, effect_guard):
    """Forward callbacks only to supported native writers; preserve legacy calls."""
    if effect_guard is None:
        return {}
    if not isinstance(backend, (LocalGovernedRecordBackend, PostgresGovernedRecordBackend)):
        raise GovernedRecordBackendError(
            "physical effect callbacks require a supported native record backend"
        )
    return {"effect_guard": effect_guard}


class GovernedRecordBackend(Protocol):
    """Narrow persistence seam used by :class:`GovernedRecordStore`."""

    kind: str
    shared: bool

    def new_id(self) -> str: ...

    def authoritative_time(self) -> float: ...

    def save(
        self,
        record: dict[str, Any],
        *,
        expected_revision: int | None = None,
        fence: GovernedMutationFence | None = None,
        max_records: int | None = None,
    ) -> dict[str, Any]: ...

    def load(self, record_id: str) -> dict[str, Any] | None: ...

    def list(self, *, limit: int | None = None) -> list[dict[str, Any]]: ...

    def iter_record_ids(
        self,
        *,
        start_after: str = "",
        limit: int = 100,
    ) -> Iterator[tuple[str, str]]: ...

    def update(
        self,
        record_id: str,
        mutate: Callable[[dict[str, Any]], None],
        *,
        expected_revision: int | None = None,
        metadata_only: bool = False,
        fence: GovernedMutationFence | None = None,
    ) -> dict[str, Any] | None: ...

    def delete(self, record_id: str, *, expected_revision: int) -> bool: ...


class LocalGovernedRecordBackend:
    """Existing private-file backend for one control-plane replica."""

    kind = "local"
    shared = False

    def __init__(
        self,
        namespace: str,
        prefix: str,
        *,
        authority_scope: str = "tenant",
        lookup_spec: RecordLookupSpec | None = None,
    ) -> None:
        scope = str(authority_scope or "").strip().lower()
        if scope not in _AUTHORITY_SCOPES:
            raise ValueError(
                "authority_scope must be tenant or deployment_global"
            )
        if scope == "deployment_global":
            self._store = _DeploymentGlobalRecordStore(namespace, prefix)
            self._archive = _DeploymentGlobalRecordStore(_archive_namespace(namespace), prefix)
        else:
            self._store = _RecordStore(namespace, prefix)
            self._archive = _RecordStore(_archive_namespace(namespace), prefix)
        self.authority_scope = scope
        self.lookup_spec = lookup_spec
        self._lookup = LocalRecordLookup(self._store, lookup_spec) if lookup_spec else None

    def new_id(self) -> str:
        return self._store.new_id()

    @staticmethod
    def authoritative_time() -> float:
        return time.time()

    def save(
        self, record, *, expected_revision=None, fence=None, max_records=None, effect_guard=None,
    ):
        def operation():
            return self._save(record, expected_revision=expected_revision, fence=fence, max_records=max_records, effect_guard=effect_guard)
        if self._lookup is None:
            return operation()
        record_id = _valid_record_id(record.get("id"), self._store.prefix)
        self.lookup_spec.keys(record)
        return self._lookup.mutate(record_id, operation)

    def _save(
        self,
        record: dict[str, Any],
        *,
        expected_revision: int | None = None,
        fence: GovernedMutationFence | None = None,
        max_records: int | None = None,
        effect_guard=None,
    ) -> dict[str, Any]:
        if fence is not None:
            raise GovernedRecordBackendError(
                "transactional mutation fences require a shared backend"
            )
        if max_records is None:
            return self._store.save(
                record,
                expected_revision=expected_revision,
                effect_guard=effect_guard,
            )
        maximum = _capacity_limit(max_records)
        from .file_lock import cross_process_lock, ensure_private_directory

        record_dir = self._store._dir()
        ensure_private_directory(record_dir)
        # All bounded creates for this local namespace take the same admission
        # lock. The capacity check and per-record atomic create therefore form
        # one cross-process critical section without changing legacy updates.
        admission_target = record_dir / ".namespace-admission"
        with cross_process_lock(admission_target, strict=True):
            record_id = _valid_record_id(record.get("id"), self._store.prefix)
            existing = self._store.load(record_id)
            # Admission counts IDs, never bodies: the old list-based check
            # parsed up to ``maximum`` JSON files per create, which turned
            # bulk imports into O(rows x namespace) reads.
            if (
                existing is None
                and sum(
                    1 for _ in self._store.iter_record_ids(limit=maximum)
                ) >= maximum
            ):
                raise GovernedRecordCapacityError(
                    "governed record namespace capacity has been reached"
                )
            return self._store.save(
                record,
                expected_revision=expected_revision,
                effect_guard=effect_guard,
            )

    def load(self, record_id: str) -> dict[str, Any] | None:
        return self._store.load(record_id)

    def list(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        if limit is None:
            return self._store.list()
        bounded = _list_limit(limit)
        return self._store.list_bounded(limit=bounded)

    def iter_record_ids(
        self,
        *,
        start_after: str = "",
        limit: int = 100,
    ) -> Iterator[tuple[str, str]]:
        return self._store.iter_record_ids(
            start_after=start_after,
            limit=limit,
        )

    def update(
        self, record_id, mutate, *, expected_revision=None, metadata_only=False, fence=None, effect_guard=None,
    ):
        def operation():
            return self._update(record_id, mutate, expected_revision=expected_revision,
                                metadata_only=metadata_only, fence=fence, effect_guard=effect_guard)
        if self._lookup is None:
            return operation()
        try:
            _valid_record_id(record_id, self._store.prefix)
        except ValueError:
            return None
        def validated_mutation(value):
            mutate(value)
            self.lookup_spec.keys(value)
        return self._lookup.mutate(record_id, lambda: self._update(
            record_id, validated_mutation, expected_revision=expected_revision,
            metadata_only=metadata_only, fence=fence, effect_guard=effect_guard))

    def _update(
        self,
        record_id: str,
        mutate: Callable[[dict[str, Any]], None],
        *,
        expected_revision: int | None = None,
        metadata_only: bool = False,
        fence: GovernedMutationFence | None = None,
        effect_guard=None,
    ) -> dict[str, Any] | None:
        if fence is not None:
            raise GovernedRecordBackendError(
                "transactional mutation fences require a shared backend"
            )
        return self._store.update(
            record_id,
            mutate,
            expected_revision=expected_revision,
            metadata_only=metadata_only,
            effect_guard=effect_guard,
        )

    def delete(self, record_id: str, *, expected_revision: int) -> bool:
        if self._lookup is None:
            return self._delete(record_id, expected_revision=expected_revision)
        try:
            _valid_record_id(record_id, self._store.prefix)
        except ValueError:
            return False
        return self._lookup.mutate(record_id, lambda: self._delete(record_id, expected_revision=expected_revision))

    def load_archived(self, record_id: str) -> dict[str, Any] | None:
        return self._archive.load(record_id)

    def list_archived(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        if limit is None:
            return self._archive.list()
        return self._archive.list_bounded(limit=_list_limit(limit))

    def archive(self, record_id: str, *, expected_revision: int) -> bool:
        """Move one delivered record, unchanged, out of the capped namespace."""
        from .file_lock import cross_process_lock, ensure_private_directory

        path, target = self._store._path(record_id), self._archive._path(record_id)  # noqa: SLF001
        if path is None or target is None:
            return False
        ensure_private_directory(target.parent)
        with cross_process_lock(path, strict=True):
            current = self._store._read_path(path)  # noqa: SLF001 - backend-owned store
            if (current is None or _RecordStore._revision(current) != expected_revision
                    or _validated_audit_queue(current) or target.exists()):
                return False
            os.replace(path, target)
        return True

    def restore(self, record_id: str) -> bool:
        """Move an archived record back so it can change again."""
        from .file_lock import cross_process_lock, ensure_private_directory

        path, source = self._store._path(record_id), self._archive._path(record_id)  # noqa: SLF001
        if path is None or source is None or not source.exists():
            return False
        ensure_private_directory(path.parent)
        with cross_process_lock(path, strict=True):
            if path.exists() or self._archive._read_path(source) is None:  # noqa: SLF001
                return False
            os.replace(source, path)
        return True

    def lookup(self, digest):
        if self._lookup is None:
            raise RecordLookupUnavailable("record lookup is not configured")
        return self._lookup.lookup(digest)

    def maintain_lookup(self, *, limit=100, rebuild=False):
        if self._lookup is None:
            raise RecordLookupUnavailable("record lookup is not configured")
        return self._lookup.maintain(limit=limit, rebuild=rebuild)

    def _delete(self, record_id: str, *, expected_revision: int) -> bool:
        """Physically remove one fully delivered retained record under CAS."""

        from .file_lock import cross_process_lock

        expected = _expected_revision(expected_revision)
        if expected is None:
            raise ValueError("expected_revision is required for governed deletion")
        active_path = self._store._path(record_id)  # noqa: SLF001 - backend-owned store
        if active_path is None:
            return False
        # Archive and restore use this same active-record lock. Choose the
        # record's location and validate CAS before removing it, without ever
        # moving an archived record into the capacity-limited active namespace.
        with cross_process_lock(active_path, strict=True):
            store, path = self._store, active_path
            try:
                locked_info = path.lstat()
            except FileNotFoundError:
                if self._lookup is not None:
                    return False
                store = self._archive
                path = store._path(record_id)  # noqa: SLF001 - backend-owned store
                if path is None:
                    return False
                try:
                    locked_info = path.lstat()
                except FileNotFoundError:
                    return False
            if _unsafe_path_alias(path, locked_info):
                raise PermissionError("governed record path alias is not permitted")
            current = store._read_path(path)  # noqa: SLF001 - backend-owned store
            if current is None:
                return False
            revision = _RecordStore._revision(current)
            if revision != expected:
                raise RecordConflict(
                    "governed record changed "
                    f"(expected revision {expected}, found {revision})"
                )
            if _validated_audit_queue(current):
                raise AuditOutboxError(
                    "governed record cannot be deleted with pending audit receipts"
                )
            path.unlink()
        return True


class _DeploymentGlobalRecordStore(_RecordStore):
    """Local compatibility projection that cannot inherit request tenancy."""

    def _dir(self):
        from .paths import data_dir

        return data_dir(self.name, tenant=None)


def _valid_record_id(record_id: object, prefix: str) -> str:
    value = str(record_id or "")
    if not _RECORD_ID_RE.fullmatch(value) or not value.startswith(f"{prefix}-"):
        raise ValueError("invalid governed record id")
    return value


def _expected_revision(value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("expected governed record revision is invalid")
    return value


def _canonical_json(record: Mapping[str, Any]) -> str:
    try:
        value = json.dumps(
            dict(record),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise _GovernedRecordValidationError(
            "governed record is not valid bounded JSON"
        ) from exc
    if len(value.encode("utf-8")) > _MAX_RECORD_JSON_BYTES:
        raise _GovernedRecordValidationError(
            "governed record exceeds the 16 MiB JSON limit"
        )
    return value


def _logical_digest(record: Mapping[str, Any]) -> str:
    logical = {key: value for key, value in record.items() if key != "_audit_pending"}
    return hashlib.sha256(_canonical_json(logical).encode("utf-8")).hexdigest()


def _prepared_record(
    record: Mapping[str, Any],
    previous: Mapping[str, Any] | None,
    *,
    bump_revision: bool,
) -> dict[str, Any]:
    saved = dict(record)
    prior_revision = _RecordStore._revision(dict(previous) if previous else None)
    saved["revision"] = prior_revision + (1 if bump_revision else 0)
    pending_items = _validated_audit_queue(saved)
    if pending_items:
        digest = _logical_digest(saved)
        stamped: list[dict[str, Any]] = []
        for item in pending_items:
            receipt = dict(item)
            receipt.setdefault("revision", saved["revision"])
            receipt.setdefault("status", str(saved.get("status") or ""))
            receipt.setdefault("record_sha256", digest)
            stamped.append(receipt)
        saved["_audit_pending"] = stamped
        _validated_audit_queue(saved)
    else:
        saved.pop("_audit_pending", None)
    # Validate and size the exact logical document before opening a transaction.
    _canonical_json(saved)
    return saved


def _encode_record(
    record: Mapping[str, Any],
    *,
    require_encryption: bool,
) -> str:
    raw = _canonical_json(record)
    from .crypto_at_rest import (
        at_rest_enabled,
        deployment_key_scope,
        external_fleet_key_scope,
        seal_to_str,
    )

    encryption_enabled = at_rest_enabled()
    if require_encryption and not encryption_enabled:
        raise GovernedRecordBackendError(
            "shared governed records require application at-rest encryption"
        )
    if require_encryption:
        # Shared rows use the externally pinned deployment key even when the
        # rest of the deployment opts into node-local tenant DEKs. This keeps
        # every Postgres reader decryptable without claiming an unfinished
        # cross-replica tenant-KMS authority.
        with deployment_key_scope(), external_fleet_key_scope():
            stored = seal_to_str(raw)
    else:
        stored = seal_to_str(raw) if encryption_enabled else raw
    if len(stored.encode("utf-8")) > _MAX_STORED_RECORD_BYTES:
        raise _GovernedRecordValidationError(
            "sealed governed record exceeds the 24 MiB storage limit"
        )
    return stored


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("governed record JSON contains a duplicate key")
        value[key] = item
    return value


def _decode_record(
    stored: object,
    *,
    record_id: str,
    prefix: str,
    revision: object,
    created_at: object,
    updated_at: object,
    require_encryption: bool,
) -> dict[str, Any]:
    if not isinstance(stored, str):
        raise PrivacyStateError("governed record payload is not text")
    if len(stored.encode("utf-8")) > _MAX_STORED_RECORD_BYTES:
        raise PrivacyStateError("governed record payload exceeds its storage bound")
    from .crypto_at_rest import (
        at_rest_enabled,
        deployment_key_scope,
        external_fleet_key_scope,
        is_sealed_str,
        strict_at_rest,
        unseal_from_str,
    )

    sealed = is_sealed_str(stored)
    if require_encryption and not sealed:
        raise PrivacyStateError(
            "unsealed shared governed record withheld by encryption floor"
        )
    if at_rest_enabled() and strict_at_rest() and not sealed:
        raise PrivacyStateError(
            "unsealed governed record withheld in strict mode"
        )
    if sealed and require_encryption:
        with deployment_key_scope(), external_fleet_key_scope():
            raw = unseal_from_str(stored)
    else:
        raw = unseal_from_str(stored) if sealed else stored
    if len(raw.encode("utf-8")) > _MAX_RECORD_JSON_BYTES:
        raise PrivacyStateError("governed record JSON exceeds its size bound")
    try:
        value = json.loads(raw, object_pairs_hook=_json_object)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PrivacyStateError("governed record JSON is invalid") from exc
    if not isinstance(value, dict):
        raise PrivacyStateError("governed record JSON is not an object")
    if value.get("id") != record_id:
        raise PrivacyStateError("governed record identity does not match its row")
    body_revision = _RecordStore._revision(value)
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or body_revision != revision
    ):
        raise PrivacyStateError("governed record revision does not match its row")
    for key, column in (("created_at", created_at), ("updated_at", updated_at)):
        body_value = value.get(key)
        if isinstance(body_value, bool) or isinstance(column, bool):
            raise PrivacyStateError("governed record timestamp is invalid")
        try:
            body_timestamp = float(body_value)
            column_timestamp = float(column)
        except (TypeError, ValueError) as exc:
            raise PrivacyStateError("governed record timestamp is invalid") from exc
        if not math.isfinite(body_timestamp) or body_timestamp != column_timestamp:
            raise PrivacyStateError("governed record timestamp does not match its row")
    _validated_audit_queue(value)
    _validate_document_evidence_record(value)
    _valid_record_id(record_id, prefix)
    return value


def _row_record(
    row: object,
    *,
    record_id: str,
    prefix: str,
    require_encryption: bool,
) -> dict[str, Any]:
    if not isinstance(row, (tuple, list)) or len(row) != 4:
        raise PrivacyStateError("governed record row has an invalid shape")
    return _decode_record(
        row[1],
        record_id=record_id,
        prefix=prefix,
        revision=row[0],
        created_at=row[2],
        updated_at=row[3],
        require_encryption=require_encryption,
    )


class PostgresGovernedRecordBackend:
    """Transactionally shared Postgres implementation of the record seam.

    Each operation owns a transaction. Connections are fresh by default; an
    explicit bounded pool can reuse them after rollback/reset. ``connect`` is
    injectable for deterministic tests and caller-owned unpooled adapters.
    """

    kind = "postgres"
    shared = True

    def __init__(
        self,
        namespace: str,
        prefix: str,
        *,
        dsn: str,
        connect: Callable[..., Any] | None = None,
        require_bound_tenant: bool = False,
        require_encryption: bool = False,
        require_shared_key_identity: bool = False,
        authority_scope: str = "tenant",
        pool_size: int = 0,
        pool_timeout_seconds: float = 5,
        lookup_spec: RecordLookupSpec | None = None,
        pool_min_size: int = 1,
    ) -> None:
        # Postgres is the shared, potentially multi-tenant authority.  Keep
        # the argument for source compatibility with injected/test adapters,
        # but never permit this backend to persist governed payloads in
        # plaintext.  Local single-replica stores retain their optional
        # encryption behavior.
        del require_encryption
        self.namespace = _required(namespace, "namespace", 128)
        self.prefix = _required(prefix, "prefix", 16)
        self._dsn = _required(dsn, "Postgres DSN", 8192)
        self._connect_override = connect
        self._require_bound_tenant = bool(require_bound_tenant)
        self._require_encryption = True
        # Every Postgres row is potentially cross-process, even when the
        # operator forgot to declare multiple replicas. Never encrypt shared
        # records with an auto-generated node-local key.
        del require_shared_key_identity
        self._require_shared_key_identity = True
        scope = str(authority_scope or "").strip().lower()
        if scope not in _AUTHORITY_SCOPES:
            raise ValueError(
                "authority_scope must be tenant or deployment_global"
            )
        self._authority_scope = scope
        self.authority_scope = scope
        self._schema_ready = False
        self._schema_lock = threading.Lock()
        self._transactions = PostgresTransactions(
            self._dsn, connect=connect, pool_size=pool_size,
            pool_timeout_seconds=pool_timeout_seconds, pool_min_size=pool_min_size,
        )
        from .governed_record_lookup_pg import PostgresRecordLookup
        self.lookup_spec = lookup_spec
        self._lookup = PostgresRecordLookup(self, lookup_spec) if lookup_spec else None

    def _connect(self):
        try:
            return self._transactions.connect()
        except ImportError as exc:
            raise GovernedRecordBackendError(
                "shared governed records require maverick-core[postgres]"
            ) from exc

    def authoritative_time(self) -> float:
        """Return database wall time for cross-replica lease decisions."""
        with self._operation("authoritative time"):
            self._require_application_crypto_authority()
            with self._raw_transaction() as cur:
                cur.execute("SELECT extract(epoch FROM clock_timestamp())")
                row = cur.fetchone()
        if not isinstance(row, (tuple, list)) or len(row) != 1:
            raise GovernedRecordBackendError(
                "shared governed-record authoritative time is unavailable"
            )
        try:
            value = float(row[0])
        except (TypeError, ValueError, OverflowError) as exc:
            raise GovernedRecordBackendError(
                "shared governed-record authoritative time is invalid"
            ) from exc
        if not math.isfinite(value) or value <= 0:
            raise GovernedRecordBackendError(
                "shared governed-record authoritative time is invalid"
            )
        return value

    @contextlib.contextmanager
    def _raw_transaction(self):
        try:
            with self._transactions.transaction() as cursor:
                yield cursor
        except ImportError as exc:
            raise GovernedRecordBackendError(
                "shared governed records require maverick-core[postgres]"
            ) from exc

    @contextlib.contextmanager
    def _operation(self, action: str):
        crypto_scope: contextlib.AbstractContextManager[Any]
        if self._authority_scope == "deployment_global":
            from .crypto_at_rest import deployment_key_scope

            crypto_scope = deployment_key_scope()
        else:
            crypto_scope = contextlib.nullcontext()
        fleet_key_scope: contextlib.AbstractContextManager[Any]
        if self._require_shared_key_identity:
            from .crypto_at_rest import external_fleet_key_scope

            fleet_key_scope = external_fleet_key_scope()
        else:
            fleet_key_scope = contextlib.nullcontext()
        try:
            with crypto_scope, fleet_key_scope:
                yield
        except (
            AuditOutboxError,
            GovernedRecordBackendError,
            PrivacyStateError,
            RecordConflict,
            _GovernedRecordValidationError,
        ):
            raise
        except Exception as exc:  # noqa: BLE001 - redact provider diagnostics
            log.error(
                "Postgres governed-record %s failed (%s)",
                action,
                type(exc).__name__,
            )
            raise GovernedRecordBackendError(
                f"shared governed-record {action} failed"
            ) from None

    @staticmethod
    def _policy_sql() -> str:
        return (
            "CREATE POLICY mvk_tenant_isolation ON governed_records "
            "USING (tenant_id = nullif(current_setting('maverick.tenant', true), '')) "
            "WITH CHECK (tenant_id = nullif(current_setting('maverick.tenant', true), ''))"
        )

    @staticmethod
    def _rls_policy_rows_are_exact(rows: object) -> bool:
        if not isinstance(rows, (tuple, list)) or len(rows) != 1:
            return False
        policy = rows[0]
        if not isinstance(policy, (tuple, list)) or len(policy) != 6:
            return False
        name, permissive, roles, command, qual, with_check = policy
        if str(name) != "mvk_tenant_isolation":
            return False
        if str(permissive).strip().lower() != "permissive":
            return False
        if isinstance(roles, (tuple, list)):
            role_names = [str(role).strip().lower() for role in roles]
        else:
            role_names = [
                item.strip().strip("\"'").lower()
                for item in str(roles).strip("{}").split(",")
                if item.strip()
            ]
        if role_names != ["public"] or str(command).strip().lower() != "all":
            return False

        def _fail_closed(expression: object) -> bool:
            text = " ".join(str(expression).lower().split())
            return (
                "tenant_id" in text
                and "current_setting" in text
                and "maverick.tenant" in text
                and "nullif" in text
                and " or " not in text
                and "is null" not in text
            )

        return _fail_closed(qual) and _fail_closed(with_check)

    def _rls_policy_is_active_on(self, cur) -> bool:
        cur.execute(
            "SELECT relrowsecurity, relforcerowsecurity "
            "FROM pg_class WHERE oid = 'governed_records'::regclass"
        )
        row = cur.fetchone()
        if not row or not (row[0] and row[1]):
            return False
        cur.execute(
            "SELECT policyname, permissive, roles, cmd, qual, with_check "
            "FROM pg_policies "
            "WHERE schemaname = current_schema() "
            "AND tablename = %s ORDER BY policyname",
            (_POSTGRES_TABLE,),
        )
        return self._rls_policy_rows_are_exact(cur.fetchall())

    @staticmethod
    def _pg_array(value: object) -> tuple[str, ...]:
        if isinstance(value, (tuple, list)):
            return tuple(str(item) for item in value)
        return tuple(
            item.strip().strip("\"'")
            for item in str(value or "").strip("{}").split(",")
            if item.strip()
        )

    def _schema_status_on(self, cur) -> str:
        """Return ``missing``, ``ready``, or ``incompatible`` without DDL."""
        cur.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user"
        )
        role = cur.fetchone()
        if not role or bool(role[0]) or bool(role[1]):
            return "incompatible"
        cur.execute(
            "SELECT to_regclass(current_schema() || '.governed_records')"
        )
        table = cur.fetchone()
        if not table or table[0] is None:
            return "missing"
        cur.execute(
            "SELECT column_name, data_type, is_nullable "
            "FROM information_schema.columns "
            "WHERE table_schema=current_schema() AND table_name=%s "
            "ORDER BY ordinal_position",
            (_POSTGRES_TABLE,),
        )
        columns = tuple(tuple(str(item) for item in row) for row in cur.fetchall())
        if columns != _POSTGRES_COLUMNS:
            return "incompatible"
        cur.execute(
            "SELECT array_agg(a.attname ORDER BY keys.ordinality) "
            "FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid "
            "JOIN unnest(i.indkey) WITH ORDINALITY AS keys(attnum, ordinality) "
            "ON true JOIN pg_attribute a ON a.attrelid=c.oid "
            "AND a.attnum=keys.attnum "
            "WHERE c.oid='governed_records'::regclass AND i.indisprimary "
            "GROUP BY i.indexrelid"
        )
        primary = cur.fetchone()
        if not primary or self._pg_array(primary[0]) != _POSTGRES_PRIMARY_KEY:
            return "incompatible"
        cur.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='governed_records'::regclass AND contype='c'"
        )
        checks = [
            " ".join(str(row[0]).lower().replace("(", " ").replace(")", " ").split())
            for row in cur.fetchall()
        ]
        tenant_check = any(
            "char_length tenant_id between 1 and 201" in check
            or (
                "char_length tenant_id >= 1" in check
                and "char_length tenant_id <= 201" in check
            )
            for check in checks
        )
        namespace_check = any(
            "char_length namespace between 1 and 128" in check
            or (
                "char_length namespace >= 1" in check
                and "char_length namespace <= 128" in check
            )
            for check in checks
        )
        record_id_check = any(
            "record_id ~" in check
            and "^[a-za-z0-9][a-za-z0-9_-]{0,63}$" in check
            for check in checks
        )
        revision_check = any(
            "revision >= 1" in check or "revision >= (1)::bigint" in check
            for check in checks
        )
        size_check = any(
            "octet_length record_json <= 25165824" in check
            or "octet_length record_json <= 25165824::integer" in check
            for check in checks
        )
        if not all((
            tenant_check,
            namespace_check,
            record_id_check,
            revision_check,
            size_check,
        )):
            return "incompatible"
        if not self._rls_policy_is_active_on(cur):
            return "incompatible"
        return "ready"

    def _schema_status(self) -> str:
        try:
            with self._raw_transaction() as cur:
                return self._schema_status_on(cur)
        except Exception:
            return "unavailable"

    def _ensure_schema(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            initial = self._schema_status()
            if initial == "ready":
                self._schema_ready = True
                return
            if initial == "incompatible":
                raise GovernedRecordBackendError(
                    "shared governed-record schema is incompatible"
                )
            if initial == "unavailable":
                raise GovernedRecordBackendError(
                    "shared governed-record schema cannot be verified"
                )
            try:
                with self._raw_transaction() as cur:
                    cur.execute(
                        "SELECT pg_advisory_xact_lock(%s)",
                        (_POSTGRES_SCHEMA_LOCK,),
                    )
                    # A concurrent migration may have completed while this
                    # transaction waited. Never run DDL over a provisioned
                    # least-privilege schema that already verifies.
                    waited = self._schema_status_on(cur)
                    if waited == "ready":
                        self._schema_ready = True
                        return
                    if waited != "missing":
                        raise GovernedRecordBackendError(
                            "shared governed-record schema is incompatible"
                        )
                    cur.execute(
                        "CREATE TABLE IF NOT EXISTS governed_records ("
                        " tenant_id TEXT NOT NULL, namespace TEXT NOT NULL,"
                        " record_id TEXT NOT NULL, revision BIGINT NOT NULL,"
                        " record_json TEXT NOT NULL,"
                        " created_at DOUBLE PRECISION NOT NULL,"
                        " updated_at DOUBLE PRECISION NOT NULL,"
                        " PRIMARY KEY (tenant_id, namespace, record_id),"
                        " CHECK (char_length(tenant_id) BETWEEN 1 AND 201),"
                        " CHECK (char_length(namespace) BETWEEN 1 AND 128),"
                        " CHECK (record_id ~ "
                        "'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),"
                        " CHECK (revision >= 1),"
                        " CHECK (octet_length(record_json) <= 25165824))"
                    )
                    cur.execute(
                        "CREATE INDEX IF NOT EXISTS "
                        "idx_governed_records_tenant_namespace_created "
                        "ON governed_records(tenant_id, namespace, "
                        "created_at DESC, record_id)"
                    )
                    # This is always a shared, potentially multi-tenant control
                    # table.  RLS is therefore unconditional rather than an
                    # optional world-model tuning knob.
                    cur.execute(
                        "ALTER TABLE governed_records ENABLE ROW LEVEL SECURITY"
                    )
                    cur.execute(
                        "ALTER TABLE governed_records FORCE ROW LEVEL SECURITY"
                    )
                    cur.execute(
                        "DROP POLICY IF EXISTS mvk_tenant_isolation "
                        "ON governed_records"
                    )
                    cur.execute(self._policy_sql())
            except Exception as exc:
                # A non-owner runtime role may not alter a table migrated by an
                # administrator. It may proceed only when the complete schema,
                # primary key, bounds, forced RLS, and sole policy now verify.
                if self._schema_status() != "ready":
                    log.error(
                        "Postgres governed-record schema unavailable (%s)",
                        type(exc).__name__,
                    )
                    raise GovernedRecordBackendError(
                        "shared governed-record schema is unavailable"
                    ) from None
            if self._schema_status() != "ready":
                raise GovernedRecordBackendError(
                    "shared governed-record schema is unavailable or ambiguous"
                )
            self._schema_ready = True

    def _tenant_key(self) -> str:
        if self._authority_scope == "deployment_global":
            return _DEPLOYMENT_GLOBAL_TENANT_KEY
        from .paths import canonical_tenant_id, current_tenant_id_strict

        tenant = current_tenant_id_strict()
        if tenant is None:
            if self._require_bound_tenant:
                raise GovernedRecordBackendError(
                    "shared governed records require an active tenant"
                )
            return _UNBOUND_TENANT_KEY
        return canonical_tenant_id(tenant)

    def _require_application_crypto_authority(self) -> None:
        """Admit the exact encryption authority before any shared DB access."""
        if self._require_encryption:
            from .crypto_at_rest import (
                EncryptionUnavailable,
                at_rest_enabled,
                require_shared_deployment_key_identity,
            )

            if not at_rest_enabled():
                raise GovernedRecordBackendError(
                    "shared governed records require application at-rest encryption"
                )
            if self._require_shared_key_identity:
                try:
                    require_shared_deployment_key_identity()
                except EncryptionUnavailable as exc:
                    raise GovernedRecordBackendError(
                        "shared governed-record encryption key identity is unavailable"
                    ) from exc

    @contextlib.contextmanager
    def _transaction(self, tenant: str):
        self._require_application_crypto_authority()
        self._ensure_schema()
        with self._raw_transaction() as cur:
            # Re-verify the complete shared-authority schema on every
            # transaction. RLS drift (especially an added permissive policy,
            # which Postgres OR-combines) or loss of the tenant-bound primary
            # key must not become an authority bypass after initialization.
            if self._schema_status_on(cur) != "ready":
                raise GovernedRecordBackendError(
                    "shared governed-record schema is unavailable or ambiguous"
                )
            # Transaction-local GUC activates the table's forced RLS policy.
            cur.execute(
                "SELECT set_config('maverick.tenant', %s, true)",
                (tenant,),
            )
            if self._lookup is not None:
                self._lookup.prepare(cur, tenant)
            yield cur

    def new_id(self) -> str:
        # A shared long-lived fleet needs the full 128 random UUID bits. The
        # validator still accepts legacy 40-bit ids already stored on disk/DB.
        return f"{self.prefix}-{uuid.uuid4().hex}"

    @staticmethod
    def _row(cur) -> object:
        return cur.fetchone()

    def _select_for_update(self, cur, tenant: str, record_id: str) -> object:
        cur.execute(
            "SELECT revision, record_json, created_at, updated_at "
            "FROM governed_records WHERE tenant_id=%s AND namespace=%s "
            "AND record_id=%s FOR UPDATE",
            (tenant, self.namespace, record_id),
        )
        return self._row(cur)

    def _enforce_mutation_fence(
        self,
        cur,
        tenant: str,
        target_record_id: str,
        fence: GovernedMutationFence | None,
    ) -> None:
        """Lock and validate shared authority before touching a target row."""
        if fence is None:
            return
        cross_scope = (
            self._authority_scope == "tenant"
            and fence.authority_scope == "deployment_global"
        )
        if fence.authority_scope != self._authority_scope and not cross_scope:
            raise GovernedRecordBackendError(
                "mutation fence and target use different authority scopes"
            )
        if fence.namespace == self.namespace and fence.record_id == target_record_id:
            raise GovernedRecordBackendError(
                "mutation fence cannot be the target record"
            )
        fence_tenant = _DEPLOYMENT_GLOBAL_TENANT_KEY if cross_scope else tenant
        if cross_scope:
            # Forced RLS permits one tenant identity at a time. Select the
            # deployment-global authority under its unreachable sentinel, then
            # restore the tenant GUC before the target row is touched. The
            # global row lock remains held until this target transaction ends.
            cur.execute(
                "SELECT set_config('maverick.tenant', %s, true)",
                (fence_tenant,),
            )
        try:
            cur.execute(
                "SELECT revision, record_json, created_at, updated_at "
                "FROM governed_records WHERE tenant_id=%s AND namespace=%s "
                "AND record_id=%s FOR UPDATE",
                (fence_tenant, fence.namespace, fence.record_id),
            )
            row = self._row(cur)
            if row is None:
                raise GovernedRecordBackendError(
                    "shared mutation fence authority is unavailable"
                )
            if cross_scope:
                from .crypto_at_rest import deployment_key_scope

                with deployment_key_scope():
                    authority = _row_record(
                        row,
                        record_id=fence.record_id,
                        prefix=fence.prefix,
                        require_encryption=self._require_encryption,
                    )
            else:
                authority = _row_record(
                    row,
                    record_id=fence.record_id,
                    prefix=fence.prefix,
                    require_encryption=self._require_encryption,
                )
            cur.execute("SELECT extract(epoch FROM clock_timestamp())")
            clock_row = self._row(cur)
            if not isinstance(clock_row, (tuple, list)) or len(clock_row) != 1:
                raise GovernedRecordBackendError(
                    "shared mutation fence clock is unavailable"
                )
            try:
                now = float(clock_row[0])
            except (TypeError, ValueError, OverflowError) as exc:
                raise GovernedRecordBackendError(
                    "shared mutation fence clock is invalid"
                ) from exc
            if not math.isfinite(now) or now <= 0:
                raise GovernedRecordBackendError(
                    "shared mutation fence clock is invalid"
                )
            fence.validate(dict(authority), now)
        finally:
            if cross_scope:
                cur.execute(
                    "SELECT set_config('maverick.tenant', %s, true)",
                    (tenant,),
                )

    def save(
        self,
        record: dict[str, Any],
        *,
        expected_revision: int | None = None,
        fence: GovernedMutationFence | None = None,
        max_records: int | None = None,
        effect_guard: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        record_id = _valid_record_id(record.get("id"), self.prefix)
        expected = _expected_revision(expected_revision)
        maximum = (
            None
            if max_records is None
            else _capacity_limit(max_records)
        )
        tenant = self._tenant_key()
        with self._operation("save"):
            with self._transaction(tenant) as cur:
                self._enforce_mutation_fence(cur, tenant, record_id, fence)
                if maximum is not None:
                    lock_material = (
                        f"governed-record-capacity\0{tenant}\0{self.namespace}"
                    ).encode()
                    lock_key = int.from_bytes(
                        hashlib.sha256(lock_material).digest()[:8],
                        byteorder="big",
                        signed=True,
                    )
                    # Serialize capacity admission across every replica that
                    # writes this tenant namespace. The count and distinct-ID
                    # insert remain in this same transaction.
                    cur.execute(
                        "SELECT pg_advisory_xact_lock(%s)",
                        (lock_key,),
                    )
                row = self._select_for_update(cur, tenant, record_id)
                previous = (
                    _row_record(
                        row,
                        record_id=record_id,
                        prefix=self.prefix,
                        require_encryption=self._require_encryption,
                    )
                    if row is not None
                    else None
                )
                if previous is None and maximum is not None:
                    cur.execute(
                        "SELECT COUNT(*) FROM governed_records "
                        "WHERE tenant_id=%s AND namespace=%s",
                        (tenant, self.namespace),
                    )
                    count_row = self._row(cur)
                    if (
                        not isinstance(count_row, (tuple, list))
                        or len(count_row) != 1
                        or isinstance(count_row[0], bool)
                        or not isinstance(count_row[0], int)
                        or count_row[0] < 0
                    ):
                        raise GovernedRecordBackendError(
                            "shared governed-record capacity count is invalid"
                        )
                    if count_row[0] >= maximum:
                        raise GovernedRecordCapacityError(
                            "governed record namespace capacity has been reached"
                        )
                if effect_guard is not None:
                    effect_guard()
                current_revision = _RecordStore._revision(previous)
                if expected is not None and current_revision != expected:
                    raise RecordConflict(
                        "governed record changed "
                        f"(expected revision {expected}, found {current_revision})"
                    )
                saved = _prepared_record(record, previous, bump_revision=True)
                stored = _encode_record(
                    saved,
                    require_encryption=self._require_encryption,
                )
                if effect_guard is not None:
                    effect_guard()
                if previous is None:
                    cur.execute(
                        "INSERT INTO governed_records "
                        "(tenant_id, namespace, record_id, revision, record_json, "
                        "created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT (tenant_id, namespace, record_id) DO NOTHING",
                        (
                            tenant,
                            self.namespace,
                            record_id,
                            saved["revision"],
                            stored,
                            float(saved["created_at"]),
                            float(saved["updated_at"]),
                        ),
                    )
                    if cur.rowcount != 1:
                        raise RecordConflict("governed record already exists")
                else:
                    cur.execute(
                        "UPDATE governed_records SET revision=%s, record_json=%s, "
                        "created_at=%s, updated_at=%s WHERE tenant_id=%s "
                        "AND namespace=%s AND record_id=%s AND revision=%s",
                        (
                            saved["revision"],
                            stored,
                            float(saved["created_at"]),
                            float(saved["updated_at"]),
                            tenant,
                            self.namespace,
                            record_id,
                            current_revision,
                        ),
                    )
                    if cur.rowcount != 1:
                        raise RecordConflict("governed record changed during save")
                if self._lookup is not None:
                    self._lookup.replace(cur, tenant, record_id, saved)
                if effect_guard is not None:
                    effect_guard()
                return saved

    def load(self, record_id: str) -> dict[str, Any] | None:
        try:
            validated = _valid_record_id(record_id, self.prefix)
        except ValueError:
            return None
        tenant = self._tenant_key()
        with self._operation("load"):
            with self._transaction(tenant) as cur:
                cur.execute(
                    "SELECT revision, record_json, created_at, updated_at "
                    "FROM governed_records WHERE tenant_id=%s AND namespace=%s "
                    "AND record_id=%s",
                    (tenant, self.namespace, validated),
                )
                row = self._row(cur)
                if row is None:
                    return None
                return _row_record(
                    row,
                    record_id=validated,
                    prefix=self.prefix,
                    require_encryption=self._require_encryption,
                )

    def list(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        return self._list_namespace(self.namespace, limit)

    def list_archived(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        return self._list_namespace(_archive_namespace(self.namespace), limit)

    def _list_namespace(self, namespace: str, limit: int | None) -> list[dict[str, Any]]:
        tenant = self._tenant_key()
        bounded = None if limit is None else _list_limit(limit)
        with self._operation("list"):
            with self._transaction(tenant) as cur:
                statement = (
                    "SELECT record_id, revision, record_json, created_at, updated_at "
                    "FROM governed_records WHERE tenant_id=%s AND namespace=%s "
                    "ORDER BY created_at DESC, record_id"
                )
                parameters: tuple[object, ...] = (tenant, namespace)
                if bounded is not None:
                    statement += " LIMIT %s"
                    parameters += (bounded,)
                cur.execute(statement, parameters)
                rows = cur.fetchall()
            return [
                _row_record(
                    (row[1], row[2], row[3], row[4]),
                    record_id=str(row[0]),
                    prefix=self.prefix,
                    require_encryption=self._require_encryption,
                )
                for row in rows
            ]

    def iter_record_ids(
        self,
        *,
        start_after: str = "",
        limit: int = 100,
    ) -> Iterator[tuple[str, str]]:
        bounded = max(0, min(10_000, int(limit)))
        if bounded == 0:
            return
        cursor = str(start_after or "")
        tenant = self._tenant_key()
        with self._operation("scan"):
            with self._transaction(tenant) as cur:
                cur.execute(
                    "SELECT record_id FROM governed_records "
                    "WHERE tenant_id=%s AND namespace=%s "
                    "ORDER BY (record_id <= %s), record_id LIMIT %s",
                    (tenant, self.namespace, cursor, bounded),
                )
                record_ids = [str(row[0]) for row in cur.fetchall()]
        for record_id in record_ids:
            yield record_id, _valid_record_id(record_id, self.prefix)

    def update(
        self,
        record_id: str,
        mutate: Callable[[dict[str, Any]], None],
        *,
        expected_revision: int | None = None,
        metadata_only: bool = False,
        fence: GovernedMutationFence | None = None,
        effect_guard: Callable[[], None] | None = None,
    ) -> dict[str, Any] | None:
        try:
            validated = _valid_record_id(record_id, self.prefix)
        except ValueError:
            return None
        expected = _expected_revision(expected_revision)
        tenant = self._tenant_key()
        with self._operation("update"):
            with self._transaction(tenant) as cur:
                self._enforce_mutation_fence(cur, tenant, validated, fence)
                row = self._select_for_update(cur, tenant, validated)
                if row is None:
                    return None
                current = _row_record(
                    row,
                    record_id=validated,
                    prefix=self.prefix,
                    require_encryption=self._require_encryption,
                )
                current_revision = _RecordStore._revision(current)
                if expected is not None and current_revision != expected:
                    raise RecordConflict(
                        "governed record changed "
                        f"(expected revision {expected}, found {current_revision})"
                    )
                if effect_guard is not None:
                    effect_guard()
                updated = dict(current)
                mutate(updated)
                if updated.get("id") != validated:
                    raise _GovernedRecordValidationError(
                        "governed record identity cannot be changed"
                    )
                if updated == current:
                    return current
                saved = _prepared_record(
                    updated,
                    current,
                    bump_revision=not metadata_only,
                )
                stored = _encode_record(
                    saved,
                    require_encryption=self._require_encryption,
                )
                if effect_guard is not None:
                    effect_guard()
                cur.execute(
                    "UPDATE governed_records SET revision=%s, record_json=%s, "
                    "created_at=%s, updated_at=%s WHERE tenant_id=%s "
                    "AND namespace=%s AND record_id=%s AND revision=%s",
                    (
                        saved["revision"],
                        stored,
                        float(saved["created_at"]),
                        float(saved["updated_at"]),
                        tenant,
                        self.namespace,
                        validated,
                        current_revision,
                    ),
                )
                if cur.rowcount != 1:
                    raise RecordConflict("governed record changed during update")
                if self._lookup is not None:
                    self._lookup.replace(cur, tenant, validated, saved)
                if effect_guard is not None:
                    effect_guard()
                return saved

    def delete(self, record_id: str, *, expected_revision: int) -> bool:
        """Physically remove one fully delivered retained record under CAS."""

        try:
            validated = _valid_record_id(record_id, self.prefix)
        except ValueError:
            return False
        expected = _expected_revision(expected_revision)
        if expected is None:
            raise ValueError("expected_revision is required for governed deletion")
        tenant = self._tenant_key()
        with self._operation("delete"):
            with self._transaction(tenant) as cur:
                namespace = self.namespace
                if self._lookup is not None:
                    row = self._select_for_update(cur, tenant, validated)
                else:
                    # Lock either location in one query: a concurrent restore
                    # may move the row while we wait for its lock. Both its old
                    # and new location must still match the locking predicate.
                    cur.execute(
                        "SELECT namespace, revision, record_json, created_at, updated_at "
                        "FROM governed_records WHERE tenant_id=%s AND namespace IN (%s, %s) "
                        "AND record_id=%s "
                        "ORDER BY CASE WHEN namespace=%s THEN 0 ELSE 1 END LIMIT 1 FOR UPDATE",
                        (tenant, namespace, _archive_namespace(namespace), validated, namespace),
                    )
                    located = self._row(cur)
                    row = None
                    if located is not None:
                        if not isinstance(located, (tuple, list)) or len(located) != 5:
                            raise PrivacyStateError("governed record row has an invalid shape")
                        namespace, *row = located
                if row is None:
                    return False
                current = _row_record(
                    row,
                    record_id=validated,
                    prefix=self.prefix,
                    require_encryption=self._require_encryption,
                )
                revision = _RecordStore._revision(current)
                if revision != expected:
                    raise RecordConflict(
                        "governed record changed "
                        f"(expected revision {expected}, found {revision})"
                    )
                if _validated_audit_queue(current):
                    raise AuditOutboxError(
                        "governed record cannot be deleted with pending audit receipts"
                    )
                cur.execute(
                    "DELETE FROM governed_records WHERE tenant_id=%s "
                    "AND namespace=%s AND record_id=%s AND revision=%s",
                    (tenant, namespace, validated, revision),
                )
                if cur.rowcount != 1:
                    raise RecordConflict("governed record changed during delete")
                if self._lookup is not None:
                    self._lookup.replace(cur, tenant, validated, None)
                return True

    def load_archived(self, record_id: str) -> dict[str, Any] | None:
        try:
            validated = _valid_record_id(record_id, self.prefix)
        except ValueError:
            return None
        tenant = self._tenant_key()
        with self._operation("load"):
            with self._transaction(tenant) as cur:
                cur.execute(
                    "SELECT revision, record_json, created_at, updated_at "
                    "FROM governed_records WHERE tenant_id=%s AND namespace=%s "
                    "AND record_id=%s",
                    (tenant, _archive_namespace(self.namespace), validated),
                )
                row = self._row(cur)
                return None if row is None else _row_record(
                    row, record_id=validated, prefix=self.prefix,
                    require_encryption=self._require_encryption,
                )

    def _move(self, cur, tenant: str, record_id: str, source: str, target: str,
              revision: int | None = None) -> bool:
        sql = ("UPDATE governed_records SET namespace=%s WHERE tenant_id=%s AND namespace=%s "
               "AND record_id=%s")
        values: list[Any] = [target, tenant, source, record_id]
        if revision is not None:
            sql += " AND revision=%s"
            values.append(revision)
        sql += (" AND NOT EXISTS (SELECT 1 FROM governed_records WHERE tenant_id=%s "
                "AND namespace=%s AND record_id=%s)")
        values += [tenant, target, record_id]
        cur.execute(sql, tuple(values))
        return cur.rowcount == 1

    def archive(self, record_id: str, *, expected_revision: int) -> bool:
        """Move one delivered record, unchanged, out of the capped namespace."""
        validated = _valid_record_id(record_id, self.prefix)
        tenant = self._tenant_key()
        with self._operation("archive"):
            with self._transaction(tenant) as cur:
                row = self._select_for_update(cur, tenant, validated)
                if row is None:
                    return False
                current = _row_record(row, record_id=validated, prefix=self.prefix,
                                      require_encryption=self._require_encryption)
                if (_RecordStore._revision(current) != expected_revision
                        or _validated_audit_queue(current)):
                    return False
                return self._move(cur, tenant, validated, self.namespace,
                                  _archive_namespace(self.namespace), expected_revision)

    def restore(self, record_id: str) -> bool:
        """Move an archived record back so it can change again."""
        try:
            validated = _valid_record_id(record_id, self.prefix)
        except ValueError:
            return False
        tenant = self._tenant_key()
        with self._operation("restore"):
            with self._transaction(tenant) as cur:
                return self._move(cur, tenant, validated,
                                  _archive_namespace(self.namespace), self.namespace)

    def lookup(self, digest):
        if self._lookup is None:
            raise RecordLookupUnavailable("record lookup is not configured")
        with self._operation("lookup"), self._transaction(self._tenant_key()) as cur:
            result = self._lookup.lookup(cur, self._tenant_key(), digest)
        # Commit bounded migration progress before reporting not-ready.
        if isinstance(result, RecordLookupUnavailable):
            raise result
        return result

    def maintain_lookup(self, *, limit=100, rebuild=False):
        if self._lookup is None:
            raise RecordLookupUnavailable("record lookup is not configured")
        with self._operation("maintain lookup"), self._transaction(self._tenant_key()) as cur:
            return self._lookup.advance(cur, self._tenant_key(), limit=limit, rebuild=rebuild)


@dataclass(frozen=True)
class _BackendSelection:
    kind: str
    dsn: str
    shared_required: bool
    pool_size: int = 0
    pool_timeout_seconds: float = 5
    pool_min_size: int = 1


@dataclass(frozen=True)
class _BackendAuthorityToken:
    """Non-secret identity of one deployment-selected persistence plane."""

    kind: str
    dsn_sha256: str
    shared_required: bool
    pool_size: int = 0
    pool_timeout_seconds: float = 5


def _backend_authority_token(selection: _BackendSelection) -> _BackendAuthorityToken:
    digest = (
        hashlib.sha256(selection.dsn.encode("utf-8")).hexdigest()
        if selection.dsn
        else ""
    )
    return _BackendAuthorityToken(
        kind=selection.kind,
        dsn_sha256=digest,
        shared_required=selection.shared_required,
        pool_size=selection.pool_size,
        pool_timeout_seconds=selection.pool_timeout_seconds,
    )


def _backend_authority_matches(
    expected: _BackendAuthorityToken,
    current: _BackendAuthorityToken,
) -> bool:
    return (
        expected.kind == current.kind
        and hmac.compare_digest(expected.dsn_sha256, current.dsn_sha256)
        and expected.shared_required is current.shared_required
        and expected.pool_size == current.pool_size
        and expected.pool_timeout_seconds == current.pool_timeout_seconds
    )


_PROCESS_AUTHORITY_LOCK = threading.Lock()
_PROCESS_AUTHORITY_TOKEN: _BackendAuthorityToken | None = None


def _admit_process_authority_selection(selection: _BackendSelection) -> None:
    """Atomically pin the first resolved deployment authority for this process."""
    global _PROCESS_AUTHORITY_TOKEN

    current = _backend_authority_token(selection)
    with _PROCESS_AUTHORITY_LOCK:
        expected = _PROCESS_AUTHORITY_TOKEN
        if expected is None:
            _PROCESS_AUTHORITY_TOKEN = current
            return
        if not _backend_authority_matches(expected, current):
            raise GovernedRecordBackendError(
                "governed-record deployment authority changed after process admission"
            )


def _reset_process_authority_pin_for_testing() -> None:
    """Clear process-lifetime authority admission state for isolated tests only."""
    global _PROCESS_AUTHORITY_TOKEN

    with _PROCESS_AUTHORITY_LOCK:
        _PROCESS_AUTHORITY_TOKEN = None


def _replica_count() -> int:
    raw: object = os.environ.get("MAVERICK_REPLICA_COUNT", "1")
    if isinstance(raw, bool):
        raise GovernedRecordBackendError("replica count must be a positive integer")
    try:
        parsed = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError) as exc:
        raise GovernedRecordBackendError(
            "replica count must be a positive integer"
        ) from exc
    if parsed < 1 or str(raw).strip() != str(parsed):
        raise GovernedRecordBackendError("replica count must be a positive integer")
    return parsed


def _selection() -> _BackendSelection:
    try:
        from .config import (
            governed_records_config_source_errors,
            load_governed_records_config,
        )

        config = load_governed_records_config()
        source_errors = governed_records_config_source_errors()
    except Exception as exc:
        raise GovernedRecordBackendError(
            "governed-record deployment policy is unavailable"
        ) from exc
    if not isinstance(config, Mapping):
        raise GovernedRecordBackendError("governed-record deployment policy is invalid")
    section = config.get("governed_records") or {}
    world = config.get("world_model") or {}
    if not isinstance(section, Mapping) or not isinstance(world, Mapping):
        raise GovernedRecordBackendError("governed-record deployment policy is invalid")
    configured = (
        os.environ.get("MAVERICK_GOVERNED_RECORDS_BACKEND")
        or section.get("backend")
        or "auto"
    )
    kind = str(configured).strip().lower()
    if kind not in _BACKENDS:
        raise GovernedRecordBackendError(
            "governed-record backend must be auto, local, or postgres"
        )
    from .enterprise import deployment_enterprise_enabled

    enterprise = deployment_enterprise_enabled(
        config=config,
        source_errors=source_errors,
    )
    replicas = _replica_count()
    shared_required = enterprise or replicas > 1
    world_kind = str(
        os.environ.get("MAVERICK_WORLD_BACKEND")
        or world.get("backend")
        or "sqlite"
    ).strip().lower()
    dsn = str(
        os.environ.get("MAVERICK_PG_DSN")
        or world.get("dsn")
        or ""
    ).strip()
    if kind == "local":
        if shared_required:
            raise GovernedRecordBackendError(
                "enterprise and multi-replica governed records require Postgres"
            )
        return _BackendSelection("local", "", False)
    select_postgres = kind == "postgres" or world_kind == "postgres"
    if kind == "auto" and shared_required and dsn:
        select_postgres = True
    if select_postgres:
        if not dsn:
            raise GovernedRecordBackendError(
                "Postgres governed records require a configured DSN"
            )
        try:
            size, timeout = validate_pool_settings(
                section.get("pool_size", 0), section.get("pool_timeout_seconds", 5),
            )
            min_size = validate_pool_min_size(section.get("pool_min_size", 1), size)
        except ValueError as exc:
            raise GovernedRecordBackendError(str(exc)) from None
        return _BackendSelection("postgres", dsn, shared_required, size, timeout,
                                 pool_min_size=min_size)
    if shared_required:
        raise GovernedRecordBackendError(
            "enterprise and multi-replica governed records require Postgres"
        )
    return _BackendSelection("local", "", False)


def configured_governed_records_backend() -> str:
    """Return the configured governed-record authority backend.

    This selection seam does not open a database or resolve a tenant. Once it
    admits either local or Postgres, however, that complete non-secret authority
    identity is process-sticky: a backend, DSN, or shared-enforcement change
    requires a process restart rather than allowing a later adapter call to
    choose a different plane. :class:`GovernedRecordStore` still performs its
    stricter first-I/O tenant, encryption, schema, and cutover checks.
    """
    try:
        selection = _selection()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        with _PROCESS_AUTHORITY_LOCK:
            admitted = _PROCESS_AUTHORITY_TOKEN is not None
        if admitted:
            raise GovernedRecordBackendError(
                "governed-record deployment authority cannot be revalidated"
            ) from None
        raise
    _admit_process_authority_selection(selection)
    return selection.kind


class GovernedRecordStore:
    """A product-neutral governed record collection.

    ``record_type`` is emitted into the audit chain and should remain stable
    across releases.  Callers own their record schema and lifecycle rules; this
    class owns only durability, CAS, and audit delivery.
    """

    def __init__(
        self,
        namespace: str,
        prefix: str,
        record_type: str,
        *,
        event_kind: str = _EVENT_KIND,
        backend: GovernedRecordBackend | None = None,
        required_backend: str | None = None,
        authority_scope: str = "tenant",
        lookup_spec: RecordLookupSpec | None = None,
        archive_when_full: bool = True,
    ) -> None:
        self.namespace = _required(namespace, "namespace", 128)
        # A store that manages its own capacity (its own retention or a
        # deliberate "remove one first" refusal) opts out of archiving.
        self.archive_when_full = bool(archive_when_full)
        self.prefix = _required(prefix, "prefix", 16)
        self.record_type = _required(record_type, "record_type", 64)
        self.event_kind = _required(event_kind, "event_kind", 64)
        scope = str(authority_scope or "").strip().lower()
        if scope not in _AUTHORITY_SCOPES:
            raise ValueError(
                "authority_scope must be tenant or deployment_global"
            )
        self.authority_scope = scope
        self.lookup_spec = lookup_spec
        self._local_backend = LocalGovernedRecordBackend(
            self.namespace,
            self.prefix,
            authority_scope=self.authority_scope,
            lookup_spec=lookup_spec,
        )
        self._backend_override = backend
        required = (
            None
            if required_backend is None
            else str(required_backend).strip().lower()
        )
        if required is not None and required not in _REQUIRED_BACKENDS:
            raise ValueError("required_backend must be local, postgres, or None")
        self._required_backend = required
        self._authority_token: _BackendAuthorityToken | None = None
        self._authority_lock = threading.Lock()
        self._postgres_backend: PostgresGovernedRecordBackend | None = None
        self._postgres_key = ""
        # Where the next ``retry_pending`` pass resumes, so a bounded pass
        # rotates through the whole store instead of the first ``limit`` ids.
        self._retry_cursor = ""

    def _assert_backend_authority(self, selection: _BackendSelection) -> None:
        """Pin selector-backed stores before any persistence-plane I/O.

        Explicit backend objects are already concrete pins, but mandatory
        authorities still require their declared ``kind`` and sharing posture
        to match the deployment selector exactly.
        """
        required = self._required_backend
        if required is None:
            return
        # ``required_backend`` is a deployment-policy constraint, not merely a
        # property check on an injected adapter.  An explicit shared test or
        # integration backend must still agree with the process-selected plane;
        # otherwise a caller could select local in configuration while writing
        # a supposedly mandatory authority through an unrelated shared object.
        if selection.kind != required:
            raise GovernedRecordBackendError(
                "governed-record deployment authority changed after store selection"
            )
        override = self._backend_override
        if override is not None:
            override_kind = str(getattr(override, "kind", "")).strip().lower()
            if override_kind != required:
                raise GovernedRecordBackendError(
                    "governed-record explicit backend does not match required authority"
                )
            if required == "postgres" and not bool(override.shared):
                raise GovernedRecordBackendError(
                    "governed-record authority requires a shared backend"
                )
            if required == "local" and bool(override.shared):
                raise GovernedRecordBackendError(
                    "governed-record authority requires a local backend"
                )
            if (
                self.authority_scope == "deployment_global"
                and getattr(override, "authority_scope", None)
                != "deployment_global"
            ):
                raise GovernedRecordBackendError(
                    "deployment-global governed authority requires a "
                    "deployment-global backend"
                )
            return
        current = _backend_authority_token(selection)
        with self._authority_lock:
            expected = self._authority_token
            if expected is None:
                self._authority_token = current
                return
            if not _backend_authority_matches(expected, current):
                raise GovernedRecordBackendError(
                    "governed-record deployment authority changed after store selection"
                )

    @staticmethod
    def _require_bound_tenant(shared_required: bool) -> None:
        if not shared_required:
            return
        from .paths import current_tenant_id_strict

        if current_tenant_id_strict() is None:
            raise GovernedRecordBackendError(
                "enterprise and multi-replica governed records require an "
                "active tenant"
            )

    @staticmethod
    def _require_application_encryption(
        required: bool,
        *,
        require_shared_key_identity: bool,
    ) -> None:
        if not required:
            return
        from .crypto_at_rest import (
            EncryptionUnavailable,
            at_rest_enabled,
            require_shared_deployment_key_identity,
        )

        if not at_rest_enabled():
            raise GovernedRecordBackendError(
                "shared governed records require application at-rest encryption"
            )
        if require_shared_key_identity:
            try:
                require_shared_deployment_key_identity()
            except EncryptionUnavailable as exc:
                raise GovernedRecordBackendError(
                    "shared governed-record encryption key identity is unavailable"
                ) from exc

    def _local_records_exist(self) -> bool:
        return next(
            iter(self._local_backend.iter_record_ids(limit=1)),
            None,
        ) is not None

    def _backend(self) -> GovernedRecordBackend:
        try:
            selection = _selection()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            with _PROCESS_AUTHORITY_LOCK:
                process_admitted = _PROCESS_AUTHORITY_TOKEN is not None
            if self._required_backend is not None or process_admitted:
                raise GovernedRecordBackendError(
                    "governed-record deployment authority cannot be revalidated"
                ) from None
            raise
        # The first successfully resolved selector identity wins the process.
        # Admit it before tenant/encryption checks, backend construction, legacy
        # scans, or record I/O so concurrent local/Postgres first use cannot
        # touch two persistence planes.
        _admit_process_authority_selection(selection)
        self._assert_backend_authority(selection)
        if self.authority_scope != "deployment_global":
            self._require_bound_tenant(selection.shared_required)
        if self._backend_override is not None:
            selected = self._backend_override
            if selection.shared_required and not bool(selected.shared):
                raise GovernedRecordBackendError(
                    "enterprise and multi-replica governed records require a "
                    "shared backend"
                )
        elif selection.kind == "local":
            selected = self._local_backend
        else:
            # Cache by a digest so diagnostics/reprs never retain an additional
            # plaintext copy of the credential-bearing DSN.
            key = hashlib.sha256(selection.dsn.encode("utf-8")).hexdigest()
            if self._postgres_backend is None or self._postgres_key != key:
                self._postgres_backend = PostgresGovernedRecordBackend(
                    self.namespace,
                    self.prefix,
                    dsn=selection.dsn,
                    require_bound_tenant=(
                        selection.shared_required
                        and self.authority_scope != "deployment_global"
                    ),
                    require_encryption=True,
                    require_shared_key_identity=True,
                    authority_scope=self.authority_scope,
                    pool_size=selection.pool_size,
                    pool_timeout_seconds=selection.pool_timeout_seconds,
                    lookup_spec=self.lookup_spec,
                    pool_min_size=selection.pool_min_size,
                )
                self._postgres_key = key
            selected = self._postgres_backend
        self._require_application_encryption(
            selection.shared_required or selected.kind == "postgres",
            require_shared_key_identity=(selected.kind == "postgres"),
        )
        if selected.shared and self._local_records_exist():
            raise GovernedRecordBackendError(
                "local governed records exist for this tenant and namespace; "
                "migrate/import them into Postgres and archive the local copies "
                "before selecting the shared backend"
            )
        return selected

    def lookup(self, digest: str) -> dict[str, Any] | None:
        backend = self._lookup_backend()
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("record lookup digest is invalid")
        return backend.lookup(digest)

    def maintain_lookup(self, *, limit: int = 100, rebuild: bool = False):
        return self._lookup_backend().maintain_lookup(limit=limit, rebuild=rebuild)

    def _lookup_backend(self):
        backend = self._backend()
        if self.lookup_spec is None or getattr(backend, "lookup_spec", None) != self.lookup_spec:
            raise RecordLookupUnavailable("record lookup backend contract is unavailable")
        return backend

    @property
    def backend_kind(self) -> str:
        """Resolved backend name, enforcing the same admission checks as I/O."""
        return self._backend().kind

    def authoritative_time(self) -> float:
        """Return the selected authority's clock for persisted claim leases."""
        backend = self._backend()
        clock = getattr(backend, "authoritative_time", None)
        if not callable(clock):
            if backend.shared:
                raise GovernedRecordBackendError(
                    "shared governed-record backend has no authoritative clock"
                )
            return time.time()
        try:
            value = float(clock())
        except GovernedRecordBackendError:
            raise
        except Exception as exc:
            raise GovernedRecordBackendError(
                "governed-record authoritative time is unavailable"
            ) from exc
        if not math.isfinite(value) or value <= 0:
            raise GovernedRecordBackendError(
                "governed-record authoritative time is invalid"
            )
        return value

    def new_id(self) -> str:
        return self._backend().new_id()

    def _flush(
        self,
        record: dict[str, Any],
        *,
        backend: GovernedRecordBackend | None = None,
    ) -> dict[str, Any]:
        """Attempt bounded outbox delivery without changing logical revision."""
        record_id = str(record.get("id") or "")
        outcome: dict[str, Any] | None = None

        def _deliver(current: dict[str, Any]) -> None:
            nonlocal outcome
            queue = _validated_audit_queue(current)
            if not queue:
                outcome = current
                return
            remaining = list(queue)
            for pending in queue[:_MAX_DELIVERIES_PER_FLUSH]:
                try:
                    from . import audit

                    if self.authority_scope == "deployment_global":
                        audit_record = audit.record_global
                        audit_tenant = ""
                    else:
                        from .paths import current_tenant_id_strict

                        audit_record = audit.record
                        audit_tenant = current_tenant_id_strict() or ""
                    ok = audit_record(
                        self.event_kind,
                        agent=str(pending.get("actor") or "system"),
                        event_id=str(pending.get("event_id") or ""),
                        occurred_at=float(pending.get("prepared_at") or 0.0),
                        actor=str(pending.get("actor") or "system"),
                        tenant=audit_tenant,
                        record_type=self.record_type,
                        action=str(pending.get("action") or ""),
                        record_id=record_id,
                        revision=int(
                            pending.get("revision")
                            or _RecordStore._revision(current)
                        ),
                        status=str(
                            pending.get("status")
                            or current.get("status")
                            or ""
                        ),
                        record_sha256=str(pending.get("record_sha256") or ""),
                    )
                    # Only the writer's explicit acknowledgement confirms
                    # delivery; malformed truthy results must retain the outbox.
                    if ok is not True:
                        raise RuntimeError("audit writer refused governed event")
                except Exception as exc:  # noqa: BLE001 - receipt stays durable
                    log.error(
                        "governed audit pending for %s/%s (%s)",
                        self.record_type,
                        pending.get("action"),
                        type(exc).__name__,
                    )
                    break
                remaining.pop(0)
            if remaining:
                current["_audit_pending"] = remaining
            else:
                current.pop("_audit_pending", None)
            outcome = current

        resolved = self._backend() if backend is None else backend
        saved = resolved.update(
            record_id,
            _deliver,
            metadata_only=True,
        )
        if saved is None:
            raise RuntimeError("governed record disappeared during audit commit")
        return saved if outcome is None else outcome

    def create(
        self,
        record: dict[str, Any],
        *,
        action: str,
        actor: str,
        fence: GovernedMutationFence | None = None,
        max_records: int | None = None,
        effect_guard: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        runtime_metrics.increment(
            "lightwork_governed_record_ops_total", op="create",
            namespace=self.namespace,
            help_text="Governed record store operations",
        )
        actor_name = _required(actor, "actor", 4096)
        action_name = _required(action, "action", 64)
        value = dict(record)
        reserved = sorted(_RESERVED_FIELDS.intersection(value))
        if reserved:
            raise ValueError(
                "governed record contains store-reserved fields: "
                + ", ".join(reserved)
            )
        now = time.time()
        value["created_at"] = now
        value["updated_at"] = now
        _queue_audit(value, action_name, actor_name)
        maximum = (
            None
            if max_records is None
            else _capacity_limit(max_records)
        )
        backend = self._backend()
        guarded = _local_effect_guard(backend, effect_guard)
        archiving = maximum is not None and self._archivable(backend)
        if archiving:
            # An archived record keeps its id: creating it again conflicts as before.
            backend.restore(str(value.get("id") or ""))
        try:
            saved = self._save_new(backend, value, fence, maximum, guarded)
        except GovernedRecordCapacityError:
            if not archiving or not self._archive_oldest(backend, maximum):
                raise
            saved = self._save_new(backend, value, fence, maximum, guarded)
        return self._flush(
            saved,
            backend=backend,
        )

    @staticmethod
    def _save_new(backend, value, fence, maximum, guarded):
        if fence is None and maximum is None:
            saved = backend.save(value, expected_revision=0, **guarded)
        elif fence is not None and maximum is None:
            saved = backend.save(
                value,
                expected_revision=0,
                fence=fence,
                **guarded,
            )
        elif fence is None:
            saved = backend.save(
                value,
                expected_revision=0,
                max_records=maximum,
                **guarded,
            )
        else:
            saved = backend.save(
                value,
                expected_revision=0,
                fence=fence,
                max_records=maximum,
                **guarded,
            )
        return saved

    def _archivable(self, backend) -> bool:
        return (self.archive_when_full and self.lookup_spec is None
                and callable(getattr(backend, "archive", None)))

    def _archive_oldest(self, backend, maximum: int) -> int:
        """Make room in a full namespace by archiving its oldest delivered records.

        Only settled records move (see ``_SETTLED_STATUSES``). Archived records
        are kept unchanged and stay readable, updatable and deletable by id;
        they only stop counting against the cap. Each move is first an
        audited update, so a record whose activity record is not delivered
        stays where it is. Returns how many records moved."""
        rows = [row for row in backend.list(limit=maximum)
                if not row.get("_audit_pending") and _settled(row)]
        rows.sort(key=lambda row: (float(row.get("updated_at") or 0), str(row.get("id"))))
        moved = 0
        for row in rows[:max(1, maximum // 100)]:
            try:
                marked = self.update(row["id"], lambda current: None, expected_revision=row["revision"],
                                     action="governed_record_archived", actor="governed-record retention")
            except RecordConflict:
                continue
            if marked and not marked.get("_audit_pending") and backend.archive(
                    marked["id"], expected_revision=marked["revision"]):
                moved += 1
        return moved

    def update(
        self,
        record_id: str,
        mutate: Callable[[dict[str, Any]], None],
        *,
        expected_revision: int,
        action: str,
        actor: str,
        fence: GovernedMutationFence | None = None,
        effect_guard: Callable[[], None] | None = None,
    ) -> dict[str, Any] | None:
        runtime_metrics.increment(
            "lightwork_governed_record_ops_total", op="update",
            namespace=self.namespace,
            help_text="Governed record store operations",
        )
        actor_name = _required(actor, "actor", 4096)
        action_name = _required(action, "action", 64)
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 0
        ):
            raise ValueError("expected_revision must be a non-negative integer")

        def _mutate(current: dict[str, Any]) -> None:
            immutable_id = current.get("id")
            mutate(current)
            if current.get("id") != immutable_id:
                raise ValueError("governed record identity cannot be changed")
            current["updated_at"] = time.time()
            _queue_audit(current, action_name, actor_name)

        backend = self._backend()
        guarded = _local_effect_guard(backend, effect_guard)
        if fence is None:
            saved = backend.update(
                str(record_id or ""),
                _mutate,
                expected_revision=expected_revision,
                **guarded,
            )
        else:
            saved = backend.update(
                str(record_id or ""),
                _mutate,
                expected_revision=expected_revision,
                fence=fence,
                **guarded,
            )
        if saved is None:
            if not self._archivable(backend):
                return None
            archived = backend.load_archived(str(record_id or ""))
            if (archived is not None and expected_revision is not None
                    and archived.get("revision") != expected_revision):
                # A stale update must not bring the record back as a side effect.
                raise RecordConflict(
                    "governed record changed "
                    f"(expected revision {expected_revision}, found {archived.get('revision')})"
                )
            if not backend.restore(str(record_id or "")):
                return None
            return self.update(record_id, mutate, expected_revision=expected_revision, action=action,
                               actor=actor, fence=fence, effect_guard=effect_guard)
        return self._flush(saved, backend=backend)

    def get(self, record_id: str) -> dict[str, Any] | None:
        runtime_metrics.increment(
            "lightwork_governed_record_ops_total", op="get",
            namespace=self.namespace,
            help_text="Governed record store operations",
        )
        backend = self._backend()
        found = backend.load(record_id)
        if found is None and self._archivable(backend):
            return backend.load_archived(record_id)
        return found

    def list(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        runtime_metrics.increment(
            "lightwork_governed_record_ops_total", op="list",
            namespace=self.namespace,
            help_text="Governed record store operations",
        )
        backend = self._backend()
        return backend.list() if limit is None else backend.list(limit=limit)

    def list_archived(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        """Records this namespace archived when it was full (not in :meth:`list`).

        Callers that must see every record (personal-data erasure) read these
        too; ordinary views list only the active namespace."""
        backend = self._backend()
        listed = getattr(backend, "list_archived", None)
        if self.lookup_spec is not None or not callable(listed):
            return []
        return listed() if limit is None else listed(limit=limit)

    def delete(self, record_id: str, *, expected_revision: int) -> bool:
        """Delete a retention-expired record only after its audit outbox cleared.

        Product services must first commit and deliver their own digest-only
        tombstone/audit event.  This primitive deliberately adds no event of its
        own because an event queued in the record being removed could be lost.
        """

        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision must be a positive integer")
        backend = self._backend()
        delete = getattr(backend, "delete", None)
        if not callable(delete):
            raise GovernedRecordBackendError(
                "governed-record backend does not support retained deletion"
            )
        record_id = str(record_id or "")
        return bool(delete(record_id, expected_revision=expected_revision))

    def count(self, *, maximum: int = 100_000) -> int:
        """Records in the namespace, WITHOUT reading any record bodies.

        One bounded id-scan window (the iterator's rotating cursor makes
        multi-page counting ambiguous, so this is a single window and
        ``maximum`` is the ceiling; the Postgres backend scans at most 10,000
        ids per window, so it cannot count past that). Capacity checks and
        posture tiles need the number, not thousands of parsed JSON bodies.
        """

        return sum(
            1 for _ in self._backend().iter_record_ids(
                limit=max(0, int(maximum)))
        )

    def iter_record_ids(
        self,
        *,
        start_after: str = "",
        limit: int = 100,
    ) -> Iterator[tuple[str, str]]:
        """Yield a bounded rotating window of backend cursor and record ids.

        This exposes the narrow scan primitive already required of every
        governed-record backend without performing any record reads.  Callers
        must persist the first tuple value as the opaque backend cursor and use
        the second value with :meth:`get`.
        """

        return self._backend().iter_record_ids(
            start_after=str(start_after or ""),
            limit=limit,
        )

    def retry_pending(self, *, limit: int = 100) -> int:
        """Retry a bounded set of stable audit receipts. Each pass resumes
        after the last record the previous pass scanned."""
        cleared = 0
        backend = self._backend()
        for cursor, record_id in backend.iter_record_ids(
                start_after=self._retry_cursor, limit=max(0, int(limit))):
            self._retry_cursor = cursor
            before = backend.load(record_id)
            if not before or not before.get("_audit_pending"):
                continue
            after = self._flush(before, backend=backend)
            if not after.get("_audit_pending"):
                cleared += 1
        return cleared


__all__ = [
    "configured_governed_records_backend",
    "GovernedRecordBackend",
    "GovernedRecordBackendError",
    "GovernedRecordCapacityError",
    "GovernedMutationFence",
    "GovernedRecordStore",
    "LocalGovernedRecordBackend",
    "PostgresGovernedRecordBackend",
]
