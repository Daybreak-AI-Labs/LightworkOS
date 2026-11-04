"""Stock, fail-closed deployment composition for packaged governance agents.

The core :mod:`maverick.governance_agents` module intentionally exposes
authority seams instead of guessing how a dashboard deployment stores
identities, resolves source evidence, enrolls adapters, or custodies execution
tokens.  This module supplies a conservative local reference composition for
those seams:

* every core store and composition database is tenant-local;
* policy approvers come from the tenant RBAC roster and exclude the publisher;
* raw context is resolved from registered source authorities or a bounded,
  in-memory server projection and is never copied into this module's SQLite;
* analysis is deterministic, offline, non-legal, and explicitly incomplete;
* execution creates only an internal governed intent -- external writes remain
  disabled -- and returns a custody-key HMAC receipt;
* plaintext execution tokens are sealed with Fernet under a private, rotatable
  tenant keyring; and
* binding rotation/revocation, token recovery/revocation, reconciliation, and
  operational readiness are explicit maintenance operations.

Installing the composition is lazy.  It does not read tenant configuration,
RBAC state, custody material, or SQLite until an operation/readiness probe is
actually attempted.  Live providers, licensed content, customer acceptance,
and external mutation authority are deliberately not implied.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from maverick import governance_agents as agents
from maverick.browser_auth_vault import (
    decrypt_entry,
    encrypt_entry,
    generate_key,
)
from maverick.file_lock import (
    atomic_create_bytes,
    atomic_read_bytes,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from maverick.paths import canonical_tenant_id, data_dir
from maverick.sqlite_closing import ClosingConnection

_KEYRING_SCHEMA = "lightwork.governance-agent.reference-keyring.v1"
_INTENT_SCHEMA = "lightwork.governance-agent.internal-intent.v1"
_READINESS_SCHEMA = "lightwork.governance-agent.composition-readiness.v1"
_STATE_SCHEMA_VERSION = 1
_MAX_KEYRING_KEYS = 3
_MAX_RBAC_MEMBERS = 10_000
_MAX_PROJECTION_ITEMS = 10_000
_MAX_PROJECTION_BYTES = 16 * 1024 * 1024
_MAX_AUTHORITY_LIFETIME_SECONDS = 366 * 24 * 60 * 60
_MIN_AUTHORITY_LIFETIME_SECONDS = 60 * 60
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")

_REFERENCE_BEHAVIOR: Mapping[str, tuple[str, str, tuple[str, ...]]] = {
    "breach_response": (
        "incident_scope_unclear",
        "create_incident_task",
        ("human_context_required", "legal_review_required"),
    ),
    "privacy_risk_assessment": (
        "purpose_not_pinned",
        "open_dpia_review",
        ("human_context_required", "legal_review_required"),
    ),
    "program_copilot": (
        "status_indeterminate",
        "create_evidence_request",
        ("calibration_unverified", "human_context_required"),
    ),
    "knowledgebase_governance": (
        "review_required",
        "request_citation",
        ("content_corpus_unavailable", "human_context_required"),
    ),
    "third_party_risk": (
        "criticality_unresolved",
        "request_due_diligence",
        ("human_context_required", "live_feed_unavailable"),
    ),
}


class GovernanceAgentsCompositionError(agents.GovernanceAgentConfigError):
    """The stock composition cannot establish an exact safe authority."""


def _canonical(value: object, *, maximum: int = 2 * 1024 * 1024) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise GovernanceAgentsCompositionError(
            "governance-agent composition material is not canonical"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise GovernanceAgentsCompositionError(
            "governance-agent composition material exceeds its byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise GovernanceAgentsCompositionError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise GovernanceAgentsCompositionError(f"{label} must be a SHA-256 digest")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise GovernanceAgentsCompositionError(f"{label} must be a finite timestamp")
    return float(value)


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite value {value}")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=object_pairs,
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise GovernanceAgentsCompositionError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise GovernanceAgentsCompositionError(f"{label} is invalid")
    return value


def governance_agent_principal_ref(tenant_id: str, principal: str) -> str:
    """Return the same opaque principal binding used by the HTTP boundary."""

    tenant = canonical_tenant_id(tenant_id)
    if (
        not isinstance(principal, str)
        or not principal
        or principal != principal.strip()
        or len(principal.encode()) > 1_024
    ):
        raise GovernanceAgentsCompositionError("RBAC principal is invalid")
    digest = hashlib.sha256(
        f"lightwork.governance-agent.identity.v1:{tenant}:{principal}".encode()
    ).hexdigest()
    return f"ga-principal-{digest[:32]}"


@dataclass(frozen=True, slots=True)
class ReferenceBindingPolicy:
    """Bounded validity and eligible approval roles for the stock runtime."""

    authority_lifetime_seconds: int = 90 * 24 * 60 * 60
    approver_roles: tuple[str, ...] = ("admin", "operator")

    def __post_init__(self) -> None:
        if (
            isinstance(self.authority_lifetime_seconds, bool)
            or not isinstance(self.authority_lifetime_seconds, int)
            or not _MIN_AUTHORITY_LIFETIME_SECONDS
            <= self.authority_lifetime_seconds
            <= _MAX_AUTHORITY_LIFETIME_SECONDS
        ):
            raise GovernanceAgentsCompositionError(
                "reference authority lifetime is outside its bound"
            )
        if (
            not isinstance(self.approver_roles, tuple)
            or not self.approver_roles
            or tuple(sorted(set(self.approver_roles)))
            != tuple(sorted(self.approver_roles))
            or not set(self.approver_roles).issubset({"admin", "operator"})
        ):
            raise GovernanceAgentsCompositionError(
                "reference approver roles are invalid"
            )


class RoleBackedPolicyApproverAuthority:
    """Resolve policy approvers from exact tenant RBAC memberships."""

    def __init__(
        self,
        roster_resolver: Callable[[str], Mapping[str, str]],
        *,
        policy: ReferenceBindingPolicy,
    ) -> None:
        if not callable(roster_resolver):
            raise TypeError("tenant RBAC roster resolver must be callable")
        self._roster_resolver = roster_resolver
        self._policy = policy

    def _eligible(self, tenant_id: str) -> tuple[str, ...]:
        tenant = canonical_tenant_id(tenant_id)
        try:
            roster = self._roster_resolver(tenant)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise GovernanceAgentsCompositionError(
                "tenant RBAC approver authority is unavailable"
            ) from exc
        if not isinstance(roster, Mapping):
            raise GovernanceAgentsCompositionError(
                "tenant RBAC approver authority is invalid"
            )
        if len(roster) > _MAX_RBAC_MEMBERS:
            raise GovernanceAgentsCompositionError(
                "tenant RBAC approver authority exceeds its member bound"
            )
        refs: list[str] = []
        for principal, role in roster.items():
            if not isinstance(role, str) or role not in {
                "admin",
                "operator",
                "auditor",
                "viewer",
            }:
                raise GovernanceAgentsCompositionError(
                    "tenant RBAC approver authority contains an invalid role"
                )
            if role in self._policy.approver_roles:
                refs.append(governance_agent_principal_ref(tenant, principal))
        result = tuple(sorted(set(refs)))
        if len(result) != len(refs):
            raise GovernanceAgentsCompositionError(
                "tenant RBAC approver authority contains duplicate identities"
            )
        return result

    def __call__(
        self,
        tenant_id: str,
        _policy_id: str,
        _revision: int,
    ) -> tuple[str, ...]:
        return self._eligible(tenant_id)

    def bind(self, excluded_principal: str) -> Callable[[str, str, int], tuple[str, ...]]:
        excluded = _identifier(excluded_principal, "publisher principal")

        def resolve(tenant_id: str, _policy_id: str, _revision: int) -> tuple[str, ...]:
            approvers = tuple(
                item for item in self._eligible(tenant_id) if item != excluded
            )
            if len(approvers) < 2:
                raise GovernanceAgentsCompositionError(
                    "policy publication requires two tenant RBAC approvers other than the publisher"
                )
            return approvers

        return resolve


class EphemeralGovernanceContextAuthority:
    """Bounded source-authority bridge that never durably copies raw context."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        max_items: int = _MAX_PROJECTION_ITEMS,
        max_bytes: int = _MAX_PROJECTION_BYTES,
    ) -> None:
        if not callable(clock):
            raise TypeError("context clock must be callable")
        if (
            isinstance(max_items, bool)
            or not isinstance(max_items, int)
            or not 1 <= max_items <= _MAX_PROJECTION_ITEMS
            or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 1_024 <= max_bytes <= _MAX_PROJECTION_BYTES
        ):
            raise GovernanceAgentsCompositionError(
                "context projection bounds are invalid"
            )
        self._clock = clock
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._items: OrderedDict[
            tuple[str, str, str, int], agents.GovernanceContextItem
        ] = OrderedDict()
        self._bytes = 0
        self._sources: dict[
            str,
            Callable[[str, str, int], agents.GovernanceContextItem | bytes],
        ] = {}
        self._lock = threading.RLock()

    @property
    def source_kinds(self) -> tuple[str, ...]:
        with self._lock:
            projected = {key[1] for key in self._items}
            return tuple(sorted(projected | set(self._sources)))

    def source_kinds_for(self, tenant_id: str) -> tuple[str, ...]:
        """Return global registered sources plus projections for one tenant."""

        tenant = canonical_tenant_id(tenant_id)
        with self._lock:
            projected = {key[1] for key in self._items if key[0] == tenant}
            return tuple(sorted(projected | set(self._sources)))

    @property
    def projected_items(self) -> int:
        with self._lock:
            return len(self._items)

    def projected_items_for(self, tenant_id: str) -> int:
        tenant = canonical_tenant_id(tenant_id)
        with self._lock:
            return sum(1 for key in self._items if key[0] == tenant)

    def register_source(
        self,
        source_kind: str,
        resolver: Callable[[str, str, int], agents.GovernanceContextItem | bytes],
    ) -> None:
        if source_kind not in agents.SOURCE_KINDS:
            raise GovernanceAgentsCompositionError("context source kind is unsupported")
        if not callable(resolver):
            raise TypeError("context source resolver must be callable")
        with self._lock:
            if source_kind in self._sources and self._sources[source_kind] is not resolver:
                raise GovernanceAgentsCompositionError(
                    "context source authority is already registered"
                )
            self._sources[source_kind] = resolver

    def unregister_source(self, source_kind: str) -> None:
        with self._lock:
            self._sources.pop(source_kind, None)

    def publish(self, tenant_id: str, item: agents.GovernanceContextItem) -> None:
        """Publish one server-owned ephemeral projection; never expose over HTTP."""

        tenant = canonical_tenant_id(tenant_id)
        normalized = self._normalize_item(item, expected=None)
        if len(normalized.content) > self._max_bytes:
            raise GovernanceAgentsCompositionError(
                "context projection exceeds the deployment byte bound"
            )
        key = (
            tenant,
            normalized.source_kind,
            normalized.source_ref,
            normalized.source_revision,
        )
        with self._lock:
            previous = self._items.pop(key, None)
            if previous is not None:
                self._bytes -= len(previous.content)
            self._items[key] = normalized
            self._bytes += len(normalized.content)
            while len(self._items) > self._max_items or self._bytes > self._max_bytes:
                _old_key, old = self._items.popitem(last=False)
                self._bytes -= len(old.content)

    def revoke(
        self,
        tenant_id: str,
        *,
        source_kind: str,
        source_ref: str,
        source_revision: int,
    ) -> bool:
        key = (
            canonical_tenant_id(tenant_id),
            source_kind,
            source_ref,
            source_revision,
        )
        with self._lock:
            previous = self._items.pop(key, None)
            if previous is None:
                return False
            self._bytes -= len(previous.content)
            return True

    def _normalize_item(
        self,
        value: object,
        *,
        expected: Mapping[str, object] | None,
    ) -> agents.GovernanceContextItem:
        if not isinstance(value, agents.GovernanceContextItem):
            raise GovernanceAgentsCompositionError(
                "context authority returned an invalid item"
            )
        item = value
        _identifier(item.item_id, "context item_id")
        if item.source_kind not in agents.SOURCE_KINDS:
            raise GovernanceAgentsCompositionError("context source kind is unsupported")
        _identifier(item.source_ref, "context source_ref")
        if (
            isinstance(item.source_revision, bool)
            or not isinstance(item.source_revision, int)
            or not 1 <= item.source_revision <= 2_147_483_647
        ):
            raise GovernanceAgentsCompositionError("context source revision is invalid")
        _timestamp(item.collected_at, "context collected_at")
        if not isinstance(item.content, bytes) or not item.content:
            raise GovernanceAgentsCompositionError("context content is invalid")
        if expected is not None and (
            item.item_id != expected["item_id"]
            or item.source_kind != expected["source_kind"]
            or item.source_ref != expected["source_ref"]
            or item.source_revision != expected["source_revision"]
        ):
            raise GovernanceAgentsCompositionError(
                "context authority changed the requested source binding"
            )
        return item

    @staticmethod
    def _reference(value: object) -> dict[str, object]:
        if not isinstance(value, Mapping) or set(value) != {
            "item_id",
            "source_kind",
            "source_ref",
            "source_revision",
        }:
            raise GovernanceAgentsCompositionError("context reference is invalid")
        item_id = _identifier(value.get("item_id"), "context item_id")
        source_kind = value.get("source_kind")
        if source_kind not in agents.SOURCE_KINDS:
            raise GovernanceAgentsCompositionError("context source kind is unsupported")
        source_ref = _identifier(value.get("source_ref"), "context source_ref")
        revision = value.get("source_revision")
        if (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or not 1 <= revision <= 2_147_483_647
        ):
            raise GovernanceAgentsCompositionError("context source revision is invalid")
        return {
            "item_id": item_id,
            "source_kind": source_kind,
            "source_ref": source_ref,
            "source_revision": revision,
        }

    def resolve(
        self,
        tenant_id: str,
        references: Sequence[Mapping[str, object]],
        *,
        limits: agents.GovernanceAgentLimits,
    ) -> tuple[agents.GovernanceContextItem, ...]:
        tenant = canonical_tenant_id(tenant_id)
        if isinstance(references, (str, bytes)) or not isinstance(references, Sequence):
            raise GovernanceAgentsCompositionError("context references are invalid")
        if not 1 <= len(references) <= limits.max_context_items:
            raise GovernanceAgentsCompositionError(
                "context references exceed the tenant item bound"
            )
        normalized_refs = tuple(self._reference(value) for value in references)
        if len({item["item_id"] for item in normalized_refs}) != len(normalized_refs):
            raise GovernanceAgentsCompositionError("context item identities are not unique")
        results: list[agents.GovernanceContextItem] = []
        total_bytes = 0
        for reference in normalized_refs:
            kind = str(reference["source_kind"])
            with self._lock:
                resolver = self._sources.get(kind)
                key = (
                    tenant,
                    kind,
                    str(reference["source_ref"]),
                    int(reference["source_revision"]),
                )
                projected = self._items.get(key)
                if projected is not None:
                    self._items.move_to_end(key)
            if resolver is not None:
                try:
                    resolved = resolver(
                        tenant,
                        str(reference["source_ref"]),
                        int(reference["source_revision"]),
                    )
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as exc:
                    raise GovernanceAgentsCompositionError(
                        "context source authority is unavailable"
                    ) from exc
                if isinstance(resolved, bytes):
                    resolved = agents.GovernanceContextItem(
                        item_id=str(reference["item_id"]),
                        source_kind=kind,
                        source_ref=str(reference["source_ref"]),
                        source_revision=int(reference["source_revision"]),
                        collected_at=_timestamp(self._clock(), "context clock"),
                        content=resolved,
                    )
                item = self._normalize_item(resolved, expected=reference)
            elif projected is not None:
                item = self._normalize_item(projected, expected=reference)
            else:
                raise GovernanceAgentsCompositionError(
                    "requested context authority is not enrolled"
                )
            total_bytes += len(item.content)
            if total_bytes > limits.max_context_bytes:
                raise GovernanceAgentsCompositionError(
                    "resolved context exceeds the tenant byte bound"
                )
            results.append(item)
        return tuple(results)


class _TenantReferenceState:
    """Tenant-local bindings, sealed token escrow, and internal intent ledger."""

    def __init__(
        self,
        *,
        tenant_id: str,
        path: Path,
        keyring_path: Path,
        policy: ReferenceBindingPolicy,
        clock: Callable[[], float],
    ) -> None:
        self.tenant_id = canonical_tenant_id(tenant_id)
        self.path = Path(path)
        self.keyring_path = Path(keyring_path)
        self.policy = policy
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _now(self) -> float:
        return _timestamp(self._clock(), "composition clock")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS bindings(
                    binding_kind TEXT NOT NULL,
                    agent_kind TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    valid_until REAL NOT NULL,
                    revoked INTEGER NOT NULL,
                    configuration_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(binding_kind,agent_kind,revision)
                );
                CREATE TABLE IF NOT EXISTS execution_tokens(
                    run_id TEXT PRIMARY KEY,
                    token_sha256 TEXT NOT NULL,
                    sealed_token TEXT NOT NULL,
                    key_revision TEXT NOT NULL,
                    revoked INTEGER NOT NULL,
                    settled INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS internal_intents(
                    run_id TEXT PRIMARY KEY,
                    token_sha256 TEXT NOT NULL UNIQUE,
                    agent_kind TEXT NOT NULL,
                    action_codes_sha256 TEXT NOT NULL,
                    intent_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS retention_anchors(
                    run_id_sha256 TEXT PRIMARY KEY,
                    token_record_sha256 TEXT NOT NULL,
                    intent_record_sha256 TEXT NOT NULL,
                    purged_at REAL NOT NULL,
                    anchor_sha256 TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS retention_anchors_no_update
                    BEFORE UPDATE ON retention_anchors
                    BEGIN SELECT RAISE(ABORT, 'immutable governance-agent retention anchor'); END;
                CREATE TRIGGER IF NOT EXISTS retention_anchors_no_delete
                    BEFORE DELETE ON retention_anchors
                    BEGIN SELECT RAISE(ABORT, 'immutable governance-agent retention anchor'); END;
                INSERT OR IGNORE INTO metadata(key,value) VALUES('schema_version','1');
                COMMIT;
                """
            )
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(_STATE_SCHEMA_VERSION):
                raise GovernanceAgentsCompositionError(
                    "governance-agent composition database schema is unsupported"
                )
        ensure_private_file(self.path)

    def _new_keyring(self) -> dict[str, Any]:
        key = generate_key()
        revision = f"key-{hashlib.sha256(key).hexdigest()[:16]}"
        return {
            "schema": _KEYRING_SCHEMA,
            "current": revision,
            "order": [revision],
            "keys": {revision: key.decode("ascii")},
        }

    def _validate_keyring(self, value: object) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "current",
            "order",
            "keys",
        }:
            raise GovernanceAgentsCompositionError("execution custody keyring is invalid")
        if value.get("schema") != _KEYRING_SCHEMA:
            raise GovernanceAgentsCompositionError(
                "execution custody keyring schema is unsupported"
            )
        current = value.get("current")
        order = value.get("order")
        keys = value.get("keys")
        if (
            not isinstance(current, str)
            or not isinstance(order, list)
            or not 1 <= len(order) <= _MAX_KEYRING_KEYS
            or any(not isinstance(item, str) for item in order)
            or len(order) != len(set(order))
            or order[0] != current
            or not isinstance(keys, Mapping)
            or set(keys) != set(order)
        ):
            raise GovernanceAgentsCompositionError("execution custody keyring is invalid")
        normalized: dict[str, str] = {}
        digests: set[str] = set()
        for revision in order:
            encoded = keys.get(revision)
            if not isinstance(encoded, str):
                raise GovernanceAgentsCompositionError(
                    "execution custody keyring material is invalid"
                )
            try:
                key_bytes = encoded.encode("ascii")
                # Constructing a Fernet token validates the key format without
                # retaining or emitting caller-controlled plaintext.
                encrypt_entry(key_bytes, {"probe": True})
            except Exception as exc:
                raise GovernanceAgentsCompositionError(
                    "execution custody keyring material is invalid"
                ) from exc
            digest = hashlib.sha256(key_bytes).hexdigest()
            if digest in digests:
                raise GovernanceAgentsCompositionError(
                    "execution custody keyring contains duplicate keys"
                )
            digests.add(digest)
            normalized[revision] = encoded
        return {
            "schema": _KEYRING_SCHEMA,
            "current": current,
            "order": list(order),
            "keys": normalized,
        }

    def _read_keyring_unlocked(self) -> dict[str, Any]:
        ensure_private_directory(self.keyring_path.parent)
        if not self.keyring_path.exists():
            value = self._new_keyring()
            try:
                atomic_create_bytes(self.keyring_path, _canonical(value))
            except FileExistsError:
                pass
        ensure_private_file(self.keyring_path)
        return self._validate_keyring(
            _json_object(atomic_read_bytes(self.keyring_path), "execution custody keyring")
        )

    def _read_keyring(self) -> dict[str, Any]:
        with cross_process_lock(self.keyring_path, strict=True):
            return self._read_keyring_unlocked()

    def _write_keyring_unlocked(self, keyring: Mapping[str, Any]) -> None:
        normalized = self._validate_keyring(keyring)
        atomic_write_bytes(self.keyring_path, _canonical(normalized))
        ensure_private_file(self.keyring_path)

    @staticmethod
    def _key(keyring: Mapping[str, Any], revision: str) -> bytes:
        keys = keyring["keys"]
        encoded = keys.get(revision) if isinstance(keys, Mapping) else None
        if not isinstance(encoded, str):
            raise GovernanceAgentsCompositionError(
                "execution custody key revision is unavailable"
            )
        return encoded.encode("ascii")

    def _binding_configuration(self, binding_kind: str, agent_kind: str) -> str:
        return _sha256(
            {
                "schema": "lightwork.governance-agent.reference-binding-config.v1",
                "binding_kind": binding_kind,
                "agent_kind": agent_kind,
                "mode": "deterministic_reference"
                if binding_kind == "adapter"
                else "internal_intent_only",
                "network_access": False,
                "external_writes": False,
                "legal_conclusions": False,
            }
        )

    def _binding_row(self, binding_kind: str, agent_kind: str) -> sqlite3.Row:
        if binding_kind not in {"adapter", "dispatcher"}:
            raise GovernanceAgentsCompositionError("binding kind is unsupported")
        if agent_kind not in agents.AGENT_KINDS:
            raise GovernanceAgentsCompositionError("governance-agent kind is unsupported")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM bindings WHERE binding_kind=? AND agent_kind=? "
                "ORDER BY revision DESC LIMIT 1",
                (binding_kind, agent_kind),
            ).fetchone()
            if row is None:
                now = self._now()
                connection.execute(
                    "INSERT INTO bindings VALUES(?,?,?,?,?,?,?)",
                    (
                        binding_kind,
                        agent_kind,
                        1,
                        now + self.policy.authority_lifetime_seconds,
                        0,
                        self._binding_configuration(binding_kind, agent_kind),
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM bindings WHERE binding_kind=? AND agent_kind=? AND revision=1",
                    (binding_kind, agent_kind),
                ).fetchone()
            connection.commit()
        if row is None:
            raise GovernanceAgentsCompositionError("binding authority is unavailable")
        if bool(row["revoked"]) or float(row["valid_until"]) <= self._now():
            raise GovernanceAgentsCompositionError(
                "binding authority is revoked or expired; rotate it explicitly"
            )
        return row

    def adapter_authority(self, agent_kind: str) -> agents.GovernanceAgentAdapterAuthority:
        row = self._binding_row("adapter", agent_kind)
        implementation = _sha256(
            {
                "schema": "lightwork.governance-agent.reference-adapter.v1",
                "agent_kind": agent_kind,
                "behavior": _REFERENCE_BEHAVIOR[agent_kind],
            }
        )
        return agents.build_adapter_authority(
            adapter_id=f"reference-adapter:{agent_kind}",
            revision=int(row["revision"]),
            agent_kind=agent_kind,
            implementation_sha256=implementation,
            configuration_sha256=str(row["configuration_sha256"]),
            deterministic=True,
            network_access=False,
            legal_conclusion_enabled=False,
            valid_until=float(row["valid_until"]),
        )

    def dispatcher_authority(
        self, agent_kind: str
    ) -> agents.GovernanceAgentDispatcherAuthority:
        row = self._binding_row("dispatcher", agent_kind)
        implementation = _sha256(
            {
                "schema": "lightwork.governance-agent.reference-dispatcher.v1",
                "agent_kind": agent_kind,
                "destination": "tenant_local_internal_intent_ledger",
                "external_writes": False,
            }
        )
        return agents.build_dispatcher_authority(
            dispatcher_id=f"reference-dispatcher:{agent_kind}",
            revision=int(row["revision"]),
            agent_kind=agent_kind,
            implementation_sha256=implementation,
            configuration_sha256=str(row["configuration_sha256"]),
            execution_enabled=True,
            valid_until=float(row["valid_until"]),
        )

    def rotate_binding(self, binding_kind: str, agent_kind: str) -> int:
        if binding_kind not in {"adapter", "dispatcher"}:
            raise GovernanceAgentsCompositionError("binding kind is unsupported")
        if agent_kind not in agents.AGENT_KINDS:
            raise GovernanceAgentsCompositionError("governance-agent kind is unsupported")
        if binding_kind == "dispatcher" and self.active_token_count() > 0:
            raise GovernanceAgentsCompositionError(
                "dispatcher rotation requires execution-token reconciliation first"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT revision FROM bindings WHERE binding_kind=? AND agent_kind=? "
                "ORDER BY revision DESC LIMIT 1",
                (binding_kind, agent_kind),
            ).fetchone()
            if row is None:
                current_revision = 0
            else:
                current_revision = int(row["revision"])
            revision = current_revision + 1
            now = self._now()
            if current_revision:
                connection.execute(
                    "UPDATE bindings SET revoked=1 WHERE binding_kind=? AND agent_kind=? "
                    "AND revision=?",
                    (binding_kind, agent_kind, current_revision),
                )
            connection.execute(
                "INSERT INTO bindings VALUES(?,?,?,?,?,?,?)",
                (
                    binding_kind,
                    agent_kind,
                    revision,
                    now + self.policy.authority_lifetime_seconds,
                    0,
                    self._binding_configuration(binding_kind, agent_kind),
                    now,
                ),
            )
            connection.commit()
        return revision

    def revoke_binding(self, binding_kind: str, agent_kind: str) -> int:
        row = self._binding_row(binding_kind, agent_kind)
        revision = int(row["revision"])
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE bindings SET revoked=1 WHERE binding_kind=? AND agent_kind=? "
                "AND revision=? AND revoked=0",
                (binding_kind, agent_kind, revision),
            )
            if changed.rowcount != 1:
                raise GovernanceAgentsCompositionError("binding authority changed")
            connection.commit()
        return revision

    def escrow_token(
        self,
        tenant_id: str,
        run_id: str,
        token: str,
        token_sha256: str,
    ) -> bool:
        if canonical_tenant_id(tenant_id) != self.tenant_id:
            raise GovernanceAgentsCompositionError("execution token tenant is misbound")
        run = _identifier(run_id, "execution run_id")
        digest = _digest(token_sha256, "execution token digest")
        if not isinstance(token, str) or not token or len(token.encode("utf-8")) > 512:
            raise GovernanceAgentsCompositionError("execution token is invalid")
        if not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), digest):
            return False
        keyring = self._read_keyring()
        revision = str(keyring["current"])
        sealed = encrypt_entry(
            self._key(keyring, revision),
            {"tenant_id": self.tenant_id, "run_id": run, "token": token},
        )
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT * FROM execution_tokens WHERE run_id=?", (run,)
            ).fetchone()
            if previous is not None:
                connection.commit()
                if not hmac.compare_digest(str(previous["token_sha256"]), digest):
                    return False
                try:
                    recovered = self.resolve_token(self.tenant_id, run)
                except agents.GovernanceAgentError:
                    return False
                return hmac.compare_digest(recovered, token)
            connection.execute(
                "INSERT INTO execution_tokens VALUES(?,?,?,?,?,?,?,?)",
                (run, digest, sealed, revision, 0, 0, now, now),
            )
            connection.commit()
        return True

    def resolve_token(self, tenant_id: str, run_id: str) -> str:
        if canonical_tenant_id(tenant_id) != self.tenant_id:
            raise GovernanceAgentsCompositionError("execution token tenant is misbound")
        run = _identifier(run_id, "execution run_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM execution_tokens WHERE run_id=?", (run,)
            ).fetchone()
        if row is None or bool(row["revoked"]):
            raise GovernanceAgentsCompositionError(
                "execution token is unavailable or revoked"
            )
        keyring = self._read_keyring()
        try:
            payload = decrypt_entry(
                self._key(keyring, str(row["key_revision"])),
                str(row["sealed_token"]),
            )
        except GovernanceAgentsCompositionError:
            raise
        except Exception as exc:
            raise GovernanceAgentsCompositionError(
                "execution token failed custody verification"
            ) from exc
        if (
            not isinstance(payload, Mapping)
            or set(payload) != {"tenant_id", "run_id", "token"}
            or payload.get("tenant_id") != self.tenant_id
            or payload.get("run_id") != run
            or not isinstance(payload.get("token"), str)
            or not hmac.compare_digest(
                hashlib.sha256(str(payload["token"]).encode()).hexdigest(),
                str(row["token_sha256"]),
            )
        ):
            raise GovernanceAgentsCompositionError(
                "execution token custody binding is invalid"
            )
        return str(payload["token"])

    def revoke_token(self, run_id: str) -> bool:
        run = _identifier(run_id, "execution run_id")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE execution_tokens SET revoked=1,updated_at=? "
                "WHERE run_id=? AND revoked=0",
                (self._now(), run),
            )
            connection.commit()
            return changed.rowcount == 1

    def reconcile_tokens(self, store: agents.GovernanceAgentStore) -> int:
        if not isinstance(store, agents.GovernanceAgentStore):
            raise TypeError("governance-agent store is required for reconciliation")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id FROM execution_tokens WHERE revoked=0 AND settled=0"
            ).fetchall()
        terminal: list[str] = []
        for row in rows:
            try:
                run = store.get_run(self.tenant_id, str(row["run_id"]))
            except agents.GovernanceAgentNotFound:
                continue
            if run.state in {"executed", "rejected", "revoked"}:
                terminal.append(run.run_id)
        if not terminal:
            return 0
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = 0
            for run_id in terminal:
                result = connection.execute(
                    "UPDATE execution_tokens SET settled=1,updated_at=? "
                    "WHERE run_id=? AND revoked=0 AND settled=0",
                    (self._now(), run_id),
                )
                changed += result.rowcount
            connection.commit()
        return changed

    def active_token_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM execution_tokens WHERE revoked=0 AND settled=0"
            ).fetchone()
        if row is None:
            raise GovernanceAgentsCompositionError(
                "execution token state is unavailable"
            )
        return int(row[0])

    def rotate_custody_key(self) -> str:
        with cross_process_lock(self.keyring_path, strict=True):
            keyring = self._read_keyring_unlocked()
            order = list(keyring["order"])
            keys = dict(keyring["keys"])
            if len(order) >= _MAX_KEYRING_KEYS:
                retiring = order[-1]
                with self._connect() as connection:
                    row = connection.execute(
                        "SELECT COUNT(*) FROM execution_tokens WHERE key_revision=? "
                        "AND revoked=0 AND settled=0",
                        (retiring,),
                    ).fetchone()
                if row is None or int(row[0]) > 0:
                    raise GovernanceAgentsCompositionError(
                        "custody rotation would retire a key with active recovery tokens"
                    )
                order.pop()
                keys.pop(retiring, None)
            key = generate_key()
            revision = f"key-{hashlib.sha256(key).hexdigest()[:16]}"
            if revision in keys:
                raise GovernanceAgentsCompositionError(
                    "custody rotation generated a duplicate revision"
                )
            order.insert(0, revision)
            keys[revision] = key.decode("ascii")
            self._write_keyring_unlocked(
                {
                    "schema": _KEYRING_SCHEMA,
                    "current": revision,
                    "order": order,
                    "keys": keys,
                }
            )
        return revision

    def retire_custody_key(self, revision: str) -> None:
        revision = _identifier(revision, "custody key revision")
        with cross_process_lock(self.keyring_path, strict=True):
            keyring = self._read_keyring_unlocked()
            if revision == keyring["current"]:
                raise GovernanceAgentsCompositionError(
                    "the current custody key cannot be retired"
                )
            if revision not in keyring["order"]:
                raise GovernanceAgentsCompositionError(
                    "custody key revision does not exist"
                )
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT COUNT(*) FROM execution_tokens WHERE key_revision=? "
                    "AND revoked=0 AND settled=0",
                    (revision,),
                ).fetchone()
            if row is None or int(row[0]) > 0:
                raise GovernanceAgentsCompositionError(
                    "custody key has active recovery tokens"
                )
            order = [item for item in keyring["order"] if item != revision]
            keys = dict(keyring["keys"])
            keys.pop(revision, None)
            self._write_keyring_unlocked(
                {
                    "schema": _KEYRING_SCHEMA,
                    "current": keyring["current"],
                    "order": order,
                    "keys": keys,
                }
            )

    def sign_receipt(self, material: Mapping[str, object]) -> str:
        keyring = self._read_keyring()
        key = self._key(keyring, str(keyring["current"]))
        return hmac.new(
            key,
            b"lightwork.governance-agent.reference-receipt.v1\x00"
            + _canonical(dict(material)),
            hashlib.sha256,
        ).hexdigest()

    def verify_receipt(self, material: Mapping[str, object], proof: str) -> bool:
        _digest(proof, "execution receipt proof")
        keyring = self._read_keyring()
        payload = (
            b"lightwork.governance-agent.reference-receipt.v1\x00"
            + _canonical(dict(material))
        )
        verified = False
        for revision in keyring["order"]:
            expected = hmac.new(
                self._key(keyring, str(revision)), payload, hashlib.sha256
            ).hexdigest()
            verified = hmac.compare_digest(expected, proof) or verified
        return verified

    def record_intent(
        self,
        run: agents.GovernanceAgentRun,
        idempotency_key: str,
    ) -> tuple[bool, str]:
        if run.tenant_id != self.tenant_id:
            raise GovernanceAgentsCompositionError("internal intent tenant is misbound")
        token_digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
        if run.execution_idempotency_sha256 is None or not hmac.compare_digest(
            run.execution_idempotency_sha256, token_digest
        ):
            raise GovernanceAgentsCompositionError(
                "internal intent execution token is misbound"
            )
        action_codes = tuple(
            sorted(
                {
                    item.recommended_action_code
                    for item in run.findings
                    if item.recommended_action_code is not None
                }
            )
        )
        if not action_codes:
            raise GovernanceAgentsCompositionError(
                "internal intent has no approved action codes"
            )
        intent = {
            "schema": _INTENT_SCHEMA,
            "tenant_sha256": hashlib.sha256(self.tenant_id.encode()).hexdigest(),
            "run_id": run.run_id,
            "agent_kind": run.agent_kind,
            "action_codes": action_codes,
            "token_sha256": token_digest,
            "status": "pending_human_action",
            "external_writes": False,
        }
        intent_sha256 = _sha256(intent)
        action_codes_sha256 = _sha256(
            {
                "schema": "lightwork.governance-agent.internal-intent-actions.v1",
                "action_codes": action_codes,
            }
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT * FROM internal_intents WHERE run_id=?", (run.run_id,)
            ).fetchone()
            if previous is not None:
                connection.commit()
                if (
                    not hmac.compare_digest(str(previous["token_sha256"]), token_digest)
                    or not hmac.compare_digest(
                        str(previous["intent_sha256"]), intent_sha256
                    )
                ):
                    raise GovernanceAgentsCompositionError(
                        "internal intent idempotency binding changed"
                    )
                return False, intent_sha256
            connection.execute(
                "INSERT INTO internal_intents VALUES(?,?,?,?,?,?,?)",
                (
                    run.run_id,
                    token_digest,
                    run.agent_kind,
                    action_codes_sha256,
                    intent_sha256,
                    "pending_human_action",
                    self._now(),
                ),
            )
            connection.commit()
        return True, intent_sha256

    def intent_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM internal_intents").fetchone()
        return 0 if row is None else int(row[0])

    def list_internal_intents(self, *, limit: int = 100) -> tuple[dict[str, object], ...]:
        """Return a bounded token-free queue for a human-owned task bridge."""

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise GovernanceAgentsCompositionError(
                "internal intent list limit is outside its bound"
            )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id,agent_kind,action_codes_sha256,intent_sha256,status,created_at "
                "FROM internal_intents ORDER BY created_at DESC,run_id LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(
            {
                "schema": _INTENT_SCHEMA,
                "tenant_id": self.tenant_id,
                "run_id": str(row["run_id"]),
                "agent_kind": str(row["agent_kind"]),
                "action_codes_sha256": str(row["action_codes_sha256"]),
                "intent_sha256": str(row["intent_sha256"]),
                "status": str(row["status"]),
                "created_at": float(row["created_at"]),
                "external_writes": False,
            }
            for row in rows
        )

    def purge_tombstoned_run_state(
        self,
        store: agents.GovernanceAgentStore,
        *,
        limit: int = 100,
    ) -> tuple[int, int]:
        """Purge sealed tokens/intents only after the core replay tombstone exists."""

        if not isinstance(store, agents.GovernanceAgentStore):
            raise TypeError("governance-agent store is required for retention")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise GovernanceAgentsCompositionError(
                "reference retention limit is outside its bound"
            )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id FROM execution_tokens UNION SELECT run_id "
                "FROM internal_intents ORDER BY run_id LIMIT ?",
                (limit,),
            ).fetchall()
        eligible = [
            str(row["run_id"])
            for row in rows
            if store.has_run_tombstone(self.tenant_id, str(row["run_id"]))
        ]
        if not eligible:
            return (0, 0)

        tokens_purged = 0
        intents_purged = 0
        zero = "0" * 64
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for run_id in eligible:
                token = connection.execute(
                    "SELECT * FROM execution_tokens WHERE run_id=?", (run_id,)
                ).fetchone()
                intent = connection.execute(
                    "SELECT * FROM internal_intents WHERE run_id=?", (run_id,)
                ).fetchone()
                if token is None and intent is None:
                    continue
                run_sha256 = hashlib.sha256(
                    f"{self.tenant_id}\x00{run_id}".encode()
                ).hexdigest()
                if connection.execute(
                    "SELECT 1 FROM retention_anchors WHERE run_id_sha256=?",
                    (run_sha256,),
                ).fetchone() is not None:
                    raise GovernanceAgentsCompositionError(
                        "retained execution state conflicts with its purge anchor"
                    )
                token_sha256 = zero
                if token is not None:
                    token_sha256 = _sha256(
                        {
                            key: token[key]
                            for key in (
                                "run_id",
                                "token_sha256",
                                "sealed_token",
                                "key_revision",
                                "revoked",
                                "settled",
                                "created_at",
                                "updated_at",
                            )
                        }
                    )
                intent_sha256 = zero
                if intent is not None:
                    intent_sha256 = _sha256(
                        {
                            key: intent[key]
                            for key in (
                                "run_id",
                                "token_sha256",
                                "agent_kind",
                                "action_codes_sha256",
                                "intent_sha256",
                                "status",
                                "created_at",
                            )
                        }
                    )
                purged_at = self._now()
                material = {
                    "schema": "lightwork.governance-agent.reference-retention-anchor.v1",
                    "tenant_sha256": hashlib.sha256(
                        self.tenant_id.encode()
                    ).hexdigest(),
                    "run_id_sha256": run_sha256,
                    "token_record_sha256": token_sha256,
                    "intent_record_sha256": intent_sha256,
                    "purged_at": purged_at,
                }
                connection.execute(
                    "INSERT INTO retention_anchors VALUES(?,?,?,?,?)",
                    (
                        run_sha256,
                        token_sha256,
                        intent_sha256,
                        purged_at,
                        _sha256(material),
                    ),
                )
                if token is not None:
                    tokens_purged += connection.execute(
                        "DELETE FROM execution_tokens WHERE run_id=?", (run_id,)
                    ).rowcount
                if intent is not None:
                    intents_purged += connection.execute(
                        "DELETE FROM internal_intents WHERE run_id=?", (run_id,)
                    ).rowcount
            connection.commit()
        return (tokens_purged, intents_purged)

    def health(self) -> dict[str, object]:
        with self._connect() as connection:
            quick = connection.execute("PRAGMA quick_check").fetchone()
            binding_count = int(connection.execute("SELECT COUNT(*) FROM bindings").fetchone()[0])
            intent_count = int(
                connection.execute("SELECT COUNT(*) FROM internal_intents").fetchone()[0]
            )
            anchors = connection.execute(
                "SELECT * FROM retention_anchors ORDER BY run_id_sha256"
            ).fetchall()
            tenant_sha256 = hashlib.sha256(self.tenant_id.encode()).hexdigest()
            for anchor in anchors:
                material = {
                    "schema": "lightwork.governance-agent.reference-retention-anchor.v1",
                    "tenant_sha256": tenant_sha256,
                    "run_id_sha256": str(anchor["run_id_sha256"]),
                    "token_record_sha256": str(anchor["token_record_sha256"]),
                    "intent_record_sha256": str(anchor["intent_record_sha256"]),
                    "purged_at": float(anchor["purged_at"]),
                }
                if not hmac.compare_digest(
                    _sha256(material), str(anchor["anchor_sha256"])
                ):
                    raise GovernanceAgentsCompositionError(
                        "reference retention anchor failed integrity verification"
                    )
        keyring = self._read_keyring()
        return {
            "database_integrity_verified": quick is not None and quick[0] == "ok",
            "binding_records": binding_count,
            "internal_intents": intent_count,
            "retention_anchors": len(anchors),
            "active_recovery_tokens": self.active_token_count(),
            "custody_key_revisions": len(keyring["order"]),
            "external_writes_enabled": False,
        }


class DeterministicReferenceAnalysisAdapter:
    """Conservative local decision aid; never presents itself as complete."""

    def __init__(self, tenant_id: str, agent_kind: str) -> None:
        self.tenant_id = canonical_tenant_id(tenant_id)
        if agent_kind not in agents.AGENT_KINDS:
            raise GovernanceAgentsCompositionError("governance-agent kind is unsupported")
        self.agent_kind = agent_kind

    def __call__(
        self,
        *,
        tenant_id: str,
        run_id: str,
        agent_kind: str,
        capability: str,
        context: tuple[agents.GovernanceContextItem, ...],
        authority: agents.GovernanceAgentAdapterAuthority,
    ) -> agents.GovernanceAgentAnalysis:
        if (
            canonical_tenant_id(tenant_id) != self.tenant_id
            or agent_kind != self.agent_kind
            or authority.agent_kind != self.agent_kind
            or authority.deterministic is not True
            or authority.network_access is not False
            or authority.legal_conclusion_enabled is not False
            or not context
        ):
            raise GovernanceAgentsCompositionError(
                "reference analysis binding is unavailable or unsafe"
            )
        finding_code, action_code, limitations = _REFERENCE_BEHAVIOR[self.agent_kind]
        evidence = tuple(sorted(item.item_id for item in context))
        finding_id = f"finding:{hashlib.sha256(f'{run_id}:{capability}'.encode()).hexdigest()[:24]}"
        finding = agents.build_finding(
            agent_kind=self.agent_kind,
            finding_id=finding_id,
            finding_code=finding_code,
            severity="medium",
            evidence_item_ids=evidence,
            recommended_action_code=action_code,
            rationale_code="authority_required",
            confidence_bps=2_500,
        )
        return agents.GovernanceAgentAnalysis(
            findings=(finding,),
            limitations=tuple(sorted(limitations)),
            complete=False,
        )


class ReferenceInternalIntentDispatcher:
    """Idempotently create a tenant-local governed intent, never an external write."""

    def __init__(
        self,
        state: _TenantReferenceState,
        agent_kind: str,
    ) -> None:
        self._state = state
        self._agent_kind = agent_kind

    def __call__(
        self,
        *,
        run: agents.GovernanceAgentRun,
        idempotency_key: str,
    ) -> agents.GovernanceAgentExecutionOutcome:
        authority = self._state.dispatcher_authority(self._agent_kind)
        if (
            run.agent_kind != self._agent_kind
            or run.execution_dispatcher_authority_sha256 is None
            or not hmac.compare_digest(
                run.execution_dispatcher_authority_sha256,
                authority.authority_sha256,
            )
        ):
            raise GovernanceAgentsCompositionError(
                "internal dispatcher authority changed before execution"
            )
        created, intent_sha256 = self._state.record_intent(run, idempotency_key)
        outcome = "applied" if created else "no_change"
        provider_status = "internal_intent_recorded" if created else "internal_intent_exists"
        material = agents.execution_receipt_signing_payload(
            run=run,
            dispatcher_authority=authority,
            outcome=outcome,
            provider_status_code=provider_status,
            external_reference_sha256=intent_sha256,
            retryable=False,
        )
        proof = self._state.sign_receipt(material)
        return agents.build_execution_outcome(
            run=run,
            dispatcher_authority=authority,
            outcome=outcome,
            provider_status_code=provider_status,
            external_reference_sha256=intent_sha256,
            retryable=False,
            receipt_proof_sha256=proof,
        )


class ReferenceExecutionReceiptVerifier:
    """Verify the current enrolled authority and a custody-key HMAC receipt."""

    def __init__(self, state: _TenantReferenceState, agent_kind: str) -> None:
        self._state = state
        self._agent_kind = agent_kind

    def __call__(
        self,
        authority: agents.GovernanceAgentDispatcherAuthority,
        outcome: agents.GovernanceAgentExecutionOutcome,
    ) -> bool:
        try:
            current = self._state.dispatcher_authority(self._agent_kind)
            if authority != current or outcome.dispatcher_authority_sha256 != current.authority_sha256:
                return False
            material = asdict(outcome)
            proof = material.pop("receipt_proof_sha256")
            material.pop("receipt_sha256")
            return self._state.verify_receipt(material, proof)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False


def _default_roster_resolver(tenant_id: str) -> Mapping[str, str]:
    from .rbac import list_tenant_roles

    return list_tenant_roles(tenant_id)


class GovernanceAgentsReferenceComposition:
    """Lazy stock composition and explicit maintenance surface."""

    def __init__(
        self,
        *,
        tenant_snapshot_resolver: Callable[
            [str], agents.GovernanceAgentTenantSnapshot
        ] = agents.load_governance_agent_tenant_snapshot,
        roster_resolver: Callable[[str], Mapping[str, str]] = _default_roster_resolver,
        context_authority: EphemeralGovernanceContextAuthority | None = None,
        binding_policy: ReferenceBindingPolicy | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(tenant_snapshot_resolver) or not callable(clock):
            raise TypeError("tenant snapshot resolver and clock must be callable")
        self._tenant_snapshot_resolver = tenant_snapshot_resolver
        self._clock = clock
        self.binding_policy = binding_policy or ReferenceBindingPolicy()
        self.context_authority = context_authority or EphemeralGovernanceContextAuthority(
            clock=clock
        )
        self.approver_authority = RoleBackedPolicyApproverAuthority(
            roster_resolver,
            policy=self.binding_policy,
        )
        self._states: dict[str, _TenantReferenceState] = {}
        self._adapters: dict[
            tuple[str, str], DeterministicReferenceAnalysisAdapter
        ] = {}
        self._dispatchers: dict[
            tuple[str, str], ReferenceInternalIntentDispatcher
        ] = {}
        self._verifiers: dict[
            tuple[str, str], ReferenceExecutionReceiptVerifier
        ] = {}
        self._lock = threading.RLock()

    def tenant_snapshot(self, tenant_id: str) -> agents.GovernanceAgentTenantSnapshot:
        tenant = canonical_tenant_id(tenant_id)
        try:
            snapshot = self._tenant_snapshot_resolver(tenant)
        except agents.GovernanceAgentError:
            raise
        except Exception as exc:
            raise GovernanceAgentsCompositionError(
                "governance-agent tenant snapshot is unavailable"
            ) from exc
        if not isinstance(snapshot, agents.GovernanceAgentTenantSnapshot):
            raise GovernanceAgentsCompositionError(
                "governance-agent tenant snapshot is invalid"
            )
        if snapshot.tenant_id != tenant:
            raise GovernanceAgentsCompositionError(
                "governance-agent tenant snapshot is misbound"
            )
        return snapshot

    def _state_for(self, tenant_id: str) -> _TenantReferenceState:
        tenant = canonical_tenant_id(tenant_id)
        with self._lock:
            state = self._states.get(tenant)
            if state is None:
                state = _TenantReferenceState(
                    tenant_id=tenant,
                    path=data_dir(
                        "governance_agents",
                        "reference-composition.sqlite3",
                        tenant=tenant,
                    ),
                    keyring_path=data_dir(
                        "governance_agents",
                        "reference-custody-keyring.json",
                        tenant=tenant,
                    ),
                    policy=self.binding_policy,
                    clock=self._clock,
                )
                self._states[tenant] = state
            return state

    def _require_agent_enabled(self, tenant_id: str, agent_kind: str) -> str:
        tenant = canonical_tenant_id(tenant_id)
        snapshot = self.tenant_snapshot(tenant)
        if agent_kind not in snapshot.enabled_agents:
            raise GovernanceAgentsCompositionError(
                "governance-agent kind is disabled by tenant configuration"
            )
        return tenant

    def policy_approvers(
        self, tenant_id: str, policy_id: str, revision: int
    ) -> tuple[str, ...]:
        return self.approver_authority(tenant_id, policy_id, revision)

    def resolve_context(
        self,
        tenant_id: str,
        references: Sequence[Mapping[str, object]],
    ) -> tuple[agents.GovernanceContextItem, ...]:
        snapshot = self.tenant_snapshot(tenant_id)
        return self.context_authority.resolve(
            tenant_id,
            references,
            limits=snapshot.limits,
        )

    def resolve_adapter(
        self, tenant_id: str, agent_kind: str
    ) -> tuple[
        agents.GovernanceAgentAdapterAuthority,
        DeterministicReferenceAnalysisAdapter,
    ]:
        tenant = self._require_agent_enabled(tenant_id, agent_kind)
        state = self._state_for(tenant)
        authority = state.adapter_authority(agent_kind)
        key = (tenant, agent_kind)
        with self._lock:
            adapter = self._adapters.get(key)
            if adapter is None:
                adapter = DeterministicReferenceAnalysisAdapter(tenant, agent_kind)
                self._adapters[key] = adapter
        return authority, adapter

    def resolve_dispatcher(
        self, tenant_id: str, agent_kind: str
    ) -> tuple[
        agents.GovernanceAgentDispatcherAuthority,
        ReferenceInternalIntentDispatcher,
        ReferenceExecutionReceiptVerifier,
    ]:
        tenant = self._require_agent_enabled(tenant_id, agent_kind)
        state = self._state_for(tenant)
        authority = state.dispatcher_authority(agent_kind)
        key = (tenant, agent_kind)
        with self._lock:
            dispatcher = self._dispatchers.get(key)
            verifier = self._verifiers.get(key)
            if dispatcher is None:
                dispatcher = ReferenceInternalIntentDispatcher(state, agent_kind)
                self._dispatchers[key] = dispatcher
            if verifier is None:
                verifier = ReferenceExecutionReceiptVerifier(state, agent_kind)
                self._verifiers[key] = verifier
        return authority, dispatcher, verifier

    def escrow_token(
        self,
        tenant_id: str,
        run_id: str,
        token: str,
        token_sha256: str,
    ) -> bool:
        self.tenant_snapshot(tenant_id)
        return self._state_for(tenant_id).escrow_token(
            tenant_id, run_id, token, token_sha256
        )

    def resolve_token(self, tenant_id: str, run_id: str) -> str:
        self.tenant_snapshot(tenant_id)
        return self._state_for(tenant_id).resolve_token(tenant_id, run_id)

    def store_factory(self, **kwargs: Any) -> agents.GovernanceAgentStore:
        tenant = canonical_tenant_id(kwargs.get("tenant_id"))
        principal = _identifier(kwargs.get("principal_ref"), "runtime principal")
        principal_resolver = kwargs.get("principal_resolver")
        supplied_snapshot = kwargs.get("tenant_snapshot_resolver")
        if not callable(principal_resolver) or not callable(supplied_snapshot):
            raise GovernanceAgentsCompositionError(
                "governance-agent request authorities are unavailable"
            )

        def bound_principal() -> str:
            resolved = principal_resolver()
            if resolved != principal:
                raise agents.GovernanceAgentPermissionDenied(
                    "governance-agent request principal changed"
                )
            return principal

        snapshot = supplied_snapshot(tenant)
        if (
            not isinstance(snapshot, agents.GovernanceAgentTenantSnapshot)
            or snapshot.tenant_id != tenant
            or snapshot != self.tenant_snapshot(tenant)
        ):
            raise GovernanceAgentsCompositionError(
                "governance-agent request snapshot changed"
            )

        def bound_snapshot(requested_tenant: str) -> agents.GovernanceAgentTenantSnapshot:
            if canonical_tenant_id(requested_tenant) != tenant:
                raise GovernanceAgentsCompositionError(
                    "governance-agent store tenant changed"
                )
            current = self.tenant_snapshot(tenant)
            if current != snapshot:
                raise GovernanceAgentsCompositionError(
                    "governance-agent tenant snapshot changed during the request"
                )
            return snapshot

        return agents.GovernanceAgentStore(
            data_dir(
                "governance_agents",
                "governance-agents.sqlite3",
                tenant=tenant,
            ),
            config_gate=lambda: None,
            principal_resolver=bound_principal,
            policy_approver_resolver=self.approver_authority.bind(principal),
            analysis_binding_resolver=self.resolve_adapter,
            execution_binding_resolver=self.resolve_dispatcher,
            execution_token_escrow=self.escrow_token,
            execution_token_resolver=self.resolve_token,
            tenant_snapshot_resolver=bound_snapshot,
            clock=self._clock,
        )

    def _maintenance_store(self, tenant_id: str) -> agents.GovernanceAgentStore:
        tenant = canonical_tenant_id(tenant_id)
        snapshot = self.tenant_snapshot(tenant)
        principal = governance_agent_principal_ref(tenant, "service:governance-maintenance")
        return self.store_factory(
            tenant_id=tenant,
            principal_ref=principal,
            principal_resolver=lambda: principal,
            tenant_snapshot_resolver=lambda requested: (
                snapshot
                if canonical_tenant_id(requested) == tenant
                else (_ for _ in ()).throw(
                    GovernanceAgentsCompositionError(
                        "maintenance snapshot tenant is misbound"
                    )
                )
            ),
        )

    def reconcile_execution_tokens(self, tenant_id: str) -> int:
        tenant = canonical_tenant_id(tenant_id)
        return self._state_for(tenant).reconcile_tokens(
            self._maintenance_store(tenant)
        )

    def purge_retention(
        self,
        tenant_id: str,
        *,
        store: agents.GovernanceAgentStore,
        limit: int = 100,
    ) -> dict[str, object]:
        """Coordinate core tombstones with reference-state secret deletion."""

        tenant = canonical_tenant_id(tenant_id)
        if not isinstance(store, agents.GovernanceAgentStore):
            raise GovernanceAgentsCompositionError(
                "governance-agent retention store is invalid"
            )
        state = self._state_for(tenant)
        settled = state.reconcile_tokens(store)
        runs_purged = store.purge_expired(tenant, limit=limit)
        tokens_purged, intents_purged = state.purge_tombstoned_run_state(
            store,
            limit=limit,
        )
        return {
            "schema": "lightwork.governance-agent.coordinated-retention.v1",
            "purged": runs_purged,
            "execution_tokens_settled": settled,
            "sealed_tokens_purged": tokens_purged,
            "internal_intents_purged": intents_purged,
            "retention_anchors": state.health()["retention_anchors"],
            "plaintext_tokens_persisted": False,
            "external_writes": False,
        }

    def rotate_adapter(self, tenant_id: str, agent_kind: str) -> int:
        tenant = self._require_agent_enabled(tenant_id, agent_kind)
        return self._state_for(tenant).rotate_binding("adapter", agent_kind)

    def revoke_adapter(self, tenant_id: str, agent_kind: str) -> int:
        tenant = self._require_agent_enabled(tenant_id, agent_kind)
        return self._state_for(tenant).revoke_binding("adapter", agent_kind)

    def rotate_dispatcher(self, tenant_id: str, agent_kind: str) -> int:
        tenant = self._require_agent_enabled(tenant_id, agent_kind)
        self.reconcile_execution_tokens(tenant)
        return self._state_for(tenant).rotate_binding("dispatcher", agent_kind)

    def revoke_dispatcher(self, tenant_id: str, agent_kind: str) -> int:
        tenant = self._require_agent_enabled(tenant_id, agent_kind)
        return self._state_for(tenant).revoke_binding("dispatcher", agent_kind)

    def rotate_custody_key(self, tenant_id: str) -> str:
        self.tenant_snapshot(tenant_id)
        return self._state_for(tenant_id).rotate_custody_key()

    def retire_custody_key(self, tenant_id: str, revision: str) -> None:
        self.tenant_snapshot(tenant_id)
        self._state_for(tenant_id).retire_custody_key(revision)

    def revoke_execution_token(self, tenant_id: str, run_id: str) -> bool:
        self.tenant_snapshot(tenant_id)
        return self._state_for(tenant_id).revoke_token(run_id)

    def list_internal_intents(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[dict[str, object], ...]:
        self.tenant_snapshot(tenant_id)
        return self._state_for(tenant_id).list_internal_intents(limit=limit)

    def readiness(self, tenant_id: str) -> dict[str, object]:
        """Perform an operational local probe without claiming external acceptance."""

        tenant = canonical_tenant_id(tenant_id)
        result: dict[str, object] = {
            "schema": _READINESS_SCHEMA,
            "tenant_id": tenant,
            "configured": False,
            "store_integrity_verified": False,
            "analysis_ready": False,
            "internal_intent_execution_ready": False,
            "external_writes_enabled": False,
            "network_analysis_enabled": False,
            "legal_conclusions_enabled": False,
            "live_provider_acceptance_verified": False,
            "live_customer_acceptance_verified": False,
        }
        try:
            snapshot = self.tenant_snapshot(tenant)
            result["configured"] = True
            approvers = self.approver_authority._eligible(tenant)
            adapters = [self.resolve_adapter(tenant, kind)[0] for kind in snapshot.enabled_agents]
            dispatchers = [
                self.resolve_dispatcher(tenant, kind)[0]
                for kind in snapshot.enabled_agents
            ]
            store = self._maintenance_store(tenant)
            integrity = store.verify_integrity(tenant)
            state_health = self._state_for(tenant).health()
            context_sources = self.context_authority.source_kinds_for(tenant)
            projected_items = self.context_authority.projected_items_for(tenant)
            result.update(
                {
                    "enabled_agents": list(snapshot.enabled_agents),
                    "eligible_policy_approvers": len(approvers),
                    "context_source_kinds": list(context_sources),
                    "ephemeral_context_items": projected_items,
                    "adapter_authorities_verified": len(adapters),
                    "dispatcher_authorities_verified": len(dispatchers),
                    "store_integrity_verified": integrity.tenant_id == tenant,
                    "analysis_configured_for_attempt": bool(context_sources),
                    # A registered resolver cannot be operationally probed
                    # without an exact source-owned reference.  A present
                    # tenant projection is the strongest non-mutating proof
                    # available to this generic readiness endpoint.
                    "context_resolution_operationally_verified": projected_items > 0,
                    "analysis_ready": projected_items > 0
                    and len(adapters) == len(snapshot.enabled_agents),
                    # A readiness probe has no request publisher to exclude.
                    # Requiring three eligible people conservatively proves
                    # two remain even when the publisher is in the roster.
                    "policy_publication_ready": len(approvers) >= 3,
                    "internal_intent_execution_ready": len(approvers) >= 3
                    and len(dispatchers) == len(snapshot.enabled_agents)
                    and state_health["database_integrity_verified"] is True,
                    "reference_state": state_health,
                }
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            result["error"] = type(exc).__name__
        return result


def install_governance_agents_composition(
    app: Any,
    *,
    tenant_snapshot_resolver: Callable[
        [str], agents.GovernanceAgentTenantSnapshot
    ] = agents.load_governance_agent_tenant_snapshot,
    roster_resolver: Callable[[str], Mapping[str, str]] = _default_roster_resolver,
    context_sources: Mapping[
        str,
        Callable[[str, str, int], agents.GovernanceContextItem | bytes],
    ]
    | None = None,
    binding_policy: ReferenceBindingPolicy | None = None,
    clock: Callable[[], float] = time.time,
) -> GovernanceAgentsReferenceComposition:
    """Attach all stock governance-agent seams to an ASGI application."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    existing = getattr(state, "governance_agents_reference_composition", None)
    if existing is not None:
        if not isinstance(existing, GovernanceAgentsReferenceComposition):
            raise GovernanceAgentsCompositionError(
                "governance-agent composition marker is invalid"
            )
        return existing
    composition = GovernanceAgentsReferenceComposition(
        tenant_snapshot_resolver=tenant_snapshot_resolver,
        roster_resolver=roster_resolver,
        binding_policy=binding_policy,
        clock=clock,
    )
    for source_kind, resolver in (context_sources or {}).items():
        composition.context_authority.register_source(source_kind, resolver)
    state.governance_agents_store_factory = composition.store_factory
    state.governance_agent_tenant_snapshot_resolver = composition.tenant_snapshot
    state.governance_agent_policy_approver_resolver = composition.policy_approvers
    state.governance_agent_context_resolver = composition.resolve_context
    state.governance_agent_adapter_resolver = composition.resolve_adapter
    state.governance_agent_dispatcher_resolver = composition.resolve_dispatcher
    state.governance_agent_execution_token_escrow = composition.escrow_token
    state.governance_agent_execution_token_resolver = composition.resolve_token
    state.governance_agent_context_authority = composition.context_authority
    state.governance_agent_composition_readiness = composition.readiness
    state.governance_agent_reference_maintenance = composition
    state.governance_agent_retention_runner = composition.purge_retention
    state.governance_agents_reference_composition = composition
    return composition


__all__ = [
    "DeterministicReferenceAnalysisAdapter",
    "EphemeralGovernanceContextAuthority",
    "GovernanceAgentsCompositionError",
    "GovernanceAgentsReferenceComposition",
    "ReferenceBindingPolicy",
    "ReferenceExecutionReceiptVerifier",
    "ReferenceInternalIntentDispatcher",
    "RoleBackedPolicyApproverAuthority",
    "governance_agent_principal_ref",
    "install_governance_agents_composition",
]
