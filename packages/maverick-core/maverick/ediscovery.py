"""Matter-scoped legal holds for eDiscovery.

A matter names custodians (principal ids), an optional date range and the
record kinds it preserves: goals and their runs, chat conversations,
attachments and approvals.  While a matter is active:

* every broad retention purge is refused for the whole workspace, because the
  stores cannot reliably map each record to a custodian;
* erasing a conversation closure is refused when that closure contains an
  in-scope record, with a plain message that names no matter.  Records outside
  the scope (other people, or dates outside the range) remain erasable.

The capability is off unless ``[ediscovery] enable = true``.  A matter recorded
while enabled keeps binding after the switch is turned off, so a hold cannot be
silently dropped by a configuration change.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory

RECORD_KINDS = ("goals", "chats", "attachments", "approvals")
STATUSES = ("active", "released")
MATTER_SCHEMA = "lightwork.ediscovery-matter.v1"
LEGAL_HOLD_MESSAGE = (
    "A legal hold applies to some of these records, so they cannot be erased. "
    "Ask your records administrator before trying again."
)
HOLD_UNVERIFIED_MESSAGE = (
    "Legal holds could not be checked, so nothing was deleted. Try again later or ask "
    "your records administrator."
)
BROAD_PURGE_MESSAGE = (
    "A legal hold is active in this workspace, so bulk deletion of old records is "
    "paused. Ask your records administrator to review the hold before trying again."
)
MAX_CUSTODIANS = 500
MAX_NAME = 200
MAX_DESCRIPTION = 2_000
MAX_SCOPE_ROWS = 100_000
_DAY = 86_400
_ID_RE = re.compile(r"mtr-[0-9a-f]{16}\Z")
_PRINCIPAL_RE = re.compile(r"[^\s\x00-\x1f\x7f]{1,256}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
# A linked messaging account, as stored by maverick.personal_identity.account_identity.
_ACCOUNT_RE = re.compile(r"account:[0-9a-f]{64}:person:[0-9a-f]{64}\Z")
# Any ``user:<channel>:account:`` text, whatever follows: such a custodian is refused, never
# narrowed silently to a single thread or to a channel identifier.
_CHANNEL_ACCOUNT_PREFIX_RE = re.compile(r"user:(?:[^\s:]+:)?account:")
# Room and thread histories append one digest to the account identity.
_THREAD_SUFFIX_RE = re.compile(r":conversation:[0-9a-f]{64}\Z")


class EdiscoveryError(RuntimeError):
    """Base class for matter failures that are safe to show to an operator."""


class EdiscoveryDisabled(EdiscoveryError):
    pass


class MatterValidationError(EdiscoveryError, ValueError):
    pass


class MatterNotFound(EdiscoveryError):
    pass


class MatterConflict(EdiscoveryError):
    pass


class MatterScopeUnverifiable(EdiscoveryError):
    """The records in scope could not be enumerated completely, so none may be erased."""


class LegalHoldApplies(EdiscoveryError):
    """Erasure or bulk deletion is refused by an active legal hold."""


class MatterExportError(EdiscoveryError):
    pass


class MatterExportTooLarge(MatterExportError):
    pass


def enabled() -> bool:
    """True only when ``[ediscovery] enable`` is explicitly true."""
    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    section = config.get("ediscovery") if isinstance(config, Mapping) else None
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise EdiscoveryDisabled("eDiscovery matters are disabled")


def store_path(tenant: str | None = None) -> Path:
    from .paths import data_dir

    if tenant is None:
        return data_dir("ediscovery", "legal-matters.sqlite3")
    return data_dir("ediscovery", "legal-matters.sqlite3", tenant=tenant)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---- validation -------------------------------------------------------------

def _text(value: object, label: str, limit: int, *, required: bool) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise MatterValidationError(f"{label} must be text")
    text = value.strip()
    if required and not text:
        raise MatterValidationError(f"{label} is required")
    if len(text) > limit:
        raise MatterValidationError(f"{label} must be {limit} characters or fewer")
    if _CONTROL_RE.search(text):
        raise MatterValidationError(f"{label} contains characters that are not allowed")
    return text


def _date(value: object, label: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
        raise MatterValidationError(f"{label} must be a date in YYYY-MM-DD form")
    try:
        _dt.date.fromisoformat(value)
    except ValueError as exc:
        raise MatterValidationError(f"{label} is not a real calendar date") from exc
    return value


def _principal_id(text: str) -> bool:
    """``user:<name>`` or ``user:<channel>:<identifier>``, with something after ``user:``."""
    if not text.startswith("user:") or not _PRINCIPAL_RE.fullmatch(text):
        return False
    rest = text[5:]
    return bool(rest) and not rest.startswith(":") and not rest.endswith(":")


def is_account_custodian(text: str) -> bool:
    """True for a linked messaging account written exactly as ``account:<hash>:person:<hash>``."""
    return _ACCOUNT_RE.fullmatch(text) is not None


def account_user_matches(conv_user_id: object, account: str) -> bool:
    """Whether a stored conversation belongs to the linked account ``account``.

    A linked account's chats are stored under the account identity itself, or under
    that identity followed by ``:conversation:<64 hex>`` for each room or thread.
    The colon is the boundary: a longer identifier that merely starts with the same
    text, or a bare substring, never matches.
    """
    if not isinstance(conv_user_id, str):
        return False
    if conv_user_id == account:
        return True
    return (conv_user_id.startswith(account)
            and _THREAD_SUFFIX_RE.fullmatch(conv_user_id, len(account)) is not None)


def _custodians(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise MatterValidationError("Add at least one custodian")
    if len(value) > MAX_CUSTODIANS:
        raise MatterValidationError(f"A matter can name at most {MAX_CUSTODIANS} custodians")
    found: set[str] = set()
    for item in value:
        text = item.strip() if isinstance(item, str) else ""
        if _CHANNEL_ACCOUNT_PREFIX_RE.match(text):
            raise MatterValidationError(
                "Write a linked messaging account as account:<hash>:person:<hash>, "
                "without the user: and channel parts")
        if not (_principal_id(text) or is_account_custodian(text)):
            raise MatterValidationError(
                "Each custodian must be a principal id such as user:name or user:channel:identifier, "
                "or a linked messaging account such as account:<hash>:person:<hash>")
        found.add(text)
    return sorted(found)


def _kinds(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise MatterValidationError("Choose at least one kind of record")
    if any(not isinstance(item, str) or item not in RECORD_KINDS for item in value):
        raise MatterValidationError("Choose only the listed kinds of record")
    if len(set(value)) != len(value):
        raise MatterValidationError("Each kind of record can be chosen once")
    return sorted(value)


def _day_start(text: str) -> float:
    moment = _dt.datetime.combine(_dt.date.fromisoformat(text), _dt.time(), tzinfo=_dt.timezone.utc)
    return moment.timestamp()


_REQUIRED_FIELDS = ("name", "custodians", "record_kinds")
_EDITABLE_FIELDS = frozenset({"name", "description", "custodians", "date_from", "date_to", "record_kinds"})


def normalize(values: Mapping[str, Any], *, partial: bool = False) -> dict[str, Any]:
    """Validate editable matter fields.  Only keys present in ``values`` are returned,
    so a partial edit never clears a field it did not mention.  Unknown keys are refused."""
    if set(values) - _EDITABLE_FIELDS:
        raise MatterValidationError("Unknown matter field")
    if not partial and any(key not in values for key in _REQUIRED_FIELDS):
        raise MatterValidationError("Name, custodians and record kinds are required")
    out: dict[str, Any] = {}
    if "name" in values:
        out["name"] = _text(values["name"], "Name", MAX_NAME, required=True)
    if "description" in values:
        out["description"] = _text(values["description"], "Description", MAX_DESCRIPTION, required=False)
    if "custodians" in values:
        out["custodians"] = _custodians(values["custodians"])
    if "record_kinds" in values:
        out["record_kinds"] = _kinds(values["record_kinds"])
    if "date_from" in values:
        out["date_from"] = _date(values["date_from"], "Start date")
    if "date_to" in values:
        out["date_to"] = _date(values["date_to"], "End date")
    return out


def _check_range(start: str | None, end: str | None) -> None:
    if start and end and start > end:
        raise MatterValidationError("The start date must be on or before the end date")


def bounds(matter: Mapping[str, Any]) -> tuple[float | None, float | None]:
    """Epoch bounds ``[start, end)`` for a matter's optional date range."""
    start = matter.get("date_from")
    end = matter.get("date_to")
    low = _day_start(start) if start else None
    high = _day_start(end) + _DAY if end else None
    return low, high


def in_range(moment: float, low: float | None, high: float | None) -> bool:
    return (low is None or moment >= low) and (high is None or moment < high)


# ---- durable ledger ---------------------------------------------------------

def _row_payload(row: sqlite3.Row | tuple, tenant: str) -> dict[str, Any]:
    tenant_id, matter_id, status, revision, payload_json, integrity = row
    if integrity != _digest(payload_json):
        raise EdiscoveryError("Legal matter records could not be verified")
    payload = json.loads(payload_json)
    if (payload.get("tenant_id") != tenant or tenant_id != tenant
            or payload.get("id") != matter_id or payload.get("status") != status
            or payload.get("revision") != revision):
        raise EdiscoveryError("Legal matter records could not be verified")
    return payload


class MatterStore:
    """Tenant-scoped matter ledger.  One integrity-checked row per matter revision."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        ensure_private_directory(self.path.parent)
        with self._connect() as connection:
            # Rollback journal, not WAL: a read never creates -wal or -shm files, so
            # checking holds does not change a removed workspace's erasure review.
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS matters("
                "tenant_id TEXT NOT NULL,matter_id TEXT NOT NULL,status TEXT NOT NULL,"
                "revision INTEGER NOT NULL,payload_json TEXT NOT NULL,"
                "integrity_sha256 TEXT NOT NULL,PRIMARY KEY(tenant_id,matter_id))"
            )

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
        finally:
            connection.close()

    @contextlib.contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            connection.execute("COMMIT")

    @staticmethod
    def _tenant(tenant: object) -> str:
        if not isinstance(tenant, str) or not tenant.strip():
            raise EdiscoveryError("An active workspace is required for legal matters")
        return tenant.strip()

    @staticmethod
    def _matter_id(value: object) -> str:
        if not isinstance(value, str) or not _ID_RE.fullmatch(value):
            raise MatterNotFound("That matter was not found.")
        return value

    def _save(self, connection: sqlite3.Connection, tenant: str, payload: dict[str, Any]) -> dict[str, Any]:
        encoded = _canonical(payload)
        connection.execute(
            "INSERT INTO matters(tenant_id,matter_id,status,revision,payload_json,integrity_sha256) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(tenant_id,matter_id) DO UPDATE SET "
            "status=excluded.status,revision=excluded.revision,payload_json=excluded.payload_json,"
            "integrity_sha256=excluded.integrity_sha256",
            (tenant, payload["id"], payload["status"], payload["revision"], encoded, _digest(encoded)),
        )
        return payload

    def _audit(self, verb: str, *, matter_id: str, actor: str, revision: int, **detail: Any) -> None:
        from .audit import EventKind, audit_event

        written = audit_event(
            EventKind.CONTROL_PLANE_ACTION, agent="ediscovery", verb=verb,
            matter_id=matter_id, actor=actor, revision=revision, **detail,
        )
        if not written:
            raise EdiscoveryError("The change was not saved because its audit record could not be written.")

    def create(self, tenant: object, *, actor: str, values: Mapping[str, Any]) -> dict[str, Any]:
        tenant_id = self._tenant(tenant)
        fields = normalize(values)
        _check_range(fields.get("date_from"), fields.get("date_to"))
        now = float(self._clock())
        matter_id = "mtr-" + secrets.token_hex(8)
        payload = {
            "schema": MATTER_SCHEMA, "id": matter_id, "tenant_id": tenant_id, "revision": 1,
            "status": "active", "name": fields["name"], "description": fields.get("description", ""),
            "custodians": fields["custodians"], "date_from": fields.get("date_from"),
            "date_to": fields.get("date_to"), "record_kinds": fields["record_kinds"],
            "created_by": actor, "created_at": now, "updated_by": actor, "updated_at": now,
            "released_by": None, "released_at": None,
        }
        with self._write() as connection:
            self._audit("ediscovery_matter_created", matter_id=matter_id, actor=actor, revision=1,
                        record_kinds=payload["record_kinds"], custodian_count=len(payload["custodians"]),
                        has_date_range=bool(payload["date_from"] or payload["date_to"]))
            return self._save(connection, tenant_id, payload)

    def update(self, tenant: object, matter_id: object, *, actor: str, expected_revision: int,
               values: Mapping[str, Any]) -> dict[str, Any]:
        tenant_id = self._tenant(tenant)
        matter_id = self._matter_id(matter_id)
        fields = normalize(values, partial=True)
        if not fields:
            raise MatterValidationError("Change at least one field")
        with self._write() as connection:
            current = self._load(connection, tenant_id, matter_id)
            self._check_revision(current, expected_revision)
            payload = {**current, **fields}
            _check_range(payload.get("date_from"), payload.get("date_to"))
            payload.update(revision=current["revision"] + 1, updated_by=actor, updated_at=float(self._clock()))
            self._audit("ediscovery_matter_edited", matter_id=matter_id, actor=actor,
                        revision=payload["revision"], changed=sorted(fields))
            return self._save(connection, tenant_id, payload)

    def record_read(self, *, actor: str, verb: str, matter_id: str = "", revision: int = 0, shown: int = 0) -> None:
        """Audit a reading of matter details.  The record names no custodian and no matter definition.

        Fails closed: the details are not shown when their access record cannot be written.
        """
        from .audit import EventKind, audit_event

        written = audit_event(EventKind.CONTROL_PLANE_ACTION, agent="ediscovery", verb=verb,
                              matter_id=matter_id, actor=actor, revision=revision, shown=shown)
        if not written:
            raise EdiscoveryError("Matter details were not shown because their access record could not be written.")

    def release(self, tenant: object, matter_id: object, *, actor: str, expected_revision: int) -> dict[str, Any]:
        tenant_id = self._tenant(tenant)
        matter_id = self._matter_id(matter_id)
        with self._write() as connection:
            current = self._load(connection, tenant_id, matter_id)
            self._check_revision(current, expected_revision)
            now = float(self._clock())
            payload = {**current, "status": "released", "revision": current["revision"] + 1,
                       "updated_by": actor, "updated_at": now, "released_by": actor, "released_at": now}
            self._audit("ediscovery_matter_released", matter_id=matter_id, actor=actor,
                        revision=payload["revision"])
            return self._save(connection, tenant_id, payload)

    @staticmethod
    def _check_revision(current: Mapping[str, Any], expected: object) -> None:
        if type(expected) is not int or expected < 1:
            raise MatterValidationError("expected_revision must be a positive whole number")
        if current["status"] != "active":
            raise MatterConflict("This matter was released and can no longer be changed.")
        if expected != current["revision"]:
            raise MatterConflict("This matter changed. Reload it and review the latest version.")

    @staticmethod
    def _load(connection: sqlite3.Connection, tenant: str, matter_id: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT tenant_id,matter_id,status,revision,payload_json,integrity_sha256 FROM matters "
            "WHERE tenant_id=? AND matter_id=?",
            (tenant, matter_id),
        ).fetchone()
        if row is None:
            raise MatterNotFound("That matter was not found.")
        return _row_payload(tuple(row), tenant)

    def get(self, tenant: object, matter_id: object) -> dict[str, Any]:
        tenant_id = self._tenant(tenant)
        matter_id = self._matter_id(matter_id)
        with self._connect() as connection:
            return self._load(connection, tenant_id, matter_id)

    def list(self, tenant: object, *, limit: int = 500) -> list[dict[str, Any]]:
        tenant_id = self._tenant(tenant)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT tenant_id,matter_id,status,revision,payload_json,integrity_sha256 FROM matters "
                "WHERE tenant_id=? ORDER BY matter_id LIMIT ?",
                (tenant_id, max(1, min(int(limit), 1_000))),
            ).fetchall()
        return [_row_payload(tuple(row), tenant_id) for row in rows]


def _active_rows(path: Path, tenant: str) -> list[dict[str, Any]]:
    """Read active matters without creating the ledger.  Missing ledger means none."""
    if not path.exists():
        return []
    with contextlib.closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
        # A file without the ledger table was never a matter ledger, so it holds no matters.
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='matters'"
        ).fetchone()
        if table is None:
            return []
        rows = connection.execute(
            "SELECT tenant_id,matter_id,status,revision,payload_json,integrity_sha256 FROM matters "
            "WHERE tenant_id=? AND status='active' ORDER BY matter_id",
            (tenant,),
        ).fetchall()
    return [_row_payload(tuple(row), tenant) for row in rows]


def active_matters() -> list[dict[str, Any]]:
    """Active matters of the current workspace.  Reads even when the feature is
    disabled, so a hold recorded earlier keeps binding.  A missing ledger is empty."""
    from .paths import current_tenant_id

    return _active_rows(store_path(), current_tenant_id() or "")


def active_matter_count() -> int:
    return len(active_matters())


def assert_no_active_matters() -> None:
    """Refuse a broad purge while any matter is active in the current workspace."""
    try:
        count = active_matter_count()
    except Exception as exc:  # failure-policy: fail_closed -- an unreadable ledger holds everything
        raise LegalHoldApplies(HOLD_UNVERIFIED_MESSAGE) from exc
    if count:
        raise LegalHoldApplies(BROAD_PURGE_MESSAGE)


# ---- scope --------------------------------------------------------------------

def _bounded(rows: Sequence[Any], label: str) -> list[Any]:
    if len(rows) > MAX_SCOPE_ROWS:
        raise MatterScopeUnverifiable(f"The {label} for this matter exceed the review window")
    return list(rows)


def conversation_user_matches(conv_user_id: object, requested: str, channel: str) -> bool:
    """Whether a stored conversation belongs to the subject ``requested`` on ``channel``.

    Most channels store externally supplied user ids and must match exactly:
    identifiers such as Twilio WhatsApp ``whatsapp:+15551234567`` or Matrix
    room ids naturally contain colons, so treating any ``<prefix>:`` as the
    requested user can disclose or erase unrelated conversations.

    The only family match is the local CLI chat namespace: each REPL session is
    stored as ``local:<uuid>``, while the documented GDPR subject is
    ``--channel cli --user local``.  The CLI erase, the admin erase and matter
    scope all use this rule.
    """
    if conv_user_id == requested:
        return True
    return channel == "cli" and requested == "local" and str(conv_user_id).startswith("local:")


def _goal_owners(custodian: str) -> list[str]:
    """The exact goal owners that belong to one custodian.

    A linked account's tasks are owned by ``user:<channel>:<account identity>`` on
    each messaging channel that can hold one (the channels that link accounts).
    """
    if not is_account_custodian(custodian):
        return [custodian]
    from .personal_identity import CHANNELS

    return [f"user:{channel}:{custodian}" for channel in sorted(CHANNELS)]


def _incident_principal_refs(custodians: Iterable[str], tenant: str) -> set[str]:
    """Uploader references of the ``user:`` custodians (linked accounts never upload to incidents)."""
    from .incident_attachment_metadata import principal_ref_for_subject

    return {principal_ref_for_subject(tenant, owner) for owner in custodians if owner.startswith("user:")}


def _incident_attachments(custodians: Sequence[str], tenant: str | None,
                          low: float | None, high: float | None) -> list[Any]:
    """Incident attachment records uploaded by a custodian, inside the matter's dates.

    The register is read in the active workspace, so the matter's own workspace must be
    the active one.  Fails closed: a register that cannot be listed completely, or a
    matter whose workspace is not the active one, refuses the matter's scope.
    """
    from .paths import current_tenant_id

    if not any(owner.startswith("user:") for owner in custodians):
        return []  # only dashboard users upload incident attachments
    if not tenant or tenant != current_tenant_id():
        raise MatterScopeUnverifiable("The incident attachments for this matter could not be listed completely")
    refs = _incident_principal_refs(custodians, tenant)
    from .incident_attachment_metadata import records_for_principal_refs

    try:
        rows = records_for_principal_refs(tenant, refs)
    except Exception as exc:  # failure-policy: fail_closed -- a partial list would hide held records
        raise MatterScopeUnverifiable("The incident attachments for this matter could not be listed completely") from exc
    return [row for row in rows if in_range(float(row.created_at), low, high)]


def _custodian_goals(world: Any, owner: str, scope: Scope, kinds: set[str],
                     low: float | None, high: float | None) -> None:
    for goal_owner in _goal_owners(owner):
        for goal in _bounded(world.list_goals(owner=goal_owner, limit=MAX_SCOPE_ROWS + 1), "goals"):
            scope.custodian_goal_ids.add(int(goal.id))
            if "goals" in kinds and goal.owner == goal_owner and in_range(float(goal.created_at), low, high):
                scope.goals[int(goal.id)] = goal


def _custodian_runs(world: Any, owner: str, scope: Scope, low: float | None, high: float | None) -> None:
    for goal_owner in _goal_owners(owner):
        for run in _bounded(world.list_episodes(limit=MAX_SCOPE_ROWS + 1, owner=goal_owner), "runs"):
            if in_range(float(run.started_at), low, high):
                scope.runs.append(run)


def _custodian_conversations(world: Any, owner: str, cache: dict[str | None, list[Any]]) -> list[Any]:
    """Conversations of one custodian.  Channel conversations are ``user:<channel>:<id>``;
    a dashboard user ``user:<name>`` is the dashboard conversation of that name; a linked
    account is matched across every channel by its stored identity (see :func:`account_user_matches`)."""
    if is_account_custodian(owner):
        if None not in cache:
            cache[None] = _bounded(world.list_conversations(), "chats")
        return [conv for conv in cache[None] if account_user_matches(conv.user_id, owner)]
    parts = owner.split(":", 2) if owner.startswith("user:") else []
    if len(parts) == 3 and parts[1] and parts[2]:
        channel, user_id = parts[1], parts[2]
    elif len(parts) == 2 and parts[1]:
        channel, user_id = "dashboard", parts[1]
    else:
        return []
    if channel not in cache:
        cache[channel] = list(world.list_conversations(channel))
    return [conv for conv in cache[channel] if conversation_user_matches(conv.user_id, user_id, channel)]


@dataclass
class Scope:
    """Every record of one matter that falls inside its custodians, kinds and dates."""

    goals: dict[int, Any] = field(default_factory=dict)
    runs: list[Any] = field(default_factory=list)
    conversations: dict[int, tuple[Any, list[Any]]] = field(default_factory=dict)
    attachments: list[Any] = field(default_factory=list)
    # Incident attachment records uploaded by a custodian (metadata only; the bytes are not here).
    incident_attachments: list[Any] = field(default_factory=list)
    approvals: list[Any] = field(default_factory=list)
    custodian_goal_ids: set[int] = field(default_factory=set)
    # (custodian, record) pairs from the employee companion and the conversation inbox.
    companion_exchanges: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    inbox_items: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def conversation_ids(self) -> set[int]:
        return set(self.conversations)

    def goal_ids(self) -> set[int]:
        """Goals that an erasure would delete: goals, their runs and their attachments."""
        return (set(self.goals) | {int(run.goal_id) for run in self.runs}
                | {int(att.goal_id) for att in self.attachments})


def _companion_exchanges(owner: str) -> list[dict[str, Any]]:
    """Every saved companion exchange of one employee, read without changing anything."""
    from .employee_companion import EmployeeCompanionStore

    return EmployeeCompanionStore().held_exchanges(owner)


def _inbox_items(owner: str) -> list[dict[str, Any]]:
    """Every message still held for one person in the conversation inbox."""
    from .conversation_inbox import owned_items

    return owned_items(owner)


def _personal_chats(scope: Scope, custodians: Sequence[str], low: float | None, high: float | None) -> None:
    for owner in custodians:
        if is_account_custodian(owner):
            continue  # companion history and inbox messages belong to dashboard users, not channel accounts
        for exchange in _bounded(_companion_exchanges(owner), "chats"):
            if in_range(float(exchange["time"]), low, high):
                scope.companion_exchanges.append((owner, exchange))
        for item in _bounded(_inbox_items(owner), "chats"):
            if in_range(float(item["created_at"]), low, high):
                scope.inbox_items.append((owner, item))


def build_scope(world: Any, matter: Mapping[str, Any], *, for_erasure: bool = False) -> Scope:
    """Enumerate the in-scope records of ``matter``.  Fails closed when incomplete.

    Companion exchanges and inbox messages are part of the export only.  An erasure
    of a channel closure does not remove them, so the erasure check skips them.
    """
    custodians = list(matter["custodians"])
    kinds = set(matter["record_kinds"])
    low, high = bounds(matter)
    scope = Scope()
    for owner in custodians:
        _custodian_goals(world, owner, scope, kinds, low, high)
    if "goals" in kinds:
        for owner in custodians:
            _custodian_runs(world, owner, scope, low, high)
    if "chats" in kinds:
        cache: dict[str | None, list[Any]] = {}
        for owner in custodians:
            for conv in _custodian_conversations(world, owner, cache):
                turns = _bounded(world.recent_turns(int(conv.id), limit=MAX_SCOPE_ROWS + 1), "chats")
                kept = [turn for turn in turns if in_range(float(turn.ts), low, high)]
                if kept or (low is None and high is None):
                    scope.conversations[int(conv.id)] = (conv, kept)
        if not for_erasure:
            _personal_chats(scope, custodians, low, high)
    if "attachments" in kinds:
        for goal_id in sorted(scope.custodian_goal_ids):
            for attachment in world.list_attachments(goal_id):
                if in_range(float(attachment.created_at), low, high):
                    scope.attachments.append(attachment)
        if not for_erasure:
            scope.incident_attachments = _incident_attachments(custodians, matter.get("tenant_id"), low, high)
    if "approvals" in kinds and not for_erasure:
        owners = {goal_owner for owner in custodians for goal_owner in _goal_owners(owner)}
        for approval in _bounded(world.list_approvals(limit=MAX_SCOPE_ROWS + 1), "approvals"):
            linked = approval.requested_by in owners or approval.goal_id in scope.custodian_goal_ids
            if linked and in_range(float(approval.requested_at), low, high):
                scope.approvals.append(approval)
    return scope


def _audit_refusal(matter: Mapping[str, Any], *, actor: str, **sizes: int) -> None:
    from .audit import AuditRefused, EventKind, audit_event

    # Recorded for the audit reader; the refusal stands even if this record cannot be written.
    # The caller raises its hold refusal next, so an audit refusal here must not replace it.
    try:
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="ediscovery", verb="ediscovery_erasure_refused",
                    matter_id=matter["id"], actor=actor, **sizes)
    except AuditRefused:
        pass


def personal_holds(owner: str) -> list[dict[str, Any]]:
    """Active matters that name ``owner`` as a custodian and keep chat records.

    Fails closed: an unreadable ledger raises :class:`LegalHoldApplies`.
    """
    try:
        matters = active_matters()
    except Exception as exc:  # failure-policy: fail_closed -- an unreadable ledger holds everything
        raise LegalHoldApplies(HOLD_UNVERIFIED_MESSAGE) from exc
    return [matter for matter in matters
            if "chats" in matter["record_kinds"] and owner in matter["custodians"]]


def assert_personal_chats_erasable(owner: str, times: Iterable[float], *, actor: str = "system") -> None:
    """Refuse erasing an employee's companion or inbox records that a matter holds in scope.

    ``times`` are the timestamps of the records the erasure would remove.  Only the
    in-scope records block the erasure, and each refusal is audited with the actor
    and a count, never content.
    """
    stamps = [float(stamp) for stamp in times]
    for matter in personal_holds(owner):
        low, high = bounds(matter)
        inside = sum(1 for stamp in stamps if in_range(stamp, low, high))
        if inside:
            _audit_refusal(matter, actor=actor, chat_records=inside)
            raise LegalHoldApplies(LEGAL_HOLD_MESSAGE)


def personal_hold_windows(owner: str) -> list[tuple[float | None, float | None]]:
    """Date windows of the matters that hold ``owner``'s chat records (see :func:`personal_holds`)."""
    return [bounds(matter) for matter in personal_holds(owner)]


def in_hold(moment: float, windows: Sequence[tuple[float | None, float | None]]) -> bool:
    return any(in_range(moment, low, high) for low, high in windows)


def assert_erasure_permitted(world: Any, *, conversation_ids: Sequence[int], goal_ids: Sequence[int],
                             actor: str = "system") -> None:
    """Refuse an erasure closure that contains any in-scope record of an active matter.

    Approvals are never deleted by an erasure, so they are not part of the closure
    check.  Any failure to enumerate a matter's scope refuses the erasure.  Each
    refusal is audited with the acting principal and closure sizes, never content.
    """
    try:
        matters = active_matters()
    except Exception as exc:  # failure-policy: fail_closed -- an unreadable ledger holds everything
        raise LegalHoldApplies(HOLD_UNVERIFIED_MESSAGE) from exc
    if not matters:
        return
    wanted_conversations = {int(item) for item in conversation_ids}
    wanted_goals = {int(item) for item in goal_ids}
    for matter in matters:
        try:
            scope = build_scope(world, matter, for_erasure=True)
        except MatterScopeUnverifiable as exc:
            raise LegalHoldApplies(LEGAL_HOLD_MESSAGE) from exc
        except Exception as exc:  # failure-policy: fail_closed -- unknown read failures refuse erasure
            raise LegalHoldApplies(HOLD_UNVERIFIED_MESSAGE) from exc
        if wanted_conversations & scope.conversation_ids() or wanted_goals & scope.goal_ids():
            _audit_refusal(matter, actor=actor, conversations=len(wanted_conversations), goals=len(wanted_goals))
            raise LegalHoldApplies(LEGAL_HOLD_MESSAGE)


def incident_attachment_refusal(tenant_id: str, *, principal_ref: str, created_at: float,
                                actor: str = "system") -> str | None:
    """The plain refusal text when an active matter holds one incident attachment, or ``None``.

    An attachment is held when its uploader is a ``user:`` custodian of a matter that
    keeps attachments and its upload time falls in the matter's dates.  The matters are
    those of ``tenant_id`` (the attachment's workspace), whichever workspace is active.
    An unreadable matter ledger holds every attachment.  Each refusal is audited with the
    actor and a count, never content.
    """
    try:
        matters = _active_rows(store_path(tenant_id), tenant_id)
    except Exception:  # failure-policy: fail_closed -- an unreadable ledger holds everything
        return HOLD_UNVERIFIED_MESSAGE
    for matter in matters:
        if "attachments" not in matter["record_kinds"]:
            continue
        if principal_ref not in _incident_principal_refs(matter["custodians"], tenant_id):
            continue
        low, high = bounds(matter)
        if in_range(float(created_at), low, high):
            _audit_refusal(matter, actor=actor, attachments=1)
            return LEGAL_HOLD_MESSAGE
    return None


def erasure_refusal(world: Any, *, conversation_ids: Sequence[int], goal_ids: Sequence[int],
                    actor: str = "system") -> str | None:
    """The plain refusal text for an erasure closure, or ``None`` when it may proceed."""
    try:
        assert_erasure_permitted(world, conversation_ids=conversation_ids, goal_ids=goal_ids, actor=actor)
    except LegalHoldApplies as exc:
        return str(exc)
    return None


__all__ = [
    "BROAD_PURGE_MESSAGE",
    "EdiscoveryDisabled",
    "EdiscoveryError",
    "HOLD_UNVERIFIED_MESSAGE",
    "LEGAL_HOLD_MESSAGE",
    "LegalHoldApplies",
    "MatterConflict",
    "MatterExportError",
    "MatterExportTooLarge",
    "MatterNotFound",
    "MatterScopeUnverifiable",
    "MatterStore",
    "MatterValidationError",
    "RECORD_KINDS",
    "STATUSES",
    "active_matter_count",
    "active_matters",
    "assert_erasure_permitted",
    "assert_no_active_matters",
    "assert_personal_chats_erasable",
    "build_scope",
    "account_user_matches",
    "conversation_user_matches",
    "enabled",
    "erasure_refusal",
    "incident_attachment_refusal",
    "in_hold",
    "is_account_custodian",
    "normalize",
    "personal_hold_windows",
    "personal_holds",
    "require_enabled",
    "store_path",
]
