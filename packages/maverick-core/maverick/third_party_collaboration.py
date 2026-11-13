"""Provider-neutral external collaboration for third-party assessments.

The lifecycle assessment remains the sole authority for questions, respondent
assignments, answers, evaluation, scoring, remediation, and decisions.  This
module adds only an invitation-scoped collaboration plane: exact authority
pins, digest-only artifact manifests, recoverable drafts, attested final batch
submission, and internal follow-up/reopen controls.

Evidence manifests are server-measured: ``measure_evidence`` receives one
file's bytes, computes its SHA-256, size and content-derived media type, keeps
only that measurement bound to the invitation, and discards the bytes.  Drafts
and final submissions accept a manifest only when it matches such a
measurement exactly, so respondent-declared sizes and digests are never
trusted.

It deliberately implements no network or email transport, identity proofing,
model inference, document byte storage, malware scanning, commercial content,
provider write, risk conclusion, or vendor approval.
"""

from __future__ import annotations

import base64
import codecs
import contextlib
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import third_party_lifecycle as lifecycle
from .file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
INVITATION_SCHEMA = "lightwork.third-party-collaboration-invitation.v1"
DRAFT_SCHEMA = "lightwork.third-party-collaboration-draft.v1"
HISTORY_SCHEMA = "lightwork.third-party-collaboration-history.v1"
CONTRACT_SCHEMA = "lightwork.third-party-collaboration-contract.v1"
RECEIPT_SCHEMA = "lightwork.third-party-collaboration-receipt.v1"
EVIDENCE_MEASUREMENT_SCHEMA = "lightwork.third-party-collaboration-evidence-measurement.v1"

NETWORK_TRANSPORT_IMPLEMENTED = False
EMAIL_DELIVERY_IMPLEMENTED = False
MODEL_INFERENCE_IMPLEMENTED = False
# Evidence bytes are measured in memory by measure_evidence and never stored.
UPLOAD_BYTES_IMPLEMENTED = False
VENDOR_ATTESTATIONS_INDEPENDENTLY_VERIFIED = False

_TOKEN_PREFIX = "tpc1."
_TOKEN_RE = re.compile(r"tpc1\.[A-Za-z0-9_-]{43}\Z")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_QUESTIONS = 1_000
_MAX_ARTIFACTS = 100
_MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
_MIN_EXPIRY_SECONDS = 5 * 60
_MAX_EXPIRY_SECONDS = 90 * 24 * 60 * 60
_MIN_RETENTION_SECONDS = 60 * 60
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
# One invitation may have its files checked this many times in total (repeat
# checks of the same file reuse one record), which bounds what a respondent can
# make the server store.
_MAX_EVIDENCE_MEASUREMENTS = 250
_EVIDENCE_SNIFF_BYTES = 65_536
_EXTENSION_RE = re.compile(r"[a-z0-9]{1,10}\Z")

INVITATION_STATES = frozenset(
    {
        "active",
        "finalizing",
        "finalized",
        "follow_up_required",
        "revoked",
        "conflicted",
    }
)
ARTIFACT_KINDS = frozenset(
    {
        "audit_report",
        "certification",
        "policy",
        "questionnaire",
        "test_report",
        "other_evidence",
    }
)


class ThirdPartyCollaborationError(RuntimeError):
    """Base error for the provider-neutral collaboration authority."""


class ThirdPartyCollaborationConfigError(ThirdPartyCollaborationError):
    """The collaboration portal's complete governing gate is disabled."""


class ThirdPartyCollaborationAuthError(ThirdPartyCollaborationError):
    """An invitation credential is invalid, expired, rotated, or unavailable."""


class ThirdPartyCollaborationConflict(ThirdPartyCollaborationError):
    """A CAS, idempotency, authority, or lifecycle state precondition failed."""


class ThirdPartyCollaborationIntegrityError(ThirdPartyCollaborationError):
    """Persisted collaboration state failed verification."""


class ThirdPartyCollaborationNotFound(ThirdPartyCollaborationError):
    """A tenant-scoped collaboration record was not found."""


class ThirdPartyCollaborationPermissionDenied(ThirdPartyCollaborationError):
    """The authenticated internal principal cannot perform an operation."""


class ThirdPartyCollaborationValidationError(ThirdPartyCollaborationError, ValueError):
    """Input is outside the collaboration authority's closed schemas."""


def enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Require exact parent, lifecycle, and collaboration-portal gates."""

    if config is None:
        try:
            from .config import config_source_errors, load_config

            if config_source_errors():
                return False
            config = load_config()
        except Exception:
            return False
    if not isinstance(config, Mapping):
        return False
    third_party = config.get("third_party_management")
    lifecycle_config = (
        third_party.get("lifecycle") if isinstance(third_party, Mapping) else None
    )
    portal = (
        lifecycle_config.get("portal")
        if isinstance(lifecycle_config, Mapping)
        else None
    )
    return (
        isinstance(third_party, Mapping)
        and third_party.get("enable") is True
        and isinstance(lifecycle_config, Mapping)
        and lifecycle_config.get("enable") is True
        and isinstance(portal, Mapping)
        and portal.get("enable") is True
    )


def require_enabled() -> None:
    """Fail closed until the portal and its lifecycle authority are enabled."""

    if not enabled():
        raise ThirdPartyCollaborationConfigError(
            "third-party collaboration is disabled; explicitly enable "
            "third_party_management.lifecycle.portal"
        )


@dataclass(frozen=True)
class ThirdPartyCollaborationPolicy:
    """Frozen deployment limits for one tenant's external portal."""

    invitation_ttl_seconds: int = 86_400
    retention_seconds: int = 31_536_000
    max_messages: int = 100
    max_artifacts: int = 20
    max_artifact_bytes: int = 10_485_760

    def normalized(self) -> ThirdPartyCollaborationPolicy:
        return ThirdPartyCollaborationPolicy(
            invitation_ttl_seconds=_integer(
                self.invitation_ttl_seconds,
                "portal invitation_ttl_seconds",
                _MIN_EXPIRY_SECONDS,
                _MAX_EXPIRY_SECONDS,
            ),
            retention_seconds=_integer(
                self.retention_seconds,
                "portal retention_seconds",
                _MIN_RETENTION_SECONDS,
                _MAX_RETENTION_SECONDS,
            ),
            max_messages=_integer(
                self.max_messages,
                "portal max_messages",
                1,
                1_000,
            ),
            max_artifacts=_integer(
                self.max_artifacts,
                "portal max_artifacts",
                0,
                _MAX_ARTIFACTS,
            ),
            max_artifact_bytes=_integer(
                self.max_artifact_bytes,
                "portal max_artifact_bytes",
                1_024,
                _MAX_ARTIFACT_BYTES,
            ),
        )


def load_policy(config: Mapping[str, Any] | None = None) -> ThirdPartyCollaborationPolicy:
    """Load the exact enabled portal contract; invalid values fail closed."""

    if config is None:
        try:
            from .config import config_source_errors, load_config

            if config_source_errors():
                raise ThirdPartyCollaborationConfigError(
                    "third-party collaboration configuration is unavailable"
                )
            config = load_config()
        except ThirdPartyCollaborationConfigError:
            raise
        except Exception as exc:
            raise ThirdPartyCollaborationConfigError(
                "third-party collaboration configuration is unavailable"
            ) from exc
    if not enabled(config):
        raise ThirdPartyCollaborationConfigError(
            "third-party collaboration portal is disabled"
        )
    third_party = config["third_party_management"]
    lifecycle_config = third_party["lifecycle"]  # type: ignore[index]
    portal = lifecycle_config["portal"]  # type: ignore[index]
    try:
        return ThirdPartyCollaborationPolicy(
            invitation_ttl_seconds=portal.get("invitation_ttl_seconds", 86_400),
            retention_seconds=portal.get("retention_seconds", 31_536_000),
            max_messages=portal.get("max_messages", 100),
            max_artifacts=portal.get("max_artifacts", 20),
            max_artifact_bytes=portal.get("max_artifact_bytes", 10_485_760),
        ).normalized()
    except ThirdPartyCollaborationValidationError as exc:
        raise ThirdPartyCollaborationConfigError(
            "third-party collaboration portal limits are invalid"
        ) from exc


@dataclass(frozen=True)
class InvitationIssue:
    invitation: Mapping[str, object]
    token: str | None
    token_disclosed: bool
    idempotent_replay: bool


@dataclass(frozen=True)
class DraftReceipt:
    tenant_id: str
    invitation_id: str
    revision: int
    draft_sha256: str
    active_question_ids: tuple[str, ...]
    required_question_ids: tuple[str, ...]
    artifact_count: int
    idempotent_replay: bool


@dataclass(frozen=True)
class FinalSubmissionReceipt:
    schema: str
    tenant_id: str
    invitation_id: str
    assessment_id: str
    assessment_revision: int
    assessment_integrity_sha256: str
    question_ids: tuple[str, ...]
    attestation_sha256: str
    evidence_status: str
    idempotent_replay: bool


@dataclass(frozen=True)
class EvidenceMeasurement:
    tenant_id: str
    invitation_id: str
    artifact_id: str
    content_sha256: str
    size_bytes: int
    media_type_ref: str
    idempotent_replay: bool


@dataclass(frozen=True)
class CollaborationIntegrityVerification:
    tenant_id: str
    verified_records: int
    history_events: int
    terminal_history_sha256: str


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ThirdPartyCollaborationValidationError(
            "collaboration state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise ThirdPartyCollaborationValidationError(
            "collaboration state exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ThirdPartyCollaborationValidationError("tenant_id is invalid") from exc


def _id(value: object, label: str, pattern: re.Pattern[str] = _ID_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ThirdPartyCollaborationValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ThirdPartyCollaborationValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ThirdPartyCollaborationValidationError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise ThirdPartyCollaborationValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _closed(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ThirdPartyCollaborationValidationError(f"{label} schema is closed")
    return value


def _sequence(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_QUESTIONS,
) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ThirdPartyCollaborationValidationError(f"{label} must be a list")
    if not minimum <= len(value) <= maximum:
        raise ThirdPartyCollaborationValidationError(
            f"{label} must contain between {minimum} and {maximum} values"
        )
    return value


def _ids(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_QUESTIONS,
) -> tuple[str, ...]:
    values = tuple(
        _id(item, label) for item in _sequence(value, label, minimum=minimum, maximum=maximum)
    )
    if len(set(values)) != len(values):
        raise ThirdPartyCollaborationValidationError(f"{label} contains duplicates")
    return values


def _json_value(value: object) -> object:
    try:
        return lifecycle._validate_json_scalar(value, "response")  # noqa: SLF001
    except lifecycle.ThirdPartyLifecycleValidationError as exc:
        raise ThirdPartyCollaborationValidationError(str(exc)) from exc


def _artifact_policy(value: object) -> dict[str, object]:
    item = _closed(
        value,
        "artifact policy",
        frozenset({"allowed_kinds", "maximum_artifacts", "maximum_total_bytes"}),
    )
    kinds = _ids(
        item["allowed_kinds"],
        "artifact kind",
        maximum=len(ARTIFACT_KINDS),
    )
    if not set(kinds).issubset(ARTIFACT_KINDS):
        raise ThirdPartyCollaborationValidationError("artifact kind is unsupported")
    maximum_artifacts = _integer(
        item["maximum_artifacts"],
        "maximum_artifacts",
        0,
        _MAX_ARTIFACTS,
    )
    maximum_total_bytes = _integer(
        item["maximum_total_bytes"],
        "maximum_total_bytes",
        0,
        _MAX_ARTIFACT_BYTES,
    )
    if maximum_artifacts == 0 and (kinds or maximum_total_bytes):
        raise ThirdPartyCollaborationValidationError(
            "a zero-artifact policy cannot allow kinds or bytes"
        )
    if maximum_artifacts > 0 and (not kinds or maximum_total_bytes == 0):
        raise ThirdPartyCollaborationValidationError(
            "an artifact policy requires kinds and a positive byte bound"
        )
    return {
        "allowed_kinds": list(kinds),
        "maximum_artifacts": maximum_artifacts,
        "maximum_total_bytes": maximum_total_bytes,
    }


def _artifact_manifests(
    value: object,
    policy: Mapping[str, object],
) -> tuple[dict[str, object], ...]:
    raw = _sequence(
        value,
        "artifact manifests",
        maximum=int(policy["maximum_artifacts"]),
    )
    artifacts: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    total_bytes = 0
    allowed = set(policy["allowed_kinds"])  # type: ignore[arg-type]
    for raw_item in raw:
        item = _closed(
            raw_item,
            "artifact manifest",
            frozenset(
                {
                    "artifact_id",
                    "kind",
                    "content_sha256",
                    "size_bytes",
                    "media_type_ref",
                }
            ),
        )
        artifact_id = _id(item["artifact_id"], "artifact_id")
        if artifact_id in seen_ids:
            raise ThirdPartyCollaborationValidationError("artifact manifests contain duplicate IDs")
        kind = _id(item["kind"], "artifact kind")
        if kind not in allowed:
            raise ThirdPartyCollaborationValidationError(
                "artifact kind is not allowed by the invitation"
            )
        size_bytes = _integer(
            item["size_bytes"],
            "artifact size_bytes",
            1,
            _MAX_ARTIFACT_BYTES,
        )
        total_bytes += size_bytes
        seen_ids.add(artifact_id)
        artifacts.append(
            {
                "artifact_id": artifact_id,
                "kind": kind,
                "content_sha256": _digest(
                    item["content_sha256"],
                    "artifact content_sha256",
                ),
                "size_bytes": size_bytes,
                "media_type_ref": _id(item["media_type_ref"], "media_type_ref"),
            }
        )
    if total_bytes > int(policy["maximum_total_bytes"]):
        raise ThirdPartyCollaborationValidationError(
            "artifact manifests exceed the invitation byte bound"
        )
    return tuple(artifacts)


_OOXML_MEDIA = (
    (b"word/", "application.vnd.openxmlformats-officedocument.wordprocessingml.document"),
    (b"xl/", "application.vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    (b"ppt/", "application.vnd.openxmlformats-officedocument.presentationml.presentation"),
)
_ZIP_EXTENSION_MEDIA = {
    "docx": "application.vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application.vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application.vnd.openxmlformats-officedocument.presentationml.presentation",
    "odt": "application.vnd.oasis.opendocument.text",
    "ods": "application.vnd.oasis.opendocument.spreadsheet",
    "odp": "application.vnd.oasis.opendocument.presentation",
}
_ODF_MEDIA = (
    (b"application/vnd.oasis.opendocument.text", "application.vnd.oasis.opendocument.text"),
    (
        b"application/vnd.oasis.opendocument.spreadsheet",
        "application.vnd.oasis.opendocument.spreadsheet",
    ),
    (
        b"application/vnd.oasis.opendocument.presentation",
        "application.vnd.oasis.opendocument.presentation",
    ),
)
_OLE_EXTENSION_MEDIA = {
    "doc": "application.msword",
    "xls": "application.vnd.ms-excel",
    "ppt": "application.vnd.ms-powerpoint",
    "msg": "application.vnd.ms-outlook",
}


def evidence_media_type(content: bytes, file_extension: str | None = None) -> str:
    """Name a file's type from its own bytes; the extension only refines a family.

    The respondent's file name never overrides what the content is: a ``.pdf``
    name on PNG bytes is recorded as a PNG image.  The extension only chooses
    between members of a family the bytes cannot tell apart cheaply (a ZIP
    container, an OLE compound file, plain text versus CSV).
    """

    head = bytes(content[:_EVIDENCE_SNIFF_BYTES])
    extension = file_extension or ""
    if head.startswith(b"%PDF-"):
        return "application.pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image.png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image.jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image.gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image.webp"
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return "image.tiff"
    if head.startswith(b"{\\rtf"):
        return "application.rtf"
    if head.startswith(b"PK\x03\x04"):
        if head[30:38] == b"mimetype":
            for marker, media in _ODF_MEDIA:
                if head[38:38 + len(marker)] == marker:
                    return media
        for marker, media in _OOXML_MEDIA:
            if b"[Content_Types].xml" in head and marker in head:
                return media
        return _ZIP_EXTENSION_MEDIA.get(extension, "application.zip")
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return _OLE_EXTENSION_MEDIA.get(extension, "application.x-ole-storage")
    if b"\x00" not in head:
        decoder = codecs.getincrementaldecoder("utf-8")()
        try:
            decoder.decode(head, final=len(content) <= len(head))
        except UnicodeDecodeError:
            return "application.octet-stream"
        return "text.csv" if extension in {"csv", "tsv"} else "text.plain"
    return "application.octet-stream"


def _new_token(token_factory: Callable[[int], bytes]) -> tuple[str, str]:
    raw = token_factory(32)
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise ThirdPartyCollaborationIntegrityError(
            "invitation token generator must return exactly 32 random bytes"
        )
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    token = f"{_TOKEN_PREFIX}{encoded}"
    if not _TOKEN_RE.fullmatch(token):
        raise ThirdPartyCollaborationIntegrityError(
            "invitation token generator produced an invalid credential"
        )
    return token, hashlib.sha256(token.encode("ascii")).hexdigest()


class ThirdPartyCollaborationStore:
    """Durable collaboration state bound to one lifecycle SQLite authority."""

    def __init__(
        self,
        path: str | Path,
        *,
        lifecycle_path: str | Path,
        config_gate: Callable[[], None] = require_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        clock: Callable[[], float] = time.time,
        token_factory: Callable[[int], bytes] = secrets.token_bytes,
        policy: ThirdPartyCollaborationPolicy | None = None,
    ) -> None:
        config_gate()
        self.path = Path(path)
        self.lifecycle_path = Path(lifecycle_path)
        if self.path.resolve() == self.lifecycle_path.resolve():
            raise ThirdPartyCollaborationValidationError(
                "collaboration and lifecycle databases must use separate files"
            )
        self._principal_resolver = principal_resolver
        self._clock = clock
        self._token_factory = token_factory
        self._policy = (
            policy
            if isinstance(policy, ThirdPartyCollaborationPolicy)
            else ThirdPartyCollaborationPolicy(
                invitation_ttl_seconds=_MAX_EXPIRY_SECONDS,
                retention_seconds=_MAX_RETENTION_SECONDS,
                max_messages=1_000,
                max_artifacts=_MAX_ARTIFACTS,
                max_artifact_bytes=_MAX_ARTIFACT_BYTES,
            )
        ).normalized()
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _actor(self) -> str:
        actor = self._principal_resolver()
        if actor is None or actor == "":
            raise ThirdPartyCollaborationPermissionDenied(
                "an authenticated internal principal is required"
            )
        return _id(actor, "authenticated principal")

    def _lifecycle_store(self, principal_ref: str = "portal-authority") -> Any:
        return lifecycle.ThirdPartyLifecycleStore(
            self.lifecycle_path,
            config_gate=lambda: None,
            principal_resolver=lambda: principal_ref,
            clock=self._clock,
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
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
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS invitations(
                    tenant_id TEXT NOT NULL,invitation_id TEXT NOT NULL,
                    token_sha256 TEXT NOT NULL,status TEXT NOT NULL,
                    expires_at REAL NOT NULL,retained_until REAL NOT NULL,
                    legal_hold INTEGER NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,invitation_id),
                    UNIQUE(tenant_id,token_sha256)
                );
                CREATE INDEX IF NOT EXISTS invitation_token
                    ON invitations(tenant_id,token_sha256,status);
                CREATE INDEX IF NOT EXISTS invitation_retention
                    ON invitations(tenant_id,retained_until,legal_hold,status);
                CREATE TABLE IF NOT EXISTS drafts(
                    tenant_id TEXT NOT NULL,invitation_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,state TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,invitation_id)
                );
                CREATE TABLE IF NOT EXISTS operations(
                    tenant_id TEXT NOT NULL,operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,
                    result_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS history(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                CREATE TABLE IF NOT EXISTS evidence_measurements(
                    tenant_id TEXT NOT NULL,invitation_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,invitation_id,artifact_id)
                );
                INSERT OR IGNORE INTO metadata(key,value) VALUES('schema_version','1');
                COMMIT;
                """
            )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if version is None or version["value"] != str(SCHEMA_VERSION):
                raise ThirdPartyCollaborationIntegrityError(
                    "third-party collaboration database schema is unsupported"
                )
        ensure_private_file(self.path)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _payload(row: sqlite3.Row, label: str) -> dict[str, object]:
        try:
            value = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ThirdPartyCollaborationIntegrityError(
                f"persisted {label} is not valid JSON"
            ) from exc
        if not isinstance(value, dict) or _sha256(value) != row["integrity_sha256"]:
            raise ThirdPartyCollaborationIntegrityError(
                f"persisted {label} failed integrity verification"
            )
        return value

    @staticmethod
    def _operation_sha256(
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> str:
        """Scope caller-controlled idempotency to one action authority.

        External respondents choose their own idempotency keys.  Hashing only
        that key would let one invitation reserve a common value for every
        other invitation in the tenant.  The server-owned action, invitation,
        and credential generation form the collision domain instead.
        """

        key = _id(idempotency_key, "idempotency_key", _OP_RE)
        action = _id(request.get("action"), "operation action")
        invitation_id = request.get("invitation_id")
        if invitation_id is not None:
            invitation_id = _id(invitation_id, "operation invitation_id")
        token_generation = request.get("token_generation")
        if token_generation is not None:
            token_generation = _integer(
                token_generation,
                "operation token_generation",
                1,
                1_000_000,
            )
        return _sha256(
            {
                "schema": "lightwork.third-party-collaboration-idempotency-scope.v1",
                "action": action,
                "invitation_id": invitation_id,
                "token_generation": token_generation,
                "idempotency_key": key,
            }
        )

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, str, sqlite3.Row | None]:
        operation_sha = ThirdPartyCollaborationStore._operation_sha256(
            idempotency_key,
            request,
        )
        request_sha = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM operations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha),
        ).fetchone()
        if row is not None:
            binding = {
                "tenant_id": row["tenant_id"],
                "operation_sha256": row["operation_sha256"],
                "request_sha256": row["request_sha256"],
                "result_kind": row["result_kind"],
                "result_json": row["result_json"],
            }
            if _sha256(binding) != row["integrity_sha256"]:
                raise ThirdPartyCollaborationIntegrityError(
                    "persisted idempotency binding failed integrity verification"
                )
            if row["request_sha256"] != request_sha:
                raise ThirdPartyCollaborationConflict(
                    "idempotency key is bound to different canonical content"
                )
        return operation_sha, request_sha, row

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        operation_sha256: str,
        request_sha256: str,
        result_kind: str,
        result: Mapping[str, object],
    ) -> None:
        operation_sha = _digest(operation_sha256, "operation_sha256")
        result_json = _canonical(dict(result)).decode("ascii")
        binding = {
            "tenant_id": tenant_id,
            "operation_sha256": operation_sha,
            "request_sha256": request_sha256,
            "result_kind": result_kind,
            "result_json": result_json,
        }
        connection.execute(
            "INSERT INTO operations VALUES(?,?,?,?,?,?)",
            (
                tenant_id,
                binding["operation_sha256"],
                request_sha256,
                result_kind,
                result_json,
                _sha256(binding),
            ),
        )

    def _history(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        action: str,
        invitation_id: str,
        actor_ref: str,
        details: Mapping[str, object],
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM history WHERE tenant_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else str(previous["integrity_sha256"])
        payload = {
            "schema": HISTORY_SCHEMA,
            "tenant_id": tenant_id,
            "sequence": sequence,
            "action": _id(action, "history action"),
            "invitation_sha256": hashlib.sha256(invitation_id.encode()).hexdigest(),
            "actor_sha256": hashlib.sha256(actor_ref.encode()).hexdigest(),
            "details": dict(details),
            "occurred_at": now,
            "previous_sha256": previous_sha,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO history VALUES(?,?,?,?)",
            (tenant_id, sequence, _canonical(payload).decode("ascii"), digest),
        )

    @staticmethod
    def _safe_invitation(payload: Mapping[str, object]) -> dict[str, object]:
        result = {
            key: payload[key]
            for key in (
                "schema",
                "tenant_id",
                "invitation_id",
                "vendor_ref",
                "assessment_id",
                "assessment_revision",
                "assessment_sha256",
                "template_id",
                "template_version",
                "template_revision",
                "template_sha256",
                "respondent_ref",
                "allowed_question_ids",
                "notice_ref",
                "notice_sha256",
                "artifact_policy",
                "token_generation",
                "status",
                "expires_at",
                "retained_until",
                "legal_hold",
                "legal_hold_evidence_ref",
                "created_at",
                "updated_at",
                "revision",
                "revocation",
                "follow_up",
            )
        }
        finalization = payload["finalization"]
        if isinstance(finalization, Mapping):
            result["finalization"] = {
                key: finalization[key]
                for key in (
                    "status",
                    "attestation_sha256",
                    "question_ids",
                    "started_at",
                    "receipt",
                    "finalized_at",
                )
            }
        else:
            result["finalization"] = None
        return result

    @staticmethod
    def _receipt(value: object, *, replay: bool) -> FinalSubmissionReceipt:
        item = _closed(
            value,
            "final submission receipt",
            frozenset(
                {
                    "schema",
                    "tenant_id",
                    "invitation_id",
                    "assessment_id",
                    "assessment_revision",
                    "assessment_integrity_sha256",
                    "question_ids",
                    "attestation_sha256",
                    "evidence_status",
                }
            ),
        )
        if item["schema"] != RECEIPT_SCHEMA:
            raise ThirdPartyCollaborationIntegrityError("final receipt schema is invalid")
        if item["evidence_status"] != "respondent_attestation_unverified":
            raise ThirdPartyCollaborationIntegrityError("final receipt evidence status is invalid")
        return FinalSubmissionReceipt(
            schema=RECEIPT_SCHEMA,
            tenant_id=_tenant(item["tenant_id"]),
            invitation_id=_id(item["invitation_id"], "invitation_id"),
            assessment_id=_id(item["assessment_id"], "assessment_id"),
            assessment_revision=_integer(
                item["assessment_revision"], "assessment_revision", 1, 1_000_000
            ),
            assessment_integrity_sha256=_digest(
                item["assessment_integrity_sha256"],
                "assessment_integrity_sha256",
            ),
            question_ids=_ids(item["question_ids"], "question_id", minimum=1),
            attestation_sha256=_digest(item["attestation_sha256"], "attestation_sha256"),
            evidence_status="respondent_attestation_unverified",
            idempotent_replay=replay,
        )

    def _get_invitation(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        invitation_id: str,
    ) -> dict[str, object]:
        row = connection.execute(
            "SELECT * FROM invitations WHERE tenant_id=? AND invitation_id=?",
            (tenant_id, invitation_id),
        ).fetchone()
        if row is None:
            raise ThirdPartyCollaborationNotFound("invitation was not found")
        payload = self._payload(row, "invitation")
        if (
            payload.get("tenant_id") != tenant_id
            or payload.get("invitation_id") != invitation_id
            or payload.get("token_sha256") != row["token_sha256"]
            or payload.get("status") != row["status"]
            or payload.get("expires_at") != row["expires_at"]
            or payload.get("retained_until") != row["retained_until"]
            or int(payload.get("legal_hold", -1)) != row["legal_hold"]
        ):
            raise ThirdPartyCollaborationIntegrityError("invitation index binding is inconsistent")
        return payload

    @staticmethod
    def _write_invitation(connection: sqlite3.Connection, payload: Mapping[str, object]) -> str:
        digest = _sha256(dict(payload))
        result = connection.execute(
            "UPDATE invitations SET token_sha256=?,status=?,expires_at=?,"
            "retained_until=?,legal_hold=?,payload_json=?,integrity_sha256=? "
            "WHERE tenant_id=? AND invitation_id=?",
            (
                payload["token_sha256"],
                payload["status"],
                payload["expires_at"],
                payload["retained_until"],
                int(bool(payload["legal_hold"])),
                _canonical(dict(payload)).decode("ascii"),
                digest,
                payload["tenant_id"],
                payload["invitation_id"],
            ),
        )
        if result.rowcount != 1:
            raise ThirdPartyCollaborationNotFound("invitation was not found")
        return digest

    def _get_draft(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        invitation_id: str,
    ) -> dict[str, object] | None:
        row = connection.execute(
            "SELECT * FROM drafts WHERE tenant_id=? AND invitation_id=?",
            (tenant_id, invitation_id),
        ).fetchone()
        if row is None:
            return None
        payload = self._payload(row, "draft")
        if (
            payload.get("tenant_id") != tenant_id
            or payload.get("invitation_id") != invitation_id
            or payload.get("revision") != row["revision"]
            or payload.get("state") != row["state"]
        ):
            raise ThirdPartyCollaborationIntegrityError("draft index binding is inconsistent")
        return payload

    @staticmethod
    def _write_draft(connection: sqlite3.Connection, payload: Mapping[str, object]) -> str:
        digest = _sha256(dict(payload))
        connection.execute(
            "INSERT INTO drafts VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(tenant_id,invitation_id) DO UPDATE SET "
            "revision=excluded.revision,state=excluded.state,"
            "payload_json=excluded.payload_json,integrity_sha256=excluded.integrity_sha256",
            (
                payload["tenant_id"],
                payload["invitation_id"],
                payload["revision"],
                payload["state"],
                _canonical(dict(payload)).decode("ascii"),
                digest,
            ),
        )
        return digest

    @staticmethod
    def _assessment_scope_sha256(
        assessment: lifecycle.Assessment,
        template: lifecycle.AssessmentTemplate,
        allowed_question_ids: Sequence[str],
    ) -> str:
        """Pin structure and answers that can affect this invitation's work.

        Other respondents may add unrelated answers. Their answer changes still
        advance the full lifecycle revision; final submission uses that freshly
        observed revision with the unchanged native CAS writer.
        """

        questions = {str(item["question_id"]): item for item in template.questions}
        dependencies: set[str] = set()
        pending = list(allowed_question_ids)
        while pending:
            question_id = pending.pop()
            if question_id in dependencies:
                continue
            if question_id not in questions:
                raise ThirdPartyCollaborationConflict("invitation question authority changed")
            dependencies.add(question_id)
            condition = questions[question_id]["condition"]
            if isinstance(condition, Mapping):
                pending.append(str(condition["question_id"]))
        authority = asdict(assessment)
        for field in ("revision", "updated_at", "integrity_sha256"):
            authority.pop(field)
        authority["responses"] = {
            question_id: dict(assessment.responses[question_id])
            for question_id in sorted(dependencies)
            if question_id in assessment.responses
        }
        return _sha256(
            {
                "schema": "lightwork.third-party-collaboration-answer-authority.v1",
                "assessment": authority,
                "question_ids": sorted(dependencies),
            }
        )

    def _assessment_matches(
        self,
        assessment: lifecycle.Assessment,
        template: lifecycle.AssessmentTemplate,
        payload: Mapping[str, object],
    ) -> bool:
        if "assessment_scope_sha256" in payload:
            return hmac.compare_digest(
                self._assessment_scope_sha256(
                    assessment, template, payload["allowed_question_ids"]  # type: ignore[arg-type]
                ),
                _digest(payload["assessment_scope_sha256"], "assessment_scope_sha256"),
            )
        # Already-issued invitations retain their exact original authority rule.
        return (
            assessment.revision == payload["assessment_revision"]
            and assessment.integrity_sha256 == payload["assessment_sha256"]
        )

    def _authority(
        self, payload: Mapping[str, object]
    ) -> tuple[lifecycle.Assessment, lifecycle.AssessmentTemplate]:
        tenant_id = str(payload["tenant_id"])
        store = self._lifecycle_store()
        try:
            assessment = store.get_assessment(tenant_id, str(payload["assessment_id"]))
            template = store.get_template_version(
                tenant_id,
                str(payload["template_id"]),
                int(payload["template_version"]),
            )
        except lifecycle.ThirdPartyLifecycleError as exc:
            raise ThirdPartyCollaborationConflict(
                "pinned assessment authority is unavailable"
            ) from exc
        if (
            assessment.template_id != payload["template_id"]
            or assessment.template_version != payload["template_version"]
            or template.revision != payload["template_revision"]
            or template.integrity_sha256 != payload["template_sha256"]
            or template.state != "approved"
            or not self._assessment_matches(assessment, template, payload)
        ):
            raise ThirdPartyCollaborationConflict("pinned assessment or template authority changed")
        return assessment, template

    @staticmethod
    def _visible_questions(
        assessment: lifecycle.Assessment,
        template: lifecycle.AssessmentTemplate,
        draft_answers: Mapping[str, Mapping[str, object]],
        allowed_question_ids: Sequence[str],
    ) -> tuple[tuple[dict[str, object], ...], tuple[str, ...], dict[str, object]]:
        allowed = set(allowed_question_ids)
        values = {
            question_id: response["value"] for question_id, response in assessment.responses.items()
        }
        visible: list[dict[str, object]] = []
        required: list[str] = []
        for question in template.questions:
            question_id = str(question["question_id"])
            condition = question["condition"]
            active = condition is None
            if isinstance(condition, Mapping):
                control = values.get(str(condition["question_id"]))
                active = control is not None and lifecycle._condition_matches(  # noqa: SLF001
                    control,
                    str(condition["operator"]),
                    condition["value"],
                )
            if not active:
                continue
            if question_id in allowed:
                visible.append(
                    {
                        key: question[key]
                        for key in (
                            "question_id",
                            "domain",
                            "prompt_ref",
                            "response_type",
                            "required",
                            "options",
                        )
                    }
                )
                if question["required"] is True:
                    required.append(question_id)
            if active and question_id in draft_answers:
                try:
                    values[question_id] = lifecycle._validate_response(  # noqa: SLF001
                        question, draft_answers[question_id]["value"]
                    )
                except lifecycle.ThirdPartyLifecycleValidationError as exc:
                    raise ThirdPartyCollaborationValidationError(str(exc)) from exc
        return tuple(visible), tuple(required), values

    def _token_invitation(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        token: str,
        *,
        states: frozenset[str] = frozenset({"active"}),
        accept_expired_terminal: bool = False,
    ) -> dict[str, object]:
        # All credential failures deliberately collapse to one response to avoid
        # tenant, state, expiry, rotation, and revocation enumeration oracles.
        invalid = ThirdPartyCollaborationAuthError("invalid invitation")
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise invalid
        token_sha = hashlib.sha256(token.encode("ascii")).hexdigest()
        row = connection.execute(
            "SELECT invitation_id FROM invitations WHERE tenant_id=? AND token_sha256=?",
            (tenant_id, token_sha),
        ).fetchone()
        if row is None:
            raise invalid
        try:
            payload = self._get_invitation(connection, tenant_id, str(row["invitation_id"]))
        except (ThirdPartyCollaborationNotFound, ThirdPartyCollaborationIntegrityError):
            raise invalid from None
        expired = float(payload["expires_at"]) <= float(self._clock())
        terminal_replay = accept_expired_terminal and payload["status"] in {
            "finalizing",
            "finalized",
        }
        if (
            payload["status"] not in states
            or (expired and not terminal_replay)
            or not hmac.compare_digest(str(payload["token_sha256"]), token_sha)
        ):
            raise invalid
        return payload

    def issue_invitation(
        self,
        tenant_id: str,
        invitation_id: str,
        *,
        assessment_id: str,
        respondent_ref: str,
        allowed_question_ids: Sequence[str],
        notice_ref: str,
        notice_sha256: str,
        artifact_policy: Mapping[str, object],
        expires_in_seconds: int,
        retention_seconds: int,
        idempotency_key: str,
    ) -> InvitationIssue:
        """Issue a one-time-disclosed invitation bound to exact authority pins."""

        tenant = _tenant(tenant_id)
        invitation = _id(invitation_id, "invitation_id")
        assessment_key = _id(assessment_id, "assessment_id")
        respondent = _id(respondent_ref, "respondent_ref")
        allowed = _ids(allowed_question_ids, "allowed_question_id", minimum=1)
        notice = _id(notice_ref, "notice_ref")
        notice_digest = _digest(notice_sha256, "notice_sha256")
        policy = _artifact_policy(artifact_policy)
        expiry = _integer(
            expires_in_seconds,
            "expires_in_seconds",
            _MIN_EXPIRY_SECONDS,
            _MAX_EXPIRY_SECONDS,
        )
        retention = _integer(
            retention_seconds,
            "retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        if expiry > self._policy.invitation_ttl_seconds:
            raise ThirdPartyCollaborationValidationError(
                "invitation expiry exceeds the configured portal TTL"
            )
        if retention > self._policy.retention_seconds:
            raise ThirdPartyCollaborationValidationError(
                "invitation retention exceeds the configured portal retention"
            )
        if (
            int(policy["maximum_artifacts"]) > self._policy.max_artifacts
            or int(policy["maximum_total_bytes"]) > self._policy.max_artifact_bytes
        ):
            raise ThirdPartyCollaborationValidationError(
                "artifact policy exceeds the configured portal limits"
            )
        if retention < expiry:
            raise ThirdPartyCollaborationValidationError(
                "retention cannot end before invitation expiry"
            )
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        lifecycle_store = self._lifecycle_store()
        try:
            assessment = lifecycle_store.get_assessment(tenant, assessment_key)
            template = lifecycle_store.get_template_version(
                tenant, assessment.template_id, assessment.template_version
            )
        except lifecycle.ThirdPartyLifecycleError as exc:
            raise ThirdPartyCollaborationConflict("assessment authority is unavailable") from exc
        question_order = tuple(str(item["question_id"]) for item in template.questions)
        if template.state != "approved" or not set(allowed).issubset(question_order):
            raise ThirdPartyCollaborationConflict(
                "invitation requires approved, known assessment questions"
            )
        if tuple(item for item in question_order if item in set(allowed)) != allowed:
            raise ThirdPartyCollaborationValidationError(
                "allowed questions must follow canonical template order"
            )
        if any(assessment.assignments.get(item) != respondent for item in allowed):
            raise ThirdPartyCollaborationPermissionDenied(
                "respondent must be the assigned authority for every allowed question"
            )
        if now + retention > assessment.retained_until:
            raise ThirdPartyCollaborationConflict(
                "invitation retention exceeds the assessment authority retention"
            )
        request = {
            "action": "issue_invitation",
            "invitation_id": invitation,
            "assessment_id": assessment_key,
            "assessment_revision": assessment.revision,
            "assessment_sha256": assessment.integrity_sha256,
            "template_revision": template.revision,
            "template_sha256": template.integrity_sha256,
            "respondent_ref": respondent,
            "allowed_question_ids": list(allowed),
            "notice_ref": notice,
            "notice_sha256": notice_digest,
            "artifact_policy": policy,
            "expires_in_seconds": expiry,
            "retention_seconds": retention,
            "actor_ref": actor,
        }
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            operation_sha, request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                if operation["result_kind"] != "invitation":
                    raise ThirdPartyCollaborationIntegrityError(
                        "invitation idempotency result is inconsistent"
                    )
                stored = json.loads(operation["result_json"])
                existing = self._get_invitation(connection, tenant, str(stored["invitation_id"]))
                return InvitationIssue(
                    invitation=self._safe_invitation(existing),
                    token=None,
                    token_disclosed=False,
                    idempotent_replay=True,
                )
            existing = connection.execute(
                "SELECT 1 FROM invitations WHERE tenant_id=? AND invitation_id=?",
                (tenant, invitation),
            ).fetchone()
            if existing is not None:
                raise ThirdPartyCollaborationConflict("invitation already exists")
            token, token_sha = _new_token(self._token_factory)
            payload: dict[str, object] = {
                "schema": INVITATION_SCHEMA,
                "tenant_id": tenant,
                "invitation_id": invitation,
                "vendor_ref": assessment.vendor_ref,
                "assessment_id": assessment.assessment_id,
                "assessment_revision": assessment.revision,
                "assessment_sha256": assessment.integrity_sha256,
                "assessment_scope_sha256": self._assessment_scope_sha256(
                    assessment, template, allowed
                ),
                "template_id": template.template_id,
                "template_version": template.version,
                "template_revision": template.revision,
                "template_sha256": template.integrity_sha256,
                "respondent_ref": respondent,
                "allowed_question_ids": list(allowed),
                "notice_ref": notice,
                "notice_sha256": notice_digest,
                "artifact_policy": policy,
                "token_sha256": token_sha,
                "token_generation": 1,
                "status": "active",
                "expires_at": now + expiry,
                "retained_until": now + retention,
                "legal_hold": False,
                "legal_hold_evidence_ref": None,
                "created_by": actor,
                "created_at": now,
                "updated_at": now,
                "revision": 1,
                "revocation": None,
                "follow_up": None,
                "finalization": None,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO invitations VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    tenant,
                    invitation,
                    token_sha,
                    "active",
                    payload["expires_at"],
                    payload["retained_until"],
                    0,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                operation_sha,
                request_sha,
                "invitation",
                {"invitation_id": invitation},
            )
            self._history(
                connection,
                tenant,
                "invitation_issued",
                invitation,
                actor,
                {
                    "assessment_sha256": assessment.integrity_sha256,
                    "template_sha256": template.integrity_sha256,
                    "allowed_question_count": len(allowed),
                    "token_generation": 1,
                },
                now,
            )
            return InvitationIssue(
                invitation=self._safe_invitation(payload),
                token=token,
                token_disclosed=True,
                idempotent_replay=False,
            )

    def get_invitation(self, tenant_id: str, invitation_id: str) -> Mapping[str, object]:
        """Return internal invitation metadata with credential material redacted."""

        tenant = _tenant(tenant_id)
        invitation = _id(invitation_id, "invitation_id")
        self._actor()
        with self._connect() as connection:
            return self._safe_invitation(self._get_invitation(connection, tenant, invitation))

    def list_invitations(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
        after: str | None = None,
    ) -> Mapping[str, object]:
        """Page credential-redacted invitations in stable identifier order."""

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 500)
        cursor = None if after is None else _id(after, "after")
        self._actor()
        query = (
            "SELECT invitation_id FROM invitations WHERE tenant_id=? "
            + ("AND invitation_id>? " if cursor is not None else "")
            + "ORDER BY invitation_id LIMIT ?"
        )
        parameters: tuple[object, ...] = (
            (tenant, cursor, bounded + 1)
            if cursor is not None
            else (tenant, bounded + 1)
        )
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
            truncated = len(rows) > bounded
            selected = rows[:bounded]
            items = [
                self._safe_invitation(
                    self._get_invitation(connection, tenant, str(row["invitation_id"]))
                )
                for row in selected
            ]
        return {
            "items": items,
            "count": len(items),
            "truncated": truncated,
            "next_after": (
                str(selected[-1]["invitation_id"])
                if truncated and selected
                else None
            ),
        }

    def contract_for_token(self, tenant_id: str, token: str) -> Mapping[str, object]:
        """Return only the server-authorized respondent contract and questions."""

        tenant = _tenant(tenant_id)
        with self._connect() as connection:
            invitation = self._token_invitation(connection, tenant, token)
            assessment, template = self._authority(invitation)
            draft = self._get_draft(connection, tenant, str(invitation["invitation_id"]))
            answers = {} if draft is None else dict(draft["answers"])  # type: ignore[arg-type]
            questions, required, values = self._visible_questions(
                assessment,
                template,
                answers,
                invitation["allowed_question_ids"],  # type: ignore[arg-type]
            )
            active_ids = tuple(str(item["question_id"]) for item in questions)
            answered = tuple(item for item in active_ids if item in values)
            return {
                "schema": CONTRACT_SCHEMA,
                "tenant_id": tenant,
                "invitation_id": invitation["invitation_id"],
                "vendor_ref": invitation["vendor_ref"],
                "assessment_id": invitation["assessment_id"],
                "notice_ref": invitation["notice_ref"],
                "notice_sha256": invitation["notice_sha256"],
                "artifact_policy": invitation["artifact_policy"],
                "questions": list(questions),
                "required_question_ids": list(required),
                "answered_question_ids": list(answered),
                "draft_revision": 0 if draft is None else draft["revision"],
                "draft_artifacts": [] if draft is None else draft["artifacts"],
                "expires_at": invitation["expires_at"],
                "limitations": [
                    "respondent_attestations_are_unverified",
                    "artifact_manifests_only_no_upload_bytes",
                    "no_network_or_email_delivery",
                    "no_model_inference",
                ],
            }

    def measure_evidence(
        self,
        tenant_id: str,
        token: str,
        *,
        content: bytes,
        file_extension: str | None = None,
    ) -> EvidenceMeasurement:
        """Measure one evidence file server-side and keep only the measurement.

        The fingerprint, size and media type come from ``content`` itself; the
        bytes are never written anywhere.  Only an active invitation whose
        artifact policy accepts files may be measured, a single file may not
        exceed the invitation's byte bound, and the number of distinct
        measurements per invitation is capped.  Checking the same file again
        returns the existing measurement.
        """

        tenant = _tenant(tenant_id)
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise ThirdPartyCollaborationValidationError("evidence content must be bytes")
        data = bytes(content)
        size_bytes = len(data)
        if not 1 <= size_bytes <= _MAX_ARTIFACT_BYTES:
            raise ThirdPartyCollaborationValidationError(
                "evidence file must contain between 1 and the maximum number of bytes"
            )
        if file_extension is not None and (
            not isinstance(file_extension, str) or not _EXTENSION_RE.fullmatch(file_extension)
        ):
            raise ThirdPartyCollaborationValidationError("evidence file extension is invalid")
        content_sha256 = hashlib.sha256(data).hexdigest()
        media_type_ref = evidence_media_type(data, file_extension)
        now = _timestamp(self._clock(), "current time")
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            invitation = self._token_invitation(connection, tenant, token)
            invitation_id = str(invitation["invitation_id"])
            policy = invitation["artifact_policy"]
            if not isinstance(policy, Mapping):
                raise ThirdPartyCollaborationIntegrityError("persisted artifact policy is invalid")
            if int(policy["maximum_artifacts"]) == 0:
                raise ThirdPartyCollaborationPermissionDenied(
                    "this invitation does not accept evidence files"
                )
            if size_bytes > int(policy["maximum_total_bytes"]):
                raise ThirdPartyCollaborationValidationError(
                    "evidence file exceeds the invitation byte bound"
                )
            artifact_id = "evidence-" + hashlib.sha256(
                f"{invitation_id}\x00{content_sha256}\x00{media_type_ref}".encode()
            ).hexdigest()[:32]
            existing = connection.execute(
                "SELECT payload_json,integrity_sha256 FROM evidence_measurements "
                "WHERE tenant_id=? AND invitation_id=? AND artifact_id=?",
                (tenant, invitation_id, artifact_id),
            ).fetchone()
            if existing is not None:
                payload = self._measurement(existing, tenant, invitation_id, artifact_id)
                return EvidenceMeasurement(
                    tenant_id=tenant,
                    invitation_id=invitation_id,
                    artifact_id=artifact_id,
                    content_sha256=str(payload["content_sha256"]),
                    size_bytes=int(payload["size_bytes"]),
                    media_type_ref=str(payload["media_type_ref"]),
                    idempotent_replay=True,
                )
            count = connection.execute(
                "SELECT COUNT(*) FROM evidence_measurements WHERE tenant_id=? AND invitation_id=?",
                (tenant, invitation_id),
            ).fetchone()[0]
            if int(count) >= _MAX_EVIDENCE_MEASUREMENTS:
                raise ThirdPartyCollaborationValidationError(
                    "too many evidence files were checked for this invitation"
                )
            payload = {
                "schema": EVIDENCE_MEASUREMENT_SCHEMA,
                "tenant_id": tenant,
                "invitation_id": invitation_id,
                "artifact_id": artifact_id,
                "content_sha256": content_sha256,
                "size_bytes": size_bytes,
                "media_type_ref": media_type_ref,
                "token_generation": invitation["token_generation"],
                "measured_at": now,
            }
            connection.execute(
                "INSERT INTO evidence_measurements VALUES(?,?,?,?,?)",
                (
                    tenant,
                    invitation_id,
                    artifact_id,
                    _canonical(payload).decode("ascii"),
                    _sha256(payload),
                ),
            )
            self._history(
                connection,
                tenant,
                "evidence_measured",
                invitation_id,
                str(invitation["respondent_ref"]),
                {
                    "artifact_id": artifact_id,
                    "content_sha256": content_sha256,
                    "size_bytes": size_bytes,
                    "media_type_ref": media_type_ref,
                },
                now,
            )
            return EvidenceMeasurement(
                tenant_id=tenant,
                invitation_id=invitation_id,
                artifact_id=artifact_id,
                content_sha256=content_sha256,
                size_bytes=size_bytes,
                media_type_ref=media_type_ref,
                idempotent_replay=False,
            )

    def _measurement(
        self,
        row: sqlite3.Row,
        tenant_id: str,
        invitation_id: str,
        artifact_id: str,
    ) -> dict[str, object]:
        payload = self._payload(row, "evidence measurement")
        if (
            payload.get("schema") != EVIDENCE_MEASUREMENT_SCHEMA
            or payload.get("tenant_id") != tenant_id
            or payload.get("invitation_id") != invitation_id
            or payload.get("artifact_id") != artifact_id
        ):
            raise ThirdPartyCollaborationIntegrityError(
                "persisted evidence measurement binding is inconsistent"
            )
        return payload

    def _require_measured(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        invitation_id: str,
        manifests: Sequence[Mapping[str, object]],
    ) -> None:
        """Accept a manifest only if it is exactly what the server measured."""

        for manifest in manifests:
            artifact_id = str(manifest["artifact_id"])
            row = connection.execute(
                "SELECT payload_json,integrity_sha256 FROM evidence_measurements "
                "WHERE tenant_id=? AND invitation_id=? AND artifact_id=?",
                (tenant_id, invitation_id, artifact_id),
            ).fetchone()
            if row is None:
                raise ThirdPartyCollaborationValidationError(
                    "artifact manifest was not measured by the server"
                )
            measured = self._measurement(row, tenant_id, invitation_id, artifact_id)
            if any(
                measured.get(key) != manifest[key]
                for key in ("content_sha256", "size_bytes", "media_type_ref")
            ):
                raise ThirdPartyCollaborationValidationError(
                    "artifact manifest does not match the server measurement"
                )

    def _normalize_submission(
        self,
        invitation: Mapping[str, object],
        assessment: lifecycle.Assessment,
        template: lifecycle.AssessmentTemplate,
        answers: object,
        artifacts: object,
        *,
        require_complete: bool,
    ) -> tuple[
        dict[str, dict[str, object]],
        tuple[dict[str, object], ...],
        tuple[str, ...],
        tuple[str, ...],
    ]:
        if not isinstance(answers, Mapping) or len(answers) > _MAX_QUESTIONS:
            raise ThirdPartyCollaborationValidationError("answers must be a bounded mapping")
        policy = invitation["artifact_policy"]
        if not isinstance(policy, Mapping):
            raise ThirdPartyCollaborationIntegrityError("persisted artifact policy is invalid")
        normalized_artifacts = _artifact_manifests(artifacts, policy)
        artifact_ids = {str(item["artifact_id"]) for item in normalized_artifacts}
        questions = {str(item["question_id"]): item for item in template.questions}
        allowed = set(invitation["allowed_question_ids"])  # type: ignore[arg-type]
        normalized: dict[str, dict[str, object]] = {}
        referenced_artifacts: set[str] = set()
        for raw_question_id, raw_answer in answers.items():
            question_id = _id(raw_question_id, "question_id")
            if question_id not in allowed or question_id not in questions:
                raise ThirdPartyCollaborationPermissionDenied(
                    "answer is outside the invitation question authority"
                )
            item = _closed(
                raw_answer,
                f"answer {question_id}",
                frozenset({"value", "artifact_ids"}),
            )
            try:
                value = lifecycle._validate_response(  # noqa: SLF001
                    questions[question_id], item["value"]
                )
            except lifecycle.ThirdPartyLifecycleValidationError as exc:
                raise ThirdPartyCollaborationValidationError(str(exc)) from exc
            answer_artifacts = _ids(
                item["artifact_ids"],
                "answer artifact_id",
                maximum=_MAX_ARTIFACTS,
            )
            if not set(answer_artifacts).issubset(artifact_ids):
                raise ThirdPartyCollaborationValidationError(
                    "answer references an unknown artifact manifest"
                )
            referenced_artifacts.update(answer_artifacts)
            normalized[question_id] = {
                "value": value,
                "artifact_ids": list(answer_artifacts),
            }
        visible, required, values = self._visible_questions(
            assessment,
            template,
            normalized,
            invitation["allowed_question_ids"],  # type: ignore[arg-type]
        )
        active = tuple(str(item["question_id"]) for item in visible)
        if not set(normalized).issubset(active):
            raise ThirdPartyCollaborationConflict(
                "one or more submitted questions are not currently visible"
            )
        if referenced_artifacts != artifact_ids:
            raise ThirdPartyCollaborationValidationError(
                "every artifact manifest must be referenced by an answer"
            )
        if require_complete:
            missing = [question_id for question_id in required if question_id not in values]
            if missing:
                raise ThirdPartyCollaborationConflict(
                    "final submission is missing required visible answers"
                )
            if not normalized:
                raise ThirdPartyCollaborationValidationError(
                    "final submission must contain at least one answer"
                )
        return normalized, normalized_artifacts, active, required

    @staticmethod
    def _draft_receipt(
        tenant_id: str,
        invitation_id: str,
        revision: int,
        draft_sha256: str,
        active: Sequence[str],
        required: Sequence[str],
        artifact_count: int,
        *,
        replay: bool,
    ) -> DraftReceipt:
        return DraftReceipt(
            tenant_id=tenant_id,
            invitation_id=invitation_id,
            revision=revision,
            draft_sha256=draft_sha256,
            active_question_ids=tuple(active),
            required_question_ids=tuple(required),
            artifact_count=artifact_count,
            idempotent_replay=replay,
        )

    def save_draft(
        self,
        tenant_id: str,
        token: str,
        *,
        answers: Mapping[str, Mapping[str, object]],
        artifacts: Sequence[Mapping[str, object]],
        expected_revision: int,
        idempotency_key: str,
    ) -> DraftReceipt:
        """Atomically replace a draft after server-side visibility validation."""

        tenant = _tenant(tenant_id)
        now = _timestamp(self._clock(), "current time")
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            invitation = self._token_invitation(connection, tenant, token)
            expected = _integer(expected_revision, "expected_revision", 0, 1_000_000)
            assessment, template = self._authority(invitation)
            normalized, manifests, active, required = self._normalize_submission(
                invitation,
                assessment,
                template,
                answers,
                artifacts,
                require_complete=False,
            )
            self._require_measured(
                connection, tenant, str(invitation["invitation_id"]), manifests
            )
            request = {
                "action": "save_draft",
                "invitation_id": invitation["invitation_id"],
                "answers": normalized,
                "artifacts": list(manifests),
                "expected_revision": expected,
                "token_generation": invitation["token_generation"],
            }
            operation_sha, request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                if operation["result_kind"] != "draft":
                    raise ThirdPartyCollaborationIntegrityError(
                        "draft idempotency result is inconsistent"
                    )
                result = json.loads(operation["result_json"])
                return self._draft_receipt(
                    tenant,
                    str(invitation["invitation_id"]),
                    int(result["revision"]),
                    _digest(result["draft_sha256"], "draft_sha256"),
                    _ids(result["active_question_ids"], "question_id"),
                    _ids(result["required_question_ids"], "question_id"),
                    _integer(result["artifact_count"], "artifact_count", 0, _MAX_ARTIFACTS),
                    replay=True,
                )
            current = self._get_draft(connection, tenant, str(invitation["invitation_id"]))
            current_revision = 0 if current is None else int(current["revision"])
            if current_revision != expected:
                raise ThirdPartyCollaborationConflict(
                    f"draft revision CAS failed: expected {expected}, found {current_revision}"
                )
            revision = current_revision + 1
            draft = {
                "schema": DRAFT_SCHEMA,
                "tenant_id": tenant,
                "invitation_id": invitation["invitation_id"],
                "answers": normalized,
                "artifacts": list(manifests),
                "state": "draft",
                "revision": revision,
                "submission_sha256": None,
                "created_at": now if current is None else current["created_at"],
                "updated_at": now,
            }
            digest = self._write_draft(connection, draft)
            result = {
                "revision": revision,
                "draft_sha256": digest,
                "active_question_ids": list(active),
                "required_question_ids": list(required),
                "artifact_count": len(manifests),
            }
            self._record_operation(
                connection,
                tenant,
                operation_sha,
                request_sha,
                "draft",
                result,
            )
            self._history(
                connection,
                tenant,
                "draft_saved",
                str(invitation["invitation_id"]),
                str(invitation["respondent_ref"]),
                {
                    "draft_sha256": digest,
                    "answer_count": len(normalized),
                    "artifact_count": len(manifests),
                    "revision": revision,
                },
                now,
            )
            return self._draft_receipt(
                tenant,
                str(invitation["invitation_id"]),
                revision,
                digest,
                active,
                required,
                len(manifests),
                replay=False,
            )

    @staticmethod
    def _finalization_authority(
        invitation: Mapping[str, object], finalization: Mapping[str, object]
    ) -> dict[str, object]:
        authority = _closed(
            finalization.get(
                "assessment_authority",
                {
                    "revision": invitation["assessment_revision"],
                    "sha256": invitation["assessment_sha256"],
                },
            ),
            "prepared assessment authority",
            frozenset({"revision", "sha256"}),
        )
        return {
            "revision": _integer(authority["revision"], "assessment_revision", 1, 1_000_000),
            "sha256": _digest(authority["sha256"], "assessment_sha256"),
        }

    @staticmethod
    def _lifecycle_responses(
        invitation: Mapping[str, object],
        answers: Mapping[str, Mapping[str, object]],
        artifacts: Sequence[Mapping[str, object]],
        attestation_sha256: str,
    ) -> dict[str, dict[str, object]]:
        artifact_map = {str(item["artifact_id"]): item for item in artifacts}
        responses: dict[str, dict[str, object]] = {}
        for question_id, answer in answers.items():
            answer_artifacts = [
                artifact_map[str(item)]
                for item in answer["artifact_ids"]  # type: ignore[index]
            ]
            evidence = {
                "schema": "lightwork.third-party-collaboration-evidence.v1",
                "invitation_id": invitation["invitation_id"],
                "question_id": question_id,
                "value": answer["value"],
                "artifacts": answer_artifacts,
                "attestation_sha256": attestation_sha256,
            }
            references = [f"portal.attestation:{invitation['invitation_id']}"]
            references.extend(f"artifact:{item['artifact_id']}" for item in answer_artifacts)
            responses[question_id] = {
                "value": answer["value"],
                "evidence_sha256": _sha256(evidence),
                "evidence_refs": references,
            }
        return responses

    def _complete_finalization(
        self,
        tenant_id: str,
        invitation_id: str,
        operation_sha256: str,
        request_sha256: str,
        lifecycle_receipt: lifecycle.AssessmentResponseBatchReceipt,
        now: float,
        *,
        replay: bool,
    ) -> FinalSubmissionReceipt:
        with self._connect() as connection:
            self._begin(connection)
            invitation = self._get_invitation(connection, tenant_id, invitation_id)
            if invitation["status"] == "finalized":
                finalization = invitation["finalization"]
                if not isinstance(finalization, Mapping):
                    raise ThirdPartyCollaborationIntegrityError(
                        "finalized invitation has no receipt"
                    )
                return self._receipt(finalization["receipt"], replay=True)
            if invitation["status"] != "finalizing":
                raise ThirdPartyCollaborationConflict(
                    "invitation is no longer available for finalization"
                )
            finalization = invitation["finalization"]
            if (
                not isinstance(finalization, Mapping)
                or finalization.get("request_sha256") != request_sha256
            ):
                raise ThirdPartyCollaborationIntegrityError("finalization binding is inconsistent")
            receipt_value = {
                "schema": RECEIPT_SCHEMA,
                "tenant_id": tenant_id,
                "invitation_id": invitation_id,
                "assessment_id": lifecycle_receipt.assessment_id,
                "assessment_revision": lifecycle_receipt.assessment_revision,
                "assessment_integrity_sha256": (lifecycle_receipt.assessment_integrity_sha256),
                "question_ids": list(lifecycle_receipt.question_ids),
                "attestation_sha256": lifecycle_receipt.attestation_sha256,
                "evidence_status": "respondent_attestation_unverified",
            }
            updated = dict(invitation)
            updated.update(
                {
                    "status": "finalized",
                    "updated_at": now,
                    "revision": int(invitation["revision"]) + 1,
                    "finalization": {
                        **dict(finalization),
                        "status": "finalized",
                        "receipt": receipt_value,
                        "finalized_at": now,
                    },
                }
            )
            self._write_invitation(connection, updated)
            draft = self._get_draft(connection, tenant_id, invitation_id)
            if draft is not None:
                completed_draft = dict(draft)
                completed_draft.update(
                    {
                        "state": "finalized",
                        "revision": int(draft["revision"]) + 1,
                        "updated_at": now,
                    }
                )
                self._write_draft(connection, completed_draft)
            self._record_operation(
                connection,
                tenant_id,
                operation_sha256,
                request_sha256,
                "final_submission",
                receipt_value,
            )
            self._history(
                connection,
                tenant_id,
                "submission_finalized",
                invitation_id,
                str(invitation["respondent_ref"]),
                {
                    "assessment_integrity_sha256": (lifecycle_receipt.assessment_integrity_sha256),
                    "attestation_sha256": lifecycle_receipt.attestation_sha256,
                    "question_ids": list(lifecycle_receipt.question_ids),
                    "evidence_status": "respondent_attestation_unverified",
                },
                now,
            )
            return self._receipt(receipt_value, replay=replay)

    def finalize_submission(
        self,
        tenant_id: str,
        token: str,
        *,
        answers: Mapping[str, Mapping[str, object]],
        artifacts: Sequence[Mapping[str, object]],
        attested: bool,
        expected_draft_revision: int,
        idempotency_key: str,
    ) -> FinalSubmissionReceipt:
        """Finalize one attested batch with crash-safe lifecycle replay."""

        tenant = _tenant(tenant_id)
        now = _timestamp(self._clock(), "current time")
        with cross_process_lock(self.path, strict=True):
            with self._connect() as connection:
                self._begin(connection)
                invitation = self._token_invitation(
                    connection,
                    tenant,
                    token,
                    states=frozenset({"active", "finalizing", "finalized"}),
                    accept_expired_terminal=True,
                )
                expected = _integer(
                    expected_draft_revision,
                    "expected_draft_revision",
                    0,
                    1_000_000,
                )
                operation_key = _id(idempotency_key, "idempotency_key", _OP_RE)
                raw_request = {
                    "action": "finalize_submission",
                    "invitation_id": invitation["invitation_id"],
                    "token_generation": invitation["token_generation"],
                    "answers": answers,
                    "artifacts": artifacts,
                    "attested": attested,
                    "expected_draft_revision": expected,
                }
                raw_request_sha = _sha256(raw_request)
                operation_sha = self._operation_sha256(operation_key, raw_request)
                invitation_id = str(invitation["invitation_id"])
                recovering = invitation["status"] == "finalizing"
                if invitation["status"] in {"finalizing", "finalized"}:
                    finalization = invitation["finalization"]
                    if (
                        not isinstance(finalization, Mapping)
                        or finalization.get("request_sha256") != raw_request_sha
                        or finalization.get("idempotency_sha256") != operation_sha
                    ):
                        raise ThirdPartyCollaborationConflict(
                            "final submission is bound to different canonical content"
                        )
                    if invitation["status"] == "finalized":
                        return self._receipt(finalization["receipt"], replay=True)
                    prepared = finalization.get("prepared_responses")
                    if not isinstance(prepared, Mapping):
                        raise ThirdPartyCollaborationIntegrityError(
                            "recoverable finalization batch is invalid"
                        )
                    lifecycle_responses = {
                        str(key): dict(value)  # type: ignore[arg-type]
                        for key, value in prepared.items()
                    }
                    attestation_sha = _digest(
                        finalization.get("attestation_sha256"),
                        "attestation_sha256",
                    )
                    lifecycle_operation = _id(
                        finalization.get("lifecycle_operation"),
                        "lifecycle_operation",
                        _OP_RE,
                    )
                    assessment_authority = self._finalization_authority(invitation, finalization)
                else:
                    if attested is not True:
                        raise ThirdPartyCollaborationPermissionDenied(
                            "explicit respondent attestation is required"
                        )
                    assessment, template = self._authority(invitation)
                    assessment_authority = {
                        "revision": assessment.revision,
                        "sha256": assessment.integrity_sha256,
                    }
                    normalized, manifests, _, _ = self._normalize_submission(
                        invitation,
                        assessment,
                        template,
                        answers,
                        artifacts,
                        require_complete=True,
                    )
                    self._require_measured(connection, tenant, invitation_id, manifests)
                    draft = self._get_draft(connection, tenant, invitation_id)
                    current_revision = 0 if draft is None else int(draft["revision"])
                    if current_revision != expected:
                        raise ThirdPartyCollaborationConflict(
                            "draft revision CAS failed before final submission"
                        )
                    attestation_sha = _sha256(
                        {
                            "schema": "lightwork.third-party-collaboration-attestation.v1",
                            "tenant_id": tenant,
                            "invitation_id": invitation_id,
                            "assessment_sha256": assessment.integrity_sha256,
                            "template_sha256": invitation["template_sha256"],
                            "respondent_ref": invitation["respondent_ref"],
                            "notice_sha256": invitation["notice_sha256"],
                            "answers": normalized,
                            "artifacts": list(manifests),
                            "attested": True,
                        }
                    )
                    lifecycle_responses = self._lifecycle_responses(
                        invitation,
                        normalized,
                        manifests,
                        attestation_sha,
                    )
                    lifecycle_operation = (
                        f"portal-final:{invitation_id}:{invitation['token_generation']}:"
                        f"{operation_sha[:32]}"
                    )
                    updated = dict(invitation)
                    updated.update(
                        {
                            "status": "finalizing",
                            "updated_at": now,
                            "revision": int(invitation["revision"]) + 1,
                            "finalization": {
                                "status": "finalizing",
                                "request_sha256": raw_request_sha,
                                "idempotency_sha256": operation_sha,
                                "attestation_sha256": attestation_sha,
                                "question_ids": sorted(lifecycle_responses),
                                "lifecycle_operation": lifecycle_operation,
                                "prepared_responses": lifecycle_responses,
                                "assessment_authority": assessment_authority,
                                "started_at": now,
                                "receipt": None,
                                "finalized_at": None,
                            },
                        }
                    )
                    self._write_invitation(connection, updated)
                    final_draft = {
                        "schema": DRAFT_SCHEMA,
                        "tenant_id": tenant,
                        "invitation_id": invitation_id,
                        "answers": normalized,
                        "artifacts": list(manifests),
                        "state": "finalizing",
                        "revision": current_revision + 1,
                        "submission_sha256": raw_request_sha,
                        "created_at": now if draft is None else draft["created_at"],
                        "updated_at": now,
                    }
                    self._write_draft(connection, final_draft)
                    self._history(
                        connection,
                        tenant,
                        "submission_finalization_started",
                        invitation_id,
                        str(invitation["respondent_ref"]),
                        {
                            "request_sha256": raw_request_sha,
                            "attestation_sha256": attestation_sha,
                            "question_ids": sorted(lifecycle_responses),
                        },
                        now,
                    )
            try:
                lifecycle_receipt = self._lifecycle_store(
                    str(invitation["respondent_ref"])
                ).record_response_batch(
                    tenant,
                    str(invitation["assessment_id"]),
                    responses=lifecycle_responses,
                    attestation_sha256=attestation_sha,
                    expected_revision=int(assessment_authority["revision"]),
                    expected_assessment_sha256=str(assessment_authority["sha256"]),
                    expected_template_revision=int(invitation["template_revision"]),
                    expected_template_sha256=str(invitation["template_sha256"]),
                    idempotency_key=lifecycle_operation,
                )
            except (
                lifecycle.ThirdPartyLifecycleConflict,
                lifecycle.ThirdPartyLifecycleNotFound,
                lifecycle.ThirdPartyLifecyclePermissionDenied,
                lifecycle.ThirdPartyLifecycleValidationError,
            ) as exc:
                with self._connect() as connection:
                    self._begin(connection)
                    current = self._get_invitation(connection, tenant, invitation_id)
                    if current["status"] == "finalizing":
                        failed = dict(current)
                        failed.update(
                            {
                                "status": "conflicted",
                                "updated_at": now,
                                "revision": int(current["revision"]) + 1,
                            }
                        )
                        self._write_invitation(connection, failed)
                        self._history(
                            connection,
                            tenant,
                            "submission_finalization_conflicted",
                            invitation_id,
                            str(invitation["respondent_ref"]),
                            {"error_code": type(exc).__name__},
                            now,
                        )
                raise ThirdPartyCollaborationConflict(
                    "lifecycle authority rejected the final response batch"
                ) from exc
            return self._complete_finalization(
                tenant,
                invitation_id,
                operation_sha,
                raw_request_sha,
                lifecycle_receipt,
                now,
                replay=recovering,
            )

    def rotate_invitation(
        self,
        tenant_id: str,
        invitation_id: str,
        *,
        expires_in_seconds: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> InvitationIssue:
        """Invalidate the current credential and disclose its replacement once."""

        tenant = _tenant(tenant_id)
        invitation_key = _id(invitation_id, "invitation_id")
        expiry = _integer(
            expires_in_seconds,
            "expires_in_seconds",
            _MIN_EXPIRY_SECONDS,
            _MAX_EXPIRY_SECONDS,
        )
        if expiry > self._policy.invitation_ttl_seconds:
            raise ThirdPartyCollaborationValidationError(
                "invitation expiry exceeds the configured portal TTL"
            )
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "rotate_invitation",
            "invitation_id": invitation_key,
            "expires_in_seconds": expiry,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            operation_sha, request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            current = self._get_invitation(connection, tenant, invitation_key)
            if operation is not None:
                return InvitationIssue(
                    invitation=self._safe_invitation(current),
                    token=None,
                    token_disclosed=False,
                    idempotent_replay=True,
                )
            if current["status"] != "active" or current["revision"] != expected:
                raise ThirdPartyCollaborationConflict(
                    "only the exact active invitation revision can be rotated"
                )
            token, token_sha = _new_token(self._token_factory)
            updated = dict(current)
            updated.update(
                {
                    "token_sha256": token_sha,
                    "token_generation": int(current["token_generation"]) + 1,
                    "expires_at": now + expiry,
                    "updated_at": now,
                    "revision": expected + 1,
                }
            )
            if float(updated["retained_until"]) < float(updated["expires_at"]):
                updated["retained_until"] = updated["expires_at"]
            self._write_invitation(connection, updated)
            self._record_operation(
                connection,
                tenant,
                operation_sha,
                request_sha,
                "invitation",
                {"invitation_id": invitation_key},
            )
            self._history(
                connection,
                tenant,
                "invitation_rotated",
                invitation_key,
                actor,
                {"token_generation": updated["token_generation"]},
                now,
            )
            return InvitationIssue(
                invitation=self._safe_invitation(updated),
                token=token,
                token_disclosed=True,
                idempotent_replay=False,
            )

    def revoke_invitation(
        self,
        tenant_id: str,
        invitation_id: str,
        *,
        reason_code: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        """Revoke an invitation unless finalization has already claimed it."""

        tenant = _tenant(tenant_id)
        invitation_key = _id(invitation_id, "invitation_id")
        reason = _id(reason_code, "reason_code")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "revoke_invitation",
            "invitation_id": invitation_key,
            "reason_code": reason,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            operation_sha, request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            current = self._get_invitation(connection, tenant, invitation_key)
            if operation is not None:
                return self._safe_invitation(current)
            if (
                current["status"] not in {"active", "follow_up_required"}
                or current["revision"] != expected
            ):
                raise ThirdPartyCollaborationConflict(
                    "only the exact open invitation revision can be revoked"
                )
            updated = dict(current)
            updated.update(
                {
                    "status": "revoked",
                    "revocation": {
                        "reason_code": reason,
                        "revoked_by": actor,
                        "revoked_at": now,
                    },
                    "updated_at": now,
                    "revision": expected + 1,
                }
            )
            self._write_invitation(connection, updated)
            self._record_operation(
                connection,
                tenant,
                operation_sha,
                request_sha,
                "invitation",
                {"invitation_id": invitation_key},
            )
            self._history(
                connection,
                tenant,
                "invitation_revoked",
                invitation_key,
                actor,
                {"reason_code": reason},
                now,
            )
            return self._safe_invitation(updated)

    def request_follow_up(
        self,
        tenant_id: str,
        invitation_id: str,
        *,
        question_ids: Sequence[str],
        reason_code: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        """Move a finalized invitation to internal follow-up-required state."""

        tenant = _tenant(tenant_id)
        invitation_key = _id(invitation_id, "invitation_id")
        questions = _ids(question_ids, "question_id", minimum=1)
        reason = _id(reason_code, "reason_code")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "request_follow_up",
            "invitation_id": invitation_key,
            "question_ids": list(questions),
            "reason_code": reason,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            operation_sha, request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            current = self._get_invitation(connection, tenant, invitation_key)
            if operation is not None:
                return self._safe_invitation(current)
            allowed = set(current["allowed_question_ids"])  # type: ignore[arg-type]
            if (
                current["status"] != "finalized"
                or current["revision"] != expected
                or not set(questions).issubset(allowed)
            ):
                raise ThirdPartyCollaborationConflict(
                    "follow-up requires an exact finalized invitation question subset"
                )
            updated = dict(current)
            updated.update(
                {
                    "status": "follow_up_required",
                    "follow_up": {
                        "question_ids": list(questions),
                        "reason_code": reason,
                        "requested_by": actor,
                        "requested_at": now,
                    },
                    "updated_at": now,
                    "revision": expected + 1,
                }
            )
            self._write_invitation(connection, updated)
            self._record_operation(
                connection,
                tenant,
                operation_sha,
                request_sha,
                "invitation",
                {"invitation_id": invitation_key},
            )
            self._history(
                connection,
                tenant,
                "follow_up_requested",
                invitation_key,
                actor,
                {"question_ids": list(questions), "reason_code": reason},
                now,
            )
            return self._safe_invitation(updated)

    def reopen_follow_up(
        self,
        tenant_id: str,
        invitation_id: str,
        *,
        expires_in_seconds: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> InvitationIssue:
        """Repin current authority and disclose a fresh follow-up credential once."""

        tenant = _tenant(tenant_id)
        invitation_key = _id(invitation_id, "invitation_id")
        expiry = _integer(
            expires_in_seconds,
            "expires_in_seconds",
            _MIN_EXPIRY_SECONDS,
            _MAX_EXPIRY_SECONDS,
        )
        if expiry > self._policy.invitation_ttl_seconds:
            raise ThirdPartyCollaborationValidationError(
                "invitation expiry exceeds the configured portal TTL"
            )
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "reopen_follow_up",
            "invitation_id": invitation_key,
            "expires_in_seconds": expiry,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            operation_sha, request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            current = self._get_invitation(connection, tenant, invitation_key)
            if operation is not None:
                return InvitationIssue(
                    invitation=self._safe_invitation(current),
                    token=None,
                    token_disclosed=False,
                    idempotent_replay=True,
                )
            follow_up = current["follow_up"]
            if (
                current["status"] != "follow_up_required"
                or current["revision"] != expected
                or not isinstance(follow_up, Mapping)
            ):
                raise ThirdPartyCollaborationConflict(
                    "only the exact follow-up-required revision can be reopened"
                )
            lifecycle_store = self._lifecycle_store()
            try:
                assessment = lifecycle_store.get_assessment(tenant, str(current["assessment_id"]))
                template = lifecycle_store.get_template_version(
                    tenant, assessment.template_id, assessment.template_version
                )
            except lifecycle.ThirdPartyLifecycleError as exc:
                raise ThirdPartyCollaborationConflict(
                    "assessment authority is unavailable for follow-up"
                ) from exc
            questions = _ids(follow_up["question_ids"], "question_id", minimum=1)
            if template.state != "approved" or any(
                assessment.assignments.get(question_id) != current["respondent_ref"]
                for question_id in questions
            ):
                raise ThirdPartyCollaborationConflict(
                    "follow-up respondent authority is no longer valid"
                )
            if now + expiry > assessment.retained_until:
                raise ThirdPartyCollaborationConflict(
                    "follow-up expiry exceeds the assessment authority retention"
                )
            token, token_sha = _new_token(self._token_factory)
            updated = dict(current)
            updated.update(
                {
                    "assessment_revision": assessment.revision,
                    "assessment_sha256": assessment.integrity_sha256,
                    "template_id": template.template_id,
                    "template_version": template.version,
                    "template_revision": template.revision,
                    "template_sha256": template.integrity_sha256,
                    "allowed_question_ids": list(questions),
                    "token_sha256": token_sha,
                    "token_generation": int(current["token_generation"]) + 1,
                    "status": "active",
                    "expires_at": now + expiry,
                    "updated_at": now,
                    "revision": expected + 1,
                    "finalization": None,
                }
            )
            if "assessment_scope_sha256" in current:
                updated["assessment_scope_sha256"] = self._assessment_scope_sha256(
                    assessment, template, questions
                )
            if float(updated["retained_until"]) < float(updated["expires_at"]):
                updated["retained_until"] = updated["expires_at"]
            self._write_invitation(connection, updated)
            connection.execute(
                "DELETE FROM drafts WHERE tenant_id=? AND invitation_id=?",
                (tenant, invitation_key),
            )
            self._record_operation(
                connection,
                tenant,
                operation_sha,
                request_sha,
                "invitation",
                {"invitation_id": invitation_key},
            )
            self._history(
                connection,
                tenant,
                "follow_up_reopened",
                invitation_key,
                actor,
                {
                    "assessment_sha256": assessment.integrity_sha256,
                    "template_sha256": template.integrity_sha256,
                    "question_ids": list(questions),
                    "token_generation": updated["token_generation"],
                },
                now,
            )
            return InvitationIssue(
                invitation=self._safe_invitation(updated),
                token=token,
                token_disclosed=True,
                idempotent_replay=False,
            )

    def set_legal_hold(
        self,
        tenant_id: str,
        invitation_id: str,
        *,
        active: bool,
        evidence_ref: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        """Set or release retention hold; it never extends credential validity."""

        tenant = _tenant(tenant_id)
        invitation_key = _id(invitation_id, "invitation_id")
        if not isinstance(active, bool):
            raise ThirdPartyCollaborationValidationError("active must be boolean")
        evidence = _id(evidence_ref, "legal_hold evidence_ref")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "set_legal_hold",
            "invitation_id": invitation_key,
            "active": active,
            "evidence_ref": evidence,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            operation_sha, request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            current = self._get_invitation(connection, tenant, invitation_key)
            if operation is not None:
                return self._safe_invitation(current)
            if current["revision"] != expected or current["status"] == "finalizing":
                raise ThirdPartyCollaborationConflict(
                    "legal hold requires an exact non-finalizing invitation revision"
                )
            updated = dict(current)
            updated.update(
                {
                    "legal_hold": active,
                    "legal_hold_evidence_ref": evidence,
                    "updated_at": now,
                    "revision": expected + 1,
                }
            )
            self._write_invitation(connection, updated)
            self._record_operation(
                connection,
                tenant,
                operation_sha,
                request_sha,
                "invitation",
                {"invitation_id": invitation_key},
            )
            self._history(
                connection,
                tenant,
                "legal_hold_changed",
                invitation_key,
                actor,
                {"active": active, "evidence_ref": evidence},
                now,
            )
            return self._safe_invitation(updated)

    def purge_expired(
        self,
        tenant_id: str,
        *,
        before: float,
        idempotency_key: str,
    ) -> Mapping[str, int]:
        """Purge retained payloads while preserving operation and hash-chain evidence."""

        tenant = _tenant(tenant_id)
        requested = _timestamp(before, "before")
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        # A cutoff in the future must not delete invitations before their
        # retention ends: nothing later than the current time is purged.
        cutoff = min(now, requested)
        request = {"action": "purge_expired", "before": requested, "actor_ref": actor}
        with cross_process_lock(self.path, strict=True), contextlib.closing(self._connect()) as connection, connection:
            self._begin(connection)
            operation_sha, request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                result = json.loads(operation["result_json"])
                return {"invitations": int(result["invitations"]), "drafts": int(result["drafts"])}
            rows = connection.execute(
                "SELECT invitation_id FROM invitations WHERE tenant_id=? "
                "AND retained_until<=? AND legal_hold=0 AND status!='finalizing'",
                (tenant, cutoff),
            ).fetchall()
            invitation_ids = [str(row["invitation_id"]) for row in rows]
            drafts = 0
            for invitation_id in invitation_ids:
                drafts += connection.execute(
                    "DELETE FROM drafts WHERE tenant_id=? AND invitation_id=?",
                    (tenant, invitation_id),
                ).rowcount
                connection.execute(
                    "DELETE FROM evidence_measurements WHERE tenant_id=? AND invitation_id=?",
                    (tenant, invitation_id),
                )
                connection.execute(
                    "DELETE FROM invitations WHERE tenant_id=? AND invitation_id=?",
                    (tenant, invitation_id),
                )
            result = {"invitations": len(invitation_ids), "drafts": drafts}
            self._record_operation(
                connection,
                tenant,
                operation_sha,
                request_sha,
                "purge",
                result,
            )
            self._history(
                connection,
                tenant,
                "retention_purged",
                "retention",
                actor,
                {"before": cutoff, "counts": result},
                now,
            )
            return result

    def verify_integrity(self, tenant_id: str) -> CollaborationIntegrityVerification:
        """Verify tenant bindings, payload digests, idempotency, and history links."""

        tenant = _tenant(tenant_id)
        verified = 0
        with self._connect() as connection:
            invitation_rows = connection.execute(
                "SELECT * FROM invitations WHERE tenant_id=? ORDER BY invitation_id",
                (tenant,),
            ).fetchall()
            for row in invitation_rows:
                payload = self._get_invitation(connection, tenant, str(row["invitation_id"]))
                if (
                    payload.get("schema") != INVITATION_SCHEMA
                    or payload.get("status") not in INVITATION_STATES
                    or not _DIGEST_RE.fullmatch(str(payload.get("token_sha256", "")))
                    or "token" in payload
                ):
                    raise ThirdPartyCollaborationIntegrityError(
                        "persisted invitation schema is invalid"
                    )
                verified += 1
            draft_rows = connection.execute(
                "SELECT * FROM drafts WHERE tenant_id=? ORDER BY invitation_id",
                (tenant,),
            ).fetchall()
            for row in draft_rows:
                payload = self._payload(row, "draft")
                if (
                    payload.get("schema") != DRAFT_SCHEMA
                    or payload.get("tenant_id") != tenant
                    or payload.get("invitation_id") != row["invitation_id"]
                    or payload.get("revision") != row["revision"]
                    or payload.get("state") != row["state"]
                ):
                    raise ThirdPartyCollaborationIntegrityError(
                        "persisted draft binding is inconsistent"
                    )
                invitation = connection.execute(
                    "SELECT 1 FROM invitations WHERE tenant_id=? AND invitation_id=?",
                    (tenant, row["invitation_id"]),
                ).fetchone()
                if invitation is None:
                    raise ThirdPartyCollaborationIntegrityError(
                        "persisted draft has no invitation authority"
                    )
                verified += 1
            measurement_rows = connection.execute(
                "SELECT * FROM evidence_measurements WHERE tenant_id=? "
                "ORDER BY invitation_id,artifact_id",
                (tenant,),
            ).fetchall()
            for row in measurement_rows:
                measured = self._measurement(
                    row,
                    tenant,
                    str(row["invitation_id"]),
                    str(row["artifact_id"]),
                )
                if (
                    not _DIGEST_RE.fullmatch(str(measured.get("content_sha256", "")))
                    or connection.execute(
                        "SELECT 1 FROM invitations WHERE tenant_id=? AND invitation_id=?",
                        (tenant, row["invitation_id"]),
                    ).fetchone()
                    is None
                ):
                    raise ThirdPartyCollaborationIntegrityError(
                        "persisted evidence measurement has no invitation authority"
                    )
                verified += 1
            operations = connection.execute(
                "SELECT * FROM operations WHERE tenant_id=? ORDER BY operation_sha256",
                (tenant,),
            ).fetchall()
            for row in operations:
                binding = {
                    "tenant_id": row["tenant_id"],
                    "operation_sha256": row["operation_sha256"],
                    "request_sha256": row["request_sha256"],
                    "result_kind": row["result_kind"],
                    "result_json": row["result_json"],
                }
                if _sha256(binding) != row["integrity_sha256"]:
                    raise ThirdPartyCollaborationIntegrityError(
                        "idempotency binding failed integrity verification"
                    )
                try:
                    result = json.loads(row["result_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ThirdPartyCollaborationIntegrityError(
                        "idempotency result is invalid"
                    ) from exc
                if not isinstance(result, dict):
                    raise ThirdPartyCollaborationIntegrityError("idempotency result is invalid")
                verified += 1
            history = connection.execute(
                "SELECT * FROM history WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous = "0" * 64
            expected_sequence = 1
            for row in history:
                payload = self._payload(row, "history")
                if (
                    row["sequence"] != expected_sequence
                    or payload.get("schema") != HISTORY_SCHEMA
                    or payload.get("tenant_id") != tenant
                    or payload.get("sequence") != expected_sequence
                    or payload.get("previous_sha256") != previous
                ):
                    raise ThirdPartyCollaborationIntegrityError(
                        "collaboration history hash chain is inconsistent"
                    )
                previous = str(row["integrity_sha256"])
                expected_sequence += 1
                verified += 1
            return CollaborationIntegrityVerification(
                tenant_id=tenant,
                verified_records=verified,
                history_events=len(history),
                terminal_history_sha256=previous,
            )
