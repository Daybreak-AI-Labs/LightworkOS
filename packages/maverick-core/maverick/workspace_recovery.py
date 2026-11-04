"""Tenant-bound local recovery, with authenticated archives and explicit review.

No caller-selected filesystem paths or unsigned/force restoration are exposed.
Live restore is reserved for the separately started, isolated recovery server.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.metadata
import importlib.util
import io
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import time
import zipfile
from collections import Counter
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from . import backup, file_lock
from .constant_time import text_equals
from .paths import current_tenant_id_strict, data_dir
from .recovery_authorities import authority_policy
from .restore_validation import SCHEMA as REFERENCE_VALIDATION_SCHEMA
from .restore_validation import VERIFICATION_SCOPE

MAX_UPLOAD_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_SNAPSHOTS = 200
MAX_COMPARISON_BYTES = 64 * 1024 * 1024
MAX_CUSTODY_UPLOAD_BYTES = 4 * 1024 * 1024
MAX_CUSTODY_REPORT_BYTES = 64 * 1024
MAX_BOOTSTRAP_RECORD_BYTES = 8 * 1024 * 1024
MAX_RECONCILIATION_ITEMS = 10_000
_ID = re.compile(r"^[0-9a-f]{32}$")
_BOOTSTRAP_SCHEMA = 1
_BOOTSTRAP_TTL_SECONDS = 24 * 60 * 60
_RESTORED_JOB_STATES = frozenset({"pending", "running"})
_RESTORED_CREDENTIAL_PATHS = frozenset({
    "connections/connections.sealed",
    "connections/oauth-setup.sealed",
    "oauth/tokens.sealed",
    "partner/tenants.sealed",
    "privacy_automation/evidence-keys.sealed",
})
_QUARANTINED_JSON_NAMESPACES = frozenset({
    "vendor_onboarding",
    "grc_sync_outbound",
    "grc_outbound_sync_states",
    "discovery_containment_bindings",
    "discovery_containment_actions",
    "provider_accounting_reviews",
})
_PASSIVE_PROTECTED_NAMESPACES = frozenset({
    "usage",
    "llm_gateway_team_budget",
    "mcp_sidecar",
    "grc_outbound_sync_events",
    "pilot_learning_exclusions",
})
_PASSIVE_SQLITE_PATHS = frozenset({
    "world.db",
    "knowledge.db",
    "entity_graph/graph.db",
})
_PASSIVE_AUTHORITY_POLICIES = frozenset({
    "budget_receipt",
    "draft_recovery_retention",
    "flow_idempotency",
    "flow_publication_history",
    "grc_delivery_history",
    "passive_sqlite",
    "privacy_data_map",
    "red_team_result",
    "usage_ledger",
})


class RecoveryError(RuntimeError):
    """Recovery cannot safely complete the requested step."""


def version() -> str:
    return importlib.metadata.version("maverick-agent")


_COHORT = ("maverick", "maverick_dashboard", "maverick_shield", "maverick_channels",
           "maverick_evolve", "maverick_knowledge", "maverick_mcp", "maverick_installer")


def application_identity() -> str:
    """Exact frozen executable, or source bytes of the installed cohort.

    A release number alone is insufficient: two development builds can share
    a version while disagreeing on accounting or other on-disk formats.
    """
    if getattr(sys, "frozen", False):
        return "binary-sha256:" + backup._sha256(Path(sys.executable))
    digest = hashlib.sha256()
    for name in _COHORT:
        spec = importlib.util.find_spec(name)
        digest.update(name.encode() + b"\0")
        if spec is None or not spec.origin:
            digest.update(b"absent\0")
            continue
        root = Path(spec.origin).parent
        for source in sorted(root.rglob("*.py")):
            digest.update(source.relative_to(root).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(source.read_bytes()).digest())
    return "source-sha256:" + digest.hexdigest()


def _root() -> Path:
    return file_lock.ensure_private_directory(_root_path())


def _root_path() -> Path:
    if not current_tenant_id_strict():
        raise RecoveryError("Select a named workspace before using recovery. Shared administration files are excluded.")
    return backup._filesystem_path(data_dir()).absolute()


def _store() -> Path:
    return file_lock.ensure_private_directory(_root() / "backups" / "recovery")


def target() -> str:
    return hashlib.sha256(json.dumps([str(_root()), current_tenant_id_strict()], separators=(",", ":")).encode()).hexdigest()


@contextmanager
def _locked():
    with file_lock.cross_process_lock(_store() / "operations", strict=True):
        yield


def _key() -> bytes:
    injected = os.environ.get("MAVERICK_BACKUP_SIGNING_KEY", "")
    if injected.strip():
        return backup._decode_operator_key(injected)
    path = _store() / "operator.key"
    if not path.exists():
        raise RecoveryError("Create or import a recovery key first, and keep a separate safe copy.")
    file_lock.ensure_private_file(path)
    return backup._decode_operator_key(file_lock.atomic_read_text(path))


def _bootstrap_path() -> Path:
    return _store() / "bootstrap.json"


def _live_state() -> dict:
    """Fingerprint all snapshot-eligible bytes without returning their content."""
    with backup._temporary_directory(prefix="lightwork-bootstrap-state-") as temporary:
        stage = file_lock.ensure_private_directory(Path(temporary) / "data")
        files = backup._stage(_root(), stage, include_keys=False)
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "file_count": len(files),
        "state_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _staged_live_state(stage: Path) -> dict:
    """Bind transformed bytes and deterministic restore-publication markers."""
    with backup._temporary_directory(prefix="lightwork-bootstrap-expected-") as temporary:
        copy = file_lock.ensure_private_directory(Path(temporary) / "data")
        files = backup._stage(stage, copy, include_keys=False)
    # The restore transaction adds derived-index invalidation markers beside
    # canonical rows. Bind those exact bytes before publication too; excluding
    # all markers from the live digest would hide post-publication tampering.
    # An existing staged marker is published verbatim and retains its own hash.
    marker = backup._DERIVED_REBUILD_MARKER_BYTES
    metadata = {"sha256": hashlib.sha256(marker).hexdigest(), "size": len(marker)}
    for relative in backup._flow_index_restore_markers(set(files)):
        files.setdefault(relative, dict(metadata))
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "file_count": len(files),
        "state_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _write_bootstrap(record: dict) -> dict:
    signed = backup._authenticate_for_write(record, _key())
    file_lock.atomic_write_text(
        _bootstrap_path(), json.dumps(signed, ensure_ascii=False, allow_nan=False)
    )
    return signed


def _read_bootstrap(*, actor: str | None = None) -> dict | None:
    path = _bootstrap_path()
    if not path.exists():
        return None
    try:
        if path.stat().st_size > MAX_BOOTSTRAP_RECORD_BYTES:
            raise RecoveryError("The bootstrap recovery record exceeds its size limit.")
        record = json.loads(file_lock.atomic_read_text(path))
        if not isinstance(record, dict):
            raise RecoveryError("The bootstrap recovery record is malformed.")
        with backup.recovery_scope(_root(), current_tenant_id_strict(), _key()):
            backup._verify_authentication(
                record, allow_unsigned=False, label="bootstrap recovery record"
            )
    except (OSError, ValueError, RecursionError, backup.BackupError) as exc:
        raise RecoveryError(
            "Bootstrap recovery state cannot be authenticated. Remain in recovery mode."
        ) from exc
    required = {
        "schema", "kind", "bootstrap_id", "state", "tenant", "target", "actor",
        "key_id", "application_version", "application_identity", "prepared_at",
        "expires_at", "empty_state_sha256", "source_offline_attested",
    }
    if (not required.issubset(record)
            or record.get("schema") != _BOOTSTRAP_SCHEMA
            or record.get("kind") != "virgin-workspace-bootstrap"
            or not isinstance(record.get("bootstrap_id"), str)
            or not _ID.fullmatch(record["bootstrap_id"])
            or record.get("state") not in {
                "prepared", "restore_pending", "reconciliation_required", "completed"
            }
            or record.get("tenant") != current_tenant_id_strict()
            or record.get("target") != target()
            or not isinstance(record.get("actor"), str) or not record["actor"]
            or record.get("key_id") != backup._key_id(_key())
            or (record.get("state") != "completed" and (
                record.get("application_version") != version()
                or record.get("application_identity") != application_identity()
            ))
            or type(record.get("prepared_at")) not in {int, float}
            or type(record.get("expires_at")) not in {int, float}
            or not isinstance(record.get("empty_state_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["empty_state_sha256"])
            or record.get("source_offline_attested") is not True):
        raise RecoveryError(
            "Bootstrap recovery state does not match this app, workspace, or recovery key."
        )
    if actor is not None and record["actor"] != actor:
        raise RecoveryError(
            "The signed-in administrator changed. Prepare bootstrap recovery again."
        )
    return record


def bootstrap_reconciliation_pending() -> bool:
    """Fail closed when a bootstrap restore lacks its completed disposition."""
    # Ordinary startup must remain a read-only check. In particular, do not
    # create a tenant directory, recovery store, or key merely to discover that
    # no bootstrap recovery has ever run.
    try:
        if not current_tenant_id_strict():
            return False
        path = _root_path() / "backups" / "recovery" / "bootstrap.json"
    except (OSError, ValueError) as exc:
        raise RecoveryError(
            "Workspace bootstrap state cannot be resolved. Remain in recovery mode."
        ) from exc
    if not path.exists():
        return False
    try:
        record = _read_bootstrap()
    except RecoveryError:
        return True
    return bool(record and record.get("state") != "completed")


def assert_bootstrap_start_allowed() -> None:
    if bootstrap_reconciliation_pending():
        raise RecoveryError(
            "Workspace bootstrap reconciliation is unfinished. Open Workspace recovery "
            "in Lightwork Desktop before starting normal work."
        )


def prepare_bootstrap(*, isolated: bool, actor: str, source_offline: bool) -> dict:
    """Bind a one-time restore path to a provably empty local workspace."""
    with _locked():
        if not isolated:
            raise RecoveryError(
                "Open local recovery mode from the desktop app before preparing an empty installation."
            )
        if not actor or source_offline is not True:
            raise RecoveryError(
                "Confirm that the source installation is offline before preparing bootstrap recovery."
            )
        blockers = restore_blockers()
        if blockers:
            raise RecoveryError(" ".join(blockers))
        live = _live_state()
        if live["file_count"] != 0:
            raise RecoveryError(
                "Bootstrap recovery is available only before this workspace contains customer or execution state."
            )
        previous = _read_bootstrap(actor=actor)
        retained_keys = None
        if previous is not None and previous.get("state") != "completed":
            retained_keys = previous.get("retained_keys")
            if isinstance(retained_keys, dict) and retained_keys.get("state") == "installing":
                raise RecoveryError(
                    "Retained-key installation was interrupted. Select the exact tested key copy again to finish it."
                )
            if retained_keys is not None:
                # Reauthorizing an expired, still-empty bootstrap must not
                # strand an already installed exact custody set.  Rebind it
                # only after reading and hashing every admitted key again.
                if (not isinstance(retained_keys, dict)
                        or retained_keys.get("state") != "installed"):
                    raise RecoveryError(
                        "Bootstrap key-custody state is incomplete. Remain in recovery mode."
                    )
                _installed_key_material(previous)
        now = time.time()
        record = {
            "schema": _BOOTSTRAP_SCHEMA,
            "kind": "virgin-workspace-bootstrap",
            "bootstrap_id": secrets.token_hex(16),
            "state": "prepared",
            "tenant": current_tenant_id_strict(),
            "target": target(),
            "actor": actor,
            "key_id": backup._key_id(_key()),
            "application_version": version(),
            "application_identity": application_identity(),
            "prepared_at": now,
            "expires_at": now + _BOOTSTRAP_TTL_SECONDS,
            "empty_state_sha256": live["state_sha256"],
            "source_offline_attested": True,
        }
        if retained_keys is not None:
            record["retained_keys"] = {
                key: value for key, value in retained_keys.items()
            }
        _write_bootstrap(record)
        return {key: value for key, value in record.items() if key != "actor"}


def configure_key(*, imported: str | None = None) -> dict:
    with _locked():
        if os.environ.get("MAVERICK_BACKUP_SIGNING_KEY", "").strip() or (_store() / "operator.key").exists():
            raise RecoveryError("A recovery key already exists. Replacing it would strand earlier snapshots.")
        key = backup._decode_operator_key(imported) if imported is not None else secrets.token_bytes(32)
        file_lock.atomic_create_text(_store() / "operator.key", key.hex() + "\n")
        # Returned only by an explicit, authenticated download. Never log it or
        # include it in the archive whose authenticity it establishes.
        return {"key": key.hex(), "key_id": backup._key_id(key)}


def export_key() -> str:
    with _locked():
        if os.environ.get("MAVERICK_BACKUP_SIGNING_KEY", "").strip():
            raise RecoveryError("The deployment custodian manages this recovery key; it cannot be downloaded from the app.")
        return _key().hex()


def encryption_custody() -> dict:
    """Report the custody boundary without generating, reading or exposing keys."""
    from . import crypto_at_rest
    from .config import load_config

    key_path = crypto_at_rest._key_path()
    sources = [key_path] if key_path.is_file() else []
    sources.extend(crypto_at_rest._keyring_dir().glob("*.key"))
    kms = load_config().get("kms") or {}
    external = bool(os.environ.get("MAVERICK_ENCRYPTION_KEY") or os.environ.get("MAVERICK_KMS_KEK")
                    or not isinstance(kms, dict) or kms.get("provider", "local") != "local")
    return {"local_key_files": len(sources), "local_export_available": bool(sources),
            "external_key_custody": external,
            "detail": "Encrypted drafts and other sealed files require their matching encryption keys. Local primary and rotation keys may be shared by several workspaces and are exported separately. Wrapped tenant keys also require their original key-encryption key. Environment and remote key-service keys are not exported."}


def export_encryption_keys() -> bytes:
    """Explicit administrator escrow; never installs or rotates shared keys."""
    from . import crypto_at_rest

    with _locked(), backup._temporary_directory(prefix="lightwork-key-escrow-") as temporary:
        signing_key = _key()
        if encryption_custody()["local_key_files"] > 512:
            raise RecoveryError("The local encryption keyring exceeds the in-app export limit.")
        directory = file_lock.ensure_private_directory(Path(temporary) / "keys")
        try:
            paths = crypto_at_rest.backup_key_material(directory)
        except crypto_at_rest.EncryptionUnavailable as exc:
            raise RecoveryError("No readable local encryption keys are available. Keep the original deployment key or key-service custody separately.") from exc
        output = io.BytesIO()
        manifest = {"schema": 1, "kind": "local-encryption-key-escrow", "workspace": current_tenant_id_strict(),
                    "shared_key_material": True, "created_at": time.time(), "files": {}}
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
            for path in paths:
                if path.stat().st_size > 4096:
                    raise RecoveryError("Local encryption key material has an unexpected size.")
                payload = file_lock.atomic_read_bytes(path)
                manifest["files"][path.name] = {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
                archive.writestr("keys/" + path.name, payload)
            archive.writestr("manifest.json", json.dumps(backup._authenticate_for_write(manifest, signing_key)))
            archive.writestr("README.txt", "Sensitive plaintext encryption keys. Store in your offline vault or secrets manager, separately from snapshots. These keys may unlock several workspaces. This is a custody export, not a workspace archive. Restore shared keys only through your deployment administrator's reviewed key-custody procedure; the app never overwrites shared keys. Environment and remote key-service keys are excluded.\n")
        return output.getvalue()


def restore_blockers() -> list[str]:
    from .config import config_source_errors, load_config
    from .control_plane_lease import override_enabled
    from .governed_records import configured_governed_records_backend
    from .grpc_dispatcher import configured_target
    from .world_model_backends import is_postgres_configured

    cfg = load_config()
    if config_source_errors(include_tenant=True):
        return ["Deployment settings are unreadable; recovery cannot establish local ownership."]
    blockers = []
    if is_postgres_configured():
        blockers.append("PostgreSQL is managed separately. Use its verified database recovery process before changing local files.")
    if configured_governed_records_backend() != "local":
        blockers.append("Governance records use a shared storage authority and require its coordinated recovery process.")
    queue = cfg.get("queue") or {}
    if not isinstance(queue, dict) or queue.get("backend") or configured_target():
        blockers.append("Independently managed workers are configured. Their shutdown and storage recovery require a coordinated administrator procedure.")
    memory = cfg.get("memory") or {}
    if not isinstance(memory, dict) or str(memory.get("backend") or "local") not in {"local", "sqlite", "auto"}:
        blockers.append("An external memory store is configured and is outside this local snapshot.")
    knowledge = cfg.get("knowledge") or {}
    if not isinstance(knowledge, dict) or str(knowledge.get("store") or "sqlite") != "sqlite" or knowledge.get("path"):
        blockers.append("Knowledge storage is outside the default local workspace and needs a coordinated recovery procedure.")
    for name in ("redis", "qdrant", "pgvector"):
        if cfg.get(name):
            blockers.append("An external " + name + " store requires its own verified recovery process.")
    if any(os.environ.get(name, "").strip() for name in ("MAVERICK_QUEUE_REDIS_DSN", "MAVERICK_PG_DSN", "MAVERICK_KNOWLEDGE_DSN", "QDRANT_URL", "REDIS_URL")):
        blockers.append("An external store connection is configured and cannot be restored by this local operation.")
    if override_enabled():
        blockers.append("The single control plane lock is disabled. Exclusive local ownership cannot be established.")
    return blockers


def _archive(identifier: str) -> Path:
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise RecoveryError("Select a snapshot from this workspace.")
    path = _store() / (identifier + ".tgz")
    if not path.is_file():
        raise RecoveryError("This snapshot is no longer available.")
    file_lock.ensure_private_file(path)
    if path.stat().st_size > MAX_UPLOAD_BYTES:
        raise RecoveryError("This snapshot exceeds the in-app archive limit.")
    return path


def _metadata(*, kind: str) -> dict:
    return {"schema": 1, "tenant_id": current_tenant_id_strict(), "application_version": version(),
            "application_identity": application_identity(),
            "kind": kind, "coverage": "tenant-local-files", "consistency": "per-file and SQLite online snapshots"}


def _compatible(manifest: dict) -> None:
    context = manifest.get("recovery")
    if not isinstance(context, dict) or type(context.get("schema")) is not int or context["schema"] != 1:
        raise RecoveryError("This archive lacks a verified workspace/version binding. Use the legacy administrator recovery process.")
    if context.get("tenant_id") != current_tenant_id_strict():
        raise RecoveryError("The snapshot belongs to a different workspace.")
    if context.get("application_version") != version():
        raise RecoveryError("The snapshot requires a different application version. Cross-version restore needs a reviewed migration plan.")
    if context.get("application_identity") != application_identity():
        raise RecoveryError("The snapshot requires a different application build. Restore with its exact build or a reviewed compatibility migration.")


def _inspect(identifier: str) -> dict:
    path = _archive(identifier)
    with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
        manifest = backup.verify_backup(path)
    compatibility = "compatible"
    try:
        _compatible(manifest)
    except RecoveryError as exc:
        compatibility = str(exc)
    files = manifest["files"]
    context = manifest.get("recovery")
    context = context if isinstance(context, dict) else {}
    result = {"id": identifier, "sha256": backup._sha256(path), "bytes": path.stat().st_size,
            "created_at": manifest.get("created_at"), "file_count": len(files),
            "expanded_bytes": sum(row["size"] for row in files.values()),
            "tenant": context.get("tenant_id"),
            "application_version": context.get("application_version"),
            "authenticated": True, "payload_verified": True, "compatibility": compatibility,
            "withheld_key_files": manifest.get("withheld_key_files"),
            "contains_encryption_key": any(name.startswith("keys/") and backup._is_key_material(Path(name)) for name in files),
            "contains_drafts": any(name.startswith("draft-recovery/") for name in files)}
    file_lock.atomic_write_text(_store() / (identifier + ".json"), json.dumps(backup._authenticate_for_write(result, _key())))
    return result


def inspect(identifier: str) -> dict:
    with _locked():
        return _inspect(identifier)


def _comparison_path(identifier: str) -> Path:
    _archive(identifier)  # Validate the server-resolved snapshot identity.
    return _store() / (identifier + ".comparison.json")


def _comparison_page(report: dict, *, offset: int, limit: int) -> dict:
    if type(offset) is not int or not 0 <= offset <= backup.MAX_ARCHIVE_MEMBERS * 2 or type(limit) is not int or not 1 <= limit <= 100:
        raise RecoveryError("The comparison page is outside the supported bounds.")
    return {**{key: value for key, value in report.items() if key not in {"items", "authentication", "actor"}},
            "items": report["items"][offset:offset + limit], "offset": offset, "limit": limit,
            "has_more": offset + limit < report["total_changes"]}


def compare_snapshot(identifier: str, *, actor: str, isolated: bool) -> dict:
    """Keep the latest signed comparison per snapshot; never change live state."""
    if not actor:
        raise RecoveryError("A current administrator identity is required for comparison.")
    with _locked():
        selected = _inspect(identifier)
        with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
            comparison = backup.compare_backup(_archive(identifier))
        if backup._sha256(_archive(identifier)) != selected["sha256"]:
            raise RecoveryError("The snapshot changed during comparison. Verify it again.")
        report = {"schema": 1, "kind": "workspace-recovery-comparison", "report_id": secrets.token_hex(16),
                  "target": target(), "tenant": current_tenant_id_strict(), "actor": actor,
                  "snapshot": {key: selected[key] for key in ("id", "sha256", "application_version", "compatibility")},
                  "application_version": version(), "application_identity": application_identity(),
                  "compared_at": time.time(), "isolated": isolated is True, "restore_authorized": False,
                  "consistency": "per-file and SQLite online snapshots; live state can change after capture",
                  "coverage": "local file metadata only; no payload, business-invariant, schema-compatibility or external-effect validation",
                  **comparison}
        signed = backup._authenticate_for_write(report, _key())
        encoded = json.dumps(signed, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_COMPARISON_BYTES:
            raise RecoveryError("The comparison exceeds the in-app evidence size limit. Existing comparison evidence was retained.")
        file_lock.atomic_write_text(_comparison_path(identifier), encoded)
        return _comparison_page(signed, offset=0, limit=50)


def _read_comparison(identifier: str, report_id: str, *, actor: str) -> dict:
    path = _comparison_path(identifier)
    try:
        if path.stat().st_size > MAX_COMPARISON_BYTES:
            raise RecoveryError("The saved comparison exceeds the evidence size limit.")
        report = json.loads(file_lock.atomic_read_text(path))
        if not isinstance(report, dict):
            raise RecoveryError("The saved comparison is malformed. Compare the snapshot again.")
        with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
            backup._verify_authentication(report, allow_unsigned=False, label="recovery comparison")
    except (OSError, ValueError, RecursionError, backup.BackupError) as exc:
        raise RecoveryError("The signed comparison is unavailable. Compare the snapshot again.") from exc
    if (not isinstance(report.get("snapshot"), dict) or not isinstance(report.get("items"), list)
            or type(report.get("total_changes")) is not int or report["total_changes"] != len(report["items"])
            or type(report.get("protected_changes")) is not int or not 0 <= report["protected_changes"] <= report["total_changes"]
            or any(not isinstance(item, dict) or not isinstance(item.get("path"), str)
                   or item.get("change") not in ("added", "changed", "deleted") or type(item.get("protected")) is not bool
                   for item in report["items"])):
        raise RecoveryError("The saved comparison is malformed. Compare the snapshot again.")
    if (report.get("schema") != 1 or report.get("kind") != "workspace-recovery-comparison"
            or not isinstance(report_id, str) or not _ID.fullmatch(report_id) or not hmac.compare_digest(str(report.get("report_id", "")), report_id)
            or report.get("target") != target() or report.get("tenant") != current_tenant_id_strict()
            or not actor or report.get("actor") != actor or report.get("application_identity") != application_identity()
            or report.get("restore_authorized") is not False
            or report.get("snapshot", {}).get("id") != identifier
            or report.get("snapshot", {}).get("sha256") != backup._sha256(_archive(identifier))):
        raise RecoveryError("The snapshot, account, build or comparison changed. Compare it again.")
    return report


def comparison_page(identifier: str, report_id: str, *, actor: str, offset: int = 0, limit: int = 50) -> dict:
    with _locked():
        return _comparison_page(_read_comparison(identifier, report_id, actor=actor), offset=offset, limit=limit)


def export_comparison(identifier: str, report_id: str, *, actor: str) -> bytes:
    with _locked():
        report = _read_comparison(identifier, report_id, actor=actor)
        return (json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")


def _create(kind: str) -> dict:
    if len(list(_store().glob("*.tgz"))) >= MAX_SNAPSHOTS:
        raise RecoveryError("The local snapshot limit is reached. Export and retire snapshots under your retention policy first.")
    identifier = secrets.token_hex(16)
    path = _store() / (identifier + ".tgz")
    with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
        backup.create_backup(path, recovery_metadata=_metadata(kind=kind))
    try:
        result = _inspect(identifier)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return result


def create() -> dict:
    with _locked():
        return _create("snapshot")


def list_snapshots() -> list[dict]:
    with _locked():
        rows = []
        for path in sorted(_store().glob("*.tgz"), key=lambda item: item.name)[:MAX_SNAPSHOTS]:
            identifier = path.stem
            if not _ID.fullmatch(identifier):
                continue
            # Listing does not claim full verification. Inspect always checks
            # the current signed manifest and all current payload bytes.
            row = {"id": identifier, "bytes": path.stat().st_size}
            try:
                cached = json.loads(file_lock.atomic_read_text(_store() / (identifier + ".json")))
                with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
                    backup._verify_authentication(cached, allow_unsigned=False, label="snapshot index")
                row["created_at"] = cached.get("created_at")
            except (OSError, ValueError, backup.BackupError, RecoveryError):
                pass
            rows.append(row)
        return rows


def retire(identifier: str, expected_sha256: str) -> dict:
    with _locked():
        selected = _inspect(identifier)
        if not hmac.compare_digest(selected["sha256"], expected_sha256):
            raise RecoveryError("The snapshot changed. Verify it again before retiring it.")
        for name in ("review.json", "last-restore.json"):
            path = _store() / name
            if path.exists():
                record = json.loads(file_lock.atomic_read_text(path))
                with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
                    backup._verify_authentication(record, allow_unsigned=False, label="recovery retention record")
                if identifier in {record.get("snapshot"), record.get("safety_snapshot")}:
                    raise RecoveryError("This snapshot is retained for the current or most recent restore.")
        comparison_path = _comparison_path(identifier)
        drill_path = _store() / (identifier + ".drill.json")
        _archive(identifier).unlink()
        (_store() / (identifier + ".json")).unlink(missing_ok=True)
        comparison_path.unlink(missing_ok=True)
        drill_path.unlink(missing_ok=True)
        (_store() / (identifier + ".custody-test.json")).unlink(missing_ok=True)
        return {"retired": True, "id": identifier}


def import_archive(staged: Path) -> dict:
    with _locked():
        if len(list(_store().glob("*.tgz"))) >= MAX_SNAPSHOTS:
            raise RecoveryError("The local snapshot limit is reached.")
        if staged.stat().st_size > MAX_UPLOAD_BYTES:
            raise RecoveryError("The archive is too large for in-app recovery.")
        with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
            manifest = backup.verify_backup(staged)
            # Foreign archives must not populate another tenant's recovery UI.
            context = manifest.get("recovery")
            if not isinstance(context, dict):
                raise RecoveryError("The archive lacks a verified workspace binding.")
            if context.get("tenant_id") != current_tenant_id_strict():
                raise RecoveryError("The snapshot belongs to a different workspace.")
        identifier = secrets.token_hex(16)
        destination = _store() / (identifier + ".tgz")
        backup._copy_verified_file(staged, destination)
        return _inspect(identifier)


def download_path(identifier: str) -> Path:
    with _locked():
        _inspect(identifier)
        return _archive(identifier)


def _last_restore() -> dict | None:
    path = _store() / "last-restore.json"
    if not path.exists():
        return None
    try:
        record = json.loads(file_lock.atomic_read_text(path))
        with backup.recovery_scope(_root(), current_tenant_id_strict(), _key()):
            backup._verify_authentication(record, allow_unsigned=False, label="restore receipt")
        return {name: record.get(name) for name in (
            "state", "snapshot", "safety_snapshot", "completed_at",
            "elapsed_seconds", "restore_mode", "reconciliation",
        )}
    except (OSError, ValueError, backup.BackupError, RecoveryError):
        return {"state": "receipt_unavailable"}


def status() -> dict:
    key_id = None
    key_error = None
    try:
        key_id = backup._key_id(_key())
    except (RecoveryError, backup.BackupError, OSError) as exc:
        key_error = str(exc)
    try:
        bootstrap = _read_bootstrap()
        bootstrap = ({key: value for key, value in bootstrap.items()
                      if key not in {"actor", "authentication", "review"}}
                     if bootstrap is not None else None)
    except RecoveryError as exc:
        bootstrap = {"state": "unavailable", "detail": str(exc)}
    return {"tenant": current_tenant_id_strict(), "target": target(), "application_version": version(),
            "key_id": key_id, "key_error": key_error, "max_archive_bytes": MAX_UPLOAD_BYTES, "max_expanded_bytes": MAX_EXPANDED_BYTES,
            "snapshots": list_snapshots(), "restore_blockers": restore_blockers(), "encryption_custody": encryption_custody(), "last_restore": _last_restore(),
            "bootstrap": bootstrap,
            "coverage": ["Files in the selected workspace, including governance/evidence records, local SQLite databases, audit files and encrypted editor drafts.",
                         "Each SQLite database is copied consistently. Ordinary live snapshots are not a simultaneous transaction across every file."],
            "excluded": ["Other workspaces and shared administration/configuration outside the selected workspace.",
                         "PostgreSQL, remote memory stores, external-provider state, object-storage buckets and independently managed workers.",
                         "Shared encryption keys outside this workspace, and environment/HSM/KMS keys. Keep their custody and restore procedures separately; encrypted data is unusable without the matching key.",
                         "Recovery archives and their signing key. Keep exported archives and a separate safe key copy outside this computer."],
            "verification_scope": VERIFICATION_SCOPE,
            "live_restore_available": False}


def drill(identifier: str, *, actor: str = "local-operator") -> dict:
    if not actor:
        raise RecoveryError("A current operator identity is required for a restore drill.")
    with _locked():
        selected = _inspect(identifier)
        if selected["compatibility"] != "compatible":
            raise RecoveryError(selected["compatibility"])
        started = time.perf_counter()
        with backup._temporary_directory(prefix="lightwork-recovery-drill-") as temporary:
            destination = file_lock.ensure_private_directory(Path(temporary) / "workspace")
            with backup.recovery_scope(destination, current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
                backup.restore_backup(_archive(identifier), replace_existing=True)
            report = {"schema": 1, "kind": "workspace-restore-drill", "report_id": secrets.token_hex(16),
                      "snapshot": identifier, "archive_sha256": selected["sha256"],
                      "snapshot_created_at": selected["created_at"], "target": target(),
                      "tenant": current_tenant_id_strict(), "actor": actor,
                      "application_version": version(), "application_identity": application_identity(),
                      "completed_at": time.time(), "restore_authorized": False,
                      "file_count": selected["file_count"], "restored": True, "post_restore_verified": True,
                      "elapsed_seconds": round(time.perf_counter() - started, 6),
                      "live_workspace_changed": False, "external_stores_tested": False,
                      "application_reference_validation": REFERENCE_VALIDATION_SCHEMA,
                      "verification_scope": VERIFICATION_SCOPE}
        if backup._sha256(_archive(identifier)) != selected["sha256"]:
            raise RecoveryError("The snapshot changed during the restore drill. Verify it again.")
        signed = backup._authenticate_for_write(report, _key())
        encoded = json.dumps(signed, allow_nan=False)
        file_lock.atomic_write_text(_store() / (identifier + ".drill.json"), encoded)
        file_lock.atomic_write_text(_store() / "last-drill.json", encoded)
        return report


def _read_drill(identifier: str, *, actor: str) -> dict | None:
    archive = _archive(identifier)
    path = _store() / (identifier + ".drill.json")
    if not path.exists():
        return None
    try:
        if path.stat().st_size > 64 * 1024:
            raise RecoveryError("The saved drill report exceeds its evidence size limit.")
        report = json.loads(file_lock.atomic_read_text(path))
        if not isinstance(report, dict):
            raise RecoveryError("The saved drill report is malformed. Run a new temporary restore drill.")
        with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
            backup._verify_authentication(report, allow_unsigned=False, label="restore drill report")
    except (OSError, ValueError, RecursionError, backup.BackupError) as exc:
        raise RecoveryError("The signed drill report is unavailable. Run a new temporary restore drill.") from exc
    if (any(not isinstance(report.get(field), str) or not report[field]
            for field in ("report_id", "application_identity", "application_version", "verification_scope"))
            or not _ID.fullmatch(report["report_id"])
            or type(report.get("snapshot_created_at")) not in {int, float} or report["snapshot_created_at"] <= 0
            or type(report.get("completed_at")) not in {int, float} or report["completed_at"] <= 0
            or type(report.get("elapsed_seconds")) not in {int, float} or report["elapsed_seconds"] < 0
            or type(report.get("file_count")) is not int or report["file_count"] < 0
            or report.get("restored") is not True or report.get("post_restore_verified") is not True
            or report.get("live_workspace_changed") is not False or report.get("external_stores_tested") is not False):
        raise RecoveryError("The saved drill report is malformed. Run a new temporary restore drill.")
    if (report.get("schema") != 1 or report.get("kind") != "workspace-restore-drill"
            or report.get("target") != target() or report.get("tenant") != current_tenant_id_strict()
            or not actor or report.get("actor") != actor or report.get("snapshot") != identifier
            or report.get("archive_sha256") != backup._sha256(archive) or report.get("restore_authorized") is not False):
        raise RecoveryError("The snapshot, account or drill report changed. Run a new temporary restore drill.")
    return report


def drill_report(identifier: str, *, actor: str) -> dict:
    with _locked():
        report = _read_drill(identifier, actor=actor)
        if report is None:
            return {"state": "not_recorded", "snapshot": identifier}
        return {**{key: value for key, value in report.items() if key not in {"authentication", "actor"}},
                "state": "recorded", "current_build_matches": report["application_identity"] == application_identity()}


def export_drill_report(identifier: str, report_id: str, *, actor: str) -> bytes:
    with _locked():
        report = _read_drill(identifier, actor=actor)
        if report is None or not isinstance(report_id, str) or not hmac.compare_digest(str(report.get("report_id", "")), report_id):
            raise RecoveryError("The saved drill report changed. Load the selected snapshot's report again.")
        return (json.dumps(report, allow_nan=False, indent=2) + "\n").encode("utf-8")


def _application_roots() -> list[str]:
    """The directories the running application's packages were imported from."""
    roots: list[str] = []
    for name in _COHORT:
        spec = importlib.util.find_spec(name)
        if spec is not None and spec.origin:
            root = str(Path(spec.origin).parent.parent)
            if root not in roots:
                roots.append(root)
    return roots


def _custody_environment(directory: Path, tenant: str) -> dict[str, str]:
    """A fresh child's settings never inherit operator credentials or aliases."""
    allowed = {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE",
               "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "LANG", "LC_ALL", "TZ"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    home = file_lock.ensure_private_directory(directory / "home")
    temporary = file_lock.ensure_private_directory(directory / "temporary")
    profile = file_lock.ensure_private_directory(directory / "profile")
    appdata = file_lock.ensure_private_directory(profile / "AppData")
    file_lock.atomic_create_text(home / "config.toml", "# Isolated recovery rehearsal; no provider configuration.\n")
    paths = [str(Path(sys.executable).parent)]
    if os.name == "nt":
        paths.append(str(Path(os.environ["SystemRoot"]) / "System32"))
    if not getattr(sys, "frozen", False):
        # Import exactly the application that is running (the identity check
        # compares source bytes), never another copy installed elsewhere.
        environment["PYTHONPATH"] = os.pathsep.join(_application_roots())
    environment.update(PATH=os.pathsep.join(paths), HOME=str(profile), USERPROFILE=str(profile),
                       APPDATA=str(appdata), LOCALAPPDATA=str(appdata), TEMP=str(temporary), TMP=str(temporary),
                       TMPDIR=str(temporary), MAVERICK_HOME=str(home), MAVERICK_CONFIG=str(home / "config.toml"),
                       MAVERICK_CLIENT_ID=tenant, PYTHONUTF8="1", PYINSTALLER_RESET_ENVIRONMENT="1", NO_COLOR="1")
    return environment


def _validate_custody_result(result: dict) -> None:
    flags = {"fresh_process": True, "coverage_complete": False, "live_workspace_changed": False, "external_stores_tested": False}
    if (not isinstance(result, dict) or result.get("schema") != 1
            or any(result.get(key) is not value for key, value in flags.items())
            or result.get("key_source") != "uploaded-custody-copy"
            or not isinstance(result.get("application_identity"), str)
            or any(type(result.get(key)) is not int or not 0 <= result[key] <= 10_000_000
                   for key in ("files_scanned", "sqlite_columns_scanned", "unexamined_files"))
            or not isinstance(result.get("checks"), list) or not 1 <= len(result["checks"]) <= 20
            or not isinstance(result.get("limits"), list) or not 1 <= len(result["limits"]) <= 20
            or any(not isinstance(item, str) or not 1 <= len(item) <= 2000 for item in result["limits"])):
        raise RecoveryError("The retained-key test report is malformed. Run a new temporary test.")
    names = set()
    totals = {"detected": 0, "verified": 0, "failed": 0, "unsupported": 0}
    for row in result["checks"]:
        if (not isinstance(row, dict) or not isinstance(row.get("format"), str) or not 1 <= len(row["format"]) <= 100
                or row["format"] in names or set(row) != {"format", *totals}
                or any(type(row.get(key)) is not int or not 0 <= row[key] <= 10_000_000 for key in totals)
                or row["detected"] != row["verified"] + row["failed"] + row["unsupported"]):
            raise RecoveryError("The retained-key test counts are malformed. Run a new temporary test.")
        names.add(row["format"])
        for key in totals:
            totals[key] += row[key]
    expected = ("failed" if totals["failed"] else "incomplete" if totals["unsupported"]
                else "verified_supported_formats" if totals["verified"] else "no_encrypted_records")
    if result.get("outcome") != expected:
        raise RecoveryError("The retained-key test outcome is malformed. Run a new temporary test.")


def test_key_custody(identifier: str, custody_path: Path | bytes, *, expected_sha256: str, actor: str) -> dict:
    """Rehearse using only a separately supplied key copy in a fresh process."""
    if not actor:
        raise RecoveryError("A current administrator identity is required to test retained keys.")
    with _locked():
        selected = _inspect(identifier)
        if selected["compatibility"] != "compatible" or selected["sha256"] != expected_sha256:
            raise RecoveryError("The snapshot or application changed. Verify the selected snapshot again.")
        if isinstance(custody_path, bytes):
            custody = custody_path
        else:
            if not 0 < custody_path.stat().st_size <= MAX_CUSTODY_UPLOAD_BYTES:
                raise RecoveryError("Select a separately retained encryption-key ZIP of at most 4 MiB.")
            custody = file_lock.atomic_read_bytes(custody_path)
        if not 0 < len(custody) <= MAX_CUSTODY_UPLOAD_BYTES:
            raise RecoveryError("The retained key copy exceeds the upload limit.")
        started = time.perf_counter()
        identity = application_identity()
        tenant = current_tenant_id_strict()
        with backup._temporary_directory(prefix="lw-custody-") as temporary:
            directory = file_lock.ensure_private_directory(Path(temporary))
            environment = _custody_environment(directory, tenant)
            file_lock.atomic_create_bytes(directory / "snapshot.tgz", file_lock.atomic_read_bytes(_archive(identifier)))
            file_lock.atomic_create_bytes(directory / "custody.zip", custody)
            file_lock.atomic_create_text(directory / "recovery.key", _key().hex())
            request = {"schema": 1, "tenant": tenant, "archive_sha256": selected["sha256"],
                       "custody_sha256": hashlib.sha256(custody).hexdigest(),
                       "application_identity": identity, "application_version": version()}
            file_lock.atomic_create_text(directory / "request.json", json.dumps(request))
            command = ([sys.executable, "--recovery-rehearsal-worker", str(directory)] if getattr(sys, "frozen", False)
                       else [sys.executable, "-m", "maverick.recovery_rehearsal", str(directory)])
            try:
                completed = subprocess.run(command, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except subprocess.TimeoutExpired as exc:
                raise RecoveryError("The temporary retained-key test exceeded its time limit. Previous evidence was kept.") from exc
            path = directory / "result.json"
            if completed.returncode or not path.is_file() or path.stat().st_size > MAX_CUSTODY_REPORT_BYTES:
                raise RecoveryError("The temporary test could not verify this snapshot and retained key copy. Previous evidence was kept.")
            try:
                result = json.loads(file_lock.atomic_read_text(path))
            except (ValueError, RecursionError) as exc:
                raise RecoveryError("The temporary retained-key test returned an unreadable report. Previous evidence was kept.") from exc
            _validate_custody_result(result)
            if result["application_identity"] != identity:
                raise RecoveryError("The temporary test used a different application build. Previous evidence was kept.")
        # Successful cleanup is part of completion; retain no uploaded keys.
        if backup._sha256(_archive(identifier)) != expected_sha256 or application_identity() != identity:
            raise RecoveryError("The snapshot or application changed during the temporary test. Previous evidence was kept.")
        report = {**result, "kind": "workspace-custody-test", "report_id": secrets.token_hex(16),
                  "snapshot": identifier, "archive_sha256": selected["sha256"], "custody_sha256": request["custody_sha256"],
                  "snapshot_created_at": selected["created_at"], "target": target(), "tenant": tenant, "actor": actor,
                  "application_version": version(), "completed_at": time.time(), "elapsed_seconds": round(time.perf_counter() - started, 6),
                  "restore_authorized": False}
        signed = backup._authenticate_for_write(report, _key())
        encoded = json.dumps(signed, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_CUSTODY_REPORT_BYTES:
            raise RecoveryError("The retained-key report exceeds its evidence size limit. Previous evidence was kept.")
        file_lock.atomic_write_text(_store() / (identifier + ".custody-test.json"), encoded)
        return {**{key: value for key, value in report.items() if key != "actor"}, "state": "recorded", "current_build_matches": True}


def _read_custody_test(identifier: str, *, actor: str) -> dict | None:
    archive = _archive(identifier)
    path = _store() / (identifier + ".custody-test.json")
    if not path.exists():
        return None
    try:
        if path.stat().st_size > MAX_CUSTODY_REPORT_BYTES:
            raise RecoveryError("The saved retained-key report exceeds its evidence size limit.")
        report = json.loads(file_lock.atomic_read_text(path))
        if not isinstance(report, dict):
            raise RecoveryError("The retained-key test report is malformed. Run a new temporary test.")
        with backup.recovery_scope(_root(), current_tenant_id_strict(), _key()):
            backup._verify_authentication(report, allow_unsigned=False, label="retained-key test report")
    except (OSError, ValueError, RecursionError, backup.BackupError) as exc:
        raise RecoveryError("The signed retained-key test is unavailable. Run a new temporary test.") from exc
    _validate_custody_result(report)
    if (any(not isinstance(report.get(field), str) or len(report[field]) != 64
            or any(char not in "0123456789abcdef" for char in report[field])
            for field in ("archive_sha256", "custody_sha256"))
            or not isinstance(report.get("application_version"), str)
            or type(report.get("completed_at")) not in {int, float} or report["completed_at"] <= 0
            or type(report.get("snapshot_created_at")) not in {int, float} or report["snapshot_created_at"] <= 0
            or type(report.get("elapsed_seconds")) not in {int, float} or report["elapsed_seconds"] < 0):
        raise RecoveryError("The retained-key test metadata is malformed. Run a new temporary test.")
    if (report.get("kind") != "workspace-custody-test" or not isinstance(report.get("report_id"), str)
            or not _ID.fullmatch(report["report_id"]) or report.get("target") != target()
            or report.get("tenant") != current_tenant_id_strict() or not actor or report.get("actor") != actor
            or report.get("snapshot") != identifier or report.get("archive_sha256") != backup._sha256(archive)
            or report.get("restore_authorized") is not False):
        raise RecoveryError("The snapshot, account or retained-key report changed. Run a new temporary test.")
    return report


def custody_test_report(identifier: str, *, actor: str) -> dict:
    with _locked():
        report = _read_custody_test(identifier, actor=actor)
        if report is None:
            return {"state": "not_recorded", "snapshot": identifier}
        return {**{key: value for key, value in report.items() if key not in {"authentication", "actor"}},
                "state": "recorded", "current_build_matches": report["application_identity"] == application_identity()}


def export_custody_test(identifier: str, report_id: str, *, actor: str) -> bytes:
    with _locked():
        report = _read_custody_test(identifier, actor=actor)
        if report is None or not isinstance(report_id, str) or not _ID.fullmatch(report_id) or not hmac.compare_digest(report["report_id"], report_id):
            raise RecoveryError("The retained-key test changed. Load the selected snapshot's evidence again.")
        return (json.dumps(report, allow_nan=False, indent=2) + "\n").encode("utf-8")


def install_retained_keys(  # noqa: C901 - crash-safe exact-key transaction
    identifier: str,
    custody: bytes,
    *,
    expected_sha256: str,
    report_id: str,
    isolated: bool,
    actor: str,
) -> dict:
    """Install an already-tested custody copy only into a virgin local install."""
    from . import crypto_at_rest
    from .recovery_rehearsal import _escrow

    with _locked():
        if not isolated:
            raise RecoveryError(
                "Retained keys can be installed only from local recovery mode."
            )
        marker = _read_bootstrap(actor=actor)
        if marker is None or marker["state"] != "prepared":
            raise RecoveryError(
                "Prepare this empty installation for bootstrap recovery first."
            )
        prior_retained = marker.get("retained_keys")
        if (marker.get("expires_at", 0) < time.time()
                and not (isinstance(prior_retained, dict)
                         and prior_retained.get("state") in {"installing", "installed"}
                         and prior_retained.get("started_at", float("inf"))
                         <= marker.get("expires_at", 0))):
            raise RecoveryError(
                "Bootstrap recovery authorization expired before key installation began. Prepare it again."
            )
        live = _live_state()
        if (live["file_count"] != 0
                or live["state_sha256"] != marker["empty_state_sha256"]):
            raise RecoveryError(
                "The workspace is no longer empty. Retained keys were not installed."
            )
        selected = _inspect(identifier)
        if (selected["compatibility"] != "compatible"
                or not hmac.compare_digest(selected["sha256"], expected_sha256)):
            raise RecoveryError(
                "The snapshot or application changed. Verify it again before installing retained keys."
            )
        report = _read_custody_test(identifier, actor=actor)
        custody_sha256 = hashlib.sha256(custody).hexdigest()
        if (report is None or not hmac.compare_digest(str(report.get("report_id", "")), report_id)
                or not hmac.compare_digest(str(report.get("custody_sha256", "")), custody_sha256)
                or not hmac.compare_digest(str(report.get("archive_sha256", "")), expected_sha256)
                or report.get("application_version") != version()
                or report.get("application_identity") != application_identity()
                or report.get("outcome") not in {"verified_supported_formats", "no_encrypted_records"}):
            raise RecoveryError(
                "Test this exact retained-key ZIP against the selected snapshot before installing it."
            )
        if any(os.environ.get(name, "").strip() for name in (
            "MAVERICK_ENCRYPTION_KEY", "MAVERICK_KMS_KEK"
        )):
            raise RecoveryError(
                "This deployment uses externally custodied encryption keys. Keep using that custodian; local keys were not installed."
            )
        if not 0 < len(custody) <= MAX_CUSTODY_UPLOAD_BYTES:
            raise RecoveryError("The retained-key ZIP exceeds the 4 MiB upload limit.")
        with backup.recovery_scope(
            _root(), current_tenant_id_strict(), _key(),
            max_expanded_bytes=MAX_EXPANDED_BYTES,
        ):
            try:
                keys = _escrow(custody, current_tenant_id_strict())
            except (OSError, ValueError, zipfile.BadZipFile, backup.BackupError) as exc:
                raise RecoveryError(
                    "The retained-key ZIP failed authentication or validation. No keys were installed."
                ) from exc
        destinations = {
            name: (crypto_at_rest._key_path() if name == "at_rest.key"
                   else crypto_at_rest._keyring_dir() / name)
            for name in keys
        }
        key_hashes = {
            name: hashlib.sha256(value).hexdigest()
            for name, value in sorted(keys.items())
        }
        key_set_sha256 = hashlib.sha256(json.dumps(
            key_hashes, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        expected_receipt = {
            "snapshot": identifier,
            "archive_sha256": expected_sha256,
            "custody_sha256": custody_sha256,
            "custody_report_id": report_id,
            "file_count": len(keys),
            "key_hashes": key_hashes,
            "key_set_sha256": key_set_sha256,
        }
        retained = marker.get("retained_keys")
        if retained is not None:
            if (not isinstance(retained, dict)
                    or retained.get("state") not in {"installing", "installed"}
                    or any(not hmac.compare_digest(str(retained.get(field, "")), value)
                           for field, value in expected_receipt.items()
                           if isinstance(value, str))
                    or retained.get("file_count") != len(keys)
                    or retained.get("key_hashes") != key_hashes):
                raise RecoveryError(
                    "A different retained-key installation is already bound to this recovery."
                )
        else:
            retained = {
                **expected_receipt,
                "state": "installing",
                "started_at": time.time(),
            }
            _write_bootstrap({
                **{key: value for key, value in marker.items()
                   if key != "authentication"},
                "retained_keys": retained,
            })

        # The at-rest key and rotation ring are shared across local workspaces.
        # Serialize this narrow installation transaction separately from the
        # workspace recovery lock.  A signed ``installing`` receipt is written
        # first, so an interruption can only resume the exact reviewed bytes.
        key_path = crypto_at_rest._key_path()
        key_lock = key_path.parent / ".bootstrap-key-install"
        with file_lock.cross_process_lock(key_lock, strict=True):
            actual_paths: dict[str, Path] = {}
            if os.path.lexists(key_path):
                actual_paths["at_rest.key"] = key_path
            ring = crypto_at_rest._keyring_dir()
            if os.path.lexists(ring):
                file_lock.ensure_private_directory(ring)
                for path in ring.glob("*.key"):
                    actual_paths[path.name] = path
            unexpected = set(actual_paths) - set(destinations)
            if unexpected:
                raise RecoveryError(
                    "Local encryption custody contains keys outside the reviewed copy. "
                    "Bootstrap recovery never replaces or combines key sets."
                )
            for name, path in sorted(destinations.items()):
                expected_text = keys[name].hex()
                if os.path.lexists(path):
                    try:
                        file_lock.ensure_private_file(path)
                        existing_text = file_lock.atomic_read_text(path).strip()
                    except OSError as exc:
                        raise RecoveryError(
                            "An installed encryption key cannot be authenticated. Remain in recovery mode."
                        ) from exc
                    if not text_equals(existing_text.casefold(), expected_text):
                        raise RecoveryError(
                            "An installed encryption key differs from the reviewed custody copy. "
                            "Bootstrap recovery never replaces key custody."
                        )
                    continue
                file_lock.ensure_private_directory(path.parent)
                file_lock.atomic_create_text(path, expected_text)

            # Re-read every byte before converting the recoverable installing
            # receipt into the durable installed receipt.
            for name, path in sorted(destinations.items()):
                try:
                    file_lock.ensure_private_file(path)
                    raw = file_lock.atomic_read_text(path).strip()
                except OSError as exc:
                    raise RecoveryError(
                        "The retained key installation is incomplete. Remain in recovery mode and retry it."
                    ) from exc
                if (not re.fullmatch(r"[0-9a-fA-F]{64}", raw)
                        or not hmac.compare_digest(
                            hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
                            key_hashes[name],
                        )):
                    raise RecoveryError(
                        "The installed encryption-key set differs from the reviewed custody copy."
                    )

            now = time.time()
            retained = {
                **expected_receipt,
                "state": "installed",
                "started_at": retained.get("started_at", now),
                "installed_at": retained.get("installed_at", now),
            }
            _write_bootstrap({
                **{key: value for key, value in marker.items()
                   if key not in {"authentication", "retained_keys"}},
                "expires_at": now + _BOOTSTRAP_TTL_SECONDS,
                "retained_keys": retained,
            })
        return {
            "state": "installed",
            "file_count": len(keys),
            "key_set_sha256": key_set_sha256,
            "snapshot": identifier,
        }


def _installed_key_material(marker: dict) -> dict[str, bytes]:
    """Read only the exact local key set admitted by the bootstrap receipt."""
    from . import crypto_at_rest

    retained = marker.get("retained_keys")
    if not isinstance(retained, dict) or retained.get("state") != "installed":
        raise RecoveryError(
            "Install the separately tested encryption-key copy before validating encrypted records."
        )
    paths: dict[str, Path] = {}
    primary = crypto_at_rest._key_path()
    if primary.exists():
        paths["at_rest.key"] = primary
    ring = crypto_at_rest._keyring_dir()
    try:
        if ring.exists():
            for path in ring.glob("*.key"):
                if not re.fullmatch(r"[0-9a-f]{16}\.key", path.name):
                    raise RecoveryError(
                        "The installed encryption-key set contains an unexpected file."
                    )
                paths[path.name] = path
    except OSError as exc:
        raise RecoveryError(
            "The installed encryption-key set cannot be inspected."
        ) from exc
    keys: dict[str, bytes] = {}
    try:
        for name, path in sorted(paths.items()):
            file_lock.ensure_private_file(path)
            raw = file_lock.atomic_read_text(path).strip()
            if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
                raise ValueError("invalid key")
            key = bytes.fromhex(raw)
            if name != "at_rest.key" and hashlib.sha256(key).hexdigest()[:16] != name[:-4]:
                raise ValueError("key identity mismatch")
            keys[name] = key
    except (OSError, ValueError) as exc:
        raise RecoveryError(
            "The installed encryption-key set no longer matches its reviewed custody copy."
        ) from exc
    digest = hashlib.sha256(json.dumps({
        name: hashlib.sha256(value).hexdigest()
        for name, value in sorted(keys.items())
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (len(keys) != retained.get("file_count")
            or not hmac.compare_digest(str(retained.get("key_set_sha256", "")), digest)):
        raise RecoveryError(
            "The installed encryption-key set changed after custody review."
        )
    return keys


def _record_decryptor_from_keys(
    keys: dict[str, bytes], expected_tenant: str
):
    """Return a no-write record decryptor bound to an explicit custody set."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from . import crypto_at_rest
    from .tenant import kms

    tenant_keys: dict[tuple[str, str], tuple[bytes, str, str]] = {}
    authenticated_wrapped_deks: dict[str, str] = {}

    def decrypt(raw: bytes, tenant: str | None, workspace: Path) -> bytes:
        try:
            if raw.startswith(crypto_at_rest._MAGIC):
                key = keys.get("at_rest.key")
                body = raw[len(crypto_at_rest._MAGIC):]
                if key is None or len(body) < 28:
                    raise ValueError("missing or truncated v1 envelope")
                return AESGCM(key).decrypt(body[:12], body[12:], None)
            if raw.startswith(crypto_at_rest._MAGIC_V2):
                body = raw[len(crypto_at_rest._MAGIC_V2):]
                if len(body) < 36:
                    raise ValueError("truncated v2 envelope")
                key_id, nonce, ciphertext = body[:8], body[8:20], body[20:]
                key = keys.get(key_id.hex() + ".key")
                primary = keys.get("at_rest.key")
                if key is None and primary is not None:
                    if crypto_at_rest._key_fingerprint(primary) == key_id:
                        key = primary
                if key is None:
                    raise ValueError("missing v2 key")
                return AESGCM(key).decrypt(nonce, ciphertext, None)
            if raw.startswith(crypto_at_rest._TENANT_MAGIC):
                if not tenant or tenant != expected_tenant:
                    raise ValueError("tenant mismatch")
                cache_key = (tenant, str(workspace))
                cached = tenant_keys.get(cache_key)
                if cached is None:
                    primary = keys.get("at_rest.key")
                    if primary is None:
                        raise ValueError("missing tenant key custody")
                    wrapped = workspace / "keys" / "dek.wrapped"
                    file_lock.ensure_private_file(wrapped)
                    payload = file_lock.atomic_read_bytes(wrapped)
                    local = kms.LocalKMS(
                        hashlib.sha256(b"maverick-kms-kek/v1\x00" + primary).digest()
                    )
                    tenant_key = local.unwrap(
                        payload,
                        context=kms._tenant_context(tenant, b"dek-wrap"),
                    )
                    if len(tenant_key) != 32:
                        raise ValueError("invalid tenant key")
                    wrapped_sha256 = hashlib.sha256(payload).hexdigest()
                    try:
                        wrapped_relative = wrapped.relative_to(workspace).as_posix().casefold()
                    except ValueError:
                        raise ValueError("wrapped DEK is outside the recovery workspace") from None
                    tenant_keys[cache_key] = (
                        tenant_key, wrapped_relative, wrapped_sha256,
                    )
                else:
                    tenant_key, wrapped_relative, wrapped_sha256 = cached
                plaintext = kms._gcm_open(
                    tenant_key,
                    crypto_at_rest._TENANT_MAGIC,
                    raw,
                    kms._tenant_context(tenant, b"tenant-data"),
                )
                # Record authentication only after the tenant ciphertext tag
                # also verifies.  Merely unwrapping arbitrary bytes is not
                # sufficient evidence that a restored wrapper belongs here.
                authenticated_wrapped_deks[wrapped_relative] = wrapped_sha256
                return plaintext
        except (OSError, ValueError, InvalidTag) as exc:
            raise RecoveryError(
                "An encrypted recovery record did not authenticate under the reviewed retained keys."
            ) from exc
        raise RecoveryError("The recovery record uses an unsupported encryption envelope.")

    def reseal(original: bytes, plaintext: bytes, tenant: str | None, workspace: Path) -> bytes:
        # Authenticate the original before using its retained envelope/key.
        decrypt(original, tenant, workspace)
        nonce = secrets.token_bytes(12)
        if original.startswith(crypto_at_rest._MAGIC):
            return crypto_at_rest._MAGIC + nonce + AESGCM(keys["at_rest.key"]).encrypt(nonce, plaintext, None)
        if original.startswith(crypto_at_rest._MAGIC_V2):
            key_id = original[len(crypto_at_rest._MAGIC_V2):][:8]
            key = keys.get(key_id.hex() + ".key") or keys["at_rest.key"]
            return crypto_at_rest._MAGIC_V2 + key_id + nonce + AESGCM(key).encrypt(nonce, plaintext, None)
        tenant_key = tenant_keys[(tenant, str(workspace))][0]
        return kms._gcm_seal(tenant_key, crypto_at_rest._TENANT_MAGIC, plaintext,
                             kms._tenant_context(tenant, b"tenant-data"))

    decrypt.reseal = reseal
    decrypt._authenticated_wrapped_deks = authenticated_wrapped_deks
    return decrypt


def _bootstrap_record_decryptor(marker: dict):
    """Return a no-write decryptor bound to the installed reviewed key set."""
    return _record_decryptor_from_keys(
        _installed_key_material(marker), current_tenant_id_strict()
    )


def _bootstrap_restore_admission(identifier: str, *, actor: str) -> tuple[str, dict]:
    """Return ordinary or virgin bootstrap mode without weakening either gate."""
    with backup.recovery_scope(
        _root(), current_tenant_id_strict(), _key(),
        max_expanded_bytes=MAX_EXPANDED_BYTES,
    ):
        comparison = backup.compare_backup(_archive(identifier))
    changed = [row for row in comparison["items"] if row["protected"]]
    if not changed:
        return "ordinary", comparison
    marker = _read_bootstrap(actor=actor)
    live = _live_state()
    if (marker is None or marker.get("state") != "prepared"
            or marker.get("expires_at", 0) < time.time()
            or live["file_count"] != 0
            or live["state_sha256"] != marker.get("empty_state_sha256")
            or comparison.get("live_file_count") != 0
            or any(row.get("current") is not None for row in comparison["items"])):
        # Preserve the existing detailed, well-known no-rewind failure.
        with backup.recovery_scope(
            _root(), current_tenant_id_strict(), _key(),
            max_expanded_bytes=MAX_EXPANDED_BYTES,
        ):
            backup.assert_accounting_unchanged(_archive(identifier))
        raise AssertionError("accounting guard did not refuse protected differences")
    return "virgin_bootstrap", comparison


def _is_restored_credential(relative: str) -> bool:
    return authority_policy(relative, is_sqlite=False) == "credential"


def _credential_store_kind(relative: str) -> str:
    """Return the exact supported tenant-sealed credential store kind."""
    parts = tuple(part.casefold() for part in PurePosixPath(relative).parts)
    suffixes = {
        ("connections", "connections.sealed"): "connections",
        ("connections", "oauth-setup.sealed"): "oauth_setup",
        ("oauth", "tokens.sealed"): "oauth_tokens",
        ("partner", "tenants.sealed"): "partner_tenants",
        ("privacy_automation", "evidence-keys.sealed"): "evidence_keys",
    }
    for suffix, kind in suffixes.items():
        if len(parts) >= len(suffix) and parts[-len(suffix):] == suffix:
            return kind
    raise RecoveryError(
        "A restored credential store has no reviewed recovery format. Nothing was restored."
    )


def _credential_json(raw: bytes) -> object:
    """Parse bounded, unambiguous JSON without retaining plaintext."""
    if len(raw) > MAX_BOOTSTRAP_RECORD_BYTES:
        raise RecoveryError(
            "A restored credential store exceeds the supported size. Nothing was restored."
        )

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non-finite constant")

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise RecoveryError(
            "A restored credential store is malformed. Nothing was restored."
        ) from exc


def _validate_credential_document(kind: str, document: object) -> int:
    """Validate the public shape of one secret document, never its values."""
    rows = 0
    if kind in {"connections", "oauth_tokens"}:
        if not isinstance(document, dict) or any(
            not isinstance(name, str) or not name or not isinstance(record, dict)
            for name, record in document.items()
        ):
            raise RecoveryError(
                "A restored credential store has an unsupported schema. Nothing was restored."
            )
        rows = len(document)
    elif kind == "oauth_setup":
        if (
            not isinstance(document, dict)
            or set(document) != {"applications", "consents"}
            or any(not isinstance(document[name], dict) for name in document)
        ):
            raise RecoveryError(
                "A restored credential store has an unsupported schema. Nothing was restored."
            )
        rows = sum(len(document[name]) for name in document)
    elif kind == "partner_tenants":
        if not isinstance(document, list) or any(
            not isinstance(record, dict) for record in document
        ):
            raise RecoveryError(
                "A restored credential store has an unsupported schema. Nothing was restored."
            )
        rows = len(document)
    elif kind == "evidence_keys":
        if (
            not isinstance(document, dict)
            or not isinstance(document.get("keys"), dict)
            or not isinstance(document.get("operations"), dict)
        ):
            raise RecoveryError(
                "A restored credential store has an unsupported schema. Nothing was restored."
            )
        rows = len(document["keys"]) + len(document["operations"])
    else:  # pragma: no cover - caller and registry form one closed set
        raise RecoveryError(
            "A restored credential store has no reviewed recovery format. Nothing was restored."
        )
    if rows > MAX_RECONCILIATION_ITEMS:
        raise RecoveryError(
            "A restored credential store exceeds the supported record limit. Nothing was restored."
        )
    return rows


def _validate_restored_credential(
    path: Path,
    relative: str,
    *,
    decryptor: Callable[[bytes, str | None, Path], bytes] | None,
    tenant: str | None,
    workspace: Path,
) -> dict:
    """Authenticate and validate one retained-key store without rewriting it."""
    if decryptor is None:
        raise RecoveryError(
            "Restored credentials require the reviewed retained encryption keys. Nothing was restored."
        )
    try:
        size = path.stat().st_size
        if size > MAX_BOOTSTRAP_RECORD_BYTES + 128:
            raise RecoveryError(
                "A restored credential store exceeds the supported size. Nothing was restored."
            )
        raw = file_lock.atomic_read_bytes(path)
    except OSError as exc:
        raise RecoveryError(
            "A restored credential store cannot be read safely. Nothing was restored."
        ) from exc
    # All five supported stores use the tenant AEAD envelope. Requiring the
    # envelope prevents a plaintext replacement from passing bootstrap merely
    # because its archive hash and operator signature are otherwise valid.
    from . import crypto_at_rest

    if not raw.startswith(crypto_at_rest._TENANT_MAGIC):
        raise RecoveryError(
            "A restored credential store is not tenant encrypted. Nothing was restored."
        )
    try:
        plaintext = decryptor(raw, tenant, workspace)
    except RecoveryError:
        raise
    except Exception as exc:  # pragma: no cover - injected decryptors stay normalized
        raise RecoveryError(
            "A restored credential store did not authenticate under the reviewed retained keys."
        ) from exc
    kind = _credential_store_kind(relative)
    records = _validate_credential_document(kind, _credential_json(plaintext))
    return {
        "path": relative,
        "kind": kind,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": size,
        "record_count": records,
        "envelope": "tenant-aead-v1",
        "disposition": "preserved_exact_authenticated",
    }


def _reconciliation_id(*parts: object) -> str:
    return hashlib.sha256(
        json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()[:32]


def _reconciliation_item(
    category: str,
    relative: str,
    record_id: object,
    *,
    prior_state: str,
    content_sha256: str,
    safe_state: str,
    requires_external_readback: bool,
    resolved: bool = False,
    resolved_disposition: str = "reauthorization_required",
) -> dict:
    return {
        "id": _reconciliation_id(
            category, relative, str(record_id), prior_state, content_sha256
        ),
        "category": category,
        "source": relative,
        "record_id": str(record_id),
        "prior_state": prior_state,
        "content_sha256": content_sha256,
        "safe_state": safe_state,
        "requires_external_readback": requires_external_readback,
        "state": "resolved" if resolved else "unresolved",
        **({"disposition": resolved_disposition} if resolved else {}),
    }


def _stage_json(path: Path) -> dict | None:
    try:
        raw = file_lock.atomic_read_bytes(path)
        if raw.lstrip().startswith((b"MVKAR", b"MVKTEN", b'"MVKAR', b'"MVKTEN')):
            return None
        value = json.loads(raw)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise RecoveryError(
            "A protected recovery record is unreadable. Nothing was restored."
        ) from exc
    if not isinstance(value, dict):
        raise RecoveryError(
            "A protected recovery record is malformed. Nothing was restored."
        )
    return value


def _write_stage_json(path: Path, record: dict, *, now: float) -> None:
    value = dict(record)
    revision = value.get("revision")
    if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 0:
        value["revision"] = revision + 1
    if "updated_at" in value:
        value["updated_at"] = now
    # An outbox receipt from the source installation must not be emitted again
    # after bootstrap. The signed bootstrap disposition replaces it as the
    # recovery audit boundary.
    value.pop("_audit_pending", None)
    rendered = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    if len(rendered.encode("utf-8")) > 16 * 1024 * 1024:
        raise RecoveryError(
            "A protected recovery record exceeds the supported size. Nothing was restored."
        )
    file_lock.atomic_write_text(path, rendered, mode=0o600)


def _record_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode()).hexdigest()


def _blocked_authority_item(
    policy: str, relative: str, path: Path, *, record_id: str | None = None
) -> dict:
    return _reconciliation_item(
        "unclassified_protected_authority",
        relative,
        record_id or path.stem,
        prior_state=f"unreadable_{policy}",
        content_sha256=backup._sha256(path),
        safe_state="global_start_blocked",
        requires_external_readback=True,
    )


def _reconcile_additional_json_authorities(  # noqa: C901, PLR0912, PLR0915
    stage: Path, *, now: float
) -> tuple[set[str], list[dict], set[str]]:
    """Quarantine every non-legacy authority named by the canonical registry."""
    removed: set[str] = set()
    items: list[dict] = []
    classified: set[str] = set()
    learning_files: list[tuple[str, str, int]] = []
    handled = {
        "agent_trust",
        "browser_vault_credential_authority",
        "compaction_prompt_state_authority",
        "compaction_selection_authority",
        "external_agents",
        "factory_learning_input_authority",
        "federation_outbox",
        "flow_learning_input_authority",
        "flow_idempotency",
        "flow_publication",
        "flow_publication_history",
        "flow_run",
        "identity_authority_registry",
        "identity_change_delivery",
        "identity_change_request",
        "identity_purview_writeback",
        "identity_scheduler",
        "learning_exclusion",
        "llm_team_budget",
        "mcp_call_budget",
        "privacy_identity_key_authority",
        "red_team_campaign",
        "red_team_result",
        "red_team_schedule",
        "usage_ledger",
        "trajectory_learning_input_authority",
        "tool_outcome_learning_authority",
    }
    passive = {
        "flow_idempotency",
        "flow_publication_history",
        "red_team_result",
        "usage_ledger",
    }
    active_flow_states = {
        "queued", "claimed", "running", "resuming", "paused_approval",
        "paused_delay", "paused_event", "indeterminate",
    }
    discard_derived_policies = {
        "compaction_prompt_state_authority",
        "compaction_selection_authority",
        "factory_learning_input_authority",
        "flow_learning_input_authority",
        "trajectory_learning_input_authority",
        "tool_outcome_learning_authority",
    }
    discard_secret_policies = {
        "browser_vault_credential_authority",
        "privacy_identity_key_authority",
    }

    for path in sorted(item for item in stage.rglob("*") if item.is_file()):
        relative = path.relative_to(stage).as_posix()
        policy = authority_policy(relative, is_sqlite=backup._is_sqlite_file(path))
        if policy not in handled:
            continue
        classified.add(relative)
        original_sha256 = backup._sha256(path)

        if policy in passive:
            continue
        if policy == "learning_exclusion":
            learning_files.append((relative, original_sha256, path.stat().st_size))
            continue
        if policy in discard_secret_policies:
            path.unlink()
            removed.add(relative)
            privacy_rotation = policy == "privacy_identity_key_authority"
            items.append(_reconciliation_item(
                "privacy_identity_key" if privacy_rotation else "credential_custody",
                relative,
                path.stem,
                prior_state="restored_untrusted_key_material",
                content_sha256=original_sha256,
                safe_state=(
                    "discarded_rotation_required"
                    if privacy_rotation else "discarded_before_publication"
                ),
                requires_external_readback=False,
                resolved=True,
                resolved_disposition=(
                    "fresh_rotation_required"
                    if privacy_rotation else "discarded_before_publication"
                ),
            ))
            continue
        if policy in discard_derived_policies:
            path.unlink()
            removed.add(relative)
            items.append(_reconciliation_item(
                "derived_learning_state",
                relative,
                path.stem,
                prior_state="restored_derived_state",
                content_sha256=original_sha256,
                safe_state="discarded_before_publication",
                requires_external_readback=False,
                resolved=True,
                resolved_disposition="discarded_before_publication",
            ))
            continue
        if policy in {"agent_trust", "flow_publication"}:
            path.unlink()
            removed.add(relative)
            items.append(_reconciliation_item(
                "agent_enrollment" if policy == "agent_trust" else "flow_publication",
                relative,
                path.stem,
                prior_state="enrolled" if policy == "agent_trust" else "published",
                content_sha256=original_sha256,
                safe_state="removed_reauthorization_required",
                requires_external_readback=False,
                resolved=True,
            ))
            continue

        record = _stage_json(path)
        if record is None:
            items.append(_blocked_authority_item(policy, relative, path))
            continue
        record_id = str(record.get("id") or path.stem)
        changed = False

        if policy == "flow_run":
            prior = str(record.get("status") or "unknown")
            if prior in active_flow_states:
                needs_readback = prior != "queued"
                record["status"] = "indeterminate" if needs_readback else "failed"
                record["resume_at"] = None
                record["human"] = {}
                record["decided_by"] = ""
                record["error"] = (
                    "Restored execution may have crossed an external boundary; "
                    "authoritative readback is required before a new request."
                    if needs_readback else
                    "Restored queued execution was retired before publication."
                )
                changed = True
                items.append(_reconciliation_item(
                    "flow_run", relative, record.get("run_id") or record_id,
                    prior_state=prior,
                    content_sha256=original_sha256,
                    safe_state=record["status"],
                    requires_external_readback=needs_readback,
                    resolved=not needs_readback,
                ))

        elif policy == "external_agents":
            if len(record) > MAX_RECONCILIATION_ITEMS or any(
                not isinstance(value, dict) for value in record.values()
            ):
                raise RecoveryError(
                    "The restored external-agent authority is malformed. Nothing was restored."
                )
            for agent_id, metadata in sorted(record.items()):
                before = _record_sha256(metadata)
                if metadata.get("contained") is not True:
                    metadata["contained"] = True
                    changed = True
                    items.append(_reconciliation_item(
                        "external_agent", relative, agent_id,
                        prior_state="enrolled",
                        content_sha256=before,
                        safe_state="contained_reenrollment_required",
                        requires_external_readback=False,
                        resolved=True,
                    ))
                executions = metadata.get("executions") or {}
                if not isinstance(executions, dict):
                    raise RecoveryError(
                        "The restored external-agent execution ledger is malformed. Nothing was restored."
                    )
                for execution_id, execution in sorted(executions.items()):
                    if not isinstance(execution, dict):
                        raise RecoveryError(
                            "The restored external-agent execution ledger is malformed. Nothing was restored."
                        )
                    prior = str(execution.get("status") or "unknown")
                    if prior not in {"pending", "executing"}:
                        continue
                    needs_readback = prior == "executing"
                    digest = _record_sha256(execution)
                    execution["status"] = "failed" if needs_readback else "denied"
                    execution["finished_at"] = now
                    execution["bootstrap_recovery_hold"] = True
                    execution.pop("digest", None)
                    changed = True
                    items.append(_reconciliation_item(
                        "external_agent_execution", relative, execution_id,
                        prior_state=prior,
                        content_sha256=digest,
                        safe_state=execution["status"],
                        requires_external_readback=needs_readback,
                        resolved=not needs_readback,
                    ))

        elif policy == "federation_outbox":
            queued = record.get("items")
            dropped = record.get("dropped", 0)
            if (not isinstance(queued, list)
                    or isinstance(dropped, bool) or not isinstance(dropped, int)
                    or dropped < 0 or len(queued) > MAX_RECONCILIATION_ITEMS):
                raise RecoveryError(
                    "The restored federation outbox is malformed. Nothing was restored."
                )
            if queued:
                record["items"] = []
                record["bootstrap_retired"] = len(queued)
                changed = True
                items.append(_reconciliation_item(
                    "federation_outbox", relative, "restored-outbox",
                    prior_state=f"queued:{len(queued)}",
                    content_sha256=original_sha256,
                    safe_state="discarded_before_publication",
                    requires_external_readback=True,
                ))

        elif policy in {"llm_team_budget", "mcp_call_budget"}:
            rows = record.get("rows")
            if not isinstance(rows, dict) or len(rows) > MAX_RECONCILIATION_ITEMS:
                raise RecoveryError(
                    "A restored egress budget ledger is malformed. Nothing was restored."
                )
            for value in rows.values():
                if not isinstance(value, dict):
                    raise RecoveryError(
                        "A restored egress budget ledger is malformed. Nothing was restored."
                    )
                value["window_started"] = now
                if policy == "llm_team_budget":
                    value["requests"] = 2**63 - 1
                    value["prompt_tokens"] = 2**63 - 1
                    value["completion_tokens"] = 2**63 - 1
                else:
                    value["count"] = 2**63 - 1
                changed = True
            if rows:
                record["bootstrap_recovery_hold"] = True
                items.append(_reconciliation_item(
                    "egress_budget", relative, policy,
                    prior_state="restored_counter_floor",
                    content_sha256=original_sha256,
                    safe_state="conservative_window_exhausted",
                    requires_external_readback=True,
                ))

        elif policy == "identity_scheduler":
            pending = record.get("pending_changes") or []
            if not isinstance(pending, list):
                raise RecoveryError(
                    "A restored identity-governance scheduler record is malformed. Nothing was restored."
                )
            attempted = (
                isinstance(record.get("callback_lease"), dict)
                or int(record.get("callback_attempts") or 0) > 0
            )
            path.unlink()
            removed.add(relative)
            items.append(_reconciliation_item(
                "identity_scheduler", relative, record_id,
                prior_state=("callback_in_progress" if attempted else
                             "pending_changes" if pending else "scheduled"),
                content_sha256=original_sha256,
                safe_state="removed_fresh_collection_required",
                requires_external_readback=attempted,
                resolved=not attempted,
            ))
            continue

        elif policy == "identity_change_delivery":
            deliveries = record.get("deliveries")
            if not isinstance(deliveries, dict):
                raise RecoveryError(
                    "A restored identity-governance delivery is malformed. Nothing was restored."
                )
            held = False
            for sink, delivery in sorted(deliveries.items()):
                if not isinstance(delivery, dict):
                    raise RecoveryError(
                        "A restored identity-governance delivery is malformed. Nothing was restored."
                    )
                prior = str(delivery.get("status") or "unknown")
                if prior == "delivered":
                    continue
                attempts = delivery.get("attempts", 0)
                if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
                    raise RecoveryError(
                        "A restored identity-governance delivery is malformed. Nothing was restored."
                    )
                needs_readback = attempts > 0 or prior in {"delivering", "failed"}
                delivery["status"] = (
                    "bootstrap_reconciliation_required" if needs_readback
                    else "bootstrap_reauthorization_required"
                )
                delivery["last_error_type"] = "BootstrapRecoveryHold"
                held = True
                items.append(_reconciliation_item(
                    "identity_change_delivery", relative, f"{record_id}:{sink}",
                    prior_state=prior,
                    content_sha256=original_sha256,
                    safe_state=delivery["status"],
                    requires_external_readback=needs_readback,
                    resolved=not needs_readback,
                ))
            if held:
                record["status"] = "bootstrap_reconciliation_required"
                record["health"] = "degraded"
                changed = True

        elif policy == "identity_purview_writeback":
            prior = str(record.get("status") or "unknown")
            attempts = record.get("attempts", 0)
            compensation_attempts = record.get("compensation_attempts", 0)
            if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
                   for value in (attempts, compensation_attempts)):
                raise RecoveryError(
                    "A restored Purview writeback intent is malformed. Nothing was restored."
                )
            active = prior in {"prepared", "failed", "applying", "compensation_failed", "compensating"}
            if active:
                needs_readback = (
                    prior in {"applying", "compensation_failed", "compensating"}
                    or attempts > 0 or compensation_attempts > 0
                )
                record["status"] = (
                    "bootstrap_reconciliation_required" if needs_readback
                    else "bootstrap_reauthorization_required"
                )
                record["operation_claim"] = None
                record["provider_write_state"] = "unknown" if needs_readback else "not_attempted"
                record["health"] = "degraded"
                record["last_error_type"] = "BootstrapRecoveryHold"
                changed = True
                items.append(_reconciliation_item(
                    "identity_purview_writeback", relative, record_id,
                    prior_state=prior,
                    content_sha256=original_sha256,
                    safe_state=record["status"],
                    requires_external_readback=needs_readback,
                    resolved=not needs_readback,
                ))

        elif policy == "identity_authority_registry":
            if record.get("status") == "active":
                prior_payload_sha = str(record.get("payload_sha256") or original_sha256)
                tombstone = {
                    "tenant_sha256": record.get("tenant_sha256"),
                    "restored_payload_sha256": prior_payload_sha,
                    "purged_at": now,
                    "reason": "bootstrap_reenrollment_required",
                }
                record["status"] = "purged"
                record["payload"] = tombstone
                record["payload_sha256"] = _record_sha256(tombstone)
                record["live_acceptance_verified"] = False
                changed = True
                items.append(_reconciliation_item(
                    "identity_authority", relative, record_id,
                    prior_state="active",
                    content_sha256=original_sha256,
                    safe_state="purged_reenrollment_required",
                    requires_external_readback=False,
                    resolved=True,
                ))

        elif policy == "identity_change_request":
            prior = str(record.get("status") or "unknown")
            if prior == "pending_human_or_service_assessment":
                attempted = record.get("provider_write_performed") is True
                record["status"] = "bootstrap_reauthorization_required"
                record["risk_score_generated"] = False
                record["provider_write_performed"] = False
                record["live_acceptance_verified"] = False
                changed = True
                items.append(_reconciliation_item(
                    "identity_change_request", relative, record_id,
                    prior_state=prior,
                    content_sha256=original_sha256,
                    safe_state="bootstrap_reauthorization_required",
                    requires_external_readback=attempted,
                    resolved=not attempted,
                ))

        elif policy == "red_team_schedule":
            prior = str(record.get("status") or "unknown")
            pending_run = record.get("pending_run")
            if prior == "active" or pending_run is not None:
                record["status"] = "cancelled"
                record["pending_run"] = None
                record["bootstrap_cancelled_at"] = now
                changed = True
                items.append(_reconciliation_item(
                    "red_team_schedule", relative, record_id,
                    prior_state="run_claimed" if pending_run is not None else prior,
                    content_sha256=original_sha256,
                    safe_state="cancelled",
                    requires_external_readback=pending_run is not None,
                    resolved=pending_run is None,
                ))

        elif policy == "red_team_campaign":
            prior = str(record.get("status") or "unknown")
            if prior in {"running", "finalizing"}:
                leases = record.get("case_leases") or {}
                if not isinstance(leases, dict):
                    raise RecoveryError(
                        "A restored red-team campaign has malformed leases. Nothing was restored."
                    )
                for lease in leases.values():
                    if not isinstance(lease, dict):
                        raise RecoveryError(
                            "A restored red-team campaign has malformed leases. Nothing was restored."
                        )
                    if lease.get("completed_at") is None:
                        lease["cancelled_at"] = now
                record["status"] = "cancelled"
                record["cancelled"] = {
                    "actor": "system:bootstrap-recovery",
                    "rationale": "Restored campaign retired before normal startup.",
                    "cancelled_at": now,
                }
                record["case_leases"] = leases
                changed = True
                items.append(_reconciliation_item(
                    "red_team_campaign", relative, record_id,
                    prior_state=prior,
                    content_sha256=original_sha256,
                    safe_state="cancelled",
                    requires_external_readback=True,
                ))

        if changed:
            _write_stage_json(path, record, now=now)
        if len(items) > MAX_RECONCILIATION_ITEMS:
            raise RecoveryError(
                "The restored external-work inventory exceeds the supported reconciliation limit."
            )

    if learning_files:
        digest = hashlib.sha256(json.dumps(
            learning_files, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        items.append(_reconciliation_item(
            "learning_exclusion_floor",
            "pilot_learning_exclusions",
            "restored-exclusion-floor",
            prior_state="restored_deny_set",
            content_sha256=digest,
            safe_state="retained_revalidation_required",
            requires_external_readback=True,
        ))
    return removed, items, classified


def _quarantine_bootstrap_records(  # noqa: C901 - linear closed policy matrix
    stage: Path, *, now: float
) -> list[dict]:
    """Put known local external authorities into an intrinsically held state."""
    items: list[dict] = []
    for path in sorted(item for item in stage.rglob("*.json") if item.is_file()):
        relative = path.relative_to(stage).as_posix()
        parts = PurePosixPath(relative).parts
        if len(parts) < 2:
            continue
        namespace = parts[-2].casefold()
        if namespace not in _QUARANTINED_JSON_NAMESPACES:
            continue
        record = _stage_json(path)
        if record is None:
            items.append(_reconciliation_item(
                "encrypted_authority",
                relative,
                path.stem,
                prior_state="encrypted",
                content_sha256=backup._sha256(path),
                safe_state="global_start_blocked",
                requires_external_readback=True,
            ))
            continue
        record_id = record.get("id", path.stem)
        changed = False
        if namespace == "vendor_onboarding":
            operation = record.get("operation")
            if isinstance(operation, dict):
                prior = str(operation.get("state") or "unknown")
                attempts = operation.get("attempts", 0)
                attempted = isinstance(attempts, int) and not isinstance(attempts, bool) and attempts > 0
                digest = hashlib.sha256(json.dumps(
                    operation, sort_keys=True, separators=(",", ":"), default=str
                ).encode()).hexdigest()
                if prior in {"prepared", "approved"} and not attempted:
                    history = list(record.get("operation_history") or [])
                    history.append(dict(operation, state="invalidated",
                                        invalidated_reason="bootstrap_reauthorization_required"))
                    record["operation"] = None
                    record["operation_history"] = history[-100:]
                    record["stage"] = "review_approved"
                    changed = True
                    items.append(_reconciliation_item(
                        "vendor_operation", relative, record_id,
                        prior_state=prior, content_sha256=digest,
                        safe_state="invalidated", requires_external_readback=False,
                        resolved=True,
                    ))
                elif prior in {"executing", "reconciliation_required"} or attempted:
                    record["operation"] = dict(
                        operation,
                        state="reconciliation_required",
                        bootstrap_recovery_hold=True,
                    )
                    record["stage"] = "reconciliation_required"
                    changed = True
                    items.append(_reconciliation_item(
                        "vendor_operation", relative, record_id,
                        prior_state=prior, content_sha256=digest,
                        safe_state="reconciliation_required",
                        requires_external_readback=True,
                    ))
        elif namespace == "grc_sync_outbound":
            prior = str(record.get("status") or "unknown")
            if prior not in {"delivered", "delivered_unconfirmed"}:
                digest = hashlib.sha256(json.dumps(
                    record.get("dispatch") or record,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode()).hexdigest()
                record["bootstrap_prior_status"] = prior
                record["status"] = "bootstrap_reauthorization_required"
                record["last_error"] = (
                    "Restored GRC delivery is held until external readback and a new authorization."
                )
                changed = True
                items.append(_reconciliation_item(
                    "grc_delivery", relative, record_id,
                    prior_state=prior, content_sha256=digest,
                    safe_state="bootstrap_reauthorization_required",
                    requires_external_readback=True,
                ))
            elif prior == "delivered_unconfirmed":
                items.append(_reconciliation_item(
                    "grc_delivery", relative, record_id,
                    prior_state=prior, content_sha256=backup._sha256(path),
                    safe_state=prior, requires_external_readback=True,
                ))
        elif namespace == "grc_outbound_sync_states":
            prior = str(record.get("status") or "unknown")
            if prior != "delivered":
                digest = str(record.get("payload_sha256") or backup._sha256(path))
                record["status"] = "conflict"
                record["failure"] = {
                    "event_id": "bootstrap-" + _reconciliation_id(relative, record_id),
                    "event_kind": "conflict",
                    "category": "bootstrap_external_readback_required",
                    "error_type": "BootstrapRecoveryHold",
                    "retryable": False,
                    "failed_at": now,
                }
                changed = True
                items.append(_reconciliation_item(
                    "grc_semantic_delivery", relative, record_id,
                    prior_state=prior, content_sha256=digest,
                    safe_state="conflict", requires_external_readback=True,
                ))
        elif namespace == "discovery_containment_bindings":
            prior = str(record.get("status") or "unknown")
            if prior == "approved":
                from . import discovery_containment

                record["status"] = "pending_review"
                record["approval"] = None
                record["state_sha256"] = discovery_containment._sha256(
                    discovery_containment._binding_state(record)
                )
                changed = True
                items.append(_reconciliation_item(
                    "containment_binding", relative, record_id,
                    prior_state=prior, content_sha256=backup._sha256(path),
                    safe_state="pending_review", requires_external_readback=False,
                    resolved=True,
                ))
        elif namespace == "discovery_containment_actions":
            prior = str(record.get("status") or "unknown")
            if prior == "prepared":
                items.append(_reconciliation_item(
                    "containment_action", relative, record_id,
                    prior_state=prior, content_sha256=str(
                        record.get("request_sha256") or backup._sha256(path)
                    ),
                    safe_state="indeterminate", requires_external_readback=True,
                ))
        elif namespace == "provider_accounting_reviews":
            prior = str(record.get("state") or "unknown")
            if prior != "completed":
                items.append(_reconciliation_item(
                    "provider_accounting", relative, record_id,
                    prior_state=prior, content_sha256=backup._sha256(path),
                    safe_state="isolated_review_required",
                    requires_external_readback=True,
                ))
        if changed:
            _write_stage_json(path, record, now=now)
        if len(items) > MAX_RECONCILIATION_ITEMS:
            raise RecoveryError(
                "The restored external-work inventory exceeds the supported reconciliation limit."
            )
    return items


def _sqlite_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0]) for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }


def _canonical_stage_payload(value: object) -> tuple[str, str]:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        encoded = rendered.encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RecoveryError(
            "A restored database authority contains invalid canonical JSON. Nothing was restored."
        ) from exc
    if not 1 <= len(encoded) <= 16 * 1024 * 1024:
        raise RecoveryError(
            "A restored database authority exceeds its supported bound. Nothing was restored."
        )
    return rendered, hashlib.sha256(encoded).hexdigest()


def _verified_sqlite_payload(raw: object, digest: object) -> dict:
    try:
        value = json.loads(str(raw))
    except (ValueError, RecursionError) as exc:
        raise RecoveryError(
            "A restored database authority contains unreadable JSON. Nothing was restored."
        ) from exc
    if not isinstance(value, dict):
        raise RecoveryError(
            "A restored database authority is malformed. Nothing was restored."
        )
    _, expected = _canonical_stage_payload(value)
    if not isinstance(digest, str) or not hmac.compare_digest(digest, expected):
        raise RecoveryError(
            "A restored database authority failed integrity verification. Nothing was restored."
        )
    return value


def _reconcile_world_database(
    connection: sqlite3.Connection, relative: str, *, now: float
) -> list[dict]:
    """Invalidate restored human approvals while retaining no-replay receipts."""
    tables = _sqlite_tables(connection)
    required = {
        "approvals",
        "approval_signoffs",
        "goals",
        "provider_operation_attempts",
    }
    if not required.issubset(tables):
        raise RecoveryError(
            "The restored world database lacks current approval authority tables. Nothing was restored."
        )
    columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(approvals)")
    }
    if not {
        "id", "action", "risk", "status", "requested_at", "decided_at",
        "claimed_by", "claimed_at", "decided_by",
    }.issubset(columns):
        raise RecoveryError(
            "The restored world approval schema is unsupported. Nothing was restored."
        )
    items: list[dict] = []
    rows = connection.execute(
        "SELECT id,action,risk,status,requested_at,claimed_by,claimed_at "
        "FROM approvals WHERE status IN ('pending','approved') ORDER BY id"
    ).fetchall()
    for approval_id, action, risk, state, requested_at, claimed_by, claimed_at in rows:
        digest = _record_sha256({
            "id": approval_id,
            "action": action,
            "risk": risk,
            "status": state,
            "requested_at": requested_at,
            "claimed_by": claimed_by,
            "claimed_at": claimed_at,
        })
        attempted = str(state) == "approved" or claimed_by is not None or claimed_at is not None
        items.append(_reconciliation_item(
            "approval_authority", relative, approval_id,
            prior_state=str(state),
            content_sha256=digest,
            safe_state="denied_reauthorization_required",
            requires_external_readback=attempted,
            resolved=not attempted,
        ))
    if rows:
        connection.execute(
            "UPDATE approvals SET status='denied', decided_at=?, decided_by=?, "
            "claimed_by=NULL, claimed_at=NULL WHERE status IN ('pending','approved')",
            (now, "system:bootstrap-recovery"),
        )
    goal_columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(goals)")
    }
    if not {
        "id", "title", "status", "updated_at", "result", "execution_principal"
    }.issubset(goal_columns):
        raise RecoveryError(
            "The restored world execution schema is unsupported. Nothing was restored."
        )
    goals = connection.execute(
        "SELECT id,title,status,updated_at,execution_principal FROM goals "
        "WHERE status IN ('pending','active') ORDER BY id"
    ).fetchall()
    for goal_id, title, state, updated_at, principal in goals:
        attempted = str(state) == "active"
        items.append(_reconciliation_item(
            "goal_execution",
            relative,
            goal_id,
            prior_state=str(state),
            content_sha256=_record_sha256({
                "id": goal_id,
                "title": title,
                "status": state,
                "updated_at": updated_at,
                "execution_principal": principal,
            }),
            safe_state="blocked_reauthorization_required",
            requires_external_readback=attempted,
            resolved=not attempted,
        ))
    if goals:
        message = "[bootstrap recovery: prior execution authority retired]"
        connection.execute(
            "UPDATE goals SET status='blocked', result=CASE "
            "WHEN result IS NULL OR result='' THEN ? ELSE result || char(10) || ? END, "
            "updated_at=? WHERE status IN ('pending','active')",
            (message, message, now),
        )
    return items


def _reconcile_privacy_discovery_database(
    connection: sqlite3.Connection, relative: str, *, now: float
) -> list[dict]:
    """Disable restored scans and make queued or leased work terminal."""
    tables = _sqlite_tables(connection)
    if not {"schedules", "jobs", "operations"}.issubset(tables):
        raise RecoveryError(
            "The restored privacy-discovery database schema is unsupported. Nothing was restored."
        )
    items: list[dict] = []
    schedules = connection.execute(
        "SELECT tenant_id,schedule_id,active,payload_json,integrity_sha256 "
        "FROM schedules WHERE active=1 ORDER BY tenant_id,schedule_id"
    ).fetchall()
    for tenant, schedule_id, active, raw, digest in schedules:
        payload = _verified_sqlite_payload(raw, digest)
        if payload.get("active") is not True or int(active) != 1:
            raise RecoveryError(
                "A restored privacy-discovery schedule index is inconsistent. Nothing was restored."
            )
        prior_sha = str(digest)
        payload["active"] = False
        payload["revision"] = int(payload.get("revision") or 0) + 1
        payload["updated_at"] = now
        rendered, changed_sha = _canonical_stage_payload(payload)
        connection.execute(
            "UPDATE schedules SET active=0,payload_json=?,integrity_sha256=? "
            "WHERE tenant_id=? AND schedule_id=?",
            (rendered, changed_sha, tenant, schedule_id),
        )
        items.append(_reconciliation_item(
            "privacy_discovery_schedule", relative, schedule_id,
            prior_state="active", content_sha256=prior_sha,
            safe_state="disabled_reauthorization_required",
            requires_external_readback=False, resolved=True,
        ))

    jobs = connection.execute(
        "SELECT tenant_id,job_id,state,payload_json,integrity_sha256 "
        "FROM jobs WHERE state IN ('queued','leased') ORDER BY tenant_id,job_id"
    ).fetchall()
    for tenant, job_id, state, raw, digest in jobs:
        payload = _verified_sqlite_payload(raw, digest)
        if payload.get("state") != state:
            raise RecoveryError(
                "A restored privacy-discovery job index is inconsistent. Nothing was restored."
            )
        needs_readback = str(state) == "leased"
        payload["state"] = "dead_letter"
        payload["lease_owner"] = None
        payload["lease_until"] = None
        payload["next_attempt_at"] = now
        payload["revision"] = int(payload.get("revision") or 0) + 1
        payload["last_error_code"] = (
            "bootstrap_outcome_unknown" if needs_readback
            else "bootstrap_reauthorization_required"
        )
        rendered, changed_sha = _canonical_stage_payload(payload)
        connection.execute(
            "UPDATE jobs SET state='dead_letter',next_attempt_at=?,lease_until=NULL,"
            "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND job_id=?",
            (now, rendered, changed_sha, tenant, job_id),
        )
        items.append(_reconciliation_item(
            "privacy_discovery_job", relative, job_id,
            prior_state=str(state), content_sha256=str(digest),
            safe_state="dead_letter", requires_external_readback=needs_readback,
            resolved=not needs_readback,
        ))
    return items


def _reconcile_privacy_remediation_database(
    connection: sqlite3.Connection, relative: str, *, now: float
) -> list[dict]:
    """Cancel fresh work and hold possibly attempted callbacks as ambiguous."""
    tables = _sqlite_tables(connection)
    required = {"remediation_work", "remediation_history", "remediation_operations"}
    if not required.issubset(tables):
        raise RecoveryError(
            "The restored privacy-remediation database schema is unsupported. Nothing was restored."
        )
    rows = connection.execute(
        "SELECT tenant_sha256,work_id,state,revision,payload_json,integrity_sha256 "
        "FROM remediation_work WHERE state IN ('queued','leased','ambiguous') "
        "ORDER BY tenant_sha256,work_id"
    ).fetchall()
    items: list[dict] = []
    for tenant, work_id, state, revision, raw, digest in rows:
        payload = _verified_sqlite_payload(raw, digest)
        if (payload.get("state") != state
                or payload.get("revision") != revision):
            raise RecoveryError(
                "A restored privacy-remediation index is inconsistent. Nothing was restored."
            )
        needs_readback = str(state) in {"leased", "ambiguous"}
        safe_state = "ambiguous" if needs_readback else "cancelled"
        if state != "ambiguous":
            payload["state"] = safe_state
            payload["previous_integrity_sha256"] = str(digest)
            payload["revision"] = int(revision) + 1
            payload["updated_at"] = now
            payload["lease_until"] = None
            payload["last_error_code"] = (
                "bootstrap_outcome_unknown" if needs_readback
                else "bootstrap_reauthorization_required"
            )
            if needs_readback:
                payload["ambiguous_at"] = now
            else:
                payload["lease_owner_sha256"] = None
                payload["lease_token_sha256"] = None
            rendered, changed_sha = _canonical_stage_payload(payload)
            connection.execute(
                "UPDATE remediation_work SET state=?,next_attempt_at=?,lease_until=NULL,"
                "revision=?,payload_json=?,integrity_sha256=? "
                "WHERE tenant_sha256=? AND work_id=? AND revision=?",
                (
                    safe_state,
                    payload.get("next_attempt_at", now),
                    payload["revision"],
                    rendered,
                    changed_sha,
                    tenant,
                    work_id,
                    revision,
                ),
            )
            connection.execute(
                "INSERT INTO remediation_history(tenant_sha256,work_id,revision,state,"
                "payload_json,integrity_sha256) VALUES(?,?,?,?,?,?)",
                (tenant, work_id, payload["revision"], safe_state, rendered, changed_sha),
            )
        items.append(_reconciliation_item(
            "privacy_remediation", relative, work_id,
            prior_state=str(state), content_sha256=str(digest),
            safe_state=safe_state, requires_external_readback=needs_readback,
            resolved=not needs_readback,
        ))
    return items


def _tree_sha256(root: Path) -> str:
    entries: list[tuple[str, str, int]] = []
    if root.exists():
        if not root.is_dir():
            raise RecoveryError(
                "A restored reconciliation source changed type. Nothing was restored."
            )
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            entries.append((
                path.relative_to(root).as_posix(),
                backup._sha256(path),
                path.stat().st_size,
            ))
    return hashlib.sha256(json.dumps(
        entries, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()


def _bind_reconciliation_sources(stage: Path, items: list[dict]) -> None:
    """Bind each disposition to its exact post-transform local state."""
    for item in items:
        if item.get("category") == "queued_work":
            item["safe_source"] = {"kind": "job_row"}
            continue
        try:
            relative = backup._safe_relative_path(
                str(item.get("source") or ""), label="reconciliation source"
            )
        except backup.BackupError as exc:
            raise RecoveryError(
                "A restored reconciliation source is invalid. Nothing was restored."
            ) from exc
        path = stage.joinpath(*relative.parts)
        if path.is_file():
            item["safe_source"] = {
                "kind": "file_sha256",
                "sha256": backup._sha256(path),
            }
        elif path.is_dir():
            item["safe_source"] = (
                {"kind": "tree_sha256", "sha256": _tree_sha256(path)}
                if any(child.is_file() for child in path.rglob("*"))
                else {"kind": "absent"}
            )
        elif not os.path.lexists(path):
            item["safe_source"] = {"kind": "absent"}
        else:
            raise RecoveryError(
                "A restored reconciliation source has an unsupported path type. Nothing was restored."
            )


def _reconcile_bootstrap_stage(  # noqa: C901 - one fail-closed staged transaction
    stage: Path,
    *,
    decryptor: Callable[[bytes, str | None, Path], bytes] | None = None,
    tenant: str | None = None,
) -> tuple[set[str], dict]:
    """Make restored queued work non-claimable before transactional publication."""
    stage = backup._filesystem_path(stage)
    removed: set[str] = set()
    preserved_credentials: list[dict] = []
    wrapped_deks: list[tuple[str, Path, str, int]] = []
    retired_task_files: dict[str, list[tuple[str, str, int]]] = {}
    protected = []
    for path in sorted(item for item in stage.rglob("*") if item.is_file()):
        relative = path.relative_to(stage).as_posix()
        parts = PurePosixPath(relative).parts
        lowered = tuple(part.casefold() for part in parts)
        if "task-file-recovery" in lowered[:-1]:
            index = lowered.index("task-file-recovery")
            root = "/".join(parts[:min(index + 2, len(parts))])
            retired_task_files.setdefault(root, []).append(
                (relative, backup._sha256(path), path.stat().st_size)
            )
            path.unlink()
            removed.add(relative)
            continue
        policy = authority_policy(
            relative,
            is_sqlite=backup._is_sqlite_file(path),
        )
        if policy == "plaintext_credential_residue":
            raise RecoveryError(
                "A restored credential store contains legacy plaintext. "
                "Nothing was restored; migrate it to tenant-encrypted custody "
                "in the source installation and create a new snapshot."
            )
        if policy == "wrapped_tenant_dek":
            digest = backup._sha256(path)
            size = path.stat().st_size
            wrapped_deks.append((relative, path, digest, size))
            protected.append((relative, digest, size))
            continue
        if _is_restored_credential(relative):
            credential = _validate_restored_credential(
                path,
                relative,
                decryptor=decryptor,
                tenant=tenant,
                workspace=stage,
            )
            preserved_credentials.append(credential)
            protected.append((relative, credential["sha256"], credential["size"]))
            continue
        if backup._accounting_file(relative, path):
            protected.append((relative, backup._sha256(path), path.stat().st_size))

    job_counts: Counter[str] = Counter()
    items = []
    from .channel_recovery import stage_authorities

    channel_items, channel_classified = stage_authorities(
        stage, decryptor=decryptor, tenant=tenant, now=time.time(), make_item=_reconciliation_item,
        blocked_item=lambda relative, namespace, digest: _reconciliation_item(
            "unclassified_protected_authority", relative, Path(relative).stem,
            prior_state=f"unreadable_{namespace}", content_sha256=digest,
            safe_state="global_start_blocked", requires_external_readback=True),
    )
    items.extend(channel_items)
    for credential in preserved_credentials:
        items.append(_reconciliation_item(
            "credential_custody",
            credential["path"],
            credential["kind"],
            prior_state="retained_key_ciphertext",
            content_sha256=credential["sha256"],
            safe_state="preserved_exact_authenticated",
            requires_external_readback=False,
            resolved=True,
            resolved_disposition="preserved_exact_authenticated",
        ))
    authenticated_wrapped_deks = 0
    for relative, path, digest, _size in wrapped_deks:
        # A successful tenant-AEAD record validation proves that this exact
        # wrapped DEK opened under the separately retained primary key.  With
        # no such authenticated ciphertext, rotate instead of silently trusting
        # a restored wrapper.
        authenticated_sources = getattr(
            decryptor, "_authenticated_wrapped_deks", {}
        )
        authenticated = (
            isinstance(authenticated_sources, dict)
            and hmac.compare_digest(
                str(authenticated_sources.get(relative.casefold(), "")), digest
            )
        )
        if authenticated:
            authenticated_wrapped_deks += 1
            items.append(_reconciliation_item(
                "credential_custody",
                relative,
                "tenant-data-encryption-key",
                prior_state="retained_key_wrapped_ciphertext",
                content_sha256=digest,
                safe_state="preserved_exact_authenticated",
                requires_external_readback=False,
                resolved=True,
                resolved_disposition="preserved_exact_authenticated",
            ))
            continue
        if preserved_credentials:
            raise RecoveryError(
                "The restored wrapped tenant key did not authenticate under "
                "the reviewed retained key set. Nothing was restored."
            )
        path.unlink()
        removed.add(relative)
        items.append(_reconciliation_item(
            "credential_custody",
            relative,
            "tenant-data-encryption-key",
            prior_state="restored_unauthenticated_wrapped_key",
            content_sha256=digest,
            safe_state="discarded_rotation_required",
            requires_external_readback=False,
            resolved=True,
            resolved_disposition="fresh_rotation_required",
        ))
    for source, files in sorted(retired_task_files.items()):
        digest = hashlib.sha256(json.dumps(
            sorted(files), separators=(",", ":")
        ).encode()).hexdigest()
        items.append(_reconciliation_item(
            "task_file_recovery", source, source.rsplit("/", 1)[-1],
            prior_state="restored_copy", content_sha256=digest,
            safe_state="discarded_before_publication",
            requires_external_readback=False, resolved=True,
        ))
    additional_removed, additional_items, additional_classified = (
        _reconcile_additional_json_authorities(stage, now=time.time())
    )
    removed.update(additional_removed)
    items.extend(additional_items)
    items.extend(_quarantine_bootstrap_records(stage, now=time.time()))
    classified_sources = {
        str(item["source"]) for item in items
        if isinstance(item.get("source"), str)
    } | additional_classified | channel_classified
    indexed_marker = stage / "provider_spend.sqlite3.active"
    if indexed_marker.exists() and not (
        (stage / "provider_spend.sqlite3").exists()
        and (stage / "provider_spend.sqlite3.seal").exists()
    ):
        raise RecoveryError("The restored indexed provider spending records are incomplete.")
    spend_path = stage / "provider_spend.json"
    if spend_path.exists():
        classified_sources.add("provider_spend.json")
        spend = None if indexed_marker.exists() else _stage_json(spend_path)
        if indexed_marker.exists():
            # This is the immutable pre-migration source, not the current
            # accounting authority. The indexed database below owns holds.
            pass
        elif spend is None:
            items.append(_reconciliation_item(
                "provider_accounting",
                "provider_spend.json",
                "encrypted-ledger",
                prior_state="encrypted",
                content_sha256=backup._sha256(spend_path),
                safe_state="global_start_blocked",
                requires_external_readback=True,
            ))
        else:
            reservations = spend.get("__provider_reservations_v1__", {})
            if not isinstance(reservations, dict):
                raise RecoveryError(
                    "The restored provider accounting inventory is malformed. Nothing was restored."
                )
            for period, providers in sorted(reservations.items()):
                if not isinstance(providers, dict):
                    raise RecoveryError(
                        "The restored provider accounting inventory is malformed. Nothing was restored."
                    )
                for provider, rows in sorted(providers.items()):
                    if not isinstance(rows, dict):
                        raise RecoveryError(
                            "The restored provider accounting inventory is malformed. Nothing was restored."
                        )
                    for request_id, row in sorted(rows.items()):
                        if not isinstance(row, dict) or row.get("state") == "settled":
                            continue
                        digest = hashlib.sha256(json.dumps(
                            row, sort_keys=True, separators=(",", ":"), default=str
                        ).encode()).hexdigest()
                        item = _reconciliation_item(
                            "provider_reservation",
                            "provider_spend.json",
                            request_id,
                            prior_state=str(row.get("state") or "unknown"),
                            content_sha256=digest,
                            safe_state="held",
                            requires_external_readback=True,
                        )
                        item["provider"] = str(provider)[:64]
                        item["period"] = str(period)[:16]
                        items.append(item)
    required_path = stage / "provider_spend.json.required"
    if required_path.exists():
        classified_sources.add("provider_spend.json.required")
        if not indexed_marker.exists():
            items.append(_reconciliation_item(
                "provider_accounting",
                "provider_spend.json.required",
                "repair-required",
                prior_state="repair_required",
                content_sha256=backup._sha256(required_path),
                safe_state="isolated_review_required",
                requires_external_readback=True,
            ))
    if indexed_marker.exists():
        classified_sources.add("provider_spend.sqlite3.active")
        classified_sources.add("provider_spend.sqlite3.seal")
        items.append(_reconciliation_item(
            "provider_accounting", "provider_spend.sqlite3.active",
            "indexed-ledger", prior_state="restored",
            content_sha256=backup._sha256(indexed_marker),
            safe_state="isolated_review_required",
            requires_external_readback=True,
        ))
    for marker in stage.rglob("provider_spend.sqlite3.active"):
        if marker == indexed_marker:
            continue
        if not marker.with_suffix("").is_file() or not marker.parent.joinpath(
            "provider_spend.sqlite3.seal"
        ).is_file():
            raise RecoveryError("The restored indexed provider spending records are incomplete.")
        relative = marker.relative_to(stage).as_posix()
        classified_sources.add(relative)
        classified_sources.add((marker.parent / "provider_spend.sqlite3.seal").relative_to(stage).as_posix())
        for legacy_name in ("provider_spend.json", "provider_spend.json.required"):
            legacy = marker.parent / legacy_name
            if legacy.exists():
                classified_sources.add(legacy.relative_to(stage).as_posix())
        items.append(_reconciliation_item(
            "provider_accounting", relative, "indexed-ledger",
            prior_state="restored", content_sha256=backup._sha256(marker),
            safe_state="isolated_review_required", requires_external_readback=True,
        ))
    job_database_count = 0
    now = time.time()
    for db in sorted(item for item in stage.rglob("*") if item.is_file()):
        if not backup._is_sqlite_file(db):
            continue
        relative = db.relative_to(stage).as_posix()
        connection = sqlite3.connect(str(backup._filesystem_path(db)))
        try:
            classified_sources.add(relative)
            policy = authority_policy(relative, is_sqlite=True)
            connection.execute("BEGIN IMMEDIATE")
            if policy == "jobs":
                tables = _sqlite_tables(connection)
                if "jobs" not in tables:
                    raise RecoveryError(
                        "The restored job database has an unsupported schema. Nothing was restored."
                    )
                columns = {
                    str(row[1]) for row in connection.execute("PRAGMA table_info(jobs)")
                }
                required = {
                    "id", "kind", "payload", "run_at", "status", "attempts",
                    "last_error", "created_at", "updated_at",
                }
                if not required.issubset(columns):
                    raise RecoveryError(
                        "A restored job database has an unsupported schema. Nothing was restored."
                    )
                job_database_count += 1
                rows = connection.execute(
                    "SELECT id, kind, payload, status FROM jobs "
                    "WHERE status IN ('pending','running') ORDER BY id"
                ).fetchall()
                for job_id, kind, payload, state in rows:
                    payload_sha256 = hashlib.sha256(str(payload).encode()).hexdigest()
                    item = _reconciliation_item(
                        "queued_work",
                        relative,
                        int(job_id),
                        prior_state=str(state),
                        content_sha256=payload_sha256,
                        safe_state="reconciliation_required",
                        requires_external_readback=str(state) == "running",
                    )
                    item["kind"] = str(kind)[:128]
                    items.append(item)
                    job_counts[str(state)] += 1
                connection.execute(
                    "UPDATE jobs SET status='reconciliation_required', last_error=?, updated_at=? "
                    "WHERE status='pending'",
                    (
                        "Restored queued work is held. Retire it in Workspace recovery before creating a new request.",
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE jobs SET status='reconciliation_required', last_error=?, updated_at=? "
                    "WHERE status='running'",
                    (
                        "Restored running work may have crossed an external boundary. Record authoritative readback in Workspace recovery.",
                        now,
                    ),
                )
            elif policy == "world":
                items.extend(_reconcile_world_database(connection, relative, now=now))
            elif policy == "provider_spend_sqlite":
                from . import provider_spend_sqlite
                seal_path = db.with_suffix(".sqlite3.seal")
                if not seal_path.is_file() or seal_path.read_text(encoding="utf-8").strip() != provider_spend_sqlite._digest_file(db):
                    raise RecoveryError("Restored provider spending records failed their integrity check.")
                tables = _sqlite_tables(connection)
                if not {"meta", "totals", "receipts", "attempts"}.issubset(tables):
                    raise RecoveryError("Restored provider spending records have an unsupported format.")
                if connection.execute("SELECT value FROM meta WHERE key='schema'").fetchone() != ("1",):
                    raise RecoveryError("Restored provider spending records are incomplete.")
                for period, provider, request_id, payload in connection.execute(
                    "SELECT period, provider, request_id, payload FROM receipts"
                ):
                    row = json.loads(payload)
                    if not isinstance(row, dict):
                        raise RecoveryError("Restored provider spending receipt is malformed.")
                    if row.get("state") == "settled":
                        continue
                    receipt_sha = hashlib.sha256(json.dumps(
                        row, sort_keys=True, separators=(",", ":"), default=str,
                    ).encode()).hexdigest()
                    item = _reconciliation_item(
                        "provider_reservation", relative, request_id,
                        prior_state=str(row.get("state") or "unknown"),
                        content_sha256=receipt_sha, safe_state="held",
                        requires_external_readback=True,
                    )
                    item["provider"] = str(provider)[:64]
                    item["period"] = str(period)[:16]
                    items.append(item)
            elif policy == "privacy_discovery":
                items.extend(_reconcile_privacy_discovery_database(
                    connection, relative, now=now
                ))
            elif policy == "privacy_remediation":
                items.extend(_reconcile_privacy_remediation_database(
                    connection, relative, now=now
                ))
            elif policy in {"passive_sqlite", "privacy_data_map"}:
                pass
            else:
                items.append(_reconciliation_item(
                    "unclassified_protected_authority",
                    relative,
                    relative,
                    prior_state=("unknown_sqlite" if policy == "unknown_sqlite"
                                 else f"unclassified:{policy}"),
                    content_sha256=backup._sha256(db),
                    safe_state="global_start_blocked",
                    requires_external_readback=True,
                ))
            connection.commit()
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise RecoveryError(
                    "A restored database failed validation after reconciliation."
                )
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    for relative, digest, _size in protected:
        if relative in classified_sources:
            continue
        live_path = stage.joinpath(*PurePosixPath(relative).parts)
        policy = authority_policy(
            relative,
            is_sqlite=live_path.is_file() and backup._is_sqlite_file(live_path),
        )
        intrinsically_safe = {
            "budget_receipt",
            "containment_action",
            "containment_binding",
            "draft_recovery_retention",
            "flow_idempotency",
            "flow_publication_history",
            "grc_delivery",
            "grc_delivery_history",
            "grc_delivery_state",
            "passive_sqlite",
            "privacy_data_map",
            "provider_accounting_review",
            "red_team_result",
            "usage_ledger",
            "validated_ai_vendor_risk_record",
            "validated_vendor_record",
            "vendor_operation",
        }
        if policy not in intrinsically_safe:
            items.append(_reconciliation_item(
                "unclassified_protected_authority",
                relative,
                relative,
                prior_state=f"unclassified:{policy or 'missing_policy'}",
                content_sha256=digest,
                safe_state="global_start_blocked",
                requires_external_readback=True,
            ))
        classified_sources.add(relative)

    protected_digest = hashlib.sha256()
    for relative, digest, size in sorted(protected):
        protected_digest.update(
            json.dumps([relative, digest, size], separators=(",", ":")).encode()
            + b"\n"
        )
    if len(items) > MAX_RECONCILIATION_ITEMS:
        raise RecoveryError(
            "The restored external-work inventory exceeds the supported reconciliation limit."
        )
    _bind_reconciliation_sources(stage, items)
    disposition_digest = hashlib.sha256(json.dumps(
        items, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    report = {
        "schema": 2,
        "items": items,
        "queued_work": {
            "database_count": job_database_count,
            "pending_quarantined": job_counts["pending"],
            "running_quarantined": job_counts["running"],
            "disposition_sha256": disposition_digest,
            "automatic_replay_blocked": True,
        },
        "credentials": {
            "preserved_count": len(preserved_credentials),
            "items": preserved_credentials,
            "wrapped_dek_count": len(wrapped_deks),
            "wrapped_dek_authenticated_count": authenticated_wrapped_deks,
            "retained_key_authentication_required": bool(
                preserved_credentials or authenticated_wrapped_deks
            ),
            "exact_ciphertext_preserved": True,
        },
        "protected_authority": {
            "file_count": len(protected),
            "classified_count": len({row[0] for row in protected}
                                    & classified_sources),
            "classification_complete": (
                len({row[0] for row in protected} & classified_sources)
                == len(protected)
            ),
            "state_sha256": protected_digest.hexdigest(),
            "disposition": "current_authority_and_external_readback_required",
        },
    }
    return removed, report


def _bootstrap_items(marker: dict) -> list[dict]:
    reconciliation = marker.get("reconciliation")
    items = reconciliation.get("items") if isinstance(reconciliation, dict) else None
    if not isinstance(items, list) or len(items) > MAX_RECONCILIATION_ITEMS:
        raise RecoveryError(
            "Bootstrap reconciliation inventory is unavailable. Remain in recovery mode."
        )
    seen: set[str] = set()
    for item in items:
        if (not isinstance(item, dict)
                or not isinstance(item.get("id"), str)
                or not _ID.fullmatch(item["id"])
                or item["id"] in seen
                or item.get("state") not in {"unresolved", "resolved"}
                or not isinstance(item.get("category"), str)
                or not isinstance(item.get("source"), str)):
            raise RecoveryError(
                "Bootstrap reconciliation inventory is malformed. Remain in recovery mode."
            )
        binding = item.get("safe_source")
        kind = binding.get("kind") if isinstance(binding, dict) else None
        if (kind not in {"absent", "file_sha256", "tree_sha256", "job_row"}
                or (kind in {"file_sha256", "tree_sha256"}
                    and (not isinstance(binding.get("sha256"), str)
                         or not re.fullmatch(r"[0-9a-f]{64}", binding["sha256"])))
                or (kind == "job_row" and item.get("category") != "queued_work")
                or (kind in {"absent", "job_row"} and set(binding) != {"kind"})
                or (kind in {"file_sha256", "tree_sha256"}
                    and set(binding) != {"kind", "sha256"})):
            raise RecoveryError(
                "Bootstrap reconciliation source binding is malformed. Remain in recovery mode."
            )
        seen.add(item["id"])
    return items


def _classified_bootstrap_reconciliation(marker: dict) -> tuple[list[dict], dict]:
    """Require a complete, signed inventory before any disposition or release."""
    items = _bootstrap_items(marker)
    reconciliation = marker.get("reconciliation")
    protected = (
        reconciliation.get("protected_authority")
        if isinstance(reconciliation, dict) else None
    )
    if (not isinstance(reconciliation, dict)
            or reconciliation.get("schema") != 2
            or not isinstance(protected, dict)
            or protected.get("classification_complete") is not True
            or type(protected.get("file_count")) is not int
            or type(protected.get("classified_count")) is not int
            or not 0 <= protected["file_count"] <= MAX_RECONCILIATION_ITEMS
            or protected["file_count"] != protected["classified_count"]
            or not isinstance(protected.get("state_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", protected["state_sha256"])):
        raise RecoveryError(
            "The restored protected-authority inventory is incomplete. Remain in recovery mode."
        )
    return items, reconciliation


def resume_bootstrap_restore(*, isolated: bool, actor: str) -> dict:
    """Recover one interrupted bootstrap publication without replaying work."""
    if not isolated:
        raise RecoveryError(
            "Resume bootstrap recovery only in local recovery mode."
        )
    with _locked():
        marker = _read_bootstrap(actor=actor)
        if marker is None or marker.get("state") != "restore_pending":
            raise RecoveryError("No interrupted bootstrap restore is ready to resume.")

        root = _root()
        try:
            with backup.recovery_scope(
                root,
                current_tenant_id_strict(),
                _key(),
                max_expanded_bytes=MAX_EXPANDED_BYTES,
            ):
                with file_lock.cross_process_lock(
                    root / backup._RESTORE_LOCK_TARGET, strict=True
                ):
                    backup._recover_transactions(root, allow_unsigned=False)
        except (OSError, backup.BackupError) as exc:
            raise RecoveryError(
                "The interrupted restore journal could not be recovered. Remain in recovery mode."
            ) from exc

        live = _live_state()
        empty = {
            "file_count": 0,
            "state_sha256": marker["empty_state_sha256"],
        }
        if live == empty:
            rearmed = {
                key: value for key, value in marker.items()
                if key not in {
                    "authentication", "snapshot", "archive_sha256",
                    "safety_snapshot", "review", "restore_pending_at",
                    "reconciliation", "expected_live_state",
                    "stage_prepared_at",
                }
            }
            rearmed["state"] = "prepared"
            report = {
                "state": "rolled_back_to_empty",
                "snapshot": marker.get("snapshot"),
                "safety_snapshot": None,
                "actor": actor,
                "completed_at": time.time(),
                "restored": False,
                "post_restore_verified": False,
                "restart_required": False,
                "restore_mode": "virgin_bootstrap",
                "external_stores_restored": False,
            }
            file_lock.atomic_write_text(
                _store() / "last-restore.json",
                json.dumps(backup._authenticate_for_write(report, _key())),
            )
            (_store() / "review.json").unlink(missing_ok=True)
            _write_bootstrap(rearmed)
            return {
                "state": "prepared",
                "outcome": "rolled_back_to_empty",
                "retry_required": True,
            }

        expected = marker.get("expected_live_state")
        if (not isinstance(expected, dict)
                or type(expected.get("file_count")) is not int
                or not 0 <= expected["file_count"] <= backup.MAX_ARCHIVE_MEMBERS
                or not isinstance(expected.get("state_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected["state_sha256"])
                or live != expected):
            raise RecoveryError(
                "The interrupted restore is neither the signed empty state nor the exact staged state. "
                "Remain in recovery mode and export support evidence."
            )
        selected = _inspect(str(marker.get("snapshot", "")))
        if not hmac.compare_digest(
            str(marker.get("archive_sha256", "")), selected["sha256"]
        ):
            raise RecoveryError(
                "The bootstrap snapshot changed after publication. Remain in recovery mode."
            )
        _, reconciliation = _classified_bootstrap_reconciliation(marker)
        retained = marker.get("retained_keys")
        decryptor = (
            _bootstrap_record_decryptor(marker)
            if isinstance(retained, dict) and retained.get("state") == "installed"
            else None
        )
        from .restore_validation import RestoreValidationError, validate_staged_restore
        try:
            validate_staged_restore(
                root,
                tenant=current_tenant_id_strict(),
                decryptor=decryptor,
            )
        except (OSError, ValueError, RestoreValidationError) as exc:
            raise RecoveryError(
                "The committed restore failed application reference validation. Remain in recovery mode."
            ) from exc

        completed_at = time.time()
        report = {
            "state": "reconciliation_required",
            "snapshot": marker["snapshot"],
            "safety_snapshot": marker.get("safety_snapshot"),
            "actor": actor,
            "completed_at": completed_at,
            "restored": True,
            "post_restore_verified": True,
            "restart_required": True,
            "restore_mode": "virgin_bootstrap",
            "reconciliation": reconciliation,
            "application_reference_validation": REFERENCE_VALIDATION_SCHEMA,
            "verification_scope": VERIFICATION_SCOPE,
            "external_stores_restored": False,
        }
        file_lock.atomic_write_text(
            _store() / "last-restore.json",
            json.dumps(backup._authenticate_for_write(report, _key())),
        )
        completed = {
            **{key: value for key, value in marker.items()
               if key != "authentication"},
            "state": "reconciliation_required",
            "restored_at": completed_at,
        }
        _write_bootstrap(completed)
        return {
            "state": "reconciliation_required",
            "outcome": "committed_state_verified",
            "unresolved": sum(
                item["state"] == "unresolved" for item in reconciliation["items"]
            ),
        }


def reconciliation_status(*, actor: str) -> dict:
    """Return bounded bootstrap work and source-review forms for administrators."""
    with _locked():
        marker = _read_bootstrap(actor=actor)
        if marker is None:
            return {"state": "not_required", "items": [], "unresolved": 0}
        if marker["state"] == "completed":
            return {
                "state": "completed",
                "items": [],
                "unresolved": 0,
                "completed_at": marker.get("completed_at"),
            }
        if marker["state"] != "reconciliation_required":
            return {"state": marker["state"], "items": [], "unresolved": 0}
        items, reconciliation = _classified_bootstrap_reconciliation(marker)
        public = []
        for item in items:
            row = {
                key: value for key, value in item.items()
                if key not in {"actor_sha256", "evidence_sha256"}
            }
            if item.get("category") == "channel_authority":
                from . import channel_recovery_controls

                try:
                    relative = backup._safe_relative_path(item["source"], label="channel recovery source")
                    decryptor = (_bootstrap_record_decryptor(marker) if marker.get("retained_keys") is not None else None)
                    row["channel_review"] = channel_recovery_controls.descriptor(
                        marker, item, _root().joinpath(*relative.parts), decryptor=decryptor,
                        tenant=current_tenant_id_strict(), workspace=_root())
                except (OSError, ValueError, TypeError, KeyError, OverflowError):
                    row["channel_review"] = {
                        "schema": 1, "status": "unavailable", "title": "Review a connected service",
                        "source_label": "Connected service",
                        "reason": "This restored item could not be checked. Keep recovery open, refresh, or create a support report.",
                    }
            public.append(row)
        return {
            "state": "reconciliation_required",
            "items": public,
            "unresolved": sum(item["state"] == "unresolved" for item in items),
            "automatic_replay_blocked": True,
            "normal_start_blocked": True,
            "protected_authority": reconciliation["protected_authority"],
        }


def channel_checkpoint_lookup(item_id: str, *, expected_review_token: str, before: str | None, isolated: bool, actor: str) -> dict:
    """Read source metadata for an authenticated held item; never release it."""
    if not isolated or not isinstance(item_id, str) or not _ID.fullmatch(item_id):
        raise RecoveryError("Look up a held connection only in isolated workspace recovery.")
    from datetime import datetime, timezone

    from maverick_channels import recovery_lookup

    from . import channel_recovery_controls, config

    def current():
        marker = _read_bootstrap(actor=actor)
        if marker is None or marker.get("state") != "reconciliation_required":
            raise RecoveryError("No restored work is awaiting source review.")
        items, _ = _classified_bootstrap_reconciliation(marker)
        item = next((row for row in items if row["id"] == item_id), None)
        if item is None or item.get("category") != "channel_authority" or item.get("state") != "unresolved":
            raise RecoveryError("This held connection changed. Refresh recovery.")
        if not isinstance(expected_review_token, str) or not hmac.compare_digest(expected_review_token, channel_recovery_controls.review_token(marker, item)):
            raise RecoveryError("The source lookup belongs to an earlier recovery review.")
        relative = backup._safe_relative_path(item["source"], label="channel source lookup")
        decryptor = _bootstrap_record_decryptor(marker) if marker.get("retained_keys") is not None else None
        record = channel_recovery_controls._current_record(_root().joinpath(*relative.parts), item, decryptor=decryptor, tenant=current_tenant_id_strict(), workspace=_root())
        kind = channel_recovery_controls._kind(item)
        if kind not in {"imessage_position", "notification_position"} or record["restore_hold"]["state"] != "unresolved":
            raise RecoveryError("This item uses a date or retained delivery receipt, not source-position lookup.")
        name = "imessage" if kind == "imessage_position" else "mastodon"
        options = (config.load_config().get("channels") or {}).get(name) or {}
        channel = recovery_lookup.configured(name, options)
        if recovery_lookup.record_identity(channel) != record["id"]:
            raise RecoveryError("The configured source identity differs from the restored connection. Keep it unresolved; no account was substituted.")
        minimum = str(record["last_rowid"] if name == "imessage" else record.get("candidate") or record["watermark"])
        return channel, minimum

    try:
        with _locked():
            channel, minimum = current()
        result = recovery_lookup.lookup(channel, minimum=minimum, before=before)
        with _locked():
            refreshed, current_minimum = current()
            if recovery_lookup.record_identity(refreshed) != recovery_lookup.record_identity(channel) or current_minimum != minimum:
                raise RecoveryError("The source configuration changed while reading it. Look up the current source again.")
    except RecoveryError:
        raise
    except Exception:
        # Provider bodies, credentials, local paths and message text stay private.
        return {"available": False, "candidates": [], "next_before": None,
                "notice": "The configured source could not establish a checkpoint. Check connection access and availability, then retry. This item stays unresolved; no position or delivery outcome was guessed."}
    return {**result, "available": True, "observed_at": datetime.now(timezone.utc).isoformat(),
            "review_token": expected_review_token, "source_label": "iMessage" if channel.name == "imessage" else "Mastodon",
            "notice": "Read-only source checkpoint metadata. Selecting a position skips collection through that item; it does not prove delivery or repeat work. Review and confirmation remain separate."}


def _job_item_path(item: dict) -> Path:
    try:
        relative = backup._safe_relative_path(item["source"], label="reconciliation source")
    except backup.BackupError as exc:
        raise RecoveryError("The restored job reconciliation source is invalid.") from exc
    path = _root().joinpath(*relative.parts)
    if not path.is_file() or not backup._is_sqlite_file(path):
        raise RecoveryError("The restored job inventory changed. Reload recovery.")
    return path


def _verify_reconciliation_source(item: dict) -> None:
    binding = item["safe_source"]
    if binding["kind"] == "job_row":
        return
    try:
        relative = backup._safe_relative_path(
            item["source"], label="reconciliation source"
        )
    except backup.BackupError as exc:
        raise RecoveryError("The restored reconciliation source is invalid.") from exc
    path = _root().joinpath(*relative.parts)
    kind = binding["kind"]
    if kind == "absent":
        valid = not os.path.lexists(path)
    elif kind == "file_sha256":
        valid = path.is_file() and hmac.compare_digest(
            backup._sha256(path), binding["sha256"]
        )
    else:
        valid = path.is_dir() and hmac.compare_digest(
            _tree_sha256(path), binding["sha256"]
        )
    if not valid:
        raise RecoveryError(
            "A restored authority changed after quarantine. Remain in recovery mode."
        )


def _resolve_job_item(item: dict, *, disposition: str, now: float) -> None:
    path = _job_item_path(item)
    try:
        job_id = int(item["record_id"])
    except (TypeError, ValueError) as exc:
        raise RecoveryError("The restored job identity is invalid.") from exc
    connection = sqlite3.connect(str(backup._filesystem_path(path)))
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT kind, payload, status FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
        if row is None or str(row[2]) != "reconciliation_required":
            raise RecoveryError("The restored job changed. Reload recovery.")
        payload_sha256 = hashlib.sha256(str(row[1]).encode()).hexdigest()
        if (not hmac.compare_digest(payload_sha256, item["content_sha256"])
                or str(row[0])[:128] != item.get("kind")):
            raise RecoveryError("The restored job binding changed. Reload recovery.")
        message = (
            "Restored queued work was retired; create a new request under current authority."
            if item["prior_state"] == "pending"
            else "Restored running work was reconciled by an administrator; no automatic retry is permitted."
        )
        connection.execute(
            "UPDATE jobs SET status='failed', last_error=?, updated_at=? "
            "WHERE id=? AND status='reconciliation_required'",
            (message, now, job_id),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def resolve_reconciliation(
    item_id: str,
    disposition: str,
    *,
    evidence_reference: str | None,
    isolated: bool,
    actor: str,
    channel_readback: dict | None = None,
    channel_answers: dict | None = None,
    expected_review_token: str | None = None,
) -> dict:
    """Record one signed, explicit no-replay disposition from recovery mode."""
    if not isolated:
        raise RecoveryError("Resolve restored work only in local recovery mode.")
    if not isinstance(item_id, str) or not _ID.fullmatch(item_id):
        raise RecoveryError("The reconciliation item is invalid.")
    with _locked():
        marker = _read_bootstrap(actor=actor)
        if marker is None or marker.get("state") != "reconciliation_required":
            raise RecoveryError("No restored work is awaiting reconciliation.")
        items, _ = _classified_bootstrap_reconciliation(marker)
        item = next((row for row in items if hmac.compare_digest(row["id"], item_id)), None)
        if item is None or (item.get("state") != "unresolved" and item.get("category") != "channel_authority"):
            raise RecoveryError("The reconciliation item changed. Reload recovery.")
        if item.get("safe_state") == "global_start_blocked":
            raise RecoveryError(
                "This encrypted authority cannot be safely rewritten in this build. Keep recovery mode active and export support evidence."
            )
        is_channel = item.get("category") == "channel_authority"
        needs_readback = item.get("requires_external_readback") is True
        allowed = ({"channel_readback_confirmed"} if is_channel else
                   {"external_effect_absent", "external_effect_recorded"}
                   if needs_readback else {"retire_and_create_new_request"})
        if disposition not in allowed:
            raise RecoveryError(
                "Choose a disposition that matches the required external readback."
            )
        reference = str(evidence_reference or "").strip()
        if channel_answers is not None or expected_review_token is not None:
            if not is_channel or channel_readback is not None or reference:
                raise RecoveryError("This review does not belong to the selected restored item.")
            from . import channel_recovery_controls

            relative = backup._safe_relative_path(item["source"], label="channel recovery source")
            decryptor = (_bootstrap_record_decryptor(marker) if marker.get("retained_keys") is not None else None)
            try:
                channel_readback = channel_recovery_controls.readback(
                    marker, item, channel_answers, expected_review_token, _root().joinpath(*relative.parts),
                    decryptor=decryptor, tenant=current_tenant_id_strict(), workspace=_root())
            except (ValueError, TypeError, KeyError, OverflowError) as exc:
                raise RecoveryError("This connected-service review is incomplete or changed. Refresh and review its details.") from exc
        if is_channel:
            if channel_readback is None or reference:
                raise RecoveryError("Import the exact channel readback; a generic reference cannot release channel authority.")
        elif channel_readback is not None:
            raise RecoveryError("Channel readback does not belong to this reconciliation item.")
        elif needs_readback:
            if not 8 <= len(reference) <= 512 or any(ord(char) < 32 for char in reference):
                raise RecoveryError(
                    "Enter a short reference to the authoritative external readback."
                )
        elif reference:
            raise RecoveryError("Queued work retirement does not accept external evidence.")
        now = time.time()
        if is_channel:
            from . import channel_recovery

            relative = backup._safe_relative_path(item["source"], label="channel recovery source")
            decryptor = (_bootstrap_record_decryptor(marker) if marker.get("retained_keys") is not None else None)
            try:
                digest, readback_digest = channel_recovery.resolve(
                    _root().joinpath(*relative.parts), item, channel_readback, actor=actor,
                    decryptor=decryptor, tenant=current_tenant_id_strict(), workspace=_root())
            except (ValueError, TypeError, KeyError, OverflowError) as exc:
                raise RecoveryError("Channel readback is unavailable, stale, ambiguous or does not match this exact restored authority.") from exc
            item["safe_source"] = {"kind": "file_sha256", "sha256": digest}
            item["evidence_sha256"] = readback_digest
        elif item["category"] == "queued_work":
            _resolve_job_item(item, disposition=disposition, now=now)
        else:
            _verify_reconciliation_source(item)
        item["state"] = "resolved"
        item["disposition"] = disposition
        item["resolved_at"] = now
        item["actor_sha256"] = hashlib.sha256(actor.encode()).hexdigest()
        if reference:
            item["evidence_sha256"] = hashlib.sha256(reference.encode()).hexdigest()
        body = {key: value for key, value in marker.items() if key != "authentication"}
        body["reconciliation"] = dict(body["reconciliation"], items=items)
        body["reconciliation_updated_at"] = now
        _write_bootstrap(body)
        remaining = sum(row["state"] == "unresolved" for row in items)
        return {
            "state": "resolved",
            "item_id": item_id,
            "disposition": disposition,
            "unresolved": remaining,
            "automatic_replay_blocked": True,
            "normal_start_blocked": True,
        }


def complete_reconciliation(*, isolated: bool, actor: str) -> dict:
    """Release normal startup only after every restored intent has a disposition."""
    if not isolated:
        raise RecoveryError("Complete restored-work review only in local recovery mode.")
    with _locked():
        marker = _read_bootstrap(actor=actor)
        if marker is None or marker.get("state") != "reconciliation_required":
            raise RecoveryError("No bootstrap reconciliation is ready to complete.")
        items, _ = _classified_bootstrap_reconciliation(marker)
        unresolved = [item for item in items if item["state"] != "resolved"]
        if unresolved:
            raise RecoveryError(
                f"Resolve all restored work before returning to normal use ({len(unresolved)} remaining)."
            )
        for item in items:
            if item["category"] != "queued_work":
                _verify_reconciliation_source(item)
                continue
            path = _job_item_path(item)
            connection = sqlite3.connect(str(backup._filesystem_path(path)))
            try:
                row = connection.execute(
                    "SELECT status FROM jobs WHERE id=?", (int(item["record_id"]),)
                ).fetchone()
            finally:
                connection.close()
            if row is None or row[0] == "reconciliation_required":
                raise RecoveryError(
                    "A restored queued item lacks its terminal local disposition."
                )
        completed_at = time.time()
        digest = hashlib.sha256(json.dumps(
            items, sort_keys=True, separators=(",", ":"), default=str
        ).encode()).hexdigest()
        report = {
            "state": "completed",
            "snapshot": marker.get("snapshot"),
            "safety_snapshot": marker.get("safety_snapshot"),
            "actor": actor,
            "completed_at": completed_at,
            "restored": True,
            "post_restore_verified": True,
            "restart_required": True,
            "restore_mode": "virgin_bootstrap",
            "reconciliation": {
                "item_count": len(items),
                "resolved_count": len(items),
                "disposition_sha256": digest,
                "automatic_replay_blocked": True,
            },
            "application_reference_validation": REFERENCE_VALIDATION_SCHEMA,
            "verification_scope": VERIFICATION_SCOPE,
            "external_stores_restored": False,
        }
        # Persist the durable completion receipt before releasing the startup
        # gate. A crash between these writes remains fail-closed.
        file_lock.atomic_write_text(
            _store() / "last-restore.json",
            json.dumps(backup._authenticate_for_write(report, _key())),
        )
        completed = {
            **{key: value for key, value in marker.items() if key != "authentication"},
            "state": "completed",
            "completed_at": completed_at,
            "reconciliation_sha256": digest,
        }
        _write_bootstrap(completed)
        return {key: value for key, value in report.items() if key != "actor"}


def prepare_restore(identifier: str, *, isolated: bool, actor: str) -> dict:
    with _locked():
        if not isolated:
            raise RecoveryError("Open local recovery mode from the desktop app before preparing a live restore.")
        blockers = restore_blockers()
        if blockers:
            raise RecoveryError(" ".join(blockers))
        selected = _inspect(identifier)
        if selected["compatibility"] != "compatible":
            raise RecoveryError(selected["compatibility"])
        restore_mode, comparison = _bootstrap_restore_admission(
            identifier, actor=actor
        )
        if restore_mode == "ordinary":
            with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
                backup.assert_accounting_unchanged(_archive(identifier))
            bootstrap = None
        else:
            bootstrap = _read_bootstrap(actor=actor)
        record_decryptor = (
            _bootstrap_record_decryptor(bootstrap)
            if bootstrap is not None and bootstrap.get("retained_keys") is not None
            else None
        )
        with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
            backup.validate_backup_application(
                _archive(identifier), _record_decryptor=record_decryptor
            )
        # A virgin target has no payload from which to build an archive. Its
        # signed, exact empty-state bootstrap marker is the rollback point.
        safety = None if bootstrap is not None else _create("before-restore")
        review = {"review": secrets.token_hex(16), "target": target(), "snapshot": identifier,
                  "actor": actor,
                  "archive_sha256": selected["sha256"],
                  "safety_snapshot": safety["id"] if safety is not None else None,
                  "expires_at": time.time() + 300, "application_version": version(),
                  "restore_mode": restore_mode,
                  "live_state_sha256": comparison["live_state_sha256"]}
        if bootstrap is not None:
            review["bootstrap_id"] = bootstrap["bootstrap_id"]
            review["empty_state_sha256"] = bootstrap["empty_state_sha256"]
        file_lock.atomic_write_text(_store() / "review.json", json.dumps(backup._authenticate_for_write(review, _key())))
        return {**review, "file_count": selected["file_count"],
                "tenant": current_tenant_id_strict(),
                "protected_changes": comparison["protected_changes"]}


def apply_restore(  # noqa: C901 - staged fail-closed recovery transaction
    review_id: str, expected_target: str, *, isolated: bool, actor: str
) -> dict:
    with _locked():
        if not isolated or restore_blockers():
            raise RecoveryError("Restore requires isolated local recovery mode with no external stores or independent workers.")
        review_path = _store() / "review.json"
        try:
            review = json.loads(file_lock.atomic_read_text(review_path))
            with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
                backup._verify_authentication(review, allow_unsigned=False, label="recovery review")
        except (OSError, ValueError, backup.BackupError) as exc:
            raise RecoveryError("The restore review is unavailable. Prepare a new review.") from exc
        if (not hmac.compare_digest(str(review.get("review", "")), review_id)
                or review.get("target") != target() or not hmac.compare_digest(target(), expected_target)
                or review.get("actor") != actor
                or review.get("application_version") != version() or review.get("expires_at", 0) < time.time()):
            raise RecoveryError("The workspace, version or restore review changed. Prepare a new review.")
        selected = _inspect(review["snapshot"])
        if selected["compatibility"] != "compatible":
            raise RecoveryError(selected["compatibility"])
        if selected["sha256"] != review["archive_sha256"]:
            raise RecoveryError("The selected snapshot changed after review.")
        restore_mode = review.get("restore_mode", "ordinary")
        if restore_mode not in {"ordinary", "virgin_bootstrap"}:
            raise RecoveryError("The restore review has an unsupported recovery mode.")
        if restore_mode == "ordinary":
            with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
                backup.assert_accounting_unchanged(_archive(review["snapshot"]))
            bootstrap = None
        else:
            bootstrap = _read_bootstrap(actor=actor)
            live = _live_state()
            if (bootstrap is None or bootstrap.get("state") != "prepared"
                    or bootstrap.get("expires_at", 0) < time.time()
                    or bootstrap.get("bootstrap_id") != review.get("bootstrap_id")
                    or bootstrap.get("empty_state_sha256") != review.get("empty_state_sha256")
                    or live["file_count"] != 0
                    or live["state_sha256"] != review.get("empty_state_sha256")):
                raise RecoveryError(
                    "The empty installation or bootstrap authorization changed. Prepare recovery again."
                )
            mode, comparison = _bootstrap_restore_admission(
                review["snapshot"], actor=actor
            )
            if (mode != "virgin_bootstrap"
                    or comparison["live_state_sha256"] != review.get("live_state_sha256")):
                raise RecoveryError(
                    "The empty installation changed after review. Prepare recovery again."
                )
        record_decryptor = (
            _bootstrap_record_decryptor(bootstrap)
            if bootstrap is not None and bootstrap.get("retained_keys") is not None
            else None
        )
        with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
            backup.validate_backup_application(
                _archive(review["snapshot"]), _record_decryptor=record_decryptor
            )
        if bootstrap is None:
            _inspect(review["safety_snapshot"])
            with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
                safety_manifest = backup.read_manifest(_archive(review["safety_snapshot"]))
            with backup._temporary_directory(prefix="lightwork-restore-drift-") as temporary, backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
                stage = file_lock.ensure_private_directory(Path(temporary) / "data")
                if backup._stage(_root(), stage, include_keys=backup._archive_includes_keys(safety_manifest["files"])) != safety_manifest["files"]:
                    raise RecoveryError("Workspace files changed after review. Prepare a new safety snapshot before restoring.")
        else:
            live = _live_state()
            if (live["file_count"] != 0
                    or live["state_sha256"] != bootstrap["empty_state_sha256"]):
                raise RecoveryError(
                    "The empty installation changed after review. Prepare recovery again."
                )
        # Consume before applying. A retry never repeats a possibly completed
        # restore; the independent pre-restore archive remains downloadable.
        pending = {"state": "completion_unconfirmed", "snapshot": review["snapshot"],
                   "safety_snapshot": review["safety_snapshot"], "actor": actor,
                   "restore_mode": restore_mode}
        file_lock.atomic_write_text(_store() / "last-restore.json", json.dumps(backup._authenticate_for_write(pending, _key())))
        if bootstrap is not None:
            bootstrap = {
                **{key: value for key, value in bootstrap.items()
                   if key != "authentication"},
                "state": "restore_pending",
                "snapshot": review["snapshot"],
                "archive_sha256": selected["sha256"],
                "safety_snapshot": review["safety_snapshot"],
                "review": review["review"],
                "restore_pending_at": time.time(),
            }
            _write_bootstrap(bootstrap)
        review_path.unlink()
        started = time.perf_counter()
        reconciliation: dict = {}

        def reconcile_stage(stage: Path) -> set[str]:
            removed, result = _reconcile_bootstrap_stage(
                stage,
                decryptor=record_decryptor,
                tenant=current_tenant_id_strict(),
            )
            expected_live_state = _staged_live_state(stage)
            staged_marker = {
                **{key: value for key, value in bootstrap.items()
                   if key not in {"authentication", "reconciliation",
                                  "expected_live_state", "stage_prepared_at"}},
                "reconciliation": result,
                "expected_live_state": expected_live_state,
                "stage_prepared_at": time.time(),
            }
            _classified_bootstrap_reconciliation(staged_marker)
            # Persist the exact transformed live-state digest and every
            # no-replay disposition before backup begins its publication
            # transaction.  An interrupted restore can therefore distinguish
            # an exact committed tree from a rolled-back empty tree.
            _write_bootstrap(staged_marker)
            reconciliation.update(result)
            return removed

        try:
            with backup.recovery_scope(_root(), current_tenant_id_strict(), _key(), max_expanded_bytes=MAX_EXPANDED_BYTES):
                backup.restore_backup(
                    _archive(review["snapshot"]),
                    replace_existing=True,
                    _stage_transform=(reconcile_stage if bootstrap is not None else None),
                    _record_decryptor=record_decryptor,
                )
        except BaseException:
            if bootstrap is not None:
                # If the transaction restored the exact empty target, retry is
                # safe. Any uncertainty retains restore_pending and blocks work.
                try:
                    live = _live_state()
                    if (live["file_count"] == 0
                            and live["state_sha256"] == bootstrap["empty_state_sha256"]):
                        retry = {
                            **{key: value for key, value in bootstrap.items()
                               if key not in {"authentication", "snapshot", "archive_sha256",
                                              "safety_snapshot", "review", "restore_pending_at",
                                              "reconciliation", "expected_live_state",
                                              "stage_prepared_at"}},
                            "state": "prepared",
                        }
                        _write_bootstrap(retry)
                except BaseException:
                    pass
            raise
        if bootstrap is not None:
            persisted = _read_bootstrap(actor=actor)
            expected_state = (
                persisted.get("expected_live_state")
                if isinstance(persisted, dict) else None
            )
            live = _live_state()
            if (persisted is None
                    or persisted.get("state") != "restore_pending"
                    or persisted.get("bootstrap_id") != bootstrap.get("bootstrap_id")
                    or persisted.get("snapshot") != review["snapshot"]
                    or persisted.get("archive_sha256") != selected["sha256"]
                    or not isinstance(expected_state, dict)
                    or expected_state != live):
                raise RecoveryError(
                    "The published bootstrap restore does not match its signed staged state. Remain in recovery mode."
                )
            _classified_bootstrap_reconciliation(persisted)
            reconciliation = persisted["reconciliation"]
            bootstrap = persisted
        completed_at = time.time()
        result_state = "reconciliation_required" if bootstrap is not None else "completed"
        report = {"state": result_state, "snapshot": review["snapshot"], "safety_snapshot": review["safety_snapshot"],
                  "actor": actor, "completed_at": completed_at,
                  "restored": True, "post_restore_verified": True, "restart_required": True,
                  "restore_mode": restore_mode,
                  "reconciliation": reconciliation if bootstrap is not None else None,
                  "application_reference_validation": REFERENCE_VALIDATION_SCHEMA,
                  "verification_scope": VERIFICATION_SCOPE,
                  "elapsed_seconds": round(time.perf_counter() - started, 6), "external_stores_restored": False}
        file_lock.atomic_write_text(_store() / "last-restore.json", json.dumps(backup._authenticate_for_write(report, _key())))
        if bootstrap is not None:
            bootstrap = {
                **{key: value for key, value in bootstrap.items()
                   if key != "authentication"},
                "state": "reconciliation_required",
                "restored_at": completed_at,
                "reconciliation": reconciliation,
            }
            _write_bootstrap(bootstrap)
        return report
