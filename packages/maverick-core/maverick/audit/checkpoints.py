"""Independent, immutable checkpoints for signed audit-day prefixes.

An audit row chain proves the rows still present, but a valid signed suffix can
be removed without breaking that remaining prefix.  Checkpoints close that gap
by publishing signed commitments to independently retained storage.

Publication has one lock order, used everywhere:

    audit-day sidecar -> checkpoint-index sidecar

The day lock is the same lock used by append and whole-file rewrite paths.  It
therefore covers snapshot verification, same-era comparison, signing, and
publication.  No checkpoint path ever acquires these locks in the reverse
order.  Verification is deliberately lock-free and non-mutating so a verifier
can operate against read-only/WORM media.

A supersession (a new era for a day whose signed prefix changed) and a
retirement (the day-file is gone) are signed with the same key as the log, so
the key's holder could replace or drop a commitment a verifier had already
retained.  The control is the report: verification against an externally
retained sequence shows every supersession and retirement published after it,
until the verifier has reviewed it and retains a newer sequence.

A supersession is also expected to be backed by an erase record: the row an
erasure stores in the world model for each audit day it rewrites.  That record
is signed with the same audit key, and its table accepts an insert from
anything that can write the world model, on SQLite and on Postgres.  It shows
that an erasure of the day was recorded there, not that one was requested or
that nothing else changed.  It tells an honest erasure apart from a bare
re-sign and gives the verifier an erasure to look up; it is not proof.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..file_lock import (
    atomic_create_bytes,
    cross_process_lock,
    ensure_private_directory,
)
from .signing import (
    _DAY_RE,
    ANCHOR_FILENAME,
    _load_or_create_keypair,
    trusted_audit_public_keys,
    verify_anchors,
)

CHECKPOINT_SCHEMA = "lightwork.audit.checkpoint.v2"
CHECKPOINT_PREFIX = "audit-checkpoint-"
_CHECKPOINT_RE = re.compile(r"^audit-checkpoint-(\d{20})\.ndjson$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_STAGE_RE = re.compile(r"\.(.+)\.[0-9a-f]{16}\.stage")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")
_MAX_CHECKPOINT_BYTES = 64 * 1024
_MAX_AUDIT_BYTES = 512 * 1024 * 1024
_RECORD_TYPES = {"checkpoint", "supersession", "retirement"}
_LIFECYCLE_REASONS = {"gdpr_reanchor", "retention_purge"}
_CHECKPOINT_BODY_KEYS = {
    "schema",
    "record_type",
    "checkpoint_sequence",
    "previous_checkpoint_sha256",
    "day",
    "row_count",
    "tip_hash",
    "created_at",
    "supersedes_checkpoint_sha256",
    "lifecycle_reason",
    "evidence_sha256",
}
_SIGNED_KEYS = {"prev_hash", "key_id", "hash", "sig"}


class AuditCheckpointError(RuntimeError):
    """An audit checkpoint could not be created or trusted."""


@dataclass(frozen=True)
class CheckpointBreak:
    """One independently verifiable checkpoint failure."""

    sequence: int
    reason: str
    detail: str


@dataclass(frozen=True)
class _ChainEntry:
    record: dict
    raw: bytes
    path: Path
    digest: str
    era: int


@dataclass(frozen=True)
class _DaySnapshot:
    rows: tuple[dict, ...]
    hashes: tuple[str, ...]

    @property
    def row_count(self) -> int:
        return len(self.rows)

    @property
    def tip_hash(self) -> str:
        return self.hashes[-1] if self.hashes else ""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path_is_alias(path: Path, info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    if reparse and attributes & reparse:
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    left_id = (left.st_dev, left.st_ino)
    right_id = (right.st_dev, right.st_ino)
    # A zero inode cannot prove pathname-to-handle custody. Size and mtime can
    # be attacker-controlled, so evidence verification fails closed on a
    # filesystem that cannot expose a stable file identity.
    return left.st_ino != 0 and right.st_ino != 0 and left_id == right_id


def _stable_read_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    attempts: int = 3,
) -> bytes:
    """Read one pathname without chmod, lock creation, or split-byte custody."""
    last_error = "file changed while it was being read"
    for _attempt in range(attempts):
        try:
            before = path.lstat()
        except OSError as exc:
            raise AuditCheckpointError(f"cannot inspect {path}") from exc
        if _path_is_alias(path, before) or not stat.S_ISREG(before.st_mode):
            raise AuditCheckpointError(f"refusing non-regular or aliased file: {path}")
        if before.st_nlink != 1:
            last_error = f"refusing multiply-linked evidence file: {path}"
            continue
        try:
            with open(path, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not _same_identity(before, opened):
                    last_error = f"file identity changed before read: {path}"
                    continue
                raw = stream.read(maximum_bytes + 1)
                after_handle = os.fstat(stream.fileno())
        except OSError as exc:
            last_error = f"cannot read {path}: {exc}"
            continue
        if len(raw) > maximum_bytes:
            raise AuditCheckpointError(f"evidence file is too large: {path}")
        try:
            after_path = path.lstat()
        except OSError as exc:
            last_error = f"cannot re-inspect {path}: {exc}"
            continue
        stable = (
            not _path_is_alias(path, after_path)
            and stat.S_ISREG(after_path.st_mode)
            and after_path.st_nlink == 1
            and _same_identity(before, after_handle)
            and _same_identity(after_handle, after_path)
            and before.st_size == after_handle.st_size == after_path.st_size == len(raw)
            and before.st_mtime_ns
            == after_handle.st_mtime_ns
            == after_path.st_mtime_ns
        )
        if stable:
            return raw
        last_error = f"file changed while it was being read: {path}"
    raise AuditCheckpointError(last_error)


def _require_readable_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AuditCheckpointError(f"cannot inspect directory: {path}") from exc
    if _path_is_alias(path, info) or not stat.S_ISDIR(info.st_mode):
        raise AuditCheckpointError(f"refusing non-directory or aliased path: {path}")


def _resolved_directories(
    audit_dir: Path | str,
    checkpoint_dir: Path | str,
) -> tuple[Path, Path]:
    audit = Path(audit_dir).expanduser().resolve()
    checkpoints = Path(checkpoint_dir).expanduser().resolve()
    if (
        checkpoints == audit
        or audit in checkpoints.parents
        or checkpoints in audit.parents
    ):
        raise AuditCheckpointError(
            "checkpoint directory must be outside and disjoint from the audit "
            "directory"
        )
    return audit, checkpoints


def _trusted_key_map(
    *,
    pubkey_hex: str | None = None,
    trusted_pubkeys: Iterable[str] | None = None,
) -> dict[str, str]:
    explicit = pubkey_hex is not None or trusted_pubkeys is not None
    if isinstance(trusted_pubkeys, str):
        supplied = [trusted_pubkeys]
    else:
        supplied = list(trusted_pubkeys or ())
    if pubkey_hex is not None:
        supplied.append(pubkey_hex)
    if not explicit:
        registry = trusted_audit_public_keys()
        supplied = list(registry.values())
    keys: dict[str, str] = {}
    for value in supplied:
        if not isinstance(value, str):
            raise AuditCheckpointError("trusted public keys must be hexadecimal strings")
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise AuditCheckpointError("trusted public key is not valid hex") from exc
        if len(raw) != 32:
            raise AuditCheckpointError("trusted Ed25519 public keys must be 32 bytes")
        key_id = _sha256(raw)[:16]
        keys[key_id] = raw.hex()
    if not keys:
        source = "pinned key set" if explicit else "local trusted key registry"
        raise AuditCheckpointError(f"{source} is empty")
    return keys


def _verify_signed_text(
    text: str,
    trusted_keys: dict[str, str],
    *,
    label: str,
) -> list[dict]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise AuditCheckpointError(
            "cryptography is required to verify audit checkpoints"
        ) from exc

    rows: list[dict] = []
    previous = ""
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditCheckpointError(
                f"{label} line {line_number} contains malformed JSON"
            ) from exc
        if not isinstance(row, dict):
            raise AuditCheckpointError(
                f"{label} line {line_number} must be a JSON object"
            )
        row_hash = row.get("hash")
        signature = row.get("sig")
        row_previous = row.get("prev_hash")
        key_id = row.get("key_id")
        if (
            not isinstance(row_hash, str)
            or not _SHA256_RE.fullmatch(row_hash)
            or not isinstance(signature, str)
            or not _SIGNATURE_RE.fullmatch(signature)
            or not isinstance(row_previous, str)
            or (row_previous != "" and not _SHA256_RE.fullmatch(row_previous))
            or not isinstance(key_id, str)
            or not _KEY_ID_RE.fullmatch(key_id)
        ):
            raise AuditCheckpointError(
                f"{label} line {line_number} has malformed signing fields"
            )
        if row_previous != previous:
            raise AuditCheckpointError(
                f"{label} line {line_number} does not extend the prior row"
            )
        payload = {key: value for key, value in row.items() if key not in {"hash", "sig"}}
        expected = _sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        )
        if expected != row_hash:
            raise AuditCheckpointError(
                f"{label} line {line_number} content hash is invalid"
            )
        public_hex = trusted_keys.get(key_id)
        if public_hex is None:
            raise AuditCheckpointError(
                f"{label} line {line_number} uses untrusted key_id {key_id}"
            )
        try:
            public = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(public_hex)
            )
            public.verify(bytes.fromhex(signature), bytes.fromhex(row_hash))
        except (InvalidSignature, ValueError) as exc:
            raise AuditCheckpointError(
                f"{label} line {line_number} signature is invalid"
            ) from exc
        rows.append(row)
        previous = row_hash
    return rows


def _decode_audit_segment(raw: bytes, *, label: str) -> str:
    from ..crypto_at_rest import is_sealed, unseal

    try:
        decoded = unseal(raw) if is_sealed(raw) else raw
        return decoded.decode("utf-8")
    except Exception as exc:  # failure-policy: fail_closed
        raise AuditCheckpointError(f"cannot decode audit segment {label}") from exc


def _snapshot_day_unlocked(
    path: Path,
    trusted_keys: dict[str, str],
) -> _DaySnapshot:
    raw = _stable_read_regular_file(path, maximum_bytes=_MAX_AUDIT_BYTES)
    text = _decode_audit_segment(raw, label=path.name)
    rows = _verify_signed_text(text, trusted_keys, label=path.name)
    if not rows:
        raise AuditCheckpointError(f"audit day {path.name} has no signed rows")
    return _DaySnapshot(
        rows=tuple(rows),
        hashes=tuple(str(row["hash"]) for row in rows),
    )


def _snapshot_day_for_publication(
    path: Path,
    trusted_keys: dict[str, str],
) -> _DaySnapshot:
    """Caller must hold the strict sidecar lock shared with audit writers."""
    return _snapshot_day_unlocked(path, trusted_keys)


def _checkpoint_files(checkpoint_dir: Path) -> list[tuple[int, Path]]:
    if not checkpoint_dir.exists():
        return []
    _require_readable_directory(checkpoint_dir)
    try:
        entries = list(checkpoint_dir.iterdir())
    except OSError as exc:
        raise AuditCheckpointError(
            f"cannot enumerate checkpoint directory: {checkpoint_dir}"
        ) from exc
    files: list[tuple[int, Path]] = []
    for path in entries:
        match = _CHECKPOINT_RE.fullmatch(path.name)
        if match:
            files.append((int(match.group(1)), path))
    return sorted(files)


def _validate_record_shape(record: dict, *, expected_sequence: int) -> None:
    if set(record) != _CHECKPOINT_BODY_KEYS | _SIGNED_KEYS:
        raise AuditCheckpointError("checkpoint schema contains unexpected fields")
    if record.get("schema") != CHECKPOINT_SCHEMA:
        raise AuditCheckpointError("checkpoint schema version is unsupported")
    record_type = record.get("record_type")
    if record_type not in _RECORD_TYPES:
        raise AuditCheckpointError("checkpoint record_type is invalid")
    if record.get("checkpoint_sequence") != expected_sequence:
        raise AuditCheckpointError("checkpoint sequence is not monotonic")
    previous = record.get("previous_checkpoint_sha256")
    if not isinstance(previous, str) or (
        previous != "" and not _SHA256_RE.fullmatch(previous)
    ):
        raise AuditCheckpointError("checkpoint previous digest is invalid")
    day = record.get("day")
    if not isinstance(day, str) or not _DAY_RE.fullmatch(day):
        raise AuditCheckpointError("checkpoint day is invalid")
    count = record.get("row_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise AuditCheckpointError("checkpoint row_count is invalid")
    tip = record.get("tip_hash")
    if not isinstance(tip, str) or not _SHA256_RE.fullmatch(tip):
        raise AuditCheckpointError("checkpoint tip_hash is invalid")
    created = record.get("created_at")
    if not isinstance(created, str):
        raise AuditCheckpointError("checkpoint created_at is invalid")
    try:
        parsed = datetime.fromisoformat(created)
    except ValueError as exc:
        raise AuditCheckpointError("checkpoint created_at is invalid") from exc
    if parsed.tzinfo is None:
        raise AuditCheckpointError("checkpoint created_at must include a timezone")

    superseded = record.get("supersedes_checkpoint_sha256")
    reason = record.get("lifecycle_reason")
    evidence = record.get("evidence_sha256")
    if not all(isinstance(value, str) for value in (superseded, reason, evidence)):
        raise AuditCheckpointError("checkpoint lifecycle fields must be strings")
    if record_type == "checkpoint":
        if superseded or reason or evidence:
            raise AuditCheckpointError("ordinary checkpoints cannot carry lifecycle fields")
    else:
        if not _SHA256_RE.fullmatch(superseded):
            raise AuditCheckpointError("lifecycle record superseded digest is invalid")
        if reason not in _LIFECYCLE_REASONS:
            raise AuditCheckpointError("checkpoint lifecycle reason is invalid")
        if not _SHA256_RE.fullmatch(evidence):
            raise AuditCheckpointError("checkpoint lifecycle evidence digest is invalid")
        expected_reason = (
            "gdpr_reanchor" if record_type == "supersession" else "retention_purge"
        )
        if reason != expected_reason:
            raise AuditCheckpointError(
                f"{record_type} record requires lifecycle reason {expected_reason}"
            )


def _read_checkpoint(
    path: Path,
    trusted_keys: dict[str, str],
    *,
    expected_sequence: int,
) -> tuple[dict, bytes]:
    raw = _stable_read_regular_file(path, maximum_bytes=_MAX_CHECKPOINT_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditCheckpointError(f"checkpoint {path.name} is not UTF-8") from exc
    rows = _verify_signed_text(text, trusted_keys, label=path.name)
    if len(rows) != 1:
        raise AuditCheckpointError(
            f"checkpoint {path.name} must contain exactly one signed row"
        )
    record = rows[0]
    _validate_record_shape(record, expected_sequence=expected_sequence)
    if record["prev_hash"] != "":
        raise AuditCheckpointError(
            f"checkpoint {path.name} single-row chain must start at genesis"
        )
    return record, raw


def _stage_links_by_target(checkpoint_dir: Path) -> dict[str, list[Path]]:
    """List publication stage files once, grouped by the target they name."""
    try:
        entries = list(checkpoint_dir.iterdir())
    except OSError as exc:
        raise AuditCheckpointError(
            f"cannot enumerate checkpoint directory: {checkpoint_dir}"
        ) from exc
    stages: dict[str, list[Path]] = {}
    for path in entries:
        match = _STAGE_RE.fullmatch(path.name)
        if match:
            stages.setdefault(match.group(1), []).append(path)
    return stages


def _recover_stage_links(target: Path, stages: list[Path]) -> None:
    """Remove interrupted publication links under the caller's index lock.

    Equal content alone does not establish a staging file's origin: only a
    regular hard link to this exact target can be the publication crash residue.
    Ordinary evidence readers retain their strict single-link requirement.
    ``stages`` are this target's ``.<target>.<16 hex>.stage`` names.
    """
    for stage in stages:
        target_info = target.lstat()
        stage_info = stage.lstat()
        if (
            _path_is_alias(target, target_info) or _path_is_alias(stage, stage_info)
            or not stat.S_ISREG(target_info.st_mode)
            or not stat.S_ISREG(stage_info.st_mode)
            or not _same_identity(target_info, stage_info)
            or target_info.st_size > _MAX_CHECKPOINT_BYTES
        ):
            continue
        with open(target, "rb") as published, open(stage, "rb") as staged:
            if not (
                _same_identity(target_info, os.fstat(published.fileno()))
                and _same_identity(stage_info, os.fstat(staged.fileno()))
            ):
                continue
            raw = published.read(_MAX_CHECKPOINT_BYTES + 1)
            if len(raw) > _MAX_CHECKPOINT_BYTES or staged.read(_MAX_CHECKPOINT_BYTES + 1) != raw:
                continue
            current_target, current_stage = target.lstat(), stage.lstat()
            if (
                _path_is_alias(target, current_target) or _path_is_alias(stage, current_stage)
                or not _same_identity(target_info, current_target)
                or not _same_identity(stage_info, current_stage)
                or current_target.st_size != len(raw)
                or current_target.st_mtime_ns != target_info.st_mtime_ns
            ):
                continue
            stage.unlink()
        _fsync_directory(target.parent)


def _load_checkpoint_chain(
    checkpoint_dir: Path,
    trusted_keys: dict[str, str],
    *,
    recover_stages: bool = False,
) -> list[_ChainEntry]:
    loaded: list[_ChainEntry] = []
    previous_digest = ""
    latest_by_day: dict[str, _ChainEntry] = {}
    era_by_day: dict[str, int] = {}
    retired_days: set[str] = set()
    # One directory listing per chain load: a per-checkpoint scan made each
    # publish quadratic in the chain length while holding the audit-day lock.
    stages = _stage_links_by_target(checkpoint_dir) if recover_stages else {}
    for expected, (filename_sequence, path) in enumerate(
        _checkpoint_files(checkpoint_dir),
        start=1,
    ):
        if filename_sequence != expected:
            raise AuditCheckpointError(
                "checkpoint filenames contain a sequence gap or rollback"
            )
        if path.name in stages:
            _recover_stage_links(path, stages[path.name])
        record, raw = _read_checkpoint(
            path,
            trusted_keys,
            expected_sequence=expected,
        )
        if record["previous_checkpoint_sha256"] != previous_digest:
            raise AuditCheckpointError(
                f"checkpoint {path.name} does not commit to its predecessor"
            )
        day = str(record["day"])
        record_type = str(record["record_type"])
        prior = latest_by_day.get(day)
        era = era_by_day.get(day, 0)
        if record_type == "checkpoint":
            if day in retired_days:
                raise AuditCheckpointError(
                    f"checkpoint {path.name} follows a retired audit day"
                )
            if prior is not None:
                prior_count = int(prior.record["row_count"])
                count = int(record["row_count"])
                if count < prior_count:
                    raise AuditCheckpointError(
                        f"checkpoint {path.name} regresses same-era row_count"
                    )
                if count == prior_count and record["tip_hash"] != prior.record["tip_hash"]:
                    raise AuditCheckpointError(
                        f"checkpoint {path.name} changes a same-era tip at equal count"
                    )
        else:
            if prior is None or record["supersedes_checkpoint_sha256"] != prior.digest:
                raise AuditCheckpointError(
                    f"checkpoint {path.name} does not supersede the latest record "
                    f"for {day}"
                )
            if record_type == "supersession":
                if day in retired_days:
                    raise AuditCheckpointError(
                        f"checkpoint {path.name} cannot supersede a retired day"
                    )
                era += 1
                era_by_day[day] = era
            else:
                if (
                    record["row_count"] != prior.record["row_count"]
                    or record["tip_hash"] != prior.record["tip_hash"]
                ):
                    raise AuditCheckpointError(
                        f"retirement {path.name} does not copy its retired commitment"
                    )
                retired_days.add(day)
        entry = _ChainEntry(
            record=record,
            raw=raw,
            path=path,
            digest=_sha256(raw),
            era=era,
        )
        loaded.append(entry)
        latest_by_day[day] = entry
        previous_digest = entry.digest
    return loaded


def _sign_checkpoint_record(
    body: dict,
    trusted_keys: dict[str, str],
) -> bytes:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise AuditCheckpointError(
            "cryptography is required to publish audit checkpoints"
        ) from exc

    private_raw, public_raw, key_id = _load_or_create_keypair()
    if trusted_keys.get(key_id) != public_raw.hex():
        raise AuditCheckpointError(
            f"active checkpoint signer {key_id} is outside the pinned trusted key set"
        )
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(private_raw)
    derived = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if derived != public_raw or _sha256(derived)[:16] != key_id:
        raise AuditCheckpointError("active audit signing keypair is inconsistent")
    payload = dict(body)
    payload["prev_hash"] = ""
    payload["key_id"] = key_id
    row_hash = _sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    )
    payload["hash"] = row_hash
    payload["sig"] = signer.sign(bytes.fromhex(row_hash)).hex()
    return (json.dumps(payload, default=str) + "\n").encode("utf-8")


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(
        str(path),
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_complete_checkpoint(
    target: Path,
    raw: bytes,
    trusted_keys: dict[str, str],
    *,
    expected_sequence: int,
) -> None:
    """Stage, fsync, verify, and only then expose the numbered pathname."""
    stage = target.parent / f".{target.name}.{secrets.token_hex(8)}.stage"
    target_published = False
    try:
        atomic_create_bytes(stage, raw, mode=0o400)
        staged_record, staged_raw = _read_checkpoint(
            stage,
            trusted_keys,
            expected_sequence=expected_sequence,
        )
        if staged_raw != raw or staged_record["checkpoint_sequence"] != expected_sequence:
            raise AuditCheckpointError("staged checkpoint failed post-write verification")
        if target.exists():
            raise AuditCheckpointError(
                f"checkpoint target already exists: {target.name}"
            )
        if os.name == "nt":
            os.rename(stage, target)
        else:
            os.link(stage, target, follow_symlinks=False)
            stage.unlink()
        target_published = True
        _fsync_directory(target.parent)
        _published_record, published_raw = _read_checkpoint(
            target,
            trusted_keys,
            expected_sequence=expected_sequence,
        )
        if published_raw != raw:
            raise AuditCheckpointError("published checkpoint bytes changed")
    except FileExistsError as exc:
        raise AuditCheckpointError(
            f"checkpoint target already exists: {target.name}"
        ) from exc
    finally:
        try:
            os.chmod(stage, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        try:
            stage.unlink()
        except OSError:
            pass
    if not target_published:
        raise AuditCheckpointError("checkpoint publication did not complete")


def _anchor_rows(
    audit_dir: Path,
    trusted_keys: dict[str, str],
) -> list[dict]:
    path = audit_dir / ANCHOR_FILENAME
    if not path.exists():
        return []
    raw = _stable_read_regular_file(path, maximum_bytes=_MAX_AUDIT_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditCheckpointError("anchor ledger is not UTF-8") from exc
    return _verify_signed_text(text, trusted_keys, label=ANCHOR_FILENAME)


def _verify_anchor_preflight(
    audit_dir: Path,
    trusted_keys: dict[str, str],
) -> list[dict]:
    # First prove the ledger using the explicit pinned set.  The existing
    # anchor verifier then checks every ledger-to-day commitment and retention
    # marker using the protected local key registry. Publication is a mutating
    # operator action, so its custody checks may harden local audit paths.
    anchor_path = audit_dir / ANCHOR_FILENAME
    with cross_process_lock(anchor_path, strict=True):
        rows = _anchor_rows(audit_dir, trusted_keys)
        anchor_breaks = verify_anchors(audit_dir)
        if anchor_breaks:
            summary = ", ".join(sorted({item.reason for item in anchor_breaks}))
            raise AuditCheckpointError(
                f"refusing to checkpoint with broken cross-file anchors: {summary}"
            )
        return rows


def _gdpr_evidence_digest(
    *,
    day: str,
    row_count: int,
    tip_hash: str,
    rows: list[dict],
    anchor_rows: list[dict],
    supersedes_checkpoint_sha256: str,
    expected_digest: str | None = None,
) -> str:
    candidates = [
        str(row["hash"])
        for row in anchor_rows
        if row.get("kind") == "anchor"
        and row.get("day") == day
        and row.get("row_count") == row_count
        and row.get("tip_hash") == tip_hash
    ]
    candidates.extend(
        str(row["hash"])
        for row in rows[:row_count]
        if row.get("kind") == "erase"
        and row.get("supersedes_checkpoint_sha256")
        == supersedes_checkpoint_sha256
    )
    if expected_digest is not None:
        if expected_digest in candidates:
            return expected_digest
        raise AuditCheckpointError(
            "GDPR supersession evidence no longer matches the committed prefix"
        )
    if candidates:
        return candidates[-1]
    raise AuditCheckpointError(
        "GDPR supersession requires a matching signed re-anchor or an erase "
        "marker bound to the exact superseded checkpoint"
    )


def _retention_evidence_digest(
    *,
    day: str,
    row_count: int,
    tip_hash: str,
    anchor_rows: list[dict],
    expected_digest: str | None = None,
) -> str:
    candidates: list[str] = []
    for row in reversed(anchor_rows):
        if row.get("kind") != "retention_purge":
            continue
        for entry in row.get("days") or ():
            if (
                isinstance(entry, dict)
                and entry.get("day") == day
                and entry.get("row_count") == row_count
                and entry.get("tip_hash") == tip_hash
            ):
                candidates.append(str(row["hash"]))
                break
    if expected_digest is not None:
        if expected_digest in candidates:
            return expected_digest
        raise AuditCheckpointError(
            "retirement evidence no longer matches the retired commitment"
        )
    if candidates:
        return candidates[0]
    raise AuditCheckpointError(
        "retirement requires signed retention evidence for the exact commitment"
    )


#: Looks up the erase records of one audit day, oldest first (see
#: ``erasure_receipts.load_audit_erase_records``).
EraseRecords = Callable[[str], Iterable[Mapping]]


def _instant(value: object) -> datetime | None:
    """An ISO timestamp with a timezone as a datetime, or None."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _backing_erase_record(
    erase_records: EraseRecords | None,
    *,
    day: str,
    row_count: int,
    tip_hash: str,
    hashes: tuple[str, ...] | None,
    not_before: object,
    superseded: str,
) -> Mapping | None:
    """The newest erase record that accounts for a day's committed prefix.

    A record matches when the day it left behind is the committed prefix, or
    a point inside it: rows appended after the erasure extend the same chain.
    ``hashes`` are the day's row hashes when its file can still be compared.
    A record issued before ``not_before``, the time of the checkpoint being
    replaced, explains an earlier change and is not reused for this one.

    The record must also list ``superseded``, the digest of the checkpoint
    being replaced: the erasure compared the day with that very checkpoint
    before it rewrote anything. An erasure that never saw this checkpoint
    folder, or ran on a day already changed some other way, does not count.
    """
    if erase_records is None:
        return None
    floor = _instant(not_before)
    for record in reversed(list(erase_records(day))):
        after, tip = record.get("rows_after"), record.get("tip_hash")
        if record.get("day") != day or not isinstance(after, int) or isinstance(after, bool):
            continue
        if superseded not in (record.get("checkpoints") or ()):
            continue
        issued = _instant(record.get("issued_at"))
        if floor is not None and (issued is None or issued < floor):
            continue
        if after == row_count and tip == tip_hash:
            return record
        if hashes is not None and 1 <= after <= min(row_count, len(hashes)) and hashes[after - 1] == tip:
            return record
    return None


def _supersession_report(
    entry: _ChainEntry,
    *,
    retained: _ChainEntry | None,
    hashes: tuple[str, ...] | None,
    erase_records: EraseRecords | None,
) -> tuple[str, str]:
    """``(reason, what the erase records say)`` for one supersession."""
    if erase_records is None:
        return "superseded_erase_record_unchecked", "erase records were not checked"
    record = entry.record
    try:
        backing = _backing_erase_record(
            erase_records, day=str(record["day"]), row_count=int(record["row_count"]),
            tip_hash=str(record["tip_hash"]), hashes=hashes,
            not_before=retained.record["created_at"] if retained is not None else None,
            superseded=str(record["supersedes_checkpoint_sha256"]),
        )
    # failure-policy: fail_closed
    except Exception as exc:
        return ("superseded_erase_record_unchecked",
                f"erase records could not be read ({type(exc).__name__})")
    if backing is not None:
        return ("superseded_after_pin",
                f"erase record {backing.get('erasure_id')} says "
                f"{backing.get('rows_erased')} of {backing.get('rows_before')} rows were erased")
    if hashes is None:
        return ("superseded_then_replaced",
                "the day was replaced or retired again since, so this record can no longer "
                "be compared with the log; the later record is reported too")
    return ("superseded_without_erase_record",
            "it was published without an erase record: by the --without-erase-record "
            "override, which leaves an audit_checkpoint_publish_without_erase_record "
            "entry in the activity log, by an earlier version, or with the signing key alone")


def _lifecycle_after_pin(
    chain: list[_ChainEntry],
    *,
    pinned_sequence: int,
    snapshots: Mapping[str, _DaySnapshot | AuditCheckpointError],
    latest_era: Mapping[str, int],
    erase_records: EraseRecords | None,
) -> list[CheckpointBreak]:
    """Report each day replaced or retired after the externally retained sequence.

    A supersession and a retirement are both signed with the key that signs
    the log, and both end what the retained record says about a day. So the
    result is never "verified" until the verifier has looked at each one and
    retains a newer sequence. A supersession also says whether a stored erase
    record, issued after the last record retained for that day, backs it.
    """
    breaks: list[CheckpointBreak] = []
    newest = int(chain[-1].record["checkpoint_sequence"])
    retain = f"Review it, then retain sequence {newest} and its digest."
    retained: dict[str, _ChainEntry] = {}
    for entry in chain:
        record = entry.record
        sequence = int(record["checkpoint_sequence"])
        day = str(record["day"])
        if sequence <= pinned_sequence:
            retained[day] = entry
            continue
        if record["record_type"] == "retirement":
            breaks.append(CheckpointBreak(
                sequence, "retired_after_pin",
                f"{day} was retired (sequence {sequence}) after retained sequence "
                f"{pinned_sequence}: its day-file is gone and a signed retention record "
                f"is the only account of it. {retain}"))
            continue
        if record["record_type"] != "supersession":
            continue
        snapshot = snapshots.get(day)
        reason, finding = _supersession_report(
            entry, retained=retained.get(day),
            # Only the day's current era can still be compared with its file.
            hashes=(
                snapshot.hashes
                if isinstance(snapshot, _DaySnapshot) and entry.era == latest_era.get(day)
                else None
            ),
            erase_records=erase_records,
        )
        advice = (
            "Compare the day with a copy kept elsewhere."
            if reason == "superseded_without_erase_record"
            else retain
        )
        breaks.append(CheckpointBreak(
            sequence, reason,
            f"{day} was given a new checkpoint (sequence {sequence}) after retained "
            f"sequence {pinned_sequence}; {finding}. {advice}"))
    return breaks


def day_checkpoint_state(
    audit_dir: Path | str,
    checkpoint_dir: Path | str,
    day: str,
    *,
    erase_records: EraseRecords | None,
    pubkey_hex: str | None = None,
    trusted_pubkeys: Iterable[str] | None = None,
) -> tuple[str | None, Mapping | None]:
    """``(digest, erase record)`` for ``day``'s newest record in this store.

    An erase asks this before it rewrites a day. ``digest`` names the
    checkpoint the day can be compared with; the erase lists it in its erase
    record, and only a listed checkpoint can later be replaced on that record.
    It is None when the store holds no record for the day, or when the store
    or the day cannot be read: nothing was compared, so nothing is listed.

    The erase record is the stored one, if any, that left the rows the day
    still starts with after comparing it with that same checkpoint. A day
    that no longer matches its checkpoint is rewritten only with such a
    record, so a change made some other way cannot gain an erase record of
    its own.
    """
    try:
        audit, checkpoints = _resolved_directories(audit_dir, checkpoint_dir)
        trusted_keys = _trusted_key_map(pubkey_hex=pubkey_hex, trusted_pubkeys=trusted_pubkeys)
        chain = _load_checkpoint_chain(checkpoints, trusted_keys)
        latest = next((entry for entry in reversed(chain) if entry.record["day"] == day), None)
        if latest is None:
            return None, None
        snapshot = _snapshot_day_unlocked(audit / f"{day}.ndjson", trusted_keys)
    except (AuditCheckpointError, OSError, ValueError):
        return None, None
    try:
        explained = _backing_erase_record(
            erase_records, day=day, row_count=snapshot.row_count, tip_hash=snapshot.tip_hash,
            hashes=snapshot.hashes, not_before=latest.record["created_at"],
            superseded=latest.digest,
        )
    # failure-policy: fail_closed
    except Exception:
        explained = None  # records that cannot be read explain nothing
    return latest.digest, explained


def _new_record_body(
    *,
    record_type: str,
    sequence: int,
    previous_digest: str,
    day: str,
    row_count: int,
    tip_hash: str,
    supersedes_digest: str = "",
    lifecycle_reason: str = "",
    evidence_digest: str = "",
) -> dict:
    return {
        "schema": CHECKPOINT_SCHEMA,
        "record_type": record_type,
        "checkpoint_sequence": sequence,
        "previous_checkpoint_sha256": previous_digest,
        "day": day,
        "row_count": row_count,
        "tip_hash": tip_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "supersedes_checkpoint_sha256": supersedes_digest,
        "lifecycle_reason": lifecycle_reason,
        "evidence_sha256": evidence_digest,
    }


def _require_erase_record(
    erase_records: EraseRecords | None,
    day: str,
    snapshot: _DaySnapshot,
    superseded: _ChainEntry,
) -> None:
    """Refuse a new era for ``day`` that no stored erase record accounts for."""
    try:
        backing = _backing_erase_record(
            erase_records, day=day, row_count=snapshot.row_count,
            tip_hash=snapshot.tip_hash, hashes=snapshot.hashes,
            not_before=superseded.record["created_at"], superseded=superseded.digest,
        )
    # failure-policy: fail_closed
    except Exception as exc:
        raise AuditCheckpointError(
            f"erase records for {day} could not be read ({type(exc).__name__}); "
            "the new checkpoint was not published"
        ) from exc
    if backing is None:
        raise AuditCheckpointError(
            f"no stored erase record backs replacing the checkpoint of {day}. "
            "If the day has already been erased, publish again with "
            "--without-erase-record: a later check against an older retained "
            "sequence will report it. A record backs a checkpoint only when "
            "the erasure found the day unchanged since that checkpoint, in a "
            "checkpoint folder it was told about"
        )


def publish_checkpoint(
    audit_dir: Path | str,
    checkpoint_dir: Path | str,
    *,
    day: str | None = None,
    pubkey_hex: str | None = None,
    trusted_pubkeys: Iterable[str] | None = None,
    supersedes_checkpoint_sha256: str | None = None,
    lifecycle_reason: str | None = None,
    erase_records: EraseRecords | None = None,
    allow_missing_erase_record: bool = False,
) -> Path:
    """Publish a stable signed commitment for one audit day.

    A changed prefix or count regression is refused by default. An operator may
    explicitly start a new GDPR-reanchored era by naming the exact digest of
    the latest checkpoint, selecting ``gdpr_reanchor``, and presenting existing
    signed re-anchor/erase evidence.

    The new era must also be backed by an erase record found through
    ``erase_records``. ``allow_missing_erase_record`` publishes without one,
    for a day erased before erase records existed; a later verification
    against an older retained sequence says so.
    """
    audit, checkpoints = _resolved_directories(audit_dir, checkpoint_dir)
    selected_day = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if not _DAY_RE.fullmatch(selected_day):
        raise AuditCheckpointError("checkpoint day must be YYYY-MM-DD")
    if supersedes_checkpoint_sha256 is not None and not _SHA256_RE.fullmatch(
        supersedes_checkpoint_sha256
    ):
        raise AuditCheckpointError("superseded checkpoint digest must be SHA-256 hex")
    if lifecycle_reason not in {None, "gdpr_reanchor"}:
        raise AuditCheckpointError("publication lifecycle reason must be gdpr_reanchor")
    if (supersedes_checkpoint_sha256 is None) != (lifecycle_reason is None):
        raise AuditCheckpointError(
            "superseded checkpoint digest and lifecycle reason must be supplied together"
        )

    # Provision/select the active signer before taking the trust snapshot so a
    # first-use local key appears in the protected registry.
    _private, active_public, active_key_id = _load_or_create_keypair()
    trusted_keys = _trusted_key_map(
        pubkey_hex=pubkey_hex,
        trusted_pubkeys=trusted_pubkeys,
    )
    if trusted_keys.get(active_key_id) != active_public.hex():
        raise AuditCheckpointError(
            f"active checkpoint signer {active_key_id} is outside the pinned "
            "trusted key set"
        )
    day_file = audit / f"{selected_day}.ndjson"
    if not day_file.exists():
        raise AuditCheckpointError(f"audit day file is missing: {day_file}")

    ensure_private_directory(checkpoints)
    index_lock = checkpoints / ".checkpoint-index"
    # Deadlock-free global order: audit day sidecar, then checkpoint index.
    with cross_process_lock(day_file, strict=True):
        anchor_rows = _verify_anchor_preflight(audit, trusted_keys)
        snapshot = _snapshot_day_for_publication(day_file, trusted_keys)
        with cross_process_lock(index_lock, strict=True):
            chain = _load_checkpoint_chain(checkpoints, trusted_keys, recover_stages=True)
            latest_for_day = next(
                (entry for entry in reversed(chain) if entry.record["day"] == selected_day),
                None,
            )
            mismatch = False
            if latest_for_day is not None:
                if latest_for_day.record["record_type"] == "retirement":
                    raise AuditCheckpointError(
                        f"audit day {selected_day} is explicitly retired"
                    )
                prior_count = int(latest_for_day.record["row_count"])
                mismatch = (
                    snapshot.row_count < prior_count
                    or snapshot.hashes[prior_count - 1]
                    != latest_for_day.record["tip_hash"]
                    if snapshot.row_count >= prior_count
                    else True
                )
                if (
                    not mismatch
                    and snapshot.row_count == prior_count
                    and snapshot.tip_hash == latest_for_day.record["tip_hash"]
                ):
                    if supersedes_checkpoint_sha256 is None:
                        return latest_for_day.path
                    if (
                        latest_for_day.record["record_type"] == "supersession"
                        and latest_for_day.record[
                            "supersedes_checkpoint_sha256"
                        ]
                        == supersedes_checkpoint_sha256
                        and latest_for_day.record["lifecycle_reason"]
                        == lifecycle_reason
                    ):
                        return latest_for_day.path

            if mismatch:
                if latest_for_day is None:
                    raise AuditCheckpointError("internal checkpoint era state is invalid")
                if (
                    supersedes_checkpoint_sha256 != latest_for_day.digest
                    or lifecycle_reason != "gdpr_reanchor"
                ):
                    raise AuditCheckpointError(
                        "audit prefix/count changed within an era; publication requires "
                        "gdpr_reanchor and the latest checkpoint's exact digest"
                    )
                record_type = "supersession"
                evidence_digest = _gdpr_evidence_digest(
                    day=selected_day,
                    row_count=snapshot.row_count,
                    tip_hash=snapshot.tip_hash,
                    rows=snapshot.rows,
                    anchor_rows=anchor_rows,
                    supersedes_checkpoint_sha256=latest_for_day.digest,
                )
                if not allow_missing_erase_record:
                    _require_erase_record(erase_records, selected_day, snapshot, latest_for_day)
            else:
                if supersedes_checkpoint_sha256 is not None:
                    raise AuditCheckpointError(
                        "supersession was requested but the prior audit prefix is intact"
                    )
                record_type = "checkpoint"
                evidence_digest = ""

            previous_digest = chain[-1].digest if chain else ""
            sequence = len(chain) + 1
            body = _new_record_body(
                record_type=record_type,
                sequence=sequence,
                previous_digest=previous_digest,
                day=selected_day,
                row_count=snapshot.row_count,
                tip_hash=snapshot.tip_hash,
                supersedes_digest=supersedes_checkpoint_sha256 or "",
                lifecycle_reason=lifecycle_reason or "",
                evidence_digest=evidence_digest,
            )
            raw = _sign_checkpoint_record(body, trusted_keys)
            target = checkpoints / f"{CHECKPOINT_PREFIX}{sequence:020d}.ndjson"
            _publish_complete_checkpoint(
                target,
                raw,
                trusted_keys,
                expected_sequence=sequence,
            )
            return target


def retire_checkpoint(
    audit_dir: Path | str,
    checkpoint_dir: Path | str,
    *,
    supersedes_checkpoint_sha256: str,
    lifecycle_reason: str,
    pubkey_hex: str | None = None,
    trusted_pubkeys: Iterable[str] | None = None,
) -> Path:
    """Publish signed retirement after an exact, signed retention purge."""
    audit, checkpoints = _resolved_directories(audit_dir, checkpoint_dir)
    if not _SHA256_RE.fullmatch(supersedes_checkpoint_sha256):
        raise AuditCheckpointError("superseded checkpoint digest must be SHA-256 hex")
    if lifecycle_reason != "retention_purge":
        raise AuditCheckpointError("retirement lifecycle reason must be retention_purge")
    _private, active_public, active_key_id = _load_or_create_keypair()
    trusted_keys = _trusted_key_map(
        pubkey_hex=pubkey_hex,
        trusted_pubkeys=trusted_pubkeys,
    )
    if trusted_keys.get(active_key_id) != active_public.hex():
        raise AuditCheckpointError(
            f"active checkpoint signer {active_key_id} is outside the pinned "
            "trusted key set"
        )
    ensure_private_directory(checkpoints)
    # Recover interrupted publication before the preliminary lookup. Release
    # the index lock before taking the day lock to preserve the global order.
    with cross_process_lock(checkpoints / ".checkpoint-index", strict=True):
        preliminary_chain = _load_checkpoint_chain(
            checkpoints, trusted_keys, recover_stages=True,
        )
    preliminary_target = next(
        (
            entry
            for entry in reversed(preliminary_chain)
            if entry.digest == supersedes_checkpoint_sha256
        ),
        None,
    )
    if preliminary_target is None:
        raise AuditCheckpointError("superseded checkpoint digest is not in history")
    day = str(preliminary_target.record["day"])
    day_file = audit / f"{day}.ndjson"
    # Retirement follows the same global order as publication and GDPR rewrite:
    # audit day, anchor ledger, then checkpoint index.
    with cross_process_lock(day_file, strict=True):
        anchor_rows = _verify_anchor_preflight(audit, trusted_keys)
        with cross_process_lock(checkpoints / ".checkpoint-index", strict=True):
            chain = _load_checkpoint_chain(checkpoints, trusted_keys, recover_stages=True)
            target_entry = next(
                (
                    entry
                    for entry in reversed(chain)
                    if entry.digest == supersedes_checkpoint_sha256
                ),
                None,
            )
            if target_entry is None:
                raise AuditCheckpointError(
                    "superseded checkpoint digest is not in history"
                )
            if str(target_entry.record["day"]) != day:
                raise AuditCheckpointError(
                    "superseded checkpoint changed day during retirement"
                )
            latest_for_day = next(
                (
                    entry
                    for entry in reversed(chain)
                    if entry.record["day"] == target_entry.record["day"]
                ),
                None,
            )
            if (
                latest_for_day is not None
                and latest_for_day.record["record_type"] == "retirement"
                and latest_for_day.record["supersedes_checkpoint_sha256"]
                == supersedes_checkpoint_sha256
            ):
                return latest_for_day.path
            if latest_for_day is None or latest_for_day.digest != target_entry.digest:
                raise AuditCheckpointError(
                    "retirement must bind the latest checkpoint for its audit day"
                )
            if target_entry.record["record_type"] == "retirement":
                return target_entry.path
            if day_file.exists():
                raise AuditCheckpointError(
                    f"refusing retirement while audit day {day} still exists"
                )
            evidence = _retention_evidence_digest(
                day=day,
                row_count=int(target_entry.record["row_count"]),
                tip_hash=str(target_entry.record["tip_hash"]),
                anchor_rows=anchor_rows,
            )
            sequence = len(chain) + 1
            body = _new_record_body(
                record_type="retirement",
                sequence=sequence,
                previous_digest=chain[-1].digest,
                day=day,
                row_count=int(target_entry.record["row_count"]),
                tip_hash=str(target_entry.record["tip_hash"]),
                supersedes_digest=target_entry.digest,
                lifecycle_reason=lifecycle_reason,
                evidence_digest=evidence,
            )
            raw = _sign_checkpoint_record(body, trusted_keys)
            target = checkpoints / f"{CHECKPOINT_PREFIX}{sequence:020d}.ndjson"
            _publish_complete_checkpoint(
                target,
                raw,
                trusted_keys,
                expected_sequence=sequence,
            )
            return target


def verify_checkpoints(  # noqa: C901 - forensic checks remain linear and explicit
    audit_dir: Path | str,
    checkpoint_dir: Path | str,
    *,
    pubkey_hex: str | None = None,
    trusted_pubkeys: Iterable[str] | None = None,
    minimum_sequence: int | None = None,
    minimum_digest: str | None = None,
    erase_records: EraseRecords | None = None,
) -> list[CheckpointBreak]:
    """Verify history, lifecycle evidence, and each current-era audit prefix.

    ``minimum_sequence`` and ``minimum_digest`` must be retained outside the
    checkpoint store. Together they detect both rollback and a signed fork.

    With ``minimum_sequence``, a supersession or retirement published after it
    is reported: the retained record no longer speaks for that day. A
    retirement is ``retired_after_pin``. A supersession is
    ``superseded_after_pin`` when ``erase_records`` finds a stored erase
    record for it, ``superseded_without_erase_record`` when it finds none,
    ``superseded_erase_record_unchecked`` when they could not be looked up and
    ``superseded_then_replaced`` when the day changed again afterwards and no
    record names it exactly.
    """
    try:
        audit, checkpoints = _resolved_directories(audit_dir, checkpoint_dir)
        trusted_keys = _trusted_key_map(
            pubkey_hex=pubkey_hex,
            trusted_pubkeys=trusted_pubkeys,
        )
        chain = _load_checkpoint_chain(checkpoints, trusted_keys)
    except (AuditCheckpointError, OSError, ValueError) as exc:
        return [CheckpointBreak(0, "checkpoint_store_invalid", str(exc))]
    if not chain:
        return [CheckpointBreak(0, "checkpoint_missing", "no checkpoints exist")]

    latest_sequence = int(chain[-1].record["checkpoint_sequence"])
    if minimum_sequence is not None and minimum_sequence < 1:
        return [
            CheckpointBreak(
                latest_sequence,
                "trusted_minimum_invalid",
                "minimum sequence must be at least 1",
            )
        ]
    if minimum_digest is not None:
        if minimum_sequence is None or not _SHA256_RE.fullmatch(minimum_digest):
            return [
                CheckpointBreak(
                    latest_sequence,
                    "trusted_minimum_invalid",
                    "minimum digest requires a minimum sequence and SHA-256 hex",
                )
            ]
    if minimum_sequence is not None and latest_sequence < minimum_sequence:
        return [
            CheckpointBreak(
                latest_sequence,
                "checkpoint_rollback",
                f"latest sequence {latest_sequence} is below trusted minimum "
                f"{minimum_sequence}",
            )
        ]
    if minimum_digest is not None:
        retained = chain[minimum_sequence - 1]  # type: ignore[operator]
        if retained.digest != minimum_digest:
            return [
                CheckpointBreak(
                    int(retained.record["checkpoint_sequence"]),
                    "checkpoint_fork",
                    "checkpoint bytes do not match the externally retained digest",
                )
            ]

    latest_era: dict[str, int] = {}
    latest_for_day: dict[str, _ChainEntry] = {}
    for entry in chain:
        day = str(entry.record["day"])
        latest_era[day] = entry.era
        latest_for_day[day] = entry

    current_entries = [
        entry
        for entry in chain
        if entry.record["record_type"] != "retirement"
        and entry.era == latest_era[str(entry.record["day"])]
        and latest_for_day[str(entry.record["day"])].record["record_type"]
        != "retirement"
    ]
    days = sorted({str(entry.record["day"]) for entry in current_entries})
    snapshots: dict[str, _DaySnapshot | AuditCheckpointError] = {}
    for day in days:
        day_file = audit / f"{day}.ndjson"
        if not day_file.exists():
            snapshots[day] = AuditCheckpointError(f"{day_file.name} is missing")
            continue
        try:
            # One non-mutating scan per day, regardless of checkpoint count.
            snapshots[day] = _snapshot_day_unlocked(day_file, trusted_keys)
        except (AuditCheckpointError, OSError, ValueError) as exc:
            snapshots[day] = AuditCheckpointError(str(exc))

    breaks: list[CheckpointBreak] = []
    if minimum_sequence is not None:
        breaks.extend(_lifecycle_after_pin(
            chain, pinned_sequence=minimum_sequence, snapshots=snapshots,
            latest_era=latest_era, erase_records=erase_records,
        ))
    anchor_rows_cache: list[dict] | AuditCheckpointError | None = None

    def lifecycle_anchor_rows() -> list[dict]:
        nonlocal anchor_rows_cache
        if anchor_rows_cache is None:
            try:
                anchor_rows_cache = _anchor_rows(audit, trusted_keys)
            except AuditCheckpointError as exc:
                anchor_rows_cache = exc
        if isinstance(anchor_rows_cache, AuditCheckpointError):
            raise anchor_rows_cache
        return anchor_rows_cache

    for entry in current_entries:
        record = entry.record
        sequence = int(record["checkpoint_sequence"])
        day = str(record["day"])
        snapshot = snapshots[day]
        if isinstance(snapshot, AuditCheckpointError):
            reason = (
                "checkpointed_day_missing"
                if "is missing" in str(snapshot)
                else "checkpointed_day_invalid"
            )
            breaks.append(CheckpointBreak(sequence, reason, str(snapshot)))
            continue
        required_count = int(record["row_count"])
        if snapshot.row_count < required_count:
            breaks.append(
                CheckpointBreak(
                    sequence,
                    "audit_tail_truncated",
                    f"{day}.ndjson has {snapshot.row_count} rows, checkpoint "
                    f"requires {required_count}",
                )
            )
            continue
        if snapshot.hashes[required_count - 1] != record["tip_hash"]:
            breaks.append(
                CheckpointBreak(
                    sequence,
                    "audit_prefix_mismatch",
                    f"{day}.ndjson row {required_count} does not match the "
                    "published checkpoint",
                )
            )
            continue
        if record["record_type"] == "supersession":
            try:
                expected_evidence = _gdpr_evidence_digest(
                    day=day,
                    row_count=required_count,
                    tip_hash=str(record["tip_hash"]),
                    rows=snapshot.rows,
                    anchor_rows=lifecycle_anchor_rows(),
                    supersedes_checkpoint_sha256=str(
                        record["supersedes_checkpoint_sha256"]
                    ),
                    expected_digest=str(record["evidence_sha256"]),
                )
            except AuditCheckpointError as exc:
                breaks.append(
                    CheckpointBreak(sequence, "lifecycle_evidence_invalid", str(exc))
                )
            else:
                if expected_evidence != record["evidence_sha256"]:
                    breaks.append(
                        CheckpointBreak(
                            sequence,
                            "lifecycle_evidence_mismatch",
                            "GDPR supersession evidence digest does not match",
                        )
                    )

    for entry in chain:
        if entry.record["record_type"] != "retirement":
            continue
        record = entry.record
        sequence = int(record["checkpoint_sequence"])
        retired_path = audit / f"{record['day']}.ndjson"
        if retired_path.exists():
            breaks.append(
                CheckpointBreak(
                    sequence,
                    "retired_day_present",
                    f"{retired_path.name} exists after signed retirement",
                )
            )
        try:
            expected_evidence = _retention_evidence_digest(
                day=str(record["day"]),
                row_count=int(record["row_count"]),
                tip_hash=str(record["tip_hash"]),
                anchor_rows=lifecycle_anchor_rows(),
                expected_digest=str(record["evidence_sha256"]),
            )
        except AuditCheckpointError as exc:
            breaks.append(
                CheckpointBreak(sequence, "lifecycle_evidence_invalid", str(exc))
            )
        else:
            if expected_evidence != record["evidence_sha256"]:
                breaks.append(
                    CheckpointBreak(
                        sequence,
                        "lifecycle_evidence_mismatch",
                        "retirement evidence digest does not match",
                    )
                )
    return breaks


def latest_checkpoint_sequence(
    checkpoint_dir: Path | str,
    *,
    pubkey_hex: str | None = None,
    trusted_pubkeys: Iterable[str] | None = None,
) -> int:
    """Return the latest structurally and cryptographically valid sequence."""
    directory = Path(checkpoint_dir).expanduser().resolve()
    trusted_keys = _trusted_key_map(
        pubkey_hex=pubkey_hex,
        trusted_pubkeys=trusted_pubkeys,
    )
    chain = _load_checkpoint_chain(directory, trusted_keys)
    return int(chain[-1].record["checkpoint_sequence"]) if chain else 0


def list_checkpoints(
    checkpoint_dir: Path | str,
    *,
    pubkey_hex: str | None = None,
    trusted_pubkeys: Iterable[str] | None = None,
) -> list[dict]:
    """Every published record, oldest first, after the same signature and
    chain checks :func:`verify_checkpoints` starts with.

    Read-only. Each row carries its sequence, day, record type, committed row
    count, creation time, its own SHA-256 and whether it is the latest record
    for its day (the only one a retirement or supersession may name).
    """
    directory = Path(checkpoint_dir).expanduser().resolve()
    if not directory.exists():
        return []
    trusted_keys = _trusted_key_map(
        pubkey_hex=pubkey_hex,
        trusted_pubkeys=trusted_pubkeys,
    )
    chain = _load_checkpoint_chain(directory, trusted_keys)
    latest = {str(entry.record["day"]): entry.digest for entry in chain}
    return [
        {
            "sequence": int(entry.record["checkpoint_sequence"]),
            "day": str(entry.record["day"]),
            "record_type": str(entry.record["record_type"]),
            "row_count": int(entry.record["row_count"]),
            "created_at": str(entry.record["created_at"]),
            "sha256": entry.digest,
            "latest_for_day": latest[str(entry.record["day"])] == entry.digest,
        }
        for entry in chain
    ]


__all__ = [
    "AuditCheckpointError",
    "CheckpointBreak",
    "CHECKPOINT_SCHEMA",
    "day_checkpoint_state",
    "latest_checkpoint_sequence",
    "list_checkpoints",
    "publish_checkpoint",
    "retire_checkpoint",
    "verify_checkpoints",
]
