"""Authenticated, bounded backup / transactional restore for one client.

Backups snapshot the active tenant/client data root. SQLite databases use the
online backup API; every payload file is content-hashed; and ``manifest.json``
is authenticated with an operator-custodied HMAC-SHA256 key supplied through
``MAVERICK_BACKUP_SIGNING_KEY`` (exactly 32 bytes encoded as hex or base64).
The HMAC is the authenticity boundary. Payload SHA-256 values alone are only
self-consistency checks and are never described or treated as authentication.

Unsigned legacy archives have an intentionally awkward compatibility path:
callers must pass ``allow_unsigned=True`` to ``read_manifest`` / ``restore_backup``
(and may create one with the same explicit flag). The CLI has no unsigned
override. ``force=True`` only overrides client/live-world admission checks and
never bypasses signature verification or schema compatibility.

Restore scans tar streams without ``getmembers``/``extractall``, enforces hard
member/path/type/per-file/expanded-size limits, writes only into a private
staging tree, and authenticates/verifies the complete payload before touching
live state. Application is journaled: originals plus SQLite sidecars are saved
first, and a failure rolls ordinary payloads back. Tenant namespace claims and
deletion tombstones remain append-only even after a failed publication: releasing
that history could reauthorize old identities. An interrupted restore is recovered
from its private journal before the next restore begins.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import stat
import tarfile
import tempfile
import time
import unicodedata
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import quote

from . import file_lock
from .constant_time import text_equals

log = logging.getLogger(__name__)

MANIFEST = "manifest.json"
SCHEMA = 2
_AUTH_ALGORITHM = "HMAC-SHA256"
_SIGNING_KEY_ENV = "MAVERICK_BACKUP_SIGNING_KEY"
_SKIP_SUFFIXES = ("-wal", "-shm", "-journal", ".tmp")
_RESTORE_TX_ROOT = ".restore-transactions"
_RESTORE_LOCK_TARGET = ".restore-transaction"
_JOURNAL = "journal.json"
_DB_SIDECARS = ("-wal", "-shm", "-journal")
_DERIVED_REBUILD_MARKER_BYTES = b"rebuild from canonical rows\n"
# The dashboard's compiled-template cache (maverick_dashboard.app) is rebuilt
# from template source checksums. Snapshotting it would make every newly
# rendered page look like a changed goal template and block recovery.
_TEMPLATE_CACHE = ("cache", "templates")
# Browser sign-in sessions (maverick_dashboard.session_registry) are never
# snapshotted or rewound: restoring an older copy would revive revoked
# sessions, and every signed-in page view updates them, so comparing them
# would block every recovery. A restore leaves the live store in place; on a
# new machine its absence signs everyone out (session ids fail closed).
_SESSION_REGISTRY = "dashboard-sessions.sqlite3"

# A live WorldModel touches its WAL/SHM sidecars on every write and only holds
# its own cross_process_lock briefly during __init__ (world_model.py), so
# checking that lock is not by itself a reliable "is anything using this
# world right now" signal for an already-running process. A sidecar mtime
# inside this window is: generous enough that ordinary read/write traffic
# (busy_timeout retries, periodic checkpoints) never trips it while idle, but
# tight enough that it still means "something touched this file moments ago".
_LIVE_WORLD_RECENCY_SECONDS = 10.0

# Generous production ceilings, but finite on every attacker-controlled axis.
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_FILE_BYTES = 8 * 1024**3
MAX_ARCHIVE_EXPANDED_BYTES = 256 * 1024**3
MAX_ARCHIVE_COMPRESSED_BYTES = 64 * 1024**3
MAX_MANIFEST_BYTES = 16 * 1024**2
MAX_ARCHIVE_PATH_BYTES = 1024
MAX_COMPONENT_UNITS = 255
_COPY_CHUNK = 1 << 20
_RECOVERY_SCOPE: ContextVar[tuple[Path, str | None, bytes] | None] = ContextVar("backup_recovery_scope", default=None)
_RECOVERY_EXPANDED_LIMIT: ContextVar[int | None] = ContextVar("backup_recovery_expanded_limit", default=None)
_RECOVERY_WHOLE_HOME: ContextVar[bool] = ContextVar("backup_recovery_whole_home", default=False)
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_WINDOWS_FORBIDDEN = frozenset('<>:"/\\|?*')
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
    "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
}


class BackupError(RuntimeError):
    """A backup cannot be created or a restore cannot be safely applied."""


def _filesystem_path(path: str | Path) -> Path:
    return Path(file_lock._windows_extended_path(path)) if os.name == "nt" else Path(path)


@contextmanager
def _temporary_directory(*, prefix: str):
    temporary = tempfile.TemporaryDirectory(prefix=prefix)
    # Cleanup must use the same long-path spelling as staging; otherwise
    # Windows can create the payload but fail to remove it after verification.
    temporary.name = str(_filesystem_path(temporary.name))
    try:
        yield Path(temporary.name)
    finally:
        temporary.cleanup()


def _client_root() -> Path:
    scope = _RECOVERY_SCOPE.get()
    if scope is not None:
        return _filesystem_path(scope[0])
    from .paths import data_dir

    return _filesystem_path(data_dir())


def _client_id() -> str | None:
    scope = _RECOVERY_SCOPE.get()
    if scope is not None:
        return scope[1]
    from .client import client_id

    return client_id()


def data_backups_dir() -> Path:
    from .paths import data_dir

    return data_dir("backups")


def _is_alias(path: Path, info: os.stat_result) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return (
        stat.S_ISLNK(info.st_mode)
        or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)
        or bool(callable(is_junction) and is_junction())
    )


def _transaction_root(root: Path) -> Path:
    path = root / _RESTORE_TX_ROOT
    # The journal preserves full payload paths under originals/. Windows needs
    # its extended filesystem spelling for hashed draft paths in that subtree.
    return Path(file_lock._windows_extended_path(path)) if os.name == "nt" else path


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_nlink


def _canonical_body(document: dict[str, Any]) -> bytes:
    body = {k: v for k, v in document.items() if k != "authentication"}
    try:
        return json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BackupError("backup metadata is not canonical JSON") from exc


def _decode_operator_key(raw: str) -> bytes:
    value = raw.strip()
    if len(value) == 64:
        try:
            decoded = bytes.fromhex(value)
        except ValueError:
            decoded = b""
        if len(decoded) == 32:
            return decoded
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        decoded = b""
    if len(decoded) != 32:
        raise BackupError(
            f"{_SIGNING_KEY_ENV} must be exactly 32 bytes encoded as hex or base64"
        )
    return decoded


def _operator_key(*, required: bool) -> bytes | None:
    scope = _RECOVERY_SCOPE.get()
    if scope is not None:
        return scope[2]
    raw = os.environ.get(_SIGNING_KEY_ENV, "")
    if not raw.strip():
        if required:
            raise BackupError(
                f"authenticated backup requires {_SIGNING_KEY_ENV}; refusing "
                "an unsigned archive (use allow_unsigned=True only for explicit "
                "legacy recovery)"
            )
        return None
    return _decode_operator_key(raw)


@contextmanager
def recovery_scope(root: Path, client: str | None, key: bytes, *, max_expanded_bytes: int | None = None, whole_home: bool = False):
    """Pin a server-resolved recovery target/key without process-env mutation.

    The recovery center is responsible for target authorization and quiescence.
    Ordinary backup CLI callers keep the existing operator environment contract.
    """
    if len(key) != 32:
        raise BackupError("recovery signing key must contain exactly 32 bytes")
    if max_expanded_bytes is not None and (type(max_expanded_bytes) is not int or max_expanded_bytes < 1):
        raise BackupError("recovery archive size limit must be a positive integer")
    token = _RECOVERY_SCOPE.set((Path(root), client, bytes(key)))
    limit_token = _RECOVERY_EXPANDED_LIMIT.set(max_expanded_bytes)
    home_token = _RECOVERY_WHOLE_HOME.set(whole_home)
    try:
        yield
    finally:
        _RECOVERY_SCOPE.reset(token)
        _RECOVERY_EXPANDED_LIMIT.reset(limit_token)
        _RECOVERY_WHOLE_HOME.reset(home_token)


def _expanded_limit() -> int:
    requested = _RECOVERY_EXPANDED_LIMIT.get()
    return min(MAX_ARCHIVE_EXPANDED_BYTES, requested) if requested is not None else MAX_ARCHIVE_EXPANDED_BYTES


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def _authenticate_for_write(
    document: dict[str, Any], key: bytes | None,
) -> dict[str, Any]:
    result = dict(document)
    if key is None:
        result["authentication"] = {"algorithm": "none"}
        return result
    signature = hmac.new(key, _canonical_body(result), hashlib.sha256).hexdigest()
    result["authentication"] = {
        "algorithm": _AUTH_ALGORITHM,
        "key_id": _key_id(key),
        "signature": signature,
    }
    return result


def _verify_authentication(
    document: dict[str, Any], *, allow_unsigned: bool, label: str,
) -> bytes | None:
    auth = document.get("authentication")
    if auth is None:
        if allow_unsigned:
            log.warning("accepting explicitly-authorized unsigned legacy %s", label)
            return None
        raise BackupError(f"{label} is unsigned; authenticity cannot be established")
    if not isinstance(auth, dict):
        raise BackupError(f"{label} authentication metadata is malformed")
    algorithm = auth.get("algorithm")
    if algorithm == "none":
        if set(auth) != {"algorithm"}:
            raise BackupError(f"{label} unsigned metadata is ambiguous")
        if not allow_unsigned:
            raise BackupError(f"{label} is unsigned; authenticity cannot be established")
        log.warning("accepting explicitly-authorized unsigned %s", label)
        return None
    if algorithm != _AUTH_ALGORITHM:
        raise BackupError(f"{label} uses an unsupported authentication algorithm")
    if set(auth) != {"algorithm", "key_id", "signature"}:
        raise BackupError(f"{label} authentication metadata is ambiguous")
    key = _operator_key(required=True)
    assert key is not None
    claimed_key_id = auth.get("key_id")
    signature = auth.get("signature")
    if claimed_key_id != _key_id(key):
        raise BackupError(f"{label} was not signed by the configured operator key")
    if not isinstance(signature, str) or len(signature) != 64:
        raise BackupError(f"{label} signature is malformed")
    expected = hmac.new(key, _canonical_body(document), hashlib.sha256).hexdigest()
    if not text_equals(expected, signature.lower()):
        raise BackupError(f"{label} signature verification failed")
    return key


def _safe_relative_path(value: str, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\0" in value or "\\" in value:
        raise BackupError(f"unsafe {label}: {value!r}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BackupError(f"unsafe {label}: {value!r}") from exc
    if len(encoded) > MAX_ARCHIVE_PATH_BYTES:
        raise BackupError(f"{label} is too long")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != value
        or any(p in {"", ".", ".."} for p in path.parts)
    ):
        raise BackupError(f"unsafe {label}: {value!r}")
    for component in path.parts:
        if (
            component.endswith((".", " "))
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in component)
            or any(c in _WINDOWS_FORBIDDEN for c in component)
        ):
            raise BackupError(f"unsafe {label}: {value!r}")
        basename = component.split(".", 1)[0].rstrip(" ").upper()
        if basename in _WINDOWS_RESERVED:
            raise BackupError(f"unsafe {label}: {value!r}")
        if (
            len(component.encode("utf-8")) > MAX_COMPONENT_UNITS
            or len(component.encode("utf-16-le")) // 2 > MAX_COMPONENT_UNITS
        ):
            raise BackupError(f"{label} component is too long")
    return path


def _is_reserved_restore_path(relative: PurePosixPath) -> bool:
    return (
        relative.parts[0] in {"backups", _RESTORE_TX_ROOT}
        or relative.as_posix() == f"{_RESTORE_LOCK_TARGET}.lock"
        or (_RECOVERY_WHOLE_HOME.get() and (
            relative.parts[0] in {"control-plane.lock", "control-plane-holder.json"}
            or (len(relative.parts) >= 3 and relative.parts[0] == "tenants"
                and relative.parts[2] in {"backups", _RESTORE_TX_ROOT, f"{_RESTORE_LOCK_TARGET}.lock"})))
    )


class _ArchiveBudget:
    def __init__(self) -> None:
        self.members = 0
        self.expanded = 0
        self.names: set[str] = set()
        self.portable_names: dict[str, str] = {}

    def observe(self, member: tarfile.TarInfo) -> str | None:
        self.members += 1
        if self.members > MAX_ARCHIVE_MEMBERS:
            raise BackupError("backup exceeds the archive member-count limit")
        name = member.name
        if not isinstance(name, str) or name in self.names:
            raise BackupError(f"duplicate or malformed archive member: {name!r}")
        self.names.add(name)
        folded = unicodedata.normalize("NFC", name).casefold()
        prior = self.portable_names.get(folded)
        if prior is not None and prior != name:
            raise BackupError(
                f"archive members collide on a case-insensitive host: {prior!r}, {name!r}"
            )
        self.portable_names[folded] = name

        if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            raise BackupError(f"unsupported archive member type: {name!r}")

        if name == MANIFEST:
            if not member.isfile() or member.issym() or member.islnk():
                raise BackupError("manifest.json must be one regular file")
            rel: str | None = None
        elif name == "data":
            if not member.isdir():
                raise BackupError("data archive root must be a directory")
            rel = None
        elif name.startswith("data/"):
            rel = name[len("data/"):]
            safe_rel = _safe_relative_path(rel, label="archive member path")
            if _is_reserved_restore_path(safe_rel):
                raise BackupError(f"archive member targets reserved restore state: {name!r}")
            if not (member.isfile() or member.isdir()) or member.issym() or member.islnk():
                raise BackupError(f"unsupported archive member type: {name!r}")
        else:
            raise BackupError(f"unexpected archive member: {name!r}")

        if member.isdir():
            if member.size not in {0, None}:
                raise BackupError(f"directory member has a payload: {name!r}")
            return rel
        if not isinstance(member.size, int) or member.size < 0:
            raise BackupError(f"archive member has an invalid size: {name!r}")
        if member.size > MAX_ARCHIVE_FILE_BYTES:
            raise BackupError(f"archive member exceeds the per-file limit: {name!r}")
        if name == MANIFEST and member.size > MAX_MANIFEST_BYTES:
            raise BackupError("manifest.json exceeds the manifest-size limit")
        self.expanded += member.size
        if self.expanded > _expanded_limit():
            raise BackupError("backup exceeds the total expanded-size limit")
        return rel


# Pax and GNU long-name headers are read whole by ``tarfile`` before a member
# reaches _ArchiveBudget, so their declared size is bounded here, ahead of that
# read. Member paths are capped at MAX_ARCHIVE_PATH_BYTES; this leaves ample room.
MAX_EXTENDED_HEADER_BYTES = 64 * 1024
_EXTENDED_HEADER_TYPES = frozenset({
    tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
    tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
})


class _BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, tarfile):  # type: ignore[no-untyped-def]
        if self.type in _EXTENDED_HEADER_TYPES and self.size > MAX_EXTENDED_HEADER_BYTES:
            raise BackupError("archive extended header exceeds its size limit")
        return super()._proc_member(tarfile)


@contextmanager
def _verified_archive(path: str | Path):
    archive = _filesystem_path(path)
    try:
        before = archive.lstat()
    except OSError as exc:
        raise BackupError(f"unreadable backup {str(path)!r}: {exc}") from exc
    if (
        _is_alias(archive, before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > MAX_ARCHIVE_COMPRESSED_BYTES
    ):
        raise BackupError("backup path must be one bounded, single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(archive), flags)
    except OSError as exc:
        raise BackupError(f"backup could not be opened safely: {exc}") from exc
    try:
        opened = os.fstat(fd)
        after = archive.lstat()
        if (
            _is_alias(archive, after)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or after.st_nlink != 1
            or _identity(before) != _identity(opened)
            or _identity(opened) != _identity(after)
        ):
            raise BackupError("backup path identity changed while opening")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            yield stream
    finally:
        if fd >= 0:
            os.close(fd)


def _read_exact(member_stream: BinaryIO, size: int, *, limit: int) -> bytes:
    if size > limit:
        raise BackupError("archive member exceeds its read limit")
    data = member_stream.read(size + 1)
    if not isinstance(data, bytes) or len(data) != size:
        raise BackupError("archive member is truncated or overlong")
    return data


def _parse_manifest(data: bytes) -> dict[str, Any]:
    def _reject_constant(value: str):
        raise ValueError(f"non-finite JSON constant {value}")

    try:
        manifest = json.loads(
            data.decode("utf-8"),
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise BackupError("manifest.json is not valid bounded JSON") from exc
    if not isinstance(manifest, dict):
        raise BackupError("manifest.json must contain an object")
    return manifest


def _read_manifest_stream(
    stream: BinaryIO, *, allow_unsigned: bool,
) -> tuple[dict[str, Any], bytes | None]:
    manifest: dict[str, Any] | None = None
    budget = _ArchiveBudget()
    try:
        with tarfile.open(fileobj=stream, mode="r|gz", tarinfo=_BoundedTarInfo) as archive:
            for member in archive:
                budget.observe(member)
                if member.name != MANIFEST:
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BackupError("backup has no readable manifest.json")
                manifest = _parse_manifest(
                    _read_exact(extracted, member.size, limit=MAX_MANIFEST_BYTES)
                )
    except BackupError:
        raise
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise BackupError(f"unreadable backup archive: {exc}") from exc
    if manifest is None:
        raise BackupError("backup has no manifest.json")
    key = _verify_authentication(
        manifest,
        allow_unsigned=allow_unsigned,
        label="backup manifest",
    )
    _manifest_files(manifest, allow_legacy_unsigned=allow_unsigned and key is None)
    return manifest, key


def _manifest_files(
    manifest: dict[str, Any], *, allow_legacy_unsigned: bool,
) -> dict[str, tuple[str, int | None]]:
    schema = manifest.get("schema")
    if type(schema) is not int or (schema != SCHEMA and not (allow_legacy_unsigned and schema == 1)):
        raise BackupError("unsupported backup manifest schema; upgrade Lightwork or use a reviewed migration")
    raw_files = manifest.get("files")
    if not isinstance(raw_files, dict) or len(raw_files) > MAX_ARCHIVE_MEMBERS:
        raise BackupError("backup manifest files map is missing or oversized")
    if not raw_files:
        raise BackupError("backup manifest contains no payload files")
    expected: dict[str, tuple[str, int | None]] = {}
    portable: dict[str, str] = {}
    total = 0
    for raw_rel, record in raw_files.items():
        rel = _safe_relative_path(raw_rel, label="manifest file path").as_posix()
        if _is_reserved_restore_path(PurePosixPath(rel)):
            raise BackupError(f"manifest targets reserved restore state: {rel}")
        folded = unicodedata.normalize("NFC", rel).casefold()
        if folded in portable and portable[folded] != rel:
            raise BackupError("manifest file paths collide on a portable host")
        portable[folded] = rel
        if isinstance(record, str) and allow_legacy_unsigned and schema == 1:
            digest, size = record, None
        elif isinstance(record, dict):
            digest, size = record.get("sha256"), record.get("size")
            if not isinstance(size, int) or size < 0 or size > MAX_ARCHIVE_FILE_BYTES:
                raise BackupError(f"invalid manifest size for {rel}")
            total += size
        else:
            raise BackupError(f"invalid manifest record for {rel}")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise BackupError(f"invalid manifest SHA-256 for {rel}")
        expected[rel] = (digest, size)
    if total > _expanded_limit():
        raise BackupError("manifest declares too much expanded data")
    if "withheld_key_files" in manifest:
        withheld = manifest["withheld_key_files"]
        if not isinstance(withheld, list) or len(withheld) > MAX_ARCHIVE_MEMBERS:
            raise BackupError("backup excluded-key list is missing or oversized")
        seen = set()
        for name in withheld:
            relative = _safe_relative_path(name, label="excluded key path")
            normalized = relative.as_posix()
            folded = unicodedata.normalize("NFC", normalized).casefold()
            if not _is_key_material(relative) or folded in seen or folded in portable:
                raise BackupError("backup excluded-key list conflicts with its payload")
            seen.add(folded)
    return expected


def read_manifest(
    tarball: str | Path, *, allow_unsigned: bool = False,
) -> dict[str, Any]:
    """Return a bounded, authenticated manifest.

    ``allow_unsigned=True`` is an explicit compatibility path for legacy
    recovery. It verifies structure and payload hashes during restore but does
    not and cannot authenticate archive provenance.
    """
    with _verified_archive(tarball) as stream:
        manifest, _ = _read_manifest_stream(stream, allow_unsigned=allow_unsigned)
        return manifest


def _new_private_empty(path: Path) -> None:
    try:
        file_lock.atomic_create_bytes(path, b"")
    except FileExistsError as exc:
        raise BackupError(f"refusing an existing or planted path: {path}") from exc
    except OSError as exc:
        raise BackupError(f"could not create private staging file: {path}") from exc


def _open_private_writer(path: Path) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise BackupError(f"private staging path disappeared: {path}") from exc
    if (
        _is_alias(path, before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not file_lock.private_path_is_restricted(path)
    ):
        raise BackupError(f"staging path is not a private regular file: {path}")
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags)
    try:
        opened = os.fstat(fd)
        after = path.lstat()
        if (
            _is_alias(path, after)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or after.st_nlink != 1
            or _identity(before) != _identity(opened)
            or _identity(opened) != _identity(after)
        ):
            raise BackupError(f"staging path identity changed: {path}")
        return fd, opened
    except BaseException:
        os.close(fd)
        raise


def _stream_to_new_private(
    reader: BinaryIO,
    destination: Path,
    *,
    expected_size: int,
    precreated: bool = False,
) -> tuple[str, int]:
    if expected_size < 0 or expected_size > MAX_ARCHIVE_FILE_BYTES:
        raise BackupError("file exceeds the backup per-file limit")
    file_lock.ensure_private_directory(destination.parent)
    if not precreated:
        _new_private_empty(destination)
    digest = hashlib.sha256()
    remaining = expected_size
    fd = -1
    try:
        fd, _ = _open_private_writer(destination)
        with os.fdopen(fd, "wb") as output:
            fd = -1
            while remaining:
                chunk = reader.read(min(_COPY_CHUNK, remaining))
                if not isinstance(chunk, bytes) or not chunk:
                    raise BackupError("source file is truncated during streaming copy")
                if len(chunk) > remaining:
                    raise BackupError("source file exceeded its declared size")
                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if reader.read(1) not in {b"", None}:
                raise BackupError("source file grew during streaming copy")
            output.flush()
            os.fsync(output.fileno())
        if not file_lock.private_path_is_restricted(destination):
            raise BackupError("streamed file did not retain private permissions")
        return digest.hexdigest(), expected_size
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _copy_verified_file(
    source: Path,
    destination: Path,
    *,
    destination_precreated: bool = False,
) -> tuple[str, int]:
    source, destination = _filesystem_path(source), _filesystem_path(destination)
    try:
        before = source.lstat()
    except OSError as exc:
        raise BackupError(f"source file could not be inspected: {source}") from exc
    if _is_alias(source, before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise BackupError(f"source is not a single-link regular file: {source}")
    if before.st_size > MAX_ARCHIVE_FILE_BYTES:
        raise BackupError(f"source file exceeds the per-file limit: {source}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(str(source), flags)
    try:
        opened = os.fstat(fd)
        after_open = source.lstat()
        if (
            _is_alias(source, after_open)
            or opened.st_nlink != 1
            or after_open.st_nlink != 1
            or _identity(before) != _identity(opened)
            or _identity(opened) != _identity(after_open)
        ):
            raise BackupError(f"source file identity changed: {source}")
        with os.fdopen(fd, "rb") as reader:
            fd = -1
            result = _stream_to_new_private(
                reader,
                destination,
                expected_size=opened.st_size,
                precreated=destination_precreated,
            )
        final = source.lstat()
        if (
            _identity(after_open) != _identity(final)
            or final.st_size != opened.st_size
            or getattr(final, "st_mtime_ns", None) != getattr(after_open, "st_mtime_ns", None)
        ):
            destination.unlink(missing_ok=True)
            raise BackupError(f"source file changed during backup: {source}")
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _consistent_db_copy(source: Path, destination: Path) -> tuple[str, int]:
    file_lock.ensure_private_directory(destination.parent)
    _new_private_empty(destination)
    try:
        src = sqlite3.connect(str(source))
        try:
            dst = sqlite3.connect(str(destination))
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
        file_lock.ensure_private_file(destination)
        size = destination.stat().st_size
        if size > MAX_ARCHIVE_FILE_BYTES:
            raise BackupError(f"database exceeds the per-file limit: {source}")
        return _sha256(destination), size
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(_filesystem_path(path), "rb") as stream:
        for chunk in iter(lambda: stream.read(_COPY_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _world_schema_version(db: Path) -> int | None:
    """Read native SQLite metadata from a private, checkpointed staging copy.

    An absent marker leaves other SQLite stores unclassified; for a known
    world, an absent/empty table is the supported unversioned legacy form.
    Nonempty metadata must identify exactly one positive integral version.
    """
    if not db.exists():
        return None
    invalid = "backup world schema metadata is invalid; use a compatible backup or a reviewed migration"
    try:
        uri = (
            "file:" + quote(str(_filesystem_path(db)), safe=":")
            if os.name == "nt" else db.resolve().as_uri()
        )
        # _stage uses SQLite's online backup API, so committed WAL pages are
        # already in the copy. Immutable avoids creating unmanifested sidecars
        # when a copied database retains its WAL journal-mode header.
        connection = sqlite3.connect(uri + "?mode=ro&immutable=1", uri=True)
        try:
            table = connection.execute(
                "SELECT type FROM sqlite_master WHERE name = 'schema_version' COLLATE NOCASE"
            ).fetchone()
            if table is None:
                return None
            if table[0] != "table":
                raise BackupError(invalid)
            rows = connection.execute("SELECT version FROM schema_version LIMIT 2").fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise BackupError(invalid) from exc
    if not rows:
        return None
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 1:
        raise BackupError(invalid)
    return rows[0][0]


def _check_supported_world_schema(value: Any) -> None:
    from .world_model import SCHEMA_VERSION

    if value is not None and (type(value) is not int or value < 1):
        raise BackupError("backup world schema metadata is invalid; use a compatible backup or a reviewed migration")
    if value is not None and value > SCHEMA_VERSION:
        raise BackupError(
            f"backup world schema v{value} is newer than this binary's v{SCHEMA_VERSION}; "
            "upgrade Lightwork first or select a compatible backup"
        )


def _validate_restore_schemas(stage: Path, manifest: dict[str, Any]) -> None:
    """Reject unsupported staged databases before recovery or publication.

    The signed v2 root declaration must match the actual root database. Legacy
    v1 archives may omit that declaration. Header/extension-discovered SQLite
    files with the native schema_version marker are checked regardless of
    filename or tenant path; the root declaration does not describe them.
    """
    declared = manifest.get("world_schema_version")
    _check_supported_world_schema(declared)
    sidecar_names = {"world.db" + suffix for suffix in _DB_SIDECARS}
    if any(path.name.casefold() in sidecar_names for path in stage.rglob("*")):
        raise BackupError(
            "backup world databases must be checkpointed without SQLite sidecars; "
            "create a fresh snapshot or use a reviewed migration"
        )
    actual = _world_schema_version(stage / "world.db")
    _check_supported_world_schema(actual)
    if (manifest.get("schema") == SCHEMA or declared is not None) and actual != declared:
        raise BackupError(
            "backup world schema does not match its manifest; use a compatible backup or a reviewed migration"
        )
    for db in stage.rglob("*"):
        if not db.is_file() or not _is_sqlite_file(db):
            continue
        # All supported SQLite snapshots are checkpointed copies. Check before
        # immutable inspection: a custom file's native marker itself could
        # otherwise be hidden in a WAL. Other component schemas are not given
        # a world version merely because they have a SQLite header.
        if any(db.with_name(db.name + suffix).exists() for suffix in _DB_SIDECARS):
            raise BackupError(
                "backup SQLite databases must be checkpointed without sidecars; "
                "create a fresh snapshot or use a reviewed migration"
            )
        _check_supported_world_schema(_world_schema_version(db))


# The at-rest encryption key (keys/at_rest.key + the keys/at_rest.d/*.key
# rotation keyring) and the audit signing key (audit/keys/) decrypt/authenticate
# everything else this snapshot carries. docs/encryption.md tells operators to
# escrow the at-rest key "not next to the data they unlock"; bundling it inside
# the very archive it decrypts does the opposite and nullifies the product's
# at-rest-encryption posture for anyone who obtains a copy (offsite backup, S3
# bucket, standby host, a DSAR export handed to the data subject).
# Only raw secrets are withheld: the at-rest primary key, its rotation keyring
# and the audit signing keys (all ``*.key``). A wrapped DEK (keys/dek.wrapped)
# is ciphertext under the primary key and public keys are public; both stay in
# the archive because recovery of the encrypted payload needs them.
#
# The same key folders sit inside every workspace folder (``tenants/<id>/``):
# each workspace's audit signing key, and a client deployment's at-rest key and
# keyring. A whole-home archive withholds those too -- matching the archive root
# alone left them bundled next to the data they unlock.
_KEY_MATERIAL_ROOTS = (("keys",), ("audit", "keys"))
# The browser auth vault (maverick.browser_auth_vault) keeps its raw Fernet key
# as ``vault/key`` (or ``vault/authorities/<id>/key``) beside the ciphertext it
# unlocks, without a ``.key`` suffix. It is withheld under its own scope so an
# older archive that bundled it never reads as carrying the at-rest keys.
_VAULT_SCOPE = "vault"


def _is_vault_key(parts: tuple[str, ...]) -> bool:
    return bool(parts) and parts[0] == "vault" and parts[-1] == "key" and (
        len(parts) == 2 or (len(parts) == 4 and parts[1] == "authorities"))


def _key_material_scope(relative: Path) -> tuple[str, ...] | None:
    """The folder a raw key file belongs to: ``()`` for the data root's own keys,
    ``("tenants", <id>)`` for one workspace's, either with ``"vault"`` appended
    for a browser-vault key; ``None`` when it is not key material."""
    parts = relative.parts
    scope: tuple[str, ...] = ()
    if len(parts) > 2 and parts[0] == "tenants":
        scope, parts = parts[:2], parts[2:]
    if relative.suffix == ".key" and any(parts[: len(root)] == root for root in _KEY_MATERIAL_ROOTS):
        return scope
    if _is_vault_key(parts):
        return (*scope, _VAULT_SCOPE)
    return None


def _is_key_material(relative: Path) -> bool:
    return _key_material_scope(relative) is not None


def _keys_included(relative: Path, include_keys: bool | frozenset) -> bool:
    """Is the raw key file at ``relative`` part of the set ``include_keys`` names?
    ``True`` takes every key; a set of scopes (see :func:`_archive_includes_keys`)
    only the keys of those folders."""
    if include_keys is True:
        return True
    return bool(include_keys) and _key_material_scope(relative) in include_keys


def withheld_key_files() -> list[str]:
    """Raw key files a default (keys-excluded) backup of the current data root
    leaves out, relative to that root: the copies the operator must escrow
    separately. ``maverick backup create`` prints this list."""
    root = _client_root()
    if not root.is_dir():
        return []
    return sorted(
        relative.as_posix()
        for relative in (path.relative_to(root) for path in root.rglob("*key"))
        if _is_key_material(relative) and (root / relative).is_file()
    )


def _excluded_from_snapshot(relative: Path, *, include_keys: bool | frozenset) -> bool:
    return (
        not relative.parts
        or relative.parts[0] in {"backups", _RESTORE_TX_ROOT}
        or tuple(part.casefold() for part in relative.parts[:2]) == _TEMPLATE_CACHE
        or (len(relative.parts) == 1 and relative.name.casefold().startswith(_SESSION_REGISTRY))
        or relative.name == f"{_RESTORE_LOCK_TARGET}.lock"
        or relative.name.endswith(_SKIP_SUFFIXES)
        or (_is_key_material(relative) and not _keys_included(relative, include_keys))
        or _is_reserved_restore_path(PurePosixPath(relative.as_posix()))
    )


def _is_sqlite_file(path: Path) -> bool:
    # Consent, A2A and other stores use .sqlite3/.sqlite, and extensions are not
    # a database format boundary. Header recognition also covers custom names.
    # Conventional names retain fail-closed validation if their header is bad.
    if path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
        return True
    try:
        with path.open("rb") as stream:
            return stream.read(16) == b"SQLite format 3\x00"
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise BackupError("could not inspect a possible SQLite database") from exc


def _stage(root: Path, stage: Path, *, include_keys: bool | frozenset,
           withheld_keys: list[str] | None = None) -> dict[str, dict[str, Any]]:
    root, stage = _filesystem_path(root), _filesystem_path(stage)
    files: dict[str, dict[str, Any]] = {}
    total = 0
    count = 0
    for source in sorted(root.rglob("*")):
        relative = source.relative_to(root)
        if _excluded_from_snapshot(relative, include_keys=include_keys):
            if withheld_keys is not None and _is_key_material(relative) and not _keys_included(relative, include_keys):
                try:
                    info = source.lstat()
                except OSError as exc:
                    raise BackupError("An excluded key file could not be inspected.") from exc
                if not stat.S_ISDIR(info.st_mode):
                    withheld_keys.append(_safe_relative_path(relative.as_posix(), label="excluded key path").as_posix())
                    if len(withheld_keys) > MAX_ARCHIVE_MEMBERS:
                        raise BackupError("The excluded-key list exceeds the backup limit.")
            continue
        try:
            info = source.lstat()
        except OSError as exc:
            raise BackupError(f"backup source could not be inspected: {source}") from exc
        if _is_alias(source, info):
            raise BackupError(f"backup source contains an unsupported alias: {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise BackupError(f"backup source is not a regular file: {relative}")
        if total + info.st_size > _expanded_limit():
            raise BackupError("live data exceeds configured backup archive limits")
        file_lock.ensure_private_file(source)
        rel = _safe_relative_path(relative.as_posix(), label="backup source path").as_posix()
        destination = stage / Path(*PurePosixPath(rel).parts)
        if _is_sqlite_file(source):
            digest, size = _consistent_db_copy(source, destination)
        else:
            digest, size = _copy_verified_file(source, destination)
        count += 1
        total += size
        if count > MAX_ARCHIVE_MEMBERS or total > _expanded_limit():
            raise BackupError("live data exceeds configured backup archive limits")
        files[rel] = {"sha256": digest, "size": size}
    directory_count = sum(1 for path in stage.rglob("*") if path.is_dir())
    if count + directory_count + 2 > MAX_ARCHIVE_MEMBERS:
        raise BackupError("staged backup exceeds the archive member-count limit")
    return files


def _unique_private_empty(parent: Path, prefix: str) -> Path:
    parent = _filesystem_path(parent)
    for _ in range(100):
        candidate = parent / f".{prefix}-{secrets.token_hex(16)}.tmp"
        try:
            file_lock.atomic_create_bytes(candidate, b"")
            return candidate
        except FileExistsError:
            continue
    raise BackupError("could not allocate a unique private staging path")


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def create_backup(
    out: str | Path | None = None,
    *,
    allow_unsigned: bool = False,
    include_keys: bool = False,
    recovery_metadata: dict[str, Any] | None = None,
) -> Path:
    """Create one private, atomically-published backup archive.

    Authenticated creation is the default and requires
    ``MAVERICK_BACKUP_SIGNING_KEY``. ``allow_unsigned=True`` exists only for
    explicit legacy interoperability; such an archive is labelled unsigned.
    Existing destination paths are refused rather than overwritten.

    ``include_keys`` defaults to ``False``: the at-rest encryption key (and
    rotation keyring), the audit signing key and the browser vault key, those
    of the data root and of every workspace folder under it, are excluded from the
    archive, matching docs/encryption.md's escrow guidance to keep key
    material off the same copy as the data it decrypts. Pass
    ``include_keys=True`` only when the operator has explicitly chosen to
    bundle the key with the archive instead of escrowing it separately.
    """
    root = _client_root()
    if not root.exists():
        raise BackupError(f"no data root to back up at {root}")
    file_lock.ensure_private_directory(root)
    key = _operator_key(required=not allow_unsigned)
    client_identifier = _client_id() or "unbound"
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    default_destination = out is None
    if default_destination:
        out = data_backups_dir() / (
            f"maverick-{client_identifier}-{timestamp}-{secrets.token_hex(4)}.tgz"
        )
    public_destination = Path(out).expanduser()
    destination = _filesystem_path(public_destination)
    try:
        if default_destination:
            file_lock.ensure_private_directory(destination.parent)
        else:
            # A caller-selected parent may contain unrelated files. Verify its
            # ACL instead of silently revoking collaborators' access to it.
            file_lock.prepare_private_directory(destination.parent)
    except OSError as exc:
        raise BackupError("backup destination directory must be private") from exc
    if os.path.lexists(destination):
        raise BackupError(f"refusing existing backup destination: {destination}")

    with _temporary_directory(prefix="mvk-backup-") as temporary:
        temp_root = file_lock.ensure_private_directory(temporary)
        stage = file_lock.ensure_private_directory(temp_root / "data")
        withheld_keys: list[str] = []
        files = _stage(root, stage, include_keys=include_keys, withheld_keys=withheld_keys)
        schema_version = _world_schema_version(stage / "world.db")
        if not files:
            raise BackupError(f"no data files to back up at {root}")
        manifest = _authenticate_for_write({
            "schema": SCHEMA,
            "client_id": _client_id(),
            "created_at": time.time(),
            "world_schema_version": schema_version,
            "files": files,
            "withheld_key_files": withheld_keys,
            **({"recovery": recovery_metadata} if recovery_metadata is not None else {}),
        }, key)
        encoded_manifest = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
        if len(encoded_manifest.encode("utf-8")) > MAX_MANIFEST_BYTES:
            raise BackupError("The complete backup manifest exceeds its supported size.")
        manifest_path = temp_root / MANIFEST
        file_lock.atomic_create_text(
            manifest_path,
            encoded_manifest,
        )

        staged_archive = _unique_private_empty(destination.parent, destination.name)
        try:
            fd, _ = _open_private_writer(staged_archive)
            with os.fdopen(fd, "wb") as output:
                with tarfile.open(fileobj=output, mode="w:gz") as archive:
                    archive.add(manifest_path, arcname=MANIFEST, recursive=False)
                    archive.add(stage, arcname="data")
                output.flush()
                os.fsync(output.fileno())

            # Validate the generated artifact through the same bounded/authenticated
            # reader used by restore before it becomes the visible DR artifact.
            with _verified_archive(staged_archive) as stream:
                _read_manifest_stream(stream, allow_unsigned=allow_unsigned)
            if os.path.lexists(destination):
                raise BackupError(f"backup destination was planted: {destination}")
            os.replace(staged_archive, destination)
            _fsync_directory(destination.parent)
            file_lock.ensure_private_file(destination)
        except BaseException:
            staged_archive.unlink(missing_ok=True)
            raise

    log.info(
        "backup written: %s (%d files, client=%s, authenticated=%s)",
        destination,
        len(files),
        client_identifier,
        key is not None,
    )
    return public_destination


def _extract_payload_stream(
    stream: BinaryIO,
    stage: Path,
    *,
    expected: dict[str, tuple[str, int | None]],
) -> None:
    budget = _ArchiveBudget()
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=stream, mode="r|gz", tarinfo=_BoundedTarInfo) as archive:
            for member in archive:
                rel = budget.observe(member)
                if rel is None or member.isdir():
                    continue
                record = expected.get(rel)
                if record is None:
                    raise BackupError(
                        f"backup payload {rel} is not in the manifest "
                        "(backup is corrupt or tampered)"
                    )
                if rel in seen:
                    raise BackupError(f"duplicate backup payload path: {rel}")
                seen.add(rel)
                expected_digest, expected_size = record
                if expected_size is not None and member.size != expected_size:
                    raise BackupError(
                        f"backup integrity check failed for {rel} (size mismatch)"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BackupError(f"backup payload is unreadable: {rel}")
                destination = stage / Path(*PurePosixPath(rel).parts)
                digest, size = _stream_to_new_private(
                    extracted,
                    destination,
                    expected_size=member.size,
                )
                if digest != expected_digest or (
                    expected_size is not None and size != expected_size
                ):
                    raise BackupError(
                        f"backup integrity check failed for {rel} "
                        "(SHA-256 mismatch — backup is corrupt or truncated)"
                    )
    except BackupError:
        raise
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise BackupError(f"unreadable backup payload: {exc}") from exc
    missing = set(expected) - seen
    if missing:
        sample = sorted(missing)[0]
        raise BackupError(f"manifest payload is missing from archive: {sample}")


def _live_path(root: Path, rel: str) -> Path:
    safe = _safe_relative_path(rel, label="restore path")
    current = root
    for component in safe.parts[:-1]:
        current = current / component
        if os.path.lexists(current):
            info = current.lstat()
            if _is_alias(current, info) or not stat.S_ISDIR(info.st_mode):
                raise BackupError(f"unsafe restore parent: {current}")
        file_lock.ensure_private_directory(current)
    return root / Path(*safe.parts)


def _validate_optional_live_file(path: Path) -> bool:
    if not os.path.lexists(path):
        return False
    info = path.lstat()
    if _is_alias(path, info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise BackupError(f"refusing planted or aliased live path: {path}")
    file_lock.ensure_private_file(path)
    return True


def _journal_document(body: dict[str, Any], key: bytes | None) -> dict[str, Any]:
    return _authenticate_for_write(body, key)


def _write_journal(tx: Path, body: dict[str, Any], key: bytes | None) -> None:
    document = _journal_document(body, key)
    file_lock.atomic_write_text(
        tx / _JOURNAL,
        json.dumps(document, sort_keys=True, separators=(",", ":")),
    )


def _load_journal(
    tx: Path, *, allow_unsigned: bool,
) -> tuple[dict[str, Any], bytes | None]:
    path = tx / _JOURNAL
    try:
        file_lock.ensure_private_file(path)
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise BackupError("restore journal is oversized")
        document = _parse_manifest(file_lock.atomic_read_bytes(path))
    except OSError as exc:
        raise BackupError(f"restore journal could not be read: {tx}") from exc
    key = _verify_authentication(
        document,
        allow_unsigned=allow_unsigned,
        label="restore journal",
    )
    return document, key


def _remove_private_tree(path: Path) -> None:
    if not os.path.lexists(path):
        return
    info = path.lstat()
    if _is_alias(path, info):
        path.unlink()
        return
    if stat.S_ISDIR(info.st_mode):
        with os.scandir(path) as entries:
            children = [Path(entry.path) for entry in entries]
        for child in children:
            _remove_private_tree(child)
        path.rmdir()
    else:
        path.unlink()


def _capture_original(
    root: Path,
    tx: Path,
    rel: str,
) -> dict[str, Any]:
    destination = _live_path(root, rel)
    existed = _validate_optional_live_file(destination)
    if existed:
        original = tx / "originals" / Path(*PurePosixPath(rel).parts)
        _copy_verified_file(destination, original)
    sidecars: list[str] = []
    if _is_sqlite_file(destination):
        for suffix in _DB_SIDECARS:
            sidecar = Path(str(destination) + suffix)
            if _validate_optional_live_file(sidecar):
                side_rel = rel + suffix
                original_sidecar = tx / "originals" / Path(*PurePosixPath(side_rel).parts)
                _copy_verified_file(sidecar, original_sidecar)
                sidecars.append(suffix)
    return {"rel": rel, "existed": existed, "sidecars": sidecars}


def _publish_staged_file(source: Path, destination: Path) -> None:
    file_lock.ensure_private_directory(destination.parent)
    if os.path.lexists(destination):
        _validate_optional_live_file(destination)
    # A restored draft already has a long hashed filename. Repeating that name
    # in the temporary path exceeds Windows path limits on ordinary profiles.
    # The random suffix supplies uniqueness without copying the payload name.
    temporary = _unique_private_empty(destination.parent, "restore")
    try:
        _copy_verified_file(
            source,
            temporary,
            destination_precreated=True,
        )
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
        file_lock.ensure_private_file(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _validate_journal_entries(document: dict[str, Any]) -> list[dict[str, Any]]:
    if document.get("journal_schema") != 1:
        raise BackupError("restore journal schema is unsupported")
    entries = document.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ARCHIVE_MEMBERS:
        raise BackupError("restore journal entries are malformed")
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise BackupError("restore journal entry is malformed")
        rel = _safe_relative_path(entry.get("rel"), label="journal path").as_posix()
        if rel in seen or not isinstance(entry.get("existed"), bool):
            raise BackupError("restore journal contains duplicate/malformed state")
        seen.add(rel)
        sidecars = entry.get("sidecars")
        if (
            not isinstance(sidecars, list)
            or len(sidecars) > len(_DB_SIDECARS)
            or any(s not in _DB_SIDECARS for s in sidecars)
            or len(set(sidecars)) != len(sidecars)
        ):
            raise BackupError("restore journal sidecar state is malformed")
        validated.append({"rel": rel, "existed": entry["existed"], "sidecars": sidecars})
    return validated


def _tenant_lifecycle_barrier(relative: str) -> bool:
    from .recovery_authorities import TENANT_LIFECYCLE_AUTHORITY_POLICIES, authority_policy

    return authority_policy(relative, is_sqlite=False) in TENANT_LIFECYCLE_AUTHORITY_POLICIES.values()


def _lifecycle_conflict() -> BackupError:
    return BackupError(
        "Restore would erase or rewrite tenant lifecycle history. Current namespace "
        "reservations and workspace deletions must be retained; reconcile this "
        "snapshot in a separate isolated installation. Force cannot bypass this guard."
    )


def _guard_lifecycle_replacement(root: Path, stage: Path, targets: set[str]) -> None:
    """Refuse an older barrier set before publishing any ordinary payload."""
    for relative in targets:
        if not _tenant_lifecycle_barrier(relative):
            continue
        destination = _live_path(root, relative)
        if not os.path.lexists(destination):
            continue
        _validate_optional_live_file(destination)
        source = stage.joinpath(*PurePosixPath(relative).parts)
        if not source.is_file() or _sha256(destination) != _sha256(source):
            raise _lifecycle_conflict()


def _publish_lifecycle_barrier(source: Path, destination: Path) -> None:
    """Publish once; a concurrently created claim or retirement always wins."""
    if not os.path.lexists(destination):
        # Unlike ordinary restore files, identity history must never use replace.
        # Publish fully written private bytes atomically without replacing a
        # concurrent claimant; readers cannot observe a partial JSON record.
        try:
            with os.fdopen(file_lock.open_private_read(source), "rb") as reader:
                file_lock.atomic_create_bytes_chunks(
                    destination, iter(lambda: reader.read(_COPY_CHUNK), b""),
                )
            return
        except FileExistsError:
            pass
    _validate_optional_live_file(destination)
    if not source.is_file() or _sha256(destination) != _sha256(source):
        raise _lifecycle_conflict()


def _rollback(root: Path, tx: Path, document: dict[str, Any]) -> None:
    entries = _validate_journal_entries(document)
    for entry in reversed(entries):
        rel = entry["rel"]
        destination = _live_path(root, rel)
        if _tenant_lifecycle_barrier(rel):
            # This applies to journals written by older versions as well. A
            # failed restore cannot release a name or undo a later retirement.
            if os.path.lexists(destination):
                _validate_optional_live_file(destination)
            elif entry["existed"]:
                _publish_lifecycle_barrier(tx / "originals" / Path(*PurePosixPath(rel).parts), destination)
            continue
        if _is_sqlite_file(destination) or entry["sidecars"]:
            for suffix in _DB_SIDECARS:
                sidecar = Path(str(destination) + suffix)
                if os.path.lexists(sidecar):
                    _validate_optional_live_file(sidecar)
                    sidecar.unlink()
        if entry["existed"]:
            original = tx / "originals" / Path(*PurePosixPath(rel).parts)
            _validate_optional_live_file(original)
            _publish_staged_file(original, destination)
        elif os.path.lexists(destination):
            _validate_optional_live_file(destination)
            destination.unlink()
        for suffix in entry["sidecars"]:
            side_rel = rel + suffix
            original_sidecar = tx / "originals" / Path(*PurePosixPath(side_rel).parts)
            _validate_optional_live_file(original_sidecar)
            _publish_staged_file(
                original_sidecar,
                Path(str(destination) + suffix),
            )


@contextmanager
def _federation_state_held_closed():
    # The federation state file is one of the files a restore replaces. Its cached connections
    # must be closed, and kept from reopening, until the replacement is done: an open file
    # cannot be replaced on Windows, and a replaced file would leave a cached connection writing
    # to the old one.
    from .federation import hold_state_file_closed

    with hold_state_file_closed():
        yield


def _recover_transactions(root: Path, *, allow_unsigned: bool) -> None:
    tx_root = _transaction_root(root)
    if not os.path.lexists(tx_root):
        return
    file_lock.ensure_private_directory(tx_root)
    transactions = sorted(tx_root.iterdir())
    if len(transactions) > 32:
        raise BackupError("too many incomplete restore transactions")
    for tx in transactions:
        info = tx.lstat()
        if _is_alias(tx, info) or not stat.S_ISDIR(info.st_mode):
            raise BackupError(f"invalid restore transaction path: {tx}")
        file_lock.ensure_private_directory(tx)
        journal = tx / _JOURNAL
        if not journal.exists():
            _remove_private_tree(tx)
            continue
        document, _ = _load_journal(tx, allow_unsigned=allow_unsigned)
        state = document.get("state")
        if state in {"prepared", "applying"}:
            with _federation_state_held_closed():
                _rollback(root, tx, document)
        elif state not in {"preparing", "committed"}:
            raise BackupError(f"unknown restore journal state: {state!r}")
        _remove_private_tree(tx)
    if tx_root.exists() and not any(tx_root.iterdir()):
        tx_root.rmdir()


def _archive_includes_keys(expected: dict) -> frozenset:
    """The key folders (see :func:`_key_material_scope`) this archive carries raw
    keys for; empty (falsy) when it carries none.

    Per folder, not all-or-nothing: an archive made before workspace keys were
    withheld holds them but no key of the data root. Reading that as "this
    archive includes keys" would make the live root keys it lacks replacement
    targets and delete them."""
    scopes = (_key_material_scope(Path(*PurePosixPath(name).parts)) for name in expected)
    return frozenset(scope for scope in scopes if scope is not None)


def _replacement_targets(root: Path, expected: dict) -> set[str]:
    # A keys-excluded archive must never turn live key material into a
    # replacement target: replace_existing unlinks targets absent from the
    # archive, which would destroy the at-rest key the restored data needs.
    include_keys = _archive_includes_keys(expected)
    targets = set(expected)
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if _excluded_from_snapshot(relative, include_keys=include_keys):
            continue
        info = path.lstat()
        if _is_alias(path, info):
            raise BackupError("live recovery target contains an alias")
        if not stat.S_ISDIR(info.st_mode):
            targets.add(_safe_relative_path(relative.as_posix(), label="live recovery path").as_posix())
        if len(targets) > MAX_ARCHIVE_MEMBERS:
            raise BackupError("live recovery target exceeds file limit")
    return targets


def _verify_restored(root: Path, expected: dict) -> None:
    for rel, (digest, size) in expected.items():
        restored = _live_path(root, rel)
        if _sha256(restored) != digest or (size is not None and restored.stat().st_size != size):
            raise BackupError("post-restore file verification failed")
        if _is_sqlite_file(restored):
            uri = ("file:" + quote(str(_filesystem_path(restored)), safe=":")
                   if os.name == "nt" else restored.resolve().as_uri())
            connection = sqlite3.connect(uri + "?mode=ro", uri=True)
            try:
                if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise BackupError("post-restore database integrity check failed")
            except sqlite3.DatabaseError as exc:
                raise BackupError("post-restore database integrity check failed") from exc
            finally:
                connection.close()


def _flow_index_restore_markers(targets: set[str]) -> set[str]:
    """Journal derived-cache invalidation alongside restored canonical rows."""
    markers = set()
    for relative in targets:
        path = PurePosixPath(relative)
        if path.parent.name == "runs" and path.parent.parent.name == "flows":
            markers.add((path.parent.parent / ".run-index-rebuild").as_posix())
        elif path.name == "run-index.sqlite3" and path.parent.name == "flows":
            markers.add((path.parent / ".run-index-rebuild").as_posix())
        if path.parent.name == "vendor_management" and path.suffix == ".json":
            markers.add((path.parent / ".record-lookup-rebuild").as_posix())
        elif path.parent.name == ".record-lookup" and path.parent.parent.name == "vendor_management":
            markers.add((path.parent.parent / ".record-lookup-rebuild").as_posix())
    return markers


def _apply_transaction(
    root: Path,
    stage: Path,
    expected: dict[str, tuple[str, int | None]],
    *,
    key: bytes | None,
    replace_existing: bool = False,
) -> None:
    with _federation_state_held_closed():
        _apply_journaled_transaction(
            root,
            stage,
            expected,
            key=key,
            replace_existing=replace_existing,
        )


def _apply_journaled_transaction(
    root: Path,
    stage: Path,
    expected: dict[str, tuple[str, int | None]],
    *,
    key: bytes | None,
    replace_existing: bool = False,
) -> None:
    tx_root = file_lock.ensure_private_directory(_transaction_root(root))
    tx = file_lock.ensure_private_directory(tx_root / secrets.token_hex(16))
    body: dict[str, Any] = {
        "journal_schema": 1,
        "state": "preparing",
        "entries": [],
    }
    _write_journal(tx, body, key)
    committed = False
    try:
        targets = _replacement_targets(root, expected) if replace_existing else set(expected)
        _guard_lifecycle_replacement(root, stage, targets)
        flow_markers = _flow_index_restore_markers(targets)
        targets.update(flow_markers)
        entries = [_capture_original(root, tx, rel) for rel in sorted(targets)]
        body["entries"] = entries
        body["state"] = "prepared"
        _write_journal(tx, body, key)
        body["state"] = "applying"
        _write_journal(tx, body, key)
        for entry in entries:
            rel = entry["rel"]
            source = stage / Path(*PurePosixPath(rel).parts)
            destination = _live_path(root, rel)
            if _tenant_lifecycle_barrier(rel):
                # Recheck at publication: a new claim/deletion can appear after
                # the initial inventory. No replace or unlink is allowed here.
                _publish_lifecycle_barrier(source, destination)
                continue
            if _is_sqlite_file(destination) or _is_sqlite_file(source):
                for suffix in _DB_SIDECARS:
                    sidecar = Path(str(destination) + suffix)
                    if os.path.lexists(sidecar):
                        _validate_optional_live_file(sidecar)
                        sidecar.unlink()
            if rel in expected:
                _publish_staged_file(source, destination)
            elif rel in flow_markers:
                # This is part of the same rollback journal, not a post-commit
                # hook that could turn successful restore into ambiguous failure.
                file_lock.atomic_write_bytes(destination, _DERIVED_REBUILD_MARKER_BYTES)
            elif destination.exists():
                destination.unlink()
        if replace_existing:
            # Validate before committing the journal so any failed check restores
            # the originals, including files created after the chosen snapshot.
            _verify_restored(root, expected)
        committed_body = dict(body)
        committed_body["state"] = "committed"
        _write_journal(tx, committed_body, key)
        body = committed_body
        committed = True
    except BaseException as original:
        try:
            if body.get("state") == "preparing":
                _remove_private_tree(tx)
            elif not committed and body.get("state") in {"prepared", "applying", "committed"}:
                _rollback(root, tx, body)
                _remove_private_tree(tx)
        except BaseException as rollback_error:
            raise BackupError(
                f"restore failed and rollback is incomplete; journal retained at {tx}: "
                f"{rollback_error}"
            ) from original
        raise
    else:
        _remove_private_tree(tx)
    finally:
        if tx_root.exists() and not any(tx_root.iterdir()):
            tx_root.rmdir()


def _refuse_if_world_appears_live(root: Path) -> None:
    """Best-effort guard: refuse to publish over world.db while something
    still appears to hold it open.

    Restore's own transaction lock (``_RESTORE_LOCK_TARGET``) only serializes
    concurrent restores against each other. WorldModel takes its own
    cross_process_lock only briefly, during __init__ -- by the time a process
    has been running for a while, that lock is free even though the process
    still keeps a live sqlite3 connection open. Publishing over world.db with
    ``os.replace`` while such a connection is open silently orphans every
    subsequent write on the old, now-unlinked inode until that process
    restarts (a split-brain, not a crash). A WAL/SHM sidecar touched in the
    last few seconds is the practically-observable proxy for "something has
    this database open right now"; it is not proof, so this refusal is
    always bypassable with ``force=True``.
    """
    now = time.time()
    for suffix in ("-wal", "-shm"):
        sidecar = root / f"world.db{suffix}"
        try:
            age = now - sidecar.stat().st_mtime
        except OSError:
            continue
        if age < _LIVE_WORLD_RECENCY_SECONDS:
            raise BackupError(
                f"world.db{suffix} was touched {age:.1f}s ago -- a process "
                "still appears to have the world database open. Restoring "
                "now would silently lose writes made through that live "
                "connection until it restarts. Stop `maverick serve` / the "
                "dashboard first, or pass force=True to override."
            )


def restore_backup(
    tarball: str | Path,
    *,
    force: bool = False,
    allow_unsigned: bool = False,
    replace_existing: bool = False,
    _stage_transform: Callable[[Path], set[str] | None] | None = None,
    _record_decryptor: Callable[[bytes, str | None, Path], bytes] | None = None,
) -> Path:
    """Authenticate, verify and transactionally restore one backup.

    ``force`` does not bypass signature verification. It does bypass the
    best-effort live-world guard (see ``_refuse_if_world_appears_live``):
    stop ``maverick serve`` / the dashboard before restoring a backup that
    carries world.db, or pass ``force=True`` if you are certain nothing has
    it open. ``allow_unsigned`` is the explicit legacy path and provides
    integrity/bounds checks, not provenance.
    Supported local application references are validated before publication;
    force never bypasses that check or database schema compatibility. Governed
    stores require full replacement.
    """
    with _verified_archive(tarball) as stream:
        manifest, key = _read_manifest_stream(stream, allow_unsigned=allow_unsigned)
        backup_client = manifest.get("client_id")
        live_client = _client_id()
        if not force and backup_client != live_client:
            raise BackupError(
                f"backup is for client {backup_client!r} but this deployment is "
                f"{live_client!r}; refusing (pass force=True to override)"
            )
        _check_supported_world_schema(manifest.get("world_schema_version"))
        expected = _manifest_files(
            manifest,
            allow_legacy_unsigned=allow_unsigned and key is None,
        )
        root = _client_root()
        with _temporary_directory(prefix="mvk-restore-") as temporary:
            stage = file_lock.ensure_private_directory(Path(temporary) / "data")
            stream.seek(0)
            _extract_payload_stream(stream, stage, expected=expected)
            _validate_restore_schemas(stage, manifest)
            _validate_application_stage(stage, decryptor=_record_decryptor)
            if _stage_transform is not None:
                # Recovery bootstrap may conservatively retire queued work before
                # any restored byte becomes live.  The signed archive is always
                # authenticated and application-validated first.  Re-stage the
                # transformed tree to re-apply the same path/type/size bounds,
                # require the exact file set, and bind the transaction's
                # post-write verification to the resulting bytes.
                allowed_removed = _stage_transform(stage) or set()
                if (not isinstance(allowed_removed, set)
                        or any(not isinstance(name, str) for name in allowed_removed)):
                    raise BackupError("restore reconciliation returned invalid path authority")
                reconciled = file_lock.ensure_private_directory(
                    Path(temporary) / "reconciled"
                )
                transformed = _stage(stage, reconciled, include_keys=True)
                removed = set(expected) - set(transformed)
                added = set(transformed) - set(expected)
                if added or removed != allowed_removed:
                    raise BackupError(
                        "restore reconciliation changed the authenticated file set"
                    )
                expected = {
                    name: (metadata["sha256"], metadata["size"])
                    for name, metadata in transformed.items()
                }
                stage = reconciled
                _validate_restore_schemas(stage, manifest)
                _validate_application_stage(stage, decryptor=_record_decryptor)
            file_lock.ensure_private_directory(root)
            if not force and "world.db" in expected:
                _refuse_if_world_appears_live(root)
            lock_target = root / _RESTORE_LOCK_TARGET
            with file_lock.cross_process_lock(lock_target, strict=True):
                if not replace_existing:
                    from .restore_validation import RestoreValidationError, guard_additive_restore

                    try:
                        guard_additive_restore(root, stage, whole_home=_RECOVERY_WHOLE_HOME.get())
                    except RestoreValidationError as exc:
                        raise BackupError(str(exc)) from exc
                _recover_transactions(root, allow_unsigned=allow_unsigned)
                _apply_transaction(
                    root,
                    stage,
                    expected,
                    key=key,
                    replace_existing=replace_existing,
                )
    log.info(
        "restore complete into %s (from client=%s, %d files verified, authenticated=%s)",
        root,
        backup_client,
        len(expected),
        key is not None,
    )
    return root


def verify_backup(tarball: str | Path) -> dict[str, Any]:
    """Authenticate and verify every payload byte without touching live state."""
    with _verified_archive(tarball) as stream:
        manifest, _ = _read_manifest_stream(stream, allow_unsigned=False)
        expected = _manifest_files(manifest, allow_legacy_unsigned=False)
        with _temporary_directory(prefix="mvk-backup-verify-") as temporary:
            stage = file_lock.ensure_private_directory(Path(temporary) / "data")
            stream.seek(0)
            _extract_payload_stream(stream, stage, expected=expected)
    return manifest


def _validate_application_stage(
    stage: Path,
    *,
    decryptor: Callable[[bytes, str | None, Path], bytes] | None = None,
) -> dict[str, Any]:
    from .restore_validation import RestoreValidationError, validate_staged_restore

    try:
        return validate_staged_restore(
            stage,
            tenant=_client_id(),
            whole_home=_RECOVERY_WHOLE_HOME.get(),
            decryptor=decryptor,
        )
    except RestoreValidationError as exc:
        raise BackupError(str(exc)) from exc


def validate_backup_application(
    tarball: str | Path,
    *,
    _record_decryptor: Callable[[bytes, str | None, Path], bytes] | None = None,
) -> dict[str, Any]:
    """Authenticate a full-replacement candidate and check supported references.

    This stages bytes privately and never opens or changes live application
    stores. Success describes only the explicitly returned validation scope.
    """
    with _verified_archive(tarball) as stream:
        manifest, _ = _read_manifest_stream(stream, allow_unsigned=False)
        if manifest.get("client_id") != _client_id():
            raise BackupError("Application validation requires the matching recovery workspace.")
        _check_supported_world_schema(manifest.get("world_schema_version"))
        expected = _manifest_files(manifest, allow_legacy_unsigned=False)
        with _temporary_directory(prefix="mvk-application-verify-") as temporary:
            stage = file_lock.ensure_private_directory(Path(temporary) / "data")
            stream.seek(0)
            _extract_payload_stream(stream, stage, expected=expected)
            _validate_restore_schemas(stage, manifest)
            return _validate_application_stage(stage, decryptor=_record_decryptor)


def _accounting_file(relative: str, path: Path) -> bool:
    from .recovery_authorities import protected_authority

    return protected_authority(relative, is_sqlite=_is_sqlite_file(path))


def compare_backup(tarball: str | Path) -> dict[str, Any]:
    """Compare authenticated payload metadata with consistent live file copies.

    This is evidence, never a restore authorization or a semantic/schema merge.
    No file payloads are returned. Live copies are individually consistent;
    callers must separately establish quiescence for any subsequent mutation.
    """
    with _verified_archive(tarball) as stream:
        manifest, _ = _read_manifest_stream(stream, allow_unsigned=False)
        if manifest.get("client_id") != _client_id():
            raise BackupError("The accounting snapshot belongs to a different recovery scope.")
        expected = _manifest_files(manifest, allow_legacy_unsigned=False)
        with _temporary_directory(prefix="lightwork-accounting-check-") as temporary:
            selected = file_lock.ensure_private_directory(temporary / "selected")
            current = file_lock.ensure_private_directory(temporary / "current")
            stream.seek(0)
            _extract_payload_stream(stream, selected, expected=expected)
            live = _stage(_client_root(), current, include_keys=_archive_includes_keys(expected))
            protected = {
                name for name in expected
                if _accounting_file(name, selected / Path(*PurePosixPath(name).parts))
            } | {
                name for name in live
                if _accounting_file(name, current / Path(*PurePosixPath(name).parts))
            }
            archived = {name: {"sha256": digest, "size": size}
                        for name, (digest, size) in expected.items()}
            changes = [{"path": name, "change": "added" if name not in archived else "deleted" if name not in live else "changed",
                        "protected": name in protected, "snapshot": archived.get(name), "current": live.get(name)}
                       for name in sorted(set(archived) | set(live)) if archived.get(name) != live.get(name)]
            return {"items": changes, "total_changes": len(changes),
                    "protected_changes": sum(row["protected"] for row in changes),
                    "protected_file_count": len(protected), "snapshot_file_count": len(archived), "live_file_count": len(live),
                    "snapshot_state_sha256": hashlib.sha256(json.dumps(archived, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                    "live_state_sha256": hashlib.sha256(json.dumps(live, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def assert_accounting_unchanged(tarball: str | Path) -> None:
    """Refuse recovery that could rewind spending or protected action history.

    Call under the recovery scope after stopping normal work, before replacing
    live files or application binaries. Comparison evidence cannot waive this.
    """
    comparison = compare_backup(tarball)
    changed = [row["path"] for row in comparison["items"] if row["protected"]]
    if changed:
        raise BackupError(
            "Automatic restore is unavailable because spending, reservations, budget controls, "
            "database state or external-action history differs from the selected snapshot. "
            "Administrator accounting and external-action reconciliation is required before "
            "restoring; newer records must not be erased or passed to an older incompatible "
            "reader, and completed or unconfirmed actions must not be repeated. "
            "Retain the current accounting and action history, and "
            "export the snapshot for administrator review. Protected files: " + ", ".join(changed[:5])
        )


__all__ = [
    "BackupError",
    "assert_accounting_unchanged",
    "compare_backup",
    "create_backup",
    "restore_backup",
    "read_manifest",
    "data_backups_dir",
    "withheld_key_files",
]
