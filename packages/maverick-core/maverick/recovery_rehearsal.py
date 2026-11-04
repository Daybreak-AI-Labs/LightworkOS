"""Bounded, offline decryption rehearsal in a disposable child process.

Only the parent-created job protocol is accepted. This is not a key importer
for a live deployment, a storage migration, or permission to restore over it.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import logging
import math
import os
import re
import sqlite3
import stat
import sys
import time
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from urllib.parse import quote

from . import backup, file_lock

MAX_CUSTODY_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_VALUE_BYTES = 16 * 1024 * 1024
MAX_SCANNED_BYTES = 128 * 1024 * 1024
MAX_FILES = 10_000
MAX_RECORDS = 100_000
MAX_SCAN_SECONDS = 35
_FORMATS = ("raw-v1", "raw-v2", "raw-tenant-local", "world-text-v1", "world-text-v2",
            "world-text-tenant-local", "unrecognized-encryption", "scan-limit")
_LIMITS = [
    "Only raw MVKAR1/MVKAR2 envelopes and MVKTEN1 with a locally derived tenant key are tested.",
    "SQLite coverage is limited to fixed encryption-migration TEXT columns in the workspace world.db; other columns and databases are unexamined.",
    "Plaintext, embedded envelopes, arbitrary file formats and application-level draft or workflow validity are not verified.",
    "Local tenant keys require the uploaded primary key and the archived wrapped DEK; environment keys, external KMS and remote stores are not tested.",
    "At most 10,000 files, 100,000 values, 16 MiB per value and 128 MiB of values are scanned for at most 35 seconds.",
    "A scan-limit count records a limit event, not the unknown number of remaining encrypted records; unexamined file counts cover visited files only.",
    "Successful decryption does not establish complete key custody, restore compatibility, active-key rotation order, or disaster recovery readiness.",
]


def _result(identity: str = "unavailable") -> dict:
    return {"schema": 1, "application_identity": identity,
            "checks": [{"format": label, "detected": 0, "verified": 0, "failed": 0, "unsupported": 0}
                       for label in _FORMATS],
            "files_scanned": 0, "sqlite_columns_scanned": 0, "unexamined_files": 0,
            "outcome": "no_encrypted_records", "fresh_process": True,
            "key_source": "uploaded-custody-copy", "coverage_complete": False,
            "live_workspace_changed": False, "external_stores_tested": False,
            "limits": list(_LIMITS)}


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _json(raw: bytes):
    return json.loads(raw, object_pairs_hook=_no_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite value")))


def _private_file(path: Path, maximum: int) -> None:
    file_lock.require_private_directory(path.parent)
    info = path.lstat()
    if (file_lock._unsafe_lock_alias(path, info) or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1 or not 0 <= info.st_size <= maximum
            or not file_lock.private_path_is_restricted(path)):
        raise ValueError("invalid private input")


def _read(path: Path, maximum: int) -> bytes:
    _private_file(path, maximum)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or opened.st_nlink != 1:
            raise ValueError("changed private input")
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("oversize input")
    return value


def _same_path(value: str | None, path: Path) -> bool:
    return bool(value) and os.path.samefile(backup._filesystem_path(value), path)


def _validate_job(job: Path) -> tuple[dict, bytes, Path]:
    from . import workspace_recovery

    request = _json(_read(job / "request.json", 4096))
    fields = {"schema", "tenant", "archive_sha256", "custody_sha256", "application_identity", "application_version"}
    if (not isinstance(request, dict) or set(request) != fields or type(request["schema"]) is not int
            or request["schema"] != 1 or not isinstance(request["tenant"], str) or not request["tenant"]
            or len(request["tenant"]) > 200
            or any(not isinstance(request[name], str) or not re.fullmatch(r"[0-9a-f]{64}", request[name])
                   for name in ("archive_sha256", "custody_sha256"))):
        raise ValueError("invalid request")
    home = job / "home"
    file_lock.require_private_directory(home)
    allowed = {"MAVERICK_HOME", "MAVERICK_CONFIG", "MAVERICK_CLIENT_ID"}
    if (any(name.upper().startswith(("MAVERICK_", "LIGHTWORK_")) and name not in allowed for name in os.environ)
            or not _same_path(os.environ.get("MAVERICK_HOME"), home)
            or not _same_path(os.environ.get("MAVERICK_CONFIG"), home / "config.toml")
            or os.environ.get("MAVERICK_CLIENT_ID") != request["tenant"]):
        raise ValueError("unexpected environment")
    if {item.name for item in home.iterdir()} != {"config.toml"}:
        raise ValueError("target is not fresh")
    config = _read(home / "config.toml", 4096).decode("utf-8")
    if any(line.strip() and not line.lstrip().startswith("#") for line in config.splitlines()):
        raise ValueError("target configuration is not empty")
    if (request["application_identity"] != workspace_recovery.application_identity()
            or request["application_version"] != workspace_recovery.version()):
        raise ValueError("different application")
    raw_key = _read(job / "recovery.key", 128).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", raw_key):
        raise ValueError("invalid recovery key")
    for filename, field, maximum in (("snapshot.tgz", "archive_sha256", MAX_ARCHIVE_BYTES),
                                     ("custody.zip", "custody_sha256", MAX_CUSTODY_BYTES)):
        path = job / filename
        _private_file(path, maximum)
        if backup._sha256(path) != request[field]:
            raise ValueError("input digest changed")
    return request, bytes.fromhex(raw_key), home


def _escrow(payload: bytes, tenant: str) -> dict[str, bytes]:
    """Authenticate the entire bounded ZIP before installing any key."""
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or not 3 <= len(names) <= 514:
            raise ValueError("invalid escrow members")
        for entry in entries:
            limit = 256 * 1024 if entry.filename == "manifest.json" else 4096
            mode = entry.external_attr >> 16
            if (entry.is_dir() or entry.flag_bits & 1 or entry.file_size > limit
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                raise ValueError("invalid escrow member")
        manifest = _json(archive.read("manifest.json"))
        if not isinstance(manifest, dict):
            raise ValueError("invalid escrow manifest")
        backup._verify_authentication(manifest, allow_unsigned=False, label="key escrow")
        if (set(manifest) != {"schema", "kind", "workspace", "shared_key_material", "created_at", "files", "authentication"}
                or type(manifest["schema"]) is not int or manifest["schema"] != 1
                or manifest["kind"] != "local-encryption-key-escrow" or manifest["workspace"] != tenant
                or manifest["shared_key_material"] is not True
                or type(manifest["created_at"]) not in (int, float) or not math.isfinite(manifest["created_at"])
                or not isinstance(manifest["files"], dict) or not 1 <= len(manifest["files"]) <= 512):
            raise ValueError("invalid escrow binding")
        files = manifest["files"]
        if set(names) != {"manifest.json", "README.txt"} | {"keys/" + name for name in files}:
            raise ValueError("unexpected escrow member")
        keys = {}
        for name, expected in files.items():
            if (name != "at_rest.key" and not re.fullmatch(r"[0-9a-f]{16}\.key", name)):
                raise ValueError("invalid key name")
            if (not isinstance(expected, dict) or set(expected) != {"size", "sha256"}
                    or type(expected["size"]) is not int or not 1 <= expected["size"] <= 4096
                    or not isinstance(expected["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", expected["sha256"])):
                raise ValueError("invalid key metadata")
            raw = archive.read("keys/" + name)
            if len(raw) != expected["size"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                raise ValueError("key digest mismatch")
            text = raw.decode("ascii").strip()
            if not re.fullmatch(r"[0-9a-fA-F]{64}", text):
                raise ValueError("invalid encryption key")
            key = bytes.fromhex(text)
            if name != "at_rest.key" and hashlib.sha256(key).hexdigest()[:16] != name[:-4]:
                raise ValueError("key identity mismatch")
            keys[name] = key
        return keys


def _deny_external(event, _args):
    if (event.startswith("socket.") or event.startswith("subprocess.")
            or event in {"os.system", "os.posix_spawn", "os.posix_spawnp", "os.fork", "os.forkpty", "os.startfile", "os.startfile/2"}
            or event.startswith("os.exec") or event.startswith("os.spawn")):
        raise PermissionError("external operations are disabled")


class _ScanLimit(Exception):
    pass


class _Scanner:
    def __init__(self, root: Path, tenant: str, keys: dict[str, bytes], result: dict):
        self.root, self.tenant, self.keys, self.result = root, tenant, keys, result
        self.rows = {row["format"]: row for row in result["checks"]}
        self.deadline = time.monotonic() + MAX_SCAN_SECONDS
        self.values = self.bytes = 0
        self.tenant_key = None

    def check_limit(self):
        if time.monotonic() >= self.deadline or self.values >= MAX_RECORDS or self.bytes >= MAX_SCANNED_BYTES:
            raise _ScanLimit

    def count(self, label, outcome):
        self.rows[label]["detected"] += 1
        self.rows[label][outcome] += 1

    def open(self, value: bytes) -> bytes:
        from . import crypto_at_rest as crypto
        from .tenant import kms

        # Preflight is essential: ordinary readers create a primary key when
        # custody is missing. Never let a rehearsal fabricate replacement keys.
        if value.startswith(crypto._MAGIC):
            if "at_rest.key" not in self.keys:
                raise ValueError("missing primary")
        elif value.startswith(crypto._MAGIC_V2):
            key_id = value[len(crypto._MAGIC_V2):len(crypto._MAGIC_V2) + 8]
            primary = self.keys.get("at_rest.key")
            if (len(key_id) != 8 or (key_id.hex() + ".key" not in self.keys
                    and (primary is None or crypto._key_fingerprint(primary) != key_id))):
                raise ValueError("missing rotation key")
        elif value.startswith(crypto._TENANT_MAGIC):
            if self.tenant_key is None:
                primary = self.keys.get("at_rest.key")
                if primary is None:
                    raise ValueError("missing local tenant custody")
                wrapped = _read(self.root / "keys" / "dek.wrapped", 4096)
                local = kms.LocalKMS(hashlib.sha256(b"maverick-kms-kek/v1\x00" + primary).digest())
                self.tenant_key = local.unwrap(wrapped, context=kms._tenant_context(self.tenant, b"dek-wrap"))
                if len(self.tenant_key) != 32:
                    raise ValueError("invalid tenant key")
            return kms._gcm_open(self.tenant_key, crypto._TENANT_MAGIC, value,
                                 kms._tenant_context(self.tenant, b"tenant-data"))
        else:
            raise ValueError("unsupported envelope")
        return crypto.unseal(value)

    def envelope(self, value: bytes, *, text=False) -> bool:
        from . import crypto_at_rest as crypto

        prefix = "world-text-" if text else "raw-"
        label = next((prefix + name for magic, name in ((crypto._MAGIC, "v1"), (crypto._MAGIC_V2, "v2"),
                                                       (crypto._TENANT_MAGIC, "tenant-local")) if value.startswith(magic)), None)
        if label is None:
            if value.startswith((b"MVKAR", b"MVKTEN")) or text:
                self.count("unrecognized-encryption", "unsupported")
                return True
            return False
        self.check_limit()
        self.values += 1
        self.bytes += len(value)
        if len(value) > MAX_VALUE_BYTES or self.bytes > MAX_SCANNED_BYTES:
            self.count(label, "unsupported")
            return True
        try:
            plaintext = self.open(value)
            if text:
                plaintext.decode("utf-8")
            del plaintext
        except Exception:
            self.count(label, "failed")
        else:
            self.count(label, "verified")
        return True

    def world(self, path: Path):
        from .encryption_migrate import _SEALED_COLUMNS

        uri = "file:" + quote(str(path), safe=":") if os.name == "nt" else path.as_uri()
        database = sqlite3.connect(uri + "?mode=ro", uri=True)
        try:
            database.execute("PRAGMA trusted_schema=OFF")
            database.execute("PRAGMA query_only=ON")
            database.enable_load_extension(False)
            database.set_progress_handler(lambda: int(time.monotonic() >= self.deadline), 1000)
            for table, column in _SEALED_COLUMNS:
                self.check_limit()
                row = database.execute("SELECT type, sql FROM sqlite_master WHERE name=?", (table,)).fetchone()
                if not row:
                    continue
                if row[0] != "table" or not row[1] or "CREATE VIRTUAL" in row[1].upper():
                    self.count("unrecognized-encryption", "unsupported")
                    continue
                columns = database.execute(f'PRAGMA table_xinfo("{table}")').fetchall()
                if not any(info[1] == column and info[6] == 0 for info in columns):
                    continue
                self.result["sqlite_columns_scanned"] += 1
                # Filter inside SQLite so a large unmarked plaintext cell is
                # never materialized in Python merely to reject its prefix.
                cursor = database.execute(
                    f'SELECT substr("{column}",1,?), length("{column}") FROM "{table}" '
                    f'WHERE typeof("{column}")=\'text\' AND substr("{column}",1,7)=\'MVKAR1:\'',
                    (MAX_VALUE_BYTES + 1,),
                )
                for value, length in cursor:
                    self.check_limit()
                    self.values += 1
                    if not isinstance(value, str) or not value.startswith("MVKAR1:"):
                        continue
                    if length > MAX_VALUE_BYTES:
                        self.count("unrecognized-encryption", "unsupported")
                        continue
                    self.bytes += len(value)
                    self.check_limit()
                    try:
                        raw = base64.b64decode(value[7:], validate=True)
                    except (ValueError, binascii.Error):
                        self.count("unrecognized-encryption", "unsupported")
                    else:
                        self.envelope(raw, text=True)
        finally:
            database.close()

    def scan(self):
        try:
            for path in self.root.rglob("*"):
                self.check_limit()
                if path.is_dir():
                    continue
                if self.result["files_scanned"] >= MAX_FILES:
                    raise _ScanLimit
                self.result["files_scanned"] += 1
                # SQLite's restore verification can create WAL/SHM sidecars
                # with platform-default ACLs. These are owned disposable
                # outputs, not uploaded custody: secure them before scanning.
                # The shared helper still refuses aliases and hard links.
                file_lock.ensure_private_file(path)
                _private_file(path, MAX_EXPANDED_BYTES)
                with path.open("rb") as stream:
                    prefix = stream.read(32)
                if prefix.startswith(b"SQLite format 3\x00"):
                    self.result["unexamined_files"] += 1
                    if path == self.root / "world.db":
                        try:
                            self.world(path)
                        except sqlite3.Error:
                            self.count("unrecognized-encryption", "unsupported")
                    continue
                if prefix.startswith((b"MVKAR", b"MVKTEN")):
                    if path.stat().st_size > MAX_VALUE_BYTES:
                        self.count("unrecognized-encryption", "unsupported")
                    else:
                        self.envelope(_read(path, MAX_VALUE_BYTES))
                else:
                    self.result["unexamined_files"] += 1
        except _ScanLimit:
            self.count("scan-limit", "unsupported")
        totals = {key: sum(row[key] for row in self.rows.values()) for key in ("failed", "unsupported", "verified")}
        self.result["outcome"] = ("failed" if totals["failed"] else "incomplete" if totals["unsupported"]
                                  else "verified_supported_formats" if totals["verified"] else "no_encrypted_records")
        return self.result


def _run(job: Path) -> dict:
    request, key, _home = _validate_job(job)
    from . import crypto_at_rest as crypto
    from . import workspace_recovery
    from .paths import current_tenant_id_strict, data_dir

    if current_tenant_id_strict() != request["tenant"]:
        raise ValueError("different tenant")
    root = file_lock.ensure_private_directory(backup._filesystem_path(data_dir()))
    sys.addaudithook(_deny_external)
    with backup.recovery_scope(root, request["tenant"], key, max_expanded_bytes=MAX_EXPANDED_BYTES):
        keys = _escrow(_read(job / "custody.zip", MAX_CUSTODY_BYTES), request["tenant"])
        backup.restore_backup(
            job / "snapshot.tgz",
            replace_existing=True,
            _record_decryptor=workspace_recovery._record_decryptor_from_keys(
                keys, request["tenant"]
            ),
        )
    custody = job / "encryption-keys"
    custody.mkdir(mode=0o700)
    file_lock.ensure_private_directory(custody)
    for name, material in keys.items():
        path = custody / name if name == "at_rest.key" else custody / "at_rest.d" / name
        file_lock.ensure_private_directory(path.parent)
        file_lock.atomic_create_text(path, material.hex())
    crypto._KEY_PATH = custody / "at_rest.key"
    return _Scanner(root, request["tenant"], keys, _result(request["application_identity"])).scan()


def main(argv=None) -> int:
    """Silent child entry point; malformed jobs never return reusable evidence."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    job = None
    logging.disable(logging.CRITICAL)
    with open(os.devnull, "w", encoding="utf-8") as sink, redirect_stdout(sink), redirect_stderr(sink):
        try:
            if len(arguments) != 1:
                raise ValueError("invalid worker arguments")
            candidate = backup._filesystem_path(Path(arguments[0]).absolute())
            file_lock.require_private_directory(candidate)
            job = candidate
            result = _run(job)
            file_lock.atomic_create_text(job / "result.json", json.dumps(result, allow_nan=False))
            return 0
        except BaseException:
            if job is not None:
                try:
                    result = _result()
                    result["outcome"] = "failed"
                    result["checks"][0].update(detected=1, failed=1)
                    result["limits"].append("The temporary test could not validate its inputs or complete safely. No decryption evidence was issued.")
                    file_lock.atomic_create_text(job / "result.json", json.dumps(result))
                except BaseException:
                    pass
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
