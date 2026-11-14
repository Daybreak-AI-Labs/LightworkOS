"""Write-once (WORM) export of closed audit day-files.

The signed hash-chain and cross-file anchors detect changes against their
retained commitments. Each closed day-file can also be copied to a configured
target. Its protection depends on that target, independently retained evidence,
and who controls the signing keys. Two targets (``[audit.worm] provider``):

  - ``s3`` -- S3 (or S3-compatible) **Object-Lock** in ``COMPLIANCE`` (or
    ``GOVERNANCE``) mode with a retain-until date: the object cannot be
    overwritten or deleted under the configured service's enforcement.
    GOVERNANCE permits authorized bypass. Lightwork checks the returned exact
    version, bytes and reported retention, without establishing independent
    provider enforcement or future availability. The bucket needs Object-Lock + versioning
    enabled (a one-time operator setup), so every re-push is a new locked version.
  - ``local`` -- copy into a WORM directory as an immutable, owner-read-only
    mode-``0400`` file (protected DACL + DOS read-only bit on Windows),
    versioned file. Best-effort on-box (an owner can still chmod it back), but
    evidence via the signed manifest hash. It is not independent immutable custody.

Only **closed** day-files (date < today, UTC) are shipped -- today's file is
still being appended. Idempotent: a manifest (``worm/manifest.ndjson``) records
each pushed file's sha256 + retain-until + locator, so re-runs skip unchanged
files. A closed file legitimately changes after ``audit seal`` / GDPR erase; on
the next push that new version is shipped (and, on S3, the prior version stays
independently locked). ``verify`` flags any closed file whose current bytes were
never shipped.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import os
import re
import stat
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..file_lock import (
    atomic_create_bytes,
    cross_process_lock,
    ensure_private_file,
    prepare_private_directory,
    private_path_is_restricted,
)
from ..paths import data_dir
from . import signing as _signing
from .signing import AuditSigner, day_files

log = logging.getLogger(__name__)

_DEFAULT_RETENTION_DAYS = 2555  # ~7 years -- a common regulatory floor (SOX/HIPAA)
_MANIFEST_NAME = "manifest.ndjson"
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_DAY_NAME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.ndjson$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_SIG_RE = re.compile(r"^[0-9a-f]{128}$")
_LOCAL_OBJECT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}\.ndjson\.\d{10,16}-[0-9a-f]{32}$"
)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_READ_CHUNK_BYTES = 1024 * 1024


class WormUnavailable(RuntimeError):
    """WORM export was requested but no usable target is configured/available."""


class WormAttemptHeld(WormUnavailable):
    """One file's earlier copy has an unknown result and awaits review.

    Held per file: other days are still exported.
    """


def _valid_day_name(name: object) -> bool:
    if not isinstance(name, str) or not _DAY_NAME_RE.fullmatch(name):
        return False
    try:
        parsed = _dt.date.fromisoformat(name.removesuffix(".ndjson"))
    except ValueError:
        return False
    return parsed.isoformat() == name.removesuffix(".ndjson")


def _path_is_alias(path: Path, info: os.stat_result) -> bool:
    """Reject symlinks and Windows reparse points without resolving them."""
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _read_custodied_file(
    path: Path,
    *,
    mode: int,
    max_bytes: int | None = None,
) -> bytes:
    """Read one private single-link regular file from an identity-bound handle.

    The bytes returned by this helper are the bytes callers authenticate.  It
    never resolves a final-component alias and refuses a pathname/descriptor
    identity mismatch, closing the common lstat/open and verify/read races.
    """
    path = Path(path)
    prepare_private_directory(path.parent)
    ensure_private_file(path, mode)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags)
    try:
        visible = path.lstat()
        opened = os.fstat(fd)
        if (
            _path_is_alias(path, visible)
            or _path_is_alias(path, opened)
            or not stat.S_ISREG(visible.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or visible.st_nlink != 1
            or opened.st_nlink != 1
            or (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise PermissionError("evidence path is not a stable private regular file")
        if max_bytes is not None and opened.st_size > max_bytes:
            raise WormUnavailable("evidence file exceeds its verification limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, _READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise WormUnavailable("evidence file exceeds its verification limit")
            chunks.append(chunk)
        after = path.lstat()
        if (
            _path_is_alias(path, after)
            or not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or not private_path_is_restricted(path, mode)
        ):
            raise PermissionError("evidence path identity or custody changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _segment_text_from_bytes(raw: bytes) -> str:
    """Decode the exact audit-segment bytes being authenticated."""
    from ..crypto_at_rest import is_sealed, unseal

    if is_sealed(raw):
        raw = unseal(raw)
    return raw.decode("utf-8")


def _trusted_public_key(key_id: str, cache: dict[str, bytes]) -> bytes:
    """Load the public key named by a signed row from the shared trust roots."""
    cached = cache.get(key_id)
    if cached is not None:
        return cached
    if not _KEY_ID_RE.fullmatch(key_id):
        raise WormUnavailable("signed evidence contains an invalid key id")
    try:
        public = _signing.trusted_audit_public_keys().get(key_id)
        if public is None:
            raise WormUnavailable("signed evidence public key is not trusted")
        raw = bytes.fromhex(public)
    except (OSError, PermissionError, ValueError) as exc:
        raise WormUnavailable("signed evidence public key is unavailable") from exc
    if len(raw) != 32 or hashlib.sha256(raw).hexdigest()[:16] != key_id:
        raise WormUnavailable("signed evidence public key does not match its key id")
    cache[key_id] = raw
    return raw


def _verified_chain_records(raw: bytes) -> list[dict[str, Any]]:
    """Verify and return records from the exact bytes supplied by the caller."""
    try:
        text = _segment_text_from_bytes(raw)
    except Exception as exc:  # failure-policy: fail_closed
        raise WormUnavailable("signed evidence cannot be decoded") from exc
    records: list[dict[str, Any]] = []
    previous = ""
    key_cache: dict[str, bytes] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise WormUnavailable("signed evidence contains malformed JSON") from exc
        if not isinstance(record, dict):
            raise WormUnavailable("signed evidence record must be an object")
        row_hash = record.get("hash")
        signature = record.get("sig")
        row_previous = record.get("prev_hash")
        key_id = record.get("key_id")
        if (
            not isinstance(row_hash, str)
            or not _SHA256_RE.fullmatch(row_hash)
            or not isinstance(signature, str)
            or not _SIG_RE.fullmatch(signature)
            or not isinstance(row_previous, str)
            or (row_previous != "" and not _SHA256_RE.fullmatch(row_previous))
            or not isinstance(key_id, str)
            or not _KEY_ID_RE.fullmatch(key_id)
            or row_previous != previous
        ):
            raise WormUnavailable("signed evidence chain structure is invalid")
        payload = {k: v for k, v in record.items() if k not in {"hash", "sig"}}
        expected_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        public_key = _trusted_public_key(key_id, key_cache)
        if expected_hash != row_hash or not _signing.verify_ed25519(
            public_key.hex(), signature, bytes.fromhex(row_hash)
        ):
            raise WormUnavailable("signed evidence hash or signature is invalid")
        records.append(record)
        previous = row_hash
    return records


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _worm_cfg() -> dict[str, Any]:
    try:
        from ..config import load_config
        cfg = ((load_config() or {}).get("audit") or {}).get("worm") or {}
    # failure-policy: best_effort
    except Exception:  # pragma: no cover -- config never blocks a run
        return {}
    return cfg if isinstance(cfg, dict) else {}


def worm_enabled() -> bool:
    """Opt-in (default off): true when ``MAVERICK_AUDIT_WORM`` is truthy or
    ``[audit.worm] provider`` names a target."""
    env = os.environ.get("MAVERICK_AUDIT_WORM")
    if env is not None and env.strip() != "":
        return _truthy(env)
    return bool(_worm_cfg().get("provider"))


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_utc(value: object) -> _dt.datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(_dt.timezone.utc)


# --- sinks ------------------------------------------------------------------

class LocalWormSink:
    """Copy each closed day-file into a WORM directory as an immutable, versioned,
    owner-read-only file. Best-effort on-box immutability; the manifest hash is the
    tamper-evidence. Each ``put`` writes a NEW file, never overwriting a prior
    version."""

    def __init__(self, directory: str | Path) -> None:
        # Local WORM may contain plaintext when at-rest sealing is explicitly
        # disabled. Create a missing dedicated directory privately, but never
        # seize the ACL of an existing caller-owned directory.
        self._dir = prepare_private_directory(Path(directory)).resolve(strict=True)

    def put(self, name: str, data: bytes, *, retain_until: _dt.datetime) -> dict:
        if not _valid_day_name(name):
            raise ValueError("WORM object name must be YYYY-MM-DD.ndjson")
        # Version by push time (+ a uuid so a same-millisecond re-push after
        # seal/erase keeps the prior copy instead of clobbering it).
        dest = self._dir / (
            f"{name}.{int(time.time() * 1000)}-{uuid.uuid4().hex}"
        )
        atomic_create_bytes(dest, data, mode=0o400)
        try:
            os.chmod(dest, 0o400)
        except OSError:  # pragma: no cover -- exotic filesystem
            pass
        ensure_private_file(dest, 0o400)
        return {"target": "local", "path": str(dest.resolve(strict=True)),
                "retain_until": retain_until.isoformat()}

    def verify(self, locator: dict, expected_sha256: str) -> bool:
        if locator.get("target") != "local":
            return False
        try:
            path = Path(str(locator.get("path") or ""))
            if not path.is_absolute() or not _LOCAL_OBJECT_RE.fullmatch(path.name):
                return False
            root = self._dir.resolve(strict=True)
            # LocalWormSink creates direct children only. Resolve the parent,
            # never the signed final component, so a replacement symlink cannot
            # be laundered into its referent before the alias check.
            if path.parent.resolve(strict=True) != root:
                return False
            data = _read_custodied_file(path, mode=0o400)
            if path.lstat().st_mode & 0o222:
                return False
            return _sha256(data) == expected_sha256
        except (OSError, PermissionError, WormUnavailable):
            return False


class S3WormSink:
    """Ship each closed day-file to S3 (or compatible) with Object-Lock so it
    cannot be altered/deleted until ``retain_until``. Lazy boto3."""

    def __init__(self, *, bucket: str, prefix: str = "", mode: str = "COMPLIANCE",
                 region: str | None = None, endpoint_url: str | None = None) -> None:
        if not bucket:
            raise WormUnavailable("[audit.worm] provider = s3 requires a bucket")
        self._bucket = bucket
        self._prefix = prefix or ""
        self._mode = (mode or "COMPLIANCE").upper()
        if self._mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise WormUnavailable(
                f"[audit.worm] mode must be COMPLIANCE or GOVERNANCE, got {mode!r}")
        self._region = region
        self._endpoint = endpoint_url
        self._client = None

    def _s3(self):
        if self._client is None:
            try:
                import boto3  # type: ignore
            except ImportError as e:  # pragma: no cover -- needs the extra
                raise WormUnavailable(
                    "S3 WORM export needs boto3 (pip install boto3)") from e
            self._client = boto3.client(
                "s3", region_name=self._region, endpoint_url=self._endpoint)
        return self._client

    def put(self, name: str, data: bytes, *, retain_until: _dt.datetime) -> dict:
        if not _valid_day_name(name):
            raise ValueError("WORM object name must be YYYY-MM-DD.ndjson")
        key = f"{self._prefix}{name}"
        resp = self._s3().put_object(
            Bucket=self._bucket, Key=key, Body=data,
            ObjectLockMode=self._mode,
            ObjectLockRetainUntilDate=retain_until,
            ChecksumAlgorithm="SHA256",
        )
        locator = {
            "target": "s3",
            "bucket": self._bucket,
            "key": key,
            "mode": self._mode,
            "retain_until": retain_until.isoformat(),
            # Bind the signed evidence to the configured S3 authority without
            # persisting a possibly credential-bearing endpoint URL.
            "authority_id": self._authority_id(),
        }
        version_id = resp.get("VersionId") if isinstance(resp, dict) else None
        # Object-Lock is version-scoped. Without a concrete VersionId the
        # manifest cannot later prove which immutable object was retained.
        if not isinstance(version_id, str) or not version_id.strip():
            raise WormUnavailable(
                "S3 WORM upload returned no VersionId; verify bucket versioning "
                "and Object Lock are enabled"
            )
        locator["version_id"] = version_id
        return locator

    def _authority_id(self) -> str:
        authority = {
            "bucket": self._bucket,
            "endpoint_url": self._endpoint or "",
            "region": self._region or "",
        }
        return _sha256(json.dumps(authority, sort_keys=True).encode("utf-8"))

    def verify(self, locator: dict, expected_sha256: str) -> bool:
        if locator.get("target") != "s3":
            return False
        bucket = str(locator.get("bucket") or "")
        key = str(locator.get("key") or "")
        version_id = locator.get("version_id")
        if (
            bucket != self._bucket
            or not _valid_day_name(key.removeprefix(self._prefix))
            or key != f"{self._prefix}{key.removeprefix(self._prefix)}"
            or not isinstance(version_id, str)
            or not version_id.strip()
            or str(locator.get("mode") or "").upper() != self._mode
            or locator.get("authority_id") != self._authority_id()
        ):
            return False
        kwargs = {"Bucket": bucket, "Key": key, "VersionId": version_id}
        try:
            obj = self._s3().get_object(**kwargs)
            body = obj.get("Body")
            data = body.read() if hasattr(body, "read") else body
            if not isinstance(data, bytes):
                return False
            if obj.get("VersionId") != version_id:
                return False
            retention = self._s3().get_object_retention(**kwargs).get("Retention")
            if not isinstance(retention, dict):
                return False
            if str(retention.get("Mode") or "").upper() != self._mode:
                return False
            expected_until = _parse_utc(locator.get("retain_until"))
            actual_until = retention.get("RetainUntilDate")
            if isinstance(actual_until, str):
                actual_until = _parse_utc(actual_until)
            if (
                expected_until is None
                or not isinstance(actual_until, _dt.datetime)
                or actual_until.tzinfo is None
                or actual_until.astimezone(_dt.timezone.utc) < expected_until
            ):
                return False
            return _sha256(data) == expected_sha256
        # failure-policy: fail_closed
        except Exception:
            return False


def build_sink(cfg: dict[str, Any] | None = None):
    """Construct the configured WORM sink, or raise :class:`WormUnavailable`."""
    cfg = cfg if cfg is not None else _worm_cfg()
    provider = str(cfg.get("provider") or "").strip().lower()
    if provider == "local":
        directory = cfg.get("dir") or str(data_dir("audit") / "worm" / "store")
        return LocalWormSink(directory)
    if provider in ("s3", "aws"):
        return S3WormSink(
            bucket=str(cfg.get("bucket") or ""),
            prefix=str(cfg.get("prefix") or ""),
            mode=str(cfg.get("mode") or "COMPLIANCE"),
            region=cfg.get("region"),
            endpoint_url=cfg.get("endpoint_url"),
        )
    raise WormUnavailable(
        "no WORM target configured; set [audit.worm] provider = s3 (or local)")


# --- manifest ---------------------------------------------------------------

def _manifest_path(audit_dir: Path) -> Path:
    return audit_dir / "worm" / _MANIFEST_NAME


def _valid_locator_schema(locator: object, *, name: str, retain_until: str) -> bool:
    if not isinstance(locator, dict) or locator.get("retain_until") != retain_until:
        return False
    target = locator.get("target")
    if not isinstance(target, str) or not target or len(target) > 32:
        return False
    if target == "local":
        return (
            set(locator) == {"target", "path", "retain_until"}
            and isinstance(locator.get("path"), str)
            and Path(locator["path"]).is_absolute()
            and Path(locator["path"]).name.startswith(f"{name}.")
        )
    if target == "s3":
        return (
            set(locator) == {
                "target", "bucket", "key", "mode", "retain_until",
                "authority_id", "version_id",
            }
            and isinstance(locator.get("bucket"), str)
            and bool(locator["bucket"])
            and isinstance(locator.get("key"), str)
            and locator["key"].endswith(name)
            and str(locator.get("mode") or "").upper() in {"COMPLIANCE", "GOVERNANCE"}
            and isinstance(locator.get("version_id"), str)
            and bool(locator["version_id"].strip())
            and isinstance(locator.get("authority_id"), str)
            and bool(_SHA256_RE.fullmatch(locator["authority_id"]))
        )
    # Explicitly injected sinks are supported by the Python API. Their opaque
    # signed locator still needs the common target/retention contract; the sink
    # itself must verify it before a manifest entry is trusted.
    return True


def _valid_manifest_record(rec: object) -> bool:
    if not isinstance(rec, dict):
        return False
    if rec.get("kind") == "worm_push_attempt":
        return _valid_attempt_record(rec)
    if rec.get("kind") == "worm_push_resolution":
        return _valid_resolution_record(rec)
    required = {
        "kind", "schema", "name", "sha256", "pushed_at", "retain_until",
        "locator", "prev_hash", "key_id", "hash", "sig",
    }
    if rec.get("schema") == 2:
        required.add("request_id")
        if not _SHA256_RE.fullmatch(str(rec.get("request_id") or "")):
            return False
    name = rec.get("name")
    pushed_at = _parse_utc(rec.get("pushed_at"))
    retain_until = _parse_utc(rec.get("retain_until"))
    return bool(
        set(rec) == required
        and rec.get("kind") == "worm_manifest"
        and rec.get("schema") in (1, 2)
        and _valid_day_name(name)
        and isinstance(rec.get("sha256"), str)
        and _SHA256_RE.fullmatch(rec["sha256"])
        and pushed_at is not None
        and retain_until is not None
        and retain_until > pushed_at
        and _valid_locator_schema(
            rec.get("locator"), name=name, retain_until=rec["retain_until"]
        )
    )


def _valid_attempt_record(rec):
    required = {"kind", "schema", "name", "sha256", "request_id", "attempted_at", "retain_until", "destination",
                "prev_hash", "key_id", "hash", "sig"}
    attempted, until = _parse_utc(rec.get("attempted_at")), _parse_utc(rec.get("retain_until"))
    return (set(rec) == required and rec.get("schema") == 1 and _valid_day_name(rec.get("name"))
            and bool(_SHA256_RE.fullmatch(str(rec.get("sha256") or "")))
            and bool(_SHA256_RE.fullmatch(str(rec.get("request_id") or "")))
            and isinstance(rec.get("destination"), dict) and bool(rec["destination"])
            and all(isinstance(key, str) and isinstance(value, str) for key, value in rec["destination"].items())
            and attempted is not None and until is not None and until > attempted)


def _valid_resolution_record(rec):
    required = {"kind", "schema", "name", "sha256", "request_id", "authorized_at", "retain_until", "destination",
                "prior_request_ids", "authorization_id", "actor", "context", "prev_hash", "key_id", "hash", "sig"}
    prior = rec.get("prior_request_ids")
    return (set(rec) == required and rec.get("schema") == 1 and _valid_day_name(rec.get("name"))
            and bool(_SHA256_RE.fullmatch(str(rec.get("sha256") or "")))
            and bool(_SHA256_RE.fullmatch(str(rec.get("request_id") or "")))
            and isinstance(prior, list) and bool(prior) and len(prior) <= 10_000
            and all(isinstance(value, str) and _SHA256_RE.fullmatch(value) for value in prior) and len(set(prior)) == len(prior)
            and bool(re.fullmatch(r"AAR-[a-f0-9]{32}", str(rec.get("authorization_id") or "")))
            and isinstance(rec.get("actor"), str) and bool(rec["actor"])
            and bool(_SHA256_RE.fullmatch(str(rec.get("context") or "")))
            and isinstance(rec.get("destination"), dict) and bool(rec["destination"])
            and all(isinstance(key, str) and isinstance(value, str) for key, value in rec["destination"].items())
            and _parse_utc(rec.get("authorized_at")) is not None and _parse_utc(rec.get("retain_until")) is not None)


def _load_manifest_records(audit_dir: Path) -> list[dict]:
    """Latest verified manifest entry per day-file name.

    The manifest is itself a signed append-only audit chain.  Skipping a bad
    line would let an attacker delete or redirect immutable-object evidence,
    so any unreadable, unsigned, malformed, or oversized manifest fails the
    whole operation closed.
    """
    path = _manifest_path(audit_dir)
    if not path.exists():
        return []
    try:
        raw = _read_custodied_file(
            path, mode=0o600, max_bytes=_MAX_MANIFEST_BYTES
        )
        records = _verified_chain_records(raw)
        for rec in records:
            if not _valid_manifest_record(rec):
                raise WormUnavailable("WORM manifest record schema is invalid")
    except WormUnavailable as exc:
        raise WormUnavailable(
            "WORM manifest signature/hash chain or schema is invalid"
        ) from exc
    except (OSError, UnicodeError, PermissionError) as exc:
        raise WormUnavailable("WORM manifest is unreadable or not private") from exc
    return records


def _load_manifest(audit_dir: Path) -> dict[str, dict]:
    return {rec["name"]: rec for rec in _load_manifest_records(audit_dir) if rec["kind"] == "worm_manifest"}


def request_receipts(audit_dir: Path, request_id: str) -> dict[str, dict]:
    """Read signed completions of one original push, including superseded ones.

    This is historical evidence of that request, not a current destination
    availability check. It never uploads or promotes an unknown PUT to success.
    """
    if not _SHA256_RE.fullmatch(request_id):
        raise WormUnavailable("invalid WORM request reference")
    return {rec["name"]: rec for rec in _load_manifest_records(audit_dir)
            if rec["kind"] == "worm_manifest" and rec.get("request_id") == request_id}


def unknown_attempts(audit_dir: Path) -> list[dict]:
    records = _load_manifest_records(audit_dir)
    completed = {(rec.get("request_id"), rec["name"], rec["sha256"]) for rec in records if rec["kind"] == "worm_manifest"}
    released = _released_versions(records)
    return [rec for rec in records if rec["kind"] == "worm_push_attempt"
            and (rec["request_id"], rec["name"], rec["sha256"]) not in completed | released]


def _released_versions(records):
    return {(prior, rec["name"], rec["sha256"]) for rec in records if rec["kind"] == "worm_push_resolution"
            for prior in rec["prior_request_ids"]}


def released_versions(audit_dir: Path) -> set[tuple[str, str, str]]:
    """Released holds only: no claim that any original copy completed."""
    return _released_versions(_load_manifest_records(audit_dir))


def _attempt_destination(sink):
    if isinstance(sink, LocalWormSink):
        return {"target": "local", "directory": str(sink._dir)}
    if isinstance(sink, S3WormSink):
        return {"target": "s3", "bucket": sink._bucket, "prefix": sink._prefix,
                "mode": sink._mode, "authority_id": sink._authority_id()}
    return {"target": "operator-supplied", "identity": type(sink).__qualname__}


def _attempt_fence(audit_dir, name, sha256, request_id, retain_until, sink, reconcile):
    records = _load_manifest_records(audit_dir)
    completed = {(rec.get("request_id"), rec["name"], rec["sha256"]) for rec in records if rec["kind"] == "worm_manifest"}
    released = _released_versions(records)
    pending = []
    for rec in records:
        if rec["kind"] != "worm_push_attempt" or rec["name"] != name or rec["sha256"] != sha256:
            continue
        identity = (rec["request_id"], name, sha256)
        if identity not in completed | released:
            pending.append(rec["request_id"])
        if identity in completed and rec["request_id"] == request_id:
            return False  # Original signed completion survives source/destination changes.
    if reconcile:
        authorization = reconcile(name, sha256, sorted(set(pending)))
        if authorization:
            _release_attempts(audit_dir, name, sha256, request_id, retain_until, sink, pending, authorization)
            pending = []
    if pending:
        raise WormAttemptHeld("an earlier WORM copy has an unknown result; no copy was repeated. Review its original proof and the current source and destination before a separate intentional attempt")
    payload = {"kind": "worm_push_attempt", "schema": 1, "name": name, "sha256": sha256,
               "request_id": request_id, "attempted_at": _utcnow().isoformat(), "retain_until": retain_until.isoformat(),
               "destination": _attempt_destination(sink)}
    _write_manifest_payload(audit_dir, payload)
    return True


def _release_attempts(audit_dir, name, sha256, request_id, retain_until, sink, pending, authorization):
    # The caller's live authority callback identifies an actual independently
    # confirmed governed review. Read it here rather than accepting a fabricated
    # actor/receipt or an operator-supplied acknowledgment as provider proof.
    from ..governed_records import GovernedRecordStore
    row = GovernedRecordStore("audit-action-reviews", "AAR", "audit_action_review").get(authorization)
    if (not row or row.get("state") != "reserved" or not row.get("reconcile") or not row.get("acknowledge_uncertain")
            or row.get("source") != str(audit_dir.absolute()) or row.get("request_id") != request_id
            or row.get("action") != "copy" or not _matches_review_destination(row.get("destination", {}), sink)
            or not any(item["name"] == name and item["sha256"] == sha256 and item["selected"] for item in row.get("rows", []))
            or row.get("retain_until") != retain_until.isoformat() or row.get("_audit_pending")):
        raise WormUnavailable("separate human copy review could not be verified")
    item = next((value for value in row.get("reconciliation", []) if value["name"] == name and value["sha256"] == sha256), None)
    if not item or not set(pending).issubset(item["prior_request_ids"]):
        raise WormUnavailable("uncertain copy holds changed after independent review")
    payload = {"kind": "worm_push_resolution", "schema": 1, "name": name, "sha256": sha256,
        "request_id": request_id, "authorized_at": _utcnow().isoformat(), "retain_until": retain_until.isoformat(),
        "destination": _attempt_destination(sink), "prior_request_ids": item["prior_request_ids"],
        "authorization_id": authorization, "actor": row["actor"], "context": row["context"]}
    # Validate the generated shape before appending its signed authority record.
    if not _valid_resolution_record({**payload, "prev_hash": "", "key_id": "", "hash": "", "sig": ""}):
        raise WormUnavailable("separate copy authorization is invalid")
    _write_manifest_payload(audit_dir, payload)


def _matches_review_destination(destination, sink):
    if isinstance(sink, LocalWormSink):
        return destination.get("provider") == "local" and Path(destination.get("directory", "")).resolve() == sink._dir
    if isinstance(sink, S3WormSink):
        if destination.get("provider") != "s3":
            return False
        expected = S3WormSink(bucket=destination.get("bucket", ""), prefix=destination.get("prefix", ""),
            mode=destination.get("mode", ""), region=destination.get("region"), endpoint_url=destination.get("endpoint_url"))
        return _attempt_destination(expected) == _attempt_destination(sink)
    return False



def _locator_verified(
    rec: dict, expected_sha256: str, sink: Any | None = None, audit_dir: Path | None = None
) -> bool:
    locator = rec.get("locator")
    if (
        not isinstance(locator, dict)
        or rec.get("sha256") != expected_sha256
        or not _valid_day_name(rec.get("name"))
        or rec.get("retain_until") != locator.get("retain_until")
        or _parse_utc(rec.get("retain_until")) is None
    ):
        return False
    target = locator.get("target")

    # An explicitly injected sink is a test/operator dependency, but its own
    # authority still has to agree with the signed locator.
    if isinstance(sink, S3WormSink):
        if (
            target != "s3"
            or locator.get("bucket") != sink._bucket
            or locator.get("key") != f"{sink._prefix}{rec['name']}"
            or str(locator.get("mode") or "").upper() != sink._mode
        ):
            return False
    elif isinstance(sink, LocalWormSink) and target != "local":
        return False
    if sink is not None and hasattr(sink, "verify"):
        try:
            return bool(sink.verify(locator, expected_sha256))
        # failure-policy: fail_closed
        except Exception:
            return False
    if target == "local":
        cfg = _worm_cfg()
        directory = None
        provider = str(cfg.get("provider") or "").strip().lower()
        if provider == "local":
            directory = cfg.get("dir")
        elif provider:
            return False
        if directory is None and audit_dir is not None:
            directory = audit_dir / "worm" / "store"
        if directory is None:
            return False
        return LocalWormSink(directory).verify(locator, expected_sha256)
    if target == "s3":
        try:
            cfg = dict(_worm_cfg())
            if str(cfg.get("provider") or "").strip().lower() not in {"s3", "aws"}:
                return False
            expected_bucket = str(cfg.get("bucket") or "")
            expected_prefix = str(cfg.get("prefix") or "")
            expected_mode = str(cfg.get("mode") or "COMPLIANCE").upper()
            if (
                locator.get("bucket") != expected_bucket
                or locator.get("key") != f"{expected_prefix}{rec['name']}"
                or str(locator.get("mode") or "").upper() != expected_mode
            ):
                return False
            sink = build_sink(cfg)
            return bool(sink.verify(locator, expected_sha256))
        # failure-policy: fail_closed
        except Exception:
            return False
    return False

def _append_manifest(audit_dir: Path, rec: dict) -> None:
    payload = {
        "kind": "worm_manifest",
        "schema": 1,
        "name": rec.get("name"),
        "sha256": rec.get("sha256"),
        "pushed_at": rec.get("pushed_at"),
        "retain_until": rec.get("retain_until"),
        "locator": rec.get("locator"),
    }
    if rec.get("request_id") is not None:
        if not _SHA256_RE.fullmatch(str(rec["request_id"])):
            raise WormUnavailable("invalid WORM request reference")
        payload.update(schema=2, request_id=rec["request_id"])
    if (
        not _valid_day_name(payload["name"])
        or not isinstance(payload["sha256"], str)
        or not _SHA256_RE.fullmatch(payload["sha256"])
        or _parse_utc(payload["pushed_at"]) is None
        or _parse_utc(payload["retain_until"]) is None
        or not _valid_locator_schema(
            payload["locator"],
            name=payload["name"],
            retain_until=payload["retain_until"],
        )
        or _parse_utc(payload["retain_until"]) <= _parse_utc(payload["pushed_at"])
    ):
        raise WormUnavailable("refusing to append an invalid WORM manifest record")
    _write_manifest_payload(audit_dir, payload)


def _write_manifest_payload(audit_dir, payload):
    path = _manifest_path(audit_dir)
    try:
        signer = AuditSigner(path)
        if signer.write(payload) is not True:
            raise WormUnavailable("could not durably append the WORM manifest")
    except WormUnavailable:
        raise
    except Exception as exc:  # failure-policy: fail_closed
        raise WormUnavailable("could not sign the WORM manifest") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _at_rest_sealing_active() -> bool:
    """Return whether WORM requires sealed input.

    An explicit at-rest opt-out is the *only* state that returns ``False``.
    Once encryption is configured/enabled, an unusable key, missing crypto
    backend, or failed probe is an availability failure -- never permission to
    put plaintext under immutable retention.  The caller turns that failure
    into a fixed, non-secret-bearing refusal for every closed day-file.
    """
    try:
        from ..crypto_at_rest import at_rest_enabled, seal
    except Exception as exc:  # failure-policy: fail_closed
        raise WormUnavailable(
            "cannot determine the at-rest sealing posture"
        ) from exc

    try:
        enabled = at_rest_enabled()
    except Exception as exc:  # failure-policy: fail_closed
        raise WormUnavailable(
            "cannot determine whether at-rest sealing is enabled"
        ) from exc
    if not enabled:
        return False

    try:
        seal(b"")  # cheap probe: exercises crypto + configured key resolution
    except Exception as exc:  # failure-policy: fail_closed
        raise WormUnavailable(
            "at-rest sealing is enabled but unavailable"
        ) from exc
    return True


def _verified_source_snapshot(audit_dir: Path, closed: list[Path]) -> dict[str, bytes]:
    """Return exact signed day bytes after exact signed-anchor verification.

    Authentication and consumption operate on the same identity-bound byte
    snapshots. The latest signed anchor must cover every closed file, and every
    signed anchor must still match its single-link day file.
    """
    if not closed:
        return {}
    try:
        prepare_private_directory(audit_dir)
        anchor_path = audit_dir / _signing.ANCHOR_FILENAME
        anchor_raw = _read_custodied_file(anchor_path, mode=0o600)
        anchor_records = _verified_chain_records(anchor_raw)
        latest: dict[str, dict[str, Any]] = {}
        anchor_keys = {
            "kind", "day", "tip_hash", "row_count", "ts",
            "prev_hash", "key_id", "hash", "sig",
        }
        purge_keys = {
            "kind", "days", "cutoff_day", "ts",
            "prev_hash", "key_id", "hash", "sig",
        }
        purged: set[str] = set()
        for record in anchor_records:
            # The ledger carries policy-retention records alongside anchors.
            # Validate them under their own strict schema rather than rejecting
            # the whole ledger -- an exact-key-set test against the anchor shape
            # made a legitimate `retention enforce` permanently break WORM push.
            if record.get("kind") == "retention_purge":
                if set(record) != purge_keys or not isinstance(record["days"], list):
                    raise WormUnavailable("signed anchor ledger schema is invalid")
                for entry in record["days"]:
                    if not isinstance(entry, dict) or not isinstance(
                        entry.get("day"), str
                    ):
                        raise WormUnavailable("signed anchor ledger schema is invalid")
                    purged.add(entry["day"])
                continue
            day = record.get("day")
            row_count = record.get("row_count")
            if (
                set(record) != anchor_keys
                or record.get("kind") != "anchor"
                or not isinstance(day, str)
                or not _valid_day_name(f"{day}.ndjson")
                or not isinstance(record.get("tip_hash"), str)
                or not _SHA256_RE.fullmatch(record["tip_hash"])
                or not isinstance(row_count, int)
                or isinstance(row_count, bool)
                or row_count < 1
                or _parse_utc(record.get("ts")) is None
            ):
                raise WormUnavailable("signed anchor ledger schema is invalid")
            latest[day] = record

        # A day retired by policy retention has no file left to read. Its anchor
        # stays in the append-only ledger by design; consuming it here would
        # fail every subsequent push on a missing file.
        for day in purged:
            latest.pop(day, None)

        requested = {path.stem: path for path in closed}
        if not set(requested).issubset(latest):
            raise WormUnavailable("one or more closed audit day-files are not anchored")

        snapshot: dict[str, bytes] = {}
        for day, anchor in latest.items():
            path = audit_dir / f"{day}.ndjson"
            raw = _read_custodied_file(path, mode=0o600)
            records = _verified_chain_records(raw)
            if (
                len(records) != anchor["row_count"]
                or not records
                or records[-1]["hash"] != anchor["tip_hash"]
            ):
                raise WormUnavailable("signed anchor does not match its audit day-file")
            if day in requested:
                snapshot[path.name] = raw
        return snapshot
    except WormUnavailable:
        raise
    except (OSError, PermissionError, UnicodeError) as exc:
        raise WormUnavailable("closed audit evidence custody is invalid") from exc


def _invalid_source_evidence(audit_dir: Path, closed: list[Path]) -> set[str]:
    """Return all closed names when the global signed snapshot is invalid."""
    try:
        _verified_source_snapshot(audit_dir, closed)
    except WormUnavailable:
        return {path.name for path in closed}
    return set()


def _read_verified_source(audit_dir: Path, path: Path) -> bytes:
    """Compatibility wrapper returning the exact authenticated source bytes."""
    snapshot = _verified_source_snapshot(audit_dir, [path])
    try:
        return snapshot[path.name]
    except KeyError as exc:  # pragma: no cover - guarded by anchor coverage
        raise WormUnavailable("closed audit evidence is not anchored") from exc


# --- orchestration ----------------------------------------------------------


def _reviewed_closed(audit_dir, today, expected_sources):
    closed = [p for p in day_files(audit_dir) if p.stem < today]
    if expected_sources is None:
        return closed
    available = {p.name: p for p in closed}
    if not set(expected_sources).issubset(available):
        raise WormUnavailable("reviewed closed audit source is missing")
    return [available[name] for name in sorted(expected_sources)]


def _reviewed_deadline(retain_until, retention_days, request_id):
    deadline = retain_until or (_utcnow() + _dt.timedelta(days=retention_days))
    if deadline.tzinfo is None or deadline <= _utcnow():
        raise WormUnavailable("reviewed retention deadline expired")
    if request_id is not None and not _SHA256_RE.fullmatch(request_id):
        raise WormUnavailable("invalid WORM request reference")
    return deadline


def _retention_days(cfg, retention_days):
    if retention_days is None:
        try:
            retention_days = int(cfg.get("retention_days") or _DEFAULT_RETENTION_DAYS)
        except (TypeError, ValueError):
            retention_days = _DEFAULT_RETENTION_DAYS
    if not isinstance(retention_days, int) or not 1 <= retention_days <= 36_500:
        raise WormUnavailable("WORM retention_days must be between 1 and 36500")
    return retention_days

def push_closed_dayfiles(
    *,
    audit_dir: Path | None = None,
    today: str | None = None,
    sink: Any | None = None,
    retention_days: int | None = None,
    dry_run: bool = False,
    expected_sources: Mapping[str, str] | None = None,
    retain_until: _dt.datetime | None = None,
    request_id: str | None = None,
    before_effect: Callable[[str, str], None] | None = None,
    completed: Callable[[str, str], None] | None = None,
    reconcile: Callable[[str, str, list[str]], str | None] | None = None,
) -> dict[str, str]:
    """Ship every closed (date < today), not-yet-shipped day-file to the WORM
    target. Returns a ``{filename: status}`` report. Idempotent: an unchanged,
    already-pushed file is skipped; a changed one is re-pushed (a new locked
    version). The current day-file and the anchor ledger are never shipped."""
    if audit_dir is None:
        audit_dir = data_dir("audit")
    today = today or _utcnow().strftime("%Y-%m-%d")
    cfg = _worm_cfg()
    retention_days = _retention_days(cfg, retention_days)

    report: dict[str, str] = {}
    if not audit_dir.exists():
        return report
    closed = _reviewed_closed(audit_dir, today, expected_sources)
    if not closed:
        return report

    try:
        source_snapshot = _verified_source_snapshot(audit_dir, closed)
    except WormUnavailable as exc:
        raise WormUnavailable(
            "WORM push refused: one or more closed audit day-files do not have "
            "an intact signed chain and cross-day anchor"
        ) from exc

    manifest = _load_manifest(audit_dir)
    if sink is None and not dry_run:
        sink = build_sink(cfg)   # raises WormUnavailable if unconfigured
    retain_until = _reviewed_deadline(retain_until, retention_days, request_id)
    native_request_id = request_id or hashlib.sha256(uuid.uuid4().bytes).hexdigest()

    # Never ship PLAINTEXT audit data into an immutable WORM lock. A closed
    # day-file is sealed in-place by `audit seal`; WORM push is a separate
    # command with no enforced ordering, so pushing first would lock plaintext
    # (sensitive action detail) under a multi-year S3 Object-Lock COMPLIANCE
    # retention -- an exposure that can't be deleted and breaks GDPR erasability.
    # Refuse an unsealed file whenever sealing is enabled. An explicit opt-out
    # permits plaintext; an enabled-but-unavailable sealer does not. Conflating
    # those states could irreversibly lock sensitive plaintext into S3 Object
    # Lock precisely during a key/KMS/crypto outage.
    try:
        seal_required = _at_rest_sealing_active()
    except WormUnavailable as exc:
        # This is a run-wide dependency outage, not a per-file validation
        # result. Raise so the CLI/cron exits non-zero rather than reporting a
        # misleading successful run that merely shipped zero files.
        raise WormUnavailable(
            "WORM push refused: at-rest encryption is enabled/configured but "
            "sealing is unavailable; restore key/crypto access and run "
            "`maverick audit seal` before WORM push"
        ) from exc
    from ..crypto_at_rest import is_sealed

    for p in closed:
        with cross_process_lock(p, strict=True):
            data = source_snapshot[p.name]
            digest = _sha256(data)
            if expected_sources is not None and _sha256(_read_custodied_file(p, mode=0o600)) != digest:
                raise WormUnavailable("reviewed audit source changed before copy")
            if expected_sources is not None and expected_sources[p.name] != digest:
                raise WormUnavailable("reviewed audit source changed")
            if seal_required and not is_sealed(data):
                report[p.name] = (
                    "refused: unsealed plaintext -- run `maverick audit seal` before "
                    "WORM push (at-rest encryption is on)"
                )
                continue
            prior = manifest.get(p.name)
            separate = bool(reconcile and reconcile(p.name, digest, []))
            if prior and prior.get("sha256") == digest and _locator_verified(prior, digest, sink, audit_dir) and not separate:
                report[p.name] = "already pushed"
                continue
            changed = prior is not None
            if dry_run:
                report[p.name] = "would re-push (changed)" if changed else "would push"
                continue
            if before_effect:
                before_effect(p.name, digest)
            try:
                fenced = _attempt_fence(audit_dir, p.name, digest, native_request_id, retain_until, sink, reconcile)
            except WormAttemptHeld:
                # Fail closed for this file only: one unresolved upload must not
                # stop every later day from being exported.
                report[p.name] = "refused: held -- an earlier copy has an unknown result; review it before retrying"
                continue
            if not fenced:
                report[p.name] = "already pushed"
                continue
            try:
                locator = sink.put(p.name, data, retain_until=retain_until)
            # failure-policy: fail_soft_with_audit
            except Exception as exc:  # surface class only; provider errors may carry secrets
                report[p.name] = f"error ({type(exc).__name__})"
                continue
            rec = {
                "name": p.name, "sha256": digest,
                "pushed_at": _utcnow().isoformat(),
                "retain_until": retain_until.isoformat(),
                "locator": locator,
            }
            rec["request_id"] = native_request_id
            if not _locator_verified(rec, digest, sink, audit_dir):
                report[p.name] = "error (retention proof unavailable)"
                continue
            _append_manifest(audit_dir, rec)
            report[p.name] = "re-pushed (changed)" if changed else "pushed"
            if completed:
                completed(p.name, report[p.name])
    return report


def verify(*, audit_dir: Path | None = None) -> dict[str, str]:
    """Check every closed local day-file against the WORM manifest. Status per
    file: ``ok`` (current bytes were shipped), ``changed since push`` (local bytes
    differ from the last shipped version -- re-push), or ``NOT pushed``."""
    if audit_dir is None:
        audit_dir = data_dir("audit")
    today = _utcnow().strftime("%Y-%m-%d")
    report: dict[str, str] = {}
    if not audit_dir.exists():
        return report
    closed = [p for p in day_files(audit_dir) if p.stem < today]
    try:
        source_snapshot = _verified_source_snapshot(audit_dir, closed)
        invalid_evidence: set[str] = set()
    except WormUnavailable:
        source_snapshot = {}
        invalid_evidence = {p.name for p in closed}
    try:
        manifest = _load_manifest(audit_dir)
    except WormUnavailable:
        return {p.name: "manifest invalid" for p in closed}
    for p in closed:
        if p.name in invalid_evidence:
            report[p.name] = "source evidence invalid"
            continue
        digest = _sha256(source_snapshot[p.name])
        prior = manifest.get(p.name)
        if prior is None:
            report[p.name] = "NOT pushed"
        elif prior.get("sha256") == digest:
            report[p.name] = "ok" if _locator_verified(prior, digest, audit_dir=audit_dir) else "NOT durably present"
        else:
            report[p.name] = "changed since push"
    return report


__all__ = [
    "WormUnavailable", "LocalWormSink", "S3WormSink", "build_sink",
    "worm_enabled", "push_closed_dayfiles", "verify", "request_receipts", "unknown_attempts",
]
