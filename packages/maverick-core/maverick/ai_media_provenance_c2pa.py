"""Bounded optional C2PA integration backed by the official ``c2patool`` CLI.

The classes in this module implement the structural ``C2PAVerifier`` and
``C2PASigner`` interfaces from :mod:`maverick.ai_media_provenance`.  They do
not make ``c2patool`` a required dependency: an absent or unusable executable
is reported as unavailable and every operation fails closed.

Media, settings, manifests, certificates, and private keys exist only in a
private temporary directory for the duration of one operation.  The returned
``manifest_sha256`` is the digest of c2patool's canonical JSON projection of
the active manifest, not a digest of the binary JUMBF manifest store.  All
validity and trust fields are exact adapter-reported observations.  They are
not certification and do not prove authorship, ownership, or truth.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from .ai_media_provenance import (
    ADAPTER_RECEIPT_SCHEMA,
    C2PABinding,
    MediaProvenanceUnavailable,
)
from .file_lock import atomic_create_bytes, ensure_private_directory, ensure_private_file

_MAX_MEDIA_BYTES = 64 * 1024 * 1024
_MAX_REPORT_BYTES = 1024 * 1024
_MAX_PROCESS_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_CERTIFICATE_BYTES = 256 * 1024
_MAX_PRIVATE_KEY_BYTES = 64 * 1024
_MAX_TRUST_ANCHOR_BYTES = 1024 * 1024
_MAX_PINNED_EXECUTABLE_BYTES = 256 * 1024 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 20_000
_MAX_ASSERTIONS = 64
_MAX_FUTURE_SKEW_SECONDS = 300.0

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:/-]{0,127}\Z")
_VERSION_RE = re.compile(
    r"c2patool(?:\.exe)? ([0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?)\r?\n?\Z"
)
_RFC3339_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_STATUS_CODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_VERSIONED_ASSERTION_RE = re.compile(r"\.v[0-9]+\Z", re.IGNORECASE)
_VENDOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,63}\Z")
_ASSET_ID_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/+\-=]{0,255}\Z")
_DNS_LABEL_RE = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)\Z")

_READER_KEYS = frozenset({
    "active_manifest",
    "manifests",
    "validation_results",
    "validation_state",
    "validation_status",
})
_REQUIRED_READER_KEYS = frozenset({
    "active_manifest",
    "manifests",
    "validation_results",
    "validation_state",
})
_RESULT_KEYS = frozenset({"activeManifest", "ingredientDeltas", "validationTime"})
_STATUS_BUCKETS = frozenset({"success", "informational", "failure"})
_STATUS_KEYS = frozenset({"code", "explanation", "success", "url"})
_SAFE_MANIFEST_KEYS = frozenset({
    "assertions",
    "claim_generator",
    "claim_generator_info",
    "title",
    "vendor",
})
_SAFE_ASSERTION_KEYS = frozenset({"data", "label"})
_SAFE_GENERATOR_KEYS = frozenset({"name", "version"})
_MANIFEST_REPORT_KEYS = frozenset({
    "assertions",
    "claim_generator",
    "claim_generator_info",
    "claim_version",
    "credentials",
    "format",
    "ingredients",
    "instance_id",
    "label",
    "metadata",
    "redactions",
    "signature_info",
    "thumbnail",
    "title",
    "vendor",
})
_SIGNATURE_INFO_KEYS = frozenset({
    "alg",
    "cert_serial_number",
    "common_name",
    "issuer",
    "revocation_status",
    "time",
})
_SIGNING_ALGORITHMS = frozenset({
    "es256",
    "es384",
    "es512",
    "ps256",
    "ps384",
    "ps512",
    "ed25519",
})
_ASSERTION_STATUS_CODES = frozenset({
    "assertion.hashedURI.match",
    "assertion.dataHash.match",
    "assertion.boxesHash.match",
    "assertion.bmffHash.match",
})


@dataclass(frozen=True)
class C2PAToolProcessResult:
    """Bounded result returned by an injected c2patool process runner."""

    returncode: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    output_truncated: bool = False


class C2PAToolProcessRunner(Protocol):
    def __call__(
        self,
        args: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> C2PAToolProcessResult: ...


@dataclass(frozen=True)
class C2PAToolSigningCredentials:
    """Ephemeral signing material supplied immediately before one operation."""

    certificate_chain: bytes = field(repr=False)
    private_key: bytes = field(repr=False)
    algorithm: str


C2PAToolCredentialProvider = Callable[[], C2PAToolSigningCredentials]
C2PAToolManifestProvider = Callable[
    [C2PABinding, tuple[str, ...]], Mapping[str, Any]
]
C2PAToolTrustAnchorProvider = Callable[[], bytes]


def _expected_sha256(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a SHA-256 digest")
    normalized = value.strip().lower().removeprefix("sha256:")
    if not _DIGEST_RE.fullmatch(normalized):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return normalized


def _file_object_identity(value: os.stat_result) -> tuple[int, ...]:
    """Return path/descriptor metadata stable across Windows stat variants."""

    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(getattr(value, "st_uid", 0)),
        int(getattr(value, "st_gid", 0)),
    )


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    """Return path metadata that also changes on chmod or file-type change."""

    return (
        *_file_object_identity(value),
        int(value.st_ctime_ns),
        int(value.st_mode),
    )


def _inspect_pinned_executable(
    candidate: Path,
    *,
    expected_sha256: str,
    expected_identity: tuple[int, ...] | None = None,
    label: str = "c2patool external signer",
) -> tuple[Path, tuple[int, ...]]:
    """Hash a regular non-symlink executable through a path-bound descriptor.

    Python cannot execute an already-open handle portably on every supported
    platform.  This closes the inspect/open/hash races that can be closed,
    records file identity, and lets the caller repeat the check immediately
    before invoking c2patool. Deployment ACLs must prevent replacement in the
    remaining spawn window.
    """

    if not candidate.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    try:
        candidate_metadata = candidate.lstat()
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise ValueError(f"{label} must be a regular non-symlink file")
        resolved = candidate.resolve(strict=True)
        path_before = resolved.lstat()
    except ValueError:
        raise
    except (OSError, RuntimeError):
        raise ValueError(f"{label} is unavailable") from None
    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    if not 1 <= path_before.st_size <= _MAX_PINNED_EXECUTABLE_BYTES:
        raise ValueError(f"{label} size is invalid")
    identity = _file_identity(path_before)
    if expected_identity is not None and identity != expected_identity:
        raise ValueError(f"{label} changed after admission")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(resolved), flags)
    except OSError:
        raise ValueError(f"{label} is unavailable") from None
    try:
        descriptor_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_before.st_mode)
            or _file_object_identity(descriptor_before)
            != _file_object_identity(path_before)
        ):
            raise ValueError(f"{label} changed during admission")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        descriptor_after = os.fstat(descriptor)
        if _file_identity(descriptor_after) != _file_identity(descriptor_before):
            raise ValueError(f"{label} changed during admission")
    finally:
        os.close(descriptor)
    try:
        path_after = resolved.lstat()
    except OSError:
        raise ValueError(f"{label} changed during admission") from None
    if (
        stat.S_ISLNK(path_after.st_mode)
        or _file_identity(path_after) != identity
        or not hmac.compare_digest(digest.hexdigest(), expected_sha256)
    ):
        raise ValueError(f"{label} digest or identity mismatch")
    return resolved, identity


def _timestamp_authority_url(value: object, *, allow_insecure: bool) -> str:
    """Return one operator-pinned public TSA URL.

    ``c2patool`` performs the request itself, so this validation is paired with
    the enterprise egress check immediately before process execution.  HTTP is
    available only as an explicit development-fixture escape hatch; production
    callers should use HTTPS or an external signer that owns timestamping.
    """

    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("c2patool timestamp authority URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("c2patool timestamp authority URL is invalid") from None
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"https", "http"}
        or (scheme == "http" and not allow_insecure)
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("c2patool timestamp authority URL is invalid")
    host = parsed.hostname.lower()
    if (
        host == "localhost"
        or host.endswith((".localhost", ".localdomain"))
        or host.endswith(".")
        or any(ord(char) > 127 for char in host)
    ):
        raise ValueError("c2patool timestamp authority host is invalid")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
            raise ValueError("c2patool timestamp authority host is invalid") from None
        rendered_host = host
    else:
        if not address.is_global:
            raise ValueError("c2patool timestamp authority host must be public")
        rendered_host = f"[{host}]" if address.version == 6 else host
    if port is not None:
        rendered_host = f"{rendered_host}:{port}"
    return urlunsplit((scheme, rendered_host, parsed.path or "", "", ""))


def _default_process_runner(
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
) -> C2PAToolProcessResult:
    """Run a fixed argv without a shell while bounding time and captured output."""

    process = subprocess.Popen(  # noqa: S603 -- fixed argv, never a shell
        list(args),
        cwd=str(cwd),
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover
        process.kill()
        raise RuntimeError("c2patool pipes are unavailable")

    stdout = bytearray()
    stderr = bytearray()
    output_truncated = threading.Event()
    lock = threading.Lock()
    captured = 0

    def drain(stream: Any, destination: bytearray) -> None:
        nonlocal captured
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            with lock:
                remaining = max(0, output_limit_bytes + 1 - captured)
                if remaining:
                    destination.extend(chunk[:remaining])
                captured += len(chunk)
                over_limit = captured > output_limit_bytes
            if over_limit:
                output_truncated.set()
                try:
                    process.kill()
                except OSError:
                    pass
                return

    threads = (
        threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
    )
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait(timeout=5.0)
    finally:
        for thread in threads:
            thread.join(timeout=1.0)
        process.stdout.close()
        process.stderr.close()

    if timed_out:
        raise subprocess.TimeoutExpired(tuple(args), timeout_seconds)
    return C2PAToolProcessResult(
        returncode=int(process.returncode),
        stdout=bytes(stdout),
        stderr=bytes(stderr),
        output_truncated=output_truncated.is_set(),
    )


def _canonical_json(value: object, *, limit: int) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise MediaProvenanceUnavailable("c2patool JSON data is unavailable") from None
    if len(encoded) > limit:
        raise MediaProvenanceUnavailable("c2patool JSON data exceeds its bound")
    return encoded


def _sha256_json(value: object, *, limit: int) -> str:
    return hashlib.sha256(_canonical_json(value, limit=limit)).hexdigest()


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_json_shape(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise MediaProvenanceUnavailable("c2patool JSON structure exceeds its bound")
        if item is None or isinstance(item, (bool, int)):
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise MediaProvenanceUnavailable("c2patool JSON number is invalid")
            continue
        if isinstance(item, str):
            if len(item) > 128 * 1024 or "\x00" in item:
                raise MediaProvenanceUnavailable("c2patool JSON string is invalid")
            continue
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
            continue
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256 or "\x00" in key:
                    raise MediaProvenanceUnavailable("c2patool JSON key is invalid")
                stack.append((child, depth + 1))
            continue
        raise MediaProvenanceUnavailable("c2patool JSON value is invalid")


def _parse_json_report(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_REPORT_BYTES:
        raise MediaProvenanceUnavailable("c2patool report is missing or oversized")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise MediaProvenanceUnavailable("c2patool report encoding is invalid")
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError):
        raise MediaProvenanceUnavailable("c2patool report is malformed") from None
    _validate_json_shape(value)
    if not isinstance(value, dict):
        raise MediaProvenanceUnavailable("c2patool report must be an object")
    keys = set(value)
    if not _REQUIRED_READER_KEYS.issubset(keys) or not keys.issubset(_READER_KEYS):
        raise MediaProvenanceUnavailable("c2patool report schema is unexpected")
    return value


def _safe_text(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise MediaProvenanceUnavailable(f"c2patool {label} is invalid")
    text = value.strip()
    if not text or len(text) > limit or any(
        ord(char) < 32 or ord(char) == 127 for char in text
    ):
        raise MediaProvenanceUnavailable(f"c2patool {label} is invalid")
    return text


def _normalize_assertion(value: object) -> str:
    label = _safe_text(value, "assertion label", 128).lower()
    label = _VERSIONED_ASSERTION_RE.sub("", label)
    if not _TOKEN_RE.fullmatch(label):
        raise MediaProvenanceUnavailable("c2patool assertion label is invalid")
    return label


def _parse_status(value: object) -> tuple[str, str | None]:
    if not isinstance(value, dict) or "code" not in value or not set(value).issubset(
        _STATUS_KEYS
    ):
        raise MediaProvenanceUnavailable("c2patool validation status is invalid")
    code = _safe_text(value["code"], "validation status code", 128)
    if not _STATUS_CODE_RE.fullmatch(code):
        raise MediaProvenanceUnavailable("c2patool validation status code is invalid")
    url = value.get("url")
    if url is not None:
        url = _safe_text(url, "validation status URL", 4096)
    explanation = value.get("explanation")
    if explanation is not None:
        _safe_text(explanation, "validation explanation", 4096)
    success = value.get("success")
    if success is not None and not isinstance(success, bool):
        raise MediaProvenanceUnavailable("c2patool validation status is invalid")
    return code, url


def _validation_statuses(report: Mapping[str, Any]) -> tuple[
    list[tuple[str, str | None]],
    list[tuple[str, str | None]],
    list[tuple[str, str | None]],
]:
    results = report.get("validation_results")
    if not isinstance(results, dict) or not set(results).issubset(_RESULT_KEYS):
        raise MediaProvenanceUnavailable("c2patool validation results are invalid")
    active = results.get("activeManifest")
    if not isinstance(active, dict) or set(active) != _STATUS_BUCKETS:
        raise MediaProvenanceUnavailable("c2patool active validation results are invalid")
    if "ingredientDeltas" in results and not isinstance(results["ingredientDeltas"], list):
        raise MediaProvenanceUnavailable("c2patool ingredient results are invalid")
    if "validationTime" in results:
        _rfc3339_timestamp(results["validationTime"], now=None)

    parsed: list[list[tuple[str, str | None]]] = []
    for bucket in ("success", "informational", "failure"):
        values = active[bucket]
        if not isinstance(values, list) or len(values) > 1024:
            raise MediaProvenanceUnavailable("c2patool validation results are invalid")
        parsed.append([_parse_status(item) for item in values])

    legacy = report.get("validation_status", [])
    if not isinstance(legacy, list) or len(legacy) > 1024:
        raise MediaProvenanceUnavailable("c2patool validation status is invalid")
    for item in legacy:
        _parse_status(item)
    return parsed[0], parsed[1], parsed[2]


def _rfc3339_timestamp(value: object, *, now: float | None) -> float:
    text = _safe_text(value, "timestamp", 64)
    if not _RFC3339_RE.fullmatch(text):
        raise MediaProvenanceUnavailable("c2patool timestamp is invalid")
    try:
        iso_value = text.removesuffix("Z") + ("+00:00" if text.endswith("Z") else "")
        parsed = datetime.fromisoformat(iso_value)
        stamp = parsed.timestamp()
    except (OSError, OverflowError, ValueError):
        raise MediaProvenanceUnavailable("c2patool timestamp is invalid") from None
    if parsed.tzinfo is None or not math.isfinite(stamp) or stamp <= 0:
        raise MediaProvenanceUnavailable("c2patool timestamp is invalid")
    if now is not None and stamp > now + _MAX_FUTURE_SKEW_SECONDS:
        raise MediaProvenanceUnavailable("c2patool signing timestamp is in the future")
    return stamp


def _claim_generator(manifest: Mapping[str, Any]) -> str:
    value = manifest.get("claim_generator")
    if value is not None:
        return _safe_text(value, "claim generator", 256)
    info = manifest.get("claim_generator_info")
    if not isinstance(info, list) or not info or not isinstance(info[0], dict):
        raise MediaProvenanceUnavailable("c2patool claim generator is missing")
    name = _safe_text(info[0].get("name"), "claim generator name", 192)
    version = info[0].get("version")
    if version is None:
        return name
    return f"{name}/{_safe_text(version, 'claim generator version', 63)}"


def _assertion_codes(
    manifest: Mapping[str, Any], statuses: Sequence[tuple[str, str | None]]
) -> tuple[str, ...]:
    assertions = manifest.get("assertions")
    if not isinstance(assertions, list) or len(assertions) > _MAX_ASSERTIONS:
        raise MediaProvenanceUnavailable("c2patool assertions are invalid")
    labels: set[str] = set()
    for assertion in assertions:
        if not isinstance(assertion, dict) or "label" not in assertion:
            raise MediaProvenanceUnavailable("c2patool assertion is invalid")
        labels.add(_normalize_assertion(assertion["label"]))
    for code, url in statuses:
        if code not in _ASSERTION_STATUS_CODES or url is None:
            continue
        marker = "/c2pa.assertions/"
        if marker not in url:
            continue
        raw_label = re.split(r"[/#?]", url.split(marker, 1)[1], maxsplit=1)[0]
        labels.add(_normalize_assertion(raw_label))
    if not labels or len(labels) > _MAX_ASSERTIONS:
        raise MediaProvenanceUnavailable("c2patool assertion coverage is unavailable")
    return tuple(sorted(labels))


def _media_extension(media: bytes, media_kind: str) -> str:
    if media_kind not in {"image", "audio", "video"}:
        raise MediaProvenanceUnavailable("c2patool media kind is unsupported")
    if media_kind == "image":
        if media.startswith(b"\xff\xd8\xff"):
            return ".jpg"
        if media.startswith(b"\x89PNG\r\n\x1a\n"):
            return ".png"
        if len(media) >= 12 and media[:4] == b"RIFF" and media[8:12] == b"WEBP":
            return ".webp"
        if len(media) >= 12 and media[4:8] == b"ftyp" and media[8:12] in {
            b"avif",
            b"avis",
        }:
            return ".avif"
    elif media_kind == "audio":
        if len(media) >= 12 and media[:4] == b"RIFF" and media[8:12] == b"WAVE":
            return ".wav"
        if media.startswith(b"fLaC"):
            return ".flac"
        if media.startswith(b"ID3") or (
            len(media) >= 2 and media[0] == 0xFF and media[1] & 0xE0 == 0xE0
        ):
            return ".mp3"
        if len(media) >= 12 and media[4:8] == b"ftyp":
            return ".m4a"
    elif len(media) >= 12 and media[4:8] == b"ftyp":
        return ".mp4"
    raise MediaProvenanceUnavailable("c2patool media format is unsupported")


def _binding_payload(binding: C2PABinding, source_sha256: str) -> dict[str, Any]:
    if not isinstance(binding, C2PABinding):
        raise MediaProvenanceUnavailable("c2patool binding is invalid")
    source = str(binding.source_content_sha256).lower().removeprefix("sha256:")
    if not _DIGEST_RE.fullmatch(source) or source != source_sha256:
        raise MediaProvenanceUnavailable("c2patool source binding does not match")
    result: dict[str, Any] = {
        "media_kind": binding.media_kind,
        "source_content_sha256": source,
        "asset_id": binding.asset_id,
        "asset_revision": binding.asset_revision,
        "asset_version_digest": binding.asset_version_digest,
        "deployment_id": binding.deployment_id,
        "deployment_revision": binding.deployment_revision,
        "deployment_artifact_digest": binding.deployment_artifact_digest,
        "context_id": binding.context_id,
        "context_revision": binding.context_revision,
        "context_digest": binding.context_digest,
    }
    if result["media_kind"] not in {"image", "audio", "video"}:
        raise MediaProvenanceUnavailable("c2patool binding media kind is invalid")
    for field_name in ("asset_revision", "deployment_revision", "context_revision"):
        value = result[field_name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise MediaProvenanceUnavailable("c2patool binding revision is invalid")
    for field_name in (
        "asset_version_digest",
        "deployment_artifact_digest",
        "context_digest",
    ):
        value = result[field_name]
        if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value.lower()):
            raise MediaProvenanceUnavailable("c2patool binding digest is invalid")
        result[field_name] = value.lower()
    asset_id = _safe_text(result["asset_id"], "binding asset identity", 36)
    if not _ASSET_ID_RE.fullmatch(asset_id):
        raise MediaProvenanceUnavailable("c2patool binding asset identity is invalid")
    result["asset_id"] = asset_id
    for field_name in ("deployment_id", "context_id"):
        identity = _safe_text(result[field_name], "binding identity", 256)
        if not _IDENTITY_RE.fullmatch(identity):
            raise MediaProvenanceUnavailable("c2patool binding identity is invalid")
        result[field_name] = identity
    return result


def _secure_write(path: Path, payload: bytes) -> None:
    atomic_create_bytes(path, payload, mode=0o600)


def _erase_file(path: Path) -> None:
    descriptor = -1
    try:
        inspected = path.lstat()
        if not stat.S_ISREG(inspected.st_mode) or inspected.st_nlink != 1:
            raise OSError("secret path is no longer a single regular file")
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (inspected.st_dev, inspected.st_ino)
        ):
            raise OSError("secret path changed")
        size = opened.st_size
        with os.fdopen(descriptor, "r+b", buffering=0, closefd=False) as stream:
            block = b"\x00" * min(8192, max(1, size))
            remaining = size
            while remaining:
                amount = min(remaining, len(block))
                stream.write(block[:amount])
                remaining -= amount
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        pass
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        path.unlink()
    except OSError:
        pass


def _read_bounded_regular_file(path: Path, limit: int) -> bytes:
    try:
        ensure_private_file(path, 0o600)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1 or metadata.st_size > limit:
            raise MediaProvenanceUnavailable("c2patool output file is invalid")
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size != metadata.st_size:
                raise MediaProvenanceUnavailable("c2patool output file changed")
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise MediaProvenanceUnavailable("c2patool output file changed")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read(limit + 1)
        finally:
            os.close(descriptor)
    except MediaProvenanceUnavailable:
        raise
    except OSError:
        raise MediaProvenanceUnavailable("c2patool output file is unavailable") from None
    if not payload or len(payload) > limit:
        raise MediaProvenanceUnavailable("c2patool output file is invalid")
    return payload


def _sanitize_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MediaProvenanceUnavailable("c2patool manifest definition is invalid")
    encoded = _canonical_json(value, limit=_MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(encoded.decode("ascii"))
    except ValueError:  # pragma: no cover - canonical JSON was just produced
        raise MediaProvenanceUnavailable("c2patool manifest definition is invalid") from None
    _validate_json_shape(manifest)
    if not isinstance(manifest, dict) or not set(manifest).issubset(_SAFE_MANIFEST_KEYS):
        raise MediaProvenanceUnavailable("c2patool manifest definition is unsafe")
    assertions = manifest.get("assertions")
    if not isinstance(assertions, list) or not 1 <= len(assertions) <= _MAX_ASSERTIONS:
        raise MediaProvenanceUnavailable("c2patool manifest assertions are invalid")
    for assertion in assertions:
        if not isinstance(assertion, dict) or set(assertion) != _SAFE_ASSERTION_KEYS:
            raise MediaProvenanceUnavailable("c2patool manifest assertion is unsafe")
        _normalize_assertion(assertion["label"])
    if "claim_generator" in manifest:
        _safe_text(manifest["claim_generator"], "manifest claim generator", 256)
    if "claim_generator_info" in manifest:
        information = manifest["claim_generator_info"]
        if not isinstance(information, list) or not 1 <= len(information) <= 8:
            raise MediaProvenanceUnavailable("c2patool claim generator info is invalid")
        for item in information:
            if not isinstance(item, dict) or not set(item).issubset(
                _SAFE_GENERATOR_KEYS
            ) or "name" not in item:
                raise MediaProvenanceUnavailable("c2patool claim generator info is unsafe")
            _safe_text(item["name"], "manifest claim generator name", 192)
            if "version" in item:
                _safe_text(item["version"], "manifest claim generator version", 63)
    if "title" in manifest:
        _safe_text(manifest["title"], "manifest title", 512)
    if "vendor" in manifest and (
        not isinstance(manifest["vendor"], str)
        or not _VENDOR_RE.fullmatch(manifest["vendor"])
    ):
        raise MediaProvenanceUnavailable("c2patool manifest vendor is invalid")
    return manifest


def _secret_bytes(value: object, *, maximum: int, kind: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise MediaProvenanceUnavailable(f"c2patool {kind} is unavailable")
    payload = bytes(value)
    if not payload or len(payload) > maximum or b"\x00" in payload:
        raise MediaProvenanceUnavailable(f"c2patool {kind} is invalid")
    return payload


def _ensure_credentials_not_in_receipt(
    receipt: Mapping[str, Any], certificate: bytes, private_key: bytes
) -> None:
    encoded = _canonical_json(receipt, limit=128 * 1024)
    for secret in (certificate, private_key):
        for line in secret.splitlines():
            fragment = line.strip()
            if len(fragment) >= 8 and not fragment.startswith(b"-----"):
                if fragment in encoded:
                    raise MediaProvenanceUnavailable(
                        "c2patool credential material appeared in its receipt"
                    )


class _C2PAToolRuntime:
    adapter_id = "c2patool"

    def __init__(
        self,
        *,
        executable: str | os.PathLike[str] | None = None,
        expected_executable_sha256: str | None = None,
        executable_locator: Callable[[str], str | None] = shutil.which,
        process_runner: C2PAToolProcessRunner = _default_process_runner,
        trust_anchor_provider: C2PAToolTrustAnchorProvider | None = None,
        temp_root: str | os.PathLike[str] | None = None,
        timeout_seconds: float = 15.0,
        output_limit_bytes: int = _MAX_REPORT_BYTES,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(executable_locator) or not callable(process_runner) or not callable(clock):
            raise TypeError("c2patool runtime dependencies must be callable")
        if trust_anchor_provider is not None and not callable(trust_anchor_provider):
            raise TypeError("c2patool trust anchor provider must be callable")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or not 0.1 <= float(timeout_seconds) <= 60.0
        ):
            raise ValueError("c2patool timeout must be between 0.1 and 60 seconds")
        if (
            not isinstance(output_limit_bytes, int)
            or isinstance(output_limit_bytes, bool)
            or not 1024 <= output_limit_bytes <= _MAX_PROCESS_OUTPUT_BYTES
        ):
            raise ValueError("c2patool output bound must be between 1 KiB and 4 MiB")
        self._explicit_executable = os.fspath(executable) if executable is not None else None
        self._expected_executable_sha256 = (
            None
            if expected_executable_sha256 is None
            else _expected_sha256(
                expected_executable_sha256,
                "c2patool expected executable digest",
            )
        )
        self._executable_locator = executable_locator
        self._process_runner = process_runner
        self._trust_anchor_provider = trust_anchor_provider
        self._temp_root = Path(temp_root) if temp_root is not None else None
        self._timeout_seconds = float(timeout_seconds)
        self._output_limit_bytes = output_limit_bytes
        self._clock = clock
        self._tool_cache: tuple[Path, str, tuple[int, ...]] | None = None

    @property
    def adapter_version(self) -> str:
        """The ADMITTED tool version, from cache only -- never a probe.

        This property is touched by ``isinstance`` against the
        runtime-checkable adapter protocols (``hasattr`` evaluates
        properties), so probing here would make a mere type check spawn the
        c2patool subprocess. Every caller that needs the live version goes
        through ``is_available()``/``_tool()`` first, which primes the cache;
        an un-admitted tool reports the same "unavailable" as before.
        """
        if self._tool_cache is not None:
            return self._tool_cache[1]
        return "unavailable"

    def _tool(self) -> tuple[str, str]:
        if self._tool_cache is not None:
            path, version, identity = self._tool_cache
            try:
                verified, _current_identity = _inspect_pinned_executable(
                    path,
                    expected_sha256=self._expected_tool_digest(),
                    expected_identity=identity,
                    label="c2patool executable",
                )
            except ValueError:
                raise MediaProvenanceUnavailable(
                    "c2patool executable failed integrity validation"
                ) from None
            return str(verified), version
        expected_digest = self._expected_tool_digest()
        resolved = self._explicit_executable or self._executable_locator("c2patool")
        if isinstance(resolved, os.PathLike):
            resolved = os.fspath(resolved)
        if not isinstance(resolved, str) or not resolved or "\x00" in resolved:
            raise MediaProvenanceUnavailable("c2patool executable is unavailable")
        path = Path(resolved)
        try:
            verified, identity = _inspect_pinned_executable(
                path,
                expected_sha256=expected_digest,
                label="c2patool executable",
            )
        except ValueError:
            raise MediaProvenanceUnavailable(
                "c2patool executable failed integrity validation"
            ) from None
        result = self._invoke(
            (str(verified), "--version"),
            cwd=verified.parent,
            env=self._environment(verified.parent),
            output_limit_bytes=4096,
        )
        try:
            version_output = result.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise MediaProvenanceUnavailable("c2patool version is unavailable") from None
        match = _VERSION_RE.fullmatch(version_output)
        if match is None:
            raise MediaProvenanceUnavailable("c2patool version is unavailable")
        try:
            verified, identity = _inspect_pinned_executable(
                verified,
                expected_sha256=expected_digest,
                expected_identity=identity,
                label="c2patool executable",
            )
        except ValueError:
            raise MediaProvenanceUnavailable(
                "c2patool executable changed during version admission"
            ) from None
        version = match.group(1)
        self._tool_cache = (verified, version, identity)
        return str(verified), version

    def _expected_tool_digest(self) -> str:
        if self._expected_executable_sha256 is None:
            raise MediaProvenanceUnavailable(
                "c2patool expected executable digest is unavailable"
            )
        return self._expected_executable_sha256

    def _verified_tool_path(self) -> str:
        """Re-hash the admitted executable immediately before process launch."""

        return self._tool()[0]

    def _admitted_tool_version(self) -> str:
        if self._tool_cache is None:
            return self._tool()[1]
        return self._tool_cache[1]

    def is_available(self) -> bool:
        try:
            self._tool()
            return True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    def _environment(self, temporary: Path) -> dict[str, str]:
        allowed = ("PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL")
        environment = {
            key: os.environ[key]
            for key in allowed
            if key in os.environ and "\x00" not in os.environ[key]
        }
        temp_value = str(temporary)
        environment.update({"TEMP": temp_value, "TMP": temp_value, "TMPDIR": temp_value})
        return environment

    def _invoke(
        self,
        args: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        output_limit_bytes: int | None = None,
    ) -> bytes:
        limit = output_limit_bytes or self._output_limit_bytes
        result = self._process_runner(
            tuple(args),
            cwd=cwd,
            env=dict(env),
            timeout_seconds=self._timeout_seconds,
            output_limit_bytes=limit,
        )
        if not isinstance(result, C2PAToolProcessResult):
            raise MediaProvenanceUnavailable("c2patool process result is invalid")
        if (
            not isinstance(result.returncode, int)
            or isinstance(result.returncode, bool)
            or not isinstance(result.stdout, bytes)
            or not isinstance(result.stderr, bytes)
            or not isinstance(result.output_truncated, bool)
        ):
            raise MediaProvenanceUnavailable("c2patool process result is invalid")
        if (
            result.output_truncated
            or len(result.stdout) + len(result.stderr) > limit
            or len(result.stdout) > _MAX_REPORT_BYTES
        ):
            raise MediaProvenanceUnavailable("c2patool process output exceeds its bound")
        if result.returncode != 0:
            raise MediaProvenanceUnavailable("c2patool process failed")
        return result.stdout

    def _workspace(self) -> tempfile.TemporaryDirectory[str]:
        if self._temp_root is not None:
            if not self._temp_root.is_dir():
                raise MediaProvenanceUnavailable("c2patool temporary root is unavailable")
        temporary = tempfile.TemporaryDirectory(
            prefix="lightwork-c2pa-",
            dir=str(self._temp_root) if self._temp_root is not None else None,
        )
        try:
            ensure_private_directory(temporary.name)
        except (OSError, PermissionError):
            temporary.cleanup()
            raise MediaProvenanceUnavailable("c2patool private workspace is unavailable") from None
        return temporary

    def _trust_anchors(self) -> bytes | None:
        if self._trust_anchor_provider is None:
            return None
        value = self._trust_anchor_provider()
        return _secret_bytes(
            value,
            maximum=_MAX_TRUST_ANCHOR_BYTES,
            kind="trust anchors",
        )

    def _settings(self) -> bytes:
        settings: dict[str, Any] = {
            "version": 1,
            "verify": {
                "ocsp_fetch": False,
                "remote_manifest_fetch": False,
                "verify_after_reading": True,
                "verify_after_sign": True,
                "verify_timestamp_trust": True,
                "verify_trust": True,
            },
        }
        return _canonical_json(settings, limit=4096)

    def _run_report(
        self,
        *,
        executable: str,
        workspace: Path,
        input_path: Path,
        settings_path: Path,
        trust_path: Path | None,
        manifest_path: Path | None = None,
        output_path: Path | None = None,
        signer_path: Path | None = None,
    ) -> dict[str, Any]:
        if manifest_path is None:
            args: tuple[str, ...] = (
                executable,
                str(input_path),
                "--settings",
                str(settings_path),
            )
            if trust_path is not None:
                # Current c2patool treats an absolute Windows path here as a
                # URL and rejects the drive-letter scheme.  The process cwd is
                # the private workspace, so the basename is both portable and
                # confined to the intended trust bundle.
                args += ("trust", "--trust_anchors", trust_path.name)
        else:
            if output_path is None:
                raise MediaProvenanceUnavailable("c2patool output path is unavailable")
            args = (
                executable,
                str(input_path),
                "--manifest",
                str(manifest_path),
                "--output",
                str(output_path),
                "--settings",
                str(settings_path),
            )
            if signer_path is not None:
                args += ("--signer-path", str(signer_path))
        stdout = self._invoke(
            args,
            cwd=workspace,
            env=self._environment(workspace),
        )
        return _parse_json_report(stdout)

    def _receipt(
        self,
        report: Mapping[str, Any],
        *,
        operation: str,
        binding: Mapping[str, Any],
        content_sha256: str,
        now: float,
    ) -> dict[str, Any]:
        active_label = _safe_text(report.get("active_manifest"), "active manifest", 512)
        manifests = report.get("manifests")
        if not isinstance(manifests, dict) or active_label not in manifests:
            raise MediaProvenanceUnavailable("c2patool active manifest is unavailable")
        manifest = manifests[active_label]
        if not isinstance(manifest, dict) or not set(manifest).issubset(
            _MANIFEST_REPORT_KEYS
        ):
            raise MediaProvenanceUnavailable("c2patool active manifest is invalid")
        successes, informational, failures = _validation_statuses(report)
        state = report.get("validation_state")
        if state not in {"Invalid", "Valid", "Trusted"}:
            raise MediaProvenanceUnavailable("c2patool validation state is invalid")
        success_codes = {code for code, _url in successes}
        all_statuses = [*successes, *informational, *failures]
        all_codes = {code for code, _url in all_statuses}
        # c2patool 0.27 reports an otherwise-valid, cryptographically verified
        # asset as ``Valid`` while placing an untrusted signer certificate in
        # the failure bucket.  Trust is a separate receipt dimension here; it
        # must not be promoted, but it also must not erase proven integrity.
        integrity_failures = [
            item for item in failures if item[0] != "signingCredential.untrusted"
        ]
        if state in {"Valid", "Trusted"} and (
            integrity_failures or "claimSignature.validated" not in success_codes
        ):
            raise MediaProvenanceUnavailable("c2patool validation report is inconsistent")
        if state == "Trusted" and "signingCredential.trusted" not in success_codes:
            raise MediaProvenanceUnavailable("c2patool trust report is inconsistent")
        validation_state = "invalid" if state == "Invalid" else "valid"
        trusted_signal = "signingCredential.trusted" in success_codes
        untrusted_signal = any(
            code.startswith("signingCredential.") and code != "signingCredential.trusted"
            for code in all_codes
        )
        if trusted_signal and untrusted_signal:
            raise MediaProvenanceUnavailable("c2patool trust report is inconsistent")
        if state == "Trusted" or trusted_signal:
            trust_chain_state = "trusted"
        elif untrusted_signal:
            trust_chain_state = "untrusted"
        else:
            trust_chain_state = "unknown"
        signature = manifest.get("signature_info")
        if (
            not isinstance(signature, dict)
            or "time" not in signature
            or not set(signature).issubset(_SIGNATURE_INFO_KEYS)
        ):
            raise MediaProvenanceUnavailable("c2patool signature information is missing")
        signing_time = _rfc3339_timestamp(signature.get("time"), now=now)
        assertions = _assertion_codes(manifest, all_statuses)
        manifest_sha256 = _sha256_json(manifest, limit=_MAX_REPORT_BYTES)
        receipt_seed = {
            "adapter_version": self._admitted_tool_version(),
            "binding": dict(binding),
            "content_sha256": content_sha256,
            "manifest_sha256": manifest_sha256,
            "operation": operation,
        }
        receipt_id = "c2patool-" + _sha256_json(
            receipt_seed, limit=16 * 1024
        )[:32]
        payload = {
            "schema": ADAPTER_RECEIPT_SCHEMA,
            "operation": operation,
            "adapter_id": self.adapter_id,
            "adapter_version": self._admitted_tool_version(),
            "standard": "c2pa",
            "receipt_id": receipt_id,
            "observed_at": now,
            **dict(binding),
            "content_sha256": content_sha256,
            "manifest_sha256": manifest_sha256,
            "claim_generator": _claim_generator(manifest),
            "signing_time": signing_time,
            "validation_state": validation_state,
            "assertion_codes": list(assertions),
            "trust_chain_state": trust_chain_state,
        }
        payload["receipt_sha256"] = _sha256_json(payload, limit=128 * 1024)
        return payload

    def attest_receipt(
        self, _receipt: Mapping[str, Any], *, binding: C2PABinding
    ) -> Mapping[str, Any]:
        """Fail closed: c2patool cannot authenticate a detached Lightwork envelope."""

        del binding
        raise MediaProvenanceUnavailable(
            "c2patool cannot authenticate a detached Lightwork receipt"
        )


class C2PAToolVerifier(_C2PAToolRuntime):
    """Local, bounded verifier implementing the ``C2PAVerifier`` protocol."""

    def verify(self, media: bytes, *, binding: C2PABinding) -> Mapping[str, Any]:
        try:
            if not isinstance(media, (bytes, bytearray, memoryview)):
                raise MediaProvenanceUnavailable("c2patool media is invalid")
            data = bytes(media)
            if not data or len(data) > _MAX_MEDIA_BYTES:
                raise MediaProvenanceUnavailable("c2patool media exceeds its bound")
            source_sha256 = hashlib.sha256(data).hexdigest()
            binding_data = _binding_payload(binding, source_sha256)
            extension = _media_extension(data, binding_data["media_kind"])
            self._tool()
            anchors = self._trust_anchors()
            with self._workspace() as temporary_name:
                workspace = Path(temporary_name)
                input_path = workspace / f"input{extension}"
                settings_path = workspace / "settings.json"
                trust_path = workspace / "trust-anchors.pem" if anchors is not None else None
                _secure_write(input_path, data)
                _secure_write(settings_path, self._settings())
                if trust_path is not None and anchors is not None:
                    _secure_write(trust_path, anchors)
                verified_executable = self._verified_tool_path()
                report = self._run_report(
                    executable=verified_executable,
                    workspace=workspace,
                    input_path=input_path,
                    settings_path=settings_path,
                    trust_path=trust_path,
                )
                now = float(self._clock())
                if not math.isfinite(now) or now <= 0 or now > 100_000_000_000.0:
                    raise MediaProvenanceUnavailable("c2patool observation time is invalid")
                return self._receipt(
                    report,
                    operation="verification",
                    binding=binding_data,
                    content_sha256=source_sha256,
                    now=now,
                )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise MediaProvenanceUnavailable("c2patool verification is unavailable") from None


class C2PAToolSigner(_C2PAToolRuntime):
    """Local, bounded signer implementing the ``C2PASigner`` protocol."""

    def __init__(
        self,
        *,
        credential_provider: C2PAToolCredentialProvider | None = None,
        manifest_provider: C2PAToolManifestProvider | None = None,
        timestamp_authority_url: str | None = None,
        allow_insecure_timestamp_authority: bool = False,
        **runtime: Any,
    ) -> None:
        super().__init__(**runtime)
        if not isinstance(allow_insecure_timestamp_authority, bool):
            raise TypeError("allow_insecure_timestamp_authority must be boolean")
        self._credential_provider = credential_provider
        self._manifest_provider = manifest_provider
        self._timestamp_authority_url = (
            None
            if timestamp_authority_url is None
            else _timestamp_authority_url(
                timestamp_authority_url,
                allow_insecure=allow_insecure_timestamp_authority,
            )
        )

    def is_available(self) -> bool:
        return (
            callable(self._credential_provider)
            and callable(self._manifest_provider)
            and super().is_available()
        )

    def sign(
        self,
        media: bytes,
        *,
        binding: C2PABinding,
        assertion_codes: Sequence[str],
    ) -> tuple[bytes, Mapping[str, Any]]:
        secret_paths: tuple[Path, ...] = ()
        try:
            if not callable(self._credential_provider) or not callable(
                self._manifest_provider
            ):
                raise MediaProvenanceUnavailable("c2patool signing providers are unavailable")
            if not isinstance(media, (bytes, bytearray, memoryview)):
                raise MediaProvenanceUnavailable("c2patool media is invalid")
            data = bytes(media)
            if not data or len(data) > _MAX_MEDIA_BYTES:
                raise MediaProvenanceUnavailable("c2patool media exceeds its bound")
            source_sha256 = hashlib.sha256(data).hexdigest()
            binding_data = _binding_payload(binding, source_sha256)
            extension = _media_extension(data, binding_data["media_kind"])
            if isinstance(assertion_codes, (str, bytes)) or not isinstance(
                assertion_codes, Sequence
            ):
                raise MediaProvenanceUnavailable("c2patool assertion request is invalid")
            requested = tuple(sorted({_normalize_assertion(item) for item in assertion_codes}))
            if not 1 <= len(requested) <= _MAX_ASSERTIONS or len(requested) != len(
                assertion_codes
            ):
                raise MediaProvenanceUnavailable("c2patool assertion request is invalid")
            self._tool()
            anchors = self._trust_anchors()
            definition = _sanitize_manifest(self._manifest_provider(binding, requested))
            if self._timestamp_authority_url is not None:
                from .enterprise import enterprise_egress_denial

                if enterprise_egress_denial(
                    self._timestamp_authority_url,
                    tool="ai_media_provenance.c2patool.tsa",
                ):
                    raise MediaProvenanceUnavailable(
                        "c2patool timestamp-authority egress is denied"
                    )
                definition["ta_url"] = self._timestamp_authority_url
            credentials = self._credential_provider()
            if not isinstance(credentials, C2PAToolSigningCredentials):
                raise MediaProvenanceUnavailable("c2patool signing credentials are unavailable")
            certificate = _secret_bytes(
                credentials.certificate_chain,
                maximum=_MAX_CERTIFICATE_BYTES,
                kind="certificate chain",
            )
            private_key = _secret_bytes(
                credentials.private_key,
                maximum=_MAX_PRIVATE_KEY_BYTES,
                kind="private key",
            )
            algorithm = str(credentials.algorithm).lower()
            if algorithm not in _SIGNING_ALGORITHMS:
                raise MediaProvenanceUnavailable("c2patool signing algorithm is unsupported")
            if b"-----BEGIN CERTIFICATE-----" not in certificate or b"PRIVATE KEY-----" not in private_key:
                raise MediaProvenanceUnavailable("c2patool signing credentials are invalid")
            with self._workspace() as temporary_name:
                workspace = Path(temporary_name)
                input_path = workspace / f"input{extension}"
                output_path = workspace / f"signed{extension}"
                settings_path = workspace / "settings.json"
                manifest_path = workspace / "manifest.json"
                certificate_path = workspace / "certificate-chain.pem"
                private_key_path = workspace / "private-key.pem"
                trust_path = workspace / "trust-anchors.pem" if anchors is not None else None
                secret_paths = (manifest_path, certificate_path, private_key_path)
                _secure_write(input_path, data)
                _secure_write(certificate_path, certificate)
                _secure_write(private_key_path, private_key)
                if trust_path is not None and anchors is not None:
                    _secure_write(trust_path, anchors)
                _secure_write(settings_path, self._settings())
                definition.update(
                    {
                        "alg": algorithm,
                        # c2patool resolves these relative to the manifest file.
                        # Relative names also avoid embedding a temporary Windows
                        # drive path in a JSON manifest consumed across platforms.
                        "private_key": private_key_path.name,
                        "sign_cert": certificate_path.name,
                    }
                )
                _secure_write(
                    manifest_path,
                    _canonical_json(definition, limit=_MAX_MANIFEST_BYTES),
                )
                verified_executable = self._verified_tool_path()
                report = self._run_report(
                    executable=verified_executable,
                    workspace=workspace,
                    input_path=input_path,
                    settings_path=settings_path,
                    trust_path=None,
                    manifest_path=manifest_path,
                    output_path=output_path,
                )
                signed_media = _read_bounded_regular_file(output_path, _MAX_MEDIA_BYTES)
                content_sha256 = hashlib.sha256(signed_media).hexdigest()
                if content_sha256 == source_sha256:
                    raise MediaProvenanceUnavailable("c2patool did not change the signed asset")
                now = float(self._clock())
                if not math.isfinite(now) or now <= 0 or now > 100_000_000_000.0:
                    raise MediaProvenanceUnavailable("c2patool observation time is invalid")
                receipt = self._receipt(
                    report,
                    operation="signing",
                    binding=binding_data,
                    content_sha256=content_sha256,
                    now=now,
                )
                if not set(requested).issubset(receipt["assertion_codes"]):
                    raise MediaProvenanceUnavailable(
                        "c2patool omitted a requested assertion"
                    )
                _ensure_credentials_not_in_receipt(receipt, certificate, private_key)
                return signed_media, receipt
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise MediaProvenanceUnavailable("c2patool signing is unavailable") from None
        finally:
            for secret_path in secret_paths:
                _erase_file(secret_path)


class C2PAToolExternalSigner(_C2PAToolRuntime):
    """C2PA signer using c2patool's external signer/KMS subprocess seam.

    The fixed, absolute executable is queried by c2patool for its certificate
    and algorithm and receives only claim bytes to sign.  Lightwork never
    receives or writes a private key.  The subprocess is expected to enforce
    its own workload identity, key policy, audit, rate limits, and HSM/KMS
    authorization; those controls are deployment acceptance requirements, not
    properties inferred by this adapter.
    """

    def __init__(
        self,
        *,
        signer_path: str | Path,
        expected_signer_sha256: str,
        manifest_provider: C2PAToolManifestProvider | None = None,
        timestamp_authority_url: str | None = None,
        allow_insecure_timestamp_authority: bool = False,
        **runtime: Any,
    ) -> None:
        super().__init__(**runtime)
        if not isinstance(allow_insecure_timestamp_authority, bool):
            raise TypeError("allow_insecure_timestamp_authority must be boolean")
        candidate = Path(signer_path)
        expected_digest = _expected_sha256(
            expected_signer_sha256,
            "c2patool expected external signer digest",
        )
        resolved, identity = _inspect_pinned_executable(
            candidate,
            expected_sha256=expected_digest,
        )
        self._signer_path = resolved
        self._expected_signer_sha256 = expected_digest
        self._signer_identity = identity
        self._manifest_provider = manifest_provider
        self._timestamp_authority_url = (
            None
            if timestamp_authority_url is None
            else _timestamp_authority_url(
                timestamp_authority_url,
                allow_insecure=allow_insecure_timestamp_authority,
            )
        )

    def is_available(self) -> bool:
        if not callable(self._manifest_provider):
            return False
        try:
            self._verified_signer_path()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False
        return super().is_available()

    def _verified_signer_path(self) -> Path:
        verified, _identity = _inspect_pinned_executable(
            self._signer_path,
            expected_sha256=self._expected_signer_sha256,
            expected_identity=self._signer_identity,
        )
        return verified

    def sign(
        self,
        media: bytes,
        *,
        binding: C2PABinding,
        assertion_codes: Sequence[str],
    ) -> tuple[bytes, Mapping[str, Any]]:
        try:
            if not callable(self._manifest_provider) or not self.is_available():
                raise MediaProvenanceUnavailable(
                    "c2patool external signing providers are unavailable"
                )
            if not isinstance(media, (bytes, bytearray, memoryview)):
                raise MediaProvenanceUnavailable("c2patool media is invalid")
            data = bytes(media)
            if not data or len(data) > _MAX_MEDIA_BYTES:
                raise MediaProvenanceUnavailable("c2patool media exceeds its bound")
            source_sha256 = hashlib.sha256(data).hexdigest()
            binding_data = _binding_payload(binding, source_sha256)
            extension = _media_extension(data, binding_data["media_kind"])
            if isinstance(assertion_codes, (str, bytes)) or not isinstance(
                assertion_codes, Sequence
            ):
                raise MediaProvenanceUnavailable("c2patool assertion request is invalid")
            requested = tuple(
                sorted({_normalize_assertion(item) for item in assertion_codes})
            )
            if not 1 <= len(requested) <= _MAX_ASSERTIONS or len(requested) != len(
                assertion_codes
            ):
                raise MediaProvenanceUnavailable("c2patool assertion request is invalid")
            self._tool()
            definition = _sanitize_manifest(self._manifest_provider(binding, requested))
            if self._timestamp_authority_url is not None:
                from .enterprise import enterprise_egress_denial

                if enterprise_egress_denial(
                    self._timestamp_authority_url,
                    tool="ai_media_provenance.c2patool.tsa",
                ):
                    raise MediaProvenanceUnavailable(
                        "c2patool timestamp-authority egress is denied"
                    )
                definition["ta_url"] = self._timestamp_authority_url
            with self._workspace() as temporary_name:
                workspace = Path(temporary_name)
                input_path = workspace / f"input{extension}"
                output_path = workspace / f"signed{extension}"
                settings_path = workspace / "settings.json"
                manifest_path = workspace / "manifest.json"
                _secure_write(input_path, data)
                _secure_write(settings_path, self._settings())
                _secure_write(
                    manifest_path,
                    _canonical_json(definition, limit=_MAX_MANIFEST_BYTES),
                )
                # Re-hash and identity-check immediately before c2patool is
                # invoked.  Independently recheck the external signer too. The
                # deployment ACL/ownership preflight prevents pathname
                # replacement in the residual cross-process windows.
                verified_signer_path = self._verified_signer_path()
                verified_executable = self._verified_tool_path()
                report = self._run_report(
                    executable=verified_executable,
                    workspace=workspace,
                    input_path=input_path,
                    settings_path=settings_path,
                    trust_path=None,
                    manifest_path=manifest_path,
                    output_path=output_path,
                    signer_path=verified_signer_path,
                )
                signed_media = _read_bounded_regular_file(output_path, _MAX_MEDIA_BYTES)
                content_sha256 = hashlib.sha256(signed_media).hexdigest()
                if content_sha256 == source_sha256:
                    raise MediaProvenanceUnavailable(
                        "c2patool did not change the signed asset"
                    )
                now = float(self._clock())
                if not math.isfinite(now) or now <= 0 or now > 100_000_000_000.0:
                    raise MediaProvenanceUnavailable(
                        "c2patool observation time is invalid"
                    )
                receipt = self._receipt(
                    report,
                    operation="signing",
                    binding=binding_data,
                    content_sha256=content_sha256,
                    now=now,
                )
                if not set(requested).issubset(receipt["assertion_codes"]):
                    raise MediaProvenanceUnavailable(
                        "c2patool omitted a requested assertion"
                    )
                return signed_media, receipt
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise MediaProvenanceUnavailable(
                "c2patool external signing is unavailable"
            ) from None


__all__ = [
    "C2PAToolCredentialProvider",
    "C2PAToolExternalSigner",
    "C2PAToolManifestProvider",
    "C2PAToolProcessResult",
    "C2PAToolProcessRunner",
    "C2PAToolSigner",
    "C2PAToolSigningCredentials",
    "C2PAToolTrustAnchorProvider",
    "C2PAToolVerifier",
]
