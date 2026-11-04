"""Governed mobile and OTT/CTV application-manifest analysis.

This module closes a concrete part of the native-consent discovery gap without
pretending to execute an application or inspect a live device.  A deployment
submits a bounded set of already-extracted manifest files.  The scanner parses
closed Android, Apple, Roku, Tizen and webOS metadata formats in memory, emits
cited permission/privacy/SDK-candidate observations, and persists only
digests and normalized findings.

Raw manifest bytes, permission descriptions and other free-form source values
never enter the durable record.  Findings remain observations until a
different principal reviews the exact application revision and scan digest.
Binary APK AXML, executable inspection, dynamic traffic, IDFA state and native
runtime behavior are deliberately not inferred from manifest metadata.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import plistlib
import re
import threading
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from .governed_records import GovernedMutationFence, GovernedRecordStore
from .privacy_ops import AuditOutboxError, RecordConflict

APPLICATION_SCHEMA = "lightwork.consent-application.v1"
SCAN_SCHEMA = "lightwork.consent-application-scan.v1"
RESULT_SCHEMA = "lightwork.consent-application-manifest-result.v1"
TOMBSTONE_SCHEMA = "lightwork.consent-application-scan-tombstone.v1"

_APPLICATIONS = GovernedRecordStore(
    "consent_applications",
    "CAP",
    "consent_application",
)
_SCANS = GovernedRecordStore(
    "consent_application_scans",
    "CAS",
    "consent_application_scan",
)

_PLATFORMS = frozenset({"android", "fireos", "ios", "tvos", "roku", "tizen", "webos"})
_APPLICATION_STATES = frozenset({"active", "revoked"})
_SCAN_STATES = frozenset({"pending_review", "accepted", "needs_changes", "rejected", "purged"})
_REVIEW_DECISIONS = frozenset({"accepted", "needs_changes", "rejected"})
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_BUNDLE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_PATH_SEGMENT_RE = re.compile(r"[^/\\\x00-\x1f\x7f]{1,255}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|"
    r"\bsk-[A-Za-z0-9_-]{16,}|"
    r"\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE,
)

_MAX_FILES = 64
_MAX_FILE_BYTES = 1_048_576
_MAX_TOTAL_BYTES = 4_194_304
_MAX_JSON_BYTES = 1_048_576
_MAX_XML_NODES = 20_000
_MAX_XML_DEPTH = 32
_MAX_TREE_NODES = 20_000
_MAX_TREE_DEPTH = 32
_MAX_FINDINGS = 2_000
_MAX_DEPENDENCIES = 500
_MAX_RECORDS = 25_000
_MAX_LIST = 500
_DEFAULT_RETENTION_SECONDS = 31_536_000

_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_TIZEN_NS = "http://tizen.org/ns/widgets"

_ANDROID_PERMISSION_CATEGORIES = {
    "android.permission.ACCESS_BACKGROUND_LOCATION": "precise_location",
    "android.permission.ACCESS_COARSE_LOCATION": "location",
    "android.permission.ACCESS_FINE_LOCATION": "precise_location",
    "android.permission.BLUETOOTH_CONNECT": "nearby_devices",
    "android.permission.BLUETOOTH_SCAN": "nearby_devices",
    "android.permission.CAMERA": "camera",
    "android.permission.GET_ACCOUNTS": "account_identity",
    "android.permission.POST_NOTIFICATIONS": "communications",
    "android.permission.READ_CALENDAR": "calendar",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.READ_MEDIA_AUDIO": "media",
    "android.permission.READ_MEDIA_IMAGES": "media",
    "android.permission.READ_MEDIA_VIDEO": "media",
    "android.permission.READ_PHONE_STATE": "device_identity",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.SEND_SMS": "communications",
    "android.permission.WRITE_CALENDAR": "calendar",
    "com.google.android.gms.permission.AD_ID": "advertising_identifier",
}

_APPLE_PERMISSION_KEYS = {
    "NSBluetoothAlwaysUsageDescription": "nearby_devices",
    "NSCalendarsUsageDescription": "calendar",
    "NSCameraUsageDescription": "camera",
    "NSContactsUsageDescription": "contacts",
    "NSHealthShareUsageDescription": "health",
    "NSHealthUpdateUsageDescription": "health",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "precise_location",
    "NSLocationWhenInUseUsageDescription": "location",
    "NSMicrophoneUsageDescription": "microphone",
    "NSMotionUsageDescription": "motion",
    "NSPhotoLibraryAddUsageDescription": "media",
    "NSPhotoLibraryUsageDescription": "media",
    "NSUserTrackingUsageDescription": "tracking_authorization",
}

_KNOWN_SDK_PREFIXES = {
    "com.adjust": "Adjust",
    "com.appsflyer": "AppsFlyer",
    "com.facebook": "Meta",
    "com.google.android.gms.ads": "Google Mobile Ads",
    "com.google.firebase.analytics": "Firebase Analytics",
    "com.segment": "Segment",
    "com.onesignal": "OneSignal",
    "adjust": "Adjust",
    "appsflyer": "AppsFlyer",
    "facebook": "Meta",
    "firebase-analytics": "Firebase Analytics",
    "google-mobile-ads": "Google Mobile Ads",
    "onesignal": "OneSignal",
    "segment": "Segment",
    "raf": "Roku Advertising Framework",
}


class ConsentApplicationScanError(RuntimeError):
    """Base application-scanner failure."""


class ConsentApplicationScanValidationError(ConsentApplicationScanError, ValueError):
    """Input is malformed, ambiguous or exceeds a closed bound."""


class ConsentApplicationScanNotFound(ConsentApplicationScanError):
    """A tenant-scoped application or scan is unavailable."""


class ConsentApplicationScanConflict(ConsentApplicationScanError):
    """CAS, idempotency or pinned authority changed."""


class ConsentApplicationScanIntegrityError(ConsentApplicationScanError):
    """A durable application or scan record failed integrity validation."""


@dataclass(frozen=True)
class ManifestFile:
    """One transient, already-extracted manifest artifact."""

    path: str
    content: bytes
    media_type: str = "application/octet-stream"


class _DuplicateManifestKeyError(ValueError):
    """A structured manifest used an ambiguous duplicate object key."""


class _UniquePlistDict(dict[str, Any]):
    """plistlib mapping that rejects last-key-wins parser ambiguity."""

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self:
            raise _DuplicateManifestKeyError("plist contains a duplicate key")
        super().__setitem__(key, value)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise _DuplicateManifestKeyError("JSON contains a duplicate key")
        output[key] = value
    return output


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ConsentApplicationScanValidationError(
            "application scan data must be finite JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise ConsentApplicationScanValidationError("application scan data exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text(value: object, label: str, limit: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        if value is None and not required:
            return ""
        raise ConsentApplicationScanValidationError(f"{label} must be text")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if required and not normalized:
        raise ConsentApplicationScanValidationError(f"{label} is required")
    if len(normalized) > limit:
        raise ConsentApplicationScanValidationError(f"{label} exceeds {limit} characters")
    if _CONTROL_RE.search(normalized):
        raise ConsentApplicationScanValidationError(f"{label} contains control characters")
    if _SECRET_RE.search(normalized):
        raise ConsentApplicationScanValidationError(f"{label} appears to contain a secret")
    return normalized


def _choice(value: object, label: str, allowed: frozenset[str]) -> str:
    normalized = _text(value, label, 64).lower()
    if normalized not in allowed:
        raise ConsentApplicationScanValidationError(
            f"{label} must be one of {', '.join(sorted(allowed))}"
        )
    return normalized


def _ref(value: object, label: str) -> str:
    normalized = _text(value, label, 192)
    if not _REF_RE.fullmatch(normalized):
        raise ConsentApplicationScanValidationError(f"{label} must be an opaque identifier")
    return normalized


def _bundle_id(value: object) -> str:
    normalized = _text(value, "bundle_id", 255)
    if _BUNDLE_RE.fullmatch(normalized):
        return normalized
    try:
        parsed = urlparse(normalized)
        port = parsed.port
    except ValueError as exc:
        raise ConsentApplicationScanValidationError("bundle_id is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.params
    ):
        raise ConsentApplicationScanValidationError("bundle_id is invalid")
    host = parsed.hostname.lower().rstrip(".")
    netloc = host if port is None or port == 443 else f"{host}:{port}"
    return urlunparse(("https", netloc, parsed.path or "/", "", "", ""))


def _revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise ConsentApplicationScanValidationError(
            "expected_revision must be a non-negative integer"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConsentApplicationScanValidationError(f"{label} must be a timestamp")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 < normalized < 100_000_000_000.0:
        raise ConsentApplicationScanValidationError(f"{label} must be a finite timestamp")
    return normalized


def _path(value: object) -> str:
    normalized = unicodedata.normalize("NFKC", _text(value, "manifest path", 1_024))
    if "\\" in normalized or normalized.startswith("/") or normalized.endswith("/"):
        raise ConsentApplicationScanValidationError("manifest path must be a relative POSIX path")
    segments = normalized.split("/")
    if any(
        segment in {"", ".", ".."} or not _SAFE_PATH_SEGMENT_RE.fullmatch(segment)
        for segment in segments
    ):
        raise ConsentApplicationScanValidationError("manifest path is unsafe")
    return "/".join(segments)


def _manifest_files(files: Sequence[ManifestFile]) -> list[ManifestFile]:
    if isinstance(files, (str, bytes, bytearray)) or not isinstance(files, Sequence):
        raise ConsentApplicationScanValidationError("files must be an array")
    if not 1 <= len(files) <= _MAX_FILES:
        raise ConsentApplicationScanValidationError(
            f"files must contain between 1 and {_MAX_FILES} artifacts"
        )
    output: list[ManifestFile] = []
    seen: set[str] = set()
    total = 0
    for item in files:
        if not isinstance(item, ManifestFile):
            raise ConsentApplicationScanValidationError("files must contain ManifestFile values")
        path = _path(item.path)
        if path.casefold() in seen:
            raise ConsentApplicationScanValidationError("manifest paths must be unique")
        seen.add(path.casefold())
        if not isinstance(item.content, bytes) or not 1 <= len(item.content) <= _MAX_FILE_BYTES:
            raise ConsentApplicationScanValidationError(
                f"manifest file bytes must be between 1 and {_MAX_FILE_BYTES}"
            )
        media_type = _text(item.media_type, "media_type", 128).lower()
        total += len(item.content)
        if total > _MAX_TOTAL_BYTES:
            raise ConsentApplicationScanValidationError("manifest bundle exceeds 4 MiB")
        output.append(ManifestFile(path=path, content=item.content, media_type=media_type))
    return sorted(output, key=lambda item: item.path.casefold())


def _safe_xml(content: bytes, label: str) -> ET.Element:
    # The source artifact is already capped at 1 MiB. Scan all of it before
    # handing bytes to Expat so a declaration cannot be hidden behind a long
    # whitespace/comment prefix and expanded during parsing.
    lowered = content.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ConsentApplicationScanValidationError(f"{label} contains a forbidden DTD/entity")
    stripped = content.lstrip()
    if not stripped.startswith(b"<"):
        raise ConsentApplicationScanValidationError(
            f"{label} must be extracted text XML; binary application manifests are unsupported"
        )
    try:
        root = ET.fromstring(content)
    except (ET.ParseError, UnicodeError, ValueError) as exc:
        raise ConsentApplicationScanValidationError(f"{label} is invalid XML") from exc
    stack: list[tuple[ET.Element, int]] = [(root, 1)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_XML_NODES or depth > _MAX_XML_DEPTH:
            raise ConsentApplicationScanValidationError(f"{label} exceeds XML bounds")
        if len(node.attrib) > 128:
            raise ConsentApplicationScanValidationError(f"{label} has too many XML attributes")
        for key, value in node.attrib.items():
            if len(str(key)) > 512 or len(str(value)) > 4_096:
                raise ConsentApplicationScanValidationError(f"{label} XML attributes exceed bounds")
        stack.extend((child, depth + 1) for child in list(node))
    return root


def _bounded_tree(value: object, label: str) -> Any:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_TREE_NODES or depth > _MAX_TREE_DEPTH:
            raise ConsentApplicationScanValidationError(f"{label} exceeds tree bounds")
        if isinstance(current, Mapping):
            if len(current) > 2_000:
                raise ConsentApplicationScanValidationError(f"{label} object exceeds bounds")
            for key, item in current.items():
                if not isinstance(key, str) or len(key) > 512:
                    raise ConsentApplicationScanValidationError(f"{label} contains an invalid key")
                stack.append((item, depth + 1))
        elif isinstance(current, (list, tuple)):
            if len(current) > 5_000:
                raise ConsentApplicationScanValidationError(f"{label} array exceeds bounds")
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            if len(current) > 16_384 or _SECRET_RE.search(current):
                raise ConsentApplicationScanValidationError(
                    f"{label} contains oversized or secret-like text"
                )
        elif isinstance(current, float) and not math.isfinite(current):
            raise ConsentApplicationScanValidationError(f"{label} contains a non-finite number")
        elif (
            isinstance(current, int)
            and not isinstance(current, bool)
            and current.bit_length() > 4_096
        ):
            raise ConsentApplicationScanValidationError(f"{label} contains an oversized integer")
        elif isinstance(current, bytes) and len(current) > 16_384:
            raise ConsentApplicationScanValidationError(f"{label} contains oversized binary data")
        elif current is not None and not isinstance(current, (bool, int, float, bytes)):
            raise ConsentApplicationScanValidationError(f"{label} contains an unsupported value")
    return value


def _safe_plist(content: bytes, label: str) -> Mapping[str, Any]:
    stripped = content.lstrip()
    if stripped.startswith(b"<"):
        lowered = content.lower()
        # plistlib accepts Apple's standard external DTD declaration but has an
        # EntityDeclHandler that rejects actual entity declarations. Keep the
        # standard format compatible while rejecting entity payloads up front.
        if b"<!entity" in lowered:
            raise ConsentApplicationScanValidationError(f"{label} contains a forbidden entity")
    try:
        parsed = plistlib.loads(content, fmt=None, dict_type=_UniquePlistDict)
    except _DuplicateManifestKeyError as exc:
        raise ConsentApplicationScanValidationError(f"{label} contains duplicate keys") from exc
    except (plistlib.InvalidFileException, OverflowError, TypeError, ValueError) as exc:
        raise ConsentApplicationScanValidationError(f"{label} is invalid plist data") from exc
    if not isinstance(parsed, Mapping):
        raise ConsentApplicationScanValidationError(f"{label} root must be an object")
    return _bounded_tree(parsed, label)


def _safe_json(content: bytes, label: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except _DuplicateManifestKeyError as exc:
        raise ConsentApplicationScanValidationError(f"{label} contains duplicate keys") from exc
    except (OverflowError, UnicodeError, ValueError) as exc:
        raise ConsentApplicationScanValidationError(f"{label} is invalid UTF-8 JSON") from exc
    if not isinstance(parsed, Mapping):
        raise ConsentApplicationScanValidationError(f"{label} root must be an object")
    return _bounded_tree(parsed, label)


def _local_name(tag: object) -> str:
    value = str(tag)
    return value.rsplit("}", 1)[-1]


def _citation(path: str, file_sha256: str, selector: str) -> dict[str, str]:
    return {
        "path": path,
        "file_sha256": file_sha256,
        "selector": _text(selector, "citation selector", 512),
    }


def _append_bounded(target: list[dict[str, Any]], value: dict[str, Any]) -> None:
    if len(target) >= _MAX_FINDINGS:
        raise ConsentApplicationScanValidationError("application findings exceed their bound")
    target.append(value)


def _sdk_candidate(name: str, version: str, citation: Mapping[str, str]) -> dict[str, Any]:
    normalized_name = _text(name, "dependency name", 255)
    normalized_version = _text(version, "dependency version", 128, required=False)
    folded = normalized_name.casefold()
    vendor = ""
    for prefix, candidate_vendor in _KNOWN_SDK_PREFIXES.items():
        if folded == prefix or folded.startswith(f"{prefix}.") or folded.startswith(f"{prefix}/"):
            vendor = candidate_vendor
            break
    return {
        "name": normalized_name,
        "name_sha256": _text_sha256(normalized_name),
        "version": normalized_version,
        "vendor_hint": vendor,
        "classification": "unreviewed_sdk_candidate",
        "citation": dict(citation),
    }


def _parse_android(
    file: ManifestFile,
    *,
    permissions: list[dict[str, Any]],
    sdk_candidates: list[dict[str, Any]],
    identities: dict[str, str],
    signals: dict[str, Any],
) -> None:
    root = _safe_xml(file.content, "AndroidManifest.xml")
    if root.tag != "manifest":
        raise ConsentApplicationScanValidationError("AndroidManifest.xml root must be manifest")
    digest = _bytes_sha256(file.content)
    package_name = str(root.attrib.get("package") or "").strip()
    if package_name:
        identities["bundle_id"] = _bundle_id(package_name)
    android_name = f"{{{_ANDROID_NS}}}name"
    android_target = f"{{{_ANDROID_NS}}}targetSdkVersion"
    android_minimum = f"{{{_ANDROID_NS}}}minSdkVersion"
    component_names: set[str] = set()
    for node in root.iter():
        # Android structural elements are unnamespaced. Accepting a matching
        # local name from an attacker-selected namespace would turn unrelated
        # XML into an authoritative permission observation.
        kind = node.tag if isinstance(node.tag, str) and "}" not in node.tag else ""
        if kind in {"uses-permission", "uses-permission-sdk-23", "permission"}:
            name = str(node.attrib.get(android_name) or "").strip()
            if name:
                normalized = _text(name, "Android permission", 255)
                _append_bounded(
                    permissions,
                    {
                        "permission": normalized,
                        "category": _ANDROID_PERMISSION_CATEGORIES.get(normalized, "other"),
                        "citation": _citation(
                            file.path, digest, f"{kind}[@android:name='{normalized}']"
                        ),
                    },
                )
                if normalized == "com.google.android.gms.permission.AD_ID":
                    signals["advertising_identifier_declared"] = True
        elif kind == "uses-sdk":
            if node.attrib.get(android_minimum):
                identities["minimum_platform_version"] = _text(
                    node.attrib[android_minimum], "minimum SDK", 64
                )
            if node.attrib.get(android_target):
                identities["target_platform_version"] = _text(
                    node.attrib[android_target], "target SDK", 64
                )
        elif kind in {"activity", "activity-alias", "service", "receiver", "provider"}:
            name = str(node.attrib.get(android_name) or "").strip()
            if name and name not in component_names:
                component_names.add(name)
                candidate = _sdk_candidate(
                    name,
                    "",
                    _citation(file.path, digest, f"{kind}[@android:name]"),
                )
                if candidate["vendor_hint"]:
                    _append_bounded(sdk_candidates, candidate)


def _parse_apple_info(
    file: ManifestFile,
    *,
    permissions: list[dict[str, Any]],
    identities: dict[str, str],
    signals: dict[str, Any],
) -> None:
    data = _safe_plist(file.content, "Info.plist")
    digest = _bytes_sha256(file.content)
    bundle = data.get("CFBundleIdentifier")
    if isinstance(bundle, str) and bundle.strip():
        identities["bundle_id"] = _bundle_id(bundle)
    version = data.get("CFBundleShortVersionString")
    if isinstance(version, str) and version.strip():
        identities["application_version"] = _text(version, "application version", 128)
    for key, category in _APPLE_PERMISSION_KEYS.items():
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            _append_bounded(
                permissions,
                {
                    "permission": key,
                    "category": category,
                    "description_sha256": _text_sha256(value.strip()),
                    "citation": _citation(file.path, digest, key),
                },
            )
            if key == "NSUserTrackingUsageDescription":
                signals["tracking_authorization_description_declared"] = True
    sk_items = data.get("SKAdNetworkItems")
    if isinstance(sk_items, list):
        signals["skadnetwork_identifier_count"] = min(len(sk_items), 10_000)


def _parse_apple_privacy(
    file: ManifestFile,
    *,
    data_types: list[dict[str, Any]],
    api_reasons: list[dict[str, Any]],
    signals: dict[str, Any],
) -> None:
    data = _safe_plist(file.content, "PrivacyInfo.xcprivacy")
    digest = _bytes_sha256(file.content)
    tracking = data.get("NSPrivacyTracking")
    if tracking is not None and not isinstance(tracking, bool):
        raise ConsentApplicationScanValidationError("NSPrivacyTracking must be boolean")
    signals["tracking_declared"] = bool(tracking)
    domains = data.get("NSPrivacyTrackingDomains", [])
    if not isinstance(domains, list) or len(domains) > 1_000:
        raise ConsentApplicationScanValidationError("NSPrivacyTrackingDomains must be bounded")
    domain_digests: list[str] = []
    for domain in domains:
        normalized = _text(domain, "tracking domain", 253).lower()
        domain_digests.append(_text_sha256(normalized))
    signals["tracking_domain_sha256"] = sorted(set(domain_digests))

    collected = data.get("NSPrivacyCollectedDataTypes", [])
    if not isinstance(collected, list) or len(collected) > 1_000:
        raise ConsentApplicationScanValidationError("NSPrivacyCollectedDataTypes must be bounded")
    for index, entry in enumerate(collected):
        if not isinstance(entry, Mapping):
            raise ConsentApplicationScanValidationError("collected data entries must be objects")
        data_type = _text(entry.get("NSPrivacyCollectedDataType"), "privacy data type", 255)
        linked = entry.get("NSPrivacyCollectedDataTypeLinked")
        used_tracking = entry.get("NSPrivacyCollectedDataTypeTracking")
        if not isinstance(linked, bool) or not isinstance(used_tracking, bool):
            raise ConsentApplicationScanValidationError("privacy data flags must be boolean")
        purposes = entry.get("NSPrivacyCollectedDataTypePurposes", [])
        if not isinstance(purposes, list) or len(purposes) > 128:
            raise ConsentApplicationScanValidationError("privacy data purposes must be bounded")
        normalized_purposes = sorted({_text(item, "privacy purpose", 255) for item in purposes})
        _append_bounded(
            data_types,
            {
                "data_type": data_type,
                "linked_to_identity": linked,
                "used_for_tracking": used_tracking,
                "purposes": normalized_purposes,
                "citation": _citation(
                    file.path,
                    digest,
                    f"NSPrivacyCollectedDataTypes[{index}]",
                ),
            },
        )

    accessed = data.get("NSPrivacyAccessedAPITypes", [])
    if not isinstance(accessed, list) or len(accessed) > 1_000:
        raise ConsentApplicationScanValidationError("NSPrivacyAccessedAPITypes must be bounded")
    for index, entry in enumerate(accessed):
        if not isinstance(entry, Mapping):
            raise ConsentApplicationScanValidationError("accessed API entries must be objects")
        api_type = _text(entry.get("NSPrivacyAccessedAPIType"), "privacy API type", 255)
        reasons = entry.get("NSPrivacyAccessedAPITypeReasons", [])
        if not isinstance(reasons, list) or len(reasons) > 128:
            raise ConsentApplicationScanValidationError("privacy API reasons must be bounded")
        _append_bounded(
            api_reasons,
            {
                "api_type": api_type,
                "reason_codes": sorted(
                    {_text(item, "privacy reason code", 64) for item in reasons}
                ),
                "citation": _citation(file.path, digest, f"NSPrivacyAccessedAPITypes[{index}]"),
            },
        )


def _parse_tizen(
    file: ManifestFile,
    *,
    permissions: list[dict[str, Any]],
    identities: dict[str, str],
) -> None:
    root = _safe_xml(file.content, "Tizen config.xml")
    if _local_name(root.tag) != "widget":
        raise ConsentApplicationScanValidationError("Tizen config.xml root must be widget")
    digest = _bytes_sha256(file.content)
    widget_id = str(root.attrib.get("id") or "").strip()
    if widget_id:
        identities["bundle_id"] = _bundle_id(widget_id)
    for node in root.iter():
        if node.tag != f"{{{_TIZEN_NS}}}privilege":
            continue
        name = str(node.attrib.get("name") or "").strip()
        if name:
            normalized = _text(name, "Tizen privilege", 255)
            _append_bounded(
                permissions,
                {
                    "permission": normalized,
                    "category": "platform_privilege",
                    "citation": _citation(file.path, digest, "tizen:privilege[@name]"),
                },
            )


def _parse_webos(
    file: ManifestFile,
    *,
    permissions: list[dict[str, Any]],
    identities: dict[str, str],
) -> None:
    data = _safe_json(file.content, "webOS appinfo.json")
    digest = _bytes_sha256(file.content)
    bundle = data.get("id")
    if isinstance(bundle, str) and bundle.strip():
        identities["bundle_id"] = _bundle_id(bundle)
    version = data.get("version")
    if isinstance(version, str) and version.strip():
        identities["application_version"] = _text(version, "application version", 128)
    permissions_value = data.get("requiredPermissions", data.get("permissions", []))
    if permissions_value is None:
        permissions_value = []
    if not isinstance(permissions_value, list) or len(permissions_value) > 1_000:
        raise ConsentApplicationScanValidationError("webOS permissions must be bounded")
    for index, permission in enumerate(permissions_value):
        normalized = _text(permission, "webOS permission", 255)
        _append_bounded(
            permissions,
            {
                "permission": normalized,
                "category": "platform_permission",
                "citation": _citation(file.path, digest, f"permissions[{index}]"),
            },
        )


def _parse_roku(
    file: ManifestFile,
    *,
    identities: dict[str, str],
    signals: dict[str, Any],
) -> None:
    try:
        text = file.content.decode("utf-8")
    except UnicodeError as exc:
        raise ConsentApplicationScanValidationError("Roku manifest must be UTF-8") from exc
    if len(text.splitlines()) > 2_000:
        raise ConsentApplicationScanValidationError("Roku manifest exceeds line bounds")
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConsentApplicationScanValidationError("Roku manifest line is invalid")
        key, raw_value = line.split("=", 1)
        normalized_key = _text(key, "Roku manifest key", 128)
        normalized_value = _text(raw_value, "Roku manifest value", 1_024, required=False)
        if normalized_key in values:
            raise ConsentApplicationScanValidationError("Roku manifest contains duplicate keys")
        values[normalized_key] = normalized_value
    for candidate in ("id", "channel_id", "bs_const_channel_id"):
        if values.get(candidate):
            identities["bundle_id"] = _bundle_id(values[candidate])
            break
    versions = [values.get(key, "") for key in ("major_version", "minor_version", "build_version")]
    if any(versions):
        identities["application_version"] = ".".join(value or "0" for value in versions)
    signals["roku_manifest_key_sha256"] = sorted(_text_sha256(key) for key in values)


def _parse_dependencies(file: ManifestFile, sdk_candidates: list[dict[str, Any]]) -> None:
    data = _safe_json(file.content, "dependencies.json")
    entries = data.get("dependencies")
    if not isinstance(entries, list) or len(entries) > _MAX_DEPENDENCIES:
        raise ConsentApplicationScanValidationError("dependencies must be a bounded array")
    digest = _bytes_sha256(file.content)
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or set(entry) - {"name", "version", "source"}:
            raise ConsentApplicationScanValidationError("dependency entries use a closed schema")
        name = _text(entry.get("name"), "dependency name", 255)
        folded = name.casefold()
        if folded in seen:
            raise ConsentApplicationScanValidationError("dependency names must be unique")
        seen.add(folded)
        version = _text(entry.get("version", ""), "dependency version", 128, required=False)
        source = _text(entry.get("source", "manifest"), "dependency source", 64).lower()
        if source not in {"manifest", "lockfile", "build_inventory", "manual_attestation"}:
            raise ConsentApplicationScanValidationError("dependency source is unsupported")
        candidate = _sdk_candidate(
            name,
            version,
            _citation(file.path, digest, f"dependencies[{index}]"),
        )
        candidate["source"] = source
        _append_bounded(sdk_candidates, candidate)


def scan_manifest_bundle(
    platform: str,
    files: Sequence[ManifestFile],
    *,
    expected_bundle_id: str | None = None,
) -> dict[str, Any]:
    """Parse one bounded manifest bundle without persisting source content."""

    normalized_platform = _choice(platform, "platform", _PLATFORMS)
    normalized_files = _manifest_files(files)
    expected = _bundle_id(expected_bundle_id) if expected_bundle_id is not None else ""
    permissions: list[dict[str, Any]] = []
    data_types: list[dict[str, Any]] = []
    api_reasons: list[dict[str, Any]] = []
    sdk_candidates: list[dict[str, Any]] = []
    identities: dict[str, str] = {}
    signals: dict[str, Any] = {
        "advertising_identifier_declared": False,
        "tracking_authorization_description_declared": False,
        "tracking_declared": False,
        "tracking_domain_sha256": [],
    }
    parsed_paths: list[str] = []
    unsupported: list[dict[str, Any]] = []
    basenames: dict[str, ManifestFile] = {}
    for file in normalized_files:
        basename = file.path.rsplit("/", 1)[-1].casefold()
        if basename in basenames:
            raise ConsentApplicationScanValidationError(
                f"manifest bundle contains ambiguous duplicate {basename}"
            )
        basenames[basename] = file

    for file in normalized_files:
        basename = file.path.rsplit("/", 1)[-1].casefold()
        if basename == "androidmanifest.xml" and normalized_platform in {"android", "fireos"}:
            _parse_android(
                file,
                permissions=permissions,
                sdk_candidates=sdk_candidates,
                identities=identities,
                signals=signals,
            )
        elif basename == "info.plist" and normalized_platform in {"ios", "tvos"}:
            _parse_apple_info(
                file,
                permissions=permissions,
                identities=identities,
                signals=signals,
            )
        elif basename == "privacyinfo.xcprivacy" and normalized_platform in {"ios", "tvos"}:
            _parse_apple_privacy(
                file,
                data_types=data_types,
                api_reasons=api_reasons,
                signals=signals,
            )
        elif basename == "config.xml" and normalized_platform == "tizen":
            _parse_tizen(file, permissions=permissions, identities=identities)
        elif basename == "appinfo.json" and normalized_platform == "webos":
            _parse_webos(file, permissions=permissions, identities=identities)
        elif basename == "manifest" and normalized_platform == "roku":
            _parse_roku(file, identities=identities, signals=signals)
        elif basename == "dependencies.json":
            _parse_dependencies(file, sdk_candidates)
        else:
            unsupported.append(
                {
                    "path": file.path,
                    "file_sha256": _bytes_sha256(file.content),
                    "bytes": len(file.content),
                    "reason": "unsupported_for_selected_platform",
                }
            )
            continue
        parsed_paths.append(file.path)

    required: set[str]
    if normalized_platform in {"android", "fireos"}:
        required = {"androidmanifest.xml"}
    elif normalized_platform in {"ios", "tvos"}:
        required = {"info.plist", "privacyinfo.xcprivacy"}
    elif normalized_platform == "tizen":
        required = {"config.xml"}
    elif normalized_platform == "webos":
        required = {"appinfo.json"}
    else:
        required = {"manifest"}
    present = set(basenames)
    missing = sorted(required - present)
    observed_bundle = identities.get("bundle_id", "")
    if expected and observed_bundle and expected != observed_bundle:
        raise ConsentApplicationScanConflict(
            "manifest bundle identifier does not match registered application"
        )
    if expected and not observed_bundle:
        raise ConsentApplicationScanValidationError(
            "required manifest did not expose the registered bundle identifier"
        )

    file_manifest = [
        {
            "path": file.path,
            "media_type": file.media_type,
            "bytes": len(file.content),
            "file_sha256": _bytes_sha256(file.content),
        }
        for file in normalized_files
    ]
    artifact_sha256 = _sha256(file_manifest)
    permissions.sort(key=lambda value: (value["permission"], value["citation"]["path"]))
    data_types.sort(key=lambda value: (value["data_type"], value["citation"]["path"]))
    api_reasons.sort(key=lambda value: (value["api_type"], value["citation"]["path"]))
    sdk_candidates.sort(key=lambda value: (value["name"].casefold(), value["citation"]["path"]))
    result = {
        "schema": RESULT_SCHEMA,
        "platform": normalized_platform,
        "artifact_sha256": artifact_sha256,
        "file_manifest": file_manifest,
        "identities": identities,
        "permissions": permissions,
        "privacy_data_types": data_types,
        "required_reason_apis": api_reasons,
        "sdk_candidates": sdk_candidates,
        "signals": signals,
        "completeness": {
            "complete": not missing,
            "required_basenames": sorted(required),
            "missing_basenames": missing,
            "parsed_paths": sorted(parsed_paths),
            "unsupported_files": unsupported,
            "source_file_count": len(normalized_files),
            "source_bytes": sum(len(file.content) for file in normalized_files),
            "dynamic_runtime_observed": False,
            "compiled_binary_inspected": False,
        },
        "limitations": [
            "manifest_observations_only",
            "no_dynamic_device_or_network_observation",
            "no_sdk_tracker_or_legal_classification",
            "no_binary_apk_axml_or_executable_analysis",
            "no_idfa_permission_state_observation",
        ],
    }
    result["result_sha256"] = _sha256(result)
    _canonical(result)
    return result


def _record_digest(record: Mapping[str, Any], *, exclude: frozenset[str]) -> str:
    return _sha256({key: value for key, value in record.items() if key not in exclude})


_STORE_FIELDS = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})


def _stored_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ConsentApplicationScanIntegrityError(f"stored {label} is invalid")
    return value


def _stored_timestamp(value: object, label: str) -> float:
    try:
        return _timestamp(value, label)
    except ConsentApplicationScanValidationError as exc:
        raise ConsentApplicationScanIntegrityError(str(exc)) from exc


def _closed_stored_fields(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    label: str,
) -> None:
    if set(value) - allowed:
        raise ConsentApplicationScanIntegrityError(f"stored {label} fields are invalid")


def _validate_result(result: object) -> dict[str, Any]:
    if not isinstance(result, Mapping) or result.get("schema") != RESULT_SCHEMA:
        raise ConsentApplicationScanIntegrityError("stored scan result is invalid")
    value = dict(result)
    _closed_stored_fields(
        value,
        frozenset(
            {
                "schema",
                "platform",
                "artifact_sha256",
                "file_manifest",
                "identities",
                "permissions",
                "privacy_data_types",
                "required_reason_apis",
                "sdk_candidates",
                "signals",
                "completeness",
                "limitations",
                "result_sha256",
            }
        ),
        "scan result",
    )
    try:
        _choice(value.get("platform"), "platform", _PLATFORMS)
        _canonical(value)
    except ConsentApplicationScanValidationError as exc:
        raise ConsentApplicationScanIntegrityError(str(exc)) from exc
    artifact_digest = _stored_digest(value.get("artifact_sha256"), "artifact digest")
    file_manifest = value.get("file_manifest")
    if not isinstance(file_manifest, list) or not 1 <= len(file_manifest) <= _MAX_FILES:
        raise ConsentApplicationScanIntegrityError("stored scan file manifest is invalid")
    normalized_files: list[dict[str, Any]] = []
    total = 0
    seen: set[str] = set()
    for entry in file_manifest:
        if not isinstance(entry, Mapping):
            raise ConsentApplicationScanIntegrityError("stored scan file manifest is invalid")
        item = dict(entry)
        _closed_stored_fields(
            item,
            frozenset({"path", "media_type", "bytes", "file_sha256"}),
            "scan file manifest",
        )
        try:
            path = _path(item.get("path"))
            media_type = _text(item.get("media_type"), "media_type", 128).lower()
        except ConsentApplicationScanValidationError as exc:
            raise ConsentApplicationScanIntegrityError(str(exc)) from exc
        if path.casefold() in seen:
            raise ConsentApplicationScanIntegrityError("stored scan file paths are ambiguous")
        seen.add(path.casefold())
        size = item.get("bytes")
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= _MAX_FILE_BYTES:
            raise ConsentApplicationScanIntegrityError("stored scan file size is invalid")
        total += size
        if total > _MAX_TOTAL_BYTES:
            raise ConsentApplicationScanIntegrityError("stored scan file total is invalid")
        normalized_files.append(
            {
                "path": path,
                "media_type": media_type,
                "bytes": size,
                "file_sha256": _stored_digest(item.get("file_sha256"), "file digest"),
            }
        )
    if not hmac.compare_digest(artifact_digest, _sha256(normalized_files)):
        raise ConsentApplicationScanIntegrityError("stored scan artifact digest mismatch")
    for field in (
        "permissions",
        "privacy_data_types",
        "required_reason_apis",
        "sdk_candidates",
    ):
        findings = value.get(field)
        if not isinstance(findings, list) or len(findings) > _MAX_FINDINGS:
            raise ConsentApplicationScanIntegrityError("stored scan findings are invalid")
    for field in ("identities", "signals", "completeness"):
        if not isinstance(value.get(field), Mapping):
            raise ConsentApplicationScanIntegrityError("stored scan result structure is invalid")
    limitations = value.get("limitations")
    if (
        not isinstance(limitations, list)
        or len(limitations) > 32
        or any(not isinstance(item, str) or len(item) > 128 for item in limitations)
    ):
        raise ConsentApplicationScanIntegrityError("stored scan limitations are invalid")
    if type(value["completeness"].get("complete")) is not bool:
        raise ConsentApplicationScanIntegrityError("stored scan completeness is invalid")
    result_digest = _stored_digest(value.get("result_sha256"), "result digest")
    expected_result = _sha256({key: item for key, item in value.items() if key != "result_sha256"})
    if not hmac.compare_digest(result_digest, expected_result):
        raise ConsentApplicationScanIntegrityError("stored scan result digest mismatch")
    return value


def _validate_application(record: object) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise ConsentApplicationScanIntegrityError("stored application is invalid")
    value = dict(record)
    if value.get("schema") != APPLICATION_SCHEMA:
        raise ConsentApplicationScanIntegrityError("stored application schema is invalid")
    _closed_stored_fields(
        value,
        frozenset(
            {
                "id",
                "schema",
                "platform",
                "bundle_id",
                "bundle_id_sha256",
                "display_name",
                "status",
                "registered_by_sha256",
                "operation_payload_sha256",
                "revocation",
                "integrity_sha256",
            }
        )
        | _STORE_FIELDS,
        "application",
    )
    try:
        _ref(value.get("id"), "application id")
        _choice(value.get("platform"), "platform", _PLATFORMS)
        bundle_id = _bundle_id(value.get("bundle_id"))
        _text(value.get("display_name"), "display_name", 255)
        status = _choice(value.get("status"), "application status", _APPLICATION_STATES)
        revision = _revision(value.get("revision"))
    except ConsentApplicationScanValidationError as exc:
        raise ConsentApplicationScanIntegrityError(str(exc)) from exc
    if revision < 1:
        raise ConsentApplicationScanIntegrityError("stored application revision is invalid")
    _stored_timestamp(value.get("created_at"), "created_at")
    _stored_timestamp(value.get("updated_at"), "updated_at")
    bundle_digest = _stored_digest(value.get("bundle_id_sha256"), "application bundle digest")
    if not hmac.compare_digest(bundle_digest, _text_sha256(bundle_id)):
        raise ConsentApplicationScanIntegrityError("stored application bundle digest mismatch")
    _stored_digest(value.get("registered_by_sha256"), "application principal digest")
    _stored_digest(value.get("operation_payload_sha256"), "application operation digest")
    revocation = value.get("revocation")
    if status == "active":
        if revocation is not None:
            raise ConsentApplicationScanIntegrityError("stored active application is revoked")
    else:
        if not isinstance(revocation, Mapping):
            raise ConsentApplicationScanIntegrityError("stored application revocation is invalid")
        revocation_value = dict(revocation)
        _closed_stored_fields(
            revocation_value,
            frozenset(
                {
                    "reason_code",
                    "revoked_at",
                    "revoked_by_sha256",
                    "expected_application_revision",
                    "operation_payload_sha256",
                }
            ),
            "application revocation",
        )
        try:
            _ref(revocation_value.get("reason_code"), "reason_code")
            prior_revision = _revision(revocation_value.get("expected_application_revision"))
        except ConsentApplicationScanValidationError as exc:
            raise ConsentApplicationScanIntegrityError(str(exc)) from exc
        if prior_revision < 1 or revision != prior_revision + 1:
            raise ConsentApplicationScanIntegrityError(
                "stored application revocation revision is invalid"
            )
        _stored_timestamp(revocation_value.get("revoked_at"), "revoked_at")
        _stored_digest(
            revocation_value.get("revoked_by_sha256"),
            "application revocation principal digest",
        )
        _stored_digest(
            revocation_value.get("operation_payload_sha256"),
            "application revocation operation digest",
        )
    integrity = _stored_digest(value.get("integrity_sha256"), "application integrity")
    expected = _record_digest(
        value,
        exclude=_STORE_FIELDS | frozenset({"integrity_sha256"}),
    )
    if not hmac.compare_digest(integrity, expected):
        raise ConsentApplicationScanIntegrityError("stored application integrity mismatch")
    return value


def _validate_scan(record: object) -> dict[str, Any]:  # noqa: C901 - closed custody schema
    if not isinstance(record, Mapping):
        raise ConsentApplicationScanIntegrityError("stored scan is invalid")
    value = dict(record)
    if value.get("schema") not in {SCAN_SCHEMA, TOMBSTONE_SCHEMA}:
        raise ConsentApplicationScanIntegrityError("stored scan schema is invalid")
    try:
        _ref(value.get("id"), "scan id")
        _ref(value.get("application_id"), "application id")
        status = _choice(value.get("status"), "scan status", _SCAN_STATES)
        revision = _revision(value.get("revision"))
    except ConsentApplicationScanValidationError as exc:
        raise ConsentApplicationScanIntegrityError(str(exc)) from exc
    if revision < 1:
        raise ConsentApplicationScanIntegrityError("stored scan revision is invalid")
    _stored_timestamp(value.get("created_at"), "created_at")
    _stored_timestamp(value.get("updated_at"), "updated_at")
    integrity = _stored_digest(value.get("integrity_sha256"), "scan integrity")
    expected = _record_digest(
        value,
        exclude=_STORE_FIELDS | frozenset({"integrity_sha256"}),
    )
    if not hmac.compare_digest(integrity, expected):
        raise ConsentApplicationScanIntegrityError("stored scan integrity mismatch")
    if status == "purged":
        _closed_stored_fields(
            value,
            frozenset(
                {
                    "id",
                    "schema",
                    "application_id",
                    "status",
                    "purged_at",
                    "delete_after",
                    "prior_status",
                    "artifact_sha256",
                    "result_sha256",
                    "integrity_sha256",
                }
            )
            | _STORE_FIELDS,
            "scan tombstone",
        )
        if value.get("schema") != TOMBSTONE_SCHEMA or "result" in value:
            raise ConsentApplicationScanIntegrityError("stored scan tombstone is invalid")
        try:
            purged_at = _timestamp(value.get("purged_at"), "purged_at")
            delete_after = _timestamp(value.get("delete_after"), "delete_after")
        except ConsentApplicationScanValidationError as exc:
            raise ConsentApplicationScanIntegrityError(str(exc)) from exc
        if delete_after <= purged_at:
            raise ConsentApplicationScanIntegrityError("stored scan tombstone retention is invalid")
        if value.get("prior_status") not in (_SCAN_STATES - {"purged"}):
            raise ConsentApplicationScanIntegrityError(
                "stored scan tombstone prior status is invalid"
            )
        for field in ("artifact_sha256", "result_sha256"):
            _stored_digest(value.get(field), "scan tombstone digest")
    else:
        _closed_stored_fields(
            value,
            frozenset(
                {
                    "id",
                    "schema",
                    "application_id",
                    "application_revision",
                    "application_integrity_sha256",
                    "status",
                    "requested_by_sha256",
                    "scanned_at",
                    "retained_until",
                    "result",
                    "result_sha256",
                    "operation_payload_sha256",
                    "review",
                    "integrity_sha256",
                }
            )
            | _STORE_FIELDS,
            "scan",
        )
        if value.get("schema") != SCAN_SCHEMA:
            raise ConsentApplicationScanIntegrityError("stored scan schema/status is invalid")
        try:
            application_revision = _revision(value.get("application_revision"))
        except ConsentApplicationScanValidationError as exc:
            raise ConsentApplicationScanIntegrityError(str(exc)) from exc
        if application_revision < 1:
            raise ConsentApplicationScanIntegrityError(
                "stored scan application revision is invalid"
            )
        _stored_digest(
            value.get("application_integrity_sha256"),
            "scan application integrity",
        )
        _stored_digest(value.get("requested_by_sha256"), "scan requester digest")
        _stored_digest(value.get("operation_payload_sha256"), "scan operation digest")
        scanned_at = _stored_timestamp(value.get("scanned_at"), "scanned_at")
        retained_until = _stored_timestamp(value.get("retained_until"), "retained_until")
        if retained_until <= scanned_at:
            raise ConsentApplicationScanIntegrityError("stored scan retention is invalid")
        result = _validate_result(value.get("result"))
        result_digest = _stored_digest(value.get("result_sha256"), "scan result digest")
        if not hmac.compare_digest(result_digest, result["result_sha256"]):
            raise ConsentApplicationScanIntegrityError("stored scan result binding mismatch")
        review = value.get("review")
        if status == "pending_review":
            if review is not None:
                raise ConsentApplicationScanIntegrityError("stored pending scan has a review")
        else:
            if not isinstance(review, Mapping):
                raise ConsentApplicationScanIntegrityError("stored scan review is invalid")
            review_value = dict(review)
            _closed_stored_fields(
                review_value,
                frozenset(
                    {
                        "decision",
                        "review_note_code",
                        "reviewer_sha256",
                        "reviewed_at",
                        "application_revision",
                        "application_integrity_sha256",
                        "result_sha256",
                    }
                ),
                "scan review",
            )
            try:
                decision = _choice(
                    review_value.get("decision"),
                    "decision",
                    _REVIEW_DECISIONS,
                )
                review_application_revision = _revision(review_value.get("application_revision"))
                _ref(review_value.get("review_note_code"), "review_note_code")
            except ConsentApplicationScanValidationError as exc:
                raise ConsentApplicationScanIntegrityError(str(exc)) from exc
            if decision != status or review_application_revision != application_revision:
                raise ConsentApplicationScanIntegrityError("stored scan review binding is invalid")
            _stored_digest(review_value.get("reviewer_sha256"), "scan reviewer digest")
            _stored_timestamp(review_value.get("reviewed_at"), "reviewed_at")
            for field in ("application_integrity_sha256", "result_sha256"):
                review_digest = _stored_digest(
                    review_value.get(field),
                    "scan review digest",
                )
                if not hmac.compare_digest(review_digest, str(value.get(field))):
                    raise ConsentApplicationScanIntegrityError(
                        "stored scan review digest binding is invalid"
                    )
    return value


def _deterministic_id(prefix: str, idempotency_key: str) -> str:
    key = _ref(idempotency_key, "idempotency_key")
    return f"{prefix}-{_text_sha256(key)[:24]}"


def _principal_sha256(actor: object) -> str:
    return _text_sha256(_text(actor, "actor", 256))


def _operation_payload_digest(value: object) -> str:
    return _sha256(value)


def _list_limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_LIST:
        raise ConsentApplicationScanValidationError(
            f"limit must be an integer between 1 and {_MAX_LIST}"
        )
    return value


def _scan_summary(record: object) -> dict[str, Any]:
    scan = _validate_scan(record)
    summary: dict[str, Any] = {
        "id": scan["id"],
        "schema": scan["schema"],
        "application_id": scan["application_id"],
        "status": scan["status"],
        "revision": scan["revision"],
        "result_sha256": scan["result_sha256"],
    }
    if scan["status"] == "purged":
        summary.update(
            {
                "prior_status": scan["prior_status"],
                "purged_at": scan["purged_at"],
                "delete_after": scan["delete_after"],
            }
        )
        return summary
    result = scan["result"]
    summary.update(
        {
            "application_revision": scan["application_revision"],
            "scanned_at": scan["scanned_at"],
            "retained_until": scan["retained_until"],
            "platform": result["platform"],
            "complete": result["completeness"]["complete"] is True,
            "permission_count": len(result["permissions"]),
            "privacy_data_type_count": len(result["privacy_data_types"]),
            "sdk_candidate_count": len(result["sdk_candidates"]),
        }
    )
    return summary


class ConsentApplicationScanService:
    """Tenant-scoped application registration, scan and independent review."""

    def __init__(
        self,
        *,
        applications: GovernedRecordStore | None = None,
        scans: GovernedRecordStore | None = None,
        clock: Any | None = None,
        retention_seconds: int = _DEFAULT_RETENTION_SECONDS,
        max_records: int = _MAX_RECORDS,
    ) -> None:
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        if isinstance(retention_seconds, bool) or not isinstance(retention_seconds, int):
            raise ConsentApplicationScanValidationError("retention_seconds must be an integer")
        if not 86_400 <= retention_seconds <= 10 * 31_536_000:
            raise ConsentApplicationScanValidationError("retention_seconds is out of bounds")
        if isinstance(max_records, bool) or not isinstance(max_records, int):
            raise ConsentApplicationScanValidationError("max_records must be an integer")
        if not 1 <= max_records <= 1_000_000:
            raise ConsentApplicationScanValidationError("max_records is out of bounds")
        self._applications = applications or _APPLICATIONS
        self._scans = scans or _SCANS
        self._clock = clock
        self._retention_seconds = retention_seconds
        self._max_records = max_records
        self._purge_cursor = ""
        self._maintenance_lock = threading.Lock()

    def _now(self) -> float:
        value = self._scans.authoritative_time() if self._clock is None else self._clock()
        return _timestamp(value, "clock")

    def _authority_backend_kind(self) -> str:
        if (
            self._applications.authority_scope != "tenant"
            or self._scans.authority_scope != "tenant"
        ):
            raise ConsentApplicationScanIntegrityError(
                "application scanning requires tenant-scoped record authorities"
            )
        application_kind = self._applications.backend_kind
        scan_kind = self._scans.backend_kind
        if application_kind != scan_kind or application_kind not in {"local", "postgres"}:
            raise ConsentApplicationScanIntegrityError(
                "application and scan records do not share one authority backend"
            )
        return application_kind

    @contextmanager
    def _application_authority_guard(self, application_id: str, backend_kind: str):
        """Serialize local authority writes; Postgres uses a transaction fence."""

        if backend_kind == "postgres":
            yield
            return
        if backend_kind != "local":
            raise ConsentApplicationScanIntegrityError(
                "application scan authority backend is invalid"
            )
        from .file_lock import cross_process_lock, ensure_private_directory
        from .paths import data_dir

        directory = ensure_private_directory(data_dir("consent_application_scanner_authority"))
        target = directory / f"{_ref(application_id, 'application id')}.authority"
        with cross_process_lock(target, strict=True):
            yield

    @staticmethod
    def _require_active_application_pin(
        application: Mapping[str, Any],
        *,
        expected_revision: int,
        expected_integrity: str,
    ) -> None:
        current = _validate_application(application)
        if current["status"] != "active":
            raise ConsentApplicationScanConflict("application was revoked or is not active")
        if (
            current["revision"] != expected_revision
            or current["integrity_sha256"] != expected_integrity
        ):
            raise ConsentApplicationScanConflict("application authority changed")

    def _application_fence(
        self,
        application: Mapping[str, Any],
    ) -> GovernedMutationFence:
        authority = _validate_application(application)
        expected_revision = int(authority["revision"])
        expected_integrity = str(authority["integrity_sha256"])

        def validate(current: dict[str, Any], _now: float) -> None:
            self._require_active_application_pin(
                current,
                expected_revision=expected_revision,
                expected_integrity=expected_integrity,
            )

        return GovernedMutationFence(
            namespace=self._applications.namespace,
            prefix=self._applications.prefix,
            record_id=str(authority["id"]),
            authority_scope=self._applications.authority_scope,
            validate=validate,
        )

    def register_application(
        self,
        *,
        platform: str,
        bundle_id: str,
        display_name: str,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        normalized_platform = _choice(platform, "platform", _PLATFORMS)
        normalized_bundle = _bundle_id(bundle_id)
        normalized_name = _text(display_name, "display_name", 255)
        principal = _principal_sha256(actor)
        record_id = _deterministic_id("CAP", idempotency_key)
        payload_digest = _operation_payload_digest(
            {
                "platform": normalized_platform,
                "bundle_id": normalized_bundle,
                "display_name": normalized_name,
                "actor_sha256": principal,
            }
        )
        existing = self._applications.get(record_id)
        if existing is not None:
            current = _validate_application(existing)
            if current.get("operation_payload_sha256") != payload_digest:
                raise ConsentApplicationScanConflict(
                    "idempotency key was already used for different application data"
                )
            return current
        record = {
            "id": record_id,
            "schema": APPLICATION_SCHEMA,
            "platform": normalized_platform,
            "bundle_id": normalized_bundle,
            "bundle_id_sha256": _text_sha256(normalized_bundle),
            "display_name": normalized_name,
            "status": "active",
            "registered_by_sha256": principal,
            "operation_payload_sha256": payload_digest,
            "revocation": None,
        }
        record["integrity_sha256"] = _record_digest(
            record,
            exclude=frozenset({"integrity_sha256"}),
        )
        try:
            created = self._applications.create(
                record,
                action="register_application",
                actor=_text(actor, "actor", 256),
                max_records=self._max_records,
            )
        except RecordConflict as exc:
            existing = self._applications.get(record_id)
            if existing is None:
                raise ConsentApplicationScanConflict("application registration conflicted") from exc
            current = _validate_application(existing)
            if current.get("operation_payload_sha256") != payload_digest:
                raise ConsentApplicationScanConflict(
                    "idempotency key was already used for different application data"
                ) from exc
            return current
        return _validate_application(created)

    def get_application(self, application_id: str) -> dict[str, Any]:
        record = self._applications.get(_ref(application_id, "application id"))
        if record is None:
            raise ConsentApplicationScanNotFound("application was not found")
        return _validate_application(record)

    def list_applications(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return [
            _validate_application(item)
            for item in self._applications.list(limit=_list_limit(limit))
        ]

    def revoke_application(
        self,
        application_id: str,
        *,
        actor: str,
        reason_code: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        revision = _revision(expected_revision)
        reason = _ref(reason_code, "reason_code")
        operator = _text(actor, "actor", 256)
        principal = _principal_sha256(operator)
        normalized_application_id = _ref(application_id, "application id")
        operation_digest = _operation_payload_digest(
            {
                "application_id": normalized_application_id,
                "expected_application_revision": revision,
                "reason_code": reason,
                "actor_sha256": principal,
            }
        )
        backend_kind = self._authority_backend_kind()

        with self._application_authority_guard(
            normalized_application_id,
            backend_kind,
        ):
            application = self.get_application(normalized_application_id)
            if application["status"] == "revoked":
                revocation = application.get("revocation")
                if isinstance(revocation, Mapping) and hmac.compare_digest(
                    str(revocation.get("operation_payload_sha256") or ""),
                    operation_digest,
                ):
                    return application
                raise ConsentApplicationScanConflict(
                    "application was already revoked by a different operation"
                )
            if application["revision"] != revision:
                raise ConsentApplicationScanConflict("application revision changed")
            now = self._now()

            def mutate(current: dict[str, Any]) -> None:
                validated = _validate_application(current)
                if validated["status"] != "active":
                    raise ConsentApplicationScanConflict("application is not active")
                current["status"] = "revoked"
                current["revocation"] = {
                    "reason_code": reason,
                    "revoked_at": now,
                    "revoked_by_sha256": principal,
                    "expected_application_revision": revision,
                    "operation_payload_sha256": operation_digest,
                }
                current["integrity_sha256"] = _record_digest(
                    current,
                    exclude=_STORE_FIELDS | frozenset({"integrity_sha256"}),
                )

            try:
                updated = self._applications.update(
                    application["id"],
                    mutate,
                    expected_revision=revision,
                    action="revoke_application",
                    actor=operator,
                )
            except RecordConflict as exc:
                raise ConsentApplicationScanConflict("application revision changed") from exc
        if updated is None:
            raise ConsentApplicationScanNotFound("application was not found")
        return _validate_application(updated)

    def scan(
        self,
        application_id: str,
        files: Sequence[ManifestFile],
        *,
        actor: str,
        idempotency_key: str,
        expected_application_revision: int,
    ) -> dict[str, Any]:
        expected_revision = _revision(expected_application_revision)
        principal = _principal_sha256(actor)
        operator = _text(actor, "actor", 256)
        record_id = _deterministic_id("CAS", idempotency_key)
        normalized_application_id = _ref(application_id, "application id")
        backend_kind = self._authority_backend_kind()
        application = self.get_application(normalized_application_id)
        if application["status"] != "active":
            raise ConsentApplicationScanConflict("application is not active")
        if application["revision"] != expected_revision:
            raise ConsentApplicationScanConflict("application revision changed before scan")
        result = scan_manifest_bundle(
            application["platform"],
            files,
            expected_bundle_id=application["bundle_id"],
        )
        with self._application_authority_guard(
            normalized_application_id,
            backend_kind,
        ):
            authority = self.get_application(normalized_application_id)
            self._require_active_application_pin(
                authority,
                expected_revision=expected_revision,
                expected_integrity=str(application["integrity_sha256"]),
            )
            payload_digest = _operation_payload_digest(
                {
                    "application_id": authority["id"],
                    "application_revision": authority["revision"],
                    "application_integrity_sha256": authority["integrity_sha256"],
                    "result_sha256": result["result_sha256"],
                    "actor_sha256": principal,
                }
            )
            existing = self._scans.get(record_id)
            if existing is not None:
                current = _validate_scan(existing)
                if current.get("operation_payload_sha256") != payload_digest:
                    raise ConsentApplicationScanConflict(
                        "idempotency key was already used for different scan data"
                    )
                return current
            now = self._now()
            record = {
                "id": record_id,
                "schema": SCAN_SCHEMA,
                "application_id": authority["id"],
                "application_revision": authority["revision"],
                "application_integrity_sha256": authority["integrity_sha256"],
                "status": "pending_review",
                "requested_by_sha256": principal,
                "scanned_at": now,
                "retained_until": now + self._retention_seconds,
                "result": result,
                "result_sha256": result["result_sha256"],
                "operation_payload_sha256": payload_digest,
                "review": None,
            }
            record["integrity_sha256"] = _record_digest(
                record,
                exclude=frozenset({"integrity_sha256"}),
            )
            fence = self._application_fence(authority) if backend_kind == "postgres" else None
            try:
                created = self._scans.create(
                    record,
                    action="scan_application_manifests",
                    actor=operator,
                    fence=fence,
                    max_records=self._max_records,
                )
            except RecordConflict as exc:
                existing = self._scans.get(record_id)
                if existing is None:
                    raise ConsentApplicationScanConflict("application scan conflicted") from exc
                current = _validate_scan(existing)
                if current.get("operation_payload_sha256") != payload_digest:
                    raise ConsentApplicationScanConflict(
                        "idempotency key was already used for different scan data"
                    ) from exc
                return current
        return _validate_scan(created)

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        record = self._scans.get(_ref(scan_id, "scan id"))
        if record is None:
            raise ConsentApplicationScanNotFound("application scan was not found")
        return _validate_scan(record)

    def list_scans(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = _list_limit(limit)
        summaries: list[dict[str, Any]] = []
        for _, record_id in self._scans.iter_record_ids(limit=bounded):
            record = self._scans.get(record_id)
            if record is None:
                raise ConsentApplicationScanIntegrityError(
                    "application scan disappeared during bounded listing"
                )
            summaries.append(_scan_summary(record))
        return summaries

    def review(
        self,
        scan_id: str,
        *,
        decision: str,
        reviewer: str,
        expected_revision: int,
        review_note_code: str,
    ) -> dict[str, Any]:
        normalized_decision = _choice(decision, "decision", _REVIEW_DECISIONS)
        revision = _revision(expected_revision)
        note_code = _ref(review_note_code, "review_note_code")
        operator = _text(reviewer, "reviewer", 256)
        reviewer_digest = _principal_sha256(operator)
        scan = self.get_scan(scan_id)
        if scan["status"] != "pending_review":
            raise ConsentApplicationScanConflict("application scan is not pending review")
        if hmac.compare_digest(reviewer_digest, str(scan["requested_by_sha256"])):
            raise ConsentApplicationScanConflict("scan requester cannot review the same scan")
        backend_kind = self._authority_backend_kind()
        application_id = str(scan["application_id"])
        with self._application_authority_guard(application_id, backend_kind):
            application = self.get_application(application_id)
            self._require_active_application_pin(
                application,
                expected_revision=int(scan["application_revision"]),
                expected_integrity=str(scan["application_integrity_sha256"]),
            )
            now = self._now()

            def mutate(current: dict[str, Any]) -> None:
                current_validated = _validate_scan(current)
                if current_validated["status"] != "pending_review":
                    raise ConsentApplicationScanConflict("application scan is not pending review")
                if (
                    current_validated["application_id"] != application["id"]
                    or current_validated["application_revision"] != application["revision"]
                    or current_validated["application_integrity_sha256"]
                    != application["integrity_sha256"]
                ):
                    raise ConsentApplicationScanConflict(
                        "application authority changed before review"
                    )
                if hmac.compare_digest(
                    reviewer_digest,
                    str(current_validated["requested_by_sha256"]),
                ):
                    raise ConsentApplicationScanConflict(
                        "scan requester cannot review the same scan"
                    )
                current["status"] = normalized_decision
                current["review"] = {
                    "decision": normalized_decision,
                    "review_note_code": note_code,
                    "reviewer_sha256": reviewer_digest,
                    "reviewed_at": now,
                    "application_revision": application["revision"],
                    "application_integrity_sha256": application["integrity_sha256"],
                    "result_sha256": current["result_sha256"],
                }
                current["integrity_sha256"] = _record_digest(
                    current,
                    exclude=_STORE_FIELDS | frozenset({"integrity_sha256"}),
                )

            fence = self._application_fence(application) if backend_kind == "postgres" else None
            try:
                updated = self._scans.update(
                    scan["id"],
                    mutate,
                    expected_revision=revision,
                    action=f"review_application_scan_{normalized_decision}",
                    actor=operator,
                    fence=fence,
                )
            except RecordConflict as exc:
                raise ConsentApplicationScanConflict("application scan revision changed") from exc
        if updated is None:
            raise ConsentApplicationScanNotFound("application scan was not found")
        return _validate_scan(updated)

    def purge_expired(
        self,
        *,
        actor: str,
        now: float | None = None,
        limit: int = 100,
    ) -> dict[str, int]:
        cutoff = self._now() if now is None else _timestamp(now, "now")
        bounded_limit = _list_limit(limit)
        operator = _text(actor, "actor", 256)
        with self._maintenance_lock:
            # Delivery is retried before physical deletion so the digest-only
            # tombstone event cannot disappear with its last durable outbox.
            self._applications.retry_pending(limit=bounded_limit)
            self._scans.retry_pending(limit=bounded_limit)
            window = list(
                self._scans.iter_record_ids(
                    start_after=self._purge_cursor,
                    limit=bounded_limit,
                )
            )
            inspected = 0
            purged = 0
            deleted = 0
            for cursor, record_id in window:
                self._purge_cursor = cursor
                record = self._scans.get(record_id)
                if record is None:
                    continue
                scan = _validate_scan(record)
                inspected += 1
                if scan["status"] == "purged":
                    if float(scan.get("delete_after") or 0.0) <= cutoff and not scan.get(
                        "_audit_pending"
                    ):
                        try:
                            removed = self._scans.delete(
                                scan["id"],
                                expected_revision=int(scan["revision"]),
                            )
                        except (AuditOutboxError, RecordConflict):
                            removed = False
                        deleted += int(removed)
                    continue
                # Never replace a record while an earlier custody event is
                # still queued on that record. Clearing it to build the
                # tombstone would silently destroy the only durable outbox.
                if scan.get("_audit_pending"):
                    continue
                if float(scan.get("retained_until") or 0.0) > cutoff:
                    continue

                def mutate(current: dict[str, Any]) -> None:
                    validated = _validate_scan(current)
                    if validated["status"] == "purged":
                        return
                    if validated.get("_audit_pending"):
                        raise AuditOutboxError("application scan audit delivery is still pending")
                    created_at = validated.get("created_at")
                    current.clear()
                    current.update(
                        {
                            "id": validated["id"],
                            "schema": TOMBSTONE_SCHEMA,
                            "application_id": validated["application_id"],
                            "status": "purged",
                            "purged_at": cutoff,
                            "delete_after": cutoff + self._retention_seconds,
                            "prior_status": validated["status"],
                            "artifact_sha256": validated["result"]["artifact_sha256"],
                            "result_sha256": validated["result_sha256"],
                        }
                    )
                    if created_at is not None:
                        current["created_at"] = created_at
                    current["integrity_sha256"] = _record_digest(
                        current,
                        exclude=_STORE_FIELDS | frozenset({"integrity_sha256"}),
                    )

                try:
                    updated = self._scans.update(
                        scan["id"],
                        mutate,
                        expected_revision=int(scan["revision"]),
                        action="purge_application_scan",
                        actor=operator,
                    )
                except (AuditOutboxError, RecordConflict):
                    continue
                if updated is not None and updated.get("status") == "purged":
                    _validate_scan(updated)
                    purged += 1
            return {"inspected": inspected, "purged": purged, "deleted": deleted}

    def verify_integrity(self, *, limit: int = 500) -> dict[str, Any]:
        bounded = _list_limit(limit)
        application_window = list(self._applications.iter_record_ids(limit=bounded + 1))
        scan_window = list(self._scans.iter_record_ids(limit=bounded + 1))
        applications_complete = len(application_window) <= bounded
        scans_complete = len(scan_window) <= bounded
        applications = 0
        for _, record_id in application_window[:bounded]:
            record = self._applications.get(record_id)
            if record is None:
                raise ConsentApplicationScanIntegrityError(
                    "application disappeared during integrity verification"
                )
            _validate_application(record)
            applications += 1
        scans = 0
        orphaned: list[str] = []
        authority_mismatches: list[str] = []
        for _, record_id in scan_window[:bounded]:
            record = self._scans.get(record_id)
            if record is None:
                raise ConsentApplicationScanIntegrityError(
                    "application scan disappeared during integrity verification"
                )
            scan = _validate_scan(record)
            scans += 1
            try:
                application = self.get_application(scan["application_id"])
            except ConsentApplicationScanNotFound:
                orphaned.append(scan["id"])
                continue
            if scan["status"] == "purged":
                continue
            result = scan["result"]
            identities = result["identities"]
            authority_matches = (
                result["platform"] == application["platform"]
                and identities.get("bundle_id") == application["bundle_id"]
            )
            if application["status"] == "active":
                authority_matches = authority_matches and (
                    scan["application_revision"] == application["revision"]
                    and scan["application_integrity_sha256"] == application["integrity_sha256"]
                )
            else:
                revocation = application["revocation"]
                authority_matches = authority_matches and (
                    isinstance(revocation, Mapping)
                    and scan["application_revision"]
                    == revocation.get("expected_application_revision")
                )
            if not authority_matches:
                authority_mismatches.append(scan["id"])
        sample_ok = not orphaned and not authority_mismatches
        complete = applications_complete and scans_complete
        return {
            "schema": "lightwork.consent-application-scan-integrity.v1",
            "ok": sample_ok and complete,
            "sample_ok": sample_ok,
            "complete": complete,
            "applications": applications,
            "scans": scans,
            "applications_complete": applications_complete,
            "scans_complete": scans_complete,
            "orphaned_scan_ids": sorted(orphaned),
            "authority_mismatch_scan_ids": sorted(authority_mismatches),
        }
