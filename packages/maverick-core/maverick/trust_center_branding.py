"""Governed tenant-private branding and exact custom-domain authority.

This module owns only code-verifiable Trust Center branding facts.  Raster
content is bounded, structurally parsed, AES-256-GCM sealed under an injected
versioned key reference, independently reviewed, and activated through CAS.
Public projection is pinned to an enrolled public client plus the exact active
consent publication.  A custom domain is never used as a tenant selector: it is
an optional, exact claim verified by an injected deployment authority.

DNS/TLS issuance, CDN routing, accessibility review, and customer brand
acceptance are deliberately outside this local authority.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import sqlite3
import struct
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import consent_storage
from .file_lock import ensure_private_directory, ensure_private_file

SCHEMA_VERSION = 1
GENESIS_SHA256 = "0" * 64
ALLOWED_MEDIA_TYPES = frozenset({"image/png", "image/jpeg"})
ALLOWED_ASSET_KINDS = frozenset({"logo", "icon"})

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_KEY_REF_RE = re.compile(r"(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_HOST_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_SAFE_CHUNKS = frozenset(
    {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"sRGB", b"gAMA", b"cHRM", b"pHYs"}
)
_JPEG_SOF = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)


class TrustCenterBrandingError(RuntimeError):
    """Closed-code base error."""

    def __init__(self, error_code: str) -> None:
        if not isinstance(error_code, str) or not re.fullmatch(
            r"[a-z][a-z0-9_]{0,95}", error_code
        ):
            raise ValueError("Trust Center branding error code is invalid")
        self.error_code = error_code
        super().__init__(error_code)


class BrandingConfigError(TrustCenterBrandingError):
    pass


class BrandingValidationError(TrustCenterBrandingError, ValueError):
    pass


class BrandingConflict(TrustCenterBrandingError):
    pass


class BrandingNotFound(TrustCenterBrandingError):
    pass


class BrandingIntegrityError(TrustCenterBrandingError):
    pass


class BrandingExternalAuthorityError(TrustCenterBrandingError):
    pass


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BrandingValidationError("branding_contract_invalid") from exc
    if len(encoded) > 2 * 1024 * 1024:
        raise BrandingValidationError("branding_contract_too_large")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise BrandingValidationError(f"branding_{label}_invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise BrandingValidationError(f"branding_{label}_invalid")
    return value


def _positive_int(value: object, label: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise BrandingValidationError(f"branding_{label}_invalid")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BrandingValidationError(f"branding_{label}_invalid")
    selected = float(value)
    if not math.isfinite(selected) or not 0 < selected < 100_000_000_000.0:
        raise BrandingValidationError(f"branding_{label}_invalid")
    return selected


def _host(value: object) -> str:
    if not isinstance(value, str) or value != value.strip().lower():
        raise BrandingValidationError("branding_domain_host_invalid")
    if "*" in value or len(value) > 253 or value.endswith("."):
        raise BrandingValidationError("branding_domain_host_invalid")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise BrandingValidationError("branding_domain_host_invalid")
    labels = value.split(".")
    if len(labels) < 2 or any(_HOST_LABEL_RE.fullmatch(label) is None for label in labels):
        raise BrandingValidationError("branding_domain_host_invalid")
    return value


def _origin_host(value: object) -> str:
    if not isinstance(value, str):
        raise BrandingValidationError("branding_public_origin_invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise BrandingValidationError("branding_public_origin_invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise BrandingValidationError("branding_public_origin_invalid")
    return _host(parsed.hostname.lower())


def _actor_sha256(tenant_sha256: str, actor_ref: object) -> str:
    actor = _identifier(actor_ref, "actor_ref")
    return _text_sha256(f"lightwork.trust-center-brand.actor.v1:{tenant_sha256}:{actor}")


def _png_dimensions(content: bytes) -> tuple[int, int]:
    if not content.startswith(_PNG_SIGNATURE):
        raise BrandingValidationError("branding_raster_signature_invalid")
    offset = len(_PNG_SIGNATURE)
    saw_ihdr = saw_idat = saw_iend = False
    width = height = 0
    while offset < len(content):
        if len(content) - offset < 12:
            raise BrandingValidationError("branding_png_structure_invalid")
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        chunk_type = content[offset + 4 : offset + 8]
        end = offset + 12 + length
        if length > len(content) or end > len(content):
            raise BrandingValidationError("branding_png_structure_invalid")
        payload = content[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", content[offset + 8 + length : end])[0]
        actual_crc = binascii.crc32(chunk_type + payload) & 0xFFFFFFFF
        if actual_crc != expected_crc or chunk_type not in _PNG_SAFE_CHUNKS:
            raise BrandingValidationError("branding_png_structure_invalid")
        if not saw_ihdr:
            if chunk_type != b"IHDR" or length != 13:
                raise BrandingValidationError("branding_png_structure_invalid")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            valid_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                color not in valid_depths
                or depth not in valid_depths[color]
                or compression != 0
                or filtering != 0
                or interlace not in {0, 1}
            ):
                raise BrandingValidationError("branding_png_structure_invalid")
            saw_ihdr = True
        elif chunk_type == b"IHDR":
            raise BrandingValidationError("branding_png_structure_invalid")
        if chunk_type == b"IDAT":
            if saw_iend:
                raise BrandingValidationError("branding_png_structure_invalid")
            saw_idat = True
        if chunk_type == b"IEND":
            if length != 0 or not saw_idat or saw_iend or end != len(content):
                raise BrandingValidationError("branding_png_structure_invalid")
            saw_iend = True
        offset = end
    if not (saw_ihdr and saw_idat and saw_iend):
        raise BrandingValidationError("branding_png_structure_invalid")
    return width, height


def _jpeg_dimensions(content: bytes) -> tuple[int, int]:  # noqa: C901
    if len(content) < 12 or not content.startswith(b"\xff\xd8"):
        raise BrandingValidationError("branding_raster_signature_invalid")
    offset = 2
    dimensions: tuple[int, int] | None = None
    saw_scan = False
    while offset < len(content):
        if content[offset] != 0xFF:
            raise BrandingValidationError("branding_jpeg_structure_invalid")
        while offset < len(content) and content[offset] == 0xFF:
            offset += 1
        if offset >= len(content):
            raise BrandingValidationError("branding_jpeg_structure_invalid")
        marker = content[offset]
        offset += 1
        if marker == 0xD9:
            if not saw_scan or dimensions is None or offset != len(content):
                raise BrandingValidationError("branding_jpeg_structure_invalid")
            return dimensions
        if marker in {0xD8, 0x00, 0x01} or 0xD0 <= marker <= 0xD7:
            raise BrandingValidationError("branding_jpeg_structure_invalid")
        if offset + 2 > len(content):
            raise BrandingValidationError("branding_jpeg_structure_invalid")
        length = struct.unpack(">H", content[offset : offset + 2])[0]
        if length < 2 or offset + length > len(content):
            raise BrandingValidationError("branding_jpeg_structure_invalid")
        payload = content[offset + 2 : offset + length]
        offset += length
        if marker == 0xFE or (0xE1 <= marker <= 0xEF):
            # Reject comments, EXIF, ICC, XMP, and arbitrary application data.
            raise BrandingValidationError("branding_jpeg_metadata_not_allowed")
        if marker == 0xE0 and not payload.startswith(b"JFIF\x00"):
            raise BrandingValidationError("branding_jpeg_metadata_not_allowed")
        if marker == 0xEE and not payload.startswith(b"Adobe"):
            raise BrandingValidationError("branding_jpeg_metadata_not_allowed")
        if marker in _JPEG_SOF:
            if dimensions is not None or len(payload) < 6:
                raise BrandingValidationError("branding_jpeg_structure_invalid")
            precision = payload[0]
            height, width = struct.unpack(">HH", payload[1:5])
            components = payload[5]
            if precision not in {8, 12} or components not in {1, 3, 4}:
                raise BrandingValidationError("branding_jpeg_structure_invalid")
            dimensions = (width, height)
        if marker == 0xDA:
            saw_scan = True
            while offset < len(content):
                next_ff = content.find(b"\xff", offset)
                if next_ff < 0 or next_ff + 1 >= len(content):
                    raise BrandingValidationError("branding_jpeg_structure_invalid")
                following = content[next_ff + 1]
                if following == 0x00 or 0xD0 <= following <= 0xD7:
                    offset = next_ff + 2
                    continue
                offset = next_ff
                break
    raise BrandingValidationError("branding_jpeg_structure_invalid")


def validate_raster(
    content: object,
    media_type: object,
    *,
    max_bytes: int,
    max_width: int,
    max_height: int,
    max_pixels: int,
) -> tuple[bytes, str, int, int, str]:
    if not isinstance(content, bytes) or not 1 <= len(content) <= max_bytes:
        raise BrandingValidationError("branding_asset_size_invalid")
    if media_type not in ALLOWED_MEDIA_TYPES:
        raise BrandingValidationError("branding_asset_media_type_invalid")
    width, height = (
        _png_dimensions(content)
        if media_type == "image/png"
        else _jpeg_dimensions(content)
    )
    if (
        width < 1
        or height < 1
        or width > max_width
        or height > max_height
        or width * height > max_pixels
    ):
        raise BrandingValidationError("branding_asset_dimensions_invalid")
    return content, media_type, width, height, hashlib.sha256(content).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustCenterBrandingConfig:
    enable: bool = False
    max_asset_bytes: int = 2 * 1024 * 1024
    max_assets: int = 1_000
    max_width: int = 4096
    max_height: int = 4096
    max_pixels: int = 8_388_608
    max_domains: int = 100
    challenge_ttl_seconds: int = 3_600
    verification_ttl_seconds: int = 7 * 24 * 60 * 60
    retention_seconds: int = 90 * 24 * 60 * 60
    key_ref: str = "env:MAVERICK_TRUST_CENTER_BRAND_ASSET_KEY"
    key_revision: int = 1

    def __post_init__(self) -> None:
        if type(self.enable) is not bool:
            raise BrandingConfigError("branding_enable_invalid")
        bounds = (
            (self.max_asset_bytes, "max_asset_bytes", 1_024, 10 * 1024 * 1024),
            (self.max_assets, "max_assets", 1, 100_000),
            (self.max_width, "max_width", 16, 16_384),
            (self.max_height, "max_height", 16, 16_384),
            (self.max_pixels, "max_pixels", 256, 64_000_000),
            (self.max_domains, "max_domains", 1, 10_000),
            (self.challenge_ttl_seconds, "challenge_ttl_seconds", 300, 86_400),
            (
                self.verification_ttl_seconds,
                "verification_ttl_seconds",
                900,
                90 * 24 * 60 * 60,
            ),
            (self.retention_seconds, "retention_seconds", 60, 10 * 365 * 24 * 60 * 60),
            (self.key_revision, "key_revision", 1, 2_147_483_647),
        )
        for value, label, low, high in bounds:
            try:
                _positive_int(value, label, low, high)
            except BrandingValidationError as exc:
                raise BrandingConfigError(exc.error_code) from exc
        if self.max_pixels > self.max_width * self.max_height:
            raise BrandingConfigError("branding_max_pixels_invalid")
        if _KEY_REF_RE.fullmatch(self.key_ref) is None:
            raise BrandingConfigError("branding_key_ref_invalid")

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any]) -> TrustCenterBrandingConfig:
        if not isinstance(config, Mapping):
            raise BrandingConfigError("branding_configuration_unavailable")
        consent = config.get("consent_preferences") or {}
        if not isinstance(consent, Mapping):
            raise BrandingConfigError("branding_configuration_invalid")
        trust_center = consent.get("trust_center") or {}
        if not isinstance(trust_center, Mapping):
            raise BrandingConfigError("branding_configuration_invalid")
        section = trust_center.get("branding") or {}
        if not isinstance(section, Mapping):
            raise BrandingConfigError("branding_configuration_invalid")
        allowed = {field for field in cls.__dataclass_fields__}
        if any(key not in allowed for key in section):
            raise BrandingConfigError("branding_configuration_unknown_key")
        try:
            return cls(**dict(section))
        except TypeError as exc:
            raise BrandingConfigError("branding_configuration_invalid") from exc


@dataclass(frozen=True, slots=True)
class BrandPublicationAuthority:
    tenant_id: str
    property_id: str
    property_revision: int
    publication_id: str
    publication_revision: int
    publication_sha256: str
    bundle_sha256: str
    client_credential_id: str
    client_revision: int
    client_record_sha256: str
    public_origin: str

    def normalized(self) -> BrandPublicationAuthority:
        tenant = _identifier(self.tenant_id, "tenant_id")
        return replace(
            self,
            tenant_id=tenant,
            property_id=_identifier(self.property_id, "property_id"),
            property_revision=_positive_int(
                self.property_revision, "property_revision", 1, 2_147_483_647
            ),
            publication_id=_identifier(self.publication_id, "publication_id"),
            publication_revision=_positive_int(
                self.publication_revision, "publication_revision", 1, 2_147_483_647
            ),
            publication_sha256=_digest(self.publication_sha256, "publication_sha256"),
            bundle_sha256=_digest(self.bundle_sha256, "bundle_sha256"),
            client_credential_id=_identifier(
                self.client_credential_id, "client_credential_id"
            ),
            client_revision=_positive_int(
                self.client_revision, "client_revision", 1, 2_147_483_647
            ),
            client_record_sha256=_digest(
                self.client_record_sha256, "client_record_sha256"
            ),
            public_origin=self.public_origin,
        )

    @property
    def public_host(self) -> str:
        return _origin_host(self.public_origin)


@dataclass(frozen=True, slots=True)
class DomainVerificationRequest:
    tenant_sha256: str
    claim_id: str
    claim_version: int
    host: str
    challenge_sha256: str
    challenge_expires_at: float


@dataclass(frozen=True, slots=True)
class DomainVerificationEvidence:
    tenant_sha256: str
    claim_id: str
    claim_version: int
    host: str
    challenge_sha256: str
    dns_evidence_sha256: str
    tls_certificate_sha256: str
    observed_at: float
    valid_until: float
    evidence_sha256: str


@dataclass(frozen=True, slots=True)
class DomainDeploymentBinding:
    tenant_sha256: str
    claim_id: str
    claim_version: int
    host: str
    challenge_sha256: str
    dns_evidence_sha256: str
    tls_certificate_sha256: str
    deployment_sha256: str
    activated_at: float
    valid_until: float


class DomainDeploymentAuthority(Protocol):
    """Deployment-owned exact DNS/TLS/CDN authority."""

    def verify(self, request: DomainVerificationRequest) -> DomainVerificationEvidence: ...

    def activate(
        self,
        request: DomainVerificationRequest,
        evidence: DomainVerificationEvidence,
    ) -> DomainDeploymentBinding: ...

    def reverify(self, binding: DomainDeploymentBinding) -> DomainDeploymentBinding: ...

    def revoke(self, binding: DomainDeploymentBinding) -> bool: ...


@dataclass(frozen=True, slots=True)
class AssetAuthority:
    asset_id: str
    asset_version: int
    authority_revision: int
    asset_kind: str
    media_type: str
    byte_size: int
    width: int
    height: int
    content_sha256: str
    custody_revision: int
    key_ref: str
    key_revision: int
    state: str
    created_at: float
    updated_at: float
    retained_until: float | None
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class DomainAuthority:
    claim_id: str
    claim_version: int
    authority_revision: int
    host: str
    state: str
    challenge_sha256: str
    challenge_expires_at: float
    deployment_sha256: str | None
    dns_evidence_sha256: str | None
    tls_certificate_sha256: str | None
    verified_until: float | None
    updated_at: float
    retained_until: float | None
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class BrandProjection:
    projection_id: str
    projection_revision: int
    property_id: str
    property_revision: int
    publication_id: str
    publication_revision: int
    publication_sha256: str
    bundle_sha256: str
    client_credential_id: str
    client_revision: int
    client_record_sha256: str
    public_origin: str
    public_host: str
    asset_id: str
    asset_version: int
    asset_authority_sha256: str
    asset_content_sha256: str
    asset_kind: str
    asset_media_type: str
    asset_width: int
    asset_height: int
    domain_claim_id: str | None
    domain_claim_version: int | None
    domain_authority_sha256: str | None
    domain_deployment_sha256: str | None
    state: str
    created_at: float
    projection_sha256: str


@dataclass(frozen=True, slots=True)
class PublicBrandAsset:
    projection: BrandProjection
    content: bytes


def _verification_request(value: DomainVerificationRequest) -> DomainVerificationRequest:
    if type(value) is not DomainVerificationRequest:
        raise BrandingIntegrityError("branding_domain_request_invalid")
    return replace(
        value,
        tenant_sha256=_digest(value.tenant_sha256, "tenant_sha256"),
        claim_id=_identifier(value.claim_id, "claim_id"),
        claim_version=_positive_int(value.claim_version, "claim_version", 1, 2_147_483_647),
        host=_host(value.host),
        challenge_sha256=_digest(value.challenge_sha256, "challenge_sha256"),
        challenge_expires_at=_timestamp(value.challenge_expires_at, "challenge_expires_at"),
    )


def _validated_evidence(
    value: object,
    request: DomainVerificationRequest,
    *,
    now: float,
    maximum_ttl: int,
) -> DomainVerificationEvidence:
    if type(value) is not DomainVerificationEvidence:
        raise BrandingExternalAuthorityError("branding_domain_evidence_invalid")
    body = asdict(value)
    supplied = body.pop("evidence_sha256", None)
    if (
        value.tenant_sha256 != request.tenant_sha256
        or value.claim_id != request.claim_id
        or value.claim_version != request.claim_version
        or value.host != request.host
        or not hmac.compare_digest(value.challenge_sha256, request.challenge_sha256)
        or _DIGEST_RE.fullmatch(value.dns_evidence_sha256 or "") is None
        or _DIGEST_RE.fullmatch(value.tls_certificate_sha256 or "") is None
        or not hmac.compare_digest(str(supplied), _sha256(body))
    ):
        raise BrandingExternalAuthorityError("branding_domain_evidence_invalid")
    observed = _timestamp(value.observed_at, "observed_at")
    valid_until = _timestamp(value.valid_until, "valid_until")
    if observed > now + 300 or valid_until <= now or valid_until > now + maximum_ttl:
        raise BrandingExternalAuthorityError("branding_domain_evidence_invalid")
    return value


def _validated_deployment(
    value: object,
    request: DomainVerificationRequest,
    *,
    now: float,
    maximum_ttl: int,
) -> DomainDeploymentBinding:
    if type(value) is not DomainDeploymentBinding:
        raise BrandingExternalAuthorityError("branding_domain_deployment_invalid")
    if (
        value.tenant_sha256 != request.tenant_sha256
        or value.claim_id != request.claim_id
        or value.claim_version != request.claim_version
        or value.host != request.host
        or not hmac.compare_digest(value.challenge_sha256, request.challenge_sha256)
        or any(
            _DIGEST_RE.fullmatch(item or "") is None
            for item in (
                value.dns_evidence_sha256,
                value.tls_certificate_sha256,
                value.deployment_sha256,
            )
        )
    ):
        raise BrandingExternalAuthorityError("branding_domain_deployment_invalid")
    activated = _timestamp(value.activated_at, "activated_at")
    valid_until = _timestamp(value.valid_until, "valid_until")
    if activated > now + 300 or valid_until <= now or valid_until > now + maximum_ttl:
        raise BrandingExternalAuthorityError("branding_domain_deployment_invalid")
    return value


@contextmanager
def _closing_sqlite(connection: Any):
    """Close a per-call sqlite3 connection on exit; a shared (Postgres) session is left as before."""
    try:
        yield connection
    finally:
        if isinstance(connection, sqlite3.Connection):
            connection.close()


class TrustCenterBrandingStore:
    """SQLite authority for encrypted assets, exact domains, and projections."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        config: TrustCenterBrandingConfig,
        key_resolver: Callable[[str, str, int], bytes],
        publication_resolver: Callable[[str, str], BrandPublicationAuthority],
        domain_authority: DomainDeploymentAuthority | None = None,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.path = Path(path).expanduser().resolve()
        self.tenant_id = _identifier(tenant_id, "tenant_id")
        self.tenant_sha256 = _text_sha256(
            f"lightwork.trust-center-brand.tenant.v1:{self.tenant_id}"
        )
        if type(config) is not TrustCenterBrandingConfig or not config.enable:
            raise BrandingConfigError("trust_center_branding_disabled")
        if not callable(key_resolver) or not callable(publication_resolver) or not callable(clock):
            raise BrandingConfigError("branding_runtime_authority_unavailable")
        self.config = config
        self._key_resolver = key_resolver
        self._publication_resolver = publication_resolver
        self._domain_authority = domain_authority
        self._clock = clock
        self._id_factory = id_factory or (
            lambda prefix: f"{prefix}-{secrets.token_urlsafe(12)}"
        )
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        ensure_private_directory(self.path.parent)
        with _closing_sqlite(self._connect()) as connection, connection:
            self._create_schema(connection)
        if not consent_storage.shared():
            ensure_private_file(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=30)
        else:
            connection = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
        except BaseException:
            if isinstance(connection, sqlite3.Connection):
                connection.close()
            raise
        return connection

    @contextmanager
    def _transaction(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_meta(connection)
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS trust_brand_meta(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema_version INTEGER NOT NULL,
                tenant_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                row_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trust_brand_asset_versions(
                asset_id TEXT NOT NULL,
                asset_version INTEGER NOT NULL,
                asset_kind TEXT NOT NULL,
                media_type TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                width INTEGER NOT NULL,
                height INTEGER NOT NULL,
                content_sha256 TEXT NOT NULL,
                created_by_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                row_sha256 TEXT NOT NULL,
                PRIMARY KEY(asset_id,asset_version)
            );
            CREATE TABLE IF NOT EXISTS trust_brand_asset_blobs(
                asset_id TEXT NOT NULL,
                asset_version INTEGER NOT NULL,
                custody_revision INTEGER NOT NULL,
                key_ref TEXT NOT NULL,
                key_revision INTEGER NOT NULL,
                encrypted_content BLOB NOT NULL,
                ciphertext_sha256 TEXT NOT NULL,
                updated_at REAL NOT NULL,
                row_sha256 TEXT NOT NULL,
                PRIMARY KEY(asset_id,asset_version),
                FOREIGN KEY(asset_id,asset_version)
                    REFERENCES trust_brand_asset_versions(asset_id,asset_version)
            );
            CREATE TABLE IF NOT EXISTS trust_brand_asset_custody(
                asset_id TEXT NOT NULL,
                asset_version INTEGER NOT NULL,
                custody_revision INTEGER NOT NULL,
                key_ref TEXT NOT NULL,
                key_revision INTEGER NOT NULL,
                ciphertext_sha256 TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                previous_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL,
                PRIMARY KEY(asset_id,asset_version,custody_revision)
            );
            CREATE TABLE IF NOT EXISTS trust_brand_asset_authorities(
                asset_id TEXT NOT NULL,
                asset_version INTEGER NOT NULL,
                authority_revision INTEGER NOT NULL,
                state TEXT NOT NULL,
                reviewed_by_sha256 TEXT,
                activated_by_sha256 TEXT,
                retained_until REAL,
                occurred_at REAL NOT NULL,
                previous_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL,
                PRIMARY KEY(asset_id,asset_version,authority_revision)
            );
            CREATE TABLE IF NOT EXISTS trust_brand_asset_heads(
                asset_id TEXT NOT NULL,
                asset_version INTEGER NOT NULL,
                authority_revision INTEGER NOT NULL,
                state TEXT NOT NULL,
                authority_sha256 TEXT NOT NULL,
                updated_at REAL NOT NULL,
                retained_until REAL,
                PRIMARY KEY(asset_id,asset_version)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS trust_brand_one_active_asset
                ON trust_brand_asset_heads(asset_id) WHERE state='active';
            CREATE TABLE IF NOT EXISTS trust_brand_asset_tombstones(
                asset_id TEXT NOT NULL,
                asset_version INTEGER NOT NULL,
                content_sha256 TEXT NOT NULL,
                final_authority_sha256 TEXT NOT NULL,
                final_ciphertext_sha256 TEXT NOT NULL,
                purged_at REAL NOT NULL,
                tombstone_sha256 TEXT NOT NULL,
                PRIMARY KEY(asset_id,asset_version)
            );
            CREATE TABLE IF NOT EXISTS trust_brand_domain_versions(
                claim_id TEXT NOT NULL,
                claim_version INTEGER NOT NULL,
                host TEXT NOT NULL,
                challenge_sha256 TEXT NOT NULL,
                challenge_expires_at REAL NOT NULL,
                created_by_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                row_sha256 TEXT NOT NULL,
                PRIMARY KEY(claim_id,claim_version)
            );
            CREATE TABLE IF NOT EXISTS trust_brand_domain_authorities(
                claim_id TEXT NOT NULL,
                claim_version INTEGER NOT NULL,
                authority_revision INTEGER NOT NULL,
                state TEXT NOT NULL,
                evidence_json TEXT,
                deployment_json TEXT,
                retained_until REAL,
                occurred_at REAL NOT NULL,
                previous_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL,
                PRIMARY KEY(claim_id,claim_version,authority_revision)
            );
            CREATE TABLE IF NOT EXISTS trust_brand_domain_heads(
                claim_id TEXT NOT NULL,
                claim_version INTEGER NOT NULL,
                authority_revision INTEGER NOT NULL,
                host TEXT NOT NULL,
                state TEXT NOT NULL,
                authority_sha256 TEXT NOT NULL,
                updated_at REAL NOT NULL,
                verified_until REAL,
                retained_until REAL,
                PRIMARY KEY(claim_id,claim_version)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS trust_brand_one_active_domain_id
                ON trust_brand_domain_heads(claim_id) WHERE state='active';
            CREATE UNIQUE INDEX IF NOT EXISTS trust_brand_one_active_host
                ON trust_brand_domain_heads(host) WHERE state='active';
            CREATE TABLE IF NOT EXISTS trust_brand_projections(
                projection_id TEXT PRIMARY KEY,
                projection_revision INTEGER NOT NULL,
                property_id TEXT NOT NULL,
                property_revision INTEGER NOT NULL,
                publication_id TEXT NOT NULL,
                publication_revision INTEGER NOT NULL,
                publication_sha256 TEXT NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                client_credential_id TEXT NOT NULL,
                client_revision INTEGER NOT NULL,
                client_record_sha256 TEXT NOT NULL,
                public_origin TEXT NOT NULL,
                public_host TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                asset_version INTEGER NOT NULL,
                asset_authority_sha256 TEXT NOT NULL,
                asset_content_sha256 TEXT NOT NULL,
                asset_kind TEXT NOT NULL,
                asset_media_type TEXT NOT NULL,
                asset_width INTEGER NOT NULL,
                asset_height INTEGER NOT NULL,
                domain_claim_id TEXT,
                domain_claim_version INTEGER,
                domain_authority_sha256 TEXT,
                domain_deployment_sha256 TEXT,
                created_at REAL NOT NULL,
                projection_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trust_brand_projection_heads(
                property_id TEXT PRIMARY KEY,
                projection_id TEXT NOT NULL,
                projection_revision INTEGER NOT NULL,
                state TEXT NOT NULL,
                updated_at REAL NOT NULL,
                FOREIGN KEY(projection_id) REFERENCES trust_brand_projections(projection_id)
            );
            CREATE TRIGGER IF NOT EXISTS trust_brand_asset_versions_no_update
                BEFORE UPDATE ON trust_brand_asset_versions
                BEGIN SELECT RAISE(ABORT,'brand asset versions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS trust_brand_asset_versions_no_delete
                BEFORE DELETE ON trust_brand_asset_versions
                BEGIN SELECT RAISE(ABORT,'brand asset versions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS trust_brand_asset_authorities_no_update
                BEFORE UPDATE ON trust_brand_asset_authorities
                BEGIN SELECT RAISE(ABORT,'brand asset authorities are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS trust_brand_domain_versions_no_update
                BEFORE UPDATE ON trust_brand_domain_versions
                BEGIN SELECT RAISE(ABORT,'brand domain versions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS trust_brand_projections_no_update
                BEFORE UPDATE ON trust_brand_projections
                BEGIN SELECT RAISE(ABORT,'brand projections are immutable'); END;
            """
        )
        now = _timestamp(self._clock(), "clock")
        row = connection.execute("SELECT * FROM trust_brand_meta WHERE singleton=1").fetchone()
        body = {
            "schema_version": SCHEMA_VERSION,
            "tenant_sha256": self.tenant_sha256,
            "created_at": now,
        }
        if row is None:
            connection.execute(
                "INSERT INTO trust_brand_meta VALUES(1,?,?,?,?)",
                (SCHEMA_VERSION, self.tenant_sha256, now, _sha256(body)),
            )
        else:
            self._verify_meta(connection)

    def _verify_meta(self, connection: sqlite3.Connection) -> None:
        row = connection.execute("SELECT * FROM trust_brand_meta WHERE singleton=1").fetchone()
        if row is None:
            raise BrandingIntegrityError("branding_store_meta_missing")
        body = {
            "schema_version": int(row["schema_version"]),
            "tenant_sha256": str(row["tenant_sha256"]),
            "created_at": float(row["created_at"]),
        }
        if (
            body["schema_version"] != SCHEMA_VERSION
            or body["tenant_sha256"] != self.tenant_sha256
            or not hmac.compare_digest(str(row["row_sha256"]), _sha256(body))
        ):
            raise BrandingIntegrityError("branding_store_meta_invalid")

    def _key(self, key_ref: str, key_revision: int) -> bytes:
        try:
            value = self._key_resolver(self.tenant_id, key_ref, key_revision)
        except Exception as exc:
            raise BrandingConfigError("branding_asset_key_unavailable") from exc
        if not isinstance(value, bytes) or len(value) != 32:
            raise BrandingConfigError("branding_asset_key_unavailable")
        return value

    def _aad(self, row: Mapping[str, Any]) -> bytes:
        return _canonical(
            {
                "schema": "lightwork.trust-center-brand-ciphertext.v1",
                "tenant_sha256": self.tenant_sha256,
                "asset_id": row["asset_id"],
                "asset_version": int(row["asset_version"]),
                "asset_kind": row["asset_kind"],
                "media_type": row["media_type"],
                "byte_size": int(row["byte_size"]),
                "width": int(row["width"]),
                "height": int(row["height"]),
                "content_sha256": row["content_sha256"],
            }
        )

    def _seal(self, content: bytes, row: Mapping[str, Any], key_ref: str, key_revision: int) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(self._key(key_ref, key_revision)).encrypt(
            nonce, content, self._aad(row)
        )

    def _unseal(
        self,
        encrypted: bytes,
        row: Mapping[str, Any],
        key_ref: str,
        key_revision: int,
    ) -> bytes:
        if len(encrypted) < 29:
            raise BrandingIntegrityError("branding_asset_ciphertext_invalid")
        try:
            return AESGCM(self._key(key_ref, key_revision)).decrypt(
                encrypted[:12], encrypted[12:], self._aad(row)
            )
        except BrandingConfigError:
            raise
        except Exception as exc:
            raise BrandingIntegrityError("branding_asset_decryption_failed") from exc

    def _asset_rows(
        self, connection: sqlite3.Connection, asset_id: str, asset_version: int
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        version = connection.execute(
            "SELECT * FROM trust_brand_asset_versions WHERE asset_id=? AND asset_version=?",
            (asset_id, asset_version),
        ).fetchone()
        head = connection.execute(
            "SELECT * FROM trust_brand_asset_heads WHERE asset_id=? AND asset_version=?",
            (asset_id, asset_version),
        ).fetchone()
        blob = connection.execute(
            "SELECT * FROM trust_brand_asset_blobs WHERE asset_id=? AND asset_version=?",
            (asset_id, asset_version),
        ).fetchone()
        if version is None or head is None:
            raise BrandingNotFound("branding_asset_not_found")
        if blob is None:
            raise BrandingNotFound("branding_asset_payload_purged")
        return version, head, blob

    def _asset_result(
        self, version: sqlite3.Row, head: sqlite3.Row, blob: sqlite3.Row
    ) -> AssetAuthority:
        return AssetAuthority(
            asset_id=str(version["asset_id"]),
            asset_version=int(version["asset_version"]),
            authority_revision=int(head["authority_revision"]),
            asset_kind=str(version["asset_kind"]),
            media_type=str(version["media_type"]),
            byte_size=int(version["byte_size"]),
            width=int(version["width"]),
            height=int(version["height"]),
            content_sha256=str(version["content_sha256"]),
            custody_revision=int(blob["custody_revision"]),
            key_ref=str(blob["key_ref"]),
            key_revision=int(blob["key_revision"]),
            state=str(head["state"]),
            created_at=float(version["created_at"]),
            updated_at=float(head["updated_at"]),
            retained_until=(
                float(head["retained_until"]) if head["retained_until"] is not None else None
            ),
            authority_sha256=str(head["authority_sha256"]),
        )

    def _append_asset_authority(
        self,
        connection: sqlite3.Connection,
        *,
        version: sqlite3.Row,
        head: sqlite3.Row | None,
        state: str,
        reviewed_by_sha256: str | None,
        activated_by_sha256: str | None,
        retained_until: float | None,
        occurred_at: float,
    ) -> sqlite3.Row:
        revision = 1 if head is None else int(head["authority_revision"]) + 1
        previous = GENESIS_SHA256 if head is None else str(head["authority_sha256"])
        body = {
            "schema": "lightwork.trust-center-brand-asset-authority.v1",
            "tenant_sha256": self.tenant_sha256,
            "asset_id": version["asset_id"],
            "asset_version": int(version["asset_version"]),
            "authority_revision": revision,
            "content_sha256": version["content_sha256"],
            "state": state,
            "reviewed_by_sha256": reviewed_by_sha256,
            "activated_by_sha256": activated_by_sha256,
            "retained_until": retained_until,
            "occurred_at": occurred_at,
            "previous_sha256": previous,
        }
        event_sha = _sha256(body)
        connection.execute(
            "INSERT INTO trust_brand_asset_authorities VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                version["asset_id"],
                version["asset_version"],
                revision,
                state,
                reviewed_by_sha256,
                activated_by_sha256,
                retained_until,
                occurred_at,
                previous,
                event_sha,
            ),
        )
        if head is None:
            connection.execute(
                "INSERT INTO trust_brand_asset_heads VALUES(?,?,?,?,?,?,?)",
                (
                    version["asset_id"],
                    version["asset_version"],
                    revision,
                    state,
                    event_sha,
                    occurred_at,
                    retained_until,
                ),
            )
        else:
            updated = connection.execute(
                "UPDATE trust_brand_asset_heads SET authority_revision=?,state=?,"
                "authority_sha256=?,updated_at=?,retained_until=? WHERE asset_id=? "
                "AND asset_version=? AND authority_revision=?",
                (
                    revision,
                    state,
                    event_sha,
                    occurred_at,
                    retained_until,
                    version["asset_id"],
                    version["asset_version"],
                    int(head["authority_revision"]),
                ),
            )
            if updated.rowcount != 1:
                raise BrandingConflict("branding_asset_changed_concurrently")
        return connection.execute(
            "SELECT * FROM trust_brand_asset_heads WHERE asset_id=? AND asset_version=?",
            (version["asset_id"], version["asset_version"]),
        ).fetchone()

    def propose_asset(
        self,
        asset_id: str,
        *,
        expected_version: int,
        asset_kind: str,
        media_type: str,
        content: bytes,
        actor_ref: str,
    ) -> AssetAuthority:
        asset = _identifier(asset_id, "asset_id")
        expected = _positive_int(expected_version, "expected_version", 0, 2_147_483_646)
        if asset_kind not in ALLOWED_ASSET_KINDS:
            raise BrandingValidationError("branding_asset_kind_invalid")
        content, media, width, height, content_sha = validate_raster(
            content,
            media_type,
            max_bytes=self.config.max_asset_bytes,
            max_width=self.config.max_width,
            max_height=self.config.max_height,
            max_pixels=self.config.max_pixels,
        )
        actor_sha = _actor_sha256(self.tenant_sha256, actor_ref)
        now = _timestamp(self._clock(), "clock")
        with self._transaction() as connection:
            live = connection.execute("SELECT COUNT(*) FROM trust_brand_asset_blobs").fetchone()[0]
            if int(live) >= self.config.max_assets:
                raise BrandingConflict("branding_asset_capacity_reached")
            current = connection.execute(
                "SELECT COALESCE(MAX(asset_version),0) FROM trust_brand_asset_versions "
                "WHERE asset_id=?",
                (asset,),
            ).fetchone()[0]
            if int(current) != expected:
                raise BrandingConflict("branding_asset_version_changed")
            version_number = expected + 1
            version_body = {
                "schema": "lightwork.trust-center-brand-asset.v1",
                "tenant_sha256": self.tenant_sha256,
                "asset_id": asset,
                "asset_version": version_number,
                "asset_kind": asset_kind,
                "media_type": media,
                "byte_size": len(content),
                "width": width,
                "height": height,
                "content_sha256": content_sha,
                "created_by_sha256": actor_sha,
                "created_at": now,
            }
            connection.execute(
                "INSERT INTO trust_brand_asset_versions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    asset,
                    version_number,
                    asset_kind,
                    media,
                    len(content),
                    width,
                    height,
                    content_sha,
                    actor_sha,
                    now,
                    _sha256(version_body),
                ),
            )
            version = connection.execute(
                "SELECT * FROM trust_brand_asset_versions WHERE asset_id=? AND asset_version=?",
                (asset, version_number),
            ).fetchone()
            encrypted = self._seal(
                content, version, self.config.key_ref, self.config.key_revision
            )
            cipher_sha = hashlib.sha256(encrypted).hexdigest()
            custody_body = {
                "schema": "lightwork.trust-center-brand-custody.v1",
                "tenant_sha256": self.tenant_sha256,
                "asset_id": asset,
                "asset_version": version_number,
                "custody_revision": 1,
                "key_ref": self.config.key_ref,
                "key_revision": self.config.key_revision,
                "ciphertext_sha256": cipher_sha,
                "occurred_at": now,
                "previous_sha256": GENESIS_SHA256,
            }
            custody_sha = _sha256(custody_body)
            blob_body = {**custody_body, "event_sha256": custody_sha}
            connection.execute(
                "INSERT INTO trust_brand_asset_blobs VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    asset,
                    version_number,
                    1,
                    self.config.key_ref,
                    self.config.key_revision,
                    encrypted,
                    cipher_sha,
                    now,
                    _sha256(blob_body),
                ),
            )
            connection.execute(
                "INSERT INTO trust_brand_asset_custody VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    asset,
                    version_number,
                    1,
                    self.config.key_ref,
                    self.config.key_revision,
                    cipher_sha,
                    now,
                    GENESIS_SHA256,
                    custody_sha,
                ),
            )
            head = self._append_asset_authority(
                connection,
                version=version,
                head=None,
                state="pending_review",
                reviewed_by_sha256=None,
                activated_by_sha256=None,
                retained_until=None,
                occurred_at=now,
            )
            blob = connection.execute(
                "SELECT * FROM trust_brand_asset_blobs WHERE asset_id=? AND asset_version=?",
                (asset, version_number),
            ).fetchone()
            return self._asset_result(version, head, blob)

    def review_asset(
        self,
        asset_id: str,
        asset_version: int,
        *,
        expected_authority_revision: int,
        actor_ref: str,
        approve: bool,
    ) -> AssetAuthority:
        asset = _identifier(asset_id, "asset_id")
        version_number = _positive_int(asset_version, "asset_version", 1, 2_147_483_647)
        expected = _positive_int(
            expected_authority_revision, "expected_authority_revision", 1, 2_147_483_647
        )
        if type(approve) is not bool:
            raise BrandingValidationError("branding_review_decision_invalid")
        reviewer = _actor_sha256(self.tenant_sha256, actor_ref)
        now = _timestamp(self._clock(), "clock")
        with self._transaction() as connection:
            version, head, blob = self._asset_rows(connection, asset, version_number)
            if int(head["authority_revision"]) != expected or head["state"] != "pending_review":
                raise BrandingConflict("branding_asset_state_changed")
            if hmac.compare_digest(str(version["created_by_sha256"]), reviewer):
                raise BrandingConflict("branding_independent_review_required")
            state = "approved" if approve else "rejected"
            retained = None if approve else now + self.config.retention_seconds
            head = self._append_asset_authority(
                connection,
                version=version,
                head=head,
                state=state,
                reviewed_by_sha256=reviewer,
                activated_by_sha256=None,
                retained_until=retained,
                occurred_at=now,
            )
            return self._asset_result(version, head, blob)

    def activate_asset(
        self,
        asset_id: str,
        asset_version: int,
        *,
        expected_authority_revision: int,
        actor_ref: str,
    ) -> AssetAuthority:
        asset = _identifier(asset_id, "asset_id")
        version_number = _positive_int(asset_version, "asset_version", 1, 2_147_483_647)
        expected = _positive_int(
            expected_authority_revision, "expected_authority_revision", 1, 2_147_483_647
        )
        actor = _actor_sha256(self.tenant_sha256, actor_ref)
        now = _timestamp(self._clock(), "clock")
        with self._transaction() as connection:
            version, head, blob = self._asset_rows(connection, asset, version_number)
            if int(head["authority_revision"]) != expected or head["state"] != "approved":
                raise BrandingConflict("branding_asset_state_changed")
            review = connection.execute(
                "SELECT reviewed_by_sha256 FROM trust_brand_asset_authorities WHERE "
                "asset_id=? AND asset_version=? AND state='approved' ORDER BY authority_revision "
                "DESC LIMIT 1",
                (asset, version_number),
            ).fetchone()
            if review is None or hmac.compare_digest(str(version["created_by_sha256"]), actor):
                raise BrandingConflict("branding_independent_activation_required")
            previous = connection.execute(
                "SELECT * FROM trust_brand_asset_heads WHERE asset_id=? AND state='active'",
                (asset,),
            ).fetchone()
            if previous is not None:
                previous_version = connection.execute(
                    "SELECT * FROM trust_brand_asset_versions WHERE asset_id=? AND asset_version=?",
                    (asset, previous["asset_version"]),
                ).fetchone()
                self._append_asset_authority(
                    connection,
                    version=previous_version,
                    head=previous,
                    state="superseded",
                    reviewed_by_sha256=None,
                    activated_by_sha256=None,
                    retained_until=now + self.config.retention_seconds,
                    occurred_at=now,
                )
            head = self._append_asset_authority(
                connection,
                version=version,
                head=head,
                state="active",
                reviewed_by_sha256=str(review["reviewed_by_sha256"]),
                activated_by_sha256=actor,
                retained_until=None,
                occurred_at=now,
            )
            return self._asset_result(version, head, blob)

    def revoke_asset(
        self,
        asset_id: str,
        asset_version: int,
        *,
        expected_authority_revision: int,
        actor_ref: str,
    ) -> AssetAuthority:
        _actor_sha256(self.tenant_sha256, actor_ref)
        asset = _identifier(asset_id, "asset_id")
        version_number = _positive_int(asset_version, "asset_version", 1, 2_147_483_647)
        expected = _positive_int(
            expected_authority_revision, "expected_authority_revision", 1, 2_147_483_647
        )
        now = _timestamp(self._clock(), "clock")
        with self._transaction() as connection:
            version, head, blob = self._asset_rows(connection, asset, version_number)
            if int(head["authority_revision"]) != expected or head["state"] in {
                "revoked",
                "superseded",
                "rejected",
            }:
                raise BrandingConflict("branding_asset_state_changed")
            head = self._append_asset_authority(
                connection,
                version=version,
                head=head,
                state="revoked",
                reviewed_by_sha256=None,
                activated_by_sha256=None,
                retained_until=now + self.config.retention_seconds,
                occurred_at=now,
            )
            return self._asset_result(version, head, blob)

    def rotate_asset_custody(
        self,
        asset_id: str,
        asset_version: int,
        *,
        expected_custody_revision: int,
        actor_ref: str,
    ) -> AssetAuthority:
        _actor_sha256(self.tenant_sha256, actor_ref)
        asset = _identifier(asset_id, "asset_id")
        version_number = _positive_int(asset_version, "asset_version", 1, 2_147_483_647)
        expected = _positive_int(
            expected_custody_revision, "expected_custody_revision", 1, 2_147_483_647
        )
        now = _timestamp(self._clock(), "clock")
        with self._transaction() as connection:
            version, head, blob = self._asset_rows(connection, asset, version_number)
            if int(blob["custody_revision"]) != expected:
                raise BrandingConflict("branding_asset_custody_changed")
            if (
                blob["key_ref"] == self.config.key_ref
                and int(blob["key_revision"]) == self.config.key_revision
            ):
                raise BrandingConflict("branding_asset_custody_already_current")
            encrypted = bytes(blob["encrypted_content"])
            if not hmac.compare_digest(
                str(blob["ciphertext_sha256"]), hashlib.sha256(encrypted).hexdigest()
            ):
                raise BrandingIntegrityError("branding_asset_ciphertext_invalid")
            content = self._unseal(
                encrypted, version, str(blob["key_ref"]), int(blob["key_revision"])
            )
            if not hmac.compare_digest(
                str(version["content_sha256"]), hashlib.sha256(content).hexdigest()
            ):
                raise BrandingIntegrityError("branding_asset_content_invalid")
            rotated = self._seal(
                content, version, self.config.key_ref, self.config.key_revision
            )
            cipher_sha = hashlib.sha256(rotated).hexdigest()
            custody_revision = expected + 1
            previous = connection.execute(
                "SELECT event_sha256 FROM trust_brand_asset_custody WHERE asset_id=? "
                "AND asset_version=? AND custody_revision=?",
                (asset, version_number, expected),
            ).fetchone()
            if previous is None:
                raise BrandingIntegrityError("branding_asset_custody_invalid")
            custody_body = {
                "schema": "lightwork.trust-center-brand-custody.v1",
                "tenant_sha256": self.tenant_sha256,
                "asset_id": asset,
                "asset_version": version_number,
                "custody_revision": custody_revision,
                "key_ref": self.config.key_ref,
                "key_revision": self.config.key_revision,
                "ciphertext_sha256": cipher_sha,
                "occurred_at": now,
                "previous_sha256": previous["event_sha256"],
            }
            event_sha = _sha256(custody_body)
            updated = connection.execute(
                "UPDATE trust_brand_asset_blobs SET custody_revision=?,key_ref=?,"
                "key_revision=?,encrypted_content=?,ciphertext_sha256=?,updated_at=?,"
                "row_sha256=? WHERE asset_id=? AND asset_version=? AND custody_revision=?",
                (
                    custody_revision,
                    self.config.key_ref,
                    self.config.key_revision,
                    rotated,
                    cipher_sha,
                    now,
                    _sha256({**custody_body, "event_sha256": event_sha}),
                    asset,
                    version_number,
                    expected,
                ),
            )
            if updated.rowcount != 1:
                raise BrandingConflict("branding_asset_custody_changed")
            connection.execute(
                "INSERT INTO trust_brand_asset_custody VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    asset,
                    version_number,
                    custody_revision,
                    self.config.key_ref,
                    self.config.key_revision,
                    cipher_sha,
                    now,
                    previous["event_sha256"],
                    event_sha,
                ),
            )
            blob = connection.execute(
                "SELECT * FROM trust_brand_asset_blobs WHERE asset_id=? AND asset_version=?",
                (asset, version_number),
            ).fetchone()
            return self._asset_result(version, head, blob)

    def get_asset(self, asset_id: str, asset_version: int) -> AssetAuthority:
        asset = _identifier(asset_id, "asset_id")
        version_number = _positive_int(asset_version, "asset_version", 1, 2_147_483_647)
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta(connection)
            return self._asset_result(*self._asset_rows(connection, asset, version_number))

    def purge_assets(self, *, before: float, limit: int = 100) -> dict[str, int]:
        selected = _timestamp(before, "before")
        page = _positive_int(limit, "limit", 1, 500)
        purged = 0
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT h.*,v.content_sha256,b.ciphertext_sha256 FROM "
                "trust_brand_asset_heads h JOIN trust_brand_asset_versions v USING(asset_id,asset_version) "
                "JOIN trust_brand_asset_blobs b USING(asset_id,asset_version) WHERE h.state IN "
                "('revoked','rejected','superseded') AND h.retained_until<=? ORDER BY "
                "h.retained_until LIMIT ?",
                (selected, page),
            ).fetchall()
            now = _timestamp(self._clock(), "clock")
            for row in rows:
                body = {
                    "schema": "lightwork.trust-center-brand-asset-tombstone.v1",
                    "tenant_sha256": self.tenant_sha256,
                    "asset_id": row["asset_id"],
                    "asset_version": int(row["asset_version"]),
                    "content_sha256": row["content_sha256"],
                    "final_authority_sha256": row["authority_sha256"],
                    "final_ciphertext_sha256": row["ciphertext_sha256"],
                    "purged_at": now,
                }
                connection.execute(
                    "INSERT OR IGNORE INTO trust_brand_asset_tombstones VALUES(?,?,?,?,?,?,?)",
                    (
                        row["asset_id"],
                        row["asset_version"],
                        row["content_sha256"],
                        row["authority_sha256"],
                        row["ciphertext_sha256"],
                        now,
                        _sha256(body),
                    ),
                )
                purged += connection.execute(
                    "DELETE FROM trust_brand_asset_blobs WHERE asset_id=? AND asset_version=?",
                    (row["asset_id"], row["asset_version"]),
                ).rowcount
        return {"purged": purged}

    def _domain_rows(
        self, connection: sqlite3.Connection, claim_id: str, claim_version: int
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        version = connection.execute(
            "SELECT * FROM trust_brand_domain_versions WHERE claim_id=? AND claim_version=?",
            (claim_id, claim_version),
        ).fetchone()
        head = connection.execute(
            "SELECT * FROM trust_brand_domain_heads WHERE claim_id=? AND claim_version=?",
            (claim_id, claim_version),
        ).fetchone()
        event = connection.execute(
            "SELECT * FROM trust_brand_domain_authorities WHERE claim_id=? AND claim_version=? "
            "ORDER BY authority_revision DESC LIMIT 1",
            (claim_id, claim_version),
        ).fetchone()
        if version is None or head is None or event is None:
            raise BrandingNotFound("branding_domain_not_found")
        return version, head, event

    def _domain_result(
        self, version: sqlite3.Row, head: sqlite3.Row, event: sqlite3.Row
    ) -> DomainAuthority:
        deployment = json.loads(event["deployment_json"]) if event["deployment_json"] else None
        return DomainAuthority(
            claim_id=str(version["claim_id"]),
            claim_version=int(version["claim_version"]),
            authority_revision=int(head["authority_revision"]),
            host=str(version["host"]),
            state=str(head["state"]),
            challenge_sha256=str(version["challenge_sha256"]),
            challenge_expires_at=float(version["challenge_expires_at"]),
            deployment_sha256=(deployment or {}).get("deployment_sha256"),
            dns_evidence_sha256=(deployment or {}).get("dns_evidence_sha256"),
            tls_certificate_sha256=(deployment or {}).get("tls_certificate_sha256"),
            verified_until=(
                float(head["verified_until"]) if head["verified_until"] is not None else None
            ),
            updated_at=float(head["updated_at"]),
            retained_until=(
                float(head["retained_until"]) if head["retained_until"] is not None else None
            ),
            authority_sha256=str(head["authority_sha256"]),
        )

    def _append_domain_authority(
        self,
        connection: sqlite3.Connection,
        *,
        version: sqlite3.Row,
        head: sqlite3.Row | None,
        state: str,
        evidence: DomainVerificationEvidence | None,
        deployment: DomainDeploymentBinding | None,
        verified_until: float | None,
        retained_until: float | None,
        occurred_at: float,
    ) -> sqlite3.Row:
        revision = 1 if head is None else int(head["authority_revision"]) + 1
        previous = GENESIS_SHA256 if head is None else str(head["authority_sha256"])
        evidence_json = _canonical(asdict(evidence)).decode("ascii") if evidence else None
        deployment_json = _canonical(asdict(deployment)).decode("ascii") if deployment else None
        body = {
            "schema": "lightwork.trust-center-domain-authority.v1",
            "tenant_sha256": self.tenant_sha256,
            "claim_id": version["claim_id"],
            "claim_version": int(version["claim_version"]),
            "host": version["host"],
            "challenge_sha256": version["challenge_sha256"],
            "authority_revision": revision,
            "state": state,
            "evidence_sha256": _text_sha256(evidence_json) if evidence_json else None,
            "deployment_sha256": deployment.deployment_sha256 if deployment else None,
            "verified_until": verified_until,
            "retained_until": retained_until,
            "occurred_at": occurred_at,
            "previous_sha256": previous,
        }
        event_sha = _sha256(body)
        connection.execute(
            "INSERT INTO trust_brand_domain_authorities VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                version["claim_id"],
                version["claim_version"],
                revision,
                state,
                evidence_json,
                deployment_json,
                retained_until,
                occurred_at,
                previous,
                event_sha,
            ),
        )
        if head is None:
            connection.execute(
                "INSERT INTO trust_brand_domain_heads VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    version["claim_id"],
                    version["claim_version"],
                    revision,
                    version["host"],
                    state,
                    event_sha,
                    occurred_at,
                    verified_until,
                    retained_until,
                ),
            )
        else:
            updated = connection.execute(
                "UPDATE trust_brand_domain_heads SET authority_revision=?,state=?,"
                "authority_sha256=?,updated_at=?,verified_until=?,retained_until=? WHERE "
                "claim_id=? AND claim_version=? AND authority_revision=?",
                (
                    revision,
                    state,
                    event_sha,
                    occurred_at,
                    verified_until,
                    retained_until,
                    version["claim_id"],
                    version["claim_version"],
                    int(head["authority_revision"]),
                ),
            )
            if updated.rowcount != 1:
                raise BrandingConflict("branding_domain_changed_concurrently")
        return connection.execute(
            "SELECT * FROM trust_brand_domain_heads WHERE claim_id=? AND claim_version=?",
            (version["claim_id"], version["claim_version"]),
        ).fetchone()

    def challenge_domain(
        self,
        claim_id: str,
        host: str,
        *,
        expected_claim_version: int,
        actor_ref: str,
    ) -> tuple[DomainAuthority, str]:
        claim = _identifier(claim_id, "claim_id")
        domain = _host(host)
        expected = _positive_int(
            expected_claim_version, "expected_claim_version", 0, 2_147_483_646
        )
        actor = _actor_sha256(self.tenant_sha256, actor_ref)
        token = self._token_factory()
        if not isinstance(token, str) or not 32 <= len(token) <= 256:
            raise BrandingConfigError("branding_domain_token_factory_invalid")
        token_sha = _text_sha256(token)
        now = _timestamp(self._clock(), "clock")
        with self._transaction() as connection:
            current = connection.execute(
                "SELECT COALESCE(MAX(claim_version),0) FROM trust_brand_domain_versions "
                "WHERE claim_id=?",
                (claim,),
            ).fetchone()[0]
            if int(current) != expected:
                raise BrandingConflict("branding_domain_version_changed")
            count = connection.execute(
                "SELECT COUNT(DISTINCT claim_id) FROM trust_brand_domain_versions"
            ).fetchone()[0]
            if expected == 0 and int(count) >= self.config.max_domains:
                raise BrandingConflict("branding_domain_capacity_reached")
            if expected:
                _, previous, _ = self._domain_rows(connection, claim, expected)
                if previous["state"] not in {"expired", "revoked", "rejected"}:
                    raise BrandingConflict("branding_domain_recovery_not_allowed")
            version_number = expected + 1
            expires = now + self.config.challenge_ttl_seconds
            body = {
                "schema": "lightwork.trust-center-domain-claim.v1",
                "tenant_sha256": self.tenant_sha256,
                "claim_id": claim,
                "claim_version": version_number,
                "host": domain,
                "challenge_sha256": token_sha,
                "challenge_expires_at": expires,
                "created_by_sha256": actor,
                "created_at": now,
            }
            connection.execute(
                "INSERT INTO trust_brand_domain_versions VALUES(?,?,?,?,?,?,?,?)",
                (
                    claim,
                    version_number,
                    domain,
                    token_sha,
                    expires,
                    actor,
                    now,
                    _sha256(body),
                ),
            )
            version = connection.execute(
                "SELECT * FROM trust_brand_domain_versions WHERE claim_id=? AND claim_version=?",
                (claim, version_number),
            ).fetchone()
            head = self._append_domain_authority(
                connection,
                version=version,
                head=None,
                state="challenged",
                evidence=None,
                deployment=None,
                verified_until=None,
                retained_until=None,
                occurred_at=now,
            )
            event = connection.execute(
                "SELECT * FROM trust_brand_domain_authorities WHERE claim_id=? AND claim_version=?",
                (claim, version_number),
            ).fetchone()
            return self._domain_result(version, head, event), token

    def _request_for(self, version: sqlite3.Row) -> DomainVerificationRequest:
        return _verification_request(
            DomainVerificationRequest(
                tenant_sha256=self.tenant_sha256,
                claim_id=str(version["claim_id"]),
                claim_version=int(version["claim_version"]),
                host=str(version["host"]),
                challenge_sha256=str(version["challenge_sha256"]),
                challenge_expires_at=float(version["challenge_expires_at"]),
            )
        )

    def verify_domain(
        self,
        claim_id: str,
        claim_version: int,
        *,
        expected_authority_revision: int,
        actor_ref: str,
    ) -> DomainAuthority:
        _actor_sha256(self.tenant_sha256, actor_ref)
        if self._domain_authority is None:
            raise BrandingExternalAuthorityError("branding_domain_authority_unavailable")
        claim = _identifier(claim_id, "claim_id")
        version_number = _positive_int(claim_version, "claim_version", 1, 2_147_483_647)
        expected = _positive_int(
            expected_authority_revision, "expected_authority_revision", 1, 2_147_483_647
        )
        now = _timestamp(self._clock(), "clock")
        with _closing_sqlite(self._connect()) as connection, connection:
            version, head, _ = self._domain_rows(connection, claim, version_number)
            if int(head["authority_revision"]) != expected or head["state"] != "challenged":
                raise BrandingConflict("branding_domain_state_changed")
            request = self._request_for(version)
        if request.challenge_expires_at <= now:
            raise BrandingConflict("branding_domain_challenge_expired")
        try:
            raw = self._domain_authority.verify(request)
        except BrandingExternalAuthorityError:
            raise
        except Exception as exc:
            raise BrandingExternalAuthorityError("branding_domain_verification_unavailable") from exc
        evidence = _validated_evidence(
            raw, request, now=now, maximum_ttl=self.config.verification_ttl_seconds
        )
        with self._transaction() as connection:
            version, head, _ = self._domain_rows(connection, claim, version_number)
            if int(head["authority_revision"]) != expected or head["state"] != "challenged":
                raise BrandingConflict("branding_domain_state_changed")
            head = self._append_domain_authority(
                connection,
                version=version,
                head=head,
                state="verified",
                evidence=evidence,
                deployment=None,
                verified_until=evidence.valid_until,
                retained_until=None,
                occurred_at=now,
            )
            event = connection.execute(
                "SELECT * FROM trust_brand_domain_authorities WHERE claim_id=? AND "
                "claim_version=? ORDER BY authority_revision DESC LIMIT 1",
                (claim, version_number),
            ).fetchone()
            return self._domain_result(version, head, event)

    def activate_domain(
        self,
        claim_id: str,
        claim_version: int,
        *,
        expected_authority_revision: int,
        actor_ref: str,
    ) -> DomainAuthority:
        _actor_sha256(self.tenant_sha256, actor_ref)
        if self._domain_authority is None:
            raise BrandingExternalAuthorityError("branding_domain_authority_unavailable")
        claim = _identifier(claim_id, "claim_id")
        version_number = _positive_int(claim_version, "claim_version", 1, 2_147_483_647)
        expected = _positive_int(
            expected_authority_revision, "expected_authority_revision", 1, 2_147_483_647
        )
        now = _timestamp(self._clock(), "clock")
        with _closing_sqlite(self._connect()) as connection, connection:
            version, head, event = self._domain_rows(connection, claim, version_number)
            if int(head["authority_revision"]) != expected or head["state"] != "verified":
                raise BrandingConflict("branding_domain_state_changed")
            if head["verified_until"] is None or float(head["verified_until"]) <= now:
                raise BrandingConflict("branding_domain_verification_expired")
            request = self._request_for(version)
            evidence = DomainVerificationEvidence(**json.loads(event["evidence_json"]))
            _validated_evidence(
                evidence, request, now=now, maximum_ttl=self.config.verification_ttl_seconds
            )
        try:
            raw = self._domain_authority.activate(request, evidence)
        except Exception as exc:
            raise BrandingExternalAuthorityError("branding_domain_activation_unavailable") from exc
        deployment = _validated_deployment(
            raw, request, now=now, maximum_ttl=self.config.verification_ttl_seconds
        )
        if (
            not hmac.compare_digest(
                deployment.dns_evidence_sha256, evidence.dns_evidence_sha256
            )
            or not hmac.compare_digest(
                deployment.tls_certificate_sha256, evidence.tls_certificate_sha256
            )
        ):
            raise BrandingExternalAuthorityError("branding_domain_deployment_invalid")
        with self._transaction() as connection:
            version, head, _ = self._domain_rows(connection, claim, version_number)
            if int(head["authority_revision"]) != expected or head["state"] != "verified":
                raise BrandingConflict("branding_domain_state_changed")
            head = self._append_domain_authority(
                connection,
                version=version,
                head=head,
                state="active",
                evidence=evidence,
                deployment=deployment,
                verified_until=deployment.valid_until,
                retained_until=None,
                occurred_at=now,
            )
            event = connection.execute(
                "SELECT * FROM trust_brand_domain_authorities WHERE claim_id=? AND "
                "claim_version=? ORDER BY authority_revision DESC LIMIT 1",
                (claim, version_number),
            ).fetchone()
            return self._domain_result(version, head, event)

    def reverify_domain(
        self,
        claim_id: str,
        claim_version: int,
        *,
        expected_authority_revision: int,
        actor_ref: str,
    ) -> DomainAuthority:
        _actor_sha256(self.tenant_sha256, actor_ref)
        if self._domain_authority is None:
            raise BrandingExternalAuthorityError("branding_domain_authority_unavailable")
        claim = _identifier(claim_id, "claim_id")
        version_number = _positive_int(claim_version, "claim_version", 1, 2_147_483_647)
        expected = _positive_int(
            expected_authority_revision, "expected_authority_revision", 1, 2_147_483_647
        )
        now = _timestamp(self._clock(), "clock")
        with _closing_sqlite(self._connect()) as connection, connection:
            version, head, event = self._domain_rows(connection, claim, version_number)
            if int(head["authority_revision"]) != expected or head["state"] != "active":
                raise BrandingConflict("branding_domain_state_changed")
            binding = DomainDeploymentBinding(**json.loads(event["deployment_json"]))
            request = self._request_for(version)
        try:
            raw = self._domain_authority.reverify(binding)
        except Exception as exc:
            raise BrandingExternalAuthorityError("branding_domain_reverification_unavailable") from exc
        current = _validated_deployment(
            raw, request, now=now, maximum_ttl=self.config.verification_ttl_seconds
        )
        with self._transaction() as connection:
            version, head, _ = self._domain_rows(connection, claim, version_number)
            if int(head["authority_revision"]) != expected or head["state"] != "active":
                raise BrandingConflict("branding_domain_state_changed")
            head = self._append_domain_authority(
                connection,
                version=version,
                head=head,
                state="active",
                evidence=None,
                deployment=current,
                verified_until=current.valid_until,
                retained_until=None,
                occurred_at=now,
            )
            event = connection.execute(
                "SELECT * FROM trust_brand_domain_authorities WHERE claim_id=? AND "
                "claim_version=? ORDER BY authority_revision DESC LIMIT 1",
                (claim, version_number),
            ).fetchone()
            return self._domain_result(version, head, event)

    def revoke_domain(
        self,
        claim_id: str,
        claim_version: int,
        *,
        expected_authority_revision: int,
        actor_ref: str,
    ) -> tuple[DomainAuthority, bool]:
        _actor_sha256(self.tenant_sha256, actor_ref)
        claim = _identifier(claim_id, "claim_id")
        version_number = _positive_int(claim_version, "claim_version", 1, 2_147_483_647)
        expected = _positive_int(
            expected_authority_revision, "expected_authority_revision", 1, 2_147_483_647
        )
        now = _timestamp(self._clock(), "clock")
        binding: DomainDeploymentBinding | None = None
        with self._transaction() as connection:
            version, head, event = self._domain_rows(connection, claim, version_number)
            if int(head["authority_revision"]) != expected or head["state"] in {
                "revoked",
                "expired",
            }:
                raise BrandingConflict("branding_domain_state_changed")
            if event["deployment_json"]:
                binding = DomainDeploymentBinding(**json.loads(event["deployment_json"]))
            head = self._append_domain_authority(
                connection,
                version=version,
                head=head,
                state="revoked",
                evidence=None,
                deployment=binding,
                verified_until=None,
                retained_until=now + self.config.retention_seconds,
                occurred_at=now,
            )
            current_event = connection.execute(
                "SELECT * FROM trust_brand_domain_authorities WHERE claim_id=? AND "
                "claim_version=? ORDER BY authority_revision DESC LIMIT 1",
                (claim, version_number),
            ).fetchone()
            result = self._domain_result(version, head, current_event)
        confirmed = binding is None
        if binding is not None and self._domain_authority is not None:
            try:
                confirmed = self._domain_authority.revoke(binding) is True
            except Exception:
                confirmed = False
        return result, confirmed

    def expire_domains(self, *, limit: int = 100) -> dict[str, int]:
        page = _positive_int(limit, "limit", 1, 500)
        now = _timestamp(self._clock(), "clock")
        expired = 0
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM trust_brand_domain_heads WHERE state IN ('active','verified','challenged') "
                "AND COALESCE(verified_until,(SELECT challenge_expires_at FROM "
                "trust_brand_domain_versions v WHERE v.claim_id=trust_brand_domain_heads.claim_id "
                "AND v.claim_version=trust_brand_domain_heads.claim_version))<=? LIMIT ?",
                (now, page),
            ).fetchall()
            for head in rows:
                version, current, event = self._domain_rows(
                    connection, str(head["claim_id"]), int(head["claim_version"])
                )
                deployment = (
                    DomainDeploymentBinding(**json.loads(event["deployment_json"]))
                    if event["deployment_json"]
                    else None
                )
                self._append_domain_authority(
                    connection,
                    version=version,
                    head=current,
                    state="expired",
                    evidence=None,
                    deployment=deployment,
                    verified_until=None,
                    retained_until=now + self.config.retention_seconds,
                    occurred_at=now,
                )
                expired += 1
        return {"expired": expired}

    def get_domain(self, claim_id: str, claim_version: int) -> DomainAuthority:
        claim = _identifier(claim_id, "claim_id")
        version_number = _positive_int(claim_version, "claim_version", 1, 2_147_483_647)
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta(connection)
            return self._domain_result(*self._domain_rows(connection, claim, version_number))

    def _current_publication(self, property_id: str, client_id: str) -> BrandPublicationAuthority:
        try:
            raw = self._publication_resolver(property_id, client_id)
        except TrustCenterBrandingError:
            raise
        except Exception as exc:
            raise BrandingExternalAuthorityError("branding_publication_authority_unavailable") from exc
        if type(raw) is not BrandPublicationAuthority:
            raise BrandingExternalAuthorityError("branding_publication_authority_invalid")
        current = raw.normalized()
        if current.tenant_id != self.tenant_id:
            raise BrandingIntegrityError("branding_publication_tenant_changed")
        _ = current.public_host
        return current

    @staticmethod
    def _projection_from_row(row: sqlite3.Row, *, state: str) -> BrandProjection:
        fields = {
            key: row[key]
            for key in (
                "projection_id",
                "projection_revision",
                "property_id",
                "property_revision",
                "publication_id",
                "publication_revision",
                "publication_sha256",
                "bundle_sha256",
                "client_credential_id",
                "client_revision",
                "client_record_sha256",
                "public_origin",
                "public_host",
                "asset_id",
                "asset_version",
                "asset_authority_sha256",
                "asset_content_sha256",
                "asset_kind",
                "asset_media_type",
                "asset_width",
                "asset_height",
                "domain_claim_id",
                "domain_claim_version",
                "domain_authority_sha256",
                "domain_deployment_sha256",
                "created_at",
                "projection_sha256",
            )
        }
        fields["state"] = state
        return BrandProjection(**fields)

    def bind_projection(
        self,
        property_id: str,
        client_credential_id: str,
        *,
        asset_id: str,
        asset_version: int,
        domain_claim_id: str | None,
        domain_claim_version: int | None,
        expected_projection_revision: int,
        actor_ref: str,
    ) -> BrandProjection:
        _actor_sha256(self.tenant_sha256, actor_ref)
        property_ref = _identifier(property_id, "property_id")
        client_ref = _identifier(client_credential_id, "client_credential_id")
        asset_ref = _identifier(asset_id, "asset_id")
        asset_ver = _positive_int(asset_version, "asset_version", 1, 2_147_483_647)
        expected = _positive_int(
            expected_projection_revision, "expected_projection_revision", 0, 2_147_483_646
        )
        if (domain_claim_id is None) != (domain_claim_version is None):
            raise BrandingValidationError("branding_domain_selector_invalid")
        current = self._current_publication(property_ref, client_ref)
        now = _timestamp(self._clock(), "clock")
        with self._transaction() as connection:
            version, asset_head, _ = self._asset_rows(connection, asset_ref, asset_ver)
            if asset_head["state"] != "active":
                raise BrandingConflict("branding_asset_not_active")
            domain: DomainAuthority | None = None
            if domain_claim_id is not None and domain_claim_version is not None:
                claim_ref = _identifier(domain_claim_id, "claim_id")
                claim_ver = _positive_int(
                    domain_claim_version, "claim_version", 1, 2_147_483_647
                )
                domain = self._domain_result(
                    *self._domain_rows(connection, claim_ref, claim_ver)
                )
                if (
                    domain.state != "active"
                    or domain.verified_until is None
                    or domain.verified_until <= now
                    or domain.host != current.public_host
                ):
                    raise BrandingConflict("branding_domain_not_active_for_client")
            head = connection.execute(
                "SELECT * FROM trust_brand_projection_heads WHERE property_id=?",
                (property_ref,),
            ).fetchone()
            revision = int(head["projection_revision"]) if head is not None else 0
            if revision != expected:
                raise BrandingConflict("branding_projection_changed")
            projection_revision = revision + 1
            projection_id = _identifier(self._id_factory("brand-projection"), "projection_id")
            body = {
                "schema": "lightwork.trust-center-brand-projection.v1",
                "tenant_sha256": self.tenant_sha256,
                "projection_id": projection_id,
                "projection_revision": projection_revision,
                "property_id": current.property_id,
                "property_revision": current.property_revision,
                "publication_id": current.publication_id,
                "publication_revision": current.publication_revision,
                "publication_sha256": current.publication_sha256,
                "bundle_sha256": current.bundle_sha256,
                "client_credential_id": current.client_credential_id,
                "client_revision": current.client_revision,
                "client_record_sha256": current.client_record_sha256,
                "public_origin": current.public_origin,
                "public_host": current.public_host,
                "asset_id": asset_ref,
                "asset_version": asset_ver,
                "asset_authority_sha256": asset_head["authority_sha256"],
                "asset_content_sha256": version["content_sha256"],
                "asset_kind": version["asset_kind"],
                "asset_media_type": version["media_type"],
                "asset_width": int(version["width"]),
                "asset_height": int(version["height"]),
                "domain_claim_id": domain.claim_id if domain else None,
                "domain_claim_version": domain.claim_version if domain else None,
                "domain_authority_sha256": domain.authority_sha256 if domain else None,
                "domain_deployment_sha256": domain.deployment_sha256 if domain else None,
                "created_at": now,
            }
            projection_sha = _sha256(body)
            connection.execute(
                "INSERT INTO trust_brand_projections VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(body[key] for key in body if key not in {"schema", "tenant_sha256"})
                + (projection_sha,),
            )
            if head is None:
                connection.execute(
                    "INSERT INTO trust_brand_projection_heads VALUES(?,?,?,?,?)",
                    (property_ref, projection_id, projection_revision, "active", now),
                )
            else:
                updated = connection.execute(
                    "UPDATE trust_brand_projection_heads SET projection_id=?,"
                    "projection_revision=?,state='active',updated_at=? WHERE property_id=? "
                    "AND projection_revision=?",
                    (projection_id, projection_revision, now, property_ref, revision),
                )
                if updated.rowcount != 1:
                    raise BrandingConflict("branding_projection_changed")
            row = connection.execute(
                "SELECT * FROM trust_brand_projections WHERE projection_id=?",
                (projection_id,),
            ).fetchone()
            return self._projection_from_row(row, state="active")

    def revoke_projection(
        self,
        property_id: str,
        *,
        expected_projection_revision: int,
        actor_ref: str,
    ) -> BrandProjection:
        _actor_sha256(self.tenant_sha256, actor_ref)
        property_ref = _identifier(property_id, "property_id")
        expected = _positive_int(
            expected_projection_revision, "expected_projection_revision", 1, 2_147_483_647
        )
        now = _timestamp(self._clock(), "clock")
        with self._transaction() as connection:
            head = connection.execute(
                "SELECT * FROM trust_brand_projection_heads WHERE property_id=?",
                (property_ref,),
            ).fetchone()
            if (
                head is None
                or int(head["projection_revision"]) != expected
                or head["state"] != "active"
            ):
                raise BrandingConflict("branding_projection_changed")
            updated = connection.execute(
                "UPDATE trust_brand_projection_heads SET state='revoked',updated_at=? "
                "WHERE property_id=? AND projection_revision=? AND state='active'",
                (now, property_ref, expected),
            )
            if updated.rowcount != 1:
                raise BrandingConflict("branding_projection_changed")
            row = connection.execute(
                "SELECT * FROM trust_brand_projections WHERE projection_id=?",
                (head["projection_id"],),
            ).fetchone()
            return self._projection_from_row(row, state="revoked")

    def resolve_projection(self, authority: BrandPublicationAuthority) -> BrandProjection:
        if type(authority) is not BrandPublicationAuthority:
            raise BrandingValidationError("branding_publication_authority_invalid")
        current = authority.normalized()
        if current.tenant_id != self.tenant_id:
            raise BrandingNotFound("branding_projection_unavailable")
        now = _timestamp(self._clock(), "clock")
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta(connection)
            head = connection.execute(
                "SELECT * FROM trust_brand_projection_heads WHERE property_id=?",
                (current.property_id,),
            ).fetchone()
            if head is None or head["state"] != "active":
                raise BrandingNotFound("branding_projection_unavailable")
            row = connection.execute(
                "SELECT * FROM trust_brand_projections WHERE projection_id=?",
                (head["projection_id"],),
            ).fetchone()
            if row is None:
                raise BrandingIntegrityError("branding_projection_invalid")
            exact = (
                row["property_revision"] == current.property_revision
                and row["publication_id"] == current.publication_id
                and row["publication_revision"] == current.publication_revision
                and hmac.compare_digest(row["publication_sha256"], current.publication_sha256)
                and hmac.compare_digest(row["bundle_sha256"], current.bundle_sha256)
                and row["client_credential_id"] == current.client_credential_id
                and row["client_revision"] == current.client_revision
                and hmac.compare_digest(row["client_record_sha256"], current.client_record_sha256)
                and row["public_origin"] == current.public_origin
                and row["public_host"] == current.public_host
            )
            if not exact:
                raise BrandingConflict("branding_projection_stale")
            version, asset_head, _ = self._asset_rows(
                connection, str(row["asset_id"]), int(row["asset_version"])
            )
            if (
                asset_head["state"] != "active"
                or not hmac.compare_digest(
                    str(asset_head["authority_sha256"]), str(row["asset_authority_sha256"])
                )
                or not hmac.compare_digest(
                    str(version["content_sha256"]), str(row["asset_content_sha256"])
                )
            ):
                raise BrandingConflict("branding_projection_asset_changed")
            if row["domain_claim_id"] is not None:
                domain = self._domain_result(
                    *self._domain_rows(
                        connection,
                        str(row["domain_claim_id"]),
                        int(row["domain_claim_version"]),
                    )
                )
                if (
                    domain.state != "active"
                    or domain.verified_until is None
                    or domain.verified_until <= now
                    or domain.host != current.public_host
                    or not hmac.compare_digest(
                        domain.authority_sha256, str(row["domain_authority_sha256"])
                    )
                    or not hmac.compare_digest(
                        str(domain.deployment_sha256), str(row["domain_deployment_sha256"])
                    )
                ):
                    raise BrandingConflict("branding_projection_domain_changed")
            projection = self._projection_from_row(row, state="active")
            body = asdict(projection)
            supplied = body.pop("projection_sha256")
            body.pop("state")
            body = {
                "schema": "lightwork.trust-center-brand-projection.v1",
                "tenant_sha256": self.tenant_sha256,
                **body,
            }
            if not hmac.compare_digest(supplied, _sha256(body)):
                raise BrandingIntegrityError("branding_projection_invalid")
            return projection

    def read_public_asset(
        self,
        authority: BrandPublicationAuthority,
        projection_id: str,
        content_sha256: str,
    ) -> PublicBrandAsset:
        projection = self.resolve_projection(authority)
        if (
            projection.projection_id != _identifier(projection_id, "projection_id")
            or not hmac.compare_digest(
                projection.asset_content_sha256,
                _digest(content_sha256, "content_sha256"),
            )
        ):
            raise BrandingNotFound("branding_asset_unavailable")
        with _closing_sqlite(self._connect()) as connection, connection:
            version, _, blob = self._asset_rows(
                connection, projection.asset_id, projection.asset_version
            )
            encrypted = bytes(blob["encrypted_content"])
            if not hmac.compare_digest(
                str(blob["ciphertext_sha256"]), hashlib.sha256(encrypted).hexdigest()
            ):
                raise BrandingIntegrityError("branding_asset_ciphertext_invalid")
            content = self._unseal(
                encrypted,
                version,
                str(blob["key_ref"]),
                int(blob["key_revision"]),
            )
        _, _, width, height, digest = validate_raster(
            content,
            projection.asset_media_type,
            max_bytes=self.config.max_asset_bytes,
            max_width=self.config.max_width,
            max_height=self.config.max_height,
            max_pixels=self.config.max_pixels,
        )
        if (
            not hmac.compare_digest(digest, projection.asset_content_sha256)
            or width != projection.asset_width
            or height != projection.asset_height
        ):
            raise BrandingIntegrityError("branding_asset_content_invalid")
        return PublicBrandAsset(projection=projection, content=content)

    def list_assets(self, *, limit: int = 200) -> tuple[AssetAuthority, ...]:
        """Every logo/icon version with its current review state (read-only)."""

        bounded = _positive_int(limit, "limit", 1, 500)
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta(connection)
            # Versions whose image was deleted after retention are not listed.
            heads = connection.execute(
                "SELECT h.asset_id,h.asset_version FROM trust_brand_asset_heads h "
                "JOIN trust_brand_asset_blobs b "
                "ON b.asset_id=h.asset_id AND b.asset_version=h.asset_version "
                "ORDER BY h.updated_at DESC,h.asset_id,h.asset_version DESC LIMIT ?",
                (bounded,),
            ).fetchall()
            return tuple(
                self._asset_result(
                    *self._asset_rows(connection, str(row["asset_id"]), int(row["asset_version"]))
                )
                for row in heads
            )

    def list_domains(self, *, limit: int = 200) -> tuple[DomainAuthority, ...]:
        """Every custom-domain claim version with its current state (read-only)."""

        bounded = _positive_int(limit, "limit", 1, 500)
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta(connection)
            heads = connection.execute(
                "SELECT claim_id,claim_version FROM trust_brand_domain_heads "
                "ORDER BY updated_at DESC,claim_id,claim_version DESC LIMIT ?",
                (bounded,),
            ).fetchall()
            return tuple(
                self._domain_result(
                    *self._domain_rows(connection, str(row["claim_id"]), int(row["claim_version"]))
                )
                for row in heads
            )

    def list_projections(self, *, limit: int = 200) -> tuple[BrandProjection, ...]:
        """The current brand projection of each website (read-only)."""

        bounded = _positive_int(limit, "limit", 1, 500)
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta(connection)
            heads = connection.execute(
                "SELECT * FROM trust_brand_projection_heads ORDER BY updated_at DESC LIMIT ?",
                (bounded,),
            ).fetchall()
            items = []
            for head in heads:
                row = connection.execute(
                    "SELECT * FROM trust_brand_projections WHERE projection_id=?",
                    (head["projection_id"],),
                ).fetchone()
                if row is None:
                    raise BrandingIntegrityError("branding_projection_missing")
                items.append(self._projection_from_row(row, state=str(head["state"])))
            return tuple(items)

    def status(self) -> dict[str, object]:
        with _closing_sqlite(self._connect()) as connection, connection:
            self._verify_meta(connection)
            live_assets = int(
                connection.execute("SELECT COUNT(*) FROM trust_brand_asset_blobs").fetchone()[0]
            )
            active_assets = int(
                connection.execute(
                    "SELECT COUNT(*) FROM trust_brand_asset_heads WHERE state='active'"
                ).fetchone()[0]
            )
            active_domains = int(
                connection.execute(
                    "SELECT COUNT(*) FROM trust_brand_domain_heads WHERE state='active'"
                ).fetchone()[0]
            )
            active_projections = int(
                connection.execute(
                    "SELECT COUNT(*) FROM trust_brand_projection_heads WHERE state='active'"
                ).fetchone()[0]
            )
        return {
            "schema": "lightwork.trust-center-branding-status.v1",
            "enabled": True,
            "safe_media_types": tuple(sorted(ALLOWED_MEDIA_TYPES)),
            "svg_html_css_url_uploads_accepted": False,
            "tenant_selector_accepted": False,
            "raw_key_accepted": False,
            "host_header_tenant_inference": False,
            "domain_deployment_authority_configured": self._domain_authority is not None,
            "live_asset_versions": live_assets,
            "active_assets": active_assets,
            "active_domains": active_domains,
            "active_projections": active_projections,
            "live_dns_tls_cd_issuance_proven": False,
            "accessibility_brand_customer_acceptance_proven": False,
        }


__all__ = [
    "ALLOWED_MEDIA_TYPES",
    "AssetAuthority",
    "BrandProjection",
    "BrandPublicationAuthority",
    "BrandingConfigError",
    "BrandingConflict",
    "BrandingExternalAuthorityError",
    "BrandingIntegrityError",
    "BrandingNotFound",
    "BrandingValidationError",
    "DomainDeploymentAuthority",
    "DomainDeploymentBinding",
    "DomainAuthority",
    "DomainVerificationEvidence",
    "DomainVerificationRequest",
    "PublicBrandAsset",
    "TrustCenterBrandingConfig",
    "TrustCenterBrandingStore",
    "validate_raster",
]
