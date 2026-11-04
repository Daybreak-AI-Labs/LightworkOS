"""Deployable runtime seams for native Data Use Governance providers.

The provider-neutral compiler and native adapters live in ``maverick-core``.
This module attaches those closed adapters to the dashboard's existing secret
provider and DNS-pinned HTTP client without transferring secret ownership to
SQLite or accepting provider statements from an API caller.

Live provider acceptance remains an operator-run activity.  Merely importing
or building this runtime never opens a socket and never resolves a secret.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

from maverick.data_use_provider_adapters import (
    CredentialLease,
    DatabricksDataUseControlAdapter,
    DataUseProviderConfigError,
    DataUseProviderCredentialError,
    DataUseProviderProtocolError,
    DataUseProviderRequestNotSent,
    DataUseProviderTransportAmbiguous,
    ProviderBindingStore,
    ProviderHttpResponse,
    ProviderLimits,
    SnowflakeDataUseControlAdapter,
    provider_config_enabled,
)

_PROVIDERS = frozenset({"snowflake", "databricks"})
_LOG = logging.getLogger(__name__)
_SECRET_REF_RE = re.compile(r"\$(?:\{([A-Z][A-Z0-9_]{0,127})\}|([A-Z][A-Z0-9_]{0,127}))\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_monotonic = time.monotonic
_SNOWFLAKE_PARTITION_PATH_RE = re.compile(r"/api/v2/statements/[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_LINK_RE = re.compile(r'<([^<>]{1,1024})>\s*;\s*rel="?next"?\Z', re.IGNORECASE)


def _validated_snowflake_partition_link(request_url: str, value: object) -> str | None:
    """Return one same-origin SQL API partition link, never an arbitrary URL."""

    if not isinstance(value, str) or len(value) > 2048 or _CONTROL_RE.search(value):
        return None
    match = _LINK_RE.fullmatch(value.strip())
    if match is None:
        return None
    try:
        request = urlsplit(request_url)
        candidate = urlsplit(urljoin(request_url, match.group(1)))
        query = parse_qs(candidate.query, keep_blank_values=True, strict_parsing=True)
        candidate_port = candidate.port
    except ValueError:
        return None
    if (
        request.scheme != "https"
        or candidate.scheme != "https"
        or candidate.hostname != request.hostname
        or candidate_port is not None
        or candidate.username is not None
        or candidate.password is not None
        or candidate.fragment
        or _SNOWFLAKE_PARTITION_PATH_RE.fullmatch(candidate.path) is None
        or set(query) != {"partition"}
        or len(query["partition"]) != 1
        or not query["partition"][0].isdigit()
        or not 1 <= int(query["partition"][0]) <= 999
    ):
        return None
    return value.strip()


def _provider(provider_id: object) -> str:
    provider = str(provider_id or "").strip().lower()
    if provider not in _PROVIDERS:
        raise DataUseProviderConfigError("native data-use provider is unsupported")
    return provider


def _root(config: Mapping[str, Any]) -> Mapping[str, Any]:
    root = config.get("data_use_governance")
    if not isinstance(root, Mapping):
        raise DataUseProviderConfigError("data-use governance configuration is unavailable")
    return root


def provider_section(config: Mapping[str, Any], provider_id: object) -> Mapping[str, Any]:
    """Return one exact, enabled provider section or fail closed."""

    provider = _provider(provider_id)
    if not provider_config_enabled(provider, config):
        raise DataUseProviderConfigError(f"{provider} native enforcement is not explicitly enabled")
    section = _root(config).get(provider)
    if not isinstance(section, Mapping):
        raise DataUseProviderConfigError(f"{provider} configuration is unavailable")
    return section


@dataclass(frozen=True)
class ProviderCredentialMetadata:
    key_id: str
    key_revision: int
    authority_sha256: str
    secret_name: str


def credential_metadata(
    config: Mapping[str, Any], provider_id: object
) -> ProviderCredentialMetadata:
    """Derive non-secret key authority metadata from closed configuration.

    ``credential_revision`` is deliberately operator-controlled.  Rotating a
    secret requires bumping the revision and CAS-re-enrolling the affected
    binding, so an old secret cannot silently satisfy the new authority.
    """

    provider = _provider(provider_id)
    section = provider_section(config, provider)
    raw_ref = section.get("credential_secret_ref")
    match = _SECRET_REF_RE.fullmatch(str(raw_ref or "").strip())
    if match is None:
        raise DataUseProviderConfigError(
            f"{provider} credential_secret_ref must be an uppercase $ENV reference"
        )
    revision = section.get("credential_revision", 1)
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or not 1 <= revision <= 2**31 - 1
    ):
        raise DataUseProviderConfigError(f"{provider} credential_revision is outside its bound")
    secret_name = match.group(1) or match.group(2)
    key_id = f"{provider}:{secret_name}"
    authority_sha256 = hashlib.sha256(
        (
            f"lightwork.data-use.secret-provider-authority.v1:{provider}:{secret_name}:{revision}"
        ).encode("ascii")
    ).hexdigest()
    return ProviderCredentialMetadata(
        key_id=key_id,
        key_revision=revision,
        authority_sha256=authority_sha256,
        secret_name=secret_name,
    )


class SecretProviderCredentialOwner:
    """Resolve short-lived bearer leases from the configured secret backend."""

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        clock=time.time,
        secret_resolver=None,
        lease_seconds: float = 65.0,
    ) -> None:
        if not isinstance(config, Mapping):
            raise DataUseProviderConfigError("provider configuration must be a mapping")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or not math.isfinite(float(lease_seconds))
            or not 60.25 < float(lease_seconds) <= 300.0
        ):
            raise DataUseProviderConfigError(
                "provider credential lease must safely exceed the maximum HTTP timeout"
            )
        self._config = config
        self._clock = clock
        self._secret_resolver = secret_resolver
        self._lease_seconds = float(lease_seconds)

    def _secret(self, name: str) -> str | None:
        if self._secret_resolver is not None:
            return self._secret_resolver(name)
        from maverick.secret_provider import get_secret

        return get_secret(name)

    def lease(self, *, provider_id: str, tenant_id: str, binding_id: str) -> CredentialLease:
        # Tenant and binding are intentionally consumed by the interface even
        # though the closed config currently assigns one credential authority
        # per provider.  They remain available for a future vault policy seam.
        if not str(tenant_id or "").strip() or not str(binding_id or "").strip():
            raise DataUseProviderCredentialError("credential lease scope is invalid")
        metadata = credential_metadata(self._config, provider_id)
        try:
            value = self._secret(metadata.secret_name)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise DataUseProviderCredentialError(
                "provider credential owner is unavailable"
            ) from exc
        if not isinstance(value, str) or not value.strip():
            raise DataUseProviderCredentialError("provider credential is unavailable")
        token = value.strip()
        authorization = token if token.startswith("Bearer ") else f"Bearer {token}"
        if len(authorization) > 8192 or _CONTROL_RE.search(authorization):
            raise DataUseProviderCredentialError("provider credential is invalid")
        try:
            now = float(self._clock())
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise DataUseProviderCredentialError("credential clock is unavailable") from exc
        return CredentialLease(
            authorization=authorization,
            key_id=metadata.key_id,
            key_revision=metadata.key_revision,
            authority_sha256=metadata.authority_sha256,
            expires_at=now + self._lease_seconds,
            revoked=False,
        )


class PinnedProviderHttpTransport:
    """Exact-HTTPS, DNS-pinned, redirect-disabled bounded provider transport."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
        max_response_bytes: int,
        allow_redirects: bool,
    ) -> ProviderHttpResponse:
        from maverick.enterprise import enterprise_egress_denial
        from maverick.tools._ssrf import BlockedHost, safe_client

        selected_method = str(method or "").upper()
        parsed = urlsplit(str(url or ""))
        if os.getenv("MAVERICK_FETCH_ALLOW_PRIVATE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            raise DataUseProviderRequestNotSent(
                "provider HTTP transport refuses private-fetch override"
            )
        if (
            selected_method not in {"GET", "POST"}
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or allow_redirects is not False
        ):
            raise DataUseProviderProtocolError("provider HTTP request is uncontrolled")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 0.1 <= float(timeout) <= 60.0
            or isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or not 1_024 <= max_response_bytes <= 1_048_576
        ):
            raise DataUseProviderProtocolError("provider HTTP bounds are invalid")
        denial = enterprise_egress_denial(url, tool="data_use_provider_adapters")
        if denial:
            raise DataUseProviderRequestNotSent("provider egress is denied")
        started_at = _monotonic()
        try:
            with safe_client(url, timeout=timeout, follow_redirects=False) as client:
                with client.stream(
                    selected_method,
                    url,
                    headers=dict(headers),
                    content=body,
                ) as response:
                    if _monotonic() - started_at > float(timeout):
                        raise DataUseProviderTransportAmbiguous(
                            "provider request exceeded its elapsed timeout"
                        )
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_size = int(declared)
                        except ValueError:
                            raise DataUseProviderProtocolError(
                                "provider content length is invalid"
                            ) from None
                        if declared_size < 0 or declared_size > max_response_bytes:
                            raise DataUseProviderProtocolError(
                                "provider response exceeds its byte bound"
                            )
                    chunks: list[bytes] = []
                    observed = 0
                    for chunk in response.iter_bytes():
                        if _monotonic() - started_at > float(timeout):
                            raise DataUseProviderTransportAmbiguous(
                                "provider response exceeded its elapsed timeout"
                            )
                        observed += len(chunk)
                        if observed > max_response_bytes:
                            raise DataUseProviderProtocolError(
                                "provider response exceeds its byte bound"
                            )
                        chunks.append(chunk)
                    safe_headers = {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower() in {"content-type", "content-length", "retry-after"}
                        and isinstance(value, str)
                        and len(value) <= 4096
                        and not _CONTROL_RE.search(value)
                    }
                    raw_link = response.headers.get("link") or response.headers.get("Link")
                    validated_link = _validated_snowflake_partition_link(url, raw_link)
                    if validated_link is not None:
                        safe_headers["link"] = validated_link
                    return ProviderHttpResponse(
                        status_code=int(response.status_code),
                        headers=safe_headers,
                        body=b"".join(chunks),
                    )
        except BlockedHost as exc:
            raise DataUseProviderRequestNotSent("provider host was blocked") from exc
        except (DataUseProviderProtocolError, DataUseProviderTransportAmbiguous):
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            # Once the client attempts dispatch, a timeout/connection reset is
            # not proof that a POST had no effect.  The adapter will distinguish
            # read-only retry from mutation ambiguity at its own state machine.
            raise DataUseProviderTransportAmbiguous(
                "provider transport outcome is unavailable"
            ) from exc


def provider_limits(config: Mapping[str, Any], provider_id: object) -> ProviderLimits:
    provider = _provider(provider_id)
    section = provider_section(config, provider)
    enforcement = _root(config).get("enforcement")
    if not isinstance(enforcement, Mapping):
        raise DataUseProviderConfigError("data-use enforcement configuration is unavailable")
    base, longest = _retry_waits(enforcement)
    return ProviderLimits(
        timeout_seconds=float(section.get("timeout_seconds", 10)),
        max_response_bytes=int(section.get("max_response_bytes", 64 * 1024)),
        max_attempts=int(enforcement.get("max_attempts", 3)),
        max_polls=min(5, int(enforcement.get("max_attempts", 3))),
        retry_base_seconds=base,
        retry_max_seconds=longest,
    )


def _retry_waits(enforcement: Mapping[str, Any]) -> tuple[float, float]:
    """In-request retry waits from ``[data_use_governance.enforcement]``.

    Retries happen inside one request, so the waits are seconds, not minutes:
    the base must be 0.05-10 and the longest 0.25-60. A value outside that
    range (older installers wrote 30 and 300, which were never applied) is
    ignored so the historical 0.25 s / 1 s waits stay in force.
    """
    def pick(key: str, lower: float, upper: float, default: float) -> float:
        value = enforcement.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not lower <= float(value) <= upper
        ):
            if value is not None:
                _LOG.warning("ignoring data-use enforcement %s outside %s-%s", key, lower, upper)
            return default
        return float(value)

    base = pick("retry_base_seconds", 0.05, 10.0, 0.25)
    longest = pick("retry_max_seconds", 0.25, 60.0, 1.0)
    return base, max(base, longest)


def adapter_authority_sha256(*, tenant_id: str, provider_id: str, binding_id: str) -> str:
    return hashlib.sha256(
        (
            "lightwork.dashboard.data-use-native-adapter.v1:"
            f"{tenant_id}:{_provider(provider_id)}:{binding_id}"
        ).encode()
    ).hexdigest()


def binding_store(path: Path) -> ProviderBindingStore:
    return ProviderBindingStore(path)


def build_adapter(
    *,
    tenant_id: str,
    provider_id: str,
    binding_id: str,
    config: Mapping[str, Any],
    store: ProviderBindingStore,
    credential_owner: object | None = None,
    transport: object | None = None,
):
    """Build one live-capable adapter without performing provider I/O."""

    provider = _provider(provider_id)
    factories = {
        "snowflake": SnowflakeDataUseControlAdapter,
        "databricks": DatabricksDataUseControlAdapter,
    }
    return factories[provider](
        tenant_id=tenant_id,
        binding_id=binding_id,
        adapter_authority_sha256=adapter_authority_sha256(
            tenant_id=tenant_id,
            provider_id=provider,
            binding_id=binding_id,
        ),
        binding_store=store,
        credential_owner=(
            credential_owner
            if credential_owner is not None
            else SecretProviderCredentialOwner(config)
        ),
        transport=(transport if transport is not None else PinnedProviderHttpTransport()),
        config=config,
        limits=provider_limits(config, provider),
    )


__all__ = [
    "PinnedProviderHttpTransport",
    "ProviderCredentialMetadata",
    "SecretProviderCredentialOwner",
    "adapter_authority_sha256",
    "binding_store",
    "build_adapter",
    "credential_metadata",
    "provider_limits",
    "provider_section",
]
