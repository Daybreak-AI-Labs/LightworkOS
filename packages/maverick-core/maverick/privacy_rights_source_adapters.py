"""Closed provider contracts for automated privacy-rights source work.

The adapters are deliberately narrow: Microsoft Graph users, Google Workspace
Directory users, Salesforce Contacts and ServiceNow users.  Raw provider
responses remain transient except when an injected encrypted artifact sink
accepts a retrieval payload.  Redirects, cross-origin pagination, arbitrary
provider paths and optimistic mutation replay are prohibited.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import quote, urlencode, urlsplit

from .privacy_rights_source_worker import (
    PreparedProviderMutation,
    PrivacyRightsSourceWorkerConfigError,
    PrivacyRightsSourceWorkerProtocolError,
    ProviderAmbiguousOutcome,
    ProviderOutcome,
    ProviderPermanentError,
    ProviderReconciliationOutcome,
    ProviderRetryableError,
)

Provider = Literal[
    "microsoft_graph_users",
    "google_workspace_users",
    "salesforce_contacts",
    "servicenow_users",
]

_MAX_JSON_DEPTH = 24
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PROVIDERS = frozenset(
    {
        "microsoft_graph_users",
        "google_workspace_users",
        "salesforce_contacts",
        "servicenow_users",
    }
)


@dataclass(frozen=True)
class AdapterLimits:
    timeout_seconds: float = 15.0
    max_response_bytes: int = 1_048_576
    max_retrieval_bytes: int = 8_388_608
    max_records: int = 200

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or not 0.1 <= float(self.timeout_seconds) <= 60.0
            or isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1_024 <= self.max_response_bytes <= 4_194_304
            or isinstance(self.max_retrieval_bytes, bool)
            or not isinstance(self.max_retrieval_bytes, int)
            or not self.max_response_bytes <= self.max_retrieval_bytes <= 33_554_432
            or isinstance(self.max_records, bool)
            or not isinstance(self.max_records, int)
            or not 1 <= self.max_records <= 1_000
        ):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights adapter limits are invalid"
            )


@dataclass(frozen=True)
class HTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    final_url: str


class HTTPTransport(Protocol):
    dns_pinned: bool
    redirects_followed: bool

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
    ) -> HTTPResponse: ...


@dataclass(frozen=True)
class ArtifactReceipt:
    opaque_ref: str
    sha256: str
    record_count: int
    tenant_bound: bool
    encrypted_at_rest: bool
    retention_enforced: bool
    raw_data_returned: bool = False


class RetrievalArtifactSink(Protocol):
    def store(
        self,
        *,
        tenant_id: str,
        case_id: str,
        source_id: str,
        operation_id: str,
        content_type: str,
        body: bytes,
        sha256: str,
        record_count: int,
    ) -> ArtifactReceipt: ...


@dataclass(frozen=True)
class MutationTargetReceipt:
    opaque_ref: str
    target_binding_sha256: str
    tenant_bound: bool
    encrypted_at_rest: bool
    retention_enforced: bool
    raw_target_returned: bool = False


class MutationTargetCustody(Protocol):
    def store(
        self,
        *,
        tenant_id: str,
        case_id: str,
        source_id: str,
        operation_id: str,
        provider: str,
        target_id: str,
        target_binding_sha256: str,
    ) -> MutationTargetReceipt: ...

    def resolve(
        self,
        *,
        tenant_id: str,
        case_id: str,
        source_id: str,
        operation_id: str,
        provider: str,
        target_ref: str,
        target_binding_sha256: str,
    ) -> str: ...


def _origin(provider: Provider, value: str) -> str:
    parsed = urlsplit(str(value or ""))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.port not in {None, 443}
    ):
        raise PrivacyRightsSourceWorkerConfigError(
            "privacy-rights provider origin is invalid"
        )
    host = parsed.hostname.rstrip(".").lower()
    admitted = {
        "microsoft_graph_users": host == "graph.microsoft.com",
        "google_workspace_users": host == "admin.googleapis.com",
        "salesforce_contacts": host.endswith(".salesforce.com")
        and host != "salesforce.com",
        "servicenow_users": host.endswith(".service-now.com")
        and host != "service-now.com",
    }
    if admitted.get(provider) is not True:
        raise PrivacyRightsSourceWorkerConfigError(
            "privacy-rights provider host is not admitted"
        )
    return f"https://{host}"


def _json(body: bytes, maximum: int) -> object:
    if not isinstance(body, bytes) or len(body) > maximum:
        raise PrivacyRightsSourceWorkerProtocolError(
            "privacy-rights provider response exceeds its byte bound"
        )

    def pairs(values: Sequence[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise PrivacyRightsSourceWorkerProtocolError(
                    "privacy-rights provider response contains duplicate keys"
                )
            result[key] = value
        return result

    try:
        value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=pairs)
    except PrivacyRightsSourceWorkerProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PrivacyRightsSourceWorkerProtocolError(
            "privacy-rights provider response is invalid JSON"
        ) from exc

    def bounded(item: object, depth: int = 0) -> None:
        if depth > _MAX_JSON_DEPTH:
            raise PrivacyRightsSourceWorkerProtocolError(
                "privacy-rights provider response is too deeply nested"
            )
        if isinstance(item, Mapping):
            if len(item) > 5_000:
                raise PrivacyRightsSourceWorkerProtocolError(
                    "privacy-rights provider response is too broad"
                )
            for key, nested in item.items():
                if not isinstance(key, str) or len(key) > 512 or _CONTROL.search(key):
                    raise PrivacyRightsSourceWorkerProtocolError(
                        "privacy-rights provider response key is invalid"
                    )
                bounded(nested, depth + 1)
        elif isinstance(item, list):
            if len(item) > 10_000:
                raise PrivacyRightsSourceWorkerProtocolError(
                    "privacy-rights provider response is too broad"
                )
            for nested in item:
                bounded(nested, depth + 1)
        elif isinstance(item, str) and (len(item) > maximum or _CONTROL.search(item)):
            raise PrivacyRightsSourceWorkerProtocolError(
                "privacy-rights provider response text is invalid"
            )

    bounded(value)
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PrivacyRightsSourceWorkerProtocolError(
            "privacy-rights provider evidence is invalid"
        ) from exc


def _safe_ref(provider: Provider, operation_id: str, suffix: str) -> str:
    digest = hashlib.sha256(
        f"{provider}\x00{operation_id}\x00{suffix}".encode()
    ).hexdigest()
    return f"{provider}:{digest[:40]}"


class StockPrivacyRightsSourceAdapter:
    """One fixed-origin, fixed-operation provider source adapter."""

    def __init__(
        self,
        *,
        provider: Provider,
        origin: str,
        transport: HTTPTransport,
        artifact_sink: RetrievalArtifactSink | None = None,
        target_custody: MutationTargetCustody | None = None,
        limits: AdapterLimits | None = None,
    ) -> None:
        if provider not in _PROVIDERS:
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights provider is unsupported"
            )
        if (
            getattr(transport, "dns_pinned", None) is not True
            or getattr(transport, "redirects_followed", None) is not False
            or not callable(getattr(transport, "request", None))
        ):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights provider transport is unsafe"
            )
        if artifact_sink is not None and not callable(
            getattr(artifact_sink, "store", None)
        ):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights retrieval artifact sink is invalid"
            )
        if target_custody is not None and (
            not callable(getattr(target_custody, "store", None))
            or not callable(getattr(target_custody, "resolve", None))
        ):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights mutation target custody is invalid"
            )
        self.provider = provider
        self.origin = _origin(provider, origin)
        self.transport = transport
        self.artifact_sink = artifact_sink
        self.target_custody = target_custody
        self.limits = limits or AdapterLimits()

    def _lookup_url(self, subject_reference: str) -> str:
        subject = str(subject_reference or "").strip()
        if (
            not subject
            or len(subject.encode("utf-8")) > 4_096
            or any(character in subject for character in "\r\n\x00")
            or (self.provider == "servicenow_users" and "^" in subject)
        ):
            raise ProviderPermanentError("provider_subject_invalid")
        encoded = quote(subject, safe="")
        if self.provider == "microsoft_graph_users":
            return f"{self.origin}/v1.0/users/{encoded}?$select=id,userPrincipalName,mail,accountEnabled"
        if self.provider == "google_workspace_users":
            return f"{self.origin}/admin/directory/v1/users/{encoded}?projection=full"
        if self.provider == "salesforce_contacts":
            escaped = subject.replace("\\", "\\\\").replace("'", "\\'")
            query = (
                "SELECT Id,Email,HasOptedOutOfEmail,LastModifiedDate "
                f"FROM Contact WHERE Email = '{escaped}' LIMIT {self.limits.max_records}"
            )
            return f"{self.origin}/services/data/v61.0/query?{urlencode({'q': query})}"
        return (
            f"{self.origin}/api/now/table/sys_user?"
            + urlencode(
                {
                    "sysparm_query": f"email={subject}",
                    "sysparm_fields": "sys_id,email,active,sys_updated_on",
                    "sysparm_limit": self.limits.max_records,
                }
            )
        )

    def _headers(self, credential: str, operation_id: str) -> dict[str, str]:
        token = str(credential or "").strip()
        if (
            not token
            or len(token.encode("utf-8")) > 16_384
            or any(character in token for character in "\r\n\x00")
            or not _IDENTIFIER.fullmatch(operation_id)
        ):
            raise ProviderPermanentError("provider_authority_invalid")
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": operation_id,
            "X-Lightwork-Operation-Id": operation_id,
        }

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        operation_id: str,
        mutation: bool,
        max_response_bytes: int | None = None,
    ) -> HTTPResponse:
        parsed = urlsplit(url)
        expected = urlsplit(self.origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname != expected.hostname
            or parsed.port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ProviderPermanentError("provider_origin_mismatch")
        maximum = (
            self.limits.max_response_bytes
            if max_response_bytes is None
            else max_response_bytes
        )
        if not 1_024 <= maximum <= self.limits.max_retrieval_bytes:
            raise ProviderPermanentError("provider_response_bound_invalid")
        try:
            response = self.transport.request(
                method,
                url,
                headers=headers,
                body=None,
                timeout=float(self.limits.timeout_seconds),
                max_response_bytes=maximum,
                allow_redirects=False,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except (ProviderPermanentError, ProviderRetryableError, ProviderAmbiguousOutcome):
            raise
        except Exception as exc:
            if mutation:
                raise ProviderAmbiguousOutcome(
                    operation_sha256=hashlib.sha256(operation_id.encode()).hexdigest(),
                    operation_ref=operation_id,
                ) from exc
            raise ProviderRetryableError("provider_transport_failed") from exc
        if (
            not isinstance(response, HTTPResponse)
            or response.final_url != url
            or not isinstance(response.headers, Mapping)
        ):
            raise ProviderPermanentError("provider_redirect_rejected")
        if (
            isinstance(response.status_code, bool)
            or not isinstance(response.status_code, int)
            or not isinstance(response.body, bytes)
            or len(response.body) > maximum
        ):
            raise ProviderPermanentError("provider_response_invalid")
        return response

    def _records(
        self,
        response: HTTPResponse,
        *,
        maximum: int | None = None,
    ) -> tuple[int, object]:
        if response.status_code == 404:
            if self.provider in {"microsoft_graph_users", "google_workspace_users"}:
                return 0, {}
            raise ProviderPermanentError("provider_request_rejected")
        if response.status_code in {408, 425, 429} or 500 <= response.status_code < 600:
            raise ProviderRetryableError("provider_temporarily_unavailable")
        if 300 <= response.status_code < 400:
            raise ProviderPermanentError("provider_redirect_rejected")
        if not 200 <= response.status_code < 300:
            raise ProviderPermanentError("provider_request_rejected")
        content_type = next(
            (
                str(value).lower()
                for key, value in response.headers.items()
                if str(key).lower() == "content-type"
            ),
            "",
        )
        if not content_type.startswith("application/json"):
            raise ProviderPermanentError("provider_content_type_invalid")
        payload = _json(
            response.body or b"{}",
            self.limits.max_response_bytes if maximum is None else maximum,
        )
        if self.provider in {"microsoft_graph_users", "google_workspace_users"}:
            return 1, payload
        if not isinstance(payload, Mapping):
            raise ProviderPermanentError("provider_response_invalid")
        records = payload.get("records" if self.provider == "salesforce_contacts" else "result")
        if not isinstance(records, list) or len(records) > self.limits.max_records:
            raise ProviderPermanentError("provider_response_invalid")
        if self.provider == "salesforce_contacts" and not records and (
            payload.get("done") is not True
            or isinstance(payload.get("totalSize"), bool)
            or payload.get("totalSize") != 0
            or payload.get("nextRecordsUrl") is not None
        ):
            raise ProviderPermanentError("provider_response_invalid")
        return len(records), payload

    def _single_record_id(self, payload: object) -> str:
        if not isinstance(payload, Mapping):
            raise ProviderPermanentError("provider_response_invalid")
        if self.provider == "salesforce_contacts":
            records = payload.get("records")
            key = "Id"
        elif self.provider == "servicenow_users":
            records = payload.get("result")
            key = "sys_id"
        else:
            value = payload.get("id")
            if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
                raise ProviderPermanentError("provider_response_invalid")
            return value
        if not isinstance(records, list) or len(records) != 1:
            raise ProviderPermanentError("provider_subject_not_unique")
        record = records[0]
        value = record.get(key) if isinstance(record, Mapping) else None
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ProviderPermanentError("provider_response_invalid")
        return value

    def _target_url(self, record_id: str) -> str:
        if not isinstance(record_id, str) or not _IDENTIFIER.fullmatch(record_id):
            raise ProviderPermanentError("provider_target_invalid")
        if self.provider == "microsoft_graph_users":
            return f"{self.origin}/v1.0/users/{quote(record_id, safe='')}"
        if self.provider == "google_workspace_users":
            return f"{self.origin}/admin/directory/v1/users/{quote(record_id, safe='')}"
        if self.provider == "salesforce_contacts":
            return f"{self.origin}/services/data/v61.0/sobjects/Contact/{record_id}"
        return f"{self.origin}/api/now/table/sys_user/{record_id}"

    def _target_binding(
        self,
        *,
        tenant_id: str,
        case_id: str,
        source_id: str,
        operation_id: str,
        target_id: str,
    ) -> str:
        return hashlib.sha256(
            _canonical(
                {
                    "schema": "lightwork.privacy-rights-mutation-target.v1",
                    "tenant_id": tenant_id,
                    "case_id": case_id,
                    "source_id": source_id,
                    "provider": self.provider,
                    "operation_id": operation_id,
                    "target_id": target_id,
                }
            )
        ).hexdigest()

    def execute(
        self,
        *,
        tenant_id: str,
        source_id: str,
        case_id: str,
        phase: str,
        subject_reference: str,
        credential: str,
        operation_id: str,
        destructive_approved: bool,
    ) -> ProviderOutcome:
        if phase not in {"discover", "retrieve", "delete", "verify_delete"}:
            raise ProviderPermanentError("provider_phase_unsupported")
        if phase == "delete" and destructive_approved is not True:
            raise ProviderPermanentError("provider_delete_not_approved")
        if phase == "delete":
            raise ProviderPermanentError("provider_prepared_mutation_required")
        headers = self._headers(credential, operation_id)
        lookup_url = self._lookup_url(subject_reference)
        lookup_maximum = (
            self.limits.max_retrieval_bytes
            if phase == "retrieve"
            else self.limits.max_response_bytes
        )
        lookup = self._request(
            "GET",
            lookup_url,
            headers=headers,
            operation_id=operation_id,
            mutation=False,
            max_response_bytes=lookup_maximum,
        )
        count, payload = self._records(lookup, maximum=lookup_maximum)
        if phase == "verify_delete":
            if count != 0:
                raise ProviderRetryableError("provider_delete_not_observed")
            # This proves absence from the provider's exact active-record lookup,
            # not hard purge. Mutation reconciliation applies the stronger rule.
            evidence_digest = hashlib.sha256(
                _canonical(
                    {
                        "schema": "lightwork.privacy-rights-lookup-absence.v1",
                        "provider": self.provider,
                        "operation_id": operation_id,
                        "lookup_url_sha256": hashlib.sha256(lookup_url.encode()).hexdigest(),
                        "response_status": lookup.status_code,
                        "response_body_sha256": hashlib.sha256(lookup.body).hexdigest(),
                        "record_count": 0,
                    }
                )
            ).hexdigest()
            return ProviderOutcome(
                status="not_found",
                record_count=0,
                acknowledgement_sha256=evidence_digest,
                acknowledgement_ref=_safe_ref(self.provider, operation_id, "verified-lookup-absence"),
                provider_evidence_sha256=evidence_digest,
                opaque_ref=_safe_ref(self.provider, operation_id, "verified-lookup-evidence"),
                external_side_effect=False,
            )
        if count == 0:
            empty_digest = hashlib.sha256(
                _canonical(
                    {
                        "provider": self.provider,
                        "operation_id": operation_id,
                        "status": "not_found",
                    }
                )
            ).hexdigest()
            return ProviderOutcome(
                status="not_found",
                record_count=0,
                acknowledgement_sha256=empty_digest,
                acknowledgement_ref=_safe_ref(self.provider, operation_id, "not-found"),
                provider_evidence_sha256=empty_digest,
                opaque_ref=_safe_ref(self.provider, operation_id, "not-found-evidence"),
                external_side_effect=False,
            )
        if count != 1:
            raise ProviderPermanentError("provider_subject_not_unique")
        self._single_record_id(payload)
        evidence_digest = hashlib.sha256(lookup.body).hexdigest()
        opaque_ref = _safe_ref(self.provider, operation_id, "discovery")
        if phase == "retrieve":
            if self.artifact_sink is None:
                raise ProviderPermanentError("provider_retrieval_sink_unavailable")
            if len(lookup.body) > self.limits.max_retrieval_bytes:
                raise ProviderPermanentError("provider_retrieval_too_large")
            content_type = str(lookup.headers.get("content-type") or "application/json")
            receipt = self.artifact_sink.store(
                tenant_id=tenant_id,
                case_id=case_id,
                source_id=source_id,
                operation_id=operation_id,
                content_type=content_type,
                body=lookup.body,
                sha256=evidence_digest,
                record_count=count,
            )
            if (
                not isinstance(receipt, ArtifactReceipt)
                or receipt.tenant_bound is not True
                or receipt.encrypted_at_rest is not True
                or receipt.retention_enforced is not True
                or receipt.raw_data_returned is not False
                or receipt.sha256 != evidence_digest
                or receipt.record_count != count
                or not _IDENTIFIER.fullmatch(receipt.opaque_ref)
            ):
                raise ProviderPermanentError("provider_retrieval_sink_invalid")
            opaque_ref = receipt.opaque_ref
        return ProviderOutcome(
            status="complete",
            record_count=count,
            acknowledgement_sha256=evidence_digest,
            acknowledgement_ref=_safe_ref(self.provider, operation_id, phase),
            provider_evidence_sha256=evidence_digest,
            opaque_ref=opaque_ref,
            external_side_effect=False,
        )

    def prepare_mutation(
        self,
        *,
        tenant_id: str,
        source_id: str,
        case_id: str,
        phase: str,
        subject_reference: str,
        credential: str,
        operation_id: str,
    ) -> PreparedProviderMutation:
        """Resolve one immutable target and place its raw ID in encrypted custody."""

        if phase != "delete":
            raise ProviderPermanentError("provider_phase_unsupported")
        if self.target_custody is None:
            raise ProviderPermanentError("provider_target_custody_unavailable")
        headers = self._headers(credential, operation_id)
        lookup = self._request(
            "GET",
            self._lookup_url(subject_reference),
            headers=headers,
            operation_id=operation_id,
            mutation=False,
        )
        count, payload = self._records(lookup)
        evidence_digest = hashlib.sha256(lookup.body).hexdigest()
        if count == 0:
            return PreparedProviderMutation(
                status="not_found",
                target_ref=None,
                target_binding_sha256=None,
                acknowledgement_sha256=evidence_digest,
                acknowledgement_ref=_safe_ref(
                    self.provider, operation_id, "already-absent"
                ),
                provider_evidence_sha256=evidence_digest,
                opaque_ref=_safe_ref(
                    self.provider, operation_id, "already-absent-evidence"
                ),
                record_count=0,
                provider_retention_state="already_absent",
            )
        if count != 1:
            raise ProviderPermanentError("provider_subject_not_unique")
        target_id = self._single_record_id(payload)
        target_binding = self._target_binding(
            tenant_id=tenant_id,
            case_id=case_id,
            source_id=source_id,
            operation_id=operation_id,
            target_id=target_id,
        )
        try:
            receipt = self.target_custody.store(
                tenant_id=tenant_id,
                case_id=case_id,
                source_id=source_id,
                operation_id=operation_id,
                provider=self.provider,
                target_id=target_id,
                target_binding_sha256=target_binding,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ProviderRetryableError("provider_target_custody_unavailable") from exc
        if (
            not isinstance(receipt, MutationTargetReceipt)
            or receipt.tenant_bound is not True
            or receipt.encrypted_at_rest is not True
            or receipt.retention_enforced is not True
            or receipt.raw_target_returned is not False
            or receipt.target_binding_sha256 != target_binding
            or not _IDENTIFIER.fullmatch(receipt.opaque_ref)
        ):
            raise ProviderPermanentError("provider_target_custody_invalid")
        return PreparedProviderMutation(
            status="ready",
            target_ref=receipt.opaque_ref,
            target_binding_sha256=target_binding,
            acknowledgement_sha256=evidence_digest,
            acknowledgement_ref=_safe_ref(self.provider, operation_id, "prepared"),
            provider_evidence_sha256=evidence_digest,
            opaque_ref=_safe_ref(self.provider, operation_id, "prepared-evidence"),
            record_count=1,
            provider_retention_state="active",
        )

    def _custodied_target(
        self,
        *,
        tenant_id: str,
        source_id: str,
        case_id: str,
        operation_id: str,
        target_ref: str,
        target_binding_sha256: str,
    ) -> str:
        if self.target_custody is None:
            raise ProviderPermanentError("provider_target_custody_unavailable")
        try:
            target_id = self.target_custody.resolve(
                tenant_id=tenant_id,
                case_id=case_id,
                source_id=source_id,
                operation_id=operation_id,
                provider=self.provider,
                target_ref=target_ref,
                target_binding_sha256=target_binding_sha256,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ProviderRetryableError("provider_target_custody_unavailable") from exc
        if (
            not isinstance(target_id, str)
            or not _IDENTIFIER.fullmatch(target_id)
            or self._target_binding(
                tenant_id=tenant_id,
                case_id=case_id,
                source_id=source_id,
                operation_id=operation_id,
                target_id=target_id,
            )
            != target_binding_sha256
        ):
            raise ProviderPermanentError("provider_target_custody_invalid")
        return target_id

    def execute_prepared(
        self,
        *,
        tenant_id: str,
        source_id: str,
        case_id: str,
        phase: str,
        credential: str,
        operation_id: str,
        target_ref: str,
        target_binding_sha256: str,
        destructive_approved: bool,
    ) -> ProviderOutcome:
        if phase != "delete":
            raise ProviderPermanentError("provider_phase_unsupported")
        if destructive_approved is not True:
            raise ProviderPermanentError("provider_delete_not_approved")
        target_id = self._custodied_target(
            tenant_id=tenant_id,
            source_id=source_id,
            case_id=case_id,
            operation_id=operation_id,
            target_ref=target_ref,
            target_binding_sha256=target_binding_sha256,
        )
        headers = self._headers(credential, operation_id)
        deleted = self._request(
            "DELETE",
            self._target_url(target_id),
            headers=headers,
            operation_id=operation_id,
            mutation=True,
        )
        if deleted.status_code in {408, 425, 429} or 500 <= deleted.status_code < 600:
            raise ProviderAmbiguousOutcome(
                operation_sha256=target_binding_sha256,
                operation_ref=operation_id,
            )
        if 300 <= deleted.status_code < 400:
            raise ProviderPermanentError("provider_redirect_rejected")
        if deleted.status_code not in {200, 202, 204, 404}:
            raise ProviderPermanentError("provider_delete_rejected")
        digest = hashlib.sha256(
            _canonical(
                {
                    "provider": self.provider,
                    "operation_id": operation_id,
                    "target_binding_sha256": target_binding_sha256,
                    "status_code": deleted.status_code,
                    "body_sha256": hashlib.sha256(deleted.body).hexdigest(),
                }
            )
        ).hexdigest()
        return ProviderOutcome(
            status="complete",
            record_count=1,
            acknowledgement_sha256=digest,
            acknowledgement_ref=_safe_ref(self.provider, operation_id, "delete"),
            provider_evidence_sha256=digest,
            opaque_ref=_safe_ref(self.provider, operation_id, "delete-evidence"),
            external_side_effect=True,
        )

    @staticmethod
    def _status_is_retryable(status_code: int) -> bool:
        return status_code in {408, 425, 429} or 500 <= status_code < 600

    def _exact_active_state(
        self,
        response: HTTPResponse,
        *,
        target_id: str,
    ) -> str:
        if self._status_is_retryable(response.status_code):
            return "unknown"
        if response.status_code == 404:
            return "absent"
        if not 200 <= response.status_code < 300:
            return "unknown"
        content_type = next(
            (
                str(value).lower()
                for key, value in response.headers.items()
                if str(key).lower() == "content-type"
            ),
            "",
        )
        if not content_type.startswith("application/json"):
            return "unknown"
        payload = _json(response.body or b"{}", self.limits.max_response_bytes)
        key = {
            "microsoft_graph_users": "id",
            "google_workspace_users": "id",
            "salesforce_contacts": "Id",
            "servicenow_users": "sys_id",
        }[self.provider]
        observed = payload.get(key) if isinstance(payload, Mapping) else None
        if observed != target_id:
            return "unknown"
        return "active"

    def _retention_probe(
        self,
        *,
        target_id: str,
        credential: str,
        operation_id: str,
    ) -> tuple[str, bytes]:
        headers = self._headers(credential, operation_id)
        if self.provider == "microsoft_graph_users":
            url = (
                f"{self.origin}/v1.0/directory/deletedItems/"
                f"{quote(target_id, safe='')}?$select=id"
            )
            response = self._request(
                "GET",
                url,
                headers=headers,
                operation_id=operation_id,
                mutation=False,
            )
            if response.status_code == 404:
                return "purged", response.body
            if 200 <= response.status_code < 300:
                return "soft_deleted", response.body
            return "retention_unknown", response.body
        if self.provider == "salesforce_contacts":
            query = (
                "SELECT Id,IsDeleted FROM Contact WHERE Id = "
                f"'{target_id}' LIMIT 1"
            )
            url = f"{self.origin}/services/data/v61.0/queryAll?{urlencode({'q': query})}"
            response = self._request(
                "GET",
                url,
                headers=headers,
                operation_id=operation_id,
                mutation=False,
            )
            if self._status_is_retryable(response.status_code):
                return "retention_unknown", response.body
            try:
                count, payload = self._records(response)
            except (ProviderPermanentError, ProviderRetryableError):
                return "retention_unknown", response.body
            if count == 0:
                return "purged", response.body
            records = payload.get("records") if isinstance(payload, Mapping) else None
            record = records[0] if isinstance(records, list) and records else None
            if isinstance(record, Mapping) and record.get("Id") == target_id:
                return (
                    "soft_deleted" if record.get("IsDeleted") is True else "active",
                    response.body,
                )
            return "retention_unknown", response.body
        # Google Admin and ServiceNow do not provide a hard-purge proof through
        # this exact active-record contract.  An active 404 therefore remains
        # retention-unknown instead of being presented as completed erasure.
        return "retention_unknown", b""

    def reconcile_mutation(
        self,
        *,
        tenant_id: str,
        source_id: str,
        case_id: str,
        phase: str,
        credential: str,
        operation_id: str,
        target_ref: str,
        target_binding_sha256: str,
    ) -> ProviderReconciliationOutcome:
        """Probe only the originally custodied immutable provider target."""

        if phase != "delete":
            raise ProviderPermanentError("provider_phase_unsupported")
        target_id = self._custodied_target(
            tenant_id=tenant_id,
            source_id=source_id,
            case_id=case_id,
            operation_id=operation_id,
            target_ref=target_ref,
            target_binding_sha256=target_binding_sha256,
        )
        headers = self._headers(credential, operation_id)
        response = self._request(
            "GET",
            self._target_url(target_id),
            headers=headers,
            operation_id=operation_id,
            mutation=False,
        )
        active_state = self._exact_active_state(response, target_id=target_id)
        retention_body = b""
        if active_state == "active":
            disposition = "absent"
            retention_state = "active"
        elif active_state == "unknown":
            disposition = "unknown"
            retention_state = "unknown"
        else:
            retention_state, retention_body = self._retention_probe(
                target_id=target_id,
                credential=credential,
                operation_id=operation_id,
            )
            disposition = (
                "applied"
                if retention_state in {"purged", "hard_deleted"}
                else "unknown"
            )
        evidence_digest = hashlib.sha256(
            _canonical(
                {
                    "provider": self.provider,
                    "operation_id": operation_id,
                    "target_binding_sha256": target_binding_sha256,
                    "active_status": response.status_code,
                    "active_body_sha256": hashlib.sha256(response.body).hexdigest(),
                    "retention_body_sha256": hashlib.sha256(
                        retention_body
                    ).hexdigest(),
                    "retention_state": retention_state,
                }
            )
        ).hexdigest()
        return ProviderReconciliationOutcome(
            disposition=disposition,
            provider_evidence_sha256=evidence_digest,
            provider_evidence_ref=_safe_ref(
                self.provider, operation_id, "reconcile-exact-target"
            ),
            record_count=1 if retention_state in {"active", "soft_deleted"} else 0,
            provider_retention_state=retention_state,
        )

    def reconcile_delete(
        self,
        *,
        subject_reference: str,
        credential: str,
        operation_id: str,
    ) -> ProviderReconciliationOutcome:
        del subject_reference, credential, operation_id
        raise ProviderPermanentError("provider_prepared_mutation_required")


__all__ = [
    "AdapterLimits",
    "ArtifactReceipt",
    "HTTPResponse",
    "HTTPTransport",
    "MutationTargetCustody",
    "MutationTargetReceipt",
    "Provider",
    "RetrievalArtifactSink",
    "StockPrivacyRightsSourceAdapter",
]
