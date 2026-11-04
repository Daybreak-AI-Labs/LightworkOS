"""Existing Google Drive / Jira protocols with explicit credential authority.

UTF-8 files, digital PDFs, native Google Docs exports and Jira Task
creation/readback/search are supported. No ambient credentials or live acceptance are
implied. Fake providers keep externally observable state independently of cases.
"""
from __future__ import annotations

import copy
import functools
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote, urlsplit

import httpx

from .governed_operations import ServiceContext, digest
from .paths import tenant_scope

GOOGLE_DOC_MIME = "application/vnd.google-apps.document"
SUPPORTED_DRIVE_MIMES = frozenset({"text/plain", "application/pdf", GOOGLE_DOC_MIME})
MAX_TEXT_BYTES = 1024 * 1024
MAX_PDF_BYTES = 16 * 1024 * 1024
DEFAULT_SAFE_READ_ATTEMPTS = 3
DEFAULT_SAFE_READ_BACKOFF_SECONDS = 0.25
MAX_SAFE_READ_ATTEMPTS = 5
MAX_SAFE_READ_BACKOFF_SECONDS = 5.0
MAX_RETRY_DELAY_SECONDS = 2.0
_RETRYABLE_READ_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_DENIED_STATUS = frozenset({401, 403})

ADAPTER_CONTRACT_FIELDS = frozenset({
    "effect", "identity", "pagination", "permission", "rate_limit",
    "timeout", "errors", "retry", "verification",
})
JIRA_VERIFICATION_RECEIPT_FIELDS = frozenset({
    "schema", "verified", "key", "target", "field_comparisons",
    "external_version", "observed_at", "observed_sha256",
    "unresolved_ambiguity",
})
JIRA_FIELD_COMPARISONS = frozenset({
    "target_key", "project", "summary", "description", "marker",
    "issue_type", "provider_version",
})


ADAPTER_CONTRACT_MATRIX = {
    "drive.search": {
        "effect": "read",
        "identity": "named tenant Drive enrollment and current credential generation",
        "pagination": "one bounded page with has_more disclosure",
        "permission": "re-resolved under the credential mutation lock before every attempt",
        "rate_limit": "HTTP 429 retries within the configured safe-read attempt and delay caps",
        "timeout": "transport timeout retries within the configured safe-read attempt cap",
        "errors": "denials are terminal; malformed or exhausted reads return no provider data",
        "retry": "bounded transient-only safe-read retry",
        "verification": "closed result projection with explicit incomplete-page disclosure",
    },
    "drive.fetch": {
        "effect": "read",
        "identity": "document id plus provider version bracket",
        "pagination": "not_applicable",
        "permission": "one credential generation is fenced before every metadata and content attempt",
        "rate_limit": "HTTP 429 retries within the configured safe-read attempt and delay caps",
        "timeout": "transport timeout retries within the configured safe-read attempt cap",
        "errors": "denials and authority changes are terminal; partial bytes are discarded",
        "retry": "bounded transient-only safe-read retry",
        "verification": "metadata-content-metadata version bracket under one credential generation",
    },
    "jira.create": {
        "effect": "non-idempotent write",
        "identity": "approved operation id, exact payload marker and named Jira destination",
        "pagination": "not_applicable",
        "permission": "current exact credential generation is locked through the single dispatch",
        "rate_limit": "HTTP 429 is indeterminate and is never retried automatically",
        "timeout": "transport timeout is indeterminate and is never retried automatically",
        "errors": "malformed successful receipt is indeterminate; definite non-success stays failed",
        "retry": "never automatic; timeout or uncertain response requires reconciliation",
        "verification": "independent exact-field readback",
    },
    "jira.verify": {
        "effect": "read",
        "identity": "exact issue key and approved payload under the original credential generation",
        "pagination": "not_applicable",
        "permission": "re-resolved under the credential mutation lock before every attempt",
        "rate_limit": "HTTP 429 retries within the configured safe-read attempt and delay caps",
        "timeout": "transport timeout retries within the configured safe-read attempt cap",
        "errors": "denials are terminal; malformed or exhausted reads return no provider data",
        "retry": "bounded transient-only safe-read retry",
        "verification": "target identity, exact field comparisons, provider version and observation time",
    },
    "jira.find": {
        "effect": "read",
        "identity": "validated project plus service-generated operation marker",
        "pagination": "at most two marker matches; any continuation is unresolved ambiguity",
        "permission": "re-resolved under the credential mutation lock before every attempt",
        "rate_limit": "HTTP 429 retries within the configured safe-read attempt and delay caps",
        "timeout": "transport timeout retries within the configured safe-read attempt cap",
        "errors": "denials are terminal; malformed, zero and multiple results never imply success",
        "retry": "bounded transient-only safe-read retry",
        "verification": "search only identifies candidates; exact verify is still required",
    },
}


class CredentialAuthorityChanged(PermissionError):
    """The credential generation changed before a known-zero provider dispatch."""


class ProviderReadUnavailable(RuntimeError):
    """A bounded safe-read attempt set ended without authoritative data."""


class ProviderMultipleMatches(RuntimeError):
    """A bounded provider search proved that more than one effect may match."""

    def __init__(self, *, minimum: int):
        if type(minimum) is not int or minimum < 2:
            raise ValueError("multiple-match lower bound must be at least two")
        super().__init__("multiple matching Jira tasks require human reconciliation")
        self.minimum = minimum


class ProviderWriteIndeterminate(RuntimeError):
    """A non-idempotent provider write may have occurred and must be reconciled."""


class _RetryableProviderRead(RuntimeError):
    def __init__(self, *, retry_after: float | None = None):
        super().__init__("transient provider read failure")
        self.retry_after = retry_after


def _read_policy(attempts: int, backoff_seconds: float) -> tuple[int, float]:
    if (
        isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or not 1 <= attempts <= MAX_SAFE_READ_ATTEMPTS
    ):
        raise ValueError("safe read attempts must be an integer from 1 through 5")
    if (
        isinstance(backoff_seconds, bool)
        or not isinstance(backoff_seconds, int | float)
        or not math.isfinite(float(backoff_seconds))
        or not 0 <= float(backoff_seconds) <= MAX_SAFE_READ_BACKOFF_SECONDS
    ):
        raise ValueError("safe read backoff must be from 0 through 5 seconds")
    return attempts, float(backoff_seconds)


def _retry_after(response: httpx.Response) -> float | None:
    raw = str(response.headers.get("retry-after") or "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    if not math.isfinite(value):
        return None
    return max(0.0, min(MAX_RETRY_DELAY_SECONDS, value))


def _bounded_safe_read(
    operation,
    *,
    attempts: int,
    backoff_seconds: float,
    sleeper,
    label: str,
):
    """Retry only read-only provider work and discard every failed response."""
    last_error: BaseException | None = None
    for attempt in range(attempts):
        retry_after = None
        try:
            return operation()
        except _RetryableProviderRead as exc:
            last_error = exc
            retry_after = exc.retry_after
        except (httpx.TransportError, TimeoutError, ConnectionError) as exc:
            last_error = exc
        if attempt + 1 >= attempts:
            break
        delay = min(MAX_RETRY_DELAY_SECONDS, backoff_seconds * (2 ** attempt))
        if retry_after is not None:
            delay = max(delay, retry_after)
        if delay:
            sleeper(delay)
    raise ProviderReadUnavailable(
        f"{label} is unavailable after {attempts} bounded safe-read attempts"
    ) from last_error


def _closed_json(response: httpx.Response, *, write: bool) -> dict:
    try:
        payload = response.json()
    except ValueError as exc:
        if write:
            raise ProviderWriteIndeterminate(
                "Jira write returned an unusable receipt; reconcile before retrying"
            ) from exc
        raise ProviderReadUnavailable("Jira returned a malformed read response") from exc
    if not isinstance(payload, dict):
        if write:
            raise ProviderWriteIndeterminate(
                "Jira write returned an unusable receipt; reconcile before retrying"
            )
        raise ProviderReadUnavailable("Jira returned a malformed read response")
    return payload


def validate_jira_verification(receipt: dict, *, expected_key: str) -> dict:
    """Validate the closed receipt contract before a workflow trusts readback."""
    if not isinstance(receipt, dict) or set(receipt) != JIRA_VERIFICATION_RECEIPT_FIELDS:
        raise ValueError("Jira verification receipt is malformed")
    comparisons = receipt.get("field_comparisons")
    target = receipt.get("target")
    observed_at = receipt.get("observed_at")
    external_version = receipt.get("external_version")
    checks = (
        receipt.get("schema") == "lightwork.jira-verification-receipt.v1",
        receipt.get("key") == expected_key,
        isinstance(target, dict),
        isinstance(target, dict)
        and set(target) == {"provider", "issue_key"},
        isinstance(target, dict)
        and target == {"provider": "jira", "issue_key": expected_key},
        isinstance(comparisons, dict),
        isinstance(comparisons, dict)
        and set(comparisons) == JIRA_FIELD_COMPARISONS,
        isinstance(comparisons, dict)
        and all(type(value) is bool for value in comparisons.values()),
        type(receipt.get("verified")) is bool,
        type(receipt.get("unresolved_ambiguity")) is bool,
        isinstance(observed_at, int | float)
        and not isinstance(observed_at, bool)
        and math.isfinite(float(observed_at))
        and float(observed_at) >= 0,
        isinstance(receipt.get("observed_sha256"), str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", receipt["observed_sha256"])),
        external_version is None
        or isinstance(external_version, str) and bool(external_version),
    )
    if not all(checks):
        raise ValueError("Jira verification receipt is malformed")
    expected_verified = (
        all(comparisons.values()) and receipt["unresolved_ambiguity"] is False
    )
    if receipt["verified"] is not expected_verified:
        raise ValueError("Jira verification receipt is internally inconsistent")
    if comparisons["provider_version"] is not bool(external_version):
        raise ValueError("Jira verification receipt has an inconsistent provider version")
    return copy.deepcopy(receipt)


@dataclass(frozen=True)
class EvidenceDocument:
    document_id: str
    version: str
    modified_at: float
    content: bytes
    mime: str = "text/plain"
    export_mime: str | None = None

    def identity(self) -> dict:
        return {"document_id": self.document_id, "version": self.version,
                "modified_at": self.modified_at, "mime": self.mime}


def resolve_connection(ctx: ServiceContext, *, document: bool = False, refresh: bool = True) -> dict:
    """Resolve the *named* tenant connection; never choose another credential."""
    from . import connections

    reference = ctx.document_credential_ref if document else ctx.credential_ref
    with tenant_scope(tenant=ctx.tenant):
        if not connections.enabled():
            raise PermissionError("named connections are disabled")
        record = connections.get_connection(reference)
    connector = "gdrive" if document else "jira"
    if (not record or record.get("connector") != connector
            or record.get("owner") != ctx.credential_authority
            or not connections._may_use(record, ctx.actor)
            or not record.get("token") or not record.get("revision")):
        raise PermissionError("named credential authority is unavailable or denied")
    base = str(record.get("base_url") or "").rstrip("/")
    parsed = urlsplit(base)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise PermissionError("connector requires a pinned HTTPS origin")
    if document and base != "https://www.googleapis.com":
        raise PermissionError("Drive requires the Google API origin")
    if refresh and record.get("oauth"):
        from .connection_oauth import renew
        with tenant_scope(tenant=ctx.tenant):
            record = renew(record, actor=ctx.actor)
    return dict(record, base_url=base)


def _scoped(method):
    @functools.wraps(method)
    def invoke(self, ctx, *args, **kwargs):
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        with tenant_scope(tenant=ctx.tenant):
            return method(self, ctx, *args, **kwargs)
    return invoke


class GoogleDriveEvidence:
    """Version-bracketed read through existing guarded Drive fetch machinery."""
    mode = "live_unverified"

    def __init__(
        self,
        *,
        safe_read_attempts: int = DEFAULT_SAFE_READ_ATTEMPTS,
        safe_read_backoff_seconds: float = DEFAULT_SAFE_READ_BACKOFF_SECONDS,
        sleeper=time.sleep,
    ):
        self.safe_read_attempts, self.safe_read_backoff_seconds = _read_policy(
            safe_read_attempts, safe_read_backoff_seconds
        )
        if not callable(sleeper):
            raise TypeError("safe read sleeper must be callable")
        self._sleeper = sleeper

    def _read(self, operation, label):
        return _bounded_safe_read(
            operation,
            attempts=self.safe_read_attempts,
            backoff_seconds=self.safe_read_backoff_seconds,
            sleeper=self._sleeper,
            label=label,
        )

    @staticmethod
    def _begin_authorized_read(ctx):
        """Refresh once, then pin every attempt to that credential generation."""
        return resolve_connection(ctx, document=True)["revision"]

    def _authorized_read(self, ctx, expected_revision, operation, label):
        from . import connections

        def dispatch_once():
            # Reconnect/revoke uses this same lock. Holding it through the read
            # prevents a credential from becoming stale between validation and
            # the provider boundary; retries reacquire and revalidate it.
            with connections._mutation_lock():
                try:
                    credential = resolve_connection(ctx, document=True, refresh=False)
                except PermissionError as exc:
                    raise CredentialAuthorityChanged(
                        "Drive credential changed: generation changed during the read"
                    ) from exc
                if credential["revision"] != expected_revision:
                    raise CredentialAuthorityChanged(
                        "Drive credential changed: generation changed during the read"
                    )
                result = operation(credential)
                try:
                    current = resolve_connection(ctx, document=True, refresh=False)
                except PermissionError as exc:
                    raise CredentialAuthorityChanged(
                        "Drive credential changed: generation changed during the read"
                    ) from exc
                if current["revision"] != expected_revision:
                    raise CredentialAuthorityChanged(
                        "Drive credential changed: generation changed during the read"
                    )
                return result

        return self._read(dispatch_once, label)

    @_scoped
    def authority_version(self, ctx):
        return resolve_connection(ctx, document=True, refresh=False)["revision"]

    def _head(self, ctx, document_id, expected_revision):
        from . import doc_discovery

        def metadata(credential):
            url = f"{credential['base_url']}/drive/v3/files/{quote(document_id, safe='')}"
            status, row = doc_discovery._get(url, credential["token"], {
                "fields": "id,version,modifiedTime,mimeType,trashed,size",
            })
            if status in _DENIED_STATUS:
                raise PermissionError("Drive evidence access is denied")
            if status in _RETRYABLE_READ_STATUS:
                raise _RetryableProviderRead
            if status == 404:
                raise FileNotFoundError("Drive evidence is missing")
            if status != 200:
                raise ProviderReadUnavailable("Drive evidence verification is unavailable")
            if not isinstance(row, dict):
                raise ProviderReadUnavailable("Drive returned malformed evidence metadata")
            return row

        row = self._authorized_read(
            ctx, expected_revision, metadata, "Drive evidence verification",
        )
        if row.get("trashed") or row.get("mimeType") not in SUPPORTED_DRIVE_MIMES:
            raise ValueError("supported Drive evidence: UTF-8 text, digital PDF, and Google Docs")
        if not row.get("version") or row.get("id") != document_id:
            raise ValueError("Drive evidence metadata is incomplete")
        modified_at = row.get("modifiedTime")
        if not isinstance(modified_at, str) or not modified_at:
            raise ValueError("Drive evidence metadata is incomplete")
        try:
            modified = datetime.fromisoformat(modified_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Drive evidence metadata is incomplete") from exc
        if modified.tzinfo is None:
            raise ValueError("Drive evidence metadata is incomplete")
        return {"document_id": document_id, "version": str(row["version"]),
                "modified_at": modified.timestamp(), "mime": row["mimeType"]}

    @_scoped
    def head(self, ctx, document_id):
        return self._head(ctx, document_id, self._begin_authorized_read(ctx))

    @_scoped
    def search(self, ctx, query, *, limit=20):
        from . import doc_discovery

        if not isinstance(query, str) or not 1 <= len(query.strip()) <= 200:
            raise ValueError("enter a document name of up to 200 characters")
        expected_revision = self._begin_authorized_read(ctx)
        term = query.strip().replace("\\", "\\\\").replace("'", "\\'")
        kinds = " or ".join(f"mimeType = '{mime}'" for mime in sorted(SUPPORTED_DRIVE_MIMES))
        def search_page(credential):
            status, data = doc_discovery._get(
                f"{credential['base_url']}/drive/v3/files",
                credential["token"],
                {
                    "q": f"trashed = false and name contains '{term}' and ({kinds})",
                    "pageSize": min(20, limit),
                    "fields": "files(id,name,mimeType),nextPageToken",
                    "orderBy": "modifiedTime desc",
                },
            )
            if status in _DENIED_STATUS:
                raise PermissionError("Drive document search access is denied")
            if status in _RETRYABLE_READ_STATUS:
                raise _RetryableProviderRead
            if status != 200:
                raise ProviderReadUnavailable("Drive document search is unavailable")
            if not isinstance(data, dict) or not isinstance(data.get("files"), list):
                raise ProviderReadUnavailable("Drive returned a malformed search response")
            return data

        data = self._authorized_read(
            ctx, expected_revision, search_page, "Drive document search",
        )
        return {"documents": [{"id": str(row["id"]), "name": str(row.get("name") or row["id"])[:256],
                               "mime": row["mimeType"]} for row in data["files"][:20]
                              if isinstance(row, dict) and row.get("id") and row.get("mimeType") in SUPPORTED_DRIVE_MIMES],
                "has_more": bool(data.get("nextPageToken"))}

    @_scoped
    def fetch(self, ctx, document_id):
        from . import doc_discovery

        expected_revision = self._begin_authorized_read(ctx)
        before = self._head(ctx, document_id, expected_revision)
        export_mime = None
        if before["mime"] == GOOGLE_DOC_MIME:
            export_mime = "text/plain"

        def safe_download(credential):
            try:
                if before["mime"] == GOOGLE_DOC_MIME:
                    # Native Docs have no stable page numbering in their text
                    # export. Cite paragraphs; do not fabricate PDF pages.
                    url = (
                        f"{credential['base_url']}/drive/v3/files/"
                        f"{quote(document_id, safe='')}/export?mimeType=text%2Fplain"
                    )
                    return doc_discovery._download(
                        url, credential["token"], MAX_TEXT_BYTES,
                    )
                return doc_discovery._fetch_gdrive(
                    credential["base_url"], credential["token"], {}, document_id,
                    MAX_PDF_BYTES if before["mime"] == "application/pdf" else MAX_TEXT_BYTES,
                )
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in _DENIED_STATUS:
                    raise PermissionError("Drive evidence access is denied") from exc
                if status in _RETRYABLE_READ_STATUS:
                    raise _RetryableProviderRead(
                        retry_after=_retry_after(exc.response)
                    ) from exc
                raise ProviderReadUnavailable("Drive evidence download is unavailable") from exc

        data, _ = self._authorized_read(
            ctx, expected_revision, safe_download, "Drive evidence download",
        )
        if before != self._head(ctx, document_id, expected_revision):
            raise ValueError("Drive evidence changed during download")
        return EvidenceDocument(content=data, export_mime=export_mime, **before)


def jira_body(payload: dict) -> dict:
    """Same v3 Task/ADF operation already supported by tools.jira."""
    if (not isinstance(payload, dict)
            or set(payload) != {"project", "summary", "description", "marker"}
            or not all(isinstance(value, str) for value in payload.values())
            or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,31}", payload["project"])
            or not re.fullmatch(r"lightwork-vop-[0-9a-f]{32}", payload["marker"])
            or not 1 <= len(payload["summary"]) <= 255
            or not 1 <= len(payload["description"]) <= 12000):
        raise ValueError("unsupported Jira Task payload")
    return {"fields": {
        "project": {"key": payload["project"]},
        "summary": payload["summary"], "issuetype": {"name": "Task"},
        "labels": [payload["marker"]],
        "description": {"type": "doc", "version": 1, "content": [{
            "type": "paragraph", "content": [
                {"type": "text", "text": payload["description"]},
            ],
        }]},
    }}


class JiraTickets:
    """Jira Cloud v3 with an enrolled Bearer token; create is non-idempotent."""
    mode = "live_unverified"
    provider_idempotency = False

    def __init__(
        self,
        *,
        safe_read_attempts: int = DEFAULT_SAFE_READ_ATTEMPTS,
        safe_read_backoff_seconds: float = DEFAULT_SAFE_READ_BACKOFF_SECONDS,
        sleeper=time.sleep,
        clock=time.time,
    ):
        self.safe_read_attempts, self.safe_read_backoff_seconds = _read_policy(
            safe_read_attempts, safe_read_backoff_seconds
        )
        if not callable(sleeper) or not callable(clock):
            raise TypeError("safe read sleeper and clock must be callable")
        self._sleeper = sleeper
        self._clock = clock

    def authority_version(self, ctx):
        return resolve_connection(ctx, refresh=False)["revision"]

    @_scoped
    def _request(
        self,
        ctx,
        method,
        path,
        *,
        expected_credential_version=None,
        safe_read=False,
        **kwargs,
    ):
        from . import connections
        from .enterprise import enterprise_egress_denial
        from .tools._ssrf import safe_client

        def dispatch_once():
            # Refresh, when needed, completes under its own connection-store lock.
            # Re-resolve after taking that same lock and keep it through dispatch so
            # reconnect/revoke cannot land between the exact revision check and the
            # provider boundary. ``refresh=False`` avoids recursively taking the
            # non-reentrant store/process lock.
            try:
                resolve_connection(ctx)
            except PermissionError as exc:
                if expected_credential_version is not None:
                    raise CredentialAuthorityChanged(
                        "approved Jira credential generation changed"
                    ) from exc
                raise
            with connections._mutation_lock():
                try:
                    credential = resolve_connection(ctx, refresh=False)
                except PermissionError as exc:
                    if expected_credential_version is not None:
                        raise CredentialAuthorityChanged(
                            "approved Jira credential generation changed"
                        ) from exc
                    raise
                if (
                    expected_credential_version is not None
                    and credential["revision"] != expected_credential_version
                ):
                    raise CredentialAuthorityChanged(
                        "approved Jira credential generation changed"
                    )
                prefix = str((credential.get("oauth") or {}).get("api_prefix") or "")
                if prefix and (
                    credential["base_url"] != "https://api.atlassian.com"
                    or not re.fullmatch(r"/ex/jira/[0-9a-f-]{36}", prefix)
                ):
                    raise PermissionError("Jira account destination is invalid")
                url = credential["base_url"] + prefix + path
                if enterprise_egress_denial(url, tool="jira"):
                    raise PermissionError("Jira egress is not permitted")
                with safe_client(url, timeout=30) as client:
                    response = client.request(
                        method,
                        url,
                        headers={
                            "Authorization": f"Bearer {credential['token']}",
                            "Accept": "application/json",
                        },
                        **kwargs,
                    )
            if response.status_code in _DENIED_STATUS:
                raise PermissionError("Jira operation access is denied")
            if response.status_code in _RETRYABLE_READ_STATUS:
                if safe_read:
                    raise _RetryableProviderRead(
                        retry_after=_retry_after(response)
                    )
                raise ProviderWriteIndeterminate(
                    "Jira write outcome is indeterminate; reconcile before retrying"
                )
            if not 200 <= response.status_code < 300:
                raise RuntimeError(
                    f"Jira operation unavailable: HTTP {response.status_code}"
                )
            return _closed_json(response, write=not safe_read)

        if not safe_read:
            try:
                return dispatch_once()
            except (httpx.TransportError, TimeoutError, ConnectionError) as exc:
                raise ProviderWriteIndeterminate(
                    "Jira write outcome is indeterminate; reconcile before retrying"
                ) from exc
        return _bounded_safe_read(
            dispatch_once,
            attempts=self.safe_read_attempts,
            backoff_seconds=self.safe_read_backoff_seconds,
            sleeper=self._sleeper,
            label="Jira read",
        )

    def create(self, ctx, payload, operation_id, *, expected_credential_version=None):
        row = self._request(ctx, "POST", "/rest/api/3/issue", json=jira_body(payload),
                            expected_credential_version=expected_credential_version)
        from .tools.jira import _require_key

        try:
            key = _require_key(str(row.get("key") or ""))
        except (TypeError, ValueError) as exc:
            raise ProviderWriteIndeterminate(
                "Jira write returned an unusable receipt; reconcile before retrying"
            ) from exc
        return {"key": key, "operation_id": operation_id}

    def verify(self, ctx, key, payload, *, expected_credential_version=None):
        from .tools.jira import _require_key

        row = self._request(ctx, "GET", f"/rest/api/3/issue/{_require_key(key)}",
                            expected_credential_version=expected_credential_version,
                            safe_read=True, params={
            "fields": "project,summary,description,labels,issuetype,updated",
        })
        expected = jira_body(payload)["fields"]
        fields = row.get("fields")
        if not isinstance(fields, dict):
            raise ProviderReadUnavailable("Jira returned a malformed read response")
        updated = fields.get("updated")
        try:
            version_available = (isinstance(updated, str) and bool(updated)
                                 and datetime.fromisoformat(updated.replace("Z", "+00:00")).tzinfo is not None)
        except ValueError:
            version_available = False
        project = fields.get("project")
        issue_type = fields.get("issuetype")
        labels = fields.get("labels")
        comparisons = {
            "target_key": row.get("key") == key,
            "project": (
                isinstance(project, dict) and project.get("key") == payload["project"]
            ),
            "summary": fields.get("summary") == expected["summary"],
            "description": fields.get("description") == expected["description"],
            "marker": isinstance(labels, list) and payload["marker"] in labels,
            "issue_type": (
                isinstance(issue_type, dict) and issue_type.get("name") == "Task"
            ),
            "provider_version": version_available,
        }
        matches = all(comparisons.values())
        receipt = {
            "schema": "lightwork.jira-verification-receipt.v1",
            "verified": matches,
            "key": key,
            "target": {"provider": "jira", "issue_key": key},
            "field_comparisons": comparisons,
            "external_version": updated if version_available else None,
            "observed_at": self._clock(),
            "observed_sha256": digest(fields),
            "unresolved_ambiguity": False,
        }
        return validate_jira_verification(receipt, expected_key=key)

    def find(self, ctx, payload, *, expected_credential_version=None):
        # Both project and marker are service-generated/validated, never free JQL.
        jira_body(payload)
        row = self._request(ctx, "POST", "/rest/api/3/search/jql",
                            expected_credential_version=expected_credential_version,
                            safe_read=True, json={
            "jql": f'project = "{payload["project"]}" AND labels = "{payload["marker"]}"',
            "fields": ["summary"], "maxResults": 2,
        })
        issues = row.get("issues")
        if not isinstance(issues, list) or len(issues) > 2:
            raise ProviderReadUnavailable("Jira returned a malformed search response")
        keys = []
        for item in issues:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                raise ProviderReadUnavailable("Jira returned a malformed search response")
            from .tools.jira import _require_key

            keys.append(_require_key(item["key"]))
        if len(set(keys)) != len(keys):
            raise ProviderReadUnavailable("Jira returned duplicate search results")
        next_page = row.get("nextPageToken")
        if next_page is not None:
            if not isinstance(next_page, str) or not next_page:
                raise ProviderReadUnavailable("Jira returned a malformed search response")
            if not keys:
                raise ProviderReadUnavailable("Jira returned inconsistent search pagination")
            # The endpoint is deliberately capped at two results. A continuation
            # token therefore proves ambiguity without requiring another page or
            # pretending that the exact total is known.
            raise ProviderMultipleMatches(minimum=len(keys) + 1)
        return keys


class FakeGoogleDriveEvidence:
    mode = "offline_synthetic"

    def __init__(self, documents=None):
        # Keys include tenant; no implicit cross-customer fallback.
        self.documents = dict(documents or {})
        self.version = "synthetic-drive-credential-v1"
        self.unavailable = False

    def authority_version(self, ctx):
        return self.version

    def fetch(self, ctx, document_id):
        if self.unavailable:
            raise RuntimeError("synthetic Drive unavailable")
        try:
            return self.documents[(ctx.tenant, document_id)]
        except KeyError:
            raise FileNotFoundError("evidence is missing") from None

    def head(self, ctx, document_id):
        return self.fetch(ctx, document_id).identity()

    def search(self, ctx, query, *, limit=20):
        matches = [{"id": key, "name": key, "mime": value.mime}
                   for (tenant, key), value in sorted(self.documents.items())
                   if tenant == ctx.tenant and query.lower() in key.lower()]
        return {"documents": matches[:limit], "has_more": len(matches) > limit}


class FakeJiraTickets:
    mode = "offline_synthetic"
    provider_idempotency = False

    def __init__(self, state=None, *, clock=time.time):
        self.state = state if state is not None else {}
        self.version = "synthetic-jira-credential-v1"
        self.creates = 0
        self.timeout_after_success = False
        self.verify_unavailable = False
        if not callable(clock):
            raise TypeError("verification clock must be callable")
        self._clock = clock

    def authority_version(self, ctx):
        return self.version

    def _credential(self, expected_credential_version):
        if expected_credential_version is not None and self.version != expected_credential_version:
            raise CredentialAuthorityChanged("approved synthetic Jira credential generation changed")

    def create(self, ctx, payload, operation_id, *, expected_credential_version=None):
        self._credential(expected_credential_version)
        jira_body(payload)
        self.creates += 1
        key = f"{payload['project']}-{len(self.state) + 1}"
        self.state[(ctx.tenant, key)] = {"payload": copy.deepcopy(payload), "version": "1"}
        if self.timeout_after_success:
            raise TimeoutError("synthetic lost success response")
        return {"key": key, "operation_id": operation_id}

    def verify(self, ctx, key, payload, *, expected_credential_version=None):
        self._credential(expected_credential_version)
        if self.verify_unavailable:
            raise RuntimeError("synthetic Jira readback unavailable")
        observed = self.state.get((ctx.tenant, key))
        expected = jira_body(payload)["fields"]
        fields = jira_body(observed["payload"])["fields"] if observed else None
        version = (observed or {}).get("version")
        project = (fields or {}).get("project")
        issue_type = (fields or {}).get("issuetype")
        labels = (fields or {}).get("labels")
        comparisons = {
            "target_key": bool(observed),
            "project": (
                isinstance(project, dict) and project.get("key") == payload["project"]
            ),
            "summary": (fields or {}).get("summary") == expected["summary"],
            "description": (fields or {}).get("description") == expected["description"],
            "marker": isinstance(labels, list) and payload["marker"] in labels,
            "issue_type": (
                isinstance(issue_type, dict) and issue_type.get("name") == "Task"
            ),
            "provider_version": isinstance(version, str) and bool(version),
        }
        receipt = {
            "schema": "lightwork.jira-verification-receipt.v1",
            "verified": all(comparisons.values()),
            "key": key,
            "target": {"provider": "jira", "issue_key": key},
            "field_comparisons": comparisons,
            "external_version": version,
            "observed_at": self._clock(),
            "observed_sha256": digest(fields),
            "unresolved_ambiguity": False,
        }
        return validate_jira_verification(receipt, expected_key=key)

    def find(self, ctx, payload, *, expected_credential_version=None):
        self._credential(expected_credential_version)
        if self.verify_unavailable:
            raise RuntimeError("synthetic Jira search unavailable")
        return [key for (tenant, key), value in self.state.items()
                if tenant == ctx.tenant and value["payload"]["marker"] == payload["marker"]]
