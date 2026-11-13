"""DSAR fulfillment: verify identity, collect, redact, deliver — governed.

The register in :mod:`maverick.privacy_ops` tracks a request; this module
EXECUTES it, as a governed pipeline with an audit answer for every stage:

* **Identity** — no response ships until HOW the requester was verified is
  recorded. The method vocabulary is fixed. A named human records every
  method except ``email_challenge``, which the public rights-request form
  performs itself (single-use link to the address given) and records
  under the actor ``public-rights-form`` -- see
  :data:`IDENTITY_METHODS_PERFORMED`.
* **Collection** — the platform's own holdings are collected via
  :func:`maverick.dsar.export_subject_data`; external sources (vendor
  exports, mailbox pulls) are logged with references so the response's
  completeness is inspectable.
* **Redaction** — the delivered bundle is passed through the
  deterministic redactor for the identifier categories in
  :data:`RESPONSE_REDACTION_CATEGORIES`; the subject's own reference is
  preserved. Names, street addresses and other details of other people
  are not detected and need human review.
* **Delivery** — a single-use style token link (stored only as a SHA-256
  digest, with expiry). The bundle is assembled AT DELIVERY TIME from the
  live stores — no second copy of personal data is persisted here.

Decision support and record-keeping for the operator's own program;
never identity assurance by itself, and never legal advice.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from collections.abc import Callable
from typing import Any

from .governed_records import GovernedRecordStore

SCHEMA = "lightwork.dsar-fulfillment.v1"
IDENTITY_METHODS = (
    "account_login", "document_check", "email_challenge",
    "in_person", "verified_by_processor", "other",
)
#: Which of those methods this platform PERFORMS rather than merely records.
#: ``email_challenge`` is performed by the public rights-request form
#: (:mod:`maverick.public_rights_form`): the requester must open a
#: single-use link sent to the address they gave. Every other method is a
#: label a named human records after doing the check elsewhere.
IDENTITY_METHODS_PERFORMED = frozenset({"email_challenge"})
#: The only categories scrubbed from a response. Anything else about a
#: third party (a name, a street address) is left in place.
RESPONSE_REDACTION_CATEGORIES = [
    "email", "phone", "national_id", "financial", "ip_address", "location",
]
REDACTION_NOTICE = (
    "Only these categories of identifier were redacted automatically: "
    + ", ".join(item.replace("_", " ") for item in RESPONSE_REDACTION_CATEGORIES)
    + ". Other third-party details, such as names and street addresses, "
    "may remain and need human review. The subject's own reference is "
    "preserved."
)
_MAX_RECORDS = 10_000
_SCAN_LIMIT = _MAX_RECORDS + 1
_MAX_SOURCES = 50
_TOKEN_TTL_MAX_HOURS = 24 * 14

_STORE = GovernedRecordStore("dsar_fulfillment", "DSF", "dsar_fulfillment")


class DsarFulfillmentError(RuntimeError):
    """Base failure for DSAR fulfillment."""


class DsarFulfillmentConfigError(DsarFulfillmentError):
    """The feature is not enabled."""


def get_dsar_fulfillment_config() -> dict[str, Any]:
    from .config import load_global_config

    try:
        config = load_global_config()
    except Exception as exc:
        raise DsarFulfillmentConfigError(
            "dsar_fulfillment configuration is unavailable") from exc
    section = (config or {}).get("dsar_fulfillment") or {}
    if not isinstance(section, dict):
        raise DsarFulfillmentConfigError("dsar_fulfillment must be a table")
    flag = section.get("enable", False)
    if not isinstance(flag, bool):
        raise DsarFulfillmentConfigError(
            "dsar_fulfillment.enable must be a boolean")
    return {"enable": flag}


def enabled() -> bool:
    try:
        return get_dsar_fulfillment_config()["enable"] is True
    except Exception:
        return False


def _require_enabled() -> None:
    if not enabled():
        raise DsarFulfillmentConfigError(
            "DSAR fulfillment requires [dsar_fulfillment] enable = true")


def _text(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ValueError(f"{label} must be 1-{limit} characters")
    return text


def _fulfillment_id(request_id: str) -> str:
    return "DSF-" + hashlib.sha256(request_id.encode()).hexdigest()[:24]


def _dsar_record_or_raise(request_id: str) -> dict[str, Any]:
    from . import privacy_ops

    record = privacy_ops.get_dsar(request_id)
    if record is None:
        raise KeyError(f"no such DSAR request: {request_id}")
    return record


def open_fulfillment(request_id: str, *, actor: str) -> dict[str, Any]:
    """Open (or return) the fulfillment record for one DSAR request."""

    _require_enabled()
    operator = _text(actor, "actor", 256)
    request = _text(request_id, "request_id", 64)
    dsar = _dsar_record_or_raise(request)
    record_id = _fulfillment_id(request)
    current = _STORE.get(record_id)
    if current is not None:
        return dict(current)
    record = {
        "id": record_id,
        "schema": SCHEMA,
        "request_id": request,
        "subject_id": str(dsar.get("subject_id") or ""),
        "subject_channel": str(dsar.get("channel") or ""),
        "identity": {"status": "unverified"},
        "sources": [],
        "response": None,
        "opened_by": operator,
    }
    return dict(
        _STORE.create(
            record, action="open_fulfillment", actor=operator,
            max_records=_MAX_RECORDS,
        )
    )


def record_identity_verification(
    fulfillment_id: str,
    *,
    method: str,
    reference: str,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """A named human records HOW the requester's identity was verified."""

    _require_enabled()
    if method not in IDENTITY_METHODS:
        raise ValueError(
            f"method must be one of: {', '.join(IDENTITY_METHODS)}")
    operator = _text(actor, "actor", 256)
    where = _text(reference, "reference", 512)

    def mutate(value: dict[str, Any]) -> None:
        value["identity"] = {
            "status": "verified",
            "method": method,
            "reference": where,
            "verified_by": operator,
            "verified_at": time.time(),
        }

    saved = _STORE.update(
        _text(fulfillment_id, "fulfillment_id", 64), mutate,
        expected_revision=int(expected_revision),
        action="record_identity_verification", actor=operator,
    )
    if saved is None:
        raise KeyError(f"no such fulfillment: {fulfillment_id}")
    return dict(saved)


def record_collection_source(
    fulfillment_id: str,
    *,
    source: str,
    reference: str,
    items: int,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """Log one collection source (a vendor export, a mailbox pull, ...)."""

    _require_enabled()
    operator = _text(actor, "actor", 256)
    name = _text(source, "source", 128)
    where = _text(reference, "reference", 512)
    if not isinstance(items, int) or isinstance(items, bool) or items < 0:
        raise ValueError("items must be a non-negative integer")

    def mutate(value: dict[str, Any]) -> None:
        sources = list(value.get("sources") or [])
        if len(sources) >= _MAX_SOURCES:
            raise ValueError(f"at most {_MAX_SOURCES} sources per request")
        sources.append(
            {
                "source": name,
                "reference": where,
                "items": items,
                "collected_by": operator,
                "collected_at": time.time(),
            }
        )
        value["sources"] = sources

    saved = _STORE.update(
        _text(fulfillment_id, "fulfillment_id", 64), mutate,
        expected_revision=int(expected_revision),
        action="record_collection_source", actor=operator,
    )
    if saved is None:
        raise KeyError(f"no such fulfillment: {fulfillment_id}")
    return dict(saved)


def prepare_response(
    fulfillment_id: str,
    *,
    actor: str,
    expected_revision: int,
    expires_hours: int = 72,
    max_reads: int | None = None,
) -> dict[str, Any]:
    """Mint the token-gated response link. Identity must be verified first.

    The token is returned ONCE and stored only as a SHA-256 digest; the
    response itself is assembled at delivery time, so no second copy of
    the subject's data is persisted by this module. ``max_reads`` caps
    how many times the link serves (``1`` = strict single-use;
    ``None`` = until expiry); the policy is reported in the response
    itself so the recipient knows the link's lifetime.
    """

    _require_enabled()
    operator = _text(actor, "actor", 256)
    if (
        not isinstance(expires_hours, int)
        or isinstance(expires_hours, bool)
        or not 1 <= expires_hours <= _TOKEN_TTL_MAX_HOURS
    ):
        raise ValueError(
            f"expires_hours must be between 1 and {_TOKEN_TTL_MAX_HOURS}")
    if max_reads is not None and (
        not isinstance(max_reads, int)
        or isinstance(max_reads, bool)
        or not 1 <= max_reads <= 100
    ):
        raise ValueError("max_reads must be between 1 and 100, or omitted")
    token = secrets.token_urlsafe(24)
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()

    def mutate(value: dict[str, Any]) -> None:
        identity = value.get("identity") or {}
        if identity.get("status") != "verified":
            raise DsarFulfillmentError(
                "identity must be verified before a response link is minted")
        value["response"] = {
            "token_sha256": digest,
            "minted_by": operator,
            "minted_at": now,
            "expires_at": now + expires_hours * 3600,
            "max_reads": max_reads,
            "reads_used": 0,
            "delivered_at": None,
        }

    saved = _STORE.update(
        _text(fulfillment_id, "fulfillment_id", 64), mutate,
        expected_revision=int(expected_revision),
        action="prepare_response", actor=operator,
    )
    if saved is None:
        raise KeyError(f"no such fulfillment: {fulfillment_id}")
    return {
        "id": saved["id"],
        "revision": saved["revision"],
        "response_path": f"/dsar/response/{token}",
        "expires_at": saved["response"]["expires_at"],
    }


def _redact_bundle(bundle: Any, subject_id: str) -> Any:
    """Scrub the listed identifier categories; the subject's own reference stays.

    Field-aware: each string leaf is redacted individually (no
    serialize/reparse round trip), with the subject's own reference
    swapped out under a NUL sentinel first — NUL cannot occur inside a
    JSON-decoded string, so the sentinel can never collide with data.
    """

    from .redaction import redact_structured

    sentinel = "\x00LIGHTWORK-SUBJECT\x00"
    normalized = json.loads(json.dumps(bundle, default=str))

    def swap(node: Any, forward: bool) -> Any:
        source, target = (
            (subject_id, sentinel) if forward else (sentinel, subject_id)
        )
        if isinstance(node, str):
            return node.replace(source, target)
        if isinstance(node, dict):
            return {key: swap(item, forward) for key, item in node.items()}
        if isinstance(node, list):
            return [swap(item, forward) for item in node]
        return node

    guarded = swap(normalized, True) if subject_id else normalized
    scrubbed = redact_structured(
        guarded, categories=RESPONSE_REDACTION_CATEGORIES)["value"]
    return swap(scrubbed, False) if subject_id else scrubbed


def response_for_token(token: str) -> dict[str, Any] | None:
    """Resolve one response token; ``None`` for unknown/expired/undelivered.

    Assembles the platform export live and redacts the categories in
    :data:`RESPONSE_REDACTION_CATEGORIES` before anything leaves. Marks
    first delivery.
    """

    _require_enabled()
    raw = str(token or "").strip()
    if not raw or len(raw) > 128:
        return None
    digest = hashlib.sha256(raw.encode()).hexdigest()
    for row in _STORE.list(limit=_SCAN_LIMIT):
        response = row.get("response") or {}
        if response.get("token_sha256") != digest:
            continue
        if time.time() > float(response.get("expires_at") or 0.0):
            return None
        max_reads = response.get("max_reads")
        reads_used = int(response.get("reads_used") or 0)
        if max_reads is not None and reads_used >= int(max_reads):
            return None

        from . import dsar as dsar_export

        subject = str(row.get("subject_id") or "")
        request = _dsar_record_or_raise(str(row["request_id"]))
        if subject != str(request.get("subject_id") or ""):
            raise DsarFulfillmentError("Fulfillment subject no longer matches the verified request")
        channel = row.get("subject_channel", str(request.get("channel") or ""))
        if channel != str(request.get("channel") or ""):
            raise DsarFulfillmentError("Fulfillment channel no longer matches the verified request")
        # A failed/ambiguous export must not consume a read or claim delivery.
        # The subsequent CAS still prevents concurrent or revoked link use.
        bundle = dsar_export.export_subject_data(subject, channel=channel or None, strict=True)
        scrubbed = _redact_bundle(bundle, subject)

        def mark(value: dict[str, Any]) -> None:
            inner = dict(value.get("response") or {})
            if inner.get("delivered_at") is None:
                inner["delivered_at"] = time.time()
            inner["reads_used"] = int(inner.get("reads_used") or 0) + 1
            value["response"] = inner

        # The read is COUNTED before the bundle ships: on a CAS race the
        # stricter outcome wins (a burned read, never a free one).
        from .governed_records import RecordConflict

        try:
            saved = _STORE.update(
                str(row["id"]), mark,
                expected_revision=int(row.get("revision") or 0),
                action="deliver_response", actor="dsar-response-link",
            )
        except RecordConflict:
            return None
        if saved is None:
            return None
        return {
            "request_id": row.get("request_id"),
            "subject_id": subject,
            "sources": list(row.get("sources") or []),
            "bundle": scrubbed,
            "access_policy": {
                "expires_at": response.get("expires_at"),
                "max_reads": max_reads,
                "reads_used": reads_used + 1,
            },
            "redaction_notice": REDACTION_NOTICE,
        }
    return None


_GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
_GRAPH_PAGE_TOP = 100
_GRAPH_TIMEOUT_SECONDS = 20.0
#: A subject addressable in Microsoft Graph is a userPrincipalName; anything
#: else (an opaque customer id, free text) cannot be collected this way.
_UPN_RE = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,255}$")


def _graph_page(url: str, token: str) -> dict[str, Any]:
    """One SSRF-pinned Graph GET returning the parsed JSON page."""

    from .enterprise import enterprise_egress_denial
    from .tools._ssrf import BlockedHost, safe_get

    deny = enterprise_egress_denial(url, tool="dsar_fulfillment")
    if deny:
        raise DsarFulfillmentError(deny)
    try:
        response = safe_get(
            url, timeout=_GRAPH_TIMEOUT_SECONDS,
            headers={"Authorization": f"Bearer {token}"},
        )
    except BlockedHost as exc:
        raise DsarFulfillmentError("blocked host (SSRF guard)") from exc
    if response.status_code != 200:
        raise DsarFulfillmentError(
            f"Microsoft Graph returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise DsarFulfillmentError(
            "Microsoft Graph returned a non-JSON body") from exc
    if not isinstance(payload, dict):
        raise DsarFulfillmentError(
            "Microsoft Graph returned an unexpected shape")
    return payload


def collect_graph_sources(
    request_id: str,
    *,
    actor: str,
    expected_revision: int,
    fetcher: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Slim Microsoft 365 collection: COUNT the subject's footprint, move no
    content.

    Probes the subject's Outlook mailbox (``GET /users/{upn}/messages``,
    application permission ``Mail.ReadBasic.All``) and OneDrive root
    (``GET /users/{upn}/drive/root/children``, ``Files.Read.All``) with
    ``$select=id`` — ids only, one bounded page each — and logs each probe
    through :func:`record_collection_source`. Message bodies and file
    bytes never transit; a fuller export stays the operator's export
    pipeline. The token comes from the data map's configured token variable
    (by default ``$MAVERICK_GRAPH_TOKEN``), else the sealed
    ``[data_map] graph_token`` saved on All settings; tests inject ``fetcher``.
    """

    _require_enabled()
    operator = _text(actor, "actor", 256)
    dsar = _dsar_record_or_raise(_text(request_id, "request_id", 64))
    subject = str(dsar.get("subject_id") or "").strip()
    if not _UPN_RE.fullmatch(subject):
        raise ValueError(
            "the DSAR subject is not a Microsoft 365 userPrincipalName; "
            "collect this subject's data through the export pipeline instead")
    if fetcher is None:
        from .data_map import DataMapConfigError, get_data_map_config, graph_token

        try:
            token_env = get_data_map_config()["graph_token_env"]
        except DataMapConfigError as exc:
            raise DsarFulfillmentConfigError(
                "The Microsoft 365 connection settings are unavailable. "
                "Review them in All settings before checking this request.") from exc
        token = graph_token(token_env)
        if not token:
            raise DsarFulfillmentConfigError(
                f"Graph collection needs a token in ${token_env} or the "
                "Microsoft 365 access key in All settings "
                "(Mail.ReadBasic.All + Files.Read.All)")

        def fetcher(target: str) -> dict[str, Any]:
            return _graph_page(target, token)

    from urllib.parse import quote

    upn = quote(subject)
    probes = (
        ("graph:outlook_mail",
         f"{_GRAPH_ROOT}/users/{upn}/messages"
         f"?$select=id&$top={_GRAPH_PAGE_TOP}"),
        ("graph:onedrive_files",
         f"{_GRAPH_ROOT}/users/{upn}/drive/root/children"
         f"?$select=id&$top={_GRAPH_PAGE_TOP}"),
    )
    revision = int(expected_revision)
    record: dict[str, Any] | None = None
    results: list[dict[str, Any]] = []
    for source, url in probes:
        try:
            page = fetcher(url)
        except DsarFulfillmentError as exc:
            # A subject without a mailbox/drive is a finding, not a crash;
            # the probe's absence is visible because no source row appears.
            results.append(
                {"source": source, "collected": False, "error": str(exc)})
            continue
        rows = page.get("value")
        if not isinstance(rows, list):
            raise DsarFulfillmentError(
                "Microsoft Graph returned an unexpected shape")
        more = bool(page.get("@odata.nextLink"))
        reference = f"{subject} (first page{', more exist' if more else ''})"
        record = record_collection_source(
            _fulfillment_id(dsar["id"]), source=source, reference=reference,
            items=len(rows), actor=operator, expected_revision=revision)
        revision = int(record["revision"])
        results.append(
            {"source": source, "collected": True, "items": len(rows),
             "more": more})
    return {"record": record, "probes": results}


def get_fulfillment(request_id: str) -> dict[str, Any] | None:
    _require_enabled()
    record = _STORE.get(_fulfillment_id(_text(request_id, "request_id", 64)))
    if record is None:
        return None
    safe = dict(record)
    response = safe.get("response")
    if isinstance(response, dict):
        safe["response"] = {
            key: value for key, value in response.items()
            if key != "token_sha256"
        }
    return safe


__all__ = [
    "IDENTITY_METHODS",
    "RESPONSE_REDACTION_CATEGORIES",
    "SCHEMA",
    "DsarFulfillmentConfigError",
    "DsarFulfillmentError",
    "collect_graph_sources",
    "enabled",
    "get_dsar_fulfillment_config",
    "get_fulfillment",
    "open_fulfillment",
    "prepare_response",
    "record_collection_source",
    "record_identity_verification",
    "response_for_token",
]
