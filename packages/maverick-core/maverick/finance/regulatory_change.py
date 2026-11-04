"""Deterministic regulatory-change ingestion with provenance and review state.

The engine deliberately does not interpret law.  It normalizes bounded official
feeds, versions records by content, matches explicit enabled scopes, and creates
a cited review item.  Applicability and legal effect remain human decisions.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import closing
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse

from ..privacy_ops import RecordConflict, _actor_label

MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_FEED_ITEMS = 5_000
MAX_FEED_PAGES = 100
MAX_POLL_BYTES = 50 * 1024 * 1024
MAX_POLL_ITEMS = 100_000
MAX_TITLE_CHARS = 2_000
MAX_SUMMARY_CHARS = 100_000
MAX_XML_NODES = 100_000
MAX_XML_DEPTH = 128
MAX_JSON_NODES = 200_000
MAX_JSON_DEPTH = 128
MAX_SCOPE_RECONCILE_BATCH = 1_000
DEFAULT_SCOPE_RECONCILE_BATCH = 500
_VALID_FORMATS = frozenset({"federal_register_json", "json", "rss", "atom"})
_VALID_SCOPE_KINDS = frozenset({"regime", "domain"})
_VALID_ACQUISITIONS = frozenset(
    {"network_retrieved", "operator_supplied", "pack_generated"}
)
_VALID_ALERT_STATUSES = frozenset(
    {"open", "in_review", "accepted", "dismissed", "inactive"}
)
_HUMAN_ALERT_STATUSES = frozenset({"in_review", "accepted", "dismissed"})
_WORD_CLEAN = re.compile(r"[^a-z0-9]+")
_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SOURCE_RECORD_SHA256 = "_source_record_sha256"
_SOURCE_RECORD_SNAPSHOT = "_source_record_snapshot"
_ALERT_PAGE_SCHEMA = "lightwork.regulatory-alert-page.v1"
_MAX_ALERT_LIST = 5_000
_MAX_ALERT_CURSOR = 512
PARSER_VERSION = "regulatory-feed-parser-v1"


class FeedParseError(ValueError):
    """A feed is unsafe, oversized, or cannot be normalized."""


class FeedFetchError(RuntimeError):
    """An official feed could not be retrieved through the guarded transport."""


@dataclass(frozen=True)
class ScopeRule:
    """Deterministic phrases that route a record to an enabled scope."""

    key: str
    kind: str
    terms: tuple[str, ...]

    def __post_init__(self) -> None:
        key = self.key.strip().lower()
        kind = self.kind.strip().lower()
        terms = tuple(str(term).strip().lower() for term in self.terms)
        if not _KEY.fullmatch(key):
            raise ValueError("scope key is invalid")
        if kind not in _VALID_SCOPE_KINDS:
            raise ValueError("scope kind must be 'regime' or 'domain'")
        if not terms or any(not term for term in terms):
            raise ValueError("scope terms must be non-empty")
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "terms", terms)


DEFAULT_SCOPE_RULES: tuple[ScopeRule, ...] = (
    ScopeRule("sox", "regime", ("sarbanes oxley", "sarbanes-oxley", "section 404")),
    ScopeRule(
        "coso",
        "regime",
        ("committee of sponsoring organizations", "coso framework", "coso"),
    ),
    ScopeRule(
        "gaap",
        "regime",
        ("generally accepted accounting principles", "us gaap", "gaap"),
    ),
    ScopeRule(
        "glba",
        "regime",
        ("gramm leach bliley", "gramm-leach-bliley", "glba"),
    ),
    ScopeRule(
        "aml",
        "regime",
        (
            "anti money laundering",
            "anti-money laundering",
            "bank secrecy act",
            "financial crimes enforcement network",
            "fincen",
        ),
    ),
    ScopeRule(
        "sec",
        "regime",
        ("securities and exchange commission", "sec rule", "sec release"),
    ),
    ScopeRule("irs", "regime", ("internal revenue service", "irs rule", "irs notice")),
    ScopeRule("dora", "regime", ("digital operational resilience act", "dora")),
    ScopeRule("basel_iii", "regime", ("basel iii", "basel 3", "basel framework")),
    ScopeRule("ifrs_17", "regime", ("ifrs 17", "insurance contracts")),
    ScopeRule("pci", "regime", ("pci dss", "payment card industry data security")),
    ScopeRule("money_transmitter", "domain", ("money transmitter", "money transmission")),
    ScopeRule("insurance_producer", "domain", ("insurance producer", "producer licensing")),
    ScopeRule("lending", "domain", ("consumer lending", "commercial lending", "lender license")),
    ScopeRule("finance", "domain", ("financial institution", "financial services")),
)


@dataclass(frozen=True)
class FeedSource:
    """An operator-configured official regulatory feed."""

    key: str
    name: str
    jurisdiction: str
    url: str
    format: str
    default_regimes: tuple[str, ...] = ()
    default_domains: tuple[str, ...] = ()
    field_map: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        key = self.key.strip().lower()
        name = self.name.strip()
        jurisdiction = self.jurisdiction.strip().upper()
        url = self.url.strip()
        feed_format = self.format.strip().lower()
        if not _KEY.fullmatch(key) or not name or not jurisdiction:
            raise ValueError("feed key, name, and jurisdiction are required")
        if not url.startswith("https://"):
            raise ValueError("official feed URL must use https")
        if feed_format not in _VALID_FORMATS:
            raise ValueError(f"unsupported feed format: {feed_format}")
        regimes = tuple(sorted({str(k).strip().lower() for k in self.default_regimes
                                if str(k).strip()}))
        domains = tuple(sorted({str(k).strip().lower() for k in self.default_domains
                                if str(k).strip()}))
        field_map = {str(k).strip(): str(v).strip() for k, v in self.field_map.items()}
        if any(not k or not v for k, v in field_map.items()):
            raise ValueError("feed field-map keys and paths must be non-empty")
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "jurisdiction", jurisdiction)
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "format", feed_format)
        object.__setattr__(self, "default_regimes", regimes)
        object.__setattr__(self, "default_domains", domains)
        object.__setattr__(self, "field_map", MappingProxyType(field_map))

    @classmethod
    def federal_register(cls) -> FeedSource:
        """Canonical Federal Register API v1 document source."""
        return cls(
            key="federal-register",
            name="Federal Register API",
            jurisdiction="US",
            url="https://www.federalregister.gov/api/v1/documents.json",
            format="federal_register_json",
        )

    @classmethod
    def texas_register(cls) -> FeedSource:
        """Official Texas Register current-issue RSS source.

        The state feed is issue-level rather than notice-level.  Opting in
        therefore routes each published issue to the finance review queue so a
        human can inspect the cited issue without the engine guessing legal
        applicability.
        """
        return cls(
            key="texas-register",
            name="Texas Register RSS",
            jurisdiction="US-TX",
            url="https://www.sos.state.tx.us/texreg/texreg.xml",
            format="rss",
            default_domains=("finance",),
        )

    @classmethod
    def eur_lex_legislation(cls) -> FeedSource:
        """EUR-Lex predefined RSS: all Parliament and Council legislation.

        One of EUR-Lex's official predefined feeds (rssId=162, verified
        2026-08-25). Cross-domain by nature -- new EU regulations and
        directives across every field -- so no default domain is claimed;
        operators route what matters via scope rules and impact mappings.
        """
        return cls(
            key="eur-lex-legislation",
            name="EUR-Lex Parliament and Council legislation",
            jurisdiction="EU",
            url="https://eur-lex.europa.eu/EN/display-feed.rss?rssId=162",
            format="rss",
        )

    @classmethod
    def edpb_news(cls) -> FeedSource:
        """European Data Protection Board news RSS (verified 2026-08-25).

        The EDPB publishes guidance, opinions, and binding decisions on
        GDPR application -- the upstream that most often obsoletes privacy
        evidence. Issue-level, human-review routed, like the state feeds.
        """
        return cls(
            key="edpb-news",
            name="EDPB news",
            jurisdiction="EU",
            url="https://www.edpb.europa.eu/feed/news_en",
            format="rss",
            default_domains=("privacy",),
        )


@dataclass(frozen=True)
class RegulatoryCitation:
    source_name: str
    feed_url: str
    retrieval_url: str
    url: str
    retrieved_at: str
    content_sha256: str
    payload_sha256: str
    source_record_sha256: str
    source_format: str
    parser_version: str
    acquisition: str
    acquired_by: str
    official_citation: str | None = None


@dataclass(frozen=True)
class NormalizedDocument:
    source_key: str
    source_name: str
    feed_url: str
    external_id: str
    jurisdiction: str
    title: str
    summary: str
    published_at: str | None
    effective_at: str | None
    record_url: str
    official_citation: str | None
    agencies: tuple[str, ...]
    tags: tuple[str, ...]
    declared_regimes: tuple[str, ...]
    declared_domains: tuple[str, ...]
    source_format: str
    parser_version: str
    source_record_sha256: str
    source_record_snapshot: str
    content_sha256: str
    citations: tuple[RegulatoryCitation, ...]


@dataclass(frozen=True)
class DocumentVersion:
    source_key: str
    external_id: str
    version: int
    content_sha256: str
    document: NormalizedDocument
    ingested_at: str


@dataclass(frozen=True)
class RegulatoryAlert:
    alert_id: str
    source_key: str
    external_id: str
    document_version: int
    content_sha256: str
    title: str
    jurisdiction: str
    record_url: str
    official_citation: str | None
    change_kind: str
    diff: dict[str, dict[str, Any]]
    matched_regimes: tuple[str, ...]
    matched_domains: tuple[str, ...]
    citations: tuple[RegulatoryCitation, ...]
    status: str
    revision: int
    created_at: str
    reviewer: str | None = None
    review_note: str | None = None
    reviewed_at: str | None = None


@dataclass(frozen=True)
class AlertReviewEvent:
    event_id: int
    alert_id: str
    from_status: str
    to_status: str
    reviewer: str
    note: str
    reviewed_at: str


@dataclass(frozen=True)
class RegulatoryAlertPage:
    """One stable, cursor-traversable page from the regulatory review queue."""

    alerts: tuple[RegulatoryAlert, ...]
    next_cursor: str
    has_more: bool
    schema: str = _ALERT_PAGE_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "alerts": [asdict(alert) for alert in self.alerts],
            "next_cursor": self.next_cursor,
            "has_more": self.has_more,
            "order": "created_at_desc_alert_id_desc",
        }


@dataclass(frozen=True)
class IngestResult:
    source_key: str
    items_seen: int
    versions_created: int
    alerts_created: int
    unchanged: int
    unmatched: int
    alert_ids: tuple[str, ...]


@dataclass(frozen=True)
class ScopeReconcileResult:
    documents_seen: int
    alerts_created: int
    alerts_updated: int
    alert_ids: tuple[str, ...]
    complete: bool
    cursor: int


def fetch_feed(source: FeedSource, *, timeout: float = 20.0) -> bytes:
    """Fetch one official HTTPS feed through Lightwork's shared SSRF guard.

    Redirect targets are revalidated and DNS is pinned by ``guarded_urlopen``.
    The response is read with a hard byte ceiling before it reaches a parser.
    Callers may inject a transport into :func:`fetch_and_ingest` for offline
    tests and air-gapped deployments.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be a number")
    bounded_timeout = float(timeout)
    if not 1.0 <= bounded_timeout <= 120.0:
        raise ValueError("timeout must be between 1 and 120 seconds")
    try:
        from urllib.request import Request

        from ..tools.http_fetch import guarded_urlopen

        request = Request(
            source.url,
            headers={
                "Accept": "application/json, application/atom+xml, application/rss+xml, text/xml",
                "User-Agent": "Lightwork-Regulatory-Monitor/1.0",
            },
            method="GET",
        )
        with guarded_urlopen(request, timeout=bounded_timeout) as response:
            raw_length = response.headers.get("Content-Length")
            if raw_length:
                try:
                    declared = int(raw_length)
                except ValueError as exc:
                    raise FeedFetchError("feed returned an invalid Content-Length") from exc
                if declared > MAX_FEED_BYTES:
                    raise FeedFetchError("feed response exceeds the 5 MiB limit")
            payload = response.read(MAX_FEED_BYTES + 1)
    except FeedFetchError:
        raise
    except Exception as exc:
        raise FeedFetchError(
            f"official feed retrieval failed safely ({type(exc).__name__})"
        ) from exc
    if len(payload) > MAX_FEED_BYTES:
        raise FeedFetchError("feed response exceeds the 5 MiB limit")
    if not payload:
        raise FeedFetchError("feed returned an empty response")
    return payload


def fetch_and_ingest(
    engine: RegulatoryChangeEngine,
    source: FeedSource,
    *,
    enabled_regimes: Iterable[str] = (),
    enabled_domains: Iterable[str] = (),
    fetched_at: str | None = None,
    timeout: float = 20.0,
    transport: Callable[[FeedSource], bytes | str] | None = None,
) -> IngestResult:
    """Retrieve and deterministically ingest one configured official source.

    Federal Register collection responses are followed through their explicit
    ``next_page_url`` chain.  The chain is same-host, cycle-checked, and bounded
    by both page count and cumulative bytes so monitoring does not silently
    stop at page one or accept an unbounded publisher response.
    """
    retrieved_at = fetched_at or _now()
    current = source
    origin_host = (urlparse(source.url).hostname or "").casefold()
    seen_urls: set[str] = set()
    total_bytes = 0
    pages: list[tuple[bytes, str]] = []
    for _page_number in range(1, MAX_FEED_PAGES + 1):
        if current.url in seen_urls:
            raise FeedFetchError("official feed pagination contains a cycle")
        seen_urls.add(current.url)
        payload = (
            fetch_feed(current, timeout=timeout)
            if transport is None
            else transport(current)
        )
        raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        if not raw:
            raise FeedFetchError("official feed returned an empty response")
        if len(raw) > MAX_FEED_BYTES:
            raise FeedFetchError("feed response exceeds the 5 MiB limit")
        total_bytes += len(raw)
        if total_bytes > MAX_POLL_BYTES:
            raise FeedFetchError("official feed poll exceeds the 50 MiB cumulative limit")
        pages.append((raw, current.url))

        next_url: object = None
        if source.format == "federal_register_json":
            body = _load_feed_json(raw, "Federal Register")
            if isinstance(body, Mapping):
                next_url = body.get("next_page_url")
        if next_url in (None, ""):
            break
        if not isinstance(next_url, str) or len(next_url) > 4_000:
            raise FeedFetchError("official feed returned an invalid next_page_url")
        parsed = urlparse(next_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname.casefold() != origin_host
        ):
            raise FeedFetchError("official feed next_page_url must remain on the source host")
        current = replace(source, url=next_url)
    else:
        raise FeedFetchError(f"official feed exceeds the {MAX_FEED_PAGES}-page limit")

    # Network I/O and every page/parser validation complete before the single
    # promotion transaction. A failed second page cannot leak first-page alerts.
    return engine.ingest_pages(
        source,
        pages,
        enabled_regimes=enabled_regimes,
        enabled_domains=enabled_domains,
        fetched_at=retrieved_at,
        acquisition="network_retrieved",
        acquired_by="system:finance-regulatory-scheduler",
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _reject_json_constant(value: str) -> None:
    raise FeedParseError(f"JSON feed contains non-finite number {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FeedParseError(f"JSON feed contains duplicate object key {key!r}")
        result[key] = value
    return result


def _validate_json_shape(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise FeedParseError(f"JSON feed exceeds {MAX_JSON_NODES} nodes")
        if depth > MAX_JSON_DEPTH:
            raise FeedParseError(f"JSON feed exceeds depth {MAX_JSON_DEPTH}")
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _load_feed_json(payload: bytes | str, label: str) -> Any:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except FeedParseError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FeedParseError(f"invalid {label} JSON") from exc
    _validate_json_shape(value)
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _encode_alert_cursor(*, created_at: str, alert_id: str) -> str:
    payload = _json({"alert_id": alert_id, "created_at": created_at, "v": 1}).encode()
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_alert_cursor(cursor: str | None) -> tuple[str, str] | None:
    if cursor in (None, ""):
        return None
    if not isinstance(cursor, str) or len(cursor) > _MAX_ALERT_CURSOR:
        raise ValueError("regulatory alert cursor is invalid")
    try:
        padding = "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(cursor + padding, altchars=b"-_", validate=True)
        value = json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("regulatory alert cursor is invalid") from exc
    if not isinstance(value, dict) or set(value) != {"alert_id", "created_at", "v"}:
        raise ValueError("regulatory alert cursor is invalid")
    created_at = value.get("created_at")
    alert_id = value.get("alert_id")
    if (
        value.get("v") != 1
        or not isinstance(created_at, str)
        or not created_at
        or len(created_at) > 64
        or not isinstance(alert_id, str)
        or not alert_id
        or len(alert_id) > 128
    ):
        raise ValueError("regulatory alert cursor is invalid")
    return created_at, alert_id


def _json_record_snapshot(item: Mapping[str, Any]) -> str:
    """Retain every publisher field in one item as bounded canonical JSON."""
    return _json(item)


def _xml_record_snapshot(element: ET.Element) -> str:
    """Retain one complete XML item after deterministic canonicalization."""
    serialized = ET.tostring(element, encoding="unicode")
    return ET.canonicalize(serialized)


def _clean_text(value: Any, *, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        text = "; ".join(_clean_text(item, limit=limit) for item in value)
    elif isinstance(value, dict):
        text = _json(value)
    else:
        text = str(value)
    return " ".join(text.split())[:limit]


def _normalize_when(value: Any) -> str | None:
    text = _clean_text(value, limit=200)
    if not text:
        return None
    try:
        if "," in text:
            parsed = parsedate_to_datetime(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if text.endswith("Z"):
            datetime.fromisoformat(text[:-1] + "+00:00")
        else:
            datetime.fromisoformat(text)
    except ValueError:
        # Publication labels in government feeds are occasionally not ISO dates.
        # Preserve the source text; never infer a date that was not supplied.
        return text
    return text


def _https_url(value: Any, fallback: str) -> str:
    text = _clean_text(value, limit=4_000)
    if text.startswith("https://"):
        return text
    try:
        parsed = urlparse(text)
        fallback_host = (urlparse(fallback).hostname or "").casefold()
    except ValueError:
        return fallback
    if (
        parsed.scheme == "http"
        and fallback_host
        and parsed.netloc.casefold() == fallback_host
    ):
        # Some official register feeds still publish same-host HTTP item links
        # even though the issuing host serves them over HTTPS.  Upgrade only
        # that narrow case; never manufacture an HTTPS URL for another host.
        return "https://" + text.removeprefix("http://")
    return fallback


def _jurisdiction(value: Any, fallback: str) -> str:
    text = _clean_text(value, limit=32).upper()
    if not text:
        return fallback
    if re.fullmatch(r"[A-Z0-9][A-Z0-9-]{1,31}", text) is None:
        raise FeedParseError("feed item jurisdiction is invalid")
    return text


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _xml_child_text(element: ET.Element, *names: str) -> str:
    wanted = {name.lower() for name in names}
    for child in list(element):
        if _local_name(child.tag) in wanted:
            return " ".join("".join(child.itertext()).split())
    return ""


def _parse_xml(payload: bytes, source: FeedSource) -> list[dict[str, Any]]:
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise FeedParseError("XML DTD and entity declarations are not allowed")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise FeedParseError("invalid XML feed") from exc
    nodes = 0
    stack: list[tuple[ET.Element, int]] = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        nodes += 1
        if nodes > MAX_XML_NODES:
            raise FeedParseError(f"XML feed exceeds {MAX_XML_NODES} nodes")
        if depth > MAX_XML_DEPTH:
            raise FeedParseError(f"XML feed exceeds depth {MAX_XML_DEPTH}")
        stack.extend((child, depth + 1) for child in list(element))
    records: list[dict[str, Any]] = []
    for element in root.iter():
        local = _local_name(element.tag)
        if local not in {"item", "entry"}:
            continue
        link = ""
        categories: list[str] = []
        for child in list(element):
            child_name = _local_name(child.tag)
            if child_name == "link" and not link:
                link = child.attrib.get("href", "") or _xml_child_text(element, "link")
            elif child_name == "category":
                category = child.attrib.get("term", "") or "".join(child.itertext())
                if category.strip():
                    categories.append(category.strip())
        source_snapshot = _xml_record_snapshot(element)
        records.append({
            "id": _xml_child_text(element, "guid", "id"),
            "title": _xml_child_text(element, "title"),
            "summary": _xml_child_text(element, "description", "summary", "content"),
            "published_at": _xml_child_text(element, "pubDate", "published", "updated"),
            "effective_at": _xml_child_text(element, "effective", "effectiveDate"),
            "url": link,
            "citation": _xml_child_text(element, "citation"),
            "tags": categories,
            _SOURCE_RECORD_SHA256: _sha256(source_snapshot.encode("utf-8")),
            _SOURCE_RECORD_SNAPSHOT: source_snapshot,
        })
        if len(records) > MAX_FEED_ITEMS:
            raise FeedParseError(f"feed exceeds {MAX_FEED_ITEMS} items")
    return records


def _dig(value: Any, dotted_path: str, default: Any = None) -> Any:
    current = value
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current


def _parse_json(payload: bytes, source: FeedSource) -> list[dict[str, Any]]:
    body = _load_feed_json(payload, "feed")
    mapping = {
        "items": "items", "id": "id", "title": "title", "summary": "summary",
        "published_at": "published_at", "effective_at": "effective_at", "url": "url",
        "citation": "citation", "tags": "tags", "agencies": "agencies",
        "regimes": "regimes", "domains": "domains", "jurisdiction": "jurisdiction",
    }
    mapping.update({str(k): str(v) for k, v in source.field_map.items()})
    if isinstance(body, list):
        items = body
    else:
        items = _dig(body, mapping["items"])
        if items is None and not source.field_map.get("items") and isinstance(body, Mapping):
            items = body.get("results", body.get("documents"))
    if not isinstance(items, list):
        raise FeedParseError("JSON feed items must be a list")
    if len(items) > MAX_FEED_ITEMS:
        raise FeedParseError(f"feed exceeds {MAX_FEED_ITEMS} items")
    records: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise FeedParseError("JSON feed item must be an object")
        record = {name: _dig(item, path) for name, path in mapping.items() if name != "items"}
        source_snapshot = _json_record_snapshot(item)
        record[_SOURCE_RECORD_SHA256] = _sha256(source_snapshot.encode("utf-8"))
        record[_SOURCE_RECORD_SNAPSHOT] = source_snapshot
        records.append(record)
    return records


def _parse_federal_register(payload: bytes) -> list[dict[str, Any]]:
    body = _load_feed_json(payload, "Federal Register")
    items = body.get("results") if isinstance(body, Mapping) else None
    if not isinstance(items, list):
        raise FeedParseError("Federal Register results must be a list")
    if len(items) > MAX_FEED_ITEMS:
        raise FeedParseError(f"feed exceeds {MAX_FEED_ITEMS} items")
    records: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise FeedParseError("Federal Register item must be an object")
        agencies = item.get("agencies") or []
        agency_names = [a.get("name", "") if isinstance(a, Mapping) else str(a) for a in agencies]
        source_snapshot = _json_record_snapshot(item)
        records.append({
            "id": item.get("document_number"),
            "title": item.get("title"),
            "summary": item.get("abstract"),
            "published_at": item.get("publication_date"),
            "effective_at": item.get("effective_on"),
            "url": item.get("html_url") or item.get("pdf_url"),
            "citation": item.get("citation"),
            "tags": item.get("topics") or [],
            "agencies": agency_names,
            "regimes": [],
            "domains": [],
            _SOURCE_RECORD_SHA256: _sha256(source_snapshot.encode("utf-8")),
            _SOURCE_RECORD_SNAPSHOT: source_snapshot,
        })
    return records


def _tuple_text(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    values = value if isinstance(value, (list, tuple, set)) else (value,)
    cleaned = {_clean_text(item, limit=500) for item in values}
    return tuple(sorted(item for item in cleaned if item))


def _canonical_fields(document: NormalizedDocument) -> dict[str, Any]:
    return {
        "source_key": document.source_key,
        "source_name": document.source_name,
        "feed_url": document.feed_url,
        "external_id": document.external_id,
        "jurisdiction": document.jurisdiction,
        "title": document.title,
        "summary": document.summary,
        "published_at": document.published_at,
        "effective_at": document.effective_at,
        "record_url": document.record_url,
        "official_citation": document.official_citation,
        "agencies": list(document.agencies),
        "tags": list(document.tags),
        "declared_regimes": list(document.declared_regimes),
        "declared_domains": list(document.declared_domains),
        "source_format": document.source_format,
        "parser_version": document.parser_version,
        "source_record_sha256": document.source_record_sha256,
    }


def _normalize_records(
    records: Iterable[Mapping[str, Any]], source: FeedSource, *, payload_sha256: str,
    fetched_at: str, retrieval_url: str, acquisition: str, acquired_by: str,
) -> list[NormalizedDocument]:
    documents: list[NormalizedDocument] = []
    snapshot_bytes = 0
    for record in records:
        source_record_sha256 = str(record.get(_SOURCE_RECORD_SHA256, ""))
        if not re.fullmatch(r"[0-9a-f]{64}", source_record_sha256):
            raise FeedParseError("feed item is missing its canonical source digest")
        source_record_snapshot = str(record.get(_SOURCE_RECORD_SNAPSHOT, ""))
        if not source_record_snapshot:
            raise FeedParseError("feed item is missing its canonical source snapshot")
        snapshot_bytes += len(source_record_snapshot.encode("utf-8"))
        if snapshot_bytes > MAX_FEED_BYTES:
            raise FeedParseError("canonical feed records exceed the 5 MiB page limit")
        title = _clean_text(record.get("title"), limit=MAX_TITLE_CHARS) or "Untitled notice"
        summary = _clean_text(record.get("summary"), limit=MAX_SUMMARY_CHARS)
        record_url = _https_url(record.get("url"), source.url)
        published_at = _normalize_when(record.get("published_at"))
        external_id = _clean_text(record.get("id"), limit=1_000)
        if not external_id:
            seed = _json([source.key, record_url, title, published_at]).encode()
            external_id = "generated-" + _sha256(seed)[:32]
        placeholder = NormalizedDocument(
            source_key=source.key,
            source_name=source.name,
            feed_url=source.url,
            external_id=external_id,
            jurisdiction=_jurisdiction(record.get("jurisdiction"), source.jurisdiction),
            title=title,
            summary=summary,
            published_at=published_at,
            effective_at=_normalize_when(record.get("effective_at")),
            record_url=record_url,
            official_citation=_clean_text(record.get("citation"), limit=1_000) or None,
            agencies=_tuple_text(record.get("agencies")),
            tags=_tuple_text(record.get("tags")),
            declared_regimes=tuple(sorted(set(source.default_regimes) |
                                          set(_tuple_text(record.get("regimes"))))),
            declared_domains=tuple(sorted(set(source.default_domains) |
                                          set(_tuple_text(record.get("domains"))))),
            source_format=source.format,
            parser_version=PARSER_VERSION,
            source_record_sha256=source_record_sha256,
            source_record_snapshot=source_record_snapshot,
            content_sha256="",
            citations=(),
        )
        content_hash = _sha256(_json(_canonical_fields(placeholder)).encode("utf-8"))
        citation = RegulatoryCitation(
            source_name=source.name,
            feed_url=source.url,
            retrieval_url=retrieval_url,
            url=record_url,
            retrieved_at=fetched_at,
            content_sha256=content_hash,
            payload_sha256=payload_sha256,
            source_record_sha256=source_record_sha256,
            source_format=source.format,
            parser_version=PARSER_VERSION,
            acquisition=acquisition,
            acquired_by=acquired_by,
            official_citation=placeholder.official_citation,
        )
        documents.append(NormalizedDocument(
            **{**asdict(placeholder), "content_sha256": content_hash,
               "citations": (citation,)},
        ))
    return documents


def parse_feed(
    payload: bytes | str,
    source: FeedSource,
    *,
    fetched_at: str | None = None,
    retrieval_url: str | None = None,
    acquisition: str = "operator_supplied",
    acquired_by: str = "system:unspecified-import",
) \
        -> list[NormalizedDocument]:
    """Normalize one bounded feed payload; performs no network request."""
    raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    if len(raw) > MAX_FEED_BYTES:
        raise FeedParseError(f"feed exceeds {MAX_FEED_BYTES} bytes")
    fetched = fetched_at or _now()
    acquisition_kind = str(acquisition or "").strip().lower()
    if acquisition_kind not in _VALID_ACQUISITIONS:
        raise FeedParseError("regulatory acquisition mode is invalid")
    actor = _actor_label(str(acquired_by or "system:unspecified-import"))
    if acquisition_kind == "network_retrieved":
        retrieved_from = source.url if retrieval_url is None else str(retrieval_url).strip()
        configured_host = (urlparse(source.url).hostname or "").casefold()
        retrieved = urlparse(retrieved_from)
        if (
            retrieved.scheme != "https"
            or not retrieved.hostname
            or retrieved.hostname.casefold() != configured_host
        ):
            raise FeedParseError("retrieval_url must be same-host HTTPS provenance")
    elif acquisition_kind == "pack_generated":
        retrieved_from = "urn:lightwork:regulatory-acquisition:pack-generated"
    else:
        retrieved_from = "urn:lightwork:regulatory-acquisition:operator-supplied"
    if source.format == "federal_register_json":
        records = _parse_federal_register(raw)
    elif source.format == "json":
        records = _parse_json(raw, source)
    else:
        records = _parse_xml(raw, source)
    return _normalize_records(
        records,
        source,
        payload_sha256=_sha256(raw),
        fetched_at=fetched,
        retrieval_url=retrieved_from,
        acquisition=acquisition_kind,
        acquired_by=actor,
    )


def _normalized_words(value: str) -> str:
    return " " + _WORD_CLEAN.sub(" ", value.lower()).strip() + " "


def _term_present(term: str, haystack: str) -> bool:
    needle = _normalized_words(term)
    return needle.strip() != "" and needle in haystack


def match_scopes(
    document: NormalizedDocument, *, enabled_regimes: Iterable[str] = (),
    enabled_domains: Iterable[str] = (), rules: Sequence[ScopeRule] = DEFAULT_SCOPE_RULES,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return enabled regime/domain keys matched by declaration or bounded phrase."""
    regimes = {str(k).strip().lower() for k in enabled_regimes if str(k).strip()}
    domains = {str(k).strip().lower() for k in enabled_domains if str(k).strip()}
    matched_regimes = regimes & {k.lower() for k in document.declared_regimes}
    matched_domains = domains & {k.lower() for k in document.declared_domains}
    text = _normalized_words(" ".join((
        document.title, document.summary, document.official_citation or "",
        *document.agencies, *document.tags,
    )))
    for rule in rules:
        key = rule.key.lower()
        enabled = regimes if rule.kind == "regime" else domains
        if key in enabled and any(_term_present(term, text) for term in rule.terms):
            (matched_regimes if rule.kind == "regime" else matched_domains).add(key)
    return tuple(sorted(matched_regimes)), tuple(sorted(matched_domains))


def _citation_from_dict(raw: Mapping[str, Any]) -> RegulatoryCitation:
    values = dict(raw)
    # Older rows predate per-item source digests. Keep them readable while
    # making the absence explicit instead of mislabelling a normalized digest.
    values.setdefault("source_record_sha256", "")
    values.setdefault("retrieval_url", str(values.get("feed_url") or ""))
    values.setdefault("source_format", "legacy")
    values.setdefault("parser_version", "legacy")
    values.setdefault("acquisition", "legacy")
    values.setdefault("acquired_by", "unknown")
    return RegulatoryCitation(**values)


def _document_from_dict(raw: Mapping[str, Any]) -> NormalizedDocument:
    citations = tuple(_citation_from_dict(c) for c in raw.get("citations", ()))
    return NormalizedDocument(
        source_key=str(raw["source_key"]), source_name=str(raw["source_name"]),
        feed_url=str(raw["feed_url"]), external_id=str(raw["external_id"]),
        jurisdiction=str(raw["jurisdiction"]), title=str(raw["title"]),
        summary=str(raw["summary"]), published_at=raw.get("published_at"),
        effective_at=raw.get("effective_at"), record_url=str(raw["record_url"]),
        official_citation=raw.get("official_citation"),
        agencies=tuple(raw.get("agencies", ())), tags=tuple(raw.get("tags", ())),
        declared_regimes=tuple(raw.get("declared_regimes", ())),
        declared_domains=tuple(raw.get("declared_domains", ())),
        source_format=str(raw.get("source_format", "legacy")),
        parser_version=str(raw.get("parser_version", "legacy")),
        source_record_sha256=str(raw.get("source_record_sha256", "")),
        source_record_snapshot=str(raw.get("source_record_snapshot", "")),
        content_sha256=str(raw["content_sha256"]), citations=citations,
    )


def _json_changed_paths(
    before_snapshot: str,
    after_snapshot: str,
    *,
    limit: int = 100,
) -> tuple[list[str], bool, bool]:
    try:
        before = json.loads(before_snapshot)
        after = json.loads(after_snapshot)
    except (TypeError, json.JSONDecodeError):
        return [], False, False
    paths: list[str] = []
    truncated = False
    stack: list[tuple[str, Any, Any]] = [("", before, after)]
    while stack:
        path, left, right = stack.pop()
        if left == right:
            continue
        if len(paths) >= limit:
            truncated = True
            break
        if isinstance(left, Mapping) and isinstance(right, Mapping):
            for key in sorted(set(left) | set(right), reverse=True):
                escaped = str(key).replace("~", "~0").replace("/", "~1")
                stack.append((f"{path}/{escaped}", left.get(key), right.get(key)))
            continue
        if isinstance(left, list) and isinstance(right, list):
            for index in range(max(len(left), len(right)) - 1, -1, -1):
                old = left[index] if index < len(left) else None
                new = right[index] if index < len(right) else None
                stack.append((f"{path}/{index}", old, new))
            continue
        paths.append(path or "/")
    return paths, truncated, True


def _diff(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    before_snapshot: str = "",
    after_snapshot: str = "",
) -> dict[str, dict[str, Any]]:
    # The source digest participates in version identity and provenance. When
    # normalization hides the changed publisher field, retain a bounded path
    # marker instead of presenting an empty update to the reviewer.
    ignored = {"source_key", "external_id", "source_record_sha256"}
    changes = {
        key: {"before": before.get(key), "after": after.get(key)}
        for key in sorted(set(before) | set(after))
        if key not in ignored and before.get(key) != after.get(key)
    }
    before_digest = str(before.get("source_record_sha256") or "")
    after_digest = str(after.get("source_record_sha256") or "")
    if not changes and before_digest != after_digest:
        paths, truncated, paths_available = _json_changed_paths(
            before_snapshot,
            after_snapshot,
        )
        changes["_publisher_record"] = {
            "before": {"sha256": before_digest},
            "after": {"sha256": after_digest},
            "changed_paths": paths,
            "paths_available": paths_available,
            "paths_truncated": truncated,
            "canonical_snapshots_retained": True,
        }
    return changes


class RegulatoryChangeEngine:
    """SQLite-backed version register and human review queue."""

    def __init__(
        self, path: str | Path, *, scope_rules: Sequence[ScopeRule] = DEFAULT_SCOPE_RULES,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.scope_rules = tuple(scope_rules)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def _initialize(self) -> None:
        with closing(self._connect()) as conn, conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS regulatory_documents (
                    source_key TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK(version > 0),
                    content_sha256 TEXT NOT NULL,
                    canonical_json TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    PRIMARY KEY (source_key, external_id, version)
                );
                CREATE INDEX IF NOT EXISTS regulatory_documents_latest
                    ON regulatory_documents(source_key, external_id, version DESC);
                CREATE TABLE IF NOT EXISTS regulatory_source_releases (
                    source_key TEXT NOT NULL,
                    release_version TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    PRIMARY KEY (source_key, release_version)
                );
                CREATE TABLE IF NOT EXISTS regulatory_alerts (
                    alert_id TEXT PRIMARY KEY,
                    source_key TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    document_version INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    title TEXT NOT NULL,
                    jurisdiction TEXT NOT NULL,
                    record_url TEXT NOT NULL,
                    official_citation TEXT,
                    change_kind TEXT NOT NULL,
                    diff_json TEXT NOT NULL,
                    matched_regimes_json TEXT NOT NULL,
                    matched_domains_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
                    created_at TEXT NOT NULL,
                    reviewer TEXT,
                    review_note TEXT,
                    reviewed_at TEXT,
                    UNIQUE(source_key, external_id, document_version),
                    FOREIGN KEY(source_key, external_id, document_version)
                        REFERENCES regulatory_documents(source_key, external_id, version)
                );
                CREATE INDEX IF NOT EXISTS regulatory_alerts_queue
                    ON regulatory_alerts(status, created_at DESC);
                CREATE TABLE IF NOT EXISTS regulatory_alert_reviews (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    note TEXT NOT NULL,
                    reviewed_at TEXT NOT NULL,
                    FOREIGN KEY(alert_id) REFERENCES regulatory_alerts(alert_id)
                );
                CREATE INDEX IF NOT EXISTS regulatory_alert_reviews_history
                    ON regulatory_alert_reviews(alert_id, event_id ASC);
                CREATE TABLE IF NOT EXISTS regulatory_scope_reconcile_state (
                    selector TEXT PRIMARY KEY,
                    scope_fingerprint TEXT NOT NULL,
                    cursor_rowid INTEGER NOT NULL DEFAULT 0 CHECK(cursor_rowid >= 0),
                    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
                    updated_at TEXT NOT NULL
                );
            """)
            columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(regulatory_alerts)").fetchall()
            }
            if "revision" not in columns:
                conn.execute(
                    "ALTER TABLE regulatory_alerts "
                    "ADD COLUMN revision INTEGER NOT NULL DEFAULT 1"
                )

    def bind_source_release(
        self,
        source_key: str,
        release_version: str,
        content_sha256: str,
    ) -> bool:
        """Bind an immutable source release identity to exactly one digest."""
        key = str(source_key or "").strip().lower()
        version = str(release_version or "").strip()
        digest = str(content_sha256 or "").strip().lower()
        if _KEY.fullmatch(key) is None:
            raise ValueError("source release key is invalid")
        if not version or len(version) > 128:
            raise ValueError("source release version is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("source release digest is invalid")
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """SELECT content_sha256 FROM regulatory_source_releases
                   WHERE source_key = ? AND release_version = ?""",
                (key, version),
            ).fetchone()
            if existing is not None:
                if str(existing["content_sha256"]) != digest:
                    raise RecordConflict(
                        "regulatory source release version is already bound to another digest"
                    )
                return False
            conn.execute(
                """INSERT INTO regulatory_source_releases
                   (source_key, release_version, content_sha256, recorded_at)
                   VALUES (?, ?, ?, ?)""",
                (key, version, digest, _now()),
            )
        return True

    def ingest(
        self, source: FeedSource, payload: bytes | str, *,
        enabled_regimes: Iterable[str] = (), enabled_domains: Iterable[str] = (),
        fetched_at: str | None = None, retrieval_url: str | None = None,
        acquisition: str = "operator_supplied",
        acquired_by: str = "system:unspecified-import",
    ) -> IngestResult:
        """Validate and atomically promote one complete feed snapshot."""
        return self.ingest_pages(
            source,
            ((payload, retrieval_url or source.url),),
            enabled_regimes=enabled_regimes,
            enabled_domains=enabled_domains,
            fetched_at=fetched_at,
            acquisition=acquisition,
            acquired_by=acquired_by,
        )

    def ingest_pages(
        self,
        source: FeedSource,
        pages: Sequence[tuple[bytes | str, str]],
        *,
        enabled_regimes: Iterable[str] = (),
        enabled_domains: Iterable[str] = (),
        fetched_at: str | None = None,
        acquisition: str = "operator_supplied",
        acquired_by: str = "system:unspecified-import",
    ) -> IngestResult:
        """Validate a complete bounded poll, then promote it in one transaction."""
        if not pages or len(pages) > MAX_FEED_PAGES:
            raise FeedParseError(f"poll must contain 1 to {MAX_FEED_PAGES} pages")
        documents: list[NormalizedDocument] = []
        total_bytes = 0
        for payload, retrieval_url in pages:
            raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
            total_bytes += len(raw)
            if total_bytes > MAX_POLL_BYTES:
                raise FeedParseError("official feed poll exceeds the 50 MiB cumulative limit")
            documents.extend(
                parse_feed(
                    raw,
                    source,
                    fetched_at=fetched_at,
                    retrieval_url=retrieval_url,
                    acquisition=acquisition,
                    acquired_by=acquired_by,
                )
            )
            if len(documents) > MAX_POLL_ITEMS:
                raise FeedParseError(f"official feed poll exceeds {MAX_POLL_ITEMS} items")

        unique: list[NormalizedDocument] = []
        seen: dict[str, NormalizedDocument] = {}
        for document in documents:
            prior = seen.get(document.external_id)
            if prior is None:
                seen[document.external_id] = document
                unique.append(document)
                continue
            if prior.content_sha256 != document.content_sha256:
                raise FeedParseError(
                    "official feed poll contains conflicting versions of one external id"
                )
        return self._apply_documents(
            source,
            unique,
            enabled_regimes=enabled_regimes,
            enabled_domains=enabled_domains,
            fetched_at=fetched_at,
        )

    @staticmethod
    def _apply_scope_change(
        conn: sqlite3.Connection,
        existing: sqlite3.Row,
        *,
        matched_regimes: tuple[str, ...],
        matched_domains: tuple[str, ...],
    ) -> bool:
        prior_regimes = tuple(json.loads(existing["matched_regimes_json"]))
        prior_domains = tuple(json.loads(existing["matched_domains_json"]))
        if matched_regimes == prior_regimes and matched_domains == prior_domains:
            return False
        added_regimes = sorted(set(matched_regimes) - set(prior_regimes))
        added_domains = sorted(set(matched_domains) - set(prior_domains))
        removed_regimes = sorted(set(prior_regimes) - set(matched_regimes))
        removed_domains = sorted(set(prior_domains) - set(matched_domains))
        changed_at = _now()
        if not matched_regimes and not matched_domains:
            next_status = "inactive"
            reviewer = "system:scope-change"
            review_note = "No enabled scope remains."
            reviewed_at = changed_at
        elif added_regimes or added_domains:
            next_status = "open"
            reviewer = review_note = reviewed_at = None
        else:
            # Removing one scope does not invalidate an independent human
            # disposition while at least one accepted scope remains.
            next_status = str(existing["status"])
            reviewer = existing["reviewer"]
            review_note = existing["review_note"]
            reviewed_at = existing["reviewed_at"]
        cursor = conn.execute(
            """UPDATE regulatory_alerts
               SET matched_regimes_json = ?, matched_domains_json = ?,
                   status = ?, reviewer = ?, review_note = ?, reviewed_at = ?,
                   revision = revision + 1
               WHERE alert_id = ? AND revision = ?""",
            (
                _json(matched_regimes),
                _json(matched_domains),
                next_status,
                reviewer,
                review_note,
                reviewed_at,
                existing["alert_id"],
                existing["revision"],
            ),
        )
        if cursor.rowcount != 1:  # pragma: no cover - BEGIN IMMEDIATE owns writer
            raise RecordConflict("regulatory alert revision conflict")
        note = _json({
            "event": "scope_set_changed",
            "added_regimes": added_regimes,
            "added_domains": added_domains,
            "removed_regimes": removed_regimes,
            "removed_domains": removed_domains,
        })
        conn.execute(
            """INSERT INTO regulatory_alert_reviews
               (alert_id, from_status, to_status, reviewer, note, reviewed_at)
               VALUES (?, ?, ?, 'system:scope-change', ?, ?)""",
            (
                existing["alert_id"],
                existing["status"],
                next_status,
                note,
                changed_at,
            ),
        )
        return True

    @staticmethod
    def _insert_alert(
        conn: sqlite3.Connection,
        document: NormalizedDocument,
        *,
        version: int,
        previous: sqlite3.Row | None,
        before: Mapping[str, Any],
        canonical: Mapping[str, Any],
        matched_regimes: tuple[str, ...],
        matched_domains: tuple[str, ...],
        created_at: str,
        change_kind: str | None = None,
        before_snapshot: str = "",
    ) -> str:
        alert_id = _sha256(
            f"{document.source_key}\0{document.external_id}\0{version}\0"
            f"{document.content_sha256}".encode()
        )[:32]
        kind = change_kind or ("new" if previous is None else "updated")
        conn.execute(
            """INSERT INTO regulatory_alerts
               (alert_id, source_key, external_id, document_version, content_sha256,
                title, jurisdiction, record_url, official_citation, change_kind,
                diff_json, matched_regimes_json, matched_domains_json, citations_json,
                status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)""",
            (
                alert_id,
                document.source_key,
                document.external_id,
                version,
                document.content_sha256,
                document.title,
                document.jurisdiction,
                document.record_url,
                document.official_citation,
                kind,
                _json(
                    {} if previous is None else _diff(
                        before,
                        canonical,
                        before_snapshot=before_snapshot,
                        after_snapshot=document.source_record_snapshot,
                    )
                ),
                _json(matched_regimes),
                _json(matched_domains),
                _json([asdict(citation) for citation in document.citations]),
                created_at,
            ),
        )
        return alert_id

    def _apply_documents(
        self,
        source: FeedSource,
        documents: Sequence[NormalizedDocument],
        *,
        enabled_regimes: Iterable[str],
        enabled_domains: Iterable[str],
        fetched_at: str | None,
    ) -> IngestResult:
        versions_created = alerts_created = unchanged = unmatched = 0
        alert_ids: list[str] = []
        created_at = fetched_at or _now()
        active_regimes = tuple(enabled_regimes)
        active_domains = tuple(enabled_domains)
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            for document in documents:
                if document.source_key != source.key:
                    raise FeedParseError("normalized document source does not match poll source")
                previous = conn.execute(
                    """SELECT version, content_sha256, canonical_json, document_json
                       FROM regulatory_documents
                       WHERE source_key = ? AND external_id = ?
                       ORDER BY version DESC LIMIT 1""",
                    (source.key, document.external_id),
                ).fetchone()
                canonical = _canonical_fields(document)
                before_snapshot = ""
                if previous is not None and previous["content_sha256"] == document.content_sha256:
                    version = int(previous["version"])
                    before = json.loads(previous["canonical_json"])
                    before_snapshot = _document_from_dict(
                        json.loads(previous["document_json"])
                    ).source_record_snapshot
                    unchanged += 1
                else:
                    version = 1 if previous is None else int(previous["version"]) + 1
                    before = {} if previous is None else json.loads(previous["canonical_json"])
                    if previous is not None:
                        before_snapshot = _document_from_dict(
                            json.loads(previous["document_json"])
                        ).source_record_snapshot
                    conn.execute(
                        """INSERT INTO regulatory_documents
                           (source_key, external_id, version, content_sha256, canonical_json,
                            document_json, ingested_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (source.key, document.external_id, version, document.content_sha256,
                         _json(canonical), _json(asdict(document)), created_at),
                    )
                    versions_created += 1

                matched_regimes, matched_domains = match_scopes(
                    document, enabled_regimes=active_regimes,
                    enabled_domains=active_domains, rules=self.scope_rules,
                )
                existing = conn.execute(
                    """SELECT alert_id, matched_regimes_json, matched_domains_json,
                              status, revision, reviewer, review_note, reviewed_at
                       FROM regulatory_alerts
                       WHERE source_key = ? AND external_id = ? AND document_version = ?""",
                    (source.key, document.external_id, version),
                ).fetchone()
                if existing is not None:
                    self._apply_scope_change(
                        conn,
                        existing,
                        matched_regimes=tuple(matched_regimes),
                        matched_domains=tuple(matched_domains),
                    )
                    alert_ids.append(str(existing["alert_id"]))
                    if not matched_regimes and not matched_domains:
                        unmatched += 1
                    continue
                if not matched_regimes and not matched_domains:
                    unmatched += 1
                    continue
                alert_id = self._insert_alert(
                    conn,
                    document,
                    version=version,
                    previous=previous,
                    before=before,
                    canonical=canonical,
                    matched_regimes=tuple(matched_regimes),
                    matched_domains=tuple(matched_domains),
                    created_at=created_at,
                    before_snapshot=before_snapshot,
                )
                alerts_created += 1
                alert_ids.append(alert_id)
        return IngestResult(
            source_key=source.key, items_seen=len(documents),
            versions_created=versions_created, alerts_created=alerts_created,
            unchanged=unchanged, unmatched=unmatched,
            alert_ids=tuple(dict.fromkeys(alert_ids)),
        )

    def reconcile_scopes(
        self,
        *,
        enabled_regimes: Iterable[str] = (),
        enabled_domains: Iterable[str] = (),
        source_key: str | None = None,
        batch_size: int = DEFAULT_SCOPE_RECONCILE_BATCH,
    ) -> ScopeReconcileResult:
        """Apply current enabled scopes in a bounded, resumable keyset batch.

        This is independent of whether an incremental source still includes an
        older record. It therefore handles removed feed configuration and
        disabled licensing domains without treating feed absence as withdrawal.
        Existing alerts for every historical version are reconciled so stale
        queue rows cannot retain a disabled scope. New alerts are backfilled only
        for the latest version of a previously unmatched document.
        """
        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or not 1 <= batch_size <= MAX_SCOPE_RECONCILE_BATCH
        ):
            raise ValueError(
                f"scope reconcile batch_size must be between 1 and "
                f"{MAX_SCOPE_RECONCILE_BATCH}"
            )
        selected_source = None if source_key is None else str(source_key or "").strip()
        if selected_source and _KEY.fullmatch(selected_source) is None:
            raise ValueError("source_key is invalid")
        active_regimes = tuple(sorted({str(value).strip().lower() for value in enabled_regimes
                                       if str(value).strip()}))
        active_domains = tuple(sorted({str(value).strip().lower() for value in enabled_domains
                                       if str(value).strip()}))
        selector = selected_source or "*"
        scope_fingerprint = _sha256(_json({
            "selector": selector,
            "enabled_regimes": active_regimes,
            "enabled_domains": active_domains,
            "rules": [asdict(rule) for rule in self.scope_rules],
        }).encode("utf-8"))
        created = updated = 0
        alert_ids: list[str] = []
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            state = conn.execute(
                """SELECT scope_fingerprint, cursor_rowid
                   FROM regulatory_scope_reconcile_state WHERE selector = ?""",
                (selector,),
            ).fetchone()
            cursor = (
                int(state["cursor_rowid"])
                if state is not None and state["scope_fingerprint"] == scope_fingerprint
                else 0
            )
            query = """
                SELECT document.rowid AS document_rowid, document.*,
                       NOT EXISTS (
                           SELECT 1 FROM regulatory_documents AS newer
                           WHERE newer.source_key = document.source_key
                             AND newer.external_id = document.external_id
                             AND newer.version > document.version
                       ) AS is_latest
                FROM regulatory_documents AS document
                WHERE document.rowid > ?
            """
            params: list[Any] = [cursor]
            if selected_source:
                query += " AND document.source_key = ?"
                params.append(selected_source)
            query += " ORDER BY document.rowid ASC LIMIT ?"
            params.append(batch_size + 1)
            fetched = conn.execute(query, params).fetchall()
            has_more = len(fetched) > batch_size
            rows = fetched[:batch_size]
            for row in rows:
                document = _document_from_dict(json.loads(row["document_json"]))
                matched_regimes, matched_domains = match_scopes(
                    document,
                    enabled_regimes=active_regimes,
                    enabled_domains=active_domains,
                    rules=self.scope_rules,
                )
                existing = conn.execute(
                    """SELECT alert_id, matched_regimes_json, matched_domains_json,
                              status, revision, reviewer, review_note, reviewed_at
                       FROM regulatory_alerts
                       WHERE source_key = ? AND external_id = ? AND document_version = ?""",
                    (document.source_key, document.external_id, int(row["version"])),
                ).fetchone()
                if existing is not None:
                    if self._apply_scope_change(
                        conn,
                        existing,
                        matched_regimes=tuple(matched_regimes),
                        matched_domains=tuple(matched_domains),
                    ):
                        updated += 1
                    alert_ids.append(str(existing["alert_id"]))
                    continue
                if (
                    not bool(row["is_latest"])
                    or (not matched_regimes and not matched_domains)
                ):
                    continue
                previous = None
                before: Mapping[str, Any] = {}
                if int(row["version"]) > 1:
                    previous = conn.execute(
                        """SELECT version, content_sha256, canonical_json, document_json
                           FROM regulatory_documents
                           WHERE source_key = ? AND external_id = ? AND version = ?""",
                        (
                            document.source_key,
                            document.external_id,
                            int(row["version"]) - 1,
                        ),
                    ).fetchone()
                    if previous is not None:
                        before = json.loads(previous["canonical_json"])
                alert_id = self._insert_alert(
                    conn,
                    document,
                    version=int(row["version"]),
                    previous=previous,
                    before=before,
                    canonical=json.loads(row["canonical_json"]),
                    matched_regimes=tuple(matched_regimes),
                    matched_domains=tuple(matched_domains),
                    created_at=_now(),
                    change_kind="scope_enabled",
                    before_snapshot=(
                        ""
                        if previous is None
                        else _document_from_dict(
                            json.loads(previous["document_json"])
                        ).source_record_snapshot
                    ),
                )
                created += 1
                alert_ids.append(alert_id)
            next_cursor = int(rows[-1]["document_rowid"]) if rows else cursor
            conn.execute(
                """INSERT INTO regulatory_scope_reconcile_state
                   (selector, scope_fingerprint, cursor_rowid, completed, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(selector) DO UPDATE SET
                       scope_fingerprint = excluded.scope_fingerprint,
                       cursor_rowid = excluded.cursor_rowid,
                       completed = excluded.completed,
                       updated_at = excluded.updated_at""",
                (
                    selector,
                    scope_fingerprint,
                    next_cursor,
                    0 if has_more else 1,
                    _now(),
                ),
            )
        return ScopeReconcileResult(
            documents_seen=len(rows),
            alerts_created=created,
            alerts_updated=updated,
            alert_ids=tuple(dict.fromkeys(alert_ids)),
            complete=not has_more,
            cursor=next_cursor,
        )

    @staticmethod
    def _alert(row: sqlite3.Row) -> RegulatoryAlert:
        return RegulatoryAlert(
            alert_id=str(row["alert_id"]), source_key=str(row["source_key"]),
            external_id=str(row["external_id"]), document_version=int(row["document_version"]),
            content_sha256=str(row["content_sha256"]), title=str(row["title"]),
            jurisdiction=str(row["jurisdiction"]), record_url=str(row["record_url"]),
            official_citation=row["official_citation"], change_kind=str(row["change_kind"]),
            diff=json.loads(row["diff_json"]),
            matched_regimes=tuple(json.loads(row["matched_regimes_json"])),
            matched_domains=tuple(json.loads(row["matched_domains_json"])),
            citations=tuple(_citation_from_dict(c) for c in json.loads(row["citations_json"])),
            status=str(row["status"]), revision=int(row["revision"]),
            created_at=str(row["created_at"]),
            reviewer=row["reviewer"], review_note=row["review_note"],
            reviewed_at=row["reviewed_at"],
        )

    def list_alerts(self, *, status: str | None = None, limit: int = 500) \
            -> list[RegulatoryAlert]:
        """Return the first bounded queue page for compatibility callers."""

        return list(self.list_alert_page(status=status, limit=limit).alerts)

    def list_alert_page(
        self,
        *,
        status: str | None = None,
        limit: int = 500,
        cursor: str | None = None,
    ) -> RegulatoryAlertPage:
        """Return a keyset page without silently hiding alerts past a cap."""

        if status is not None and status not in _VALID_ALERT_STATUSES:
            raise ValueError("invalid alert status")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_ALERT_LIST
        ):
            raise ValueError(f"alert list limit must be between 1 and {_MAX_ALERT_LIST}")
        position = _decode_alert_cursor(cursor)
        query = "SELECT * FROM regulatory_alerts"
        params: list[Any] = []
        conditions: list[str] = []
        if status is not None:
            conditions.append("status = ?")
            params.append(status)
        if position is not None:
            conditions.append("(created_at < ? OR (created_at = ? AND alert_id < ?))")
            params.extend((position[0], position[0], position[1]))
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC, alert_id DESC LIMIT ?"
        params.append(limit + 1)
        with closing(self._connect()) as conn, conn:
            rows = conn.execute(query, params).fetchall()
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        alerts = tuple(self._alert(row) for row in page_rows)
        next_cursor = ""
        if has_more and alerts:
            last = alerts[-1]
            next_cursor = _encode_alert_cursor(
                created_at=last.created_at,
                alert_id=last.alert_id,
            )
        return RegulatoryAlertPage(
            alerts=alerts,
            next_cursor=next_cursor,
            has_more=has_more,
        )

    def list_alert_summary_page(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Return queue metadata without materializing diffs or citations."""

        if status is not None and status not in _VALID_ALERT_STATUSES:
            raise ValueError("invalid alert status")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_ALERT_LIST
        ):
            raise ValueError(f"alert list limit must be between 1 and {_MAX_ALERT_LIST}")
        position = _decode_alert_cursor(cursor)
        query = """
            SELECT alert_id, source_key, external_id, document_version,
                   content_sha256, title, jurisdiction, record_url,
                   official_citation, change_kind, matched_regimes_json,
                   matched_domains_json, status, revision, created_at,
                   reviewer, reviewed_at
            FROM regulatory_alerts
        """
        params: list[Any] = []
        conditions: list[str] = []
        if status is not None:
            conditions.append("status = ?")
            params.append(status)
        if position is not None:
            conditions.append("(created_at < ? OR (created_at = ? AND alert_id < ?))")
            params.extend((position[0], position[0], position[1]))
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC, alert_id DESC LIMIT ?"
        params.append(limit + 1)
        with closing(self._connect()) as conn, conn:
            rows = conn.execute(query, params).fetchall()
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        alerts = [
            {
                "alert_id": str(row["alert_id"]),
                "source_key": str(row["source_key"]),
                "external_id": str(row["external_id"]),
                "document_version": int(row["document_version"]),
                "content_sha256": str(row["content_sha256"]),
                "title": str(row["title"]),
                "jurisdiction": str(row["jurisdiction"]),
                "record_url": str(row["record_url"]),
                "official_citation": row["official_citation"],
                "change_kind": str(row["change_kind"]),
                "matched_regimes": list(json.loads(row["matched_regimes_json"])),
                "matched_domains": list(json.loads(row["matched_domains_json"])),
                "status": str(row["status"]),
                "revision": int(row["revision"]),
                "created_at": str(row["created_at"]),
                "reviewer": row["reviewer"],
                "reviewed_at": row["reviewed_at"],
            }
            for row in page_rows
        ]
        next_cursor = ""
        if has_more and alerts:
            last = alerts[-1]
            next_cursor = _encode_alert_cursor(
                created_at=str(last["created_at"]),
                alert_id=str(last["alert_id"]),
            )
        return {
            "schema": _ALERT_PAGE_SCHEMA,
            "alerts": alerts,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "order": "created_at_desc_alert_id_desc",
            "projection": "summary",
        }

    def alert_status_counts(self) -> dict[str, int]:
        """Return exact queue counts without materializing or truncating alerts."""

        with closing(self._connect()) as conn, conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS count FROM regulatory_alerts GROUP BY status"
            ).fetchall()
        counts = {str(row["status"]): int(row["count"]) for row in rows}
        unknown = set(counts) - _VALID_ALERT_STATUSES
        if unknown:
            raise RuntimeError("regulatory queue contains an invalid status")
        return dict(sorted(counts.items()))

    def get_alert(self, alert_id: str) -> RegulatoryAlert | None:
        identity = str(alert_id or "").strip()
        if not identity or len(identity) > 128:
            return None
        with closing(self._connect()) as conn, conn:
            row = conn.execute(
                "SELECT * FROM regulatory_alerts WHERE alert_id = ?",
                (identity,),
            ).fetchone()
        return None if row is None else self._alert(row)

    def disposition_alert(
        self, alert_id: str, *, status: str, reviewer: str, note: str = "",
        expected_revision: int, reviewed_at: str | None = None,
    ) -> RegulatoryAlert:
        if status not in _HUMAN_ALERT_STATUSES:
            raise ValueError("status must be in_review, accepted, or dismissed")
        reviewer_clean = reviewer.strip()
        if not reviewer_clean:
            raise ValueError("reviewer is required")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision must be a positive integer")
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT status, revision FROM regulatory_alerts WHERE alert_id = ?", (alert_id,),
            ).fetchone()
            if existing is None:
                raise KeyError(alert_id)
            if int(existing["revision"]) != expected_revision:
                raise RecordConflict("regulatory alert revision conflict")
            allowed = {
                "open": {"in_review", "accepted", "dismissed"},
                "in_review": {"accepted", "dismissed"},
                "accepted": set(),
                "dismissed": set(),
                "inactive": set(),
            }
            if status not in allowed[str(existing["status"])]:
                raise ValueError(
                    f"regulatory alert cannot transition from {existing['status']} to {status}"
                )
            reviewed = reviewed_at or _now()
            note_clean = note.strip()[:10_000]
            cursor = conn.execute(
                """UPDATE regulatory_alerts
                   SET status = ?, reviewer = ?, review_note = ?, reviewed_at = ?,
                       revision = revision + 1
                   WHERE alert_id = ? AND revision = ?""",
                (
                    status,
                    reviewer_clean,
                    note_clean,
                    reviewed,
                    alert_id,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise RecordConflict("regulatory alert revision conflict")
            conn.execute(
                """INSERT INTO regulatory_alert_reviews
                   (alert_id, from_status, to_status, reviewer, note, reviewed_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (alert_id, existing["status"], status, reviewer_clean, note_clean, reviewed),
            )
            row = conn.execute(
                "SELECT * FROM regulatory_alerts WHERE alert_id = ?", (alert_id,),
            ).fetchone()
            conn.commit()
        assert row is not None
        return self._alert(row)

    def alert_review_history(self, alert_id: str, *, limit: int = 500) \
            -> list[AlertReviewEvent]:
        bounded = max(1, min(int(limit), 5_000))
        with closing(self._connect()) as conn, conn:
            alert = conn.execute(
                "SELECT 1 FROM regulatory_alerts WHERE alert_id = ?", (alert_id,),
            ).fetchone()
            if alert is None:
                raise KeyError(alert_id)
            rows = conn.execute(
                """SELECT * FROM regulatory_alert_reviews
                   WHERE alert_id = ? ORDER BY event_id ASC LIMIT ?""",
                (alert_id, bounded),
            ).fetchall()
        return [AlertReviewEvent(
            event_id=int(row["event_id"]), alert_id=str(row["alert_id"]),
            from_status=str(row["from_status"]), to_status=str(row["to_status"]),
            reviewer=str(row["reviewer"]), note=str(row["note"]),
            reviewed_at=str(row["reviewed_at"]),
        ) for row in rows]

    def document_versions(
        self, source_key: str, external_id: str, *, limit: int = 500,
    ) -> list[DocumentVersion]:
        bounded = max(1, min(int(limit), 5_000))
        with closing(self._connect()) as conn, conn:
            rows = conn.execute(
                """SELECT * FROM regulatory_documents
                   WHERE source_key = ? AND external_id = ?
                   ORDER BY version ASC LIMIT ?""",
                (source_key, external_id, bounded),
            ).fetchall()
        return [DocumentVersion(
            source_key=str(row["source_key"]), external_id=str(row["external_id"]),
            version=int(row["version"]), content_sha256=str(row["content_sha256"]),
            document=_document_from_dict(json.loads(row["document_json"])),
            ingested_at=str(row["ingested_at"]),
        ) for row in rows]


__all__ = [
    "DEFAULT_SCOPE_RULES", "AlertReviewEvent", "DocumentVersion", "FeedFetchError",
    "FeedParseError", "FeedSource", "IngestResult", "NormalizedDocument", "RegulatoryAlert",
    "RegulatoryAlertPage", "RegulatoryChangeEngine", "RegulatoryCitation", "ScopeRule", "match_scopes",
    "fetch_and_ingest", "fetch_feed", "parse_feed",
]
