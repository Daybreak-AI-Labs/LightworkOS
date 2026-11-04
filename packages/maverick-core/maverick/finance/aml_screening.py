"""Deterministic AML/KYC/watchlist ingestion, matching, and case review.

The engine deliberately stops at decision support.  It ingests operator-
selected lists, preserves the exact list provenance used for every hit, and
opens a revision-CAS case for independent human review.  It never blocks a
payment, closes a customer, or files a report on its own.

List parsing and matching are offline and deterministic.  The transparent
matching ladder mirrors Lightwork's existing typo-tolerant lookup behavior:
normalised exact match, unique prefix/substring candidates, token overlap, and
a bounded character-similarity fallback.  Unlike an inventory lookup, a
sanctions ambiguity is never discarded: every plausible candidate is retained
in the case evidence for the reviewers.
"""
from __future__ import annotations

import csv
import difflib
import hashlib
import io
import json
import math
import re
import time
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..governed_records import GovernedRecordStore
from ..privacy_ops import RecordConflict, _actor_label

LIST_SCHEMA = "lightwork.finance-screening-list.v1"
LIST_METADATA_SCHEMA = "lightwork.finance-screening-list-metadata.v1"
CASE_SCHEMA = "lightwork.finance-screening-case.v1"
PARSER_VERSION = "finance-watchlist-parser-v1"
MATCH_RULE_VERSION = "finance-entity-match-ladder-v1"
NON_DETERMINATION_NOTICE = (
    "Potential-match decision support only; not an OFAC determination, KYC "
    "approval, account action, SAR decision, or legal advice."
)

_LISTS = GovernedRecordStore(
    "finance_screening_lists", "FSL", "finance_screening_list",
)
_LIST_METADATA = GovernedRecordStore(
    "finance_screening_list_metadata", "FLM", "finance_screening_list_metadata",
)
_CASES = GovernedRecordStore(
    "finance_screening_cases", "FSC", "finance_screening_case",
)

_LIST_KINDS = frozenset({"sanctions", "pep", "internal_watchlist", "kyc"})
_FORMATS = frozenset({"auto", "text", "json", "csv", "xml"})
_DECISIONS = frozenset({"clear", "escalate"})
_FINAL_STATUS = {"clear": "cleared", "escalate": "escalated"}
_FINAL_CASE_STATUSES = frozenset(_FINAL_STATUS.values())
_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
_MAX_NORMALIZED_LIST_JSON_BYTES = 15 * 1024 * 1024
_MAX_ENTRIES = 50_000
_MAX_ALIASES = 64
_MAX_LISTS_PER_SCREEN = 16
_MAX_LIST_VERSION_ENUMERATION = 10_000
# A pre-index deployment may contain immutable list bodies without their small
# metadata companions.  Repair only a tightly bounded number per request so a
# legacy inventory can never turn a metadata/status read into a bulk body read.
_MAX_LEGACY_METADATA_RECOVERY = 4
_MAX_HITS = 100
_MAX_FUZZY_CANDIDATES = 500
_MAX_CASE_GENERATIONS = 10_000
_MAX_XML_NODES = 100_000
_MAX_XML_DEPTH = 64
_MAX_XML_CANDIDATE_NESTING = 4
_MAX_NAME = 256
_MAX_TEXT = 4_000
_FUZZY_THRESHOLD = 0.82
_TOKEN_THRESHOLD = 0.72
_STABLE_ID_HEX = 48
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_NON_WORD = re.compile(r"[^a-z0-9\s]")
_WS = re.compile(r"\s+")
_XML_CANDIDATE_TAGS = frozenset(
    {"sdnentry", "entry", "sanctionsentry", "entity", "identity"}
)
_REVIEW_POLICY = {
    "initial_reviewers": 2,
    "disagreement_adjudicators": 2,
    "rule": (
        "Two initial reviewers finalize by consensus. If they disagree, two "
        "additional reviewers, distinct from the submitter and every prior "
        "reviewer, must independently agree to finalize."
    ),
}


class ScreeningIncompleteError(RuntimeError):
    """A configured bound would omit a list, plausible comparison, or hit."""


def enabled() -> bool:
    """Return the deployment-global finance-operations feature gate."""
    try:
        from ..config import config_source_errors, load_global_config

        config = load_global_config()
        if config_source_errors(include_tenant=False):
            return False
        section = config.get("finance_operations")
        return isinstance(section, dict) and section.get("enable") is True
    except Exception:  # pragma: no cover - authority reads fail closed
        return False


def _required(value: object, label: str, limit: int = _MAX_TEXT) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    if _CONTROL_RE.search(text):
        raise ValueError(f"{label} contains control characters")
    if len(text) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    return text


def _token(value: object, label: str, allowed: frozenset[str]) -> str:
    token = _required(value, label, 80).lower()
    if token not in allowed:
        raise ValueError(f"{label} must be one of {sorted(allowed)}")
    return token


def _source_ref(value: object) -> str:
    source = _required(value, "source_ref", 2_000)
    parsed = urlparse(source)
    if parsed.scheme not in {"https", "urn"}:
        raise ValueError("source_ref must be an https URL or an operator-controlled urn")
    if parsed.scheme == "https" and not parsed.netloc:
        raise ValueError("source_ref must contain a host")
    if parsed.scheme == "urn" and not parsed.path:
        raise ValueError("source_ref URN must contain an identifier")
    return source


def _timestamp(value: object | None, label: str) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a timestamp")
    if isinstance(value, (int, float)):
        result = float(value)
    else:
        raw = str(value).strip().replace("Z", "+00:00")
        try:
            result = datetime.fromisoformat(raw).astimezone(timezone.utc).timestamp()
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} must be an ISO-8601 or Unix timestamp") from exc
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{label} must be a positive finite timestamp")
    if result > time.time() + 300:
        raise ValueError(f"{label} cannot be in the future")
    return result


def normalize_name(value: object) -> str:
    """Return a stable ASCII comparison form without changing stored evidence."""
    folded = unicodedata.normalize("NFKD", str(value or "")).casefold()
    folded = "".join(char for char in folded if not unicodedata.combining(char))
    return _WS.sub(" ", _NON_WORD.sub(" ", folded)).strip()


def _tokens(value: object) -> set[str]:
    return {token for token in normalize_name(value).split() if len(token) > 1}


def _trigrams(value: str) -> set[str]:
    compact = value.replace(" ", "")
    if len(compact) < 3:
        return {compact} if compact else set()
    return {compact[index : index + 3] for index in range(len(compact) - 2)}


def _jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left and right else 0.0


def _stable_record_id(prefix: str, fingerprint: str) -> str:
    """Return a backend-valid deterministic identity with 192 collision bits."""
    return f"{prefix}-{fingerprint[:_STABLE_ID_HEX]}"


def _case_occurrence_fingerprint(series_fingerprint: str, generation: int) -> str:
    return hashlib.sha256(f"{series_fingerprint}:{generation}".encode()).hexdigest()


def _case_occurrence_id(series_fingerprint: str, generation: int) -> str:
    return _stable_record_id(
        "FSC",
        _case_occurrence_fingerprint(series_fingerprint, generation),
    )


def _case_at_generation(
    series_fingerprint: str,
    generation: int,
) -> dict[str, Any] | None:
    """Load one deterministic occurrence without scanning unrelated cases."""
    occurrence_fingerprint = _case_occurrence_fingerprint(
        series_fingerprint,
        generation,
    )
    record_id = _case_occurrence_id(series_fingerprint, generation)
    current = _CASES.get(record_id)
    candidates = [current] if current is not None else []
    if generation == 1:
        # Compatibility with the first implementation, whose generation-one
        # identity was derived directly from the series fingerprint.
        legacy_id = _stable_record_id("FSC", series_fingerprint)
        if legacy_id != record_id:
            legacy = _CASES.get(legacy_id)
            if legacy is not None:
                candidates.append(legacy)
    if len(candidates) > 1:
        raise RecordConflict("multiple screening cases claim generation one")
    if not candidates:
        return None
    record = candidates[0]
    legacy_match = (
        generation == 1
        and not record.get("series_fingerprint")
        and record.get("fingerprint") == series_fingerprint
    )
    current_match = (
        record.get("series_fingerprint") == series_fingerprint
        and record.get("fingerprint") == occurrence_fingerprint
        and record.get("generation") == generation
    )
    if not (legacy_match or current_match):
        raise RecordConflict("deterministic screening-case identity is inconsistent")
    return record


def _concurrent_winner(
    store: GovernedRecordStore,
    record_id: str,
    *,
    schema: str,
    fingerprint: str,
) -> dict[str, Any]:
    """Load and verify the record that won a deterministic create race."""
    winner = store.get(record_id)
    if (
        winner is None
        or winner.get("schema") != schema
        or winner.get("fingerprint") != fingerprint
    ):
        raise RecordConflict(
            "deterministic governed-record conflict winner could not be verified"
        )
    return winner


def _payload_bytes(payload: bytes | str) -> bytes:
    if isinstance(payload, str):
        encoded = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        encoded = payload
    else:
        raise ValueError("payload must be bytes or text")
    if not encoded:
        raise ValueError("payload is empty")
    if len(encoded) > _MAX_PAYLOAD_BYTES:
        raise ValueError("payload exceeds the 16 MiB ingestion limit")
    return encoded


def _entry(
    name: object,
    *,
    entry_id: object = "",
    aliases: Iterable[object] = (),
    entity_type: object = "unknown",
    programs: Iterable[object] = (),
) -> dict[str, Any] | None:
    canonical = str(name or "").strip()
    normalized = normalize_name(canonical)
    if not normalized:
        return None
    canonical = canonical[:_MAX_NAME]
    alias_values: list[str] = []
    seen = {normalized}
    for raw in aliases:
        value = str(raw or "").strip()[:_MAX_NAME]
        key = normalize_name(value)
        if value and key and key not in seen:
            alias_values.append(value)
            seen.add(key)
        if len(alias_values) >= _MAX_ALIASES:
            break
    program_values = sorted(
        {str(value or "").strip()[:128] for value in programs if str(value or "").strip()}
    )[:64]
    supplied_id = str(entry_id or "").strip()[:128]
    identity_material = json.dumps(
        [supplied_id, normalized, sorted(normalize_name(item) for item in alias_values)],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return {
        "entry_id": supplied_id or "sha256:" + hashlib.sha256(
            identity_material.encode("utf-8")
        ).hexdigest(),
        "name": canonical,
        "normalized_name": normalized,
        "aliases": alias_values,
        "entity_type": str(entity_type or "unknown").strip()[:80] or "unknown",
        "programs": program_values,
    }


def _dict_entry(row: Mapping[str, Any]) -> dict[str, Any] | None:
    lowered = {str(key).casefold(): value for key, value in row.items()}
    name = next(
        (
            lowered[key]
            for key in ("name", "sdnname", "full_name", "fullname", "caption")
            if key in lowered and str(lowered[key] or "").strip()
        ),
        "",
    )
    if not name:
        parts = [
            str(lowered.get(key) or "").strip()
            for key in ("firstname", "first_name", "lastname", "last_name")
        ]
        name = " ".join(part for part in parts if part)
    aliases_raw = lowered.get("aliases") or lowered.get("aka") or []
    if isinstance(aliases_raw, str):
        aliases = re.split(r"[|;]", aliases_raw)
    elif isinstance(aliases_raw, Iterable) and not isinstance(aliases_raw, Mapping):
        aliases = list(aliases_raw)
    else:
        aliases = []
    programs_raw = lowered.get("programs") or lowered.get("program") or []
    programs = (
        re.split(r"[|;,]", programs_raw)
        if isinstance(programs_raw, str)
        else list(programs_raw) if isinstance(programs_raw, Iterable) else []
    )
    return _entry(
        name,
        entry_id=lowered.get("uid") or lowered.get("id") or lowered.get("entry_id") or "",
        aliases=aliases,
        entity_type=lowered.get("type") or lowered.get("sdntype") or "unknown",
        programs=programs,
    )


def _parse_json(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("screening list JSON is invalid") from exc
    if isinstance(data, Mapping):
        data = data.get("entries", data.get("names"))
    if not isinstance(data, list):
        raise ValueError("screening list JSON must contain an entries or names array")
    rows: list[dict[str, Any]] = []
    for item in data:
        parsed = _dict_entry(item) if isinstance(item, Mapping) else _entry(item)
        if parsed:
            rows.append(parsed)
    return rows


def _parse_csv(text: str) -> list[dict[str, Any]]:
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect=dialect)
    raw_rows = list(reader)
    if not raw_rows:
        return []
    header = [str(value).strip().casefold() for value in raw_rows[0]]
    known = {"name", "sdnname", "full_name", "fullname", "caption", "firstname"}
    rows: list[dict[str, Any]] = []
    if known.intersection(header):
        for raw in raw_rows[1:]:
            parsed = _dict_entry(dict(zip(header, raw, strict=False)))
            if parsed:
                rows.append(parsed)
        return rows
    # OFAC's legacy primary CSV has no header: UID, name, type, program, ...
    for raw in raw_rows:
        parsed = _entry(
            raw[1] if len(raw) > 1 else raw[0] if raw else "",
            entry_id=raw[0] if raw else "",
            entity_type=raw[2] if len(raw) > 2 else "unknown",
            programs=[raw[3]] if len(raw) > 3 else [],
        )
        if parsed:
            rows.append(parsed)
    return rows


def _local_name(tag: object) -> str:
    return str(tag or "").split("}")[-1].casefold()


def _child_text(node: ET.Element, names: set[str]) -> str:
    for child in node.iter():
        if _local_name(child.tag) in names and str(child.text or "").strip():
            return str(child.text).strip()
    return ""


def _person_name(node: ET.Element) -> str:
    full = _child_text(node, {"name", "fullname", "identityname", "caption"})
    if full:
        return full
    first = _child_text(node, {"firstname", "first_name", "givenname"})
    last = _child_text(node, {"lastname", "last_name", "surname"})
    return " ".join(part for part in (first, last) if part)


def _bounded_xml_tree(text: str) -> tuple[ET.Element, list[ET.Element]]:
    """Parse XML once while bounding structure and selecting disjoint candidates.

    Only outermost candidate elements are returned. Nested ``entity``/``identity``
    shapes therefore retain their parent metadata without causing each nested
    subtree to be traversed repeatedly. Candidate nesting remains bounded so an
    adversarial chain cannot turn later extraction into quadratic work.
    """
    depth = 0
    node_count = 0
    candidate_depth = 0
    candidates: list[ET.Element] = []
    try:
        parser = ET.iterparse(io.StringIO(text), events=("start", "end"))
        for event, node in parser:
            tag = _local_name(node.tag)
            if event == "start":
                depth += 1
                node_count += 1
                if node_count > _MAX_XML_NODES:
                    raise ValueError(
                        f"screening list XML exceeds the {_MAX_XML_NODES}-node limit"
                    )
                if depth > _MAX_XML_DEPTH:
                    raise ValueError(
                        f"screening list XML exceeds the {_MAX_XML_DEPTH}-level depth limit"
                    )
                if tag in _XML_CANDIDATE_TAGS:
                    if candidate_depth == 0:
                        candidates.append(node)
                        if len(candidates) > _MAX_ENTRIES:
                            raise ValueError(
                                "screening list XML exceeds the candidate limit"
                            )
                    candidate_depth += 1
                    if candidate_depth > _MAX_XML_CANDIDATE_NESTING:
                        raise ValueError(
                            "screening list XML contains excessive nested candidates"
                        )
                continue
            if tag in _XML_CANDIDATE_TAGS:
                candidate_depth -= 1
            depth -= 1
    except ET.ParseError as exc:
        raise ValueError("screening list XML is invalid") from exc
    root = parser.root
    if root is None:  # pragma: no cover - ElementTree rejects an empty document
        raise ValueError("screening list XML is invalid")
    return root, candidates


def _parse_xml(text: str) -> list[dict[str, Any]]:
    # The payload is bounded before parsing, so scan it in full.  Limiting this
    # check to a prefix would allow a declaration after a long XML comment.
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ValueError("screening list XML declarations are not allowed")
    root, candidates = _bounded_xml_tree(text)
    if not candidates:
        candidates = list(root)
    rows: list[dict[str, Any]] = []
    for node in candidates:
        name = _person_name(node)
        if not name:
            continue
        aliases: list[str] = []
        for child in node.iter():
            if _local_name(child.tag) in {"aka", "alias", "alternateidentity"}:
                alias = _person_name(child)
                if alias:
                    aliases.append(alias)
        programs = [
            str(child.text).strip()
            for child in node.iter()
            if _local_name(child.tag) in {"program", "sanctionsprogram"}
            and str(child.text or "").strip()
        ]
        parsed = _entry(
            name,
            entry_id=_child_text(node, {"uid", "id", "entryid", "logicalid"}),
            aliases=aliases,
            entity_type=_child_text(node, {"sdntype", "type", "entitytype"}) or "unknown",
            programs=programs,
        )
        if parsed:
            rows.append(parsed)
    return rows


def parse_list(payload: bytes | str, *, data_format: str = "auto") -> tuple[str, list[dict[str, Any]], str]:
    """Parse one bounded list and return ``(format, entries, sha256)``."""
    raw = _payload_bytes(payload)
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8-sig", errors="strict")
    fmt = _token(data_format, "data_format", _FORMATS)
    if fmt == "auto":
        stripped = text.lstrip()
        if stripped.startswith(("{", "[")):
            fmt = "json"
        elif stripped.startswith("<"):
            fmt = "xml"
        elif "\n" in text and any(delimiter in text.splitlines()[0] for delimiter in (",", "\t", ";", "|")):
            fmt = "csv"
        else:
            fmt = "text"
    if fmt == "json":
        entries = _parse_json(text)
    elif fmt == "csv":
        entries = _parse_csv(text)
    elif fmt == "xml":
        entries = _parse_xml(text)
    else:
        entries = [parsed for line in text.splitlines() if (parsed := _entry(line))]
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in entries:
        key = (str(entry["entry_id"]), str(entry["normalized_name"]))
        deduped.setdefault(key, entry)
        if len(deduped) > _MAX_ENTRIES:
            raise ValueError(f"screening list exceeds the {_MAX_ENTRIES}-entry limit")
    if not deduped:
        raise ValueError("screening list contains no usable names")
    return fmt, list(deduped.values()), digest


def _stored_timestamp(value: object, label: str, *, optional: bool = False) -> float | None:
    if value is None and optional:
        return None
    if isinstance(value, bool):
        raise ScreeningIncompleteError(f"screening list {label} is invalid")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ScreeningIncompleteError(
            f"screening list {label} is invalid"
        ) from exc
    if not math.isfinite(result) or result <= 0:
        raise ScreeningIncompleteError(f"screening list {label} is invalid")
    return result


def _list_metadata_projection(
    record: Mapping[str, Any],
    *,
    require_entries: bool,
) -> dict[str, Any]:
    """Validate one immutable list authority and return its small projection."""
    list_id = str(record.get("id") or "")
    if not re.fullmatch(r"FSL-[A-Za-z0-9_-]{1,59}", list_id):
        raise ScreeningIncompleteError("screening list identity is invalid")
    if record.get("schema") != LIST_SCHEMA:
        raise ScreeningIncompleteError("screening list schema is invalid")
    kind = str(record.get("list_kind") or "")
    if kind not in _LIST_KINDS:
        raise ScreeningIncompleteError("screening list kind is invalid")
    source_name = str(record.get("source_name") or "")
    version = str(record.get("version") or "")
    status = str(record.get("status") or "")
    if not source_name or not version or not status:
        raise ScreeningIncompleteError("screening list metadata is incomplete")
    provenance = record.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ScreeningIncompleteError("screening list provenance is invalid")
    source_ref = str(provenance.get("source_ref") or "")
    try:
        source_ref = _source_ref(source_ref)
    except ValueError as exc:
        raise ScreeningIncompleteError("screening list source identity is invalid") from exc
    digest = str(record.get("content_sha256") or "")
    release_fingerprint = str(record.get("release_fingerprint") or "")
    fingerprint = str(record.get("fingerprint") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ScreeningIncompleteError("screening list content digest is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", release_fingerprint):
        raise ScreeningIncompleteError("screening list release fingerprint is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        raise ScreeningIncompleteError("screening list fingerprint is invalid")
    expected_release = hashlib.sha256(
        json.dumps([kind, source_ref, version], separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    expected_fingerprint = hashlib.sha256(
        json.dumps(
            [kind, source_ref, version, digest],
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if release_fingerprint != expected_release or fingerprint != expected_fingerprint:
        raise ScreeningIncompleteError("screening list identity binding is invalid")
    if list_id != _stable_record_id("FSL", release_fingerprint):
        raise ScreeningIncompleteError("screening list record identity is inconsistent")
    parser_version = str(record.get("parser_version") or "")
    if parser_version != PARSER_VERSION:
        raise ScreeningIncompleteError("screening list parser version is invalid")
    if (
        provenance.get("content_sha256") != digest
        or provenance.get("parser_version") != parser_version
        or str(provenance.get("format") or "") not in (_FORMATS - {"auto"})
    ):
        raise ScreeningIncompleteError("screening list provenance binding is invalid")
    entry_count = record.get("entry_count")
    if (
        isinstance(entry_count, bool)
        or not isinstance(entry_count, int)
        or entry_count < 1
        or entry_count > _MAX_ENTRIES
    ):
        raise ScreeningIncompleteError("screening list entry count is invalid")
    if require_entries:
        entries = record.get("entries")
        if not isinstance(entries, list) or len(entries) != entry_count:
            raise ScreeningIncompleteError("screening list entries are inconsistent")
    revision = record.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ScreeningIncompleteError("screening list revision is invalid")
    created_at = _stored_timestamp(record.get("created_at"), "created_at")
    updated_at = _stored_timestamp(record.get("updated_at"), "updated_at")
    retrieved_at = _stored_timestamp(provenance.get("retrieved_at"), "retrieved_at")
    published_at = _stored_timestamp(
        provenance.get("published_at"),
        "published_at",
        optional=True,
    )
    ingested_by = str(provenance.get("ingested_by") or "")
    if not ingested_by:
        raise ScreeningIncompleteError("screening list ingestion actor is invalid")
    notice = str(record.get("notice") or "")
    if notice != NON_DETERMINATION_NOTICE:
        raise ScreeningIncompleteError("screening list notice is invalid")
    return {
        "id": list_id,
        "schema": LIST_SCHEMA,
        "status": status,
        "list_kind": kind,
        "source_name": source_name,
        "version": version,
        "release_fingerprint": release_fingerprint,
        "fingerprint": fingerprint,
        "content_sha256": digest,
        "parser_version": parser_version,
        "entry_count": entry_count,
        "provenance": {
            "source_ref": source_ref,
            "published_at": published_at,
            "retrieved_at": retrieved_at,
            "ingested_by": ingested_by,
            "format": str(provenance["format"]),
            "content_sha256": digest,
            "parser_version": parser_version,
        },
        "notice": notice,
        "revision": revision,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _metadata_digest(metadata: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(
            dict(metadata),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ScreeningIncompleteError(
            "screening list metadata is not canonical JSON"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _metadata_record_id(list_id: str) -> str:
    return _stable_record_id("FLM", hashlib.sha256(list_id.encode("utf-8")).hexdigest())


def _validated_metadata_record(record: Mapping[str, Any]) -> dict[str, Any]:
    if record.get("schema") != LIST_METADATA_SCHEMA or record.get("status") != "indexed":
        raise ScreeningIncompleteError("screening list metadata index is invalid")
    list_id = str(record.get("list_id") or "")
    if str(record.get("id") or "") != _metadata_record_id(list_id):
        raise ScreeningIncompleteError("screening list metadata identity is invalid")
    value = record.get("list_metadata")
    if not isinstance(value, Mapping):
        raise ScreeningIncompleteError("screening list metadata projection is invalid")
    metadata = _list_metadata_projection(value, require_entries=False)
    if metadata["id"] != list_id:
        raise ScreeningIncompleteError("screening list metadata target is invalid")
    expected = _metadata_digest(metadata)
    if record.get("metadata_sha256") != expected:
        raise ScreeningIncompleteError("screening list metadata digest is invalid")
    return metadata


def _publish_list_metadata(
    list_record: Mapping[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    metadata = _list_metadata_projection(list_record, require_entries=True)
    metadata_id = _metadata_record_id(str(metadata["id"]))
    digest = _metadata_digest(metadata)
    expected = {
        "id": metadata_id,
        "schema": LIST_METADATA_SCHEMA,
        "status": "indexed",
        "list_id": metadata["id"],
        "metadata_sha256": digest,
        "list_metadata": metadata,
    }

    def _verify_existing(existing: Mapping[str, Any] | None) -> dict[str, Any] | None:
        if existing is None:
            return None
        try:
            current = _validated_metadata_record(existing)
        except ScreeningIncompleteError as exc:
            raise RecordConflict("screening list metadata index is inconsistent") from exc
        if _metadata_digest(current) != digest:
            raise RecordConflict("screening list metadata is bound to different content")
        return current

    current = _verify_existing(_LIST_METADATA.get(metadata_id))
    if current is not None:
        return current
    try:
        saved = _LIST_METADATA.create(
            expected,
            action="index_screening_list",
            actor=actor,
        )
    except RecordConflict as exc:
        winner = _verify_existing(_LIST_METADATA.get(metadata_id))
        if winner is None:
            raise RecordConflict(
                "screening list metadata conflict winner could not be verified"
            ) from exc
        return winner
    return _validated_metadata_record(saved)


def ingest_list(
    *,
    list_kind: str,
    source_name: str,
    source_ref: str,
    version: str,
    payload: bytes | str,
    ingested_by: str,
    published_at: object | None = None,
    retrieved_at: object | None = None,
    data_format: str = "auto",
    expected_sha256: str = "",
) -> dict[str, Any]:
    """Ingest an immutable, cited list version; identical replays are idempotent."""
    kind = _token(list_kind, "list_kind", _LIST_KINDS)
    source = _required(source_name, "source_name", 200)
    citation = _source_ref(source_ref)
    release = _required(version, "version", 128)
    actor = _required(ingested_by, "ingested_by", 4096)
    fmt, entries, digest = parse_list(payload, data_format=data_format)
    expected = str(expected_sha256 or "").strip().lower().removeprefix("sha256:")
    if expected and (not re.fullmatch(r"[0-9a-f]{64}", expected) or expected != digest):
        raise ValueError("payload SHA-256 does not match expected_sha256")
    published = _timestamp(published_at, "published_at")
    retrieved = _timestamp(retrieved_at, "retrieved_at") or time.time()
    release_fingerprint = hashlib.sha256(
        json.dumps([kind, citation, release], separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    fingerprint = hashlib.sha256(
        json.dumps([kind, citation, release, digest], separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    # The publisher/source release identity, not its bytes, owns the record ID.
    # That makes a declared version an immutable one-digest binding and turns a
    # concurrent same-version/different-payload race into a governed CAS conflict.
    record_id = _stable_record_id("FSL", release_fingerprint)

    def _verified_release(existing: Mapping[str, Any] | None) -> dict[str, Any] | None:
        if existing is None:
            return None
        if (
            existing.get("schema") != LIST_SCHEMA
            or existing.get("release_fingerprint") != release_fingerprint
            or existing.get("list_kind") != kind
            or existing.get("version") != release
            or (existing.get("provenance") or {}).get("source_ref") != citation
        ):
            raise RecordConflict("screening list release identity is inconsistent")
        if (
            existing.get("fingerprint") != fingerprint
            or existing.get("content_sha256") != digest
        ):
            raise RecordConflict(
                "screening list release is already bound to different content"
            )
        return dict(existing)

    existing = _verified_release(_LISTS.get(record_id))
    if existing is not None:
        _publish_list_metadata(existing, actor=actor)
        return existing
    record = {
        "id": record_id,
        "schema": LIST_SCHEMA,
        "status": "active",
        "list_kind": kind,
        "source_name": source,
        "version": release,
        "release_fingerprint": release_fingerprint,
        "fingerprint": fingerprint,
        "content_sha256": digest,
        "parser_version": PARSER_VERSION,
        "entry_count": len(entries),
        "entries": entries,
        "provenance": {
            "source_ref": citation,
            "published_at": published,
            "retrieved_at": retrieved,
            "ingested_by": _actor_label(actor),
            "format": fmt,
            "content_sha256": digest,
            "parser_version": PARSER_VERSION,
        },
        "notice": NON_DETERMINATION_NOTICE,
    }
    normalized_bytes = len(json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8"))
    if normalized_bytes > _MAX_NORMALIZED_LIST_JSON_BYTES:
        raise ValueError(
            "normalized screening list exceeds the 15 MiB governed-record bound"
        )
    try:
        saved = _LISTS.create(record, action="ingest_list", actor=actor)
    except RecordConflict as exc:
        winner = _verified_release(_LISTS.get(record_id))
        if winner is None:
            raise RecordConflict(
                "screening list release conflict winner could not be verified"
            ) from exc
        saved = winner
    _publish_list_metadata(saved, actor=actor)
    return saved


def ingest_configured_sdn_path(
    *,
    ingested_by: str = "system:configured-sdn-import",
) -> dict[str, Any] | None:
    """Import the legacy ``[screening] sdn_path`` into governed list storage.

    The exact bytes are retained through their content digest. The local path is
    not exposed in case evidence; a digest of its resolved identity is embedded
    in an operator-controlled URN instead. An absent setting is a no-op, while a
    configured but missing, unreadable, or oversized file fails closed.
    """
    from ..config import load_config

    config = load_config() or {}
    section = config.get("screening") or {}
    configured = str(section.get("sdn_path") or "").strip()
    if not configured:
        return None
    try:
        path = Path(configured).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("configured [screening] sdn_path is unavailable") from exc
    if not path.is_file():
        raise ValueError("configured [screening] sdn_path is not a regular file")
    try:
        with path.open("rb") as handle:
            payload = handle.read(_MAX_PAYLOAD_BYTES + 1)
    except OSError as exc:
        raise ValueError("configured [screening] sdn_path is unreadable") from exc
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise ValueError("configured [screening] sdn_path exceeds the 16 MiB limit")
    digest = hashlib.sha256(payload).hexdigest()
    path_identity = hashlib.sha256(str(path).encode("utf-8")).hexdigest()
    return ingest_list(
        list_kind="sanctions",
        source_name="Configured [screening] sdn_path",
        source_ref=f"urn:lightwork:screening:sdn-path:{path_identity}",
        version=f"sha256:{digest}",
        payload=payload,
        ingested_by=ingested_by,
        retrieved_at=time.time(),
        data_format="auto",
        expected_sha256=digest,
    )


def _bounded_record_ids(
    store: GovernedRecordStore,
) -> set[str]:
    """Enumerate at most the supported inventory without reading record bodies."""
    ids: set[str] = set()
    cursor = ""
    while True:
        remaining = _MAX_LIST_VERSION_ENUMERATION + 1 - len(ids)
        batch = list(store.iter_record_ids(
            start_after=cursor,
            limit=min(1_000, remaining),
        ))
        if not batch:
            break
        wrapped = False
        for next_cursor, record_id in batch:
            cursor = str(next_cursor or "")
            value = str(record_id or "")
            if not cursor or not value:
                raise ScreeningIncompleteError(
                    "screening list inventory cursor is invalid"
                )
            if value in ids:
                wrapped = True
                break
            ids.add(value)
            if len(ids) > _MAX_LIST_VERSION_ENUMERATION:
                raise ScreeningIncompleteError(
                    "screening list-version inventory exceeds its completeness limit"
                )
        if wrapped or len(batch) < min(1_000, remaining):
            break
    return ids


def _indexed_list_metadata() -> list[dict[str, Any]]:
    """Return a complete small index, repairing only bounded legacy gaps."""
    full_ids = _bounded_record_ids(_LISTS)
    index_rows = _LIST_METADATA.list(limit=_MAX_LIST_VERSION_ENUMERATION + 1)
    if len(index_rows) > _MAX_LIST_VERSION_ENUMERATION:
        raise ScreeningIncompleteError(
            "screening list metadata inventory exceeds its completeness limit"
        )
    indexed: dict[str, dict[str, Any]] = {}
    for row in index_rows:
        metadata = _validated_metadata_record(row)
        list_id = str(metadata["id"])
        if list_id in indexed:
            raise ScreeningIncompleteError(
                "screening list metadata contains a duplicate target"
            )
        indexed[list_id] = metadata
    stale = set(indexed) - full_ids
    if stale:
        raise ScreeningIncompleteError(
            "screening list metadata references a missing list body"
        )
    missing = sorted(full_ids - set(indexed))
    for list_id in missing[:_MAX_LEGACY_METADATA_RECOVERY]:
        record = _LISTS.get(list_id)
        if record is None:
            raise ScreeningIncompleteError(
                "screening list disappeared during metadata recovery"
            )
        indexed[list_id] = _publish_list_metadata(
            record,
            actor="system:screening-list-metadata-backfill",
        )
    if len(missing) > _MAX_LEGACY_METADATA_RECOVERY:
        raise ScreeningIncompleteError(
            "legacy screening list metadata recovery made bounded progress; "
            "additional list bodies remain"
        )
    return sorted(
        indexed.values(),
        key=lambda row: (
            float(row.get("created_at") or 0),
            str(row.get("id") or ""),
        ),
        reverse=True,
    )


def list_versions(*, list_kind: str | None = None, limit: int = 1_000) -> list[dict[str, Any]]:
    """Return list-version metadata without deserializing indexed list bodies."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 10_001:
        raise ValueError("limit must be between 1 and 10001")
    kind = None if list_kind is None else _token(list_kind, "list_kind", _LIST_KINDS)
    rows = _indexed_list_metadata()
    selected = [row for row in rows if kind is None or row.get("list_kind") == kind]
    return selected[:limit]


def get_list(list_id: str) -> dict[str, Any] | None:
    return _LISTS.get(_required(list_id, "list_id", 64))


def _latest_lists() -> list[dict[str, Any]]:
    def _rank(row: Mapping[str, Any]) -> tuple[float, float, str]:
        provenance = row.get("provenance") or {}
        try:
            retrieved = float(provenance.get("retrieved_at") or 0)
        except (TypeError, ValueError, OverflowError):
            retrieved = 0.0
        try:
            created = float(row.get("created_at") or 0)
        except (TypeError, ValueError, OverflowError):
            created = 0.0
        return retrieved, created, str(row.get("id") or "")

    versions = list_versions(limit=_MAX_LIST_VERSION_ENUMERATION + 1)
    if len(versions) > _MAX_LIST_VERSION_ENUMERATION:
        raise ScreeningIncompleteError(
            "screening list-version enumeration exceeded its completeness limit"
        )
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for row in versions:
        if row.get("status") != "active":
            continue
        provenance = row.get("provenance") or {}
        key = (
            str(row.get("list_kind") or ""),
            str(provenance.get("source_ref") or ""),
        )
        if not key[1]:
            raise ScreeningIncompleteError(
                "active screening list is missing its immutable source identity"
            )
        rank = _rank(row)
        prior = latest.get(key)
        prior_rank = _rank(prior or {})
        if prior is None or rank > prior_rank:
            latest[key] = row
    selected = sorted(latest.values(), key=_rank, reverse=True)
    if len(selected) > _MAX_LISTS_PER_SCREEN:
        raise ScreeningIncompleteError(
            f"{len(selected)} active list sources exceed the "
            f"{_MAX_LISTS_PER_SCREEN}-list screening limit"
        )
    records: list[dict[str, Any]] = []
    for metadata in selected:
        record = _LISTS.get(str(metadata["id"]))
        if record is None:
            raise ScreeningIncompleteError(
                "selected screening list body is unavailable"
            )
        projection = _list_metadata_projection(record, require_entries=True)
        if _metadata_digest(projection) != _metadata_digest(metadata):
            raise ScreeningIncompleteError(
                "selected screening list body does not match its metadata index"
            )
        records.append(record)
    return records


def _candidate_names(entry: Mapping[str, Any]) -> list[tuple[str, str]]:
    values = [(str(entry.get("name") or ""), "primary")]
    values.extend((str(alias), "alias") for alias in entry.get("aliases") or [])
    return [(value, kind) for value, kind in values if normalize_name(value)]


def _match_entry(
    subject: str,
    entry: Mapping[str, Any],
    *,
    fuzzy_budget: int,
) -> tuple[dict[str, Any] | None, int]:
    want = normalize_name(subject)
    want_tokens = _tokens(want)
    want_trigrams = _trigrams(want)
    best: tuple[float, str, str] | None = None
    fuzzy_pool: list[tuple[float, str, str]] = []
    for candidate, name_kind in _candidate_names(entry):
        normalized = normalize_name(candidate)
        if normalized == want:
            score, method = 1.0, "normalized_exact"
        elif min(len(want), len(normalized)) >= 4 and (
            normalized.startswith(want) or want.startswith(normalized)
        ):
            score, method = 0.96, "prefix"
        elif min(len(want), len(normalized)) >= 5 and (
            want in normalized or normalized in want
        ):
            score, method = 0.92, "substring"
        else:
            token_score = _jaccard(want_tokens, _tokens(normalized))
            if token_score >= _TOKEN_THRESHOLD:
                score, method = token_score, "token_jaccard"
            else:
                trigram_score = _jaccard(want_trigrams, _trigrams(normalized))
                if trigram_score < 0.20 and token_score == 0:
                    continue
                fuzzy_pool.append((max(trigram_score, token_score), candidate, name_kind))
                continue
        proposed = (score, method, candidate)
        if best is None or proposed[0] > best[0]:
            best = proposed
    ranked_fuzzy = sorted(fuzzy_pool, reverse=True)
    if len(ranked_fuzzy) > fuzzy_budget:
        raise ScreeningIncompleteError(
            "plausible fuzzy candidates exceed the global comparison budget"
        )
    fuzzy_attempts = 0
    for _prefilter, candidate, _name_kind in ranked_fuzzy:
        fuzzy_attempts += 1
        ratio = difflib.SequenceMatcher(
            None, want[:_MAX_NAME], normalize_name(candidate)[:_MAX_NAME], autojunk=False
        ).ratio()
        if ratio >= _FUZZY_THRESHOLD and (best is None or ratio > best[0]):
            best = (ratio, "character_similarity", candidate)
    if best is None:
        return None, fuzzy_attempts
    score, method, matched_name = best
    return {
        "entry_id": str(entry.get("entry_id") or ""),
        "entry_name": str(entry.get("name") or ""),
        "matched_name": matched_name,
        "match_method": method,
        "score": round(float(score), 6),
        "entity_type": str(entry.get("entity_type") or "unknown"),
        "programs": list(entry.get("programs") or []),
    }, fuzzy_attempts


def match_subject(subject_name: str, list_records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return bounded, provenance-bearing candidates without persisting a case."""
    subject = _required(subject_name, "subject_name", _MAX_NAME)
    records = list(list_records)
    if not records or len(records) > _MAX_LISTS_PER_SCREEN:
        raise ValueError(f"one to {_MAX_LISTS_PER_SCREEN} list records are required")
    hits: list[dict[str, Any]] = []
    fuzzy_budget = _MAX_FUZZY_CANDIDATES
    for list_record in records:
        entries = list_record.get("entries")
        provenance = list_record.get("provenance")
        if not isinstance(entries, list) or not isinstance(provenance, Mapping):
            raise ValueError("screening list record is malformed")
        citation = {
            "list_id": str(list_record.get("id") or ""),
            "list_revision": int(list_record.get("revision") or 0),
            "list_kind": str(list_record.get("list_kind") or ""),
            "source_name": str(list_record.get("source_name") or ""),
            "source_ref": str(provenance.get("source_ref") or ""),
            "list_version": str(list_record.get("version") or ""),
            "published_at": provenance.get("published_at"),
            "retrieved_at": provenance.get("retrieved_at"),
            "content_sha256": str(list_record.get("content_sha256") or ""),
            "parser_version": str(list_record.get("parser_version") or ""),
        }
        for entry in entries:
            # Exact/prefix/token paths return quickly.  The module-level list
            # and payload bounds keep the total deterministic; fuzzy candidates
            # are additionally capped before SequenceMatcher is reached.
            hit, fuzzy_attempts = _match_entry(
                subject,
                entry,
                fuzzy_budget=fuzzy_budget,
            )
            fuzzy_budget -= fuzzy_attempts
            if hit is None:
                continue
            if len(hits) >= _MAX_HITS:
                raise ScreeningIncompleteError(
                    f"screening matches exceed the {_MAX_HITS}-hit result limit"
                )
            hits.append({**hit, "citation": citation, "rule_version": MATCH_RULE_VERSION})
    hits.sort(key=lambda item: (-float(item["score"]), item["entry_name"], item["entry_id"]))
    return hits


def screen_subject(
    subject_name: str,
    *,
    screened_by: str,
    subject_ref: str = "",
    list_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Screen a subject and open one idempotent four-eyes case on any hit."""
    subject = _required(subject_name, "subject_name", _MAX_NAME)
    actor = _required(screened_by, "screened_by", 4096)
    reference = str(subject_ref or "").strip()[:256]
    ids = [str(value or "").strip() for value in (list_ids or []) if str(value or "").strip()]
    if len(ids) > _MAX_LISTS_PER_SCREEN:
        raise ValueError(f"no more than {_MAX_LISTS_PER_SCREEN} list_ids are allowed")
    if ids:
        selection_mode = "explicit_list_ids"
        records = []
        for list_id in ids:
            row = get_list(list_id)
            if row is None:
                raise KeyError("screening list not found")
            records.append(row)
    else:
        selection_mode = "latest_active_per_source"
        ingest_configured_sdn_path()
        records = _latest_lists()
    if not records:
        raise ValueError("no active screening list versions are available")
    hits = match_subject(subject, records)
    screened_lists = [
        {
            "list_id": row["id"],
            "revision": row["revision"],
            "content_sha256": row["content_sha256"],
            "source_ref": row["provenance"]["source_ref"],
            "version": row["version"],
        }
        for row in records
    ]
    result = {
        "match": bool(hits),
        "subject_name": subject,
        "subject_ref": reference,
        "hits": hits,
        "screened_lists": screened_lists,
        "rule_version": MATCH_RULE_VERSION,
        "completeness": {
            "complete_for_selected_scope": True,
            "all_latest_active_sources_screened": selection_mode
            == "latest_active_per_source",
            "selection_mode": selection_mode,
            "selected_list_count": len(records),
            "truncated": False,
            "limits": {
                "lists": _MAX_LISTS_PER_SCREEN,
                "fuzzy_comparisons": _MAX_FUZZY_CANDIDATES,
                "hits": _MAX_HITS,
            },
        },
        "notice": NON_DETERMINATION_NOTICE,
        "case": None,
    }
    if not hits:
        return result
    fingerprint_material = {
        "subject": normalize_name(subject),
        "subject_ref": reference,
        "lists": sorted(
            screened_lists,
            key=lambda row: (
                str(row["list_id"]),
                int(row["revision"]),
                str(row["content_sha256"]),
            ),
        ),
        "entries": sorted(
            {
                (
                    str(hit["citation"]["list_id"]),
                    int(hit["citation"]["list_revision"]),
                    str(hit["entry_id"]),
                )
                for hit in hits
            }
        ),
        "rule_version": MATCH_RULE_VERSION,
    }
    series_fingerprint = hashlib.sha256(
        json.dumps(fingerprint_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    previous_case_id = ""
    for generation in range(1, _MAX_CASE_GENERATIONS + 1):
        existing = _case_at_generation(series_fingerprint, generation)
        if existing is None:
            break
        if existing.get("status") not in _FINAL_CASE_STATUSES:
            result["case"] = existing
            return result
        previous_case_id = str(existing.get("id") or "")
    else:
        raise ScreeningIncompleteError(
            f"screening case series exceeds the {_MAX_CASE_GENERATIONS}-generation limit"
        )
    occurrence_fingerprint = _case_occurrence_fingerprint(
        series_fingerprint,
        generation,
    )
    record_id = _case_occurrence_id(series_fingerprint, generation)
    record = {
        "id": record_id,
        "schema": CASE_SCHEMA,
        "status": "open",
        "fingerprint": occurrence_fingerprint,
        "series_fingerprint": series_fingerprint,
        "generation": generation,
        "previous_case_id": previous_case_id,
        "subject": {"name": subject, "reference": reference},
        "screened_by": _actor_label(actor),
        "rule_version": MATCH_RULE_VERSION,
        "screened_lists": screened_lists,
        "hits": hits,
        "dispositions": [],
        "review_policy": dict(_REVIEW_POLICY),
        "notice": NON_DETERMINATION_NOTICE,
    }
    try:
        result["case"] = _CASES.create(
            record,
            action="open_screening_case",
            actor=actor,
        )
    except RecordConflict:
        result["case"] = _concurrent_winner(
            _CASES,
            record_id,
            schema=CASE_SCHEMA,
            fingerprint=occurrence_fingerprint,
        )
    return result


def list_cases(*, status: str | None = None, limit: int = 1_000) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 10_001:
        raise ValueError("limit must be between 1 and 10001")
    state = str(status or "").strip().lower()
    rows = _CASES.list(limit=limit)
    return [row for row in rows if not state or row.get("status") == state]


def get_case(case_id: str) -> dict[str, Any] | None:
    return _CASES.get(_required(case_id, "case_id", 64))


def record_disposition(
    case_id: str,
    *,
    decision: str,
    rationale: str,
    decided_by: str,
    expected_revision: int,
) -> dict[str, Any] | None:
    """Record one review under the explicit independent-adjudication rule.

    Two initial reviewers may finalize by agreement. If they disagree, a third
    reviewer begins adjudication and a fourth, distinct reviewer must reach the
    same decision. The submitter and every prior reviewer are ineligible, and
    each mutation is guarded by the caller's expected revision.
    """
    choice = _token(decision, "decision", _DECISIONS)
    reason = _required(rationale, "rationale", _MAX_TEXT)
    actor = _required(decided_by, "decided_by", 4096)
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 0:
        raise ValueError("expected_revision must be a non-negative integer")

    def _mutate(record: dict[str, Any]) -> None:
        if record.get("status") in {"cleared", "escalated"}:
            raise ValueError("final screening cases are read-only")
        identity = _actor_label(actor)
        if identity == record.get("screened_by"):
            raise ValueError("the screening submitter cannot review the same case")
        dispositions = list(record.get("dispositions") or [])
        if any(item.get("decided_by") == identity for item in dispositions):
            raise ValueError("a reviewer may decide a screening case only once")
        if len(dispositions) >= 4:
            raise ValueError(
                "independent adjudication is exhausted; administrative escalation is required"
            )
        dispositions.append(
            {
                "decision": choice,
                "rationale": reason,
                "decided_by": identity,
                "decided_at": time.time(),
            }
        )
        record["dispositions"] = dispositions
        if len(dispositions) < 2:
            record["status"] = "pending_second_review"
            return
        first, second = dispositions[0], dispositions[1]
        if first["decided_by"] == second["decided_by"]:
            raise ValueError("final disposition requires two independent reviewers")
        if len(dispositions) == 2 and first["decision"] == second["decision"]:
            record["status"] = _FINAL_STATUS[first["decision"]]
            record["final_disposition"] = {
                "decision": first["decision"],
                "reviewers": [first["decided_by"], second["decided_by"]],
                "resolution": "initial_consensus",
                "finalized_at": time.time(),
                "human_reviewed": True,
            }
            return
        if len(dispositions) == 2:
            record["status"] = "review_required"
            record["adjudication"] = {
                "status": "pending_first_adjudicator",
                "initial_reviewers": [first["decided_by"], second["decided_by"]],
            }
            return
        if len(dispositions) == 3:
            record["status"] = "pending_adjudication_review"
            record["adjudication"] = {
                "status": "pending_second_adjudicator",
                "initial_reviewers": [first["decided_by"], second["decided_by"]],
                "first_adjudicator": dispositions[2]["decided_by"],
            }
            return
        third, fourth = dispositions[2], dispositions[3]
        if third["decision"] == fourth["decision"]:
            record["status"] = _FINAL_STATUS[third["decision"]]
            record["adjudication"] = {
                "status": "consensus",
                "initial_reviewers": [first["decided_by"], second["decided_by"]],
            }
            record["final_disposition"] = {
                "decision": third["decision"],
                "reviewers": [third["decided_by"], fourth["decided_by"]],
                "initial_reviewers": [first["decided_by"], second["decided_by"]],
                "resolution": "independent_adjudication",
                "finalized_at": time.time(),
                "human_reviewed": True,
            }
            return
        record["status"] = "review_required"
        record["adjudication"] = {
            "status": "no_consensus",
            "initial_reviewers": [first["decided_by"], second["decided_by"]],
            "adjudicators": [third["decided_by"], fourth["decided_by"]],
        }

    return _CASES.update(
        _required(case_id, "case_id", 64),
        _mutate,
        expected_revision=expected_revision,
        action="screening_disposition",
        actor=actor,
    )


__all__ = [
    "CASE_SCHEMA",
    "LIST_METADATA_SCHEMA",
    "LIST_SCHEMA",
    "MATCH_RULE_VERSION",
    "NON_DETERMINATION_NOTICE",
    "RecordConflict",
    "ScreeningIncompleteError",
    "enabled",
    "get_case",
    "get_list",
    "ingest_configured_sdn_path",
    "ingest_list",
    "list_cases",
    "list_versions",
    "match_subject",
    "normalize_name",
    "parse_list",
    "record_disposition",
    "screen_subject",
]
