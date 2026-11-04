"""Data map: the governed inventory of where personal data actually lives.

The discovery half of a privacy program: a register of data assets (tables,
sites, shares, datasets) with a pure-Python column classifier that flags
likely personal-data categories, a warehouse importer that reads an
``information_schema.columns`` CSV export, and a SharePoint connector that
enumerates sites via Microsoft Graph. Assets link to the specialist records
that govern them (RoPA entries, assessments, vendors, AI systems).

Classification is name-based heuristics over column and asset names — a
triage signal for a human data-mapping exercise, not a scanner that has
read the data. Never legal advice.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

from .governed_records import GovernedRecordStore

ASSET_SCHEMA = "lightwork.data-asset.v1"
ASSET_KINDS = ("table", "dataset", "file_share", "site", "bucket", "other")
LINK_KINDS = ("ropa", "assessment", "vendor", "ai_system")

#: Personal-data categories the classifier can flag, by column-name pattern.
CLASSIFIER_CATEGORIES = (
    "email", "phone", "name", "address", "national_id", "date_of_birth",
    "financial", "health", "credentials", "ip_address", "location",
)
#: GDPR Art. 9-adjacent categories that mark an asset special-category.
SPECIAL_CATEGORIES = frozenset({"health"})
#: Categories that identify a person — the assets a DSAR search plan
#: should send a human to. Owned here, next to the classifier vocabulary
#: it subsets, so a new category is weighed for DSAR relevance in one place.
IDENTIFYING_CATEGORIES = frozenset({
    "email", "phone", "name", "address", "national_id",
    "date_of_birth", "ip_address", "location",
})

_ASSETS = GovernedRecordStore("data_map", "DMA", "data_asset")
_MAX_LIST = 500
#: The register's capacity, and a full-scan window one past it: posture
#: counts and the DSAR worksheet must see every asset, not an mtime-ranked
#: subset.
_MAX_RECORDS = 10_000
_SCAN_LIMIT = _MAX_RECORDS + 1
_MAX_LINKS = 50
_MAX_COLUMNS = 400
_MAX_IMPORT_ROWS = 10_000
_MAX_IMPORT_TABLES = 500
_MAX_SITES = 50
_GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
_GRAPH_TIMEOUT_SECONDS = 20.0
#: File-content scan bounds: a bounded sample of a site's document library,
#: not a crawler.
_MAX_FILES_SCANNED = 25
_MAX_FILE_SAMPLE_CHARS = 100_000
_MAX_FILE_BYTES = 5_000_000
_TEXT_FILE_SUFFIXES = (".csv", ".json", ".log", ".md", ".ndjson",
                       ".tsv", ".txt", ".yaml", ".yml")
#: Document formats the platform reads with the STDLIB ALONE, via the same
#: hardened extractor the DPA/vendor-paper pipelines use (OOXML containers
#: and untrusted PDF content streams). Legacy .doc/.xls and images stay off
#: this list: reading them needs a third-party parser, which is a decision
#: to take deliberately, not to smuggle in through a scanner.
_DOCUMENT_FILE_MIMES = {
    ".docx": ("application/vnd.openxmlformats-officedocument"
              ".wordprocessingml.document"),
    ".pptx": ("application/vnd.openxmlformats-officedocument"
              ".presentationml.presentation"),
    ".xlsx": ("application/vnd.openxmlformats-officedocument"
              ".spreadsheetml.sheet"),
    ".pdf": "application/pdf",
}
#: Graph identifiers appear inside request paths; refuse anything that could
#: smuggle path segments or query strings (site ids are hostname,guid,guid
#: composites; item ids are base64ish and may contain "!").
_GRAPH_ID_RE = re.compile(r"^[A-Za-z0-9!_.,-]{1,512}$")

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (category, re.compile(expression))
    for category, expression in (
        ("email", r"(?:^|[_-])e[_-]?mail(?:$|[_-])"),
        ("phone", r"(?:^|[_-])(?:tele[_-]?phone|phone|mobile|msisdn|fax)"
                  r"(?:$|[_-])"),
        ("name", r"(?:^|_)(?:first|last|middle|full|sur|given|family|maiden)"
                 r"[_-]?name|(?:^|_)name(?:$|_)"),
        ("address", r"address|street|postcode|postal|zip[_-]?code|city"),
        ("national_id", r"ssn|social[_-]?security|passport|national[_-]?id|"
                        r"tax[_-]?id|driver[_-]?licen[cs]e|nino|cpf|aadhaar"),
        ("date_of_birth", r"(?:birth[_-]?date|date[_-]?of[_-]?birth|"
                          r"(?:^|_)dob(?:$|_)|birthday)"),
        ("financial", r"iban|swift|account[_-]?number|routing|credit[_-]?card|"
                      r"card[_-]?number|(?:^|_)pan(?:$|_)|salary|payroll"),
        ("health", r"(?:^|[_-])health(?:$|[_-])|medical|diagnos|prescription|"
                   r"allerg|disabilit|blood[_-]?type|icd[_-]?10"),
        ("credentials", r"password|passwd|secret|api[_-]?key|token|"
                        r"private[_-]?key|credential"),
        ("ip_address", r"ip[_-]?addr|(?:^|_)ipv?[46]?(?:$|_)"),
        ("location", r"latitude|longitude|geo[_-]?|gps"),
    )
)


class DataMapError(RuntimeError):
    """Base failure for the governed data map."""


class DataMapConfigError(DataMapError):
    """The feature is not enabled or configured safely."""


def get_data_map_config() -> dict[str, Any]:
    from .config import load_global_config

    try:
        config = load_global_config()
    except Exception as exc:
        raise DataMapConfigError("data_map configuration is unavailable") from exc
    section = (config or {}).get("data_map") or {}
    if not isinstance(section, dict):
        raise DataMapConfigError("data_map must be a table")
    flag = section.get("enable", False)
    if not isinstance(flag, bool):
        raise DataMapConfigError("data_map.enable must be a boolean")
    token_env = str(
        section.get("graph_token_env") or "MAVERICK_GRAPH_TOKEN"
    ).strip()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", token_env):
        raise DataMapConfigError(
            "data_map.graph_token_env must name an environment variable "
            "(UPPER_SNAKE_CASE)"
        )
    return {"enable": flag, "graph_token_env": token_env}


def graph_token(env_name: str = "MAVERICK_GRAPH_TOKEN") -> str:
    """The Microsoft Graph token: the environment variable ``env_name`` wins
    (the data map passes its ``graph_token_env``); otherwise ``[data_map]
    graph_token``, saved sealed on the All settings page and opened when the
    configuration loads. Empty means Graph collection is refused."""
    token = os.environ.get(env_name, "").strip()
    if token:
        return token
    from .config import load_global_config

    try:
        section = (load_global_config() or {}).get("data_map") or {}
    except Exception:  # unreadable configuration means "not set"
        return ""
    value = section.get("graph_token") if isinstance(section, dict) else None
    return value.strip() if isinstance(value, str) else ""


def enabled() -> bool:
    try:
        return get_data_map_config()["enable"] is True
    except Exception:
        return False


def _require_enabled() -> dict[str, Any]:
    settings = get_data_map_config()
    if settings["enable"] is not True:
        raise DataMapConfigError("the data map requires [data_map] enable = true")
    return settings


def _text(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ValueError(f"{label} must be 1-{limit} characters")
    return text


def classify_column(column_name: str) -> list[str]:
    """The categories a column name suggests; empty when nothing matches."""

    # CamelCase carries its word boundaries in case; materialize them as
    # underscores BEFORE lowering so the anchored patterns still see them
    # ("MobileNumber" -> "mobile_number"). The anchors are what keep
    # "mail_server", "microphone_enabled" and "healthcheck_status" clean.
    lowered = re.sub(
        r"(?<=[a-z0-9])(?=[A-Z])", "_", str(column_name or "").strip()
    ).lower()
    if not lowered:
        return []
    return [
        category for category, pattern in _PATTERNS if pattern.search(lowered)
    ]


def classify_columns(column_names: list[str]) -> dict[str, list[str]]:
    """Map each flagged column to its categories (clean columns omitted)."""

    flagged: dict[str, list[str]] = {}
    for raw in list(column_names)[:_MAX_COLUMNS]:
        categories = classify_column(str(raw))
        if categories:
            flagged[str(raw).strip()] = categories
    return flagged


def _asset_id(system: str, name: str) -> str:
    return (
        "DMA-"
        + hashlib.sha256(
            f"{system.lower()}:{name.lower()}".encode()
        ).hexdigest()[:24]
    )


def _categories_of(flagged: Mapping[str, list[str]]) -> list[str]:
    found: set[str] = set()
    for categories in flagged.values():
        found.update(categories)
    return sorted(found)


def register_data_asset(
    name: str,
    *,
    system: str,
    kind: str,
    owner: str,
    actor: str,
    columns: list[str] | None = None,
    location: str = "",
    source: str = "manual",
    max_records: int | None = _MAX_RECORDS,
) -> dict[str, Any]:
    """Register or refresh one data asset; re-registration reclassifies.

    ``max_records`` is the capacity cap enforced on create; bulk importers
    that pre-check capacity once for the whole batch pass ``None`` so each
    row does not repeat the store's full-namespace capacity scan.
    """

    _require_enabled()
    if kind not in ASSET_KINDS:
        raise ValueError(f"kind must be one of: {', '.join(ASSET_KINDS)}")
    asset_name = _text(name, "name", 512)
    system_name = _text(system, "system", 256)
    steward = _text(owner, "owner", 256)
    operator = _text(actor, "actor", 256)
    origin = _text(source, "source", 64)
    where = str(location or "").strip()[:1024]
    names = [str(column) for column in (columns or [])][:_MAX_COLUMNS]
    flagged = classify_columns(names)
    categories = _categories_of(flagged)
    record_id = _asset_id(system_name, asset_name)
    body = {
        "name": asset_name,
        "system": system_name,
        "kind": kind,
        "owner": steward,
        "location": where,
        "source": origin,
        "column_count": len(names),
        "flagged_columns": flagged,
        "categories": categories,
        "special_category": bool(SPECIAL_CATEGORIES.intersection(categories)),
        "last_classified_at": time.time(),
    }
    current = _ASSETS.get(record_id)
    if current is None:
        record = {
            "id": record_id,
            "schema": ASSET_SCHEMA,
            "links": [],
            "registered_at": time.time(),
            **body,
        }
        return dict(
            _ASSETS.create(
                record,
                action="register_data_asset",
                actor=operator,
                max_records=max_records,
            )
        )

    def mutate(value: dict[str, Any]) -> None:
        value.update(body)

    saved = _ASSETS.update(
        record_id,
        mutate,
        expected_revision=int(current.get("revision") or 0),
        action="register_data_asset",
        actor=operator,
    )
    if saved is None:
        raise DataMapError("the data asset changed during save")
    return dict(saved)


def link_asset_record(
    asset_id: str,
    *,
    kind: str,
    reference: str,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """Attach one specialist record (by reference) to the asset row."""

    _require_enabled()
    if kind not in LINK_KINDS:
        raise ValueError(f"kind must be one of: {', '.join(LINK_KINDS)}")
    operator = _text(actor, "actor", 256)
    where = _text(reference, "reference", 512)

    def mutate(value: dict[str, Any]) -> None:
        links = list(value.get("links") or [])
        links.append(
            {
                "kind": kind,
                "reference": where,
                "linked_by": operator,
                "linked_at": time.time(),
            }
        )
        value["links"] = links[-_MAX_LINKS:]

    saved = _ASSETS.update(
        _text(asset_id, "asset_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="link_asset_record",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"data asset is not registered: {asset_id}")
    return dict(saved)


def get_data_asset(asset_id: str) -> dict[str, Any] | None:
    _require_enabled()
    row = _ASSETS.get(_text(asset_id, "asset_id", 64))
    return dict(row) if row else None


def list_data_assets(*, system: str | None = None) -> list[dict[str, Any]]:
    _require_enabled()
    rows = _ASSETS.list(limit=_SCAN_LIMIT)
    if system:
        wanted = str(system).strip().lower()
        rows = [
            row for row in rows
            if str(row.get("system") or "").lower() == wanted
        ]
    rows.sort(key=lambda row: (str(row.get("system")), str(row.get("name"))))
    return [dict(row) for row in rows]


def data_map_posture() -> dict[str, Any]:
    _require_enabled()
    rows = _ASSETS.list(limit=_SCAN_LIMIT)
    by_system: dict[str, int] = {}
    by_category: dict[str, int] = {}
    flagged = 0
    special = 0
    unlinked_flagged = 0
    for row in rows:
        system = str(row.get("system") or "unknown")
        by_system[system] = by_system.get(system, 0) + 1
        categories = list(row.get("categories") or [])
        if categories:
            flagged += 1
            if not row.get("links"):
                unlinked_flagged += 1
        if row.get("special_category"):
            special += 1
        for category in categories:
            by_category[category] = by_category.get(category, 0) + 1
    return {
        "assets": len(rows),
        "flagged_assets": flagged,
        "special_category_assets": special,
        "unlinked_flagged_assets": unlinked_flagged,
        "by_system": dict(sorted(by_system.items())),
        "by_category": dict(sorted(by_category.items())),
    }


#: information_schema.columns export aliases (case-insensitive).
_SCHEMA_CSV_HEADERS = {
    "table": ("table_name", "table", "object_name"),
    "schema": ("table_schema", "schema", "schema_name", "database"),
    "column": ("column_name", "column", "field", "field_name"),
}


def import_information_schema_csv(
    csv_text: str,
    *,
    system: str,
    owner: str,
    imported_by: str = "",
) -> dict[str, int]:
    """Import a warehouse ``information_schema.columns`` CSV as table assets.

    Works with the stock exports of Snowflake, BigQuery, Redshift, and
    Postgres (``SELECT table_schema, table_name, column_name FROM
    information_schema.columns``). One asset per table, columns classified.
    """

    _require_enabled()
    from .csv_alias import alias_rows

    tables: dict[str, list[str]] = {}
    skipped = 0
    for entry in alias_rows(csv_text, _SCHEMA_CSV_HEADERS,
                            limit=_MAX_IMPORT_ROWS):
        if not entry.get("table") or not entry.get("column"):
            skipped += 1
            continue
        qualified = entry["table"]
        if entry.get("schema"):
            qualified = f"{entry['schema']}.{qualified}"
        columns = tables.setdefault(qualified, [])
        if len(columns) < _MAX_COLUMNS:
            columns.append(entry["column"])
    # Capacity is checked ONCE for the whole batch: the store's per-create
    # capacity check is a full namespace scan, which would turn a 500-table
    # import into 500 scans. Existing tables refresh in place and consume
    # no budget; new tables past the cap are skipped, not raised.
    system_name = _text(system, "system", 256)
    existing = {
        str(row.get("id") or "") for row in _ASSETS.list(limit=_SCAN_LIMIT)
    }
    budget = _MAX_RECORDS - len(existing)
    imported = 0
    for qualified, columns in list(tables.items())[:_MAX_IMPORT_TABLES]:
        is_new = _asset_id(system_name, qualified) not in existing
        if is_new and budget <= 0:
            skipped += 1
            continue
        try:
            register_data_asset(
                qualified,
                system=system_name,
                kind="table",
                owner=owner,
                actor=imported_by or "import:information_schema",
                columns=columns,
                source="information_schema",
                max_records=None,
            )
            imported += 1
            if is_new:
                budget -= 1
        except Exception:
            skipped += 1
    return {"imported": imported, "skipped": skipped}


#: Cap on one content-verification sample; the classifier has its own
#: global ceiling, this keeps register writes bounded.
_MAX_CONTENT_SAMPLE = 200_000


def classify_asset_content(
    asset_id: str,
    text_sample: str,
    *,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """Content-verify one asset from a bounded sample of its actual data.

    Where :func:`classify_column` reads NAMES, this runs the
    deterministic content classifier over a real sample (rows the
    operator pastes or pipes in) and records what was actually FOUND —
    ``content_categories`` with per-category counts, merged into the
    asset's categories. A content-verified category is evidence; a
    name-suggested one is a hint, and the record now distinguishes them.
    """

    _require_enabled()
    from .content_classifier import classify_text

    operator = _text(actor, "actor", 256)
    sample = str(text_sample or "")
    if not sample.strip():
        raise ValueError("text_sample must not be empty")
    if len(sample) > _MAX_CONTENT_SAMPLE:
        raise ValueError(
            f"text_sample must be at most {_MAX_CONTENT_SAMPLE} characters")
    report = classify_text(sample)

    def mutate(value: dict[str, Any]) -> None:
        merged = sorted(
            set(value.get("categories") or []) | set(report["categories"])
        )
        value["categories"] = merged
        value["content_categories"] = report["categories"]
        value["content_counts"] = report["counts"]
        value["content_verified_at"] = time.time()
        value["content_verified_by"] = operator
        value["special_category"] = bool(
            SPECIAL_CATEGORIES.intersection(merged))

    saved = _ASSETS.update(
        _text(asset_id, "asset_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="classify_asset_content",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"data asset is not registered: {asset_id}")
    return dict(saved)


def _sql_identifier(part: str) -> str:
    return '"' + part.replace('"', '""').upper() + '"'


def masking_policy_sql(
    *, system: str = "snowflake", unmasked_role: str = "DATA_STEWARD",
) -> str:
    """Deterministic Snowflake masking-policy DDL from the data map.

    The classifier's findings, pushed to where the data lives: one
    ``CREATE MASKING POLICY IF NOT EXISTS`` per flagged category and one
    ``ALTER TABLE ... SET MASKING POLICY`` per flagged column, for every
    ``table`` asset in the named system. ``unmasked_role`` names the
    Snowflake role that sees clear text. A column flagged with several
    categories gets the first policy and a comment naming the rest —
    Snowflake allows one masking policy per column. Emitted as SQL text
    for the operator's review pipeline — Lightwork never executes it,
    and the header says so. Snowflake only in v1; other engines are a
    decision.
    """

    _require_enabled()
    engine = str(system or "").strip().lower()
    if engine != "snowflake":
        raise ValueError("only system='snowflake' is supported in v1")
    role = str(unmasked_role or "").strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", role):
        raise ValueError(
            "unmasked_role must be an UPPER_SNAKE_CASE identifier")
    rows = sorted(
        (
            row for row in _ASSETS.list(limit=_SCAN_LIMIT)
            if row.get("kind") == "table" and (row.get("flagged_columns"))
        ),
        key=lambda row: str(row.get("name") or ""),
    )
    categories_in_use = sorted(
        {
            category
            for row in rows
            for cols in (row.get("flagged_columns") or {}).values()
            for category in cols
        }
    )
    lines = [
        "-- Lightwork data-map masking policies (Snowflake).",
        "-- Generated from the governed register; REVIEW before applying.",
        "-- Lightwork emits this DDL and never executes it.",
        "",
    ]
    for category in categories_in_use:
        policy = _sql_identifier(f"LIGHTWORK_MASK_{category}")
        lines.append(
            f"CREATE MASKING POLICY IF NOT EXISTS {policy} AS "
            "(val string) RETURNS string ->\n"
            f"  CASE WHEN CURRENT_ROLE() IN ('{role}') THEN val "
            f"ELSE '[MASKED:{category}]' END;"
        )
    for row in rows:
        table = ".".join(
            _sql_identifier(part)
            for part in str(row.get("name") or "").split(".")
        )
        for column, cats in sorted(
            (row.get("flagged_columns") or {}).items()
        ):
            if not cats:
                continue
            ordered = sorted(cats)
            policy = _sql_identifier(f"LIGHTWORK_MASK_{ordered[0]}")
            extra = (
                f"  -- also flagged: {', '.join(ordered[1:])} "
                "(Snowflake allows one policy per column)"
                if len(ordered) > 1 else ""
            )
            lines.append(
                f"ALTER TABLE {table} MODIFY COLUMN "
                f"{_sql_identifier(column)} SET MASKING POLICY {policy};"
                + extra
            )
    if not rows:
        lines.append("-- No flagged table assets in the register yet.")
    return "\n".join(lines) + "\n"


def _default_graph_fetch(url: str, token: str) -> dict[str, Any]:
    """GET through the SSRF-pinned, enterprise-egress-guarded client."""

    from .enterprise import enterprise_egress_denial
    from .tools._ssrf import BlockedHost, safe_client

    deny = enterprise_egress_denial(url, tool="data_map")
    if deny:
        raise DataMapError(deny)
    try:
        with safe_client(url, timeout=_GRAPH_TIMEOUT_SECONDS) as client:
            response = client.get(
                url, headers={"Authorization": f"Bearer {token}"}
            )
    except BlockedHost as exc:
        raise DataMapError("blocked host (SSRF guard)") from exc
    if response.status_code != 200:
        raise DataMapError(
            f"Microsoft Graph returned HTTP {response.status_code}"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise DataMapError("Microsoft Graph returned a non-JSON body") from exc
    if not isinstance(payload, dict):
        raise DataMapError("Microsoft Graph returned an unexpected shape")
    return payload


def _sharepoint_site_rows(
    search: str,
    fetcher: Callable[[str], dict[str, Any]] | None,
) -> list[Any]:
    """One bounded page of the Microsoft Graph site listing (the census)."""
    settings = _require_enabled()
    query = str(search or "").strip()[:256]
    if fetcher is None:
        from urllib.parse import quote

        token = graph_token(settings["graph_token_env"])
        if not token:
            raise DataMapConfigError(
                "the SharePoint sync needs a Microsoft Graph token in "
                f"${settings['graph_token_env']} (Sites.Read.All)"
            )
        if query:
            url = f"{_GRAPH_ROOT}/sites?search={quote(query)}"
        else:
            url = f"{_GRAPH_ROOT}/sites/getAllSites"

        def fetch(target: str) -> dict[str, Any]:
            return _default_graph_fetch(target, token)

        payload = fetch(url)
    else:
        suffix = f"sites?search={query}" if query else "sites/getAllSites"
        payload = fetcher(f"{_GRAPH_ROOT}/{suffix}")
    rows = payload.get("value")
    if not isinstance(rows, list):
        raise DataMapError("Microsoft Graph returned an unexpected shape")
    return rows


def find_sharepoint_site_id(
    web_url: str,
    *,
    search: str = "",
    fetcher: Callable[[str], dict[str, Any]] | None = None,
) -> str | None:
    """The Graph site id of the census site at ``web_url`` (its asset
    location), from the same bounded listing the census reads; ``None`` when
    that page does not contain it. Reads only."""
    wanted = str(web_url or "").strip().rstrip("/").lower()
    if not wanted:
        return None
    for row in _sharepoint_site_rows(search, fetcher)[:_MAX_SITES]:
        if not isinstance(row, dict):
            continue
        if str(row.get("webUrl") or "").strip().rstrip("/").lower() != wanted:
            continue
        site_id = str(row.get("id") or "").strip()
        return site_id if _GRAPH_ID_RE.fullmatch(site_id) else None
    return None


def sync_sharepoint_sites(
    *,
    actor: str,
    owner: str,
    search: str = "",
    fetcher: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, int]:
    """Enumerate SharePoint sites via Microsoft Graph into site assets.

    Uses ``GET /sites?search={query}`` when a query is given, else
    ``GET /sites/getAllSites`` (both need the ``Sites.Read.All``
    application permission). One page, bounded — a census, not a crawler.
    """

    rows = _sharepoint_site_rows(search, fetcher)
    imported = 0
    skipped = 0
    for row in rows[:_MAX_SITES]:
        if not isinstance(row, dict):
            skipped += 1
            continue
        name = str(
            row.get("displayName") or row.get("name") or ""
        ).strip()
        if not name:
            skipped += 1
            continue
        try:
            register_data_asset(
                name,
                system="sharepoint",
                kind="site",
                owner=owner,
                actor=actor,
                location=str(row.get("webUrl") or "").strip(),
                source="microsoft_graph",
            )
            imported += 1
        except Exception:
            skipped += 1
    return {"imported": imported, "skipped": skipped}


def _default_graph_download(url: str, token: str) -> bytes:
    """Download one drive item's BYTES through the SSRF-pinned client.

    Bytes, not text: an OOXML container or PDF has to reach the extractor
    intact, and a text file is decoded by the caller that knows its kind.

    ``GET .../content`` answers ``302 Found`` with a preauthenticated
    download URL in ``Location`` (no Authorization header on that hop --
    sending the bearer to a non-Graph host would leak it). The pinned
    client never follows redirects itself; the one expected hop is
    re-validated through ``safe_client`` like any other URL.
    """

    from .enterprise import enterprise_egress_denial
    from .tools._ssrf import BlockedHost, safe_client

    deny = enterprise_egress_denial(url, tool="data_map")
    if deny:
        raise DataMapError(deny)
    try:
        with safe_client(url, timeout=_GRAPH_TIMEOUT_SECONDS) as client:
            response = client.get(
                url, headers={"Authorization": f"Bearer {token}"}
            )
        if response.status_code in (301, 302, 307, 308):
            target = str(response.headers.get("location") or "")
            if not target.startswith("https://"):
                raise DataMapError(
                    "Microsoft Graph redirected to a non-https URL")
            deny = enterprise_egress_denial(target, tool="data_map")
            if deny:
                raise DataMapError(deny)
            with safe_client(target, timeout=_GRAPH_TIMEOUT_SECONDS) as hop:
                response = hop.get(target)
    except BlockedHost as exc:
        raise DataMapError("blocked host (SSRF guard)") from exc
    if response.status_code != 200:
        raise DataMapError(
            f"file download returned HTTP {response.status_code}")
    return response.content[:_MAX_FILE_BYTES]


def _classify_files(
    candidates,
    fetch,
    *,
    listed: int,
) -> dict[str, Any]:
    """Sample listed files, classify each, and return EVIDENCE only.

    ``candidates`` yields ``(name, key, size)``; ``fetch(key)`` returns the
    file's bytes or raises :class:`DataMapError`. Shared by every backing
    store so the sampling bounds, the routing between plain text and the
    stdlib document extractor, and the "unreadable is NOT clean" rule are
    written once and cannot drift apart per connector.
    """

    from .content_classifier import classify_text

    # The same hardened extractor the DPA and vendor-paper pipelines use --
    # imported at call time to keep the module graph acyclic.
    from .privacy_ops import _document_text

    counts: dict[str, int] = {}
    flagged_files: list[dict[str, Any]] = []
    sampled = 0
    skipped = 0
    for name, key, size in candidates:
        lowered = str(name or "").lower()
        suffix = f".{lowered.rsplit('.', 1)[-1]}" if "." in lowered else ""
        document_mime = _DOCUMENT_FILE_MIMES.get(suffix)
        if ((suffix not in _TEXT_FILE_SUFFIXES and document_mime is None)
                or size > _MAX_FILE_BYTES):
            skipped += 1
            continue
        try:
            payload = fetch(key)
        except DataMapError:
            skipped += 1
            continue
        if document_mime is None:
            sample = payload.decode("utf-8", errors="replace")
        else:
            sample = _document_text(payload, document_mime)
            if not sample.strip():
                # An unreadable container (a scanned PDF, an encrypted or
                # bomb-shaped OOXML) is NOT evidence that the file is clean.
                # Count it as skipped so the record can never imply coverage
                # the scan did not actually have.
                skipped += 1
                continue
        sampled += 1
        report = classify_text(sample[:_MAX_FILE_SAMPLE_CHARS])
        if report["categories"]:
            flagged_files.append(
                {"name": str(name)[:256], "categories": report["categories"]})
        for category, n in report["counts"].items():
            counts[category] = counts.get(category, 0) + int(n)
    return {
        "counts": counts,
        "categories": sorted(counts),
        "files_listed": listed,
        "files_sampled": sampled,
        "files_skipped": skipped,
        "flagged_files": flagged_files[:_MAX_FILES_SCANNED],
    }


def _record_file_scan(asset_id: str, evidence: dict[str, Any], *,
                      scope: dict[str, Any], action: str,
                      operator: str, expected_revision: int) -> dict[str, Any]:
    """Merge one scan's evidence into the asset under CAS."""

    found = evidence["categories"]

    def mutate(value: dict[str, Any]) -> None:
        merged = sorted(set(value.get("categories") or []) | set(found))
        value["categories"] = merged
        value["content_categories"] = found
        value["content_counts"] = dict(sorted(evidence["counts"].items()))
        value["content_verified_at"] = time.time()
        value["content_verified_by"] = operator
        value["special_category"] = bool(
            SPECIAL_CATEGORIES.intersection(merged))
        value["file_scan"] = {
            **scope,
            "files_listed": evidence["files_listed"],
            "files_sampled": evidence["files_sampled"],
            "files_skipped": evidence["files_skipped"],
            "flagged_files": evidence["flagged_files"],
        }

    saved = _ASSETS.update(
        _text(asset_id, "asset_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action=action,
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"data asset is not registered: {asset_id}")
    return dict(saved)


def scan_sharepoint_site_files(
    asset_id: str,
    *,
    site_id: str,
    actor: str,
    expected_revision: int,
    fetcher: Callable[[str], dict[str, Any]] | None = None,
    downloader: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Content-scan a SharePoint site's document library into its asset.

    Lists ``GET /sites/{site-id}/drive/root/children`` (application
    permission ``Files.Read.All``; ``Sites.Read.All`` also grants it), then
    samples up to ``_MAX_FILES_SCANNED`` readable files via
    ``GET .../items/{id}/content`` and runs the deterministic content
    classifier over each. Readable means plain-text formats plus the
    documents the stdlib extractor handles -- docx, xlsx, pptx and PDF
    content streams -- so the register covers the formats a policy
    document, an HR roster or an export actually arrives in. What lands on
    the asset is EVIDENCE, not content: per-category counts, which file
    names were flagged, and the verification stamp -- never a byte of the
    files themselves.

    ``site_id`` is the Graph site identifier from the census
    (``sync_sharepoint_sites``). One listing page, bounded -- a sample,
    not a crawler; ``skipped`` counts what the bounds excluded.
    """

    settings = _require_enabled()
    operator = _text(actor, "actor", 256)
    site = str(site_id or "").strip()
    if not _GRAPH_ID_RE.fullmatch(site):
        raise ValueError("site_id must be a Microsoft Graph site identifier")
    if fetcher is None or downloader is None:
        token = graph_token(settings["graph_token_env"])
        if not token:
            raise DataMapConfigError(
                "the SharePoint file scan needs a Microsoft Graph token in "
                f"${settings['graph_token_env']} (Files.Read.All)"
            )
        if fetcher is None:
            def fetcher(target: str) -> dict[str, Any]:
                return _default_graph_fetch(target, token)
        if downloader is None:
            def downloader(target: str) -> bytes:
                return _default_graph_download(target, token)

    listing = fetcher(
        f"{_GRAPH_ROOT}/sites/{site}/drive/root/children"
        f"?$top={_MAX_FILES_SCANNED}")
    rows = listing.get("value")
    if not isinstance(rows, list):
        raise DataMapError("Microsoft Graph returned an unexpected shape")

    def candidates():
        for row in rows[:_MAX_FILES_SCANNED]:
            if not isinstance(row, dict) or "file" not in row:
                yield "", "", _MAX_FILE_BYTES + 1      # counted as skipped
                continue
            item_id = str(row.get("id") or "")
            if not _GRAPH_ID_RE.fullmatch(item_id):
                # A hostile id must never be spliced into a request path.
                yield "", "", _MAX_FILE_BYTES + 1
                continue
            yield (str(row.get("name") or ""), item_id,
                   int(row.get("size") or 0))

    evidence = _classify_files(
        candidates(),
        lambda item_id: downloader(
            f"{_GRAPH_ROOT}/sites/{site}/drive/items/{item_id}/content"),
        listed=len(rows),
    )
    return _record_file_scan(
        asset_id, evidence, scope={"site_id": site},
        action="scan_sharepoint_site_files",
        operator=operator, expected_revision=expected_revision)


def scan_s3_bucket_objects(
    asset_id: str,
    *,
    bucket: str,
    prefix: str = "",
    actor: str,
    expected_revision: int,
    lister: Callable[[str, str], list[dict[str, Any]]] | None = None,
    getter: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Content-scan one bounded page of an S3 prefix into its asset.

    Same contract as the SharePoint scan and the same shared core: one
    listing page (``ListObjectsV2``, ``MaxKeys`` bounded), bounded samples
    of the readable formats, and EVIDENCE only on the record -- category
    counts and flagged object KEYS, never object bytes. Reads only:
    ``s3:ListBucket`` and ``s3:GetObject``.

    The AWS client is the platform's existing optional ``[s3]`` extra,
    imported lazily; tests inject ``lister``/``getter`` instead, so the
    scan is exercised with no cloud account and no credentials.
    """

    _require_enabled()
    operator = _text(actor, "actor", 256)
    bucket_name = _text(bucket, "bucket", 255)
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,253}[a-z0-9]", bucket_name):
        raise ValueError("bucket must be a valid S3 bucket name")
    key_prefix = str(prefix or "")[:512]
    if "\x00" in key_prefix:
        raise ValueError("prefix must not contain NUL")

    if lister is None or getter is None:
        try:
            import boto3
        except ImportError as exc:      # pragma: no cover - optional extra
            raise DataMapConfigError(
                "the S3 object scan needs the [s3] extra (boto3); install it "
                "or inject a lister/getter"
            ) from exc
        client = boto3.client("s3")
        if lister is None:
            def lister(name: str, where: str) -> list[dict[str, Any]]:
                page = client.list_objects_v2(
                    Bucket=name, Prefix=where, MaxKeys=_MAX_FILES_SCANNED)
                return list(page.get("Contents") or [])
        if getter is None:
            def getter(key: str) -> bytes:
                body = client.get_object(Bucket=bucket_name, Key=key)["Body"]
                return body.read(_MAX_FILE_BYTES)

    objects = lister(bucket_name, key_prefix)
    if not isinstance(objects, list):
        raise DataMapError("the S3 listing returned an unexpected shape")

    def candidates():
        for row in objects[:_MAX_FILES_SCANNED]:
            if not isinstance(row, dict):
                yield "", "", _MAX_FILE_BYTES + 1
                continue
            key = str(row.get("Key") or "")
            if not key or key.endswith("/"):        # a folder marker
                yield "", "", _MAX_FILE_BYTES + 1
                continue
            yield key, key, int(row.get("Size") or 0)

    def fetch(key: str) -> bytes:
        try:
            return getter(key)
        except DataMapError:
            raise
        except Exception as exc:        # an unreadable object is a skip
            raise DataMapError(f"s3 object unreadable: {type(exc).__name__}") from exc

    evidence = _classify_files(candidates(), fetch, listed=len(objects))
    return _record_file_scan(
        asset_id, evidence,
        scope={"bucket": bucket_name, "prefix": key_prefix},
        action="scan_s3_bucket_objects",
        operator=operator, expected_revision=expected_revision)


__all__ = [
    "ASSET_KINDS",
    "ASSET_SCHEMA",
    "CLASSIFIER_CATEGORIES",
    "DataMapConfigError",
    "DataMapError",
    "IDENTIFYING_CATEGORIES",
    "LINK_KINDS",
    "classify_asset_content",
    "masking_policy_sql",
    "SPECIAL_CATEGORIES",
    "classify_column",
    "classify_columns",
    "data_map_posture",
    "enabled",
    "find_sharepoint_site_id",
    "get_data_asset",
    "get_data_map_config",
    "import_information_schema_csv",
    "link_asset_record",
    "list_data_assets",
    "register_data_asset",
    "scan_s3_bucket_objects",
    "scan_sharepoint_site_files",
    "sync_sharepoint_sites",
]
