"""Privacy-bounded analytics over immutable consumer-consent receipts.

This module is read-only with respect to the consent authority.  It emits
aggregate event trends, suppresses cohorts below an explicit unique-profile
threshold, and labels bounded/truncated source reads rather than implying that
a partial result is complete.  Profile and subject identifiers are never part
of an analytics result.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import consent_storage
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

ANALYTICS_SCHEMA = "lightwork.consent-analytics.v1"
_DIMENSIONS = frozenset(
    {
        "purpose_id",
        "action",
        "channel",
        "vendor_id",
        "country_code",
        "region_code",
        "privacy_signal",
        "policy_id",
        "policy_version",
        "day",
    }
)
_MAX_DIMENSIONS = 4
_MAX_RECEIPTS = 100_000
_MAX_ROWS = 10_000
_MAX_JSON_BYTES = 2 * 1_024 * 1_024


class ConsentAnalyticsError(RuntimeError):
    """Base analytics error."""


class ConsentAnalyticsConfigError(ConsentAnalyticsError):
    """Analytics is not explicitly enabled."""


class ConsentAnalyticsValidationError(ConsentAnalyticsError, ValueError):
    """An analytics request is outside the closed contract."""


class ConsentAnalyticsUnavailable(ConsentAnalyticsError):
    """The receipt authority is missing or corrupt."""


def enabled() -> bool:
    """Return true only when consent and analytics are independently enabled."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    consent = config.get("consent_preferences")
    if not isinstance(consent, Mapping) or consent.get("enable") is not True:
        return False
    analytics = consent.get("analytics")
    return isinstance(analytics, Mapping) and analytics.get("enable") is True


_DEFAULT_COHORT = 10
_MIN_COHORT = 2


def analytics_limits(config: Mapping[str, Any] | None = None) -> tuple[int, int, int | None]:
    """``(default cohort, smallest cohort, look-back days)`` for this installation.

    ``[consent_preferences.analytics] min_cohort_size`` is both the default and
    the floor: a request may ask for a larger cohort, never a smaller one.
    Unset keeps the historical default of 10 with requests allowed down to 2.
    ``retention_days`` limits how far back a snapshot may read receipts; unset
    means no look-back limit (the historical behaviour).
    """
    if config is None:
        from .config import load_config

        config = load_config() or {}
    consent = config.get("consent_preferences") if isinstance(config, Mapping) else None
    section = consent.get("analytics") if isinstance(consent, Mapping) else None
    section = section if isinstance(section, Mapping) else {}
    default, floor = _DEFAULT_COHORT, _MIN_COHORT
    if "min_cohort_size" in section:
        try:
            floor = default = _integer(
                section["min_cohort_size"], "analytics min_cohort_size", 2, 100_000
            )
        except ConsentAnalyticsValidationError as exc:
            raise ConsentAnalyticsConfigError(str(exc)) from exc
    lookback = None
    if "retention_days" in section:
        try:
            lookback = _integer(section["retention_days"], "analytics retention_days", 1, 3_650)
        except ConsentAnalyticsValidationError as exc:
            raise ConsentAnalyticsConfigError(str(exc)) from exc
    return default, floor, lookback


def require_enabled() -> None:
    if not enabled():
        raise ConsentAnalyticsConfigError(
            "consent analytics is disabled; enable [consent_preferences] and "
            "[consent_preferences.analytics] explicitly"
        )


def _canonical(value: object) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentAnalyticsValidationError(
            "analytics data must be finite JSON"
        ) from exc
    if len(payload) > _MAX_JSON_BYTES:
        raise ConsentAnalyticsValidationError("analytics result exceeds 2 MiB")
    return payload


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise ConsentAnalyticsValidationError("tenant_id is invalid") from exc


def _timestamp(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConsentAnalyticsValidationError(f"{field} must be a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ConsentAnalyticsValidationError(f"{field} must be a finite timestamp")
    return result


def _integer(value: object, field: str, lower: int, upper: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not lower <= value <= upper
    ):
        raise ConsentAnalyticsValidationError(
            f"{field} must be an integer between {lower} and {upper}"
        )
    return value


def _dimensions(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not 1 <= len(value) <= _MAX_DIMENSIONS:
        raise ConsentAnalyticsValidationError("dimensions count is invalid")
    result: list[str] = []
    for item in value:
        if item not in _DIMENSIONS:
            raise ConsentAnalyticsValidationError(
                f"unsupported analytics dimension: {item!r}"
            )
        if item in result:
            raise ConsentAnalyticsValidationError("analytics dimensions must be unique")
        result.append(item)
    return tuple(result)


def _loads(value: object, field: str) -> Any:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1_048_576:
        raise ConsentAnalyticsUnavailable(f"stored {field} is invalid")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ConsentAnalyticsUnavailable(f"stored {field} is invalid") from exc


@dataclass(frozen=True)
class AnalyticsCell:
    dimensions: dict[str, str | int | None]
    unique_profiles: int
    receipt_events: int
    choice_events: int


@dataclass(frozen=True)
class AnalyticsSnapshot:
    schema: str
    tenant_sha256: str
    start_at: float
    end_at: float
    dimensions: tuple[str, ...]
    min_cohort_size: int
    cells: tuple[AnalyticsCell, ...]
    suppressed_cells: int
    source_profile_count: int | None
    source_receipt_count: int | None
    source_truncated: bool
    complete: bool
    limitations: tuple[str, ...]
    snapshot_sha256: str


class ConsentAnalytics:
    """Read and aggregate one tenant's immutable consent receipts."""

    def __init__(self, consent_database: str | Path) -> None:
        self.path = Path(consent_database)

    def _connect(self) -> sqlite3.Connection:
        if consent_storage.shared():
            if not consent_storage.store_exists(self.path):
                raise ConsentAnalyticsUnavailable("consent receipt authority is unavailable")
            try:
                conn = consent_storage.connect(self.path, timeout=5, read_only=True)
            except (consent_storage.ConsentStorageError, sqlite3.Error) as exc:
                raise ConsentAnalyticsUnavailable(
                    "consent receipt authority is unavailable"
                ) from exc
            conn.row_factory = sqlite3.Row
            return conn
        if not self.path.is_file():
            raise ConsentAnalyticsUnavailable("consent receipt authority is unavailable")
        try:
            conn = sqlite3.connect(
                f"{self.path.resolve().as_uri()}?mode=ro",
                uri=True,
                timeout=5,
                factory=ClosingConnection,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")
            return conn
        except sqlite3.Error as exc:
            raise ConsentAnalyticsUnavailable(
                "consent receipt authority is unavailable"
            ) from exc

    @staticmethod
    def _dimension_value(
        dimension: str,
        *,
        row: sqlite3.Row,
        context: dict[str, Any],
        choice: dict[str, Any],
    ) -> str | int | None:
        if dimension in {"purpose_id", "action", "channel", "vendor_id"}:
            value = choice.get(dimension)
        elif dimension in {"country_code", "region_code"}:
            geolocation = context.get("geolocation")
            value = geolocation.get(dimension) if isinstance(geolocation, dict) else None
        elif dimension == "privacy_signal":
            value = context.get("privacy_signal")
        elif dimension == "policy_id":
            value = row["policy_id"]
        elif dimension == "policy_version":
            return int(row["policy_version"])
        else:
            return (
                datetime.fromtimestamp(float(row["created_at"]), timezone.utc)
                .date()
                .isoformat()
            )
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > 128:
            raise ConsentAnalyticsUnavailable("stored analytics dimension is invalid")
        return value

    def snapshot(  # noqa: C901
        self,
        tenant_id: str,
        start_at: float,
        end_at: float,
        dimensions: Sequence[str],
        *,
        min_cohort_size: int | None = None,
        max_receipts: int = 10_000,
        max_rows: int = 1_000,
    ) -> AnalyticsSnapshot:
        require_enabled()
        tenant = _tenant_id(tenant_id)
        start = _timestamp(start_at, "start_at")
        end = _timestamp(end_at, "end_at")
        if end <= start:
            raise ConsentAnalyticsValidationError("end_at must be later than start_at")
        selected = _dimensions(dimensions)
        default_cohort, smallest_cohort, lookback_days = analytics_limits()
        requested = (
            default_cohort
            if min_cohort_size is None
            else _integer(min_cohort_size, "min_cohort_size", 2, 100_000)
        )
        # The installation's smallest cohort is a privacy floor: a request can
        # only suppress more, never less.
        cohort = max(requested, smallest_cohort)
        window_limited = False
        if lookback_days is not None:
            earliest = time.time() - lookback_days * 86_400
            if start < earliest:
                start, window_limited = earliest, True
            if end <= start:
                raise ConsentAnalyticsValidationError(
                    "the requested period is older than the analytics look-back limit"
                )
        receipt_limit = _integer(max_receipts, "max_receipts", 1, _MAX_RECEIPTS)
        row_limit = _integer(max_rows, "max_rows", 1, _MAX_ROWS)

        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT sequence, profile_id, policy_id, policy_version, "
                    "context_json, choices_json, created_at FROM consent_receipts "
                    "WHERE tenant = ? AND created_at >= ? AND created_at < ? "
                    "ORDER BY sequence LIMIT ?",
                    (tenant, start, end, receipt_limit + 1),
                ).fetchall()
        except sqlite3.Error as exc:
            raise ConsentAnalyticsUnavailable("consent receipts cannot be read") from exc

        source_truncated = len(rows) > receipt_limit
        rows = rows[:receipt_limit]
        source_profiles = {str(row["profile_id"]) for row in rows}
        profile_sets: dict[tuple[object, ...], set[str]] = defaultdict(set)
        receipts: dict[tuple[object, ...], set[int]] = defaultdict(set)
        choices_by_cell: dict[tuple[object, ...], int] = defaultdict(int)

        for row in rows:
            context = _loads(row["context_json"], "receipt context")
            choices = _loads(row["choices_json"], "receipt choices")
            if not isinstance(context, dict) or not isinstance(choices, list):
                raise ConsentAnalyticsUnavailable("stored receipt shape is invalid")
            if len(choices) > 128:
                raise ConsentAnalyticsUnavailable("stored receipt choices are unbounded")
            for choice in choices:
                if not isinstance(choice, dict):
                    raise ConsentAnalyticsUnavailable("stored receipt choice is invalid")
                key = tuple(
                    self._dimension_value(
                        dimension,
                        row=row,
                        context=context,
                        choice=choice,
                    )
                    for dimension in selected
                )
                profile_sets[key].add(str(row["profile_id"]))
                receipts[key].add(int(row["sequence"]))
                choices_by_cell[key] += 1

        cells: list[AnalyticsCell] = []
        suppressed = 0
        for key in sorted(profile_sets, key=lambda item: tuple(str(value) for value in item)):
            unique_profiles = len(profile_sets[key])
            if unique_profiles < cohort:
                suppressed += 1
                continue
            cells.append(
                AnalyticsCell(
                    dimensions=dict(zip(selected, key, strict=True)),
                    unique_profiles=unique_profiles,
                    receipt_events=len(receipts[key]),
                    choice_events=choices_by_cell[key],
                )
            )
        row_truncated = len(cells) > row_limit
        cells = cells[:row_limit]
        below_global_threshold = len(source_profiles) < cohort
        limitations = [
            "event trends do not represent current preference state",
            "small cohorts are suppressed by unique profile count",
            "location and privacy signals are asserted collection context, not verified facts",
        ]
        if window_limited:
            limitations.append("start moved to the installation's analytics look-back limit")
        if source_truncated:
            limitations.append("source receipt limit reached; aggregates are partial")
        if row_truncated:
            limitations.append("result row limit reached; aggregates are partial")
        if below_global_threshold:
            cells = []
            limitations.append("entire result suppressed below the global cohort threshold")
        complete = not source_truncated and not row_truncated
        body = {
            "schema": ANALYTICS_SCHEMA,
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "start_at": start,
            "end_at": end,
            "dimensions": list(selected),
            "min_cohort_size": cohort,
            "cells": [asdict(cell) for cell in cells],
            "suppressed_cells": suppressed,
            "source_profile_count": (
                None if below_global_threshold else len(source_profiles)
            ),
            "source_receipt_count": None if below_global_threshold else len(rows),
            "source_truncated": source_truncated,
            "complete": complete,
            "limitations": limitations,
        }
        return AnalyticsSnapshot(
            schema=ANALYTICS_SCHEMA,
            tenant_sha256=body["tenant_sha256"],
            start_at=start,
            end_at=end,
            dimensions=selected,
            min_cohort_size=cohort,
            cells=tuple(cells),
            suppressed_cells=suppressed,
            source_profile_count=body["source_profile_count"],
            source_receipt_count=body["source_receipt_count"],
            source_truncated=source_truncated,
            complete=complete,
            limitations=tuple(limitations),
            snapshot_sha256=_sha256(body),
        )


__all__ = [
    "ANALYTICS_SCHEMA",
    "AnalyticsCell",
    "AnalyticsSnapshot",
    "ConsentAnalytics",
    "ConsentAnalyticsConfigError",
    "ConsentAnalyticsError",
    "ConsentAnalyticsUnavailable",
    "ConsentAnalyticsValidationError",
    "analytics_limits",
    "enabled",
    "require_enabled",
]
