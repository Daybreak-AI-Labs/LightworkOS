"""Scheduled bridge from deterministic finance probes into Security/GRC.

Each cycle opens a normal Security/GRC audit engagement, appends one
``needs_review`` control test per finance control, and creates the matching
evidence request.  Machine observations therefore reach the existing controls
and evidence workflow without promoting themselves into an audit verdict.
The return path consumes only human pass/fail tests backed by approved evidence
and the corresponding accepted evidence request.

The cycle authority is a tenant-scoped governed record with a deterministic
period ID.  That makes scheduler retries idempotent and keeps every mutation
revision-CAS and audit-outbox backed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from ..governed_records import GovernedRecordStore
from ..privacy_ops import RecordConflict, _actor_label

CONTROL_SET_VERSION = "lightwork-finance-controls-v1"
CYCLE_SCHEMA = "lightwork.finance-control-cycle.v1"
RECONCILE_STATE_SCHEMA = "lightwork.finance-control-reconcile-state.v1"
NON_OPINION_NOTICE = (
    "Automated control observation only. Every GRC test remains needs_review "
    "until a qualified human reviews and approves cited evidence."
)

_CYCLES = GovernedRecordStore(
    "finance_control_cycles", "FCT", "finance_control_test_cycle",
)
_RECONCILE_STATE = GovernedRecordStore(
    "finance_control_reconcile_state",
    "FCR",
    "finance_control_reconcile_state",
)
_RECONCILE_STATE_ID = "FCR-control-cycle-scan"

_MAX_DETAIL = 4_000
_MIN_INTERVAL = 300.0
_MAX_INTERVAL = 31 * 24 * 60 * 60.0
_DEFAULT_INTERVAL = 24 * 60 * 60.0
_DEFAULT_EVIDENCE_DUE_DAYS = 7
_CYCLE_LEASE_SECONDS = 300.0
_RECOVERABLE_CYCLE_STATUS = frozenset({"running", "failed"})
_GRC_RECONCILABLE_STATUS = frozenset(
    {
        "pending_human_evidence",
        "human_review_passed",
        "human_review_failed",
    }
)
_GRC_TERMINAL_STATUS = frozenset({"human_review_passed", "human_review_failed"})
_MAX_RECONCILE_BATCH = 500
_MAX_CYCLE_SUMMARY_SCAN = 5_000
_MAX_CYCLE_CURSOR = 512


@dataclass(frozen=True)
class FinanceControlObservation:
    """One bounded fact set presented to, but not decided for, GRC."""

    control_id: str
    title: str
    observed_state: str
    detail: str
    framework: str
    citations: tuple[str, ...]
    probe_version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["citations"] = list(self.citations)
        return value


def enabled() -> bool:
    try:
        from ..config import config_source_errors, load_global_config

        config = load_global_config()
        if config_source_errors(include_tenant=False):
            return False
        section = config.get("finance_operations")
        return isinstance(section, dict) and section.get("enable") is True
    except Exception:  # pragma: no cover - policy reads fail closed
        return False


def _section() -> dict[str, Any]:
    from ..config import load_config

    config = load_config() or {}
    value = config.get("finance_operations")
    return dict(value) if isinstance(value, dict) else {}


def schedule_config() -> dict[str, Any]:
    section = _section()
    raw_interval = section.get("control_test_interval_seconds", _DEFAULT_INTERVAL)
    if isinstance(raw_interval, bool) or not isinstance(raw_interval, (int, float)):
        raise ValueError("control_test_interval_seconds must be a number")
    interval = float(raw_interval)
    if not math.isfinite(interval) or interval < 0 or interval > _MAX_INTERVAL:
        raise ValueError(
            "control_test_interval_seconds must be zero or between 300 and 2678400"
        )
    if 0 < interval < _MIN_INTERVAL:
        raise ValueError(
            "control_test_interval_seconds must be zero or between 300 and 2678400"
        )
    raw_days = section.get("evidence_due_days", _DEFAULT_EVIDENCE_DUE_DAYS)
    if isinstance(raw_days, bool) or not isinstance(raw_days, int) or not 1 <= raw_days <= 365:
        raise ValueError("evidence_due_days must be an integer between 1 and 365")
    return {
        "interval_seconds": interval,
        "evidence_due_days": raw_days,
        "control_owner": str(section.get("control_owner") or "Finance Control Owner").strip()[:256],
    }


def _validated_execution_config(
    control_owner: object,
    evidence_due_days: object,
) -> dict[str, Any]:
    """Validate the durable configuration that governs one cycle's side effects."""
    if not isinstance(control_owner, str):
        raise ValueError("finance control cycle control_owner is invalid")
    owner = control_owner.strip()
    if not owner or owner != control_owner or len(owner) > 256:
        raise ValueError("finance control cycle control_owner is invalid")
    if (
        isinstance(evidence_due_days, bool)
        or not isinstance(evidence_due_days, int)
        or not 1 <= evidence_due_days <= 365
    ):
        raise ValueError("finance control cycle evidence_due_days is invalid")
    return {
        "control_owner": owner,
        "evidence_due_days": evidence_due_days,
    }


def _execution_config_from_schedule(
    config: Mapping[str, Any],
    *,
    fallback_owner: str,
) -> dict[str, Any]:
    """Freeze the effective owner and deadline policy for a newly claimed cycle."""
    configured_owner = str(config.get("control_owner") or "").strip()
    owner = configured_owner or _actor_label(fallback_owner)
    return _validated_execution_config(owner, config.get("evidence_due_days"))


def _cycle_execution_config(
    cycle: Mapping[str, Any],
    *,
    allow_legacy: bool,
) -> dict[str, Any] | None:
    """Load and validate a cycle's immutable execution-policy snapshot.

    Pre-snapshot records omitted both fields. Recoverable legacy cycles may be
    backfilled once under their recovery CAS; a partially present snapshot is
    corruption and always fails closed.
    """
    has_owner = "control_owner" in cycle
    has_due_days = "evidence_due_days" in cycle
    if not has_owner and not has_due_days:
        if allow_legacy:
            return None
        raise ValueError("finance control cycle execution configuration is missing")
    if not has_owner or not has_due_days:
        raise ValueError("finance control cycle execution configuration is incomplete")
    return _validated_execution_config(
        cycle.get("control_owner"),
        cycle.get("evidence_due_days"),
    )


def _bounded(value: object, limit: int = _MAX_DETAIL) -> str:
    return str(value or "").strip()[:limit]


def _status_observations() -> list[FinanceControlObservation]:
    from .status import finance_status

    control_ids = {
        "Segregation of duties (roster)": "FIN-SOD-01",
        "Maker-checker on money movement": "FIN-MC-01",
        "Amount-aware authorization (DoA tiers)": "FIN-DOA-01",
        "Tamper-evident book of record": "FIN-AUD-01",
        "Sanctions screening": "FIN-AML-01",
        "Encryption at rest": "FIN-DATA-01",
        "Data-egress lock": "FIN-EGR-01",
        "Compliance regimes enabled": "FIN-REGIME-01",
    }
    rows: list[FinanceControlObservation] = []
    for check in finance_status():
        control_id = control_ids.get(check.control)
        if not control_id:
            continue
        rows.append(
            FinanceControlObservation(
                control_id=control_id,
                title=check.control,
                observed_state=check.status,
                detail=_bounded(check.detail),
                framework=str(check.regulation or "Finance controls")[:500],
                citations=(
                    "urn:lightwork:finance-status",
                    "urn:lightwork:finance-regimes",
                ),
            )
        )
    return rows


def _aml_freshness_observation(now: float) -> FinanceControlObservation:
    from .aml_screening import ScreeningIncompleteError, list_versions

    section = _section()
    max_age_hours = section.get("sanctions_max_age_hours", 72)
    if isinstance(max_age_hours, bool) or not isinstance(max_age_hours, (int, float)):
        max_age_hours = 72
    max_age_hours = max(1.0, min(float(max_age_hours), 24 * 365.0))
    try:
        rows = list_versions(list_kind="sanctions", limit=10_001)
    except ScreeningIncompleteError:
        rows = [None] * 10_001
    if len(rows) > 10_000:
        return FinanceControlObservation(
            "FIN-AML-02",
            "Sanctions-list provenance and freshness",
            "action_needed",
            "Governed sanctions-list inventory exceeds the 10,000-version "
            "completeness bound; freshness was not inferred from a truncated set.",
            "AML / BSA / OFAC",
            ("https://ofac.treasury.gov/sanctions-list-service",),
        )
    if not rows:
        return FinanceControlObservation(
            "FIN-AML-02",
            "Sanctions-list provenance and freshness",
            "action_needed",
            "No governed sanctions-list version is available.",
            "AML / BSA / OFAC",
            ("https://ofac.treasury.gov/sanctions-list-service",),
        )
    latest = max(
        rows,
        key=lambda row: float((row.get("provenance") or {}).get("retrieved_at") or 0),
    )
    retrieved = float((latest.get("provenance") or {}).get("retrieved_at") or 0)
    age_hours = max(0.0, (now - retrieved) / 3600.0) if retrieved else math.inf
    current = age_hours <= max_age_hours
    return FinanceControlObservation(
        "FIN-AML-02",
        "Sanctions-list provenance and freshness",
        "active" if current else "action_needed",
        (
            f"Latest governed list {latest.get('id')} version {latest.get('version')} "
            f"was retrieved {age_hours:.1f} hours ago; configured ceiling is "
            f"{max_age_hours:.1f} hours. SHA-256 {latest.get('content_sha256')}."
        ),
        "AML / BSA / OFAC",
        (str((latest.get("provenance") or {}).get("source_ref") or "urn:missing"),),
    )


def _regulatory_observation() -> FinanceControlObservation:
    from ..paths import data_dir
    from .regulatory_change import RegulatoryChangeEngine

    engine = RegulatoryChangeEngine(
        data_dir("finance_operations", "regulatory_change.sqlite3")
    )
    alerts = engine.list_alerts(limit=500)
    cited = [
        str(citation.url or citation.feed_url)
        for alert in alerts
        for citation in alert.citations
    ]
    citations = tuple(dict.fromkeys(value for value in cited if value))[:10]
    return FinanceControlObservation(
        "FIN-RCM-01",
        "Regulatory-change intake and review queue",
        "active" if alerts else "needs_review",
        (
            f"Deterministic regulatory queue is readable with {len(alerts)} bounded "
            "alert(s); an empty queue does not by itself prove feed freshness."
        ),
        "Regulatory change management",
        citations or ("https://www.federalregister.gov/developers/documentation/api/v1",),
    )


def _licensing_observation() -> FinanceControlObservation:
    from .licensing import load_licensing_pack, validate_licensing_pack

    verticals = ("money_transmitter", "insurance_producer")
    digests: list[str] = []
    citations: list[str] = []
    for vertical in verticals:
        pack = load_licensing_pack(vertical)
        validate_licensing_pack(pack)
        digests.append(f"{vertical}={pack.content_sha256}")
        for requirement in pack.requirements:
            citations.extend(citation.url for citation in requirement.citations)
    return FinanceControlObservation(
        "FIN-LIC-01",
        "State licensing data-pack integrity",
        "action_needed",
        (
            "Validated 50-state versioned packs for source routing, but all legal "
            "determinations still require jurisdiction-specific review: "
            + ", ".join(digests)
        ),
        "State licensing",
        tuple(dict.fromkeys(citations))[:10] or ("urn:lightwork:licensing-pack",),
    )


def _anomaly_observation() -> FinanceControlObservation:
    section = _section()
    configured = section.get("anomaly_enable", True) is True
    try:
        from .anomaly_engine import FinanceAnomalyConfig

        # Constructor validation is itself a deterministic readiness check; it
        # does not claim a population was scanned or a finding was cleared.
        FinanceAnomalyConfig()
        ready = configured
        detail = (
            "Deterministic duplicate-payment, Benford eligibility, approval-"
            "threshold, split-payment, and off-hours rules are loadable. "
            "Operating effectiveness still requires cited run evidence."
        )
    except Exception as exc:  # failure is safe to expose only by type
        ready = False
        detail = f"Finance anomaly rules are unavailable ({type(exc).__name__})."
    return FinanceControlObservation(
        "FIN-ANO-01",
        "Deterministic finance anomaly monitoring",
        "active" if ready else "action_needed",
        detail,
        "Finance monitoring",
        ("urn:lightwork:finance-anomaly-rules-v1",),
    )


def default_observations(*, now: float | None = None) -> list[FinanceControlObservation]:
    """Collect bounded observations; a failed probe becomes visible degradation."""
    observed_at = time.time() if now is None else float(now)
    rows = _status_observations()
    probes: tuple[tuple[str, str, Callable[[], FinanceControlObservation]], ...] = (
        ("FIN-AML-02", "Sanctions-list provenance and freshness", lambda: _aml_freshness_observation(observed_at)),
        ("FIN-RCM-01", "Regulatory-change intake and review queue", _regulatory_observation),
        ("FIN-LIC-01", "State licensing data-pack integrity", _licensing_observation),
        ("FIN-ANO-01", "Deterministic finance anomaly monitoring", _anomaly_observation),
    )
    for control_id, title, probe in probes:
        try:
            rows.append(probe())
        except Exception as exc:  # visible, redacted degradation
            rows.append(
                FinanceControlObservation(
                    control_id,
                    title,
                    "probe_error",
                    f"Probe failed safely ({type(exc).__name__}).",
                    "Finance controls",
                    ("urn:lightwork:finance-control-probe",),
                )
            )
    return rows


def _validate_observations(
    values: Iterable[FinanceControlObservation | Mapping[str, Any]],
) -> list[FinanceControlObservation]:
    rows: list[FinanceControlObservation] = []
    for value in values:
        if isinstance(value, FinanceControlObservation):
            row = value
        elif isinstance(value, Mapping):
            raw_citations = value.get("citations") or ()
            if not isinstance(raw_citations, (list, tuple)):
                raise ValueError("control observation citations must be a collection")
            row = FinanceControlObservation(
                control_id=str(value.get("control_id") or ""),
                title=str(value.get("title") or ""),
                observed_state=str(value.get("observed_state") or ""),
                detail=str(value.get("detail") or ""),
                framework=str(value.get("framework") or ""),
                citations=tuple(raw_citations),
                probe_version=str(value.get("probe_version") or "1.0.0"),
            )
        else:
            raise ValueError("control observations must be objects")
        if not row.control_id.strip() or not row.title.strip() or not row.observed_state.strip():
            raise ValueError("control observations require id, title, and state")
        if isinstance(row.citations, (str, bytes)) or any(
            not isinstance(item, str) for item in row.citations
        ):
            raise ValueError("control observation citations must be non-empty strings")
        citations = tuple(
            dict.fromkeys(
                item.strip()[:2_000]
                for item in row.citations
                if item.strip()
            )
        )[:20]
        if not citations:
            raise ValueError(f"control observation {row.control_id} requires a citation")
        rows.append(
            FinanceControlObservation(
                row.control_id.strip()[:80],
                row.title.strip()[:300],
                row.observed_state.strip()[:80],
                row.detail.strip()[:_MAX_DETAIL],
                row.framework.strip()[:500] or "Finance controls",
                citations,
                row.probe_version.strip()[:80] or "1.0.0",
            )
        )
    if not rows or len(rows) > 64:
        raise ValueError("one to 64 finance control observations are required")
    if len({row.control_id for row in rows}) != len(rows):
        raise ValueError("finance control observation ids must be unique")
    return rows


def _cycle_bucket(now: float, interval: float) -> int:
    period = interval or _DEFAULT_INTERVAL
    return int(now // period)


def _cycle_id(bucket: int, interval: float) -> str:
    digest = hashlib.sha256(
        f"{CONTROL_SET_VERSION}:{interval:.6f}:{bucket}".encode()
    ).hexdigest()[:32]
    return f"FCT-{digest}"


def list_cycles(*, limit: int = 500) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 10_001:
        raise ValueError("limit must be between 1 and 10001")
    rows = _CYCLES.list(limit=limit)
    for row in rows:
        _cycle_execution_config(row, allow_legacy=True)
    return rows


def get_cycle(cycle_id: str) -> dict[str, Any] | None:
    cycle = _CYCLES.get(str(cycle_id or "").strip())
    if cycle is not None:
        _cycle_execution_config(cycle, allow_legacy=True)
    return cycle


def _cycle_summary(cycle: Mapping[str, Any]) -> dict[str, Any]:
    """Project cycle queue metadata without observations or GRC workpapers."""

    _cycle_execution_config(cycle, allow_legacy=True)
    status = str(cycle.get("status") or "")
    if status not in _RECOVERABLE_CYCLE_STATUS | _GRC_RECONCILABLE_STATUS:
        raise ValueError("finance control cycle status is invalid")
    observations = cycle.get("observations")
    if not isinstance(observations, list) or len(observations) > 64:
        raise ValueError("finance control cycle observations are invalid")
    return {
        "id": cycle.get("id"),
        "schema": cycle.get("schema"),
        "status": status,
        "control_set_version": cycle.get("control_set_version"),
        "schedule_bucket": cycle.get("schedule_bucket"),
        "interval_seconds": cycle.get("interval_seconds"),
        "observed_at": cycle.get("observed_at"),
        "started_by": cycle.get("started_by"),
        "engagement_id": cycle.get("engagement_id"),
        "engagement_revision": cycle.get("engagement_revision"),
        "control_count": len(observations),
        "grc_result_counts": dict(cycle.get("grc_result_counts") or {}),
        "completed_at": cycle.get("completed_at"),
        "human_review_completed_at": cycle.get("human_review_completed_at"),
        "revision": cycle.get("revision"),
        "created_at": cycle.get("created_at"),
        "updated_at": cycle.get("updated_at"),
    }


def _encode_cycle_cursor(*, backend: str, position: str, cycle_id: str) -> str:
    payload = json.dumps(
        {
            "backend": backend,
            "cycle_id": cycle_id,
            "position": position,
            "v": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_cycle_cursor(
    cursor: str | None,
    *,
    backend: str,
) -> tuple[str, str]:
    if cursor in (None, ""):
        return "", ""
    if not isinstance(cursor, str) or len(cursor) > _MAX_CYCLE_CURSOR:
        raise ValueError("cycle summary cursor is invalid")
    try:
        raw = base64.b64decode(
            cursor + "=" * (-len(cursor) % 4),
            altchars=b"-_",
            validate=True,
        )
        value = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("cycle summary cursor is invalid") from exc
    if not isinstance(value, dict) or set(value) != {
        "backend",
        "cycle_id",
        "position",
        "v",
    }:
        raise ValueError("cycle summary cursor is invalid")
    position = value.get("position")
    cycle_id = value.get("cycle_id")
    if (
        value.get("v") != 1
        or value.get("backend") != backend
        or not isinstance(position, str)
        or len(position) > 256
        or not isinstance(cycle_id, str)
        or len(cycle_id) > 64
    ):
        raise ValueError("cycle summary cursor is invalid")
    return position, cycle_id


def list_cycle_summaries(
    *,
    limit: int = 100,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Return a hard-bounded metadata projection for cycle queue pages."""

    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= _MAX_CYCLE_SUMMARY_SCAN
    ):
        raise ValueError(
            f"cycle summary limit must be between 1 and {_MAX_CYCLE_SUMMARY_SCAN}"
        )
    backend = _CYCLES.backend_kind
    start_after, last_cycle_id = _decode_cycle_cursor(cursor, backend=backend)
    window = list(
        _CYCLES.iter_record_ids(
            start_after=start_after,
            limit=limit + 1,
        )
    )
    forward: list[tuple[str, str]] = []
    for position, cycle_id in window:
        if last_cycle_id and cycle_id <= last_cycle_id:
            break
        forward.append((position, cycle_id))
    selected = forward[:limit]
    rows: list[dict[str, Any]] = []
    for _position, cycle_id in selected:
        cycle = _CYCLES.get(cycle_id)
        if cycle is not None:
            rows.append(_cycle_summary(cycle))
    has_more = len(forward) > limit
    next_cursor = ""
    if has_more and selected:
        position, cycle_id = selected[-1]
        next_cursor = _encode_cycle_cursor(
            backend=backend,
            position=position,
            cycle_id=cycle_id,
        )
    return {
        "cycles": rows,
        "count_cap": limit,
        "truncated": has_more,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "record_reads": len(selected),
        "order": "cycle_id_ascending",
    }


def cycle_status_summary(*, scan_limit: int = 500) -> dict[str, Any]:
    """Count a hard-bounded scan while retaining no full cycle records."""

    page = list_cycle_summaries(limit=scan_limit)
    counts: dict[str, int] = {}
    for row in page["cycles"]:
        state = str(row["status"])
        counts[state] = counts.get(state, 0) + 1
    return {
        "total": len(page["cycles"]),
        "by_status": dict(sorted(counts.items())),
        "count_cap": scan_limit,
        "truncated": page["truncated"],
        "record_reads": page["record_reads"],
    }


def _procedure(
    row: FinanceControlObservation,
    observed_at: float,
    cycle_id: str,
) -> str:
    payload = {
        "automated_observation": row.to_dict(),
        "cycle_id": cycle_id,
        "observed_at": observed_at,
        "control_set_version": CONTROL_SET_VERSION,
        "required_human_result": True,
        "notice": NON_OPINION_NOTICE,
    }
    encode = lambda: json.dumps(  # noqa: E731 - closure keeps the bounded search clear
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    rendered = encode()
    if len(rendered) <= _MAX_DETAIL:
        return rendered

    observation = payload["automated_observation"]
    detail = str(observation.get("detail") or "")
    observation["detail_truncated"] = True
    observation["detail"] = ""
    rendered = encode()
    if len(rendered) > _MAX_DETAIL:
        raise ValueError(
            f"control observation {row.control_id} citations exceed procedure size limit"
        )
    low, high = 0, len(detail)
    best = rendered
    while low <= high:
        middle = (low + high) // 2
        observation["detail"] = detail[:middle]
        candidate = encode()
        if len(candidate) <= _MAX_DETAIL:
            best = candidate
            low = middle + 1
        else:
            high = middle - 1
    return best


def _engagement_marker(cycle_id: str) -> str:
    return f"Lightwork finance control cycle {cycle_id}"


def _engagement_id(cycle_id: str) -> str:
    digest = hashlib.sha256(f"finance-control:{cycle_id}".encode()).hexdigest()[:40]
    return f"AUD-{digest}"


def _engagement_scope(cycle_id: str) -> str:
    return (
        "Deterministic finance control observations routed for evidence-backed "
        "human testing. Machine output is not an audit opinion. Correlation: "
        f"{_engagement_marker(cycle_id)}."
    )


def _request_description(
    row: FinanceControlObservation,
    cycle_id: str,
) -> str:
    return (
        f"{_engagement_marker(cycle_id)}; provide and human-approve evidence for "
        f"{row.control_id} - {row.title}. Observation state: {row.observed_state}. "
        "Citations: " + ", ".join(row.citations)
    )[:2_000]


def _get_engagement(ops, engagement_id: str) -> dict[str, Any] | None:
    getter = getattr(ops, "get_audit_engagement", None)
    if not callable(getter):
        raise RuntimeError("GRC adapter cannot retrieve audit engagements")
    value = getter(engagement_id)
    return dict(value) if isinstance(value, Mapping) else None


def _refresh_engagement(ops, engagement: Mapping[str, Any]) -> dict[str, Any]:
    engagement_id = str(engagement.get("id") or "")
    refreshed = _get_engagement(ops, engagement_id)
    if refreshed is None:
        raise RuntimeError("GRC engagement disappeared during finance reconciliation")
    return refreshed


def _validate_cycle_engagement(
    engagement: Mapping[str, Any],
    cycle_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    if (
        engagement.get("id") != engagement_id
        or engagement.get("framework") != CONTROL_SET_VERSION
        or _engagement_marker(cycle_id) not in str(engagement.get("scope") or "")
    ):
        raise RuntimeError("GRC engagement correlation does not match finance cycle")
    return dict(engagement)


def _approved_evidence_ids(
    ops,
    values: object,
    *,
    cache: dict[str, dict[str, Any]],
    context: str,
) -> list[str]:
    """Resolve a bounded evidence set and fail closed unless every item is approved."""
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise RuntimeError(f"GRC {context} has an invalid evidence collection")
    if not values or len(values) > 256:
        raise RuntimeError(f"GRC {context} requires one to 256 evidence records")
    evidence_ids: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise RuntimeError(f"GRC {context} has an invalid evidence identifier")
        evidence_id = value.strip()
        if not evidence_id or evidence_id != value or len(evidence_id) > 80:
            raise RuntimeError(f"GRC {context} has an invalid evidence identifier")
        if evidence_id not in evidence_ids:
            evidence_ids.append(evidence_id)
    getter = getattr(ops, "get_evidence", None)
    if not callable(getter):
        raise RuntimeError("GRC adapter cannot verify control-test evidence")
    for evidence_id in evidence_ids:
        if evidence_id not in cache:
            evidence = getter(evidence_id)
            if not isinstance(evidence, Mapping):
                raise RuntimeError(f"GRC {context} cites unavailable evidence")
            cache[evidence_id] = dict(evidence)
        if cache[evidence_id].get("status") != "approved":
            raise RuntimeError(f"GRC {context} cites evidence that is not approved")
    return evidence_ids


def _terminal_grc_tests(
    ops,
    raw_tests: object,
    *,
    expected: set[str],
    evidence_cache: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not isinstance(raw_tests, (list, tuple)) or len(raw_tests) > 10_000:
        raise RuntimeError("GRC engagement control tests are invalid or unbounded")
    terminal_tests: dict[str, dict[str, Any]] = {}
    for raw_test in raw_tests:
        if not isinstance(raw_test, Mapping):
            raise RuntimeError("GRC engagement contains an invalid control test")
        control_id = str(raw_test.get("control_id") or "").strip()
        if control_id not in expected:
            continue
        result = str(raw_test.get("result") or "").lower()
        if result == "needs_review":
            continue
        if result not in {"pass", "fail"}:
            raise RuntimeError("GRC engagement contains an invalid control-test result")
        test_id = str(raw_test.get("id") or "").strip()
        tested_by = str(raw_test.get("tested_by") or "").strip()
        tested_at = raw_test.get("tested_at")
        if not test_id or len(test_id) > 80 or not tested_by or len(tested_by) > 256:
            raise RuntimeError("GRC terminal control test has invalid attribution")
        if (
            isinstance(tested_at, bool)
            or not isinstance(tested_at, (int, float))
            or not math.isfinite(float(tested_at))
            or float(tested_at) <= 0
        ):
            raise RuntimeError("GRC terminal control test has an invalid timestamp")
        evidence_ids = _approved_evidence_ids(
            ops,
            raw_test.get("evidence_ids"),
            cache=evidence_cache,
            context="terminal control test",
        )
        # Security/GRC workpapers are append-only. The last terminal test for a
        # control is consequently the current human disposition.
        terminal_tests[control_id] = {
            "control_id": control_id,
            "result": result,
            "test_id": test_id,
            "evidence_ids": evidence_ids,
            "tested_by": tested_by,
            "tested_at": float(tested_at),
        }
    return terminal_tests


def _accepted_grc_requests(
    ops,
    raw_requests: object,
    *,
    rows: list[FinanceControlObservation],
    cycle_id: str,
    evidence_cache: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not isinstance(raw_requests, (list, tuple)) or len(raw_requests) > 5_000:
        raise RuntimeError("GRC engagement evidence requests are invalid or unbounded")
    if any(not isinstance(request, Mapping) for request in raw_requests):
        raise RuntimeError("GRC engagement contains an invalid evidence request")
    for request in raw_requests:
        control_ids = request.get("control_ids") or []
        if (
            isinstance(control_ids, (str, bytes))
            or not isinstance(control_ids, (list, tuple))
            or len(control_ids) > 256
            or any(not isinstance(value, str) or not value.strip() for value in control_ids)
        ):
            raise RuntimeError("GRC evidence request has invalid control identifiers")

    accepted_requests: dict[str, dict[str, Any]] = {}
    for row in rows:
        description = _request_description(row, cycle_id)
        matches = [
            request
            for request in raw_requests
            if isinstance(request, Mapping)
            and request.get("description") == description
            and row.control_id in (request.get("control_ids") or ())
        ]
        if len(matches) > 1:
            raise RuntimeError("GRC engagement has duplicate finance evidence requests")
        if not matches:
            continue
        request = matches[0]
        request_status = str(request.get("status") or "open").lower()
        if request_status not in {"open", "submitted", "accepted", "rejected", "closed"}:
            raise RuntimeError("GRC finance evidence request has an invalid status")
        if request_status not in {"accepted", "closed"}:
            continue
        request_id = str(request.get("id") or "").strip()
        if not request_id or len(request_id) > 80:
            raise RuntimeError("GRC accepted evidence request has an invalid identifier")
        accepted_requests[row.control_id] = {
            "request_id": request_id,
            "evidence_ids": set(_approved_evidence_ids(
                ops,
                request.get("evidence_ids"),
                cache=evidence_cache,
                context="accepted finance evidence request",
            )),
        }
    return accepted_requests


def _grc_disposition_snapshot(
    cycle: Mapping[str, Any],
    engagement: Mapping[str, Any],
    *,
    ops,
) -> dict[str, Any]:
    """Derive the finance-side view of human GRC work without mutating GRC."""
    cycle_id = str(cycle.get("id") or "")
    engagement_id = str(cycle.get("engagement_id") or "")
    if (
        not engagement_id
        or engagement.get("id") != engagement_id
        or engagement.get("framework") != CONTROL_SET_VERSION
        or _engagement_marker(cycle_id) not in str(engagement.get("scope") or "")
    ):
        raise RuntimeError("GRC engagement correlation does not match finance cycle")
    revision = engagement.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise RuntimeError("GRC engagement revision is invalid")

    rows = _validate_observations(cycle.get("observations") or ())
    evidence_cache: dict[str, dict[str, Any]] = {}
    terminal_tests = _terminal_grc_tests(
        ops,
        engagement.get("control_tests") or [],
        expected={row.control_id for row in rows},
        evidence_cache=evidence_cache,
    )
    accepted_requests = _accepted_grc_requests(
        ops,
        engagement.get("evidence_requests") or [],
        rows=rows,
        cycle_id=cycle_id,
        evidence_cache=evidence_cache,
    )

    results: list[dict[str, Any]] = []
    pending: list[str] = []
    for row in rows:
        test = terminal_tests.get(row.control_id)
        request = accepted_requests.get(row.control_id)
        if test is None or request is None:
            pending.append(row.control_id)
            continue
        if not set(test["evidence_ids"]).issubset(request["evidence_ids"]):
            raise RuntimeError(
                "GRC terminal control test is not backed by its accepted evidence request"
            )
        results.append({**test, "evidence_request_id": request["request_id"]})

    passes = sum(result["result"] == "pass" for result in results)
    failures = sum(result["result"] == "fail" for result in results)
    status = "pending_human_evidence"
    if not pending:
        status = "human_review_failed" if failures else "human_review_passed"
    return {
        "status": status,
        "engagement_revision": revision,
        "engagement_status": str(engagement.get("status") or "planned")[:80],
        "grc_results": results,
        "grc_pending_control_ids": pending,
        "grc_result_counts": {
            "total": len(rows),
            "pass": passes,
            "fail": failures,
            "pending": len(pending),
        },
    }


def reconcile_control_cycle(
    cycle_id: str,
    *,
    actor: str,
    ops=None,
) -> dict[str, Any] | None:
    """Read human GRC dispositions back into one governed finance cycle."""
    if not enabled():
        raise RuntimeError("finance operations are disabled ([finance_operations] enable)")
    operator = str(actor or "").strip()
    if not operator:
        raise ValueError("actor is required")
    identifier = str(cycle_id or "").strip()
    if not identifier:
        raise ValueError("cycle_id is required")
    if ops is None:
        from .. import security_ops as ops
    ops_enabled = getattr(ops, "enabled", None)
    if not callable(ops_enabled) or not ops_enabled():
        raise RuntimeError("Security/GRC operations are disabled")

    for _attempt in range(3):
        cycle = _CYCLES.get(identifier)
        if cycle is None:
            return None
        _cycle_execution_config(cycle, allow_legacy=True)
        if cycle.get("status") not in _GRC_RECONCILABLE_STATUS:
            raise ValueError("finance control cycle is not ready for GRC reconciliation")
        engagement_id = str(cycle.get("engagement_id") or "")
        engagement = _get_engagement(ops, engagement_id)
        if engagement is None:
            raise RuntimeError("persisted GRC engagement is unavailable")
        snapshot = _grc_disposition_snapshot(cycle, engagement, ops=ops)
        stable_fields = (
            "status",
            "engagement_revision",
            "engagement_status",
            "grc_results",
            "grc_pending_control_ids",
            "grc_result_counts",
        )
        if all(cycle.get(field) == snapshot[field] for field in stable_fields):
            return cycle
        reconciled_at = _CYCLES.authoritative_time()

        def _mutate(
            record: dict[str, Any],
            disposition: Mapping[str, Any] = snapshot,
            stamped_at: float = reconciled_at,
        ) -> None:
            if record.get("status") not in _GRC_RECONCILABLE_STATUS:
                raise RecordConflict("finance control cycle is no longer reconcilable")
            previous_status = str(record.get("status") or "")
            record.update(disposition)
            record["grc_reconciled_at"] = stamped_at
            if disposition["status"] in _GRC_TERMINAL_STATUS:
                if previous_status != disposition["status"] or not record.get(
                    "human_review_completed_at"
                ):
                    record["human_review_completed_at"] = stamped_at
            elif previous_status in _GRC_TERMINAL_STATUS:
                record.pop("human_review_completed_at", None)
                record["human_review_reopened_at"] = stamped_at

        try:
            updated = _CYCLES.update(
                identifier,
                _mutate,
                expected_revision=cycle["revision"],
                action="reconcile_grc_dispositions",
                actor=operator,
            )
        except RecordConflict:
            continue
        if updated is None:
            raise RuntimeError("finance control cycle disappeared")
        return updated
    raise RecordConflict("finance control cycle changed during GRC reconciliation")


def _reconcile_scan_cursor() -> tuple[dict[str, Any] | None, str]:
    state = _RECONCILE_STATE.get(_RECONCILE_STATE_ID)
    if state is None:
        return None, ""
    cursor = state.get("cursor")
    if (
        state.get("schema") != RECONCILE_STATE_SCHEMA
        or state.get("status") != "active"
        or not isinstance(cursor, str)
        or len(cursor) > 256
    ):
        raise ValueError("finance control reconciliation cursor is invalid")
    return state, cursor


def _advance_reconcile_scan_cursor(
    state: dict[str, Any] | None,
    cursor: str,
    *,
    actor: str,
) -> None:
    if not cursor:
        return
    if state is None:
        try:
            _RECONCILE_STATE.create(
                {
                    "id": _RECONCILE_STATE_ID,
                    "schema": RECONCILE_STATE_SCHEMA,
                    "status": "active",
                    "cursor": cursor,
                },
                action="start_control_reconcile_scan",
                actor=actor,
            )
        except RecordConflict:
            # A concurrent scanner advanced the shared cursor. Repeating part
            # of the window on the next turn is safe and bounded.
            pass
        return

    def _mutate(record: dict[str, Any]) -> None:
        if (
            record.get("schema") != RECONCILE_STATE_SCHEMA
            or record.get("status") != "active"
        ):
            raise RecordConflict("finance control reconciliation cursor changed")
        record["cursor"] = cursor

    try:
        _RECONCILE_STATE.update(
            _RECONCILE_STATE_ID,
            _mutate,
            expected_revision=state["revision"],
            action="advance_control_reconcile_scan",
            actor=actor,
        )
    except RecordConflict:
        # Another scheduler completed a valid window first.
        pass


def reconcile_scheduled_cycles(
    *,
    actor: str,
    scan_limit: int = 100,
    priority_cycle_id: str = "",
    ops=None,
) -> list[dict[str, Any]]:
    """Reconcile a rotating bounded window and an optional current cycle.

    The backend-provided opaque cursor is tenant-governed, so more than 10,001
    records and multiple scheduler processes cannot permanently starve an old
    pending cycle or a later revision to a completed human disposition.
    """
    if not enabled():
        raise RuntimeError("finance operations are disabled ([finance_operations] enable)")
    if (
        isinstance(scan_limit, bool)
        or not isinstance(scan_limit, int)
        or scan_limit < 1
        or scan_limit > _MAX_RECONCILE_BATCH
    ):
        raise ValueError(f"scan_limit must be between 1 and {_MAX_RECONCILE_BATCH}")
    operator = str(actor or "").strip()
    if not operator:
        raise ValueError("actor is required")
    priority = str(priority_cycle_id or "").strip()
    state, cursor = _reconcile_scan_cursor()
    scanned = list(
        _CYCLES.iter_record_ids(start_after=cursor, limit=scan_limit)
    )
    identifiers = [record_id for _next_cursor, record_id in scanned]
    if priority and priority not in identifiers:
        identifiers.insert(0, priority)

    reconciled: list[dict[str, Any]] = []
    error_types: list[str] = []
    for identifier in identifiers:
        try:
            cycle = _CYCLES.get(identifier)
            if cycle is None or cycle.get("status") not in _GRC_RECONCILABLE_STATUS:
                continue
            result = reconcile_control_cycle(identifier, actor=operator, ops=ops)
            if result is not None:
                reconciled.append(result)
        except Exception as exc:  # failure-policy: continue bounded rotating scan
            error_types.append(type(exc).__name__[:200])

    if scanned:
        _advance_reconcile_scan_cursor(
            state,
            scanned[-1][0],
            actor=operator,
        )
    if error_types:
        raise RuntimeError(
            f"{len(error_types)} scheduled GRC reconciliation(s) failed safely"
        )
    return reconciled


def _has_control_test(
    engagement: Mapping[str, Any],
    row: FinanceControlObservation,
    procedure: str,
) -> bool:
    return any(
        isinstance(item, Mapping)
        and item.get("control_id") == row.control_id
        and item.get("procedure") == procedure
        and item.get("result") == "needs_review"
        for item in engagement.get("control_tests") or ()
    )


def _has_evidence_request(
    engagement: Mapping[str, Any],
    row: FinanceControlObservation,
    description: str,
) -> bool:
    return any(
        isinstance(item, Mapping)
        and item.get("description") == description
        and row.control_id in (item.get("control_ids") or ())
        for item in engagement.get("evidence_requests") or ()
    )


def _persist_progress(
    cycle: dict[str, Any],
    engagement: Mapping[str, Any],
    *,
    generation: int,
    control_index: int,
    phase: str,
    actor: str,
) -> dict[str, Any]:
    lease_until = _CYCLES.authoritative_time() + _CYCLE_LEASE_SECONDS

    def _mutate(record: dict[str, Any]) -> None:
        if (
            record.get("status") != "running"
            or int(record.get("run_generation") or 0) != generation
        ):
            raise RecordConflict("finance control cycle execution was superseded")
        record["engagement_id"] = str(engagement.get("id") or "")
        record["engagement_revision"] = int(engagement.get("revision") or 0)
        record["step_cursor"] = {
            "control_index": control_index,
            "phase": phase,
        }
        record["lease_until"] = lease_until

    updated = _CYCLES.update(
        cycle["id"],
        _mutate,
        expected_revision=cycle["revision"],
        action="control_cycle_progress",
        actor=actor,
    )
    if updated is None:
        raise RuntimeError("finance control cycle disappeared")
    return updated


def _execute_cycle(
    cycle: dict[str, Any],
    rows: list[FinanceControlObservation],
    *,
    actor: str,
    ops,
    generation: int,
) -> dict[str, Any]:
    config = _cycle_execution_config(cycle, allow_legacy=False)
    assert config is not None
    observed_at = float(cycle["observed_at"])
    owner = config["control_owner"]
    stamp = datetime.fromtimestamp(observed_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cycle_id = str(cycle["id"])
    engagement_id = str(cycle.get("engagement_id") or "")
    deterministic_id = _engagement_id(cycle_id)
    if not engagement_id:
        # Pre-deterministic cycles cannot distinguish a missing create from a
        # create that committed immediately before process loss. Never scan an
        # unbounded GRC store or risk creating a duplicate engagement.
        raise RuntimeError("finance control cycle lacks deterministic GRC correlation")
    engagement = _get_engagement(ops, engagement_id)
    if engagement is None:
        initial_cursor = {"control_index": 0, "phase": "engagement"}
        if (
            engagement_id != deterministic_id
            or cycle.get("step_cursor") != initial_cursor
            or int(cycle.get("engagement_revision") or 0) != 0
        ):
            raise RuntimeError("persisted GRC engagement is unavailable")
        try:
            engagement = ops.create_audit_engagement(
                f"Finance automated control observations - {stamp} [{cycle_id}]",
                CONTROL_SET_VERSION,
                _engagement_scope(cycle_id),
                owner,
                due_at=observed_at + config["evidence_due_days"] * 86400,
                created_by=actor,
                engagement_id=engagement_id,
            )
        except Exception:
            # A concurrent creator, or a provider that committed immediately
            # before raising, is safe to recover by deterministic identity.
            engagement = _get_engagement(ops, engagement_id)
            if engagement is None:
                raise
    if not isinstance(engagement, Mapping):
        raise RuntimeError("GRC engagement creation returned an invalid record")
    engagement = _validate_cycle_engagement(engagement, cycle_id, engagement_id)
    if cycle.get("step_cursor") == {"control_index": 0, "phase": "engagement"}:
        cycle = _persist_progress(
            cycle,
            engagement,
            generation=generation,
            control_index=0,
            phase="control_test",
            actor=actor,
        )
    engagement = _refresh_engagement(ops, engagement)

    for index, row in enumerate(rows):
        procedure = _procedure(row, observed_at, cycle_id)
        description = _request_description(row, cycle_id)
        if not _has_control_test(engagement, row, procedure):
            updated = ops.record_control_test(
                engagement["id"],
                row.control_id,
                procedure,
                "needs_review",
                evidence_ids=[],
                tested_by=actor,
                expected_revision=engagement["revision"],
            )
            if updated is None:
                raise RuntimeError(
                    "GRC engagement disappeared while recording a control test"
                )
            engagement = _refresh_engagement(ops, updated)
        cycle = _persist_progress(
            cycle,
            engagement,
            generation=generation,
            control_index=index,
            phase="evidence_request",
            actor=actor,
        )
        if not _has_evidence_request(engagement, row, description):
            updated = ops.add_evidence_request(
                engagement["id"],
                description,
                owner,
                observed_at + config["evidence_due_days"] * 86400,
                control_ids=[row.control_id],
                requested_by=actor,
                expected_revision=engagement["revision"],
            )
            if updated is None:
                raise RuntimeError(
                    "GRC engagement disappeared while requesting evidence"
                )
            engagement = _refresh_engagement(ops, updated)
        cycle = _persist_progress(
            cycle,
            engagement,
            generation=generation,
            control_index=index + 1,
            phase="control_test" if index + 1 < len(rows) else "complete",
            actor=actor,
        )

    completed_at = _CYCLES.authoritative_time()

    def _complete(record: dict[str, Any]) -> None:
        if record.get("status") not in {"running", "failed"}:
            raise ValueError("finance control cycle is not executable")
        if int(record.get("run_generation") or 0) != generation:
            raise RecordConflict("finance control cycle execution was superseded")
        record["status"] = "pending_human_evidence"
        record["engagement_id"] = engagement["id"]
        record["engagement_revision"] = engagement["revision"]
        record["completed_at"] = completed_at
        record["error_type"] = ""
        record["lease_until"] = 0.0

    completed = _CYCLES.update(
        cycle["id"],
        _complete,
        expected_revision=cycle["revision"],
        action="route_to_grc",
        actor=actor,
    )
    if completed is None:
        raise RuntimeError("finance control cycle disappeared")
    return completed


def _claim_cycle(
    cycle: dict[str, Any],
    *,
    actor: str,
    execution_config: Mapping[str, Any],
) -> dict[str, Any] | None:
    status = str(cycle.get("status") or "")
    if status not in _RECOVERABLE_CYCLE_STATUS:
        return None
    now = _CYCLES.authoritative_time()
    if status == "running" and float(cycle.get("lease_until") or 0) > now:
        return None
    generation = int(cycle.get("run_generation") or 0) + 1
    snapshot = _validated_execution_config(
        execution_config.get("control_owner"),
        execution_config.get("evidence_due_days"),
    )

    def _mutate(record: dict[str, Any]) -> None:
        current = str(record.get("status") or "")
        if current not in _RECOVERABLE_CYCLE_STATUS:
            raise RecordConflict("finance control cycle is no longer recoverable")
        if current == "running" and float(record.get("lease_until") or 0) > now:
            raise RecordConflict("finance control cycle has an active execution lease")
        persisted = _cycle_execution_config(record, allow_legacy=True)
        if persisted is None:
            record.update(snapshot)
        elif persisted != snapshot:
            raise RecordConflict("finance control cycle execution configuration changed")
        record["status"] = "running"
        record["run_generation"] = generation
        record["attempt_count"] = int(record.get("attempt_count") or 1) + 1
        record["lease_until"] = now + _CYCLE_LEASE_SECONDS
        record["error_type"] = ""
        record.pop("failed_at", None)

    return _CYCLES.update(
        cycle["id"],
        _mutate,
        expected_revision=cycle["revision"],
        action="resume_control_cycle",
        actor=actor,
    )


def _mark_cycle_failed(cycle_id: str, generation: int, actor: str, exc: Exception) -> None:
    error_type = type(exc).__name__[:200]
    failed_at = _CYCLES.authoritative_time()
    for _attempt in range(3):
        current = _CYCLES.get(cycle_id)
        if (
            current is None
            or current.get("status") != "running"
            or int(current.get("run_generation") or 0) != generation
        ):
            return
        def _failed(record: dict[str, Any]) -> None:
            if (
                record.get("status") != "running"
                or int(record.get("run_generation") or 0) != generation
            ):
                raise RecordConflict("finance control cycle execution was superseded")
            record["status"] = "failed"
            record["error_type"] = error_type
            record["failed_at"] = failed_at
            record["lease_until"] = 0.0

        try:
            _CYCLES.update(
                cycle_id,
                _failed,
                expected_revision=current["revision"],
                action="control_cycle_failed",
                actor=actor,
            )
            return
        except RecordConflict:
            continue


def run_control_cycle(
    *,
    actor: str,
    now: float | None = None,
    observations: Iterable[FinanceControlObservation | Mapping[str, Any]] | None = None,
    ops=None,
) -> dict[str, Any]:
    """Run or return the idempotent scheduled cycle for the current period."""
    if not enabled():
        raise RuntimeError("finance operations are disabled ([finance_operations] enable)")
    operator = str(actor or "").strip()
    if not operator:
        raise ValueError("actor is required")
    observed_at = time.time() if now is None else float(now)
    if not math.isfinite(observed_at) or observed_at <= 0:
        raise ValueError("now must be a positive finite timestamp")
    config = schedule_config()
    interval = float(config["interval_seconds"] or _DEFAULT_INTERVAL)
    bucket = _cycle_bucket(observed_at, interval)
    cycle_id = _cycle_id(bucket, interval)
    if ops is None:
        from .. import security_ops as ops
    existing = _CYCLES.get(cycle_id)
    execution_config = (
        None
        if existing is None
        else _cycle_execution_config(existing, allow_legacy=True)
    )
    if existing is not None and existing.get("status") not in _RECOVERABLE_CYCLE_STATUS:
        return existing
    if existing is not None and (
        existing.get("status") == "running"
        and float(existing.get("lease_until") or 0) > _CYCLES.authoritative_time()
    ):
        return existing
    if not ops.enabled():
        raise RuntimeError("Security/GRC operations are disabled")
    if existing is not None:
        if execution_config is None:
            execution_config = _execution_config_from_schedule(
                config,
                fallback_owner=str(existing.get("started_by") or operator),
            )
        rows = _validate_observations(existing.get("observations") or ())
        for row in rows:
            _procedure(row, float(existing["observed_at"]), str(existing["id"]))
        try:
            cycle = _claim_cycle(
                existing,
                actor=operator,
                execution_config=execution_config,
            )
        except RecordConflict:
            # Another scheduler generation won the recovery CAS. It owns the
            # lease and will reconcile the same deterministic workflow.
            return _CYCLES.get(cycle_id) or existing
        if cycle is None:
            return _CYCLES.get(cycle_id) or existing
    else:
        execution_config = _execution_config_from_schedule(
            config,
            fallback_owner=operator,
        )
        rows = _validate_observations(
            default_observations(now=observed_at)
            if observations is None
            else observations
        )
        for row in rows:
            _procedure(row, observed_at, cycle_id)
        runtime_now = _CYCLES.authoritative_time()
        record = {
            "id": cycle_id,
            "schema": CYCLE_SCHEMA,
            "status": "running",
            "control_set_version": CONTROL_SET_VERSION,
            "schedule_bucket": bucket,
            "interval_seconds": interval,
            "observed_at": observed_at,
            "started_by": _actor_label(operator),
            # Reserve the GRC identity before the external create. A crash
            # after that create can then recover by direct bounded lookup.
            "engagement_id": _engagement_id(cycle_id),
            "engagement_revision": 0,
            "observations": [row.to_dict() for row in rows],
            "step_cursor": {"control_index": 0, "phase": "engagement"},
            "run_generation": 1,
            "attempt_count": 1,
            "lease_until": runtime_now + _CYCLE_LEASE_SECONDS,
            "error_type": "",
            "notice": NON_OPINION_NOTICE,
            **execution_config,
        }
        try:
            cycle = _CYCLES.create(
                record,
                action="start_control_cycle",
                actor=operator,
            )
        except RecordConflict:
            raced = _CYCLES.get(cycle_id)
            if raced is None:
                raise
            return raced
    try:
        return _execute_cycle(
            cycle,
            rows,
            actor=operator,
            ops=ops,
            generation=int(cycle.get("run_generation") or 0),
        )
    except Exception as exc:
        # Keep failure visible and redacted. Reconciliation markers and the
        # durable cursor allow the next attempt to reuse every committed GRC
        # side effect, including a call that committed before raising.
        _mark_cycle_failed(
            cycle["id"],
            int(cycle.get("run_generation") or 0),
            operator,
            exc,
        )
        raise


__all__ = [
    "CONTROL_SET_VERSION",
    "CYCLE_SCHEMA",
    "RECONCILE_STATE_SCHEMA",
    "FinanceControlObservation",
    "NON_OPINION_NOTICE",
    "RecordConflict",
    "default_observations",
    "enabled",
    "get_cycle",
    "cycle_status_summary",
    "list_cycle_summaries",
    "list_cycles",
    "reconcile_control_cycle",
    "reconcile_scheduled_cycles",
    "run_control_cycle",
    "schedule_config",
]
