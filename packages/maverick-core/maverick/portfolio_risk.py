"""Tenant-governed, transparent portfolio risk rollups and quarter snapshots.

Formula v1 is deliberately simple and inspectable. Current derived findings map
low/medium/high/critical to 25/50/75/100 points. An exact-digest, unexpired
human risk acceptance contributes zero residual points, except that critical
findings are never suppressible. Asset, ancestor, and portfolio scores are the
maximum applicable contributor score; risk load is the additive point total.

This is decision-support and evidence metadata only. It is not a certification,
legal classification, conformity assessment, compliance verdict, or legal
advice.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from . import model_risk_assurance as mra
from .governed_records import GovernedRecordCapacityError, GovernedRecordStore
from .privacy_ops import RecordConflict

REPORT_SCHEMA = "lightwork.model-risk-portfolio-report.v1"
SNAPSHOT_SCHEMA = "lightwork.model-risk-portfolio-snapshot.v1"
TREND_SCHEMA = "lightwork.model-risk-portfolio-trend.v1"
FORMULA_VERSION = "portfolio-risk-formula-v1"
SEVERITY_POINTS = {"low": 25, "medium": 50, "high": 75, "critical": 100}

_SNAPSHOTS = GovernedRecordStore(
    "model_risk_portfolio_snapshots",
    "MRP",
    "model_risk_portfolio_snapshot",
)
_PERIOD_RE = re.compile(r"(20[0-9]{2})-Q([1-4])\Z")
_MAX_SNAPSHOTS = 256
_MAX_SUPERSESSIONS = 512
_MAX_STABILITY_ATTEMPTS = 3
_MAX_REPORT_JSON_BYTES = 12 * 1024 * 1024
_MAX_TREND_CONTRIBUTORS = 500
_ACTIVE_INCIDENT_STATES = frozenset({"open", "contained"})
_SAFE_DRILL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}\Z")


class PortfolioRiskError(RuntimeError):
    """Base failure for portfolio risk reporting."""


class PortfolioRiskConfigError(PortfolioRiskError):
    """The opt-in portfolio-risk capability is unavailable or malformed."""


class PortfolioRiskStateError(PortfolioRiskError):
    """Governed source or snapshot state is malformed or unstable."""


class ClosedPortfolioPeriod(PortfolioRiskError):
    """A caller attempted to mutate an immutable closed quarter."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _public_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "_audit_pending"}


def _record_sha256(record: Mapping[str, Any]) -> str:
    return _sha256(_public_record(record))


def _citation(record: Mapping[str, Any], relation: str) -> dict[str, Any]:
    record_id = str(record.get("id") or "")
    revision = record.get("revision")
    if not record_id or not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise PortfolioRiskStateError("a governed source citation is malformed")
    return {
        "record_id": record_id,
        "revision": revision,
        "record_sha256": _record_sha256(record),
        "relation": relation,
    }


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a finite positive timestamp")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a finite positive timestamp") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{label} must be a finite positive timestamp")
    return parsed


def _quarter_at(now: float) -> dict[str, Any]:
    current = datetime.fromtimestamp(_timestamp(now, "now"), tz=timezone.utc)
    quarter = ((current.month - 1) // 3) + 1
    start_month = ((quarter - 1) * 3) + 1
    start = datetime(current.year, start_month, 1, tzinfo=timezone.utc)
    if quarter == 4:
        end = datetime(current.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(current.year, start_month + 3, 1, tzinfo=timezone.utc)
    return {
        "period_id": f"{current.year:04d}-Q{quarter}",
        "period_start": start.timestamp(),
        "period_end": end.timestamp(),
    }


def _period_bounds(period_id: str) -> dict[str, Any]:
    match = _PERIOD_RE.fullmatch(str(period_id or ""))
    if match is None:
        raise ValueError("period_id must use YYYY-Q1 through YYYY-Q4")
    year = int(match.group(1))
    quarter = int(match.group(2))
    month = ((quarter - 1) * 3) + 1
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    if quarter == 4:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, month + 3, 1, tzinfo=timezone.utc)
    return {
        "period_id": period_id,
        "period_start": start.timestamp(),
        "period_end": end.timestamp(),
    }


def _snapshot_id(period_id: str) -> str:
    return f"MRP-{_sha256({'period_id': period_id})[:24]}"


def _previous_period_id(period_id: str) -> str:
    match = _PERIOD_RE.fullmatch(str(period_id or ""))
    if match is None:
        raise ValueError("period_id must use YYYY-Q1 through YYYY-Q4")
    year = int(match.group(1))
    quarter = int(match.group(2))
    if quarter == 1:
        return f"{year - 1:04d}-Q4"
    return f"{year:04d}-Q{quarter - 1}"


def _risk_direction(delta: int) -> str:
    if delta > 0:
        return "worsened"
    if delta < 0:
        return "improved"
    return "unchanged"


def _trend_limit(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("contributor_limit must be an integer")
    if value < 1 or value > _MAX_TREND_CONTRIBUTORS:
        raise ValueError(
            f"contributor_limit must be between 1 and {_MAX_TREND_CONTRIBUTORS}"
        )
    return value


def enabled() -> bool:
    """Return the explicit default-off global feature and dependency posture."""

    try:
        from .config import config_source_errors, load_global_config

        cfg = load_global_config()
        if config_source_errors(include_tenant=False) or not isinstance(cfg, dict):
            return False
        section = cfg.get("portfolio_risk")
        if not isinstance(section, dict):
            return False
        flag = section.get("enable", False)
        if not isinstance(flag, bool) or flag is not True:
            return False
        return mra.enabled()
    except Exception:
        return False


def _require_enabled() -> None:
    if not enabled():
        raise PortfolioRiskConfigError(
            "portfolio risk requires [portfolio_risk] enable = true and "
            "enabled model-risk assurance dependencies"
        )


def _tenant_label() -> str:
    from .paths import current_tenant_id_strict

    return current_tenant_id_strict() or "default"


def _source_manifest(
    nodes: list[dict[str, Any]],
    contributors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    sources: dict[tuple[str, str, int | None, str], dict[str, Any]] = {}
    for node in nodes:
        for citation in node["source_citations"]:
            key = (
                "governed_record",
                citation["record_id"],
                citation["revision"],
                citation["record_sha256"],
            )
            sources[key] = {
                "source_kind": "governed_record",
                "source_id": citation["record_id"],
                "revision": citation["revision"],
                "source_sha256": citation["record_sha256"],
            }
    for contributor in contributors:
        if contributor["source_kind"] == "finding":
            key = (
                "finding",
                contributor["finding_id"],
                None,
                contributor["finding_sha256"],
            )
            sources[key] = {
                "source_kind": "finding",
                "source_id": contributor["finding_id"],
                "revision": None,
                "source_sha256": contributor["finding_sha256"],
            }
        for citation in contributor["source_citations"]:
            key = (
                "governed_record",
                citation["record_id"],
                citation["revision"],
                citation["record_sha256"],
            )
            sources[key] = {
                "source_kind": "governed_record",
                "source_id": citation["record_id"],
                "revision": citation["revision"],
                "source_sha256": citation["record_sha256"],
            }
    return sorted(
        sources.values(),
        key=lambda row: (
            row["source_kind"],
            row["source_id"],
            -1 if row["revision"] is None else row["revision"],
            row["source_sha256"],
        ),
    )


class PortfolioRiskService:
    """Build stable reports and publish CAS-governed tenant quarter snapshots."""

    def __init__(
        self,
        *,
        officer: mra.ModelRiskAssuranceOfficer | None = None,
        snapshots: GovernedRecordStore | None = None,
        clock: Callable[[], float] | None = None,
        enforce_feature: bool = True,
    ) -> None:
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        if not isinstance(enforce_feature, bool):
            raise ValueError("enforce_feature must be a boolean")
        self._officer = officer or mra.ModelRiskAssuranceOfficer()
        self._snapshots = snapshots or _SNAPSHOTS
        self._clock = clock
        self._enforce_feature = enforce_feature

    def _require_active(self) -> None:
        if self._enforce_feature:
            _require_enabled()
        if self._officer.backend_kind != self._snapshots.backend_kind:
            raise PortfolioRiskStateError(
                "portfolio snapshots and model-risk authority use different backends"
            )

    def _now(self) -> float:
        source = self._clock or self._snapshots.authoritative_time
        return _timestamp(source(), "authority clock")

    def _build_report(  # noqa: C901 - one explicit, auditable formula boundary
        self,
        *,
        now: float,
    ) -> dict[str, Any]:
        observations = self._officer.list_inventory()
        declarations = {
            str(row.get("asset_id") or ""): row
            for row in self._officer.list_declarations()
        }
        findings = self._officer.findings(now=now)
        incidents = [
            row
            for row in self._officer.list_incidents()
            if row.get("status") in _ACTIVE_INCIDENT_STATES
        ]

        nodes: list[dict[str, Any]] = []
        nodes_by_asset: dict[str, dict[str, Any]] = {}
        for observation in observations:
            asset_id = str(observation.get("asset_id") or "")
            if not asset_id or asset_id in nodes_by_asset:
                raise PortfolioRiskStateError("portfolio inventory identity is malformed")
            declaration = declarations.get(asset_id)
            parent_asset_id = None
            citations = [_citation(observation, "portfolio_observation")]
            if declaration is not None:
                hierarchy = self._officer.hierarchy_binding(asset_id)
                parent_asset_id = hierarchy["parent_asset_id"]
                citations.append(_citation(declaration, "portfolio_declaration"))
            node = {
                "asset_id": asset_id,
                "asset_type": str((observation.get("identity") or {}).get("asset_type") or ""),
                "display_name": str(observation.get("display_name") or ""),
                "parent_asset_id": parent_asset_id,
                "child_asset_ids": [],
                "source_citations": citations,
                "direct_contributor_ids": [],
                "direct_inherent_score": 0,
                "direct_residual_score": 0,
                "inherent_score": 0,
                "residual_score": 0,
                "inherent_risk_load": 0,
                "residual_risk_load": 0,
                "inherent_top_contributor_ids": [],
                "residual_top_contributor_ids": [],
            }
            nodes.append(node)
            nodes_by_asset[asset_id] = node

        for node in nodes:
            parent = node["parent_asset_id"]
            if parent is not None:
                if parent not in nodes_by_asset:
                    raise PortfolioRiskStateError(
                        "portfolio hierarchy references an asset outside current inventory"
                    )
                nodes_by_asset[parent]["child_asset_ids"].append(node["asset_id"])
        for node in nodes:
            node["child_asset_ids"].sort()

        contributors: list[dict[str, Any]] = []
        represented_incidents: set[str] = set()
        for finding in findings:
            asset_id = str(finding.get("asset_id") or "")
            node = nodes_by_asset.get(asset_id)
            if node is None:
                raise PortfolioRiskStateError("a current finding references unknown inventory")
            severity = str(finding.get("severity") or "")
            if severity not in SEVERITY_POINTS:
                raise PortfolioRiskStateError("a current finding has an invalid severity")
            finding_id = str(finding.get("id") or "")
            finding_sha256 = str(finding.get("finding_sha256") or "")
            if not finding_id or not re.fullmatch(r"[0-9a-f]{64}", finding_sha256):
                raise PortfolioRiskStateError("a current finding identity is malformed")
            acceptance = self._officer.current_risk_acceptance(finding, now=now)
            citations = [dict(row) for row in finding.get("citations") or []]
            acceptance_view = None
            if acceptance is not None:
                acceptance_citation = _citation(acceptance, "accepts_exact_finding")
                citations.append(acceptance_citation)
                acceptance_view = {
                    "record_id": acceptance["id"],
                    "revision": acceptance["revision"],
                    "record_sha256": acceptance_citation["record_sha256"],
                    "finding_sha256": acceptance["finding_sha256"],
                    "expires_at": acceptance["expires_at"],
                    "reviewer": acceptance["reviewer"],
                }
            if finding.get("finding_type") == "active_incident":
                incident_id = str((finding.get("details") or {}).get("incident_id") or "")
                if incident_id:
                    represented_incidents.add(incident_id)
            points = SEVERITY_POINTS[severity]
            contributor = {
                "contributor_id": finding_id,
                "source_kind": "finding",
                "finding_id": finding_id,
                "finding_sha256": finding_sha256,
                "finding_type": str(finding.get("finding_type") or ""),
                "asset_id": asset_id,
                "severity": severity,
                "summary": str(finding.get("summary") or ""),
                "accepted": acceptance is not None,
                "acceptance": acceptance_view,
                "inherent_points": points,
                "residual_points": 0 if acceptance is not None else points,
                "source_citations": sorted(
                    citations,
                    key=lambda row: (
                        str(row.get("record_id") or ""),
                        int(row.get("revision") or 0),
                        str(row.get("relation") or ""),
                    ),
                ),
            }
            contributors.append(contributor)
            node["direct_contributor_ids"].append(finding_id)

        for incident in incidents:
            incident_id = str(incident.get("id") or "")
            if incident_id in represented_incidents:
                continue
            asset_id = str(incident.get("asset_id") or "")
            node = nodes_by_asset.get(asset_id)
            if node is None:
                raise PortfolioRiskStateError("an active incident references unknown inventory")
            severity = str(incident.get("severity") or "")
            if severity not in SEVERITY_POINTS:
                raise PortfolioRiskStateError("an active incident has an invalid severity")
            points = SEVERITY_POINTS[severity]
            contributor_id = f"incident:{incident_id}"
            contributor = {
                "contributor_id": contributor_id,
                "source_kind": "incident",
                "finding_id": None,
                "finding_sha256": None,
                "finding_type": "active_incident_without_derived_finding",
                "asset_id": asset_id,
                "severity": severity,
                "summary": str(incident.get("summary") or ""),
                "accepted": False,
                "acceptance": None,
                "inherent_points": points,
                "residual_points": points,
                "source_citations": [_citation(incident, "reports_active_incident")],
            }
            contributors.append(contributor)
            node["direct_contributor_ids"].append(contributor_id)

        contributors.sort(key=lambda row: (row["asset_id"], row["contributor_id"]))
        contributor_by_id = {row["contributor_id"]: row for row in contributors}
        if len(contributor_by_id) != len(contributors):
            raise PortfolioRiskStateError("portfolio contributor identity collision")
        for node in nodes:
            node["direct_contributor_ids"].sort()
            direct = [contributor_by_id[item] for item in node["direct_contributor_ids"]]
            node["direct_inherent_score"] = max(
                (row["inherent_points"] for row in direct),
                default=0,
            )
            node["direct_residual_score"] = max(
                (row["residual_points"] for row in direct),
                default=0,
            )

        visiting: set[str] = set()
        visited: set[str] = set()

        def rollup(asset_id: str) -> None:
            if asset_id in visited:
                return
            if asset_id in visiting:
                raise PortfolioRiskStateError("portfolio hierarchy contains a cycle")
            visiting.add(asset_id)
            node = nodes_by_asset[asset_id]
            for child_id in node["child_asset_ids"]:
                rollup(child_id)
            direct = [contributor_by_id[item] for item in node["direct_contributor_ids"]]
            inherent_score = node["direct_inherent_score"]
            residual_score = node["direct_residual_score"]
            inherent_load = sum(row["inherent_points"] for row in direct)
            residual_load = sum(row["residual_points"] for row in direct)
            inherent_top = {
                row["contributor_id"]
                for row in direct
                if row["inherent_points"] == inherent_score and inherent_score > 0
            }
            residual_top = {
                row["contributor_id"]
                for row in direct
                if row["residual_points"] == residual_score and residual_score > 0
            }
            for child_id in node["child_asset_ids"]:
                child = nodes_by_asset[child_id]
                inherent_load += child["inherent_risk_load"]
                residual_load += child["residual_risk_load"]
                if child["inherent_score"] > inherent_score:
                    inherent_score = child["inherent_score"]
                    inherent_top = set(child["inherent_top_contributor_ids"])
                elif child["inherent_score"] == inherent_score and inherent_score > 0:
                    inherent_top.update(child["inherent_top_contributor_ids"])
                if child["residual_score"] > residual_score:
                    residual_score = child["residual_score"]
                    residual_top = set(child["residual_top_contributor_ids"])
                elif child["residual_score"] == residual_score and residual_score > 0:
                    residual_top.update(child["residual_top_contributor_ids"])
            node["inherent_score"] = inherent_score
            node["residual_score"] = residual_score
            node["inherent_risk_load"] = inherent_load
            node["residual_risk_load"] = residual_load
            node["inherent_top_contributor_ids"] = sorted(inherent_top)
            node["residual_top_contributor_ids"] = sorted(residual_top)
            visiting.remove(asset_id)
            visited.add(asset_id)

        roots = sorted(
            node["asset_id"] for node in nodes if node["parent_asset_id"] is None
        )
        for root in roots:
            rollup(root)
        if len(visited) != len(nodes):
            raise PortfolioRiskStateError("portfolio hierarchy has no valid root")

        inherent_score = max((nodes_by_asset[root]["inherent_score"] for root in roots), default=0)
        residual_score = max((nodes_by_asset[root]["residual_score"] for root in roots), default=0)
        inherent_top = sorted({
            contributor_id
            for root in roots
            if nodes_by_asset[root]["inherent_score"] == inherent_score
            for contributor_id in nodes_by_asset[root]["inherent_top_contributor_ids"]
        })
        residual_top = sorted({
            contributor_id
            for root in roots
            if nodes_by_asset[root]["residual_score"] == residual_score
            for contributor_id in nodes_by_asset[root]["residual_top_contributor_ids"]
        })
        severity_counts = Counter(row["severity"] for row in contributors)
        residual_counts = Counter(
            row["severity"] for row in contributors if row["residual_points"] > 0
        )
        for node in nodes:
            node["source_citations"].sort(
                key=lambda row: (row["record_id"], row["revision"], row["relation"])
            )
        nodes.sort(key=lambda row: row["asset_id"])
        manifest = _source_manifest(nodes, contributors)
        hierarchy_content = [
            {
                "asset_id": node["asset_id"],
                "asset_type": node["asset_type"],
                "parent_asset_id": node["parent_asset_id"],
                "source_citations": node["source_citations"],
            }
            for node in nodes
        ]
        quarter = _quarter_at(now)
        report = {
            "schema": REPORT_SCHEMA,
            "formula_version": FORMULA_VERSION,
            "formula": {
                "severity_points": dict(SEVERITY_POINTS),
                "asset_aggregation": "maximum current contributor severity",
                "hierarchy_aggregation": "maximum direct or child score",
                "portfolio_aggregation": "maximum root score",
                "risk_load": "additive contributor points",
                "residual_rule": (
                    "only an exact-digest, non-expired acceptance suppresses a "
                    "non-critical finding; critical findings are never suppressible"
                ),
            },
            "tenant": _tenant_label(),
            **quarter,
            "as_of": now,
            "generated_at": now,
            "portfolio_inherent_score": inherent_score,
            "portfolio_score": residual_score,
            "inherent_risk_load": sum(row["inherent_points"] for row in contributors),
            "risk_load": sum(row["residual_points"] for row in contributors),
            "inherent_top_contributor_ids": inherent_top,
            "top_contributor_ids": residual_top,
            "root_asset_ids": roots,
            "counts": {
                "assets": len(nodes),
                "declared_assets": len(declarations),
                "current_findings": len(findings),
                "active_incidents": len(incidents),
                "contributors": len(contributors),
                "accepted_findings": sum(row["accepted"] for row in contributors),
                "inherent_by_severity": {
                    severity: severity_counts[severity] for severity in SEVERITY_POINTS
                },
                "residual_by_severity": {
                    severity: residual_counts[severity] for severity in SEVERITY_POINTS
                },
            },
            "hierarchy_sha256": _sha256(hierarchy_content),
            "assets": nodes,
            "contributors": contributors,
            "source_manifest": manifest,
            "source_state_sha256": _sha256(manifest),
            "legal_certification": False,
            "compliance_verdict": "not_provided",
            "notice": mra.NON_CERTIFICATION_NOTICE,
        }
        report["report_sha256"] = _sha256(report)
        if len(_canonical(report)) > _MAX_REPORT_JSON_BYTES:
            raise PortfolioRiskStateError("portfolio report exceeds the governed size limit")
        return report

    def _stable_report(self, *, now: float) -> dict[str, Any]:
        previous: dict[str, Any] | None = None
        for _attempt in range(_MAX_STABILITY_ATTEMPTS):
            current = self._build_report(now=now)
            if previous is not None and (
                previous["report_sha256"] == current["report_sha256"]
            ):
                return current
            previous = current
        raise PortfolioRiskStateError(
            "portfolio authority changed during a bounded report read; retry"
        )

    def current_report(self, *, now: float | None = None) -> dict[str, Any]:
        """Return a stable current-quarter report for the active tenant."""

        self._require_active()
        current = self._now() if now is None else _timestamp(now, "now")
        return self._stable_report(now=current)

    @staticmethod
    def _validated_snapshot(record: Mapping[str, Any]) -> dict[str, Any]:
        row = _public_record(record)
        if (
            row.get("schema") != SNAPSHOT_SCHEMA
            or row.get("record_kind") != "quarterly_portfolio_snapshot"
            or row.get("status") != "published"
            or row.get("legal_certification") is not False
            or row.get("compliance_verdict") != "not_provided"
            or row.get("notice") != mra.NON_CERTIFICATION_NOTICE
            or not isinstance(row.get("revision"), int)
            or isinstance(row.get("revision"), bool)
            or int(row.get("revision") or 0) < 1
            or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("report_sha256") or ""))
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(row.get("source_state_sha256") or ""),
            )
        ):
            raise PortfolioRiskStateError("portfolio snapshot is malformed")
        period = _period_bounds(str(row.get("period_id") or ""))
        if (
            row.get("id") != _snapshot_id(period["period_id"])
            or row.get("period_start") != period["period_start"]
            or row.get("period_end") != period["period_end"]
        ):
            raise PortfolioRiskStateError("portfolio snapshot period binding is malformed")
        report = row.get("report")
        if not isinstance(report, Mapping):
            raise PortfolioRiskStateError("portfolio snapshot report is malformed")
        expected_report = dict(report)
        report_digest = expected_report.pop("report_sha256", None)
        if (
            report.get("schema") != REPORT_SCHEMA
            or report.get("formula_version") != FORMULA_VERSION
            or report.get("tenant") != _tenant_label()
            or report.get("period_id") != row.get("period_id")
            or report.get("period_start") != row.get("period_start")
            or report.get("period_end") != row.get("period_end")
            or report.get("legal_certification") is not False
            or report.get("compliance_verdict") != "not_provided"
            or report.get("notice") != mra.NON_CERTIFICATION_NOTICE
            or report_digest != row.get("report_sha256")
            or report_digest != _sha256(expected_report)
            or report.get("source_state_sha256") != row.get("source_state_sha256")
        ):
            raise PortfolioRiskStateError("portfolio snapshot failed integrity validation")
        history = row.get("supersessions")
        if not isinstance(history, list) or len(history) > _MAX_SUPERSESSIONS:
            raise PortfolioRiskStateError("portfolio snapshot supersession history is malformed")
        previous_revision = 0
        for item in history:
            if not isinstance(item, Mapping):
                raise PortfolioRiskStateError(
                    "portfolio snapshot supersession history is malformed"
                )
            revision = item.get("record_revision")
            if (
                isinstance(revision, bool)
                or not isinstance(revision, int)
                or revision <= previous_revision
                or revision >= int(row.get("revision") or 0)
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("record_sha256") or ""))
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("report_sha256") or ""))
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(item.get("source_state_sha256") or ""),
                )
            ):
                raise PortfolioRiskStateError(
                    "portfolio snapshot supersession history is malformed"
                )
            _timestamp(item.get("generated_at"), "superseded report generated_at")
            _timestamp(item.get("superseded_at"), "snapshot superseded_at")
            if not str(item.get("superseded_by") or "").strip():
                raise PortfolioRiskStateError(
                    "portfolio snapshot supersession history is malformed"
                )
            previous_revision = revision
        return row

    def refresh_current_snapshot(
        self,
        *,
        actor: str,
        expected_revision: int = 0,
        period_id: str | None = None,
    ) -> dict[str, Any]:
        """CAS-publish the current quarter; closed periods are immutable."""

        self._require_active()
        operator = str(actor or "").strip()
        if not operator or len(operator) > 256:
            raise ValueError("actor must be between 1 and 256 characters")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise ValueError("expected_revision must be a non-negative integer")
        now = self._now()
        current_period = _quarter_at(now)
        requested = current_period["period_id"] if period_id is None else period_id
        requested_bounds = _period_bounds(requested)
        if requested != current_period["period_id"]:
            if requested_bounds["period_end"] <= now:
                raise ClosedPortfolioPeriod(
                    f"portfolio period {requested} is closed and immutable"
                )
            raise ValueError("only the active quarter may be refreshed")
        report = self._stable_report(now=now)
        record_id = _snapshot_id(requested)
        existing = self._snapshots.get(record_id)
        found_revision = int((existing or {}).get("revision") or 0)
        if found_revision != expected_revision:
            raise RecordConflict(
                "portfolio snapshot changed "
                f"(expected revision {expected_revision}, found {found_revision})"
            )
        if existing is None:
            record = {
                "id": record_id,
                "schema": SNAPSHOT_SCHEMA,
                "record_kind": "quarterly_portfolio_snapshot",
                **requested_bounds,
                "report": report,
                "report_sha256": report["report_sha256"],
                "source_state_sha256": report["source_state_sha256"],
                "supersessions": [],
                "status": "published",
                "legal_certification": False,
                "compliance_verdict": "not_provided",
                "notice": mra.NON_CERTIFICATION_NOTICE,
            }
            try:
                created = self._snapshots.create(
                    record,
                    action="portfolio_snapshot_published",
                    actor=operator,
                    max_records=_MAX_SNAPSHOTS,
                )
            except GovernedRecordCapacityError as exc:
                raise PortfolioRiskStateError(
                    "portfolio snapshot capacity has been reached"
                ) from exc
            return self._snapshot_view(created, now=now)

        current = self._validated_snapshot(existing)
        if current["report_sha256"] == report["report_sha256"]:
            return self._snapshot_view(existing, now=now)
        history = list(current["supersessions"])
        if len(history) >= _MAX_SUPERSESSIONS:
            raise PortfolioRiskStateError(
                "portfolio snapshot supersession capacity has been reached"
            )
        history.append({
            "record_revision": current["revision"],
            "record_sha256": _record_sha256(current),
            "report_sha256": current["report_sha256"],
            "source_state_sha256": current["source_state_sha256"],
            "generated_at": current["report"]["generated_at"],
            "superseded_at": now,
            "superseded_by": operator,
        })

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validated_snapshot(row)
            if validated["period_end"] <= now:
                raise ClosedPortfolioPeriod(
                    f"portfolio period {requested} is closed and immutable"
                )
            row["report"] = report
            row["report_sha256"] = report["report_sha256"]
            row["source_state_sha256"] = report["source_state_sha256"]
            row["supersessions"] = history
            row["status"] = "published"

        updated = self._snapshots.update(
            record_id,
            mutate,
            expected_revision=expected_revision,
            action="portfolio_snapshot_superseded",
            actor=operator,
        )
        if updated is None:
            raise PortfolioRiskStateError("portfolio snapshot disappeared")
        return self._snapshot_view(updated, now=now)

    def _snapshot_view(
        self,
        record: Mapping[str, Any],
        *,
        now: float,
    ) -> dict[str, Any]:
        row = self._validated_snapshot(record)
        return {
            **row,
            "period_status": "closed" if row["period_end"] <= now else "current",
        }

    def get_snapshot(
        self,
        period_id: str,
        *,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        """Return one integrity-checked active-tenant quarter snapshot."""

        self._require_active()
        period = _period_bounds(period_id)
        current = self._now() if now is None else _timestamp(now, "now")
        record = self._snapshots.get(_snapshot_id(period["period_id"]))
        return None if record is None else self._snapshot_view(record, now=current)

    def list_snapshots(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """List integrity-checked quarter snapshots for the active tenant."""

        self._require_active()
        current = self._now() if now is None else _timestamp(now, "now")
        rows = self._snapshots.list(limit=_MAX_SNAPSHOTS + 1)
        if len(rows) > _MAX_SNAPSHOTS:
            raise PortfolioRiskStateError("portfolio snapshot capacity is malformed")
        return sorted(
            (self._snapshot_view(row, now=current) for row in rows),
            key=lambda row: row["period_id"],
            reverse=True,
        )

    @staticmethod
    def _trend_contributors(
        snapshot: Mapping[str, Any],
    ) -> dict[str, dict[str, Any]]:
        report = snapshot.get("report") or {}
        raw = report.get("contributors")
        counts = report.get("counts") or {}
        if not isinstance(raw, list) or not isinstance(counts, Mapping):
            raise PortfolioRiskStateError("portfolio snapshot contributors are malformed")
        expected_count = counts.get("contributors")
        if (
            not isinstance(expected_count, int)
            or isinstance(expected_count, bool)
            or expected_count != len(raw)
        ):
            raise PortfolioRiskStateError("portfolio snapshot contributor count is malformed")
        required_fields = {
            "contributor_id",
            "source_kind",
            "finding_id",
            "finding_sha256",
            "finding_type",
            "asset_id",
            "severity",
            "summary",
            "accepted",
            "acceptance",
            "inherent_points",
            "residual_points",
            "source_citations",
        }
        result: dict[str, dict[str, Any]] = {}
        for item in raw:
            if not isinstance(item, Mapping) or set(item) != required_fields:
                raise PortfolioRiskStateError(
                    "portfolio snapshot contributor projection is malformed"
                )
            contributor_id = str(item.get("contributor_id") or "")
            asset_id = str(item.get("asset_id") or "")
            source_kind = str(item.get("source_kind") or "")
            severity = str(item.get("severity") or "")
            finding_id = item.get("finding_id")
            finding_sha256 = item.get("finding_sha256")
            inherent = item.get("inherent_points")
            residual = item.get("residual_points")
            accepted = item.get("accepted")
            if (
                not _SAFE_DRILL_ID_RE.fullmatch(contributor_id)
                or not _SAFE_DRILL_ID_RE.fullmatch(asset_id)
                or source_kind not in {"finding", "incident"}
                or severity not in SEVERITY_POINTS
                or not isinstance(inherent, int)
                or isinstance(inherent, bool)
                or inherent != SEVERITY_POINTS[severity]
                or not isinstance(residual, int)
                or isinstance(residual, bool)
                or residual not in {0, inherent}
                or not isinstance(accepted, bool)
            ):
                raise PortfolioRiskStateError(
                    "portfolio snapshot contributor identity is malformed"
                )
            if source_kind == "finding":
                if (
                    finding_id != contributor_id
                    or not isinstance(finding_sha256, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", finding_sha256)
                ):
                    raise PortfolioRiskStateError(
                        "portfolio snapshot finding drill-through is malformed"
                    )
            elif finding_id is not None or finding_sha256 is not None:
                raise PortfolioRiskStateError(
                    "portfolio snapshot incident drill-through is malformed"
                )
            if accepted:
                if source_kind != "finding" or residual != 0 or severity == "critical":
                    raise PortfolioRiskStateError(
                        "portfolio snapshot accepted contributor is malformed"
                    )
            elif residual != inherent:
                raise PortfolioRiskStateError(
                    "portfolio snapshot residual contributor is malformed"
                )
            if contributor_id in result:
                raise PortfolioRiskStateError(
                    "portfolio snapshot contributor identity is duplicated"
                )
            result[contributor_id] = {
                "contributor_id": contributor_id,
                "finding_id": finding_id,
                "asset_id": asset_id,
                "source_kind": source_kind,
                "finding_type": str(item.get("finding_type") or ""),
                "severity": severity,
                "inherent_points": inherent,
                "residual_points": residual,
                "accepted": accepted,
            }
        return result

    @staticmethod
    def _snapshot_reference(snapshot: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "snapshot_id": snapshot["id"],
            "snapshot_revision": snapshot["revision"],
            "period_id": snapshot["period_id"],
            "report_sha256": snapshot["report_sha256"],
            "source_state_sha256": snapshot["source_state_sha256"],
        }

    def portfolio_trend(
        self,
        *,
        now: float | None = None,
        contributor_limit: int = 100,
    ) -> dict[str, Any]:
        """Compare the current snapshot with the latest earlier quarter safely."""

        self._require_active()
        current_time = self._now() if now is None else _timestamp(now, "now")
        limit = _trend_limit(contributor_limit)
        current_period = _quarter_at(current_time)["period_id"]
        snapshots = self.list_snapshots(now=current_time)
        current = next(
            (row for row in snapshots if row["period_id"] == current_period),
            None,
        )
        if current is None:
            raise PortfolioRiskStateError(
                f"current portfolio snapshot {current_period} is missing"
            )
        prior = next(
            (row for row in snapshots if row["period_id"] < current_period),
            None,
        )
        current_contributors = self._trend_contributors(current)
        expected_prior = _previous_period_id(current_period)
        projection: dict[str, Any] = {
            "schema": TREND_SCHEMA,
            "tenant": _tenant_label(),
            "as_of": current_time,
            "current_period_id": current_period,
            "expected_prior_period_id": expected_prior,
            "prior_period_id": None,
            "is_consecutive": False,
            "comparison_available": prior is not None,
            "current_snapshot": self._snapshot_reference(current),
            "prior_snapshot": None,
            "direction": "not_available",
            "direction_basis": None,
            "portfolio_score": {
                "prior": None,
                "current": int(current["report"]["portfolio_score"]),
                "delta": None,
            },
            "risk_load": {
                "prior": None,
                "current": int(current["report"]["risk_load"]),
                "delta": None,
            },
            "contributor_deltas": [],
            "contributor_delta_count": 0,
            "contributor_limit": limit,
            "contributors_truncated": False,
            "drill_through_ids": {
                "contributor_ids": [],
                "finding_ids": [],
            },
            "legal_certification": False,
            "compliance_verdict": "not_provided",
            "notice": mra.NON_CERTIFICATION_NOTICE,
        }
        if prior is None:
            projection["trend_sha256"] = _sha256(projection)
            return projection

        prior_contributors = self._trend_contributors(prior)
        score_prior = int(prior["report"]["portfolio_score"])
        score_current = int(current["report"]["portfolio_score"])
        load_prior = int(prior["report"]["risk_load"])
        load_current = int(current["report"]["risk_load"])
        score_delta = score_current - score_prior
        load_delta = load_current - load_prior
        basis = "portfolio_score" if score_delta else "risk_load"
        direction_delta = score_delta or load_delta
        contributor_deltas: list[dict[str, Any]] = []
        for contributor_id in sorted(set(prior_contributors) | set(current_contributors)):
            before = prior_contributors.get(contributor_id)
            after = current_contributors.get(contributor_id)
            if before is not None and after is not None and (
                before["finding_id"] != after["finding_id"]
                or before["asset_id"] != after["asset_id"]
                or before["source_kind"] != after["source_kind"]
            ):
                raise PortfolioRiskStateError(
                    "portfolio contributor drill-through identity changed across snapshots"
                )
            identity = after or before
            if identity is None:  # pragma: no cover - set union makes this unreachable
                raise PortfolioRiskStateError("portfolio contributor identity is missing")
            prior_points = int(before["residual_points"]) if before else 0
            current_points = int(after["residual_points"]) if after else 0
            delta = current_points - prior_points
            contributor_deltas.append({
                "contributor_id": contributor_id,
                "finding_id": identity["finding_id"],
                "asset_id": identity["asset_id"],
                "source_kind": identity["source_kind"],
                "prior_present": before is not None,
                "current_present": after is not None,
                "prior_residual_points": prior_points,
                "current_residual_points": current_points,
                "delta": delta,
                "direction": _risk_direction(delta),
            })
        contributor_deltas.sort(
            key=lambda row: (-abs(row["delta"]), row["contributor_id"]),
        )
        selected = contributor_deltas[:limit]
        projection.update({
            "prior_period_id": prior["period_id"],
            "is_consecutive": prior["period_id"] == expected_prior,
            "prior_snapshot": self._snapshot_reference(prior),
            "direction": _risk_direction(direction_delta),
            "direction_basis": basis,
            "portfolio_score": {
                "prior": score_prior,
                "current": score_current,
                "delta": score_delta,
            },
            "risk_load": {
                "prior": load_prior,
                "current": load_current,
                "delta": load_delta,
            },
            "contributor_deltas": selected,
            "contributor_delta_count": len(contributor_deltas),
            "contributors_truncated": len(contributor_deltas) > limit,
            "drill_through_ids": {
                "contributor_ids": [row["contributor_id"] for row in selected],
                "finding_ids": sorted({
                    row["finding_id"]
                    for row in selected
                    if row["finding_id"] is not None
                }),
            },
        })
        projection["trend_sha256"] = _sha256(projection)
        return projection

    def get_contributor_drillthrough(
        self,
        period_id: str,
        contributor_id: str,
        *,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        """Return a content-free contributor/finding identifier projection."""

        identifier = str(contributor_id or "")
        if not _SAFE_DRILL_ID_RE.fullmatch(identifier):
            raise ValueError("contributor_id is invalid")
        snapshot = self.get_snapshot(period_id, now=now)
        if snapshot is None:
            return None
        contributor = self._trend_contributors(snapshot).get(identifier)
        if contributor is None:
            return None
        return {
            **self._snapshot_reference(snapshot),
            **contributor,
            "legal_certification": False,
            "compliance_verdict": "not_provided",
        }


_DEFAULT = PortfolioRiskService()


def current_report(*, now: float | None = None) -> dict[str, Any]:
    return _DEFAULT.current_report(now=now)


def refresh_current_snapshot(**kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.refresh_current_snapshot(**kwargs)


def get_snapshot(period_id: str, *, now: float | None = None) -> dict[str, Any] | None:
    return _DEFAULT.get_snapshot(period_id, now=now)


def list_snapshots(*, now: float | None = None) -> list[dict[str, Any]]:
    return _DEFAULT.list_snapshots(now=now)


def portfolio_trend(
    *,
    now: float | None = None,
    contributor_limit: int = 100,
) -> dict[str, Any]:
    """Return the bounded current-versus-prior-quarter trend projection."""

    return _DEFAULT.portfolio_trend(
        now=now,
        contributor_limit=contributor_limit,
    )


def get_contributor_drillthrough(
    period_id: str,
    contributor_id: str,
    *,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Return a content-free contributor reference for dashboard drill-through."""

    return _DEFAULT.get_contributor_drillthrough(
        period_id,
        contributor_id,
        now=now,
    )


__all__ = [
    "ClosedPortfolioPeriod",
    "FORMULA_VERSION",
    "PortfolioRiskConfigError",
    "PortfolioRiskError",
    "PortfolioRiskService",
    "PortfolioRiskStateError",
    "REPORT_SCHEMA",
    "SEVERITY_POINTS",
    "SNAPSHOT_SCHEMA",
    "TREND_SCHEMA",
    "current_report",
    "enabled",
    "get_contributor_drillthrough",
    "get_snapshot",
    "list_snapshots",
    "portfolio_trend",
    "refresh_current_snapshot",
]
