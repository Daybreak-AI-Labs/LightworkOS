"""Bridge versioned regulatory alerts into AI-governance impact and notices.

The finance regulatory-change engine is the source/version authority and the
AI evidence gateway is the policy-impact authority.  This module deliberately
does not reinterpret either.  Operators configure explicit :class:`ImpactRule`
mappings from a matched regime/domain to policy, control, asset, and evidence
records.  A matching upstream alert then creates:

* the existing ``ai-regulatory-impact.v1`` record for human review;
* a tenant-bound staleness record naming the exact evidence affected; and
* an idempotent customer notice which may be delivered through an injected
  notifier or Lightwork's configured notification backends.

Only bounded alert metadata and before/after values are retained.  Full source
documents, notification credentials, and delivery-provider receipts are never
persisted.  The output is decision support, not a legal applicability opinion.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

IMPACT_QUERY_SCHEMA = "lightwork.ai-regulatory-impact-query.v1"
STALENESS_SCHEMA = "lightwork.ai-regulatory-staleness.v1"
NOTICE_SCHEMA = "lightwork.ai-regulatory-customer-notice.v1"
NON_LEGAL_NOTICE = (
    "Regulatory-change decision support requiring human review; not legal "
    "advice, a legal applicability determination, or a certification."
)

_STALENESS = GovernedRecordStore(
    "ai_regulatory_staleness", "ARS", "ai_regulatory_staleness",
)
_NOTICES = GovernedRecordStore(
    "ai_regulatory_notices", "ARN", "ai_regulatory_customer_notice",
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_RULES = 256
_MAX_VALUES = 256
_MAX_EVIDENCE = 5_000
_MAX_RECORDS = 5_000
_MAX_DIFF_FIELDS = 64
_MAX_DIFF_VALUE = 1_000
_MAX_LIST_LIMIT = 500


class AIRegulatoryFeedError(RuntimeError):
    """Base failure for the AI regulatory-change bridge."""


class AIRegulatoryFeedConfigError(AIRegulatoryFeedError):
    """The default-off bridge or one of its dependencies is unavailable."""


class AIRegulatoryFeedStateError(AIRegulatoryFeedError):
    """Persisted authority or supplied regulatory evidence is malformed."""


@dataclass(frozen=True)
class ImpactRule:
    """An operator-reviewed mapping from regulation scope to tenant records."""

    rule_id: str
    regimes: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    policy_ids: tuple[str, ...] = ("default",)
    control_ids: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()
    evidence_kinds: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", _identity(self.rule_id, "rule_id"))
        for field_name in (
            "regimes", "domains", "policy_ids", "control_ids", "asset_ids",
            "evidence_kinds", "evidence_ids",
        ):
            normalized = _identities(getattr(self, field_name), field_name)
            object.__setattr__(self, field_name, tuple(normalized))
        if not self.regimes and not self.domains:
            raise ValueError("an impact rule requires at least one regime or domain")
        if not self.policy_ids:
            raise ValueError("an impact rule requires at least one policy_id")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=str,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _stable_id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{_sha256([str(part) for part in parts])[:32]}"


def _identity(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not _ID_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _identities(values: object, label: str) -> list[str]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise ValueError(f"{label} must be a bounded list")
    if len(values) > _MAX_VALUES:
        raise ValueError(f"{label} exceeds {_MAX_VALUES} values")
    return sorted({_identity(value, label) for value in values})


def _text(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if not text or len(text) > limit or _CONTROL_RE.search(text):
        raise ValueError(f"{label} is invalid")
    return text


def _digest(value: object, label: str) -> str:
    text = str(value or "").strip().lower().removeprefix("sha256:")
    if not _DIGEST_RE.fullmatch(text):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return text


def _https_url(value: object, label: str) -> str:
    text = _text(value, label, 2_000)
    parsed = urlsplit(text)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{label} must be a credential-free HTTPS URL")
    return text


def _timestamp(value: object, label: str) -> str:
    text = _text(value, label, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return text


def _revision(value: object, label: str = "expected_revision") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _require_tenant() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if not tenant:
        raise AIRegulatoryFeedStateError(
            "AI regulatory-change records require an explicit tenant authority"
        )
    return tenant


def _tenant_sha256() -> str:
    return hashlib.sha256(_require_tenant().encode("utf-8")).hexdigest()


def get_ai_regulatory_feed_config() -> dict[str, bool]:
    """Return validated deployment-global bridge configuration."""

    try:
        from .config import config_source_errors, load_global_config

        config = load_global_config()
        if config_source_errors(include_tenant=False) or not isinstance(config, dict):
            raise AIRegulatoryFeedConfigError(
                "AI regulatory-feed configuration is unreadable"
            )
    except AIRegulatoryFeedConfigError:
        raise
    except Exception as exc:
        raise AIRegulatoryFeedConfigError(
            "AI regulatory-feed configuration is unavailable"
        ) from exc
    section = config.get("ai_regulatory_feed") or {}
    if not isinstance(section, dict):
        raise AIRegulatoryFeedConfigError("ai_regulatory_feed must be a table")
    unknown = set(section) - {"enable"}
    if unknown:
        raise AIRegulatoryFeedConfigError(
            f"unknown ai_regulatory_feed keys: {', '.join(sorted(unknown))}"
        )
    value = section.get("enable", False)
    if not isinstance(value, bool):
        raise AIRegulatoryFeedConfigError(
            "ai_regulatory_feed.enable must be a boolean"
        )
    finance = config.get("finance_operations") or {}
    # The production feature gate is named ``[evidence_gateway]``.  The draft
    # originally looked for a non-existent ``[ai_evidence_gateway]`` table,
    # which made the bridge impossible to enable through a lint-valid config.
    gateway = config.get("evidence_gateway") or {}
    if not isinstance(finance, dict) or not isinstance(gateway, dict):
        raise AIRegulatoryFeedConfigError(
            "finance_operations and evidence_gateway must be tables"
        )
    return {
        "enable": value,
        "finance_operations_enable": finance.get("enable", False) is True,
        "ai_evidence_gateway_enable": gateway.get("enable", False) is True,
    }


def enabled() -> bool:
    try:
        config = get_ai_regulatory_feed_config()
        return bool(
            config["enable"]
            and config["finance_operations_enable"]
            and config["ai_evidence_gateway_enable"]
        )
    except Exception:
        return False


def _require_enabled() -> None:
    if not enabled():
        raise AIRegulatoryFeedConfigError(
            "AI regulatory feed requires [ai_regulatory_feed] enable = true, "
            "[finance_operations] enable = true, and "
            "[evidence_gateway] enable = true"
        )


def _mapping(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise ValueError("regulatory alert must be a mapping or dataclass")


def _citation(value: object) -> dict[str, Any]:
    row = _mapping(value)
    citation = {
        "source_name": _text(row.get("source_name"), "citation source_name", 256),
        "feed_url": _https_url(row.get("feed_url"), "citation feed_url"),
        "retrieval_url": _https_url(
            row.get("retrieval_url"), "citation retrieval_url"
        ),
        "record_url": _https_url(
            row.get("record_url") or row.get("url"), "citation record_url"
        ),
        "retrieved_at": _timestamp(row.get("retrieved_at"), "citation retrieved_at"),
        "content_sha256": _digest(
            row.get("content_sha256"), "citation content_sha256"
        ),
    }
    for field in ("payload_sha256", "source_record_sha256"):
        if row.get(field) not in (None, ""):
            citation[field] = _digest(row[field], f"citation {field}")
    for field, limit in {
        "source_format": 64,
        "parser_version": 64,
        "acquisition": 64,
        "acquired_by": 256,
        "official_citation": 1_000,
    }.items():
        if row.get(field) not in (None, ""):
            citation[field] = _text(row[field], f"citation {field}", limit)
    return citation


def _safe_diff_value(value: object) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("regulatory diff contains a non-finite number")
        return value
    if isinstance(value, str):
        text = value.strip()
        if len(text) > _MAX_DIFF_VALUE:
            text = text[: _MAX_DIFF_VALUE - 1] + "…"
        if _CONTROL_RE.search(text):
            raise ValueError("regulatory diff contains control characters")
        return text
    # Nested publisher metadata can be large and may contain arbitrary source
    # text.  Bind it through the alert digest but do not copy it into notices.
    return {"value_sha256": _sha256(value), "redacted": True}


def _safe_diff(value: object) -> list[dict[str, object]]:
    if not isinstance(value, Mapping):
        raise ValueError("regulatory alert diff must be a mapping")
    if len(value) > _MAX_DIFF_FIELDS:
        raise ValueError("regulatory alert diff exceeds the field limit")
    changes: list[dict[str, object]] = []
    for raw_path in sorted(value, key=str):
        path = _text(str(raw_path), "regulatory diff path", 256)
        entry = value[raw_path]
        if not isinstance(entry, Mapping):
            raise ValueError("regulatory alert diff entry must be a mapping")
        changes.append({
            "path": path,
            "before": _safe_diff_value(entry.get("before")),
            "after": _safe_diff_value(entry.get("after")),
        })
    return changes


def _alert(value: object) -> dict[str, Any]:
    row = _mapping(value)
    citations_raw = row.get("citations")
    if (
        isinstance(citations_raw, (str, bytes, bytearray))
        or not isinstance(citations_raw, Sequence)
        or not 1 <= len(citations_raw) <= 64
    ):
        raise ValueError("regulatory alert citations must be a bounded list")
    citations = sorted(
        [_citation(citation) for citation in citations_raw],
        key=lambda citation: (citation["source_name"], citation["record_url"]),
    )
    document_version = row.get("document_version")
    revision = row.get("revision")
    if (
        isinstance(document_version, bool)
        or not isinstance(document_version, int)
        or document_version < 1
    ):
        raise ValueError("document_version must be a positive integer")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("alert revision must be a positive integer")
    matched_regimes = _identities(row.get("matched_regimes") or (), "matched_regimes")
    matched_domains = _identities(row.get("matched_domains") or (), "matched_domains")
    if not matched_regimes and not matched_domains:
        raise ValueError("regulatory alert has no matched tenant scope")
    return {
        "alert_id": _identity(row.get("alert_id"), "alert_id"),
        "source_key": _identity(row.get("source_key"), "source_key"),
        "external_id": _identity(row.get("external_id"), "external_id"),
        "document_version": document_version,
        "content_sha256": _digest(row.get("content_sha256"), "content_sha256"),
        "title": _text(row.get("title"), "alert title", 2_000),
        "jurisdiction": _identity(row.get("jurisdiction"), "jurisdiction"),
        "record_url": _https_url(row.get("record_url"), "record_url"),
        "official_citation": (
            None
            if row.get("official_citation") in (None, "")
            else _text(row.get("official_citation"), "official_citation", 1_000)
        ),
        "change_kind": _identity(row.get("change_kind"), "change_kind"),
        "changes": _safe_diff(row.get("diff") or {}),
        "matched_regimes": matched_regimes,
        "matched_domains": matched_domains,
        "citations": citations,
        "revision": revision,
    }


def _validate_rules(rules: object) -> list[ImpactRule]:
    if isinstance(rules, (str, bytes, bytearray)) or not isinstance(rules, Sequence):
        raise ValueError("impact rules must be a bounded list")
    if not 1 <= len(rules) <= _MAX_RULES:
        raise ValueError(f"impact rules must contain between 1 and {_MAX_RULES} rows")
    normalized: list[ImpactRule] = []
    for value in rules:
        normalized.append(value if isinstance(value, ImpactRule) else ImpactRule(**_mapping(value)))
    if len({rule.rule_id for rule in normalized}) != len(normalized):
        raise ValueError("impact rule ids must be unique")
    return sorted(normalized, key=lambda rule: rule.rule_id)


def query_impact(
    alert: object,
    rules: Sequence[ImpactRule | Mapping[str, Any]],
    *,
    evidence_records: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Resolve explicit affected controls and customer records for one alert."""

    normalized_alert = _alert(alert)
    normalized_rules = _validate_rules(rules)
    if len(evidence_records) > _MAX_EVIDENCE:
        raise ValueError("evidence_records exceeds the operational limit")
    evidence: dict[str, Mapping[str, Any]] = {}
    for record in evidence_records:
        if not isinstance(record, Mapping):
            raise ValueError("evidence record must be a mapping")
        record_id = _identity(record.get("id"), "evidence id")
        if record_id in evidence:
            raise ValueError("duplicate evidence id")
        evidence[record_id] = record

    matched_regimes = set(normalized_alert["matched_regimes"])
    matched_domains = set(normalized_alert["matched_domains"])
    matched: list[ImpactRule] = [
        rule
        for rule in normalized_rules
        if matched_regimes.intersection(rule.regimes)
        or matched_domains.intersection(rule.domains)
    ]
    policy_ids = sorted({value for rule in matched for value in rule.policy_ids})
    control_ids = sorted({value for rule in matched for value in rule.control_ids})
    asset_ids = sorted({value for rule in matched for value in rule.asset_ids})
    explicit_evidence = {value for rule in matched for value in rule.evidence_ids}
    evidence_kinds = {value for rule in matched for value in rule.evidence_kinds}
    stale_evidence_ids = set(explicit_evidence)
    for record_id, record in evidence.items():
        if (
            (asset_ids and record.get("asset_id") in asset_ids)
            or (evidence_kinds and record.get("evidence_kind") in evidence_kinds)
        ):
            stale_evidence_ids.add(record_id)
    missing = explicit_evidence - set(evidence)
    if missing:
        raise AIRegulatoryFeedStateError(
            "impact rule cites unknown evidence: " + ", ".join(sorted(missing))
        )
    body = {
        "schema": IMPACT_QUERY_SCHEMA,
        "alert_id": normalized_alert["alert_id"],
        "alert_revision": normalized_alert["revision"],
        "content_sha256": normalized_alert["content_sha256"],
        "matched_rule_ids": [rule.rule_id for rule in matched],
        "affected_policy_ids": policy_ids,
        "control_ids": control_ids,
        "affected_asset_ids": asset_ids,
        "stale_evidence_ids": sorted(stale_evidence_ids),
        "match_reasons": [
            f"operator rule {rule.rule_id} matched regulatory scope"
            for rule in matched
        ],
    }
    body["query_sha256"] = _sha256(body)
    return body


def _public(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in record.items()
        if key != "_audit_pending" and not str(key).startswith("pending_")
    }


class RegulatoryFeedBridge:
    """Tenant-bound, crash-recoverable regulatory impact bridge."""

    def __init__(
        self,
        *,
        staleness_store: GovernedRecordStore | None = None,
        notice_store: GovernedRecordStore | None = None,
        impact_recorder: Callable[..., Mapping[str, Any]] | None = None,
        evidence_lister: Callable[[], Sequence[Mapping[str, Any]]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._staleness = staleness_store or _STALENESS
        self._notices = notice_store or _NOTICES
        self._impact_recorder = impact_recorder
        self._evidence_lister = evidence_lister
        self._clock = clock or time.time

    @staticmethod
    def _capacity(store: GovernedRecordStore, label: str) -> None:
        if len(store.list(limit=_MAX_RECORDS + 1)) > _MAX_RECORDS:
            raise AIRegulatoryFeedStateError(
                f"{label} exceeds the {_MAX_RECORDS}-record capacity"
            )

    def _evidence(self) -> list[Mapping[str, Any]]:
        if self._evidence_lister is not None:
            rows = list(self._evidence_lister())
        else:
            from . import model_risk_assurance as mra

            rows = list(mra.list_evidence())
        if len(rows) > _MAX_EVIDENCE:
            raise AIRegulatoryFeedStateError("model-risk evidence exceeds the bridge limit")
        return rows

    def _record_impact(self, alert: Mapping[str, Any], impact: Mapping[str, Any], actor: str) -> dict[str, Any]:
        recorder = self._impact_recorder
        if recorder is None:
            from .ai_evidence.delivery import record_regulatory_impact

            recorder = record_regulatory_impact
        saved = recorder(
            alert["alert_id"],
            alert_revision=alert["revision"],
            content_sha256=alert["content_sha256"],
            citations=alert["citations"],
            affected_policy_ids=impact["affected_policy_ids"],
            affected_asset_ids=impact["affected_asset_ids"],
            control_ids=impact["control_ids"],
            match_reasons=impact["match_reasons"],
            actor=actor,
        )
        if not isinstance(saved, Mapping):
            raise AIRegulatoryFeedStateError("impact recorder returned no governed record")
        return _public(saved)

    def sync_alert(
        self,
        alert: object,
        *,
        rules: Sequence[ImpactRule | Mapping[str, Any]],
        actor: str,
        deliver: bool = False,
        notification_sink: Callable[[Mapping[str, Any]], object] | None = None,
    ) -> dict[str, Any]:
        """Create/recover impact, staleness, and notice records for an alert."""

        _require_enabled()
        tenant_sha256 = _tenant_sha256()
        operator = _text(actor, "actor", 256)
        normalized_alert = _alert(alert)
        impact_query = query_impact(
            normalized_alert,
            rules,
            evidence_records=self._evidence(),
        )
        if not impact_query["matched_rule_ids"]:
            raise AIRegulatoryFeedStateError(
                "regulatory alert does not match an operator-reviewed impact rule"
            )
        impact = self._record_impact(normalized_alert, impact_query, operator)
        impact_id = _identity(impact.get("id") or impact.get("impact_id"), "impact id")

        self._capacity(self._staleness, "regulatory staleness")
        staleness_id = _stable_id("ARS", tenant_sha256, impact_id)
        staleness_body = {
            "id": staleness_id,
            "schema": STALENESS_SCHEMA,
            "tenant_sha256": tenant_sha256,
            "impact_id": impact_id,
            "alert_id": normalized_alert["alert_id"],
            "alert_revision": normalized_alert["revision"],
            "content_sha256": normalized_alert["content_sha256"],
            "query_sha256": impact_query["query_sha256"],
            "affected_policy_ids": impact_query["affected_policy_ids"],
            "affected_asset_ids": impact_query["affected_asset_ids"],
            "control_ids": impact_query["control_ids"],
            "stale_evidence_ids": impact_query["stale_evidence_ids"],
            "state": "active",
            "resolution": None,
        }
        staleness = self._create_exact(
            self._staleness,
            staleness_body,
            action="ai_regulatory_staleness_recorded",
            actor=operator,
            mutable_fields=frozenset({"state", "resolution"}),
        )

        self._capacity(self._notices, "regulatory notices")
        notice_id = _stable_id("ARN", tenant_sha256, impact_id)
        notice_body = {
            "id": notice_id,
            "schema": NOTICE_SCHEMA,
            "tenant_sha256": tenant_sha256,
            "impact_id": impact_id,
            "alert_id": normalized_alert["alert_id"],
            "alert_revision": normalized_alert["revision"],
            "content_sha256": normalized_alert["content_sha256"],
            "title": normalized_alert["title"],
            "jurisdiction": normalized_alert["jurisdiction"],
            "record_url": normalized_alert["record_url"],
            "official_citation": normalized_alert["official_citation"],
            "change_kind": normalized_alert["change_kind"],
            "changes": normalized_alert["changes"],
            "affected_policy_ids": impact_query["affected_policy_ids"],
            "affected_asset_ids": impact_query["affected_asset_ids"],
            "control_ids": impact_query["control_ids"],
            "stale_evidence_ids": impact_query["stale_evidence_ids"],
            "notice": NON_LEGAL_NOTICE,
            "delivery": {
                "status": "pending",
                "attempts": 0,
                "delivered_at": None,
                "last_error_type": None,
            },
        }
        notice = self._create_exact(
            self._notices,
            notice_body,
            action="ai_regulatory_notice_queued",
            actor=operator,
            mutable_fields=frozenset({"delivery"}),
        )
        if deliver and notice["delivery"]["status"] != "sent":
            notice = self.deliver_notice(
                notice_id,
                expected_revision=int(notice["revision"]),
                actor=operator,
                notification_sink=notification_sink,
            )
        return {
            "impact_query": impact_query,
            "impact": impact,
            "staleness": staleness,
            "notice": notice,
        }

    def sync_finance_alert(
        self,
        alert_id: str,
        *,
        rules: Sequence[ImpactRule | Mapping[str, Any]],
        actor: str,
        deliver: bool = False,
        notification_sink: Callable[[Mapping[str, Any]], object] | None = None,
        engine: object | None = None,
    ) -> dict[str, Any]:
        """Load an alert from the governed finance engine before bridging it.

        The dashboard and schedulers use this entry point so callers cannot
        substitute an arbitrary alert body for the finance engine's versioned,
        citation-complete authority record.
        """

        _require_enabled()
        _require_tenant()
        identifier = _identity(alert_id, "alert_id")
        authority = engine
        if authority is None:
            from .finance.regulatory_change import RegulatoryChangeEngine
            from .paths import data_dir

            authority = RegulatoryChangeEngine(
                data_dir("finance_operations", "regulatory_change.sqlite3")
            )
        getter = getattr(authority, "get_alert", None)
        if not callable(getter):
            raise AIRegulatoryFeedStateError(
                "regulatory source authority does not expose get_alert"
            )
        alert = getter(identifier)
        if alert is None:
            raise AIRegulatoryFeedStateError("regulatory alert does not exist")
        return self.sync_alert(
            alert,
            rules=rules,
            actor=actor,
            deliver=deliver,
            notification_sink=notification_sink,
        )

    @staticmethod
    def _create_exact(
        store: GovernedRecordStore,
        body: Mapping[str, Any],
        *,
        action: str,
        actor: str,
        mutable_fields: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        existing = store.get(str(body["id"]))
        if existing is not None:
            for key, value in body.items():
                if key in mutable_fields:
                    continue
                if existing.get(key) != value:
                    raise RecordConflict(
                        "regulatory bridge identity was reused with different content"
                    )
            return _public(existing)
        try:
            return _public(store.create(dict(body), action=action, actor=actor))
        except RecordConflict:
            recovered = store.get(str(body["id"]))
            if recovered is None:
                raise
            for key, value in body.items():
                if key in mutable_fields:
                    continue
                if recovered.get(key) != value:
                    raise
            return _public(recovered)

    @staticmethod
    def _default_sink(payload: Mapping[str, Any]) -> bool:
        from .notifications import notify

        controls = ", ".join(payload.get("control_ids") or []) or "none named"
        evidence = ", ".join(payload.get("stale_evidence_ids") or []) or "none named"
        fired = notify(
            (
                f"{payload['title']}\nControls: {controls}\n"
                f"Evidence now stale: {evidence}\n{payload['record_url']}"
            ),
            title="Lightwork regulatory change",
            priority="high",
            category="ai_regulatory_change",
            async_dispatch=False,
            batch=False,
        )
        return fired > 0

    def deliver_notice(
        self,
        notice_id: str,
        *,
        expected_revision: int,
        actor: str,
        notification_sink: Callable[[Mapping[str, Any]], object] | None = None,
    ) -> dict[str, Any]:
        """Deliver a safe notice projection with CAS retry semantics."""

        _require_enabled()
        tenant_sha256 = _tenant_sha256()
        record_id = _identity(notice_id, "notice_id")
        expected = _revision(expected_revision)
        operator = _text(actor, "actor", 256)
        current = self._notices.get(record_id)
        if current is None:
            raise AIRegulatoryFeedStateError("regulatory notice does not exist")
        if current.get("tenant_sha256") != tenant_sha256:
            raise AIRegulatoryFeedStateError("regulatory notice tenant binding failed")
        delivery = current.get("delivery")
        if not isinstance(delivery, Mapping):
            raise AIRegulatoryFeedStateError("regulatory notice delivery state is malformed")
        if delivery.get("status") == "sent":
            return _public(current)
        if int(current.get("revision", -1)) != expected:
            raise RecordConflict("regulatory notice changed before delivery")
        payload = self._notice_projection(current)
        sink = notification_sink or self._default_sink
        error_type: str | None = None
        delivered = False
        try:
            delivered = bool(sink(payload))
            if not delivered:
                error_type = "NotificationNotDelivered"
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # failure-policy: visible_degradation
            error_type = type(exc).__name__

        def mutate(row: dict[str, Any]) -> None:
            state = row.get("delivery")
            if not isinstance(state, Mapping) or state.get("status") == "sent":
                raise RecordConflict("regulatory notice delivery authority changed")
            attempts = state.get("attempts")
            if isinstance(attempts, bool) or not isinstance(attempts, int):
                raise AIRegulatoryFeedStateError("notice attempts are malformed")
            row["delivery"] = {
                "status": "sent" if delivered else "failed",
                "attempts": attempts + 1,
                "delivered_at": float(self._clock()) if delivered else None,
                "last_error_type": error_type,
            }

        saved = self._notices.update(
            record_id,
            mutate,
            expected_revision=expected,
            action=(
                "ai_regulatory_notice_delivered"
                if delivered
                else "ai_regulatory_notice_delivery_failed"
            ),
            actor=operator,
        )
        if saved is None:
            raise AIRegulatoryFeedStateError("regulatory notice disappeared")
        return _public(saved)

    @staticmethod
    def _notice_projection(record: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": NOTICE_SCHEMA,
            "notice_id": record.get("id"),
            "idempotency_key": record.get("id"),
            "title": record.get("title"),
            "jurisdiction": record.get("jurisdiction"),
            "record_url": record.get("record_url"),
            "official_citation": record.get("official_citation"),
            "change_kind": record.get("change_kind"),
            "changes": record.get("changes"),
            "affected_policy_ids": record.get("affected_policy_ids"),
            "affected_asset_ids": record.get("affected_asset_ids"),
            "control_ids": record.get("control_ids"),
            "stale_evidence_ids": record.get("stale_evidence_ids"),
            "notice": NON_LEGAL_NOTICE,
        }

    def get_notice(self, notice_id: str) -> dict[str, Any] | None:
        _require_enabled()
        tenant_sha256 = _tenant_sha256()
        row = self._notices.get(_identity(notice_id, "notice_id"))
        if row is None:
            return None
        if row.get("tenant_sha256") != tenant_sha256:
            raise AIRegulatoryFeedStateError("regulatory notice tenant binding failed")
        return _public(row)

    def list_notices(self, *, limit: int = 100) -> list[dict[str, Any]]:
        _require_enabled()
        tenant_sha256 = _tenant_sha256()
        bounded = _revision(limit, "limit")
        if not 1 <= bounded <= _MAX_LIST_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST_LIMIT}")
        rows = self._notices.list(limit=bounded + 1)
        if len(rows) > bounded:
            rows = rows[:bounded]
        out = []
        for row in rows:
            if row.get("tenant_sha256") != tenant_sha256:
                raise AIRegulatoryFeedStateError("regulatory notice tenant binding failed")
            out.append(_public(row))
        return sorted(out, key=lambda row: str(row.get("id") or ""))

    def list_active_staleness(
        self,
        *,
        evidence_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        _require_enabled()
        tenant_sha256 = _tenant_sha256()
        selected = None if evidence_id is None else _identity(evidence_id, "evidence_id")
        bounded = _revision(limit, "limit")
        if not 1 <= bounded <= _MAX_LIST_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST_LIMIT}")
        rows = self._staleness.list(limit=_MAX_RECORDS + 1)
        if len(rows) > _MAX_RECORDS:
            raise AIRegulatoryFeedStateError("regulatory staleness exceeds capacity")
        out = []
        for row in rows:
            if row.get("tenant_sha256") != tenant_sha256:
                raise AIRegulatoryFeedStateError("regulatory staleness tenant binding failed")
            if row.get("state") != "active":
                continue
            stale_ids = row.get("stale_evidence_ids")
            if not isinstance(stale_ids, list):
                raise AIRegulatoryFeedStateError("stale evidence binding is malformed")
            if selected is None or selected in stale_ids:
                out.append(_public(row))
        return sorted(out, key=lambda row: str(row.get("id") or ""))[:bounded]

    def resolve_staleness(
        self,
        staleness_id: str,
        *,
        expected_revision: int,
        resolution: str,
        actor: str,
    ) -> dict[str, Any]:
        """Human-CAS resolve a staleness record after control/evidence refresh."""

        _require_enabled()
        tenant_sha256 = _tenant_sha256()
        record_id = _identity(staleness_id, "staleness_id")
        expected = _revision(expected_revision)
        reason = _text(resolution, "resolution", 4_000)
        operator = _text(actor, "actor", 256)

        def mutate(row: dict[str, Any]) -> None:
            if row.get("tenant_sha256") != tenant_sha256 or row.get("state") != "active":
                raise RecordConflict("regulatory staleness authority changed")
            row["state"] = "resolved"
            row["resolution"] = {
                "actor": operator,
                "rationale": reason,
                "resolved_at": float(self._clock()),
            }

        saved = self._staleness.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="ai_regulatory_staleness_resolved",
            actor=operator,
        )
        if saved is None:
            raise AIRegulatoryFeedStateError("regulatory staleness does not exist")
        return _public(saved)


_DEFAULT = RegulatoryFeedBridge()


def sync_alert(alert: object, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.sync_alert(alert, **kwargs)


def sync_finance_alert(alert_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.sync_finance_alert(alert_id, **kwargs)


def list_reviewed_alerts(*, status: str = "accepted", limit: int = 100) -> list[Any]:
    """The finance regulatory-change queue page the bridge reads."""
    from .finance.regulatory_change import RegulatoryChangeEngine
    from .paths import data_dir

    engine = RegulatoryChangeEngine(
        data_dir("finance_operations", "regulatory_change.sqlite3")
    )
    return engine.list_alerts(status=status, limit=limit)


def sync_reviewed_alerts(
    *,
    rules: Sequence[Mapping[str, Any]],
    actor: str,
    status: str = "accepted",
    limit: int = 100,
    deliver: bool = False,
) -> dict[str, Any]:
    """Run each alert in one review-queue state through the bridge.

    Idempotent per alert (the bridge is). Listing failures raise; a failure
    on one alert is collected and the others still run. Returns the number
    of alerts read, one row per alert that produced an impact record, the
    per-alert failures, and whether nothing was queued.
    """
    alerts = list_reviewed_alerts(status=status, limit=limit)
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    for alert in alerts:
        try:
            result = sync_alert(alert, rules=rules, actor=actor, deliver=deliver)
        except (KeyError, ValueError, RuntimeError) as exc:
            failures.append(f"{getattr(alert, 'alert_id', '?')}: {exc}")
            continue
        impact = result.get("impact")
        if impact is None:
            continue
        staleness = result.get("staleness") or {}
        notice = result.get("notice") or {}
        rows.append({
            "alert_id": getattr(alert, "alert_id", "?"),
            "impact_id": impact.get("id"),
            "stale_evidence": len(staleness.get("stale_evidence_ids") or []),
            "notice_id": notice.get("id"),
            "notice_status": (notice.get("delivery") or {}).get("status"),
        })
    return {"alerts": len(alerts), "bridged": rows, "failures": failures}


def deliver_notice(notice_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.deliver_notice(notice_id, **kwargs)


def get_notice(notice_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_notice(notice_id)


def list_notices(*, limit: int = 100) -> list[dict[str, Any]]:
    return _DEFAULT.list_notices(limit=limit)


def list_active_staleness(
    *, evidence_id: str | None = None, limit: int = 100,
) -> list[dict[str, Any]]:
    return _DEFAULT.list_active_staleness(evidence_id=evidence_id, limit=limit)


def resolve_staleness(staleness_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.resolve_staleness(staleness_id, **kwargs)


__all__ = [
    "list_reviewed_alerts",
    "sync_reviewed_alerts",
    "AIRegulatoryFeedConfigError",
    "AIRegulatoryFeedError",
    "AIRegulatoryFeedStateError",
    "IMPACT_QUERY_SCHEMA",
    "ImpactRule",
    "NON_LEGAL_NOTICE",
    "NOTICE_SCHEMA",
    "RegulatoryFeedBridge",
    "STALENESS_SCHEMA",
    "deliver_notice",
    "enabled",
    "get_ai_regulatory_feed_config",
    "get_notice",
    "list_active_staleness",
    "list_notices",
    "query_impact",
    "resolve_staleness",
    "sync_alert",
    "sync_finance_alert",
]
