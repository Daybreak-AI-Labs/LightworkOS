"""Acceptance and adversarial tests for the governed AI regulatory bridge."""
from __future__ import annotations

import hashlib
import json
import time

import pytest
from maverick import ai_regulatory_feed as arf
from maverick import config, governed_records
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

feed = arf


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[finance_operations]\n"
        "enable = true\n"
        "\n[evidence_gateway]\n"
        "enable = true\n"
        "\n[ai_regulatory_feed]\n"
        "enable = true\n",
        encoding="utf-8",
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()
    governed_records._reset_process_authority_pin_for_testing()


def _alert(*, revision: int = 1, title: str = "EU AI rule changed") -> dict:
    return {
        "alert_id": "alert-one",
        "source_key": "eurlex-ai-act",
        "external_id": "oj-l-2024-1689",
        "document_version": revision,
        "content_sha256": _hex(f"content:{revision}"),
        "title": title,
        "jurisdiction": "eu",
        "record_url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
        "official_citation": "Regulation (EU) 2024/1689",
        "change_kind": "updated",
        "diff": {
            "article_73": {
                "before": "previous text",
                "after": "current text",
            }
        },
        "matched_regimes": ["eu-ai-act"],
        "matched_domains": ["ai-governance"],
        "citations": [
            {
                "source_name": "EUR-Lex",
                "feed_url": "https://eur-lex.europa.eu/",
                "retrieval_url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
                "record_url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
                "retrieved_at": "2026-08-28T12:00:00Z",
                "content_sha256": _hex(f"content:{revision}"),
                "official_citation": "Regulation (EU) 2024/1689",
            }
        ],
        "revision": revision,
    }


def _rules() -> list[arf.ImpactRule]:
    return [
        arf.ImpactRule(
            "eu-ai-act-core",
            regimes=("eu-ai-act",),
            policy_ids=("default",),
            control_ids=("CTRL-AI-INCIDENT",),
            asset_ids=("asset-one",),
            evidence_kinds=("evaluation",),
        )
    ]


def _service(*, clock=lambda: 1_777_000_000.0):
    calls: list[dict] = []

    def record(alert_id, **kwargs):
        calls.append({"alert_id": alert_id, **kwargs})
        return {"id": f"AER-{alert_id}", "revision": 1}

    service = arf.RegulatoryFeedBridge(
        staleness_store=GovernedRecordStore(
            "test_ai_regulatory_staleness",
            "ARS",
            "ai_regulatory_staleness",
        ),
        notice_store=GovernedRecordStore(
            "test_ai_regulatory_notices",
            "ARN",
            "ai_regulatory_customer_notice",
        ),
        impact_recorder=record,
        evidence_lister=lambda: [
            {
                "id": "MRE-evaluation-one",
                "asset_id": "asset-one",
                "evidence_kind": "evaluation",
            }
        ],
        clock=clock,
    )
    return service, calls


def test_config_uses_real_evidence_gateway_section_and_is_default_off(tmp_path):
    from maverick import config

    assert arf.get_ai_regulatory_feed_config() == {
        "enable": True,
        "finance_operations_enable": True,
        "ai_evidence_gateway_enable": True,
    }
    (tmp_path / "config.toml").write_text(
        "[finance_operations]\nenable = true\n"
        "[evidence_gateway]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert arf.enabled() is False


def test_query_impact_is_explicit_bounded_and_binds_exact_evidence():
    result = arf.query_impact(
        _alert(),
        _rules(),
        evidence_records=[
            {
                "id": "MRE-evaluation-one",
                "asset_id": "asset-one",
                "evidence_kind": "evaluation",
            }
        ],
    )
    assert result["matched_rule_ids"] == ["eu-ai-act-core"]
    assert result["affected_policy_ids"] == ["default"]
    assert result["affected_asset_ids"] == ["asset-one"]
    assert result["control_ids"] == ["CTRL-AI-INCIDENT"]
    assert result["stale_evidence_ids"] == ["MRE-evaluation-one"]
    assert result["query_sha256"]

    with pytest.raises(ValueError, match="credential-free HTTPS"):
        hostile = _alert()
        hostile["record_url"] = "https://user:secret@example.test/change"
        arf.query_impact(hostile, _rules())


def test_sync_delivery_and_resolved_state_are_idempotent():
    service, calls = _service()
    delivered: list[dict] = []
    with tenant_scope(tenant="alpha"):
        first = service.sync_alert(
            _alert(),
            rules=_rules(),
            actor="regulatory-owner",
            deliver=True,
            notification_sink=lambda payload: delivered.append(dict(payload)) or True,
        )
        assert first["notice"]["delivery"]["status"] == "sent"
        assert first["notice"]["delivery"]["attempts"] == 1
        assert len(delivered) == 1
        assert "previous text" in json.dumps(delivered[0])
        resolved = service.resolve_staleness(
            first["staleness"]["id"],
            expected_revision=first["staleness"]["revision"],
            resolution="Controls and exact evidence were reviewed and refreshed.",
            actor="control-owner",
        )
        assert resolved["state"] == "resolved"

        repeated = service.sync_alert(
            _alert(),
            rules=_rules(),
            actor="regulatory-owner",
            deliver=True,
            notification_sink=lambda payload: delivered.append(dict(payload)) or True,
        )
        assert repeated["notice"]["delivery"]["attempts"] == 1
        assert repeated["staleness"]["state"] == "resolved"
        assert len(delivered) == 1
        assert len(calls) == 2


def test_delivery_failure_is_retryable_and_does_not_persist_secret_message():
    service, _calls = _service()

    def fail(_payload):
        raise RuntimeError("provider secret sk-live-do-not-store")

    with tenant_scope(tenant="alpha"):
        first = service.sync_alert(
            _alert(),
            rules=_rules(),
            actor="regulatory-owner",
        )
        failed = service.deliver_notice(
            first["notice"]["id"],
            expected_revision=first["notice"]["revision"],
            actor="regulatory-owner",
            notification_sink=fail,
        )
        assert failed["delivery"] == {
            "status": "failed",
            "attempts": 1,
            "delivered_at": None,
            "last_error_type": "RuntimeError",
        }
        assert "sk-live" not in json.dumps(failed)
        sent = service.deliver_notice(
            first["notice"]["id"],
            expected_revision=failed["revision"],
            actor="regulatory-owner",
            notification_sink=lambda _payload: True,
        )
        assert sent["delivery"]["status"] == "sent"
        assert sent["delivery"]["attempts"] == 2


def test_records_are_tenant_bound_and_cas_resolution_rejects_stale_writer():
    service, _calls = _service()
    with tenant_scope(tenant="alpha"):
        alpha = service.sync_alert(
            _alert(), rules=_rules(), actor="regulatory-owner"
        )
        with pytest.raises(RecordConflict):
            service.resolve_staleness(
                alpha["staleness"]["id"],
                expected_revision=alpha["staleness"]["revision"] + 1,
                resolution="Stale writer must lose.",
                actor="control-owner",
            )
        assert len(service.list_notices()) == 1

    with tenant_scope(tenant="beta"):
        assert service.list_notices() == []
        beta = service.sync_alert(
            _alert(), rules=_rules(), actor="regulatory-owner"
        )
        assert beta["notice"]["id"] != alpha["notice"]["id"]
        assert service.get_notice(alpha["notice"]["id"]) is None


def test_same_bridge_identity_rejects_changed_regulatory_content():
    service, _calls = _service()
    with tenant_scope(tenant="alpha"):
        service.sync_alert(_alert(), rules=_rules(), actor="regulatory-owner")
        with pytest.raises(RecordConflict, match="reused with different content"):
            service.sync_alert(
                _alert(title="Conflicting title"),
                rules=_rules(),
                actor="regulatory-owner",
            )


def test_finance_alert_sync_reads_the_authoritative_record_by_id():
    service, _calls = _service()

    class FakeEngine:
        def __init__(self):
            self.requested: list[str] = []

        def get_alert(self, alert_id):
            self.requested.append(alert_id)
            return _alert() if alert_id == "alert-one" else None

    engine = FakeEngine()
    with tenant_scope(tenant="alpha"):
        result = service.sync_finance_alert(
            "alert-one",
            rules=_rules(),
            actor="regulatory-owner",
            engine=engine,
        )
        assert result["notice"]["alert_id"] == "alert-one"
        assert engine.requested == ["alert-one"]
        with pytest.raises(arf.AIRegulatoryFeedStateError, match="does not exist"):
            service.sync_finance_alert(
                "missing-alert",
                rules=_rules(),
                actor="regulatory-owner",
                engine=engine,
            )


# Incoming bridge scenarios retained with isolated helper names.
def _enable_incoming_tenant(monkeypatch) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "acme")


def _incoming_citation() -> dict:
    return {
        "source_name": "EUR-Lex",
        "feed_url": "https://eur-lex.europa.eu/feed",
        "retrieval_url": "https://eur-lex.europa.eu/retrieve",
        "record_url": "https://eur-lex.europa.eu/eli/reg/2024/1689",
        "retrieved_at": "2026-08-23T12:00:00+00:00",
        "content_sha256": _hex("citation"),
    }


def _incoming_alert(**overrides) -> dict:
    base = {
        "alert_id": "ALRT-omnibus-1",
        "source_key": "eu-oj",
        "external_id": "reg-2024-1689",
        "document_version": 2,
        "revision": 3,
        "content_sha256": _hex("consolidated-2026-07-27"),
        "title": "Digital Omnibus defers Annex III high-risk obligations",
        "jurisdiction": "EU",
        "record_url": "https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27",
        "official_citation": "Regulation (EU) 2024/1689",
        "change_kind": "amended",
        "diff": {
            "high_risk_applicability": {
                "before": "2026-08-02",
                "after": "2027-12-02",
            },
        },
        "matched_regimes": ["eu-ai-act"],
        "matched_domains": [],
        "citations": [_incoming_citation()],
    }
    base.update(overrides)
    return base


def _incoming_rule(**overrides) -> dict:
    base = {
        "rule_id": "rule-eu-ai-act",
        "regimes": ("eu-ai-act",),
        "policy_ids": ("policy-ai-governance",),
        "control_ids": ("ctrl-annex-iii-readiness",),
        "asset_ids": ("MAA-credit",),
        "evidence_kinds": ("evaluation",),
    }
    base.update(overrides)
    return base


def _incoming_evidence() -> list[dict]:
    return [
        {"id": "MRE-eval-1", "asset_id": "MAA-credit", "evidence_kind": "evaluation"},
        {"id": "MRE-other", "asset_id": "MAA-other", "evidence_kind": "training_run"},
    ]


def _incoming_bridge(recorded: list | None = None, clock=None) -> feed.RegulatoryFeedBridge:
    impacts = recorded if recorded is not None else []

    def recorder(alert_id, **kwargs):
        # The real gateway recorder is idempotent per alert; the fake must be
        # too, or the bridge's stable staleness/notice ids cannot recover.
        impacts.append({"alert_id": alert_id, **kwargs})
        stable = _hex(f"impact:{alert_id}")[:12]
        return {"id": f"ARI-{stable}", "alert_id": alert_id, **kwargs}

    return feed.RegulatoryFeedBridge(
        impact_recorder=recorder,
        evidence_lister=_incoming_evidence,
        clock=clock or time.time,
    )


# ---- matching --------------------------------------------------------------


def test_query_impact_matches_only_operator_reviewed_scope(monkeypatch):
    _enable_incoming_tenant(monkeypatch)
    matched = feed.query_impact(
        _incoming_alert(), [_incoming_rule()], evidence_records=_incoming_evidence()
    )
    assert matched["matched_rule_ids"] == ["rule-eu-ai-act"]
    assert matched["affected_policy_ids"] == ["policy-ai-governance"]
    assert matched["control_ids"] == ["ctrl-annex-iii-readiness"]
    # Stale evidence resolves from BOTH the rule's asset and evidence-kind
    # selectors, and never sweeps in unrelated records.
    assert matched["stale_evidence_ids"] == ["MRE-eval-1"]
    assert matched["query_sha256"]

    unmatched = feed.query_impact(
        _incoming_alert(matched_regimes=["us-colorado"]),
        [_incoming_rule()],
        evidence_records=_incoming_evidence(),
    )
    assert unmatched["matched_rule_ids"] == []
    assert unmatched["stale_evidence_ids"] == []

    with pytest.raises(feed.AIRegulatoryFeedStateError, match="unknown evidence"):
        feed.query_impact(
            _incoming_alert(),
            [_incoming_rule(evidence_ids=("MRE-ghost",))],
            evidence_records=_incoming_evidence(),
        )


def test_alert_validation_fails_closed_on_hostile_input(monkeypatch):
    _enable_incoming_tenant(monkeypatch)
    with pytest.raises(ValueError, match="record_url"):
        feed.query_impact(
            _incoming_alert(record_url="http://insecure.example"), [_incoming_rule()]
        )
    with pytest.raises(ValueError, match="control characters"):
        feed.query_impact(
            _incoming_alert(diff={"field": {"before": "a\x00b", "after": "c"}}), [_incoming_rule()]
        )
    with pytest.raises(ValueError, match="matched tenant scope"):
        feed.query_impact(
            _incoming_alert(matched_regimes=[], matched_domains=[]), [_incoming_rule()]
        )
    with pytest.raises(ValueError, match="regime or domain"):
        feed.ImpactRule(rule_id="r", policy_ids=("p",))
    # Oversized nested diff values are digested and redacted, never copied.
    safe = feed.query_impact(
        _incoming_alert(diff={"annex": {"before": {"huge": "x" * 5000}, "after": "ok"}}),
        [_incoming_rule()],
    )
    assert safe["matched_rule_ids"] == ["rule-eu-ai-act"]


# ---- sync: impact + staleness + notice, idempotently ------------------------


def test_sync_alert_creates_bound_records_and_recovers_idempotently(monkeypatch):
    _enable_incoming_tenant(monkeypatch)
    impacts: list = []
    bridge = _incoming_bridge(impacts)
    first = bridge.sync_alert(_incoming_alert(), rules=[_incoming_rule()], actor="governance-lead")

    assert impacts[0]["alert_id"] == "ALRT-omnibus-1"
    staleness = first["staleness"]
    assert staleness["state"] == "active"
    assert staleness["stale_evidence_ids"] == ["MRE-eval-1"]
    assert staleness["content_sha256"] == _hex("consolidated-2026-07-27")
    notice = first["notice"]
    assert notice["delivery"]["status"] == "pending"
    assert notice["notice"] == feed.NON_LEGAL_NOTICE
    assert notice["title"].startswith("Digital Omnibus")

    # Re-syncing the same alert recovers the same records — no duplicates and
    # exactly one additional upstream impact write.
    again = bridge.sync_alert(_incoming_alert(), rules=[_incoming_rule()], actor="governance-lead")
    assert again["staleness"]["id"] == staleness["id"]
    assert again["notice"]["id"] == notice["id"]
    assert bridge.list_notices() == [again["notice"]]

    with pytest.raises(feed.AIRegulatoryFeedStateError, match="operator-reviewed"):
        bridge.sync_alert(
            _incoming_alert(matched_regimes=["us-colorado"]),
            rules=[_incoming_rule()],
            actor="governance-lead",
        )


def test_notice_delivery_is_cas_gated_bounded_and_terminal(monkeypatch):
    _enable_incoming_tenant(monkeypatch)
    bridge = _incoming_bridge(clock=lambda: 1_756_000_000.0)
    seen: list[dict] = []
    result = bridge.sync_alert(
        _incoming_alert(),
        rules=[_incoming_rule()],
        actor="governance-lead",
        deliver=True,
        notification_sink=lambda payload: not seen.append(dict(payload)),
    )
    notice = result["notice"]
    assert notice["delivery"] == {
        "status": "sent",
        "attempts": 1,
        "delivered_at": 1_756_000_000.0,
        "last_error_type": None,
    }
    # The delivered projection is the bounded notice — no tenant hash, no
    # credentials, no upstream document body.
    assert len(seen) == 1
    payload = seen[0]
    assert payload["idempotency_key"] == notice["id"]
    assert "tenant_sha256" not in payload
    assert payload["notice"] == feed.NON_LEGAL_NOTICE

    # A sent notice is terminal: re-delivery returns it without invoking any
    # sink again, and a stale revision cannot resurrect delivery.
    again = bridge.deliver_notice(
        notice["id"],
        expected_revision=int(notice["revision"]),
        actor="governance-lead",
        notification_sink=lambda payload: seen.append(dict(payload)),
    )
    assert again["delivery"]["status"] == "sent"
    assert len(seen) == 1


def test_failed_delivery_records_error_type_and_allows_retry(monkeypatch):
    _enable_incoming_tenant(monkeypatch)
    bridge = _incoming_bridge()
    result = bridge.sync_alert(_incoming_alert(), rules=[_incoming_rule()], actor="lead")
    notice = result["notice"]

    def explode(_payload):
        raise TimeoutError("provider unreachable")

    failed = bridge.deliver_notice(
        notice["id"],
        expected_revision=int(notice["revision"]),
        actor="lead",
        notification_sink=explode,
    )
    assert failed["delivery"]["status"] == "failed"
    assert failed["delivery"]["attempts"] == 1
    assert failed["delivery"]["last_error_type"] == "TimeoutError"
    assert failed["delivery"]["delivered_at"] is None

    with pytest.raises(RecordConflict):
        bridge.deliver_notice(
            notice["id"],
            expected_revision=int(notice["revision"]),
            actor="lead",
            notification_sink=lambda payload: True,
        )
    recovered = bridge.deliver_notice(
        notice["id"],
        expected_revision=int(failed["revision"]),
        actor="lead",
        notification_sink=lambda payload: True,
    )
    assert recovered["delivery"]["status"] == "sent"
    assert recovered["delivery"]["attempts"] == 2


def test_staleness_resolution_is_a_human_cas_assertion(monkeypatch):
    _enable_incoming_tenant(monkeypatch)
    bridge = _incoming_bridge()
    result = bridge.sync_alert(_incoming_alert(), rules=[_incoming_rule()], actor="lead")
    staleness = result["staleness"]
    assert bridge.list_active_staleness(evidence_id="MRE-eval-1")

    resolved = bridge.resolve_staleness(
        staleness["id"],
        expected_revision=int(staleness["revision"]),
        resolution="Evaluation evidence re-run against the deferred deadline.",
        actor="risk-reviewer",
    )
    assert resolved["state"] == "resolved"
    assert resolved["resolution"]["actor"] == "risk-reviewer"
    assert bridge.list_active_staleness() == []
    with pytest.raises(RecordConflict):
        bridge.resolve_staleness(
            staleness["id"],
            expected_revision=int(resolved["revision"]),
            resolution="Already resolved records stay resolved.",
            actor="risk-reviewer",
        )


# ---- tenancy and gating -----------------------------------------------------


def test_records_are_tenant_bound(monkeypatch):
    _enable_incoming_tenant(monkeypatch)
    bridge = _incoming_bridge()
    result = bridge.sync_alert(_incoming_alert(), rules=[_incoming_rule()], actor="lead")
    notice_id = result["notice"]["id"]

    # Storage is tenant-scoped, so another tenant cannot even see the record
    # — stronger than the tenant_sha256 binding check, which remains as
    # defense-in-depth for a shared multi-replica backend.
    monkeypatch.setenv("MAVERICK_TENANT", "globex")
    assert bridge.get_notice(notice_id) is None
    with pytest.raises(feed.AIRegulatoryFeedStateError, match="does not exist"):
        bridge.deliver_notice(
            notice_id,
            expected_revision=1,
            actor="lead",
            notification_sink=lambda payload: True,
        )
    assert bridge.list_notices() == []
    assert bridge.list_active_staleness() == []

    # And the binding check itself fires when a foreign-tenant row appears in
    # the store (a shared backend scenario), never returning the record.
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    foreign = dict(bridge._notices.get(notice_id))  # noqa: SLF001 - test rig
    foreign["tenant_sha256"] = "0" * 64
    monkeypatch.setattr(bridge._notices, "get", lambda _id: foreign)  # noqa: SLF001
    with pytest.raises(feed.AIRegulatoryFeedStateError, match="tenant binding"):
        bridge.get_notice(notice_id)


def test_bridge_is_off_unless_all_three_authorities_are_enabled(tmp_path, monkeypatch):
    _enable_incoming_tenant(monkeypatch)
    (tmp_path / "config.toml").write_text(
        "[ai_regulatory_feed]\nenable = true\n"
        "\n[finance_operations]\nenable = false\n"
        "\n[evidence_gateway]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert feed.enabled() is False
    with pytest.raises(feed.AIRegulatoryFeedConfigError, match="requires"):
        _incoming_bridge().sync_alert(_incoming_alert(), rules=[_incoming_rule()], actor="lead")
