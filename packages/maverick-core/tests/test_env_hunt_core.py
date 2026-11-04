"""Synthetic attack chains for the deployable defensive SOC hunter."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import maverick.env_hunt as env_hunt
import pytest
from maverick.audit.errors import AuditRefused
from maverick.env_hunt import (
    CloudTrailConnector,
    ConnectorRegistry,
    GovernedApproval,
    QueryRequest,
    ResponseNotAuthorized,
    ResponseReceipt,
    TelemetryEvent,
)


def _event(
    event_id: str,
    timestamp: float,
    action: str,
    *,
    source: str = "synthetic",
    category: str = "identity",
    principal: str = "attacker@example.com",
    target: str = "host-1",
    outcome: str = "success",
    **attributes,
) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=event_id,
        source=source,
        observed_at=timestamp,
        category=category,
        action=action,
        principal=principal,
        target=target,
        outcome=outcome,
        attributes=attributes,
    )


@pytest.fixture
def synthetic_attack_chain() -> tuple[TelemetryEvent, ...]:
    return (
        _event("initial", 100, "ConsoleLogin", source="aws.cloudtrail", mfa="No"),
        _event("persist", 200, "CreateAccessKey", source="aws.cloudtrail"),
        _event(
            "exfil", 300, "upload", source="edr.generic", category="network",
            bytes_out=20 * 1024 * 1024,
        ),
    )


def test_environment_hunter_is_explicitly_opt_in_and_execution_has_second_gate(monkeypatch):
    assert env_hunt.enabled({}) is False
    assert env_hunt.enabled({"env_hunt": {"enable": True}}) is True
    assert env_hunt.response_execution_enabled({"env_hunt": {"enable": True}}) is False
    assert env_hunt.response_execution_enabled({
        "env_hunt": {"enable": True, "response_execution": True},
    }) is True
    for malformed in ("false", 1, [], {"value": True}):
        config = {"env_hunt": {"enable": malformed, "response_execution": malformed}}
        assert env_hunt.enabled(config) is False
        assert env_hunt.response_execution_enabled(config) is False

    from maverick import config

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"env_hunt": {"enable": False, "response_execution": False}},
    )
    monkeypatch.setattr(
        config,
        "load_global_config",
        lambda: {"env_hunt": {"enable": True, "response_execution": True}},
    )
    assert env_hunt.enabled() is True
    assert env_hunt.response_execution_enabled() is True

    monkeypatch.setattr(
        config,
        "config_source_errors",
        lambda **_kwargs: {"tenant.toml": "malformed"},
    )
    assert env_hunt.enabled() is False
    assert env_hunt.response_execution_enabled() is False


def test_connector_registry_is_read_only_ephemeral_and_audits_metadata_only():
    rows = [{
        "eventID": "cloud-1",
        "eventTime": "2026-07-19T12:00:00Z",
        "eventName": "ConsoleLogin",
        "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
        "additionalEventData": {"MFAUsed": "No"},
    }]
    audit = []
    registry = ConnectorRegistry(
        audit_recorder=lambda kind, payload: audit.append((kind, payload)) or True,
    )
    registry.register(CloudTrailConnector(lambda request: rows))
    request = QueryRequest(
        start=1_700_000_000, end=2_000_000_000,
        query="eventName=ConsoleLogin", filters={"account": "123"},
    )
    batch = registry.ingest("cloudtrail", request)
    assert batch.raw_persisted is False
    assert batch.audited is True
    assert batch.events[0].action == "ConsoleLogin"
    assert "userIdentity" not in str(audit)
    assert audit[0][1]["query_sha256"] == request.digest
    with pytest.raises(ValueError, match="read-only"):
        QueryRequest(start=1, end=2, read_only=False)
    with pytest.raises(ValueError, match="credentials"):
        QueryRequest(start=1, end=2, filters={"api_token": "do-not-log"})
    with pytest.raises(ValueError, match="credentials"):
        QueryRequest(start=1, end=2, query="Authorization: Bearer abcdefghijkl")


def test_environment_hunt_never_downgrades_an_explicit_audit_refusal(
    synthetic_attack_chain,
):
    """Ordinary recorder failures degrade; a custody refusal must stay fatal."""

    def refuse(*_args, **_kwargs):
        raise AuditRefused("signed audit custody is unavailable")

    registry = ConnectorRegistry(audit_recorder=refuse)
    registry.register(CloudTrailConnector(lambda _request: ()))
    with pytest.raises(AuditRefused, match="custody"):
        registry.ingest("cloudtrail", QueryRequest(start=1, end=2))

    with pytest.raises(AuditRefused, match="custody"):
        env_hunt.scan(synthetic_attack_chain, audit_recorder=refuse)

    ip_event = _event("ip", 400, "connection", target="203.0.113.7")
    ip_finding = env_hunt.detect(
        [ip_event],
        [env_hunt.SigmaRule({
            "id": "ip-rule",
            "title": "IP event",
            "detection": {
                "selection": {"action": "connection"},
                "condition": "selection",
            },
        })],
    )[0]
    investigation = env_hunt.build_investigation([ip_finding], [ip_event])

    @dataclass
    class Provider:
        name: str = "approved-intel"

        def lookup(self, _indicator):
            return {"reputation": "known"}

    with pytest.raises(AuditRefused, match="custody"):
        env_hunt.enrich(
            investigation,
            [Provider()],
            allowed_sources=["approved-intel"],
            audit_recorder=refuse,
        )

    with pytest.raises(AuditRefused, match="custody"):
        env_hunt.propose_response(
            "isolate_host",
            "host-1",
            "contain the cited event",
            (synthetic_attack_chain[-1].evidence(),),
            audit_recorder=refuse,
        )


def test_vendor_parsers_cover_cloud_host_edr_siem_kubernetes_and_identity():
    examples = [
        env_hunt.parse_guardduty({
            "id": "g1", "createdAt": "2026-07-19T12:00:00Z", "type": "Exfiltration:S3",
            "resource": {"resourceType": "S3Bucket"}, "severity": 8,
        }),
        env_hunt.parse_syslog({
            "event_id": "s1", "timestamp": 1, "program": "sshd", "message": "login failed",
        }),
        env_hunt.parse_edr({
            "id": "e1", "timestamp": 2, "action": "process_start", "host": "host-1",
        }),
        env_hunt.parse_siem({
            "id": "q1", "timestamp": 3, "action": "search", "vendor": "splunk",
        }),
        env_hunt.parse_kubernetes_audit({
            "auditID": "k1", "stageTimestamp": "2026-07-19T12:00:00Z", "verb": "create",
            "user": {"username": "alice", "groups": ["dev"]},
            "objectRef": {"resource": "clusterrolebindings", "name": "admin"},
            "responseStatus": {"code": 201},
        }),
        env_hunt.parse_okta({
            "uuid": "o1", "published": "2026-07-19T12:00:00Z",
            "eventType": "user.session.start", "actor": {"alternateId": "alice"},
            "outcome": {"result": "SUCCESS"},
        }),
        env_hunt.parse_entra({
            "id": "a1", "createdDateTime": "2026-07-19T12:00:00Z",
            "activityDisplayName": "Add service principal", "result": "success",
        }),
    ]
    assert len({event.source for event in examples}) == len(examples)
    assert all(event.event_id and event.action for event in examples)


def test_connector_credentials_are_redacted_before_evidence_and_persistence(tmp_path):
    credential = "Bearer supersecrettoken123456"  # pragma: allowlist secret
    event = env_hunt.parse_edr({
        "id": "credential-bearing-event",
        "timestamp": 2,
        "vendor": "example",
        "category": "endpoint",
        "action": "upload",
        "user": credential,
        "host": "host-1",
        "bytes_out": 10 * 1024 * 1024,
    })
    assert credential not in event.principal
    assert event.principal == "[REDACTED:credential]"

    finding = next(
        item for item in env_hunt.detect([event]) if item.rule_id == "LW-SIGMA-004"
    )
    investigation = env_hunt.build_investigation([finding], [event])
    store = env_hunt.HuntStore(
        tmp_path / "credential-safe.sqlite3",
        audit_recorder=lambda _kind, _payload: True,
    )
    stored_finding = store.create_finding(finding, actor="analyst")
    stored_investigation = store.create_investigation(investigation, actor="analyst")
    persisted = json.dumps(
        {"finding": stored_finding, "investigation": stored_investigation},
        sort_keys=True,
    )
    assert credential not in persisted
    assert "[REDACTED:credential]" in persisted

    with pytest.raises(ValueError, match="credential-like values"):
        store.update_investigation(
            investigation.investigation_id,
            {"summary": f"Authorization: Basic {credential}"},
            expected_revision=1,
            actor="analyst",
        )


def test_environment_store_rejects_direct_credential_values_and_sigma_scrubs_metadata(
    tmp_path,
):
    credential = "password='do not persist this value'"  # pragma: allowlist secret
    store = env_hunt.HuntStore(
        tmp_path / "direct-credential.sqlite3",
        audit_recorder=lambda _kind, _payload: True,
    )
    with pytest.raises(ValueError, match="credential-like values"):
        store.create_investigation(
            {
                "investigation_id": "direct-secret",
                "status": "open",
                "summary": credential,
            },
            actor="analyst",
        )

    rule = env_hunt.SigmaRule({
        "id": "metadata-redaction",
        "title": "Credential-bearing rule metadata",
        "description": credential,
        "detection": {"selection": {"action": "upload"}, "condition": "selection"},
    })
    assert credential not in rule.description
    assert "[REDACTED:credential]" in rule.description


def test_curated_sigma_and_attack_chain_correlation_cite_exact_events(synthetic_attack_chain):
    findings = env_hunt.detect(synthetic_attack_chain)
    assert {finding.rule_id for finding in findings} >= {"LW-SIGMA-001", "LW-SIGMA-002"}
    correlations = env_hunt.correlate(synthetic_attack_chain, findings)
    assert len(correlations) == 1
    correlation = correlations[0]
    assert correlation.rule_id == "LW-CORR-001"
    assert [item.event_id for item in correlation.evidence] == ["initial", "persist", "exfil"]
    assert correlation.mitre_techniques == ("T1078", "T1098", "T1041")


def test_customer_sigma_import_and_safe_unsupported_regex(tmp_path):
    path = tmp_path / "customer.yml"
    path.write_text(
        """title: Suspicious endpoint process
id: customer-rule-1
logsource:
  product: edr
detection:
  selection:
    action|contains: process
  condition: selection
tags:
  - attack.t1059
level: medium
""",
        encoding="utf-8",
    )
    rule = env_hunt.load_sigma_rules([path])[0]
    event = _event("endpoint", 1, "process_start", source="edr.generic", category="endpoint")
    assert env_hunt.rule_matches(rule, event) is True
    unsafe = env_hunt.SigmaRule({
        "id": "unsafe-regex", "title": "unsafe", "detection": {
            "selection": {"action|re": "(a+)+$"}, "condition": "selection",
        },
    })
    assert env_hunt.rule_matches(unsafe, event) is False
    filtered = env_hunt.SigmaRule({
        "id": "condition-rule", "title": "common Sigma condition",
        "detection": {
            "selection": {"action": "process_*"},
            "filter_known": {"target": "known-server"},
            "condition": "selection and not filter_known",
        },
    })
    assert env_hunt.rule_matches(filtered, event) is True

    imported = env_hunt.load_sigma_texts([path.read_text(encoding="utf-8")])
    assert imported[0].id == "customer-rule-1"
    with pytest.raises(ValueError, match="duplicate"):
        env_hunt.load_sigma_texts([
            path.read_text(encoding="utf-8"), path.read_text(encoding="utf-8"),
        ])
    with pytest.raises(ValueError, match="exceeds"):
        env_hunt.load_sigma_texts(["x" * (1024 * 1024 + 1)])


def test_scan_investigation_timeline_and_allowlisted_enrichment(synthetic_attack_chain):
    audit = []
    report = env_hunt.scan(
        synthetic_attack_chain,
        audit_recorder=lambda kind, payload: audit.append((kind, payload)) or True,
    )
    assert report.correlation_findings == 1
    assert report.audited_findings == len(report.findings)
    investigation = env_hunt.build_investigation(report.findings, synthetic_attack_chain)
    assert [entry.event_id for entry in investigation.timeline] == ["initial", "persist", "exfil"]
    assert investigation.confidence > 50

    @dataclass
    class Provider:
        name: str
        calls: int = 0

        def lookup(self, indicator):
            self.calls += 1
            return {"reputation": "known", "unsafe_raw": "discard me"}

    allowed = Provider("approved-intel")
    blocked = Provider("unapproved-intel")
    ip_event = _event("ip", 400, "connection", target="203.0.113.7")
    ip_finding = env_hunt.detect(
        [ip_event],
        [env_hunt.SigmaRule({
            "id": "ip-rule", "title": "IP event",
            "detection": {"selection": {"action": "connection"}, "condition": "selection"},
        })],
    )[0]
    ip_investigation = env_hunt.build_investigation([ip_finding], [ip_event])
    enrichment_audit = []
    enriched = env_hunt.enrich(
        ip_investigation,
        [allowed, blocked],
        allowed_sources=["approved-intel"],
        audit_recorder=lambda kind, payload: enrichment_audit.append((kind, payload)) or True,
    )
    assert allowed.calls == 1
    assert blocked.calls == 0
    assert enriched.enrichments[0].fields == {"reputation": "known"}
    assert enrichment_audit[0][0] == "env_hunt_enrichment"
    assert "203.0.113.7" not in str(enrichment_audit)


def test_response_is_never_autonomous_and_requires_exact_governed_approval(
    synthetic_attack_chain, tmp_path,
):
    evidence = (synthetic_attack_chain[-1].evidence("large outbound transfer"),)
    audit = []
    proposal = env_hunt.propose_response(
        "isolate_host", "host-1", "contain the cited exfiltration", evidence,
        executor="test-edr",
        audit_recorder=lambda kind, payload: audit.append((kind, payload)) or True,
    )

    class Verifier:
        def verify(self, candidate, approval):
            return "human:cab" if approval.signature == "valid-signature" else None

    class Executor:
        name = "test-edr"

        def __init__(self):
            self.calls = 0

        def execute(self, candidate, governed_approval):
            self.calls += 1
            return ResponseReceipt(
                candidate.proposal_id, governed_approval.approval_id,
                self.name, "isolated",
            )

    executor = Executor()
    ledger = env_hunt.HuntStore(
        tmp_path / "responses.sqlite3",
        audit_recorder=lambda kind, payload: audit.append((kind, payload)) or True,
    )
    approval = GovernedApproval(
        proposal_id=proposal.proposal_id,
        proposal_sha256=proposal.digest,
        approval_id="approval-1",
        approved_by="cab",
        signature="valid-signature",
        executor=executor.name,
    )
    with pytest.raises(ResponseNotAuthorized, match="disabled"):
        env_hunt.execute_response(
            proposal, approval, approval_verifier=Verifier(), executor=executor,
        )
    assert executor.calls == 0
    mismatched = GovernedApproval(
        proposal_id=proposal.proposal_id,
        proposal_sha256="0" * 64,
        approval_id="approval-1",
        approved_by="cab",
        signature="valid-signature",
    )
    with pytest.raises(ResponseNotAuthorized, match="exact"):
        env_hunt.execute_response(
            proposal, mismatched, approval_verifier=Verifier(), executor=executor,
            execution_ledger=ledger,
            execution_enabled=True,
        )
    assert executor.calls == 0
    receipt = env_hunt.execute_response(
        proposal, approval, approval_verifier=Verifier(), executor=executor,
        execution_ledger=ledger,
        execution_enabled=True,
        audit_recorder=lambda kind, payload: audit.append((kind, payload)) or True,
    )
    assert receipt.outcome == "isolated"
    assert executor.calls == 1
    replay = env_hunt.execute_response(
        proposal, approval, approval_verifier=Verifier(), executor=executor,
        execution_ledger=ledger,
        execution_enabled=True,
        audit_recorder=lambda kind, payload: audit.append((kind, payload)) or True,
    )
    assert replay == receipt
    assert executor.calls == 1
    assert ledger.get_response_execution(proposal.proposal_id)["status"] == "completed"
    assert "env_hunt_response_execution_claimed" in [kind for kind, _ in audit]
    assert "env_hunt_response_executed" in [kind for kind, _ in audit]

    unaudited = env_hunt.propose_response(
        "isolate_host", "host-2", "audit is unavailable", evidence,
        executor="test-edr",
        audit_recorder=lambda _kind, _payload: False,
    )
    unaudited_approval = GovernedApproval(
        unaudited.proposal_id, unaudited.digest, "approval-2", "cab", "valid-signature",
        executor=executor.name,
    )
    with pytest.raises(ResponseNotAuthorized, match="audit"):
        env_hunt.execute_response(
            unaudited, unaudited_approval, approval_verifier=Verifier(), executor=executor,
            execution_ledger=ledger,
            execution_enabled=True,
        )
    assert executor.calls == 1


def test_ambiguous_response_claim_is_never_retried(tmp_path, synthetic_attack_chain):
    evidence = (synthetic_attack_chain[-1].evidence(),)
    proposal = env_hunt.propose_response(
        "isolate_host",
        "host-1",
        "contain the cited event",
        evidence,
        executor="failing-edr",
        audit_recorder=lambda *_args: True,
    )
    approval = GovernedApproval(
        proposal.proposal_id,
        proposal.digest,
        "approval-ambiguous",
        "offline-cab",
        "valid",
        executor="failing-edr",
    )

    class Verifier:
        def verify(self, _proposal, _approval):
            return "cab-key"

    class Executor:
        name = "failing-edr"

        def __init__(self):
            self.calls = 0

        def execute(self, _proposal, _approval):
            self.calls += 1
            raise TimeoutError("external outcome unknown")

    audit = []
    ledger = env_hunt.HuntStore(
        tmp_path / "ambiguous.sqlite3",
        audit_recorder=lambda kind, payload: audit.append((kind, payload)) or True,
    )
    executor = Executor()
    with pytest.raises(RuntimeError, match="ambiguous"):
        env_hunt.execute_response(
            proposal,
            approval,
            approval_verifier=Verifier(),
            executor=executor,
            execution_ledger=ledger,
            execution_enabled=True,
            audit_recorder=lambda *_args: True,
        )
    with pytest.raises(env_hunt.ResponseExecutionPending, match="already claimed"):
        env_hunt.execute_response(
            proposal,
            approval,
            approval_verifier=Verifier(),
            executor=executor,
            execution_ledger=ledger,
            execution_enabled=True,
            audit_recorder=lambda *_args: True,
        )
    assert executor.calls == 1
    assert ledger.get_response_execution(proposal.proposal_id)["status"] == "ambiguous"
    assert "env_hunt_response_ambiguous" in [kind for kind, _payload in audit]
    ledger.mark_response_execution_ambiguous(
        proposal_id=proposal.proposal_id,
        proposal_sha256=proposal.digest,
        approval_id=approval.approval_id,
        executor=approval.executor,
        error_kind="TimeoutError",
        actor="system:env-hunt",
    )
    assert [kind for kind, _payload in audit].count("env_hunt_response_ambiguous") == 1


def test_response_parameters_reject_raw_credentials_and_excessive_depth(
    synthetic_attack_chain,
):
    evidence = (synthetic_attack_chain[0].evidence(),)
    with pytest.raises(ValueError, match="raw telemetry"):
        env_hunt.ResponseProposal.build(
            "disable_identity",
            "alice@example.com",
            "containment",
            evidence,
            {"raw_events": [{"id": "secret"}]},
        )
    with pytest.raises(ValueError, match="credential-like"):
        env_hunt.ResponseProposal.build(
            "disable_identity",
            "alice@example.com",
            "containment",
            evidence,
            {"note": "Authorization: Bearer abcdefghijkl"},
        )
    nested = {"level": {"level": {"level": {"level": {"level": {"level": {
        "level": "too deep",
    }}}}}}}
    with pytest.raises(ValueError, match="nesting depth"):
        env_hunt.ResponseProposal.build(
            "disable_identity",
            "alice@example.com",
            "containment",
            evidence,
            nested,
        )


def test_response_executor_registry_ships_empty_and_is_vendor_neutral():
    registry = env_hunt.ResponseExecutorRegistry()
    assert registry.names() == ()

    class Executor:
        name = "client-edr"

        def execute(self, proposal, approval):
            return ResponseReceipt(
                proposal.proposal_id, approval.approval_id, self.name, "ok",
            )

    executor = Executor()
    registry.register(executor)
    assert registry.names() == ("client-edr",)
    assert registry.get("CLIENT-EDR") is executor
    with pytest.raises(ValueError, match="already registered"):
        registry.register(executor)
    with pytest.raises(KeyError, match="unknown response executor"):
        registry.get("not-configured")


def test_response_proposal_can_use_existing_ed25519_approval_boundary(
    synthetic_attack_chain,
):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from maverick.approval_signing import sign_request

    proposal = env_hunt.ResponseProposal.build(
        "disable_identity",
        "attacker@example.com",
        "contain the cited chain",
        (synthetic_attack_chain[0].evidence(),),
        executor="client-idp",
    )
    private = ed25519.Ed25519PrivateKey.generate()
    private_hex = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    signature = sign_request(
        env_hunt.response_approval_request(
            proposal,
            approval_id="approval-crypto",
            approved_by="offline-cab",
        ),
        private_hex,
    )
    approval = GovernedApproval(
        proposal.proposal_id,
        proposal.digest,
        "approval-crypto",
        "offline-cab",
        signature,
        executor="client-idp",
    )
    verifier = env_hunt.Ed25519ApprovalVerifier([public_hex])
    assert verifier.verify(proposal, approval)
    replacement = GovernedApproval(
        proposal.proposal_id,
        proposal.digest,
        "replacement-approval",
        "offline-cab",
        signature,
        executor="client-idp",
    )
    assert verifier.verify(proposal, replacement) is None
    changed_decider = GovernedApproval(
        proposal.proposal_id,
        proposal.digest,
        "approval-crypto",
        "different-cab",
        signature,
        executor="client-idp",
    )
    assert verifier.verify(proposal, changed_decider) is None


def test_environment_store_only_exposes_derived_record_methods(tmp_path):
    audit = []
    store = env_hunt.HuntStore(
        tmp_path / "soc.sqlite3",
        audit_recorder=lambda kind, payload: audit.append((kind, payload)) or True,
    )
    assert not hasattr(store, "save_telemetry")
    assert not hasattr(store, "create_event")
    event = _event("store-finding", 10, "ConsoleLogin", source="aws.cloudtrail", mfa="No")
    finding = env_hunt.detect([event])[0]
    store.create_finding(finding, actor="analyst")
    assert audit[0][0] == "env_hunt_record_changed"


def test_connector_config_template_is_explicit_and_every_source_defaults_off():
    template = env_hunt.connector_config_template()
    assert template["enable"] is False
    assert tuple(template["connectors"]) == env_hunt.CONNECTOR_NAMES
    assert all(value == {
        "enable": False, "push_enable": False, "pivot_enable": False,
    } for value in template["connectors"].values())
    assert env_hunt.connector_enablement({}) == dict.fromkeys(env_hunt.CONNECTOR_NAMES, False)
    assert env_hunt.connector_enablement({
        "env_hunt": {
            "enable": False,
            "connectors": {"cloudtrail": {"enable": True}},
        },
    })["cloudtrail"] is False
    enabled = {
        "env_hunt": {
            "enable": True,
            "connectors": {
                "cloudtrail": {
                    "enable": True,
                    "push_enable": True,
                    "pivot_enable": True,
                },
            },
        },
    }
    assert env_hunt.connector_push_enablement(enabled)["cloudtrail"] is True
    assert env_hunt.connector_pivot_enablement(enabled)["cloudtrail"] is True
    enabled["env_hunt"]["connectors"]["cloudtrail"]["push_enable"] = False
    assert env_hunt.connector_push_enablement(enabled)["cloudtrail"] is False
    assert env_hunt.connector_pivot_enablement(enabled)["cloudtrail"] is True


def test_connector_activation_fails_closed_when_a_config_source_is_unreadable(monkeypatch):
    from maverick import config

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "env_hunt": {
                "enable": True,
                "connectors": {"cloudtrail": {"enable": True}},
            },
        },
    )
    monkeypatch.setattr(
        config,
        "config_source_errors",
        lambda **_kwargs: {"tenant.toml": "malformed"},
    )

    assert env_hunt.connector_enablement()["cloudtrail"] is False


def test_connector_factory_fails_closed_until_enabled_and_transport_registered():
    disabled = env_hunt.ConnectorFactoryRegistry({
        "env_hunt": {
            "enable": False,
            "connectors": {"cloudtrail": {"enable": True}},
        },
    })
    disabled.register_transport("cloudtrail", lambda _request: ())
    with pytest.raises(env_hunt.ConnectorDisabled, match="disabled"):
        disabled.build_connector("cloudtrail")
    assert disabled.available_names() == ()
    assert disabled.tools() == ()

    enabled = env_hunt.ConnectorFactoryRegistry({
        "env_hunt": {
            "enable": True,
            "connectors": {
                "cloudtrail": {"enable": True},
                "guardduty": {"enable": False},
            },
        },
    })
    enabled.register_transport("guardduty", lambda _request: ())
    with pytest.raises(env_hunt.ConnectorUnavailable, match="no registered transport"):
        enabled.build_connector("cloudtrail")
    with pytest.raises(env_hunt.ConnectorDisabled, match="disabled"):
        enabled.build_connector("guardduty")
    assert enabled.available_names() == ()
    assert enabled.statuses()["cloudtrail"] == {
        "enabled": True, "registered": False, "available": False,
    }


def test_every_named_connector_has_an_explicit_knob_factory_and_tool():
    config = {
        "env_hunt": {
            "enable": True,
            "connectors": {
                name: {"enable": True} for name in env_hunt.CONNECTOR_NAMES
            },
        },
    }
    factory = env_hunt.ConnectorFactoryRegistry(
        config, audit_recorder=lambda _kind, _payload: True,
    )
    for name in env_hunt.CONNECTOR_NAMES:
        factory.register_transport(name, lambda _request: ())
    assert factory.available_names() == tuple(sorted(env_hunt.CONNECTOR_NAMES))
    assert {tool.name for tool in factory.tools()} == {
        f"env_hunt_query_{name}" for name in env_hunt.CONNECTOR_NAMES
    }
    assert all(status["available"] for status in factory.statuses().values())


def test_enabled_connector_tool_is_bounded_read_only_and_credential_safe():
    credential = "customer-secret-credential"  # pragma: allowlist secret
    captured = []
    audit = []

    def transport(request):
        # A real startup closure may use a secret from its own boundary. The
        # factory receives only this callable and never receives the credential.
        assert credential
        captured.append(request)
        return [{
            "eventID": "cloud-tool-1",
            "eventTime": 1_000,
            "eventName": "ConsoleLogin",
            "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
        }]

    factory = env_hunt.ConnectorFactoryRegistry(
        {
            "env_hunt": {
                "enable": True,
                "connectors": {"cloudtrail": {"enable": True}},
            },
        },
        audit_recorder=lambda kind, payload: audit.append((kind, payload)) or True,
    )
    assert factory.tools() == ()
    factory.register_transport("cloudtrail", transport)
    tools = factory.tools()
    assert [tool.name for tool in tools] == ["env_hunt_query_cloudtrail"]
    metadata = tools[0].to_anthropic()
    assert metadata["input_schema"]["additionalProperties"] is False
    assert metadata["input_schema"]["properties"]["limit"]["maximum"] == 1000
    assert credential not in json.dumps(metadata)

    registry = factory.tool_registry()
    output = asyncio.run(registry.run(
        "env_hunt_query_cloudtrail",
        {"start": 900, "end": 1_100, "query": "eventName=ConsoleLogin", "limit": 2},
    ))
    result = json.loads(output)
    assert result["events"][0]["event_id"] == "cloud-tool-1"
    assert result["raw_persisted"] is False
    assert captured[0].read_only is True
    assert captured[0].limit == 2
    assert audit[0][0] == "env_hunt_ingestion"
    assert credential not in json.dumps(audit)
    assert credential not in output

    calls_before = len(captured)
    too_large = asyncio.run(registry.run(
        "env_hunt_query_cloudtrail",
        {"start": 900, "end": 1_100, "limit": 1001},
    ))
    assert "ERROR:" in too_large and "between 1 and 1000" in too_large
    secret_arg = asyncio.run(registry.run(
        "env_hunt_query_cloudtrail",
        {"start": 900, "end": 1_100, "api_token": credential},
    ))
    assert "ERROR:" in secret_arg and "api_token" in secret_arg
    assert credential not in secret_arg
    wide_window = asyncio.run(registry.run(
        "env_hunt_query_cloudtrail",
        {"start": 1, "end": 8 * 24 * 3600},
    ))
    assert "ERROR:" in wide_window and "window" in wide_window
    assert len(captured) == calls_before
