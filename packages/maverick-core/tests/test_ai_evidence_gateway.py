from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import ai_evidence_gateway as gateway
from maverick.ai_evidence_ledger import (
    SegmentedLedgerError,
    SegmentedReceiptLedger,
)
from maverick.privacy_ops import RecordConflict


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _enable(monkeypatch, tenant: str = "gateway-test-tenant") -> None:
    monkeypatch.setenv("MAVERICK_EVIDENCE_GATEWAY", "1")
    monkeypatch.setenv("MAVERICK_CLIENT_ID", tenant)
    # Some security fixtures resolve the deliberately-unbound setup identity
    # before the test body installs its tenant. Refresh the process floor after
    # the explicit test binding is present.
    from maverick import client

    client.reset_client_cache()


def _policy(
    *,
    policy_id: str = "default",
    actor: str = "policy-admin",
    model: str = "model-v1",
    context: str = "context-v1",
    **kwargs,
):
    return gateway.upsert_policy(
        policy_id,
        actor=actor,
        model_sha256=_sha(model),
        context_sha256=_sha(context),
        **kwargs,
    )


def _deliver(
    *,
    generated_text: str = "Generated answer.",
    input_text: str = "Sensitive user question.",
    conversation_id: str = "conversation-1",
    idempotency_key: str = "turn-1",
    policy_id: str = "default",
    model: str = "model-v1",
    context: str = "context-v1",
    **kwargs,
):
    return gateway.deliver_text(
        generated_text,
        input_text=input_text,
        conversation_id=conversation_id,
        idempotency_key=idempotency_key,
        actor="delivery-service",
        policy_id=policy_id,
        model_sha256=_sha(model),
        context_sha256=_sha(context),
        **kwargs,
    )


def _citation() -> dict:
    url = gateway.FRAMEWORK_SOURCES["ec_article_50"]["url"]
    return {
        "source_name": "European Commission",
        "feed_url": url,
        "retrieval_url": url,
        "record_url": url,
        "retrieved_at": "2026-07-20T12:00:00Z",
        "content_sha256": _sha("official-record-content"),
        "payload_sha256": _sha("feed-payload"),
        "source_record_sha256": _sha("source-record"),
        "source_format": "html",
        "parser_version": "test-parser-v1",
        "acquisition": "official_feed",
        "acquired_by": "test-ingestor",
        "official_citation": "European Commission Article 50 guidance",
    }


def _impact(
    *,
    policy_id: str = "default",
    alert_id: str = "ec-article-50-guidance-update",
):
    return gateway.record_regulatory_impact(
        alert_id,
        alert_revision=7,
        content_sha256=_sha("normalized-regulatory-change"),
        citations=[_citation()],
        affected_policy_ids=(policy_id,),
        affected_asset_ids=("model-asset-1",),
        control_ids=("eu_ai_act_article_50",),
        match_reasons=("enabled regime and control matched deterministically",),
        actor="regulatory-ingestor",
    )


def test_gateway_is_default_off_and_requires_explicit_tenant(monkeypatch):
    monkeypatch.delenv("MAVERICK_EVIDENCE_GATEWAY", raising=False)
    assert gateway.enabled() is False
    with pytest.raises(gateway.EvidenceGatewayDisabled):
        gateway.list_policies()

    monkeypatch.setenv("MAVERICK_EVIDENCE_GATEWAY", "1")
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="explicit tenant",
    ):
        gateway.list_policies()


def test_exact_text_receipt_is_hash_only_signed_and_revision_aligned(monkeypatch):
    _enable(monkeypatch)
    policy = _policy()
    assert policy["revision"] == 1
    assert policy["record_revision"] == policy["revision"]

    result = _deliver()
    receipt = result["receipt"]
    expected = (
        f"{gateway.DEFAULT_DISCLOSURE_TEXT}\n\nGenerated answer.\n\n"
        f"[lightwork-ai-generated; evidence-receipt={receipt['receipt_id']}]"
    )
    assert result["delivered_text"] == expected
    signed = receipt["signed_receipt"]
    assert signed["input_sha256"] == _sha("Sensitive user question.")
    assert signed["generated_output_sha256"] == _sha("Generated answer.")
    assert signed["delivered_output_sha256"] == _sha(expected)
    assert signed["policy_binding"]["record_revision"] == policy["revision"]
    assert receipt["policy_id"] == "default"
    assert receipt["model_sha256"] == _sha("model-v1")
    assert receipt["context_sha256"] == _sha("context-v1")
    assert receipt["conversation_sha256"] == _sha("conversation-1")
    assert receipt["modality"] == "text"
    assert receipt["sequence"] == 1
    assert receipt["assurance"] == {"status": "current", "reasons": []}

    persisted = json.dumps(receipt, sort_keys=True)
    assert "Sensitive user question." not in persisted
    assert "Generated answer." not in persisted
    assert expected not in persisted
    assert signed["stores_raw_interaction_content"] is False

    trust = gateway.trusted_public_keys()
    assert gateway.verify_interaction_receipt(
        receipt,
        trusted_public_keys=trust,
    )
    assert gateway.verify_interaction_receipt(receipt)
    tampered = copy.deepcopy(receipt)
    tampered["signed_receipt"]["delivered_output_sha256"] = "0" * 64
    assert not gateway.verify_interaction_receipt(
        tampered,
        trusted_public_keys=trust,
    )
    assert not gateway.verify_interaction_receipt(
        receipt,
        trusted_public_keys={},
    )


def test_read_only_preflight_verifies_and_blocks_tampered_gateway_ledger(
    monkeypatch,
):
    _enable(monkeypatch)
    _policy()
    _deliver()
    from maverick import operator_preflight

    config = {"evidence_gateway": {"enable": True}}
    before = {
        path.relative_to(gateway._receipt_path().parents[1]).as_posix()
        for path in gateway._receipt_path().parents[1].rglob("*")
    }
    checks = {
        check.id: check
        for check in operator_preflight._gateway_evidence_checks(config)
    }
    after = {
        path.relative_to(gateway._receipt_path().parents[1]).as_posix()
        for path in gateway._receipt_path().parents[1].rglob("*")
    }
    assert checks["gateway_ledgers"].status == "ready"
    assert before == after

    ledger = gateway._receipt_ledger()
    state = ledger.state()
    segment = ledger._segment_path(state.active_segment)
    rows = segment.read_text(encoding="utf-8").splitlines()
    payload = json.loads(rows[-1])
    payload["receipt_payload_sha256"] = "f" * 64
    rows[-1] = json.dumps(payload)
    segment.write_text("\n".join(rows) + "\n", encoding="utf-8")

    tampered = {
        check.id: check
        for check in operator_preflight._gateway_evidence_checks(config)
    }
    assert tampered["gateway_ledgers"].status == "blocked"
    assert "read-only integrity validation" in tampered[
        "gateway_ledgers"
    ].detail


def test_conversation_order_idempotency_and_changed_risk_inputs_fail(monkeypatch):
    _enable(monkeypatch)
    _policy()
    first = _deliver()
    replay = _deliver()
    assert replay["idempotent_replay"] is True
    assert replay["delivered_text"] == first["delivered_text"]
    assert replay["receipt"]["receipt_id"] == first["receipt"]["receipt_id"]

    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="different deepfake",
    ):
        _deliver(deepfake=True)
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="different model_sha256",
    ):
        _deliver(model="model-v2")
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="different policy_id",
    ):
        _deliver(policy_id="another-policy")

    second = _deliver(
        generated_text="Second answer.",
        input_text="Second question.",
        idempotency_key="turn-2",
    )
    assert second["receipt"]["sequence"] == 2
    assert second["delivered_text"].startswith(
        gateway.DEFAULT_DISCLOSURE_TEXT
    )
    # A retry stays reproducible even after the conversation advances.
    assert _deliver()["idempotent_replay"] is True


def test_failed_signing_does_not_permanently_poison_conversation(monkeypatch):
    # _conversation_reservation reserves the conversation and only
    # _complete_conversation ever clears it. If rendering or signing raised
    # after the reservation (signer refusal, segment/capacity error, disk
    # full), nothing released it -- every later delivery for this
    # conversation with a DIFFERENT idempotency key raised
    # ConversationOrderError forever, since real clients mint a fresh key
    # per attempt rather than resending the exact same one.
    _enable(monkeypatch)
    _policy()
    first = _deliver(idempotency_key="turn-1")
    assert first["receipt"]["sequence"] == 1

    real_sign_event = gateway._sign_event

    def boom(*args, **kwargs):
        raise gateway.EvidenceGatewayStateError("audit signer refused evidence")

    monkeypatch.setattr(gateway, "_sign_event", boom)
    with pytest.raises(gateway.EvidenceGatewayStateError):
        _deliver(idempotency_key="turn-2")
    monkeypatch.setattr(gateway, "_sign_event", real_sign_event)

    # A fresh idempotency key (the usual client behaviour on retry) must
    # recover instead of raising ConversationOrderError forever.
    retry = _deliver(idempotency_key="turn-2-retry")
    assert retry["idempotent_replay"] is False
    assert retry["receipt"]["sequence"] == 2
    third = _deliver(idempotency_key="turn-3")
    assert third["receipt"]["sequence"] == 3

    # The abandoned attempt's sequence number was given back -- the chain
    # stays gapless (1, 2, 3) and correctly linked, exactly what
    # _conversation_chains_valid requires.
    assert (
        third["receipt"]["signed_receipt"]["parent_receipt_hash"]
        == retry["receipt"]["signed_receipt"]["hash"]
    )
    assert (
        retry["receipt"]["signed_receipt"]["parent_receipt_hash"]
        == first["receipt"]["signed_receipt"]["hash"]
    )


def test_partial_ledger_write_does_not_abandon_the_reservation(monkeypatch):
    # If the signed row actually landed in the ledger before a LATER step
    # failed (e.g. the receipt-store bookkeeping), that sequence number is
    # legitimately spent. Abandoning it would let a different receipt reuse
    # the same sequence number -- a chain collision. The only safe recovery
    # for this narrower case is resending the SAME idempotency key (the
    # ledger-recovery path this file already tests elsewhere).
    _enable(monkeypatch)
    _policy()
    _deliver(idempotency_key="turn-1")

    real_create = gateway._RECEIPTS.create

    def boom_create(*args, **kwargs):
        raise RuntimeError("simulated post-sign failure")

    monkeypatch.setattr(gateway._RECEIPTS, "create", boom_create)
    with pytest.raises(RuntimeError):
        _deliver(idempotency_key="turn-2")
    monkeypatch.setattr(gateway._RECEIPTS, "create", real_create)

    with pytest.raises(gateway.ConversationOrderError):
        _deliver(idempotency_key="turn-2-retry")
    # The existing same-key ledger-recovery path still works.
    recovered = _deliver(idempotency_key="turn-2")
    assert recovered["idempotent_replay"] is True
    assert recovered["receipt"]["sequence"] == 2


def test_every_delivery_gets_disclosure_and_caller_cannot_consume_it_early(
    monkeypatch,
):
    _enable(monkeypatch)
    _policy()
    hidden_preparatory = _deliver(human_interaction=True)
    assert hidden_preparatory["receipt"]["sequence"] == 1
    assert hidden_preparatory["delivered_text"].startswith(
        gateway.DEFAULT_DISCLOSURE_TEXT
    )

    first_human = _deliver(
        generated_text="First human-facing answer.",
        input_text="First human-facing question.",
        idempotency_key="turn-2",
        human_interaction=True,
    )
    assert first_human["receipt"]["sequence"] == 2
    assert first_human["delivered_text"].startswith(
        gateway.DEFAULT_DISCLOSURE_TEXT
    )
    assert gateway.verify_interaction_receipt(first_human["receipt"])

    later_human = _deliver(
        generated_text="Later human-facing answer.",
        input_text="Later human-facing question.",
        idempotency_key="turn-3",
        human_interaction=True,
    )
    assert later_human["receipt"]["sequence"] == 3
    assert later_human["delivered_text"].startswith(
        gateway.DEFAULT_DISCLOSURE_TEXT
    )

    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="human_interaction cannot be disabled",
    ):
        _deliver(
            generated_text="Machine-only internal output.",
            idempotency_key="turn-4",
            human_interaction=False,
        )


def test_first_delivery_provisions_the_default_policy(monkeypatch):
    """A tenant with no policy yet is receipted and disclosed, not withheld."""
    _enable(monkeypatch)
    assert gateway.get_policy("default") is None

    delivered = _deliver()

    policy = gateway.get_policy("default")
    assert policy is not None and policy["revision"] == 1
    assert policy["settings"]["disclosure_text"] == gateway.DEFAULT_DISCLOSURE_TEXT
    assert policy["settings"]["machine_marker"] == gateway.DEFAULT_MACHINE_MARKER
    assert policy["settings"]["supported_modalities"] == ["text"]
    assert delivered["delivered_text"].startswith(gateway.DEFAULT_DISCLOSURE_TEXT)
    assert delivered["receipt"]["policy_id"] == "default"
    assert gateway.verify_interaction_receipt(delivered["receipt"])

    # The provisioned policy is the tenant's policy from then on: a second
    # delivery reuses revision 1 instead of publishing another snapshot.
    _deliver(idempotency_key="turn-2", generated_text="Second answer.")
    assert gateway.get_policy("default")["revision"] == 1


def test_only_the_default_policy_is_provisioned_on_delivery(monkeypatch):
    _enable(monkeypatch)
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="policy 'custom' does not exist",
    ):
        _deliver(policy_id="custom")
    assert gateway.get_policy("custom") is None
    assert gateway.get_policy("default") is None


def test_delivery_caller_cannot_disable_ai_content_marking(monkeypatch):
    _enable(monkeypatch)
    _policy()
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="synthetic_content cannot be disabled",
    ):
        _deliver(synthetic_content=False)
    assert gateway.list_interaction_receipts() == []


def test_inline_exception_cannot_bypass_visible_marking(monkeypatch):
    _enable(monkeypatch)
    _policy()
    exception = {
        "decision_id": "decision-1",
        "reviewer": "not-a-governed-authority",
        "approved_at": "2026-07-20T12:00:00Z",
        "rationale": "Caller supplied.",
    }
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="inline exceptions are not accepted",
    ):
        _deliver(
            deepfake=True,
            editorial_exception=exception,
        )
    assert gateway.list_interaction_receipts() == []

    delivered = _deliver(deepfake=True)
    assert gateway.DEFAULT_VISIBLE_MARKER in delivered["delivered_text"]
    transparency = delivered["receipt"]["signed_receipt"]["transparency"]
    assert transparency["visible_marking_required"] is True
    assert transparency["visible_marking_applied"] is True


def test_unsupported_required_media_marking_fails_closed(monkeypatch):
    _enable(monkeypatch)
    _policy(supported_modalities=("text", "image"))
    with pytest.raises(
        gateway.UnsupportedMediaMarking,
        match="not implemented",
    ):
        _deliver(modality="image", deepfake=True)
    assert gateway.list_interaction_receipts() == []


def test_policy_model_and_context_changes_stale_old_receipts(monkeypatch):
    _enable(monkeypatch)
    first_policy = _policy()
    delivery = _deliver()
    updated = gateway.upsert_policy(
        "default",
        actor="policy-admin",
        expected_revision=first_policy["revision"],
        model_sha256=_sha("model-v2"),
        context_sha256=_sha("context-v2"),
    )
    assert updated["revision"] == 2
    assert updated["record_revision"] == 2
    assert updated["snapshot_count"] == 2

    stale = gateway.get_interaction_receipt(
        delivery["receipt"]["receipt_id"]
    )
    assert stale is not None
    assert stale["assurance"]["status"] == "stale"
    assert set(stale["assurance"]["reasons"]) >= {
        "stale_policy_revision",
        "stale_policy_digest",
        "stale_model",
        "stale_context",
    }
    # Historical snapshots retain only policy text and can reproduce exact
    # output bytes without retaining the generated output itself.
    replay = _deliver()
    assert replay["idempotent_replay"] is True
    assert replay["delivered_text"] == delivery["delivered_text"]


def test_retry_recovers_signed_receipt_after_governed_store_failure(monkeypatch):
    _enable(monkeypatch)
    first_policy = _policy()
    real_create = gateway._RECEIPTS.create
    failures = {"remaining": 1}

    def fail_once(record, *, action, actor):
        if failures["remaining"]:
            failures["remaining"] -= 1
            raise RuntimeError("simulated governed receipt persistence failure")
        return real_create(record, action=action, actor=actor)

    monkeypatch.setattr(gateway._RECEIPTS, "create", fail_once)
    with pytest.raises(
        RuntimeError,
        match="simulated governed receipt persistence failure",
    ):
        _deliver()

    ledger_rows = gateway._signed_rows(
        gateway._receipt_path(),
        "receipt_id",
        _stable_receipt_id := gateway._stable_id(
            "AIR",
            "gateway-test-tenant",
            _sha("conversation-1"),
            _sha("turn-1"),
        ),
    )
    assert len(ledger_rows) == 1
    assert gateway.list_interaction_receipts() == []
    assert not gateway._receipt_ledger_chain_valid([])

    # Recovery must use the signed row and its immutable policy snapshot even
    # if the current policy authority changes between the append and retry.
    gateway.upsert_policy(
        "default",
        actor="policy-admin",
        expected_revision=first_policy["revision"],
        disclosure_text="Updated disclosure.",
        model_sha256=_sha("model-v2"),
        context_sha256=_sha("context-v2"),
    )
    recovered = _deliver()
    assert recovered["idempotent_replay"] is True
    assert recovered["receipt"]["receipt_id"] == _stable_receipt_id
    assert recovered["receipt"]["signed_receipt"]["hash"] == ledger_rows[0]["hash"]
    assert (
        recovered["receipt"]["signed_receipt"]["issued_at"]
        == ledger_rows[0]["issued_at"]
    )
    assert recovered["delivered_text"].startswith(
        gateway.DEFAULT_DISCLOSURE_TEXT
    )
    assert gateway._receipt_ledger_chain_valid(
        gateway.list_interaction_receipts()
    )

    next_turn = _deliver(
        generated_text="Next answer.",
        input_text="Next question.",
        idempotency_key="turn-2",
        model="model-v2",
        context="context-v2",
    )
    assert next_turn["receipt"]["sequence"] == 2


def test_signing_identity_transaction_prevents_duplicate_rows(monkeypatch):
    _enable(monkeypatch)
    _policy()

    def call():
        return _deliver()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: call(), range(2)))
    assert {row["receipt"]["receipt_id"] for row in results} == {
        results[0]["receipt"]["receipt_id"]
    }
    assert sorted(row["idempotent_replay"] for row in results) == [False, True]
    rows = [
        json.loads(line)
        for line in gateway._receipt_path().read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 1
    assert rows[0]["receipt_id"] == results[0]["receipt"]["receipt_id"]


def test_delivery_fails_closed_before_receipt_capacity_is_crossed(monkeypatch):
    _enable(monkeypatch)
    _policy()
    monkeypatch.setattr(gateway, "_MAX_RECEIPTS", 1)
    first = _deliver()

    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="receipt capacity has been reached",
    ):
        _deliver(
            generated_text="Second answer.",
            input_text="Second question.",
            idempotency_key="turn-2",
        )

    receipts = gateway.list_interaction_receipts(limit=1)
    assert [row["receipt_id"] for row in receipts] == [
        first["receipt"]["receipt_id"]
    ]
    assert len(gateway._signed_ledger_rows(gateway._receipt_path())) == 1
    conversation = gateway._CONVERSATIONS.get(
        gateway._stable_id("AIC", _sha("conversation-1"))
    )
    assert conversation is not None
    assert conversation["pending"] is None
    assert gateway.summary()["readiness"]["ready"] is True
    packet = gateway.render_assurance_packet(actor="assurance-officer")
    assert packet["verification"]["receipt_ledger_chain_valid"] is True
    assert gateway.verify_assurance_packet(packet)


def test_policy_and_impact_capacity_refuse_before_namespace_oversize(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setattr(gateway, "_MAX_POLICIES", 1)
    policy = _policy()

    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="policy capacity has been reached",
    ):
        _policy(policy_id="second-policy")
    assert [row["id"] for row in gateway.list_policies()] == [policy["id"]]

    monkeypatch.setattr(gateway, "_MAX_IMPACTS", 1)
    impact = _impact()
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="impact capacity has been reached",
    ):
        _impact(alert_id="second-regulatory-alert")

    # The ceiling does not break exact idempotent recovery at capacity.
    assert _impact()["id"] == impact["id"]
    assert [row["id"] for row in gateway.list_regulatory_impacts(limit=1)] == [
        impact["id"]
    ]
    assert gateway.summary()["regulatory_impacts"]["total"] == 1


def test_exact_concurrent_impact_create_recovers_idempotently(monkeypatch):
    _enable(monkeypatch)
    _policy()
    real_create = gateway._IMPACTS.create

    def commit_then_report_conflict(*args, **kwargs):
        real_create(*args, **kwargs)
        raise RecordConflict("simulated concurrent replica winner")

    monkeypatch.setattr(
        gateway._IMPACTS,
        "create",
        commit_then_report_conflict,
    )
    impact = _impact()

    assert impact["status"] == "pending_review"
    assert [row["id"] for row in gateway.list_regulatory_impacts()] == [
        impact["id"]
    ]


def test_accepted_impact_refreshes_policy_and_stales_receipt(monkeypatch):
    _enable(monkeypatch)
    policy = _policy()
    delivery = _deliver()
    impact = _impact()
    accepted = gateway.review_regulatory_impact(
        impact["id"],
        decision="accepted",
        reviewer="risk-committee",
        rationale="Official cited change affects the enabled policy.",
        expected_revision=impact["revision"],
    )
    assert accepted["status"] == "accepted"
    assert accepted["review"]["human_review"] is True
    assert accepted["policy_refreshes"][0]["policy_record_revision"] == (
        policy["revision"] + 1
    )
    refreshed = gateway.get_policy()
    assert refreshed is not None
    assert refreshed["regulatory_bindings"][0]["impact_id"] == impact["id"]
    stale = gateway.get_interaction_receipt(
        delivery["receipt"]["receipt_id"]
    )
    assert stale is not None
    assert stale["assurance"]["status"] == "stale"
    with pytest.raises(RecordConflict):
        gateway.review_regulatory_impact(
            impact["id"],
            decision="dismissed",
            reviewer="other-reviewer",
            rationale="Concurrent dismissal must not overwrite acceptance.",
            expected_revision=impact["revision"],
        )


def test_policy_updates_cannot_forge_or_erase_regulatory_bindings(monkeypatch):
    _enable(monkeypatch)
    _policy()
    impact = _impact()
    gateway.review_regulatory_impact(
        impact["id"],
        decision="accepted",
        reviewer="risk-committee",
        rationale="Bind the cited, reviewed change.",
        expected_revision=impact["revision"],
    )
    current = gateway.get_policy()
    assert current is not None
    binding = current["regulatory_bindings"][0]

    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="only be changed by an accepted regulatory impact",
    ):
        gateway.upsert_policy(
            "default",
            actor="policy-admin",
            expected_revision=current["revision"],
            model_sha256=_sha("model-v1"),
            context_sha256=_sha("context-v1"),
            regulatory_bindings=[],
        )

    updated = gateway.upsert_policy(
        "default",
        actor="policy-admin",
        expected_revision=current["revision"],
        model_sha256=_sha("model-v2"),
        context_sha256=_sha("context-v2"),
    )
    assert updated["regulatory_bindings"] == [binding]


def test_acceptance_claim_is_recoverable_and_blocks_dismissal(monkeypatch):
    _enable(monkeypatch)
    _policy()
    impact = _impact()
    real_bind = gateway._bind_impact_to_policy

    def unavailable(*_args, **_kwargs):
        raise gateway.EvidenceGatewayStateError("policy backend unavailable")

    monkeypatch.setattr(gateway, "_bind_impact_to_policy", unavailable)
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="policy backend unavailable",
    ):
        gateway.review_regulatory_impact(
            impact["id"],
            decision="accepted",
            reviewer="risk-committee",
            rationale="Apply the cited change.",
            expected_revision=impact["revision"],
        )
    refreshing = gateway.list_regulatory_impacts()[0]
    assert refreshing["status"] == "accepted_refreshing"
    cockpit = gateway.summary()
    assert cockpit["refreshing_regulatory_impact_count"] == 1
    assert "regulatory_impacts_refreshing" in cockpit["readiness"]["gaps"]
    with pytest.raises(RecordConflict, match="already being applied"):
        gateway.review_regulatory_impact(
            impact["id"],
            decision="dismissed",
            reviewer="other-reviewer",
            rationale="Cannot race the claimed acceptance.",
            expected_revision=refreshing["revision"],
        )

    monkeypatch.setattr(gateway, "_bind_impact_to_policy", real_bind)
    recovered = gateway.review_regulatory_impact(
        impact["id"],
        decision="accepted",
        reviewer="risk-committee",
        rationale="Apply the cited change.",
        # The original revision is accepted only for the identical claimed
        # review, making a failed policy refresh retryable.
        expected_revision=impact["revision"],
    )
    assert recovered["status"] == "accepted"


def test_acceptance_reserves_binding_capacity_for_crash_recovery(monkeypatch):
    _enable(monkeypatch)
    _policy()
    monkeypatch.setattr(gateway, "_MAX_AFFECTED", 1)
    first = _impact(alert_id="capacity-reservation-one")
    second = _impact(alert_id="capacity-reservation-two")
    real_bind = gateway._bind_impact_to_policy

    def unavailable(*_args, **_kwargs):
        raise gateway.EvidenceGatewayStateError("simulated worker crash")

    monkeypatch.setattr(gateway, "_bind_impact_to_policy", unavailable)
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="simulated worker crash",
    ):
        gateway.review_regulatory_impact(
            first["id"],
            decision="accepted",
            reviewer="risk-committee",
            rationale="Reserve capacity before applying the cited change.",
            expected_revision=first["revision"],
        )
    assert gateway.get_regulatory_impact(first["id"])["status"] == (
        "accepted_refreshing"
    )

    monkeypatch.setattr(gateway, "_bind_impact_to_policy", real_bind)
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="acceptance was not claimed",
    ):
        gateway.review_regulatory_impact(
            second["id"],
            decision="accepted",
            reviewer="risk-committee",
            rationale="This review must not consume reserved capacity.",
            expected_revision=second["revision"],
        )
    assert gateway.get_regulatory_impact(second["id"])["status"] == (
        "pending_review"
    )

    recovered = gateway.review_regulatory_impact(
        first["id"],
        decision="accepted",
        reviewer="risk-committee",
        rationale="Reserve capacity before applying the cited change.",
        expected_revision=first["revision"],
    )
    assert recovered["status"] == "accepted"
    assert gateway.get_policy()["regulatory_bindings"][0]["impact_id"] == (
        first["id"]
    )
    assert {
        row["status"] for row in gateway.list_regulatory_impacts()
    } == {"accepted", "pending_review"}


def test_policy_history_rolls_over_at_256_without_orphaning_receipts(
    monkeypatch,
):
    _enable(monkeypatch)
    policy = _policy()
    original = _deliver()
    for revision in range(2, gateway._MAX_POLICY_HISTORY + 2):
        policy = gateway.upsert_policy(
            "default",
            actor="policy-admin",
            expected_revision=policy["revision"],
            disclosure_text=f"AI disclosure revision {revision}.",
            model_sha256=_sha("model-v1"),
            context_sha256=_sha("context-v1"),
        )
    assert policy["revision"] == gateway._MAX_POLICY_HISTORY + 1
    assert policy["snapshot_count"] == gateway._MAX_POLICY_HISTORY + 1

    impact = _impact(alert_id="history-rollover-impact")
    accepted = gateway.review_regulatory_impact(
        impact["id"],
        decision="accepted",
        reviewer="risk-committee",
        rationale="Exercise rollover at the exact hot-history ceiling.",
        expected_revision=impact["revision"],
    )
    assert accepted["status"] == "accepted"
    refreshed = gateway.get_policy()
    assert refreshed["revision"] == gateway._MAX_POLICY_HISTORY + 2
    assert refreshed["snapshot_count"] == gateway._MAX_POLICY_HISTORY + 1
    assert len(gateway._POLICY_SNAPSHOTS.list(limit=10)) == 1

    historical = gateway.get_interaction_receipt(
        original["receipt"]["receipt_id"]
    )
    assert historical is not None
    assert historical["assurance"]["status"] == "stale"
    assert gateway.verify_interaction_receipt(historical)


def test_non_ascii_policy_text_and_tenant_compare_without_type_error(monkeypatch):
    # Canonical JSON keeps non-ASCII text, and hmac.compare_digest raised
    # TypeError for equal values: re-archiving a snapshot whose disclosure is
    # not ASCII, or reading a receipt that carries a Unicode tenant id.
    _enable(monkeypatch)
    monkeypatch.setenv("MAVERICK_TENANT", "équipe-santé")
    policy = _policy(disclosure_text="Divulgación: contenido generado por IA — revísalo.")
    assert policy["revision"] == 1
    snapshot = gateway._policy_record("default")["current"]
    gateway._archive_policy_snapshot(snapshot, actor="policy-admin")
    gateway._archive_policy_snapshot(snapshot, actor="policy-admin")
    assert len(gateway._POLICY_SNAPSHOTS.list(limit=10)) == 1

    delivery = _deliver()
    receipt = gateway.get_interaction_receipt(delivery["receipt"]["receipt_id"])
    assert receipt is not None
    assert receipt["signed_receipt"]["tenant_id"] == "équipe-santé"


def test_summary_treats_tampered_receipt_as_not_ready(monkeypatch):
    _enable(monkeypatch)
    _policy()
    delivery = _deliver()
    record = gateway._RECEIPTS.get(delivery["receipt"]["receipt_id"])
    assert record is not None

    def tamper(row):
        row["signed_receipt"]["delivered_output_sha256"] = "f" * 64

    gateway._RECEIPTS.update(
        record["id"],
        tamper,
        expected_revision=record["revision"],
        action="test_tamper",
        actor="test",
    )
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="diverges from its signed ledger authority",
    ):
        gateway.get_interaction_receipt(delivery["receipt"]["receipt_id"])
    cockpit = gateway.summary()
    assert cockpit["unverified_interaction_receipt_count"] == 1
    assert cockpit["readiness"]["ready"] is False
    assert "unverified_interaction_receipts" in cockpit["readiness"]["gaps"]


def test_summary_and_packet_reject_missing_receipt_store_rows(monkeypatch):
    _enable(monkeypatch)
    _policy()
    _deliver(
        generated_text="First answer.",
        conversation_id="ledger-completeness",
        idempotency_key="turn-1",
    )
    _deliver(
        generated_text="Second answer.",
        conversation_id="ledger-completeness",
        idempotency_key="turn-2",
    )
    all_receipts = gateway.list_interaction_receipts()
    assert len(all_receipts) == 2
    assert gateway._receipt_ledger_chain_valid(all_receipts)

    # Simulate loss of the terminal governed-store row while the signed ledger
    # remains intact. The remaining conversation prefix and ledger are each
    # internally valid, but their exact identities no longer reconcile.
    remaining_prefix = [
        row for row in all_receipts if row["signed_receipt"]["sequence"] == 1
    ]
    assert gateway._conversation_chains_valid(remaining_prefix)
    assert not gateway._receipt_ledger_chain_valid(remaining_prefix)
    assert not gateway._receipt_ledger_chain_valid([])
    terminal_id = next(
        row["receipt_id"]
        for row in all_receipts
        if row["signed_receipt"]["sequence"] == 2
    )
    real_get = gateway._RECEIPTS.get

    def missing_terminal(record_id):
        if record_id == terminal_id:
            return None
        return real_get(record_id)

    monkeypatch.setattr(gateway._RECEIPTS, "get", missing_terminal)
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="missing its governed authority record",
    ):
        gateway.get_interaction_receipt(terminal_id)

    cockpit = gateway.summary()
    assert cockpit["interaction_receipts"]["conversation_chains_valid"] is False
    assert cockpit["interaction_receipts"]["ledger_chain_valid"] is False
    assert cockpit["interaction_receipts"]["missing_governed"] == 1
    assert "invalid_receipt_ledger_chain" in cockpit["readiness"]["gaps"]
    assert cockpit["readiness"]["ready"] is False

    packet = gateway.render_assurance_packet(actor="assurance-officer")
    assert packet["verification"]["receipt_ledger_chain_valid"] is False
    assert "invalid_receipt_ledger_chain" in packet["readiness"]["gaps"]
    assert packet["readiness"]["ready"] is False


def test_composite_packet_has_official_sources_and_external_verification(monkeypatch):
    _enable(monkeypatch)
    _policy()
    _deliver()
    packet = gateway.render_assurance_packet(actor="assurance-officer")
    assert packet["legal_certification"] is False
    assert packet["compliance_verdict"] == "not_provided"
    assert packet["stores_raw_interaction_content"] is False
    assert set(packet["framework_sources"]) == {
        "ec_article_50",
        "ec_gpai_guidelines",
        "nist_ai_rmf_1_0",
        "omb_m_25_22",
    }
    assert all(
        source["url"].startswith("https://")
        for source in packet["framework_sources"].values()
    )
    trust = gateway.trusted_public_keys()
    assert gateway.verify_assurance_packet(
        packet,
        trusted_public_keys=trust,
    )
    assert gateway.verify_assurance_packet(packet)
    assert not gateway.verify_assurance_packet(
        packet,
        trusted_public_keys={},
    )
    tampered = copy.deepcopy(packet)
    tampered["readiness"]["ready"] = not tampered["readiness"]["ready"]
    assert not gateway.verify_assurance_packet(
        tampered,
        trusted_public_keys=trust,
    )


def test_packet_issue_key_replays_exact_packet_once(monkeypatch):
    _enable(monkeypatch)
    _policy()
    _deliver()

    first = gateway.issue_assurance_packet(
        profile="combined",
        actor="assurance-officer",
        idempotency_key="download-request-1",
    )
    replay = gateway.issue_assurance_packet(
        profile="combined",
        actor="assurance-officer",
        idempotency_key="download-request-1",
    )
    assert first["idempotent_replay"] is False
    assert replay["idempotent_replay"] is True
    assert replay["packet"] == first["packet"]
    assert replay["packet"]["generated_at"] == first["packet"]["generated_at"]
    assert gateway._packet_ledger().state().total_receipts == 1
    assert len(gateway._PACKET_REPLAYS.list(limit=10)) == 1

    other_actor = gateway.issue_assurance_packet(
        profile="combined",
        actor="other-assurance-officer",
        idempotency_key="download-request-1",
    )
    assert other_actor["packet"]["packet_id"] != first["packet"]["packet_id"]
    assert gateway._packet_ledger().state().total_receipts == 2


def test_packet_issue_recovers_crash_after_attestation(monkeypatch):
    """A signed packet must remain recoverable until replay authority commits."""

    _enable(monkeypatch)
    _policy()
    _deliver()
    real_attestation = gateway._attestation
    injected = {"pending": True}

    def sign_then_crash(**kwargs):
        attestation = real_attestation(**kwargs)
        if injected["pending"]:
            injected["pending"] = False
            raise RuntimeError("simulated process crash after packet signing")
        return attestation

    monkeypatch.setattr(gateway, "_attestation", sign_then_crash)
    with pytest.raises(RuntimeError, match="simulated process crash"):
        gateway.issue_assurance_packet(
            profile="combined",
            actor="assurance-officer",
            idempotency_key="crash-recovery-request",
        )

    checkpoints = gateway._PACKET_REPLAYS.list(limit=10)
    assert len(checkpoints) == 1
    assert checkpoints[0]["status"] == "prepared"
    generated_at = checkpoints[0]["packet_body"]["generated_at"]
    assert gateway._packet_ledger().state().total_receipts == 1

    recovered = gateway.issue_assurance_packet(
        profile="combined",
        actor="assurance-officer",
        idempotency_key="crash-recovery-request",
    )
    assert recovered["idempotent_replay"] is False
    assert recovered["packet"]["generated_at"] == generated_at
    assert gateway.verify_assurance_packet(recovered["packet"])
    assert gateway._packet_ledger().state().total_receipts == 1

    committed = gateway._PACKET_REPLAYS.list(limit=10)
    assert committed[0]["status"] == "issued"
    assert "packet_body" not in committed[0]
    replay = gateway.issue_assurance_packet(
        profile="combined",
        actor="assurance-officer",
        idempotency_key="crash-recovery-request",
    )
    assert replay["idempotent_replay"] is True
    assert replay["packet"] == recovered["packet"]


def test_packet_rechecks_half_committed_receipt_before_attesting(monkeypatch):
    _enable(monkeypatch)
    _policy()
    delivery = _deliver()
    signed = delivery["receipt"]["signed_receipt"]
    orphan_event = {
        key: copy.deepcopy(value)
        for key, value in signed.items()
        if key not in {"prev_hash", "key_id", "hash", "sig"}
    }
    orphan_event.update(
        {
            "receipt_id": gateway._stable_id(
                "AIR",
                "gateway-test-tenant",
                _sha("packet-race-conversation"),
                _sha("packet-race-turn"),
            ),
            "issued_at": float(signed["issued_at"]) + 1.0,
            "conversation_sha256": _sha("packet-race-conversation"),
            "sequence": 1,
            "idempotency_sha256": _sha("packet-race-turn"),
            "parent_receipt_hash": "",
        }
    )
    orphan_event.pop("receipt_payload_sha256")
    orphan_event["receipt_payload_sha256"] = gateway._sha256(orphan_event)
    real_packet_json_size = gateway._packet_json_size
    injected = {"done": False}

    def append_after_initial_snapshot(value):
        if not injected["done"]:
            injected["done"] = True
            gateway._sign_event(
                orphan_event,
                path=gateway._receipt_path(),
                identity_key="receipt_id",
                identity=orphan_event["receipt_id"],
            )
        return real_packet_json_size(value)

    monkeypatch.setattr(
        gateway,
        "_packet_json_size",
        append_after_initial_snapshot,
    )
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="receipt ledger changed during packet snapshot",
    ):
        gateway.render_assurance_packet(actor="assurance-officer")
    assert not gateway._receipt_ledger_chain_valid(
        gateway.list_interaction_receipts()
    )


def test_historical_packet_accepts_a_later_trust_registry_superset(monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    _enable(monkeypatch)
    _policy()
    _deliver()
    packet = gateway.render_assurance_packet(actor="assurance-officer")
    trust = gateway.trusted_public_keys()
    extra_private = Ed25519PrivateKey.generate()
    extra_public = extra_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    expanded_trust = {
        **trust,
        hashlib.sha256(extra_public).hexdigest()[:16]: extra_public.hex(),
    }
    assert gateway.verify_assurance_packet(
        packet,
        trusted_public_keys=expanded_trust,
    )


def test_packet_window_is_bounded_manifested_and_verifiable(monkeypatch):
    _enable(monkeypatch)
    _policy(policy_id="policy-a")
    _policy(policy_id="policy-b")
    _deliver(
        policy_id="policy-a",
        conversation_id="conversation-a",
        idempotency_key="turn-a",
    )
    _deliver(
        policy_id="policy-b",
        conversation_id="conversation-b",
        idempotency_key="turn-b",
    )
    monkeypatch.setattr(gateway, "_MAX_PACKET_POLICIES", 1)
    monkeypatch.setattr(gateway, "_MAX_PACKET_RECEIPTS", 1)
    packet = gateway.render_assurance_packet(actor="assurance-officer")
    window = packet["evidence_window"]
    assert window["source_counts"]["policies"] == 2
    assert window["source_counts"]["interaction_receipts"] == 2
    assert window["included_counts"]["policies"] == 1
    assert window["included_counts"]["interaction_receipts"] == 1
    assert "packet_window_truncated" in packet["readiness"]["gaps"]
    assert packet["readiness"]["ready"] is False
    assert gateway.verify_assurance_packet(packet)


def test_packet_attestations_roll_over_to_segmented_index(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setenv("MAVERICK_EVIDENCE_PACKET_SEGMENT_ROWS", "1")
    _policy()
    _deliver()

    first = gateway.render_assurance_packet(
        actor="assurance-officer",
        packet_id="packet-one",
    )
    second = gateway.render_assurance_packet(
        actor="assurance-officer",
        packet_id="packet-two",
    )

    ledger = gateway._packet_ledger()
    assert ledger.verify_integrity() == (True, "")
    assert ledger.state().total_receipts == 2
    assert ledger.index_path.exists()
    assert (ledger.segment_dir / "segment-00000001.ndjson").exists()
    assert gateway.verify_assurance_packet(first)
    assert gateway.verify_assurance_packet(second)
    assert {
        row["packet_id"]
        for row in gateway._signed_ledger_rows(gateway._packet_path())
    } == {first["packet_id"], second["packet_id"]}


def test_packet_capacity_withholds_new_attestation_before_signing(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setattr(gateway, "_MAX_PACKETS", 1)
    _policy()
    _deliver()

    first = gateway.render_assurance_packet(
        actor="assurance-officer",
        packet_id="packet-one",
    )
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="capacity has been reached",
    ):
        gateway.render_assurance_packet(
            actor="assurance-officer",
            packet_id="packet-two",
        )

    ledger = gateway._packet_ledger()
    assert ledger.state().total_receipts == 1
    assert [
        row["packet_id"]
        for row in gateway._signed_ledger_rows(gateway._packet_path())
    ] == [first["packet_id"]]


def test_metadata_cannot_claim_raw_input_text(monkeypatch):
    _enable(monkeypatch)
    with pytest.raises(
        ValueError,
        match="unsupported non-governance fields",
    ):
        _policy(metadata={"input_text": "raw prompt"})


def test_corrupted_regulatory_impact_is_not_repackaged(monkeypatch):
    _enable(monkeypatch)
    _policy()
    impact = _impact()
    persisted = gateway._IMPACTS.get(impact["id"])
    assert persisted is not None

    def tamper(row):
        row["citations"][0]["content_sha256"] = "f" * 64

    gateway._IMPACTS.update(
        persisted["id"],
        tamper,
        expected_revision=persisted["revision"],
        action="test_tamper",
        actor="test",
    )
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="integrity validation",
    ):
        gateway.list_regulatory_impacts()


def test_regulatory_impact_cursor_pages_501_rows_pending_first(monkeypatch):
    _enable(monkeypatch)
    rows = [
        {
            "id": f"AII-{index:032x}",
            "revision": 1,
            "status": "accepted",
            "created_at": float(index),
            "updated_at": float(index),
        }
        for index in range(2, 502)
    ]
    pending = {
        "id": f"AII-{1:032x}",
        "revision": 1,
        "status": "pending_review",
        "created_at": 1.0,
        "updated_at": 1.0,
    }
    rows.append(pending)
    monkeypatch.setattr(
        gateway._IMPACTS,
        "list",
        lambda *, limit: [dict(row) for row in rows[:limit]],
    )
    monkeypatch.setattr(
        gateway,
        "_validated_impact_view",
        lambda row: dict(row),
    )

    first = gateway.list_regulatory_impacts_page(
        limit=500,
        pending_first=True,
    )
    assert first["snapshot_total"] == 501
    assert first["count"] == 500
    assert first["items"][0]["id"] == pending["id"]
    assert first["next_cursor"]

    rows.append(
        {
            "id": f"AII-{502:032x}",
            "revision": 1,
            "status": "pending_review",
            "created_at": 502.0,
            "updated_at": 502.0,
        }
    )
    second = gateway.list_regulatory_impacts_page(
        limit=500,
        cursor=first["next_cursor"],
        pending_first=True,
    )
    assert second["count"] == 1
    assert second["snapshot_total"] == 501
    assert second["items"][0]["id"] != f"AII-{502:032x}"

    pending_only = gateway.list_regulatory_impacts_page(
        limit=10,
        status="pending_review",
    )
    assert [row["id"] for row in pending_only["items"]] == [
        f"AII-{502:032x}",
        pending["id"],
    ]

    rows[0]["revision"] = 2
    rows[0]["updated_at"] = 503.0
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="restart pagination",
    ):
        gateway.list_regulatory_impacts_page(
            limit=500,
            cursor=first["next_cursor"],
            pending_first=True,
        )


def test_seed_demo_is_idempotent_and_offline(monkeypatch):
    _enable(monkeypatch)
    first = gateway.seed_demo()
    second = gateway.seed_demo()
    assert first["synthetic"] is True
    assert first["network_access"] is False
    assert first["policy_id"] == second["policy_id"]
    assert first["receipt_id"] == second["receipt_id"]
    assert first["regulatory_impact_id"] == second["regulatory_impact_id"]
    assert first["idempotent_replay"] is False
    assert second["idempotent_replay"] is True
    assert len(gateway.list_policies()) == 1
    assert len(gateway.list_interaction_receipts()) == 1
    assert len(gateway.list_regulatory_impacts()) == 1
    assert "synthetic_demo_data_present" in second["summary"]["readiness"]["gaps"]


def test_synthetic_policy_cannot_claim_production_readiness(monkeypatch):
    _enable(monkeypatch)
    _policy(metadata={"synthetic": True})
    _deliver()

    result = gateway.summary()
    assert result["readiness"]["ready"] is False
    assert "synthetic_demo_data_present" in result["readiness"]["gaps"]

    packet = gateway.render_assurance_packet(actor="assurance-officer")
    assert packet["readiness"]["ready"] is False
    assert "synthetic_demo_data_present" in packet["readiness"]["gaps"]
    assert gateway.verify_assurance_packet(packet)

    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="require separate tenant namespaces",
    ):
        _policy(policy_id="production-policy")
    assert [row["policy_id"] for row in gateway.list_policies()] == ["default"]


def test_production_policy_blocks_later_synthetic_mode_claim(monkeypatch):
    _enable(monkeypatch)
    production = _policy()

    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="require separate tenant namespaces",
    ):
        _policy(
            policy_id="synthetic-policy",
            metadata={"synthetic": True},
        )
    assert [row["id"] for row in gateway.list_policies()] == [production["id"]]


def test_rejected_new_policy_does_not_claim_tenant_mode(monkeypatch):
    _enable(monkeypatch)
    with pytest.raises(RecordConflict):
        gateway.upsert_policy(
            "rejected-synthetic-policy",
            actor="policy-admin",
            expected_revision=99,
            model_sha256=_sha("model-v1"),
            context_sha256=_sha("context-v1"),
            metadata={"synthetic": True},
        )

    assert gateway.list_policies() == []
    production = _policy()
    assert production["metadata"] == {}


def test_demo_seed_refuses_to_mix_with_live_tenant_evidence(monkeypatch):
    _enable(monkeypatch)
    _policy()
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="empty or dedicated demo tenant",
    ):
        gateway.seed_demo()


def test_segmented_receipts_cross_link_and_cursor_snapshot_is_stable(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setenv("MAVERICK_EVIDENCE_RECEIPT_SEGMENT_ROWS", "2")
    _policy()
    for turn in range(1, 6):
        _deliver(
            generated_text=f"Answer {turn}.",
            input_text=f"Question {turn}.",
            conversation_id=f"conversation-{turn}",
            idempotency_key=f"turn-{turn}",
        )

    ledger = gateway._receipt_ledger()
    valid, detail = ledger.verify_integrity()
    assert (valid, detail) == (True, "")
    assert ledger.state().total_receipts == 5
    assert len(list(ledger.segment_dir.glob("segment-*.ndjson"))) == 2
    monkeypatch.setattr(gateway, "_MAX_RECEIPT_LIST", 2)
    monkeypatch.setattr(gateway, "_MAX_PACKET_RECEIPTS", 2)
    assert gateway.summary()["interaction_receipt_count"] == 5
    packet = gateway.render_assurance_packet(actor="assurance-officer")
    assert packet["evidence_window"]["source_counts"][
        "interaction_receipts"
    ] == 5
    assert packet["evidence_window"]["included_counts"][
        "interaction_receipts"
    ] == 2
    assert gateway.verify_assurance_packet(packet)

    first = gateway.list_interaction_receipts_page(limit=2)
    assert [row["ledger_ordinal"] for row in first["items"]] == [5, 4]
    assert first["snapshot_total"] == 5
    assert first["next_cursor"]

    _deliver(
        generated_text="Later answer.",
        input_text="Later question.",
        conversation_id="conversation-later",
        idempotency_key="turn-later",
    )
    second = gateway.list_interaction_receipts_page(
        limit=2,
        cursor=first["next_cursor"],
    )
    assert [row["ledger_ordinal"] for row in second["items"]] == [3, 2]
    assert second["snapshot_total"] == 5
    assert all(row["ledger_ordinal"] != 6 for row in second["items"])

    tampered_cursor = first["next_cursor"][:-1] + (
        "A" if first["next_cursor"][-1] != "A" else "B"
    )
    with pytest.raises(ValueError, match="cursor is invalid"):
        gateway.list_interaction_receipts_page(
            limit=2,
            cursor=tampered_cursor,
        )


def test_legacy_receipt_file_is_indexed_without_rewriting_signed_bytes(
    monkeypatch,
):
    from maverick.audit.signing import AuditSigner

    _enable(monkeypatch)
    path = gateway._receipt_path()
    legacy_event = {
        "receipt_id": "AIR-" + "1" * 32,
        "receipt_payload_sha256": "2" * 64,
        "legacy": True,
    }
    signer = AuditSigner(path)
    assert signer.write(legacy_event)
    original = path.read_bytes()

    ledger = SegmentedReceiptLedger(
        path,
        tenant_id="gateway-test-tenant",
        segment_rows=1,
        max_receipts=10,
    )
    recovered = ledger.find(legacy_event["receipt_id"])
    assert recovered is not None
    assert recovered["legacy"] is True
    assert path.read_bytes() == original
    assert ledger.state().total_receipts == 1

    next_event = {
        "receipt_id": "AIR-" + "3" * 32,
        "receipt_payload_sha256": "4" * 64,
        "legacy": False,
    }
    signed, _public_key = ledger.append(
        next_event,
        identity=next_event["receipt_id"],
    )
    assert signed["receipt_id"] == next_event["receipt_id"]
    segment = ledger.segment_dir / "segment-00000001.ndjson"
    segment_rows = [
        json.loads(line)
        for line in segment.read_text(encoding="utf-8").splitlines()
    ]
    assert segment_rows[0]["previous_segment_tip"] == json.loads(
        original.decode("utf-8")
    )["hash"]
    assert segment_rows[0]["previous_total_receipts"] == 1
    assert ledger.verify_integrity() == (True, "")


def test_crash_reconciliation_accepts_only_an_append_extension(monkeypatch):
    from maverick.audit.signing import AuditSigner

    _enable(monkeypatch)
    ledger = gateway._receipt_ledger()
    first = {
        "receipt_id": "AIR-" + "5" * 32,
        "receipt_payload_sha256": "6" * 64,
    }
    ledger.append(first, identity=first["receipt_id"])
    state_before = ledger.state()

    # Simulate a process dying after the durable signed append but before the
    # SQLite/index-state commit.
    orphan = {
        "receipt_id": "AIR-" + "7" * 32,
        "receipt_payload_sha256": "8" * 64,
    }
    assert AuditSigner(ledger.legacy_path).write(orphan)
    recovered = ledger.find(orphan["receipt_id"])
    assert recovered is not None
    assert ledger.state().total_receipts == 2
    assert ledger.state().generation > state_before.generation
    assert ledger.verify_integrity() == (True, "")

    # A shorter ledger is not a crash extension.  Reconciliation must refuse
    # to bless the surviving prefix with a fresh signed state.
    lines = ledger.legacy_path.read_text(encoding="utf-8").splitlines()
    ledger.legacy_path.write_text(lines[0] + "\n", encoding="utf-8")
    valid, detail = ledger.verify_integrity()
    assert valid is False
    assert "truncated or diverged" in detail
    with pytest.raises(SegmentedLedgerError, match="truncated or diverged"):
        ledger.state()


def test_index_tamper_and_missing_segment_state_never_verify_clean(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setenv("MAVERICK_EVIDENCE_RECEIPT_SEGMENT_ROWS", "1")
    _policy()
    _deliver(conversation_id="one", idempotency_key="one")
    _deliver(conversation_id="two", idempotency_key="two")
    ledger = gateway._receipt_ledger()
    assert ledger.verify_integrity() == (True, "")

    connection = sqlite3.connect(ledger.index_path)
    try:
        connection.execute(
            "UPDATE receipts SET row_hash=? WHERE ordinal=1",
            ("f" * 64,),
        )
        connection.commit()
    finally:
        connection.close()
    valid, detail = ledger.verify_integrity()
    assert valid is False
    assert "diverges" in detail
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="does not match its signed row",
    ):
        gateway.list_interaction_receipts_page(limit=10)
    with pytest.raises(
        SegmentedLedgerError,
        match="does not match its signed row",
    ):
        list(ledger.iter_entries())

    # Restore by rebuilding from an authenticated physical extension, then
    # prove that deleting the authenticated state beside numbered segments is
    # not treated as a fresh migration.
    ledger.index_path.unlink()
    assert ledger.state().total_receipts == 2
    ledger.state_path.unlink()
    with pytest.raises(
        SegmentedLedgerError,
        match="exists without authenticated index state",
    ):
        ledger.state()


def test_non_ascii_index_metadata_is_rebuilt_not_a_type_error(monkeypatch):
    # A damaged derivative index is rebuilt from the signed ledger; non-ASCII
    # metadata must not raise TypeError from hmac.compare_digest instead.
    _enable(monkeypatch)
    _policy()
    _deliver(conversation_id="one", idempotency_key="one")
    ledger = gateway._receipt_ledger()
    expected = ledger.state()
    connection = sqlite3.connect(ledger.index_path)
    try:
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='state_hash'",
            ("é" * 64,),
        )
        connection.commit()
    finally:
        connection.close()
    assert ledger.state().total_receipts == expected.total_receipts
    assert ledger.verify_integrity() == (True, "")


def test_targeted_reads_verify_historical_segment_signatures(monkeypatch):
    _enable(monkeypatch)
    ledger = SegmentedReceiptLedger(
        gateway._receipt_path(),
        tenant_id="gateway-test-tenant",
        segment_rows=1,
        max_receipts=10,
    )
    events = [
        {
            "receipt_id": f"AIR-{digit * 32}",
            "receipt_payload_sha256": digit * 64,
            "immutable_claim": f"claim-{digit}",
        }
        for digit in ("1", "2", "3")
    ]
    for event in events:
        ledger.append(event, identity=event["receipt_id"])

    # Keep the indexed identity/hash/payload fields untouched while modifying
    # a different historical field.  The active segment and index still look
    # current, so the targeted read itself must verify the historical signature.
    first = json.loads(ledger.legacy_path.read_text(encoding="utf-8"))
    first["immutable_claim"] = "tampered"
    ledger.legacy_path.write_text(
        json.dumps(first) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(SegmentedLedgerError, match="failed verification"):
        ledger.find(events[0]["receipt_id"])
    with pytest.raises(SegmentedLedgerError, match="failed verification"):
        ledger.page(limit=3)


def test_index_cannot_turn_a_signed_identity_into_a_false_absence(monkeypatch):
    _enable(monkeypatch)
    ledger = gateway._receipt_ledger()
    event = {
        "receipt_id": "AIR-" + "4" * 32,
        "receipt_payload_sha256": "5" * 64,
    }
    ledger.append(event, identity=event["receipt_id"])
    connection = sqlite3.connect(ledger.index_path)
    try:
        connection.execute(
            "UPDATE receipts SET identity=? WHERE ordinal=1",
            ("AIR-" + "6" * 32,),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SegmentedLedgerError, match="omits a signed row"):
        ledger.find(event["receipt_id"])


def test_oversized_receipt_is_rejected_before_any_evidence_append(monkeypatch):
    _enable(monkeypatch)
    ledger = SegmentedReceiptLedger(
        gateway._receipt_path(),
        tenant_id="gateway-test-tenant",
        segment_rows=100,
        segment_bytes=1024 * 1024,
        max_receipts=10,
    )
    event = {
        "receipt_id": "AIR-" + "7" * 32,
        "receipt_payload_sha256": "8" * 64,
        "oversized": "x" * (1024 * 1024),
    }
    with pytest.raises(
        SegmentedLedgerError,
        match="withheld before signing",
    ):
        ledger.append(event, identity=event["receipt_id"])
    assert ledger.state().total_receipts == 0
    assert not ledger.legacy_path.exists()
    assert not ledger.segment_dir.exists()


def test_receipt_cursor_has_a_strict_encoded_size_bound(monkeypatch):
    _enable(monkeypatch)
    ledger = gateway._receipt_ledger()
    with pytest.raises(ValueError, match="cursor is invalid"):
        ledger.page(limit=1, cursor="A" * 2_049)


@pytest.mark.parametrize(
    "row",
    [
        (0, "receipt", "a" * 64, "b" * 64, 0, 1),
        (1, "", "a" * 64, "b" * 64, 0, 1),
        (1, "receipt", "not-a-digest", "b" * 64, 0, 1),
        (1, "receipt", "a" * 64, "b" * 64, -1, 1),
        (1, "receipt", "a" * 64, "b" * 64, 0, 0),
    ],
)
def test_malformed_derivative_index_rows_fail_closed(row):
    with pytest.raises(SegmentedLedgerError, match="invalid row"):
        SegmentedReceiptLedger._entry_from_sql(row)


def test_segment_boundary_concurrency_keeps_unique_identities(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setenv("MAVERICK_EVIDENCE_RECEIPT_SEGMENT_ROWS", "2")
    _policy()

    def deliver(index):
        return _deliver(
            generated_text=f"Concurrent answer {index}.",
            input_text=f"Concurrent question {index}.",
            conversation_id=f"concurrent-{index}",
            idempotency_key=f"concurrent-{index}",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(deliver, range(8)))
    assert len({row["receipt"]["receipt_id"] for row in results}) == 8
    ledger = gateway._receipt_ledger()
    assert ledger.state().total_receipts == 8
    assert ledger.verify_integrity() == (True, "")
    page = gateway.list_interaction_receipts_page(limit=8)
    assert len(page["items"]) == 8
    assert len({row["ledger_ordinal"] for row in page["items"]}) == 8


def test_assurance_retries_valid_delivery_instead_of_false_tamper(monkeypatch):
    _enable(monkeypatch)
    _policy()
    _deliver(conversation_id="before", idempotency_key="before")
    real_count = gateway._governed_receipt_count
    inserted = False

    def append_between_scan_and_count():
        nonlocal inserted
        if not inserted:
            inserted = True
            _deliver(
                generated_text="Concurrent committed answer.",
                input_text="Concurrent committed question.",
                conversation_id="concurrent-commit",
                idempotency_key="concurrent-commit",
            )
        return real_count()

    monkeypatch.setattr(
        gateway,
        "_governed_receipt_count",
        append_between_scan_and_count,
    )
    result = gateway.summary()

    assert result["interaction_receipt_count"] == 2
    assert result["interaction_receipts"]["ledger_total"] == 2
    assert result["interaction_receipts"]["missing_governed"] == 0
    assert result["interaction_receipts"]["extra_governed"] == 0
    assert result["interaction_receipts"]["ledger_chain_valid"] is True
    assert result["readiness"]["ready"] is True


def test_assurance_waits_out_half_commit_and_never_returns_stale_ready(
    monkeypatch,
):
    _enable(monkeypatch)
    _policy()
    _deliver(conversation_id="before", idempotency_key="before")
    real_create = gateway._RECEIPTS.create
    real_count = gateway._governed_receipt_count
    append_reached_governed_store = threading.Event()
    release_append = threading.Event()
    worker_started = False

    def paused_create(record, **kwargs):
        if record.get("receipt_id") != gateway._stable_id(
            "AIR",
            "gateway-test-tenant",
            _sha("half-commit"),
            _sha("half-commit"),
        ):
            return real_create(record, **kwargs)
        append_reached_governed_store.set()
        assert release_append.wait(5)
        return real_create(record, **kwargs)

    monkeypatch.setattr(gateway._RECEIPTS, "create", paused_create)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = None

        def count_during_half_commit():
            nonlocal future, worker_started
            if not worker_started:
                worker_started = True
                future = pool.submit(
                    _deliver,
                    generated_text="Half committed answer.",
                    input_text="Half committed question.",
                    conversation_id="half-commit",
                    idempotency_key="half-commit",
                )
                assert append_reached_governed_store.wait(5)
                # Let the snapshot finish its stale scan/count.  Its end-token
                # acquisition must then wait for this whole delivery commit.
                threading.Timer(0.1, release_append.set).start()
            return real_count()

        monkeypatch.setattr(
            gateway,
            "_governed_receipt_count",
            count_during_half_commit,
        )
        result = gateway.summary()
        assert future is not None
        future.result(timeout=5)

    assert result["interaction_receipt_count"] == 2
    assert result["interaction_receipts"]["ledger_total"] == 2
    assert result["interaction_receipts"]["missing_governed"] == 0
    assert result["interaction_receipts"]["ledger_chain_valid"] is True
    assert result["readiness"]["ready"] is True


def test_assurance_reports_indeterminate_after_bounded_write_churn(monkeypatch):
    _enable(monkeypatch)
    _policy()
    _deliver(conversation_id="before", idempotency_key="before")
    real_count = gateway._governed_receipt_count
    attempt = 0

    def append_on_every_snapshot():
        nonlocal attempt
        attempt += 1
        _deliver(
            generated_text=f"Concurrent answer {attempt}.",
            input_text=f"Concurrent question {attempt}.",
            conversation_id=f"churn-{attempt}",
            idempotency_key=f"churn-{attempt}",
        )
        return real_count()

    monkeypatch.setattr(
        gateway,
        "_governed_receipt_count",
        append_on_every_snapshot,
    )
    with pytest.raises(
        gateway.EvidenceGatewaySnapshotIndeterminate,
        match="changed during every bounded assurance snapshot",
    ):
        gateway.summary()
    assert attempt == gateway._MAX_RECEIPT_SNAPSHOT_ATTEMPTS


def test_entry_stream_releases_append_lock_before_expensive_validation(
    monkeypatch,
):
    _enable(monkeypatch)
    ledger = gateway._receipt_ledger()
    first = {
        "receipt_id": "AIR-" + "1" * 32,
        "receipt_payload_sha256": "2" * 64,
    }
    second = {
        "receipt_id": "AIR-" + "3" * 32,
        "receipt_payload_sha256": "4" * 64,
    }
    ledger.append(first, identity=first["receipt_id"])
    validation_started = threading.Event()
    release_validation = threading.Event()
    real_validate = ledger._validated_entry_rows

    def slow_validation(entries):
        validation_started.set()
        assert release_validation.wait(5)
        return real_validate(entries)

    monkeypatch.setattr(ledger, "_validated_entry_rows", slow_validation)
    stream = ledger.iter_entries(batch_size=1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        reader = pool.submit(next, stream)
        assert validation_started.wait(5)
        writer = pool.submit(
            ledger.append,
            second,
            identity=second["receipt_id"],
        )
        signed, _key = writer.result(timeout=5)
        assert signed["receipt_id"] == second["receipt_id"]
        release_validation.set()
        assert reader.result(timeout=5).identity == first["receipt_id"]


def test_segment_byte_bound_rolls_before_oversized_append(monkeypatch):
    _enable(monkeypatch)
    ledger = SegmentedReceiptLedger(
        gateway._receipt_path(),
        tenant_id="gateway-test-tenant",
        segment_rows=100,
        segment_bytes=1024 * 1024,
        max_receipts=10,
    )
    first = {
        "receipt_id": "AIR-" + "9" * 32,
        "receipt_payload_sha256": "a" * 64,
        "bounded_padding": "x" * 525_000,
    }
    second = {
        "receipt_id": "AIR-" + "b" * 32,
        "receipt_payload_sha256": "c" * 64,
        "bounded_padding": "y" * 525_000,
    }
    ledger.append(first, identity=first["receipt_id"])
    ledger.append(second, identity=second["receipt_id"])
    assert (ledger.segment_dir / "segment-00000001.ndjson").exists()
    assert ledger.verify_integrity() == (True, "")

    monkeypatch.setenv("MAVERICK_EVIDENCE_RECEIPT_SEGMENT_BYTES", "10")
    with pytest.raises(
        gateway.EvidenceGatewayStateError,
        match="receipt_segment_bytes must be an integer",
    ):
        gateway._receipt_ledger()


def test_append_verifies_a_bounded_number_of_rows_regardless_of_segment_size(
    monkeypatch,
):
    # Append() must not re-verify every row in the active segment (via
    # _verify_file -> _iter_verified_rows) on EVERY call, or one delivery's
    # cost would grow with the whole segment instead of staying bounded --
    # roughly 4x across a 4,096-row segment, under a lock that serializes
    # ALL governed-output delivery. A call-count assertion is used instead of
    # wall-clock timing: it directly proves the fixed shape (append() checks
    # only the row(s) IT wrote) without being sensitive to machine speed.
    _enable(monkeypatch)
    ledger = SegmentedReceiptLedger(
        gateway._receipt_path(),
        tenant_id="gateway-test-tenant",
        segment_rows=10_000,
        max_receipts=10_000,
    )
    import maverick.ai_evidence_ledger as ledger_mod

    calls = {"n": 0}
    real_verify = ledger_mod._verify_chained_row

    def counting_verify(*args, **kwargs):
        calls["n"] += 1
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(ledger_mod, "_verify_chained_row", counting_verify)

    n = 300
    for i in range(n):
        event = {
            "receipt_id": f"AIR-{i:032x}",
            "receipt_payload_sha256": "ab" * 32,
        }
        ledger.append(event, identity=event["receipt_id"])

    # One row verified per append (all land in the same never-rolled
    # segment, so no header row is involved). A reintroduced full-segment
    # re-verify would instead check 1+2+...+300 = 45,150 rows.
    assert calls["n"] == n
    assert ledger.verify_integrity() == (True, "")


def test_verify_appended_row_rejects_a_tip_mismatch(monkeypatch):
    # Direct unit test of the new append-time check's actual safety
    # property: a row whose prev_hash does not match the tip append()
    # believes it extended must be refused, not silently accepted.
    _enable(monkeypatch)
    ledger = SegmentedReceiptLedger(
        gateway._receipt_path(),
        tenant_id="gateway-test-tenant",
        segment_rows=10_000,
        max_receipts=10_000,
    )
    first = {"receipt_id": "AIR-" + "1" * 32, "receipt_payload_sha256": "2" * 64}
    ledger.append(first, identity=first["receipt_id"])
    segment_path = ledger._segment_path(0)
    with pytest.raises(SegmentedLedgerError, match="failed verification"):
        ledger._verify_appended_row(
            segment_path,
            offset_before=0,
            expected_previous="f" * 64,
        )
