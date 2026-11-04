"""Operator-facing assurance status and next-action derivation."""
from __future__ import annotations

import pytest
from maverick_dashboard.operator_cockpit import gateway_view


def test_empty_gateway_routes_operator_to_first_policy():
    view = gateway_view(
        {
            "current_policy_count": 0,
            "interaction_receipt_count": 0,
            "readiness": {
                "ready": False,
                "gaps": ["no_current_policy", "no_interaction_receipts"],
            },
        },
        [],
        [],
        [],
    )

    assert view["status"]["key"] == "empty"
    assert view["done_count"] == 0
    assert view["demo_seed_allowed"] is True
    assert "first production policy" in view["next_action"]["title"]
    assert view["next_action"]["code"].startswith("PUT /api/")
    assert view["gaps"][0]["label"] == (
        "No current gateway policy is configured."
    )


def test_production_impact_hides_demo_loader_before_first_policy():
    view = gateway_view(
        {
            "current_policy_count": 0,
            "interaction_receipt_count": 0,
            "readiness": {
                "ready": False,
                "gaps": ["no_current_policy", "no_interaction_receipts"],
            },
        },
        [],
        [],
        [{"impact_id": "ARI-production"}],
    )

    assert view["demo_seed_allowed"] is False


def test_synthetic_demo_never_counts_as_production_readiness():
    digest = "a" * 64
    view = gateway_view(
        {
            "current_policy_count": 1,
            "interaction_receipt_count": 1,
            "current_interaction_receipt_count": 1,
            "readiness": {
                "ready": False,
                "gaps": ["synthetic_demo_data_present"],
            },
            "interaction_receipts": {
                "total": 1,
                "current": 1,
                "unverified": 0,
                "conversation_chains_valid": True,
                "ledger_chain_valid": True,
            },
        },
        [{"metadata": {"demo": True}, "model_sha256": digest}],
        [{"receipt_id": "demo", "issued_at": "2026-07-29T10:00:00Z"}],
        [],
    )

    assert view["status"]["key"] == "demo"
    assert view["synthetic"] is True
    assert view["production_ready"] is False
    assert view["done_count"] == 0
    assert view["demo_seed_allowed"] is True
    assert "dedicated tenant" in view["next_action"]["title"]


def test_integrity_failure_outranks_other_queue_work():
    view = gateway_view(
        {
            "current_policy_count": 1,
            "interaction_receipt_count": 3,
            "pending_regulatory_impact_count": 2,
            "readiness": {
                "ready": False,
                "gaps": [
                    "pending_regulatory_impacts",
                    "invalid_receipt_ledger_chain",
                ],
            },
            "interaction_receipts": {
                "total": 3,
                "current": 3,
                "unverified": 0,
                "conversation_chains_valid": True,
                "ledger_chain_valid": False,
            },
        },
        [{}],
        [{}],
        [{}, {}],
    )

    assert view["status"]["key"] == "blocked"
    assert view["ingestion"] == "blocked"
    assert "integrity" in view["next_action"]["title"].lower()
    assert view["gaps"][1]["critical"] is True


def test_current_production_evidence_routes_to_packet_export():
    view = gateway_view(
        {
            "current_policy_count": 1,
            "interaction_receipt_count": 2,
            "current_interaction_receipt_count": 2,
            "stale_interaction_receipt_count": 0,
            "unverified_interaction_receipt_count": 0,
            "pending_regulatory_impact_count": 0,
            "refreshing_regulatory_impact_count": 0,
            "readiness": {"ready": True, "gaps": []},
            "interaction_receipts": {
                "total": 2,
                "current": 2,
                "unverified": 0,
                "conversation_chains_valid": True,
                "ledger_chain_valid": True,
            },
        },
        [{"metadata": {}}],
        [{"issued_at": "2026-07-29T11:00:00Z"}],
        [],
    )

    assert view["status"]["key"] == "ready"
    assert view["production_ready"] is True
    assert view["done_count"] == 4
    assert view["demo_seed_allowed"] is False
    assert "assurance-packet" in view["next_action"]["code"]


@pytest.mark.parametrize(
    ("gap", "expected_detail"),
    [
        ("unbound_policy_models", "model_sha256"),
        ("unbound_policy_contexts", "context_sha256"),
        ("interaction_disclosure_disabled", "interaction disclosure"),
        (
            "machine_readable_marking_disabled",
            "machine-readable",
        ),
    ],
)
def test_policy_readiness_gap_keeps_policy_step_incomplete(
    gap,
    expected_detail,
):
    view = gateway_view(
        {
            "current_policy_count": 1,
            "interaction_receipt_count": 1,
            "current_interaction_receipt_count": 1,
            "stale_interaction_receipt_count": 0,
            "unverified_interaction_receipt_count": 0,
            "pending_regulatory_impact_count": 0,
            "refreshing_regulatory_impact_count": 0,
            "readiness": {"ready": False, "gaps": [gap]},
            "interaction_receipts": {
                "total": 1,
                "current": 1,
                "unverified": 0,
                "conversation_chains_valid": True,
                "ledger_chain_valid": True,
            },
        },
        [{"metadata": {}}],
        [{"issued_at": "2026-07-29T11:00:00Z"}],
        [],
    )

    assert view["status"]["key"] == "review"
    assert view["production_ready"] is False
    assert view["progress"][0] == {
        "label": "Production policy controls complete",
        "done": False,
    }
    assert view["done_count"] == 3
    assert view["progress_percent"] == 75
    assert expected_detail in view["next_action"]["detail"]
    assert view["next_action"]["code"].startswith("PUT /api/")
    assert "assurance-packet" not in view["next_action"]["code"]


@pytest.mark.parametrize(
    ("gap", "count_overrides", "expected_title"),
    [
        (
            "stale_interaction_receipts",
            {"stale_interaction_receipt_count": 1},
            "Refresh stale",
        ),
        (
            "pending_regulatory_impacts",
            {"pending_regulatory_impact_count": 1},
            "Review 1 pending",
        ),
        (
            "regulatory_impacts_refreshing",
            {"refreshing_regulatory_impact_count": 1},
            "Wait for accepted-impact",
        ),
    ],
)
def test_non_policy_review_flow_keeps_its_next_action(
    gap,
    count_overrides,
    expected_title,
):
    summary = {
        "current_policy_count": 1,
        "interaction_receipt_count": 1,
        "current_interaction_receipt_count": 1,
        "stale_interaction_receipt_count": 0,
        "unverified_interaction_receipt_count": 0,
        "pending_regulatory_impact_count": 0,
        "refreshing_regulatory_impact_count": 0,
        "readiness": {"ready": False, "gaps": [gap]},
        "interaction_receipts": {
            "total": 1,
            "current": 1,
            "unverified": 0,
            "conversation_chains_valid": True,
            "ledger_chain_valid": True,
        },
    }
    summary.update(count_overrides)

    view = gateway_view(
        summary,
        [{"metadata": {}}],
        [{"issued_at": "2026-07-29T11:00:00Z"}],
        [{}],
    )

    assert view["progress"][0]["done"] is True
    assert view["next_action"]["title"].startswith(expected_title)
