"""Exact approval-card integrity, privacy, and expiry boundaries."""
from __future__ import annotations

import json

import pytest
from maverick.approval_cards import (
    ApprovalCardError,
    build_approval_card,
    decode_approval_detail,
    encode_approval_detail,
    require_current_approval_card,
)


def _card(*, expires_at: float = 200.0, **changes) -> dict:
    values = {
        "action": "browser.type",
        "summary": "Type into the reviewed password field",
        "target_label": "#password on the reviewed sign-in page",
        "target": {"page": "https://example.test/sign-in", "selector": "#password"},
        "parameters": {"selector": "#password", "text": "private-value"},
        "parameter_summary": ["Type 13 characters into #password"],
        "actor": "user:alice",
        "workspace": "tenant-a",
        "role": "operator",
        "authority_versions": {"role_revision": "role-v1"},
        "input_versions": {"request_revision": "input-v1"},
        "credential_versions": {"browser_session_sha256": "a" * 64},
        "budget": {"currency": "USD", "maximum": 1.0},
        "expires_at": expires_at,
        "known_effects": ["Changes the reviewed field once."],
        "unresolved_assumptions": ["The page script may react to the input."],
        "before": "The reviewed field is unchanged.",
        "after": "The reviewed field contains the supplied value.",
        "irreversible": False,
    }
    values.update(changes)
    return build_approval_card(**values)


def test_card_commits_sensitive_values_without_persisting_them():
    card = _card()
    encoded = encode_approval_detail(card)

    assert "private-value" not in encoded
    assert decode_approval_detail(encoded) == card
    assert card["authorization"] == {
        "state": "recommendation_only",
        "authority_required": True,
        "prediction_grants_authority": False,
    }
    assert card["consequences"]["known_effects"]
    assert card["consequences"]["unresolved_assumptions"]


def test_labels_drop_bidirectional_and_zero_width_characters():
    card = _card(summary="Delete \u202etxt.exe", target_label="report\u200b.pdf")
    assert "\u202e" not in json.dumps(card, ensure_ascii=False)
    assert "\u200b" not in json.dumps(card, ensure_ascii=False)


def test_tamper_and_authoritative_expiry_fail_closed():
    card = _card(expires_at=200.0)
    tampered = json.loads(json.dumps(card))
    tampered["target"]["label"] = "a different target"

    with pytest.raises(ApprovalCardError, match="integrity"):
        require_current_approval_card(tampered, now=100.0)
    with pytest.raises(ApprovalCardError, match="expired"):
        require_current_approval_card(card, now=200.0)
    with pytest.raises(ApprovalCardError, match="changed"):
        require_current_approval_card(
            card, expected_binding="b" * 64, now=100.0,
        )
    with pytest.raises(ApprovalCardError, match="SHA-256"):
        require_current_approval_card(
            card, expected_binding="é" * 64, now=100.0,
        )


def test_card_redacts_lightwork_tokens_and_rejects_them_in_version_maps():
    token = "lw-rest-" + "A" * 43
    card = _card(
        target_label=f'input[value="{token}"]',
        parameter_summary=[f"Click selector carrying {token}"],
    )
    encoded = encode_approval_detail(card)
    assert token not in encoded
    assert "REDACTED:lightwork_agent_token" in encoded

    with pytest.raises(ApprovalCardError, match="secret-bearing"):
        _card(credential_versions={"session": token})
