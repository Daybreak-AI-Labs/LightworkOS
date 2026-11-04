"""Public evidence-domain boundaries preserve established gateway behavior."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from maverick import ai_evidence_gateway as legacy
from maverick.ai_evidence import definitions, delivery


def test_delivery_facade_resolves_legacy_gateway_at_call_time(monkeypatch):
    calls = []
    monkeypatch.setattr(legacy, "enabled", lambda: True)
    monkeypatch.setattr(legacy, "deliver_text", lambda text, **kw: calls.append((text, kw)) or {"delivered_text": text})

    assert delivery.enabled()
    assert delivery.deliver_text("answer", input_text="question", conversation_id="c", idempotency_key="i") == {
        "delivered_text": "answer",
    }
    assert calls[0][0] == "answer"
    assert calls[0][1]["idempotency_key"] == "i"


def test_governance_definitions_and_errors_remain_compatible():
    assert legacy.FRAMEWORK_SOURCES is definitions.FRAMEWORK_SOURCES
    assert legacy.POLICY_SCHEMA == definitions.POLICY_SCHEMA
    assert delivery.EvidenceGatewayError is legacy.EvidenceGatewayError


def test_rendering_rejects_inconsistent_disclosure_before_delivery():
    settings = {
        "require_interaction_disclosure": False,
        "require_machine_readable_marking": True,
        "require_visible_marking": True,
        "disclosure_text": "disclosure",
        "machine_marker": "machine {receipt_id}",
        "visible_marker": "visible",
    }
    with pytest.raises(legacy.EvidenceGatewayStateError):
        legacy._render_text(
            "answer", receipt_id="r", settings=settings, human_interaction=True,
            apply_interaction_disclosure=True, synthetic_content=True, deepfake=False,
            public_interest_text=False, editorial_exception=None,
        )


def test_namespace_does_not_depend_on_gateway_private_functions():
    root = Path(__file__).parents[1] / "maverick" / "ai_evidence"
    for source in root.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "ai_evidence_gateway":
                assert all(not alias.name.startswith("_") for alias in node.names)
