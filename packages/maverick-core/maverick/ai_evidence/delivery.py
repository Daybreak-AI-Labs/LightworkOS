"""Public runtime boundary for governed human-facing evidence delivery.

The gateway remains the authority for tenant identity, signed receipts,
policy decisions and storage. Resolve its methods at call time so legacy
imports and existing gateway integration overrides retain their behavior.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .. import ai_evidence_gateway as _gateway
from ..ai_evidence_gateway import EvidenceGatewayError


def enabled() -> bool:
    """Whether the evidence gateway is enabled for this execution."""
    return _gateway.enabled()


def deliver_text(
    generated_text: str,
    *,
    input_text: str,
    conversation_id: str,
    idempotency_key: str,
    actor: str = "gateway",
    policy_id: str = "default",
    model_sha256: str = "",
    context_sha256: str = "",
    modality: str = "text",
    human_interaction: bool = True,
    synthetic_content: bool = True,
    deepfake: bool = False,
    public_interest_text: bool = False,
    editorial_exception: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply gateway policy and produce its signed delivery receipt."""
    return _gateway.deliver_text(
        generated_text, input_text=input_text, conversation_id=conversation_id,
        idempotency_key=idempotency_key, actor=actor, policy_id=policy_id,
        model_sha256=model_sha256, context_sha256=context_sha256, modality=modality,
        human_interaction=human_interaction, synthetic_content=synthetic_content,
        deepfake=deepfake, public_interest_text=public_interest_text,
        editorial_exception=editorial_exception,
    )


def record_regulatory_impact(
    alert_id: str,
    *,
    alert_revision: int,
    content_sha256: str,
    citations: Sequence[Mapping[str, Any]],
    affected_policy_ids: Sequence[str] = ("default",),
    affected_asset_ids: Sequence[str] = (),
    control_ids: Sequence[str] = (),
    match_reasons: Sequence[str] = (),
    actor: str,
    impact_id: str | None = None,
) -> dict[str, Any]:
    """Record a citation-backed regulatory impact through the gateway."""
    return _gateway.record_regulatory_impact(
        alert_id, alert_revision=alert_revision, content_sha256=content_sha256,
        citations=citations, affected_policy_ids=affected_policy_ids,
        affected_asset_ids=affected_asset_ids, control_ids=control_ids,
        match_reasons=match_reasons, actor=actor, impact_id=impact_id,
    )


__all__ = ["EvidenceGatewayError", "deliver_text", "enabled", "record_regulatory_impact"]
