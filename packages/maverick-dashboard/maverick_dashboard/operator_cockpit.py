"""Presentation-only state for the AI assurance operator cockpit.

The gateway module owns evidence authority.  This module never reads or writes
records; it converts its already-projected summary into an operator-friendly
status, prioritized next action, and first-evidence checklist.  Keeping this
logic out of the template makes empty/error states deterministic and testable.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_CRITICAL_GAPS = frozenset(
    {
        "invalid_conversation_receipt_chains",
        "invalid_receipt_ledger_chain",
        "unverified_interaction_receipts",
    }
)
_POLICY_BINDING_GAPS = frozenset(
    {
        "unbound_policy_models",
        "unbound_policy_contexts",
    }
)
_POLICY_TRANSPARENCY_GAPS = frozenset(
    {
        "interaction_disclosure_disabled",
        "machine_readable_marking_disabled",
    }
)
_POLICY_READINESS_GAPS = (
    _POLICY_BINDING_GAPS | _POLICY_TRANSPARENCY_GAPS
)

_GAP_LABELS = {
    "no_current_policy": "No current gateway policy is configured.",
    "interaction_disclosure_disabled": (
        "A policy does not require interaction disclosure."
    ),
    "machine_readable_marking_disabled": (
        "A policy does not require machine-readable marking."
    ),
    "unbound_policy_models": "A current policy is not bound to a model digest.",
    "unbound_policy_contexts": (
        "A current policy is not bound to a context digest."
    ),
    "synthetic_demo_data_present": (
        "Synthetic demo data is present; it is not production evidence."
    ),
    "no_interaction_receipts": "No governed delivery receipt has been recorded.",
    "stale_interaction_receipts": (
        "One or more receipts no longer match current policy authority."
    ),
    "unverified_interaction_receipts": (
        "One or more receipt signatures could not be verified."
    ),
    "invalid_conversation_receipt_chains": (
        "A conversation receipt chain failed integrity verification."
    ),
    "invalid_receipt_ledger_chain": (
        "The governed receipt ledger failed integrity verification."
    ),
    "pending_regulatory_impacts": (
        "One or more regulatory impacts await human review."
    ),
    "regulatory_impacts_refreshing": (
        "An accepted regulatory impact is still refreshing dependent evidence."
    ),
}


def _integer(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def display_timestamp(value: object) -> str:
    """Return a human-readable UTC timestamp without locale ambiguity."""

    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        from .plain_labels import datetime_text

        return datetime_text(value)
    text = str(value or "").strip()
    return text


def _gaps(summary: Mapping[str, Any]) -> list[str]:
    readiness = _mapping(summary.get("readiness"))
    raw = readiness.get("gaps", summary.get("gaps", []))
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return []
    return [str(item) for item in raw if str(item).strip()]


def _synthetic_present(
    gaps: Sequence[str],
    policies: Sequence[Mapping[str, Any]],
) -> bool:
    if "synthetic_demo_data_present" in gaps:
        return True
    return any(
        _mapping(policy.get("metadata")).get("demo") is True
        or _mapping(policy.get("metadata")).get("synthetic") is True
        for policy in policies
    )


def _next_action(
    *,
    gaps: Sequence[str],
    synthetic: bool,
    policy_count: int,
    receipt_count: int,
    pending_impacts: int,
    refreshing_impacts: int,
) -> dict[str, str]:
    gap_set = set(gaps)
    if gap_set & _CRITICAL_GAPS:
        return {
            "title": "Investigate receipt integrity before relying on packets",
            "detail": (
                "Do not treat an exported packet as assurance evidence until "
                "the signature and ledger-chain failures are resolved."
            ),
            "code": "GET /api/v1/security/assurance/gateway/summary",
            "href": "/docs",
            "label": "Open API reference",
        }
    if synthetic:
        return {
            "title": "Create production evidence in a dedicated tenant",
            "detail": (
                "This tenant contains a labeled synthetic scenario. Keep it "
                "for demos and use a separate production tenant for customer evidence."
            ),
            "code": "MAVERICK_TENANT=<production-tenant> maverick dashboard",
            "href": "/start",
            "label": "Review setup",
        }
    if not policy_count:
        return {
            "title": "Create and bind the first production policy",
            "detail": (
                "Require disclosure and machine-readable marking, then bind "
                "the policy to exact model and context digests."
            ),
            "code": (
                "PUT /api/v1/security/assurance/gateway/policies/{policy_id}"
            ),
            "href": "/docs",
            "label": "Open API reference",
        }
    policy_gaps = gap_set & _POLICY_READINESS_GAPS
    if policy_gaps:
        has_binding_gaps = bool(policy_gaps & _POLICY_BINDING_GAPS)
        has_transparency_gaps = bool(
            policy_gaps & _POLICY_TRANSPARENCY_GAPS
        )
        if has_binding_gaps and has_transparency_gaps:
            title = "Complete policy binding and transparency controls"
            detail = (
                "Update every current policy: bind exact model and context "
                "digests, and require interaction disclosure plus "
                "machine-readable marking."
            )
        elif has_binding_gaps:
            title = "Bind production policies to exact evidence digests"
            detail = (
                "Set model_sha256 and context_sha256 on every current policy "
                "to the exact digests used for governed delivery."
            )
        else:
            title = "Enable required policy transparency controls"
            detail = (
                "Require interaction disclosure plus machine-readable "
                "marking on every current production policy."
            )
        return {
            "title": title,
            "detail": detail,
            "code": (
                "PUT /api/v1/security/assurance/gateway/policies/{policy_id}"
            ),
            "href": "/docs",
            "label": "Open API reference",
        }
    if not receipt_count:
        return {
            "title": "Send one governed delivery through the gateway",
            "detail": (
                "The first delivery creates the hash-only receipt that proves "
                "policy, model, context, and disclosure state."
            ),
            "code": "POST /api/v1/security/assurance/gateway/deliver",
            "href": "/docs",
            "label": "Open API reference",
        }
    if "stale_interaction_receipts" in gap_set:
        return {
            "title": "Refresh stale model and policy bindings",
            "detail": (
                "Issue a new governed delivery after the current policy, model, "
                "and context digests are bound."
            ),
            "code": "GET /api/v1/security/assurance/gateway/receipts",
            "href": "/docs",
            "label": "Inspect receipt API",
        }
    if pending_impacts:
        return {
            "title": f"Review {pending_impacts} pending regulatory impact(s)",
            "detail": (
                "Accept or dismiss each cited impact with a human disposition "
                "before calling the evidence set current."
            ),
            "code": (
                "GET /api/v1/security/assurance/gateway/regulatory-impacts"
            ),
            "href": "/docs",
            "label": "Open API reference",
        }
    if refreshing_impacts:
        return {
            "title": "Wait for accepted-impact evidence refresh",
            "detail": (
                "The authority change is accepted, but dependent policies or "
                "assets have not all reached the refreshed state."
            ),
            "code": (
                "GET /api/v1/security/assurance/gateway/regulatory-impacts"
            ),
            "href": "/docs",
            "label": "Inspect impact status",
        }
    return {
        "title": "Export the exact signed assurance packet",
        "detail": (
            "The deterministic checks are current. Export a packet for the "
            "reviewer; it is evidence, not a legal certification."
        ),
        "code": (
            "POST /api/v1/security/assurance/gateway/assurance-packet"
        ),
        "href": "",
        "label": "",
    }


def gateway_view(
    summary: Mapping[str, Any] | None,
    policies: Sequence[Mapping[str, Any]] | None,
    receipts: Sequence[Mapping[str, Any]] | None,
    regulatory_impacts: Sequence[Mapping[str, Any]] | None,
) -> dict[str, Any]:
    """Return a bounded, template-ready cockpit view."""

    summary = _mapping(summary)
    policies = list(policies or ())
    receipts = list(receipts or ())
    regulatory_impacts = list(regulatory_impacts or ())
    receipt_summary = _mapping(summary.get("interaction_receipts"))
    impact_summary = _mapping(summary.get("regulatory_impacts"))
    policy_count = _integer(
        summary.get("current_policy_count", len(policies))
    )
    receipt_count = _integer(
        summary.get(
            "interaction_receipt_count",
            receipt_summary.get("total", len(receipts)),
        )
    )
    current_receipts = _integer(
        summary.get(
            "current_interaction_receipt_count",
            receipt_summary.get("current"),
        )
    )
    stale_receipts = _integer(
        summary.get(
            "stale_interaction_receipt_count",
            receipt_summary.get("stale"),
        )
    )
    unverified_receipts = _integer(
        summary.get(
            "unverified_interaction_receipt_count",
            receipt_summary.get("unverified"),
        )
    )
    pending_impacts = _integer(
        summary.get("pending_regulatory_impact_count")
    )
    refreshing_impacts = _integer(
        summary.get("refreshing_regulatory_impact_count")
    )
    impact_count = _integer(
        impact_summary.get("total", len(regulatory_impacts))
    )
    gaps = _gaps(summary)
    gap_set = set(gaps)
    synthetic = _synthetic_present(gaps, policies)
    chains_valid = (
        receipt_summary.get("conversation_chains_valid", True) is True
        and receipt_summary.get("ledger_chain_valid", True) is True
    )
    integrity_ok = (
        receipt_count > 0
        and unverified_receipts == 0
        and chains_valid
        and not (gap_set & _CRITICAL_GAPS)
    )
    regulatory_current = (
        receipt_count > 0
        and pending_impacts == 0
        and refreshing_impacts == 0
    )
    policy_ready = (
        policy_count > 0
        and not synthetic
        and not (gap_set & _POLICY_READINESS_GAPS)
    )
    progress = [
        {
            "label": "Production policy controls complete",
            "done": policy_ready,
        },
        {
            "label": "First governed delivery recorded",
            "done": receipt_count > 0 and not synthetic,
        },
        {
            "label": "Receipt signatures and chains verified",
            "done": integrity_ok and not synthetic,
        },
        {
            "label": "Regulatory impact queue current",
            "done": regulatory_current and not synthetic,
        },
    ]
    done_count = sum(item["done"] for item in progress)

    if gap_set & _CRITICAL_GAPS:
        status = {
            "key": "blocked",
            "label": "Integrity review required",
            "detail": "Receipt evidence has a verification blocker.",
        }
        ingestion = "blocked"
    elif synthetic:
        status = {
            "key": "demo",
            "label": "Synthetic demo only",
            "detail": "No production assurance conclusion is available.",
        }
        ingestion = "synthetic"
    elif not policy_count:
        status = {
            "key": "empty",
            "label": "Not started",
            "detail": "Create a production policy to begin evidence capture.",
        }
        ingestion = "not configured"
    elif not receipt_count:
        status = {
            "key": "waiting",
            "label": "Awaiting first delivery",
            "detail": "Policy authority exists; no interaction receipt exists yet.",
        }
        ingestion = "awaiting first receipt"
    elif gaps:
        status = {
            "key": "review",
            "label": "Review required",
            "detail": "Evidence is recording, with deterministic gaps to resolve.",
        }
        ingestion = "recording with gaps"
    else:
        status = {
            "key": "ready",
            "label": "Evidence ready",
            "detail": "All deterministic gateway readiness checks are current.",
        }
        ingestion = "recording"

    last_receipt = receipts[0] if receipts else {}
    last_issued = (
        last_receipt.get("issued_at")
        or last_receipt.get("created_at")
        or ""
    )
    return {
        "status": status,
        "ingestion": ingestion,
        "synthetic": synthetic,
        "demo_seed_allowed": synthetic or (
            policy_count == 0
            and receipt_count == 0
            and impact_count == 0
        ),
        "production_ready": status["key"] == "ready",
        "progress": progress,
        "done_count": done_count,
        "total_steps": len(progress),
        "progress_percent": done_count * 25,
        "next_action": _next_action(
            gaps=gaps,
            synthetic=synthetic,
            policy_count=policy_count,
            receipt_count=receipt_count,
            pending_impacts=pending_impacts,
            refreshing_impacts=refreshing_impacts,
        ),
        "gaps": [
            {
                "code": gap,
                "label": _GAP_LABELS.get(
                    gap,
                    gap.replace("_", " ").strip().capitalize() + ".",
                ),
                "critical": gap in _CRITICAL_GAPS,
            }
            for gap in gaps
        ],
        "counts": {
            "policies": policy_count,
            "receipts": receipt_count,
            "current_receipts": current_receipts,
            "stale_receipts": stale_receipts,
            "unverified_receipts": unverified_receipts,
            "pending_impacts": pending_impacts,
            "refreshing_impacts": refreshing_impacts,
        },
        "last_receipt_issued_at": display_timestamp(last_issued),
        "impact_rows_loaded": len(regulatory_impacts),
    }


__all__ = ["display_timestamp", "gateway_view"]
