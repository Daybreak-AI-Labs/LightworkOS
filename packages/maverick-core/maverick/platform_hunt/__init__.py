"""Defensive threat hunting inside the Lightwork platform.

This package deliberately coexists with the legacy :mod:`maverick.threat_hunt`
module. New integrations should import this package by its unambiguous name.
"""
from .engine import build_baseline, enabled, scan
from .integrity import verify_audit_chain
from .models import (
    BaselineProfile,
    ChainIntegrityStatus,
    ContainmentProposal,
    EvidenceRef,
    Finding,
    HuntEvent,
    HuntReport,
    Investigation,
    canonical_digest,
    deterministic_id,
)
from .sources import collect_lightwork_events
from .store import HuntStore, RecordNotFound, RevisionConflict

__all__ = [
    "BaselineProfile",
    "ChainIntegrityStatus",
    "ContainmentProposal",
    "EvidenceRef",
    "Finding",
    "HuntEvent",
    "HuntReport",
    "HuntStore",
    "Investigation",
    "RecordNotFound",
    "RevisionConflict",
    "build_baseline",
    "canonical_digest",
    "collect_lightwork_events",
    "deterministic_id",
    "enabled",
    "scan",
    "verify_audit_chain",
]
