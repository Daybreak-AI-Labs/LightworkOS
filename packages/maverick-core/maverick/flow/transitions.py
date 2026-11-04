"""Admission decisions for durable workflow deliveries and resumes.

These functions only classify an observed checkpoint. The caller owns the
run lock and persists claims before invoking an executor; a classification
alone never grants authority or proves that an external effect did not happen.
"""
from __future__ import annotations

from enum import Enum, auto

from .run_state import (
    PAUSED_STATUSES,
    STATUS_BUDGET_LIMITED,
    STATUS_CLAIMED,
    STATUS_FAILED,
    STATUS_PAUSED_APPROVAL,
    STATUS_QUEUED,
    STATUS_RUNNING,
)


class DeliveryDecision(Enum):
    START = auto()
    RETURN_CHECKPOINT = auto()
    QUARANTINE = auto()


class ResumeDecision(Enum):
    PAUSED = auto()
    APPROVAL = auto()
    RETRY_FAILURE = auto()
    REFUSE = auto()


def decide_delivery(status: str | None) -> DeliveryDecision:
    """Classify a fresh queue delivery while its durable run lock is held."""
    if status in {STATUS_QUEUED, STATUS_CLAIMED}:
        return DeliveryDecision.START
    if status == STATUS_RUNNING:
        # The abandoned worker may already have crossed an external boundary.
        return DeliveryDecision.QUARANTINE
    return DeliveryDecision.RETURN_CHECKPOINT


def decide_resume(status: str, cursor: str | None, *, from_failure: bool) -> ResumeDecision:
    """Classify a saved run without mutating the checkpoint or approval data."""
    if from_failure and status in {STATUS_FAILED, STATUS_BUDGET_LIMITED} and cursor:
        return ResumeDecision.RETRY_FAILURE
    if status == STATUS_PAUSED_APPROVAL:
        return ResumeDecision.APPROVAL
    if status in PAUSED_STATUSES:
        return ResumeDecision.PAUSED
    return ResumeDecision.REFUSE
