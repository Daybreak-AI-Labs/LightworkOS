"""Environment-hunt derived-state store.

The implementation intentionally reuses the platform hunter's CAS and durable
audit-outbox store. It exposes no telemetry-write method, so raw customer events
remain ephemeral in :class:`~maverick.env_hunt.models.IngestionBatch`.
"""
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from ..platform_hunt.store import (
    AuditRecorder,
    RecordNotFound,
    RevisionConflict,
)
from ..platform_hunt.store import (
    HuntStore as _PlatformHuntStore,
)
from .models import credential_text_detected


def _reject_credential_values(value: object) -> None:
    """Fail closed if derived state still contains credential-like text.

    Normalized telemetry is scrubbed before findings and timelines are built.
    This store check is deliberately independent defense in depth for callers
    that submit mappings directly, custom Sigma metadata, enrichment results,
    and response receipts.
    """
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    stack = [value]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > 100_000:
            raise ValueError("environment hunter record is too structurally complex")
        if isinstance(current, dict):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, (list, tuple, set, frozenset)):
            stack.extend(current)
        elif isinstance(current, str) and credential_text_detected(current):
            raise ValueError(
                "credential-like values cannot be persisted in environment hunter records"
            )


class HuntStore(_PlatformHuntStore):
    """Environment-derived records with their own signed audit event kind."""

    def __init__(
        self, path: str | Path, audit_recorder: AuditRecorder | None = None,
    ) -> None:
        super().__init__(
            path,
            audit_recorder=audit_recorder,
            record_change_event_kind="env_hunt_record_changed",
        )

    def _create(self, record_type: str, record: object, *, actor: str) -> dict[str, Any]:
        _reject_credential_values(record)
        return super()._create(record_type, record, actor=actor)

    def _update(
        self,
        record_type: str,
        record_id: str,
        changes: dict[str, Any],
        *,
        expected_revision: int,
        actor: str,
        action: str = "update",
    ) -> dict[str, Any]:
        _reject_credential_values(changes)
        return super()._update(
            record_type,
            record_id,
            changes,
            expected_revision=expected_revision,
            actor=actor,
            action=action,
        )

    def claim_response_execution(self, **kwargs) -> dict[str, Any]:
        _reject_credential_values(kwargs)
        return super().claim_response_execution(**kwargs)

    def complete_response_execution(self, **kwargs) -> dict[str, Any]:
        _reject_credential_values(kwargs)
        return super().complete_response_execution(**kwargs)

    def mark_response_execution_ambiguous(self, **kwargs) -> None:
        _reject_credential_values(kwargs)
        super().mark_response_execution_ambiguous(**kwargs)

__all__ = ["HuntStore", "RecordNotFound", "RevisionConflict"]
