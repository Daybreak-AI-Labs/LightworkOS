"""Audit log for Lightwork.

Append-only NDJSON sink at ``~/.maverick/audit/YYYY-MM-DD.ndjson``.
Daily rotation. Each line is a versioned JSON event.

Event types (see ``events.py``):
  - goal_start / goal_end       — goal lifecycle
  - episode_start / episode_end — best-of-N attempt lifecycle
  - tool_call / tool_result     — every tool invocation
  - shield_block                — Shield denied an input/output/tool call
  - consent_prompt / consent_result — destructive-action gates
  - secret_redacted             — secret detector hit
  - erase                       — GDPR Art.17 erasure
  - halt                        — killswitch fired

This module is intentionally minimal. Ordinary audit failures are logged and
remain best-effort. An explicit AuditRefused is different: when a deployment's
required signing or custody policy cannot be satisfied, callers must propagate
the refusal rather than continue an action with weaker evidence than promised.
"""
from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Runtime exports are lazy below. Keep their module edge explicit for
    # static reachability tools without reintroducing package-import effects.
    from . import erase  # noqa: F401

# Keep package import side-effect free. In particular, offline signature and
# checkpoint verification must not import writer.py, whose live sink resolves
# deployment config and tenant storage. Public names retain their historical
# ``maverick.audit`` locations and are cached after first use.
_EXPORT_MODULE = {
    "AuditCheckpointError": ".checkpoints",
    "CheckpointBreak": ".checkpoints",
    "latest_checkpoint_sequence": ".checkpoints",
    "publish_checkpoint": ".checkpoints",
    "verify_checkpoints": ".checkpoints",
    "delete_user": ".erase",
    "scrub_user": ".erase",
    "AuditRefused": ".errors",
    "AuditEvent": ".events",
    "EventKind": ".events",
    "TOOL_CALL_COMMITMENT_ALGORITHM": ".events",
    "tool_call_commitment": ".events",
    "day_files": ".reader",
    "event_paths": ".reader",
    "iter_events": ".reader",
    "AuditSigner": ".signing",
    "ChainBreak": ".signing",
    "ensure_anchors": ".signing",
    "reanchor_file": ".signing",
    "sign_detached_digest": ".signing",
    "verify_detached_digest": ".signing",
    "verify_anchors": ".signing",
    "verify_chain": ".signing",
    "AuditLog": ".writer",
    "AuditWriteRefused": ".writer",
    "audit_event": ".writer",
    "default_audit_log": ".writer",
    "global_audit_log": ".writer",
    "goal_context": ".writer",
    "reanchor_after_erase": ".writer",
    "record": ".writer",
    "record_global": ".writer",
    "reset_goal_context": ".writer",
    "set_goal_context": ".writer",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULE.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORT_MODULE))

__all__ = [
    "AuditEvent",
    "EventKind",
    "TOOL_CALL_COMMITMENT_ALGORITHM",
    "tool_call_commitment",
    "AuditLog",
    "AuditRefused",
    "AuditWriteRefused",
    "AuditCheckpointError",
    "CheckpointBreak",
    "audit_event",
    "default_audit_log",
    "global_audit_log",
    "record",
    "record_global",
    "reanchor_after_erase",
    "scrub_user",
    "delete_user",
    "AuditSigner",
    "ChainBreak",
    "verify_chain",
    "sign_detached_digest",
    "verify_detached_digest",
    "reanchor_file",
    "ensure_anchors",
    "verify_anchors",
    "publish_checkpoint",
    "verify_checkpoints",
    "latest_checkpoint_sequence",
    "day_files",
    "event_paths",
    "iter_events",
    "set_goal_context",
    "reset_goal_context",
    "goal_context",
]
