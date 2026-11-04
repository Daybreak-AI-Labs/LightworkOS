"""Read-only normalization seams for Lightwork platform telemetry."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, is_dataclass
from typing import Any

from .models import HuntEvent, deterministic_id


def _mapping(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if is_dataclass(value):
        return asdict(value)
    try:
        return dict(vars(value))
    except TypeError as exc:
        raise ValueError("platform telemetry row must be a mapping or dataclass") from exc


def _normalize(rows: Iterable[object], source: str, default_kind: str) -> list[HuntEvent]:
    events: list[HuntEvent] = []
    for value in rows:
        row = _mapping(value)
        row.setdefault("kind", default_kind)
        if not row.get("event_id") and not row.get("id"):
            # Signed audit records already carry a stable content hash.  Use it
            # as their identity so a sliding time window or bounded-slice index
            # cannot mint duplicate findings/approvals for unchanged evidence.
            signed_hash = str(row.get("hash") or "")
            if source == "audit" and len(signed_hash) == 64:
                try:
                    int(signed_hash, 16)
                except ValueError:
                    signed_hash = ""
            else:
                signed_hash = ""
            row["event_id"] = (
                f"audit_{signed_hash}" if signed_hash else deterministic_id(source, row)
            )
        if not any(key in row for key in ("observed_at", "ts", "timestamp")):
            for key in ("decided_at", "updated_at", "requested_at", "created_at", "started_at"):
                if row.get(key) is not None:
                    row["observed_at"] = row[key]
                    break
            else:
                row["observed_at"] = 0.0
        if not any(key in row for key in ("actor", "agent", "principal")):
            row["actor"] = row.get("decided_by", row.get("requested_by", row.get("owner", "system")))
        events.append(HuntEvent.from_mapping(source, row))
    return events


def collect_lightwork_events(
    *,
    audit_events: Iterable[object] = (),
    approvals: Iterable[object] = (),
    budgets: Iterable[object] = (),
    budget_receipts: Iterable[object] = (),
    goals: Iterable[object] = (),
) -> tuple[HuntEvent, ...]:
    """Normalize signed-audit, receipt, and optional enrichment snapshots.

    The caller controls tenant selection and time windows. Raw rows are never
    retained by the hunter; only normalized events live for the duration of a scan.
    When a production ``chain_status`` is supplied to :func:`scan`, only ``audit``
    and ``budget.receipts`` sources may drive verdicts. Mutable world snapshots
    remain non-authoritative enrichment unless a future adapter proves an exact
    commitment to a signed row.
    """
    events = _normalize(audit_events, "audit", "audit_event")
    events.extend(_normalize(approvals, "world.approvals", "approval"))
    events.extend(_normalize(budgets, "world.budgets", "budget"))
    events.extend(_normalize(budget_receipts, "budget.receipts", "budget"))
    events.extend(_normalize(goals, "world.goals", "goal"))
    return tuple(sorted(events, key=lambda event: (event.observed_at, event.event_id)))


__all__ = ["collect_lightwork_events"]
