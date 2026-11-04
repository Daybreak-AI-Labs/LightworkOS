"""Shared SQL aggregates for SQLite and tenant-scoped Postgres shoring reports."""
from __future__ import annotations

from typing import Any

# Count all matching goals in the database, not the newest N in Python.
# A legacy row has no trustworthy completion timestamp, so its turnaround
# remains unmeasured rather than being inferred from a later edit time.
AGGREGATE_SQL = """
SELECT
  COALESCE(SUM(CASE WHEN LOWER(status) = 'done' THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN LOWER(status) IN ('blocked','cancelled','failed','error') THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN LOWER(status) NOT IN ('done','blocked','cancelled','failed','error') THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN LOWER(status) = 'done' AND completed_at >= created_at THEN 1 ELSE 0 END), 0),
  MAX(CASE WHEN LOWER(status) = 'done' AND completed_at >= created_at
      THEN (completed_at - created_at) / 3600.0 ELSE NULL END),
  COALESCE(SUM(CASE WHEN LOWER(status) = 'done' AND completed_at IS NULL THEN 1 ELSE 0 END), 0)
FROM goals
"""
EVENT_TIME_SQL = "CASE WHEN LOWER(status) = 'done' THEN COALESCE(completed_at, updated_at) ELSE updated_at END"


def measurements(row: Any) -> dict:
    delivered, blocked, in_flight, measured, max_hours, legacy = row
    return {
        "delivered": int(delivered), "blocked": int(blocked), "in_flight": int(in_flight),
        "measurement_complete": True,
        "turnaround_measurement_complete": int(measured) == int(delivered),
        "max_turnaround_hours": float(max_hours) if max_hours is not None else None,
        "legacy_completion_count": int(legacy),
    }
