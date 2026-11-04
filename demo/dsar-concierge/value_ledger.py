"""Counted value for DSAR work — per completed request, never re-estimated.

Baselines are the human hours a privacy team spends per request kind
(locate, compile, review, respond), env-overridable so a client's own
numbers drive the story. Business-side value is the requester-facing
time the agent removes (chasing, status emails).
"""
from __future__ import annotations

import os


def _f(env: str, default: float) -> float:
    try:
        return float(os.environ.get(env, "") or default)
    except ValueError:
        return default


HOURLY_RATE = _f("VALUE_HOURLY_RATE", 60.0)

REQUEST_HOURS = {
    "access": _f("VALUE_DSAR_ACCESS_HOURS", 2.5),
    "portability": _f("VALUE_DSAR_PORTABILITY_HOURS", 2.5),
    "erasure": _f("VALUE_DSAR_ERASURE_HOURS", 3.0),
}
BUSINESS_HOURS_PER_REQUEST = 0.25   # status-chasing the agent removes


def request_value(kind: str) -> dict:
    privacy_hours = REQUEST_HOURS.get(kind, REQUEST_HOURS["access"])
    total = privacy_hours + BUSINESS_HOURS_PER_REQUEST
    return {"privacy_hours": privacy_hours,
            "business_hours": BUSINESS_HOURS_PER_REQUEST,
            "hours": round(total, 2),
            "dollars": round(total * HOURLY_RATE, 2),
            "rate": HOURLY_RATE}
