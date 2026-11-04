"""Tenant settings and benchmark changes use the existing governed store."""
from __future__ import annotations

import math
import os
import time

from .. import config
from ..governed_records import GovernedRecordStore
from ..privacy_ops import RecordConflict
from .taxonomy import definition

SETTINGS = GovernedRecordStore("intent_value_settings", "IVS", "intent_value")
BENCHMARKS = GovernedRecordStore("intent_value_benchmarks", "IVB", "intent_value")
SETTINGS_ID = "IVS-settings"


def policy() -> dict:
    global_cfg = config.load_global_config().get("intent_value", {}) or {}
    cfg = config.load_config().get("intent_value", {}) or {}
    healthy = not config.config_source_errors(include_tenant=True)
    return {"enabled": healthy and global_cfg.get("enabled", True) is True and cfg.get("enabled", True) is True,
            "completion_confirmation": cfg.get("completion_confirmation", False) is True,
            "recommendations": global_cfg.get("recommendations", True) is True and cfg.get("recommendations", True) is True}


def settings() -> dict:
    value = config.get_value()
    row = SETTINGS.get(SETTINGS_ID)
    if row and row.get("_audit_pending"):
        # Reads never write: the explicit sync or a write path retries the receipt.
        raise RuntimeError("Company assumptions are waiting for their audit receipt.")
    configured = config.load_config().get("value", {}) or {}
    result = {"revision": 0, "completion_confirmation": policy()["completion_confirmation"],
              "hourly_rate": value["hourly_rate"], "currency": value["currency"],
              "labor_provenance": "Company configuration" if "hourly_rate" in configured else "Provisional Lightwork labor-rate assumption",
              "history": [], "enabled": policy()["enabled"]}
    if row and not row.get("_audit_pending"):
        result.update({key: row[key] for key in ("revision", "completion_confirmation", "hourly_rate", "currency", "labor_provenance", "history")})
    if os.environ.get("MAVERICK_VALUE_HOURLY_RATE"):
        result.update(hourly_rate=value["hourly_rate"], labor_provenance="Deployment labor-rate override",
                      labor_locked=True)
    else:
        result["labor_locked"] = False
    result["audit_pending"] = bool(row and row.get("_audit_pending"))
    return result


def number(value, name, maximum=100_000):
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be a finite nonnegative number, at most {maximum}.")
    return float(value)


def save_settings(*, hourly_rate, currency, completion_confirmation, expected_revision, actor, guard):
    current = settings()
    if current["labor_locked"] and hourly_rate != current["hourly_rate"]:
        raise ValueError("The deployment sets the effective labor rate; this workspace cannot override it.")
    number(hourly_rate, "Hourly rate")
    if currency not in {"USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CHF", "INR"}:
        raise ValueError("Choose a supported labor currency; costs keep their original currency.")
    if type(completion_confirmation) is not bool:
        raise ValueError("Choose whether to enable optional completion confirmation.")
    before = {key: current[key] for key in ("hourly_rate", "currency", "completion_confirmation")}
    values = dict(hourly_rate=hourly_rate, currency=currency, completion_confirmation=completion_confirmation,
                  labor_provenance="Company-provided assumption", history=[*current["history"], {"at": time.time(), "actor": actor, "before": before}])
    if expected_revision == 0:
        return SETTINGS.create({"id": SETTINGS_ID, **values}, action="intent_value.settings", actor=actor, effect_guard=guard)
    return SETTINGS.update(SETTINGS_ID, lambda row: row.update(values), expected_revision=expected_revision,
                           action="intent_value.settings", actor=actor, effect_guard=guard)


def benchmark(identifier):
    item = definition(identifier)
    if item is None:
        return None
    row = BENCHMARKS.get("IVB-" + identifier.replace(".", "-"))
    if row and row.get("_audit_pending"):
        # Reads never write: the explicit sync or a write path retries the receipt.
        raise RuntimeError("The company benchmark is waiting for its audit receipt.")
    return row["benchmark"] if row else item["benchmark"]


def retry_pending() -> int:
    """Retry the audit receipts of company assumptions and benchmarks.

    Only write-capable flows call this (the explicit sync, saves and prepared
    actions); a read reports a pending receipt instead of writing it."""
    return SETTINGS.retry_pending(limit=100) + BENCHMARKS.retry_pending(limit=100)


def save_benchmark(identifier, *, minutes, low_minutes, high_minutes, attributable_share,
                   review_minutes, reason, expected_revision, actor, guard):
    item = definition(identifier)
    if item is None:
        raise ValueError("Choose a known business activity.")
    for key, value in {"minutes": minutes, "low_minutes": low_minutes, "high_minutes": high_minutes,
                       "review_minutes": review_minutes}.items():
        number(value, key)
    number(attributable_share, "Lightwork share", 1)
    if not low_minutes <= minutes <= high_minutes or not reason.strip():
        raise ValueError("Enter a range containing the estimate and explain the company assumption.")
    current = BENCHMARKS.get("IVB-" + identifier.replace(".", "-"))
    if expected_revision and current is None:
        raise RecordConflict("The benchmark changed or was removed.")
    prior = current["benchmark"] if current else item["benchmark"]
    value = {**prior, "minutes": minutes, "low_minutes": low_minutes, "high_minutes": high_minutes,
             "attributable_share": attributable_share, "review_minutes": review_minutes,
             "review_basis": "Company-provided retained review effort", "provenance": reason[:1000],
             "version": f"tenant-{expected_revision + 1}", "effective_date": time.strftime("%Y-%m-%d", time.gmtime()),
             "override": True, "provisional": False}
    values = {"benchmark": value, "history": [*(current or {}).get("history", []), {"at": time.time(), "actor": actor, "before": prior}]}
    if expected_revision == 0:
        return BENCHMARKS.create({"id": "IVB-" + identifier.replace(".", "-"), **values}, action="intent_value.benchmark", actor=actor, effect_guard=guard)
    return BENCHMARKS.update(current["id"], lambda row: row.update(values), expected_revision=expected_revision,
                             action="intent_value.benchmark", actor=actor, effect_guard=guard)
