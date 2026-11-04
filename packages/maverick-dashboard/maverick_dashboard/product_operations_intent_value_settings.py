"""Reviewed administrative assumptions use the same tenant-scoped native APIs."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import intent_value_api as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class SettingsInput(StrictInput):
    hourly_rate: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    currency: Literal["USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CHF", "INR"]
    completion_confirmation: bool = False


class BenchmarkInput(StrictInput):
    identifier: str = Field(max_length=100)
    minutes: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    low_minutes: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    high_minutes: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    attributable_share: float = Field(ge=0, le=1, allow_inf_nan=False)
    review_minutes: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    reason: str = Field(min_length=1, max_length=1000)


def settings_snapshot(request, _selection):
    native.authority(request, admin=True)
    value = native.settings_endpoint(request)
    return Snapshot(digest(value), "Current company work-value assumptions",
        "Changes affect new estimates. Existing work retains its assumptions until deliberately recalculated.",
        fields=[{"name": "hourly_rate", "label": "Labor rate per hour", "kind": "number", "required": True, "value": value["hourly_rate"]},
                {"name": "currency", "label": "Labor currency", "kind": "select", "required": True, "value": value["currency"],
                 "choices": [{"value": currency, "label": currency} for currency in ("USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CHF", "INR")]},
                {"name": "completion_confirmation", "label": "Offer optional completion confirmation (never execution evidence)",
                 "kind": "checkbox", "value": value["completion_confirmation"]}])


def settings_prepare(request, _selection, arguments):
    native.authority(request, admin=True)
    value = native.settings_endpoint(request)
    body = native.SettingsIn(revision=value["revision"], **arguments)
    if value["labor_locked"] and body.hourly_rate != value["hourly_rate"]:
        raise HTTPException(422, "The labor rate is controlled by deployment configuration. An installation administrator must update that setting.")
    return Preview("Review company assumptions. Historic estimates stay explainable; confirmation never grants execution credit.",
        changes=[{"label": "Labor rate", "before": str(value["hourly_rate"]) + " " + value["currency"],
                  "after": str(body.hourly_rate) + " " + body.currency},
                 {"label": "Optional completion confirmation", "before": str(value["completion_confirmation"]), "after": str(body.completion_confirmation)}],
        native={"revision": value["revision"]})


def settings_execute(request, _selection, arguments, prepared, _operation):
    value = native.save_settings_endpoint(request, native.SettingsIn(revision=prepared["revision"], **arguments))
    return _result(value)


def benchmark_snapshot(request, _selection):
    native.authority(request, admin=True)
    rows = native.benchmarks_endpoint(request)["benchmarks"]
    fields = [{"name": "identifier", "label": "Business activity", "kind": "select", "required": True,
               "choices": [{"value": row["id"], "label": row["label"]} for row in rows]}]
    fields.extend({"name": name, "label": label, "kind": "number", "required": True} for name, label in (
        ("minutes", "Typical component effort in minutes"), ("low_minutes", "Lower effort estimate in minutes"),
        ("high_minutes", "Upper effort estimate in minutes"), ("attributable_share", "Share attributable to Lightwork (0 to 1)"),
        ("review_minutes", "Retained human review minutes")))
    fields.append({"name": "reason", "label": "Why this company assumption applies", "kind": "text", "required": True})
    return Snapshot(digest([(row["id"], row["revision"]) for row in rows]), "Current company benchmark versions",
        "Defaults are provisional planning assumptions. This creates a company override with retained history.", fields=fields)


def benchmark_prepare(request, _selection, arguments):
    native.authority(request, admin=True)
    rows = native.benchmarks_endpoint(request)["benchmarks"]
    row = next((row for row in rows if row["id"] == arguments["identifier"]), None)
    if row is None:
        raise HTTPException(422, "Choose a known business activity.")
    values = {key: value for key, value in arguments.items() if key != "identifier"}
    native.BenchmarkIn(revision=row["revision"], **values)
    if not values["low_minutes"] <= values["minutes"] <= values["high_minutes"]:
        raise HTTPException(422, "The typical effort must lie within the lower and upper estimates.")
    labels = {"minutes": "Typical minutes", "low_minutes": "Lower minutes", "high_minutes": "Upper minutes",
              "attributable_share": "Lightwork share", "review_minutes": "Retained review minutes", "reason": "Reason"}
    return Preview("Review the override for " + row["label"] + ". Existing estimates change only on deliberate recalculation.",
        changes=[{"label": labels[key], "before": str(row["benchmark"].get(key, "")), "after": str(value)} for key, value in values.items()],
        native={"revision": row["revision"]})


def benchmark_execute(request, _selection, arguments, prepared, _operation):
    values = {key: value for key, value in arguments.items() if key != "identifier"}
    result = native.benchmark_endpoint(request, arguments["identifier"], native.BenchmarkIn(revision=prepared["revision"], **values))
    return _result(result)


def _result(value):
    pending = value.get("state") == "audit_pending"
    return Outcome("unconfirmed" if pending else "confirmed",
        "Audit delivery is pending. Refresh before continuing." if pending else "Company assumptions saved with version history. Existing estimates remain unchanged until recalculated.",
        {"Inspect": {"href": "/work-value", "label": "Inspect assumptions and work estimates"}})


def entries(common):
    return (Adapter("learning.work_value_settings", "Change company labor assumptions and optional confirmation", input_model=SettingsInput,
                    snapshot=settings_snapshot, prepare=settings_prepare, execute=settings_execute, **common),
            Adapter("learning.work_value_benchmark", "Override a company effort benchmark", input_model=BenchmarkInput,
                    snapshot=benchmark_snapshot, prepare=benchmark_prepare, execute=benchmark_execute, **common))
