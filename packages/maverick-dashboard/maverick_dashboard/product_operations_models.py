"""Model evidence and paid tests use the same native authorization and receipts."""
from __future__ import annotations

from fastapi import HTTPException
from maverick import model_tests
from maverick.governed_operations import digest
from pydantic import Field

from . import auth, provider_readiness
from . import model_tests_api as native
from .draft_api import context_for
from .plain_labels import money
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class TestInput(StrictInput):
    model: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern=r"^(generation|vision)$")


def providers_snapshot(request, selection):
    """Answer provider-status questions from the same source as Settings."""
    auth.require_global_permission(request, "admin")
    if selection:
        raise HTTPException(422, "Open Settings to check your AI services.")
    current = provider_readiness.workspace_readiness()
    rows = [{"name": row["name"], "label": row["label"],
             "status": row["status_label"], "used_for_work": row["routed"],
             "next_step": row["reason"]}
            for row in current["providers"] if row["routed"] or row["configured"]]
    details = {"overall": current["verdict_label"], "next_step": current["reason"],
               "services": rows, "href": "/settings"}
    from .system_checks_api import _diagnostics

    observed = _diagnostics()
    details.update(recorded_connection_pauses=observed["paused_services"], recent_calls=observed["recent_calls"],
                   observation_scope="Recent local records only. A pause can belong to an older connection configuration. No service was contacted or work retried; no recorded pause does not establish availability.")
    return Snapshot(digest(details), "Current AI service and model routing status",
                    current["summary"] + ". " + current["reason"], details=details)


def providers_prepare(request, selection, _arguments):
    state = providers_snapshot(request, selection)
    return Preview(state.summary, native=state.details)


def snapshot(request, selection):
    native.authority(request)
    from maverick import model_discovery
    from maverick.llm import _allowed_model_specs
    from maverick.model_discovery import spec_for
    from maverick.model_guidance import describe
    evidence = model_discovery.snapshot()
    models = []
    for provider, row in evidence.items():
        for name in (row.get("models") or [])[:500]:
            spec = spec_for(provider, name)
            models.append({"model": spec, "availability": "Previously reported; refresh needed" if row.get("stale", True) else "Reported by the last successful check",
                            **describe(spec, provider=provider, capability=(row.get("capabilities") or {}).get(name),
                            fetched_at=row.get("fetched_at"), stale=row.get("stale", True))})
    details = {"models": models, "approved_models": sorted(_allowed_model_specs()),
               "scope": "Provider-reported evidence for the current workspace and connection only. Previous choices can remain visible after a failed check, but cannot supply current zero-price spending permission. Tools remain untested; successful text generation does not establish tool support."}
    return Snapshot(digest(details), "Current approved-model policy and cached provider metadata", "Compare reported model capabilities and dated prices.", details=details)


def test_snapshot(request, selection):
    base = snapshot(request, selection)
    blocked = ""
    try:
        model_tests.policy()
    except (PermissionError, ValueError):
        blocked = "Enable bounded model tests in All settings before requesting a paid test."
    fields = [{"name": "model", "label": "Exact model name from your provider", "kind": "text", "value": ""},
              {"name": "kind", "label": "Single synthetic sample", "kind": "select", "value": "generation",
               "choices": [{"value": key, "label": value} for key, value in model_tests.KINDS.items()]}]
    return Snapshot(base.revision, base.source, "Review one bounded potentially paid call. No automatic retry or model failover.",
                    details=base.details, fields=fields, blocked=blocked)


def prepare_test(request, selection, arguments):
    row = native.call(model_tests.prepare, context_for(request), arguments["model"], arguments["kind"], native.guard_for(request, context_for(request)))
    caps = row["limits"]
    return Preview(f"Run one potentially paid synthetic sample on {row['model']}; at most {money(caps['max_dollars'])}, {caps['max_output_tokens']} output tokens and {caps['max_wall_seconds']} seconds of local waiting. Cancellation cannot retract an already sent request.",
        changes=[{"field": "Model test", "before": "Not dispatched", "after": model_tests.KINDS[row["kind"]]}], native={"check_id": row["id"]})


def execute_test(request, selection, arguments, review, operation_id):
    result, background = native.start(request, context_for(request), review["check_id"], True)
    return Outcome(_test_status(result["check"], replay=background is None), "Use the model test history to read this exact request's result. No uncertain call is retried.", result, background=background)


def _test_status(value, *, replay):
    if value.get("may_still_be_running"):
        return "unconfirmed"
    if value["state"] in {"queued", "executing"}:
        return "queued"
    if value["state"] in {"passed", "not_matched", "refused", "cancelled"}:
        return "replayed" if replay else "confirmed"
    return "unconfirmed"


def recover_test(request, selection, arguments, review, operation_id):
    native.authority(request)
    row = model_tests.get(context_for(request), review["check_id"])
    if row is not None and row["state"] != "prepared":
        value = model_tests.public(row)
        return Outcome(_test_status(value, replay=True), "The original test's saved status was read. No paid request was repeated.", {"check": value})
    return None


def history_snapshot(request, selection):
    native.authority(request)
    rows = [model_tests.public(row) for row in model_tests.history(context_for(request))]
    return Snapshot(digest(rows), "Durable model test receipts in this account and workspace", "Review the original test results; unknown results were not replayed.", {"checks": rows})


def cancel_snapshot(request, selection):
    state = history_snapshot(request, selection)
    rows = [row for row in state.details["checks"] if row.get("may_still_be_running") or row["state"] in {"prepared", "queued", "executing"}]
    return Snapshot(state.revision, state.source, "Stop a pending test. A transmitted request may still be billable.", {"checks": rows},
        fields=[{"name": "check_id", "label": "Pending model test", "kind": "select", "value": rows[-1]["id"] if rows else "",
                 "choices": [{"value": row["id"], "label": row["model"] + " / " + model_tests.KINDS[row["kind"]]} for row in rows]}],
        blocked="No pending model tests in this account and workspace." if not rows else "")


class CancelInput(StrictInput):
    check_id: str = Field(pattern=r"^[a-f0-9]{32}$")


def prepare_cancel(request, selection, arguments):
    state = cancel_snapshot(request, selection)
    if not any(row["id"] == arguments["check_id"] for row in state.details["checks"]):
        raise HTTPException(409, "Choose a current owned model test.")
    return Preview("Stop this test; cancellation cannot undo a transmitted request.")


def execute_cancel(request, selection, arguments, review, operation_id):
    context = context_for(request)
    row = native.call(model_tests.cancel, context, arguments["check_id"], native.guard_for(request, context))
    return Outcome("confirmed", "The test's stop request was saved. No paid request was retried.", {"check": model_tests.public(row)})


class SelfHostedPrice(StrictInput):
    provider: str = Field(pattern=r"^(ollama|vllm|tgi)$")
    free: bool
    confirmed: bool = False


def self_hosted_snapshot(request, selection):
    """The Settings page's "Mark a self-hosted server free" form: the same
    administrator check, the same words for how each server is charged."""
    from . import admin_pages

    auth.require_global_permission(request, "admin")
    rows = admin_pages.self_hosted_states()
    summary = "How each self-hosted server is charged now. " + "; ".join(
        f"{row['label']}: {row['state']}" for row in rows) + "."
    fields = [{"name": "provider", "label": "Server", "kind": "select", "value": rows[0]["provider"],
               "choices": [{"value": row["provider"], "label": row["label"]} for row in rows]},
              {"name": "free", "label": "Free: it charges nothing. Turn off to charge it again.",
               "kind": "boolean", "value": True},
              {"name": "confirmed", "kind": "boolean", "value": False,
               "label": "Needed to mark it free: I run this server, or I checked that it charges nothing."}]
    return Snapshot(digest(rows), "Current self-hosted server prices", summary, {"servers": rows}, fields=fields)


def prepare_self_hosted(request, selection, arguments):
    from . import admin_pages

    state = self_hosted_snapshot(request, selection)
    if arguments["free"] and not arguments["confirmed"]:
        raise HTTPException(400, admin_pages.SELF_HOSTED_CONFIRM)
    row = next(row for row in state.details["servers"] if row["provider"] == arguments["provider"])
    after = "Marked free" if arguments["free"] else "Charged again"
    summary = ("Stop charging this server's use against spending limits." if arguments["free"]
               else "Charge this server's use against spending limits again.")
    return Preview(summary, changes=[{"field": f"Charge for {row['label']}", "before": row["state"], "after": after}])


def execute_self_hosted(request, selection, arguments, review, operation_id):
    from . import admin_pages

    if arguments["free"] and not arguments["confirmed"]:
        raise HTTPException(400, admin_pages.SELF_HOSTED_CONFIRM)
    admin_pages.apply_self_hosted_free(request, arguments["provider"], arguments["free"])
    row = next(row for row in admin_pages.self_hosted_states() if row["provider"] == arguments["provider"])
    return Outcome("confirmed", f"{row['label']} is now: {row['state']}.", {"server": row})


class ModelPrice(StrictInput):
    model: str = Field(min_length=1, max_length=128)
    input_per_mtok: float = Field(ge=0, le=1_000_000, allow_inf_nan=False)
    output_per_mtok: float = Field(ge=0, le=1_000_000, allow_inf_nan=False)
    source: str = Field(min_length=1, max_length=300)
    as_of: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    valid_until: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    confirmed: bool = False


class SavedPrice(StrictInput):
    model: str = Field(min_length=1, max_length=128)


def _ceiling(rate: dict) -> str:
    return (f"Input {money(rate['input_per_mtok'], 4)} and output "
            f"{money(rate['output_per_mtok'], 4)} per million tokens")


def _prices(request) -> dict:
    """The Settings page's "Prices for the models you use": the same
    administrator check, the same words for each price status."""
    from . import admin_pages

    auth.require_global_permission(request, "admin")
    return {"models_in_use": [{"work": row["label"], "model": row["spec"], "price_status": row["status"]}
                              for row in admin_pages.model_price_states()],
            "saved_prices": [{"model": row["spec"], "ceiling": _ceiling(row), "source": row["source"],
                              "applies_from": row["as_of"], "review_by": row["valid_until"],
                              "status": "Active" if row["active"] else "Expired: requests stop"}
                             for row in admin_pages.saved_model_rates()]}


def price_snapshot(request, selection):
    from datetime import datetime, timedelta, timezone

    state = _prices(request)
    today = datetime.now(timezone.utc).date()
    stopped = [row["model"] for row in state["models_in_use"]
               if row["price_status"] == "Will stop before a paid request"]
    summary = ("Every model in use has a usable price." if not stopped else
               "These models stop before a paid request until they have a price: "
               + ", ".join(sorted(set(stopped))) + ".")
    fields = [{"name": "model", "label": "Exact model, written as provider:model-name", "kind": "text",
               "value": stopped[0] if stopped else "", "max_length": 128},
              {"name": "input_per_mtok", "label": "Maximum input price, USD per million tokens",
               "kind": "number", "value": None},
              {"name": "output_per_mtok", "label": "Maximum output price, USD per million tokens",
               "kind": "number", "value": None},
              {"name": "source", "label": "Where you checked the price (no secrets)", "kind": "text",
               "value": "", "max_length": 300},
              {"name": "as_of", "label": "Price applies from (year-month-day)", "kind": "text",
               "value": today.isoformat(), "max_length": 10},
              {"name": "valid_until", "label": "Review again by (year-month-day)", "kind": "text",
               "value": (today + timedelta(days=30)).isoformat(), "max_length": 10},
              {"name": "confirmed", "kind": "boolean", "value": False,
               "label": "I checked this model's own USD rate and used a ceiling high enough for our agreement."}]
    return Snapshot(digest(state), "Current model prices and saved spending ceilings", summary, state, fields=fields)


def prepare_price(request, selection, arguments):
    from . import admin_pages

    # The same checks as saving, so a change that cannot be saved is refused
    # here, before the person is asked to confirm it.
    spec, rate = admin_pages.check_model_rate_input(
        request, arguments["model"], input_per_mtok=arguments["input_per_mtok"],
        output_per_mtok=arguments["output_per_mtok"], source=arguments["source"],
        as_of=arguments["as_of"], valid_until=arguments["valid_until"],
        confirmed=arguments["confirmed"])
    saved = next((row["ceiling"] for row in _prices(request)["saved_prices"] if row["model"] == spec), None)
    return Preview("Save a spending ceiling for this model. Lightwork uses it to guard spending limits. "
                   "Your provider's invoice remains the final bill.",
                   changes=[{"field": f"Spending ceiling for {spec}", "before": saved or "No saved price",
                             "after": _ceiling(rate)},
                            {"field": "Review the price again by", "before": "",
                             "after": rate["valid_until"]}])


def execute_price(request, selection, arguments, review, operation_id):
    from . import admin_pages

    done = admin_pages.apply_model_rate(
        request, arguments["model"], input_per_mtok=arguments["input_per_mtok"],
        output_per_mtok=arguments["output_per_mtok"], source=arguments["source"],
        as_of=arguments["as_of"], valid_until=arguments["valid_until"], confirmed=arguments["confirmed"])
    return Outcome("confirmed", f"The spending ceiling for {done['model']} is saved: {_ceiling(done['price'])}.", done)


def remove_price_snapshot(request, selection):
    state = _prices(request)
    choices = [{"value": row["model"], "label": f"{row['model']}: {row['ceiling']}"} for row in state["saved_prices"]]
    return Snapshot(digest(state), "Current model prices and saved spending ceilings",
                    "Remove a saved spending ceiling. A model left without a usable price stops before a paid request.",
                    state, fields=[{"name": "model", "label": "Saved price", "kind": "select",
                                    "value": choices[0]["value"] if choices else "", "choices": choices}],
                    blocked="" if choices else "No saved spending ceiling to remove.")


def prepare_remove_price(request, selection, arguments):
    row = next((row for row in _prices(request)["saved_prices"] if row["model"] == arguments["model"]), None)
    if row is None:
        raise HTTPException(409, "Choose a saved model rate to remove.")
    return Preview("Remove this saved spending ceiling. The model stops before a paid request unless another price applies.",
                   changes=[{"field": f"Spending ceiling for {row['model']}", "before": row["ceiling"],
                             "after": "No saved price"}])


def execute_remove_price(request, selection, arguments, review, operation_id):
    from . import admin_pages

    done = admin_pages.remove_model_rate(request, arguments["model"])
    return Outcome("confirmed", f"The saved spending ceiling for {done['model']} was removed.", done)


class ToolPrice(StrictInput):
    service: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    dollars: float = Field(ge=0, le=10_000, allow_inf_nan=False)
    per: str = Field(pattern=r"^(request|page|character|image|second|terabyte)$")
    confirmed: bool = False


class SavedToolPrice(StrictInput):
    service: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")


def _tool_prices(request) -> dict:
    """The Settings page's "Prices for paid tool services": the same
    administrator check, the same words for each service's charge."""
    from . import admin_pages

    auth.require_global_permission(request, "admin")
    return {"services": admin_pages.tool_price_states()}


def tool_price_snapshot(request, selection):
    from . import admin_pages

    state = _tool_prices(request)
    unpriced = [row["service"] for row in state["services"] if not row["priced"]]
    summary = ("Every listed paid tool service has a price." if not unpriced else
               "These services are charged the safety ceiling per call: " + ", ".join(unpriced) + ".")
    choices = [{"value": row["service"], "label": row["label"]} for row in admin_pages._tool_price_choices()]
    fields = [{"name": "service", "label": "Service", "kind": "select",
               "value": unpriced[0] if unpriced else choices[0]["value"], "choices": choices},
              {"name": "dollars", "label": "Price in USD", "kind": "number", "value": None},
              {"name": "per", "label": "Charged per", "kind": "select", "value": "request",
               "choices": [{"value": unit, "label": words.capitalize()}
                           for unit, words in admin_pages.TOOL_PRICE_UNIT_WORDS.items()]},
              {"name": "confirmed", "kind": "boolean", "value": False,
               "label": "I checked this service's own price."}]
    return Snapshot(digest(state), "Current paid tool service prices", summary, state, fields=fields)


def _tool_charge_now(request, service: str) -> str:
    row = next((row for row in _tool_prices(request)["services"] if row["service"] == service), None)
    return row["charge"] if row else "Safety ceiling per call"


def prepare_tool_price(request, selection, arguments):
    from . import admin_pages

    service, amount, unit = admin_pages.check_tool_price_input(
        request, arguments["service"], dollars=arguments["dollars"], per=arguments["per"],
        confirmed=arguments["confirmed"])
    return Preview("Save the price this tool service is charged against spending limits. "
                   "Its invoice remains the final bill.",
                   changes=[{"field": f"Charge for {service}", "before": _tool_charge_now(request, service),
                             "after": admin_pages._tool_charge((amount, unit), 0.0)}])


def execute_tool_price(request, selection, arguments, review, operation_id):
    from . import admin_pages

    done = admin_pages.apply_tool_price(request, arguments["service"], dollars=arguments["dollars"],
                                        per=arguments["per"], confirmed=arguments["confirmed"])
    return Outcome("confirmed", f"{done['service']} is now charged "
                   f"{admin_pages._tool_charge((done['dollars'], done['per']), 0.0)}.", done)


def remove_tool_price_snapshot(request, selection):
    state = _tool_prices(request)
    choices = [{"value": row["service"], "label": f"{row['label']}: {row['charge']}"}
               for row in state["services"] if row["priced"]]
    return Snapshot(digest(state), "Current paid tool service prices",
                    "Remove a saved tool price. That service is then charged the safety ceiling per call.",
                    state, fields=[{"name": "service", "label": "Saved price", "kind": "select",
                                    "value": choices[0]["value"] if choices else "", "choices": choices}],
                    blocked="" if choices else "No saved tool price to remove.")


def prepare_remove_tool_price(request, selection, arguments):
    row = next((row for row in _tool_prices(request)["services"]
                if row["service"] == arguments["service"] and row["priced"]), None)
    if row is None:
        raise HTTPException(409, "Choose a saved tool price to remove.")
    return Preview("Remove this saved tool price. The service is then charged the safety ceiling per call.",
                   changes=[{"field": f"Charge for {row['service']}", "before": row["charge"],
                             "after": "Safety ceiling per call"}])


def execute_remove_tool_price(request, selection, arguments, review, operation_id):
    from . import admin_pages

    done = admin_pages.remove_tool_price(request, arguments["service"])
    return Outcome("confirmed", f"The saved price for {done['service']} was removed.", done)


def entries():
    pages = ("/settings", "/settings/all")
    return [Adapter("models.provider_status", "Check AI service status", "models", "/settings",
                    (*pages, "/providers"),
                    EmptyInput, providers_snapshot, providers_prepare,
                    aliases=("which ai services are connected", "which ai provider is in use", "check model connection", "which services are paused")),
            Adapter("models.guidance", "Compare model capabilities", "models", "/settings", pages, EmptyInput, snapshot,
                    lambda request, selection, args: Preview("Current model evidence", native=snapshot(request, selection).details)),
            Adapter("models.test", "Run a bounded model test", "models", "/settings", pages, TestInput, test_snapshot, prepare_test, execute_test, recover_test),
            Adapter("models.test.history", "Check model test results", "models", "/settings", pages, EmptyInput, history_snapshot,
                    lambda request, selection, args: Preview("Original model test receipts", native=history_snapshot(request, selection).details)),
            Adapter("models.test.cancel", "Stop a model test", "models", "/settings", pages, CancelInput, cancel_snapshot, prepare_cancel, execute_cancel),
            Adapter("models.self_hosted_price", "Mark a self-hosted server free or charged", "models", "/settings", pages,
                    SelfHostedPrice, self_hosted_snapshot, prepare_self_hosted, execute_self_hosted,
                    aliases=("mark ollama free", "self-hosted model price", "safety ceiling price",
                             "charge a self-hosted server again")),
            Adapter("models.price.set", "Set a model's spending ceiling", "models", "/settings#settings-model-prices",
                    pages, ModelPrice, price_snapshot, prepare_price, execute_price,
                    aliases=("set a model price", "price a private model", "model has no price",
                             "save a company rate")),
            Adapter("models.price.remove", "Remove a model's saved spending ceiling", "models",
                    "/settings#settings-model-prices", pages, SavedPrice, remove_price_snapshot,
                    prepare_remove_price, execute_remove_price,
                    aliases=("remove a model price", "remove a company rate")),
            Adapter("tools.price.set", "Set a paid tool service's price", "models",
                    "/settings#settings-tool-prices", pages, ToolPrice, tool_price_snapshot,
                    prepare_tool_price, execute_tool_price,
                    aliases=("set a tool price", "price a paid tool", "tool safety ceiling",
                             "deepl price", "search price")),
            Adapter("tools.price.remove", "Remove a paid tool service's price", "models",
                    "/settings#settings-tool-prices", pages, SavedToolPrice, remove_tool_price_snapshot,
                    prepare_remove_tool_price, execute_remove_tool_price,
                    aliases=("remove a tool price",))]
