"""Copilot reads and changes partner request limits through the services
behind the Agent trust page: installation administrators only, in the
installation's own tenant, with the audit row written before any change.
The actor is always the signed-in person, never a model-supplied value."""
from __future__ import annotations

from maverick.governed_operations import digest
from pydantic import Field

from . import trust_page_api as native
from .product_errors import product_error
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_PAGES = ("/trust", "/external-agents")
_MAX = 2_000_000
_UNREADABLE = "The saved request limits can't be read. Start over first."


class PartnerLimit(StrictInput):
    partner: str = Field(min_length=1, max_length=200)
    limit: int = Field(ge=1, le=_MAX)


class Partner(StrictInput):
    partner: str = Field(min_length=1, max_length=200)


class StorageLimit(StrictInput):
    limit: int = Field(ge=1, le=_MAX)


def _state(request) -> dict:
    native.require_global_permission(request, "admin")
    value = native.federation_limits()
    if value is None:
        raise ValueError("partner request counts are unavailable")
    peers = value["peers"]
    store = peers[0] if peers else {}
    return {"unreadable": value["unreadable"],
            "partners": [{"partner": p["peer"], "used": p["used"], "limit": p["limit"],
                          "reached": p["reached"]} for p in peers],
            "storage_used": store.get("storage_used"), "storage_limit": store.get("storage_limit"),
            "storage_full": bool(store.get("storage_full"))}


def _summary(state: dict) -> str:
    if state["unreadable"]:
        return "The saved request limits can't be read, so new partner requests are turned away."
    if not state["partners"]:
        return "No partner installations are set up."
    if state["storage_full"]:
        return "Storage for partner requests is full, so every partner is turned away."
    parts = [f"{p['partner']}: {p['used']:,} of {p['limit']:,}" for p in state["partners"]]
    return "Requests used per partner. " + "; ".join(parts) + "."


def _snapshot(request, _selection, *, fields=(), needs_partners=True, needs_unreadable=False):
    state = _state(request)
    blocked = ""
    if needs_unreadable and not state["unreadable"]:
        blocked = "The saved request limits can be read, so there is nothing to start over."
    elif not needs_unreadable and state["unreadable"]:
        blocked = _UNREADABLE
    elif needs_partners and not state["partners"]:
        blocked = "No partner installations are set up."
    choices = [{"value": p["partner"], "label": p["partner"]} for p in state["partners"]]
    shaped = [dict(f, choices=choices, value=choices[0]["value"] if choices else "")
              if f["kind"] == "select" else f for f in fields]
    return Snapshot(digest(state), "Current partner request limits", _summary(state),
                    details=state, fields=shaped, blocked=blocked)


def show_snapshot(request, selection):
    return _snapshot(request, selection, needs_partners=False)


def show_prepare(request, selection, _arguments):
    state = show_snapshot(request, selection)
    return Preview(state.summary, native=state.details)


_PARTNER = {"name": "partner", "label": "Partner", "kind": "select"}
_LIMIT = {"name": "limit", "label": "New limit", "kind": "number", "value": None}


def raise_snapshot(request, selection):
    return _snapshot(request, selection, fields=(_PARTNER, _LIMIT))


def _partner(state: dict, name: str) -> dict:
    row = next((p for p in state["partners"] if p["partner"] == name), None)
    if row is None:
        raise product_error(404, "partner_missing", "Choose a partner that is set up on this installation.")
    return row


def raise_prepare(request, _selection, arguments):
    row = _partner(_state(request), arguments["partner"])
    if arguments["limit"] <= row["limit"]:
        raise product_error(422, "partner_limit_not_higher",
                            f"Choose a number above {row['limit']:,}. Nothing was changed.")
    return Preview("Raise this partner's request limit. Earlier requests stay on record.",
                   changes=[{"field": f"Requests {row['partner']} may send",
                             "before": f"{row['limit']:,}", "after": f"{arguments['limit']:,}"}])


def raise_execute(request, _selection, arguments, _review, _operation):
    usage = native.apply_peer_limit(request, arguments["partner"], limit=arguments["limit"], reset=False)
    return Outcome("confirmed", "Limit raised.", usage)


def reset_snapshot(request, selection):
    return _snapshot(request, selection, fields=(_PARTNER,))


def reset_prepare(request, _selection, arguments):
    row = _partner(_state(request), arguments["partner"])
    return Preview("Start counting this partner's requests again. Earlier requests stay on record.",
                   changes=[{"field": f"Requests counted for {row['partner']}",
                             "before": f"{row['used']:,}", "after": "0"}])


def reset_execute(request, _selection, arguments, _review, _operation):
    usage = native.apply_peer_limit(request, arguments["partner"], limit=None, reset=True)
    return Outcome("confirmed", "Count started again.", usage)


def storage_snapshot(request, selection):
    return _snapshot(request, selection, fields=(_LIMIT,), needs_partners=False)


def storage_prepare(request, _selection, arguments):
    state = _state(request)
    current = state["storage_limit"] or 0
    if arguments["limit"] <= current:
        raise product_error(422, "storage_limit_not_higher",
                            f"Choose a number above {current:,}. Nothing was changed.")
    return Preview("Keep more partner requests. This uses more disk space and makes each check a little slower.",
                   changes=[{"field": "Partner requests kept", "before": f"{current:,}",
                             "after": f"{arguments['limit']:,}"}])


def storage_execute(request, _selection, arguments, _review, _operation):
    limit = native.apply_storage_limit(request, arguments["limit"])
    return Outcome("confirmed", "Storage limit raised.", {"storage_limit": limit})


def start_over_snapshot(request, selection):
    return _snapshot(request, selection, needs_partners=False, needs_unreadable=True)


def start_over_prepare(_request, _selection, _arguments):
    return Preview("Set the unreadable limits aside and use the standard limits. The unreadable copy is kept.",
                   changes=[{"field": "Saved request limits", "before": "Can't be read",
                             "after": "Standard limits"}])


def start_over_execute(request, _selection, _arguments, _review, _operation):
    native.start_over_limits(request)
    return Outcome("confirmed", "Standard limits restored.")


def entries():
    family = "connections"
    return (
        Adapter("trust.partner_limits.show", "Show partner request limits", family, "/trust", _PAGES,
                EmptyInput, show_snapshot, show_prepare,
                aliases=("partner request limits", "federation limits", "partner storage full")),
        Adapter("trust.partner_limits.raise", "Raise a partner's request limit", family, "/trust", _PAGES,
                PartnerLimit, raise_snapshot, raise_prepare, raise_execute,
                aliases=("raise partner limit", "partner refused")),
        Adapter("trust.partner_limits.reset", "Start a partner's request count again", family, "/trust", _PAGES,
                Partner, reset_snapshot, reset_prepare, reset_execute,
                aliases=("reset partner count",)),
        Adapter("trust.partner_limits.storage", "Raise the partner request storage limit", family, "/trust", _PAGES,
                StorageLimit, storage_snapshot, storage_prepare, storage_execute,
                aliases=("partner storage full", "raise storage limit")),
        Adapter("trust.partner_limits.start_over", "Start over with standard partner limits", family, "/trust", _PAGES,
                EmptyInput, start_over_snapshot, start_over_prepare, start_over_execute,
                aliases=("partner limits unreadable",)),
    )
