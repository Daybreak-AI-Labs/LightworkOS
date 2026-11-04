"""Typed Copilot parity for the same native registered-vendor decisions."""
from __future__ import annotations

from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import vendor_profile as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGES = (
    "/privacy",
    "/privacy/vendors/*",
    "/third-party/lifecycle",
    "/third-party/intelligence",
    "/third-party/contracts",
)


class VendorIn(StrictInput):
    vendor: str = Field(pattern=r"^VMR-[a-f0-9]{24}$")


class LinkIn(VendorIn):
    intelligence: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=8, max_length=500)


class ActivateIn(VendorIn):
    lifecycle: str | None = Field(default=None, max_length=128)
    reason: str = Field(min_length=8, max_length=500)


def snapshot(request, selection, *, action="inspect"):
    if selection:
        raise HTTPException(422, "Choose the actual registered vendor in this review.")
    tenant, _, context = native.authority(request, write=action != "inspect", admin=action == "bind")
    vendors = native.vm.list_vendors()
    fields = [{"name": "vendor", "label": "Registered vendor", "kind": "select", "required": True,
               "choices": [{"value": row["id"], "label": row["name"]} for row in vendors]}]
    bound = [context, vendors]
    if action == "bind":
        if not native.intelligence_api.third_party_intelligence_enabled_for_page():
            return Snapshot(digest(bound), "Current registered vendors", native.NOTICE, fields=fields, blocked="Turn on Third-party intelligence in Settings first.")
        rows = native._bounded(native.intelligence_store(request, tenant).list_vendors(tenant, limit=1000), "intelligence vendor")
        fields.append({"name": "intelligence", "label": "Existing unbound Intelligence identity", "kind": "select", "required": True,
                       "choices": [{"value": row.vendor_id, "label": row.display_label} for row in rows if row.register_vendor_id is None]})
        bound.append([row.integrity_sha256 for row in rows])
    elif action == "activate":
        if not native.lifecycle_api.third_party_lifecycle_enabled_for_page():
            return Snapshot(digest(bound), "Current registered vendors", native.NOTICE, fields=fields, blocked="Turn on Third-party lifecycle and evaluate the vendor assessment first.")
        rows = native._bounded(native.lifecycle_store(request, tenant).list_lifecycles(tenant, limit=1000), "lifecycle")
        names = {row["id"]: row["name"] for row in vendors}
        fields.append({"name": "lifecycle", "label": "Optional tracked lifecycle to activate with its registered vendor", "kind": "select", "required": False,
                       "choices": [{"value": row.lifecycle_id, "label": names[row.vendor_ref] + " · " + row.stage} for row in rows if row.vendor_ref in names]})
        bound.append([row.integrity_sha256 for row in rows])
    if action != "inspect":
        fields.append({"name": "reason", "label": "Reason for this identity or activation decision", "kind": "textarea", "required": True})
    return Snapshot(digest(bound), "Current authorized registered vendors and retained native records", native.NOTICE,
                    fields=fields, blocked="Register the vendor in Privacy first." if not vendors else "")


def prepare(request, selection, arguments, *, action="inspect"):
    snapshot(request, selection, action=action)
    identifier = arguments["vendor"]
    if action == "inspect":
        value = native.profile(request, identifier)
        return Preview("Current native vendor, lifecycle, assessments, screening and contracts.",
            changes=[{"label": key.replace("_", " "), "after": value[key]} for key in ("vendor", "lifecycle", "assessments", "intelligence", "screening", "decisions", "due_diligence", "contracts", "activation_blocked")],
            native={"open": {"label": "Open this complete registered vendor profile", "href": "/privacy/vendors/" + identifier + "#vendor-profile"}})
    prepared = native.prepare(request, identifier, action,
        **{key: value for key, value in arguments.items() if key != "vendor"})
    return Preview(native.NOTICE, changes=native.changes(prepared),
        native={"prepared": prepared, "open": {"label": "Open the same native vendor controls", "href": "/privacy/vendors/" + identifier + "#vendor-profile"}})


def outcome(value, *, replay=False):
    return Outcome("replayed" if value["confirmed"] and replay else "confirmed" if value["confirmed"] else "unconfirmed",
                   value["message"], {"Retained original steps": value.get("results", []),
                       "open": {"label": "Open the current registered vendor", "href": value["open"]}})


def execute(request, _selection, _arguments, prepared, operation):
    return outcome(native.apply(request, prepared["prepared"], operation))


def recover(request, _selection, _arguments, prepared, operation):
    value = native.original(request, prepared["prepared"], operation)
    return None if value["state"] == "absent" else outcome(value, replay=True)


def read_recovery(request, _selection, _arguments, prepared, operation):
    value = native.original(request, prepared["prepared"], operation)
    if value["state"] == "absent":
        return Outcome("unconfirmed", value["message"])
    return outcome(value, replay=True)


def original_snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Read the retained native vendor decision from its profile.")
    _, _, context = native.authority(request)
    return Snapshot(context, "Current registered-vendor workspace", "Open the vendor profile and read its retained original; no identity link or activation is repeated.")


def original_prepare(request, selection, _arguments):
    original_snapshot(request, selection)
    return Preview("Choose the registered vendor and read its retained original decision.", native={"open": {"label": "Open the vendor register", "href": "/privacy"}})


def entries():
    common = {"family": "reviews", "pages": PAGES, "direct_ui": "/privacy", "review_max_bytes": 300000}
    return (
        Adapter("vendors.profile.inspect", "Inspect one registered vendor's lifecycle and risk", input_model=VendorIn, snapshot=snapshot, prepare=prepare, **common),
        Adapter("vendors.identity.link", "Link an existing Intelligence identity to a registered vendor", input_model=LinkIn,
            snapshot=partial(snapshot, action="bind"), prepare=partial(prepare, action="bind"), execute=execute, recover=recover, read_recovery=read_recovery, **common),
        Adapter("vendors.lifecycle.activate", "Review an evaluated assessment and activate the registered vendor", input_model=ActivateIn,
            snapshot=partial(snapshot, action="activate"), prepare=partial(prepare, action="activate"), execute=execute, recover=recover, read_recovery=read_recovery, **common),
        Adapter("vendors.profile.original", "Read a retained vendor decision without repeating it", input_model=EmptyInput,
            snapshot=original_snapshot, prepare=original_prepare, **common),
    )
