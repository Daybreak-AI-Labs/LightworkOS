"""Copilot shares the native complete banner withdrawal and original reader."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import consent_publication_withdrawal as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class WebsiteInput(StrictInput):
    website: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class OriginalInput(StrictInput):
    request: str = Field(pattern=r"^[a-f0-9]{32}$")


def snapshot(request, _selection):
    value = native.catalog(request)
    return Snapshot(digest(value), "Current workspace consent banners", native.NOTICE,
        fields=[{"name": "website", "label": "Website or app", "kind": "select", "required": True, "choices": value["websites"]}],
        blocked="No website or app has a published banner in this workspace." if not value["websites"] else "")


def prepare(request, _selection, arguments):
    value = native.prepare(request, arguments["website"])
    return Preview("Review every website setting and the exact current banner before withdrawing it.", changes=native.changes(value), native=value)


def outcome(value):
    return Outcome("confirmed" if value["confirmed"] else "unconfirmed", value["message"],
        {"Current banner": value.get("current", "Current state is separate from the original outcome."), "Effect": native.NOTICE,
         "Original withdrawal": {"href": "/consent/publishing?withdrawal=" + value["operation"] + "#cpp-withdrawal-original", "label": "Read the original result"}})


def execute(request, _selection, arguments, prepared, operation):
    if arguments["website"] != prepared["source"]["property"]["property_id"]:
        raise HTTPException(409, "The selected website changed. Review it again.")
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation, *, read_only=False):
    if not read_only and native.owned(request, operation, prepared) is None:
        return None
    return outcome(native.original(request, operation, prepared=prepared))


def original_snapshot(request, _selection):
    value = native.catalog(request)
    return Snapshot(digest(value), "Your original consent banner withdrawal requests", "Read the accepted native request without withdrawing again.",
        fields=[{"name": "request", "label": "Original withdrawal", "kind": "select", "required": True, "choices": value["requests"]}],
        blocked="No original withdrawal request is retained for this account and workspace." if not value["requests"] else "")


def read_prepare(request, _selection, arguments):
    value = native.original(request, arguments["request"])
    return Preview(value["message"], native=outcome(value).details)


def entries():
    common = {"family": "preferences", "pages": ("/consent/publishing",), "direct_ui": native.PAGE}
    return (
        Adapter("consent.banner.withdraw", "Withdraw a website or app consent banner", input_model=WebsiteInput, snapshot=snapshot,
                prepare=prepare, execute=execute, recover=recover, read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
        Adapter("consent.banner.withdrawal_original", "Read an original banner withdrawal", input_model=OriginalInput,
                snapshot=original_snapshot, prepare=read_prepare, **common),
    )
