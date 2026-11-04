"""Copilot opens the same protected ordinary consent delivery controls."""
from maverick.governed_operations import digest

from . import consent_delivery_managed_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, selection):
    body = native.state(request)
    sub = body["subscription"]
    public = {"Saved signing keys":len(body["keys"]),"Automatic delivery authorized":bool(sub and sub["active"]),
              "Worker enabled":body["worker"]["enabled"],"Held for review":bool(body["holding"])}
    stable = {**body, "worker": {key: value for key, value in body["worker"].items() if key != "last_check"}}
    return Snapshot(digest(stable),"Current delivery setup", "Open complete ordinary setup. No update is sent by opening it.", public)


def prepare(request, selection, _arguments):
    snapshot(request, selection)
    body = native.state(request)
    return Preview("Open signing-key and automatic delivery controls. Your current entries stay in place; nothing is saved or sent.",
                   native={"consent_delivery_review":{"scope":"current_page","context":body["context"]}})


def entries():
    return (Adapter("artifacts.consent_delivery_controls","Open complete consent delivery controls","artifacts","/consent/delivery",
        ("/consent/delivery",),EmptyInput,snapshot,prepare,
        aliases=("open complete consent delivery controls","set up automatic consent delivery","save a consent signing key")),)
