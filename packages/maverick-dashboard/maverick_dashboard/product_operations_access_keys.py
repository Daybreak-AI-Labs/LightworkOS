"""Copilot opens protected native access-key controls; never handles keys."""
from __future__ import annotations

from maverick.governed_operations import digest

from . import access_key_requests as native
from .product_operations import Adapter, Preview, Snapshot, StrictInput


def snapshot(request, _selection):
    context = native.authority(request)
    return Snapshot(digest(context), "Protected access-key controls for your current account", "Choose, review and confirm in the native form. A key is shown only there, once.")


def prepare_for(original):
    def prepare(request, _selection, _arguments):
        context = native.authority(request)
        return Preview("Open your original key request records." if original else "Open the protected key controls. Choose the current key or permissions, then review and confirm there.",
                       native={"access_key_form": {"context": context, "original": original}, "Open protected controls": {"href": native.PAGE, "label": "Access keys"}})
    return prepare


def entries():
    common = {"family": "preferences", "pages": ("/account/api-keys",), "direct_ui": native.PAGE, "input_model": StrictInput, "snapshot": snapshot}
    return (Adapter("account.access_keys", "Manage access keys in protected controls", prepare=prepare_for(False), **common),
            Adapter("account.access_key_originals", "Read original access-key requests", prepare=prepare_for(True), **common))
