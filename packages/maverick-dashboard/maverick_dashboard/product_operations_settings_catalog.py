"""Copilot hands all organization settings to their protected native controls."""
from __future__ import annotations

from . import settings_all_page
from . import settings_catalog_requests as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def _snapshot(request, original):
    current = native.authority(request)
    revision = settings_all_page._revision()
    native.authority(request, current)
    return Snapshot(revision, "Current organization settings and original requests",
        "Open protected named controls to choose, completely review and save settings, or read your original request. Credentials stay outside this conversation.",
        details={"settings_catalog_form": {"context": current, "original": original}})


def configure(request, _selection):
    return _snapshot(request, False)


def originals(request, _selection):
    return _snapshot(request, True)


def prepare(request, selection, _arguments):
    value = configure(request, selection)
    return Preview(value.summary, native=value.details)


def prepare_originals(request, selection, _arguments):
    value = originals(request, selection)
    return Preview(value.summary, native=value.details)


def entries():
    pages = ("/settings", "/settings/all")
    return (Adapter("settings.organization.configure", "Choose, review and save organization settings", "preferences", "/settings/all",
                    pages, EmptyInput, configure, prepare, aliases=("all settings", "change organization settings", "configure limits")),
            Adapter("settings.organization.original_results", "Read my original settings requests", "preferences", "/settings/all#settings-original-requests",
                    pages, EmptyInput, originals, prepare_originals, aliases=("settings save lost reply", "original configuration request")))
