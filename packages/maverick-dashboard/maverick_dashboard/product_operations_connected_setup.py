"""Copilot opens complete native setup forms without sending or enabling work."""
from __future__ import annotations

import json

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import company_signin_migration, company_signin_tests, connected_event_sources_api
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def event_snapshot(request, _selection):
    value = connected_event_sources_api.call(lambda: connected_event_sources_api.catalog(request))
    return Snapshot(digest(value), "Current saved accounts for connected automations", connected_event_sources_api.NOTICE)


def event_prepare(request, selection, _arguments):
    value = event_snapshot(request, selection)
    return Preview(value.summary + " Choose a named saved account and source in the complete Automations form. "
        "Checking and reviewing happen there before you explicitly arm the automation. This handoff does not poll, create or send anything.",
        native={"open": {"label": "Choose and review a connected automation", "href": "/automations#auto-event-form"}})


def signin_snapshot(request, _selection):
    value = json.loads(company_signin_tests.status(request).body)
    return Snapshot(digest(value), "Your retained company sign-in checks", "A provider connection check and a real sign-in are separate. Neither enables company sign-in or grants access.")


def signin_prepare(request, selection, _arguments):
    value = signin_snapshot(request, selection)
    try:
        current, _owner = company_signin_migration.authority(request)
    except HTTPException:
        return Preview(value.summary + " Open Settings to save and check provider details. Managed installation policies still apply.",
            native={"open": {"label": "Set up and check company sign-in", "href": "/settings/all#settings-signin-guide"}})
    return Preview(value.summary + " Open Settings to try a real sign-in, explicitly grant administrator access, then separately review activation. No settings or roles change through this handoff.",
        native={"company_signin_migration": {"context": current, "original": False},
                "open": {"label": "Set up and check company sign-in", "href": "/settings/all#settings-signin-guide"}})


def entries():
    return (
        Adapter("automations.connected.configure", "Set up a connected-app automation", "schedules", "/automations#auto-event-form",
            ("/automations", "/connections", "/tasks"), EmptyInput, event_snapshot, event_prepare,
            aliases=("watch SharePoint", "watch Salesforce", "watch ServiceNow", "watch Teams", "connected event source")),
        Adapter("settings.company_signin.configure", "Set up and check company sign-in", "preferences", "/settings/all#settings-signin-guide",
            ("/settings", "/settings/all", "/users"), EmptyInput, signin_snapshot, signin_prepare,
            aliases=("try company sign-in", "SSO setup", "test provider login")),
    )
