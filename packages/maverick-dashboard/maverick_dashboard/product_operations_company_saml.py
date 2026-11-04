"""Copilot opens the same complete protected single-sign-on setup form."""
from __future__ import annotations

from maverick.governed_operations import digest

from . import company_saml_setup
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, _selection):
    value = company_saml_setup.catalog(request)
    return Snapshot(digest(value), "Current single-sign-on setup and installed readiness", value["runtime"]["message"],
                    {"company_saml_setup": {"context": value["context"], "original": False}})


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    context, _owner = company_saml_setup.authority(request)
    return Preview(current.summary + " Upload and review provider files in the protected native form. "
                   "Save inactive setup, try a real sign-in, grant a role separately and explicitly review activation. This handoff changes nothing.",
                   native={"company_saml_setup": {"context": context, "original": False},
                           "open": {"label": "Set up single sign-on", "href": "/settings/all#company-saml-setup"}})


def entries():
    return (Adapter("settings.single_signon.configure", "Set up single sign-on", "preferences", "/settings/all#company-saml-setup",
                    ("/settings", "/settings/all", "/users"), EmptyInput, snapshot, prepare,
                    aliases=("SAML setup", "upload identity provider metadata", "try single sign-on")),)
