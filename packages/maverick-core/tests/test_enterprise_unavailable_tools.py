"""Admins can learn which connector tools Enterprise mode refuses.

While the hand-written connectors still read operator-global environment
credentials, a signed-in person's task cannot run them in Enterprise mode
(``_ambient_credential_denial``). ``enterprise_unavailable_tool_names`` states
the same rule ahead of time so the Tools page can say so before rollout.
"""
from __future__ import annotations

import asyncio

from maverick.tools import (
    AUTHENTICATED_AMBIENT_CRED_TOOL_NAMES,
    Tool,
    ToolRegistry,
    _ambient_credential_denial,
    enterprise_unavailable_tool_names,
)


def test_nothing_is_unavailable_when_enterprise_mode_is_off(monkeypatch):
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)

    assert enterprise_unavailable_tool_names() == frozenset()


def test_named_flagship_connectors_are_unavailable_in_enterprise_mode(monkeypatch):
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)

    names = enterprise_unavailable_tool_names()

    for flagship in (
        "salesforce", "servicenow", "workday", "sap", "msgraph", "slack_bot",
        "jira", "confluence", "snowflake",
    ):
        assert flagship in names
    # Ordinary tools and the principal-scoped generic REST connectors stay usable.
    for usable in ("read_file", "http_fetch", "web_search", "zapier"):
        assert usable not in names


def test_listing_matches_what_a_signed_in_call_is_actually_refused(monkeypatch):
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    listed = enterprise_unavailable_tool_names()

    for name in AUTHENTICATED_AMBIENT_CRED_TOOL_NAMES | {"read_file", "zapier"}:
        refused = _ambient_credential_denial(name, "user:alice") is not None
        assert (name in listed) is refused, name


def test_listing_agrees_with_the_registry_refusal_end_to_end(monkeypatch):
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    reg = ToolRegistry(principal="user:alice")
    reg.register(Tool(
        name="salesforce", description="bespoke connector",
        input_schema={"type": "object", "properties": {}},
        fn=lambda _args: "borrowed operator credential",
    ))

    assert "salesforce" in enterprise_unavailable_tool_names()
    assert asyncio.run(reg.run("salesforce", {})).startswith("REFUSED (credentials)")
