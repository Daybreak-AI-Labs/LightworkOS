"""Tool usability is the conjunction of explicit prerequisites."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _ready_row(name: str, **overrides):
    from maverick_dashboard.app import _tool_permission_row

    inputs = {
        "catalog_present": True,
        "base_acl_allowed": True,
        "provider_status": "ready",
        "connection_status": "ready",
        "feature_policy_status": "ready",
        "sandbox_status": "ready",
        "sandbox_constructed": True,
    }
    inputs.update(overrides)
    return _tool_permission_row(name, **inputs)


@pytest.mark.parametrize(
    ("dimension", "overrides"),
    (
        ("provider", {"provider_status": "blocked"}),
        ("connection", {"connection_status": "blocked"}),
        ("feature_policy", {"feature_policy_status": "blocked"}),
        ("base_acl", {"base_acl_allowed": False}),
        (
            "sandbox",
            {"sandbox_status": "blocked", "sandbox_constructed": False},
        ),
    ),
)
def test_each_unready_prerequisite_independently_blocks_usability(
    dimension: str,
    overrides: dict,
) -> None:
    row = _ready_row(f"blocked-{dimension}", **overrides)

    assert row["prerequisites"][dimension]["status"] == "blocked"
    assert dimension in row["unready_dimensions"]
    assert row["usable"] is False
    assert row["enabled"] is False
    assert row["state"] in {"policy_blocked", "prerequisite_blocked"}


def test_undeclared_dependencies_are_unknown_and_never_usable() -> None:
    from maverick_dashboard.app import _tool_permission_row

    row = _tool_permission_row(
        "registered-without-dependency-metadata",
        catalog_present=True,
        base_acl_allowed=True,
        sandbox_constructed=True,
    )

    for dimension in ("provider", "connection", "feature_policy", "sandbox"):
        assert row["prerequisites"][dimension]["status"] == "unknown"
        assert row["prerequisites"][dimension]["ready"] is None
    assert row["policy_allowed"] is True
    assert row["sandbox_constructed"] is True
    assert row["sandbox_ready"] is None
    assert row["state"] == "readiness_unknown"
    assert row["usable"] is False
    assert row["enabled"] is False


def test_tool_is_usable_only_when_every_prerequisite_is_explicitly_ready() -> None:
    row = _ready_row("fully-ready")

    assert all(
        evidence["status"] == "ready"
        for evidence in row["prerequisites"].values()
    )
    assert row["unready_dimensions"] == []
    assert row["policy_allowed"] is True
    assert row["usable"] is True
    assert row["enabled"] is True
    assert row["state"] == "usable"


def test_permissions_api_and_page_never_claim_blocked_tools_are_usable(
    monkeypatch,
) -> None:
    from maverick_dashboard import app as dashboard_app

    rows = [
        _ready_row("provider-blocked", provider_status="blocked"),
        _ready_row("connection-blocked", connection_status="blocked"),
        _ready_row("feature-blocked", feature_policy_status="blocked"),
        _ready_row("base-acl-blocked", base_acl_allowed=False),
        _ready_row(
            "sandbox-blocked",
            sandbox_status="blocked",
            sandbox_constructed=False,
        ),
    ]
    snapshot = {
        "tools": rows,
        "capabilities": {},
        "channels": [],
        "sandbox": {},
        "budget": {},
        "network": "deny",
        "plugins": [],
        "providers": [],
        "provider_states": [],
        "retention": {},
        "overlay_denied": [],
        "error": None,
        "sandbox_warning": None,
    }
    monkeypatch.setattr(dashboard_app, "_permissions_snapshot", lambda: snapshot)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = TestClient(dashboard_app.app, base_url="http://127.0.0.1")

    api_response = client.get("/api/v1/permissions")
    page_response = client.get("/permissions")

    assert api_response.status_code == 200
    api_rows = api_response.json()["tools"]
    assert len(api_rows) == 5
    assert not any(row["usable"] or row["enabled"] for row in api_rows)
    assert page_response.status_code == 200
    assert page_response.text.count('data-tool-usable="false"') == 5
    assert 'data-tool-usable="true"' not in page_response.text
    assert 'data-provider-state="blocked"' in page_response.text
    assert 'data-connection-state="blocked"' in page_response.text
    assert 'data-feature-policy-state="blocked"' in page_response.text
    assert 'data-base-acl-state="blocked"' in page_response.text
    assert 'data-sandbox-state="blocked"' in page_response.text
    assert "Available to attempt" not in page_response.text
