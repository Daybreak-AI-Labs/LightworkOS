"""Read-only connector bridge: a GET-only, LOW-risk variant of a vendor connector
that a read-only finance pack can actually reach -- closing the pack<->connector
gap surfaced in test_fleet_spine, without handing a read-only seat a write-capable
tool. Reference slice: modern_treasury_read -> finance_treasury / finance_cashflow."""
from __future__ import annotations

from maverick.capability import Capability
from maverick.domain import builtin_dir, domain_capability, load_domains
from maverick.safety.tool_risk import tool_risk
from maverick.tools.enterprise_connectors import (
    ENTERPRISE_CONNECTOR_NAMES,
    READ_CONNECTOR_NAMES,
    enterprise_connectors,
)


def _tools() -> dict:
    return {t.name: t for t in enterprise_connectors()}


def test_read_connector_is_registered_low_and_get_only():
    tools = _tools()
    assert "modern_treasury_read" in tools
    assert "modern_treasury_read" in READ_CONNECTOR_NAMES
    # a read seat is LOW -- not auto-classified high like the write connectors,
    # so it passes a read-only pack's ceiling
    assert tool_risk("modern_treasury_read") == "low"
    assert "modern_treasury_read" not in ENTERPRISE_CONNECTOR_NAMES
    # GET-only schema (the model can't even express a write)
    assert tools["modern_treasury_read"].input_schema["properties"]["op"]["enum"] == ["get"]


def test_read_connector_blocks_unapproved_modern_treasury_paths_before_auth():
    fn = _tools()["modern_treasury_read"].fn

    blocked_paths = (
        "/api/payment_orders/po_sensitive_123?include=counterparty,internal_account,bank_details",
        "/api/counterparties",
        "/api/ledger_accounts",
    )
    for path in blocked_paths:
        out = fn({"path": path})
        assert "read path is not allowed" in out
        assert "Allowed prefixes" in out


def test_read_connector_blocks_dot_segment_allowlist_bypasses_before_auth():
    fn = _tools()["modern_treasury_read"].fn

    blocked_paths = (
        "/api/internal_accounts/../counterparties",
        "/api/transactions/../payment_orders",
        "/api/internal_accounts/%2e%2e/counterparties",
        "/api/internal_accounts%2f..%2fcounterparties",
        "/api/internal_accounts/./counterparties",
    )
    for path in blocked_paths:
        out = fn({"path": path})
        assert "read path is not allowed" in out
        assert "Allowed prefixes" in out
        assert "requires MODERN_TREASURY_BASE_URL" not in out


def test_read_connector_advertises_cash_positioning_allowlist():
    tool = _tools()["modern_treasury_read"]

    assert "/api/internal_accounts" in tool.description
    assert "/api/transactions" in tool.description
    assert "/api/ledger_account_balances" in tool.description
    assert "/api/counterparties" not in tool.description


def test_read_connector_refuses_writes_while_the_write_seat_stays_high():
    fn = _tools()["modern_treasury_read"].fn
    for op in ("post", "put", "patch", "delete"):
        out = fn({"op": op, "path": "/api/payment_orders", "confirm": True})
        assert "read-only" in out, f"{op} should be refused by the read seat"
        assert "DRY RUN" not in out  # refused outright, not just write-gated
    # the paired write connector keeps full capability and stays high-risk
    assert tool_risk("modern_treasury") == "high"


def test_treasury_packs_can_now_reach_the_executable_read_seat():
    parent = Capability(principal="agent:finance_controller-0", max_risk="high")
    for pack in ("finance_treasury", "finance_cashflow"):
        prof = load_domains(builtin_dir())[pack]
        cap = domain_capability(prof, parent, f"agent:{pack}-1")
        # the read seat is reachable under the pack's read-only ceiling...
        assert cap.permits("modern_treasury_read"), pack
        # ...while the write connector is dropped and the money seal holds
        assert not cap.permits("modern_treasury"), pack
        assert not cap.permits("wire_transfer"), pack
