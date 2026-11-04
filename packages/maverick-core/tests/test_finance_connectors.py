"""Finance long-pole + cross-suite connector gap-fill (enterprise_connectors).

The 182-connector long tail already covered most SaaS; this batch fills the
vendor systems the suites referenced but lacked -- weighted to the finance towers
(banking/treasury, AP/spend, tax, close/EPM, equity). Each must build into a
confirm-gated, high-risk REST tool, and the hand-assigned auth modes (Basic /
raw-header / custom-scheme) must be wired correctly (verified at the spec level,
so no httpx/network needed; make_rest_tool's auth machinery is covered in
test_enterprise_connectors)."""
from __future__ import annotations

from maverick.safety.tool_risk import tool_risk
from maverick.tools.enterprise_connectors import (
    _SPECS,
    ENTERPRISE_CONNECTOR_NAMES,
    enterprise_connectors,
)

_NEW = [
    "modern_treasury", "mercury", "wise", "airbase", "navan", "pleo", "avalara",
    "vertex_tax", "floqast", "pigment", "planful", "carta", "ironclad",
    "contractbook", "clio", "hibob", "lattice", "launchdarkly", "split",
    "samsara", "easypost", "flexport", "shippo", "crunchbase", "secureframe",
    "zuora", "chargebee", "recurly", "gocardless", "freshbooks",
]


def _spec(name: str) -> dict:
    return next(s for s in _SPECS if s["name"] == name)


def test_new_connectors_registered_unique_and_high_risk():
    names = [t.name for t in enterprise_connectors()]
    for n in _NEW:
        assert n in ENTERPRISE_CONNECTOR_NAMES, n
        assert names.count(n) == 1, f"{n} not unique"
        assert tool_risk(n) == "high", f"{n} should be high-risk (write-capable connector)"


def test_finance_long_pole_towers_are_covered():
    # The towers the finance-agent-suite §9 flagged as unstubbed: banking/treasury,
    # AP/spend, tax, close/EPM, equity -- each now has a credential-ready connector.
    for n in ("modern_treasury", "avalara", "carta", "floqast", "airbase", "planful"):
        assert n in ENTERPRISE_CONNECTOR_NAMES


def test_non_default_auth_modes_are_wired():
    # Basic auth (API key, or account:key / org:key as user:pass).
    for n in ("modern_treasury", "avalara", "hibob", "easypost", "chargebee", "recurly"):
        assert _spec(n).get("basic") is True, f"{n} should be Basic auth"
    # Raw token in Authorization (no Bearer scheme).
    assert _spec("launchdarkly").get("scheme") == ""
    # Custom auth header, raw token.
    assert _spec("crunchbase").get("token_header") == "X-cb-user-key"
    assert _spec("crunchbase").get("scheme") == ""
    # Custom scheme word.
    assert _spec("shippo").get("scheme") == "ShippoToken"


def test_every_new_spec_has_explicit_env_auth():
    # House rule: no ambient creds -- every connector names its base_url + token env
    # and documents itself for the operator.
    for n in _NEW:
        s = _spec(n)
        assert s["base_url_env"] and s["token_env"] and s["description"], n
        assert s["base_url_env"].endswith("_BASE_URL") and s["token_env"].endswith("_TOKEN"), n
