"""Write-capable connectors fail safe to high risk.

Enterprise connectors mutate external business state (CRM/ERP records,
payments, payroll), provision infrastructure, manage secrets/identity, or run
remote code/SQL. If anything unclassified defaulted to ``medium``, a
``max_risk="medium"`` ceiling (and governance gates keyed on risk) would
silently admit them. Instead:

* the long-tail REST/GraphQL connectors (``enterprise_connectors.py``) are
  resolved by name from the spec list -> high, so new connectors are covered
  automatically;
* the dedicated-module connectors (salesforce, jira, servicenow, snowflake,
  ...) are listed in ``_DEFAULT_RISK`` as high.

A config override still wins, so a trusted connector can be relaxed.
"""
from __future__ import annotations

import importlib

import pytest


def _write_config(tmp_path, body: str = "") -> None:
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.toml").write_text(body)
    import maverick.config as cfg_mod
    importlib.reload(cfg_mod)


@pytest.fixture()
def _home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _write_config(tmp_path)  # no overrides
    return tmp_path


# --- the systematic rule: every enterprise connector spec is high -----------

def test_every_enterprise_connector_is_high(_home):
    from maverick.safety.tool_risk import tool_risk
    from maverick.tools.enterprise_connectors import ENTERPRISE_CONNECTOR_NAMES
    assert ENTERPRISE_CONNECTOR_NAMES, "expected a non-empty connector list"
    not_high = [n for n in ENTERPRISE_CONNECTOR_NAMES if tool_risk(n) != "high"]
    assert not_high == [], f"these connectors are not high: {not_high}"


def test_sample_enterprise_connectors_high(_home):
    from maverick.safety.tool_risk import tool_risk
    for n in ("okta", "paypal", "kubernetes", "vault", "workday", "zendesk"):
        assert tool_risk(n) == "high", n


# --- dedicated-module connectors --------------------------------------------

def test_dedicated_connectors_high(_home):
    from maverick.safety.tool_risk import tool_risk
    for n in (
        "salesforce", "jira", "servicenow", "snowflake", "oracle", "sap",
        "workday", "database", "bigquery", "http_fetch", "notebook_exec",
        "plaid", "truelayer",
        "notion", "databricks", "learn_capability", "gdrive", "msgraph",
    ):
        assert tool_risk(n) == "high", n


# --- precision: read-only / unknown stay put --------------------------------

def test_readonly_and_unknown_stay_medium(_home):
    from maverick.safety.tool_risk import tool_risk, tool_risk_is_classified
    # Reviewed medium-risk tools (bounded goal-local memory) stay medium.
    for n in ("kv_memory", "remember_outcome_key"):
        assert tool_risk(n) == "medium", n
    # bitbucket/translate/wolfram used to sit here as "pure lookups", but they
    # exchange credentials with and dispatch data to an external service, so
    # they are deliberately classified high now.
    for n in ("bitbucket", "translate", "wolfram"):
        assert tool_risk(n) == "high", n
    # An unrecognized name no longer slips under a medium ceiling: it fails
    # safe to high, without being marked as intentionally classified.
    assert tool_risk("some_unknown_tool") == "high"
    assert tool_risk_is_classified("some_unknown_tool") is False


def test_builtin_classifications_unaffected(_home):
    from maverick.safety.tool_risk import tool_risk
    assert tool_risk("shell") == "high"
    assert tool_risk("read_file") == "low"
    assert tool_risk("mcp_x__y") == "high"  # MCP rule still applies


def test_open_banking_connectors_exceed_medium_ceiling(_home):
    from maverick.safety.tool_risk import tools_exceeding
    assert tools_exceeding(["plaid", "truelayer"], "medium") == {
        "plaid", "truelayer",
    }


# --- overrides still win over the connector defaults ------------------------

def test_override_relaxes_connector(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _write_config(tmp_path, '\n'.join([
        "[security.tool_risk]",
        'salesforce = "low"',   # dedicated-module connector relaxed
        'okta = "medium"',      # long-tail enterprise connector relaxed
    ]))
    from maverick.safety.tool_risk import tool_risk
    assert tool_risk("salesforce") == "low"
    assert tool_risk("okta") == "medium"
    assert tool_risk("jira") == "high"  # untouched connector still high
