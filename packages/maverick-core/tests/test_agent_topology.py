"""Agent reachability, MCP inventory, and blast-radius governance."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import agent_topology as topology
from maverick import config, domain, entity_graph, mcp_client
from maverick import model_risk_assurance as mra


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[entity_graph]\n"
        "enable = true\n"
        "\n[evidence_graph]\n"
        "enable = true\n"
        "\n[model_risk_assurance]\n"
        "enable = true\n"
        "gate_promotions = true\n"
        "\n[agent_topology]\n"
        "enable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture
def _configured(monkeypatch):
    profiles = {
        "risk_agent": domain.DomainProfile(
            name="risk_agent",
            compartment="risk",
            allow_tools=["read_file", "http_fetch"],
            deny_tools=["shell"],
            max_risk="medium",
            allow_paths=["C:/tenant/reports"],
            allow_hosts=["api.example.com"],
            mcp_servers=["vendor_api", "local_scanner"],
            models={"default": "provider:model-v1"},
            knowledge_sources=["risk-policy"],
        ),
        "legal_agent": domain.DomainProfile(
            name="legal_agent",
            allow_tools=["read_file"],
            mcp_servers=["vendor_api"],
        ),
        "isolated_agent": domain.DomainProfile(
            name="isolated_agent",
            allow_tools=["read_file"],
        ),
    }
    specs = [
        mcp_client.MCPServerSpec(
            name="vendor_api",
            url="https://mcp.example.test/private/path?tenant=secret",
            auth_token="DO-NOT-EXPOSE",
            headers={"X-Tenant-Secret": "DO-NOT-EXPOSE"},  # pragma: allowlist secret
        ),
        mcp_client.MCPServerSpec(
            name="local_scanner",
            command="C:/tenant/private/tools/scanner.exe",
            args=["--private-path", "C:/tenant/raw"],
            env={"SCANNER_SECRET": "DO-NOT-EXPOSE"},  # pragma: allowlist secret
            pin_sha256=_hex("scanner-binary"),
        ),
    ]
    monkeypatch.setattr(domain, "enabled_domains", lambda: profiles)
    monkeypatch.setattr(mcp_client, "load_mcp_specs_from_config", lambda: specs)
    monkeypatch.setattr(
        entity_graph,
        "neighborhood",
        lambda kind, name, depth=2: {
            "enabled": True,
            "found": True,
            "entity": {"kind": kind, "name": name},
            "nodes": [{"kind": kind, "name": name}],
            "edges": [],
            "depth": depth,
        },
    )
    return profiles, specs


def test_agent_view_shows_transitive_reachability_and_every_trust_boundary(_configured):
    view = topology.agent_view("risk_agent")
    assert view["found"] is True
    node_ids = {node["id"] for node in view["nodes"]}
    assert {
        "agent:risk_agent",
        "tool:read_file",
        "mcp_server:vendor_api",
        "endpoint:https://mcp.example.test",
        "data_endpoint:api.example.com",
        "knowledge_source:risk-policy",
        "model:provider:model-v1",
    } <= node_ids
    assert {
        "capability_allowlist",
        "external_mcp",
        "network",
        "process",
        "egress_allowlist",
        "filesystem_capability",
        "retrieval_boundary",
        "model_provider",
    } <= set(view["trust_boundaries"])
    assert view["operational_lineage"]["depth"] == 4

    serialised = json.dumps(view)
    assert "DO-NOT-EXPOSE" not in serialised
    assert "/private/path" not in serialised
    assert "C:/tenant/raw" not in serialised
    assert "scanner.exe" in serialised


def test_mcp_blast_radius_lists_affected_agents_and_downstream_endpoint(_configured):
    radius = topology.blast_radius("mcp_server", "vendor_api")
    assert radius["found"] is True
    assert [row["agent"] for row in radius["affected_agents"]] == [
        "legal_agent",
        "risk_agent",
    ]
    assert {node["id"] for node in radius["downstream"]} == {
        "endpoint:https://mcp.example.test",
    }
    assert radius["affected_count"] == 2


def test_wildcard_allowed_host_is_projected_and_queryable(_configured):
    """Shipped packs list hosts as fnmatch globs; one must not break the view."""
    profiles, _specs = _configured
    profiles["legal_agent"].allow_hosts = ["*.stripe.com"]

    view = topology.agent_view("legal_agent")
    assert "data_endpoint:*.stripe.com" in {node["id"] for node in view["nodes"]}
    # Every profile is projected for any query, so this used to fail here too.
    assert topology.blast_radius("mcp_server", "vendor_api")["affected_count"] == 2
    radius = topology.blast_radius("data_endpoint", "*.stripe.com")
    assert [row["agent"] for row in radius["affected_agents"]] == ["legal_agent"]


def test_sync_promotes_mcp_servers_to_safe_governed_inventory(_configured):
    first = topology.sync_mcp_inventory(actor="topology-operator")
    second = topology.sync_mcp_inventory(actor="topology-operator")
    assert first["count"] == 2
    assert second == first

    officer = mra.ModelRiskAssuranceOfficer()
    rows = {
        row["identity"]["source_id"]: row
        for row in officer.list_inventory()
        if row["identity"]["source"] == topology.MCP_INVENTORY_SOURCE
    }
    assert set(rows) == {"local_scanner", "vendor_api"}
    assert all(row["identity"]["asset_type"] == "tool" for row in rows.values())
    assert rows["local_scanner"]["metadata"]["supply_chain_status"] == "pinned"
    assert rows["vendor_api"]["metadata"]["supply_chain_status"] == "unpinned"
    assert rows["vendor_api"]["metadata"]["endpoint"] == "https://mcp.example.test"
    assert rows["vendor_api"]["metadata"]["referencing_agents"] == [
        "legal_agent",
        "risk_agent",
    ]
    serialised = json.dumps(rows)
    assert "DO-NOT-EXPOSE" not in serialised
    assert "X-Tenant-Secret" not in serialised
    assert "SCANNER_SECRET" not in serialised
    assert "C:/tenant/raw" not in serialised


def test_agent_names_lists_configured_agents(_configured):
    names = topology.agent_names()
    assert "risk_agent" in names
    assert names == sorted(names)


def test_unknown_agent_and_unsupported_blast_kind_fail_honestly(_configured):
    missing = topology.agent_view("missing_agent")
    assert missing == {
        "schema": topology.TOPOLOGY_SCHEMA,
        "found": False,
        "agent": "missing_agent",
        "nodes": [],
        "edges": [],
        "operational_lineage": None,
    }
    with pytest.raises(ValueError, match="unsupported"):
        topology.blast_radius("person", "someone")


def test_feature_gate_is_strict(tmp_path):
    (tmp_path / "config.toml").write_text(
        "[entity_graph]\nenable = true\n"
        "[evidence_graph]\nenable = true\n"
        "[model_risk_assurance]\nenable = true\n"
        "[agent_topology]\nenable = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert topology.enabled() is False
    with pytest.raises(topology.AgentTopologyConfigError, match="requires"):
        topology.agent_view("risk_agent")
    with pytest.raises(topology.AgentTopologyConfigError, match="requires"):
        topology.agent_names()
