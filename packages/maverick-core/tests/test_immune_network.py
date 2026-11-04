"""Composition-risk discovery over agent graphs and the real pack roster."""
from __future__ import annotations

import pytest
from maverick.immune import network as n


@pytest.fixture(autouse=True)
def _container_sandbox(monkeypatch):
    """Model `shell` as a pure state-changing tool: a container sandbox with no
    network. (On the default `local` backend it can also reach outside.)"""
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda: {"sandbox": {"backend": "docker"}})


def _g(agents, flows=()):
    return n.load_graph({"agents": agents, "flows": [list(f) for f in flows]})


def test_classify_uses_explicit_tables_and_risk():
    assert n.classify("knowledge_search") == {n.SENSITIVE}
    assert n.classify("web_search") == {n.EXTERNAL}
    assert n.classify("email") == {n.EXTERNAL, n.MUTATE}
    assert n.classify("shell") == {n.MUTATE}
    assert n.classify("spawn_subagent") == frozenset()  # a flow, not a power
    assert n.classify("mcp_remote__anything") == {n.SENSITIVE, n.MUTATE, n.EXTERNAL}


def test_single_agent_rule_of_two_is_clean():
    # Two of three is allowed; nothing reaches outside, so no finding.
    assert n.findings(_g({"a": ["knowledge_search", "shell"]})) == []


def test_chain_of_individually_clean_agents_is_a_trifecta():
    g = _g({"reader": ["knowledge_search"], "writer": ["shell"], "mailer": ["web_search"]},
           [("reader", "writer"), ("writer", "mailer")])
    (f,) = n.findings(g)
    assert f.kind == "trifecta"
    assert f.path == ("reader", "writer", "mailer")
    assert f.witness == {n.SENSITIVE: ("reader", "knowledge_search"),
                         n.MUTATE: ("writer", "shell"),
                         n.EXTERNAL: ("mailer", "web_search")}
    assert f.sink_risk == "low"


def test_flow_direction_matters():
    g = _g({"reader": ["knowledge_search"], "mailer": ["web_search"]}, [("mailer", "reader")])
    assert n.findings(g) == []
    g = _g({"reader": ["knowledge_search"], "mailer": ["web_search"]}, [("reader", "mailer")])
    (f,) = n.findings(g)
    assert (f.kind, f.path) == ("exfiltration", ("reader", "mailer"))


def test_witness_prefers_least_guarded_sink():
    (f,) = n.findings(_g({"a": ["knowledge_search", "email", "web_search"]}))
    assert f.witness[n.EXTERNAL] == ("a", "web_search")


def test_blast_radius_counts_downstream_agents():
    g = _g({"a": [], "b": [], "c": []}, [("a", "b"), ("b", "c")])
    assert n.blast_radius(g) == {"a": 2, "b": 1, "c": 0}


def test_load_graph_rejects_unknown_agents():
    with pytest.raises(ValueError, match="unknown agents"):
        n.load_graph({"agents": {"a": []}, "flows": [["a", "ghost"]]})


_DIALS = ("MAVERICK_WORKFORCE_LEVELS", "MAVERICK_WORKFORCE_DATA_GROUNDING")


def test_what_if_dials_never_touch_the_process_environment(monkeypatch):
    """A what-if check passes its dials to the capability builder: the
    environment every running agent reads is never written."""
    import os

    from maverick.domain import available_domains
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "0")
    monkeypatch.delenv("MAVERICK_WORKFORCE_DATA_GROUNDING", raising=False)
    writes: list[str] = []
    real_putenv, real_unsetenv = os.putenv, os.unsetenv
    monkeypatch.setattr(os, "putenv", lambda k, v: (writes.append(k), real_putenv(k, v)))
    monkeypatch.setattr(os, "unsetenv", lambda k: (writes.append(k), real_unsetenv(k)))
    profile = available_domains()["aero_airworthiness"]
    assert "calendar" in n.runtime_tools(profile, levels=True, grounding=True)
    n.roster_graph({"aero_airworthiness": profile}, levels=True, grounding=False)
    assert not [k for k in writes if k in _DIALS]
    assert os.environ["MAVERICK_WORKFORCE_LEVELS"] == "0"
    assert "MAVERICK_WORKFORCE_DATA_GROUNDING" not in os.environ
    # The deployment's own dial is untouched: live agents still see levels off.
    assert "calendar" not in n.runtime_tools(profile)


def test_runtime_capability_is_what_gets_audited():
    """The runtime expansion (autonomy levels) must be visible to the audit:
    the pack TOML never lists calendar, the runtime capability does."""
    from maverick.domain import available_domains
    profile = available_domains()["aero_airworthiness"]
    assert "calendar" not in profile.allow_tools
    assert "calendar" not in n.runtime_tools(profile, levels=False, grounding=False)
    assert "calendar" in n.runtime_tools(profile, levels=True, grounding=False)


def test_swarm_hub_connects_every_member():
    from maverick.domain import available_domains
    domains = {k: v for k, v in available_domains().items() if k.startswith("aero_")}
    g = n.roster_graph(domains, swarm=True, levels=False, grounding=False)
    assert n.blast_radius(g)["orchestrator"] == len(domains)


def test_pack_audit_reports_runtime_expansion(monkeypatch):
    from maverick.domain import available_domains
    from maverick.domain_audit import audit_profile
    profile = available_domains()["aero_airworthiness"]
    # The pack audit reads the deployment's own dials.
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "0")
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "0")
    assert audit_profile(profile).runtime_expansion == []
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "1")
    assert audit_profile(profile).runtime_expansion == ["calendar", "email", "notify"]


def test_an_unset_dial_keeps_the_deployment_setting(monkeypatch):
    from maverick.domain import available_domains
    profile = available_domains()["aero_airworthiness"]
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "1")
    # levels not given: the deployment's "on" applies; given, it wins for this call only.
    assert "calendar" in n.runtime_tools(profile, grounding=False)
    assert "calendar" not in n.runtime_tools(profile, levels=False, grounding=False)
    import os
    assert os.environ["MAVERICK_WORKFORCE_LEVELS"] == "1"
