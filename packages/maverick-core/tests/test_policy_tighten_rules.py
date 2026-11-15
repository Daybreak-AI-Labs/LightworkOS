"""Every tighten-only key, loaded through ``load_config`` with a tenant overlay.

For each ruled key: a stricter tenant value takes effect; a looser one does
not and is reported once; with the organisation silent, the consumer's own
default is the bar on both sides.
"""
from __future__ import annotations

import json
import logging

import pytest
from maverick.policy_tighten import TENANT_RULES


def _prot(default: bool):  # a protection: may only turn on
    return dict(os=False, s=True, ol=True, l=False, us=None if default else True, ul=False if default else None)


def _perm(default: bool):  # a permission: may only turn off
    return dict(os=True, s=False, ol=False, l=True, us=False if default else None, ul=None if default else True)


_DEFAULT_KEYS = ["budget.max_dollars", "governance.*", "plugins.*", "safety.*"]
CASES = {
    "governance.deny_actions": dict(os=["shell"], s=["shell", "browser"], l=[], us=["shell"]),
    "governance.require_human_actions": dict(os=["shell"], s=["shell", "browser"], l=[], us=["shell"]),
    "governance.deny_min_risk": dict(os="medium", s="low", l="high", us="high"),
    "governance.require_human_min_risk": dict(os="medium", s="low", l="high", us="high"),
    "governance.deny_above": dict(os=100, s=50, l=500, us=10),
    "governance.require_human_above": dict(os=100, s=50, l=500, us=10),
    "governance.require_fresh_human_approval": _prot(False),
    "governance.profile": dict(os="standard", s="regulated", l="essentials", us="standard"),
    "safety.profile": dict(os="balanced", s="strict", l="permissive", us="strict", ul="permissive"),
    "safety.block_threshold": dict(os="high", s="medium", l="critical", us="medium", ul="critical"),
    "safety.scan_input": _prot(True),
    "safety.scan_tool_calls": _prot(True),
    "safety.scan_output": _prot(True),
    "safety.constitution": dict(os=["a"], s=["a", "b"], l=[], us=["b"]),
    "safety.compartments": _prot(False),
    "safety.compartment_unseal": dict(os="orchestrator", s="human", l="both", us=None, ul="both"),
    "safety.require_shield": _prot(False),
    "safety.consent_mode": dict(os="dashboard", s="ask", l="auto-approve", us="ask", ul="auto-approve"),
    "safety.review_checkpoint": dict(os={"dollars": 10}, s={"dollars": 5}, l={"dollars": 20},
                                     us={"dollars": 5}),
    "safety.max_scan_chars": dict(os=262144, s=100000, l=5000000, us=100000, ul=50000000),
    "safety.supply_chain_pinning": _prot(False),
    "safety.cascade": _prot(False),
    "safety.decode_hidden": _prot(True),
    "safety.shield_rate_limit": dict(os="100/60", s="50/60", l="200/60", us="50/60"),
    "safety.quorum_required": dict(os=2, s=3, l=1, us="2"),
    "safety.quorum_protected_keys": dict(os=["governance.*", "safety.*"], s=["governance.*", "safety.*", "x.*"],
                                         l=["safety.*"], us=[*_DEFAULT_KEYS, "x.*"], ul=["plugins.*"]),
    "safety.quorum_ttl_days": dict(os=5, s=3, l=7, us=3, ul=30),
    "safety.goal_risk_floor": dict(os="medium", s="high", l="low", us="medium"),
    "safety.goal_risk_require_human": dict(os="high", s="medium", l="never", us="high"),
    **{f"capabilities.{name}": _perm(False) for name in (
        "computer_use", "browser", "web_search", "mobile_tools", "ros", "code_exec")},
    "capabilities.enforce": _prot(False),
    "capabilities.per_call_tokens": _prot(False),
    "capabilities.per_call_token_ttl": dict(os=30, s=10, l=60, us=10, ul=86400),
    "sandbox.backend": dict(os="docker", s="gvisor", l="local", us="docker"),
    "sandbox.network_policy": dict(os="allowlist", s="deny-all", l="open", us="deny-all"),
    "sandbox.network": dict(os="egress-allow", s="egress-deny", ol="egress-deny", l="egress-allow",
                            us=None, ul="egress-allow"),
    "sandbox.host_key_checking": dict(os="accept-new", s="yes", l="no", us="yes", ul="no"),
    "sandbox.require_container": _prot(False),
    "sandbox.firecracker_strict": _prot(True),
    **{f"sandbox.{name}": _perm(False) for name in (
        "allow_network", "allow_root", "reuse_container", "cross_run_pool")},
    "sandbox.pids_limit": dict(os=256, s=128, l=1024, us=256, ul=1000000),
    "sandbox.memory": dict(os="2g", s="1g", l="8g", us="2g", ul="16g"),
    "sandbox.memory_mb": dict(os=2048, s=1024, l=4096, us=1024),
    "sandbox.cpus": dict(os=2, s=1, l=4, us=1),
    "sandbox.long_command_timeout": dict(os=600, s=300, l=1200, us=300, ul=86400),
    "sandbox.timeout": dict(os=60, s=30, l=120, us=30, ul=120),
    "security.allowed_tools": dict(os=["a", "b"], s=["a"], l=[], us=["a"]),
    "security.denied_tools": dict(os=["shell"], s=["shell", "x"], l=[], us=["shell"]),
    "security.max_risk": dict(os="medium", s="low", l="high", us="medium"),
    "security.channels": dict(os={"slack": {"denied_tools": ["shell"]}},
                              s={"slack": {"denied_tools": ["shell", "x"]}},
                              l={"slack": {"denied_tools": []}}, us={"slack": {"max_risk": "low"}}),
    "security.users": dict(os={"tg:1": {"denied_tools": ["shell"]}},
                           s={"tg:1": {"denied_tools": ["shell", "x"]}},
                           l={"tg:1": {"denied_tools": []}}, us={"tg:1": {"max_risk": "low"}}),
    "security.network_policy": dict(os="allowlist", s="deny-all", l="open", us="deny-all"),
    "security.approvals_required": dict(os=2, s=3, l=1, us=2),
    "security.approvals_required_by_risk": dict(os={"high": 2}, s={"high": 3}, l={"high": 1},
                                                us={"high": 2}),
    "security.tool_risk": dict(os={"web_search": "medium"}, s={"web_search": "high"},
                               l={"web_search": "low"}, us={"read_file": "high"}, ul={"shell": "low"}),
    "security.auto_fix": _perm(False),
    "security.isolate_parsers": _prot(False),
    "security.secure_defaults": _prot(True),
}


def test_every_ruled_key_has_a_case():
    ruled = {f"{section}.{key}" for section, keys in TENANT_RULES.items() for key in keys}
    assert ruled == set(CASES)


def _toml(value) -> str:
    if isinstance(value, dict):
        return "{" + ", ".join(f"{json.dumps(k)} = {_toml(v)}" for k, v in value.items()) + "}"
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(value)


@pytest.fixture
def load(tmp_path, monkeypatch, caplog):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    tenant_path = tmp_path / "tenants" / "acme" / "config.toml"
    tenant_path.parent.mkdir(parents=True)

    def run(key, org, tenant):
        section, name = key.split(".", 1)
        org_text = f"[{section}]\n{name} = {_toml(org)}\n" if org is not None else ""
        (tmp_path / "config.toml").write_text(org_text, encoding="utf-8")
        tenant_path.write_text(f"[{section}]\n{name} = {_toml(tenant)}\n", encoding="utf-8")
        config.reset_config_cache()
        config._LOOSENING_LOGGED.clear()
        caplog.clear()
        monkeypatch.setenv("MAVERICK_TENANT", "acme")
        with caplog.at_level(logging.WARNING, logger="maverick.config"):
            merged = config.load_config().get(section, {})
            config.load_config()
        reported = key in config.tenant_ignored_settings()
        warnings = [r for r in caplog.records if "cannot loosen" in r.getMessage() and key in r.getMessage()]
        monkeypatch.delenv("MAVERICK_TENANT")
        return merged, reported, len(warnings)

    return run


@pytest.mark.parametrize("key", sorted(CASES))
def test_a_tenant_may_tighten_never_loosen_each_key(load, key):
    case = CASES[key]
    name = key.split(".", 1)[1]
    merged, reported, _ = load(key, case["os"], case["s"])
    assert merged.get(name) == case.get("se", case["s"]) and not reported
    merged, reported, warnings = load(key, case.get("ol", case["os"]), case["l"])
    assert merged.get(name) == case.get("ol", case["os"]) and reported and warnings == 1
    if case.get("us") is not None:
        merged, reported, _ = load(key, None, case["us"])
        assert merged.get(name) == case["us"] and not reported
    if case.get("ul") is not None:
        merged, reported, warnings = load(key, None, case["ul"])
        assert name not in merged and reported and warnings == 1
