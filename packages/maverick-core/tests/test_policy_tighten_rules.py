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


_DECISION_DEFAULTS = ["security", "workspace_boundaries", "data_erasure_retention", "spending",
                      "user_facing", "governance"]
_DEFAULT_KEYS = ["budget.max_dollars", "governance.*", "plugins.*", "safety.*"]
CASES = {
    # A workspace may charge paid tool calls more, never less: a higher
    # per-call ceiling, or a higher price in the unit the organisation set.
    "budget.unpriced_tool_call_dollars": dict(os=0.25, s=0.5, l=0.05, us=0.5, ul=0.01),
    "budget.max_unmetered_hold_dollars": dict(os=2.0, s=3.0, l=0.5, us=2.0, ul=0.5),
    "budget.tool_prices": dict(os={"deepl": {"dollars": 0.02, "per": "request"}},
                               s={"deepl": {"dollars": 0.03, "per": "request"}},
                               l={"deepl": {"dollars": 0.01, "per": "request"}},
                               ul={"deepl": {"dollars": 0.01, "per": "request"}}),
    # A workspace may lower a task's caps, never raise them; zero is a cap.
    "budget.max_dollars": dict(os=5.0, s=2.0, ol=0, l=10.0, us=2.0),
    "budget.max_wall_seconds": dict(os=1800, s=600, l=3600, us=600),
    "budget.max_tool_calls": dict(os=50, s=20, l=100, us=20),
    "budget.max_input_tokens": dict(os=100000, s=50000, l=200000, us=50000),
    "budget.max_output_tokens": dict(os=20000, s=10000, l=40000, us=10000),
    "budget.task_limits_enabled": _prot(True),
    "budget.strict_pricing": _prot(True),
    # Per AI service, in any spelling: lower or add a cap, never raise one.
    "budget.provider_caps": dict(os={"anthropic": 50.0}, s={"Anthropic": 20.0, "openai": 10.0},
                                 se={"anthropic": 20.0, "openai": 10.0}, l={"ANTHROPIC": 100.0},
                                 us={"openai": 10.0}),
    # Warnings may be added, never removed.
    "budget.warning_thresholds": dict(os=[0.8, 1.0], s=[0.5, 0.8, 1.0], l=[1.0],
                                      us=[0.5, 0.8, 0.95, 1.0], ul=[5]),
    # A deny-like list only grows: the tenant's names are added to the
    # organisation's, so only a value the consumer cannot read is ignored.
    "governance.deny_actions": dict(os=["shell"], s=["browser"], se=["shell", "browser"], l="shell", us=["shell"]),
    "governance.require_human_actions": dict(os=["shell"], s=["browser"], se=["shell", "browser"], l=[""],
                                             us=["shell"]),
    "governance.deny_min_risk": dict(os="medium", s="low", l="high", us="high"),
    "governance.require_human_min_risk": dict(os="medium", s="low", l="high", us="high"),
    "governance.deny_above": dict(os=100, s=50, se={"*": 50.0}, l=500, us=0, use={"*": 0.0}),
    "governance.require_human_above": dict(os=100, s=50, se={"*": 50.0}, l=500, us=10, use={"*": 10.0}),
    "governance.require_fresh_human_approval": _prot(False),
    "governance.profile": dict(os="standard", s="regulated", l="essentials", us="standard"),
    "safety.profile": dict(os="balanced", s="strict", l="permissive", us="strict", ul="permissive"),
    "safety.block_threshold": dict(os="high", s="medium", l="critical", us="medium", ul="critical"),
    "safety.scan_input": _prot(True),
    "safety.scan_tool_calls": _prot(True),
    "safety.scan_output": _prot(True),
    "safety.constitution": dict(os=["a"], s=["b"], se=["a", "b"], l="a", us=["b"]),
    "safety.compartments": _prot(False),
    "safety.compartment_unseal": dict(os="orchestrator", s="human", l="both", us=None, ul="both"),
    "safety.require_shield": _prot(False),
    # Unset means "ask only for risky actions" in a secure install and "never
    # ask" otherwise, so no fixed looser value exists for the unset case.
    "safety.consent_mode": dict(os="dashboard", s="ask", l="auto-approve", us="ask"),
    "safety.review_checkpoint": dict(os={"dollars": 10}, s={"dollars": 5}, l={"dollars": 20},
                                     us={"dollars": 5}),
    "safety.max_scan_chars": dict(os=262144, s=100000, l=5000000, us=100000, ul=50000000),
    "safety.supply_chain_pinning": _prot(False),
    "safety.cascade": _prot(False),
    "safety.decode_hidden": _prot(True),
    "safety.shield_rate_limit": dict(os="100/60", s="50/60", l="200/60", us="50/60"),
    "safety.quorum_required": dict(os=2, s=3, l=1, us="2"),
    "safety.quorum_protected_keys": dict(os=["governance.*", "safety.*"], s=["x.*"],
                                         se=["governance.*", "safety.*", "x.*"], l="x.*",
                                         us=["x.*"], use=[*_DEFAULT_KEYS, "x.*"], ul=5),
    "safety.quorum_ttl_days": dict(os=5, s=3, l=7, us=3, ul=0),
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
    # User 0 is root: a workspace may leave it, never choose it.
    "sandbox.run_as_user": dict(os=0, s=1000, ol=1000, l=0, us=2000, ul=0),
    "sandbox.pids_limit": dict(os=256, s=128, l=1024, us=256, ul=1000000),
    "sandbox.memory": dict(os="2g", s="1g", l="8g", us="2g", ul="16g"),
    "sandbox.memory_mb": dict(os=2048, s=1024, l=4096, us=1024),
    "sandbox.cpus": dict(os=2, s=1, l=4, us=1),
    "sandbox.long_command_timeout": dict(os=600, s=300, l=1200, us=300, ul=86400),
    "sandbox.timeout": dict(os=60, s=30, l=120, us=30, ul=120),
    "sandbox.warm": _perm(False),
    # A workspace may add hosts a tool must not reach and narrow the hosts it
    # may reach; a tool rule that is not a table is ignored.
    "sandbox.tool": dict(os={"http_fetch": {"allow_egress": ["a.example", "b.example"]}},
                         s={"http_fetch": {"allow_egress": ["a.example"], "deny_egress": ["x.example"]}},
                         l={"http_fetch": {"allow_egress": ["c.example"]}},
                         us={"shell": {"deny_egress": ["*"]}}, ul={"shell": "open"}),
    # A workspace adds areas where a run must ask a person; it never removes one.
    "approval.decision_areas": dict(
        os=["security"], s=["security", "legal"], l=[], us=[*_DECISION_DEFAULTS, "legal"],
        ul=["security"]),
    "approval.decision_admin_areas": dict(
        os=["governance"], s=["governance", "security"], l=[], us=["governance", "security"],
        ul=[]),
    "approval.decision_expiry_hours": dict(os=72, s=24, l=240, us=24, ul=720),
    "approval.record_checks": _prot(True),
    "approval.require_acknowledgement": _prot(True),
    "approval.separate_approver": dict(os="when_available", s="always", l="never", us="always",
                                       ul="never"),
    "security.allowed_tools": dict(os=["a", "b"], s=["a"], l=[], us=["a"]),
    "security.denied_tools": dict(os=["shell"], s="x", se=["shell", "x"], l=5, us="shell", use=["shell"]),
    "security.max_risk": dict(os="medium", s="low", l="high", us="medium"),
    "security.channels": dict(os={"slack": {"max_risk": "medium"}}, s={"slack": {"max_risk": "low"}},
                              l={"slack": {"max_risk": "high"}}, us={"slack": {"max_risk": "low"}}),
    "security.users": dict(os={"tg:1": {"max_risk": "medium"}}, s={"tg:1": {"max_risk": "low"}},
                           l={"tg:1": {"max_risk": "high"}}, us={"tg:1": {"max_risk": "low"}}),
    "security.network_policy": dict(os="allowlist", s="deny-all", l="open", us="deny-all"),
    "security.approvals_required": dict(
        os=2, s=3, se=dict.fromkeys(("default", "low", "medium", "high", "critical"), 3), l=1,
        us=2, use=dict.fromkeys(("default", "low", "medium", "high", "critical"), 2)),
    "security.approvals_required_by_risk": dict(os={"high": 2}, s={"high": 3}, l={"high": 1},
                                                us={"high": 2}),
    "security.tool_risk": dict(os={"web_search": "medium"}, s={"web_search": "high"},
                               l={"web_search": "low"}, us={"read_file": "high"}, ul={"shell": "low"}),
    "security.auto_fix": _perm(False),
    "security.allow_self_approval": _perm(False),
    "security.isolate_parsers": _prot(False),
    "security.secure_defaults": _prot(True),
    # A workspace may protect code more, never less: stricter protection,
    # the checker on, a container required, more repair rounds and looks.
    # The default egress plane: denied hosts only grow; an allow list may only
    # narrow one the organisation set (a new one approves hosts under the
    # allowlist posture).
    "egress.deny": dict(os=["169.254.169.254"], s=["169.254.169.254", "x.example"], l=[],
                        us=["x.example"], ul=5),
    "egress.allow": dict(os=["a.example", "b.example"], s=["a.example"], l=["c.example"],
                         ul=["c.example"]),
    # A workspace plane replaces [egress], so only one the organisation set is tightened.
    "tenancy.egress": dict(os={"acme": {"deny": ["169.254.169.254"]}},
                           s={"acme": {"deny": ["169.254.169.254", "x.example"]}},
                           l={"acme": {"allow": ["c.example"]}}, ul={"acme": {"deny": ["x.example"]}}),
    # Each can lift the egress lock.
    "enterprise.mode": _prot(False),
    "enterprise.require": _prot(False),
    # Exceptions to the lock: only removed (empty means none).
    "enterprise.allowed_hosts": dict(os=["a.example", "b.example"], s=["a.example"],
                                     l=["a.example", "b.example", "c.example"], ul=["c.example"]),
    "enterprise.local_providers": dict(os=["ollama", "vllm"], s=["ollama"], l=["ollama", "vllm", "openai"],
                                       ul=["ollama"]),
    "profile.name": dict(os="standard", s="enterprise", ol="enterprise", l="standard", us="enterprise"),
    "compliance.profiles": dict(os=["hipaa"], s=["gdpr"], se=["hipaa", "gdpr"], l="hipaa", us=["gdpr"],
                                ul=["no_such_profile"]),
    # A workspace may word the AI disclosure its own way, never remove it.
    "compliance.disclosure_text": dict(os="Org text", s="Workspace text", l="", us="Workspace text",
                                       ul="  "),
    "codebase.enable": _perm(False),
    "codebase.default_protect": dict(os="approve", s="block", l="audit", ul="audit"),
    "codebase.checker": _prot(True),
    "codebase.require_container": _prot(False),
    "codebase.repair_rounds": dict(os=2, s=3, l=1, us=3, ul=0),
    "codebase.check_rounds": dict(os=2, s=3, l=1, us=3, ul=1),
    "codebase.checkers": dict(os=2, s=3, l=1, us=2, ul=0),
    "codebase.max_repros": dict(os=5, s=8, l=2, us=8, ul=1),
    # Where checks run and which models check are the organisation's alone:
    # a workspace file may not set them at all.
    "codebase.checker_image": dict(os="lw-checker:1", s="lw-checker:1", l="other:1",
                                   ul="other:1"),
    "codebase.checker_models": dict(os=["model-a"], s=["model-a"], l=["model-b"],
                                    ul=["model-b"]),
    # The second checker for protected paths, and whether the factory may change
    # the Lightwork that runs it, are the organisation's alone too.
    "codebase.protected_checker_model": dict(os="openai:m", s="openai:m", l="gemini:g",
                                             ul="gemini:g"),
    "codebase.allow_self_changes": dict(os=False, s=False, l=True, ul=True),
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
        assert merged.get(name) == case.get("use", case["us"]) and not reported
    if case.get("ul") is not None:
        merged, reported, warnings = load(key, None, case["ul"])
        assert not merged.get(name) and reported and warnings == 1


# --- What each consumer does with the merged result ------------------------

@pytest.fixture
def consumer(tmp_path, monkeypatch):
    """Load an organisation file and a tenant overlay, then ask a consumer."""
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    for name in ("MAVERICK_CONFIG", "MAVERICK_APPROVALS_REQUIRED", "MAVERICK_QUORUM_REQUIRED",
                 "MAVERICK_SHIELD_MAX_SCAN_CHARS", "MAVERICK_TOOL_TOKEN_TTL", "MAVERICK_CONSENT_MODE",
                 "MAVERICK_SHIELD_RATE_LIMIT", "MAVERICK_GOAL_RISK_FLOOR", "MAVERICK_GOAL_RISK_REQUIRE_HUMAN",
                 "MAVERICK_REVIEW_CHECKPOINT_DOLLARS", "MAVERICK_REVIEW_CHECKPOINT_TOOL_CALLS",
                 "MAVERICK_REVIEW_CHECKPOINT_WALL_SECONDS", "MAVERICK_LONG_CMD_TIMEOUT"):
        monkeypatch.delenv(name, raising=False)
    tenant_path = tmp_path / "tenants" / "acme" / "config.toml"
    tenant_path.parent.mkdir(parents=True)

    def run(org: str, tenant: str | None, ask):
        (tmp_path / "config.toml").write_text(org, encoding="utf-8")
        if tenant is None:
            tenant_path.unlink(missing_ok=True)
        else:
            tenant_path.write_text(tenant, encoding="utf-8")
        config.reset_config_cache()
        monkeypatch.setenv("MAVERICK_TENANT", "acme")
        try:
            return ask(), config.tenant_ignored_settings()
        finally:
            monkeypatch.delenv("MAVERICK_TENANT")

    return run


def test_a_workspace_can_lower_but_never_raise_a_task_budget(consumer, monkeypatch):
    from maverick.budget import resolve_budget_caps
    from maverick.provider_cost_cap import caps_from_config

    for name in ("MAVERICK_BUDGET_DOLLARS", "MAVERICK_BILLING_STRICT"):
        monkeypatch.delenv(name, raising=False)

    def ask():
        return resolve_budget_caps(), caps_from_config()

    org = ("[budget]\nmax_dollars = 5.0\nmax_wall_seconds = 600\nmax_tool_calls = 0\n"
           "[budget.provider_caps]\nanthropic = 50.0\n")
    raised = ("[budget]\nmax_dollars = 50.0\nmax_wall_seconds = 6000\nmax_tool_calls = 10\n"
              "task_limits_enabled = false\n[budget.provider_caps]\nANTHROPIC = 500.0\n")
    (caps, providers), ignored = consumer(org, raised, ask)
    assert caps == {"max_dollars": 5.0, "max_wall_seconds": 600.0, "max_tool_calls": 0}
    assert providers == {"anthropic": 50.0}
    assert {"budget.max_dollars", "budget.max_wall_seconds", "budget.max_tool_calls",
            "budget.task_limits_enabled", "budget.provider_caps"} <= ignored
    lowered = "[budget]\nmax_dollars = 1.5\n[budget.provider_caps]\nAnthropic = 20.0\n"
    (caps, providers), ignored = consumer(org, lowered, ask)
    assert caps["max_dollars"] == 1.5 and providers == {"anthropic": 20.0} and not ignored
    # An organisation cap the budget cannot read stays the organisation's.
    _, ignored = consumer('[budget]\nmax_dollars = "lots"\n', lowered, lambda: None)
    assert "budget.max_dollars" in ignored


def test_a_workspace_cannot_turn_on_self_approval_or_run_as_root(consumer, monkeypatch):
    """Neither key had a rule, so a workspace file could let people approve
    their own requests and run sandbox pods as root."""
    from maverick import config
    from maverick.safety.dual_control import allow_self_approval

    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)

    def ask():
        return allow_self_approval(), int(config.load_config().get("sandbox", {}).get("run_as_user", 1000))

    loose = "[security]\nallow_self_approval = true\n[sandbox]\nrun_as_user = 0\n"
    strict = "[security]\nallow_self_approval = false\n[sandbox]\nrun_as_user = 1000\n"
    for org in ("", strict):
        result, ignored = consumer(org, loose, ask)
        assert result == (False, 1000)
        assert {"security.allow_self_approval", "sandbox.run_as_user"} <= ignored
    # A value that the sandbox would read as user 0 is refused in any spelling.
    for spelling in ('"0"', "0.5", "false"):
        result, ignored = consumer("", f"[sandbox]\nrun_as_user = {spelling}\n", ask)
        assert result == (False, 1000) and "sandbox.run_as_user" in ignored, spelling
    result, ignored = consumer(loose, strict, ask)  # stricter than the organisation: applies
    assert result == (False, 1000) and not ignored
    result, ignored = consumer("", "[sandbox]\nrun_as_user = 2000\n", ask)  # another ordinary user
    assert result == (False, 2000) and not ignored


def _deny_above():
    from maverick.governance import Policy
    return Policy.from_config().deny_above


def _approvals():
    from maverick.safety.dual_control import required_approvals
    return [required_approvals(tier) for tier in ("low", "medium", "high")]


def _web_search_risk():
    from maverick.safety.tool_risk import tool_risk
    return tool_risk("web_search")


def _sandbox_timeout():
    from maverick.config import get_sandbox
    return get_sandbox()["timeout"]


def _checkpoint():
    from maverick.review_checkpoint import policy_from_config
    return policy_from_config().dollars


def _protected():
    from maverick.quorum import configured_policy
    return configured_policy().protected_keys


def _acl_lists():
    from maverick.safety.tool_acl import _load_lists
    return _load_lists()


SEVEN = [
    # 1. zero is the strictest governance threshold, both ways
    ("[governance]\ndeny_above = 0\n", "[governance]\ndeny_above = 1000000\n", _deny_above,
     {"*": 0.0}, {"governance.deny_above"}),
    ("", "[governance]\ndeny_above = 0\n", _deny_above, {"*": 0.0}, set()),
    # 2. approvals per tier as dual control reads them, both shapes
    ("[security]\napprovals_required = 2\n", "[security]\napprovals_required = {high = 3}\n",
     _approvals, [2, 2, 3], set()),
    ("[security]\napprovals_required = {high = 3}\n", "[security]\napprovals_required = 2\n",
     _approvals, [2, 2, 3], {"security.approvals_required"}),  # its 2 for high is not applied
    # 3. an exact rating cannot undercut the organisation's pattern
    ('[security.tool_risk]\n"web_*" = "high"\n', '[security.tool_risk]\nweb_search = "medium"\n',
     _web_search_risk, "high", {"security.tool_risk"}),
    # 4. a table where the consumer reads a number is ignored and reported
    ("[sandbox]\ntimeout = 30\n", "[sandbox]\ntimeout = {a = 10}\n", _sandbox_timeout, 30,
     {"sandbox.timeout"}),
    # 5. text where the consumer reads only numbers is ignored and reported
    ("[safety.review_checkpoint]\ndollars = 5\n", '[safety.review_checkpoint]\ndollars = "3"\n',
     _checkpoint, 5.0, {"safety.review_checkpoint"}),
    ("", '[governance]\ndeny_above = "500"\n', _deny_above, {}, {"governance.deny_above"}),
    # 6. an empty protected list means the four defaults; a tenant only adds
    ("[safety]\nquorum_required = 2\nquorum_protected_keys = []\n",
     '[safety]\nquorum_protected_keys = ["x.y"]\n', _protected,
     frozenset({"x.y", "safety.*", "governance.*", "plugins.*", "budget.max_dollars"}), set()),
    # 7. an honest stricter list is applied and not reported; a single name counts
    ('[security]\ndenied_tools = ["a"]\n', '[security]\ndenied_tools = ["b"]\n', _acl_lists,
     (set(), {"a", "b"}), set()),
    ('[security]\nallowed_tools = "shell"\n', '[security]\nallowed_tools = ["shell"]\n', _acl_lists,
     ({"shell"}, set()), set()),
    ("", 'safety = "x"\n', lambda: None, None, {"safety"}),
]


@pytest.mark.parametrize(("org", "tenant", "ask", "effective", "reported"), SEVEN)
def test_the_consumer_sees_the_stricter_value(consumer, org, tenant, ask, effective, reported):
    result, ignored = consumer(org, tenant, ask)
    assert result == effective
    assert ignored == reported


# --- Property: the consumer under (organisation + tenant) is never looser ---

_INF = float("inf")


def _floor_rank(level):
    return {"low": 3, "medium": 2, "high": 1}.get(level, 0)


def _strictness(key: str):
    """Scores the consumer's effective policy for ``key``: each number may
    only rise and each set may only grow when the tenant layer is added."""
    import importlib

    from maverick import quorum
    from maverick.governance import Policy
    from maverick.safety import consent, dual_control, goal_risk, tool_acl
    from maverick.sandbox import network_policy
    tool_risk = importlib.import_module("maverick.safety.tool_risk")  # the package re-exports a function

    section, name = key.split(".", 1)
    if section == "governance":
        policy = Policy.from_config()
        if name in {"deny_above", "require_human_above"}:
            table = getattr(policy, name)
            return [-(table.get(a, table.get("*", _INF))) for a in ("*", "pay", "other")]
        if name in {"deny_actions", "require_human_actions"}:
            return [frozenset(getattr(policy, name))]
        if name in {"deny_min_risk", "require_human_min_risk"}:
            return [_floor_rank(getattr(policy, name))]
        return [int(policy.require_fresh_human_approval)]
    if key == "security.approvals_required" or key == "security.approvals_required_by_risk":
        return [dual_control.required_approvals(t) for t in (None, "low", "medium", "high", "critical")]
    if key == "security.tool_risk":
        return [tool_risk.risk_rank(tool_risk.tool_risk(t)) for t in ("web_search", "shell", "read_file", "mcp_x")]
    if key in {"security.denied_tools", "security.allowed_tools"}:
        allowed, denied = tool_acl._load_lists()
        return [frozenset(denied), -(len(allowed) if allowed else _INF)]
    if key == "security.max_risk":
        return [_floor_rank(tool_acl.resolve_max_risk())]
    if key == "security.network_policy":
        return [("open", "allowlist", "deny-all").index(network_policy.network_posture())]
    if key in {"safety.quorum_required", "safety.quorum_protected_keys", "safety.quorum_ttl_days"}:
        policy = quorum.configured_policy()
        if policy is None:
            return [1, frozenset(), -_INF]
        return [policy.required, frozenset(policy.protected_keys), -policy.ttl_days]
    if key == "safety.consent_mode":
        return [-consent._strictness(consent._installation_mode(r)) for r in ("low", "high")]
    if key == "safety.max_scan_chars":
        from maverick_shield.builtin_rules import _max_scan_chars
        return [-_max_scan_chars()]
    if key == "safety.review_checkpoint":
        from maverick.review_checkpoint import policy_from_config
        policy = policy_from_config()
        return [-(getattr(policy, f) or _INF) for f in ("dollars", "tool_calls", "wall_seconds")]
    if key == "safety.shield_rate_limit":
        from maverick.safety.shield_rate_limit import configured_rate
        rate = configured_rate()
        return [-(rate[0] / rate[1] if rate else _INF)]
    if key == "safety.goal_risk_floor":
        return [3 - _floor_rank(goal_risk.config_floor())]
    if key == "safety.goal_risk_require_human":
        return [int(goal_risk.require_human_for(t)) for t in ("medium", "high")]
    if key == "capabilities.per_call_token_ttl":
        from maverick.tool_token import _ttl_seconds
        return [-_ttl_seconds()]
    raise KeyError(key)


PROPERTY_KEYS = [
    "governance.deny_actions", "governance.require_human_actions", "governance.deny_min_risk",
    "governance.require_human_min_risk", "governance.deny_above", "governance.require_human_above",
    "governance.require_fresh_human_approval", "security.approvals_required",
    "security.approvals_required_by_risk", "security.tool_risk", "security.denied_tools",
    "security.allowed_tools", "security.max_risk", "security.network_policy", "safety.quorum_required",
    "safety.quorum_protected_keys", "safety.quorum_ttl_days", "safety.consent_mode",
    "safety.max_scan_chars", "safety.review_checkpoint", "safety.shield_rate_limit",
    "safety.goal_risk_floor", "safety.goal_risk_require_human", "capabilities.per_call_token_ttl",
]
_EXTRAS = [None, 0, "0", "3", "x", True, 5, ["a"], {"a": 1}, {"*": 0}]


def _values(key: str) -> list:
    case = CASES[key]
    seen: list = []
    for value in [*(case.get(k) for k in ("os", "s", "l", "us", "ul")), *_EXTRAS]:
        if value not in seen:
            seen.append(value)
    return seen


def _no_looser(before, after) -> bool:
    for old, new in zip(before, after, strict=True):
        if isinstance(old, frozenset):
            if not old <= new:
                return False
        elif new < old:
            return False
    return True


@pytest.mark.parametrize("key", PROPERTY_KEYS)
def test_adding_a_tenant_layer_never_loosens_what_the_consumer_does(consumer, key):
    from maverick.governance import GovernancePolicyError

    section, name = key.split(".", 1)

    def entry(value):
        return "" if value is None else f"[{section}]\n{name} = {_toml(value)}\n"

    def ask():
        try:
            return _strictness(key)
        except (GovernancePolicyError, AttributeError, TypeError, ValueError):
            return "refused"  # the consumer cannot work with this configuration

    for org in _values(key):
        before, _ = consumer(entry(org), None, ask)
        for tenant in _values(key):
            if tenant is None:
                continue
            after, _ = consumer(entry(org), entry(tenant), ask)
            if before == "refused":
                continue  # the organisation's own value already stops every call
            assert after != "refused", (org, tenant)
            assert _no_looser(before, after), (org, tenant, before, after)


def test_a_workspace_cannot_remove_an_area_that_needs_a_decision(consumer):
    from maverick import decision_requests as dr

    (areas, admin), ignored = consumer(
        "", '[approval]\ndecision_areas = ["security", "legal"]\ndecision_admin_areas = []\n',
        lambda: (dr.areas(), dr.admin_areas()))
    assert areas == [*dr.DEFAULT_AREAS, "legal"] and admin == ["governance"]
    assert {"approval.decision_areas", "approval.decision_admin_areas"} <= set(ignored)


# --- Keys without a rule: only the organisation sets them -------------------

def _unruled_keys() -> list[str]:
    """Every key the code names in a policy section without a tighten rule,
    plus one no code reads yet, so a key added later is covered too."""
    from maverick import config_contracts, config_lint
    from maverick.policy_tighten import WORKSPACE_INFRASTRUCTURE

    named = {f"{section}.{key}" for section in TENANT_RULES
             for key in (config_lint.KNOWN_SCHEMA.get(section) or ())}
    for registry in (config_contracts.TEXT_SETTINGS, config_contracts.INTEGER_SETTINGS,
                     config_contracts.BOOLEAN_SETTINGS, config_contracts.CHOICE_SETTINGS,
                     config_contracts.NUMBER_LIST_SETTINGS):
        named.update(name for name in registry
                     if name.count(".") == 1 and name.split(".")[0] in TENANT_RULES)
    named.update(f"{section}.a_setting_added_later" for section in TENANT_RULES)
    named.update(f"sandbox.{key}" for key in WORKSPACE_INFRASTRUCTURE)
    return sorted(key for key in named if key.split(".", 1)[1] not in TENANT_RULES[key.split(".")[0]])


def test_the_unruled_key_list_comes_from_the_code():
    keys = _unruled_keys()
    assert {"sandbox.image", "sandbox.kubeconfig", "safety.receipt_key", "capabilities.deferred_tools",
            "approval.undo_grace_seconds", "sandbox.workspace_infrastructure"} <= set(keys)
    assert "sandbox.tool" not in keys and "approval.record_checks" not in keys
    assert {f"budget.{key}" for key in ("guidance", "warnings", "self_tuning", "receipts",
                                        "provider_caps_period")} <= set(keys)
    assert not {"budget.max_dollars", "budget.strict_pricing"} & set(keys)


@pytest.mark.parametrize("key", _unruled_keys())
def test_a_workspace_value_for_a_key_without_a_rule_is_ignored(load, key):
    name = key.split(".", 1)[1]
    merged, reported, warnings = load(key, "organisation-value", "workspace-value")
    assert merged.get(name) == "organisation-value" and reported and warnings == 1
    merged, reported, warnings = load(key, None, {"a": "workspace-table"})
    assert name not in merged and reported and warnings == 1


_INFRASTRUCTURE = (
    'provider = "e2b"\napi_key = "acme-key"\nkubeconfig = "/srv/acme/kube"\ncontext = "acme"\n'
    'namespace = "acme"\nhost = "acme@build.example"\n')


def test_the_organisation_switch_lets_a_workspace_name_its_own_work_area_servers(consumer, tmp_path):
    from maverick import config

    def ask():
        return config.load_config().get("sandbox", {})

    org = ('[sandbox]\nbackend = "kubernetes"\nnamespace = "org"\nkubeconfig = "/srv/org/kube"\n'
           'extra_kubectl_args = ["--v=2"]\nssh_args = ["-p2222"]\n')
    tenant = ("[sandbox]\n" + _INFRASTRUCTURE + 'extra_kubectl_args = ["--v=2"]\n'
              'ssh_args = ["-oProxyCommand=sh"]\nbackend = "local"\nimage = "acme:1"\n')
    infrastructure = {"sandbox.context", "sandbox.namespace", "sandbox.host"}
    # Never the workspace's: a cluster settings file can name a program this
    # computer runs, a key or provider picks another service, options run here.
    organisation_only = {"sandbox.provider", "sandbox.api_key", "sandbox.kubeconfig",
                         "sandbox.extra_kubectl_args", "sandbox.ssh_args", "sandbox.backend", "sandbox.image"}
    # Off (the default): every one stays the organisation's and is listed.
    sandbox, ignored = consumer(org, tenant, ask)
    assert sandbox["namespace"] == "org" and "host" not in sandbox and sandbox["backend"] == "kubernetes"
    assert infrastructure | organisation_only <= ignored
    # The switch in a workspace file is itself ignored.
    sandbox, ignored = consumer(org, tenant + "workspace_infrastructure = true\n", ask)
    assert sandbox["namespace"] == "org" and "sandbox.workspace_infrastructure" in ignored
    # On: the workspace picks a context and namespace in the organisation's
    # cluster settings, and a remote computer only from the organisation's list.
    on = org + "workspace_infrastructure = true\n"
    sandbox, ignored = consumer(on, tenant, ask)
    assert {k: sandbox[k] for k in ("context", "namespace", "kubeconfig")} == {
        "context": "acme", "namespace": "acme", "kubeconfig": "/srv/org/kube"}
    assert "host" not in sandbox and "provider" not in sandbox and "api_key" not in sandbox
    assert sandbox["extra_kubectl_args"] == ["--v=2"] and sandbox["ssh_args"] == ["-p2222"]
    assert ignored == organisation_only | {"sandbox.host"}
    sandbox, ignored = consumer(on + 'workspace_hosts = ["*@build.example"]\n', tenant, ask)
    assert sandbox["host"] == "acme@build.example" and "sandbox.host" not in ignored
    # A name the cluster tools could read as something else is ignored.
    sandbox, ignored = consumer(on, '[sandbox]\nnamespace = "x/../y"\ncontext = "-v"\n', ask)
    assert sandbox["namespace"] == "org" and {"sandbox.namespace", "sandbox.context"} <= ignored
    # While a settings file cannot be read, the switch counts as off.
    config.dashboard_overrides_path().parent.mkdir(parents=True, exist_ok=True)
    config.dashboard_overrides_path().write_text("[sandbox\n", encoding="utf-8")
    sandbox, ignored = consumer(on, tenant, ask)
    assert sandbox["namespace"] == "org" and infrastructure <= ignored


def test_a_switch_the_consumer_reads_only_as_true_or_false(consumer, monkeypatch):
    """``record_checks`` and ``require_acknowledgement`` read anything but
    true or false as on, so a workspace false never lands under such a value."""
    from maverick import approval_checks
    from maverick.safety.consent import approval_requires_acknowledgement

    monkeypatch.delenv("MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT", raising=False)

    def ask():
        return approval_checks.enabled(), approval_requires_acknowledgement()

    org = '[approval]\nrecord_checks = "false"\nrequire_acknowledgement = "no"\n'
    tenant = "[approval]\nrecord_checks = false\nrequire_acknowledgement = false\n"
    assert consumer(org, None, ask)[0] == (True, True)
    result, ignored = consumer(org, tenant, ask)
    assert result == (True, True)
    assert ignored == {"approval.record_checks", "approval.require_acknowledgement"}


def test_a_workspace_cannot_reach_more_of_the_network(consumer, monkeypatch):
    """Each of these workspace values used to approve or unblock hosts."""
    from maverick import compliance_profiles, enterprise, profile
    from maverick.tenant.egress import egress_allowed
    from maverick.tools import _ssrf

    for name in ("MAVERICK_ENTERPRISE", "MAVERICK_PROFILE", "MAVERICK_COMPLIANCE_PROFILES",
                 "MAVERICK_FETCH_ALLOW_PRIVATE"):
        monkeypatch.delenv(name, raising=False)

    def reach(host):
        return lambda: egress_allowed("http_fetch", host, tenant="acme")

    allowlist = '[security]\nnetwork_policy = "allowlist"\n'
    tool = '[sandbox.tool.http_fetch]\nallow_egress = ["evil.example"]\n'
    assert consumer(allowlist, tool, reach("evil.example")) == (False, {"sandbox.tool"})
    plane = '[tenancy.egress.acme]\nallow = ["evil.example"]\n'
    assert consumer(allowlist, plane, reach("evil.example")) == (False, {"tenancy.egress"})
    assert consumer(allowlist + '[egress]\nallow = ["a.example"]\n', '[egress]\nallow = ["evil.example"]\n',
                    reach("evil.example")) == (False, {"egress.allow"})
    org = '[egress]\ndeny = ["169.254.169.254"]\n'
    assert consumer(org, "[egress]\ndeny = []\n", reach("169.254.169.254"))[0] is False
    # A narrower tool list the organisation set still applies.
    narrowed = '[sandbox.tool.http_fetch]\nallow_egress = ["a.example"]\n'
    result, ignored = consumer(allowlist + '[sandbox.tool.http_fetch]\nallow_egress = ["a.example", "b.example"]\n',
                               narrowed, lambda: (reach("a.example")(), reach("b.example")()))
    assert result == (True, False) and not ignored
    # The egress lock and what decides it.
    lock = '[enterprise]\nmode = true\n[profile]\nname = "enterprise"\n[compliance]\nprofiles = ["hipaa"]\n'
    loose = ('[enterprise]\nmode = false\nallowed_hosts = ["evil.example"]\n[profile]\nname = "standard"\n'
             '[compliance]\nprofiles = []\n[tools]\nfetch_allow_private = true\n')
    result, ignored = consumer(lock, loose, lambda: (
        enterprise.enterprise_enabled(), profile.active_profile(), compliance_profiles.resolve_profiles(),
        enterprise.egress_permitted("https://evil.example/"), _ssrf.allow_private()))
    assert result == (True, "enterprise", ["hipaa"], False, False)
    assert {"enterprise.mode", "enterprise.allowed_hosts", "profile.name", "tools.fetch_allow_private"} <= ignored


@pytest.mark.parametrize(("host", "applied"), [
    ("$(touch /tmp/q)@build.example.com", False),
    ("%h%r@build.example.com", False),
    ("ssh://x@evil.com:22/@build.example.com", False),
    ("`id`@build.example.com", False),
    ("u@[::1]", True),
    ("deploy@build.example.com", True),
    # ssh has no port syntax here: the port comes from ssh_args or ssh config.
    ("deploy@build.example.com:22", False),
])
def test_a_workspace_host_has_a_plain_shape_before_it_matches(consumer, host, applied):
    """Older ssh clients pass a user name with % or $ to a ProxyCommand or
    Match exec, so only user@host or host with a port is accepted."""
    from maverick import config

    org = '[sandbox]\nworkspace_infrastructure = true\nworkspace_hosts = ["*@build.example.com", "u@[::1]", "*@build.example.com:22"]\n'
    sandbox, ignored = consumer(org, f"[sandbox]\nhost = {json.dumps(host)}\n",
                                lambda: config.load_config().get("sandbox", {}))
    assert (sandbox.get("host") == host) is applied and ("sandbox.host" in ignored) is not applied


@pytest.mark.parametrize("invisible", ["\u200b", "\ufeff", "\u2060", "\u200c", " \u200b\t\ufeff "])
def test_invisible_disclosure_text_cannot_turn_the_disclosure_off(load, invisible):
    merged, reported, _ = load("compliance.disclosure_text", "Org text", invisible)
    assert merged.get("disclosure_text") == "Org text" and reported
