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
    # A workspace may charge paid tool calls more, never less: a higher
    # per-call ceiling, or a higher price in the unit the organisation set.
    "budget.unpriced_tool_call_dollars": dict(os=0.25, s=0.5, l=0.05, us=0.5, ul=0.01),
    "budget.tool_prices": dict(os={"deepl": {"dollars": 0.02, "per": "request"}},
                               s={"deepl": {"dollars": 0.03, "per": "request"}},
                               l={"deepl": {"dollars": 0.01, "per": "request"}},
                               ul={"deepl": {"dollars": 0.01, "per": "request"}}),
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
    "codebase.default_protect": dict(os="approve", s="block", l="audit", ul="audit"),
    "codebase.checker": _prot(True),
    "codebase.require_container": _prot(False),
    "codebase.repair_rounds": dict(os=2, s=3, l=1, us=3, ul=0),
    "codebase.check_rounds": dict(os=2, s=3, l=1, us=3, ul=1),
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
