"""The All settings catalog only names settings the kernel really reads.

Each entry records the kernel module that reads it. These tests fail if an
entry names a config table the kernel does not know (``KNOWN_SECTIONS``), a
key its reader never mentions, an environment override its reader does not
consult, or a per-tool limit for a tool that does not exist -- so the page can
never offer a control that silently does nothing.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from maverick.migrate import KNOWN_SECTIONS
from maverick_dashboard import settings_catalog as catalog


def _source(module: str) -> str:
    spec = importlib.util.find_spec(module)
    assert spec is not None and spec.origin, f"reader module {module} is missing"
    return Path(spec.origin).read_text(encoding="utf-8")


def _quoted(text: str, name: str) -> bool:
    return f'"{name}"' in text or f"'{name}'" in text


_CONFIG = _source("maverick.config")
_TOOLS_DIR = Path(importlib.util.find_spec("maverick.tools").origin).parent


@pytest.mark.parametrize("setting", catalog.SETTINGS, ids=lambda s: s.id)
def test_every_catalog_key_is_read_by_the_kernel(setting):
    assert setting.top in KNOWN_SECTIONS, f"{setting.top} is not a known config table"
    reader = _source(setting.reader)
    # Voice upload/concurrency keys are consumed by the API, but its helper
    # reads the voice table through the shared voice-model configuration getter.
    delegated_tables = ""
    if setting.top == "voice" and setting.reader == "maverick_dashboard.api":
        assert "from maverick.voice_models import _voice_cfg" in reader
        delegated_tables = _source("maverick.voice_models")
    for part in setting.path[:-1]:
        # The table may be fetched through a config getter (get_budget_overrides,
        # get_billing_stripe) that the reader calls.
        assert _quoted(reader, part) or _quoted(_CONFIG, part) or _quoted(delegated_tables, part), (
            f"{setting.id}: table {part!r} is not read by {setting.reader}"
        )
    if setting.key_kind == "tool":
        registered = any(
            f'name="{setting.key}"' in path.read_text(encoding="utf-8")
            for path in _TOOLS_DIR.glob("*.py")
        )
        assert registered, f"{setting.id}: {setting.key!r} is not a registered tool"
        assert _quoted(reader, setting.top)
    elif setting.key_kind == "entries":
        # The rows are the table's own keys: the reader must read the whole table.
        assert _quoted(reader, setting.top), f"{setting.id}: {setting.reader} never reads it"
        for fixed in setting.fixed_keys:
            # A fixed row is its own setting (or a table of settings) under
            # the same table: ``rate_limits.shell``,
            # ``llm_gateway.team_budgets.default.max_requests``.
            assert any(i == f"{setting.section}.{fixed}"
                       or i.startswith(f"{setting.section}.{fixed}.")
                       for i in catalog.BY_ID), fixed
    else:
        assert _quoted(reader, setting.key), (
            f"{setting.id}: key {setting.key!r} is not read by {setting.reader}"
        )
    for name in setting.env:
        assert name in reader, f"{setting.id}: {setting.reader} never reads {name}"


def test_catalog_is_well_formed_and_plain():
    ids = [s.id for s in catalog.SETTINGS]
    assert len(ids) == len(set(ids)), "duplicate catalog entries"
    for s in catalog.SETTINGS:
        assert s.group in catalog.GROUPS
        assert s.label and s.help.endswith(".")
        assert "_" not in s.label and "_" not in s.help, s.id
        assert "[" not in s.help and "MAVERICK" not in s.help, s.id
        for _value, label in s.choices:
            assert "_" not in label, s.id
        if s.warning:
            assert s.weaker is not None, s.id


def test_catalog_does_not_change_kernel_defaults():
    from maverick import config

    defaults = {
        "safety.profile": config.get_safety()["profile"],
        "safety.scan_input": config.get_safety()["scan_input"],
        "ifc.mode": config.get_ifc()["mode"],
        "swarm.max_total_spawns": config.get_swarm()["max_total_spawns"],
        "repl.max_seconds": config.get_repl()["max_seconds"],
        "harness_refine.require_approval": config.get_harness_refine()["require_approval"],
        "earned_autonomy.max_auto_risk": config.get_earned_autonomy()["max_auto_risk"],
        "commerce.max_session_spend": config.get_commerce()["max_session_spend"],
        "durable.keep_last": config.get_durable()["keep_last"],
        "flows.max_node_retries": config.get_flows()["max_node_retries"],
        "knowledge_sources.max_items": config.get_knowledge_sources()["max_items"],
        "knowledge_sources.max_pages": config.get_knowledge_sources()["max_pages"],
        "knowledge_sources.max_download_mib": config.get_knowledge_sources()["max_download_mib"],
        "knowledge_sources.max_text_kib": config.get_knowledge_sources()["max_text_kib"],
        "knowledge_sources.max_refresh_minutes": config.get_knowledge_sources()["max_refresh_minutes"],
        "knowledge_sources.permission_filter": config.get_knowledge_sources()["permission_filter"],
    }
    for setting_id, kernel_default in defaults.items():
        assert catalog.BY_ID[setting_id].default == kernel_default, setting_id


def test_coerce_validates_types_and_bounds():
    budget = catalog.BY_ID["budget.max_tool_calls"]
    assert catalog.coerce(budget, 25) == 25
    assert catalog.coerce(budget, None) is None  # no limit
    for bad in (0, 2.5, "lots", True):
        with pytest.raises(catalog.SettingError):
            catalog.coerce(budget, bad)
    profile = catalog.BY_ID["safety.profile"]
    assert catalog.coerce(profile, "strict") == "strict"
    with pytest.raises(catalog.SettingError):
        catalog.coerce(profile, "paranoid")
    toggle = catalog.BY_ID["audit.sign"]
    with pytest.raises(catalog.SettingError):
        catalog.coerce(toggle, "false")
    hooks = catalog.BY_ID["webhooks.outbound"]
    assert catalog.coerce(hooks, ["https://a.example/x", " ", "https://a.example/x"]) == [
        "https://a.example/x"
    ]
    with pytest.raises(catalog.SettingError):
        catalog.coerce(hooks, ["http://insecure.example"])
    rate = catalog.BY_ID["rate_limits.shell"]
    assert catalog.coerce(rate, {"count": 5, "seconds": 60}) == "5/60"
    with pytest.raises(catalog.SettingError):
        catalog.coerce(rate, {"count": 0, "seconds": 60})
    providers = catalog.BY_ID["routing.allowed_providers"]
    assert catalog.coerce(providers, []) is None  # empty never means "allow none"


def test_weakening_directions():
    w = catalog.weakens
    assert w(catalog.BY_ID["audit.sign"], True, False)
    assert not w(catalog.BY_ID["audit.sign"], False, True)
    assert w(catalog.BY_ID["safety.profile"], "balanced", "off")
    assert not w(catalog.BY_ID["safety.profile"], "balanced", "strict")
    assert w(catalog.BY_ID["security.approvals_required"], 2, 1)
    assert w(catalog.BY_ID["retention.audit_days"], None, 30)
    assert w(catalog.BY_ID["retention.audit_days"], 90, 30)
    assert not w(catalog.BY_ID["retention.audit_days"], 30, 90)
    assert w(catalog.BY_ID["a2a.enabled"], False, True)
    assert not w(catalog.BY_ID["persona.name"], "", "Ada")


def test_cross_checks_refuse_configurations_the_kernel_rejects():
    with pytest.raises(catalog.SettingError):
        catalog.cross_checks({"residency.strict": True, "residency.region": ""})
    catalog.cross_checks({"residency.strict": True, "residency.region": "eu"})


def test_admin_policy_defaults_match_the_kernel():
    from maverick import config, governed_actions, provider_cost_cap

    ekko = config.get_ekko()
    for key in ("retention_days", "enrollment_days", "min_occurrences", "min_distinct_days",
                "capture_level"):
        assert catalog.BY_ID[f"ekko.{key}"].default == ekko[key], key
    assert catalog.BY_ID["actions.require_approval_at"].default == \
        governed_actions._require_approval_at()
    assert catalog.BY_ID["budget.provider_caps_period"].default == \
        provider_cost_cap.period_from_config()
    harness = config.get_self_harness()
    for key in ("risk_limited", "auto_run", "corpus_harvest", "transfer_auto",
                "eval_budget_dollars"):
        assert catalog.BY_ID[f"self_harness.{key}"].default == harness[key], key
    assert catalog.BY_ID["knowledge_access.enable"].default is config.knowledge_access_enabled()
    assert catalog.BY_ID["candidate_promotion.enable"].default is \
        config.candidate_promotion_enabled()


def test_rows_are_validated_cell_by_cell():
    import dataclasses

    caps = dataclasses.replace(catalog.BY_ID["budget.provider_caps"],
                               choices=(("anthropic", "Anthropic"),))
    assert catalog.coerce(caps, [{"name": "anthropic", "cap": 12.5}]) == {"anthropic": 12.5}
    for bad in ([{"name": "openai", "cap": 5}], [{"name": "anthropic", "cap": 0}],
                [{"name": "anthropic", "cap": float("inf")}], "anthropic=5",
                [{"name": "anthropic", "cap": 5}, {"name": "anthropic", "cap": 6}]):
        with pytest.raises(catalog.SettingError):
            catalog.coerce(caps, bad)
    rules = catalog.BY_ID["eu_ai_incidents.authorities"]
    people = dataclasses.replace(rules.columns[0], choices=(("user:ada", "Ada"),))
    rules = dataclasses.replace(rules, columns=(people, *rules.columns[1:]))
    assert catalog.coerce(rules, [{"principal": "user:ada", "role": "safety_officer",
                                   "authority_refs": " a-1 , b.2 "}]) == [
        {"principal": "user:ada", "role": "safety_officer", "authority_refs": ["a-1", "b.2"]}]
    with pytest.raises(catalog.SettingError):
        catalog.coerce(rules, [{"principal": "user:ada", "role": "safety_officer",
                                "authority_refs": "bad\x1bref"}])


def test_row_weakening_directions():
    w = catalog.weakens
    acl = catalog.BY_ID["security.channels"]
    base = {"slack": {"denied_tools": ["shell"], "allowed_tools": ["read_file"],
                      "max_risk": "medium"}}
    tighter = {"slack": {"denied_tools": ["shell", "browser"], "allowed_tools": ["read_file"],
                         "max_risk": "low"}, "sms": {"denied_tools": ["shell"],
                                                     "allowed_tools": [], "max_risk": ""}}
    assert not w(acl, base, tighter)
    assert w(acl, base, {})
    assert w(acl, base, {"slack": {**base["slack"], "max_risk": ""}})
    assert w(acl, base, {"slack": {**base["slack"], "allowed_tools": []}})
    caps = catalog.BY_ID["budget.provider_caps"]
    assert w(caps, {"openai": 5.0}, {"openai": 6.0}) and w(caps, {"openai": 5.0}, {})
    assert not w(caps, {"openai": 5.0}, {"openai": 4.0, "anthropic": 9.0})
    chains = catalog.BY_ID["provider_failover.chains"]
    assert w(chains, {}, {"a": ["b"]}) and not w(chains, {"a": ["b", "c"]}, {"a": ["b"]})
    defaults = catalog.BY_ID["dashboard.default_suites"]
    assert not w(defaults, None, ["finance"]) and w(defaults, ["finance"], None)
    assert w(defaults, ["finance"], ["finance", "tax"])
    delegation = catalog.BY_ID["approval.delegation"]
    assert w(delegation, [], [{"delegate_to": "user:a", "min_risk": "", "tool_glob": "*"}])
    authorities = catalog.BY_ID["eu_ai_incidents.authorities"]
    row = {"principal": "user:a", "role": "legal_counsel", "authority_refs": ["x"]}
    assert w(authorities, [], [row]) and not w(authorities, [row], [])
