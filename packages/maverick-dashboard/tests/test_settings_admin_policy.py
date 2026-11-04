"""Settings > All settings: admin safety policy and the installer-only settings.

Tools per chat app, spending per AI service, review pauses, the approval
floor and approval rules, Ekko's app policy, self-improvement, incident
report deciders, cost collection, red-team limits, research promotion,
catalogs, backup models, Bedrock sign-in, screen control, departments and
sign-in groups. Each value must reach the kernel reader unchanged, be
validated on the server, need confirmation when it loosens a protection and
leave one activity record row per change.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

from test_support.settings_pages import every_group, save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
                 "MAVERICK_REVIEW_CHECKPOINT_DOLLARS", "MAVERICK_REVIEW_CHECKPOINT_TOOL_CALLS",
                 "MAVERICK_REVIEW_CHECKPOINT_WALL_SECONDS", "MAVERICK_PROVIDER_CAPS_PERIOD",
                 "MAVERICK_GOVERNED_ACTIONS", "MAVERICK_EKKO", "MAVERICK_KNOWLEDGE_ACCESS",
                 "MAVERICK_CANDIDATE_PROMOTION",
                 "MAVERICK_SELF_HARNESS", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _installer(text: str) -> None:
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text(text, encoding="utf-8")
    config.reset_config_cache()


def _loaded():
    from maverick import config

    config.reset_config_cache()
    return config.load_config()


def _save(changes, confirm=False):
    return save_catalog(client, API, json={"changes": changes, "confirm": confirm})


def _row(setting_id):
    for group in client.get(API).json()["groups"]:
        for row in group["settings"]:
            if row["id"] == setting_id:
                return row
    raise AssertionError(setting_id)


def _loosens(change, audit_rows):
    """A change that loosens a protection is refused until confirmed."""
    r = _save([change])
    assert r.status_code == 409, r.text
    assert r.json()["confirm"][0]["id"] == change["id"]
    assert r.json()["confirm"][0]["warning"]
    before = len(audit_rows)
    r = _save([change], confirm=True)
    assert r.status_code == 200, r.text
    assert len(audit_rows) == before + 1 and audit_rows[-1]["confirmed"] is True
    return r


# ------------------------------------------------------------------ page
def test_page_shows_the_new_controls_in_plain_language(monkeypatch):
    from test_support.plain_language import developer_terms

    _installer('[channels.slack]\nenabled = true\n')
    page = every_group(client)
    for text in ("Tools allowed in each chat app", "Most to spend with each AI service",
                 "Pause for a review after spending", "Suggest reviewers for approvals",
                 "Apps Ekko may notice", "Use the careful improvement profile",
                 "People who decide serious AI incident reports", "Backup AI models",
                 "How Lightwork signs in to Amazon Bedrock", "Departments turned off",
                 "Roles for sign-in groups", "People &amp; access"):
        assert text in page, text
    assert 'data-grid-state=' in page and "data-grid-add" in page
    assert developer_terms(page) == []


def test_chat_apps_and_services_come_from_what_is_set_up():
    _installer('[channels.slack]\nenabled = true\n[channels.telegram]\nenabled = false\n'
               '[providers.anthropic]\napi_key = "sk-test"\n')  # pragma: allowlist secret
    acl = _row("security.channels")
    assert [k["value"] for k in acl["grid"]["key_choices"]] == ["slack", "telegram"]
    assert [k["label"] for k in acl["grid"]["key_choices"]] == ["Slack", "Telegram"]
    # The tool list is long: the page loads it on demand, admin only.
    column = acl["grid"]["columns"][0]
    assert column["choices"] == [] and column["choices_url"].endswith("column=denied_tools")
    tools = client.get(column["choices_url"]).json()["choices"]
    assert {"shell", "mcp_*"} <= {c["value"] for c in tools}
    caps = _row("budget.provider_caps")
    assert [k["value"] for k in caps["grid"]["key_choices"]] == ["anthropic"]
    assert client.get(API + "/choices/security.channels?column=max_risk").status_code == 404


def test_empty_selectors_say_what_to_do_first():
    page = every_group(client)
    assert "No chat apps are set up yet. Set one up on the Channels page first." in page
    assert "No groups have arrived from your sign-in provider yet." in page


# ----------------------------------------------------- tools per chat app
def test_tools_per_chat_app_reach_the_tool_rules(audit_rows):
    from maverick.safety.tool_acl import resolve_lists, resolve_max_risk

    _installer('[channels.slack]\nenabled = true\n[channels.telegram]\nenabled = true\n')
    value = [{"name": "slack", "denied_tools": ["shell"], "allowed_tools": [],
              "max_risk": "medium"}]
    r = _save([{"id": "security.channels", "value": value}])
    assert r.status_code == 200, r.text
    _loaded()
    allowed, denied = resolve_lists(channel="slack")
    assert "shell" in denied and resolve_max_risk(channel="slack") == "medium"
    assert audit_rows[-1]["section"] == "security" and audit_rows[-1]["key"] == "channels"
    assert audit_rows[-1]["actor"] and audit_rows[-1]["confirmed"] is False
    row = _row("security.channels")
    assert row["value_text"] == "1 chat app"
    assert row["grid"]["rows"][0]["cells"]["denied_tools"][0]["value"] == "shell"
    # Tightening (another app, another blocked tool) needs no confirmation.
    tighter = value + [{"name": "telegram", "denied_tools": ["shell", "http_fetch"],
                        "allowed_tools": [], "max_risk": "low"}]
    assert _save([{"id": "security.channels", "value": tighter}]).status_code == 200


@pytest.mark.parametrize("loosened", [
    [{"name": "slack", "denied_tools": [], "allowed_tools": [], "max_risk": "medium"}],
    [{"name": "slack", "denied_tools": ["shell"], "allowed_tools": [], "max_risk": "high"}],
    [{"name": "slack", "denied_tools": ["shell"], "allowed_tools": [], "max_risk": ""}],
    [{"name": "slack", "denied_tools": ["shell"], "allowed_tools": ["read_file", "shell"],
      "max_risk": "medium"}],
    [],
])
def test_loosening_tools_for_a_chat_app_needs_confirmation(audit_rows, loosened):
    _installer('[channels.slack]\nenabled = true\n')
    start = [{"name": "slack", "denied_tools": ["shell"], "allowed_tools": ["read_file"],
              "max_risk": "medium"}]
    assert _save([{"id": "security.channels", "value": start}]).status_code == 200
    _loosens({"id": "security.channels", "value": loosened}, audit_rows)


def test_tools_per_chat_app_are_validated(audit_rows):
    _installer('[channels.slack]\nenabled = true\n')
    for bad in (
        [{"name": "carrier-pigeon", "denied_tools": [], "allowed_tools": [], "max_risk": ""}],
        [{"name": "slack", "denied_tools": ["no_such_tool_anywhere"], "allowed_tools": [],
          "max_risk": ""}],
        [{"name": "slack", "denied_tools": [], "allowed_tools": [], "max_risk": "extreme"}],
        [{"name": "slack", "denied_tools": "shell", "allowed_tools": [], "max_risk": ""}],
        [{"name": "slack", "denied_tools": ["sh\ud800"], "allowed_tools": [], "max_risk": ""}],
    ):
        # Sent as escaped JSON, the way any script can send it.
        body = json.dumps({"expected_revision": client.get(API, params={"q":"__revision__"}).json()["revision"], "changes": [{"id": "security.channels", "value": bad}],
                           "confirm": True})
        r = client.post(API, content=body, headers={"Content-Type": "application/json"})
        assert r.status_code == 400, bad
        assert r.json()["message"].startswith("Tools allowed in each chat app")
    assert "security" not in _loaded() and audit_rows == []


def test_installer_rules_for_a_chat_app_are_shown_and_cannot_be_dropped(audit_rows):
    _installer('[channels.slack]\nenabled = true\n'
               '[security.channels.slack]\ndenied_tools = ["shell", "computer"]\n')
    row = _row("security.channels")
    assert row["source"] == "installer"
    assert [c["value"] for c in row["grid"]["rows"][0]["cells"]["denied_tools"]] == [
        "shell", "computer"]
    r = _save([{"id": "security.channels", "value": []}], confirm=True)
    assert r.status_code == 400 and "installer" in r.json()["message"]
    # Allowing a tool the installer blocked is a loosening and is written in full,
    # so the installer's list cannot show through underneath.
    _loosens({"id": "security.channels", "value": [
        {"name": "slack", "denied_tools": ["computer"], "allowed_tools": [], "max_risk": ""}]},
        audit_rows)
    assert _loaded()["security"]["channels"]["slack"]["denied_tools"] == ["computer"]


# ------------------------------------------------- spending per AI service
def test_spending_limits_per_service_reach_the_cost_cap(audit_rows):
    from maverick import provider_cost_cap

    _installer('[providers.anthropic]\napi_key = "sk-test"\n')  # pragma: allowlist secret
    assert _save([{"id": "budget.provider_caps",
                   "value": [{"name": "anthropic", "cap": 50}]}]).status_code == 200
    _loaded()
    assert provider_cost_cap.caps_from_config() == {"anthropic": 50.0}
    assert _save([{"id": "budget.provider_caps",
                   "value": [{"name": "anthropic", "cap": 20}]}]).status_code == 200
    _loosens({"id": "budget.provider_caps", "value": [{"name": "anthropic", "cap": 80}]},
             audit_rows)
    _loosens({"id": "budget.provider_caps", "reset": True}, audit_rows)
    assert provider_cost_cap.caps_from_config() == {}
    for bad in ([{"name": "anthropic", "cap": 0}], [{"name": "anthropic", "cap": "lots"}],
                [{"name": "not-set-up", "cap": 5}], [{"name": "anthropic", "cap": True}]):
        assert _save([{"id": "budget.provider_caps", "value": bad}]).status_code == 400
    # Month to day spreads the same limit over a shorter period.
    assert _save([{"id": "budget.provider_caps_period", "value": "month"}]).status_code == 200
    assert provider_cost_cap.period_from_config() == "month"
    _loosens({"id": "budget.provider_caps_period", "value": "day"}, audit_rows)


# --------------------------------------------------------- review pauses
def test_review_pauses_reach_the_checkpoint_and_loosening_is_confirmed(audit_rows):
    from maverick.review_checkpoint import policy_from_config

    assert _row("safety.review_checkpoint.dollars")["value_text"] == "Off"
    changes = [{"id": "safety.review_checkpoint.dollars", "value": 10},
               {"id": "safety.review_checkpoint.tool_calls", "value": 200},
               {"id": "safety.review_checkpoint.wall_seconds", "value": 30}]
    assert _save(changes).status_code == 200
    _loaded()
    policy = policy_from_config()
    assert (policy.dollars, policy.tool_calls, policy.wall_seconds) == (10.0, 200, 1800.0)
    assert _row("safety.review_checkpoint.wall_seconds")["value_text"] == "30 minutes"
    _loosens({"id": "safety.review_checkpoint.dollars", "value": 50}, audit_rows)
    _loosens({"id": "safety.review_checkpoint.tool_calls", "value": None}, audit_rows)
    assert policy_from_config().tool_calls is None
    assert _save([{"id": "safety.review_checkpoint.dollars", "value": 0}]).status_code == 400


# ------------------------------------------------------------- approvals
def test_approval_floor_reaches_governed_actions(audit_rows):
    from maverick import governed_actions

    assert _save([{"id": "actions.require_approval_at", "value": "medium"}]).status_code == 200
    _loaded()
    assert governed_actions._require_approval_at() == "medium"
    _loosens({"id": "actions.require_approval_at", "value": "high"}, audit_rows)
    assert _save([{"id": "actions.require_approval_at", "value": "never"}]).status_code == 400
    assert _save([{"id": "actions.enable", "value": True}]).status_code == 200
    assert governed_actions.enabled() is True
    _loosens({"id": "actions.enable", "value": False}, audit_rows)


def test_approval_rules_route_approvals_to_a_person(audit_rows):
    from maverick.approval_delegation import route
    from maverick_dashboard import rbac

    rbac.set_role("user:ada", "admin")
    rules = [{"delegate_to": "user:ada", "min_risk": "high", "tool_glob": "*"}]
    _loosens({"id": "approval.delegation", "value": rules}, audit_rows)
    _loaded()
    assert route({"risk": "high", "tool": "shell"}) == "user:ada"
    assert route({"risk": "low", "tool": "shell"}) is None
    assert audit_rows[-1]["new"] == rules
    assert _row("approval.delegation")["value_text"] == "1 rule"
    for bad in ([{"delegate_to": "user:nobody", "min_risk": "", "tool_glob": "*"}],
                [{"delegate_to": "", "min_risk": "", "tool_glob": "*"}],
                [{"delegate_to": "user:ada", "min_risk": "huge", "tool_glob": "*"}],
                [{"delegate_to": "user:ada", "min_risk": "", "tool_glob": "no such tool"}],
                rules + rules):
        assert _save([{"id": "approval.delegation", "value": bad}],
                     confirm=True).status_code == 400, bad


# ------------------------------------------------------------------ Ekko
def test_ekko_app_policy_reaches_the_kernel(audit_rows):
    from maverick import config

    _loosens({"id": "ekko.allowed_apps", "value": ["excel", "word"]}, audit_rows)
    assert _save([{"id": "ekko.blocked_apps", "value": ["word"]}]).status_code == 200
    assert _save([{"id": "ekko.retention_days", "value": 7}]).status_code == 200
    _loaded()
    policy = config.get_ekko()
    assert policy["allowed_apps"] == ["excel"] and "word" in policy["blocked_apps"]
    assert policy["retention_days"] == 7
    # Always-blocked apps are not offered at all.
    offered = {c["value"] for c in _row("ekko.allowed_apps")["choices"]}
    assert "email" not in offered and "excel" in offered
    assert _save([{"id": "ekko.allowed_apps", "value": ["email"]}]).status_code == 400
    _loosens({"id": "ekko.capture_level", "value": "guided"}, audit_rows)
    _loosens({"id": "ekko.retention_days", "value": 20}, audit_rows)
    _loosens({"id": "ekko.blocked_apps", "value": []}, audit_rows)
    r = _save([{"id": "ekko.min_distinct_days", "value": 25}])
    assert r.status_code == 400 and "days Ekko keeps what it notices" in r.json()["message"]


# ------------------------------------------------------ self-improvement
def test_first_self_improvement_change_keeps_the_careful_profile(audit_rows):
    from maverick import config

    assert config.get_self_harness()["risk_limited"] is True
    assert _save([{"id": "self_harness.transfer_auto", "value": True}]).status_code == 200
    _loaded()
    harness = config.get_self_harness()
    # Writing one key must not switch the careful profile or nightly runs off.
    assert harness["risk_limited"] is True and harness["auto_run"] is True
    assert harness["transfer_auto"] is True
    assert [row["key"] for row in audit_rows] == ["transfer_auto"]
    _loosens({"id": "self_harness.risk_limited", "value": False}, audit_rows)
    assert config.get_self_harness()["risk_limited"] is False
    # Reset writes the careful default back rather than letting an older one apply.
    assert _save([{"id": "self_harness.risk_limited", "reset": True}]).status_code == 200
    assert config.get_self_harness()["risk_limited"] is True
    _loosens({"id": "self_harness.corpus_harvest", "value": "auto"}, audit_rows)
    assert config.get_self_harness()["corpus_harvest"] == "auto"


def test_an_older_partial_table_shows_its_real_values():
    _installer("[self_harness]\nmin_support = 4\n")
    assert _row("self_harness.risk_limited")["value"] is False
    assert _row("self_harness.auto_run")["value"] is False


# ------------------------------------------------------ AI governance
def test_incident_report_deciders_match_what_the_incident_pages_accept(audit_rows):
    from maverick_dashboard import rbac

    rbac.set_role("user:ada", "admin")
    value = [{"principal": "user:ada", "role": "legal_counsel",
              "authority_refs": "de-bnetza, fr-cnil, de-bnetza"}]
    _loosens({"id": "eu_ai_incidents.authorities", "value": value}, audit_rows)
    entry = _loaded()["eu_ai_incidents"]["authorities"][0]
    assert set(entry) == {"principal", "role", "authority_refs"}
    assert entry["authority_refs"] == ["de-bnetza", "fr-cnil"]
    # Removing a person is not a loosening.
    assert _save([{"id": "eu_ai_incidents.authorities", "value": []}]).status_code == 200
    for bad in (
        value + [{"principal": "user:ada", "role": "safety_officer", "authority_refs": "x"}],
        [{"principal": "user:ada", "role": "chief", "authority_refs": "x"}],
        [{"principal": "user:ada", "role": "legal_counsel", "authority_refs": ""}],
        [{"principal": "user:ada", "role": "legal_counsel", "authority_refs": "no spaces"}],
    ):
        assert _save([{"id": "eu_ai_incidents.authorities", "value": bad}],
                     confirm=True).status_code == 400, bad


def test_governance_limits_are_accepted_by_the_kernel(audit_rows):
    from maverick import ai_cost_collectors, red_team_assurance
    from maverick.config import candidate_promotion_enabled
    from maverick_dashboard import candidate_promotion_composition as promotion

    changes = [
        {"id": "ai_cost_roi.aws.enable", "value": True},
        {"id": "ai_cost_roi.collector_poll_seconds", "value": 6},
        {"id": "red_team_assurance.enable", "value": True},
        {"id": "red_team_assurance.max_cases", "value": 20},
        {"id": "red_team_assurance.campaign_ttl_seconds", "value": 48},
        {"id": "red_team_assurance.evidence_validity_seconds", "value": 30},
        {"id": "candidate_promotion.review_ttl_seconds", "value": 30},
    ]
    assert _save(changes).status_code == 200
    cfg = _loaded()
    schedule = ai_cost_collectors.configured_collector_schedule(cfg["ai_cost_roi"])
    assert schedule.poll_seconds == 6 * 3600
    settings = red_team_assurance._settings()
    assert (settings["max_cases"], settings["campaign_ttl_seconds"],
            settings["evidence_validity_seconds"]) == (20, 48 * 3600, 30 * 86400)
    _loosens({"id": "candidate_promotion.enable", "value": True}, audit_rows)
    assert candidate_promotion_enabled() is True
    policy = promotion.policy_from_config(_loaded())
    assert policy is not None and policy.review_ttl_seconds == 1800
    _loosens({"id": "red_team_assurance.evidence_validity_seconds", "value": 90}, audit_rows)


def test_knowledge_library_and_supplier_previews(audit_rows):
    from maverick import config

    assert _save([{"id": "knowledge_access.enable", "value": False}]).status_code == 200
    assert config.knowledge_access_enabled() is False
    _loosens({"id": "vendor_onboarding.reviewed_uploads", "value": False}, audit_rows)
    assert config.vendor_reviewed_uploads_enabled() is False


# ------------------------------------------------------- integrations
def test_catalogs_and_backup_models(audit_rows):
    from maverick import mcp_registry, templates
    from maverick.provider_failover import fallback_models

    _loosens({"id": "template_registries.indexes",
              "value": ["https://catalog.example.com/lightwork"]}, audit_rows)
    _loaded()
    assert templates._configured_template_indexes() == ["https://catalog.example.com/lightwork"]
    for bad in (["http://catalog.example.com"], ["https://catalog.example.com/x?token=abc"]):
        assert _save([{"id": "mcp_registries.indexes", "value": bad}],
                     confirm=True).status_code == 400
    _loosens({"id": "mcp_registries.indexes", "value": ["https://tools.example.com"]},
             audit_rows)
    assert mcp_registry._configured_mcp_registries() == ["https://tools.example.com"]
    models = [c["value"] for c in _row("provider_failover.chains")["grid"]["key_choices"]]
    primary, backup = models[0], models[1]
    _loosens({"id": "provider_failover.chains",
              "value": [{"name": primary, "fallbacks": [backup]}]}, audit_rows)
    assert fallback_models(primary) == [backup]
    # Removing a backup sends nothing anywhere new.
    assert _save([{"id": "provider_failover.chains", "value": []}]).status_code == 200
    assert _save([{"id": "provider_failover.chains",
                   "value": [{"name": primary, "fallbacks": ["made-up-model"]}]}],
                 confirm=True).status_code == 400


def test_bedrock_sign_in_is_saved_and_kept_when_its_key_is_cleared(audit_rows):
    from maverick import config
    from maverick_dashboard import settings_store

    assert _save([{"id": "providers.bedrock.auth_mode", "value": "api_key"}]).status_code == 200
    assert _loaded()["providers"]["bedrock"] == {"auth_mode": "api_key"}
    assert config.config_source_errors() == {}
    settings_store.set_provider("openai", api_key="sk-keep")  # pragma: allowlist secret
    assert _loaded()["providers"]["bedrock"] == {"auth_mode": "api_key"}
    assert _save([{"id": "providers.bedrock.auth_mode", "value": "iam"}]).status_code == 200
    assert _save([{"id": "providers.bedrock.auth_mode", "value": "password"}]).status_code == 400
    # The catalog save never touched the stored key, which stays sealed.
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert "sk-keep" not in stored and "sk-keep" not in client.get(API).text


def test_screen_control_settings_reach_the_kernel(audit_rows):
    from maverick.vision_click import min_confidence_floor

    assert _save([{"id": "computer_use.vision_min_confidence", "value": 70}]).status_code == 200
    _loaded()
    assert min_confidence_floor() == pytest.approx(0.7)
    _loosens({"id": "computer_use.vision_min_confidence", "value": 40}, audit_rows)


# ------------------------------------------------------ people & access
def test_departments_turned_off_and_by_default(audit_rows):
    from maverick.domain import _disabled_suites
    from maverick.suite_grants import default_suites

    assert _save([{"id": "suites.*", "value": [{"name": "finance", "on": False}]}]).status_code == 200
    _loaded()
    assert _disabled_suites() == {"finance"}
    assert _row("suites.*")["value_text"] == "1 department"
    assert _save([{"id": "suites.*", "value": [{"name": "nowhere", "on": False}]}]).status_code == 400
    # Moving from "every department" to a short list narrows access.
    assert _save([{"id": "dashboard.default_suites", "value": ["finance"]}]).status_code == 200
    assert default_suites() == frozenset({"finance"})
    _loosens({"id": "dashboard.default_suites", "value": ["finance", "tax"]}, audit_rows)
    _loosens({"id": "dashboard.default_suites", "value": []}, audit_rows)
    assert default_suites() is None


def test_sign_in_groups_map_to_roles_and_departments(monkeypatch, audit_rows):
    from maverick_dashboard import scim, scim_groups

    monkeypatch.setattr(scim, "_load_groups", lambda: {
        "a" * 32: {"id": "a" * 32, "displayName": "Finance Team", "members": []}})
    row = _row("dashboard.group_roles")
    assert [k["value"] for k in row["grid"]["key_choices"]] == ["Finance Team"]
    _loosens({"id": "dashboard.group_roles",
              "value": [{"name": "Finance Team", "role": "operator"}]}, audit_rows)
    _loosens({"id": "dashboard.group_suites",
              "value": [{"name": "Finance Team", "suites": ["finance", "tax"]}]}, audit_rows)
    _loaded()
    assert scim_groups._ci_mapping("group_roles") == {"finance team": "operator"}
    assert scim_groups._ci_mapping("group_suites") == {"finance team": ["finance", "tax"]}
    for bad in ([{"name": "Unknown Group", "role": "operator"}],
                [{"name": "Finance Team", "role": "emperor"}]):
        assert _save([{"id": "dashboard.group_roles", "value": bad}],
                     confirm=True).status_code == 400


def test_non_admins_cannot_read_the_new_option_lists(monkeypatch):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    assert client.get(API + "/choices/security.channels?column=denied_tools").status_code == 403
    assert _save([{"id": "actions.require_approval_at", "value": "low"}]).status_code == 403
