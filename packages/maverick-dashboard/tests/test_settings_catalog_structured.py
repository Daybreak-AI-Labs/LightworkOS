"""Settings > All settings: structured rows (lists, tables, documents, levels).

Each row added by ``settings_catalog_structured`` (and the fingerprint rows of
``settings_catalog_governance``) is filled in by choosing from real data, is
validated on the server, asks before it loosens a protection, writes one
audit row per change, and -- the point of these tests -- changes what the
kernel reads.
"""
from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_all_page as page
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard import settings_catalog_structured as structured
from maverick_dashboard.app import app

from test_support.settings_pages import every_group, save_catalog
from test_support.starlette_state import patch_state

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"
ROWS = [catalog.BY_ID[s.id] for s in structured.entries(catalog.S, catalog.C, catalog.Column)]
_PASSWORD = "team-password-for-tests-only-0000000001"  # pragma: allowlist secret
_OTHER = "team-password-for-tests-only-0000000002"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in list(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")) and name not in {
                "MAVERICK_HOME", "MAVERICK_ENCRYPT_AT_REST"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(page, "_CHECK_TIMES", [])
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


def _save(changes, confirm=False):
    return save_catalog(client, API, json={"changes": changes, "confirm": confirm})


def _saved(changes):
    """Save, confirming only when the server asks."""
    first = _save(changes)
    if first.status_code == 409 and "confirm" in first.json():
        first = _save(changes, confirm=True)
    assert first.status_code == 200, first.text
    return first


def _row(setting_id):
    for group in client.get(API).json()["groups"]:
        for row in group["settings"]:
            if row["id"] == setting_id:
                return row
    raise AssertionError(setting_id)


def _loaded():
    from maverick import config

    config.reset_config_cache()
    return config.load_config()


def _base_config(text: str) -> None:
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text(text, encoding="utf-8")
    config.reset_config_cache()


def _changed(audit_rows, setting_id):
    setting = catalog.BY_ID[setting_id]
    return [a for a in audit_rows if a.get("key") == setting.key
            and a.get("section") == setting.section]


def _choices(setting_id, column=""):
    url = f"{API}/choices/{setting_id}" + (f"?column={column}" if column else "")
    response = client.get(url)
    assert response.status_code == 200, response.text
    return [c["value"] for c in response.json()["choices"]]


# ------------------------------------------------------------------- catalog
def test_rows_are_plain_and_named_by_their_readers():
    from test_support.plain_language import developer_terms

    assert len(ROWS) == 21
    for row in ROWS:
        assert row.help.endswith(".") and "_" not in row.label, row.id
        assert row.control != "text" or row.pattern or row.workspace_segment, row.id
    page_text = every_group(client)
    for marker in ("data-picks", "data-document", "data-fingerprint", "data-segment-at",
                   "data-preview-url", "data-grid-keysearch"):
        assert marker in page_text, marker
    assert developer_terms(page_text) == []


# --------------------------------------------------- tools everywhere / person
def test_tools_blocked_everywhere_reach_the_tool_rules(audit_rows):
    from maverick.safety import tool_acl

    assert "shell" in _choices("security.denied_tools")
    r = _save([{"id": "security.denied_tools", "value": ["shell"]}])
    assert r.status_code == 200, r.text  # blocking more is never asked about
    assert "shell" in tool_acl.resolve_lists()[1]
    assert _changed(audit_rows, "security.denied_tools")[-1]["new"] == ["shell"]
    row = _row("security.denied_tools")
    assert row["picks"][0]["value"] == "shell" and row["choices_url"]
    unblock = _save([{"id": "security.denied_tools", "value": []}])
    assert unblock.status_code == 409 and unblock.json()["confirm"][0]["id"] == \
        "security.denied_tools"
    assert _save([{"id": "security.denied_tools", "value": ["no_such_tool_xyz"]}]
                 ).status_code == 400


def test_only_these_tools_narrows_every_run_and_asks_before_opening_up(audit_rows):
    from maverick.safety import tool_acl

    assert _save([{"id": "security.allowed_tools", "value": ["read_file"]}]).status_code == 200
    assert tool_acl.resolve_lists()[0] == {"read_file"}
    widen = _save([{"id": "security.allowed_tools", "value": ["read_file", "shell"]}])
    assert widen.status_code == 409
    empty = _save([{"id": "security.allowed_tools", "value": []}])
    assert empty.status_code == 409  # empty means every tool
    _saved([{"id": "security.allowed_tools", "value": []}])
    assert tool_acl.resolve_lists()[0] == set()


def test_tools_for_one_person_come_from_people_who_wrote_in(audit_rows):
    from maverick import world_model
    from maverick.safety import tool_acl

    world = world_model.WorldModel(world_model.DEFAULT_DB)
    world.get_or_create_conversation(channel="telegram", user_id="12345")
    person = "telegram:12345"
    assert person in _choices("security.users")
    assert _row("security.users")["grid"]["key_choices_url"]
    rules = [{"name": person, "denied_tools": ["shell"], "allowed_tools": [],
              "max_risk": "low"}]
    assert _save([{"id": "security.users", "value": rules}]).status_code == 200
    assert "shell" in tool_acl.resolve_lists(channel="telegram", user_id=person)[1]
    assert tool_acl.resolve_max_risk(channel="telegram", user_id=person) == "low"
    assert _changed(audit_rows, "security.users")
    stranger = [{"name": "telegram:99999", "denied_tools": [], "allowed_tools": [],
                 "max_risk": ""}]
    assert _save([{"id": "security.users", "value": stranger}]).status_code == 400
    assert _save([{"id": "security.users", "value": []}]).status_code == 409


# ------------------------------------------------------------------ approvals
def test_more_approvers_for_riskier_actions(audit_rows, monkeypatch):
    from maverick.safety.dual_control import required_approvals

    rows = [{"name": "critical", "people": 3}]
    assert _save([{"id": "security.approvals_required_by_risk", "value": rows}]
                 ).status_code == 200
    assert required_approvals("critical") == 3 and required_approvals("high") == 1
    _base_config("[security]\napprovals_required = 4\n")
    assert required_approvals("critical") == 4  # a level never needs fewer people
    fewer = _save([{"id": "security.approvals_required_by_risk",
                    "value": [{"name": "critical", "people": 2}]}])
    assert fewer.status_code == 409
    assert _save([{"id": "security.approvals_required_by_risk",
                   "value": [{"name": "extreme", "people": 2}]}]).status_code == 400
    monkeypatch.setenv("MAVERICK_APPROVALS_REQUIRED", "2")
    assert _save([{"id": "security.approvals_required_by_risk", "value": rows}],
                 confirm=True).status_code == 409
    assert required_approvals("critical") == 2  # the environment still wins


# ------------------------------------------------------------------ gateway
def _gateway_settings():
    from maverick.llm_gateway import get_llm_gateway_config

    return get_llm_gateway_config()


def test_team_passwords_are_sealed_and_let_that_team_in(audit_rows):
    from maverick import config
    from maverick.llm_gateway import _team_for_token

    rows = [{"name": "ops", "password": _PASSWORD}]
    first = _save([{"id": "llm_gateway.team_passwords", "value": rows}])
    assert first.status_code == 409  # a new team can send requests
    assert _save([{"id": "llm_gateway.team_passwords", "value": rows}],
                 confirm=True).status_code == 200
    assert _PASSWORD not in config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert _PASSWORD not in client.get(API).text
    assert _team_for_token(_PASSWORD, _gateway_settings()) == "ops"
    assert _changed(audit_rows, "llm_gateway.team_passwords")[-1]["new"] == {"ops": "set"}
    assert _PASSWORD not in repr(audit_rows)
    grid = _row("llm_gateway.team_passwords")["grid"]
    assert grid["rows"][0]["cells"]["password"] == {"is_set": True}
    # Leaving the password empty keeps it; a new team needs one.
    assert _save([{"id": "llm_gateway.team_passwords",
                   "value": [{"name": "ops", "password": ""}]}]).status_code == 200
    assert _team_for_token(_PASSWORD, _gateway_settings()) == "ops"
    assert _save([{"id": "llm_gateway.team_passwords",
                   "value": [{"name": "ops", "password": ""}, {"name": "sales", "password": ""}]}],
                 confirm=True).status_code == 400
    same = [{"name": "ops", "password": ""}, {"name": "sales", "password": _PASSWORD}]
    assert _save([{"id": "llm_gateway.team_passwords", "value": same}],
                 confirm=True).status_code == 400
    assert _save([{"id": "llm_gateway.team_passwords",
                   "value": [{"name": "default", "password": _OTHER}]}],
                 confirm=True).status_code == 400


def test_team_limits_hold_each_team_to_its_budget(audit_rows):
    from maverick.llm_gateway import _team_budget_limits

    _saved([{"id": "llm_gateway.team_passwords",
             "value": [{"name": "ops", "password": _PASSWORD}]}])
    assert _choices("llm_gateway.team_budgets.teams") == ["ops"]
    limits = [{"name": "ops", "max_requests": 10, "max_prompt_tokens": 0,
               "max_completion_tokens": 500}]
    assert _save([{"id": "llm_gateway.team_budgets.teams", "value": limits}]).status_code == 200
    budget = _team_budget_limits(_gateway_settings(), "ops")
    assert budget["max_requests"] == 10 and budget["max_completion_tokens"] == 500
    raised = [{**limits[0], "max_requests": 20}]
    assert _save([{"id": "llm_gateway.team_budgets.teams", "value": raised}]).status_code == 409
    no_limit = [{**limits[0], "max_completion_tokens": 0}]
    assert _save([{"id": "llm_gateway.team_budgets.teams", "value": no_limit}]
                 ).status_code == 409
    # The team's password can't go while it still has limits.
    gone = _save([{"id": "llm_gateway.team_passwords", "value": []}], confirm=True)
    assert gone.status_code == 400 and "no password" in gone.json()["message"]
    assert _save([{"id": "llm_gateway.team_budgets.teams",
                   "value": [{**limits[0], "name": "ghosts"}]}]).status_code == 400
    assert _loaded()["llm_gateway"]["team_budgets"]["ops"]["max_requests"] == 10


# ---------------------------------------------------------------------- voice
def test_named_voices_and_language_voices_reach_spoken_replies(audit_rows):
    from maverick.voice_personas import get_persona, resolve_speech_args, voice_for_language

    voices = _choices("voice.personas", "voice")
    assert "openai:nova" in voices and "elevenlabs:21m00Tcm4TlvDq8ikWAM" in voices
    personas = [{"name": "concierge", "voice": "openai:nova", "language": "en"}]
    assert _save([{"id": "voice.personas", "value": personas}]).status_code == 200
    preset = get_persona("concierge")
    assert (preset.backend, preset.voice, preset.language) == ("openai", "nova", "en")
    assert resolve_speech_args({"persona": "concierge", "text": "hi"})["voice"] == "nova"
    languages = [{"name": "fr", "voice": "openai:alloy"}]
    assert _save([{"id": "voice.languages", "value": languages}]).status_code == 200
    assert voice_for_language("fr-CA").voice == "alloy"
    assert _changed(audit_rows, "voice.personas") and _changed(audit_rows, "voice.languages")
    assert _save([{"id": "voice.personas", "value": [{"name": "x", "voice": "made-up"}]}]
                 ).status_code == 400
    assert _save([{"id": "voice.languages", "value": [{"name": "xx", "voice": "openai:nova"}]}]
                 ).status_code == 400


# -------------------------------------------------------------------- sandbox
def test_outside_work_area_options_reach_the_program(audit_rows, monkeypatch, tmp_path):
    from maverick.sandbox import build_sandbox, sdk

    seen = {}

    def fake_backend(name, **kwargs):
        seen.update(name=name, **kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(sdk, "load_entry_point_backend", fake_backend)
    rows = [{"name": "region", "value": "eu-west"}]
    assert _save([{"id": "sandbox.options", "value": rows}]).status_code == 409
    _saved([{"id": "sandbox.options", "value": rows}])
    build_sandbox(workdir=str(tmp_path), backend="ep:acme")
    assert seen["name"] == "acme" and seen["options"] == {"region": "eu-west"}
    assert _changed(audit_rows, "sandbox.options")
    assert _save([{"id": "sandbox.options", "value": [{"name": "1bad", "value": "x"}]}],
                 confirm=True).status_code == 400


# -------------------------------------------------------------------- plugins
def _program(tmp_path, name="node"):
    path = tmp_path / "bin" / (name + ".exe" if os.name == "nt" else name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_typescript_plugins_start_the_program_chosen(audit_rows, monkeypatch, tmp_path):
    from maverick import ts_plugin_host

    started = []
    monkeypatch.setattr(ts_plugin_host, "load_ts_plugin",
                        lambda command, **_kw: started.append(command) or [])
    program, script = _program(tmp_path), tmp_path / "plugin.js"
    script.write_text("// plugin\n", encoding="utf-8")
    rules = [{"program": str(program), "file": str(script), "args": "--quiet"}]
    assert _save([{"id": "plugins.ts", "value": rules}]).status_code == 409
    _saved([{"id": "plugins.ts", "value": rules}])
    ts_plugin_host.load_configured_ts_plugins()
    assert started == [[str(program), str(script), "--quiet"]]
    assert _changed(audit_rows, "plugins.ts")
    not_runnable = tmp_path / "plain.txt"
    not_runnable.write_text("x", encoding="utf-8")
    bad = [{"program": str(not_runnable), "file": "", "args": ""}]
    assert _save([{"id": "plugins.ts", "value": bad}], confirm=True).status_code == 400
    outside = [{"program": "/proc/self/exe", "file": "", "args": ""}]
    assert _save([{"id": "plugins.ts", "value": outside}], confirm=True).status_code == 400


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_program_other_accounts_can_replace_is_refused(audit_rows, tmp_path):
    # Lightwork later runs the chosen program, so any account on the server that
    # can change the file, or swap it inside its folder, could run code as Lightwork.
    writable = _program(tmp_path, "shared-node")
    writable.chmod(0o777)
    rules = [{"program": str(writable), "file": "", "args": ""}]
    r = _save([{"id": "plugins.ts", "value": rules}], confirm=True)
    assert r.status_code == 400 and "change" in r.text
    open_folder = tmp_path / "open"
    open_folder.mkdir()
    open_folder.chmod(0o777)
    swappable = open_folder / "node"
    swappable.write_text("#!/bin/sh\n", encoding="utf-8")
    swappable.chmod(0o755)
    rules = [{"program": str(swappable), "file": "", "args": ""}]
    r = _save([{"id": "plugins.ts", "value": rules}], confirm=True)
    assert r.status_code == 400 and "change" in r.text
    safe = _program(tmp_path, "node")
    _saved([{"id": "plugins.ts", "value": [{"program": str(safe), "file": "", "args": ""}]}])


@pytest.mark.skipif(os.name == "nt", reason="POSIX links and permission bits")
def test_a_location_is_stored_as_the_file_that_was_checked(tmp_path):
    # "link/.." means a different file to the server (which follows the link)
    # than to the stored text (which drops "link/.."), so the checks would
    # pass on one file and Lightwork would later use another.
    from maverick_dashboard import settings_paths

    (tmp_path / "a" / "b").mkdir(parents=True)
    checked = tmp_path / "a" / "key.pem"
    checked.write_text("private", encoding="utf-8")
    checked.chmod(0o600)
    stored = tmp_path / "key.pem"
    stored.write_text("readable by anyone", encoding="utf-8")
    stored.chmod(0o644)
    (tmp_path / "lnk").symlink_to(tmp_path / "a" / "b")
    with pytest.raises(settings_paths.PathRefused):
        settings_paths.check(str(tmp_path / "lnk" / ".." / "key.pem"), kind="file", private=True)
    with pytest.raises(settings_paths.PathRefused):
        settings_paths.check(str(stored), kind="file", private=True)
    assert settings_paths.check(str(checked), kind="file", private=True) == str(checked)
    assert settings_paths.check(str(tmp_path / "a" / "b" / ".." / "key.pem"), kind="file",
                                private=True) == str(checked)
    assert settings_paths.check(str(tmp_path / "lnk"), kind="folder") == str(tmp_path / "lnk")


def test_network_plugins_connect_only_on_this_server(audit_rows, monkeypatch, tmp_path):
    from maverick import grpc_plugin_host

    dialled = []
    monkeypatch.setattr(grpc_plugin_host, "load_grpc_plugin",
                        lambda target, command=None, **_kw: dialled.append((target, command))
                        or [])
    program = _program(tmp_path, "tool-server")
    rules = [{"target": "localhost:50051", "program": str(program), "args": "--port,50051"},
             {"target": "unix:///run/tools.sock", "program": "", "args": ""}]
    _saved([{"id": "plugins.grpc", "value": rules}])
    grpc_plugin_host.load_configured_grpc_plugins()
    assert dialled == [("localhost:50051", [str(program), "--port", "50051"]),
                       ("unix:///run/tools.sock", None)]
    remote = [{"target": "tools.example.com:50051", "program": "", "args": ""}]
    assert _save([{"id": "plugins.grpc", "value": remote}], confirm=True).status_code == 400


# ------------------------------------------------------------------ workforce
def test_each_agents_independence_reaches_the_autonomy_check(audit_rows):
    from maverick.agent_autonomy import AutonomyLevel, effective_profile

    agent = _choices("workforce.agents", "name")[0]
    rules = [{"name": agent, "default": "auto", "low": "", "medium": "", "high": "suggest",
              "onboarding": False}]
    assert _save([{"id": "workforce.agents", "value": rules}]).status_code == 409
    _saved([{"id": "workforce.agents", "value": rules}])
    profile = effective_profile(agent, None)
    assert profile.default is AutonomyLevel.AUTO and profile.high is AutonomyLevel.SUGGEST
    assert profile.onboarding is False
    assert _changed(audit_rows, "workforce.agents")
    assert _save([{"id": "workforce.agents", "value": [{**rules[0], "name": "no_such_agent"}]}],
                 confirm=True).status_code == 400


# -------------------------------------------------------------------- finance
def test_other_rule_feeds_are_checked_with_their_field_names(audit_rows):
    from maverick_dashboard.finance_scheduler import configured_sources

    feeds = [{"key": "ca-notices", "name": "California notices", "jurisdiction": "US-CA",
              "url": "https://notices.example.gov/feed.json", "format": "json",
              "default_regimes": ["sox"], "default_domains": ["lending"],
              "field_map": "items=data.results, title=headline"}]
    assert _save([{"id": "finance_operations.state_feeds", "value": feeds}]).status_code == 409
    _saved([{"id": "finance_operations.state_feeds", "value": feeds}])
    source = next(s for s in configured_sources(_loaded()["finance_operations"])
                  if s.key == "ca-notices")
    assert source.jurisdiction == "US-CA" and source.format == "json"
    assert dict(source.field_map) == {"items": "data.results", "title": "headline"}
    assert source.default_regimes == ("sox",) and source.default_domains == ("lending",)
    for bad in ({"field_map": "colour=hue"}, {"url": "http://notices.example.gov/feed"},
                {"jurisdiction": "US-ZZ"}):
        assert _save([{"id": "finance_operations.state_feeds", "value": [{**feeds[0], **bad}]}],
                     confirm=True).status_code == 400, bad


# ----------------------------------------------------------- governance/grc
def test_extra_details_asked_of_the_grc_system(audit_rows):
    from maverick.grc_sync import get_grc_sync_config

    rows = [{"name": "sysparm_fields", "value": "sys_id,number"}]
    assert _save([{"id": "grc_sync.response_field_params", "value": rows}]).status_code == 200
    assert get_grc_sync_config()["response_field_params"] == {"sysparm_fields": "sys_id,number"}
    nine = [{"name": f"p{i}", "value": "x"} for i in range(9)]
    assert _save([{"id": "grc_sync.response_field_params", "value": nine}]).status_code == 400


def test_the_trial_measure_comes_from_the_release_setup(audit_rows, monkeypatch):
    from maverick import config
    from maverick_dashboard.candidate_promotion_composition import policy_from_config

    class Adapter:
        @staticmethod
        def canary_metrics():
            return ("p95_latency_ms",)

    patch_state(monkeypatch, app.state, "candidate_promotion_deployment_adapter", Adapter(),
                raising=False)
    assert _choices("candidate_promotion.canary_metric") == ["error_rate", "p95_latency_ms"]
    change = [{"id": "candidate_promotion.canary_metric", "value": "p95_latency_ms"}]
    assert _save(change).status_code == 409
    _saved(change)
    _base_config("[candidate_promotion]\nenable = true\n")
    policy = policy_from_config(config.load_global_config())
    assert policy.canary_invariants[0].metric == "p95_latency_ms"
    assert _save([{"id": "candidate_promotion.canary_metric", "value": "made_up"}],
                 confirm=True).status_code == 400


# ---------------------------------------------------------- learning (harness)
def test_repeats_needed_for_each_kind_of_mistake(audit_rows):
    from maverick.config import get_self_harness

    assert "timeout" in _choices("self_harness.min_support_by_class")
    rows = [{"name": "auth", "support": 5}]
    assert _save([{"id": "self_harness.min_support_by_class", "value": rows}]).status_code == 200
    assert get_self_harness()["min_support_by_class"] == {"auth": 5}
    assert get_self_harness()["risk_limited"] is True  # the careful profile stays on
    fewer = _save([{"id": "self_harness.min_support_by_class",
                    "value": [{"name": "auth", "support": 4}]}])
    assert fewer.status_code == 409
    careful = _save([{"id": "self_harness.min_support_by_class",
                      "value": [{"name": "auth", "support": 2}]}], confirm=True)
    assert careful.status_code == 400 and "at least 3" in careful.json()["message"]


# -------------------------------------------------------------- trust roots
def _key_hex():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    public = Ed25519PrivateKey.generate().public_key()
    return public.public_bytes(serialization.Encoding.Raw,
                               serialization.PublicFormat.Raw).hex()


_K1, _K2 = "KEY-" + "1" * 32, "KEY-" + "2" * 32


def _roots(version, keys):
    from maverick.ai_benchmark_exchange_transport import TRUST_ROOT_SCHEMA

    return json.dumps({"schema": TRUST_ROOT_SCHEMA, "version": version, "keys": keys})


def test_trusted_benchmark_keys_are_imported_from_the_coordinators_file(audit_rows):
    from maverick.ai_benchmark_exchange import _operator_configured_integrations

    first, second = _key_hex(), _key_hex()
    v1 = _roots(1, [{"key_id": _K1, "public_key_hex": first, "introduced_in": 1}])
    change = [{"id": "ai_benchmark_exchange.trust_roots", "value": v1}]
    assert _save(change).status_code == 409  # trusting a new key is confirmed
    _saved(change)
    _base_config("[ai_benchmark_exchange]\nenable = true\n")
    roots, _coordinator = _operator_configured_integrations()
    assert roots.version == 1 and roots.keys[0].public_key_hex == first
    row = _row("ai_benchmark_exchange.trust_roots")
    assert row["document"]["text"] == "Version 1: 1 trusted key"
    assert first not in json.dumps(row) and first not in repr(audit_rows)
    assert _changed(audit_rows, "ai_benchmark_exchange.trust_roots")[-1]["new"]["text"] == \
        "Version 1: 1 trusted key"
    # The coordinator's rules: newer versions only, keys retired not dropped.
    assert _save(change, confirm=True).status_code == 200  # the same file changes nothing
    dropped = _roots(2, [{"key_id": _K2, "public_key_hex": second, "introduced_in": 2}])
    refused = _save([{"id": "ai_benchmark_exchange.trust_roots", "value": dropped}],
                    confirm=True)
    assert refused.status_code == 400 and "retired" in refused.json()["message"]
    older = _roots(1, [{"key_id": _K1, "public_key_hex": first, "introduced_in": 1},
                       {"key_id": _K2, "public_key_hex": second, "introduced_in": 1}])
    assert _save([{"id": "ai_benchmark_exchange.trust_roots", "value": older}],
                 confirm=True).status_code == 400
    rotated = _roots(2, [
        {"key_id": _K1, "public_key_hex": first, "introduced_in": 1, "revoked_in": 2},
        {"key_id": _K2, "public_key_hex": second, "introduced_in": 2}])
    _saved([{"id": "ai_benchmark_exchange.trust_roots", "value": rotated}])
    roots, _coordinator = _operator_configured_integrations()
    assert roots.version == 2
    assert _row("ai_benchmark_exchange.trust_roots")["document"]["text"] == \
        "Version 2: 1 trusted key"
    assert _save([{"id": "ai_benchmark_exchange.trust_roots", "value": "not a document"}],
                 confirm=True).status_code == 400


# --------------------------------------------------------------- fingerprints
def test_a_fingerprint_is_worked_out_from_the_uploaded_program(audit_rows):
    program = b"#!/bin/sh\necho content credentials\n"
    setting_id = "ai_media_provenance.c2patool_executable_sha256"
    r = client.post(f"{API}/fingerprint?setting_id={setting_id}", content=program,
                    headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 200, r.text
    digest = hashlib.sha256(program).hexdigest()
    assert r.json()["fingerprint"] == digest
    assert r.json()["shown"] == " ".join(digest[i:i + 4] for i in range(0, 16, 4)).upper() + " …"
    change = [{"id": setting_id, "value": r.json()["fingerprint"]}]
    assert _save(change).status_code == 409  # a different program would be trusted
    _saved(change)
    assert _loaded()["ai_media_provenance"]["c2patool_executable_sha256"] == digest
    assert _save([{"id": setting_id, "value": "typed-by-hand"}], confirm=True).status_code == 400
    assert client.post(f"{API}/fingerprint?setting_id={setting_id}&server=true").status_code == 400
    assert client.post(f"{API}/fingerprint?setting_id={setting_id}", content=b"").status_code == 400
    assert client.post(f"{API}/fingerprint?setting_id=audit.sign", content=b"x").status_code == 404
    foreign = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "https://evil.example"})
    assert foreign.post(f"{API}/fingerprint?setting_id={setting_id}",
                        content=program).status_code == 403


def test_an_installed_library_fingerprint_matches_the_kernels_own_check():
    pytest.importorskip("PIL")
    from maverick.ai_evidence_local_parsers import _distribution_manifest_sha256

    setting_id = "ai_evidence_analysis.ocr.pillow_manifest_sha256"
    assert _row(setting_id)["fingerprint_from_server"] is True
    r = client.post(f"{API}/fingerprint?setting_id={setting_id}&server=true")
    assert r.status_code == 200, r.text
    assert r.json()["fingerprint"] == _distribution_manifest_sha256("Pillow")


# -------------------------------------------------------------- SIEM custody
def test_the_security_monitoring_address_gets_each_workspaces_own_part(audit_rows):
    from maverick.unified_audit_custody import _resolved_siem_destination, settings_from

    template = "https://siem.example.com/{tenant_sha256}/ingest"
    missing = _save([{"id": "audit.unified.custody.siem_enable", "value": True}])
    assert missing.status_code == 400  # an address is needed first
    _saved([{"id": "audit.unified.custody.siem_destination_template", "value": template},
            {"id": "audit.unified.custody.siem_enable", "value": True}])
    settings = settings_from(_loaded(), tenant_id="acme")
    assert settings.siem_enable is True
    assert _resolved_siem_destination(settings, "ab" * 32) == \
        f"https://siem.example.com/{'ab' * 32}/ingest"
    row = _row("audit.unified.custody.siem_destination_template")
    assert row["value"] == "https://siem.example.com/ingest" and row["segment_at"] == 0
    assert "[workspace]" in row["value_text"]
    # An address without the part gets it at the end; anything else is refused.
    end = _save([{"id": "audit.unified.custody.siem_destination_template",
                  "value": "https://siem.example.com/ingest"}], confirm=True)
    assert end.status_code == 200
    assert _loaded()["audit"]["unified"]["custody"]["siem_destination_template"] == \
        "https://siem.example.com/ingest/{tenant_sha256}"
    for bad in ("http://siem.example.com/x", "https://siem.example.com/x?token=1",
                "https://siem.example.com/{tenant_sha256}/{tenant_sha256}",
                "https://siem.example.com/{other}"):
        assert _save([{"id": "audit.unified.custody.siem_destination_template", "value": bad}],
                     confirm=True).status_code == 400, bad
    assert _save([{"id": "audit.unified.custody.siem_destination_template",
                   "value": "https://other.example.com/x"}]).status_code == 409


def test_custody_needs_somewhere_to_send_copies():
    _base_config("[audit]\nsign = true\n[audit.unified]\nenable = true\n")
    refused = _save([{"id": "audit.unified.custody.enable", "value": True},
                     {"id": "audit.unified.custody.checkpoint_enable", "value": False}])
    assert refused.status_code == 400


# ------------------------------------------------------- public base address
def test_the_public_address_is_used_to_check_chat_service_signatures(monkeypatch):
    from maverick_channels.base import public_url_for

    request = SimpleNamespace(url=SimpleNamespace(path="/sms/inbound"), headers={})
    assert _save([{"id": "channels.public_base_url", "value": "https://bot.example.com/"}]
                 ).status_code == 200
    assert public_url_for(request) == "https://bot.example.com/sms/inbound"
    monkeypatch.setenv("MAVERICK_PUBLIC_BASE_URL", "https://env.example.com")
    assert public_url_for(request) == "https://env.example.com/sms/inbound"
    assert _row("channels.public_base_url")["locked"] is True
    monkeypatch.delenv("MAVERICK_PUBLIC_BASE_URL")
    assert _save([{"id": "channels.public_base_url", "value": "http://bot.example.com"}]
                 ).status_code == 400


# ----------------------------------------------------------- governance level
def test_a_governance_level_is_previewed_then_applied_with_its_settings(audit_rows):
    _base_config("[dreaming]\nenable = false\n")
    preview = client.get(f"{API}/preview/governance.profile?value=regulated")
    assert preview.status_code == 200, preview.text
    items = {item["id"]: item for item in preview.json()["items"]}
    assert items["actions.enable"]["new"] == "On"
    assert items["learning.dreaming"]["now"] == "Off"
    assert items["retention.audit_days"]["lowers"] is True
    change = [{"id": "governance.profile", "value": "regulated"}]
    asked = _save(change)
    assert asked.status_code == 409
    asked_ids = {item["id"] for item in asked.json()["confirm"]}
    assert {"retention.audit_days", "learning.dreaming"} <= asked_ids
    saved = _save(change, confirm=True)
    assert saved.status_code == 200
    # The reply carries the level and every setting it changed, not every row.
    shown = {row["id"]: row for group in saved.json()["groups"] for row in group["settings"]}
    assert {"governance.profile", "actions.enable", "retention.audit_days"} <= set(shown)
    assert shown["retention.audit_days"]["value"] == 365
    assert set(saved.json()["changed"]) <= set(shown) and len(shown) < len(catalog.SETTINGS) // 4
    loaded = _loaded()
    assert loaded["governance"]["profile"] == "regulated"
    assert loaded["actions"]["enable"] is True and loaded["retention"]["audit_days"] == 365
    assert loaded["dreaming"]["enable"] is True
    kinds = [a["kind"] for a in audit_rows]
    from maverick.audit import EventKind

    assert EventKind.LEARNING_CONTROL_CHANGED in kinds
    assert _changed(audit_rows, "governance.profile")
    assert _changed(audit_rows, "actions.enable") and _changed(audit_rows, "retention.audit_days")
    # Applying the same level again changes nothing.
    again = client.get(f"{API}/preview/governance.profile?value=regulated").json()
    assert again["items"] == []


def test_a_level_leaves_settings_the_server_decides_alone(monkeypatch):
    from maverick_dashboard import settings_governance_level

    settings, _learning = settings_governance_level._expansion("standard")
    locked = next(s for s, _value in settings if s.env)
    monkeypatch.setenv(locked.env[0], "0")
    shown = client.get(f"{API}/preview/governance.profile?value=standard").json()
    assert locked.label in shown["kept"]
    assert all(item["id"] != locked.id for item in shown["items"])
    before = _loaded()
    _saved([{"id": "governance.profile", "value": "standard"}])
    assert catalog.lookup(_loaded(), locked.path) == catalog.lookup(before, locked.path)


def test_a_level_needs_the_installer(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_installer(name, *args, **kwargs):
        if name.startswith("maverick_installer"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_installer)
    r = _save([{"id": "governance.profile", "value": "standard"}], confirm=True)
    assert r.status_code == 409 and "installer" in r.json()["message"]
    assert client.get(f"{API}/preview/governance.profile?value=standard").status_code == 409


# ------------------------------------------------------------ code vault notes
def test_a_note_from_a_protected_project_runs_under_its_protection(monkeypatch):
    from maverick_dashboard import code_actions_api, code_ops_api

    started = []
    monkeypatch.setattr(code_ops_api, "_repo", lambda name: SimpleNamespace(protect="block"))
    monkeypatch.setattr(code_actions_api, "_provider_missing", lambda: False)
    monkeypatch.setattr(code_actions_api, "_run_feature",
                        lambda *args: started.append(args))
    recorded = []
    monkeypatch.setattr(code_ops_api, "record",
                        lambda request, action, **kw: recorded.append((action, kw)))
    watcher = SimpleNamespace(notes=[{"id": "abc123", "title": "billing: add retries",
                                      "task": "In the billing code project.\nAdd retries"}])
    key = (code_ops_api._workspace(), "billing")
    monkeypatch.setitem(code_ops_api._watchers, key, watcher)
    url = "/api/v1/code/watch/billing/notes/abc123/start"
    assert client.post(url, json={}).status_code == 422
    r = client.post(url, json={"confirm": True})
    assert r.status_code == 202, r.text
    assert r.json() == {"started": True, "repo": "billing", "protect": "block"}
    assert started == [("billing", "billing: add retries",
                        "In the billing code project.\nAdd retries", None, "", None)]
    assert recorded == [("code_watch_note_start",
                         {"installation": False, "repo": "billing", "note": "abc123",
                          "protect": "block"})]
    assert client.post("/api/v1/code/watch/billing/notes/nope/start",
                       json={"confirm": True}).status_code == 404
    monkeypatch.setattr(code_actions_api, "_provider_missing", lambda: True)
    assert client.post(url, json={"confirm": True}).status_code == 503


def test_the_feature_path_labels_the_work_with_the_projects_protection(monkeypatch):
    """``_run_feature`` (the path a note now takes) runs ``features.propose``,
    which enforces the project's protection mode around the work."""
    import inspect

    from maverick.codebase import features
    from maverick_dashboard import code_actions_api

    assert "features.propose(" in inspect.getsource(code_actions_api._run_feature)
    assert 'labelled_run({f"code:{name}"}, mode=repo.protect)' in inspect.getsource(
        features.propose)


def test_the_code_page_no_longer_starts_notes_as_ordinary_tasks():
    from pathlib import Path

    script = (Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static"
              / "lightwork-code.js").read_text(encoding="utf-8")
    body = script.split("async function startNoteTask", 1)[1].split("\n  }\n", 1)[0]
    assert "/api/v1/goals" not in body and "/notes/" in body
