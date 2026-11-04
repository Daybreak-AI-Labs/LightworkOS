"""Settings > All settings: learning, research and self-improvement rows, and
the Learning page's own switch for each learning system.

Every row saves and reads back through the catalog API into what the kernel's
``load_config`` returns; invalid values are refused; the secret is sealed and
never shown; loosening a protection needs confirmation (409, then 200); each
change writes an audit row; deployment variables lock their rows; and the
readers this package changed (automatic skill writing, step scoring, the
autonomy switches) really follow the saved value. Each learning system can be
switched on its own, and the master switch still switches them all.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard import settings_catalog_learning as learning_rows
from maverick_dashboard.app import app

from test_support.settings_pages import save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"

ROWS = learning_rows.entries(catalog.Setting, catalog.Column, catalog.Column)
ROW_IDS = {s.id for s in ROWS}
KEY_HEX = "3b" * 32  # any 32-byte public key in its stored form

SAMPLE: dict[str, object] = {
    "self_improvement.prm_endpoint": "https://score.example.com/v1",
    "self_improvement.prm_api_key": "prm-key-do-not-show-123",  # pragma: allowlist secret
    "self_improvement.prm_path": "/srv/lightwork/prm",
    "self_harness.holdout_container_image": "sha256:" + "a" * 64,
    "flows.action_evidence_issuer": "lightwork.prod",
    "flows.action_evidence_revoked_keys": ["0123456789abcdef"],
    "self_modify.editable_paths": ["packages/example/*.py"],
    "self_modify.eval_tests": ["tests/test_a.py::test_one", "tests/test_b.py::test_two"],
    "adapter_rung.base_model": "ollama:llama3",
    "adapter_rung.store_dir": "/srv/lightwork/adapters",
    "candidate_promotion.allowed_targets": ["installed-lightwork", "staging-lightwork"],
    "ai_benchmark_exchange.coordinator.origin": "https://bench.example.org",
    "paper_review.playbook_path": "/srv/lightwork/playbook.json",
    "dreaming.trusted_insight_pubkeys": [KEY_HEX],
}

INVALID: dict[str, list[object]] = {
    "self_improvement.prm_endpoint": ["http://score.example.com", "ftp://x"],
    "self_improvement.prm_path": ["relative/path", "/srv/../etc/passwd"],
    "self_harness.eval_corpus": ["corpus.json", "/srv/../../etc"],
    "self_harness.holdout_ledger": ["~/../x"],
    "self_harness.holdout_container_image": ["sha256:xyz", "python:3.12"],
    "flows.action_evidence_issuer": ["https://issuer.example", "-bad"],
    "flows.action_evidence_revoked_keys": [["XYZ"], ["0123456789ABCDEF"]],
    "self_modify.editable_paths": [["/etc/passwd"], ["../outside/*.py"]],
    "self_modify.eval_tests": [["-p evilplugin"], ["tests/x.py::a b"]],
    "adapter_rung.base_model": ["bad model!"],
    "adapter_rung.store_dir": ["adapters"],
    "candidate_promotion.allowed_targets": [["bad target!"]],
    "ai_benchmark_exchange.coordinator.origin": [
        "http://bench.example.org", "https://bench.example.org/submit", "https://localhost"],
    "paper_review.playbook_path": ["playbook.json"],
    "dreaming.trusted_insight_pubkeys": [["not a key"]],
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    names = {"MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
             "MAVERICK_SELF_MODIFY", "MAVERICK_APPROVER_KEYS"}
    names |= {env for s in catalog.SETTINGS for env in s.env}
    from maverick_dashboard.settings_store import LEARNING_SUBSYSTEMS

    names |= {s["env"] for s in LEARNING_SUBSYSTEMS}
    for name in names:
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": str(getattr(kind, "value", kind)), **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _loaded():
    from maverick import config

    config.reset_config_cache()
    return config.load_config()


def _save(changes, confirm=False, http=client):
    return save_catalog(http, API, json={"changes": changes, "confirm": confirm})


def _row(setting_id):
    for group in client.get(API).json()["groups"]:
        for row in group["settings"]:
            if row["id"] == setting_id:
                return row
    raise AssertionError(setting_id)


def _shown(setting, stored):
    return round(stored / setting.scale, 6) if isinstance(stored, (int, float)) else stored


def _data_file(name: str) -> str:
    """A file Lightwork will create, inside its data folder (the folder exists)."""
    from maverick.paths import maverick_home

    folder = maverick_home() / "learning"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    return str(folder / name)


def _valid(setting):
    """A valid value, different from the default, in the page's own units."""
    if setting.control == "path":
        return _data_file(setting.key + ".json")
    if setting.id in SAMPLE:
        return SAMPLE[setting.id]
    if setting.control == "toggle":
        return not setting.default
    if setting.control == "select":
        return next(v for v, _ in setting.choices if v != setting.default)
    if setting.control == "multiselect":
        return [setting.choices[0][0]]
    if setting.control == "number":
        top = setting.maximum
        return setting.minimum if _shown(setting, setting.default) == top else top
    raise AssertionError(f"no sample value for {setting.id}")


def _stored(setting, value):
    if setting.control == "number":
        number = value * setting.scale
        return int(round(number)) if setting.integer else number
    return value


# ----------------------------------------------------------------- catalog
def test_rows_belong_to_this_package_and_are_known_to_the_catalog():
    assert len(ROWS) >= 100
    for setting in ROWS:
        assert catalog.BY_ID[setting.id] == setting
    # Research rungs and learning switches are all present.
    for setting_id in ("self_modify.editable_paths", "adapter_rung.enable",
                       "emergent_protocol.enable", "flows.action_recipes",
                       "reflexion.enable", "self_learning.auto_distill",
                       "self_improvement.prm_backend", "dreaming.cron"):
        assert setting_id in ROW_IDS


def test_changing_own_code_prompts_or_behaviour_is_off_and_confirmed():
    for setting_id in ("adapter_rung.enable", "adapter_rung.allow_synthetic",
                       "adapter_rung.allow_model_output", "emergent_protocol.enable",
                       "self_learning.auto_distill", "flows.learned_operators",
                       "flows.composed_operators", "flows.action_recipes",
                       "flows.action_recipe_transforms", "flows.action_recipe_choices",
                       "flows.action_recipe_teaching", "flows.action_workflow_learning",
                       "flows.action_workflow_memory_learning",
                       "flows.action_episode_capture"):
        setting = catalog.BY_ID[setting_id]
        assert setting.default is False and setting.weaker is True, setting_id
        assert setting.warning.endswith("."), setting_id
    for setting_id in ("self_modify.editable_paths", "self_modify.eval_tests"):
        assert catalog.BY_ID[setting_id].default == [] and catalog.BY_ID[setting_id].warning


def test_defaults_match_the_kernel():
    from maverick import config

    harness = config.get_self_harness()
    for key in ("require_held_out", "min_held_out", "min_delta", "judge_samples",
                "candidates_per_signature", "metamorphic", "promote_as_canary",
                "calibrate_judge", "semantic_mining", "efficacy_review", "store",
                "retire_after_days"):
        assert catalog.BY_ID[f"self_harness.{key}"].default == harness[key], key
    improvement = config.get_self_improvement()
    for key in ("max_auto_rung", "min_improvement", "evaluator_eps",
                "capture", "causal_promotion"):
        assert catalog.BY_ID[f"self_improvement.{key}"].default == improvement[key], key
    flows = config.get_flows()
    for setting in ROWS:
        if setting.section == "flows":
            assert setting.default == flows[setting.key], setting.id
    dreaming = config.get_dreaming()
    for key in ("snapshots", "benchmark_gate", "prune_facts", "user_notes", "rehearse"):
        assert catalog.BY_ID[f"dreaming.{key}"].default == dreaming[key], key
    assert catalog.BY_ID["jit_rl.beta"].default == config.get_jit_rl()["beta"]
    assert catalog.BY_ID["credit.min_budget_headroom"].default == \
        config.get_credit()["min_budget_headroom"]
    assert catalog.BY_ID["self_learning.auto_distill"].default is \
        config.get_self_learning()["auto_distill"] is False


# settings_catalog_learning.cross_checks: sending results needs the service
# address, which the installer normally wrote; seed it so the row saves alone.
_INSTALLED_WITH = {
    "ai_benchmark_exchange.coordinator.enable":
        '[ai_benchmark_exchange.coordinator]\norigin = "https://bench.example.com"\n',
}


def _install_companions(setting) -> None:
    text = _INSTALLED_WITH.get(setting.id)
    if text:
        from maverick import config

        config.config_path().parent.mkdir(parents=True, exist_ok=True)
        config.config_path().write_text(text, encoding="utf-8")
        config.reset_config_cache()


@pytest.mark.parametrize("setting", ROWS, ids=lambda s: s.id)
def test_every_row_saves_and_reads_back(setting, audit_rows):
    _install_companions(setting)
    value = _valid(setting)
    r = _save([{"id": setting.id, "value": value}], confirm=True)
    assert r.status_code == 200, r.text
    present, stored = catalog.lookup(_loaded(), setting.path)
    assert present, setting.id
    expected = _stored(setting, value)
    if isinstance(expected, float):
        assert stored == pytest.approx(expected)
    else:
        assert stored == expected
    row = _row(setting.id)
    assert row["source"] == "here"
    if setting.secret:
        assert row["is_set"] is True and row["value"] is None
        assert str(value) not in r.text
    # One audit row for the change, never a secret's value.
    assert [a["kind"] for a in audit_rows] == ["setting_changed"]
    assert (audit_rows[0]["section"], audit_rows[0]["key"]) == (setting.section, setting.key)
    if setting.secret:
        assert audit_rows[0]["new"] == "set" and str(value) not in repr(audit_rows)
    # Reset gives the default back.
    assert _save([{"id": setting.id, "reset": True}], confirm=True).status_code == 200
    if setting.partial_default is catalog._NO_PARTIAL:
        assert _row(setting.id)["source"] == "default"
    else:  # written as the default itself, so an older default cannot return
        assert catalog.lookup(_loaded(), setting.path)[1] == setting.default


def test_a_first_instruction_setting_keeps_the_careful_profile(audit_rows):
    from maverick import config

    before = config.get_self_harness()
    assert _save([{"id": "self_harness.semantic_mining", "value": True}]).status_code == 200
    after = config.get_self_harness()
    assert after["semantic_mining"] is True
    for key in ("risk_limited", "auto_run", "require_held_out", "min_held_out", "min_delta",
                "judge_samples", "candidates_per_signature", "metamorphic",
                "promote_as_canary", "calibrate_judge"):
        assert after[key] == before[key], key


def _invalid(setting):
    if setting.id in INVALID:
        return INVALID[setting.id]
    if setting.control == "toggle":
        return ["yes", 1]
    if setting.control == "select":
        return ["not-an-option", True]
    if setting.control == "multiselect":
        return [["not-an-option"]]
    if setting.control == "number":
        return [setting.maximum + 1, setting.minimum - 1, "lots"]
    if setting.control == "secret":
        return ["", "bad\x1bvalue"]
    raise AssertionError(f"no invalid value for {setting.id}")


@pytest.mark.parametrize("setting", ROWS, ids=lambda s: s.id)
def test_invalid_values_are_refused(setting, audit_rows):
    for bad in _invalid(setting):
        r = _save([{"id": setting.id, "value": bad}], confirm=True)
        assert r.status_code == 400, (setting.id, bad, r.text)
        assert r.json()["message"]
    assert catalog.lookup(_loaded(), setting.path)[0] is False
    assert audit_rows == []


def _strong_and_weak(setting):
    if setting.control == "toggle":
        return (not setting.weaker), setting.weaker
    if setting.control == "select" and setting.order:
        return setting.order[0], setting.order[-1]
    if setting.control == "number" and setting.weaker in {"lower", "higher"}:
        low, high = setting.minimum, setting.maximum
        return (high, low) if setting.weaker == "lower" else (low, high)
    if setting.weaker == "shrink":
        return SAMPLE[setting.id], []
    return None, _valid(setting)


WEAKENING = [s for s in ROWS if s.warning]


@pytest.mark.parametrize("setting", WEAKENING, ids=lambda s: s.id)
def test_loosening_needs_confirmation(setting, audit_rows):
    _install_companions(setting)
    strong, weak = _strong_and_weak(setting)
    if strong is not None:
        assert _save([{"id": setting.id, "value": strong}], confirm=True).status_code == 200
    audit_rows.clear()
    r = _save([{"id": setting.id, "value": weak}])
    assert r.status_code == 409, r.text
    assert r.json()["confirm"][0]["id"] == setting.id
    assert audit_rows == []
    r = _save([{"id": setting.id, "value": weak}], confirm=True)
    assert r.status_code == 200, r.text
    assert audit_rows[-1]["confirmed"] is True


@pytest.mark.parametrize("setting", [s for s in ROWS if s.env], ids=lambda s: s.id)
def test_deployment_variables_lock_their_rows(setting, monkeypatch, audit_rows):
    monkeypatch.setenv(setting.env[0], "1")
    row = _row(setting.id)
    assert row["locked"] is True and row["source"] == "deployment"
    r = _save([{"id": setting.id, "value": _valid(setting)}], confirm=True)
    assert r.status_code == 409
    assert catalog.lookup(_loaded(), setting.path)[0] is False


def test_only_global_admins_change_learning_rows(monkeypatch, audit_rows):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    r = _save([{"id": "self_modify.editable_paths", "value": ["packages/x/*.py"]}],
              confirm=True)
    assert r.status_code == 403
    assert "self_modify" not in _loaded()


# ------------------------------------------------ readers follow the values
def test_saved_auto_distill_turns_on_automatic_skill_writing(monkeypatch, audit_rows):
    from maverick.orchestrator import _auto_distill_enabled

    assert _auto_distill_enabled() is False
    assert _save([{"id": "self_learning.auto_distill", "value": True}]).status_code == 409
    assert _save([{"id": "self_learning.auto_distill", "value": True}],
                 confirm=True).status_code == 200
    assert _auto_distill_enabled() is True
    # The deployment variable still decides when it is set.
    monkeypatch.setenv("MAVERICK_AUTO_DISTILL", "0")
    assert _auto_distill_enabled() is False


def test_saved_step_scoring_choice_is_used(monkeypatch, audit_rows):
    from maverick import prm

    assert isinstance(prm.build_from_env(), prm.NullPRM)
    r = _save([{"id": "self_improvement.prm_backend", "value": "heuristic"}], confirm=True)
    assert r.status_code == 200
    assert isinstance(prm.build_from_env(), prm.HeuristicPRM)
    secret = "prm-remote-key-never-shown"  # pragma: allowlist secret
    r = _save([{"id": "self_improvement.prm_backend", "value": "remote"},
               {"id": "self_improvement.prm_endpoint", "value": "https://score.example.com"},
               {"id": "self_improvement.prm_api_key", "value": secret}], confirm=True)
    assert r.status_code == 200 and secret not in r.text
    remote = prm.build_from_env()
    assert isinstance(remote, prm.RemotePRM)
    assert remote.endpoint == "https://score.example.com" and remote.api_key == secret
    from maverick import config

    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert secret not in stored and "MVKAR1:" in stored
    assert secret not in client.get(API).text
    # A set deployment variable wins over the saved choice.
    monkeypatch.setenv("MAVERICK_PRM", "null")
    assert isinstance(prm.build_from_env(), prm.NullPRM)


def test_autonomy_switches_show_the_deployment_variable(monkeypatch, audit_rows):
    monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
    assert _row("autonomy.enable")["locked"] is True
    monkeypatch.delenv("MAVERICK_AUTONOMY_GATE")
    monkeypatch.setenv("MAVERICK_AUTONOMOUS", "0")
    assert _row("autonomy.headless_assume")["locked"] is True


def test_saved_values_reach_their_kernel_readers(audit_rows):
    from maverick import calibration, config, self_modify
    from maverick_dashboard import automation_queue, candidate_promotion_composition

    changes = [
        {"id": "self_modify.editable_paths", "value": ["packages/example/*.py"]},
        {"id": "dreaming.cron", "value": "0 2 * * *"},
        {"id": "flows.action_recipes", "value": True},
        {"id": "self_harness.store", "value": "world"},
        {"id": "calibration.collect_from_coding", "value": True},
        {"id": "candidate_promotion.enable", "value": True},
        {"id": "candidate_promotion.allowed_targets",
         "value": ["installed-lightwork", "staging-lightwork"]},
        {"id": "self_improvement.max_auto_rung", "value": "prompt"},
    ]
    assert _save(changes, confirm=True).status_code == 200
    config.reset_config_cache()
    assert self_modify.default_surface().editable_globs == ("packages/example/*.py",)
    assert automation_queue._dream_cron() == "0 2 * * *"
    assert config.get_flows()["action_recipes"] is True
    assert config.get_self_harness()["store"] == "world"
    assert calibration.collect_from_coding_enabled() is True
    assert config.get_self_improvement()["max_auto_rung"] == "prompt"
    policy = candidate_promotion_composition.policy_from_config(config.load_global_config())
    assert policy.allowed_targets == ("installed-lightwork", "staging-lightwork")


def test_benchmark_service_settings_build_a_working_connection(audit_rows):
    from maverick import ai_benchmark_exchange

    r = _save([{"id": "ai_benchmark_exchange.enable", "value": True},
               {"id": "ai_benchmark_exchange.coordinator.enable", "value": True},
               {"id": "ai_benchmark_exchange.coordinator.origin",
                "value": "https://bench.example.org"},
               {"id": "ai_benchmark_exchange.coordinator.max_request_bytes", "value": 64}],
              confirm=True)
    assert r.status_code == 200, r.text
    assert _loaded()["ai_benchmark_exchange"]["coordinator"]["max_request_bytes"] == 65536
    roots, coordinator = ai_benchmark_exchange._operator_configured_integrations()
    assert roots is None and coordinator is not None


def test_turning_on_benchmark_sharing_keeps_its_settings_valid(audit_rows):
    from maverick import ai_benchmark_exchange

    r = _save([{"id": "ai_benchmark_exchange.enable", "value": True}], confirm=True)
    assert r.status_code == 200
    # The service connection stays off, and its settings still read as valid.
    assert _loaded()["ai_benchmark_exchange"]["coordinator"] == {"enable": False}
    assert ai_benchmark_exchange._operator_configured_integrations() == (None, None)


# ---------------------------------------------- one switch per learning system
LEARNING = "/api/v1/learning"


def _components():
    return {c["key"]: c for c in client.get(LEARNING).json()["components"]}


def test_each_learning_system_has_its_own_switch(audit_rows):
    from maverick import reflexion

    parts = _components()
    assert all(c["on"] and c["wanted"] and not c["managed"]
               for key, c in parts.items() if key != "budget_tuning")
    assert parts["budget_tuning"]["on"] is False
    assert parts["budget_tuning"]["wanted"] is False
    r = client.post(LEARNING, json={"enabled": False, "subsystem": "reflexion"})
    assert r.status_code == 200, r.text
    parts = {c["key"]: c for c in r.json()["components"]}
    assert parts["reflexion"]["on"] is False and parts["reflexion"]["wanted"] is False
    assert sum(1 for c in parts.values() if not c["on"]) == 2
    assert reflexion.enabled() is False
    assert audit_rows[-1]["kind"] == "learning_control_changed"
    assert audit_rows[-1]["control"] == "reflexion" and audit_rows[-1]["enabled"] is False
    assert client.post(LEARNING, json={"enabled": True, "subsystem": "reflexion"}
                       ).status_code == 200
    assert reflexion.enabled() is True


def test_master_switch_still_turns_everything_off(audit_rows):
    total = client.get(LEARNING).json()["components_total"]
    assert client.post(LEARNING, json={"enabled": False}).json()["components_on"] == 0
    r = client.post(LEARNING, json={"enabled": True, "subsystem": "consequence"})
    assert r.json()["components_on"] == 1
    assert client.post(LEARNING, json={"enabled": False}).json()["components_on"] == 0
    assert client.post(LEARNING, json={"enabled": True}).json()["components_on"] == total


def test_a_system_that_needs_another_shows_it_is_waiting(audit_rows):
    r = client.post(LEARNING, json={"enabled": False, "subsystem": "self_improvement"})
    parts = {c["key"]: c for c in r.json()["components"]}
    assert parts["factory_learning"]["on"] is False
    assert parts["factory_learning"]["wanted"] is True
    assert parts["factory_learning"]["waiting_on"] == parts["self_improvement"]["label"]


def test_switching_improvement_of_instructions_keeps_the_careful_profile(audit_rows):
    from maverick import config

    assert client.post(LEARNING, json={"enabled": False, "subsystem": "self_harness"}
                       ).status_code == 200
    harness = config.get_self_harness()
    assert harness["enable"] is False
    assert harness["risk_limited"] is True and harness["auto_run"] is True


def test_learning_switch_refusals(monkeypatch, audit_rows):
    r = client.post(LEARNING, json={"enabled": False, "subsystem": "nope"})
    assert r.status_code == 400
    monkeypatch.setenv("MAVERICK_REFLEXION", "1")
    assert _components()["reflexion"]["managed"] is True
    r = client.post(LEARNING, json={"enabled": False, "subsystem": "reflexion"})
    assert r.status_code == 409
    assert "deployment settings" in r.json()["detail"]
    assert audit_rows == []


def test_learning_switches_need_a_global_admin(monkeypatch, audit_rows):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    r = client.post(LEARNING, json={"enabled": False, "subsystem": "reflexion"})
    assert r.status_code == 403
    assert not [a for a in audit_rows if a["kind"] == "learning_control_changed"]
    assert "reflexion" not in _loaded()


def test_learning_page_offers_a_switch_per_system_in_plain_language():
    from test_support.plain_language import developer_terms

    page = client.get("/learning").text
    assert 'id="lrn-parts"' in page
    for key in ("reflexion", "jit_rl", "self_harness", "consequence"):
        assert f'data-part="{key}"' in page
    assert "Turn each part of learning on or off" in page
    assert "Remember lessons from mistakes" in page
    assert 'href="/settings/all"' in page
    assert developer_terms(page) == []
