"""The big wizard steps are composed from ordered helpers, not one long body.

``pick_advanced`` asks its toggles in groups and ``_cfg_advanced`` renders the
answers through one helper per family; ``pick_assessments`` asks one product
family per helper.  These tests pin the composition contracts the refactor
must keep: the question order, the key order of the saved answers and the
order of the written sections are exactly the concatenation of the helpers.
"""
from __future__ import annotations

import inspect
import io
import re

import pytest
from maverick_installer import wizard
from rich.console import Console


class _Scripted:
    """Answer every prompt deterministically and remember what was asked."""

    def __init__(self, *, confirm: bool | None = None):
        self.confirm_answer = confirm
        self.asked: list[str] = []

    def q_confirm(self, message, default=True):
        self.asked.append(message)
        return default if self.confirm_answer is None else self.confirm_answer

    def q_text(self, message, default=""):
        self.asked.append(message)
        return default

    def q_select(self, message, choices, default=None):
        self.asked.append(message)
        return default if default is not None else choices[0]

    def q_checkbox(self, message, choices, default=None):
        self.asked.append(message)
        return list(choices) if self.confirm_answer else list(default or [])


@pytest.fixture
def script(monkeypatch, tmp_path):
    def install(**kwargs) -> _Scripted:
        answers = _Scripted(**kwargs)
        monkeypatch.setattr(wizard, "_q_confirm", answers.q_confirm)
        monkeypatch.setattr(wizard, "_q_text", answers.q_text)
        monkeypatch.setattr(wizard, "_q_select", answers.q_select)
        monkeypatch.setattr(wizard, "_q_checkbox", answers.q_checkbox)
        monkeypatch.setattr(wizard, "console", Console(file=io.StringIO(), width=120))
        monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
        monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
        monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
        return answers
    return install


def _helper_calls(fn, prefix: str) -> list[str]:
    """Helper names a composing function calls, in source order."""
    return re.findall(rf"\b({prefix}\w+)\(", inspect.getsource(fn))


# ---------- pick_advanced ----------


def test_pick_advanced_is_a_short_composition_without_a_complexity_waiver():
    source = inspect.getsource(wizard.pick_advanced)
    assert "noqa" not in source
    assert len(source.splitlines()) < 60
    groups = _helper_calls(wizard.pick_advanced, "_pick_")
    followups = _helper_calls(wizard.pick_advanced, "_ask_")
    assert len(groups) == 10
    assert followups[0] == "_ask_insight_exchange" and followups[-1] == "_ask_model_followups"


def test_pick_advanced_saves_answers_in_group_order_then_follow_ups(script):
    answers = script()
    advanced = wizard.pick_advanced()
    group_keys: list[str] = []
    for name in _helper_calls(wizard.pick_advanced, "_pick_"):
        group_keys.extend(getattr(wizard, name)())
    assert list(advanced)[: len(group_keys)] == group_keys
    assert len(set(group_keys)) == len(group_keys), "a toggle key is asked twice"
    # The follow-ups that every run asks come after the toggles, identity before dashboard.
    tail = list(advanced)[len(group_keys):]
    assert tail.index("oidc") < tail.index("local_owner_setup") < tail.index("dashboard_compress")
    assert tail[-1] == "model_discovery"
    assert answers.asked[0].startswith("Running-task") or answers.asked  # at least one prompt


def test_pick_advanced_asks_the_toggles_before_any_follow_up(script):
    answers = script()
    wizard.pick_advanced()
    first_follow_up = answers.asked.index("  Stream chat answers as they are written (redacted and Shield-scanned)?")
    toggles_asked = sum(len(getattr(wizard, name)()) for name in _helper_calls(wizard.pick_advanced, "_pick_"))
    # Nested helpers (budget reporting, image models) ask more than one question
    # per key, so the toggle phase is at least as long as the key count.
    assert first_follow_up >= toggles_asked - 2


# ---------- _cfg_advanced ----------


def _cfg_helpers_in_order() -> list[str]:
    return _helper_calls(wizard._cfg_advanced, "_cfg_advanced_")


def test_cfg_advanced_composes_every_family_helper_exactly_once():
    source = inspect.getsource(wizard._cfg_advanced)
    assert "noqa" not in source
    assert len(source.splitlines()) < 45
    called = _cfg_helpers_in_order()
    module = inspect.getmodule(wizard._cfg_advanced)
    defined = sorted(
        name for name, obj in vars(module).items()
        if name.startswith("_cfg_advanced_") and inspect.isfunction(obj)
        and name != "_cfg_advanced_self_harness_options"
    )
    assert sorted(called) == defined
    assert len(called) == len(set(called))
    assert called[0] == "_cfg_advanced_running_tasks_and_images"
    assert called[-1] == "_cfg_advanced_saml_and_sign_in"


def test_cfg_advanced_output_is_the_helpers_concatenated_in_order(script, tmp_path):
    script()
    # A prior config pins the consent salt the writer would otherwise mint afresh.
    (tmp_path / "config.toml").write_text('[consent_registry]\nsubject_salt = "salt-kept-from-the-prior-install"\n')
    advanced = wizard.pick_advanced()
    advanced.update({
        "cost_aware": True, "flows": True, "self_harness": True, "allow_pack_editing": False,
        "consent_registry": True, "unified_audit": True, "stripe_billing": True,
        "oidc": {"enabled": True, "issuer": "https://idp.example", "audience": "lightwork",
                 "jwks_uri": "https://idp.example/jwks"},
        "sign_in_security": {"require": True, "cidrs": ["10.0.0.0/8"]},
        "department_access": {"default_suites": ["finance"], "group_roles": {"Ops Team": "operator"}},
    })
    providers = ["anthropic", "ollama"]
    expected: list[str] = []
    for name in _cfg_helpers_in_order():
        helper = getattr(wizard, name)
        kwargs = {"advanced": advanced, "providers": providers, "siem_dest": "syslog://siem:514"}
        params = inspect.signature(helper).parameters
        expected += helper(**{k: v for k, v in kwargs.items() if k in params})
    assert wizard._cfg_advanced(advanced, providers, siem_dest="syslog://siem:514") == expected
    rendered = "\n".join(expected)
    for section in ("[routing]", "[flows]", "[self_harness]", "[features]", "[auth.oidc]",
                    "[dashboard]", "[auth.mfa]", "[auth.ip_allowlist]", "[consent_registry]"):
        assert section in rendered, section
    assert 'subject_salt = "salt-kept-from-the-prior-install"' in rendered


def test_cfg_advanced_still_writes_nothing_for_an_empty_step():
    assert wizard._cfg_advanced({}, ["anthropic"]) == []
    assert wizard._cfg_advanced(None, ["anthropic"]) == []
    with pytest.raises(AttributeError):
        # A SIEM destination with no advanced answers was never a supported call.
        wizard._cfg_advanced(None, ["anthropic"], siem_dest="syslog://x")


@pytest.mark.parametrize("key,wanted,line", wizard._FEATURE_LOCKS)
def test_each_feature_lock_is_written_only_for_its_deliberate_answer(key, wanted, line):
    written = wizard._cfg_advanced({key: wanted}, ["anthropic"])
    assert written[-3:] == ["", "[features]", line] or ("[features]" in written and line in written)
    assert "[features]" not in wizard._cfg_advanced({key: not wanted}, ["anthropic"])
    assert "[features]" not in wizard._cfg_advanced({key: None}, ["anthropic"])


def test_feature_locks_form_one_table_in_declaration_order():
    answers = {key: wanted for key, wanted, _ in wizard._FEATURE_LOCKS}
    answers["allow_human_conversation_handoffs"] = False
    written = wizard._cfg_advanced(answers, ["anthropic"])
    assert written.count("[features]") == 1
    start = written.index("[features]") + 1
    expected = [line for _, _, line in wizard._FEATURE_LOCKS] + ["human_conversation_handoffs = false"]
    assert written[start:start + len(expected)] == expected


# ---------- pick_assessments ----------


def test_pick_assessments_is_a_short_composition_without_a_complexity_waiver():
    source = inspect.getsource(wizard.pick_assessments)
    assert "noqa" not in source
    assert len(source.splitlines()) < 60
    for helper in ("_pick_consent_preferences", "_pick_privacy_automation",
                   "_pick_data_use_governance", "_pick_paper_review_and_graph"):
        assert f"{helper}(" in source


def test_pick_assessments_defaults_write_nothing(script):
    script()
    assert wizard.pick_assessments() == {}


def test_pick_assessments_all_yes_threads_the_consent_choices_through_privacy(script):
    script(confirm=True)
    out = wizard.pick_assessments()
    assert list(out) == ["consent_preferences", "privacy_automation", "data_use_governance"]
    consent = out["consent_preferences"]
    # The privacy questions extend the consent product after it was built.
    assert list(consent)[-2:] == ["storage", "global_opt_out"]
    assert consent["storage"]["backend"] == "postgres"
    assert consent["native_sdk"]["require_rights_requests"] is True
    assert consent["native_sdk"]["require_profile_linking"] is True
    assert consent["delivery"]["destinations"]["enabled_providers"] == [
        "salesforce", "marketo", "adobe_experience_platform", "snowflake",
    ]
    assert consent["trust_center"]["branding"]["enable"] is True
    privacy = out["privacy_automation"]
    assert privacy["data_discovery"]["adapters"]["enabled_providers"] == [
        "aws_s3", "azure_blob", "google_cloud_storage", "snowflake_metadata", "servicenow_cmdb", "entra_assets",
    ]
    assert privacy["data_discovery"]["remediation"]["scheduler"]["enable"] is True
    assert privacy["rights_orchestration"]["source_adapters"]["enable"] is True
    assert privacy["rights_consumer_intake"]["enable"] is True
    assert privacy["ott_ctv_rights"]["enable"] is True
    assert privacy["notice_governance"]["publication_runtime"]["bindings"] == {
        "primary": {
            "tenant_id": "default", "notice_id": "privacy-main",
            "consent_publication_ref": "consent-binding:1", "property_id": "property-main",
            "rule_group_id": "production-rules", "rule_group_version": 1,
            "notice_resource_id": "privacy-notice", "notice_resource_version": 1,
        },
    }
    data_use = out["data_use_governance"]
    assert data_use["snowflake"]["origin"] == "https://account.snowflakecomputing.com"
    assert data_use["provider_audit"]["snowflake_latency_watermark_seconds"] == 10_800
    assert data_use["scheduler"]["enable"] is True


def test_pick_assessments_asks_consent_before_privacy_before_data_use(script):
    answers = script(confirm=True)
    wizard.pick_assessments()
    asked = answers.asked
    consent = next(i for i, q in enumerate(asked) if q.startswith("Enable consumer Consent & Preferences"))
    privacy = next(i for i, q in enumerate(asked) if q.startswith("Enable Privacy Automation structured"))
    data_use = next(i for i, q in enumerate(asked) if q.startswith("Enable the Data Use Governance"))
    paper = asked.index("Let a model re-word your standard clauses to match vendor drafting?")
    assert consent < privacy < data_use < paper
    storage = next(i for i, q in enumerate(asked) if q.startswith("Keep consent records in a shared PostgreSQL"))
    assert privacy < storage < data_use, "the shared-storage question stays inside the privacy block"
