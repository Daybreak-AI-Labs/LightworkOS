"""Wizard parity with kernel features.

Confirms the eight new wizard steps emit correct TOML, the three new
channel adapters round-trip, and the `_safe_*` helpers replace the
crash-on-bad-input ``int()`` / ``float()`` calls.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover -- Py 3.10 CI matrix
    import tomli as tomllib  # type: ignore[no-redef]


# ---------- _safe_int / _safe_float ----------

def test_safe_int_handles_whitespace():
    from maverick_installer.wizard import _safe_int
    assert _safe_int("  42 ", default=0) == 42


def test_safe_int_falls_back_on_junk():
    from maverick_installer.wizard import _safe_int
    assert _safe_int("not-a-number", default=9) == 9
    assert _safe_int("", default=5) == 5
    assert _safe_int(None, default=7) == 7  # type: ignore[arg-type]


def test_safe_float_falls_back_on_junk():
    from maverick_installer.wizard import _safe_float
    assert _safe_float("xyz", default=1.5) == 1.5
    assert _safe_float("", default=2.5) == 2.5
    assert _safe_float("3.14", default=0) == 3.14


# ---------- wizard sections must be known to config-lint ----------

def test_wizard_written_sections_are_known_to_config_lint():
    """Every [section] block the wizard writes must be a section the runtime
    registry (migrate.KNOWN_SECTIONS, which config-lint sources) recognizes --
    otherwise an operator who enables a documented, wizard-offered feature gets
    a false "unknown config section" warning. Regression: [self_harness],
    [self_improvement], [dreaming], [fleet_memory], [rehearsal], [memory_guard],
    [actions], [domains], [fairness_monitor], [speculative] and [tax] all
    shipped unrecognized (the section-parity test only checked the two
    registries against each other, not against what the wizard writes)."""
    import re
    from pathlib import Path

    from maverick.migrate import KNOWN_SECTIONS
    from maverick_installer import wizard

    src = Path(wizard.__file__).read_text(encoding="utf-8")
    written = set(re.findall(
        r"""lines\.append\(\s*["']\[([a-z_][a-z0-9_]*)\]["']\s*\)""", src))
    assert written, "no [section] writes found in the wizard -- regex stale?"
    missing = sorted(written - set(KNOWN_SECTIONS))
    assert not missing, f"wizard writes sections config-lint will false-flag: {missing}"


def test_model_risk_literal_sections_are_known_to_config_lint():
    from maverick.migrate import KNOWN_SECTIONS
    from maverick_installer import wizard

    rendered = wizard._cfg_security_suite({
        "security_ops": True,
        "evidence_graph": True,
        "model_risk_assurance": True,
    })
    sections = set(tomllib.loads("\n".join(rendered)))
    missing = sorted(sections - set(KNOWN_SECTIONS))
    assert not missing, f"model-risk sections config-lint will false-flag: {missing}"


# ---------- new CHANNELS entries ----------

def test_new_channels_added():
    from maverick_installer.wizard import CHANNELS
    ids = {c[0] for c in CHANNELS}
    assert "bluesky" in ids
    assert "mastodon" in ids
    assert "voice" in ids


def test_bluesky_channel_env_vars():
    from maverick_installer.wizard import CHANNELS
    spec = next(c for c in CHANNELS if c[0] == "bluesky")
    assert "BLUESKY_HANDLE" in spec[2]
    assert "BLUESKY_PASSWORD" in spec[2]


# ---------- new pick_*() functions exist ----------

@pytest.mark.parametrize("name", [
    "pick_web_search",
    "pick_mcp_servers",
    "pick_plugins",
    "pick_tool_acl",
    "pick_rate_limits",
    "pick_retention",
    "pick_persona",
    "pick_notifications",
    "pick_deadline_alerts",
    "pick_webhooks",
    "pick_self_learning",
    "pick_ekko",
    "pick_automation_import",
    "pick_event_triggers",
])
def test_new_pick_exists(name):
    from maverick_installer import wizard
    assert callable(getattr(wizard, name)), f"{name} missing"


def test_collect_api_keys_prompts_for_openai_compatible_base_url(monkeypatch):
    from maverick_installer import wizard

    prompts: list[str] = []
    answers = {
        "OPENAI_COMPATIBLE_API_KEY": "sk-compatible",
        "OPENAI_COMPATIBLE_BASE_URL": "http://localhost:1234/v1",
    }

    def fake_secret(prompt: str, *args, **kwargs):
        prompts.append(prompt)
        for env_name, value in answers.items():
            if env_name in prompt:
                return value
        return ""

    monkeypatch.setattr(wizard, "_q_secret", fake_secret)
    keys = wizard.collect_api_keys(["openai_compatible"], set())

    assert keys == answers
    assert any("OPENAI_COMPATIBLE_API_KEY" in prompt for prompt in prompts)
    assert any("OPENAI_COMPATIBLE_BASE_URL" in prompt for prompt in prompts)


# ---------- write_config emits new TOML sections ----------

def _write_full_config(tmp_path: Path, monkeypatch, **overrides) -> dict:
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    base = dict(
        providers=["anthropic"],
        role_models={},
        channels={},
        safety={"profile": "balanced", "block_threshold": "high",
                "scan_input": True, "scan_tool_calls": True, "scan_output": True},
        budget={"max_dollars": 5.0, "max_wall_seconds": 3600.0, "max_tool_calls": 500},
        sandbox={"backend": "local", "workdir": str(tmp_path / "ws"), "timeout": 60},
        keys={},
        capabilities={"computer_use": False, "browser": False},
    )
    base.update(overrides)
    wizard.write_config(**base)
    body = (tmp_path / "config.toml").read_text()
    return tomllib.loads(body)


def test_write_config_emits_mcp_servers(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        mcp_servers={"fs": {"command": "npx", "args": ["-y", "x"]}},
    )
    assert parsed["mcp_servers"]["fs"]["command"] == "npx"
    assert parsed["mcp_servers"]["fs"]["args"] == ["-y", "x"]


def test_write_config_emits_mcp_registries(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        mcp_registries=["https://registry.example.com/catalog",
                        "https://internal.acme/catalog"],
    )
    assert parsed["mcp_registries"]["indexes"] == [
        "https://registry.example.com/catalog", "https://internal.acme/catalog"]


def test_write_config_emits_knowledge(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        knowledge={"enable": True, "embedder": "hosted", "store": "pgvector",
                   "dsn": "postgresql://x", "revision": "operator-recorded-202609"},
    )
    assert parsed["knowledge"]["enable"] is True
    assert parsed["knowledge"]["embedder"] == "hosted"
    assert parsed["knowledge"]["store"] == "pgvector"
    assert parsed["knowledge"]["dsn"] == "postgresql://x"
    assert parsed["knowledge"]["revision"] == "operator-recorded-202609"


def test_write_config_omits_knowledge_by_default(tmp_path: Path, monkeypatch):
    # No override -> no [knowledge] section (per-domain RAG is opt-in).
    parsed = _write_full_config(tmp_path, monkeypatch)
    assert "knowledge" not in parsed


def test_write_config_emits_regulated_scalars(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        advanced={"residency_region": "eu",
                  "compliance_disclosure_text": "AI assistant in use."},
    )
    assert parsed["residency"]["region"] == "eu"
    assert parsed["compliance"]["disclosure_text"] == "AI assistant in use."


def test_write_config_omits_mcp_registries_by_default(tmp_path: Path, monkeypatch):
    # No override -> no [mcp_registries] section (discovery uses the built-in
    # default index, so the config stays minimal).
    parsed = _write_full_config(tmp_path, monkeypatch)
    assert "mcp_registries" not in parsed


def test_write_config_emits_template_registries(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        template_registries=["https://templates.example.com/catalog"],
    )
    assert parsed["template_registries"]["indexes"] == [
        "https://templates.example.com/catalog"]
    # default: omitted
    assert "template_registries" not in _write_full_config(tmp_path, monkeypatch)


def test_write_config_emits_plugins(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, plugins=["weather", "github-issues"],
    )
    assert parsed["plugins"]["enabled"] == ["weather", "github-issues"]


@pytest.mark.parametrize(
    "security_suite",
    [
        pytest.param(None, id="advanced-questionnaire-only"),
        pytest.param(
            {"ai_regulatory_feed": False, "ai_literacy": False},
            id="advanced-promotes-security-declines",
        ),
    ],
)
def test_write_config_reconciles_shared_security_questionnaires(
    tmp_path: Path,
    monkeypatch,
    security_suite,
):
    parsed = _write_full_config(
        tmp_path,
        monkeypatch,
        advanced={"ai_regulatory_feed": True, "ai_literacy": True},
        security_suite=security_suite,
    )

    body_lines = (tmp_path / "config.toml").read_text().splitlines()
    assert body_lines.count("[ai_regulatory_feed]") == 1
    assert body_lines.count("[ai_literacy]") == 1
    assert parsed["ai_regulatory_feed"] == {"enable": True}
    assert parsed["ai_literacy"] == {"enable": True}


def test_write_config_self_harness_ships_production_floors(tmp_path: Path, monkeypatch):
    # Enabling self-harness writes the validation floors so a wizard-built config
    # is production-safe by default (an operator can relax them).
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"self_harness": True})
    assert parsed["self_harness"]["enable"] is True
    assert parsed["self_harness"]["require_held_out"] is True
    assert parsed["self_harness"]["min_held_out"] == 5
    assert parsed["self_harness"]["min_delta"] == 0.02
    # The optional advanced knobs are NOT written unless opted into, so the
    # default block stays minimal and each knob keeps its historical default.
    for k in ("eval_corpus", "eval_budget_dollars", "mine_bucket_by",
              "semantic_mining", "efficacy_review", "promote_as_canary",
              "auto_run", "metamorphic", "relapse_failure_share",
              "calibrate_judge", "transfer_auto", "corpus_harvest", "store",
              "candidates_per_signature", "retire_after_days", "holdout_ledger",
              "holdout_container_image", "holdout_require_independent_custody"):
        assert k not in parsed["self_harness"]


def test_write_config_self_harness_advanced_knobs(tmp_path: Path, monkeypatch):
    # The advanced-paths follow-up surfaces the newer knobs; the writer emits each
    # one only when opted into, and they round-trip through config.get_self_harness.
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={
        "self_harness": True,
        "self_harness_eval_corpus": "/etc/maverick/corpus.json",
        "self_harness_eval_budget": 2.5,
        "self_harness_holdout_ledger": "/protected/self-harness-holdout.db",
        "self_harness_holdout_container_image": "sha256:" + "a" * 64,
        "self_harness_require_independent_custody": True,
        "self_harness_bucket_domain": True,
        "self_harness_semantic_mining": True,
        "self_harness_efficacy_review": True,
        "self_harness_canary": True,
        "self_harness_auto_run": True,
        "self_harness_metamorphic": True,
        "self_harness_relapse": True,
        "self_harness_calibrate_judge": True,
        "self_harness_transfer_auto": True,
        "self_harness_corpus_harvest": "propose",
        "self_harness_store": "world",
        "self_harness_candidates": 3,
        "self_harness_retire_days": 45,
    })
    sh = parsed["self_harness"]
    assert sh["eval_corpus"] == "/etc/maverick/corpus.json"
    assert sh["eval_budget_dollars"] == 2.5
    assert sh["holdout_ledger"] == "/protected/self-harness-holdout.db"
    assert sh["holdout_container_image"] == "sha256:" + "a" * 64
    assert sh["holdout_require_independent_custody"] is True
    assert sh["mine_bucket_by"] == ["domain"]
    assert sh["semantic_mining"] is True
    assert sh["efficacy_review"] is True
    assert sh["promote_as_canary"] is True
    assert sh["auto_run"] is True
    assert sh["metamorphic"] is True
    assert sh["relapse_failure_share"] == 0.5
    assert sh["calibrate_judge"] is True
    assert sh["transfer_auto"] is True
    assert sh["corpus_harvest"] == "propose"
    assert sh["store"] == "world"
    assert sh["candidates_per_signature"] == 3
    assert sh["retire_after_days"] == 45
    # The kernel actually reads what the wizard wrote.
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: parsed)
    resolved = config.get_self_harness()
    assert resolved["eval_corpus"] == "/etc/maverick/corpus.json"
    assert resolved["eval_budget_dollars"] == 2.5
    assert resolved["holdout_ledger"] == "/protected/self-harness-holdout.db"
    assert resolved["holdout_container_image"] == "sha256:" + "a" * 64
    assert resolved["holdout_require_independent_custody"] is True
    assert resolved["mine_bucket_by"] == ("domain",)
    assert resolved["semantic_mining"] is True
    assert resolved["efficacy_review"] is True
    assert resolved["promote_as_canary"] is True
    assert resolved["auto_run"] is True
    assert resolved["metamorphic"] is True
    assert resolved["relapse_failure_share"] == 0.5
    assert resolved["calibrate_judge"] is True
    assert resolved["transfer_auto"] is True
    assert resolved["corpus_harvest"] == "propose"
    assert resolved["store"] == "world"
    assert resolved["candidates_per_signature"] == 3
    assert resolved["retire_after_days"] == 45.0


def test_write_config_self_harness_default_candidate_count_omitted(tmp_path: Path, monkeypatch):
    # Opting into the advanced follow-up but leaving best-of-N / retire at their
    # defaults must NOT write the knob (default 1 / 0 == historical behavior).
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={
        "self_harness": True,
        "self_harness_candidates": 1,
        "self_harness_retire_days": 0,
        "self_harness_eval_corpus": "/etc/maverick/corpus.json",
        "self_harness_eval_budget": 0,          # explicit 0 = uncapped, not written
    })
    assert "candidates_per_signature" not in parsed["self_harness"]
    assert "retire_after_days" not in parsed["self_harness"]
    assert "eval_budget_dollars" not in parsed["self_harness"]


def test_write_config_emits_self_learning(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        self_learning={
            "enable": True, "preflight": True, "create_tools": True,
            "max_acquisitions": 3,
        },
    )
    assert parsed["self_learning"]["enable"] is True
    assert parsed["self_learning"]["create_tools"] is True
    assert parsed["self_learning"]["max_acquisitions"] == 3
    # The retired add_mcp_servers knob is no longer written.
    assert "add_mcp_servers" not in parsed["self_learning"]


def test_write_config_emits_explicit_ekko_policy(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        ekko={
            "enable": True,
            "planning_enabled": True,
            "build_enabled": True,
            "retention_days": 14,
            "capture_level": "application_metadata",
            "allowed_apps": ["excel", "powerpoint"],
            "provider_egress": False,
        },
    )
    assert parsed["ekko"] == {
        "enable": True,
        "planning_enabled": True,
        "build_enabled": True,
        "retention_days": 14,
        "capture_level": "application_metadata",
        "allowed_apps": ["excel", "powerpoint"],
        "provider_egress": False,
    }


def test_write_config_can_record_explicit_ekko_opt_out(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, ekko={"enable": False},
    )
    assert parsed["ekko"] == {"enable": False}


def test_write_config_emits_durable_when_enabled(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        durable={"enabled": True, "keep_last": 5},
    )
    assert parsed["durable"]["enabled"] is True
    assert parsed["durable"]["keep_last"] == 5


def test_write_config_omits_durable_when_disabled(tmp_path: Path, monkeypatch):
    # Off by default: a disabled durable dict writes no [durable] section,
    # keeping the config minimal (the kernel defaults to off anyway).
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        durable={"enabled": False},
    )
    assert "durable" not in parsed


def test_write_config_emits_workspace_journal_when_enabled(tmp_path: Path,
                                                           monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        workspace={"journal": True, "journal_strict": True},
    )
    assert parsed["workspace"]["journal"] is True
    assert parsed["workspace"]["journal_strict"] is True


def test_write_config_omits_workspace_journal_when_declined(tmp_path: Path,
                                                            monkeypatch):
    # Off by default: declining writes no [workspace] section at all — the
    # kernel's journal default is off, so the config stays minimal.
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        workspace={"journal": False},
    )
    assert "workspace" not in parsed


def test_write_config_roundtrips_backslash_paths_and_allowlist(tmp_path: Path, monkeypatch):
    """A Windows backslash workdir must round-trip (escaped TOML basic string)
    and a channel allowed_user_ids must emit as an ARRAY. Regression: the raw
    f'{k} = "{v}"' emit turned C:\\Users... into an invalid \\U escape (config
    unreadable on Windows) and rendered a list as a quoted string."""
    # This test isolates TOML escaping from the separately tested workspace
    # provisioning, and must never create the synthetic user's home directory.
    import maverick_installer.wizard as wizard
    monkeypatch.setattr(wizard, '_prepare_wizard_workspace', dict)
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        sandbox={"backend": "local", "workdir": r"C:\Users\me\maverick ws", "timeout": 60},
        channels={"discord": {
            "enabled": True,
            "bot_token": "${DISCORD_BOT_TOKEN}",
            "allowed_user_ids": ["111", "222"],
        }},
    )
    # Round-trips without TOMLDecodeError and preserves the backslashes.
    assert parsed["sandbox"]["workdir"] == r"C:\Users\me\maverick ws"
    # The allowlist is a TOML array, not a stringified list.
    assert parsed["channels"]["discord"]["allowed_user_ids"] == ["111", "222"]


def test_write_config_emits_tool_acl(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        tool_acl={
            "denied_tools": ["computer"],
            "channels": {"telegram": {"denied_tools": ["shell"]}},
        },
    )
    assert parsed["security"]["denied_tools"] == ["computer"]
    assert parsed["security"]["channels"]["telegram"]["denied_tools"] == ["shell"]


def test_write_config_emits_rate_limits_with_glob(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        rate_limits={"web_search": "10/60", "mcp_*": "60/60"},
    )
    assert parsed["rate_limits"]["web_search"] == "10/60"
    # Glob keys must be quoted in TOML.
    assert parsed["rate_limits"]["mcp_*"] == "60/60"


def test_write_config_emits_retention(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        retention={
            "audit_days": 90, "episodes_days": 365, "events_days": 180,
            "messages_days": 180,
        },
    )
    assert parsed["retention"]["audit_days"] == 90
    assert parsed["retention"]["episodes_days"] == 365
    assert parsed["retention"]["messages_days"] == 180


def test_write_config_emits_persona(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        persona={"name": "Hawk", "style": "concise"},
    )
    assert parsed["persona"]["name"] == "Hawk"
    assert parsed["persona"]["style"] == "concise"


def test_write_config_emits_notifications(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        notifications={"backend": "ntfy", "topic": "alerts"},
    )
    assert parsed["notifications"]["backend"] == "ntfy"
    assert parsed["notifications"]["topic"] == "alerts"


def test_write_config_emits_webhooks(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        webhooks={"outbound": ["https://a.example", "https://b.example"],
                  "secret": "${MAVERICK_WEBHOOK_SECRET}"},
    )
    assert parsed["webhooks"]["outbound"] == ["https://a.example", "https://b.example"]
    assert parsed["webhooks"]["secret"] == "${MAVERICK_WEBHOOK_SECRET}"


def test_write_config_emits_deliverable_handoff(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        deliverables={"handoff_webhook": "https://sor.example/ingest"},
    )
    assert parsed["deliverables"]["handoff_webhook"] == "https://sor.example/ingest"


def test_write_config_emits_personas(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        personas={"default": ["fpa_analyst", "treasurer"]},
    )
    assert parsed["personas"]["default"] == ["fpa_analyst", "treasurer"]


def test_write_config_emits_a2a(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, a2a={"enabled": True},
    )
    assert parsed["a2a"]["enabled"] is True


def test_write_config_emits_web_search_capability(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, web_search_enabled=True,
    )
    assert parsed["capabilities"]["web_search"] is True


def test_write_config_omits_empty_optional_sections(tmp_path: Path, monkeypatch):
    """Unspecified optionals should not emit empty sections."""
    parsed = _write_full_config(tmp_path, monkeypatch)
    for sec in ("mcp_servers", "plugins", "security", "rate_limits",
                "retention", "persona", "notifications", "webhooks", "a2a",
                "self_learning"):
        assert sec not in parsed, f"{sec} should be absent"


# ---------- pick_*() functions return safe defaults when declined ----------

class _StubQ:
    """Mock the questionary primitives — every prompt returns 'no'/empty."""

    def __init__(self, monkeypatch):
        monkeypatch.setattr(
            "maverick_installer.wizard._q_confirm",
            lambda *a, **kw: False,
        )
        monkeypatch.setattr(
            "maverick_installer.wizard._q_text",
            lambda *a, **kw: kw.get("default", ""),
        )
        monkeypatch.setattr(
            "maverick_installer.wizard._q_select",
            lambda *a, **kw: kw.get("default", a[1][0]) if len(a) > 1 else "",
        )
        monkeypatch.setattr(
            "maverick_installer.wizard._q_checkbox",
            lambda *a, **kw: kw.get("default", []),
        )


def test_pick_mcp_servers_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_mcp_servers
    assert pick_mcp_servers() == {}


def test_pick_plugins_returns_empty_when_no_entry_points(monkeypatch):
    _StubQ(monkeypatch)
    # Make the wizard's ``from maverick.plugins import _entry_points`` fail
    # WITHOUT re-importing the module. Popping the module and letting the import
    # re-execute it would bind a second maverick.plugins object as the package
    # attribute while only the sys.modules entry is restored, so every later
    # string-form monkeypatch ("maverick.plugins.x") in the same process would
    # patch the copy while the app kept calling the original.
    monkeypatch.setitem(sys.modules, "maverick.plugins", None)
    import maverick_installer.wizard as w
    assert w.pick_plugins() == []


def test_pick_tool_acl_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_tool_acl
    assert pick_tool_acl(channels={}) == {}


def test_pick_rate_limits_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_rate_limits
    assert pick_rate_limits(channels={}) == {}


def test_pick_retention_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_retention
    assert pick_retention() == {}


def test_pick_retention_accepted_includes_messages_days(monkeypatch):
    """Messages is the fourth retention knob, prompted alongside
    audit/episodes/events when the operator opts in to auto-pruning."""
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: kw.get("default", ""))
    assert wizard.pick_retention() == {
        "audit_days": 90,
        "episodes_days": 365,
        "events_days": 180,
        "messages_days": 180,
    }


def test_pick_persona_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_persona
    assert pick_persona() == {}


def test_pick_a2a_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_a2a
    assert pick_a2a() == ({}, [])


def test_pick_notifications_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_notifications
    cfg, envs = pick_notifications()
    assert cfg == {"personal_alerts": False, "personal_critical_bypass": False, "personal_background": False,
                   "metric_alerts": False}
    assert envs == []


def test_pick_webhooks_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_webhooks
    cfg, envs = pick_webhooks()
    assert cfg == {}
    assert envs == []


def test_pick_web_search_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_web_search
    enabled, envs = pick_web_search()
    assert enabled is False
    assert envs == []


# ---------- new advanced knobs (build-wave feature toggles) ----------

def test_write_config_emits_tools_output_cache(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, advanced={"output_cache": True},
    )
    assert parsed["tools"]["output_cache"] is True


def test_write_config_tools_block_coexists(tmp_path: Path, monkeypatch):
    # deferred_loading + output_cache + hardware_sensors share a single [tools] table.
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        advanced={
            "deferred_tools": True,
            "output_cache": True,
            "hardware_sensors": True,
        },
    )
    assert parsed["tools"]["deferred_loading"] is True
    assert parsed["tools"]["output_cache"] is True
    assert parsed["tools"]["hardware_sensors"] is True


def test_write_config_emits_full_tool_exposure_only_when_chosen(tmp_path: Path, monkeypatch):
    # [tools] exposure defaults to "core" in the kernel; the wizard writes the
    # key only when the operator picked "show every tool".
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        capabilities={"computer_use": False, "tool_exposure": "full"},
    )
    assert parsed["tools"]["exposure"] == "full"
    assert "tool_exposure" not in parsed.get("capabilities", {})
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        capabilities={"computer_use": False, "tool_exposure": "core"},
    )
    assert "exposure" not in parsed.get("tools", {})
    assert "tool_exposure" not in parsed.get("capabilities", {})


def test_write_config_emits_consequence_when_enabled(tmp_path: Path, monkeypatch):
    # The Consequence Engine has a config knob + kernel reader, so the wizard
    # must reach it too. Pin that the wizard emits it.
    parsed = _write_full_config(
        tmp_path, monkeypatch, advanced={"consequence": True},
    )
    assert parsed["consequence"]["enable"] is True


def test_write_config_persists_consequence_opt_out(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"consequence": False})
    assert parsed["consequence"]["enable"] is False


def test_write_config_emits_cortex_when_enabled(tmp_path: Path, monkeypatch):
    # Cortex (the governed company memory) has a kernel knob and a CLI; the
    # wizard step beside fleet memory is what makes it reachable from the
    # installer. Pin that accepting it writes the section the kernel reads.
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"cortex": True})
    assert parsed["cortex"]["enable"] is True


def test_write_config_persists_cortex_opt_out(tmp_path: Path, monkeypatch):
    # Default-on in the kernel, so a deliberate "no" must be written rather
    # than omitted (omitting would silently mean on).
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"cortex": False})
    assert parsed["cortex"]["enable"] is False


def test_write_config_omits_cortex_when_unanswered(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"fleet_memory": True})
    assert "cortex" not in parsed


def test_write_config_emits_shoring_when_enabled(tmp_path: Path, monkeypatch):
    # Autonomous Shoring has a kernel knob ([shoring] enable) and a dashboard
    # surface; the wizard step beside Cortex is what makes it reachable from
    # the installer. Accepting it writes the section the kernel reads.
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"shoring": True})
    assert parsed["shoring"]["enable"] is True


def test_write_config_persists_shoring_opt_out(tmp_path: Path, monkeypatch):
    # Default-on in the kernel, so a deliberate "no" must be written rather
    # than omitted (omitting would silently mean on).
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"shoring": False})
    assert parsed["shoring"]["enable"] is False


def test_write_config_omits_shoring_when_unanswered(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"cortex": True})
    assert "shoring" not in parsed


def test_write_config_emits_routing_energy_aware(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, advanced={"energy_aware": True},
    )
    assert parsed["routing"]["energy_aware"] is True
    assert parsed["routing"]["allowed_providers"] == ["anthropic"]


def test_write_config_emits_system_local_first(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, advanced={"local_first": True},
    )
    assert parsed["system"]["local_first"] is True
    assert "local_first" not in parsed


def test_write_config_emits_local_first_model_for_local_provider(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, providers=["anthropic", "ollama"],
        advanced={"local_first": True},
    )
    assert parsed["system"]["local_first"] is True
    assert parsed["local_first"]["model"].startswith("ollama:")


def test_write_config_emits_self_learning_distill_local(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        self_learning={"enable": True, "distill_local": True},
    )
    assert parsed["self_learning"]["distill_local"] is True


def test_write_config_omits_new_knobs_when_off(tmp_path: Path, monkeypatch):
    # Empty advanced -> no [system], no energy-aware-only [routing], no [tools].
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={})
    assert "system" not in parsed
    assert "routing" not in parsed
    assert "tools" not in parsed


def test_pick_advanced_includes_new_toggles(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_advanced
    adv = pick_advanced()
    for key in ("output_cache", "local_first", "energy_aware", "hardware_sensors"):
        assert key in adv, f"{key} missing from pick_advanced()"


def test_pick_self_learning_includes_distill_local(monkeypatch):
    # Force every confirm to True so the enabled branch runs.
    monkeypatch.setattr("maverick_installer.wizard._q_confirm", lambda *a, **kw: True)
    from maverick_installer.wizard import pick_self_learning
    result = pick_self_learning()
    assert result["enable"] is True
    assert result["distill_local"] is True


def test_pick_self_learning_defaults_to_safe_governed_learning(monkeypatch):
    """Accepting every prompt default enables learning, not executable autonomy."""
    monkeypatch.setattr(
        "maverick_installer.wizard._q_confirm",
        lambda *a, default=False, **kw: default,
    )
    from maverick_installer.wizard import pick_self_learning

    result = pick_self_learning()

    assert result == {
        "enable": True,
        "preflight": True,
        "create_tools": False,
        "provision_packs": True,
            "allow_mcp_acquisition": False,
            "allow_provider_egress": False,
        "distill_local": True,
        "max_acquisitions": 5,
    }


def test_pick_ekko_defaults_off_without_follow_up_prompts(monkeypatch):
    from maverick_installer import wizard

    prompts: list[str] = []

    def _confirm(prompt, *args, default=False, **kwargs):
        prompts.append(prompt)
        return default

    monkeypatch.setattr(wizard, "_q_confirm", _confirm)
    monkeypatch.setattr(
        wizard, "_q_text",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("unexpected follow-up")),
    )

    assert wizard.pick_ekko() == {"enable": False}
    assert len(prompts) == 1


def test_pick_ekko_enabled_branch_is_bounded_and_local_first(monkeypatch):
    from maverick_installer import wizard

    confirms = iter([True, True, True])  # enable, private plans, automatic drafts
    answers = iter(["Excel, PowerPoint, mystery.exe", "999", "1", "999"])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **k: next(confirms))
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: next(answers))
    monkeypatch.setattr(
        wizard, "_q_select",
        lambda *a, **k: "application_metadata - application identity + timing only",
    )

    result = wizard.pick_ekko()

    assert result["enable"] is True
    assert result["planning_enabled"] is True
    assert result["build_enabled"] is True
    assert result["allowed_apps"] == ["excel", "powerpoint"]
    assert result["retention_days"] == 30
    assert result["enrollment_days"] == 30
    assert result["min_occurrences"] == 2
    assert result["min_distinct_days"] == 30
    assert result["provider_egress"] is False


# ---------- finance suite wizard step (finance-agent-suite §8) ----------

def test_pick_finance_skipped(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_finance
    assert pick_finance() == {"enable": False}


def test_write_config_emits_finance_governance(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        finance={"enable": True, "regimes": ["sox", "gaap"],
                 "require_human_above": 5000.0, "deny_above": 50000.0,
                 "sdn_path": "/etc/ofac/sdn.txt"},
    )
    assert parsed["governance"]["require_human_min_risk"] == "high"
    assert parsed["governance"]["require_human_above"]["*"] == 5000.0
    assert parsed["governance"]["deny_above"]["*"] == 50000.0
    assert parsed["finance"]["regimes"] == ["sox", "gaap"]
    assert parsed["screening"]["sdn_path"] == "/etc/ofac/sdn.txt"


def test_write_config_merges_finance_keys_into_profile_governance(
    tmp_path: Path,
    monkeypatch,
):
    parsed = _write_full_config(
        tmp_path,
        monkeypatch,
        governance_profile="regulated",
        finance={
            "enable": True,
            "require_fresh_human_approval": True,
            "require_human_above": 5000.0,
        },
    )

    body_lines = (tmp_path / "config.toml").read_text().splitlines()
    assert body_lines.count("[governance]") == 1
    assert parsed["governance"]["profile"] == "regulated"
    assert parsed["governance"]["require_human_min_risk"] == "high"
    assert parsed["governance"]["require_fresh_human_approval"] is True
    assert parsed["governance"]["require_human_above"]["*"] == 5000.0


def test_write_config_emits_finance_operations_and_new_regimes(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path,
        monkeypatch,
        finance={
            "enable": True,
            "regimes": ["sox", "dora", "basel_iii", "ifrs_17", "pci"],
            "require_human_above": 5000.0,
            "deny_above": 0,
            "sdn_path": "",
            "operations_enable": True,
            "federal_register_enable": True,
            "texas_register_enable": True,
            "regulatory_domains": ["finance", "money_transmitter"],
            "regulatory_poll_seconds": 3600,
            "control_test_interval_seconds": 86400,
            "anomaly_enable": True,
            "sanctions_max_age_hours": 72,
            "control_owner": "Finance Assurance",
        },
    )
    assert parsed["finance"]["regimes"] == [
        "sox", "dora", "basel_iii", "ifrs_17", "pci",
    ]
    operations = parsed["finance_operations"]
    assert operations["enable"] is True
    assert operations["federal_register_enable"] is True
    assert operations["texas_register_enable"] is True
    assert operations["regulatory_domains"] == ["finance", "money_transmitter"]
    assert operations["state_feeds"] == []
    assert operations["control_owner"] == "Finance Assurance"


def test_write_config_can_explicitly_disable_finance_operations(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path,
        monkeypatch,
        finance={
            "enable": True,
            "regimes": ["sox"],
            "require_human_above": 0,
            "deny_above": 0,
            "sdn_path": "",
            "operations_enable": False,
        },
    )
    assert parsed["finance_operations"] == {"enable": False}


def test_write_config_emits_require_fresh_human_approval(tmp_path: Path, monkeypatch):
    # Opt-in per-action oversight: the [governance] scalar is emitted only when
    # the wizard pick set it.
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        finance={"enable": True, "regimes": ["sox"], "require_human_above": 5000.0,
                 "deny_above": 0, "require_fresh_human_approval": True, "sdn_path": ""},
    )
    assert parsed["governance"]["require_fresh_human_approval"] is True
    # Absent by default (backwards compatible).
    parsed2 = _write_full_config(
        tmp_path, monkeypatch,
        finance={"enable": True, "regimes": ["sox"], "require_human_above": 5000.0,
                 "deny_above": 0, "sdn_path": ""},
    )
    assert "require_fresh_human_approval" not in parsed2["governance"]


def test_write_config_omits_finance_when_off(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch)
    assert "finance" not in parsed
    assert "governance" not in parsed
    assert "screening" not in parsed


def test_write_config_finance_zero_pauses_all_without_a_hard_ceiling(tmp_path: Path, monkeypatch):
    from maverick import config

    _write_full_config(
        tmp_path, monkeypatch,
        finance={"enable": True, "regimes": ["sox"],
                 "require_human_above": 0, "deny_above": 0, "sdn_path": ""},
    )
    parsed = config.load_config(tmp_path / "config.toml")
    assert parsed["governance"]["require_human_min_risk"] == "high"
    assert parsed["governance"]["require_human_above"] == {"*": 0}
    assert "screening" not in parsed


# ---------- learning defaults: reasoning_reward + jit_rl opt-out, governance opt-in ----------

def test_pick_advanced_includes_learning_toggles(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_advanced
    adv = pick_advanced()
    for key in ("structured_verifier_off", "jit_rl_off",
                "reward_laundering", "signed_approval"):
        assert key in adv, f"{key} missing from pick_advanced()"


def test_pick_advanced_defaults_governed_learning_on_but_dgm_off(monkeypatch):
    """The advanced wizard's Enter path keeps DGM as a separate opt-in."""
    from maverick_installer import wizard

    monkeypatch.setattr(
        wizard,
        "_q_confirm",
        lambda *a, default=False, **kw: default,
    )
    monkeypatch.setattr(
        wizard,
        "_q_select",
        lambda *a, default=None, **kw: default,
    )
    monkeypatch.setattr(
        wizard,
        "_q_text",
        lambda *a, default="", **kw: default,
    )
    monkeypatch.setattr(
        wizard,
        "_q_checkbox",
        lambda *a, default=None, **kw: default or [],
    )

    advanced = wizard.pick_advanced()

    governed_learning = {
        "reflexion",
        "self_harness",
        "dreaming",
        "skill_synthesis",
        "experience_guidance",
        "credit_assignment",
        "causal_promotion",
        "factory_learning",
        "evaluator_evolution",
        "rehearsal",
        "data_engine",
        "operations_scientist",
        "consequence",
        "cortex",
        "shoring",
    }
    assert all(advanced[key] is True for key in governed_learning)
    assert advanced["structured_verifier_off"] is False
    assert advanced["jit_rl_off"] is False
    assert advanced["self_modify"] is False


def test_write_config_disables_reasoning_reward(tmp_path: Path, monkeypatch):
    # The rubric verifier is on by default; the wizard opt-out writes enable=false.
    parsed = _write_full_config(
        tmp_path, monkeypatch, advanced={"structured_verifier_off": True})
    assert parsed["reasoning_reward"]["enable"] is False
    # The kernel reads what the wizard wrote.
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: parsed)
    assert config.get_reasoning_reward()["enable"] is False


def test_write_config_disables_jit_rl(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"jit_rl_off": True})
    assert parsed["jit_rl"]["enable"] is False
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: parsed)
    assert config.get_jit_rl()["enable"] is False


def test_write_config_emits_reward_laundering_floor(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, advanced={"reward_laundering": True})
    assert parsed["calibration"]["enforce"] is True
    assert parsed["calibration"]["min_resistance"] == 0.5
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: parsed)
    assert config.get_calibration()["min_resistance"] == 0.5


def test_write_config_emits_signed_approval(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(
        tmp_path, monkeypatch, advanced={"signed_approval": True})
    assert parsed["self_improvement"]["require_signed_approval"] is True
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: parsed)
    assert config.get_self_improvement()["require_signed_approval"] is True


def test_write_config_omits_learning_knobs_by_default(tmp_path: Path, monkeypatch):
    # No advanced opt-in -> the on-by-default features write no override sections,
    # and the opt-in governance knobs are absent.
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={})
    assert "reasoning_reward" not in parsed
    assert "jit_rl" not in parsed
    assert "calibration" not in parsed
    assert "self_improvement" not in parsed


def test_write_config_emits_audit_rewards(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"audit_rewards": True})
    assert parsed["reasoning_reward"]["audit_rewards"] is True
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: parsed)
    assert config.get_reasoning_reward()["audit_rewards"] is True


def test_write_config_reasoning_reward_both_keys_one_table(tmp_path: Path, monkeypatch):
    # structured_verifier_off + audit_rewards must share ONE [reasoning_reward]
    # table (two tables would be invalid TOML).
    parsed = _write_full_config(
        tmp_path, monkeypatch,
        advanced={"structured_verifier_off": True, "audit_rewards": True})
    assert parsed["reasoning_reward"]["enable"] is False
    assert parsed["reasoning_reward"]["audit_rewards"] is True


def test_pick_advanced_includes_self_modify(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_advanced
    assert "self_modify" in pick_advanced()


def test_write_config_emits_self_modify(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"self_modify": True})
    assert parsed["self_modify"]["enable"] is True
    from maverick import config
    monkeypatch.setattr(config, "load_global_config", lambda *a, **k: parsed)
    resolved = config.get_self_modify()
    assert resolved["enable"] is True
    assert resolved["editable_paths"] == []  # allowlist stays commented -> inert
    body = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert "Research-only DGM cycles" in body
    assert "runner NEVER applies or promotes code" in body
    assert "two discriminating eval_tests" in body
    assert "require_container=true" in body
    assert '# eval_tests = ["path/test_feature.py::case_a",' in body


@pytest.mark.parametrize("advanced", [{}, {"self_modify": False}])
def test_write_config_omits_self_modify_when_off(
    tmp_path: Path, monkeypatch, advanced,
):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced=advanced)
    assert "self_modify" not in parsed


def test_pick_advanced_includes_commerce(monkeypatch):
    # The Commerce suite tools are a new capability: knob (rule 5) AND wizard
    # step (rule 6). Off by default, like fleet_memory.
    _StubQ(monkeypatch)
    from maverick_installer.wizard import AGENT_SUITES, pick_advanced
    adv = pick_advanced()
    assert "commerce" in adv
    assert adv["commerce"] is False
    # ...and the suite itself is toggleable under [suites] like every other.
    assert "commerce" in {key for key, _label in AGENT_SUITES}


def test_write_config_emits_commerce(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"commerce": True})
    assert parsed["commerce"]["enable"] is True
    assert parsed["commerce"]["backend"] == "demo"
    # The wizard-written section is exactly what the kernel reads back.
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: parsed)
    resolved = config.get_commerce()
    assert resolved["enable"] is True
    assert resolved["backend"] == "demo"
    assert resolved["max_session_spend"] > 0  # caps default, never "no cap"
    from maverick import commerce
    monkeypatch.delenv("MAVERICK_COMMERCE", raising=False)
    assert commerce.enabled() is True


@pytest.mark.parametrize("advanced", [{}, {"commerce": False}])
def test_write_config_omits_commerce_when_off(tmp_path: Path, monkeypatch, advanced):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced=advanced)
    assert "commerce" not in parsed


def test_pick_advanced_includes_adapter_rung(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_advanced
    assert "adapter_rung" in pick_advanced()


def test_pick_per_tenant_keys_defaults_off(monkeypatch):
    _StubQ(monkeypatch)
    from maverick_installer.wizard import pick_per_tenant_keys
    assert pick_per_tenant_keys() is False


def test_write_config_emits_per_tenant_keys(tmp_path: Path, monkeypatch):
    # BYOK opt-in writes the [providers] scalar BEFORE the [providers.<name>]
    # subtables (else TOML rejects the whole file), and the kernel reads it back.
    parsed = _write_full_config(tmp_path, monkeypatch, per_tenant_keys=True)
    assert parsed["providers"]["per_tenant_keys"] is True
    # The subtable still round-trips alongside the scalar.
    assert parsed["providers"]["anthropic"]["api_key"] == "${ANTHROPIC_API_KEY}"

    from maverick import config
    monkeypatch.setattr(config, "load_global_config", lambda *a, **k: parsed)
    monkeypatch.delenv("MAVERICK_PER_TENANT_KEYS", raising=False)
    assert config.providers_per_tenant_keys() is True


def test_write_config_omits_per_tenant_keys_by_default(tmp_path: Path, monkeypatch):
    # Off by default: no bare [providers] scalar, only the provider subtable.
    parsed = _write_full_config(tmp_path, monkeypatch)
    assert "per_tenant_keys" not in parsed["providers"]


def test_write_config_emits_adapter_rung(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"adapter_rung": True})
    assert parsed["adapter_rung"]["enable"] is True
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: parsed)
    resolved = config.get_adapter_rung()
    assert resolved["enable"] is True
    assert resolved["base_model"] is None  # base stays commented -> rung is inert
    assert resolved["allow_model_output"] is False  # distillation guard stays closed


def test_write_config_omits_adapter_rung_when_off(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={})
    assert "adapter_rung" not in parsed


def test_write_config_emits_chat_and_limit_knobs(tmp_path: Path, monkeypatch):
    # Knobs added with chat streaming and bounded connectors/SQL: the wizard is
    # what makes them reachable (rule 6); defaults are omitted, changes written.
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={
        "stream_answers": False, "verify_chat_answers": True,
        "risk_proportional_verify": True,
        "query_timeout_seconds": 60, "connector_max_attempts": 2})
    assert parsed["chat"]["stream_answers"] is False
    assert parsed["verification"] == {"risk_proportional": True, "verify_chat_answers": True}
    assert parsed["query_limits"]["timeout_seconds"] == 60
    assert parsed["connector_limits"]["max_attempts"] == 2
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={
        "stream_answers": True, "query_timeout_seconds": 30, "connector_max_attempts": 3})
    assert not {"chat", "query_limits", "connector_limits"} & parsed.keys()


def test_write_config_emits_immune_canaries_when_enabled(tmp_path: Path, monkeypatch):
    # [immune] canaries is a kernel knob (maverick.config.get_immune); the
    # wizard step is what makes it reachable (rule 6). Off by default.
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"immune_canaries": True})
    assert parsed["immune"]["canaries"] is True
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"fleet_memory": True})
    assert "immune" not in parsed


def test_write_config_emits_swarm_scale_when_raised(tmp_path: Path, monkeypatch):
    # [swarm] is a kernel knob (maverick.config.get_swarm); the wizard step
    # is what makes raising the 64-agent default reachable (rule 6).
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={
        "swarm_max_total_spawns": 300, "swarm_max_concurrent_model_calls": 12})
    assert parsed["swarm"] == {"max_total_spawns": 300, "max_concurrent_model_calls": 12}
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={})
    assert "swarm" not in parsed


def test_write_config_emits_twin_record_alongside_canaries(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"immune_twin_record": True})
    assert parsed["immune"] == {"twin_record": True}
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={
        "immune_canaries": True, "immune_twin_record": True})
    assert parsed["immune"] == {"canaries": True, "twin_record": True}


def test_write_config_emits_ifc_mode_only_when_changed(tmp_path: Path, monkeypatch):
    # [ifc] is a kernel knob (maverick.config.get_ifc); audit is the default.
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={"ifc_mode": "block"})
    assert parsed["ifc"] == {"mode": "block"}
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={})
    assert "ifc" not in parsed


def test_write_config_emits_codebase_when_enabled(tmp_path: Path, monkeypatch):
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={
        "codebase_enable": True, "codebase_protect": "approve"})
    assert parsed["codebase"] == {"enable": True, "default_protect": "approve"}
    parsed = _write_full_config(tmp_path, monkeypatch, advanced={})
    assert "codebase" not in parsed


def test_pick_notifications_writes_the_keys_the_kernel_reads(monkeypatch):
    from maverick_installer import wizard

    answers = iter(["ntfy      - free, no signup, push to phone via ntfy.sh"])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_a, **_k: True)
    monkeypatch.setattr(wizard, "_q_select", lambda *_a, **_k: next(answers))
    monkeypatch.setattr(wizard, "_q_text", lambda message, **_k: (
        "https://lightwork.example/" if "origin" in message else "my-alerts"))
    cfg, _ = wizard.pick_notifications()
    assert cfg == {"backend": "ntfy", "ntfy_topic": "my-alerts", "delivery_receipts": True,
                   "personal_alerts": True, "personal_critical_bypass": True, "personal_background": True,
                   "personal_external": True, "personal_dashboard_url": "https://lightwork.example",
                   "metric_alerts": True}
    # Private delivery refuses anything but an HTTPS origin at send time, so the
    # step does not save one it would refuse (it must not keep "my-alerts").
    for origin in ("my-alerts", "http://lightwork.example", "https://lightwork.example/app"):
        monkeypatch.setattr(wizard, "_q_select", lambda *_a, **_k: "ntfy      - free, no signup, push to phone via ntfy.sh")
        monkeypatch.setattr(wizard, "_q_text", lambda message, origin=origin, **_k: (
            origin if "origin" in message else "my-alerts"))
        cfg, _ = wizard.pick_notifications()
        assert "personal_external" not in cfg and "personal_dashboard_url" not in cfg
    for choice, key in (("slack     - incoming webhook", "slack_webhook"),
                        ("discord   - webhook URL", "discord_webhook")):
        monkeypatch.setattr(wizard, "_q_select", lambda *_a, choice=choice, **_k: choice)
        cfg, _ = wizard.pick_notifications()
        assert key in cfg and "webhook_url" not in cfg
