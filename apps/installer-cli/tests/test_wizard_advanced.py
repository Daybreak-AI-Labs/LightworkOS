"""The wizard's advanced step writes opt-ins and default-on learning opt-outs.

The keys it writes are exactly the ones the kernel modules read (the rule-6
integrity check: a wizard toggle must actually reach the feature).
"""
from __future__ import annotations

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


def _write(
    cfg_dir,
    monkeypatch,
    advanced,
    capabilities=None,
    security_suite=None,
    assessments=None,
):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    from maverick_installer.wizard import write_config
    write_config(
        providers=["anthropic"], role_models={},
        channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={"ANTHROPIC_API_KEY": "x"},
        capabilities=capabilities or {}, advanced=advanced,
        security_suite=security_suite,
        assessments=assessments,
    )
    return (cfg_dir / "config.toml").read_text()


def test_advanced_all_on_writes_kernel_sections(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {
        "cost_aware": True, "verify_ensemble": True,
        "tree_of_thought": True, "compact_history": True, "reflexion": True,
    })
    assert "[routing]" in cfg
    assert 'allowed_providers = ["anthropic"]' in cfg
    assert "cost_aware = true" in cfg
    assert "verify_ensemble = true" in cfg
    assert "[planning]" in cfg and 'mode = "tree_of_thought"' in cfg
    assert "[context]" in cfg and "compact = true" in cfg
    assert "[reflexion]" in cfg and "enable = true" in cfg


def test_document_engine_choices_reach_runtime_configuration(tmp_path, monkeypatch):
    from maverick import config
    written = tomllib.loads(_write(tmp_path, monkeypatch, {
        "macro_cell_edits": True, "native_recalculation": True, "pdf_ocr": True,
        "document_engine_image": "registry.invalid/documents@sha256:" + "a" * 64,
    }))
    monkeypatch.setattr(config, "load_config", lambda: written)
    actual = config.get_document_tools()
    assert actual["macro_cell_edits"] and actual["native_recalculation"] and actual["pdf_ocr"]
    assert actual["engine_image"] == written["documents"]["engine_image"]
    assert actual["ocr_max_pages"] == 20
    monkeypatch.setattr(config, "load_config", dict)
    defaults = config.get_document_tools()
    assert not any(defaults[key] for key in ("macro_cell_edits", "native_recalculation", "pdf_ocr"))


def test_governed_postgres_pool_toggle_writes_one_shared_table(tmp_path, monkeypatch):
    from maverick_installer import wizard
    for security_suite in (None, {}, {"vendor_onboarding": True}):
        written = tomllib.loads(_write(tmp_path, monkeypatch, {
            "governed_pg_pool": True,
        }, security_suite=security_suite))
        assert written["governed_records"] == {
            "backend": "auto", "pool_size": 1, "pool_timeout_seconds": 5,
        }
        if security_suite is None:
            assert "security_ops" not in written
    defaults = tomllib.loads("\n".join(wizard._cfg_security_suite({})))
    assert defaults["governed_records"]["pool_size"] == 0


def test_advanced_all_off_persists_default_on_learning_opt_out(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, dict.fromkeys(
        ["cost_aware", "verify_ensemble", "tree_of_thought",
         "compact_history", "reflexion", "enforce_quotas", "pg_rls"], False,
    ))
    for section in ("[routing]", "[planning]", "[context]", "[quotas]",
                    "[world_model]"):
        assert section not in cfg
    assert tomllib.loads(cfg)["reflexion"]["enable"] is False


def test_workspace_recovery_requires_explicit_opt_in(tmp_path, monkeypatch):
    from maverick import config
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_, default=False, **__: default)
    monkeypatch.setattr(wizard, "_q_select", lambda *_, default=None, **__: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *_, default="", **__: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *_, **__: [])
    assert wizard.pick_advanced()["allow_workspace_recovery"] is False
    written = tomllib.loads(_write(tmp_path, monkeypatch, {"allow_workspace_recovery": True}))
    monkeypatch.setattr(config, "load_config", lambda: written)
    assert config.get_features()["workspace_recovery"] is True
    written = tomllib.loads(_write(tmp_path, monkeypatch, {"allow_workspace_recovery": False}))
    monkeypatch.setattr(config, "load_config", lambda: written)
    assert config.get_features()["workspace_recovery"] is False


def test_voice_declines_share_one_voice_table(tmp_path, monkeypatch):
    """voice_commands=False + voice_local_stt=False must merge into ONE
    [voice] table (two would be a duplicate-key TOML error)."""
    cfg = _write(tmp_path, monkeypatch, {
        "voice_commands": False, "voice_local_stt": False,
    })
    assert cfg.count("[voice]") == 1
    parsed = tomllib.loads(cfg)
    assert parsed["voice"]["dashboard_commands"] is False
    assert parsed["voice"]["auto_fetch_model"] is False


def test_support_report_opt_out_reaches_runtime_feature_gate(tmp_path, monkeypatch):
    from maverick import config
    written = _write(tmp_path, monkeypatch, {"allow_support_center": False})
    assert tomllib.loads(written)["features"]["support_center"] is False
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    assert config.get_features()["support_center"] is False


def test_voice_local_stt_decline_writes_auto_fetch_off(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"voice_local_stt": False})
    parsed = tomllib.loads(cfg)
    assert parsed["voice"] == {"auto_fetch_model": False}


def test_voice_explicit_accept_persists_download_consent(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {
        "voice_commands": True, "voice_local_stt": True,
    })
    assert tomllib.loads(cfg)["voice"] == {"auto_fetch_model": True}


def test_voice_unanswered_choice_does_not_enable_download(tmp_path, monkeypatch):
    assert "[voice]" not in _write(tmp_path, monkeypatch, {})


def test_pg_rls_writes_world_model_section_with_prep_reminder(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"pg_rls": True})
    assert "[world_model]" in cfg
    assert "rls = true" in cfg
    # The guided opt-in must point at the prep commands, or NULL-tenant rows vanish.
    assert "rls-preflight" in cfg and "backfill" in cfg
    parsed = tomllib.loads(cfg)
    assert parsed["world_model"]["rls"] is True


def test_unified_audit_is_default_off_and_enables_signed_six_suite_projection(
    tmp_path,
    monkeypatch,
):
    absent = tomllib.loads(_write(tmp_path / "off", monkeypatch, {}))
    assert "audit" not in absent

    parsed = tomllib.loads(
        _write(
            tmp_path / "on",
            monkeypatch,
            {"audit_sign": False, "unified_audit": True},
        )
    )
    assert parsed["audit"]["sign"] is True
    assert parsed["audit"]["unified"] == {
        "enable": True,
        "page_size": 100,
        "lease_seconds": 120,
        "max_lag_seconds": 300,
        "max_attempts": 5,
        "retry_backoff_seconds": 30,
        "poll_seconds": 60,
        "custody": {
            "enable": True,
            "authority_revision": 1,
            "checkpoint_enable": True,
            "worm_enable": False,
            "siem_enable": False,
            "max_siem_events_per_run": 500,
            "retry_backoff_seconds": 30,
            "max_retry_backoff_seconds": 3600,
        },
    }


def test_pick_advanced_can_enable_shared_governance_inventory(monkeypatch):
    from maverick_installer import wizard

    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        return "shared governance inventory" in prompt.lower()

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(
        wizard,
        "_q_select",
        lambda *args, default=None, **kwargs: default,
    )
    monkeypatch.setattr(
        wizard,
        "_q_text",
        lambda *args, default="", **kwargs: default,
    )
    monkeypatch.setattr(
        wizard,
        "_q_checkbox",
        lambda *args, default=None, **kwargs: default or [],
    )

    advanced = wizard.pick_advanced()

    assert advanced["governance_inventory"] is True
    assert any(
        "shared governance inventory" in prompt.lower() and default is False
        for prompt, default in prompts
    )


def test_governance_inventory_writes_closed_bounds_and_one_entity_graph(
    tmp_path,
    monkeypatch,
):
    cfg = _write(tmp_path, monkeypatch, {"governance_inventory": True})

    assert cfg.count("[entity_graph]") == 1
    parsed = tomllib.loads(cfg)
    assert parsed["entity_graph"] == {"enable": True}
    assert parsed["governance_inventory"] == {
        "enable": True,
        "retention_seconds": 31_536_000,
        "max_source_records": 10_000,
        "max_entities": 20_000,
        "max_relationships": 40_000,
        "max_export_bytes": 10_485_760,
        "max_snapshots": 10_000,
    }


def test_governance_inventory_reconciles_entity_graph_decline_once(
    tmp_path,
    monkeypatch,
):
    assessments = {"entity_graph": False}

    cfg = _write(
        tmp_path,
        monkeypatch,
        {"governance_inventory": True},
        assessments=assessments,
    )

    assert cfg.count("[entity_graph]") == 1
    parsed = tomllib.loads(cfg)
    assert parsed["entity_graph"] == {"enable": True}
    assert parsed["governance_inventory"]["enable"] is True
    assert assessments == {"entity_graph": False}


def test_governance_inventory_decline_preserves_entity_graph_opt_out(
    tmp_path,
    monkeypatch,
):
    parsed = tomllib.loads(
        _write(
            tmp_path,
            monkeypatch,
            {"governance_inventory": False},
            assessments={"entity_graph": False},
        )
    )

    assert "governance_inventory" not in parsed
    assert parsed["entity_graph"] == {"enable": False}


def test_kernel_modules_read_what_the_wizard_writes(tmp_path, monkeypatch):
    """End-to-end: write via the wizard, then the kernel sees each flag."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in ("MAVERICK_TREE_OF_THOUGHT", "MAVERICK_COMPACT_HISTORY",
                "MAVERICK_REFLEXION"):
        monkeypatch.delenv(env, raising=False)

    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    _write(cfg_dir, monkeypatch, {
        "tree_of_thought": True, "compact_history": True, "reflexion": True,
        "cost_aware": True, "verify_ensemble": True,
    })

    from maverick import context_compactor, reflexion, tree_of_thought
    assert tree_of_thought.enabled() is True
    assert context_compactor.enabled() is True
    assert reflexion.enabled() is True


def test_self_harness_toggle_writes_and_reaches_the_kernel(tmp_path, monkeypatch):
    """Rule-6: the self-harness wizard toggle writes [self_harness] and the
    kernel module actually reads it (a capability needs a config knob AND a
    wizard step -- this proves the step reaches the feature)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_SELF_HARNESS", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"self_harness": True})
    assert "[self_harness]" in cfg and "enable = true" in cfg

    from maverick import self_harness
    assert self_harness.enabled() is True


def test_self_harness_off_persists_opt_out(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"self_harness": False})
    assert tomllib.loads(cfg)["self_harness"]["enable"] is False


def test_effort_and_cache_prewarm_write_and_are_read(tmp_path, monkeypatch):
    """Rule-6: the new efficiency toggles reach the kernel that reads them."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in ("MAVERICK_EFFORT", "MAVERICK_EFFORT_ENABLED",
                "MAVERICK_EFFORT_ORCHESTRATOR", "MAVERICK_CACHE_PREWARM",
                "MAVERICK_CONFIG"):
        monkeypatch.delenv(env, raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"effort": True, "cache_prewarm": True})
    assert "[effort]" in cfg and "enabled = true" in cfg
    assert "[cache]" in cfg and "prewarm = true" in cfg
    # The kernel reads exactly these (config resolves via HOME/~/.maverick).
    from maverick.effort import effort_for_role
    from maverick.llm import cache_prewarm_enabled
    assert effort_for_role("orchestrator", "claude-opus-4-8") == "high"
    assert cache_prewarm_enabled() is True


def test_effort_and_cache_off_write_no_sections(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"effort": False, "cache_prewarm": False})
    assert "[effort]" not in cfg and "[cache]" not in cfg


def test_risk_proportional_verify_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's risk-proportional toggle writes
    [verification] risk_proportional, and the kernel reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_RISK_PROPORTIONAL_VERIFY", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"risk_proportional_verify": True})
    assert "[verification]" in cfg
    assert "risk_proportional = true" in cfg

    from maverick.agent import _risk_proportional_verify_enabled
    assert _risk_proportional_verify_enabled() is True


def test_autonomy_gate_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's autonomy toggle writes [autonomy] enable,
    and the kernel's autonomy gate reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_AUTONOMY_GATE", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"autonomy_gate": True})
    assert "[routing]" in cfg
    assert 'allowed_providers = ["anthropic"]' in cfg
    assert "[autonomy]" in cfg
    assert "enable = true" in cfg

    parsed = tomllib.loads(cfg)
    assert parsed["routing"]["allowed_providers"] == ["anthropic"]

    from maverick import autonomy
    assert autonomy.autonomy_enabled() is True


def test_headless_assume_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's headless toggle writes [autonomy]
    headless_assume, and the kernel reads it back -- independent of the gate's
    `enable` (assume-and-proceed is a distinct axis)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_AUTONOMOUS", raising=False)
    monkeypatch.delenv("MAVERICK_AUTONOMY_GATE", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"headless_assume": True})
    assert "[autonomy]" in cfg
    assert "headless_assume = true" in cfg

    parsed = tomllib.loads(cfg)
    assert parsed["autonomy"] == {"headless_assume": True}  # enable stays off

    from maverick import autonomy
    assert autonomy.assume_when_headless() is True
    assert autonomy.autonomy_enabled() is False


def test_confirm_plan_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's show-the-plan toggle writes [autonomy]
    confirm_plan, and the kernel reads it back independently of the gate."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_AUTONOMY_GATE", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"confirm_plan": True})
    assert tomllib.loads(cfg)["autonomy"] == {"confirm_plan": True}

    from maverick import autonomy
    assert autonomy.confirm_plan_enabled() is True
    assert autonomy.autonomy_enabled() is False


def test_governed_actions_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's governed-actions toggle writes [actions] enable,
    and the kernel's lineage gate reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_GOVERNED_ACTIONS", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"governed_actions": True})
    assert "[actions]" in cfg
    parsed = tomllib.loads(cfg)
    assert parsed["actions"] == {"enable": True}

    from maverick import governed_actions
    assert governed_actions.enabled() is True


def test_calibration_enforce_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's calibration toggle writes [calibration]
    enforce, and the kernel's config reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"calibration_enforce": True})
    assert "[calibration]" in cfg
    assert "enforce = true" in cfg

    from maverick.config import get_calibration
    assert get_calibration()["enforce"] is True


def test_fairness_monitor_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's fairness-monitor toggle writes [fairness_monitor]
    enable, and the kernel's config reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_FAIRNESS_MONITOR", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"fairness_monitor": True})
    assert "[fairness_monitor]" in cfg
    assert "enable = true" in cfg

    from maverick.config import get_fairness_monitor
    assert get_fairness_monitor()["enable"] is True


def test_sota_loop_toggles_write_and_are_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's SOTA-loop toggles write their config sections,
    and the kernel reads each back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in ("MAVERICK_ADAPTIVE_COMPUTE", "MAVERICK_BEST_OF_N",
                "MAVERICK_SKILL_SYNTHESIS", "MAVERICK_EXPERIENCE_GUIDANCE"):
        monkeypatch.delenv(env, raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {
        "adaptive_compute": True, "best_of_n": True,
        "skill_synthesis": True, "experience_guidance": True,
    })
    for section in ("[adaptive_compute]", "[search]", "[skill_synthesis]", "[experience]"):
        assert section in cfg

    from maverick import adaptive_compute, best_of_n, experience
    from maverick.skill import synthesis as skill_synthesis
    assert adaptive_compute.enabled() is True
    assert best_of_n.enabled() is True
    assert skill_synthesis.enabled() is True
    assert experience.enabled() is True


def test_credit_assignment_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's CSCA toggle writes [credit] enable, and the
    kernel reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CREDIT", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"credit_assignment": True})
    assert "[credit]" in cfg
    assert "enable = true" in cfg

    from maverick import credit
    assert credit.enabled() is True


def test_enforce_capabilities_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's capability toggle writes [capabilities]
    enforce, and the kernel reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"enforce_capabilities": True})
    assert "[capabilities]" in cfg
    assert "enforce = true" in cfg

    from maverick.capability import capability_enforced
    assert capability_enforced() is True


def test_per_call_token_exchange_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's per-call token-exchange toggle writes
    [capabilities] per_call_tokens (implying enforce), and the kernel reads it
    back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TOOL_TOKENS", raising=False)
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"per_call_token_exchange": True})
    assert "[capabilities]" in cfg
    assert "per_call_tokens = true" in cfg
    assert "enforce = true" in cfg  # token exchange implies enforcement

    from maverick.tool_token import tool_tokens_enabled
    assert tool_tokens_enabled() is True


def test_enforce_capabilities_reuses_existing_capabilities_table(tmp_path, monkeypatch):
    """The normal wizard path already writes [capabilities]; enabling
    enforcement must add to that table instead of emitting a duplicate TOML
    table that makes the entire config unreadable."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)

    cfg = _write(
        cfg_dir,
        monkeypatch,
        {"enforce_capabilities": True},
        capabilities={"computer_use": False, "browser": False, "ros": False, "code_exec": False},
    )

    assert cfg.count("[capabilities]") == 1
    parsed = tomllib.loads(cfg)
    assert parsed["capabilities"] == {
        "computer_use": False,
        "browser": False,
        "ros": False,
        "code_exec": False,
        "enforce": True,
    }

    from maverick.capability import capability_enforced

    assert capability_enforced() is True
def _write_with_flows(cfg_dir, monkeypatch, flows, advanced):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    from maverick_installer.wizard import write_config
    write_config(
        providers=["anthropic"], role_models={},
        channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={"ANTHROPIC_API_KEY": "x"},
        capabilities={}, advanced=advanced, flows=flows,
    )
    return (cfg_dir / "config.toml").read_text()


def test_flows_requested_by_both_steps_emits_one_table(tmp_path, monkeypatch):
    """The dedicated flow-engine step AND the advanced 'Flow engine?' toggle can
    both ask for [flows]. Emitting the table twice is invalid TOML -- tomllib
    rejects the whole file and load_config() falls back to {} (every wizard
    choice silently lost, and the smoke test reports 'sandbox backend missing').
    Saying yes to both must still produce exactly one parseable [flows] table."""
    cfg = _write_with_flows(
        tmp_path, monkeypatch,
        flows={"enable": True},
        advanced={"flows": True, "flows_auto_evolve": True,
                  "flows_public_url": "https://ops.example.com"},
    )
    assert cfg.count("[flows]") == 1
    parsed = tomllib.loads(cfg)  # a duplicate table would raise here
    assert parsed["flows"]["enable"] is True
    assert parsed["flows"]["auto_evolve"] is True
    assert parsed["flows"]["public_url"] == "https://ops.example.com"
    # The smoke test's canary -- the rest of the config survives the round-trip.
    assert parsed["sandbox"]["backend"] == "local"


def test_flows_only_advanced_step_still_writes_table(tmp_path, monkeypatch):
    """Enabling flows via only the advanced toggle (no dedicated flows arg) still
    emits a single valid [flows] table with the folded extras."""
    cfg = _write_with_flows(
        tmp_path, monkeypatch,
        flows=None,
        advanced={"flows": True, "flows_auto_evolve": True},
    )
    assert cfg.count("[flows]") == 1
    parsed = tomllib.loads(cfg)
    assert parsed["flows"] == {"enable": True, "auto_evolve": True}


def test_tenant_by_user_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's tenant toggle writes [tenancy] by_user, and
    the kernel reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"tenant_by_user": True})
    assert "[tenancy]" in cfg
    assert "by_user = true" in cfg

    from maverick.paths import tenant_by_user_enabled
    assert tenant_by_user_enabled() is True


def test_enforce_quotas_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's quota toggle writes [quotas] enforce + the
    daily caps, and the kernel reads them back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in ("MAVERICK_QUOTA_ENFORCE", "MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY",
                "MAVERICK_QUOTA_MAX_TOKENS_PER_DAY"):
        monkeypatch.delenv(env, raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"enforce_quotas": True})
    assert "[quotas]" in cfg
    assert "enforce = true" in cfg
    assert "max_dollars_per_day = 25.0" in cfg
    assert "max_tokens_per_day = 5000000" in cfg

    from maverick.quotas import over_quota, quotas_enforced
    assert quotas_enforced() is True
    # Nothing recorded yet, so a fresh principal is under quota.
    assert over_quota("alice") is None


def test_oidc_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's OIDC toggle writes a single [auth.oidc] table
    (enabled/issuer/audience/jwks_uri), the config round-trips through the TOML
    parser, and the kernel reads it back via maverick.oidc."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in ("MAVERICK_OIDC_ENABLED", "MAVERICK_OIDC_ISSUER",
                "MAVERICK_OIDC_AUDIENCE", "MAVERICK_OIDC_JWKS_URI",
                "MAVERICK_OIDC_ALGORITHMS"):
        monkeypatch.delenv(env, raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"oidc": {
        "enabled": True,
        "issuer": "https://issuer.example.com",
        "audience": "maverick-client",
        "jwks_uri": "https://issuer.example.com/jwks",
    }})
    # Exactly one [auth.oidc] table -- no duplicate-table bug.
    assert cfg.count("[auth.oidc]") == 1
    # The whole config must still parse (a duplicate table would raise here).
    parsed = tomllib.loads(cfg)
    assert parsed["auth"]["oidc"] == {
        "enabled": True,
        "issuer": "https://issuer.example.com",
        "audience": "maverick-client",
        "jwks_uri": "https://issuer.example.com/jwks",
    }

    from maverick.oidc import load_oidc_config, oidc_enabled
    assert oidc_enabled() is True
    resolved = load_oidc_config()
    assert resolved.issuer == "https://issuer.example.com"
    assert resolved.audience == "maverick-client"
    assert resolved.jwks_uri == "https://issuer.example.com/jwks"
    # Allowlist defaults to asymmetric-only (the wizard doesn't surface it).
    assert resolved.algorithms == ["RS256", "ES256"]


def test_oidc_disabled_writes_no_section(tmp_path, monkeypatch):
    """Declining OIDC (the default) emits no [auth.oidc] table, and the kernel
    sees OIDC as off."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_OIDC_ENABLED", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"oidc": {"enabled": False}})
    assert "[auth.oidc]" not in cfg

    from maverick.oidc import oidc_enabled
    assert oidc_enabled() is False


def test_oidc_browser_login_writes_and_enables(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's optional browser-login fields land in
    [auth.oidc], round-trip through TOML, and the kernel sees login_enabled()."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in (
        "MAVERICK_OIDC_ENABLED", "MAVERICK_OIDC_ISSUER", "MAVERICK_OIDC_AUDIENCE",
        "MAVERICK_OIDC_JWKS_URI", "MAVERICK_OIDC_ALGORITHMS",
        "MAVERICK_OIDC_CLIENT_ID", "MAVERICK_OIDC_CLIENT_SECRET",
        "MAVERICK_OIDC_REDIRECT_URI", "MAVERICK_OIDC_SESSION_SECRET",
    ):
        monkeypatch.delenv(env, raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"oidc": {
        "enabled": True,
        "issuer": "https://issuer.example.com",
        "audience": "maverick-client",
        "jwks_uri": "https://issuer.example.com/jwks",
        "client_id": "dash-client",
        "client_secret": "shhh",  # pragma: allowlist secret
        "redirect_uri": "https://dash.example.com/auth/callback",
        "session_secret": "a-long-random-session-secret",  # pragma: allowlist secret
    }})
    assert cfg.count("[auth.oidc]") == 1
    parsed = tomllib.loads(cfg)["auth"]["oidc"]
    assert parsed["client_id"] == "dash-client"
    assert parsed["redirect_uri"] == "https://dash.example.com/auth/callback"
    assert parsed["session_secret"] == "a-long-random-session-secret"  # pragma: allowlist secret

    from maverick.oidc import login_enabled
    assert login_enabled() is True


def test_oidc_bearer_only_omits_login_fields(tmp_path, monkeypatch):
    """A bearer-only OIDC config (no browser-login opt-in) writes none of the
    login keys, so the kernel leaves the login flow off."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in (
        "MAVERICK_OIDC_ENABLED", "MAVERICK_OIDC_CLIENT_ID",
        "MAVERICK_OIDC_SESSION_SECRET",
    ):
        monkeypatch.delenv(env, raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"oidc": {
        "enabled": True,
        "issuer": "https://issuer.example.com",
        "audience": "maverick-client",
        "jwks_uri": "https://issuer.example.com/jwks",
    }})
    assert "client_id" not in cfg
    assert "session_secret" not in cfg

    from maverick.oidc import login_enabled, oidc_enabled
    assert oidc_enabled() is True
    assert login_enabled() is False


def test_enterprise_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's enterprise toggle writes [enterprise] mode, and
    the kernel reads it back as enterprise_enabled()."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"enterprise": True})
    assert "[enterprise]" in cfg
    assert "mode = true" in cfg

    from maverick.enterprise import enterprise_enabled
    assert enterprise_enabled() is True


def test_encrypt_at_rest_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's encryption toggle writes [encryption] at_rest,
    and the kernel reads it back as at_rest_enabled()."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_ENCRYPT_AT_REST", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"encrypt_at_rest": True})
    assert "[encryption]" in cfg
    assert "at_rest = true" in cfg

    from maverick.crypto_at_rest import at_rest_enabled
    assert at_rest_enabled() is True


def test_encrypt_per_tenant_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the per-tenant toggle writes [encryption] per_tenant under
    at_rest, and the kernel reads it back as per_tenant_at_rest()."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in ("MAVERICK_ENCRYPT_AT_REST", "MAVERICK_ENCRYPT_PER_TENANT",
                "MAVERICK_ENTERPRISE"):
        monkeypatch.delenv(env, raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch,
                 {"encrypt_at_rest": True, "encrypt_per_tenant": True})
    assert "[encryption]" in cfg
    assert "at_rest = true" in cfg and "per_tenant = true" in cfg

    from maverick.crypto_at_rest import per_tenant_at_rest
    assert per_tenant_at_rest() is True


def test_hedge_requests_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the hedge toggle writes [latency] hedge_ms, and the kernel's
    LLM path reads it back as a positive hedge delay."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_LLM_HEDGE_MS", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"hedge_requests": True})
    assert "[latency]" in cfg and "hedge_ms = 1500" in cfg

    from maverick.llm import _hedge_ms
    assert _hedge_ms() == 1500.0


def test_audit_sign_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's audit-signing toggle writes [audit] sign, and
    the kernel's signing resolver reads it back. This is the tamper-evidence
    control `maverick audit verify` and `maverick soc2` depend on."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"audit_sign": True})
    assert "[audit]" in cfg
    assert "sign = true" in cfg

    from maverick.audit.writer import _resolve_signing
    # explicit=None -> falls through to MAVERICK_AUDIT_SIGN env (unset) ->
    # [audit] sign in the config the wizard just wrote.
    assert _resolve_signing(None) is True


def test_document_access_derives_signed_audit_dependency(tmp_path, monkeypatch):
    cfg = _write(
        tmp_path,
        monkeypatch,
        {},
        security_suite={
            "administration_document_access": True,
            "incident_attachment_metadata": True,
        },
    )
    parsed = tomllib.loads(cfg)

    assert parsed["audit"]["sign"] is True
    assert parsed["administration_document_access"]["enable"] is True
    assert parsed["incident_attachment_metadata"]["enable"] is True


def test_vendor_reviewed_upload_choice_reaches_closed_runtime_configuration(tmp_path, monkeypatch):
    from maverick.config import vendor_reviewed_uploads_enabled
    from maverick.vendor_onboarding_config import VendorOnboardingSettings

    for allowed in (True, False):
        parsed = tomllib.loads(_write(tmp_path, monkeypatch, {}, security_suite={
            "vendor_onboarding": True, "vendor_onboarding_owner": "procurement",
            "vendor_reviewed_uploads": allowed,
        }))
        assert VendorOnboardingSettings.from_config(parsed).reviewed_uploads is allowed
        assert vendor_reviewed_uploads_enabled(parsed) is allowed


def test_anonymous_logs_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's anonymous-mode toggle writes [privacy]
    anonymous, and the kernel reads it back as anon_enabled() -- the PII-scrub
    over logs and audit events."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_ANON", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"anonymous_logs": True})
    assert "[privacy]" in cfg
    assert "anonymous = true" in cfg

    from maverick.privacy import anon_enabled
    assert anon_enabled() is True


def test_security_autofix_writes_security_section(tmp_path, monkeypatch):
    # The remediate auto-fix opt-in is reachable from the wizard (rule 6) and
    # writes [security] auto_fix = true for the kernel's auto_fix_enabled() gate.
    text = _write(tmp_path, monkeypatch, {"security_autofix": True})
    assert "[security]" in text and "auto_fix = true" in text


def test_security_autofix_off_writes_no_security_section(tmp_path, monkeypatch):
    text = _write(tmp_path, monkeypatch, {"security_autofix": False})
    assert "auto_fix" not in text


def test_pack_editing_lock_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: declining dashboard pack editing writes [features]
    pack_editing = false, and the kernel reads it back as disabled."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"allow_pack_editing": False})
    assert "[features]" in cfg
    assert "pack_editing = false" in cfg

    from maverick.config import get_features
    assert get_features()["pack_editing"] is False


def test_pack_editing_default_on_writes_no_features_section(tmp_path, monkeypatch):
    """Leaving pack editing on (the default) emits no [features] table, and the
    kernel still reports it enabled."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg = _write(tmp_path, monkeypatch, {"allow_pack_editing": True})
    assert "[features]" not in cfg


def test_role_editing_lock_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: declining dashboard role editing writes [features]
    role_editing = false, and the kernel reads it back as disabled."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"allow_role_editing": False})
    assert "[features]" in cfg
    assert "role_editing = false" in cfg

    from maverick.config import get_features
    assert get_features()["role_editing"] is False


def test_both_editing_locks_share_one_features_table(tmp_path, monkeypatch):
    """Locking both pack and role editing must emit a single [features] table
    (two would be a duplicate-key TOML error); the whole config still parses and
    the kernel reads both flags off."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch,
                 {"allow_pack_editing": False, "allow_role_editing": False})
    assert cfg.count("[features]") == 1
    parsed = tomllib.loads(cfg)  # a duplicate table would raise here
    assert parsed["features"] == {"pack_editing": False, "role_editing": False}

    from maverick.config import get_features
    feats = get_features()
    assert feats["pack_editing"] is False and feats["role_editing"] is False


def test_external_agents_connectors_write_and_are_read(tmp_path, monkeypatch):
    """Rule-6 loop: the governed-execution follow-up writes [external_agents]
    connectors, and the kernel's execute allowlist reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_EXTERNAL_AGENTS", raising=False)
    monkeypatch.delenv("MAVERICK_EXTERNAL_CONNECTORS", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {
        "external_agents": True,
        "external_connectors": ["salesforce", "servicenow"],
    })
    assert "[external_agents]" in cfg
    assert 'connectors = ["salesforce", "servicenow"]' in cfg
    parsed = tomllib.loads(cfg)
    assert parsed["external_agents"]["connectors"] == ["salesforce", "servicenow"]

    from maverick.external_agents import execute_connectors
    assert execute_connectors() == ["salesforce", "servicenow"]


def test_external_agents_without_connectors_stays_screen_only(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"external_agents": True})
    parsed = tomllib.loads(cfg)
    assert parsed["external_agents"] == {"enable": True}  # no hardening keys


def test_external_agents_identity_hardening_flags_write_and_are_read(
        tmp_path, monkeypatch):
    """Rule-6 loop: the require_signed / mint_approval follow-ups write
    [external_agents] keys and the kernel's get_external_agents reads them."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {
        "external_agents": True,
        "external_require_signed": True,
        "external_mint_approval": True,
    })
    parsed = tomllib.loads(cfg)
    assert parsed["external_agents"]["require_signed"] is True
    assert parsed["external_agents"]["mint_approval"] is True

    from maverick.config import get_external_agents
    xa = get_external_agents()
    assert xa["require_signed"] is True and xa["mint_approval"] is True


def test_governed_mcp_sidecar_manifest_writes_a_closed_config(tmp_path, monkeypatch):
    """Rule-6 loop: the external-client sidecar is wizard-configurable and
    its emitted manifest passes the runtime's strict parser."""
    cfg = _write(tmp_path, monkeypatch, {
        "mcp_sidecar": {
            "enable": True,
            "upstream_url": "https://mcp.example.test/mcp",
            "upstream_token_env": "UPSTREAM_MCP_TOKEN",
            "require_shield": True,
            "max_calls_per_window": 25,
            "budget_window_seconds": 3600,
            "listen_host": "127.0.0.1",
            "listen_port": 8787,
            "tools": {
                "search": {
                    "risk": "low",
                    "description": "Reviewed search",
                    "obligation_tags": ["inventory-reviewed"],
                },
            },
        },
    })

    parsed = tomllib.loads(cfg)
    sidecar = parsed["mcp_sidecar"]
    assert sidecar["enable"] is True
    assert sidecar["upstream_url"] == "https://mcp.example.test/mcp"
    assert sidecar["tools"]["search"]["input_schema"] == {
        "type": "object", "properties": {},
    }
    from maverick_mcp.sidecar import SidecarConfig

    loaded = SidecarConfig.from_mapping(sidecar)
    assert loaded.tools[0].governed_action == "mcp_sidecar__search"


def test_governed_execution_planes_write_and_are_read(tmp_path, monkeypatch):
    """Rule-6 loop: the governed-kernel and self-refinement opt-ins write
    [repl] / [harness_refine] and the kernel's getters read them back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_REPL", raising=False)
    monkeypatch.delenv("MAVERICK_HARNESS_REFINE", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"repl": True, "harness_refine": True})
    parsed = tomllib.loads(cfg)
    assert parsed["repl"] == {"enable": True}
    # require_approval is default-on and fails closed, so an accepted gate
    # writes no line at all.
    assert parsed["harness_refine"] == {"enable": True}

    from maverick.config import get_harness_refine, get_repl
    assert get_repl()["enable"] is True
    refine = get_harness_refine()
    assert refine["enable"] is True and refine["require_approval"] is True


def test_declined_refinement_approval_gate_is_written_explicitly(
        tmp_path, monkeypatch):
    """Declining the gate is a real decision: it must reach the file, because
    the default (and a malformed value) both mean 'approval required'."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_HARNESS_REFINE", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {
        "harness_refine": True, "harness_refine_require_approval": False,
    })
    assert tomllib.loads(cfg)["harness_refine"]["require_approval"] is False

    from maverick.config import get_harness_refine
    assert get_harness_refine()["require_approval"] is False


def test_advanced_off_writes_no_governed_execution_sections(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"repl": False, "harness_refine": False})
    assert "[repl]" not in cfg and "[harness_refine]" not in cfg


def test_run_forking_writes_only_an_explicit_decline(tmp_path, monkeypatch):
    """[session_tree] is on by default (lineage only, no execution), so an
    accepted prompt stays byte-identical and only a decline writes."""
    assert "[session_tree]" not in _write(tmp_path, monkeypatch,
                                         {"session_tree": True})
    cfg = _write(tmp_path, monkeypatch, {"session_tree": False})
    assert tomllib.loads(cfg)["session_tree"]["enable"] is False


def test_audit_worm_writes_worm_section(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"audit_worm": True})
    assert "[audit.worm]" in cfg
    assert 'provider = "local"' in cfg
    assert "worm push" in cfg or "worm" in cfg  # points at the command/docs
    parsed = tomllib.loads(cfg)
    assert parsed["audit"]["worm"]["provider"] == "local"
    assert parsed["audit"]["worm"]["retention_days"] == 2555


def test_audit_worm_off_writes_no_worm_section(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"audit_worm": False})
    assert "[audit.worm]" not in cfg


def test_dual_approval_writes_security_quorum(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"dual_approval": True})
    assert "[security]" in cfg
    assert "approvals_required = 2" in cfg
    assert "allow_self_approval = false" in cfg
    parsed = tomllib.loads(cfg)
    assert parsed["security"]["approvals_required"] == 2
    from maverick.safety.dual_control import required_approvals
    monkeypatch.setattr("maverick.safety.dual_control._security_cfg",
                        lambda: parsed["security"])
    assert required_approvals("high") == 2   # rule-6: the kernel reads it back


def test_dual_approval_off_writes_no_quorum(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"dual_approval": False})
    assert "approvals_required" not in cfg


def test_saml_writes_auth_saml_template(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"saml": True})
    assert "[auth.saml]" in cfg
    assert "sp_entity_id" in cfg and "acs_url" in cfg and "idp_metadata_url" in cfg
    parsed = tomllib.loads(cfg)
    assert "saml" in parsed["auth"]


def test_saml_off_writes_no_section(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"saml": False})
    assert "[auth.saml]" not in cfg


def test_donate_trajectories_writes_and_is_read(tmp_path, monkeypatch):
    """Rule-6 loop: the wizard's donation toggle writes [telemetry]
    donate_trajectories, and the kernel reads it back -- the entry point to the
    self-learning training corpus (donation -> ingest -> DPO)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"donate_trajectories": True})
    assert "[telemetry]" in cfg
    assert "donate_trajectories = true" in cfg
    # Metadata-only by default: the wizard step does not turn on text egress.
    assert "donate_text" not in cfg

    from maverick.donation import _donations_enabled
    assert _donations_enabled() is True


def test_donate_trajectories_off_writes_no_section(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"donate_trajectories": False})
    assert "[telemetry]" not in cfg


def test_department_access_writes_dashboard_scoping(tmp_path, monkeypatch):
    # The department-access step writes [dashboard] default_suites + the SCIM
    # group-mapping tables, and the result must be valid, round-trippable TOML
    # (group names carry spaces, so the keys must be quoted).
    cfg = _write(tmp_path, monkeypatch, {"department_access": {
        "default_suites": ["finance", "tax"],
        "group_roles": {"Finance Team": "operator"},
        "group_suites": {"Finance Team": ["finance", "tax"]},
    }})
    assert "[dashboard]" in cfg
    assert 'default_suites = ["finance", "tax"]' in cfg
    assert "[dashboard.group_roles]" in cfg
    assert "[dashboard.group_suites]" in cfg
    parsed = tomllib.loads(cfg)
    dash = parsed["dashboard"]
    assert dash["default_suites"] == ["finance", "tax"]
    assert dash["group_roles"]["Finance Team"] == "operator"
    assert dash["group_suites"]["Finance Team"] == ["finance", "tax"]


def test_department_access_absent_writes_no_dashboard_section(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"department_access": {}})
    assert "[dashboard.group_roles]" not in cfg
    assert "default_suites" not in cfg


def test_customer_workflow_options_share_one_valid_features_table(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"allow_project_reviews": True,
        "allow_outcome_measurement": True, "allow_workflow_readiness": False,
        "allow_action_center": False, "allow_guided_onboarding": False})
    features = tomllib.loads(cfg)["features"]
    assert features["project_reviews"] is True
    assert features["outcome_measurement"] is True
    assert features["workflow_readiness"] is False
    assert features["action_center"] is False
    assert features["guided_onboarding"] is False
    assert cfg.count("[features]") == 1


def test_signing_identity_admission_is_an_explicit_installer_opt_in(tmp_path, monkeypatch):
    enabled = _write(tmp_path, monkeypatch, {"allow_signing_identity_transition": True, "allow_workspace_recovery": True})
    features = tomllib.loads(enabled)["features"]
    assert features["signing_identity_transition"] is True
    assert features["workspace_recovery"] is True
    disabled = _write(tmp_path, monkeypatch, {"allow_signing_identity_transition": False})
    assert tomllib.loads(disabled).get("features", {}).get("signing_identity_transition", False) is False


def test_dashboard_compress_decline_is_written_and_accept_is_the_default(tmp_path, monkeypatch):
    # Response compression is default-on in the app, so only a
    # deliberate "no" (a proxy already compresses) reaches config.toml.
    off = _write(tmp_path, monkeypatch, {"dashboard_compress": False})
    assert tomllib.loads(off)["dashboard"]["compress"] is False
    on = _write(tmp_path, monkeypatch, {"dashboard_compress": True})
    assert "compress" not in tomllib.loads(on).get("dashboard", {})


def test_glass_effects_for_everyone_is_written_only_when_chosen(tmp_path, monkeypatch):
    # Glass effects are off by default (solid panes respond faster), so only a
    # deliberate "yes" reaches config.toml -- as the value the dashboard reads.
    on = _write(tmp_path, monkeypatch, {"dashboard_glass": True})
    assert tomllib.loads(on)["dashboard"]["glass"] == "on"
    off = _write(tmp_path, monkeypatch, {"dashboard_glass": False})
    assert "glass" not in tomllib.loads(off).get("dashboard", {})
    from maverick_dashboard.app import _VALID_GLASS
    assert tomllib.loads(on)["dashboard"]["glass"] in _VALID_GLASS


def test_the_glass_question_defaults_to_off(monkeypatch):
    from maverick_installer import wizard

    asked = {}

    def confirm(question, *, default=False):
        if "glass effects" in question.lower():
            asked["default"] = default
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *args, default=None, **kwargs: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, default="", **kwargs: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *args, default=None, **kwargs: default or [])
    advanced = wizard.pick_advanced()
    assert asked == {"default": False}
    assert advanced["dashboard_glass"] is False


def test_navigation_areas_are_written_only_when_chosen(tmp_path, monkeypatch):
    # The classic sidebar is the default, so only a deliberate "yes" reaches
    # config.toml -- as the values the dashboard reads.
    on = _write(tmp_path, monkeypatch, {"dashboard_navigation": "areas", "dashboard_navigation_personal": True})
    table = tomllib.loads(on)["dashboard"]
    assert (table["navigation"], table["navigation_personal"]) == ("areas", True)
    off = _write(tmp_path, monkeypatch, {"dashboard_navigation": "classic", "dashboard_navigation_personal": False})
    assert {"navigation", "navigation_personal"}.isdisjoint(tomllib.loads(off).get("dashboard", {}))
    from maverick_dashboard.navigation_api import NAVIGATION_MODES
    assert table["navigation"] in NAVIGATION_MODES


def test_the_navigation_questions_default_to_the_classic_sidebar(monkeypatch):
    from maverick_installer import wizard

    asked = {}

    def confirm(question, *, default=False):
        if "sidebar" in question.lower():
            asked[question.split("?")[0]] = default
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *args, default=None, **kwargs: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, default="", **kwargs: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *args, default=None, **kwargs: default or [])
    advanced = wizard.pick_advanced()
    assert len(asked) == 2 and not any(asked.values())
    assert advanced["dashboard_navigation"] == "classic"
    assert advanced["dashboard_navigation_personal"] is False


def test_model_discovery_decline_is_written_and_accept_is_the_default(tmp_path, monkeypatch):
    # Settings > Models discovers reachable models by default, so only a
    # deliberate "no" reaches config.toml, alongside any per-role picks.
    off = _write(tmp_path, monkeypatch, {"model_discovery": False})
    assert tomllib.loads(off)["models"]["discovery"] is False
    on = _write(tmp_path, monkeypatch, {"model_discovery": True})
    assert "discovery" not in tomllib.loads(on).get("models", {})
    from maverick_installer.wizard import _cfg_role_models
    both = "\n".join(_cfg_role_models({"coder": "openai:gpt-5.4"}, discovery=False))
    parsed = tomllib.loads(both)["models"]
    assert parsed == {"coder": "openai:gpt-5.4", "discovery": False}
    assert _cfg_role_models({}, discovery=True) == []


def test_bedrock_auth_mode_is_written_and_iam_needs_no_key(tmp_path, monkeypatch):
    # The wizard asks how to authenticate to Bedrock and writes it; IAM
    # signing carries no api_key line, a bearer token does.
    from maverick_installer import wizard

    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", tmp_path / "config.toml")
    for mode in ("iam", "api_key"):
        wizard.write_config(
            providers=["bedrock"], role_models={}, channels={},
            safety={"profile": "balanced"},
            budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
            sandbox={"backend": "local", "workdir": "~/ws"},
            keys={}, capabilities={}, advanced={},
            provider_options={"bedrock": {"auth_mode": mode}},
        )
        parsed = tomllib.loads((tmp_path / "config.toml").read_text())
        assert parsed["providers"]["bedrock"]["auth_mode"] == mode
        assert ("api_key" in parsed["providers"]["bedrock"]) == (mode == "api_key")

    monkeypatch.setattr(wizard, "_q_select", lambda *a, **k: "api_key - Bedrock bearer token in BEDROCK_API_KEY")
    assert wizard.pick_bedrock_auth() == {"auth_mode": "api_key"}


def test_fact_tags_share_one_memory_table(tmp_path, monkeypatch):
    cfg = tomllib.loads(_write(tmp_path, monkeypatch, {"fact_tags": True, "temporal_memory": True}))
    assert cfg["memory"] == {"fact_tags": True, "temporal": True}


def test_bounded_rebuild_setting_is_written_by_knowledge_wizard():
    from maverick_installer.wizard import _cfg_knowledge
    cfg = tomllib.loads("\n".join(_cfg_knowledge({"enable": True, "reindex_jobs": True})))
    assert cfg["knowledge"]["reindex_jobs"] is True


def test_spending_alerts_keep_their_default_unless_changed(tmp_path, monkeypatch):
    def section(answer, **extra):
        cfg = _write(tmp_path, monkeypatch, {"spending_alert_at": answer, **extra})
        return tomllib.loads(cfg).get("spending_limits")

    assert section("50, 75, 100") is None  # the default needs no line
    assert section("") is None
    assert section("lots") is None  # unreadable keeps the default, never turns alerts off
    assert section("90, 80") == {"alert_at": [80, 90]}
    assert section("none") == {"alert_at": []}
    # The section the kernel reads: spending_alerts.alert_at() follows it.
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    section("80%, 90", spending_workspace_monthly="200")
    from maverick import config, spending_alerts
    config.reset_config_cache()
    assert spending_alerts.alert_at() == [80, 90]
    config.reset_config_cache()


def test_typical_cost_minimum_keeps_its_default_unless_changed(tmp_path, monkeypatch):
    def section(answer):
        cfg = _write(tmp_path, monkeypatch, {"typical_cost_min_runs": answer})
        return tomllib.loads(cfg).get("spending_limits")

    assert section("10") is None  # the default needs no line
    assert section("") is None
    assert section("1") is None  # out of range keeps the default
    assert section("lots") is None
    assert section("25") == {"typical_cost_min_runs": 25}
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    section("30")
    from maverick import config, typical_cost
    config.reset_config_cache()
    assert typical_cost.min_runs() == 30
    config.reset_config_cache()


def _answer_connections(monkeypatch, *, named, self_connect):
    from maverick_installer import wizard

    def confirm(prompt, *, default=False):
        if "Named connections?" in prompt:
            return named
        if "connect their own read-only Google Drive" in prompt:
            return self_connect
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **kw: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **kw: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **kw: [])
    return wizard.pick_advanced()


def test_employee_connected_accounts_need_named_connections_and_the_wizard_says_so(monkeypatch, capsys):
    from maverick_installer import wizard

    answers = _answer_connections(monkeypatch, named=False, self_connect=True)

    assert answers["connections_self_connect"] is False
    assert "only when named connections are on" in capsys.readouterr().out.replace("\n", " ")
    written = tomllib.loads("\n".join(wizard._cfg_advanced(answers, [])))
    assert "connections" not in written


def test_employee_connected_accounts_are_written_with_named_connections(monkeypatch):
    from maverick_installer import wizard

    answers = _answer_connections(monkeypatch, named=True, self_connect=True)

    written = tomllib.loads("\n".join(wizard._cfg_advanced(answers, [])))
    assert written["connections"]["enable"] is True
    assert written["connections"]["allow_self_connect"] is True


def test_public_chat_is_off_by_default_and_on_only_when_chosen(tmp_path, monkeypatch):
    """Public website chat stays closed unless the owner answers yes: no section
    is written by default, and the dashboard gate reads the section the wizard writes."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)

    default = _write(cfg_dir, monkeypatch, {})
    assert "[public_chat]" not in default

    chosen = _write(cfg_dir, monkeypatch, {"allow_public_chat": True})
    assert tomllib.loads(chosen)["public_chat"] == {"enabled": True}

    from maverick import config
    from maverick_dashboard import public_chat_api

    config.reset_config_cache()
    assert public_chat_api.public_chat_enabled() is True
