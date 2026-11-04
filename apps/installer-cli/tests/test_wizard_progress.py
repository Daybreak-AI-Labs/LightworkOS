"""Progress-bar UX for the advanced wizard flow: ordered STEPS list,
the _step_indicator formatter, and the Step N/M lines surfacing in run()."""
from __future__ import annotations

# ---------- STEPS list ----------

def test_steps_list_is_ordered_and_unique():
    from maverick_installer import wizard
    assert len(wizard.STEPS) == 44
    keys = [k for k, _ in wizard.STEPS]
    assert keys[0] == "deployment"
    assert keys[-1] == "a2a"
    assert keys[7] == "approvals"
    assert keys[9] == "research_execution"
    assert keys[10] == "candidate_promotion"
    assert keys[11] == "knowledge_access"
    assert keys[25:30] == ["intent_value", "assessments", "security_suite", "monitoring", "advanced"]
    assert len(set(keys)) == len(keys)  # no dupes


# ---------- _step_indicator ----------

def test_step_indicator_formats_step_n_of_m():
    from maverick_installer import wizard
    out = wizard._step_indicator(3)
    assert "Step 3/44" in out
    assert wizard.STEPS[2][1] in out  # the label


def test_step_indicator_includes_breadcrumb_of_done_labels():
    from maverick_installer import wizard
    out = wizard._step_indicator(3, done=["Deployment", "Providers"])
    assert "Step 3/44" in out
    assert "Deployment" in out
    assert "Providers" in out


def test_step_indicator_no_breadcrumb_when_done_empty():
    from maverick_installer import wizard
    out = wizard._step_indicator(1, done=[])
    assert "Step 1/44" in out
    assert "›" not in out


# ---------- indicator surfaces in run() ----------

def test_run_prints_step_indicators(monkeypatch, tmp_path):
    import io

    from maverick_installer import wizard
    from rich.console import Console

    # A fresh installation. The config paths are frozen at the wizard's first
    # import, which in a shared worker can be an earlier test's home holding a
    # saved setup; run() would then stop at the existing-setup notice.
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path / ".maverick")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / ".maverick" / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".maverick" / ".env")

    # Use a no-color console so Rich doesn't fragment "Step N/M" with
    # inline ANSI codes, which would break the substring assertions.
    monkeypatch.setattr(
        wizard, "console",
        Console(file=io.StringIO(), force_terminal=False, no_color=True),
    )

    # Present an interactive stdin so run()'s non-TTY guard doesn't
    # short-circuit the prompt flow under pytest.
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    # Skip the mode picker / consumer branch and preflight.
    monkeypatch.setattr(wizard, "pick_mode", lambda: "advanced")
    monkeypatch.setattr(wizard, "preflight", lambda: True)

    # Stub every pick_* with a benign return matching its shape.
    monkeypatch.setattr(wizard, "pick_deployment", lambda: "desktop")
    monkeypatch.setattr(wizard, "pick_providers", lambda: ["anthropic"])
    monkeypatch.setattr(wizard, "pick_models_per_role", lambda providers, provider_options=None: {})
    monkeypatch.setattr(wizard, "pick_channels", lambda deployment: ({}, set()))
    monkeypatch.setattr(wizard, "pick_safety", dict)
    monkeypatch.setattr(wizard, "pick_signed_skills", dict)
    monkeypatch.setattr(wizard, "pick_budget", dict)
    monkeypatch.setattr(wizard, "pick_sandbox", dict)
    monkeypatch.setattr(wizard, "pick_research_execution", lambda: {"enable": False})
    monkeypatch.setattr(wizard, "pick_candidate_promotion", lambda: {"enable": False})
    monkeypatch.setattr(wizard, "pick_knowledge_access", lambda: {"enable": True})
    monkeypatch.setattr(wizard, "pick_capabilities", dict)
    monkeypatch.setattr(wizard, "pick_ekko", lambda: {"enable": False})
    monkeypatch.setattr(wizard, "pick_intent_value", lambda: {"enabled": True, "recommendations": True, "completion_confirmation": False})
    monkeypatch.setattr(wizard, "pick_security_suite", dict)
    monkeypatch.setattr(wizard, "pick_monitoring", lambda: ({}, {}))
    monkeypatch.setattr(wizard, "pick_advanced", dict)
    monkeypatch.setattr(wizard, "pick_web_search", lambda: (False, []))
    monkeypatch.setattr(wizard, "pick_mcp_servers", dict)
    monkeypatch.setattr(wizard, "pick_plugins", list)
    monkeypatch.setattr(wizard, "pick_tool_acl", lambda channels: {})
    monkeypatch.setattr(wizard, "pick_rate_limits", lambda channels: {})
    monkeypatch.setattr(wizard, "pick_retention", dict)
    monkeypatch.setattr(wizard, "pick_analytics", dict)
    monkeypatch.setattr(wizard, "pick_persona", dict)
    monkeypatch.setattr(wizard, "pick_notifications", lambda: ({}, []))
    monkeypatch.setattr(wizard, "pick_webhooks", lambda: ({}, []))
    monkeypatch.setattr(wizard, "pick_a2a", lambda: ({}, []))

    # Avoid touching disk / network past the prompt loop.
    monkeypatch.setattr(wizard, "_save_partial", lambda state: None)
    monkeypatch.setattr(wizard, "collect_api_keys", lambda providers, envs: {})
    # Decline the final "write config and finish?" so we stop cleanly
    # right after the prompt loop, before write_config / smoke_test.
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: False)
    # Free-text questions in unstubbed steps (e.g. the drafting org name)
    # keep their defaults rather than reaching a real prompt.
    monkeypatch.setattr(wizard, "_q_text",
                        lambda *a, **kw: kw.get("default", ""))
    # Choice questions in unstubbed steps (e.g. who approves a risky action
    # the requester asked for) take their defaults too.
    monkeypatch.setattr(wizard, "_q_select",
                        lambda *a, **kw: kw.get("default") or (a[1][0] if len(a) > 1 and a[1] else ""))

    rc = wizard.run()
    assert rc == 0

    out = wizard.console.file.getvalue()
    assert "Step 1/44" in out
    assert "Step 3/44" in out
    assert "Step 28/44 Security & GRC" in out
    assert "Step 29/44 Monitoring and key management" in out
    assert "Step 44/44" in out
    # Breadcrumb of earlier answers trails later steps.
    assert "Deployment" in out
