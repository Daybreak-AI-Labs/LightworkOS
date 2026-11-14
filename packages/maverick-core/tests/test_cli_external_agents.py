"""`maverick external-agents`: the headless console for the bring-your-own-
agent gateway (enroll / mint / show / admin without the dashboard)."""
from __future__ import annotations

import pytest
from maverick import external_agents as xa
from maverick.agent_trust import agent_for_token, lookup


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _run(*args, **kw):
    from click.testing import CliRunner
    from maverick.cli import main
    return CliRunner().invoke(main, list(args), **kw)


def _enroll_cli(*extra):
    return _run("external-agents", "enroll", "sf-quotebot", "agentforce",
                "--description", "quoting agent",
                "--owner", "jordan@corp.test",
                "--department", "sales",
                "--max-risk", "medium", "--max-dollars", "5", *extra)


# ---- enroll + list ---------------------------------------------------------


def test_enroll_and_list_roundtrip():
    r = _enroll_cli("--allow-tool", "quote_read",
                    "--allow-tool", "quote_send:high",
                    "--deny-tool", "shell",
                    "--budget-period", "monthly",
                    "--max-wall-seconds", "600",
                    "--data-scope", "sales",
                    "--expires-days", "30")
    assert r.exit_code == 0, r.output
    assert "enrolled 'sf-quotebot'" in r.output
    assert "trust=registered" in r.output

    # The tool entries landed split: bare names on the trust entry, the
    # operator's risk rating in the sidecar map; the period stuck.
    agent = lookup("sf-quotebot")
    assert agent is not None
    assert agent.allow_tools == frozenset({"quote_read", "quote_send"})
    assert agent.deny_tools == frozenset({"shell"})
    assert agent.max_wall_seconds == 600
    assert agent.expires_at is not None
    row = xa.roster()[0]
    assert row["tool_risks"] == {"quote_send": "high"}
    assert row["period"] == "monthly"

    r = _run("external-agents", "list")
    assert r.exit_code == 0, r.output
    assert "sf-quotebot" in r.output
    assert "Salesforce Agentforce" in r.output
    assert "dept=sales" in r.output
    assert "$0.00/$5.00 monthly" in r.output
    assert "runs=0" in r.output
    assert "active" in r.output


def test_enroll_bad_platform_or_tool_risk_exits_nonzero():
    r = _run("external-agents", "enroll", "x-bot", "skynet")
    assert r.exit_code != 0
    assert "unknown platform" in r.output

    r = _run("external-agents", "enroll", "x-bot", "bedrock",
             "--allow-tool", "nuke:apocalyptic")
    assert r.exit_code != 0
    assert "unknown risk" in r.output


def test_list_empty_roster():
    r = _run("external-agents", "list")
    assert r.exit_code == 0
    assert "no external agents enrolled" in r.output


def test_enrollment_works_with_plane_disabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_EXTERNAL_AGENTS", raising=False)
    assert xa.enabled() is False
    assert _enroll_cli().exit_code == 0
    r = _run("external-agents", "list")
    assert r.exit_code == 0 and "sf-quotebot" in r.output


# ---- mint ------------------------------------------------------------------


def test_mint_prints_token_once_and_it_verifies():
    _enroll_cli()
    r = _run("external-agents", "mint", "sf-quotebot")
    assert r.exit_code == 0, r.output
    assert "shown once, store it now" in r.output
    tokens = [ln for ln in r.output.splitlines() if ln.startswith("lw-rest-")]
    assert len(tokens) == 1
    resolved = agent_for_token(tokens[0], "rest")
    assert resolved is not None and resolved.id == "sf-quotebot"
    # The roster names the surface but never the value.
    r = _run("external-agents", "list")
    assert tokens[0] not in r.output
    r = _run("external-agents", "show", "sf-quotebot")
    assert tokens[0] not in r.output and "rest" in r.output


def test_mint_other_surface_and_unknown_agent():
    _enroll_cli()
    r = _run("external-agents", "mint", "sf-quotebot", "--surface", "mcp")
    assert r.exit_code == 0
    token = [ln for ln in r.output.splitlines()
             if ln.startswith("lw-mcp-")][0]
    assert agent_for_token(token, "mcp").id == "sf-quotebot"

    r = _run("external-agents", "mint", "ghost")
    assert r.exit_code == 1
    assert "not enrolled" in r.output


def test_mint_step_up_gate_parks_then_mints_with_approval_id(tmp_path):
    import re
    _enroll_cli()
    (tmp_path / "config.toml").write_text(
        "[external_agents]\nmint_approval = true\n", encoding="utf-8")
    from maverick import config
    config.reset_config_cache()
    # The gated first run parks an approval and prints how to continue.
    r = _run("external-agents", "mint", "sf-quotebot")
    assert r.exit_code == 1
    assert "approval required" in r.output
    assert "--approval-id" in r.output
    assert "lw-rest-" not in r.output
    approval_id = int(re.search(r"approval #(\d+)", r.output).group(1))
    from maverick.world_model import WorldModel
    assert WorldModel().decide_approval(approval_id, "approved",
                                        decided_by="admin@corp.test") is True
    r = _run("external-agents", "mint", "sf-quotebot",
             "--approval-id", str(approval_id))
    assert r.exit_code == 0, r.output
    tokens = [ln for ln in r.output.splitlines() if ln.startswith("lw-rest-")]
    assert len(tokens) == 1
    assert agent_for_token(tokens[0], "rest").id == "sf-quotebot"
    # One approval mints exactly one credential.
    r = _run("external-agents", "mint", "sf-quotebot",
             "--approval-id", str(approval_id))
    assert r.exit_code == 1
    assert "one-shot" in r.output


# ---- show ------------------------------------------------------------------


def test_show_renders_detail():
    _enroll_cli("--allow-tool", "quote_send:high")
    xa.record_run("sf-quotebot", {
        "title": "Quote for Northwind renewal", "outcome": "success",
        "summary": "Drafted and sent the renewal quote.",
        "cost_dollars": 1.25, "input_tokens": 900, "output_tokens": 400})
    r = _run("external-agents", "show", "sf-quotebot")
    assert r.exit_code == 0, r.output
    assert "Salesforce Agentforce" in r.output
    assert "jordan@corp.test" in r.output
    assert "$1.25/$5.00 monthly" in r.output
    assert "1 run(s)" in r.output
    assert "quote_send=high" in r.output
    assert "goal #" in r.output and "success" in r.output


def test_show_unknown_exits_nonzero():
    r = _run("external-agents", "show", "ghost")
    assert r.exit_code == 1
    assert "not enrolled" in r.output


# ---- revoke / restore ------------------------------------------------------


def test_revoke_and_restore():
    _enroll_cli()
    r = _run("external-agents", "revoke", "sf-quotebot")
    assert r.exit_code == 0 and "revoked" in r.output
    assert lookup("sf-quotebot").revoked is True

    r = _run("external-agents", "restore", "sf-quotebot")
    assert r.exit_code == 0 and "restored" in r.output
    assert lookup("sf-quotebot").revoked is False

    r = _run("external-agents", "revoke", "ghost")
    assert r.exit_code == 1 and "no trust entry" in r.output
    r = _run("external-agents", "restore", "ghost")
    assert r.exit_code == 1


def test_ordinary_restore_and_gateway_release_refuse_security_containment():
    from maverick import agent_trust
    from maverick.revocation import shared

    assert _enroll_cli().exit_code == 0
    contained = shared().revoke(
        "agent:sf-quotebot", reason="soc: incident", protected=True,
    )
    assert agent_trust.set_revoked("sf-quotebot", True)
    assert xa.contain("sf-quotebot", contained_by="soc")

    restored = _run("external-agents", "restore", "sf-quotebot")
    assert restored.exit_code == 1
    assert "security-contained" in restored.output
    released = _run("external-agents", "release", "sf-quotebot")
    assert released.exit_code == 1
    assert "security-contained" in released.output
    # Removing the entry (then re-enrolling) must not be a way around it.
    removed = _run("external-agents", "remove", "sf-quotebot", "--yes")
    assert removed.exit_code == 1
    assert "security-contained" in removed.output
    removed = _run("trust", "rm", "sf-quotebot")
    assert removed.exit_code == 1
    assert "security-contained" in removed.output
    # `security release` would lift only the revocation row and print success.
    released = _run("security", "release", "agent:sf-quotebot")
    assert released.exit_code == 1
    assert "control-plane release" in released.output

    assert shared().revoked()["agent:sf-quotebot"] == contained
    assert agent_trust.load_registry()["sf-quotebot"].revoked is True
    assert xa.containment_state("sf-quotebot") is True


# ---- release / reset-budget ------------------------------------------------


def test_release_succeeds_and_unknown_exits_one():
    _enroll_cli()
    r = _run("external-agents", "release", "sf-quotebot")
    assert r.exit_code == 0 and "released" in r.output
    assert xa.roster()[0]["contained"] is False

    r = _run("external-agents", "release", "ghost")
    assert r.exit_code == 1
    assert "not enrolled" in r.output


def test_reset_budget_succeeds_and_unknown_exits_one():
    _enroll_cli()
    xa.record_run("sf-quotebot", {
        "title": "Big renewal push", "outcome": "success",
        "summary": "Spent past the cap.", "cost_dollars": 9.0})
    assert xa.roster()[0]["over_budget"] is True

    r = _run("external-agents", "reset-budget", "sf-quotebot")
    assert r.exit_code == 0 and "budget reset" in r.output
    row = xa.roster()[0]
    assert row["over_budget"] is False
    assert row["period_spent"] == 0.0
    assert row["spent_dollars"] == pytest.approx(9.0)  # history preserved

    r = _run("external-agents", "reset-budget", "ghost")
    assert r.exit_code == 1
    assert "not enrolled" in r.output


# ---- remove ----------------------------------------------------------------


def test_remove_with_yes_and_unknown_exits_one():
    _enroll_cli()
    r = _run("external-agents", "remove", "sf-quotebot", "--yes")
    assert r.exit_code == 0 and "removed" in r.output
    assert lookup("sf-quotebot") is None
    assert xa.roster() == []

    r = _run("external-agents", "remove", "sf-quotebot", "--yes")
    assert r.exit_code == 1
    assert "not enrolled" in r.output


def test_remove_prompts_without_yes():
    _enroll_cli()
    r = _run("external-agents", "remove", "sf-quotebot", input="n\n")
    assert r.exit_code != 0  # aborted at the prompt
    assert xa.roster() != []


def test_trust_add_stores_bearer_tokens_hashed_not_raw(tmp_path):
    from maverick import agent_trust

    added = _run("trust", "add", "peer1", "--a2a-token", "RAW-BEARER-abc123")
    assert added.exit_code == 0, added.output
    stored = "".join(p.read_text(encoding="utf-8") for p in tmp_path.rglob("agent_trust*.json"))
    assert stored and "RAW-BEARER-abc123" not in stored
    agent = agent_for_token("RAW-BEARER-abc123", "a2a")
    assert agent is not None and agent.id == "peer1"
    assert agent_trust.lookup("peer1") is not None
