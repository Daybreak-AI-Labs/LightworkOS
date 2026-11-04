"""Department first outcomes: bundled sample data a real pack can run on."""
from __future__ import annotations

import csv
import io

import pytest
from maverick import sample_outcomes as so
from maverick.domain import available_domains

DEPARTMENTS = ("finance", "privacy", "security", "legal", "hr", "procurement", "customer_support", "tax")
TEXT_SUFFIXES = (".csv", ".md")


def test_exactly_eight_departments_in_display_order():
    assert tuple(so.FIRST_OUTCOMES) == DEPARTMENTS
    assert [row["department"] for row in so.departments()] == list(DEPARTMENTS)


@pytest.mark.parametrize("department", DEPARTMENTS)
def test_fixtures_load_and_parse(department):
    files = so.load_fixtures(department)
    outcome = so.get(department)
    assert "README.md" in files and set(outcome.files) <= set(files)
    for name, text in files.items():
        assert name.endswith(TEXT_SUFFIXES), name
        assert 0 < len(text.encode("utf-8")) < 16_000, name
        if name.endswith(".csv"):
            rows = list(csv.DictReader(io.StringIO(text)))
            assert len(rows) >= 1 and all(None not in row.values() for row in rows), name
    # The README says what a correct result contains and repeats the sample rule.
    readme = " ".join(files["README.md"].split())
    assert "Northwind Fixtures" in readme and "Synthetic" in readme
    assert "A correct result" in readme
    assert "never counts as real evidence" in readme


@pytest.mark.parametrize("department", DEPARTMENTS)
def test_each_outcome_resolves_to_a_pack_that_can_read_its_files(department):
    outcome = so.get(department)
    packs = available_domains()
    assert outcome.pack in packs
    profile = packs[outcome.pack]
    # Every fixture is a text file; read_file is the tool that reads it.
    assert "read_file" in profile.allow_tools and "read_file" not in profile.deny_tools
    assert all(name.endswith(TEXT_SUFFIXES) for name in outcome.files)
    # The gate is the pack's own output contract, so the result lands where we say.
    assert outcome.gate == profile.output.gate
    assert outcome.lands_in == ("Approvals" if profile.output.gate == "approval" else "Results")


def test_finance_seeds_the_three_exceptions_and_expected_shape_names_them():
    files = so.load_fixtures("finance")
    invoices = list(csv.DictReader(io.StringIO(files["invoices.csv"])))
    vendors = {r["vendor"] for r in csv.DictReader(io.StringIO(files["vendor_master.csv"]))}
    pos = {r["po_number"]: r for r in csv.DictReader(io.StringIO(files["purchase_orders.csv"]))}
    by_key = {}
    duplicates, mismatches, unknown = [], [], []
    for inv in invoices:
        key = (inv["vendor"], inv["po_number"], inv["amount_usd"])
        if key in by_key:
            duplicates.append((inv["invoice_id"], by_key[key]))
        by_key.setdefault(key, inv["invoice_id"])
        if inv["vendor"] not in vendors:
            unknown.append(inv["invoice_id"])
        elif inv["amount_usd"] != pos[inv["po_number"]]["total_usd"]:
            mismatches.append(inv["invoice_id"])
    assert duplicates == [("INV-1043", "INV-1041")]
    assert mismatches == ["INV-1044"] and unknown == ["INV-1045"]
    expected = so.expected_result("finance")
    for token in ("INV-1043", "INV-1041", "INV-1044", "INV-1045", so.get("finance").lands_in):
        assert token in expected


def test_sample_workspace_is_created_under_the_workdir_and_flagged(tmp_path):
    target = so.create_sample_workspace("legal", tmp_path)
    assert target == tmp_path / "sample-outcomes" / "legal"
    assert so.is_sample_workspace(target) and not so.is_sample_workspace(tmp_path)
    marker = (target / so.SAMPLE_MARKER_FILENAME).read_text(encoding="utf-8")
    assert "never counts as real evidence" in marker and "legal_nda_desk" in marker
    for rel in so.relative_paths("legal"):
        assert (tmp_path / rel).is_file(), rel
    # Re-running refreshes in place instead of failing.
    (target / "nda_playbook.md").write_text("edited", encoding="utf-8")
    so.create_sample_workspace("legal", tmp_path)
    assert "playbook" in (target / "nda_playbook.md").read_text(encoding="utf-8")


def test_sample_workspace_uses_the_configured_sandbox_workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_WORKDIR", str(tmp_path / "work"))
    from maverick import config
    config.reset_config_cache()
    try:
        assert so.sample_workspace_path("tax") == tmp_path / "work" / "sample-outcomes" / "tax"
    finally:
        config.reset_config_cache()


def test_goal_text_points_at_the_workspace_files_and_repeats_the_rule():
    for department in DEPARTMENTS:
        outcome = so.get(department)
        text = so.goal_description(department)
        assert so.SAMPLE_RULE in text and outcome.lands_in in text
        for rel in so.relative_paths(department):
            assert rel in text and rel.startswith("sample-outcomes/")
        assert outcome.title.startswith(so.SAMPLE_TITLE_PREFIX)
        command = so.cli_command(department)
        # --sample gives the CLI run the brief above, not just the title.
        assert command == f"maverick start --sample {department}"
        assert "--model" not in command and "claude" not in command


def test_resolve_department_accepts_labels_and_slugs_and_falls_back():
    assert so.resolve_department("Privacy & compliance") == "privacy"
    assert so.resolve_department("customer_support") == "customer_support"
    assert so.resolve_department("HR") == "hr"
    assert so.resolve_department("$5") == "finance"
    assert so.resolve_department("") == "finance"
    assert so.resolve_department("nonsense", default=None) is None


def test_goal_is_marked_as_sample_in_the_world(tmp_path):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal(so.get("hr").title, so.goal_description("hr"))
    so.mark_goal_as_sample(world, goal_id, "hr")
    goal = world.get_goal(goal_id)
    assert so.is_sample_goal(world, goal)
    events = world.goal_events(goal_id)
    assert [e.kind for e in events] == [so.SAMPLE_EVENT_KIND]
    assert "hr_onboarding" in events[0].content
    plain = world.create_goal("Reconcile the ledger", "")
    assert not so.is_sample_goal(world, world.get_goal(plain))


def test_config_knob_round_trips(tmp_path, monkeypatch):
    from maverick import config

    cfg = tmp_path / "config.toml"
    cfg.write_text('[first_outcome]\ndepartment = "security"\nsample_workspace_created = true\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    try:
        assert config.get_first_outcome() == {"department": "security", "sample_workspace_created": True}
        cfg.write_text("[budget]\n", encoding="utf-8")
        config.reset_config_cache()
        assert config.get_first_outcome() == {"department": None, "sample_workspace_created": False}
    finally:
        config.reset_config_cache()


@pytest.fixture
def fresh_install(tmp_path, monkeypatch):
    """A fresh install: default configuration, no tool servers, no plugins."""
    import os

    from maverick import config, tools
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox.local import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text("[client]\nid = 'fresh-install'\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    for name in ("_apply_python_plugins", "_apply_ts_plugins", "_apply_grpc_plugins"):
        monkeypatch.setattr(tools, name, lambda registry: None)
    config.reset_config_cache()
    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(llm=None, world=world, budget=Budget(max_dollars=1), blackboard=Blackboard(),
                       sandbox=LocalBackend(workdir=tmp_path), goal_id=world.create_goal("sample check"),
                       use_skills=False)
    yield ctx
    world.close()
    config.reset_config_cache()


@pytest.mark.parametrize("department", DEPARTMENTS)
def test_every_offered_sample_specialist_can_start_on_a_fresh_install(fresh_install, department):
    """The kernel refuses to start a specialist whose workflow needs a
    tool the install lacks (an AP connector, web search). Every sample runs
    its pack exactly as the orchestrator builds it, on a default install."""
    from maverick.domain import agent_from_profile, enabled_domains

    outcome = so.get(department)
    profile = enabled_domains()[outcome.pack]
    agent = agent_from_profile(profile, fresh_install, so.goal_description(department), depth=0)
    # The sample files are workspace files: the specialist reads them itself.
    assert agent.capability.permits("read_file")
    assert "read_file" in {tool.name for tool in agent.tools.all()}


def _start_sample(monkeypatch, tmp_path, *args, backend="local", sandbox_workdir=None,
                  configured_backend=None):
    """Run ``maverick start`` with a stand-in kernel that records what the run got."""
    import types

    import maverick.cli as cli_mod
    from click.testing import CliRunner
    from maverick import config, killswitch

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-dummy")  # pragma: allowlist secret
    if configured_backend is not None:
        cfg = tmp_path / "sample-config.toml"
        cfg.write_text(f"[sandbox]\nbackend = '{configured_backend}'\n", encoding="utf-8")
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    killswitch._last_file_check_ts = 0.0
    killswitch.clear()
    seen = {}

    def run_goal_sync(llm, world, bud, goal_id, **kw):
        goal = world.get_goal(goal_id)
        seen.update(title=goal.title, description=goal.description, domain=kw.get("domain"),
                    sample=so.is_sample_goal(world, types.SimpleNamespace(id=goal_id, title="")))
        world.set_goal_status(goal_id, "done", result="FINAL: ok")
        return "FINAL: ok"

    kernel = types.SimpleNamespace(
        LLM=lambda model=None: object(),
        build_sandbox=lambda **kw: types.SimpleNamespace(workdir=sandbox_workdir or tmp_path / "work"),
        run_goal_sync=run_goal_sync,
    )
    monkeypatch.setattr(cli_mod, "_kernel", lambda: kernel)
    sandbox_args = ["--sandbox", backend] if backend is not None else []
    result = CliRunner().invoke(cli_mod.main, ["start", *args, *sandbox_args,
                                               "--workdir", str(tmp_path / "work")])
    return result, seen


def test_the_printed_sample_command_runs_the_dashboard_brief(monkeypatch, tmp_path):
    # The command setup prints must pass more than the title and pack, or the
    # run never learns which sample files to read or that its output is sample data.
    result, seen = _start_sample(monkeypatch, tmp_path, *so.cli_command("finance").split()[2:])
    assert result.exit_code == 0, result.output
    outcome = so.get("finance")
    assert seen == {"title": outcome.title, "description": so.goal_description("finance"),
                    "domain": outcome.pack, "sample": True}
    workspace = so.sample_workspace_path("finance", tmp_path / "work")
    assert so.is_sample_workspace(workspace)
    assert all((workspace / name).is_file() for name in outcome.files)


@pytest.mark.parametrize("args", [["--sample", "marketing"], ["Other task", "--sample", "finance"],
                                  ["--sample", "finance", "--domain", "legal_nda_desk"]])
def test_sample_start_refuses_unknown_or_mixed_input_before_any_goal(monkeypatch, tmp_path, args):
    result, seen = _start_sample(monkeypatch, tmp_path, *args)
    assert result.exit_code == 2, result.output
    assert seen == {} and "goal #" not in result.output
    assert not (tmp_path / "work" / so.SAMPLE_WORKSPACE_DIRNAME).exists()


@pytest.mark.parametrize("backend", ["ssh", "modal", "firecracker"])
@pytest.mark.parametrize("from_config", [False, True])
def test_sample_start_refuses_non_shared_backends_before_start(monkeypatch, tmp_path, backend, from_config):
    import maverick.cli as cli_mod
    from maverick import budget

    def unexpected(*args, **kwargs):
        pytest.fail("unsupported samples must be rejected before setup or spending")

    monkeypatch.setattr(cli_mod, "_place_sample", unexpected)
    monkeypatch.setattr(budget, "budget_from_config", unexpected)
    result, seen = _start_sample(
        monkeypatch, tmp_path, "--sample", "finance",
        backend=None if from_config else backend,
        configured_backend=backend if from_config else None,
    )
    assert result.exit_code == 2, result.output
    assert f"--sample is not supported with the '{backend}' sandbox" in result.output
    assert "No task was started" in result.output
    assert seen == {} and "goal #" not in result.output
    assert not (tmp_path / "work" / so.SAMPLE_WORKSPACE_DIRNAME).exists()


def test_sample_start_refuses_unknown_configured_backend(monkeypatch, tmp_path):
    result, seen = _start_sample(
        monkeypatch, tmp_path, "--sample", "finance", backend=None, configured_backend="ep:remote",
    )
    assert result.exit_code == 2, result.output
    assert "--sample is not supported" in result.output
    assert seen == {} and "goal #" not in result.output


def test_sample_start_honors_explicit_backend_over_remote_config(monkeypatch, tmp_path):
    result, seen = _start_sample(
        monkeypatch, tmp_path, "--sample", "finance", backend="local", configured_backend="ssh",
    )
    assert result.exit_code == 0, result.output
    assert seen["sample"] is True


@pytest.mark.parametrize("backend", ["local", "docker", "podman", "gvisor", "devcontainer", "kubernetes"])
def test_sample_start_places_fixtures_in_effective_sandbox_workdir(monkeypatch, tmp_path, backend):
    effective = tmp_path / "effective-workspace"
    result, seen = _start_sample(
        monkeypatch, tmp_path, "--sample", "finance", backend=backend, sandbox_workdir=effective,
    )
    assert result.exit_code == 0, result.output
    assert seen["sample"] is True
    assert all((effective / rel).is_file() for rel in so.relative_paths("finance"))
    assert not (tmp_path / "work" / so.SAMPLE_WORKSPACE_DIRNAME).exists()
