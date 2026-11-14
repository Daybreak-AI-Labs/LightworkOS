"""CLI refusals and run results remain visible to automation."""
import datetime as dt
import json
import os
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from click.testing import CliRunner
from maverick import cli
from maverick.world_model import WorldModel


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import killswitch
    killswitch.clear()
    yield
    killswitch.clear()


def invoke(*args, **kwargs):
    return CliRunner().invoke(cli.main, list(args), **kwargs)


@pytest.fixture
def runtime(monkeypatch):
    from maverick import operator_preflight, providers
    box, seen = SimpleNamespace(close=Mock()), []
    def run(_llm, world, budget, gid, **_kwargs):
        seen.append(budget)
        world.set_goal_status(gid, "done")
        return "answer"
    kernel = SimpleNamespace(LLM=lambda **_: None, build_sandbox=lambda **_: box, run_goal_sync=run)
    monkeypatch.setattr(cli, "_require_llm_key", lambda *_: None)
    monkeypatch.setattr(cli, "_cli_model", lambda *_: "fixture:offline")
    monkeypatch.setattr(cli, "_kernel", lambda: kernel)
    monkeypatch.setattr(operator_preflight, "_model_specs", lambda _: {})
    monkeypatch.setattr(operator_preflight, "_routed_configuration_missing", lambda _: {})
    monkeypatch.setattr(providers, "missing_sdks", lambda _: [])
    return kernel, box, seen


def patch_fleet(monkeypatch, status):
    from maverick import fleet
    monkeypatch.setattr("maverick.config.load_config", lambda: {"roles": {"viewer": {"allow_tools": []}}})
    value = SimpleNamespace(agents=[SimpleNamespace(name="researcher", role="viewer")],
                            owner="", principal_for=lambda _: "agent:demo.researcher")
    monkeypatch.setattr(fleet, "load_fleet", lambda _: value)
    monkeypatch.setattr(fleet, "record_run", lambda *_: None)
    run = Mock(return_value=status)
    monkeypatch.setattr("maverick.runner.run_goal_in_thread", run)
    return run


def test_fleet_uses_selected_database(monkeypatch, tmp_path):
    run = patch_fleet(monkeypatch, "done")
    db = tmp_path / "other.db"
    result = invoke("--db", str(db), "fleet", "run", "demo", "researcher", "task")
    assert result.exit_code == 0, result.output
    assert run.call_args.kwargs["db_path"] == db


@pytest.mark.parametrize("status,expected", [("done", 0), ("blocked", 2), ("error", 1), (None, 1)])
def test_fleet_reports_unsuccessful_results(monkeypatch, status, expected):
    patch_fleet(monkeypatch, status)
    assert invoke("fleet", "run", "demo", "researcher", "task").exit_code == expected


@pytest.mark.parametrize("command", ["debate", "plan-reflect"])
@pytest.mark.parametrize("stop", ["halt", "suspended"])
def test_model_commands_obey_execution_stop(monkeypatch, command, stop, runtime):
    from maverick import killswitch
    from maverick.tenant.registry import create_tenant, suspend_tenant
    if stop == "halt":
        killswitch.halt("operator stop")
    else:
        create_tenant("acme")
        suspend_tenant("acme")
        monkeypatch.setenv("MAVERICK_TENANT", "acme")
    runtime[0].LLM = Mock(side_effect=AssertionError("provider constructed"))
    result = invoke(command, "question")
    assert result.exit_code == 3, (result.output, result.exception)
    runtime[0].LLM.assert_not_called()


def test_template_budget_obeys_config_but_explicit_flags_keep_precedence(monkeypatch, tmp_path, runtime):
    template = SimpleNamespace(name="example", budget_dollars=50, budget_wall_seconds=900,
                               render=lambda **_: ("task", ""))
    monkeypatch.setattr("maverick.templates.load_template", lambda _: template)
    (tmp_path / "config.toml").write_text('[budget]\nmax_dollars=1.0\nmax_wall_seconds=60\n')
    first = invoke("start", "--template", "example")
    second = invoke("start", "--template", "example", "--max-dollars", "4", "--max-wall-seconds", "120")
    assert first.exit_code == second.exit_code == 0, (first.output, second.output)
    assert [(b.max_dollars, b.max_wall_seconds) for b in runtime[2]] == [(1, 60), (4, 120)]


@pytest.mark.parametrize("all_days", [False, True])
def test_audit_refuses_unknown_rostered_tenant(all_days):
    from maverick.tenant.registry import create_tenant
    create_tenant("acme")
    result = invoke("audit", "verify", "--tenant", "acmee", *(["--all"] if all_days else []))
    assert result.exit_code != 0, result.output
    assert "no such tenant" in result.output


@pytest.mark.parametrize("value", ["nan", "inf", "-0.1"])
def test_canary_refuses_invalid_tolerance(value):
    from maverick.release_canary import CanaryStore
    store = CanaryStore()
    store.record("base", {"cost": 1})
    store.record("candidate", {"cost": 9})
    result = invoke("canary", "compare", "base", "candidate", "--tolerance", value)
    assert result.exit_code == 2, result.output


def test_safety_unknown_backend_is_not_isolated(monkeypatch):
    monkeypatch.setattr("maverick.config.get_sandbox", lambda: {"backend": "dcoker"})
    result = invoke("safety", "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["sandbox"]["isolated"] is False


def test_unknown_active_tenant_refused_before_world_creation(monkeypatch, tmp_path):
    from maverick.tenant.registry import create_tenant
    create_tenant("acme")
    monkeypatch.setenv("MAVERICK_TENANT", "acmee")
    result = invoke("status")
    assert result.exit_code == 2, result.output
    assert "no such tenant" in result.output
    assert not (tmp_path / "home" / "tenants" / "acmee").exists()
    assert invoke("tenant", "list").exit_code == 0
    assert invoke("version").exit_code == 0


@pytest.mark.parametrize("kind", ["goal", "corpus"])
def test_exports_are_private_and_refuse_symlinks(monkeypatch, tmp_path, kind):
    if kind == "goal":
        db = tmp_path / "other.db"
        world = WorldModel(db)
        gid = world.create_goal("task")
        world.close()
        args = ["--db", str(db), "export", str(gid), "-o"]
    else:
        monkeypatch.setattr("maverick.self_harness.settings", lambda: {"eval_corpus": "corpus"})
        monkeypatch.setattr("maverick.self_harness_eval._load_raw", lambda _: {"model": []})
        args = ["self-harness", "corpus", "export", "--out"]
    target = tmp_path / "export.json"
    old_umask = os.umask(0o022)
    try:
        result = invoke(*args, str(target))
    finally:
        os.umask(old_umask)
    assert result.exit_code == 0, result.output
    assert target.stat().st_mode & 0o777 == 0o600
    link = tmp_path / "link.json"
    link.symlink_to(target)
    before = target.read_bytes()
    assert invoke(*args, str(target)).exit_code != 0
    assert invoke(*args, str(link)).exit_code != 0
    assert target.read_bytes() == before


def test_user_export_includes_oldest_turn_above_limit(tmp_path):
    db = tmp_path / "other.db"
    world = WorldModel(db)
    conversation = world.get_or_create_conversation("telegram", "person")
    with world._writing() as conn:
        conn.executemany("INSERT INTO turns(conversation_id,role,content,ts) VALUES(?,?,?,?)",
                         [(conversation.id, "user", str(n), n) for n in range(10_001)])
    world.close()
    result = invoke("--db", str(db), "export-user", "--channel", "telegram", "--user", "person")
    assert result.exit_code == 0, result.output
    turns = json.loads(result.output)["conversations"][0]["turns"]
    assert len(turns) == 10_001 and turns[0]["content"] == "0"


@pytest.mark.parametrize("command", [["health", "1"], ["cost-by-tag", "--json"]])
def test_diagnostics_use_selected_database(monkeypatch, tmp_path, command):
    import maverick.world_model as wm
    opened = []
    def open_selected(path=None):
        opened.append(path)
        return Mock()
    monkeypatch.setattr(wm, "open_world", open_selected)
    monkeypatch.setattr(wm, "close_world_if_owned", lambda _: None)
    monkeypatch.setattr("maverick.health_score.goal_health", lambda *_: None)
    monkeypatch.setattr("maverick.cost.by_tag.gather", lambda _: [])
    db = tmp_path / "other.db"
    invoke("--db", str(db), "diag", *command)
    assert opened == [db]


@pytest.mark.parametrize("mode", ["skip", "raise", "blocked", "failed"])
def test_watch_reports_any_unsuccessful_marker(monkeypatch, tmp_path, runtime, mode):
    marked = tmp_path / "notes.py"
    marked.write_text("# AI: examine this task\n")
    if mode == "skip":
        monkeypatch.setattr(cli, "_watch_goal_allowed", lambda _: (False, "refused"))
    else:
        def run(_llm, world, _budget, gid, **_kwargs):
            if mode == "raise":
                raise RuntimeError("fixture failure")
            world.set_goal_status(gid, mode)
            return mode
        runtime[0].run_goal_sync = run
    assert invoke("watch", str(marked), "--run").exit_code == 1


def test_cost_uses_utc_month_with_a_visible_recent_window(monkeypatch):
    world = Mock()
    boundary = dt.datetime(2024, 2, 1, tzinfo=dt.timezone.utc).timestamp()
    world.list_episodes.return_value = [SimpleNamespace(
        started_at=boundary, cost_dollars=3, input_tokens=0, output_tokens=0, tool_calls=0,
    )]
    monkeypatch.setattr(cli, "open_world", lambda _: world)
    try:
        with monkeypatch.context() as local:
            local.setenv("TZ", "Etc/GMT+8")
            if hasattr(time, "tzset"):
                time.tzset()
            result = invoke("cost", "--month", "2024-02")
    finally:
        if hasattr(time, "tzset"):
            time.tzset()
    assert result.exit_code == 0, result.output
    assert "$3.0000" in result.output
    assert "10,000" in result.output and "recent" in result.output


@pytest.mark.parametrize("confidence,word", [("95", "true"), ("nan", "true"), ("0.5", "ture")])
def test_calibration_rejects_invalid_samples_before_recording(monkeypatch, confidence, word):
    record = Mock(return_value=True)
    monkeypatch.setattr("maverick.calibration.record_sample", record)
    result = invoke("calibrate", "--sample", confidence, word)
    assert result.exit_code == 2, result.output
    record.assert_not_called()


def run_args(command, tmp_path):
    db = tmp_path / "world.db"
    args = ["--db", str(db), command]
    if command == "start":
        args.append("task")
    elif command == "resume":
        world = WorldModel(db)
        args.append(str(world.create_goal("task")))
        world.close()
    elif command == "watch":
        marked = tmp_path / "notes.py"
        marked.write_text("# AI: examine this task\n")
        args.extend([str(marked), "--run"])
    return args


@pytest.mark.parametrize("command", ["start", "chat", "resume", "watch"])
def test_cli_closes_sandbox_on_exit(tmp_path, runtime, command):
    result = invoke(*run_args(command, tmp_path), input="exit\n")
    assert result.exit_code == 0, result.output
    runtime[1].close.assert_called_once_with()


@pytest.mark.parametrize("command", ["start", "resume"])
@pytest.mark.parametrize("status", ["failed", "cancelled"])
def test_run_terminal_failure_is_nonzero(command, status, tmp_path, runtime):
    def run(_llm, world, _budget, gid, **_kwargs):
        world.set_goal_status(gid, status)
        return status
    runtime[0].run_goal_sync = run
    assert invoke(*run_args(command, tmp_path)).exit_code != 0


@pytest.mark.parametrize("command", ["start", "resume", "facts"])
def test_untrusted_results_cannot_emit_terminal_controls(command, tmp_path, runtime):
    args = run_args(command, tmp_path)
    text = "safe\x1b]0;spoofed-title\x07tail"
    if command == "facts":
        world = WorldModel(tmp_path / "world.db")
        world.upsert_fact("key", text)
        world.close()
    def run(_llm, world, _budget, gid, **_kwargs):
        world.set_goal_status(gid, "done")
        return text
    runtime[0].run_goal_sync = run
    result = invoke(*args)
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output and "\x07" not in result.output
    assert "safetail" in result.output


def test_result_write_does_not_mask_run_exception(monkeypatch, tmp_path, runtime):
    monkeypatch.setenv("MAVERICK_DEBUG", "1")
    runtime[0].run_goal_sync = Mock(side_effect=RuntimeError("original run failure"))
    monkeypatch.setattr("maverick.cli.run_result.write_if_requested", Mock(side_effect=OSError("disk full")))
    result = invoke("start", "task", "--result-file", str(tmp_path / "result.json"))
    assert isinstance(result.exception, RuntimeError)
    assert str(result.exception) == "original run failure"


@pytest.mark.parametrize("command", ["harvest", "review", "import", "quality"])
def test_corpus_writes_obey_learning_halt(monkeypatch, tmp_path, command):
    from maverick import killswitch
    monkeypatch.setattr("maverick.self_harness.settings", lambda: {"eval_corpus": "corpus"})
    monkeypatch.setattr(cli, "_corpus_key_and_path", lambda _: ("model", "corpus"))
    operation = Mock(return_value=0 if command in {"harvest", "import"} else [])
    targets = {"harvest": "maverick.self_improvement_runner.run_corpus_harvest",
               "review": "maverick.self_harness_eval.resolve_pending",
               "import": "maverick.self_harness_eval.import_corpus",
               "quality": "maverick.self_improvement_runner.run_corpus_quality"}
    monkeypatch.setattr(targets[command], operation)
    source = tmp_path / "source.json"
    source.write_text('{}')
    args = {"harvest": ["--auto"], "review": ["--accept", "1"],
            "import": [str(source), "--replace"], "quality": ["--retire"]}[command]
    killswitch.halt("operator stop")
    result = invoke("self-harness", "corpus", command, *args)
    assert result.exit_code != 0, result.output
    operation.assert_not_called()
    assert "HALT" in result.output


@pytest.mark.parametrize("args", [["retire", "--older-than-days", "-1", "--yes"],
                                  ["canary", "--model", "fixture", "--graduate-after", "0"]])
def test_harness_rejects_invalid_lifecycle_thresholds(args):
    assert invoke("self-harness", *args).exit_code == 2


def test_onboard_can_finish_after_a_rejected_first_invite():
    from maverick.tenant.registry import get_tenant
    from maverick_dashboard import invites
    first = invoke("tenant", "onboard", "acme", "--admin-email", "invalid")
    assert first.exit_code == 2 and get_tenant("acme") is not None
    retry = invoke("tenant", "onboard", "acme", "--admin-email", "admin@example.test")
    assert retry.exit_code == 0, retry.output
    assert len([i for i in invites.list_invites() if i.tenant == "acme" and i.pending]) == 1
    assert invoke("tenant", "onboard", "acme", "--admin-email", "other@example.test").exit_code == 2


@pytest.mark.parametrize("spent,durable,expected_exit,remaining", [
    (0.75, False, 0, 0.25), (1.0, False, 2, None),
    (1.25, False, 2, None), (-1.0, False, 1, None), (0.75, True, 0, 1.0),
])
def test_resume_uses_remaining_cap_without_charging_history_again(
    monkeypatch, tmp_path, runtime, spent, durable, expected_exit, remaining,
):
    from maverick import checkpoint
    monkeypatch.setattr(checkpoint, "enabled", lambda: durable)
    db = tmp_path / "world.db"
    world = WorldModel(db)
    gid = world.create_goal("task")
    episode = world.start_episode(gid)
    world.end_episode(episode, "first attempt", "interrupted", cost_dollars=spent)
    world.set_goal_status(gid, "blocked")
    world.close()
    result = invoke("--db", str(db), "resume", str(gid), "--max-dollars", "1")
    assert result.exit_code == expected_exit, (result.output, result.exception)
    if expected_exit:
        assert runtime[2] == []
    else:
        assert runtime[2][0].max_dollars == remaining
        assert runtime[2][0].dollars == 0
