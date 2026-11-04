"""Operator CLI for the self-harness learned guidance: `maverick self-harness`.

The loop was invisible from the command line -- an operator could not see what
their agents had learned or roll any of it back. This pins the inspection/undo
surface: ``harness show`` (what was learned, per model), ``harness log`` (the
audit trail of learn/forget events), and ``harness forget`` (the rollback).

Every store/audit path is redirected under a tmp ``MAVERICK_HOME`` so the tests
never touch a real install.
"""
from __future__ import annotations

import json
import re

import pytest
from click.testing import CliRunner
from maverick import self_harness as sh
from maverick.cli import main


def _write_shared_fixture(blocks, path):
    sh._write_addenda(blocks, path)
    meta = sh.load_line_meta(path)
    for model, block in blocks.items():
        for line in sh._bullets(block):
            sh._upsert_line_meta(meta, model, line, {"source_goal_ids": [0]}, now=1)
    sh._write_line_meta(meta, path)


@pytest.fixture
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    return tmp_path


def _seed(model="claude-x", lines=("verify the precondition", "check inputs first")):
    block = "Operating guidance learned for this model:\n" + "\n".join(f"- {x}" for x in lines)
    _write_shared_fixture({model: block}, sh._store_path())


def test_show_lists_learned_guidance(_home):
    _seed()
    r = CliRunner().invoke(main, ["self-harness", "show"])
    assert r.exit_code == 0, r.output
    assert "claude-x" in r.output
    assert "verify the precondition" in r.output and "check inputs first" in r.output


def test_show_json_is_machine_readable(_home):
    _seed()
    r = CliRunner().invoke(main, ["self-harness", "show", "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data == {"claude-x": ["verify the precondition", "check inputs first"]}


def test_show_filters_by_model(_home):
    _seed("model-a", ["line a"])
    _write_shared_fixture({**sh.load_addenda(sh._store_path()),
                       "model-b": "Operating guidance learned for this model:\n- line b"},
                      sh._store_path())
    r = CliRunner().invoke(main, ["self-harness", "show", "--model", "model-a"])
    assert "line a" in r.output and "line b" not in r.output


def test_show_warns_when_disabled(_home, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "0")  # explicit opt-out
    _seed()
    r = CliRunner().invoke(main, ["self-harness", "show"])
    assert r.exit_code == 0
    assert "OFF" in r.output                            # operator is told it won't recall
    assert "verify the precondition" in r.output        # but can still inspect it


def test_show_empty(_home):
    r = CliRunner().invoke(main, ["self-harness", "show"])
    assert r.exit_code == 0 and "no learned guidance" in r.output


def test_holdout_ledger_cli_provisions_once_and_verifies_json(_home):
    path = _home / "sealed-holdout.db"
    runner = CliRunner()
    created = runner.invoke(
        main, ["self-harness", "holdout", "provision", "--path", str(path)])
    assert created.exit_code == 0, created.output
    assert path.exists() and "ledger id" in created.output

    duplicate = runner.invoke(
        main, ["self-harness", "holdout", "provision", "--path", str(path)])
    assert duplicate.exit_code != 0

    verified = runner.invoke(
        main, ["self-harness", "holdout", "verify", "--path", str(path), "--json"])
    assert verified.exit_code == 0, verified.output
    payload = json.loads(verified.output)
    assert payload["path"] == str(path)
    assert payload["events"] == 0 and payload["queries"] == 0
    assert re.fullmatch(r"[0-9a-f]{64}", payload["ledger_id"])


def test_holdout_ledger_cli_requires_path_or_config(_home, monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"self_harness": {}})
    result = CliRunner().invoke(main, ["self-harness", "holdout", "verify"])
    assert result.exit_code != 0 and "holdout ledger path" in result.output


def test_forget_removes_all_for_model(_home):
    _seed()
    r = CliRunner().invoke(main, ["self-harness", "forget", "--model", "claude-x", "--yes"])
    assert r.exit_code == 0 and "removed" in r.output
    assert sh.list_learned() == {}


def test_forget_one_line_keeps_the_rest(_home):
    _seed()
    r = CliRunner().invoke(
        main, ["self-harness", "forget", "--model", "claude-x",
               "--line", "check inputs first", "--yes"])
    assert r.exit_code == 0 and "removed" in r.output
    assert sh.list_learned() == {"claude-x": ["verify the precondition"]}


def test_forget_aborts_without_confirmation(_home):
    _seed()
    r = CliRunner().invoke(main, ["self-harness", "forget", "--model", "claude-x"], input="n\n")
    assert "aborted" in r.output
    assert sh.list_learned() == {"claude-x": ["verify the precondition", "check inputs first"]}


def test_forget_nothing_to_remove(_home):
    r = CliRunner().invoke(main, ["self-harness", "forget", "--model", "ghost", "--yes"])
    assert r.exit_code == 0 and "nothing to remove" in r.output


def test_log_smoke_and_records_forget(_home):
    _seed()
    # a forget is audited; the log surface should not error and ideally show it.
    CliRunner().invoke(main, ["self-harness", "forget", "--model", "claude-x", "--yes"])
    r = CliRunner().invoke(main, ["self-harness", "log"])
    assert r.exit_code == 0, r.output


def test_log_renders_human_readable_timestamp(_home):
    # The audit ts is an epoch float; the operator-facing log must render it as a
    # calendar timestamp, not a raw 1.78e9 float (which answers "when?" with noise).
    _seed()
    CliRunner().invoke(main, ["self-harness", "forget", "--model", "claude-x", "--yes"])
    r = CliRunner().invoke(main, ["self-harness", "log"])
    assert r.exit_code == 0, r.output
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", r.output), r.output
    assert not re.search(r"\b1[0-9]{9}\.\d", r.output), r.output  # no raw epoch float


def test_preview_explains_scoped_exclusion(_home):
    # All-scoped failures are excluded by the trace-poisoning guard, so preview
    # must say "0 eligible" + explain why, not a bare "no weaknesses" that reads
    # as "this model never fails".
    from maverick import reflexion
    for i in range(4):
        reflexion.record(goal_text=f"export ledger {i}", failure_class="timeout",
                         failure_msg="timed out", reflection="x",
                         model_id="claude-x", channel="slack:x", user_id="u1", goal_id=0)
    r = CliRunner().invoke(main, ["self-harness", "preview", "--model", "claude-x"])
    assert r.exit_code == 0, r.output
    assert "0 eligible" in r.output
    assert "excluded by design" in r.output


def test_preview_counts_eligible_unscoped(_home):
    # Unscoped failures ARE eligible; if they just don't meet min-support, the
    # count reflects that (and no scoped-exclusion note is shown).
    from maverick import reflexion
    for i in range(4):
        reflexion.record(goal_text=f"export ledger {i}", failure_class="timeout",
                         failure_msg="timed out", reflection="x", model_id="claude-x", goal_id=0)
    r = CliRunner().invoke(
        main, ["self-harness", "preview", "--model", "claude-x", "--min-support", "99"])
    assert r.exit_code == 0, r.output
    assert "4 eligible" in r.output
    assert "excluded by design" not in r.output


def test_preview_rejects_nonpositive_min_support(_home):
    # min_support < 1 disables mining; the command must say so loudly instead of
    # printing "No recurring weaknesses" (which reads as "your model has none").
    for bad in ("0", "-3"):
        r = CliRunner().invoke(main, ["self-harness", "preview", "--min-support", bad])
        assert r.exit_code != 0, r.output
        assert "min-support" in r.output.lower(), r.output


def _seed_with_meta(model, line, **prov):
    block = "Operating guidance learned for this model:\n- " + line
    _write_shared_fixture({model: block}, sh._store_path())
    rec = {"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "model_id": model, "text": line, "learned_at": 1700000000.0,
           "updated_at": 1700000000.0, **prov}
    sh._write_line_meta({sh._line_id(model, line): rec}, sh._store_path())


def test_show_verbose_renders_provenance(_home):
    _seed_with_meta("claude-x", "verify the token first", signature="auth: 401 expired",
                    rationale="targets 4 'auth' failures", held_out_delta=0.2, samples=8)
    r = CliRunner().invoke(main, ["self-harness", "show", "--verbose"])
    assert r.exit_code == 0, r.output
    assert "auth: 401 expired" in r.output
    assert "held-out +0.2 over 8 samples" in r.output
    assert "2023-11" in r.output                         # learned date rendered


def test_retire_cli_removes_stale_line(_home):
    _seed_with_meta("claude-x", "stale line")             # dated 2023 -> stale
    r = CliRunner().invoke(
        main, ["self-harness", "retire", "--older-than-days", "1", "--yes"])
    assert r.exit_code == 0, r.output
    assert "retired 1 line" in r.output
    assert sh.recall_addendum("claude-x", sh._store_path()) == ""


def test_retire_cli_aborts_without_confirmation(_home):
    _seed_with_meta("claude-x", "stale line")
    r = CliRunner().invoke(
        main, ["self-harness", "retire", "--older-than-days", "1"], input="n\n")
    assert "aborted" in r.output
    assert "stale line" in sh.recall_addendum("claude-x", sh._store_path())


def test_show_verbose_renders_usage(_home):
    _seed_with_meta("claude-x", "verify the token first", signature="auth: 401",
                    held_out_delta=0.2, samples=8, last_recalled_at=1700500000.0)
    r = CliRunner().invoke(main, ["self-harness", "show", "--verbose"])
    assert r.exit_code == 0, r.output
    assert "last recalled" in r.output


def test_conflicts_cli_flags_contradictions(_home):
    block = ("Operating guidance learned for this model:\n"
             "- Prefer streaming for large exports\n"
             "- Avoid streaming for large exports")
    _write_shared_fixture({"claude-x": block}, sh._store_path())
    r = CliRunner().invoke(main, ["self-harness", "conflicts"])
    assert r.exit_code == 0, r.output
    assert "possible conflict" in r.output
    assert "Prefer streaming" in r.output and "Avoid streaming" in r.output


def test_conflicts_cli_clean(_home):
    _write_shared_fixture(
        {"claude-x": "Operating guidance learned for this model:\n- Verify the token first"},
        sh._store_path())
    r = CliRunner().invoke(main, ["self-harness", "conflicts"])
    assert r.exit_code == 0 and "no conflicting guidance" in r.output


def test_conflicts_semantic_flags_reworded_pair(_home, monkeypatch):
    # Two lines that share no content tokens: the lexical heuristic is blind;
    # --semantic wires the verifier-role judge and flags the contradiction.
    from maverick import llm as llm_mod
    _seed("claude-x", ("prefer streaming large exports",
                       "batch everything without exception"))
    r = CliRunner().invoke(main, ["self-harness", "conflicts"])
    assert r.exit_code == 0 and "no conflicting guidance" in r.output

    class _Judge:
        def __init__(self, *a, **k):
            self.model = "fake"

        def complete(self, *a, **k):
            return type("R", (), {"text": "yes"})()

    monkeypatch.setattr(llm_mod, "LLM", _Judge)
    monkeypatch.setattr(llm_mod, "model_for_role", lambda role: "verifier-model")
    r = CliRunner().invoke(main, ["self-harness", "conflicts", "--semantic"])
    assert r.exit_code == 0, r.output
    assert "1 possible conflict(s)" in r.output


def test_conflicts_semantic_falls_back_without_provider(_home, monkeypatch):
    from maverick import llm as llm_mod
    _seed("claude-x", ("line one here", "another thing entirely"))

    def _boom(*a, **k):
        raise RuntimeError("no provider configured")

    monkeypatch.setattr(llm_mod, "LLM", _boom)
    r = CliRunner().invoke(main, ["self-harness", "conflicts", "--semantic"])
    assert r.exit_code == 0, r.output
    assert "semantic judge unavailable" in r.output
    assert "no conflicting guidance" in r.output      # lexical heuristic still ran


def test_run_cli_requires_enable(_home, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "0")      # explicit opt-out
    r = CliRunner().invoke(main, ["self-harness", "run", "--model", "m"])
    assert r.exit_code != 0 and "self-harness is off" in r.output


def test_run_cli_halt_is_generic_and_nonzero(_home, monkeypatch):
    from maverick import learning_guard

    monkeypatch.setattr(
        learning_guard,
        "check_learning_halt",
        lambda *_: (_ for _ in ()).throw(
            learning_guard.Halted("secret operator text", "test")),
    )
    result = CliRunner().invoke(
        main, ["self-harness", "run", "--model", "m"])

    assert result.exit_code != 0
    assert "global learning HALT is active" in result.output
    assert "secret operator text" not in result.output


def test_run_cli_dry_pass(_home, monkeypatch):
    from maverick import config, reflexion
    from maverick import self_improvement as si
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "risk_limited": False}})
    monkeypatch.setattr(si, "enabled", lambda: True)         # gate ON, so "dry" is the reason
    for i in range(3):
        reflexion.record(goal_text=f"export the nightly ledger {i}", failure_class="timeout",
                         failure_msg="timed out", reflection="r", model_id="claude-x", goal_id=0)
    r = CliRunner().invoke(
        main, ["self-harness", "run", "--model", "claude-x", "--no-retire"])
    assert r.exit_code == 0, r.output
    # a weakness is mined but, with no live scorer, nothing is promoted (dry)
    assert "mined=1" in r.output and "promoted=0" in r.output
    assert "dry pass" in r.output
    assert sh.recall_addendum("claude-x", sh._store_path()) == ""


def test_run_cli_retires_stale(_home, monkeypatch):
    import time

    from maverick import config
    # config turns retirement on; the stale line is older than the TTL
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "retire_after_days": 30}})
    block = "Operating guidance learned for this model:\n- ancient line"
    _write_shared_fixture({"claude-x": block}, sh._store_path())
    rec = {"model_id": "claude-x", "text": "ancient line",
           "learned_at": time.time() - 100 * 86400, "updated_at": time.time() - 100 * 86400}
    sh._write_line_meta({sh._line_id("claude-x", "ancient line"): rec}, sh._store_path())
    r = CliRunner().invoke(main, ["self-harness", "run", "--model", "claude-x"])
    assert r.exit_code == 0, r.output
    assert "retired=1" in r.output
    assert sh.recall_addendum("claude-x", sh._store_path()) == ""


def test_run_cli_warns_when_frozen(_home, monkeypatch):
    import maverick.calibration as calibration
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "risk_limited": False}})
    monkeypatch.setattr(calibration, "learning_frozen", lambda: True)
    r = CliRunner().invoke(main, ["self-harness", "run", "--model", "claude-x"])
    assert r.exit_code == 0, r.output
    assert "FROZEN" in r.output and "verifier drift" in r.output


def test_run_cli_warns_when_gate_off(_home, monkeypatch):
    import maverick.calibration as calibration
    from maverick import config
    from maverick import self_improvement as si
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "risk_limited": False}})
    monkeypatch.setattr(calibration, "learning_frozen", lambda: False)
    monkeypatch.setattr(si, "enabled", lambda: False)        # promotion gate OFF
    r = CliRunner().invoke(main, ["self-harness", "run", "--model", "claude-x"])
    assert r.exit_code == 0, r.output
    assert "promotion gate is OFF" in r.output


def test_run_cli_all_models(_home, monkeypatch):
    # the fleet sweep runs a cycle per distinct configured model
    from maverick import self_improvement_runner as runner
    monkeypatch.setattr(runner, "harness_fleet_models", lambda: ["model-a", "model-b"])
    r = CliRunner().invoke(main, ["self-harness", "run", "--all-models", "--no-retire"])
    assert r.exit_code == 0, r.output
    assert "model: model-a" in r.output and "model: model-b" in r.output


def test_run_cli_forwards_exact_deployed_prompt(_home, monkeypatch):
    from maverick import self_improvement_runner as runner

    prompt = _home / "deployed-system.txt"
    prompt.write_bytes(b"Exact deployed system prompt\n")
    seen = []

    def _spy(**kwargs):
        seen.append(kwargs.get("evaluation_system"))
        return sh.SelfHarnessReport(model_id="model-a"), 0

    monkeypatch.setattr(runner, "run_self_harness_cycle", _spy)
    result = CliRunner().invoke(
        main,
        ["self-harness", "run", "--model", "model-a",
         "--system-prompt-file", str(prompt)],
    )

    assert result.exit_code == 0, result.output
    assert seen == ["Exact deployed system prompt\n"]


@pytest.mark.parametrize("payload", [b"", b"\x00bad", b"\xff"])
def test_run_cli_rejects_invalid_deployed_prompt(_home, payload):
    prompt = _home / "bad-system.txt"
    prompt.write_bytes(payload)

    result = CliRunner().invoke(
        main,
        ["self-harness", "run", "--model", "model-a",
         "--system-prompt-file", str(prompt)],
    )

    assert result.exit_code != 0
    assert "cannot read deployed system prompt" in result.output


def test_transfer_cli_requires_corpus_then_reports(_home, monkeypatch):
    from maverick import config
    from maverick import self_improvement_runner as runner
    # no eval corpus -> friendly refusal (transfer validates against it)
    r = CliRunner().invoke(main, ["self-harness", "transfer", "--from", "m1"])
    assert r.exit_code != 0 and "eval_corpus" in r.output
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "eval_corpus": "/etc/maverick/c.json"}})
    monkeypatch.setattr(
        runner, "run_self_harness_transfer",
        lambda src, targets=None, force=False, **kw: {
            "m2": {"attempted": ["ln"], "promoted": ["ln"], "skipped": []}})
    r = CliRunner().invoke(main, ["self-harness", "transfer", "--from", "m1"])
    assert r.exit_code == 0, r.output
    assert "m1 -> m2: attempted=1 promoted=1" in r.output
    assert "+ (canary) ln" in r.output


def test_corpus_quality_reports_and_retires(_home, monkeypatch, tmp_path):
    import json as _json

    from maverick import config
    from maverick import self_harness_eval as ev
    from maverick import self_improvement_runner as runner
    cpath = tmp_path / "corpus.json"
    cpath.write_text(_json.dumps({"m1": [{"goal": "easy", "expected": "y"},
                                         {"goal": "hard", "expected": "y"}]}))
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "eval_corpus": str(cpath)}})
    monkeypatch.setattr(runner, "run_corpus_quality", lambda **kw: [
        {"goal": "easy", "expected": "y", "passes": 2, "samples": 2,
         "baseline_rate": 1.0, "discriminative": False, "age_days": 3.0},
        {"goal": "hard", "expected": "y", "passes": 1, "samples": 2,
         "baseline_rate": 0.5, "discriminative": True, "age_days": None}])
    r = CliRunner().invoke(main, ["self-harness", "corpus", "quality",
                                  "--model", "m1"])
    assert r.exit_code == 0, r.output
    assert "DEAD" in r.output and "2 case(s); 1 non-discriminative" in r.output
    assert "age=3.0d" in r.output
    r = CliRunner().invoke(main, ["self-harness", "corpus", "quality",
                                  "--model", "m1", "--retire"])
    assert r.exit_code == 0, r.output
    assert "retired 1 case(s)" in r.output
    assert [c["goal"] for c in ev.load_eval_corpus(cpath)["m1"]] == ["hard"]


def test_corpus_harvest_requires_corpus(_home):
    r = CliRunner().invoke(main, ["self-harness", "corpus", "harvest"])
    assert r.exit_code != 0 and "eval_corpus" in r.output


def test_corpus_review_lists_and_resolves(_home, monkeypatch, tmp_path):
    import json as _json

    from maverick import config
    from maverick import self_harness_eval as ev
    cpath = tmp_path / "corpus.json"
    cpath.write_text(_json.dumps({"m1": [{"goal": "live", "expected": "x"}]}))
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "eval_corpus": str(cpath)}})
    ev.stage_candidates(cpath, "m1", [{"goal": "g1", "expected": "e1", "privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0]}])
    r = CliRunner().invoke(main, ["self-harness", "corpus", "review",
                                  "--model", "m1"])
    assert r.exit_code == 0, r.output
    assert "1. g1" in r.output and "expected: e1" in r.output
    # Harvested goal text is run-history text: terminal control bytes are
    # stripped before echoing (ANSI/OSC injection).
    ev.stage_candidates(cpath, "m1", [{"goal": "evil \x1b[31mred\x1b[0m goal",
                                       "expected": "\x1b]0;t\x07done", "privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0]}])
    r = CliRunner().invoke(main, ["self-harness", "corpus", "review",
                                  "--model", "m1"])
    assert r.exit_code == 0, r.output
    assert "\x1b" not in r.output and "evil red goal" in r.output
    r = CliRunner().invoke(main, ["self-harness", "corpus", "review",
                                  "--model", "m1", "--accept", "1"])
    assert r.exit_code == 0, r.output
    assert "merged 1 into the corpus" in r.output
    assert "+ accepted: g1" in r.output          # WHAT was resolved is echoed
    assert any(c["goal"] == "g1" for c in ev.load_eval_corpus(cpath)["m1"])
    # an out-of-range index is a hard error, not a silent no-op
    r = CliRunner().invoke(main, ["self-harness", "corpus", "review",
                                  "--model", "m1", "--accept", "9"])
    assert r.exit_code != 0 and "out of range" in r.output
    # drain the remaining (control-char) candidate, then the list is empty
    r = CliRunner().invoke(main, ["self-harness", "corpus", "review",
                                  "--model", "m1", "--reject", "1"])
    assert r.exit_code == 0 and "\x1b" not in r.output
    r = CliRunner().invoke(main, ["self-harness", "corpus", "review",
                                  "--model", "m1"])
    assert "no pending corpus candidates" in r.output


def test_run_cli_echoes_relapsed_lines(_home, monkeypatch):
    from maverick import self_improvement_runner as runner
    rep = sh.SelfHarnessReport(model_id="claude-x")
    rep.relapsed = ["shaky line"]
    monkeypatch.setattr(runner, "run_self_harness_cycle", lambda **k: (rep, 0))
    r = CliRunner().invoke(main, ["self-harness", "run", "--model", "claude-x"])
    assert r.exit_code == 0, r.output
    assert "back on canary probation" in r.output and "~ shaky line" in r.output


def test_run_cli_canary_flag_stages_promotions(_home, monkeypatch):
    # --canary forwards a staging override; without it the cycle gets None so
    # [self_harness] promote_as_canary keeps deciding.
    from maverick import self_improvement_runner as runner
    seen = []

    def _spy(**kw):
        seen.append(kw.get("canary"))
        return sh.SelfHarnessReport(model_id="claude-x"), 0

    monkeypatch.setattr(runner, "run_self_harness_cycle", _spy)
    r = CliRunner().invoke(main, ["self-harness", "run", "--model", "claude-x", "--canary"])
    assert r.exit_code == 0, r.output
    r = CliRunner().invoke(main, ["self-harness", "run", "--model", "claude-x"])
    assert r.exit_code == 0, r.output
    assert seen == [True, None]


# ---- efficacy / canary / domain-scoped forget -----------------------------

def _seed_scoped(model, domain, line, **meta):
    """Seed a single line under a domain-scoped composite key, with sidecar meta."""
    key = sh._scoped_key(model, f"domain={domain}")
    block = "Operating guidance learned for this model:\n- " + line
    store = sh.load_addenda(sh._store_path())
    store[key] = block
    _write_shared_fixture(store, sh._store_path())
    if meta:
        rec = {"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "model_id": model, "text": line, "learned_at": 1700000000.0,
               "updated_at": 1700000000.0, **meta}
        m = sh.load_line_meta(sh._store_path())
        rec["model_id"] = key
        m[sh._line_id(key, line)] = rec
        sh._write_line_meta(m, sh._store_path())


def test_efficacy_shows_outcome_record(_home):
    _seed_with_meta("claude-x", "verify the token first",
                    recall_success=3, recall_failure=1)
    r = CliRunner().invoke(main, ["self-harness", "efficacy", "--model", "claude-x"])
    assert r.exit_code == 0, r.output
    assert "verify the token first" in r.output
    assert "3✓" in r.output and "1✗" in r.output
    assert "75%" in r.output                                 # 3/(3+1)


def test_efficacy_renders_domain_tag_and_no_rate(_home):
    # a domain-scoped line with no outcomes yet: tagged by department, rate "—".
    _seed_scoped("claude-x", "finance", "reconcile before posting")
    r = CliRunner().invoke(main, ["self-harness", "efficacy", "--model", "claude-x"])
    assert r.exit_code == 0, r.output
    assert "reconcile before posting" in r.output
    assert "domain=finance" in r.output
    assert "—" in r.output                                   # no outcomes -> no rate


def test_efficacy_empty(_home):
    r = CliRunner().invoke(main, ["self-harness", "efficacy", "--model", "ghost"])
    assert r.exit_code == 0 and "no learned guidance" in r.output


def test_canary_lists_probation_lines(_home):
    _seed_with_meta("claude-x", "stream large exports", canary=True)
    r = CliRunner().invoke(main, ["self-harness", "canary", "--model", "claude-x"])
    assert r.exit_code == 0, r.output
    assert "1 line(s) on canary probation" in r.output
    assert "stream large exports" in r.output


def test_canary_none_on_probation(_home):
    _seed_with_meta("claude-x", "permanent line")            # not a canary
    r = CliRunner().invoke(main, ["self-harness", "canary", "--model", "claude-x"])
    assert r.exit_code == 0 and "no lines on canary probation" in r.output


def test_canary_review_graduates_and_demotes(_home):
    # a proven canary graduates (flag cleared, line kept); a failing one is pulled.
    _seed_with_meta("claude-x", "proven line", canary=True,
                    recall_success=3, recall_failure=0)
    _write_shared_fixture(
        {**sh.load_addenda(sh._store_path()),
         "claude-x": ("Operating guidance learned for this model:\n"
                      "- proven line\n- failing line")},
        sh._store_path())
    m = sh.load_line_meta(sh._store_path())
    m[sh._line_id("claude-x", "failing line")] = {
        "privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0],
        "model_id": "claude-x", "text": "failing line", "canary": True,
        "recall_success": 0, "recall_failure": 2}
    sh._write_line_meta(m, sh._store_path())
    r = CliRunner().invoke(main, ["self-harness", "canary", "--model", "claude-x", "--review"])
    assert r.exit_code == 0, r.output
    assert "graduated: proven line" in r.output
    assert "demoted:   failing line" in r.output
    # graduated stays (no longer a canary); demoted is gone.
    assert sh.list_canaries("claude-x") == []
    assert "proven line" in sh.recall_addendum("claude-x", sh._store_path())
    assert "failing line" not in sh.recall_addendum("claude-x", sh._store_path())


def test_forget_domain_scopes_removal(_home):
    # model-wide + a finance block; forget --domain finance leaves model-wide intact.
    _seed("claude-x", ["check inputs first"])
    _seed_scoped("claude-x", "finance", "reconcile before posting")
    r = CliRunner().invoke(
        main, ["self-harness", "forget", "--model", "claude-x",
               "--domain", "finance", "--yes"])
    assert r.exit_code == 0 and "removed" in r.output
    assert "reconcile before posting" not in sh.recall_addendum(
        "claude-x", sh._store_path(), domain="finance")
    assert "check inputs first" in sh.recall_addendum("claude-x", sh._store_path())


def test_forget_domain_nothing_to_remove(_home):
    _seed("claude-x", ["check inputs first"])               # no finance block
    r = CliRunner().invoke(
        main, ["self-harness", "forget", "--model", "claude-x",
               "--domain", "finance", "--yes"])
    assert r.exit_code == 0 and "nothing to remove" in r.output
    assert "check inputs first" in sh.recall_addendum("claude-x", sh._store_path())
