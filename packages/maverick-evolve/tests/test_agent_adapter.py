from __future__ import annotations

import random

import pytest
from maverick_evolve import EvalCase, evolve_live, make_agent_factory
from maverick_evolve.agent_adapter import (
    _extract_answer,
    env_for,
    overlay_for,
    subprocess_run_one,
    write_overlay,
)


def test_env_for_maps_import_time_knobs():
    env = env_for({"max_swarm_fanout": 12, "verifier_confidence": 0.8})
    assert env["MAVERICK_MAX_SWARM_FANOUT"] == "12"
    assert env["MAVERICK_VERIFIER_CONFIDENCE"] == "0.8"


def test_overlay_for_enables_features():
    ov = overlay_for({
        "adaptive_compute.low_uncertainty": 0.3,
        "search.n": 4,
        "autonomy.disagreement_high": 0.6,
    })
    assert ov["adaptive_compute"] == {"enable": True, "low_uncertainty": 0.3}
    assert ov["search"] == {"enable": True, "n": 4}
    assert ov["autonomy"]["enable"] is True


def test_render_overlay_is_valid_toml(tmp_path):
    try:
        import tomllib  # 3.11+
    except ModuleNotFoundError:  # 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    cfg = {"search.n": 3, "adaptive_compute.low_uncertainty": 0.25}
    p = write_overlay(cfg, tmp_path / "config.toml")
    parsed = tomllib.loads(p.read_text())
    assert parsed["search"]["n"] == 3
    assert parsed["adaptive_compute"]["enable"] is True


def test_unknown_knobs_ignored():
    assert env_for({"mystery": 1}) == {}
    assert overlay_for({"mystery": 1}) == {}


def test_env_for_clamps_out_of_bounds_safety_cap():
    # A loaded/hand-edited archive config with an out-of-bounds fan-out (never
    # produced by mutate's clamp) must NOT raise the kernel's fan-out safety cap
    # on a live run: env_for clamps it to the declared max (16).
    env = env_for({"max_swarm_fanout": 4096})
    assert env["MAVERICK_MAX_SWARM_FANOUT"] == "16"
    # low end clamps too, and a below-floor verifier confidence is lifted.
    assert env_for({"max_swarm_fanout": 0})["MAVERICK_MAX_SWARM_FANOUT"] == "1"
    assert env_for({"verifier_confidence": 2.0})["MAVERICK_VERIFIER_CONFIDENCE"] == "0.95"


def test_overlay_for_clamps_out_of_bounds():
    ov = overlay_for({"search.n": 999})
    assert ov["search"]["n"] == 5  # declared max


def test_extract_answer_strips_prompt_echo_and_budget():
    # The title line echoes the prompt verbatim; scoring the whole envelope let
    # a wrong answer whose reference appears in the prompt score 1.0.
    envelope = ("goal #4 created: Is the capital of France Paris or Lyon?\n\n"
                "DONE.\n\nThe capital of France is Lyon.\n\n[$0.02 spent]")
    answer = _extract_answer(envelope)
    assert answer == "The capital of France is Lyon."
    # "Paris" (a substring scorer's reference, echoed in the prompt) is gone,
    # so the wrong answer no longer scores as a match.
    assert "Paris" not in answer
    assert "goal #4 created" not in answer and "spent" not in answer


def test_extract_answer_exposes_failure_prefix_for_rehearsal_grader():
    # A blocked/errored run is wrapped in DONE too; extraction must surface the
    # "Stopped"/"ERROR" prefix so rehearsal_completed can grade it incomplete
    # (the raw envelope always starts with "goal #N created", hiding it).
    envelope = ("goal #9 created: reconcile ledger\n\n"
                "DONE.\n\nStopped: the assistant ran into an error.\n\n[$0.10 spent]")
    assert _extract_answer(envelope).startswith("Stopped")


def test_extract_answer_raises_without_done_marker():
    with pytest.raises(ValueError):
        _extract_answer("goal #1 created: hi\n\n(no result envelope)")


def test_subprocess_run_one_uses_overlay_without_replacing_operator_config(monkeypatch, tmp_path):
    seen = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        seen["env"] = kwargs["env"]
        seen["cwd"] = kwargs["cwd"]

        class Proc:
            # realistic CLI envelope: title line (echoes prompt) + DONE result.
            stdout = "goal #7 created: hello\n\nDONE.\n\nok\n\n[$0.01 spent]"
            returncode = 0

        return Proc()

    operator_config = tmp_path / "operator.toml"
    operator_config.write_text('[sandbox]\nbackend = "docker"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(operator_config))
    monkeypatch.setattr("maverick_evolve.agent_adapter.subprocess.run", fake_run)

    out = subprocess_run_one(
        "hello", {"search.n": 5, "max_swarm_fanout": 3}, workdir=str(tmp_path), python="py"
    )

    assert out == "ok"  # extracted from the envelope, not the whole stdout
    assert seen["args"] == ["py", "-m", "maverick.cli", "start", "hello"]
    assert seen["cwd"] == str(tmp_path)
    assert seen["env"]["MAVERICK_CONFIG"] == str(operator_config)
    assert seen["env"]["MAVERICK_CONFIG_OVERLAY"] != str(operator_config)
    assert seen["env"]["MAVERICK_MAX_SWARM_FANOUT"] == "3"


@pytest.mark.asyncio
async def test_full_wiring_with_fake_run_one(monkeypatch):
    """The end-to-end proof: a fake run_one that reads a config knob drives the
    real factory -> eval harness -> continuous-evolution loop, and it climbs.
    This is the same wiring the live subprocess runner uses."""
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)

    async def fake_run_one(prompt: str, config: dict) -> str:
        # The "agent" is better when the fanout knob is higher; the eval case's
        # threshold comes from the prompt (graded landscape).
        return "GOOD" if config.get("max_swarm_fanout", 0) >= int(prompt) else "BAD"

    cases = [EvalCase(prompt=str(t), check=lambda o: o == "GOOD")
             for t in (2, 4, 6, 8, 10, 12, 14)]
    space = {"max_swarm_fanout": ("int", 1, 16)}
    best, history = await evolve_live(
        {"max_swarm_fanout": 4}, cases,
        run_one=fake_run_one,
        rounds=3, generations_per_round=40, space=space, rng=random.Random(0),
    )
    assert best.config["max_swarm_fanout"] >= 12
    assert best.score >= 6 / 7 - 1e-9


@pytest.mark.asyncio
async def test_make_agent_factory_produces_runnable_agent():
    async def fake_run_one(prompt, config):
        return f"answer for {prompt} with n={config.get('n')}"

    factory = make_agent_factory(fake_run_one)
    agent = factory({"n": 7})
    out = await agent("hello")
    assert out == "answer for hello with n=7"


def test_cli_load_cases(tmp_path):
    import json

    from maverick_evolve.cli import _load_cases
    p = tmp_path / "cases.json"
    p.write_text(json.dumps([
        {"prompt": "capital of France?", "reference": "Paris"},
        {"prompt": "no-ref still loads"},
        {"not_a_prompt": 1},  # skipped
    ]))
    cases = _load_cases(str(p))
    assert len(cases) == 2
    assert cases[0].reference == "Paris"


def test_cli_live_requires_cases(capsys):
    from maverick_evolve.cli import main
    rc = main(["--live"])
    assert rc == 2
    assert "requires --cases" in capsys.readouterr().out
