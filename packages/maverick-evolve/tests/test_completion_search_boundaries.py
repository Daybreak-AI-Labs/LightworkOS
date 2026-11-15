from __future__ import annotations

import random
from types import SimpleNamespace

from maverick_evolve.agent_adapter import env_for, subprocess_run_one
from maverick_evolve.config_space import SPACE, default_config, mutate


def test_leading_dash_prompt_is_a_literal_cli_argument(monkeypatch):
    seen = []

    def run(args, **kwargs):
        seen.append(args)
        return SimpleNamespace(returncode=0, stdout="DONE.\n\nanswer", stderr="")

    monkeypatch.setattr("maverick_evolve.agent_adapter.subprocess.run", run)
    assert subprocess_run_one("--help", {}, python="py") == "answer"
    assert seen == [["py", "-m", "maverick.cli", "start", "--", "--help"]]


def test_completion_search_keeps_explicit_verifier_threshold_fixed():
    assert "verifier_confidence" not in SPACE
    assert "verifier_confidence" not in default_config()
    config = {**default_config(), "verifier_confidence": 0.8}
    rng = random.Random(7)
    for _ in range(100):
        config = mutate(config, rng)
        assert config["verifier_confidence"] == 0.8
    assert env_for(config)["MAVERICK_VERIFIER_CONFIDENCE"] == "0.8"
    assert env_for({"verifier_confidence": 2})["MAVERICK_VERIFIER_CONFIDENCE"] == "0.95"
