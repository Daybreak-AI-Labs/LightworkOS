"""`maverick onboard` must be automatable.

Unconditional prompts for the business description and industry would make
even `onboard --name X --no-llm --yes` abort on non-interactive stdin, so
CI/scripted onboarding would be impossible. Prompts fire only on a TTY;
--description/--industry supply the values otherwise, and a missing --name
errors cleanly instead of hanging.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)


def test_onboard_completes_non_interactively_with_flags():
    res = CliRunner().invoke(main, [
        "onboard", "--name", "Acme Corp", "--description", "We sell widgets",
        "--industry", "retail", "--no-llm", "--yes",
    ])
    assert res.exit_code == 0, res.output
    assert "Activated" in res.output


def test_onboard_non_interactive_requires_name():
    res = CliRunner().invoke(main, ["onboard", "--no-llm", "--yes"])
    assert res.exit_code == 2, res.output
    assert "name is required" in res.output
