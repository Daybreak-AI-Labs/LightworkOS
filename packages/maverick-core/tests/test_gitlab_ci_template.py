"""Structure test for the reusable GitLab CI template.

The template is a CI wrapper around `maverick start`. These assertions pin
the safety defaults: non-interactive consent, a hard budget cap, and a
sandbox scoped to the checkout. Uses PyYAML when available, otherwise falls
back to string assertions.
"""

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_TEMPLATE = _REPO_ROOT / "deploy" / "gitlab-ci" / "maverick.gitlab-ci.yml"
_README = _REPO_ROOT / "deploy" / "gitlab-ci" / "README.md"


def test_template_files_exist():
    assert _TEMPLATE.is_file()
    assert _README.is_file()


def test_template_parses_and_defines_the_job():
    text = _TEMPLATE.read_text(encoding="utf-8")
    try:
        import yaml  # noqa: PLC0415
    except ModuleNotFoundError:
        # No PyYAML: validate structure via string assertions.
        assert ".maverick:" in text
        assert "script:" in text
        return

    data = yaml.safe_load(text)
    assert isinstance(data, dict)
    assert ".maverick" in data, "the reusable .maverick job must be defined"
    job = data[".maverick"]
    assert "script" in job and job["script"], "the job must run a script"


def test_safety_defaults_present():
    text = _TEMPLATE.read_text(encoding="utf-8")

    # Non-interactive consent.
    assert "MAVERICK_CONSENT_MODE: \"auto-deny\"" in text

    # Hard budget cap wired into config/env.
    assert "MAVERICK_MAX_DOLLARS" in text
    assert "max_dollars = ${MAVERICK_MAX_DOLLARS}" in text

    # Default local sandbox scoped to the checkout.
    assert "workdir = \"${CI_PROJECT_DIR}\"" in text

    # It installs maverick-agent and runs a goal.
    assert "maverick-agent" in text
    assert "MAVERICK_GOAL" in text
    assert "start" in text


def test_readme_documents_required_variables():
    text = _README.read_text(encoding="utf-8")
    assert "include:" in text
    assert "ANTHROPIC_API_KEY" in text
    assert "MAVERICK_GOAL" in text
    assert "MAVERICK_MAX_DOLLARS" in text
