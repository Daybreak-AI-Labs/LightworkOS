"""Setup refuses unusable or unsafe answers before publishing them."""
import io
import json
from pathlib import Path

import pytest
from maverick_installer import wizard
from maverick_installer.wizard import advanced
from rich.console import Console


@pytest.fixture
def prompts(monkeypatch):
    console = Console(file=io.StringIO(), width=160)
    monkeypatch.setattr(wizard, "console", console)
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **kw: True)
    return console.file


@pytest.mark.parametrize("location", ["flows", "advanced"])
def test_approval_url_reasks_plain_http_and_accepts_exact_loopback(monkeypatch, prompts, location):
    urls = iter(["http://ops.example", "http://localhost.evil.example", "http://127.0.0.1:8000"])
    monkeypatch.setattr(wizard, "_q_text", lambda prompt, **kw: next(urls) if "base URL" in prompt else kw.get("default", ""))
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **kw: prompt.startswith("Enable the flow engine"))
    if location == "flows":
        result = wizard.pick_flows()["public_url"]
    else:
        result = {"flows": True}
        advanced._ask_flow_followups(result)
        result = result["flows_public_url"]
    assert result == "http://127.0.0.1:8000"
    assert next(urls, None) is None


def test_handoff_requests_the_existing_webhook_signing_secret(monkeypatch, prompts):
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: "https://handoff.example/receive")
    config, needed = wizard.pick_deliverable_handoff()
    assert config == {"handoff_webhook": "https://handoff.example/receive"}
    assert needed == ["MAVERICK_WEBHOOK_SECRET"]


def test_rate_limits_reask_invalid_specs_without_dropping_the_cap(monkeypatch, prompts):
    answers = iter(["typo", "0/60", "3/60", "", "", ""])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    assert wizard.pick_rate_limits({}) == {"web_search": "3/60"}
    assert next(answers, None) is None


def test_preflight_reports_unexecutable_docker_as_a_warning(monkeypatch, tmp_path, prompts):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard.shutil, "which", lambda name: "/not-executable/docker")
    def fail(*a, **kw):
        raise PermissionError("Cannot execute docker")
    monkeypatch.setattr(wizard.subprocess, "run", fail)
    assert wizard.preflight()
    assert "Docker isn't running" in prompts.getvalue()


def test_scim_mapping_reasks_unknown_roles_and_malformed_lines(monkeypatch, prompts):
    answers = iter(["broken line", "Finance = administratr", "Finance = viewer", ""])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    assert advanced._collect_group_pairs("Groups", csv_value=False) == {"Finance": "viewer"}
    assert next(answers, None) is None
    assert "=" in prompts.getvalue() and "role" in prompts.getvalue()


def test_answer_path_write_failure_reasks_only_the_workspace(monkeypatch, tmp_path, prompts):
    partial = tmp_path / "wizard-partial.json"
    work = tmp_path / "bad-work"
    state = {"providers": ["anthropic"], "sandbox": {"backend": "docker", "workdir": str(work)}}
    partial.write_text(json.dumps(state))
    monkeypatch.setattr(wizard, "PARTIAL_STATE_PATH", partial)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: str(tmp_path / "good-work"))
    assert wizard._advanced_write_failed(PermissionError(13, "denied", str(work / "probe"))) == 1
    saved = json.loads(partial.read_text())
    assert saved["providers"] == state["providers"]
    assert saved["sandbox"] == {"backend": "docker", "workdir": str(tmp_path / "good-work")}
    assert "Workspace directory" in prompts.getvalue()
    assert not Path(saved["sandbox"]["workdir"]).exists()


@pytest.mark.parametrize("failed_name", ["", "config.toml.lock", ".config.toml-publication.tmp"])
def test_config_publication_failure_preserves_a_containing_workspace(monkeypatch, tmp_path, prompts, failed_name):
    work = tmp_path / "work"
    config_dir = work / ".maverick"
    config_dir.mkdir(parents=True)
    partial = config_dir / "wizard-partial.json"
    state = {"providers": ["anthropic"], "sandbox": {"backend": "docker", "workdir": str(work)}}
    partial.write_text(json.dumps(state))
    monkeypatch.setattr(wizard, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(wizard, "CONFIG_FILE", config_dir / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", config_dir / ".env")
    monkeypatch.setattr(wizard, "PARTIAL_STATE_PATH", partial)
    asked = []
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: asked.append(a[0]) or str(tmp_path / "other"))
    assert wizard._advanced_write_failed(PermissionError(13, "denied", str(config_dir / failed_name))) == 1
    assert asked == []
    assert json.loads(partial.read_text()) == state

    # A dedicated work folder inside the configuration directory is still an
    # answer-owned path, rather than a configuration publication location.
    state["sandbox"]["workdir"] = str(config_dir / "work")
    partial.write_text(json.dumps(state))
    assert wizard._advanced_write_failed(PermissionError(13, "denied", str(config_dir / "work" / "probe"))) == 1
    assert asked == ["Workspace directory"]
    assert json.loads(partial.read_text())["sandbox"]["workdir"] == str(tmp_path / "other")
