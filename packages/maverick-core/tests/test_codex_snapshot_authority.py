"""Snapshot admission uses synthetic files only; never launch a Codex process."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from maverick.providers import codex_cli_provider as codex


@pytest.mark.skipif(os.name != "nt", reason="native Windows executable lookup")
def test_captured_pathext_and_path_select_binary_without_live_environment(monkeypatch, tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    later = tmp_path / "later"
    later.mkdir()
    for directory in (original, later):
        for suffix in (".exe", ".cmd"):
            (directory / f"fixture{suffix}").write_text("never executed", encoding="utf-8")
    environment = {
        "PATH": str(original), "PATHEXT": ".EXE", "CODEX_HOME": str(tmp_path / "auth"),
    }
    monkeypatch.setenv("PATH", str(later))
    monkeypatch.setenv("PATHEXT", ".CMD")
    before = dict(os.environ)
    client = codex.CodexCLIClient(
        api_key="fixture", environment=environment, provider_options={"binary": "fixture"},  # pragma: allowlist secret - synthetic CLI snapshot fixture
    )
    assert Path(client._binary_path) == original / "fixture.exe"
    assert dict(os.environ) == before
    assert environment["PATHEXT"] == ".EXE"


@pytest.mark.skipif(os.name != "nt", reason="native Windows executable lookup")
def test_snapshot_does_not_implicitly_search_current_directory(monkeypatch, tmp_path):
    (tmp_path / "fixture.exe").write_text("never executed", encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(tmp_path)
    assert codex._snapshot_binary("fixture", {"PATH": str(other), "PATHEXT": ".EXE"}) is None
    assert codex._snapshot_binary("fixture", {"PATH": "", "PATHEXT": ".EXE"}) is None
    assert codex._snapshot_binary("fixture", {"PATHEXT": ".EXE"}) is None
    assert Path(codex._snapshot_binary("fixture", {"PATH": ".", "PATHEXT": ".EXE"})) == tmp_path / "fixture.exe"


@pytest.mark.skipif(os.name != "nt", reason="native Windows executable lookup")
def test_snapshot_pathext_order_and_explicit_path_are_preserved(monkeypatch, tmp_path):
    for suffix in (".exe", ".cmd"):
        (tmp_path / f"fixture{suffix}").write_text("never executed", encoding="utf-8")
    monkeypatch.setenv("PATHEXT", ".EXE")
    environment = {"PATH": str(tmp_path), "PATHEXT": ".CMD;.EXE"}
    assert Path(codex._snapshot_binary("fixture", environment)).suffix.lower() == ".cmd"
    assert Path(codex._snapshot_binary(str(tmp_path / "fixture.exe"), environment)).suffix.lower() == ".exe"


@pytest.mark.parametrize("environment", [{}, {"HOME": ""}, {"USERPROFILE": ""}, {"CODEX_HOME": "  "}])
def test_explicit_unresolved_home_refuses_before_binary_or_auth_discovery(monkeypatch, environment):
    monkeypatch.setattr(Path, "home", lambda: pytest.fail("live home discovery"))
    monkeypatch.setattr(codex, "_snapshot_binary", lambda *_: pytest.fail("binary lookup before refusal"))
    monkeypatch.setattr(codex, "_auth_file_present", lambda *_: pytest.fail("auth lookup before refusal"))
    with pytest.raises(RuntimeError, match="captured home directory"):
        codex.CodexCLIClient(api_key="fixture", environment=environment, provider_options={})  # pragma: allowlist secret - repeated synthetic fixture


def test_captured_home_is_pinned_for_auth_admission_and_child_environment(monkeypatch, tmp_path):
    first = tmp_path / "first"
    auth = first / ".codex"
    auth.mkdir(parents=True)
    (auth / "auth.json").write_text("{}", encoding="utf-8")
    home_key = "USERPROFILE" if os.name == "nt" else "HOME"
    environment = {home_key: str(first), "PATH": "", "OPENAI_API_KEY": "not-for-child"}
    monkeypatch.setenv(home_key, str(tmp_path / "later"))
    monkeypatch.setattr(Path, "home", lambda: pytest.fail("live home discovery"))
    client = codex.CodexCLIClient(environment=environment, provider_options={"binary": sys.executable})
    monkeypatch.chdir(tmp_path)
    assert codex.codex_home(client._environment) == auth
    assert client._subprocess_env()["CODEX_HOME"] == str(auth)
    assert "OPENAI_API_KEY" not in client._subprocess_env()
    assert "USERPROFILE" not in client._subprocess_env()
    assert "CODEX_HOME" not in environment


def test_relative_codex_home_is_pinned_before_execution_directory_changes(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    client = codex.CodexCLIClient(
        api_key="fixture", environment={"CODEX_HOME": "relative-auth"},  # pragma: allowlist secret - repeated synthetic fixture
        provider_options={"binary": sys.executable},
    )
    later = tmp_path / "later"
    later.mkdir()
    monkeypatch.chdir(later)
    assert client._subprocess_env()["CODEX_HOME"] == str(tmp_path / "relative-auth")


def test_legacy_direct_constructor_discovers_and_pins_home_once(monkeypatch, tmp_path):
    for name in ("CODEX_HOME", "HOME", "USERPROFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(codex.shutil, "which", lambda _: sys.executable)
    client = codex.CodexCLIClient(api_key="fixture", provider_options={})  # pragma: allowlist secret - repeated synthetic fixture
    monkeypatch.setattr(Path, "home", lambda: pytest.fail("home reread after admission"))
    assert client._subprocess_env()["CODEX_HOME"] == str(tmp_path / ".codex")


@pytest.mark.asyncio
async def test_login_receives_same_pinned_home_without_forwarding_access_token(monkeypatch, tmp_path):
    home_key = "USERPROFILE" if os.name == "nt" else "HOME"
    client = codex.CodexCLIClient(
        api_key="synthetic-no-dispatch-token", environment={home_key: str(tmp_path)},
        provider_options={"binary": sys.executable},
    )
    calls = []

    async def record(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(codex, "run_owned", record)
    monkeypatch.setenv(home_key, str(tmp_path / "later"))
    await client._ensure_login(time.monotonic() + 10, lambda: None)
    assert len(calls) == 1
    assert calls[0][1]["env"]["CODEX_HOME"] == str(tmp_path / ".codex")
    assert "CODEX_ACCESS_TOKEN" not in calls[0][1]["env"]
    assert "synthetic-no-dispatch-token" not in str(calls[0][0])
    assert calls[0][1]["input"] == "synthetic-no-dispatch-token"
