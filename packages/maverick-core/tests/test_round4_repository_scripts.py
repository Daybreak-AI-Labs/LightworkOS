"""Regression checks for the local demo and legacy parser bootstrap."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


def _script(name):
    path = Path(__file__).resolve().parents[3] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_demo_requires_exact_loopback_host_for_all_requests(monkeypatch):
    import uvicorn

    captured = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: captured.append(app))
    _script("demo_vendor_onboarding").serve(None, SimpleNamespace(tenant="demo"), 8766)
    app = captured[0]

    @app.api_route("/boundary-probe", methods=["GET", "POST"])
    def probe():
        return {"local": True}

    with TestClient(app, base_url="http://127.0.0.1:8766") as client:
        for host in ("rebound.example:8766", "127.0.0.1:8767", "localhost:8766"):
            assert client.get("/boundary-probe", headers={"Host": host}).status_code == 403
        assert client.get("/boundary-probe", headers=[
            ("Host", "127.0.0.1:8766"), ("Host", "rebound.example:8766"),
        ]).status_code == 403
        assert client.get("/boundary-probe").status_code == 200
        assert client.post("/boundary-probe").status_code == 403
        assert client.post("/boundary-probe", headers={"Origin": "http://127.0.0.1:8766"}).status_code == 200


def test_tomli_bootstrap_requires_reviewed_hash_before_parsing(monkeypatch, tmp_path):
    module = _script("install_release_cohort")
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        if "install" not in command:
            raise subprocess.CalledProcessError(1, command)
        assert "--require-hashes" in command
        requirements = Path(command[command.index("--requirement") + 1]).read_text()
        assert "tomli==2.5.0" in requirements
        assert "--hash=sha256:32a7b79ac57a2e83670ce329ccf675798bc5a2094783a63676866b70503f2e2b" in requirements
        # A rejected download must never reach the fallback parser process.
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(module.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        module._parse_toml_with_python(tmp_path / "source.toml", sys.executable)
    assert len(commands) == 2
