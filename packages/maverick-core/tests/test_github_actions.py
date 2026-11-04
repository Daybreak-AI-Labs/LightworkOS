"""Tests for the GitHub Actions tool (maverick.tools.github_actions)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _fake_httpx(monkeypatch, **methods):
    """Install a dummy httpx module with the given methods (get/post/...) ."""
    mod = types.ModuleType("httpx")
    for name, value in methods.items():
        setattr(mod, name, value)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status: int, body: object):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = str(body)
    return r


# ---------- GitHub Actions ----------

def test_gha_requires_op():
    from maverick.tools.github_actions import github_actions
    assert "op is required" in github_actions().fn({})


def test_gha_missing_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.github_actions import github_actions
    out = github_actions().fn({"op": "runs", "owner": "o", "repo": "r"})
    assert "GITHUB_TOKEN" in out


def test_gha_runs_list(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    body = {"workflow_runs": [
        {"id": 111, "name": "CI", "status": "completed",
         "conclusion": "success", "head_branch": "main", "event": "push"},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.github_actions import github_actions
    out = github_actions().fn({"op": "runs", "owner": "o", "repo": "r"})
    assert "111" in out and "success" in out


def test_gha_dispatch_dry_run(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.github_actions import github_actions
    out = github_actions().fn({
        "op": "dispatch", "owner": "o", "repo": "r",
        "workflow": "ci.yml", "ref": "main",
    })
    assert "DRY RUN" in out


def test_gha_cancel_confirmed(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock(return_value=_resp(202, {})))
    from maverick.tools.github_actions import github_actions
    out = github_actions().fn({
        "op": "cancel", "owner": "o", "repo": "r", "run_id": 42,
        "confirm": True,
    })
    assert "cancelled run 42" in out
