"""Share a run as a sanitized private gist (`maverick share`)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_build_gist_payload_is_private_and_named(monkeypatch):
    from maverick import run_share
    from maverick.replay import export as replay_export

    def _fake_export(goal_id, out_path):
        Path(out_path).write_text(
            json.dumps({"goal": goal_id, "events": []}), encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(replay_export, "export_json", _fake_export)
    payload = run_share.build_gist_payload(7)
    assert payload["public"] is False                       # secret gist
    assert "maverick-run-7.json" in payload["files"]
    assert '"goal": 7' in payload["files"]["maverick-run-7.json"]["content"]


def test_share_run_posts_private_gist_and_returns_url(monkeypatch):
    import httpx
    from maverick import run_share

    monkeypatch.setattr(run_share, "build_gist_payload", lambda gid: {"files": {}})
    seen = {}

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"html_url": "https://gist.github.com/u/abc123"}

    def _fake_post(url, **kw):
        seen.update(url=url, headers=kw.get("headers", {}), json=kw.get("json"))
        return _Resp()

    monkeypatch.setattr(httpx, "post", _fake_post)
    url = run_share.share_run(7, token="ghp_secrettoken")
    assert url == "https://gist.github.com/u/abc123"
    assert seen["url"] == "https://api.github.com/gists"
    assert seen["headers"]["Authorization"] == "Bearer ghp_secrettoken"


def test_share_run_requires_a_token(monkeypatch):
    from maverick import run_share
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="GitHub sharing is not connected"):
        run_share.share_run(7)


def test_share_cli_refuses_another_world_and_a_missing_run(monkeypatch, tmp_path):
    # The run log behind `share` belongs to the workspace's own world. A run
    # from `--db other.db` has goal ids that also exist there, so sharing it
    # could mix two runs; a run absent from that world is refused too.
    from click.testing import CliRunner
    from maverick import run_share
    from maverick.cli import main
    from maverick.workspace import Workspace

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    uploaded = []
    monkeypatch.setattr(run_share, "share_run", lambda goal_id: uploaded.append(goal_id) or "url")
    other = CliRunner().invoke(main, ["--db", str(tmp_path / "other.db"), "share", "1"])
    assert other.exit_code == 1 and "--db" in other.output
    missing = CliRunner().invoke(main, ["share", "99"])
    assert missing.exit_code == 1 and "#99" in missing.output
    from maverick.world_model import WorldModel

    world = WorldModel(path=Workspace.current().db_path)
    goal_id = world.create_goal("shared run", "")
    world.close()
    shared = CliRunner().invoke(main, ["--db", str(Workspace.current().db_path), "share", str(goal_id)])
    assert shared.exit_code == 0, shared.output
    assert uploaded == [goal_id]
