"""`maverick runs` / `maverick runs --json` — the contract the VS Code
extension's runs view consumes. Keep field names stable."""
import json

from click.testing import CliRunner
from maverick import cli as cli_mod
from maverick.world_model import WorldModel

# WorldModel takes a Path; the CLI's --db takes a string (main() wraps it
# in Path itself). Seed via Path, invoke via str.

# Fields the extension relies on; assert the JSON shape stays stable.
_EXPECTED_KEYS = {
    "episode_id", "goal_id", "goal_title", "goal_status", "outcome",
    "running", "started_at", "ended_at", "duration_s", "cost_dollars",
    "input_tokens", "output_tokens", "tool_calls",
}


def _seed(db_path):
    wm = WorldModel(db_path)
    gid = wm.create_goal("ship the runs view")
    # one finished run + one still-live run on the same goal
    ep1 = wm.start_episode(gid)
    wm.end_episode(ep1, summary="done", outcome="completed",
                   cost_dollars=0.1234, input_tokens=100, output_tokens=50,
                   tool_calls=3)
    wm.start_episode(gid)  # live (ended_at is NULL)
    wm.close()
    return gid


def test_runs_json_shape_and_running_flag(tmp_path):
    db = tmp_path / "wm.db"
    gid = _seed(db)
    res = CliRunner().invoke(cli_mod.main, ["--db", str(db), "runs", "--json"])
    assert res.exit_code == 0, res.output
    rows = json.loads(res.output)
    assert len(rows) == 2
    for r in rows:
        assert set(r) == _EXPECTED_KEYS
        assert r["goal_id"] == gid
        assert r["goal_title"] == "ship the runs view"
    live = [r for r in rows if r["running"]]
    done = [r for r in rows if not r["running"]]
    assert len(live) == 1 and len(done) == 1
    assert live[0]["ended_at"] is None and live[0]["duration_s"] is None
    assert done[0]["outcome"] == "completed"
    assert done[0]["cost_dollars"] == 0.1234
    assert done[0]["duration_s"] is not None


def test_runs_empty_json_is_array(tmp_path):
    db = tmp_path / "empty.db"
    WorldModel(db).close()
    res = CliRunner().invoke(cli_mod.main, ["--db", str(db), "runs", "--json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output) == []


def test_runs_human_output(tmp_path):
    db = tmp_path / "wm.db"
    _seed(db)
    res = CliRunner().invoke(cli_mod.main, ["--db", str(db), "runs"])
    assert res.exit_code == 0, res.output
    assert "Recent runs" in res.output
    assert "running" in res.output  # the live episode


def test_runs_human_output_strips_terminal_controls(tmp_path):
    db = tmp_path / "wm.db"
    wm = WorldModel(db)
    gid = wm.create_goal("\x1b]0;PWNED\x07safe [link](https://attacker.invalid)\x1b[31m")
    ep = wm.start_episode(gid)
    wm.end_episode(ep, summary="done", outcome="completed")
    wm.close()

    json_res = CliRunner().invoke(cli_mod.main, ["--db", str(db), "runs", "--json"])
    assert json_res.exit_code == 0, json_res.output
    assert json.loads(json_res.output)[0]["goal_title"].startswith("\x1b]0;PWNED")

    res = CliRunner().invoke(cli_mod.main, ["--db", str(db), "runs"])
    assert res.exit_code == 0, res.output
    assert "\x1b" not in res.output
    assert "\x07" not in res.output
    assert "safe [link](https://attacker.invalid)" in res.output
