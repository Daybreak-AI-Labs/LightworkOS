"""Agent fleets: the per-employee roster model + CLI (Layer C)."""
from __future__ import annotations

import pytest
from click.testing import CliRunner


def test_valid_name():
    from maverick.fleet import valid_name
    assert valid_name("acme") and valid_name("acme_ops-1")
    assert not valid_name("../evil")
    assert not valid_name("a/b")
    assert not valid_name("")


def test_save_load_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.fleet import Fleet, FleetAgent, load_fleet, save_fleet
    fl = Fleet(name="acme", owner="user:alice", agents=(
        FleetAgent("researcher", "analyst", "does research"),
        FleetAgent("coder", "engineer"),
    ))
    save_fleet(fl)
    got = load_fleet("acme")
    assert got is not None
    assert got.owner == "user:alice"
    assert [a.name for a in got.agents] == ["researcher", "coder"]
    assert got.agents[0].role == "analyst"
    assert got.principal_for("coder") == "agent:acme.coder"


def test_saved_file_is_0600(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.file_lock import private_path_is_restricted
    from maverick.fleet import Fleet, save_fleet
    path = save_fleet(Fleet(name="f1", owner="user:x"))
    assert private_path_is_restricted(path, 0o600)


def test_save_rejects_bad_name(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.fleet import Fleet, save_fleet
    with pytest.raises(ValueError):
        save_fleet(Fleet(name="../evil", owner="x"))


def test_list_and_remove(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.fleet import Fleet, list_fleets, remove_fleet, save_fleet
    save_fleet(Fleet(name="a", owner="x"))
    save_fleet(Fleet(name="b", owner="y"))
    assert {f.name for f in list_fleets()} == {"a", "b"}
    assert remove_fleet("a") is True
    assert {f.name for f in list_fleets()} == {"b"}
    assert remove_fleet("missing") is False


def test_load_rejects_malformed_fleet_json(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.fleet import fleets_dir, list_fleets, load_fleet

    d = fleets_dir()
    d.mkdir(parents=True)
    (d / "bad_agent.json").write_text(
        '{"name":"bad_agent","owner":"x","agents":["notdict"]}',
        encoding="utf-8",
    )
    (d / "bad_created.json").write_text(
        '{"name":"bad_created","owner":"x","created_at":"nope"}',
        encoding="utf-8",
    )
    (d / "bad_agents.json").write_text(
        '{"name":"bad_agents","owner":"x","agents":{"not":"list"}}',
        encoding="utf-8",
    )

    assert load_fleet("bad_agent") is None
    assert load_fleet("bad_created") is None
    assert load_fleet("bad_agents") is None
    assert list_fleets() == []

def test_cli_create_list_show_rm(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    # `fleet create` validates roles against config (undefined roles are
    # rejected), so the roles this fleet declares must be configured.
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {
        "roles": {"analyst": {"allow_tools": ["read_file"]},
                  "engineer": {"allow_tools": ["read_file", "write_file"]}},
    })
    from maverick.cli import main
    r = CliRunner()
    c = r.invoke(main, ["fleet", "create", "acme", "--owner", "user:alice",
                        "--agent", "researcher:analyst", "--agent", "coder:engineer"])
    assert c.exit_code == 0, c.output
    assert "2 agent" in c.output

    lst = r.invoke(main, ["fleet", "list"])
    assert "acme" in lst.output and "user:alice" in lst.output

    show = r.invoke(main, ["fleet", "show", "acme"])
    assert "researcher" in show.output and "analyst" in show.output
    assert "agent:acme.coder" in show.output

    assert r.invoke(main, ["fleet", "rm", "acme"]).exit_code == 0
    assert "no fleets" in r.invoke(main, ["fleet", "list"]).output


def test_cli_create_rejects_bad_agent(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.cli import main
    res = CliRunner().invoke(main, ["fleet", "create", "f", "--owner", "x",
                                    "--agent", "noRole"])
    assert res.exit_code == 2
    assert "NAME:ROLE" in res.output


def test_cli_show_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.cli import main
    assert CliRunner().invoke(main, ["fleet", "show", "ghost"]).exit_code == 1


def test_remove_fleet_deletes_run_index(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.fleet import Fleet, load_runs, record_run, remove_fleet, runs_path, save_fleet

    save_fleet(Fleet(name="a", owner="x"))
    record_run("a", "agent", 123)
    assert runs_path("a").exists()

    assert remove_fleet("a") is True
    assert not runs_path("a").exists()
    assert load_runs("a") == []


def test_record_run_is_atomic_under_concurrency(monkeypatch, tmp_path):
    """Concurrent runs of the same fleet must not lose run-log entries to a
    read-modify-write race."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    import threading

    from maverick.fleet import load_runs, record_run

    n = 50
    barrier = threading.Barrier(n)

    def _rec(i):
        barrier.wait()  # maximize overlap on the read-modify-write
        record_run("acme", f"agent{i}", i)

    threads = [threading.Thread(target=_rec, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    runs = load_runs("acme")
    assert len(runs) == n, f"lost entries: {len(runs)} of {n}"
    assert {r["goal_id"] for r in runs} == set(range(n))
