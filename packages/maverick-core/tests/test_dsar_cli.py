"""`maverick dsar export` -- print a subject-data bundle as JSON.

The exporter (`maverick.dsar.export_subject_data`) is already tested in
`test_dsar.py`; these cover the thin CLI wrapper: it serializes the bundle for a
seeded subject, emits valid JSON whose ``counts``/``world`` reflect the seeded
data, exits 0, and honors ``--output`` (write to file) and ``--json`` (compact).

Hermetic + HOME-isolated: the autouse ``_isolate_maverick_home`` conftest
fixture points ``Path.home()`` at a per-test tmp dir, so the world DB the
exporter opens via ``world_for_tenant`` lives under the test's sandbox.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.paths import data_dir
from maverick.world_model import WorldModel


@pytest.fixture(autouse=True)
def _clear_world_cache():
    """Close cached tenant world handles between CLI tests."""
    import maverick.world_model as wm

    def _drain():
        for world in list(wm._tenant_worlds.values()):
            try:
                world.close()
            except Exception:
                pass
        wm._tenant_worlds.clear()

    _drain()
    yield
    _drain()


def _world_db() -> Path:
    """The default (no-tenant) world DB path the exporter will open."""
    return Path.home() / ".maverick" / "world.db"


def _seed_world() -> None:
    """Seed alice's conversation + turns + goal (mirrors test_dsar.py)."""
    wm = WorldModel(_world_db())
    conv = wm.get_or_create_conversation("telegram", "alice")
    gid = wm.create_goal("alice's goal", "do the alice thing")
    wm.set_goal_status(gid, "active")
    ep = wm.start_episode(gid)
    wm.end_episode(ep, summary="done", outcome="succeeded", cost_dollars=0.01)
    wm.append_turn(conv.id, "user", "alice secret message", goal_id=gid)
    wm.append_turn(conv.id, "assistant", "alice reply", goal_id=gid)
    wm.close()


def test_dsar_export_prints_seeded_bundle_and_exits_zero():
    _seed_world()
    result = CliRunner().invoke(main, ["dsar", "export", "--user", "alice"])
    assert result.exit_code == 0
    bundle = json.loads(result.output)

    # Envelope reflects the requested subject. The subject was seeded on a
    # single channel, so the exporter infers it (channel is part of subject
    # identity; an unambiguous id resolves to its one channel).
    assert bundle["subject"] == {"user_id": "alice", "channel": "telegram"}
    assert bundle["tenant"] is None

    # Counts/world reflect the seeded data.
    assert bundle["counts"]["conversations"] == 1
    assert bundle["counts"]["turns"] == 2
    assert bundle["counts"]["goals"] == 1
    assert bundle["counts"]["episodes"] == 1

    convs = bundle["world"]["conversations"]
    assert len(convs) == 1
    assert convs[0]["user_id"] == "alice"
    contents = [t["content"] for t in convs[0]["turns"]]
    assert "alice secret message" in contents
    assert "alice reply" in contents

    goals = bundle["world"]["goals"]
    assert len(goals) == 1
    assert goals[0]["title"] == "alice's goal"
    assert goals[0]["episodes"][0]["outcome"] == "succeeded"


def _seed_world_at(path: Path, message: str) -> None:
    """Seed alice's single-turn conversation in the given world DB."""
    wm = WorldModel(path)
    conv = wm.get_or_create_conversation("telegram", "alice")
    wm.append_turn(conv.id, "user", message)
    wm.close()


def test_dsar_export_without_tenant_uses_active_tenant_not_shared(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    _seed_world_at(_world_db(), "shared secret must not leak")
    _seed_world_at(data_dir("world.db"), "active tenant message")

    result = CliRunner().invoke(main, ["dsar", "export", "--user", "alice"])
    assert result.exit_code == 0
    bundle = json.loads(result.output)

    contents = [
        turn["content"]
        for conversation in bundle["world"]["conversations"]
        for turn in conversation["turns"]
    ]
    assert "active tenant message" in contents
    assert "shared secret must not leak" not in contents


def test_dsar_export_unknown_user_is_empty_and_exits_zero():
    _seed_world()
    result = CliRunner().invoke(main, ["dsar", "export", "--user", "nobody"])
    assert result.exit_code == 0
    bundle = json.loads(result.output)
    assert bundle["world"] == {"conversations": [], "goals": [], "facts": {}, "fact_history": {}}
    assert bundle["counts"]["conversations"] == 0


def test_dsar_export_refuses_unreadable_store_without_creating_artifact(
    monkeypatch, tmp_path,
):
    def unavailable(*_args, **_kwargs):
        raise OSError("private world path should not be shown")

    monkeypatch.setattr("maverick.world_model.world_for_tenant", unavailable)
    output = tmp_path / "incomplete-export.json"
    result = CliRunner().invoke(
        main, ["dsar", "export", "--user", "alice", "--output", str(output)]
    )

    assert result.exit_code != 0
    assert not output.exists()
    assert "private world path" not in result.output


def test_dsar_export_output_writes_file(tmp_path):
    _seed_world()
    out = tmp_path / "alice_dsar.json"
    result = CliRunner().invoke(
        main, ["dsar", "export", "--user", "alice", "--output", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["subject"]["user_id"] == "alice"
    assert bundle["counts"]["turns"] == 2
    # Stdout only confirms the write; the bundle went to the file.
    assert f"exported to {out}" in result.output


def test_dsar_export_default_is_pretty_printed():
    _seed_world()
    result = CliRunner().invoke(main, ["dsar", "export", "--user", "alice"])
    assert result.exit_code == 0
    # indent=2 output spans multiple lines and indents nested keys.
    assert "\n  " in result.output


def test_dsar_export_json_flag_is_compact_single_line():
    _seed_world()
    result = CliRunner().invoke(main, ["dsar", "export", "--user", "alice", "--json"])
    assert result.exit_code == 0
    bundle = json.loads(result.output)
    assert bundle["subject"]["user_id"] == "alice"
    # Compact form: a single JSON line (click.echo adds one trailing newline).
    assert result.output.strip().count("\n") == 0


def test_dsar_export_unknown_tenant_fails_without_creating_it():
    from maverick.paths import tenant_namespace_reserved

    _seed_world_at(data_dir("world.db", tenant="acme"), "acme message")
    known = CliRunner().invoke(main, ["dsar", "export", "--user", "alice", "--tenant", "acme"])
    assert known.exit_code == 0, known.output

    typo = CliRunner().invoke(main, ["dsar", "export", "--user", "alice", "--tenant", "acmee"])
    assert typo.exit_code != 0
    assert "no such tenant" in typo.output
    assert not tenant_namespace_reserved("acmee")


def test_dsar_export_output_is_private_even_over_an_existing_file(tmp_path):
    _seed_world()
    output = tmp_path / "export.json"
    output.write_text("old", encoding="utf-8")
    output.chmod(0o644)
    result = CliRunner().invoke(
        main, ["dsar", "export", "--user", "alice", "--output", str(output)])
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text(encoding="utf-8"))["subject"]["user_id"] == "alice"
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_dsar_export_output_through_a_symlinked_parent_but_not_a_symlinked_file(tmp_path):
    _seed_world()
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real, target_is_directory=True)
    result = CliRunner().invoke(
        main, ["dsar", "export", "--user", "alice", "--output", str(tmp_path / "link" / "out.json")])
    assert result.exit_code == 0, result.output
    assert (real / "out.json").stat().st_mode & 0o777 == 0o600

    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    (real / "trap.json").symlink_to(victim)
    result = CliRunner().invoke(
        main, ["dsar", "export", "--user", "alice", "--output", str(real / "trap.json")])
    assert result.exit_code != 0
    assert "symlink" in result.output
    assert victim.read_text(encoding="utf-8") == "keep"
    assert (real / "trap.json").is_symlink()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_dsar_export_writes_into_a_fifo_the_caller_owns_but_not_through_a_link(tmp_path):
    import threading

    _seed_world()
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    received = []
    reader = threading.Thread(target=lambda: received.append(fifo.read_text(encoding="utf-8")))
    reader.start()
    result = CliRunner().invoke(
        main, ["dsar", "export", "--user", "alice", "--json", "--output", str(fifo)])
    reader.join(timeout=30)
    assert result.exit_code == 0, result.output
    assert json.loads(received[0])["subject"]["user_id"] == "alice"
    assert "exported to" not in result.stdout   # the note went to stderr

    (tmp_path / "pipe-link").symlink_to(fifo)
    linked = CliRunner().invoke(
        main, ["dsar", "export", "--user", "alice", "--output", str(tmp_path / "pipe-link")])
    assert linked.exit_code != 0


def test_dsar_export_output_to_dev_stdout_writes_the_stream():
    _seed_world()
    result = CliRunner().invoke(
        main, ["dsar", "export", "--user", "alice", "--json", "--output", "/dev/stdout"])
    assert result.exit_code == 0, result.output
    # The "exported to" note goes to stderr, so stdout is exactly the bundle.
    assert json.loads(result.stdout)["subject"]["user_id"] == "alice"
