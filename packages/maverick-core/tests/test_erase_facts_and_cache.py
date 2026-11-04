"""`maverick erase` must also wipe facts derived from the user's episodes
and the (content-addressed) LLM cache -- GDPR Art. 17 gaps found in the
red-team audit.

The facts gap was a double bug: facts.source_episode_id has an FK to
episodes(id), so with foreign_keys=ON + deferred checks, erasing a user who
had ANY distilled fact failed the COMMIT and aborted the whole erase.
"""
import os

import pytest
from click.testing import CliRunner
from maverick import cli as cli_mod
from maverick.world_model import WorldModel


def _seed_user_with_fact(db):
    wm = WorldModel(db)
    conv_id = wm.get_or_create_conversation("telegram", "u123").id
    gid = wm.create_goal("look up my address")
    wm.append_turn(conv_id, "user", "I live at 1 Privacy Lane", goal_id=gid)
    ep = wm.start_episode(gid)
    # A fact distilled from the user's run -- carries PII + an FK to the episode.
    wm.upsert_fact("home_address", "1 Privacy Lane", episode_id=ep)
    wm.close()
    return gid


def test_erase_succeeds_and_removes_facts(tmp_path, monkeypatch):
    os.environ.pop("MAVERICK_DB", None)
    import maverick.audit as audit_mod
    monkeypatch.setattr(audit_mod, "scrub_user", lambda *a, **k: (0, 0))
    monkeypatch.setattr(audit_mod, "record", lambda kind, **payload: None)
    monkeypatch.setattr(audit_mod, "reanchor_after_erase", lambda *a, **k: None)

    db = tmp_path / "world.db"
    _seed_user_with_fact(db)

    result = CliRunner().invoke(
        cli_mod.main,
        ["--db", str(db), "erase", "--channel", "telegram", "--user", "u123", "--yes"],
    )
    # Must NOT abort on the facts FK; erase has to complete.
    assert result.exit_code == 0, result.output

    wm = WorldModel(db)
    # The PII-bearing fact is gone, and so are the goals/episodes.
    assert wm.get_facts() == {}
    rows = wm.conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    assert rows == 0
    wm.close()


def test_reupsert_tracks_latest_source_episode(tmp_path):
    wm = WorldModel(tmp_path / "source.db")
    first_goal = wm.create_goal("first")
    second_goal = wm.create_goal("second")
    first_episode = wm.start_episode(first_goal)
    second_episode = wm.start_episode(second_goal)

    wm.upsert_fact("owner", "first", episode_id=first_episode)
    wm.upsert_fact("owner", "second", episode_id=second_episode)

    row = wm.conn.execute(
        "SELECT source_episode_id FROM facts WHERE key = ?", ("owner",)
    ).fetchone()
    assert row[0] == second_episode
    wm.close()


def test_erase_clears_llm_cache(tmp_path, monkeypatch):
    os.environ.pop("MAVERICK_DB", None)
    import maverick.audit as audit_mod
    monkeypatch.setattr(audit_mod, "scrub_user", lambda *a, **k: (0, 0))
    monkeypatch.setattr(audit_mod, "record", lambda kind, **payload: None)
    monkeypatch.setattr(audit_mod, "reanchor_after_erase", lambda *a, **k: None)

    # Point the LLM cache at a temp db and seed it with a prompt+answer.
    cache_db = tmp_path / "llm_cache.db"
    import maverick.cache.llm as llm_cache_mod
    monkeypatch.setattr(llm_cache_mod, "DEFAULT_DB", cache_db)
    cache = llm_cache_mod.LLMCache(db_path=cache_db)
    key = llm_cache_mod.cache_key(
        provider="anthropic", model="x", system="sys",
        messages=[{"role": "user", "content": "I live at 1 Privacy Lane"}],
        tools=None, max_tokens=10,
    )
    cache.store(key, provider="anthropic", model="x", text="sure")
    assert cache.lookup(key) is not None

    # A second principal's row in the same database must also be removed: the
    # content-addressed key cannot prove which subject appears in a prompt.
    from maverick.connections import bind_principal
    with bind_principal("user:someone-else"):
        other = llm_cache_mod.LLMCache(db_path=cache_db)
        other.store(key, provider="anthropic", model="x", text="other")
        assert other.lookup(key) is not None

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    wm.get_or_create_conversation("telegram", "u123")
    wm.create_goal("hi")
    wm.close()

    result = CliRunner().invoke(
        cli_mod.main,
        ["--db", str(db), "erase", "--channel", "telegram", "--user", "u123", "--yes"],
    )
    assert result.exit_code == 0, result.output
    # The cached prompt/answer (which held the user's PII) is gone.
    assert llm_cache_mod.LLMCache(db_path=cache_db).lookup(key) is None
    with bind_principal("user:someone-else"):
        assert llm_cache_mod.LLMCache(db_path=cache_db).lookup(key) is None


def test_all_authority_cache_purge_requires_explicit_confirmation(
    tmp_path, monkeypatch,
):
    import maverick.cache.llm as llm_cache_mod

    cache_db = tmp_path / "llm_cache.db"
    monkeypatch.setattr(llm_cache_mod, "DEFAULT_DB", cache_db)
    cache = llm_cache_mod.LLMCache(db_path=cache_db)
    with pytest.raises(PermissionError, match="confirmed"):
        cache.purge_all_authorities_for_erasure()
