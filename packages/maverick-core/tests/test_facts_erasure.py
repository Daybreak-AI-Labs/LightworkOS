"""GDPR fact export/erase only touches explicitly user-scoped global facts.

Facts are global key/value pairs with no per-user attribution.  A raw
substring search on user ids is unsafe because short/common ids can match
unrelated operator knowledge such as API tokens or other users' data.
"""
from __future__ import annotations

import json


def test_facts_matching_requires_user_scoped_key_prefix(tmp_path):
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    w.upsert_fact("user:u123:phone", "+1555")       # explicit subject scope
    w.upsert_fact("u123_phone", "+1555")            # legacy substring in key
    w.upsert_fact("note", "owner is u123")          # legacy substring in value
    w.upsert_fact("office", "123 Main St")          # unrelated
    assert w.facts_matching("u123") == {"user:u123:phone": "+1555"}
    w.close()


def test_delete_facts_matching_returns_keys_and_keeps_others(tmp_path):
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    w.upsert_fact("user:u123:phone", "+1555")
    w.upsert_fact("user:u123:note", "owner is u123")
    w.upsert_fact("u123_phone", "+1555")
    w.upsert_fact("note", "owner is u123")
    w.upsert_fact("office", "123 Main St")
    removed = w.delete_facts_matching("u123")
    assert removed == ["user:u123:note", "user:u123:phone"]   # sorted
    assert set(w.get_facts()) == {"u123_phone", "note", "office"}
    # Empty token is a no-op (never nukes the whole table).
    assert w.delete_facts_matching("") == []
    assert set(w.get_facts()) == {"u123_phone", "note", "office"}
    w.close()


def test_fact_subject_token_is_delimiter_safe():
    from maverick.cli import _fact_subject_token

    assert _fact_subject_token("sms", "+1") == "sms:%2B1"
    assert _fact_subject_token("telegram", "a:b") == "telegram:a%3Ab"


def test_short_user_id_does_not_match_unrelated_fact_substrings(tmp_path):
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    w.upsert_fact("api_token", "SECRET-999")
    w.upsert_fact("team_password", "do-not-disclose")
    w.upsert_fact("incident_note", "call alice")
    w.upsert_fact("user:a:preference", "ok")
    assert w.facts_matching("a") == {"user:a:preference": "ok"}
    assert w.delete_facts_matching("a") == ["user:a:preference"]
    assert set(w.get_facts()) == {"api_token", "team_password", "incident_note"}
    w.close()


def _setup_subject_db(tmp_path):
    from maverick.world_model import WorldModel
    db = tmp_path / "world.db"
    w = WorldModel(db)
    w.get_or_create_conversation("telegram", "u123")  # erase needs a conv
    w.upsert_fact("user:telegram:u123:addr", "secret place")  # explicit scope
    w.upsert_fact("u123_addr", "legacy secret place")        # substring only; keep
    w.upsert_fact("global_cfg", "keep me")            # unrelated
    w.close()
    return db


def test_erase_scrubs_only_user_scoped_facts(tmp_path, monkeypatch):
    import maverick.audit as audit_mod
    from click.testing import CliRunner
    from maverick import cli as cli_mod
    from maverick.world_model import WorldModel

    monkeypatch.setattr(audit_mod, "scrub_user", lambda *a, **k: (0, 0))
    monkeypatch.setattr(audit_mod, "record", lambda kind, **payload: None)

    db = _setup_subject_db(tmp_path)
    res = CliRunner().invoke(cli_mod.main, [
        "--db", str(db), "erase", "--channel", "telegram",
        "--user", "u123", "--yes",
    ])
    assert res.exit_code == 0, res.output
    assert "1 fact(s) scrubbed" in res.output
    assert "user:telegram:u123:addr" in res.output  # the removed key is reported

    w = WorldModel(db)
    facts = w.get_facts()
    w.close()
    assert "user:telegram:u123:addr" not in facts
    assert facts.get("u123_addr") == "legacy secret place"  # substring not scrubbed
    assert facts.get("global_cfg") == "keep me"             # unrelated kept


def test_export_user_includes_only_user_scoped_facts(tmp_path):
    from click.testing import CliRunner
    from maverick import cli as cli_mod

    db = _setup_subject_db(tmp_path)
    res = CliRunner().invoke(cli_mod.main, [
        "--db", str(db), "export-user", "--channel", "telegram", "--user", "u123",
    ])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["facts"] == {"user:telegram:u123:addr": "secret place"}


def test_export_user_includes_fact_history(tmp_path, monkeypatch):
    # Art.15: with temporal memory on, superseded fact values are the subject's
    # personal data and must appear in the export (not just the current value).
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    from click.testing import CliRunner
    from maverick import cli as cli_mod
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    w = WorldModel(db)
    w.get_or_create_conversation("telegram", "u123")
    k = "user:telegram:u123:addr"
    w.upsert_fact(k, "first place")
    w.upsert_fact(k, "second place")  # evolves -> history
    w.close()

    res = CliRunner().invoke(cli_mod.main, [
        "--db", str(db), "export-user", "--channel", "telegram", "--user", "u123",
    ])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    vals = [v["value"] for v in data["fact_history"][k]]
    assert vals == ["first place", "second place"]  # oldest-first, both retained
    assert data["facts"][k] == "second place"       # current value still correct
