"""GDPR export-user / erase must safely match CLI `chat` conversations.

`chat` scopes each REPL session to a unique ``local:<uuid>`` user_id, so an
exact match on the documented ``--user local`` found nothing -- a user could
never export (Art. 15) or erase (Art. 17) their own CLI chat history.  The
CLI-only family match must not apply to colon-bearing ids from other channels.
"""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from maverick.cli import _conversation_user_matches, main
from maverick.world_model import open_world


def test_user_match_predicate():
    assert _conversation_user_matches("local:abc123", "local", "cli") is True
    assert _conversation_user_matches("local", "local", "cli") is True
    assert _conversation_user_matches("12345", "12345", "sms") is True
    # No colon boundary -> not a prefix match (don't over-match 12345 vs 1234).
    assert _conversation_user_matches("123456", "12345", "sms") is False
    assert _conversation_user_matches("other:x", "local", "cli") is False
    # Prefix matching is CLI/local-specific; non-CLI colon-bearing ids are exact-only.
    assert _conversation_user_matches("whatsapp:+15551234567", "whatsapp", "whatsapp") is False
    assert _conversation_user_matches("!room:server", "!room", "matrix") is False


def test_export_and_erase_reach_cli_chat_sessions(tmp_path: Path):
    db = tmp_path / "world.db"
    w = open_world(db)
    c1 = w.get_or_create_conversation("cli", "local:aaa")
    c2 = w.get_or_create_conversation("cli", "local:bbb")
    other = w.get_or_create_conversation("telegram", "999")
    w.append_turn(c1.id, "user", "secret-session-one")
    w.append_turn(c2.id, "user", "secret-session-two")
    w.append_turn(other.id, "user", "unrelated-telegram")

    runner = CliRunner()
    exp = runner.invoke(main, ["--db", str(db), "export-user", "--channel", "cli", "--user", "local"])
    assert exp.exit_code == 0
    assert "secret-session-one" in exp.output
    assert "secret-session-two" in exp.output
    assert "unrelated-telegram" not in exp.output  # scoped to the cli channel

    er = runner.invoke(main, ["--db", str(db), "erase", "--channel", "cli", "--user", "local", "--yes"])
    assert er.exit_code == 0

    after = runner.invoke(main, ["--db", str(db), "export-user", "--channel", "cli", "--user", "local"])
    assert "secret-session-one" not in after.output
    assert "secret-session-two" not in after.output
    # The unrelated telegram conversation is untouched.
    assert w.get_or_create_conversation("telegram", "999").id == other.id


def test_export_and_erase_do_not_prefix_match_non_cli_colon_ids(tmp_path: Path):
    db = tmp_path / "world.db"
    w = open_world(db)
    c1 = w.get_or_create_conversation("whatsapp", "whatsapp:+15551234567")
    c2 = w.get_or_create_conversation("whatsapp", "whatsapp:+15557654321")
    w.append_turn(c1.id, "user", "secret-whatsapp-one")
    w.append_turn(c2.id, "user", "secret-whatsapp-two")

    runner = CliRunner()
    exp = runner.invoke(
        main,
        ["--db", str(db), "export-user", "--channel", "whatsapp", "--user", "whatsapp"],
    )
    assert exp.exit_code == 0
    assert "secret-whatsapp-one" not in exp.output
    assert "secret-whatsapp-two" not in exp.output

    er = runner.invoke(
        main,
        ["--db", str(db), "erase", "--channel", "whatsapp", "--user", "whatsapp", "--yes"],
    )
    assert er.exit_code == 0
    assert "no conversation found" in er.output

    remaining = {c.user_id for c in w.list_conversations("whatsapp")}
    assert remaining == {"whatsapp:+15551234567", "whatsapp:+15557654321"}


def test_erase_scrubs_dreaming_user_notes(monkeypatch, tmp_path: Path):
    from maverick import config, user_notes
    original = config.get_dreaming
    monkeypatch.setattr(config, "get_dreaming", lambda: {**original(), "user_notes": True})

    db = tmp_path / "world.db"
    notes_path = tmp_path / "user_notes.ndjson"
    monkeypatch.setattr(user_notes, "default_path", lambda: notes_path)

    w = open_world(db)
    c1 = w.get_or_create_conversation("cli", "local:aaa")
    c2 = w.get_or_create_conversation("cli", "local:bbb")
    other = w.get_or_create_conversation("telegram", "999")
    w.append_turn(c1.id, "user", "Please always call me Alice.")
    w.append_turn(c2.id, "user", "I prefer short answers.")
    w.append_turn(other.id, "user", "Never use emoji.")
    assert user_notes.consolidate(w, path=notes_path) == 3

    result = CliRunner().invoke(
        main,
        ["--db", str(db), "erase", "--channel", "cli", "--user", "local", "--yes"],
    )

    assert result.exit_code == 0, result.output
    assert "2 user note(s) scrubbed" in result.output
    assert user_notes.notes_for("cli", "local:aaa", notes_path) == []
    assert user_notes.notes_for("cli", "local:bbb", notes_path) == []
    assert user_notes.notes_for("telegram", "999", notes_path) == ["Never use emoji."]


def test_erase_uses_backend_erase_hook_for_non_sqlite_world(monkeypatch, tmp_path: Path):
    """Postgres worlds must not be driven through SQLite-only ``world.conn`` SQL."""
    from maverick import audit as audit_mod
    from maverick import cli as cli_mod
    from maverick.world_model import Conversation

    class PostgresLikeWorld:
        conn = None  # The test fails if erase tries the SQLite direct-SQL path.

        def __init__(self) -> None:
            self.erase_calls: list[list[int]] = []

        def list_conversations(self, channel: str | None = None):
            assert channel == "telegram"
            return [Conversation(42, "telegram", "u123", 1.0, 2.0)]

        def erase_conversations(self, conversation_ids: list[int]):
            self.erase_calls.append(conversation_ids)
            return {7}, [], 3

        def delete_facts_matching(self, token: str):
            assert token == "telegram:u123"
            return []

    fake_world = PostgresLikeWorld()
    monkeypatch.setattr(cli_mod, "open_world", lambda _path: fake_world)
    monkeypatch.setattr(audit_mod, "scrub_user", lambda *_args, **_kwargs: (0, 0))
    monkeypatch.setattr(audit_mod, "reanchor_after_erase", lambda: 0)
    monkeypatch.setattr(audit_mod, "record", lambda *_args, **_kwargs: None)

    result = CliRunner().invoke(
        main,
        ["--db", str(tmp_path / "ignored.db"), "erase", "--channel", "telegram", "--user", "u123", "--yes"],
    )

    assert result.exit_code == 0, result.output
    assert fake_world.erase_calls == [[42]]
    assert "erased 1 conversation(s), 3 turn(s), 1 goal(s)" in result.output


def test_erase_refuses_backend_without_atomic_erasure_contract(
    monkeypatch,
    tmp_path: Path,
):
    """A custom backend must not fall into private SQLite table surgery."""
    from maverick import cli as cli_mod
    from maverick.world_model import Conversation

    class UnsupportedWorld:
        def list_conversations(self, channel: str | None = None):
            assert channel == "telegram"
            return [Conversation(42, "telegram", "u123", 1.0, 2.0)]

        @property
        def conn(self):
            raise AssertionError("legacy private-SQL fallback must not run")

    monkeypatch.setattr(cli_mod, "open_world", lambda _path: UnsupportedWorld())
    result = CliRunner().invoke(
        main,
        [
            "--db",
            str(tmp_path / "ignored.db"),
            "erase",
            "--channel",
            "telegram",
            "--user",
            "u123",
            "--yes",
        ],
    )

    assert result.exit_code != 0
    assert "does not implement the atomic erase_conversations contract" in result.output
    assert "partial legacy SQL deletion" in result.output
