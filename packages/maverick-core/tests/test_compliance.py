"""Tests for the EU AI Act Article 50 first-turn disclosure (maverick.compliance)."""
from __future__ import annotations

# ---------- EU AI Act Article 50 disclosure ----------

class TestArticle50Disclosure:
    def test_first_turn_returns_disclosure(self, tmp_path):
        from maverick.compliance import first_turn_disclosure
        from maverick.world_model import WorldModel
        wm = WorldModel(tmp_path / "w.db")
        msg = first_turn_disclosure(wm, "telegram", "user-42")
        assert msg is not None
        assert "Lightwork" in msg
        assert "AI" in msg

    def test_after_assistant_turn_returns_none(self, tmp_path):
        from maverick.compliance import first_turn_disclosure
        from maverick.world_model import WorldModel
        wm = WorldModel(tmp_path / "w.db")
        conv = wm.get_or_create_conversation("telegram", "user-42")
        wm.append_turn(conv.id, "user", "hello")
        wm.append_turn(conv.id, "assistant", "hi back")
        assert first_turn_disclosure(wm, "telegram", "user-42") is None

    def test_only_user_turn_still_returns_disclosure(self, tmp_path):
        """User turn without assistant turn = still first interaction
        from the user's perspective (they haven't gotten a reply yet)."""
        from maverick.compliance import first_turn_disclosure
        from maverick.world_model import WorldModel
        wm = WorldModel(tmp_path / "w.db")
        conv = wm.get_or_create_conversation("telegram", "user-42")
        wm.append_turn(conv.id, "user", "hello")
        assert first_turn_disclosure(wm, "telegram", "user-42") is not None

    def test_trailing_user_turn_after_assistant_returns_none(self, tmp_path):
        """A failed/blocked goal leaves the conversation's last row as a 'user'
        turn (no assistant reply written). The disclosure must NOT re-fire on the
        next message just because the newest row is a user turn -- scan for ANY
        prior assistant turn, not only the single newest row."""
        from maverick.compliance import first_turn_disclosure
        from maverick.world_model import WorldModel
        wm = WorldModel(tmp_path / "w.db")
        conv = wm.get_or_create_conversation("telegram", "user-42")
        wm.append_turn(conv.id, "user", "hello")
        wm.append_turn(conv.id, "assistant", "hi back")
        wm.append_turn(conv.id, "user", "second message (goal then failed)")
        assert first_turn_disclosure(wm, "telegram", "user-42") is None

    def test_empty_disclosure_text_opts_out(self, tmp_path, monkeypatch):
        from maverick.compliance import first_turn_disclosure
        from maverick.world_model import WorldModel
        monkeypatch.setenv("MAVERICK_AI_DISCLOSURE", "")
        wm = WorldModel(tmp_path / "w.db")
        assert first_turn_disclosure(wm, "telegram", "user-42") is None

    def test_custom_disclosure_text(self, tmp_path, monkeypatch):
        from maverick.compliance import first_turn_disclosure
        from maverick.world_model import WorldModel
        monkeypatch.setenv("MAVERICK_AI_DISCLOSURE", "Howdy, I am the AI.")
        wm = WorldModel(tmp_path / "w.db")
        msg = first_turn_disclosure(wm, "telegram", "user-42")
        assert msg == "Howdy, I am the AI."
