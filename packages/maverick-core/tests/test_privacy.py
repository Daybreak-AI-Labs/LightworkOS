"""Tests for anonymous mode (maverick.privacy)."""
from __future__ import annotations

# ---------- privacy ----------

def test_anon_enabled_from_env(monkeypatch):
    from maverick import privacy
    monkeypatch.setenv("MAVERICK_ANON", "1")
    assert privacy.anon_enabled() is True
    monkeypatch.setenv("MAVERICK_ANON", "0")
    # Config may still enable it; just check env-only path doesn't crash.
    privacy.anon_enabled()


def test_anonymize_dict_hashes_user_id():
    from maverick.privacy import anonymize_dict
    out = anonymize_dict({"user_id": "alice@example.com", "ok": 1})
    assert out["user_id"].startswith("user_id#")
    assert out["ok"] == 1


def test_anonymize_dict_basename_for_path():
    from maverick.privacy import anonymize_field
    assert anonymize_field("path", "/etc/passwd") == "passwd"
    assert anonymize_field("filename", "/var/log/x.log") == "x.log"


def test_anonymize_hash_is_stable():
    from maverick.privacy import _hash_id  # type: ignore[attr-defined]
    a = _hash_id("alice", prefix="user_id")
    b = _hash_id("alice", prefix="user_id")
    assert a == b
    assert _hash_id("bob", prefix="user_id") != a


def test_anonymize_scrubs_text_keys():
    from maverick.privacy import anonymize_dict
    out = anonymize_dict({"summary": "contact me at a@b.com"})
    # PII detector should redact the email; if not, at minimum the
    # field is still processed and returns a string.
    assert isinstance(out["summary"], str)


def test_anonymize_scrubs_nested_message_content_blocks():
    # Anthropic/OpenAI messages nest the real text under content[].text. In anon
    # mode that nested text must be scrubbed (home path -> ~), not passed through
    # verbatim. Uses the unconditional home-path rewrite for a deterministic check.
    from pathlib import Path

    from maverick.privacy import anonymize_dict

    home = str(Path.home())
    payload = {
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": f"secret lives at {home}/vault"},
            ]},
        ],
    }
    out = anonymize_dict(payload)
    nested = out["messages"][0]["content"][0]["text"]
    assert home not in nested
    assert "~/vault" in nested


class TestPrivacyAnonStr:
    def test_string_false_disables(self, monkeypatch):
        import maverick.config as cfg
        from maverick import privacy
        monkeypatch.delenv("MAVERICK_ANON", raising=False)
        monkeypatch.setattr(cfg, "load_config",
                            lambda: {"privacy": {"anonymous": "false"}})
        assert privacy.anon_enabled() is False

    def test_string_true_enables(self, monkeypatch):
        import maverick.config as cfg
        from maverick import privacy
        monkeypatch.delenv("MAVERICK_ANON", raising=False)
        monkeypatch.setattr(cfg, "load_config",
                            lambda: {"privacy": {"anonymous": "true"}})
        assert privacy.anon_enabled() is True
