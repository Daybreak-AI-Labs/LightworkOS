"""The comment store behind threads and @mentions (NOT-4)."""
from __future__ import annotations

import pytest
from maverick import comments


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_reads_never_create_the_store():
    assert comments.list_for("task", "1") == []
    assert comments.mentions_for("user:ana", since=0) == []
    assert comments.count_by("user:ana") == 0 and comments.get(1) is None
    assert not comments._path().exists()


def test_a_thread_keeps_order_mentions_and_author_only_deletes():
    first = comments.add("task", "7", author="user:ana", body="Can you check the totals?",
                         mentions=["user:ben", "user:ana", "user:ben"])
    assert first["mentions"] == ["user:ben"]  # no self-mention, no duplicates
    comments.add("task", "7", author="user:ben", body="Done.")
    assert [c["body"] for c in comments.list_for("task", "7")] == ["Can you check the totals?", "Done."]
    assert [c["id"] for c in comments.mentions_for("user:ben", since=0)] == [first["id"]]
    assert comments.mentions_for("user:ana", since=0) == []
    assert comments.remove(first["id"], by="user:ben") is False  # not the author
    assert comments.remove(first["id"], by="user:ana") is True
    assert [c["body"] for c in comments.list_for("task", "7")] == ["Done."]
    assert comments.mentions_for("user:ben", since=0) == []  # a deleted comment withdraws its mention


def test_refusals_are_plain_sentences():
    with pytest.raises(comments.CommentError, match="Write a comment"):
        comments.add("task", "1", author="user:ana", body="   ")
    with pytest.raises(comments.CommentError, match="tasks, runs, approvals and policies"):
        comments.add("folder", "1", author="user:ana", body="hi")
    with pytest.raises(comments.CommentError, match="Sign in"):
        comments.add("task", "1", author="agent:bot", body="hi")
    with pytest.raises(comments.CommentError, match="under 4,000"):
        comments.add("task", "1", author="user:ana", body="x" * 4001)


def test_a_person_can_erase_their_comments_and_others_stay():
    comments.add("policy", "tools", author="user:ana", body="Why block web fetch?")
    comments.add("policy", "tools", author="user:ben", body="Because of the audit.")
    assert comments.count_by("user:ana") == 1
    assert comments.erase_person("user:ana") == 1
    assert [c["author"] for c in comments.list_for("policy", "tools")] == ["user:ben"]


def test_the_setting_turns_comments_off(home):
    from maverick import config

    assert comments.enabled() is True
    (home / "config.toml").write_text("[collaboration]\ncomments = false\n", encoding="utf-8")
    config.reset_config_cache()
    assert comments.enabled() is False


def test_a_mention_alert_follows_the_persons_own_mention_choice(monkeypatch, home):
    from maverick.personal_notifications import PersonalInbox, explain, validate_preferences

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    source = explain({"ref": "comment:1", "version": "1", "category": "mention", "title": "Policy: Tool permissions",
                      "label": "Mentioned you", "href": "/permissions#comment-1", "goal_id": None,
                      "reason": "dana mentioned you in a comment"})
    assert source["action"] == "Read the comment and reply" and source["no_due"] == "Nothing is due"
    inbox = PersonalInbox("user:lee", path=home / "inbox.json")
    off = inbox.refresh([source], validate_preferences({"mentions": False}))
    assert off["items"] == []
    on = PersonalInbox("user:lee", path=home / "inbox2.json").refresh([source], validate_preferences({}))
    assert [item["ref"] for item in on["items"]] == ["comment:1"]


def test_a_long_thread_shows_its_newest_comments_oldest_first():
    # Listing the oldest 200 hid comment 201 onwards, including one just posted.
    for n in range(1, 206):
        comments.add("task", "7", author="user:alice", body=f"comment {n}")
    thread = comments.list_for("task", "7")
    assert len(thread) == 200
    assert thread[0]["body"] == "comment 6" and thread[-1]["body"] == "comment 205"
    assert [row["id"] for row in thread] == sorted(row["id"] for row in thread)
