"""Linear + Jira inbound webhook receiver tests (pure functions)."""
from __future__ import annotations

import hashlib
import hmac
import time

from maverick.issue_webhooks import (
    build_brief,
    canonical_signature,
    event_timestamp_ms,
    is_fresh,
    parse_issue_event,
    verify_signature,
)


def _sig(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class TestSignature:
    def test_canonical_signature_normalizes_equivalent_forms(self):
        digest = "abc123"
        assert canonical_signature(digest) == digest
        assert canonical_signature("sha256=" + digest) == digest
        assert canonical_signature("  sha256=" + digest + "  ") == digest
        assert canonical_signature(None) is None

    def test_bare_hex_signature_accepts(self):
        secret = "s3cr3t"
        body = b'{"hello":"world"}'
        assert verify_signature(body, _sig(body, secret), secret) is True

    def test_sha256_prefixed_signature_accepts(self):
        secret = "s3cr3t"
        body = b'{"hello":"world"}'
        assert verify_signature(body, "sha256=" + _sig(body, secret), secret) is True

    def test_wrong_signature_rejects(self):
        assert verify_signature(b"{}", "deadbeef", "s3cr3t") is False

    def test_missing_signature_rejects(self):
        assert verify_signature(b"{}", None, "s3cr3t") is False

    def test_no_secret_fails_closed(self):
        # Unlike github_app's dev fail-open: these routes are public.
        assert verify_signature(b"{}", "deadbeef", None) is False


class TestParseLinear:
    def _payload(self, assignee_id="bot-1"):
        return {
            "type": "Issue", "action": "update",
            # An assignment transition carries the prior assignee in updatedFrom.
            "updatedFrom": {"assigneeId": None},
            "data": {
                "identifier": "ENG-123", "title": "Fix it",
                "description": "broken", "assigneeId": assignee_id,
                "assignee": {"id": assignee_id},
            },
        }

    def test_assigned_to_bot(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_LINEAR_ID", "bot-1")
        ev = parse_issue_event("linear", self._payload("bot-1"))
        assert ev is not None
        assert ev.provider == "linear"
        assert ev.issue_id == "ENG-123"
        assert ev.title == "Fix it"
        assert ev.body == "broken"

    def test_assigned_to_other_returns_none(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_LINEAR_ID", "bot-1")
        assert parse_issue_event("linear", self._payload("human-2")) is None

    def test_no_bot_configured_fails_closed(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_BOT_LINEAR_ID", raising=False)
        assert parse_issue_event("linear", self._payload("anyone")) is None

    def test_unassigned_returns_none(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_BOT_LINEAR_ID", raising=False)
        payload = {"type": "Issue", "action": "update", "data": {"identifier": "ENG-1"}}
        assert parse_issue_event("linear", payload) is None

    def test_non_issue_type_returns_none(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_LINEAR_ID", "bot-1")
        payload = {"type": "Comment", "action": "create", "data": {"id": "c1"}}
        assert parse_issue_event("linear", payload) is None

    def test_update_without_assignee_change_returns_none(self, monkeypatch):
        # Regression: an edit (priority/state/description) while the bot stays
        # the assignee, but with no assignee in updatedFrom, must NOT fire a
        # goal — only the assign transition should.
        monkeypatch.setenv("MAVERICK_BOT_LINEAR_ID", "bot-1")
        payload = self._payload("bot-1")
        payload["updatedFrom"] = {"priority": 1}  # priority changed, not assignee
        assert parse_issue_event("linear", payload) is None

    def test_create_needs_no_updated_from(self, monkeypatch):
        # A create is the initial assignment; it has no updatedFrom.
        monkeypatch.setenv("MAVERICK_BOT_LINEAR_ID", "bot-1")
        payload = self._payload("bot-1")
        payload["action"] = "create"
        payload.pop("updatedFrom", None)
        assert parse_issue_event("linear", payload) is not None


class TestParseJira:
    def _payload(self, account_id="acct-1"):
        return {
            "webhookEvent": "jira:issue_updated",
            # An assignment transition lists the assignee in changelog.items.
            "changelog": {"items": [{"field": "assignee", "to": account_id}]},
            "issue": {
                "key": "PROJ-7",
                "fields": {
                    "summary": "Add retry",
                    "description": {
                        "type": "doc", "version": 1,
                        "content": [{
                            "type": "paragraph",
                            "content": [{"type": "text", "text": "fails"}],
                        }],
                    },
                    "assignee": {"accountId": account_id},
                },
            },
        }

    def test_assigned_to_bot_flattens_adf(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_JIRA_ACCOUNT_ID", "acct-1")
        ev = parse_issue_event("jira", self._payload("acct-1"))
        assert ev is not None
        assert ev.provider == "jira"
        assert ev.issue_id == "PROJ-7"
        assert ev.title == "Add retry"
        assert "fails" in ev.body

    def test_assigned_to_other_returns_none(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_JIRA_ACCOUNT_ID", "acct-1")
        assert parse_issue_event("jira", self._payload("other")) is None

    def test_email_match(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_JIRA_ACCOUNT_ID", "bot@example.com")
        payload = self._payload("acct-1")
        payload["issue"]["fields"]["assignee"]["emailAddress"] = "bot@example.com"
        assert parse_issue_event("jira", payload) is not None

    def test_no_bot_configured_fails_closed(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_BOT_JIRA_ACCOUNT_ID", raising=False)
        assert parse_issue_event("jira", self._payload("acct-1")) is None

    def test_wrong_event_returns_none(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_JIRA_ACCOUNT_ID", "acct-1")
        payload = self._payload("acct-1")
        payload["webhookEvent"] = "comment_created"
        assert parse_issue_event("jira", payload) is None

    def test_update_without_assignee_change_returns_none(self, monkeypatch):
        # Regression: an issue_updated that didn't touch the assignee (e.g. a
        # priority change) while the bot stays assigned must NOT fire a goal.
        monkeypatch.setenv("MAVERICK_BOT_JIRA_ACCOUNT_ID", "acct-1")
        payload = self._payload("acct-1")
        payload["changelog"] = {"items": [{"field": "priority", "to": "High"}]}
        assert parse_issue_event("jira", payload) is None

    def test_issue_created_needs_no_changelog(self, monkeypatch):
        # issue_created is the initial assignment; no changelog required.
        monkeypatch.setenv("MAVERICK_BOT_JIRA_ACCOUNT_ID", "acct-1")
        payload = self._payload("acct-1")
        payload["webhookEvent"] = "jira:issue_created"
        payload.pop("changelog", None)
        assert parse_issue_event("jira", payload) is not None


class TestParseGitLab:
    def _payload(self, action="update"):
        return {
            "object_kind": "issue",
            "object_attributes": {"action": action, "iid": 7, "title": "Fix it", "description": "Details"},
            "project": {"path_with_namespace": "team/repo"},
            "assignees": [{"id": 2, "username": "lightwork-bot"}],
            "changes": {"assignees": {"previous": [], "current": [{"id": 2, "username": "lightwork-bot"}]}},
        }

    def test_new_bot_assignment_starts_one_goal(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_GITLAB_USERNAME", "lightwork-bot")
        event = parse_issue_event("gitlab", self._payload())
        assert event is not None
        assert event.issue_id == "team/repo#7"

    def test_regular_edits_and_reopen_without_assignment_do_not_start_paid_work(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_GITLAB_USERNAME", "lightwork-bot")
        for action in ("update", "reopen"):
            payload = self._payload(action)
            payload["changes"] = {"labels": {"previous": [], "current": ["urgent"]}}
            assert parse_issue_event("gitlab", payload) is None

    def test_bot_already_assigned_does_not_restart_when_other_assignee_changes(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_GITLAB_USERNAME", "lightwork-bot")
        payload = self._payload()
        payload["changes"] = {"assignees": {
            "previous": [{"id": 2, "username": "lightwork-bot"}],
            "current": [{"id": 2, "username": "lightwork-bot"}, {"id": 3, "username": "person"}],
        }}
        assert parse_issue_event("gitlab", payload) is None

    def test_id_based_assignee_change_needs_the_bot_to_be_new(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_GITLAB_USERNAME", "lightwork-bot")
        payload = self._payload()
        payload["changes"] = {"assignee_ids": {"previous": [1], "current": [2]}}
        assert parse_issue_event("gitlab", payload) is not None
        payload["changes"] = {"assignee_ids": {"previous": [2], "current": [2, 3]}}
        assert parse_issue_event("gitlab", payload) is None
        payload["assignees"] = [{"username": "lightwork-bot"}]
        assert parse_issue_event("gitlab", payload) is None  # numeric prior owner cannot be resolved

    def test_open_is_initial_assignment_without_changes(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BOT_GITLAB_USERNAME", "lightwork-bot")
        payload = self._payload("open")
        payload.pop("changes")
        assert parse_issue_event("gitlab", payload) is not None


class TestUnknownProvider:
    def test_returns_none(self):
        assert parse_issue_event("github", {"type": "Issue"}) is None


class TestBuildBrief:
    def test_includes_issue_id_title_body(self):
        from maverick.issue_webhooks import IssueEvent
        ev = IssueEvent(
            provider="linear", issue_id="ENG-9", title="Do the thing",
            body="here is how", assignee="bot-1",
        )
        brief = build_brief(ev)
        assert "ENG-9" in brief
        assert "Do the thing" in brief
        assert "here is how" in brief


class TestFreshness:
    """Replay defence: the signed body's timestamp must be recent."""

    def test_event_timestamp_ms_linear_and_jira(self):
        assert event_timestamp_ms("linear", {"webhookTimestamp": 1_700_000_000_000}) == 1_700_000_000_000
        assert event_timestamp_ms("jira", {"timestamp": 1_700_000_000_000}) == 1_700_000_000_000

    def test_event_timestamp_ms_missing_or_garbage(self):
        assert event_timestamp_ms("linear", {}) is None
        assert event_timestamp_ms("jira", {"timestamp": "not-a-number"}) is None

    def test_fresh_event_passes(self):
        now = time.time()
        ms = int(now * 1000)
        assert is_fresh("linear", {"webhookTimestamp": ms}, now=now) is True
        assert is_fresh("jira", {"timestamp": ms}, now=now) is True

    def test_stale_event_rejected(self):
        now = time.time()
        old_ms = int((now - 10_000) * 1000)  # ~2.8h old, well past the 300s window
        assert is_fresh("linear", {"webhookTimestamp": old_ms}, now=now) is False

    def test_future_skew_rejected(self):
        now = time.time()
        future_ms = int((now + 10_000) * 1000)
        assert is_fresh("jira", {"timestamp": future_ms}, now=now) is False

    def test_missing_timestamp_fails_closed(self):
        # No timestamp -> cannot prove freshness -> reject (a replayer can't add
        # one without breaking the body HMAC, so real events are unaffected).
        assert is_fresh("linear", {"type": "Issue"}, now=time.time()) is False

    def test_seconds_valued_timestamp_tolerated(self):
        now = time.time()
        assert is_fresh("jira", {"timestamp": int(now)}, now=now) is True

    def test_explicit_window_override(self):
        now = time.time()
        ms = int((now - 120) * 1000)  # 2 min old
        assert is_fresh("linear", {"webhookTimestamp": ms}, now=now, max_age_seconds=60) is False
        assert is_fresh("linear", {"webhookTimestamp": ms}, now=now, max_age_seconds=600) is True
