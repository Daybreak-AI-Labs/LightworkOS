"""The test-message policy uses the same immutable sender IDs as live chat."""
import time
from contextlib import nullcontext

import pytest
from fastapi import HTTPException
from maverick_dashboard import channel_test_requests as requests


def test_legacy_mattermost_allowlist_requires_user_ids_before_review(monkeypatch):
    sender = "a" * 26
    record = {"id": "receipt", "channel": "mattermost", "account_sha256": "account",
              "created_at": time.time() - 1, "message": {"user_id": "b" * 26, "sender_id": sender}}
    with pytest.raises(HTTPException, match="user id"):
        requests._source("mattermost", {"allowed_user_ids": [sender, "alice"]}, record, "account")
    monkeypatch.setattr(requests.auth, "fresh_configuration", nullcontext)
    monkeypatch.setattr(requests.transport, "_channel_config", lambda _: {
        "bot_token": "fixture-token", "allowed_user_ids": ["alice"]})
    with pytest.raises(HTTPException, match="user id"):
        requests.configuration("mattermost")  # The catalog must show the repair before its per-row filter.
    assert requests._source("mattermost", {"allowed_user_ids": [sender]}, record, "account")["sender"] == sender
    with pytest.raises(HTTPException) as denied:
        requests._source("mattermost", {"allowed_user_ids": ["c" * 26]}, record, "account")
    assert denied.value.status_code == 403
