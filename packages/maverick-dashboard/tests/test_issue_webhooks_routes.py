"""Inbound Linear + Jira issue-assigned webhook tests.

Mirrors test_webhook_start.py: a valid HMAC signature + an assigned-to-bot
event creates a goal (and a world-model row); an invalid signature, or a
non-assignment event, does not. The runner is monkeypatched so no real LLM
call happens.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")

SECRET = "test-webhook-secret"
JIRA_SECRET = "test-jira-secret"  # pragma: allowlist secret
LINEAR_BOT = "linear-bot-id"
JIRA_BOT = "jira-bot-account-id"


def _sign(body: bytes, secret: str = SECRET) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


@pytest.fixture(autouse=True)
def _isolated_world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    # Reset the dashboard's per-DB-path WorldModel cache so each test gets
    # its own DB (the cache keys on DEFAULT_DB, which we just repointed).
    from maverick_dashboard import app as app_mod
    app_mod._world_cache.clear()
    # Each test starts with an empty replay-dedup cache so a fresh delivery
    # isn't mistaken for a replay of an earlier test's identical body.
    app_mod._issue_webhook_seen.clear()
    yield


@pytest.fixture
def _no_real_run(monkeypatch):
    """Stub the background runner so the route returns immediately."""
    import maverick.runner as runner_mod
    called = []

    def fake_run(
        goal_id, max_dollars=None, max_wall_seconds=None, max_depth=3, **_kwargs,
    ):
        called.append((goal_id, max_dollars))
        return "queued"

    monkeypatch.setattr(runner_mod, "run_goal_in_thread", fake_run)
    return called


@pytest.fixture
def _configured(monkeypatch):
    monkeypatch.setenv("MAVERICK_LINEAR_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("MAVERICK_JIRA_WEBHOOK_SECRET", JIRA_SECRET)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.setenv("MAVERICK_BOT_LINEAR_ID", LINEAR_BOT)
    monkeypatch.setenv("MAVERICK_BOT_JIRA_ACCOUNT_ID", JIRA_BOT)


def _linear_assigned(assignee_id=LINEAR_BOT):
    return {
        "type": "Issue",
        "action": "update",
        # Linear stamps each delivery; the receiver age-checks it (anti-replay).
        "webhookTimestamp": int(time.time() * 1000),
        # An assignment transition carries the prior assignee in updatedFrom;
        # the receiver requires it so a non-assignment edit can't re-fire a goal.
        "updatedFrom": {"assigneeId": None},
        "data": {
            "id": "uuid-1",
            "identifier": "ENG-123",
            "title": "Fix the login bug",
            "description": "Users can't log in on Safari.",
            "assigneeId": assignee_id,
            "assignee": {"id": assignee_id, "email": "bot@example.com"},
        },
    }


def _jira_assigned(account_id=JIRA_BOT):
    return {
        "webhookEvent": "jira:issue_updated",
        # Jira stamps each delivery; the receiver age-checks it (anti-replay).
        "timestamp": int(time.time() * 1000),
        # An assignment transition lists the assignee in changelog.items; the
        # receiver requires it so a non-assignment edit can't re-fire a goal.
        "changelog": {"items": [{"field": "assignee", "to": account_id}]},
        "issue": {
            "key": "PROJ-7",
            "fields": {
                "summary": "Add a retry to the uploader",
                "description": {
                    "type": "doc", "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": "Uploads fail under load."}],
                    }],
                },
                "assignee": {"accountId": account_id, "emailAddress": "bot@example.com"},
            },
        },
    }


# ----- Linear -----

def test_linear_valid_signature_assigned_to_bot_creates_goal(_configured, _no_real_run):
    body = json.dumps(_linear_assigned()).encode()
    resp = client.post(
        "/webhook/linear", content=body,
        headers={"Linear-Signature": _sign(body)},
    )
    assert resp.status_code == 201
    goal_id = resp.json()["goal_id"]
    assert isinstance(goal_id, int)
    assert len(_no_real_run) == 1 and _no_real_run[0][0] == goal_id

    # The goal row really landed in the world model with the issue content.
    from maverick.world_model import DEFAULT_DB, WorldModel
    g = WorldModel(DEFAULT_DB).get_goal(goal_id)
    assert g is not None
    assert g.status == "pending"
    assert "ENG-123" in g.title
    assert "Fix the login bug" in g.title
    assert "Users can't log in on Safari." in g.description


def test_linear_invalid_signature_rejected(_configured, _no_real_run):
    body = json.dumps(_linear_assigned()).encode()
    resp = client.post(
        "/webhook/linear", content=body,
        headers={"Linear-Signature": "deadbeef"},
    )
    assert resp.status_code == 403
    assert _no_real_run == []


def test_linear_assigned_to_someone_else_ignored(_configured, _no_real_run):
    body = json.dumps(_linear_assigned(assignee_id="some-other-human")).encode()
    resp = client.post(
        "/webhook/linear", content=body,
        headers={"Linear-Signature": _sign(body)},
    )
    assert resp.status_code == 200
    assert resp.json()["ignored"] is True
    assert _no_real_run == []


def test_linear_non_assign_event_ignored(_configured, _no_real_run):
    # A comment event (wrong type) must not spawn a goal even when signed.
    payload = {"type": "Comment", "action": "create", "data": {"id": "c1"}}
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook/linear", content=body,
        headers={"Linear-Signature": _sign(body)},
    )
    assert resp.status_code == 200
    assert resp.json()["ignored"] is True
    assert _no_real_run == []


def test_linear_missing_bot_id_fails_closed(monkeypatch, _no_real_run):
    monkeypatch.setenv("MAVERICK_LINEAR_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.delenv("MAVERICK_BOT_LINEAR_ID", raising=False)

    body = json.dumps(_linear_assigned(assignee_id="some-human")).encode()
    resp = client.post(
        "/webhook/linear", content=body,
        headers={"Linear-Signature": _sign(body)},
    )
    assert resp.status_code == 200
    assert resp.json()["ignored"] is True
    assert _no_real_run == []


def test_linear_rejects_control_secret_reuse(monkeypatch, _no_real_run):
    monkeypatch.setenv("MAVERICK_LINEAR_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("MAVERICK_INBOUND_WEBHOOK_SECRET", SECRET)
    body = json.dumps(_linear_assigned()).encode()
    resp = client.post("/webhook/linear", content=body,
                       headers={"Linear-Signature": _sign(body)})
    assert resp.status_code == 401
    assert not _no_real_run


# ----- Jira -----

def test_jira_valid_signature_assigned_to_bot_creates_goal(_configured, _no_real_run):
    body = json.dumps(_jira_assigned()).encode()
    resp = client.post(
        "/webhook/jira", content=body,
        headers={"X-Hub-Signature": "sha256=" + _sign(body, JIRA_SECRET)},
    )
    assert resp.status_code == 201
    goal_id = resp.json()["goal_id"]
    assert isinstance(goal_id, int)
    assert len(_no_real_run) == 1 and _no_real_run[0][0] == goal_id

    from maverick.world_model import DEFAULT_DB, WorldModel
    g = WorldModel(DEFAULT_DB).get_goal(goal_id)
    assert g is not None
    assert g.status == "pending"
    assert "PROJ-7" in g.title
    assert "Add a retry to the uploader" in g.title
    assert "Uploads fail under load." in g.description


def test_jira_invalid_signature_rejected(_configured, _no_real_run):
    body = json.dumps(_jira_assigned()).encode()
    resp = client.post(
        "/webhook/jira", content=body,
        headers={"X-Hub-Signature": "sha256=deadbeef"},
    )
    assert resp.status_code == 403
    assert _no_real_run == []


def test_jira_assigned_to_someone_else_ignored(_configured, _no_real_run):
    body = json.dumps(_jira_assigned(account_id="other-human")).encode()
    resp = client.post(
        "/webhook/jira", content=body,
        headers={"X-Hub-Signature": "sha256=" + _sign(body, JIRA_SECRET)},
    )
    assert resp.status_code == 200
    assert resp.json()["ignored"] is True
    assert _no_real_run == []


def test_jira_missing_bot_id_fails_closed(monkeypatch, _no_real_run):
    monkeypatch.setenv("MAVERICK_JIRA_WEBHOOK_SECRET", JIRA_SECRET)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.delenv("MAVERICK_BOT_JIRA_ACCOUNT_ID", raising=False)

    body = json.dumps(_jira_assigned(account_id="some-human")).encode()
    resp = client.post(
        "/webhook/jira", content=body,
        headers={"X-Hub-Signature": "sha256=" + _sign(body, JIRA_SECRET)},
    )
    assert resp.status_code == 200
    assert resp.json()["ignored"] is True
    assert _no_real_run == []


# ----- shared auth -----

def test_no_secret_configured_fails_closed(monkeypatch, _no_real_run):
    monkeypatch.delenv("MAVERICK_LINEAR_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    import maverick.webhooks as wh
    monkeypatch.setattr(wh, "_load_config_outbound", lambda: ([], None))

    body = json.dumps(_linear_assigned()).encode()
    resp = client.post(
        "/webhook/linear", content=body,
        headers={"Linear-Signature": _sign(body)},
    )
    assert resp.status_code == 401
    assert _no_real_run == []


def test_linear_oversized_content_length_rejected_before_signature_check(
    _configured, _no_real_run, monkeypatch,
):
    import maverick.issue_webhooks as iw
    from maverick_dashboard import app as app_mod

    def fail_verify(*args, **kwargs):
        raise AssertionError("signature verification should not run for oversized bodies")

    monkeypatch.setattr(iw, "verify_signature", fail_verify)
    body = b"x" * (app_mod._MAX_WEBHOOK_BODY_BYTES + 1)
    resp = client.post(
        "/webhook/linear",
        content=body,
        headers={"Linear-Signature": "invalid"},
    )
    assert resp.status_code == 413
    assert _no_real_run == []


# ----- replay defence (parity with /webhook/start) -----

def test_linear_stale_event_rejected(_configured, _no_real_run):
    # A correctly-signed but old delivery (captured + replayed later) is refused
    # by the freshness check before it can re-spawn a paid goal.
    payload = _linear_assigned()
    payload["webhookTimestamp"] = int((time.time() - 10_000) * 1000)
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook/linear", content=body,
        headers={"Linear-Signature": _sign(body)},
    )
    assert resp.status_code == 403
    assert _no_real_run == []


def test_jira_undated_event_rejected(_configured, _no_real_run):
    # No timestamp -> freshness can't be proven -> fail closed (a replayer can't
    # add one without breaking the signed body, so real events are unaffected).
    payload = _jira_assigned()
    payload.pop("timestamp", None)
    body = json.dumps(payload).encode()
    resp = client.post(
        "/webhook/jira", content=body,
        headers={"X-Hub-Signature": "sha256=" + _sign(body, JIRA_SECRET)},
    )
    assert resp.status_code == 403
    assert _no_real_run == []


def test_linear_duplicate_delivery_rejected(_configured, _no_real_run):
    # First delivery spawns a goal (201); the identical replayed POST within the
    # window is a duplicate (409) and must not drive the swarm a second time.
    body = json.dumps(_linear_assigned()).encode()
    headers = {"Linear-Signature": _sign(body)}
    first = client.post("/webhook/linear", content=body, headers=headers)
    assert first.status_code == 201
    second = client.post("/webhook/linear", content=body, headers=headers)
    assert second.status_code == 409
    assert len(_no_real_run) == 1


def test_refused_delivery_can_be_retried(monkeypatch, _no_real_run):
    # A delivery refused before any work started (no provider yet) must not be
    # remembered as delivered: the sender's retry spawns the goal, and only a
    # delivery that did start work is then refused as a duplicate.
    monkeypatch.setenv("MAVERICK_LINEAR_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("MAVERICK_BOT_LINEAR_ID", LINEAR_BOT)
    import maverick_dashboard.app as app_mod

    def no_provider():
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="no model provider is configured")

    monkeypatch.setattr(app_mod, "require_provider_or_400", no_provider)
    body = json.dumps(_linear_assigned()).encode()
    headers = {"Linear-Signature": _sign(body)}
    assert client.post("/webhook/linear", content=body, headers=headers).status_code == 400
    assert _no_real_run == []

    monkeypatch.setattr(app_mod, "require_provider_or_400", lambda: None)
    retry = client.post("/webhook/linear", content=body, headers=headers)
    assert retry.status_code == 201, retry.text
    assert len(_no_real_run) == 1
    assert client.post("/webhook/linear", content=body, headers=headers).status_code == 409


def test_linear_duplicate_delivery_rejected_with_prefixed_variant(_configured, _no_real_run):
    # Replay dedup must key on the canonical digest that verification accepts,
    # not the raw header string, or a captured bare Linear signature can be
    # replayed as an equivalent sha256=<digest> header within the fresh window.
    body = json.dumps(_linear_assigned()).encode()
    digest = _sign(body)
    first = client.post(
        "/webhook/linear",
        content=body,
        headers={"Linear-Signature": digest},
    )
    assert first.status_code == 201
    second = client.post(
        "/webhook/linear",
        content=body,
        headers={"Linear-Signature": "sha256=" + digest},
    )
    assert second.status_code == 409
    assert len(_no_real_run) == 1


def test_jira_duplicate_delivery_rejected_with_bare_variant(_configured, _no_real_run):
    # Same bypass in the opposite direction for Jira: a prefixed signature and
    # its bare digest form are the same verified delivery.
    body = json.dumps(_jira_assigned()).encode()
    digest = _sign(body, JIRA_SECRET)
    first = client.post(
        "/webhook/jira",
        content=body,
        headers={"X-Hub-Signature": "sha256=" + digest},
    )
    assert first.status_code == 201
    second = client.post(
        "/webhook/jira",
        content=body,
        headers={"X-Hub-Signature": digest},
    )
    assert second.status_code == 409
    assert len(_no_real_run) == 1


# ---- GitLab (X-Gitlab-Token + X-Gitlab-Event-UUID) --------------------------

GITLAB_TOKEN = "gitlab-shared-token"
GITLAB_BOT = "maverick-bot"


def _gitlab_payload(assignee=GITLAB_BOT, action="open"):
    # Opening an issue assigned to the bot is its first assignment; an update
    # starts work only with evidence that the bot was newly assigned.
    return {
        "object_kind": "issue",
        "event_type": "issue",
        "object_attributes": {
            "iid": 42,
            "title": "Fix the flaky login test",
            "description": "It fails on retry.",
            "action": action,
        },
        "assignees": [{"username": assignee}],
        "project": {"path_with_namespace": "group/repo"},
    }


@pytest.fixture
def _gitlab_configured(monkeypatch):
    monkeypatch.setenv("MAVERICK_GITLAB_WEBHOOK_TOKEN", GITLAB_TOKEN)
    monkeypatch.setenv("MAVERICK_BOT_GITLAB_USERNAME", GITLAB_BOT)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")


def _post_gitlab(payload, token=GITLAB_TOKEN, uuid="uuid-1"):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Gitlab-Token"] = token
    if uuid is not None:
        headers["X-Gitlab-Event-UUID"] = uuid
    return client.post("/webhook/gitlab", content=json.dumps(payload).encode(),
                       headers=headers)


def test_gitlab_assigned_creates_goal(_gitlab_configured, _no_real_run):
    r = _post_gitlab(_gitlab_payload())
    assert r.status_code == 201, r.text
    goal_id = r.json()["goal_id"]
    from maverick_dashboard.app import _world
    g = _world().get_goal(goal_id)
    assert g is not None and "group/repo#42" in g.title
    assert _no_real_run and _no_real_run[0][0] == goal_id


def test_gitlab_bad_token_403(_gitlab_configured, _no_real_run):
    assert _post_gitlab(_gitlab_payload(), token="wrong").status_code == 403


def test_gitlab_unconfigured_401(monkeypatch, _no_real_run):
    monkeypatch.delenv("MAVERICK_GITLAB_WEBHOOK_TOKEN", raising=False)
    assert _post_gitlab(_gitlab_payload()).status_code == 401


def test_gitlab_assigned_to_someone_else_ignored(_gitlab_configured, _no_real_run):
    r = _post_gitlab(_gitlab_payload(assignee="someone-else"))
    assert r.status_code == 200 and r.json() == {"ignored": True}
    assert not _no_real_run


def test_gitlab_missing_uuid_403(_gitlab_configured, _no_real_run):
    assert _post_gitlab(_gitlab_payload(), uuid=None).status_code == 403


def test_gitlab_duplicate_uuid_409(_gitlab_configured, _no_real_run):
    assert _post_gitlab(_gitlab_payload(), uuid="dup-1").status_code == 201
    assert _post_gitlab(_gitlab_payload(), uuid="dup-1").status_code == 409


def test_gitlab_close_event_ignored(_gitlab_configured, _no_real_run):
    r = _post_gitlab(_gitlab_payload(action="close"))
    assert r.status_code == 200 and r.json() == {"ignored": True}
