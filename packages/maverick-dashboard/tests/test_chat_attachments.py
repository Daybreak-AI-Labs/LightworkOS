"""Chat composer file uploads flow into a goal's attachments."""
from __future__ import annotations

from fastapi.testclient import TestClient

_ORIGIN = {"origin": "http://127.0.0.1"}


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _prep(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # a provider is configured
    # Keep attachment bytes + the goal run inside the test sandbox.
    import maverick.attachments as att
    monkeypatch.setattr(att, "DEFAULT_ROOT", tmp_path / "attachments")
    monkeypatch.setattr("maverick.runner.run_goal_in_thread", lambda *a, **k: None)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_chat_send_stores_attachment(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post(
        "/chat/send",
        data={"title": "summarize this", "description": ""},
        files={"files": ("notes.txt", b"hello world", "text/plain")},
        headers=_ORIGIN, follow_redirects=False,
    )
    assert r.status_code == 303
    from maverick_dashboard import app as dash
    g = dash._world().list_goals()[-1]
    atts = dash._world().list_attachments(g.id)
    assert [a.filename for a in atts] == ["notes.txt"]
    assert atts[0].size_bytes == len(b"hello world")


def test_chat_send_empty_file_input_still_works(monkeypatch, tmp_path):
    """An unfilled file input posts an empty part (filename="") — this must not
    400 a normal, attachment-less goal. Posts the exact multipart a browser sends."""
    _prep(monkeypatch, tmp_path)
    b = "X7X7boundary"
    body = (
        f'--{b}\r\nContent-Disposition: form-data; name="title"\r\n\r\nno file here\r\n'
        f'--{b}\r\nContent-Disposition: form-data; name="files"; filename=""\r\n'
        f'Content-Type: application/octet-stream\r\n\r\n\r\n'
        f'--{b}--\r\n'
    ).encode()
    r = _client().post(
        "/chat/send", content=body, follow_redirects=False,
        headers={"origin": "http://127.0.0.1",
                 "content-type": f"multipart/form-data; boundary={b}"},
    )
    assert r.status_code == 303
    from maverick_dashboard import app as dash
    g = dash._world().list_goals()[-1]
    assert dash._world().list_attachments(g.id) == []


def test_chat_send_rejects_disallowed_type(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post(
        "/chat/send",
        data={"title": "bad upload", "description": ""},
        files={"files": ("evil.exe", b"MZ\x90\x00", "application/x-msdownload")},
        headers=_ORIGIN, follow_redirects=False,
    )
    assert r.status_code == 400
    assert "Attachment" in r.json()["detail"]


def test_chat_page_has_attach_control(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/chat")
    assert r.status_code == 200
    assert 'name="files"' in r.text
    assert 'id="attach-btn"' in r.text
    assert (
        'id="attach-input" multiple aria-label="Attach files to this task" '
        'tabindex="-1"'
    ) in r.text
    assert 'enctype="multipart/form-data"' in r.text


def test_chat_pages_read_plainly_and_offer_a_menu_on_small_screens(monkeypatch, tmp_path):
    from test_support.plain_language import developer_terms

    _prep(monkeypatch, tmp_path)
    r = _client().get("/chat")
    assert developer_terms(r.text) == []
    assert 'id="cs-menu" aria-controls="cs-side"' in r.text
    assert 'aria-label="Start task"' in r.text and "Run this task" not in r.text
    assert "transcribe failed" not in r.text


def test_chat_searches_published_specialists_instead_of_shipping_the_roster(monkeypatch, tmp_path):
    import re

    _prep(monkeypatch, tmp_path)
    client = _client()
    page = client.get("/chat").text
    picker = page.split('id="chat-specialist"', 1)[1].split("</select>", 1)[0]
    # Only "Let Lightwork choose the team" is shipped; the roster is searched.
    assert picker.count("<option") == 1
    assert 'id="chat-specialist-search"' in page and "Find a specialist" in page
    context = re.search(r'name="specialist_context" value="([^"]*)"', page).group(1)
    found = client.get("/api/v1/chat/specialists", params={"q": "invoice", "limit": 5})
    assert found.status_code == 200 and found.headers["cache-control"].startswith("no-store")
    body = found.json()
    assert body["context"] == context and 0 < len(body["items"]) <= 5 and body["total"] >= len(body["items"])
    assert all(set(item) == {"value", "label", "revision"} for item in body["items"])
    assert all("invoice" in (item["label"] + item["value"]).casefold() for item in body["items"])
    assert client.get("/api/v1/chat/specialists", params={"limit": 51}).status_code == 422



def test_chat_digests_only_the_specialists_it_ships(monkeypatch, tmp_path):
    """Each revision digests a whole specialist definition: /chat digested all
    2,031 (about 93 ms of every open) to ship at most two, and each search
    digested every match to return one page."""
    import re

    from maverick import governed_operations
    from maverick.domain import enabled_domains
    from maverick.governed_operations import dataclass_digest
    from maverick_dashboard import product_operations_task_launch as launch

    _prep(monkeypatch, tmp_path)
    client = _client()
    name = sorted(enabled_domains())[7]
    digests = []
    real = governed_operations.dataclass_digest

    def counting(value):
        digests.append(value)
        return real(value)

    monkeypatch.setattr(launch, "dataclass_digest", counting)
    monkeypatch.setattr(governed_operations, "dataclass_digest", counting)
    page = client.get("/chat", params={"specialist": name}).text
    assert len(digests) <= 2
    picker = page.split('id="chat-specialist"', 1)[1].split("</select>", 1)[0]
    option = re.search(rf'<option value="{name}" data-revision="([0-9a-f]+)"', picker)
    assert option and option.group(1) == real(enabled_domains()[name])
    digests.clear()
    body = client.get("/api/v1/chat/specialists", params={"q": "invoice", "limit": 5}).json()
    assert len(digests) == len(body["items"]) <= 5
    profiles = enabled_domains()
    assert all(item["revision"] == dataclass_digest(profiles[item["value"]]) for item in body["items"])


def _failing_publication(monkeypatch):
    import maverick_dashboard.attachment_submission as submission

    def broken(world, goal_id, records):
        raise OSError("simulated storage failure")
    monkeypatch.setattr(submission, "publish_batch", broken)


def test_unsaved_files_say_what_happened_and_how_to_recover(monkeypatch, tmp_path, caplog):
    """Live: every chat task with a file failed with 'This cannot be done right
    now' and left a draft that could not be discarded. The real cause was
    swallowed. It is logged now, and the person reads what happened."""
    import logging

    _prep(monkeypatch, tmp_path)
    _failing_publication(monkeypatch)
    with caplog.at_level(logging.ERROR):
        r = _client().post("/chat/send", data={"title": "use the note"},
                           files={"files": ("QA-tiny.txt", b"code word", "text/plain")},
                           headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["code"] == "attachments_not_saved"
    assert "could not be saved" in detail["message"] and "nothing was spent" in detail["message"]
    from maverick_dashboard import app as dash
    goal = dash._world().list_goals()[-1]
    assert detail["next_action"] == {"label": "Open the saved draft", "href": f"/chat/goal/{goal.id}"}
    assert any("simulated storage failure" in (rec.exc_text or "") for rec in caplog.records)


def test_a_draft_whose_files_were_not_saved_can_be_discarded(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    _failing_publication(monkeypatch)
    client = _client()
    client.post("/chat/send", data={"title": "use the note"},
                files={"files": ("QA-tiny.txt", b"code word", "text/plain")},
                headers=_ORIGIN, follow_redirects=False)
    from maverick_dashboard import app as dash
    goal = dash._world().list_goals()[-1]
    assert goal.status == "draft"
    page = client.get(f"/chat/goal/{goal.id}").text
    assert 'id="discard-draft-btn"' in page and 'id="recover-submission-btn"' not in page
    assert "Your files were not saved" in page
    retry = client.post(f"/chat/goal/{goal.id}/recover-submission", headers=_ORIGIN, follow_redirects=False)
    assert retry.status_code == 409 and retry.json()["detail"]["code"] == "attachments_not_saved"
    gone = client.post(f"/chat/goal/{goal.id}/discard-draft", headers=_ORIGIN, follow_redirects=False)
    assert gone.status_code == 303 and gone.headers["location"] == "/chat"
    assert dash._world().get_goal(goal.id).status == "cancelled"
    assert client.post(f"/chat/goal/{goal.id}/discard-draft", headers=_ORIGIN,
                       follow_redirects=False).status_code == 409


def test_only_the_person_who_sent_a_draft_can_discard_it(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick_dashboard import app as dash
    goal_id = dash._world().create_goal("someone else's draft", "", owner="user:other")
    dash._world().set_goal_status(goal_id, "draft")
    r = _client().post(f"/chat/goal/{goal_id}/discard-draft", headers=_ORIGIN, follow_redirects=False)
    assert r.status_code in (403, 404)
    assert dash._world().get_goal(goal_id).status == "draft"
