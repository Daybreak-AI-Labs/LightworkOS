"""Share links end-to-end: create (operator), public read-only view (auth-exempt
token), and revoke. A bad/revoked/expired token 404s and leaks nothing."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _world(tmp_path, monkeypatch):
    from maverick import audit, config, world_model
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    return world_model.WorldModel(tmp_path / "world.db")


def _make_goal(w, *, approve=True):
    gid = w.create_goal("Refresh forecast", "", domain="finance_cash13w")
    w.set_goal_status(gid, "done", result="| Week | Net |\n| --- | --- |\n| W1 | 300 |")
    if approve:
        w.record_signoff(gid, "approved", decided_by="reviewer")
    return gid


def _create(goal_id, **changes):
    preview = client.post(f"/api/v1/goals/{goal_id}/share/preview")
    if preview.status_code != 200:
        return preview
    payload = {"confirm": True, "source_sha256": preview.json()["source"]["sha256"],
               "lifetime_seconds": 3600, "label": "Forecast review"}
    payload.update(changes)
    return client.post(f"/api/v1/goals/{goal_id}/share", json=payload)


def test_create_and_view_then_revoke(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = _make_goal(w)
    # create (operator in auth-off mode owns this unowned task)
    r = _create(gid)
    assert r.status_code == 201, r.text
    body = r.json()
    assert "/share/" in body["url"]
    token = body["url"].split("/share/")[1]

    # public view works WITHOUT auth headers (the token is the credential)
    anon = TestClient(app, base_url="http://127.0.0.1")  # no Origin / no bearer
    page = anon.get(f"/share/{token}")
    assert page.status_code == 200
    assert "Refresh forecast" in page.text
    assert "<td>300</td>" in page.text          # deliverable rendered
    assert "shared for reading only" in page.text.lower()

    # revoke -> the link dies
    rev = client.post(f"/api/v1/goals/{gid}/share/{body['id']}/revoke")
    assert rev.status_code == 200 and rev.json()["ok"] is True
    assert anon.get(f"/share/{token}").status_code == 404


def test_bad_token_404(tmp_path, monkeypatch):
    _world(tmp_path, monkeypatch)
    assert TestClient(app, base_url="http://127.0.0.1").get("/share/not-a-real-token").status_code == 404


def test_empty_finished_answer_cannot_be_shared(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("No answer yet", "")
    w.set_goal_status(gid, "done", result="")
    assert _create(gid).status_code == 409
    _, token = w.create_share_link(gid, created_by="operator")
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404


def test_existing_token_fails_closed_when_domain_policy_is_missing(
    tmp_path, monkeypatch,
):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("orphaned", "", domain="removed_pack")
    w.set_goal_status(gid, "done", result="must stay private")
    _, token = w.create_share_link(gid, created_by="operator")

    page = TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}")

    assert page.status_code == 404
    assert "must stay private" not in page.text


def test_gated_share_requires_current_approval(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = _make_goal(w, approve=False)
    assert _create(gid).status_code == 409

    w.record_signoff(gid, "approved", decided_by="reviewer")
    created = _create(gid)
    assert created.status_code == 201
    token = created.json()["url"].split("/share/")[1]
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 200

    # A later edit atomically revokes the approval. Existing copied tokens are
    # checked again at view time, so they cannot expose the replacement bytes.
    w.set_goal_status(gid, "done", result="replacement")
    assert w.signoff_for(gid) is None
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404
    assert _create(gid).status_code == 409


def test_share_section_on_goal_page(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = _make_goal(w)
    t = client.get(f"/chat/goal/{gid}").text
    assert "share-create" in t and "Review share link" in t


def test_revoke_is_goal_scoped(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    g1 = _make_goal(w)
    g2 = _make_goal(w)
    token = _create(g1).json()["url"].split("/share/")[1]
    lid = w.share_links_for_goal(g1)[0]["id"]
    # try to revoke g1's link via g2's path -> no-op, link stays live
    client.post(f"/api/v1/goals/{g2}/share/{lid}/revoke")
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 200


def test_foreign_operator_with_task_access_cannot_revoke_owner_link(tmp_path, monkeypatch):
    from maverick_dashboard import api

    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("Owner's approved result", "", owner="user:alice")
    w.set_goal_status(gid, "done", result="Shared answer")
    link_id, token = w.create_share_link(gid, created_by="user:alice")
    # Simulate a collaborator allowed to see this task and operate generally.
    # Task access alone must not grant authority over its public release.
    monkeypatch.setattr(api, "assert_goal_access", lambda request, goal: None)
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:bob")

    response = client.post(f"/api/v1/goals/{gid}/share/{link_id}/revoke")

    assert response.status_code == 403
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 200


def test_preview_does_not_mint_and_changed_result_requires_a_new_preview(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = _make_goal(w)
    preview = client.post(f"/api/v1/goals/{gid}/share/preview")
    assert preview.status_code == 200
    assert not w.share_links_for_goal(gid)
    w.set_goal_status(gid, "done", result="A changed release")
    w.record_signoff(gid, "approved", decided_by="reviewer")
    response = client.post(f"/api/v1/goals/{gid}/share", json={"confirm": True,
        "source_sha256": preview.json()["source"]["sha256"], "lifetime_seconds": 3600, "label": "Review"})
    assert response.status_code == 409
    assert not w.share_links_for_goal(gid)


def test_explicit_confirmation_and_policy_lifetime_are_required(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = _make_goal(w)
    assert _create(gid, confirm=False).status_code == 409
    assert _create(gid, lifetime_seconds=900000).status_code == 422
    assert not w.share_links_for_goal(gid)


def test_new_link_does_not_release_changed_ungated_content(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("Private draft", "")
    w.set_goal_status(gid, "done", result="Reviewed bytes")
    response = _create(gid)
    assert response.status_code == 201
    token = response.json()["url"].split("/share/")[1]
    w.set_goal_status(gid, "done", result="Unreviewed replacement")
    assert TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").status_code == 404
    listing = client.get(f"/api/v1/goals/{gid}/share").json()["links"]
    assert listing[0]["label"] == "Forecast review"
    assert listing[0]["state"] == "source changed"
