"""Video walkthroughs: artifact listing, media serving, and the export
endpoint over the real replay-to-MP4 machinery (render itself is stubbed —
the encode needs Pillow + ffmpeg and is covered by core's replay tests)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    return tmp_path / "mvhome"


@pytest.fixture
def world(home, tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    w = world_model.WorldModel(tmp_path / "world.db")
    yield w
    w.close()


@pytest.fixture
def client(world, monkeypatch):
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod
    monkeypatch.setattr(app_mod, "_world", lambda: world)
    monkeypatch.setattr(api_mod, "_world", lambda: world)
    return TestClient(app_mod.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_empty_state_is_honest(client, home):
    r = client.get("/walkthroughs")
    assert r.status_code == 200
    assert "No walkthroughs yet" in r.text
    # the real export path, but never a server folder path on the page
    assert "/api/v1/goals/" in r.text and "/walkthrough" in r.text
    assert str(home / "walkthroughs") not in r.text
    # no finished tasks yet: the next step is a button, not a number field
    assert 'href="/chat"' in r.text
    assert 'type="number"' not in r.text
    # no fake thumbnails / placeholder videos
    assert "<video" not in r.text


def test_page_lists_artifacts_with_video_and_captions(client, world, home):
    d = home / "walkthroughs"
    d.mkdir(parents=True)
    world.create_goal("exported", "")  # goal id 1
    world.set_goal_status(1, "done")
    for _ in range(6):
        world.create_goal("padding", "")
    (d / "goal-7.mp4").write_bytes(b"\x00\x00fake")
    (d / "goal-7.vtt").write_text("WEBVTT\n")
    (d / "freeform.mp4").write_bytes(b"\x00")  # non goal-N name: never served
    r = client.get("/walkthroughs")
    assert r.status_code == 200
    assert "<video controls" in r.text
    assert 'src="/walkthroughs/media/goal-7.mp4"' in r.text
    assert '<track kind="captions" src="/walkthroughs/media/goal-7.vtt"' in r.text
    # goal-N names link to the run's tutorial export
    assert "/api/v1/goals/7/tutorial.md" in r.text
    # finished tasks are picked from a list
    assert '<select class="select" id="wt-goal-id" required>' in r.text
    assert '<option value="1" data-has-video="0">exported (done)' in r.text
    assert "· goal-7.mp4" not in r.text  # titled by task, not by file name
    assert 'src="/walkthroughs/media/freeform.mp4"' not in r.text


def test_media_route_serves_and_guards(client, world, home):
    d = home / "walkthroughs"
    d.mkdir(parents=True)
    for _ in range(3):
        world.create_goal("walkthrough", "")
    (d / "goal-3.mp4").write_bytes(b"MP4DATA")
    (d / "goal-3.vtt").write_text("WEBVTT\n")
    (home / "secret.txt").write_text("nope")

    r = client.get("/walkthroughs/media/goal-3.mp4")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("video/mp4")
    assert r.content == b"MP4DATA"
    r = client.get("/walkthroughs/media/goal-3.vtt")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/vtt")
    # unknown artifact
    assert client.get("/walkthroughs/media/goal-99.mp4").status_code == 404
    # %2f-encoded traversal never matches the route (the path param cannot
    # span "/"), and names that do reach the handler are pattern-gated.
    assert client.get("/walkthroughs/media/..%2fsecret.txt").status_code == 404
    assert client.get("/walkthroughs/media/secret.txt").status_code == 400
    assert client.get("/walkthroughs/media/..mp4").status_code in (400, 404)


def test_walkthroughs_hide_cross_user_artifacts(client, world, home, monkeypatch):
    import maverick_dashboard.auth as auth
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import rbac

    rbac.set_role("user:bob", "operator")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth,
        "verify_oidc_token",
        lambda token, **_kw: VerifiedPrincipal(
            sub=token, issuer="https://issuer.example", audience="maverick",
            claims={"sub": token},
        ),
    )
    alice = world.create_goal("alice private", owner="user:alice")
    bob = world.create_goal("bob visible", owner="user:bob")
    d = home / "walkthroughs"
    d.mkdir(parents=True)
    (d / f"goal-{alice}.mp4").write_bytes(b"alice video")
    (d / f"goal-{alice}.vtt").write_text("WEBVTT\nalice secret\n")
    (d / f"goal-{bob}.mp4").write_bytes(b"bob video")

    headers = {"Authorization": "Bearer bob"}
    page = client.get("/walkthroughs", headers=headers)
    assert page.status_code == 200
    assert f"goal-{bob}.mp4" in page.text
    assert f"goal-{alice}.mp4" not in page.text
    assert client.get(f"/walkthroughs/media/goal-{bob}.mp4", headers=headers).status_code == 200
    assert client.get(f"/walkthroughs/media/goal-{alice}.mp4", headers=headers).status_code == 404
    assert client.get(f"/walkthroughs/media/goal-{alice}.vtt", headers=headers).status_code == 404


def test_export_missing_goal_404(client):
    r = client.post("/api/v1/goals/99999/walkthrough")
    assert r.status_code == 404


def test_export_without_events_400(client, world):
    gid = world.create_goal("never ran", "")
    r = client.post(f"/api/v1/goals/{gid}/walkthrough")
    assert r.status_code == 400
    assert "no events recorded" in r.json()["detail"]


@pytest.fixture
def render_stub(monkeypatch):
    """Stub maverick.replay.video.render (the encode half needs ffmpeg)."""
    from maverick.replay import video as replay_video
    calls = []

    def fake_render(goal_id, out_path, *, sandbox=None, events=None, fps=25):
        out_path.write_bytes(b"\x00fakemp4")
        calls.append({"goal_id": goal_id, "out_path": out_path,
                      "events": events})
        return SimpleNamespace(
            frames=len(events or []), frame_dir=out_path.parent,
            concat_path=out_path.parent / "frames.ffconcat",
            command=["ffmpeg", "-y"], encoded=True, detail="stub encode",
        )

    monkeypatch.setattr(replay_video, "render", fake_render)
    return calls


def test_export_writes_video_and_captions(client, world, home, render_stub):
    gid = world.create_goal("ran fine", "")
    world.append_event(gid, "planner", "plan", "step one then step two")
    world.append_event(gid, "worker", "observation", "did the thing")
    r = client.post(f"/api/v1/goals/{gid}/walkthrough")
    assert r.status_code == 201
    body = r.json()
    assert body["encoded"] is True
    assert body["frames"] == 2
    assert body["video"] == f"goal-{gid}.mp4"
    assert body["captions"] == f"goal-{gid}.vtt"
    # render got the run's real events, into the walkthroughs dir
    assert render_stub[0]["out_path"] == home / "walkthroughs" / f"goal-{gid}.mp4"
    assert [e["kind"] for e in render_stub[0]["events"]] == ["plan", "observation"]
    # the captions track is real WebVTT derived from the storyboard
    vtt = (home / "walkthroughs" / f"goal-{gid}.vtt").read_text()
    assert vtt.startswith("WEBVTT")
    assert "-->" in vtt
    assert "00:00:00.000" in vtt
    # the page now lists it
    page = client.get("/walkthroughs").text
    assert f'src="/walkthroughs/media/goal-{gid}.mp4"' in page


def test_export_reports_unencoded_honestly(client, world, monkeypatch):
    """No Pillow/ffmpeg -> encoded=false, no video name, command included."""
    from maverick.replay import video as replay_video
    def fake_render(goal_id, out_path, *, sandbox=None, events=None, fps=25):
        return SimpleNamespace(
            frames=len(events or []), frame_dir=out_path.parent,
            concat_path=out_path.parent / "frames.ffconcat",
            command=["ffmpeg", "-y", "out.mp4"], encoded=False,
            detail="Pillow not installed; wrote frame manifest",
        )
    monkeypatch.setattr(replay_video, "render", fake_render)
    gid = world.create_goal("ran", "")
    world.append_event(gid, "a", "plan", "x")
    body = client.post(f"/api/v1/goals/{gid}/walkthrough").json()
    assert body["encoded"] is False
    assert body["video"] is None
    assert body["ffmpeg_command"][0] == "ffmpeg"
    assert "Pillow" in body["detail"]


def test_workspace_walkthroughs_do_not_cross_read_or_overwrite(
    client, world, home, render_stub, monkeypatch
):
    gid = world.create_goal("same task id", "")
    world.append_event(gid, "worker", "observation", "workspace A content")
    monkeypatch.setenv("MAVERICK_TENANT", "workspace-a")
    assert client.post(f"/api/v1/goals/{gid}/walkthrough").status_code == 201
    a = home / "tenants" / "workspace-a" / "walkthroughs"
    original = (a / f"goal-{gid}.vtt").read_text()
    assert "workspace A content" in original
    assert client.get(f"/walkthroughs/media/goal-{gid}.vtt").text == original

    from maverick.world_model import WorldModel
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod

    other = WorldModel(home / "other-world.db")
    monkeypatch.setattr(api_mod, "_world", lambda: other)
    monkeypatch.setattr(app_mod, "_world", lambda: other)
    assert other.create_goal("other workspace task", "") == gid
    other.append_event(gid, "worker", "observation", "workspace B content")
    monkeypatch.setenv("MAVERICK_TENANT", "workspace-b")
    assert client.get(f"/walkthroughs/media/goal-{gid}.vtt").status_code == 404
    assert client.get(f"/walkthroughs/media/goal-{gid}.mp4").status_code == 404
    assert f"goal-{gid}.mp4" not in client.get("/walkthroughs").text
    assert client.post(f"/api/v1/goals/{gid}/walkthrough").status_code == 201
    b = home / "tenants" / "workspace-b" / "walkthroughs"
    assert render_stub[-1]["out_path"] == b / f"goal-{gid}.mp4"
    assert (a / f"goal-{gid}.vtt").read_text() == original
    response = client.get(f"/walkthroughs/media/goal-{gid}.vtt")
    assert response.status_code == 200
    assert "workspace B content" in response.text
    assert "workspace A content" not in response.text
    other.close()
