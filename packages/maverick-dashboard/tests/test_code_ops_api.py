"""Code page: download a copy (``maverick code export``) and watch a code
project for notes to Lightwork (``maverick watch``), over a real vault."""
from __future__ import annotations

import io
import shutil
import subprocess
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True, "default_protect": "block"})
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()
    try:
        yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    finally:
        from maverick_dashboard import code_ops_api
        code_ops_api.stop_watchers(timeout=5)
        code_ops_api._watchers.clear()
        config.reset_config_cache()
        audit_writer._default = None
        audit_writer._defaults.clear()
        dash_app._world_cache.clear()


def _as(monkeypatch, role: str) -> None:
    from maverick_dashboard import auth, rbac
    rbac.set_role(f"user:{role}1", role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: f"user:{role}1")


def _audit(monkeypatch) -> list[str]:
    from maverick.audit import writer
    seen: list[str] = []
    real = writer.audit_event

    def spy(kind, **payload):
        if payload.get("verb"):
            seen.append(payload["verb"])
        return real(kind, **payload)
    monkeypatch.setattr(writer, "audit_event", spy)
    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


def _git(*args, cwd):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True,
                   capture_output=True)


@pytest.fixture
def project(tmp_path, client):
    src = tmp_path / "src"
    src.mkdir()
    _git("init", "-q", "-b", "main", cwd=src)
    (src / "app.py").write_text("def total(xs):\n    # AI: add input validation for empty lists\n"
                                "    return sum(xs)\n")
    (src / "notes.md").write_text("# AI: this file type is not scanned\n")
    _git("add", "-A", cwd=src)
    _git("commit", "-q", "-m", "init", cwd=src)
    from maverick.codebase import vault
    vault.register("website", str(src))
    return src


# ---- download a copy (code export) ---------------------------------------------

def test_download_is_confirmed_recorded_and_contains_the_project(client, monkeypatch, project):
    assert client.post("/api/v1/code/repos/website/export", json={}).status_code == 422
    assert client.post("/api/v1/code/repos/nope/export", json={"confirm": True}).status_code == 404
    seen = _audit(monkeypatch)
    r = client.post("/api/v1/code/repos/website/export", json={"confirm": True})
    assert r.status_code == 200, r.text
    assert 'filename="website-copy.zip"' in r.headers["content-disposition"]
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert "website/app.py" in zf.namelist()
    assert "AI: add input validation" in zf.read("website/app.py").decode()
    assert seen == ["code_export"]


def test_download_removes_the_plaintext_temporary_copy(client, monkeypatch, project):
    from pathlib import Path

    from maverick_dashboard import code_ops_api

    exported = []
    original = code_ops_api._export

    def capture(name):
        path = original(name)
        exported.append(Path(path))
        return path

    monkeypatch.setattr(code_ops_api, "_export", capture)
    response = client.post("/api/v1/code/repos/website/export", json={"confirm": True})
    assert response.status_code == 200, response.text
    assert exported and not exported[0].exists() and not exported[0].parent.exists()


def test_download_refuses_oversized_projects(client, monkeypatch, project):
    from maverick_dashboard import code_ops_api
    monkeypatch.setattr(code_ops_api, "_MAX_EXPORT_BYTES", 10)
    r = client.post("/api/v1/code/repos/website/export", json={"confirm": True})
    assert r.status_code == 413 and "too large" in r.json()["detail"]


def test_code_routes_need_a_workspace_administrator(client, monkeypatch, project):
    _as(monkeypatch, "operator")
    assert client.post("/api/v1/code/repos/website/export", json={"confirm": True}).status_code == 403
    assert client.get("/api/v1/code/watch").status_code == 403
    assert client.post("/api/v1/code/watch/website/start", json={"confirm": True}).status_code == 403
    assert client.post("/api/v1/code/watch/website/stop", json={}).status_code == 403


def test_code_routes_say_so_when_code_projects_are_off(client, monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": False, "default_protect": "block"})
    assert client.post("/api/v1/code/repos/website/export", json={"confirm": True}).status_code == 503
    assert client.post("/api/v1/code/watch/website/start", json={"confirm": True}).status_code == 503


# ---- watch for notes (watch) ------------------------------------------------------

def _wait(client, state="watching", notes=True, seconds=20.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        rows = client.get("/api/v1/code/watch").json()["watching"]
        if rows and rows[0]["state"] == state and (not notes or rows[0]["notes"]):
            return rows[0]
        time.sleep(0.1)
    raise AssertionError(client.get("/api/v1/code/watch").json())


def test_watch_finds_notes_and_stops_on_request(client, monkeypatch, project):
    from maverick_dashboard import code_ops_api
    monkeypatch.setattr(code_ops_api, "_INTERVAL", 0.2)
    assert client.post("/api/v1/code/watch/website/start", json={}).status_code == 422
    seen = _audit(monkeypatch)
    r = client.post("/api/v1/code/watch/website/start", json={"confirm": True})
    assert r.status_code == 202, r.text
    row = _wait(client)
    assert [(n["file"], n["line"], n["note"]) for n in row["notes"]] == [
        ("app.py", 2, "add input validation for empty lists")]
    task = row["notes"][0]["task"]
    assert task.startswith("In the website code project.\nFrom app.py:2") and "/tmp" not in task
    # Starting twice keeps one watcher.
    client.post("/api/v1/code/watch/website/start", json={"confirm": True})
    assert len(code_ops_api._watchers) == 1
    stopped = client.post("/api/v1/code/watch/website/stop", json={}).json()
    assert stopped["state"] == "stopped"
    assert seen == ["code_watch_start", "code_watch_stop"]
    watcher = next(iter(code_ops_api._watchers.values()))
    watcher.thread.join(5)
    assert not watcher.thread.is_alive()
    assert client.post("/api/v1/code/watch/other/stop", json={}).status_code == 404


def test_work_from_a_note_runs_under_the_projects_protection(client, monkeypatch, project):
    """A note from a project set to "code never leaves Lightwork" starts work
    through the governed code-change path, labelled with the project and at
    its protection mode -- never as an ordinary task."""
    from maverick import ifc
    from maverick.codebase import features
    from maverick_dashboard import code_actions_api, code_ops_api
    monkeypatch.setattr(code_ops_api, "_INTERVAL", 0.2)
    monkeypatch.setattr(code_actions_api, "_provider_missing", lambda: False)
    seen_policy = []

    def runner(goal_id, work):
        seen_policy.append(ifc._RUN_LABELS.get())
        (work / "app.py").write_text("def f(xs):\n    return xs or []\n")

    monkeypatch.setattr(features, "default_runner",
                        lambda max_dollars=None, user_id=None, allowed_suites=None: runner)
    monkeypatch.setattr(features, "default_reviewer", lambda: None)
    client.post("/api/v1/code/watch/website/start", json={"confirm": True})
    note = _wait(client)["notes"][0]
    audit = _audit(monkeypatch)
    url = f"/api/v1/code/watch/website/notes/{note['id']}/start"
    r = client.post(url, json={"confirm": True})
    assert r.status_code == 202, r.text
    assert r.json()["protect"] == "block"
    assert seen_policy == [(frozenset({"code:website"}), "block")]
    proposals = features.list_proposals("website")
    assert len(proposals) == 1 and proposals[0]["status"] == "pending"
    assert audit[-1] == "code_watch_note_start"
    assert client.post("/api/v1/code/watch/website/notes/0000/start",
                       json={"confirm": True}).status_code == 404


def test_watch_is_bounded_and_stops_at_shutdown(client, monkeypatch, project):
    from maverick_dashboard import code_ops_api
    monkeypatch.setattr(code_ops_api, "_INTERVAL", 0.2)
    monkeypatch.setattr(code_ops_api, "_MAX_WATCHERS", 0)
    r = client.post("/api/v1/code/watch/website/start", json={"confirm": True})
    assert r.status_code == 409 and "Stop one first" in r.json()["detail"]
    monkeypatch.setattr(code_ops_api, "_MAX_WATCHERS", 10)
    client.post("/api/v1/code/watch/website/start", json={"confirm": True})
    _wait(client)
    code_ops_api.stop_watchers(timeout=5)
    assert not any(t.is_alive() for t in code_ops_api._watch_threads)


@pytest.mark.parametrize("revoke_before_dispatch", [False, True])
def test_named_note_preserves_identity_and_rechecks_dispatch_authority(
        client, monkeypatch, project, revoke_before_dispatch):
    from maverick.codebase import features
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import auth, code_actions_api, code_ops_api, rbac

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **kwargs: VerifiedPrincipal(
        sub=token, issuer="https://issuer.example", audience="maverick", claims={"sub": token}))
    rbac.set_role("user:alice", "admin")
    rbac.set_role("user:recovery", "admin")
    client.headers["Authorization"] = "Bearer alice"
    monkeypatch.setattr(code_ops_api, "_INTERVAL", 0.2)
    monkeypatch.setattr(code_actions_api, "_provider_missing", lambda: False)
    assert client.post("/api/v1/code/watch/website/start", json={"confirm": True}).status_code == 202
    note = _wait(client)["notes"][0]
    queued, admissions, identities = [], [], []
    native = code_actions_api._run_feature
    monkeypatch.setattr(code_actions_api, "_run_feature", lambda *args: queued.append(args))
    response = client.post(f"/api/v1/code/watch/website/notes/{note['id']}/start",
                           json={"confirm": True})
    assert response.status_code == 202, response.text
    assert len(queued) == 1 and queued[0][-2:] == ("user:alice", "alice")
    monkeypatch.setattr(features, "default_runner", lambda **kwargs: identities.append(kwargs))
    monkeypatch.setattr(features, "default_reviewer", lambda: None)
    monkeypatch.setattr(features, "propose", lambda *args, **kwargs: admissions.append(kwargs))
    if revoke_before_dispatch:
        rbac.set_role("user:alice", "viewer")
    native(*queued[0])
    if revoke_before_dispatch:
        assert not admissions and not identities
    else:
        assert admissions == [{"reviewer": None, "owner": "user:alice"}]
        assert identities == [{"max_dollars": None, "user_id": "alice", "allowed_suites": None}]


def test_watch_stops_itself_after_repeated_read_failures(client, monkeypatch, project):
    from maverick.codebase import vault
    from maverick_dashboard import code_ops_api
    monkeypatch.setattr(code_ops_api, "_INTERVAL", 0.05)
    client.post("/api/v1/code/watch/website/start", json={"confirm": True})
    _wait(client)

    def broken(name):
        raise vault.VaultError("unreadable")
    monkeypatch.setattr(vault, "get", broken)
    row = _wait(client, state="failed", notes=False)
    assert "three times" in row["reason"]


def test_code_page_offers_download_and_watch(client, project):
    from test_support.plain_language import developer_terms, visible_text
    page = client.get("/code").text
    text = visible_text(page)
    assert "Watch for notes to Lightwork" in text and "Start watching" in text
    assert developer_terms(page) == []


def test_one_workspace_cannot_take_every_watch_slot(client, monkeypatch, project):
    """Watching is shared by the whole installation: one workspace gets a fair
    share of the slots, so it can't leave other workspaces unable to watch."""
    import types

    from maverick_dashboard import code_ops_api
    monkeypatch.setattr(code_ops_api, "_INTERVAL", 0.2)
    real_live = code_ops_api._live
    monkeypatch.setattr(code_ops_api, "_live",
                        lambda w: True if isinstance(w, types.SimpleNamespace) else real_live(w))
    here = code_ops_api._workspace()
    share = getattr(code_ops_api, "_MAX_WATCHERS_PER_WORKSPACE", 3)

    def fill(workspace: str) -> None:
        for i in range(share):
            code_ops_api._watchers[(workspace, f"p{i}")] = types.SimpleNamespace()

    def unfill() -> None:
        for key in [k for k, w in code_ops_api._watchers.items() if isinstance(w, types.SimpleNamespace)]:
            del code_ops_api._watchers[key]
    try:
        fill(here)
        r = client.post("/api/v1/code/watch/website/start", json={"confirm": True})
        assert r.status_code == 409 and "This workspace" in r.json()["detail"]
        assert "Stop one first" in r.json()["detail"]
        unfill()
        fill("other")
        assert client.post("/api/v1/code/watch/website/start", json={"confirm": True}).status_code == 202
    finally:
        unfill()
