"""Owner-scoped multi-tenant authorization and route permissions.

With multi-user OIDC on, an authenticated user must not read or control another
user's goals: every goal route (and the fleets surface) is scoped to the
caller's principal, with no ambient administrator or installation-credential
bypass. Exceptional employee-content reads require their separately tested
reviewed grants. Viewers cannot claim approvals or curate the gallery, and the
cost export, cost anomalies, automation runs, run comparison and workforce
metrics are scoped to the caller.

Hermetic, like ``test_oidc_gate.py``: no real crypto/JWT/network. We monkeypatch
the OIDC seam so a request's ``Authorization: Bearer <name>`` header maps to a
``VerifiedPrincipal`` with ``sub == <name>`` (principal ``user:<name>``). The
WorldModel is pointed at a fresh tmp DB per test, and ``run_goal_in_thread`` is
neutered so POSTs don't spawn a real agent.
"""
from __future__ import annotations

import sqlite3
import types

import maverick_dashboard.auth as auth
import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import api as api_mod
from maverick_dashboard import app as app_mod
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


# ----------------------------- fixtures / helpers -----------------------------


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A fresh WorldModel on a tmp DB, shared by both ``_world()`` caches.

    api.py and app.py keep separate per-path caches but both read
    ``world_model.DEFAULT_DB``; pointing it at a unique tmp file gives each
    test an isolated DB that both surfaces agree on.
    """
    from maverick import world_model

    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    # Drop any cached WorldModel from a prior test so the new DEFAULT_DB binds.
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod

    api_mod._world_cache.clear()
    app_mod._world_cache.clear()
    return world_model.WorldModel(db)


def _enable_oidc_principal_map(monkeypatch, *, operator=True):
    """OIDC on; the bearer token string *is* the subject.

    ``Bearer alice`` -> principal ``user:alice``. Lets each request act as a
    chosen user with no real JWT.
    """
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    if operator:
        from maverick_dashboard import rbac
        monkeypatch.setattr(rbac, "default_role", lambda: "operator")

    def _verify(token, **_kw):
        return VerifiedPrincipal(
            sub=token, issuer="https://issuer.example", audience="maverick",
            claims={"sub": token},
        )

    monkeypatch.setattr(auth, "verify_oidc_token", _verify)


def _origin() -> dict:
    """Same-origin header so mutating POSTs pass the central CSRF check.

    In loopback/no-token mode (the test setup) the bearer_auth middleware
    same-origin-gates every mutating method before the route runs; without a
    matching Origin a POST 403s regardless of ownership.
    """
    return {"Origin": "http://127.0.0.1"}


def _as(user: str, *, post: bool = False) -> dict:
    """Headers acting as ``user`` (principal ``user:<user>``).

    ``post=True`` also adds the same-origin header required by mutating routes.
    """
    headers = {"Authorization": f"Bearer {user}"}
    if post:
        headers.update(_origin())
    return headers


def test_unassigned_oidc_user_can_view_but_cannot_operate(monkeypatch, tmp_path):
    from maverick import config
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_ADMINS", raising=False)
    config.reset_config_cache()
    _enable_oidc_principal_map(monkeypatch, operator=False)
    assert client.get("/providers", headers=_as("alice")).status_code == 200
    assert client.post("/api/v1/goals", headers=_as("alice", post=True),
                       json={"title": "work"}).status_code == 403
    assert client.post("/api/v1/approvals/1/approve", headers=_as("alice", post=True)).status_code == 403


@pytest.fixture
def no_run(monkeypatch):
    """Neuter the background runner so POST /goals doesn't spawn an agent."""
    import maverick.runner as runner

    monkeypatch.setattr(runner, "run_goal_in_thread", lambda *a, **k: "queued")
    # Generous rate cap so a test that creates several goals never 429s; the
    # global ceiling derives as 10x this.
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "1000")
    # A provider key so create_goal passes the "no LLM configured" guard.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")


# ------------------------------- REST: GET / list -----------------------------


def test_owner_can_get_own_goal(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    gid = world.create_goal("alice's goal", owner="user:alice")
    resp = client.get(f"/api/v1/goals/{gid}", headers=_as("alice"))
    assert resp.status_code == 200
    assert resp.json()["id"] == gid


def test_different_principal_gets_404_on_get(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    gid = world.create_goal("alice's goal", owner="user:alice")
    resp = client.get(f"/api/v1/goals/{gid}", headers=_as("mallory"))
    assert resp.status_code == 404
    # 404 not 403: never reveal the goal exists.
    assert resp.json()["detail"] == "no such goal"


def test_cross_user_404_on_every_readonly_byid_route(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    gid = world.create_goal("alice's goal", owner="user:alice")
    for path in (
        f"/api/v1/goals/{gid}",
        f"/api/v1/goals/{gid}/events",
        f"/api/v1/goals/{gid}/open_questions",
        f"/api/v1/goals/{gid}/attachments",
    ):
        r = client.get(path, headers=_as("mallory"))
        assert r.status_code == 404, f"{path} leaked to a non-owner ({r.status_code})"


def test_cross_user_404_on_mutating_byid_routes(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    gid = world.create_goal("alice's goal", owner="user:alice")
    # cancel
    assert client.post(
        f"/api/v1/goals/{gid}/cancel", headers=_as("mallory", post=True)
    ).status_code == 404
    # answer
    r = client.post(
        f"/api/v1/goals/{gid}/answer",
        json={"question_id": 1, "answer": "x"},
        headers=_as("mallory", post=True),
    )
    assert r.status_code == 404
    # The goal must still be untouched (not cancelled by the failed attempt).
    assert world.get_goal(gid).status == "pending"


def test_cross_user_404_on_upload_attachment(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    gid = world.create_goal("alice's goal", owner="user:alice")
    resp = client.post(
        f"/api/v1/goals/{gid}/attachments",
        files={"file": ("note.txt", b"hello", "text/plain")},
        headers=_as("mallory", post=True),
    )
    assert resp.status_code == 404
    # Nothing was stored against the goal.
    assert world.list_attachments(gid) == []


def test_cross_user_404_on_resume(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    gid = world.create_goal("alice's goal", owner="user:alice")
    world.set_goal_status(gid, "cancelled")
    resp = client.post(f"/api/v1/goals/{gid}/resume", headers=_as("mallory", post=True))
    assert resp.status_code == 404
    assert world.get_goal(gid).status == "cancelled"


def test_owner_can_cancel_and_resume_own_goal(world, monkeypatch, no_run):
    _enable_oidc_principal_map(monkeypatch)
    gid = world.create_goal("alice's goal", owner="user:alice")
    assert client.post(
        f"/api/v1/goals/{gid}/cancel", headers=_as("alice", post=True)
    ).status_code == 204
    assert world.get_goal(gid).status == "cancelled"
    assert client.post(
        f"/api/v1/goals/{gid}/resume", headers=_as("alice", post=True)
    ).status_code == 204
    assert world.get_goal(gid).status == "pending"


def test_list_goals_scoped_to_caller(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    a1 = world.create_goal("a-one", owner="user:alice")
    a2 = world.create_goal("a-two", owner="user:alice")
    world.create_goal("b-one", owner="user:bob")
    world.create_goal("legacy", owner="")  # unowned legacy goal

    ids = {g["id"] for g in client.get("/api/v1/goals", headers=_as("alice")).json()}
    assert ids == {a1, a2}  # not bob's, not the legacy unowned one


def test_create_goal_stamps_caller_as_owner(world, monkeypatch, no_run):
    _enable_oidc_principal_map(monkeypatch)
    resp = client.post(
        "/api/v1/goals", json={"title": "stamp me"}, headers=_as("alice", post=True),
    )
    assert resp.status_code == 201
    gid = resp.json()["id"]
    assert world.get_goal(gid).owner == "user:alice"


# --------------------------------- REST: admin --------------------------------


def test_admin_reads_and_controls_only_own_content(world, monkeypatch, no_run):
    _enable_oidc_principal_map(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    a = world.create_goal("a-one", owner="user:alice")
    b = world.create_goal("b-one", owner="user:bob")

    own = world.create_goal("admin-owned", owner="user:root")
    # Governance role does not grant employee private content.
    ids = {g["id"] for g in client.get("/api/v1/goals", headers=_as("root")).json()}
    assert ids == {own}
    assert client.get(f"/api/v1/goals/{a}", headers=_as("root")).status_code == 404
    assert client.get(f"/api/v1/goals/{own}", headers=_as("root")).status_code == 200
    # A read grant would still not authorize mutation.
    assert client.post(
        f"/api/v1/goals/{b}/cancel", headers=_as("root", post=True)
    ).status_code == 404
    assert world.get_goal(b).status != "cancelled"


def test_admin_via_config_admins_list(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    # No env override -> admins come from [dashboard] admins in config.
    monkeypatch.delenv("MAVERICK_DASHBOARD_ADMINS", raising=False)
    import maverick.config as config

    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"dashboard": {"admins": ["user:root"]}})
    gid = world.create_goal("alice's goal", owner="user:alice")
    assert client.get(f"/api/v1/goals/{gid}", headers=_as("root")).status_code == 404
    # A non-listed user is still blocked.
    assert client.get(f"/api/v1/goals/{gid}", headers=_as("mallory")).status_code == 404


# ------------------------------- REST: auth OFF -------------------------------


def test_auth_off_sees_only_explicit_unowned_goals(world, monkeypatch):
    """Turning named login off must not make employee content public."""
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    a = world.create_goal("a-one", owner="user:alice")
    b = world.create_goal("b-one", owner="user:bob")
    legacy = world.create_goal("legacy", owner="")
    ids = {g["id"] for g in client.get("/api/v1/goals").json()}
    assert ids == {legacy}
    assert a not in ids and b not in ids


def test_gallery_delete_requires_goal_owner(world, monkeypatch, tmp_path):
    _enable_oidc_principal_map(monkeypatch)

    import maverick.ux_store as ux

    monkeypatch.setattr(ux, "_shared", None)
    real = ux.UxStore

    def _factory(path=None):
        return real(path=tmp_path / "ux.json")

    monkeypatch.setattr(ux, "UxStore", _factory)

    alice_gid = world.create_goal("alice showcase", owner="user:alice")
    assert client.post(
        f"/api/v1/gallery/{alice_gid}",
        json={"blurb": "exemplary"},
        headers=_as("alice", post=True),
    ).status_code == 201

    denied = client.delete(
        f"/api/v1/gallery/{alice_gid}", headers=_as("mallory", post=True)
    )
    assert denied.status_code == 404
    assert denied.json()["detail"] == "no such goal"

    alice_listing = client.get(
        "/api/v1/gallery", headers=_as("alice")
    ).json()["gallery"]
    assert [entry["goal_id"] for entry in alice_listing] == [alice_gid]

    assert client.delete(
        f"/api/v1/gallery/{alice_gid}", headers=_as("alice", post=True)
    ).status_code == 200
    assert client.get("/api/v1/gallery", headers=_as("alice")).json()["gallery"] == []


def test_auth_off_cannot_get_or_mutate_named_employee_goal(world, monkeypatch, no_run):
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    gid = world.create_goal("owned-by-someone", owner="user:alice")
    assert client.get(f"/api/v1/goals/{gid}").status_code == 404
    assert client.post(f"/api/v1/goals/{gid}/cancel", headers=_origin()).status_code == 404
    assert world.get_goal(gid).status != "cancelled"


def test_auth_off_create_leaves_owner_empty(world, monkeypatch, no_run):
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    resp = client.post(
        "/api/v1/goals", json={"title": "no owner"}, headers=_origin(),
    )
    assert resp.status_code == 201
    assert world.get_goal(resp.json()["id"]).owner == ""


# ---------------------------------- HTML pages --------------------------------


def test_goals_page_filters_to_caller(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    world.create_goal("alice-secret-goal", owner="user:alice")
    world.create_goal("bob-secret-goal", owner="user:bob")
    body = client.get("/goals", headers=_as("alice")).text
    assert "alice-secret-goal" in body
    assert "bob-secret-goal" not in body


def test_chat_goal_page_cross_user_404(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    gid = world.create_goal("alice's goal", owner="user:alice")
    assert client.get(f"/chat/goal/{gid}", headers=_as("alice")).status_code == 200
    assert client.get(f"/chat/goal/{gid}", headers=_as("mallory")).status_code == 404


def test_chat_send_stamps_owner(world, monkeypatch, no_run):
    _enable_oidc_principal_map(monkeypatch)
    resp = client.post(
        "/chat/send",
        data={"title": "via chat"},
        headers={**_as("alice"), **_origin()},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    g = world.list_goals(owner="user:alice")
    assert len(g) == 1 and g[0].title == "via chat"


# ----------------------------------- fleets -----------------------------------


def _patch_fleets(monkeypatch):
    from maverick.fleet import Fleet

    fleets = [
        Fleet(name="alice-fleet", owner="user:alice"),
        Fleet(name="bob-fleet", owner="user:bob"),
        Fleet(name="admin-fleet", owner="user:root"),
        Fleet(name="local-fleet", owner=""),
    ]
    import maverick.fleet as fleet_mod

    monkeypatch.setattr(fleet_mod, "list_fleets", lambda *a, **k: list(fleets))


def test_fleets_api_scoped_to_caller(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    _patch_fleets(monkeypatch)
    names = {f["name"] for f in client.get("/api/v1/fleets", headers=_as("alice")).json()["fleets"]}
    assert names == {"alice-fleet"}


def test_fleets_api_admin_sees_only_owned(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    _patch_fleets(monkeypatch)
    names = {f["name"] for f in client.get("/api/v1/fleets", headers=_as("root")).json()["fleets"]}
    assert names == {"admin-fleet"}


def test_fleets_api_auth_off_sees_only_unowned(world, monkeypatch):
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    _patch_fleets(monkeypatch)
    names = {f["name"] for f in client.get("/api/v1/fleets").json()["fleets"]}
    assert names == {"local-fleet"}


def test_fleets_page_filters_to_caller(world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    _patch_fleets(monkeypatch)
    body = client.get("/fleets", headers=_as("alice")).text
    assert "alice-fleet" in body
    assert "bob-fleet" not in body


origin_client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_access_world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    app_mod._world_cache.clear()
    yield


def _as_principal(monkeypatch, principal):
    """Simulate an authenticated caller with a given principal."""
    from maverick_dashboard import auth
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)


def _seeded_world():
    """A minimal world whose .conn is a real sqlite with two owners' episodes."""
    # check_same_thread=False: the StreamingResponse generator runs on a worker
    # thread under TestClient, so the test fixture's connection must be shareable.
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE goals (id INTEGER PRIMARY KEY, owner TEXT, domain TEXT)")
    conn.execute(
        "CREATE TABLE episodes (id INTEGER PRIMARY KEY, goal_id INT, started_at REAL,"
        " ended_at REAL, outcome TEXT, cost_dollars REAL, input_tokens INT,"
        " output_tokens INT, tool_calls INT)"
    )
    conn.executemany("INSERT INTO goals VALUES (?,?,?)",
                     [(1, "user:alice", ""), (2, "user:bob", ""), (3, "", "")])
    conn.executemany(
        "INSERT INTO episodes VALUES (?,?,?,?,?,?,?,?,?)",
        [(10, 1, 100.0, 200.0, "alice-outcome", 1.5, 10, 5, 2),
         (20, 2, 100.0, 200.0, "bob-secret", 9.9, 1, 1, 1),
         (30, 3, 100.0, 200.0, "local-outcome", 2.0, 1, 1, 1)],
    )
    conn.commit()
    # The export reads through the backend-portable ``query`` contract (SQLite
    # paramstyle in, index+key rows out), which this stub mirrors on its sqlite.
    return types.SimpleNamespace(
        conn=conn, query=lambda sql, params=(): conn.execute(sql, tuple(params)).fetchall()
    )


class _Ep:
    def __init__(self, goal_id, cost):
        self.goal_id = goal_id
        self.cost_dollars = cost


class _Goal:
    def __init__(self, gid, owner, domain, status="done"):
        self.id = gid
        self.owner = owner
        self.domain = domain
        self.status = status
        self.title = f"{owner} {domain}"
        self.updated_at = float(gid)


class _Spend:
    def __init__(self, goal_id, cost):
        self.goal_id = goal_id
        self.cost_dollars = cost


class _Approval:
    def __init__(self, requested_by, decided_by=None):
        self.requested_by = requested_by
        self.decided_by = decided_by
        self.claimed_by = None
        self.requested_at = 10.0
        self.decided_at = 11.0 if decided_by else None
        self.action = "approve secret spend"
        self.status = "approved" if decided_by else "pending"
        self.provenance = None


class _WorkforceWorld:
    goals = [
        _Goal(1, "user:alice", "finance_ar"),
        _Goal(2, "user:bob", "finance_ap"),
    ]
    episodes = [
        ("user:alice", _Spend(1, 12.34)),
        ("user:bob", _Spend(2, 99.99)),
    ]
    approvals = [
        _Approval("user:alice", "user:alice"),
        _Approval("user:bob", "user:bob"),
    ]

    def list_goals(self, limit=500, order="desc", owner=None):
        rows = [g for g in self.goals if owner is None or g.owner == owner]
        return rows[:limit]

    def list_episodes(self, limit=500, goal_id=None, owner=None):
        rows = [e for e_owner, e in self.episodes if owner is None or e_owner == owner]
        if goal_id is not None:
            rows = [e for e in rows if e.goal_id == goal_id]
        return rows[:limit]

    def list_approvals(self, limit=500):
        return self.approvals[:limit]


def test_viewer_cannot_claim_or_release_approval(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    from maverick_dashboard import rbac
    rbac.set_role("user:v", "viewer")
    aid = app_mod._world().create_approval(
        "wire_transfer", risk="high", scope="acct", detail="$5k")
    _as_principal(monkeypatch, "user:v")
    assert origin_client.post(f"/api/v1/approvals/{aid}/claim").status_code == 403
    assert origin_client.post(f"/api/v1/approvals/{aid}/release").status_code == 403
    # And the claim never took effect.
    assert app_mod._world().get_approval(aid).claimed_by is None


def test_viewer_cannot_curate_gallery(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    from maverick_dashboard import rbac
    rbac.set_role("user:v", "viewer")
    _as_principal(monkeypatch, "user:v")
    # The 'operate' gate runs before the goal lookup, so a viewer is refused
    # publishing to / unpublishing from the deployment-wide gallery outright.
    assert origin_client.post("/api/v1/gallery/1").status_code == 403
    assert origin_client.delete("/api/v1/gallery/1").status_code == 403


def test_cost_csv_scoped_to_owner(monkeypatch):
    monkeypatch.setattr(app_mod, "_world", lambda: _seeded_world())
    monkeypatch.setattr(app_mod, "goal_owner_filter", lambda request: "user:alice")
    body = origin_client.get("/api/v1/cost.csv").text
    assert "alice-outcome" in body
    assert "bob-secret" not in body  # the other tenant's episode is withheld


def test_cost_csv_authoff_only_sees_unowned(monkeypatch):
    monkeypatch.setattr(app_mod, "_world", lambda: _seeded_world())
    monkeypatch.setattr(app_mod, "goal_owner_filter", lambda request: "")
    body = origin_client.get("/api/v1/cost.csv").text
    assert "local-outcome" in body
    assert "alice-outcome" not in body and "bob-secret" not in body


def test_cost_anomalies_scoped_to_owner(monkeypatch):
    class _W:
        def list_goals(self, owner=None, limit=None, order="asc"):
            assert owner == "user:alice"
            return [types.SimpleNamespace(id=i) for i in (1, 2, 3)]

        def list_episodes(self, limit=500):
            # alice owns 1,2,3 (3 is the outlier); bob's goal 9 is a huge outlier.
            return [_Ep(1, 1.0), _Ep(2, 1.0), _Ep(3, 50.0), _Ep(9, 9999.0)]

    monkeypatch.setattr(app_mod, "_world", lambda: _W())
    monkeypatch.setattr(app_mod, "goal_owner_filter", lambda request: "user:alice")
    data = origin_client.get("/api/v1/cost/anomalies").json()
    assert data["goals_considered"] == 3  # only alice's goals were considered
    assert 9 not in {a["goal_id"] for a in data["anomalies"]}  # bob's never leaks


def test_automation_runs_scoped_to_owner(monkeypatch):
    g_alice = types.SimpleNamespace(id=1, title="alice run", status="done",
                                    created_at=1, owner="user:alice")
    g_bob = types.SimpleNamespace(id=2, title="bob run", status="failed",
                                  created_at=2, owner="user:bob")

    class _W:
        def goals_for_origin(self, kind, ref, *, limit=20):
            return [g_alice, g_bob]

    monkeypatch.setattr(api_mod, "_world", lambda: _W())
    monkeypatch.setattr(api_mod, "goal_owner_filter", lambda request: "user:alice")
    monkeypatch.setattr(api_mod, "can_access_goal",
                        lambda request, g: g.owner == "user:alice")

    data = origin_client.get("/api/v1/automation-runs?kind=trigger&ref=nightly").json()
    titles = {r["title"] for r in data["runs"]}
    assert titles == {"alice run"}        # bob's run title does not leak
    assert data["summary"] == {"done": 1}  # summary recomputed from owned goals only


def test_runs_compare_missing_goal_has_no_id_oracle(monkeypatch):
    class _W:
        def get_goal(self, gid):
            return None  # nonexistent

    monkeypatch.setattr(app_mod, "_world", lambda: _W())
    r = origin_client.get("/api/v1/runs/compare?ids=4242")
    assert r.status_code == 404
    # The detail must NOT echo the id (else it distinguishes "missing" from
    # "exists-but-forbidden", which assert_goal_access deliberately hides).
    assert r.json()["detail"] == "no such goal"
    assert "4242" not in r.json()["detail"]


def test_workforce_outcomes_api_scoped_to_owner(monkeypatch):
    monkeypatch.setattr(api_mod, "_world", lambda: _WorkforceWorld())
    monkeypatch.setattr(api_mod, "goal_owner_filter", lambda request: "user:alice")

    data = origin_client.get("/api/v1/outcomes").json()

    assert data["firm"] == {
        "goals_total": 1,
        "goals_completed": 1,
        "approvals": 1,
        "human_decisions": 1,
        "spend_dollars": 12.34,
    }
    assert {w["worker"] for w in data["workers"]} == {"finance_ar"}


def test_department_review_api_scoped_to_owner(monkeypatch):
    monkeypatch.setattr(api_mod, "_world", lambda: _WorkforceWorld())
    monkeypatch.setattr(api_mod, "goal_owner_filter", lambda request: "user:alice")

    data = origin_client.get("/api/v1/departments/finance/review").json()

    assert data["delivery"]["goals_total"] == 1
    assert data["delivery"]["spend_dollars"] == 12.34
    assert {w["worker"] for w in data["delivery"]["workers"]} == {"finance_ar"}


def test_workforce_page_rollup_scoped_to_owner(monkeypatch):
    monkeypatch.setattr(app_mod, "_world", lambda: _WorkforceWorld())
    monkeypatch.setattr(app_mod, "goal_owner_filter", lambda request: "user:alice")

    body = origin_client.get("/workforce").text

    # The server-rendered firm rollup stays owner-scoped; the charts moved to
    # the board API (scoped in test_workforce_board_api_scoped_to_owner).
    assert "$12.34" in body
    assert "$112.33" not in body


def test_workforce_board_api_scoped_to_owner(monkeypatch):
    import sqlite3

    world = _WorkforceWorld()
    # The board's windowed KPI counts aggregate the goals table directly.
    world.conn = sqlite3.connect(":memory:", check_same_thread=False)
    world.conn.execute(
        "CREATE TABLE goals (id INTEGER, owner TEXT, status TEXT, "
        "created_at REAL, updated_at REAL, domain TEXT)")
    world.query = lambda sql, params=(): world.conn.execute(sql, tuple(params)).fetchall()
    monkeypatch.setattr(api_mod, "_world", lambda: world)
    monkeypatch.setattr(api_mod, "goal_owner_filter", lambda request: "user:alice")

    data = origin_client.get("/api/v1/dashboards/workforce").json()

    assert data["kpis"]["spend_dollars"] == 12.34
    assert {c["worker"] for c in data["leaders"]} == {"finance_ar"}
