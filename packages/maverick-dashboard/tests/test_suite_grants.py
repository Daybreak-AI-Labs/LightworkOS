"""Per-user department (suite) grants: store, resolution, and gate enforcement.

Job-function scoping on top of privilege RBAC — a finance-scoped user sees and
dispatches Finance specialists only. Safety invariants under test:
  * auth OFF (no principal) -> every suite gate is a no-op (single-user mode);
  * no stored grant (and no configured default) -> unrestricted (opt-in);
  * a dashboard admin is never scoped, even with a stored grant;
  * a scoped user is 403'd from other departments' detail/review/deploy and
    from dispatching a fleet agent bound to another department's pack.
"""
from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


# ---------- store + grant resolution (no HTTP) ----------

def test_store_roundtrip_and_validation(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick_dashboard import suite_grants
    assert suite_grants.list_grants() == {}
    assert suite_grants.get_grant("user:alice") is None

    suite_grants.set_suites("user:alice", ["finance", "tax"])
    assert suite_grants.get_grant("user:alice") == frozenset({"finance", "tax"})
    assert suite_grants.list_grants() == {"user:alice": ["finance", "tax"]}

    # An explicit EMPTY grant is valid ("no departments"), distinct from no entry.
    suite_grants.set_suites("user:alice", [])
    assert suite_grants.get_grant("user:alice") == frozenset()

    # The absent deployment default is unrestricted, so deleting even an empty
    # restriction would broaden access. Removal is refused and non-mutating.
    with pytest.raises(ValueError, match="would broaden access"):
        suite_grants.remove_grant("user:alice")
    assert suite_grants.get_grant("user:alice") == frozenset()

    with pytest.raises(ValueError):
        suite_grants.set_suites("user:x", ["not_a_suite"])
    with pytest.raises(ValueError):
        suite_grants.set_suites("", ["finance"])
    with pytest.raises(ValueError):
        suite_grants.set_suites("user:x", "finance")  # a bare string, not a list


def test_corrupt_store_is_revalidated_on_read(monkeypatch, tmp_path):
    # A partially malformed store is one untrusted policy snapshot, not a bag of
    # independently salvageable grants: dropping only the restrictive rows can
    # widen those principals to the unrestricted default.
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick_dashboard import suite_grants
    p = suite_grants.store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        '{"user:a": ["finance", "bogus_suite", 7], "": ["legal"], "user:b": "legal"}',
        encoding="utf-8")
    original = p.read_text(encoding="utf-8")
    with pytest.raises(suite_grants.SuiteGrantStoreError):
        suite_grants.list_grants()
    with pytest.raises(suite_grants.SuiteGrantStoreError):
        suite_grants.set_suites("user:new", ["finance"])
    assert p.read_text(encoding="utf-8") == original


def test_concurrent_set_suites_does_not_lose_grants(monkeypatch, tmp_path):
    """set_suites does a load-modify-save; without the lock two concurrent
    grants both load the same store and the second drops the first — a lost
    grant/revoke on a security store. All N must survive."""
    import threading

    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick_dashboard import suite_grants
    n = 24

    def assign(i: int):
        suite_grants.set_suites(f"user:u{i:03d}", ["finance"])

    threads = [threading.Thread(target=assign, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(suite_grants.list_grants()) == n
    assert list((tmp_path / ".maverick").glob("*.tmp")) == []


def test_granted_suites_explicit_beats_config_default(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick_dashboard import suite_grants
    # No entry, no config default -> unrestricted.
    assert suite_grants.granted_suites("user:new") is None
    # Config default applies to users with no explicit grant; unknown keys drop.
    import maverick.config as config
    monkeypatch.setattr(config, "load_config",
                        lambda: {"dashboard": {"default_suites": ["finance", "bogus"]}})
    assert suite_grants.granted_suites("user:new") == frozenset({"finance"})
    # An explicit grant wins over the default.
    suite_grants.set_suites("user:new", ["legal"])
    assert suite_grants.granted_suites("user:new") == frozenset({"legal"})


def test_remove_grant_only_uses_a_no_broader_default(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    import maverick.config as config
    from maverick_dashboard import suite_grants

    suite_grants.set_suites("user:fin", ["finance", "tax"])
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"dashboard": {"default_suites": ["finance"]}},
    )

    suite_grants.remove_grant("user:fin")

    assert suite_grants.get_grant("user:fin") is None
    assert suite_grants.granted_suites("user:fin") == frozenset({"finance"})


# ---------- HTTP enforcement ----------

def _client(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _as(monkeypatch, principal):
    """Simulate an authenticated caller. Both modules need the patch: the auth
    gates read auth.caller_principal, and api.py's owner checks bound their own
    reference at import time."""
    from maverick_dashboard import api, auth
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(api, "caller_principal", lambda request: principal)


def test_auth_off_suite_gates_are_a_noop(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    r = c.get("/api/v1/departments")
    assert r.status_code == 200
    keys = {d["key"] for d in r.json()}
    assert {"finance", "legal"} <= keys           # unfiltered catalog
    assert c.get("/api/v1/departments/legal").status_code == 200


def test_scoped_user_sees_only_granted_departments(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import suite_grants
    suite_grants.set_suites("user:fin", ["finance", "tax"])
    _as(monkeypatch, "user:fin")

    keys = {d["key"] for d in c.get("/api/v1/departments").json()}
    assert keys == {"finance", "tax"}

    assert c.get("/api/v1/departments/finance").status_code == 200
    assert c.get("/api/v1/departments/legal").status_code == 403
    assert c.get("/api/v1/departments/legal/review").status_code == 403
    assert c.post("/api/v1/departments/legal/deploy").status_code == 403
    # A missing department still 404s first (existence is public catalog).
    assert c.get("/api/v1/departments/nope").status_code == 404


def test_direct_goal_admission_checks_inherited_suite(monkeypatch, tmp_path):
    from fastapi import HTTPException
    from maverick_dashboard import api

    (tmp_path / "client_fork.toml").write_text(
        'name = "client_fork"\nextends = "aero_avionics"\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    checked = []

    def require(request, suite):
        checked.append(suite)
        raise HTTPException(403, "outside granted departments")

    monkeypatch.setattr(api, "require_suite", require)
    with pytest.raises(HTTPException) as exc:
        api._require_enabled_specialist(None, "client_fork")
    assert exc.value.status_code == 403
    assert checked == ["aerospace_defense"]


def test_domain_read_scope_checks_inherited_suite(monkeypatch, tmp_path):
    from maverick_dashboard import auth

    (tmp_path / "client_fork.toml").write_text(
        'name = "client_fork"\nextends = "aero_avionics"\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    monkeypatch.setattr(auth, "caller_suites", lambda request: frozenset({"finance"}))
    assert not auth.domain_suites_allowed(None, "client_fork")
    assert auth.domain_suites_allowed(None, "finance_ap")


def test_deleted_generic_specialist_does_not_lose_persisted_goal_scope(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from maverick import domain
    from maverick_dashboard import auth
    from starlette.requests import Request

    pack = tmp_path / "client_fork.toml"
    pack.write_text('name = "client_fork"\nextends = "finance_ap"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    monkeypatch.setattr(auth, "caller_suites", lambda request: frozenset({"sales"}))
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: "user:alice")
    request = Request({"type": "http", "method": "GET", "path": "/chat/goal/1", "headers": []})
    goal = SimpleNamespace(id=1, owner="user:alice", domain="client_fork")

    assert domain.suites_for_domain("client_fork") == frozenset({"finance"})
    assert not auth.domain_suites_allowed(None, "client_fork")
    assert not auth.can_access_goal(request, goal)
    pack.unlink()
    # Old goals retain the domain string after their specialist is removed.
    assert not auth.domain_suites_allowed(None, "client_fork")
    assert not auth.can_access_goal(request, goal)
    assert domain.suites_for_domain("finance_ap") == frozenset({"finance"})

    # A fork's own prefix can still be granted while the missing parent suite
    # cannot be reconstructed from the persisted goal's domain string.
    prefixed = tmp_path / "gtm_fork.toml"
    prefixed.write_text('name = "gtm_fork"\nextends = "finance_ap"\n', encoding="utf-8")
    monkeypatch.setattr(auth, "caller_suites", lambda request: frozenset({"sales_gtm"}))
    goal.domain = "gtm_fork"
    assert domain.suites_for_domain("gtm_fork") == frozenset({"sales_gtm", "finance"})
    assert not auth.can_access_goal(request, goal)
    prefixed.unlink()
    assert not auth.domain_suites_allowed(request, "gtm_fork")
    assert not auth.can_access_goal(request, goal)

    # A valid generic pack has no inherited department and stays available.
    monkeypatch.setattr(
        domain, "available_domains",
        lambda: {"general_assistant": domain.DomainProfile(name="general_assistant")},
    )
    assert domain.suites_for_domain("general_assistant") == frozenset()
    assert auth.domain_suites_allowed(None, "general_assistant")
    goal.domain = "general_assistant"
    assert auth.can_access_goal(request, goal)

    # Unscoped administrators can still recover old records after deletion.
    monkeypatch.setattr(auth, "caller_suites", lambda request: None)
    assert auth.domain_suites_allowed(None, "client_fork")
    goal.domain = "client_fork"
    assert auth.can_access_goal(request, goal)


def test_finance_operations_and_workspace_require_finance_grant(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text("[finance_operations]\nenable = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "maverick-home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    from maverick import config
    from maverick_dashboard import rbac, suite_grants

    config.reset_config_cache()
    c = _client(monkeypatch, tmp_path)
    rbac.set_role("user:legal-only", "operator")
    suite_grants.set_suites("user:legal-only", ["legal"])
    _as(monkeypatch, "user:legal-only")
    assert c.get("/api/v1/finance-operations/summary").status_code == 403
    assert c.get("/finance").status_code == 403

    rbac.set_role("user:finance", "operator")
    suite_grants.set_suites("user:finance", ["finance"])
    _as(monkeypatch, "user:finance")
    assert c.get("/api/v1/finance-operations/summary").status_code == 200
    assert c.get("/finance").status_code == 200
    config.reset_config_cache()


def test_unscoped_user_and_admin_are_unrestricted(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import suite_grants
    # Authenticated but no grant -> unrestricted (opt-in scoping).
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    _as(monkeypatch, "user:anyone")
    assert c.get("/api/v1/departments/legal").status_code == 200
    # A dashboard admin is never scoped, even with a stored grant.
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:boss")
    suite_grants.set_suites("user:boss", ["finance"])
    _as(monkeypatch, "user:boss")
    assert c.get("/api/v1/departments/legal").status_code == 200
    keys = {d["key"] for d in c.get("/api/v1/departments").json()}
    assert "legal" in keys


def test_scoped_user_cannot_dispatch_other_departments_agent(monkeypatch, tmp_path):
    # The dispatch gate: even a fleet the caller OWNS is blocked when the agent
    # is bound to a specialist pack outside their department grant (403 fires
    # before any provider/governance/capability work).
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    c = _client(monkeypatch, tmp_path)
    from maverick.fleet import Fleet, FleetAgent, save_fleet
    from maverick_dashboard import api, suite_grants

    monkeypatch.setattr(
        api,
        "require_provider_or_400",
        lambda **_: pytest.fail("provider preflight ran before department authorization"),
    )
    save_fleet(Fleet(name="mixed", owner="user:fin", agents=(
        FleetAgent(name="legal_contracts", role="legal",
                   description="", domain="legal_contracts"),
    )))
    suite_grants.set_suites("user:fin", ["finance"])
    _as(monkeypatch, "user:fin")

    r = c.post("/api/v1/fleets/mixed/run",
               json={"agent": "legal_contracts", "prompt": "review this NDA"})
    assert r.status_code == 403
    assert "department" in r.json()["detail"]


def test_admin_manages_grants_via_api(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:boss")
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import suite_grants
    _as(monkeypatch, "user:boss")

    assert c.put("/api/v1/users/user:fin/suites",
                 json={"suites": ["finance"]}).status_code == 204
    assert suite_grants.get_grant("user:fin") == frozenset({"finance"})
    assert c.put("/api/v1/users/user:fin/suites",
                 json={"suites": ["not_a_suite"]}).status_code == 400

    body = c.get("/api/v1/users/suites").json()
    assert body["grants"] == {"user:fin": ["finance"]}
    assert "finance" in body["suites"]
    assert body["default_suites"] is None

    removed = c.delete("/api/v1/users/user:fin/suites")
    assert removed.status_code == 409
    assert "would broaden access" in removed.json()["detail"]
    assert suite_grants.get_grant("user:fin") == frozenset({"finance"})


def test_grant_api_requires_global_admin(monkeypatch, tmp_path):
    # The grant store is global control-plane data: an operator (or a viewer)
    # must not scope users. require_global_permission ignores tenant roles.
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import rbac
    rbac.set_role("user:op", "operator")
    _as(monkeypatch, "user:op")
    assert c.get("/api/v1/users/suites").status_code == 403
    assert c.put("/api/v1/users/user:x/suites",
                 json={"suites": ["finance"]}).status_code == 403
    assert c.delete("/api/v1/users/user:x/suites").status_code == 403


def test_users_page_manages_department_access(monkeypatch, tmp_path):
    # The /users admin page renders the department-access section and its forms
    # write the same store the API uses (auth off = local admin mode).
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import suite_grants
    page = c.get("/users")
    assert page.status_code == 200
    assert "Department access" in page.text

    r = c.post("/users/suites/set",
               data={"principal": "user:fin", "suites": ["finance", "tax"]})
    assert r.status_code == 200                       # 303 -> followed to /users
    assert suite_grants.get_grant("user:fin") == frozenset({"finance", "tax"})
    assert c.post("/users/suites/set",
                  data={"principal": "user:fin", "suites": ["bogus"]}).status_code == 400

    r = c.post("/users/suites/remove", data={"principal": "user:fin"})
    assert r.status_code == 409
    assert "would broaden access" in r.json()["detail"]
    assert suite_grants.get_grant("user:fin") == frozenset({"finance", "tax"})


def test_users_page_preselects_current_grant(monkeypatch, tmp_path):
    # Each grant row carries its own edit form with the CURRENT departments
    # preselected (like the role dropdown), so re-saving never overwrites blind.
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import suite_grants
    suite_grants.set_suites("user:fin", ["finance"])
    page = c.get("/users").text
    assert 'value="finance" checked' in page
    assert 'value="legal" selected' not in page


def test_scoped_user_sees_filtered_pack_catalog(monkeypatch, tmp_path):
    # The catalog surfaces mirror /departments: a finance-scoped user browses
    # finance specialists (plus generic no-suite packs), and another
    # department's pack config 403s rather than rendering.
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import suite_grants
    suite_grants.set_suites("user:fin", ["finance"])
    _as(monkeypatch, "user:fin")

    agents = c.get("/api/v1/agents").json()["agents"]
    suites = {a.get("suite") for a in agents}
    assert suites <= {"finance", None} and "finance" in suites

    # Use a REAL legal pack so resolved_view() is non-None and the suite gate
    # (not a missing-pack 404) is what answers — this test must not depend on
    # another test polluting the domain registry with a synthetic pack.
    assert c.get("/api/v1/agents/finance_ap").status_code == 200
    assert c.get("/api/v1/agents/legal_briefs").status_code == 403
    assert c.get("/api/v1/agents/definitely_missing").status_code == 404

    # Marketplace: grouped browse and flat search both scope to the grant.
    store = c.get("/api/v1/marketplace/packs").json()["departments"]
    assert {d["key"] for d in store} == {"finance"}
    results = c.get("/api/v1/marketplace/packs?q=contract").json()["results"]
    assert all(r["suite"] == "finance" for r in results)

    # Unscoped callers still see the full catalog.
    _as(monkeypatch, None)
    all_suites = {a.get("suite")
                  for a in c.get("/api/v1/agents").json()["agents"]}
    assert "legal" in all_suites


def test_scoped_user_sees_filtered_agents_and_safe_workforce_recovery(monkeypatch, tmp_path):
    # /agents keeps its filtered roster. /workforce's company rollups are
    # unfiltered, so a scoped user gets their own department board instead.
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import suite_grants
    suite_grants.set_suites("user:fin", ["finance"])
    _as(monkeypatch, "user:fin")

    workforce = c.get("/workforce", headers={"Accept": "text/html"})
    assert workforce.status_code == 200
    assert "Other people's work and inaccessible departments are excluded. These are not company totals." in workforce.text.replace("&#39;", "'")
    assert "Capital Markets" not in workforce.text

    agents_page = c.get("/agents").text
    assert "legal_contracts" not in agents_page
    # The roster is searched through the page's picker endpoint, which is
    # scoped the same way: the finance pack is found, another department's is not.
    picker = {item["name"] for item in c.get(
        "/agents/picker", params={"q": "finance_ap", "setup": "1"}).json()["items"]}
    assert "finance_ap" in picker
    assert c.get("/agents/picker", params={"q": "legal_contracts", "setup": "1"}).json()["items"] == []
    # Deep-linking another department's editor renders no config.
    selected = c.get("/agents?name=legal_contracts").text
    assert "legal_contracts" not in selected


def test_kernel_gate_blocks_dispatch_and_deploy_for_scoped_user(monkeypatch, tmp_path):
    # The dispatch/deploy denials now come from the KERNEL chokepoints
    # (maverick.fleet / maverick.departments), mapped to HTTP 403 here.
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    c = _client(monkeypatch, tmp_path)
    from maverick.fleet import Fleet, FleetAgent, save_fleet
    from maverick_dashboard import api, suite_grants

    monkeypatch.setattr(
        api,
        "require_provider_or_400",
        lambda **_: pytest.fail("provider preflight ran before department authorization"),
    )
    save_fleet(Fleet(name="mixed", owner="user:fin", agents=(
        FleetAgent(name="legal_contracts", role="legal",
                   description="", domain="legal_contracts"),
    )))
    suite_grants.set_suites("user:fin", ["finance"])
    _as(monkeypatch, "user:fin")

    r = c.post("/api/v1/fleets/mixed/run",
               json={"agent": "legal_contracts", "prompt": "review this NDA"})
    assert r.status_code == 403
    assert "department" in r.json()["detail"]
    assert c.post("/api/v1/departments/legal/deploy").status_code == 403


def test_scoped_user_sees_filtered_compartments_and_deliverables(monkeypatch, tmp_path):
    # /compartments and /deliverables previously rendered the full pack/
    # department catalog to scoped users, diverging from /agents. Both must now
    # filter to the caller's grant.
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import suite_grants
    suite_grants.set_suites("user:fin", ["finance"])
    _as(monkeypatch, "user:fin")

    comp = c.get("/compartments")
    assert comp.status_code == 200
    assert "finance_ap" in comp.text
    assert "legal_contracts" not in comp.text

    deliv = c.get("/deliverables")
    assert deliv.status_code == 200
    assert "legal_contracts" not in deliv.text


def test_cross_suite_fork_is_hidden_from_compartments_without_both_grants(monkeypatch, tmp_path):
    domains_dir = tmp_path / "domains"
    domains_dir.mkdir()
    (domains_dir / "legal_client.toml").write_text(
        'name = "legal_client"\nextends = "aero_avionics"\n'
        'description = "Private cross-suite sentinel"\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(domains_dir))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    c = _client(monkeypatch, tmp_path)
    from maverick_dashboard import suite_grants

    suite_grants.set_suites("user:aero", ["aerospace_defense"])
    _as(monkeypatch, "user:aero")
    response = c.get("/compartments", params={"q": "Private cross-suite sentinel"})
    assert response.status_code == 200
    assert "No agents or specialists match this search" in response.text


def test_cross_suite_fork_requires_both_grants_on_agent_and_deliverable_views(
    monkeypatch, tmp_path,
):
    domains_dir = tmp_path / "domains"
    domains_dir.mkdir()
    (domains_dir / "legal_client.toml").write_text(
        'name = "legal_client"\nextends = "aero_avionics"\n'
        'description = "Private cross-suite sentinel"\n'
        '[output]\nshape = "report"\n'
        'deliverable = "Private cross-suite artifact"\n'
        'consumers = ["cross_suite_private_role"]\n'
        'cadence = "on-demand"\ngate = "review"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(domains_dir))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    c = _client(monkeypatch, tmp_path)
    from maverick.domain import available_domains
    from maverick_dashboard import suite_grants

    assert "legal_client" in available_domains()
    _as(monkeypatch, "user:limited")
    for suites in (["aerospace_defense"], ["legal"]):
        suite_grants.set_suites("user:limited", suites)
        names = {a["name"] for a in c.get("/api/v1/agents").json()["agents"]}
        assert "legal_client" not in names
        assert 'data-name="legal_client"' not in c.get("/agents?name=legal_client").text
        assert c.get("/api/v1/agents/legal_client").status_code == 403
        assert c.get("/api/v1/agents/legal_client/jobcard").status_code == 403
        assert "Private cross-suite artifact" not in c.get(
            "/deliverables?role=cross_suite_private_role",
        ).text

    suite_grants.set_suites("user:limited", ["aerospace_defense", "legal"])
    agents = c.get("/api/v1/agents").json()["agents"]
    fork = next(a for a in agents if a["name"] == "legal_client")
    assert fork["suites"] == ["aerospace_defense", "legal"]
    detail = c.get("/api/v1/agents/legal_client")
    assert detail.status_code == 200
    assert detail.json()["name"] == "legal_client"
    assert detail.json()["suites"] == fork["suites"]
    assert c.get("/api/v1/agents/legal_client/jobcard").json()[
        "job_description"
    ]["suites"] == fork["suites"]
    assert 'data-name="legal_client"' in c.get("/agents?name=legal_client").text
    assert "Private cross-suite artifact" in c.get(
        "/deliverables?role=cross_suite_private_role",
    ).text
