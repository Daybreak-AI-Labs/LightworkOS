"""Effective access: what one person can do, and which rule allows it.

The report must never drift from enforcement, so these tests compare it with
the real checks: the app's page-admission dependency for every page, and real
HTTP requests for the admin, audit and operate powers.
"""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

BANNED = ("user:", "principal", "tenant", "override", "deployment", "SSO", "None", "{{")


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


# -- role descriptions ---------------------------------------------------------

def test_every_role_has_a_plain_description(client):
    from maverick_dashboard import rbac
    from maverick_dashboard.access_explanations import role_descriptions
    from maverick_dashboard.identity_format import role_description
    rbac.set_custom_role("records-officer", ["view", "audit", "operate"], "Keeps the records straight")
    rbac.set_custom_role("helper", ["view"], "")
    described = role_descriptions()
    assert set(described) == set(rbac.known_roles())
    assert all(text.strip() for text in described.values())
    assert described["operator"].startswith("Does the work.")
    assert described["records-officer"] == (
        "Keeps the records straight. Can view work and results, run and change work, "
        "and decide approvals and read the activity record.")
    # A custom role without a description still says what it allows.
    assert described["helper"] == "Can view work and results."
    assert role_description("x", ()) == "Allows nothing yet."


def test_role_pickers_say_what_the_chosen_role_allows(client):
    from maverick.tenant.registry import create_tenant
    from maverick_dashboard import rbac, subject_directory
    create_tenant("acme-roles", display_name="Acme")
    rbac.set_role("user:dana@corp.com", "operator")
    subject_directory.record_login("okta|newcomer-42", ["new@corp.com"])
    rbac.set_custom_role("records-officer", ["view", "audit"], "Reviews the records")
    page = client.get("/users").text
    # Every role picker points at a description of the chosen role.
    selects = re.findall(r'<select class="select" name="role"[^>]*>', page)
    selects += re.findall(r'<select id="wm-role"[^>]*>', page)
    assert len(selects) == 4  # role change, give a role, change several people, workspace member
    for tag in selects:
        described_by = re.search(r'aria-describedby="([^"]+)"', tag).group(1).split()
        for target in described_by:
            assert f'id="{target}"' in page, (tag, target)
    # The row of someone with a role says what their current role allows.
    assert "Operator: Does the work." in page
    # Each option carries its description for the live update.
    assert 'data-description="Reviews the records. Can view work and results and read the activity record."' in page
    # "What each role can do" covers custom roles too.
    guide = visible_text(page).split("What each role can do", 1)[1].split("Custom roles", 1)[0]
    assert "Records officer" in guide and "Reviews the records." in guide
    for word in ("Administrator", "Operator", "Auditor", "Viewer"):
        assert word in guide


def test_invite_picker_describes_the_role_it_starts_with(client):
    from jinja2 import ChoiceLoader, DictLoader
    from maverick_dashboard import admin_pages
    from maverick_dashboard.app import templates
    from starlette.requests import Request
    request = Request({"type": "http", "method": "GET", "path": "/users", "headers": [],
                       "query_string": b""})
    context = {**admin_pages._users_context(request), "invites_on": True}
    env = templates.env.overlay(loader=ChoiceLoader([
        DictLoader({"base.html": "{% block content %}{% endblock %}"}), templates.env.loader]))
    body = env.get_template("users.html").render(**context)
    invite = body.split('action="/users/invite"', 1)[1].split("</form>", 1)[0]
    assert 'aria-describedby="invite-role-chosen invite-role-help"' in invite
    assert 'id="invite-role-chosen"' in invite
    assert "Viewer: Looks but doesn&#39;t touch. Sees dashboards and results." in invite
    assert '<option value="viewer" data-description="' in invite and " selected>" in invite


# -- the person report against the real checks ------------------------------------

ROLES = ("admin", "operator", "auditor", "viewer", "records-officer")


def _page_opens(path: str, principal: str) -> bool:
    """The app's own page admission dependency, asked for ``principal``."""
    from maverick_dashboard import app as dash_app
    from maverick_dashboard.effective_access import probe
    try:
        dash_app.enforce_page_visibility(probe(principal, path))
    except HTTPException as exc:
        assert exc.status_code == 403
        return False
    return True


@pytest.mark.parametrize("role", ROLES)
def test_report_matches_the_real_checks_for_each_role(client, monkeypatch, role):
    from maverick_dashboard import auth, effective_access, rbac, ui_visibility
    rbac.set_custom_role("records-officer", ["view", "audit", "operate"], "")
    rbac.set_role("user:boss", "admin")  # keeps a global administrator on the roster
    who = f"user:{role}@corp.com"
    rbac.set_role(who, role)
    # An administrator's page-visibility choice must show up as "hidden".
    if role == "operator":
        ui_visibility.set_visibility("/spend", "operator", False)
    report = effective_access.person(who)

    opened = {p["path"] for g in report["screens"]["groups"] for p in g["pages"]}
    hidden = {p["path"] for p in report["screens"]["hidden"]}
    ready = [p for p in ui_visibility.PAGES if ui_visibility.customer_ready(p)]
    for page in ready:
        assert (page["path"] in opened) == _page_opens(page["path"], who), (role, page["path"])
    assert len(opened) + len(hidden) + report["screens"]["closed"] == len(ready)
    if role == "operator":
        assert "/spend" in hidden and "/spend" not in opened
        assert next(p for p in report["screens"]["hidden"] if p["path"] == "/spend")["by_setting"]

    # Powers agree with real requests made as that person.
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)
    powers = report["installation"]["powers"]
    assert powers["admin"] == (client.get("/spending-limits").status_code == 200)
    assert powers["audit"] == (client.get("/safety").status_code == 200)
    decided = client.post("/api/v1/approvals/987654/approve").status_code
    assert decided in (403, 404)
    assert powers["operate"] == (decided == 404)
    assert powers["view"] is True
    assert report["installation"]["label"] in ("Administrator", "Operator", "Auditor", "Viewer",
                                               "Records officer")
    assert report["installation"]["source"] == "Explicit installation role"
    assert report["approvals"]["can_decide"] == powers["operate"]


def test_workspace_role_replaces_the_installation_role_inside_it(client):
    from maverick.paths import tenant_scope
    from maverick.tenant.registry import create_tenant
    from maverick_dashboard import effective_access, rbac
    create_tenant("acme-access", display_name="Acme")
    rbac.set_role("user:dana@corp.com", "operator")
    rbac.set_tenant_role("acme-access", "user:dana@corp.com", "viewer")
    report = effective_access.person("user:dana@corp.com")
    assert report["installation"]["powers"]["operate"] is True
    acme = next(w for w in report["workspaces"] if w["id"] == "acme-access")
    assert acme["label"] == "Viewer" and acme["source"] == "Current workspace membership"
    assert acme["powers"]["operate"] is False and acme["name"] == "Acme"
    # Inside that workspace, the person's own requests are answered the same way.
    with tenant_scope(tenant="acme-access"):
        inside = effective_access.person("user:dana@corp.com")
    assert inside["current"]["id"] == "acme-access"
    assert inside["approvals"]["can_decide"] is False


def test_departments_and_spending_limits_name_their_rule(client):
    from maverick import spending_limits
    from maverick.quotas import UsageLedger
    from maverick_dashboard import effective_access, rbac, suite_grants
    rbac.set_role("user:dana@corp.com", "operator")
    suite_grants.set_suites("user:dana@corp.com", ["finance"])
    spending_limits.set_user_limit("user:dana@corp.com", "20", "day", actor="user:boss@corp.com")
    spending_limits.set_workspace_limit("100", "month", actor="user:cfo@corp.com")
    UsageLedger().record("user:dana@corp.com", 4.5, 0, 0)
    report = effective_access.person("user:dana@corp.com")
    assert report["departments"]["all"] is False
    assert report["departments"]["names"] == ["Finance"]
    assert report["departments"]["source"] == "Their own department setting on the Users page"
    person, workspace = report["spending"]["limits"]
    assert person["kind"] == "person" and person["remaining"] == 15.5
    assert person["set"]["by"] == "user:boss@corp.com"
    assert workspace["kind"] == "workspace" and workspace["set"]["by"] == "user:cfo@corp.com"

    page = client.get("/users/access", params={"person": "user:dana@corp.com"})
    assert page.status_code == 200
    assert page.headers["cache-control"] == "private, no-store"
    text = visible_text(page.text)
    for word in BANNED:
        assert word not in text, word
    assert "Access for user" not in text
    assert "Their personal limit" in text and "$20.00 per day" in text and "$15.50" in text
    assert "Set by boss@corp.com" in text and "Set by cfo@corp.com" in text
    assert "Finance." in text and "Their own department setting on the Users page" in text
    assert "They can decide approvals." in text
    assert "Only requests from their departments: Finance." in text


def test_check_access_is_for_administrators_and_people_only(client, monkeypatch):
    from maverick_dashboard import auth, rbac
    assert client.get("/users/access", params={"person": "agent:helper"}).status_code == 404
    assert client.get("/users/access").status_code == 404
    rbac.set_role("user:vic@corp.com", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vic@corp.com")
    assert client.get("/users/access", params={"person": "user:vic@corp.com"}).status_code == 403


def test_viewer_report_reads_plainly_and_flags_an_unknown_person(client):
    page = client.get("/users/access", params={"person": "user:new@corp.com"}).text
    text = visible_text(page)
    assert "hasn't signed in or been invited yet" in text
    assert "Sign-in is off." in text
    assert "Viewer" in text  # the first-login default role
    assert "Configured first-login default" in text


def test_users_page_links_each_person_to_check_access(client):
    from maverick_dashboard import rbac
    rbac.set_role("user:dana@corp.com", "operator")
    page = client.get("/users").text
    assert 'href="/users/access?person=user%3Adana%40corp.com"' in page
    assert 'action="/users/access"' in page and 'name="person"' in page


# -- the specialist report -------------------------------------------------------

def _clean_builtin_name() -> str:
    from maverick.domain import builtin_dir, lint_profile, load_domains
    for name, prof in sorted(load_domains(builtin_dir()).items()):
        if not lint_profile(prof)[0] and prof.workflow:
            return name
    raise AssertionError("no lint-error-clean built-in pack found")


@pytest.mark.parametrize("levels_on", [False, True])
def test_specialist_levels_match_the_runtime_gate(client, monkeypatch, tmp_path, levels_on):
    from maverick import agent_autonomy
    from maverick.domain import available_domains
    from maverick.domain_edit import resolved_view
    from maverick_dashboard import effective_access
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "1" if levels_on else "0")
    name = _clean_builtin_name()
    view = resolved_view(name)
    report = effective_access.agent(name, view)
    profile = available_domains()[name].autonomy
    for tier in report["tiers"]:
        # The level shown is the one the runtime gate decides for that risk.
        assert tier["level"] == agent_autonomy.decide(name, profile, risk=tier["risk"]).level.value
        assert tier["label"] and tier["means"] and tier["rule"]
    if not levels_on:
        assert {t["level"] for t in report["tiers"]} == {"suggest"}
        assert report["tiers"][0]["rule"].startswith("Independence levels are off")
    else:
        assert all(("Standard for" in t["rule"] or "Built into" in t["rule"]) for t in report["tiers"])
    required = sorted({tool for step in available_domains()[name].workflow for tool in step.tools})
    assert report["required"] == required


def test_specialist_access_names_the_editor_setting_and_spending(client, monkeypatch, tmp_path):
    import maverick.audit as audit
    from maverick import spending_limits
    from maverick.runner import configured_max_dollars
    monkeypatch.setattr(audit, "audit_event", lambda *_args, **_kwargs: True)
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "1")
    name = _clean_builtin_name()
    current = client.get(f"/api/v1/agents/{name}").json()
    policy = {**current["autonomy"]["pack"], "default": "request", "high": "suggest", "onboarding": True}
    from test_support.agent_drafts import publish as _publish

    saved = _publish(name, {"autonomy": policy}, app=client)
    assert saved.status_code == 200 and saved.json()["confirmed"], saved.text
    spending_limits.set_workspace_limit("300", "month", actor="user:cfo@corp.com")
    page = client.get(f"/agents?name={name}").text
    panel = visible_text(page).split("Check access", 1)[1].split("Tasks it works on also count", 1)[0]
    assert "Set in this specialist's Independence settings (its level for high-risk actions)" in panel
    assert "lowered one step from Ask before acting while it is supervised" in panel
    assert "$300.00 per month" in panel and "left" in panel
    ceiling = configured_max_dollars()
    if ceiling is not None:
        assert f"stops at ${ceiling:,.2f}" in panel
    assert 'id="agent-access"' in page and "<summary>" in page


# -- specialist or agent: the report names which kind it is --------------------

def test_agent_built_here_is_called_an_agent_not_a_specialist(client, monkeypatch, tmp_path):
    from maverick.domain_edit import write_override
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "1")
    write_override("acme_quote_helper", {
        "description": "Drafts customer quotes", "persona": "You draft quotes for customers.",
        "max_risk": "low", "allow_tools": ["read_file"]})
    page = client.get("/agents?name=acme_quote_helper").text
    panel = visible_text(page).split("Check access", 1)[1].split("Spending limits", 1)[0]
    assert "Agent built in this workspace" in panel
    assert "what this agent can do" in panel
    assert "specialist" not in panel.lower()
    assert "Standard for agents without a department" in panel


def test_customized_builtin_stays_a_specialist_marked_customized(client, monkeypatch, tmp_path):
    from maverick.domain_edit import write_override
    from maverick_dashboard import effective_access
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    name = _clean_builtin_name()
    from maverick.domain_edit import resolved_view
    plain = effective_access.agent(name, resolved_view(name))
    assert (plain["kind"], plain["label"], plain["customized"]) == ("specialist", "Specialist", False)
    write_override(name, {"description": "Tuned for this workspace."})
    tuned = effective_access.agent(name, resolved_view(name))
    assert (tuned["kind"], tuned["customized"]) == ("specialist", True)
    panel = visible_text(client.get(f"/agents?name={name}").text).split("Check access", 1)[1]
    assert panel.lstrip().startswith("Specialist · Customized")


@pytest.fixture
def outside(tmp_path, monkeypatch, client):
    from maverick import agent_trust, external_agents
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(agent_trust, "managed_path", lambda: tmp_path / "agent_trust.json")
    monkeypatch.setattr(external_agents, "registry_path", lambda: tmp_path / "external_agents.json")
    return external_agents


@pytest.mark.parametrize("ceiling", ["low", "medium", "high"])
def test_outside_agent_tiers_match_what_screening_answers(outside, ceiling):
    from maverick_dashboard import effective_access
    outside.enroll("sf-quotebot", "agentforce", description="Quoting agent",
                   max_risk=ceiling, max_dollars=5.0, deny_tools=["delete_record"])
    report = effective_access.outside_agent("sf-quotebot")
    assert (report["kind"], report["label"]) == ("outside", "Outside agent")
    assert report["blocked"] == ["delete_record"]
    # One action the catalog rates at each risk, so the tool ceiling and the
    # risk ceiling agree on what the tier means.
    # (An unrated name such as send_email is not medium: it takes the high
    # refusal floor, so the medium tier uses a deliberately medium-rated tool.)
    rated = {"low": "read_file", "medium": "kv_memory", "high": "write_file"}
    from maverick.safety.tool_risk import tool_risk
    assert {risk: tool_risk(tool, overrides={}) for risk, tool in rated.items()} == {
        "low": "low", "medium": "medium", "high": "high"}
    for tier in report["tiers"]:
        verdict = outside.screen("sf-quotebot", rated[tier["risk"]], risk=tier["risk"])
        expected = ("auto" if verdict["allowed"]
                    else "request" if verdict.get("requires_approval") else "refused")
        assert tier["level"] == expected, (tier, verdict)
        assert tier["rule"]


def test_outside_agent_over_its_limit_is_refused_like_screening(outside):
    from maverick_dashboard import effective_access
    outside.enroll("sf-quotebot", "agentforce", max_risk="high", max_dollars=1.0)
    meta = outside._load_sidecar()
    meta["sf-quotebot"]["spent_dollars"] = 2.0
    meta["sf-quotebot"]["period"] = "total"
    outside._save_sidecar(meta)
    report = effective_access.outside_agent("sf-quotebot")
    assert report["spending"]["over"] and report["spending"]["remaining"] == 0.0
    for tier in report["tiers"]:
        assert tier["level"] == "refused"
        assert outside.screen("sf-quotebot", "quote.create", risk=tier["risk"])["rule"] == "budget"


def test_outside_agent_page_shows_check_access(outside, client):
    outside.enroll("sf-quotebot", "agentforce", description="Quoting agent",
                   max_risk="medium", max_dollars=5.0)
    page = client.get("/external-agents/sf-quotebot").text
    text = visible_text(page)
    panel = text.split("Check access", 1)[1]
    assert 'id="agent-access"' in page
    assert panel.lstrip().startswith("Outside agent")
    assert ("High-risk actions Refused It may not take this action. "
            "Above the riskiest action it is allowed (medium)") in panel
    assert "$5.00 per month" in panel and "left" in panel
    assert "specialist" not in panel.lower()


def test_an_ai_action_reports_every_resource_it_reached_not_just_the_fingerprinted_ones():
    from maverick_dashboard import content_access
    event = {"agent": "specialist", "model": "model-x",
             "resources": ["", "a"] + [f"file-{i}" for i in range(40)]}
    fields = content_access.ai_action_fields(event)
    assert fields["resources_reached"] == 41                      # the blank one is not a resource
    assert len(fields["resource_fingerprints"]) == 5
    assert fields["resource_fingerprints"][0] == content_access.resource_fingerprint("a")
