"""Page fixes from the measured accessibility pass (axe-core, keyboard runs).

Each test names the measured problem it guards against: a spending field
that refused round amounts, form errors not tied to their fields, a one-time
invite link 2,357 px below the focus, task row links that failed contrast
and named no task, scroll boxes a keyboard could not reach, status roles on
text that never changes, and raw agent trace read out from the task log.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).parents[1] / "maverick_dashboard"
TEMPLATES = ROOT / "templates"
_ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_DASHBOARD_INVITES",
                 "MAVERICK_DASHBOARD_REQUIRE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.runtime_overrides as overrides
    monkeypatch.setattr(overrides, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    import maverick_dashboard.rbac as rbac
    roles = tmp_path / "home" / ".maverick"
    monkeypatch.setattr(rbac, "store_path", lambda: roles / "dashboard-users.json")
    monkeypatch.setattr(rbac, "tenant_store_path", lambda: roles / "dashboard-tenant-roles.json")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers=_ORIGIN)


class Tags(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def find(self, **wanted):
        return [attrs for tag, attrs in self.tags
                if all(attrs.get(key) == value for key, value in wanted.items())]


# ---- Settings: spending per task -------------------------------------------

def test_the_spending_field_accepts_dollars_and_cents_and_ties_its_error_to_it():
    page = _client().get("/settings")
    assert page.status_code == 200
    tags = Tags(page.text)
    (field,) = tags.find(id="settings-task-budget")
    # step="0.5" made 7.50 invalid ("nearest valid values are 7.01 and 7.51").
    assert field["step"] == "0.01" and field["min"] == "0.01"
    assert field["aria-describedby"] == "task-limit-help"
    (error,) = tags.find(id="settings-task-budget-error")
    assert "hidden" in error and error.get("role") == "alert"
    # The page script replaces the browser bubble with this message and links
    # it to the field (tests/js/form_field_errors.test.js runs it).
    assert "getElementById('settings-task-budget-error')" in page.text


def test_money_inputs_step_in_cents():
    offenders = []
    for path in sorted(TEMPLATES.glob("*.html")):
        for tag in re.findall(r"<input\b[^>]*>", path.read_text(encoding="utf-8")):
            if 'type="number"' in tag and re.search(r'(name|id)="[^"]*dollar', tag, re.IGNORECASE):
                step = re.search(r'step="([^"]*)"', tag)
                if not step or step.group(1) not in {"0.01", "any"}:
                    offenders.append(f"{path.name}: {tag}")
    assert offenders == []


# ---- Users: invite someone by email ----------------------------------------

def _invite_admin(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    token = "measured-a11y-invite-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", token)
    return {"Authorization": f"Bearer {token}"}


def test_the_invite_email_error_is_tied_to_the_field(monkeypatch):
    page = _client().get("/users", headers=_invite_admin(monkeypatch))
    assert page.status_code == 200
    tags = Tags(page.text)
    (field,) = tags.find(name="email", type="email")
    assert field["id"] == "invite-email-input" and "required" in field
    (error,) = tags.find(id="invite-email-error")
    assert "hidden" in error and error.get("role") == "alert"
    assert "getElementById('invite-email-error')" in page.text


def test_the_one_time_invite_link_is_shown_first_and_takes_focus(monkeypatch):
    headers = _invite_admin(monkeypatch)
    page = _client().post("/users/invite", data={"email": "new@corp.example", "role": "viewer"},
                          headers=headers)
    assert page.status_code == 200
    html = page.text
    tags = Tags(html)
    (panel,) = tags.find(id="invite-result")
    assert panel["tabindex"] == "-1" and panel["aria-labelledby"] == "invite-result-title"
    assert tags.find(id="invite-result-title")
    # Right under the page header, above every other section of the page,
    # not 2,357 px further down beside the form.
    result_at = html.index('id="invite-result"')
    assert html.index('id="page-hero-title"') < result_at < html.index('id="invite-email"')
    assert "/auth/invite/inv_" in html[result_at:html.index('id="invite-email"')]
    assert "document.getElementById('invite-result')" in html and ".focus()" in html
    # Focus lands on the result, so a second toast would only repeat it.
    assert 'data-mv-toast="Invitation for' not in html


# ---- Tasks: row links -------------------------------------------------------

def test_task_row_links_keep_full_contrast_and_name_their_task():
    from maverick_dashboard.app import _world
    world = _world()
    goal = world.get_goal(world.create_goal("Summarize vendor contracts", "Top five"))
    listing = _client().get("/goals").text
    for label, href in (("Result", f"/chat/goal/{goal.id}"), ("Steps", f"/goals/{goal.id}/trajectory"),
                        ("Plan", f"/goals/{goal.id}/plan")):
        assert f'<a href="{href}">{label}<span class="sr-only">: Summarize vendor contracts</span></a>' in listing
    template = (TEMPLATES / "goals.html").read_text(encoding="utf-8")
    # opacity: 0.72 dropped the muted links to 3.97:1 in the dark theme.
    actions = re.search(r"\.g-row__actions\{([^}]*)\}", template).group(1)
    assert "opacity" not in actions
    assert ".g-row:hover .g-row__actions" not in template
    # Rows the search and "Show more" build carry the same names.
    assert """'">Result<span class="sr-only">: ' + esc(g.title) + '</span></a>'""" in template


# ---- Scroll boxes -----------------------------------------------------------

SCROLL_BOXES = {
    "security.html": 'class="sec-scroll"',
    "ai_evidence_analysis.html": 'class="evidence-table"',
    "skills.html": 'id="sc-tool-list"',
    "immune.html": 'class="ic-table-wrap"',
    "code.html": 'class="ic-table-wrap"',
}


@pytest.mark.parametrize("name,marker", sorted(SCROLL_BOXES.items()))
def test_scroll_boxes_are_named_regions_a_keyboard_can_scroll(name, marker):
    source = (TEMPLATES / name).read_text(encoding="utf-8")
    boxes = [tag for tag in re.findall(r"<div\b[^>]*>", source) if marker in tag]
    assert boxes, name
    for tag in boxes:
        assert 'tabindex="0"' in tag and 'role="region"' in tag, tag
        named_by = re.search(r'aria-labelledby="([^"]+)"', tag)
        if named_by:
            assert f'id="{named_by.group(1)}"' in source, tag
        else:
            assert re.search(r'aria-label="[^"]+"', tag), tag
    # A list of every tool is not read out as one announcement on load.
    if name == "skills.html":
        assert "aria-live" not in boxes[0]


def test_scroll_boxes_built_by_the_code_page_are_reachable_too():
    script = (ROOT / "static" / "lightwork-code.js").read_text(encoding="utf-8")
    block = script[script.index('var wrap = el("div", "ic-table-wrap");'):][:400]
    assert 'wrap.tabIndex = 0' in block and 'wrap.setAttribute("role", "region")' in block
    assert 'wrap.setAttribute("aria-label", "Notes to Lightwork found in " + w.repo)' in block


# ---- Status roles and the task log ------------------------------------------

def test_status_roles_stay_off_text_that_never_changes():
    workforce = (TEMPLATES / "workforce.html").read_text(encoding="utf-8")
    badge = re.search(r'<span class="badge dept-readiness"[^>]*>', workforce).group(0)
    assert "role=" not in badge  # filled once at load for every department
    agents = (TEMPLATES / "agents.html").read_text(encoding="utf-8")
    assert '<div class="panel" role="status"' not in agents
    assert '<div class="jc-sec" role="status">' not in agents
    # Summaries the page writes once when it loads are not announced either.
    learning = (TEMPLATES / "learning.html").read_text(encoding="utf-8")
    for source, ident in ((workforce, "fa-autonomy-status"), (learning, "fa-flywheel-status")):
        line = re.search(rf'<p [^>]*id="{ident}"[^>]*>', source).group(0)
        assert "role=" not in line and "aria-live" not in line, line


def test_the_kernel_planning_trace_is_kept_out_of_the_spoken_task_log():
    template = (TEMPLATES / "chat_goal.html").read_text(encoding="utf-8")
    # The main step list shows plain narration (stream P); the kernel's raw
    # trace lives only in the folded "Technical details" list.
    assert 'id="raw-trace-list"' in template and '<details class="raw-trace" id="raw-trace"' in template
    assert "stepRow(kind, step.text, '', helper)" in template
