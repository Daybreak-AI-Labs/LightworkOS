"""Operator mission-control (/oversight).

Unifies every control-plane intervention — governance holds, shield blocks,
capability + egress denials, consent denials, killswitch halts — into one
operator pane, alongside live halt state, pending approvals, and active agents.

Hermetic like the other dashboard tests: OIDC off (``require_principal``
returns None), HOME/MAVERICK_HOME isolated so the audit log + HALT file land in
tmp, and the WorldModel points at a fresh DB.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    # Use a fresh audit writer pinned at the isolated HOME so record() and the
    # page read the same log.
    import maverick.audit.writer as aw
    aw._default = None


def test_oversight_page_renders_and_nav_link(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/oversight")
    assert r.status_code == 200
    assert "oversight" in r.text.lower()
    # Nav link is wired into the primary menu.
    assert 'href="/oversight"' in r.text
    assert ">Oversight<" in r.text


def test_unifies_every_guardrail(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.audit import record
    record("governance_denied", agent="acme.coder", tool="shell",
           rule="require_human_actions", reason="'shell' requires human approval")
    record("shield_block", agent="acme.coder", stage="tool", reason="prompt injection")
    record("capability_denied", agent="acme.coder", tool="s3", principal="agent:acme.coder")
    record("egress_blocked", agent="acme.coder", provider="openai")

    text = _client().get("/oversight").text
    # Every guardrail's events surface in one pane (the gap: capability + egress
    # had no aggregated view before).
    for label in ("Held by a company rule", "Stopped by the safety filter", "Tool not allowed",
                  "Data not allowed to leave"):
        assert label in text
    # And their key details render, in plain words.
    assert "company rule: require human actions" in text
    assert "prompt injection" not in text
    assert "Not allowed to use this tool" in text
    assert "Not allowed to send data to That service" in text
    from test_support.plain_language import developer_terms
    assert developer_terms(text) == []


def test_consent_approve_excluded_deny_counted(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.audit import record
    record("consent_result", agent="a", decision="approve", action="deploy")
    record("consent_result", agent="a", decision="deny", action="rm -rf /")
    from test_support.element_text import element_texts
    from test_support.plain_language import visible_text

    response = _client().get("/oversight")
    assert response.status_code == 200
    text = visible_text(response.text)
    # A denial is an intervention; an approval is not.
    assert "1 intervention in this window" in text
    cells = element_texts(response.text, "td")
    assert len(cells) == 5  # Exactly one five-column event row, never the approval.
    assert cells[1] == cells[4] == "Consent refused"
    assert "Consent refused" in text
    assert "rm -rf /" not in text
    assert "deploy" not in text


def test_non_intervention_events_excluded(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.audit import record
    record("tool_call", agent="a", name="read_file", input_summary="x")
    text = _client().get("/oversight").text
    # Ordinary activity isn't an intervention -> empty state.
    assert "No recorded interventions on this day." in text and "Pick another day" in text


def test_halt_state_reflected(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.killswitch as ks
    ks.clear()  # no in-process latch
    # The HALT file stat is cached for 1s; reset the cache marker before each
    # read so it re-stats the isolated file. (base.html's halt-pill JS always
    # contains "HALTED. Click to resume.", so assert on the template marker.)
    ks._last_file_check_ts = 0.0
    page = _client().get("/oversight").text
    assert 'data-halted="false"' in page and "Stop all work now" in page
    # Arm the killswitch (the same HALT file the nav pill / api toggle uses).
    p = ks._halt_file_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("test halt", encoding="utf-8")
    ks._last_file_check_ts = 0.0
    page = _client().get("/oversight").text
    assert 'data-halted="true"' in page and "Resume all work" in page


def test_pending_holds_are_actionable_inline(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    w.create_approval(
        "shell", risk="high", detail="'shell' requires human approval",
        provenance="governance",
    )
    text = _client().get("/oversight").text
    assert 'href="/approvals"' in text          # still links to the full queue
    # ...but the hold is also actionable right here: the action + inline
    # approve/deny buttons wired to the decision API render on the console.
    assert "shell" in text
    assert 'data-action="approve"' in text
    assert 'data-action="deny"' in text
    assert "/api/v1/approvals/" in text
    # Governance REQUIRE_HUMAN holds are labelled with the EU AI Act's
    # human-oversight requirement (Article 14), in plain words.
    assert "human-oversight requirement" in text


def test_pending_exact_operation_renders_current_and_actionable_inline(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    import re
    import time

    from maverick.approval_cards import build_approval_card, encode_approval_detail
    from maverick.world_model import WorldModel

    card = build_approval_card(
        action="browser.click",
        summary="Approve the reviewed customer change",
        target_label="Customer settings save button",
        target={"page": "https://customer.test/settings", "selector": "#save"},
        parameters={"selector": "#save"},
        parameter_summary=["Activate the Save button once"],
        actor="local:dashboard",
        workspace="default",
        role="operator",
        authority_versions={"role_revision": "role-v1"},
        input_versions={"page_revision": "page-v1"},
        credential_versions={"browser_session_sha256": "a" * 64},
        budget={"currency": "USD", "maximum": 0.25},
        expires_at=time.time() + 300,
        known_effects=["The reviewed customer setting will be saved."],
        unresolved_assumptions=[],
        irreversible=False,
        before="The setting is disabled.",
        after="The setting is enabled.",
    )
    world = WorldModel(tmp_path / "world.db")
    approval_id = world.create_approval(
        "browser.click",
        risk="high",
        scope="#save",
        detail=encode_approval_detail(card),
    )

    text = _client().get("/oversight").text
    row = re.search(
        rf'<article class="approval-item" data-id="{approval_id}".*?</article>',
        text, flags=re.DOTALL,
    )

    assert row is not None
    assert "Approve the reviewed customer change" in row.group(0)
    assert "Customer settings save button" in row.group(0)
    assert f'data-binding="{card["binding_sha256"]}"' in row.group(0)
    assert 'data-action="approve" disabled' not in row.group(0)
    assert "older request is missing the details" not in row.group(0)


def test_oversight_approval_sources_use_trusted_provenance(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.world_model import WorldModel

    w = WorldModel(tmp_path / "world.db")
    w.create_approval(
        "governed-shell", risk="high", detail="policy requires operator review",
        provenance="governance",
    )
    w.create_approval(
        "ordinary-shell", risk="high", detail="governance",
        provenance=None,
    )

    text = _client().get("/oversight").text

    assert "Governed shell" in text
    assert "Ordinary shell" in text
    assert text.count("Required human oversight (EU AI Act)") == 1
    assert text.count('class="muted">An agent asked for permission</span>') == 1


def test_no_pending_holds_shows_empty_state(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    text = _client().get("/oversight").text
    assert '<p class="mv-empty__title">Nothing needs your decision right now</p>' in text


def _enable_oidc_principal_map(monkeypatch):
    """Map ``Bearer <name>`` to the dashboard principal ``user:<name>``."""
    import maverick_dashboard.auth as auth
    from maverick.oidc import VerifiedPrincipal

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    def _verify(token, **_kw):
        return VerifiedPrincipal(
            sub=token, issuer="https://issuer.example", audience="maverick",
            claims={"sub": token},
        )

    monkeypatch.setattr(auth, "verify_oidc_token", _verify)


def _as(user: str) -> dict:
    return {"Authorization": f"Bearer {user}"}


def test_viewer_cannot_read_or_operate_the_global_approval_queue(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _enable_oidc_principal_map(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")

    from maverick.world_model import WorldModel
    from maverick_dashboard import rbac

    rbac.set_role("user:viewer", "viewer")
    WorldModel(tmp_path / "world.db").create_approval(
        "tenant-secret-operation",
        risk="high",
        detail="Sensitive cross-owner target and parameters",
    )

    response = _client().get("/oversight", headers=_as("viewer"))

    assert response.status_code == 403
    assert "tenant-secret-operation" not in response.text
    assert "Sensitive cross-owner target and parameters" not in response.text


def test_oversight_audit_events_are_owner_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _enable_oidc_principal_map(monkeypatch)
    monkeypatch.delenv("MAVERICK_DASHBOARD_ADMINS", raising=False)
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")

    from maverick.audit import record
    from maverick.world_model import WorldModel

    w = WorldModel(tmp_path / "world.db")
    alice_goal = w.create_goal("alice active", owner="user:alice")
    bob_goal = w.create_goal("bob active", owner="user:bob")
    w.set_goal_status(alice_goal, "active")
    w.set_goal_status(bob_goal, "active")
    record(
        "capability_denied", agent="alice.agent.internal", goal_id=alice_goal,
        tool="alice-secret-tool", principal="user:alice",
    )
    record(
        "capability_denied", agent="bob.agent.internal", goal_id=bob_goal,
        tool="prod-admin-shell", principal="user:bob",
    )

    text = _client().get("/oversight", headers=_as("alice")).text

    # Even owned audit rows are metadata; exact source-task links remain scoped.
    # The acting agent's identifier is metadata; its tool stays private.
    lowered = text.lower()
    assert "alice.agent.internal" in lowered
    assert "alice secret tool" not in lowered and "alice-secret-tool" not in lowered
    assert "alice active" in lowered
    assert "bob.agent.internal" not in lowered
    assert "prod admin shell" not in lowered and "prod-admin-shell" not in lowered
    assert '<div class="num">1</div>' in text


def test_oversight_admin_keeps_source_ownership(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _enable_oidc_principal_map(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")

    from maverick.audit import record
    from maverick.world_model import WorldModel

    w = WorldModel(tmp_path / "world.db")
    alice_goal = w.create_goal("alice active", owner="user:alice")
    bob_goal = w.create_goal("bob active", owner="user:bob")
    record("shield_block", agent="alice.agent.internal", goal_id=alice_goal, reason="alice-block")
    record("shield_block", agent="bob.agent.internal", goal_id=bob_goal, reason="bob-block")

    text = _client().get("/oversight", headers=_as("root")).text

    assert "alice-block" not in text and "alice active" not in text
    assert "bob-block" not in text and "bob active" not in text
    assert "No recorded interventions on this day." in text


def test_day_traversal_is_neutralized(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/oversight?day=../../../etc/passwd")
    assert r.status_code == 200  # safe_audit_day collapses it; no 500, no escape
    assert "../../../etc/passwd" not in r.text


# --- live "Active now" panel ------------------------------------------------

def test_active_endpoint_lists_running_agents(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("ship the thing", "do it")
    w.set_goal_status(gid, "active")
    w.append_event(gid, "coder", "tool_call", "shell: ls -la")
    event_ts = w.conn.execute(
        "SELECT ts FROM goal_events WHERE goal_id = ? ORDER BY id DESC LIMIT 1",
        (gid,),
    ).fetchone()[0]
    with w._writing() as conn:
        conn.execute("UPDATE goals SET updated_at = ? WHERE id = ?", (event_ts - 7200, gid))

    body = _client().get("/api/v1/oversight/active").json()
    g = next((x for x in body["goals"] if x["id"] == gid), None)
    assert g is not None
    assert g["title"] == "ship the thing"
    assert "shell" in g["activity"]  # latest event surfaces as current activity
    assert g["updated_at"] == event_ts


def test_active_endpoint_excludes_finished_goals(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    done = w.create_goal("old", "x")
    w.set_goal_status(done, "done")
    running = w.create_goal("now", "y")
    w.set_goal_status(running, "active")
    ids = {g["id"] for g in _client().get("/api/v1/oversight/active").json()["goals"]}
    assert running in ids
    assert done not in ids


def test_oversight_page_has_live_active_panel(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    text = _client().get("/oversight").text
    assert 'id="active-now"' in text
    assert "/api/v1/oversight/active" in text  # the client polls this endpoint


# --- multi-day (incident-review) range --------------------------------------

def _write_event_on_day(audit_dir, day, kind, **payload):
    """Append one raw audit event to a specific day-file (the writer only ever
    names by *today*, so multi-day fixtures are written directly)."""
    import json
    audit_dir.mkdir(parents=True, exist_ok=True)
    ev = {"v": 1, "ts": 1_000_000.0, "kind": kind, "agent": "a", "goal_id": None, **payload}
    with open(audit_dir / f"{day}.ndjson", "a", encoding="utf-8") as f:
        f.write(json.dumps(ev) + "\n")


def test_multiday_range_spans_day_files(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.paths import data_dir
    audit_dir = data_dir("audit")
    _write_event_on_day(audit_dir, "2026-01-10", "governance_denied",
                        reason="jan-hold", rule="r")
    _write_event_on_day(audit_dir, "2026-02-20", "shield_block",
                        stage="tool", reason="feb-block")
    _write_event_on_day(audit_dir, "2026-03-30", "capability_denied",
                        tool="s3outofrange")  # outside the window
    text = _client().get("/oversight?since=2026-01-01&until=2026-02-28").text
    assert "jan-hold" not in text and "feb-block" not in text
    assert "Safety filter stopped it at tool" in text
    assert "Held by a company rule" in text
    assert "s3outofrange" not in text          # March is outside [since, until]
    assert "2026-01-01" in text and "2026-02-28" in text  # range shown in label


def test_range_inputs_present(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    text = _client().get("/oversight").text
    assert 'name="since"' in text
    assert 'name="until"' in text


def test_range_day_traversal_neutralized(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/oversight?since=../../etc&until=../../passwd")
    assert r.status_code == 200  # safe_audit_day collapses bad bounds -> open
    # The crafted values are neutralized to None (empty inputs), never echoed
    # back or used as a path component.
    assert "../../etc" not in r.text
    assert "../../passwd" not in r.text


def test_active_now_panel_diff_renders_and_respects_focus(monkeypatch, tmp_path):
    """The live table is updated in place, not rebuilt via innerHTML every
    5 s, so it keeps keyboard focus on the 'why?' buttons and does not poll
    hidden tabs."""
    _isolate(monkeypatch, tmp_path)
    text = _client().get("/oversight").text
    script = text[text.index('id="active-now"'):]
    # Rows are keyed by goal id and updated in place; no wholesale rebuild.
    assert "tr.dataset.goal" in script
    assert "box.innerHTML = h" not in script
    # Refresh is skipped while the tab is hidden or focus is inside the table.
    assert "if (document.hidden) return;" in script
    assert "box.contains(document.activeElement)" in script
    # The refresh window is announced to assistive tech.
    assert "setAttribute('aria-busy', 'true')" in script
    assert "removeAttribute('aria-busy')" in script
