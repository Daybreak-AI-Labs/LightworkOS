"""AI workflow builder: draft (chat + upload) -> edit -> save as a template.

Hermetic like the other dashboard tests: HOME/MAVERICK_HOME isolated to tmp,
the WorldModel + the template store (USER_TEMPLATES is import-time bound, so
monkeypatch it) point under tmp, and no provider key is needed because the LLM
call is either injected or the endpoint's `draft_workflow` is monkeypatched.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from test_support.navigation import assert_navigation_link


def _client():
    # Mutating /api/v1 requests in no-token mode must pass the same-origin CSRF check.
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    # The playbook form saves a domain pack via /agents/<name>/override; point the
    # user domains dir at tmp so a test never writes to the real ~/.maverick/domains.
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.templates as tpl
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tmp_path / ".maverick" / "templates")


def _enable_proxy_auth(monkeypatch):
    import maverick_dashboard.auth as auth

    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: True)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)


# --- pure parsing / prompt building (no LLM) --------------------------------

def test_parse_workflow_normalizes():
    from maverick_dashboard.workflow_ai import parse_workflow
    d = parse_workflow(
        '{"name": "Weekly Report!", "title": "Weekly {{topic}} report", '
        '"params": ["topic", "bad-name", "topic"], "steps": ["a", "b", "  "], '
        '"budget_dollars": 99}'
    )
    assert d["name"] == "weekly-report"            # slugified
    assert d["title"] == "Weekly {{topic}} report"
    assert d["params"] == ["topic"]                # non-identifier + dup dropped
    assert d["steps"] == ["a", "b"]                # blank dropped
    assert d["budget_dollars"] == 99.0             # explicit allowance retained
    assert "1. a" in d["body"] and "2. b" in d["body"]


def test_parse_workflow_strips_code_fence():
    from maverick_dashboard.workflow_ai import parse_workflow
    d = parse_workflow('```json\n{"name":"x","title":"X","steps":["do it"]}\n```')
    assert d["name"] == "x" and d["steps"] == ["do it"]
    assert d["budget_dollars"] is None


def test_save_workflow_without_caps_round_trips_none(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.templates import load_template

    response = _client().post("/api/v1/workflows", json={
        "name": "no-generated-cap", "title": "Workflow", "body": "Do the agreed work.",
    })
    assert response.status_code in {200, 201}, response.text
    saved = load_template("no-generated-cap")
    assert saved.budget_dollars is None and saved.budget_wall_seconds is None


def test_parse_workflow_rejects_unusable():
    from maverick_dashboard.workflow_ai import parse_workflow
    with pytest.raises(ValueError):
        parse_workflow("not json at all")
    with pytest.raises(ValueError):
        parse_workflow('{"title": "x", "steps": []}')   # no steps -> unusable


def test_build_prompt_includes_brief_and_doc():
    from maverick_dashboard.workflow_ai import build_prompt
    p = build_prompt("my brief", "DOC BODY TEXT")
    assert "my brief" in p and "DOC BODY TEXT" in p


def test_workflow_provider_boundary_refuses_raw_credentials_and_large_briefs():
    from maverick_dashboard import workflow_ai

    with pytest.raises(ValueError, match="credential"):
        workflow_ai.build_prompt(
            "use sk-proj-abcdefghijklmnopqrstuvwx", "")  # pragma: allowlist secret
    with pytest.raises(ValueError, match="credential"):
        workflow_ai.build_prompt(
            "summarize this", "API_TOKEN=sk-proj-abcdefghijklmnopqrstuvwx")  # pragma: allowlist secret
    with pytest.raises(ValueError, match="too long"):
        workflow_ai.build_prompt("x" * (workflow_ai._MAX_BRIEF_CHARS + 1), "")


def test_draft_workflow_uses_injected_complete_under_cap():
    from maverick_dashboard import workflow_ai

    seen = {}

    class _Resp:
        text = '{"name":"demo","title":"Demo","steps":["step one"],"budget_dollars":2}'

    def fake_complete(*, system, messages, budget, max_tokens, model):
        seen["system"] = system
        seen["budget"] = budget
        return _Resp()

    d = workflow_ai.draft_workflow("do a thing", complete=fake_complete)
    assert d["name"] == "demo" and d["steps"] == ["step one"]
    assert d["budget_dollars"] == 2.0
    # Drafting is hard-capped (kernel rule: budget caps are not optional).
    assert seen["budget"].max_dollars == workflow_ai.DRAFT_MAX_DOLLARS
    assert "STRICT JSON" in seen["system"]


# --- playbook parsing / drafting (no LLM) -----------------------------------

def test_parse_playbook_normalizes():
    from maverick_dashboard.workflow_ai import parse_playbook
    d = parse_playbook(
        '{"name": "AP Invoice Bot!", "description": "  Pays   invoices ", '
        '"persona": "You are careful.", "max_risk": "EXTREME", '
        '"steps": [{"name": "Read", "instruction": "ocr", "tools": ["ocr_read"], "gate": "maybe"}, '
        '{"name": "Pay", "instruction": "pay", "tools": ["send_payment"], "gate": "APPROVAL"}, '
        '{"name": "  ", "instruction": "dropped"}]}'
    )
    assert d["form"] == "playbook"
    assert d["name"] == "ap-invoice-bot"                 # slugified
    assert d["description"] == "Pays invoices"           # whitespace collapsed
    assert d["max_risk"] == "medium"                     # unknown risk -> default
    assert [s["gate"] for s in d["workflow"]] == [None, "approval"]  # bad gate dropped; cased
    assert len(d["workflow"]) == 2                       # nameless step dropped
    # No top-level allow_tools -> derive the allowlist from the steps' own tools.
    assert d["allow_tools"] == ["ocr_read", "send_payment"]


def test_parse_playbook_keeps_explicit_allowlist_and_strips_fence():
    from maverick_dashboard.workflow_ai import parse_playbook
    d = parse_playbook(
        '```json\n{"name":"x","allow_tools":["a","b"],"deny_tools":["shell"],'
        '"max_risk":"high","steps":[{"name":"go"}]}\n```'
    )
    assert d["name"] == "x" and d["allow_tools"] == ["a", "b"]
    assert d["deny_tools"] == ["shell"] and d["max_risk"] == "high"
    assert d["workflow"] == [{"name": "go", "instruction": "", "tools": [], "gate": None}]


def test_parse_playbook_rejects_unusable():
    from maverick_dashboard.workflow_ai import parse_playbook
    with pytest.raises(ValueError):
        parse_playbook("not json at all")
    with pytest.raises(ValueError):
        parse_playbook('{"name": "x", "steps": []}')   # no steps -> unusable


def test_draft_playbook_uses_injected_complete_under_cap():
    from maverick_dashboard import workflow_ai

    seen = {}

    class _Resp:
        text = '{"name":"clerk","allow_tools":["t"],"max_risk":"low","steps":[{"name":"do it"}]}'

    def fake_complete(*, system, messages, budget, max_tokens, model):
        seen["system"] = system
        seen["budget"] = budget
        return _Resp()

    d = workflow_ai.draft_playbook("an AP clerk", complete=fake_complete)
    assert d["form"] == "playbook" and d["name"] == "clerk"
    assert seen["budget"].max_dollars == workflow_ai.DRAFT_MAX_DOLLARS
    assert "AGENT PLAYBOOKS" in seen["system"]


def test_draft_playbook_uses_factory_guidance_and_drops_unavailable_tools(monkeypatch):
    from maverick import factory_learning
    from maverick_dashboard import workflow_ai

    seen = {}

    class _Resp:
        text = (
            '{"name":"mailer","allow_tools":["email_tool","invented_sender"],'
            '"max_risk":"medium","steps":[{"name":"Send","tools":'
            '["email_tool","invented_sender"],"gate":"approval"}]}'
        )

    monkeypatch.setattr(
        factory_learning, "augment_system_prompt",
        lambda system, **kwargs: system + "\nPROMOTED FACTORY CORRECTION",
    )

    def fake_complete(*, system, messages, budget, max_tokens, model):
        seen["system"] = system
        return _Resp()

    draft = workflow_ai.draft_playbook(
        "email an approved report", complete=fake_complete,
        available_tools={"email_tool"},
    )

    assert "PROMOTED FACTORY CORRECTION" in seen["system"]
    assert "email_tool" in seen["system"]
    assert draft["allow_tools"] == ["email_tool"]
    assert draft["workflow"][0]["tools"] == ["email_tool"]
    assert any("invented_sender" in note for note in draft["notes"])
    assert any("not runtime-enforced pauses" in note for note in draft["notes"])


# --- refine (iterate on an existing draft) ----------------------------------

def test_build_refine_prompt_includes_current_and_instruction():
    from maverick_dashboard.workflow_ai import build_refine_prompt
    p = build_refine_prompt({"title": "Weekly report", "params": ["topic"]}, "make it daily")
    assert "Weekly report" in p and "make it daily" in p
    assert "COMPLETE" in p  # asks for a full revision, not a diff


def test_build_refine_prompt_bounds_untrusted_current_draft():
    from maverick_dashboard import workflow_ai

    prompt = workflow_ai.build_refine_prompt(
        {"persona": "x" * (workflow_ai._MAX_DOC_CHARS * 2)}, "make it safer")
    assert len(prompt) < workflow_ai._MAX_DOC_CHARS + 500
    assert "[truncated]" in prompt


def test_refine_boundary_refuses_credentials_and_large_instructions():
    from maverick_dashboard import workflow_ai

    with pytest.raises(ValueError, match="credential"):
        workflow_ai.build_refine_prompt(
            {"persona": "sk-proj-abcdefghijklmnopqrstuvwx"}, "make it safer")  # pragma: allowlist secret
    with pytest.raises(ValueError, match="too long"):
        workflow_ai.build_refine_prompt(
            {"name": "safe"}, "x" * (workflow_ai._MAX_INSTRUCTION_CHARS + 1))


def test_parsers_refuse_model_output_that_contains_raw_credentials():
    from maverick_dashboard.workflow_ai import parse_playbook, parse_workflow

    with pytest.raises(ValueError, match="credential"):
        parse_workflow(
            '{"name":"x","steps":["use sk-proj-abcdefghijklmnopqrstuvwx"]}')  # pragma: allowlist secret
    with pytest.raises(ValueError, match="credential"):
        parse_playbook(
            '{"name":"x","steps":[{"name":"sk-proj-abcdefghijklmnopqrstuvwx"}]}')  # pragma: allowlist secret


def test_refine_workflow_revises_under_cap():
    from maverick_dashboard import workflow_ai
    seen = {}

    class _Resp:
        text = '{"name":"r","title":"R","steps":["a","email the team"]}'

    def fake_complete(*, system, messages, budget, max_tokens, model):
        seen["system"] = system
        seen["budget"] = budget
        seen["content"] = messages[0]["content"]
        return _Resp()

    d = workflow_ai.refine_workflow(
        {"title": "R", "body": "## Steps\n1. a"}, "add a step to email the team",
        complete=fake_complete,
    )
    assert d["steps"] == ["a", "email the team"]
    assert seen["budget"].max_dollars == workflow_ai.DRAFT_MAX_DOLLARS
    assert "WORKFLOWS" in seen["system"]                  # same system prompt as drafting
    assert "email the team" in seen["content"]            # instruction reached the model


def test_refine_playbook_uses_playbook_parser():
    from maverick_dashboard import workflow_ai

    class _Resp:
        text = ('{"name":"bot","allow_tools":["pay"],"max_risk":"high",'
                '"steps":[{"name":"Pay","gate":"approval"}]}')

    d = workflow_ai.refine_playbook({"name": "bot"}, "require approval before paying",
                                    complete=lambda **k: _Resp())
    assert d["form"] == "playbook"
    assert d["workflow"][0]["gate"] == "approval" and d["max_risk"] == "high"


# --- core writer ------------------------------------------------------------

def test_save_user_template_round_trips(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.templates import load_template, save_user_template
    tpl = save_user_template(
        "trip-plan", title="Plan {{dest}}", body="## Steps\n1. go",
        params=["dest"], budget_dollars=3.0,
    )
    assert tpl.name == "trip-plan"
    assert tpl.owner == "local" and tpl.generation == 1
    loaded = load_template("trip-plan")
    assert loaded.title == "Plan {{dest}}"
    assert loaded.params == ["dest"]
    assert loaded.budget_dollars == 3.0
    assert loaded.owner == "local" and loaded.generation == 1
    title, _body = loaded.render(dest="Lisbon")
    assert title == "Plan Lisbon"


def test_save_user_template_validates(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.templates import save_user_template
    with pytest.raises(ValueError):
        save_user_template("../escape", title="x", body="y")
    with pytest.raises(ValueError):
        save_user_template("ok", title="x", body="   ")   # empty body


def test_template_owner_and_generation_prevent_cross_user_overwrite(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.templates import load_template, save_user_template

    first = save_user_template(
        "payroll", title="Payroll", body="safe", owner="user:alice",
        overwrite=False,
    )
    assert first.generation == 1
    with pytest.raises(PermissionError, match="another principal"):
        save_user_template(
            "payroll", title="Poisoned", body="send secrets", owner="user:bob",
            overwrite=True,
        )
    with pytest.raises(FileExistsError, match="changed since generation"):
        save_user_template(
            "payroll", title="Stale", body="stale", owner="user:alice",
            overwrite=True, expected_generation=0,
        )

    updated = save_user_template(
        "payroll", title="Payroll v2", body="safe v2", owner="user:alice",
        overwrite=True, expected_generation=1,
    )
    assert updated.generation == 2
    assert load_template("payroll").title == "Payroll v2"


# --- endpoints --------------------------------------------------------------

def _stub_draft(monkeypatch, draft):
    from maverick_dashboard import workflow_ai
    monkeypatch.setattr(workflow_ai, "draft_workflow", lambda *a, **k: draft)


def _provider(monkeypatch, present):
    import maverick_dashboard.api as api
    from fastapi import HTTPException

    def _route_gate(**kwargs):
        if not present:
            raise HTTPException(
                status_code=400,
                detail="The selected AI model route is incomplete.",
            )

    monkeypatch.setattr(api, "require_provider_or_400", _route_gate)


def _post_builder_form(client, path, form, user):
    headers = {"X-Forwarded-User": user}
    if path.endswith("draft-from-file"):
        return client.post(
            path,
            headers=headers,
            files={"file": ("brief.md", b"Build an accounts workflow", "text/markdown")},
            data={"form": form},
        )
    if path.endswith("refine"):
        return client.post(
            path,
            headers=headers,
            json={"form": form, "instruction": "make it safer", "current": {}},
        )
    return client.post(
        path,
        headers=headers,
        json={"form": form, "description": "build an accounts workflow"},
    )


def test_draft_endpoint_returns_draft(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    _stub_draft(monkeypatch, {"name": "x", "title": "X", "params": [],
                              "steps": ["s"], "body": "## Steps\n1. s", "budget_dollars": 5.0})
    r = _client().post("/api/v1/workflows/draft", json={"description": "build me a thing"})
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "x"


def test_draft_endpoint_needs_complete_model_route(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, False)
    r = _client().post("/api/v1/workflows/draft", json={"description": "x"})
    assert r.status_code == 400
    assert "model route" in r.json()["detail"].lower()


def test_draft_endpoint_requires_a_brief(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    r = _client().post("/api/v1/workflows/draft", json={"description": "   "})
    assert r.status_code == 400


def test_authoring_endpoints_reject_unknown_form(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    r = _client().post(
        "/api/v1/workflows/draft",
        json={"description": "x", "form": "playbok"},
    )
    assert r.status_code == 400
    assert "template" in r.json()["detail"]


def test_refine_endpoint_bounds_current_draft_before_provider_call(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    from maverick_dashboard import workflow_ai

    called = []
    monkeypatch.setattr(
        workflow_ai, "refine_playbook", lambda *a, **k: called.append(True))
    r = _client().post(
        "/api/v1/workflows/refine",
        json={
            "form": "playbook",
            "instruction": "make it safer",
            "current": {"persona": "x" * 60_000},
        },
    )
    assert r.status_code == 400
    assert "too large" in r.json()["detail"]
    assert called == []


def test_draft_from_file_feeds_text(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    captured = {}
    from maverick_dashboard import workflow_ai

    def fake(brief="", source_text="", **k):
        captured["src"] = source_text
        return {"name": "doc-wf", "title": "Doc", "params": [],
                "steps": ["s"], "body": "b", "budget_dollars": 5.0}

    monkeypatch.setattr(workflow_ai, "draft_workflow", fake)
    r = _client().post(
        "/api/v1/workflows/draft-from-file",
        files={"file": ("spec.md", b"Build a weekly report workflow", "text/markdown")},
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "doc-wf"
    assert "weekly report" in captured["src"].lower()


def test_draft_from_file_rejects_binary(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    r = _client().post(
        "/api/v1/workflows/draft-from-file",
        files={"file": ("x.bin", b"\xff\xfe\x00\x01\x02", "application/octet-stream")},
    )
    assert r.status_code == 400


def test_save_endpoint_persists_a_runnable_template(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post("/api/v1/workflows", json={
        "name": "my-wf", "title": "My WF", "body": "## Steps\n1. do it",
        "params": ["x"], "budget_dollars": 4.0,
    })
    assert r.status_code == 201, r.text
    assert r.json()["saved"] is True
    assert r.json()["generation"] == 1
    from maverick.templates import load_template
    assert load_template("my-wf").title == "My WF"


def test_save_endpoint_rejects_bad_name(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post("/api/v1/workflows", json={
        "name": "../etc/passwd", "title": "x", "body": "## Steps\n1. y",
    })
    assert r.status_code == 400


def test_save_endpoint_conflicts_without_overwrite(monkeypatch, tmp_path):
    # A fresh save colliding with an existing template is a 409, not a silent
    # clobber; the edit flow must bind replacement to a reviewed generation.
    _isolate(monkeypatch, tmp_path)
    c = _client()
    base = {"name": "dup", "title": "First", "body": "## Steps\n1. a"}
    assert c.post("/api/v1/workflows", json=base).status_code == 201
    r2 = c.post("/api/v1/workflows", json={**base, "title": "Second"})
    assert r2.status_code == 409
    from maverick.templates import load_template
    assert load_template("dup").title == "First"       # untouched
    r3 = c.post("/api/v1/workflows", json={
        **base, "title": "Second", "overwrite": True, "expected_generation": 1,
    })
    assert r3.status_code == 201
    assert load_template("dup").title == "Second"


def test_save_user_template_preserves_explicit_budget_and_folds_placeholders(monkeypatch, tmp_path):
    # Explicit budgets are retained; every {{placeholder}} used in the
    # title/body becomes a fillable param so none renders as a literal.
    _isolate(monkeypatch, tmp_path)
    from maverick.templates import load_template, save_user_template
    save_user_template(
        "clamp", title="Email {{recipient}}",
        body="## Steps\n1. write to {{recipient}} about {{topic}}",
        params=["topic"], budget_dollars=999.0, budget_wall_seconds=0.0,
    )
    t = load_template("clamp")
    assert t.budget_dollars == 999.0
    assert t.budget_wall_seconds == 0.0     # explicit zero remains a refusal
    assert set(t.params) == {"topic", "recipient"}


def test_draft_endpoint_wraps_llm_error_as_502(monkeypatch, tmp_path):
    # A non-ValueError from the drafter (budget overrun / provider error) must
    # surface as an upstream 502, never an unhandled 500.
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    from maverick.budget import BudgetExceeded
    from maverick_dashboard import workflow_ai
    fixture = "sk-abcdefghijklmnopqrstuvwxyz123456"  # pragma: allowlist secret

    def boom(*a, **k):
        raise BudgetExceeded(f"drafting cap hit {fixture}")

    monkeypatch.setattr(workflow_ai, "draft_workflow", boom)
    r = _client().post("/api/v1/workflows/draft", json={"description": "x"})
    assert r.status_code == 502
    assert fixture not in r.text


def test_builder_allows_unsaved_playbook_draft_when_pack_editing_off(monkeypatch, tmp_path):
    # Draft/refine remains useful to an operator; only validate/save is disabled.
    _isolate(monkeypatch, tmp_path)
    import maverick.config as cfg
    real = cfg.get_features
    monkeypatch.setattr(cfg, "get_features", lambda: {**real(), "pack_editing": False})
    html = _client().get("/workflow-builder").text
    assert "var PACK_EDITING = false" in html
    assert "draft now; admin validates and saves" in html
    assert 'id="pb-save-btn" class="btn btn--primary" disabled' in html
    assert "review instructions do not automatically pause the work" in html


def _stub_playbook(monkeypatch, draft):
    from maverick_dashboard import workflow_ai
    monkeypatch.setattr(workflow_ai, "draft_playbook", lambda *a, **k: draft)


_PB_DRAFT = {
    "form": "playbook", "name": "ap-bot", "description": "AP clerk",
    "persona": "You are careful.", "allow_tools": ["ocr_read", "send_payment"],
    "deny_tools": ["shell"], "max_risk": "medium",
    "workflow": [
        {"name": "Read", "instruction": "ocr", "tools": ["ocr_read"], "gate": None},
        {"name": "Pay", "instruction": "pay", "tools": ["send_payment"], "gate": "approval"},
    ],
}


def test_draft_endpoint_form_playbook_routes_to_playbook(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    _stub_playbook(monkeypatch, _PB_DRAFT)
    r = _client().post("/api/v1/workflows/draft",
                       json={"description": "an AP clerk", "form": "playbook"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["form"] == "playbook"
    assert body["workflow"][1]["gate"] == "approval"


def test_draft_endpoint_defaults_to_template_form(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    # No `form` field at all -> the template drafter, unchanged.
    _stub_draft(monkeypatch, {"name": "t", "title": "T", "params": [],
                              "steps": ["s"], "body": "b", "budget_dollars": 5.0})
    r = _client().post("/api/v1/workflows/draft", json={"description": "x"})
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "t"


def test_draft_from_file_form_playbook(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    captured = {}
    from maverick_dashboard import workflow_ai

    def fake(brief="", source_text="", **k):
        captured["src"] = source_text
        return _PB_DRAFT

    monkeypatch.setattr(workflow_ai, "draft_playbook", fake)
    r = _client().post(
        "/api/v1/workflows/draft-from-file",
        files={"file": ("runbook.md", b"An AP invoice runbook", "text/markdown")},
        data={"form": "playbook"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["form"] == "playbook"
    assert "ap invoice" in captured["src"].lower()


def _specialist_decision(client, name, action, **fields):
    """Review one complete specialist-draft decision, then confirm it."""
    context = client.get("/api/v1/specialist-drafts", params={"name": name})
    assert context.status_code == 200, context.text
    review = client.post("/api/v1/specialist-drafts/review", json={
        "name": name, "action": action, "context": context.json()["context"], **fields})
    if review.status_code != 200:
        return review
    return client.post("/api/v1/specialist-drafts/apply",
                       json={"token": review.json()["token"], "confirmed": True})


def test_save_playbook_via_agent_override_round_trips(monkeypatch, tmp_path):
    """The playbook form persists through the reviewed draft path: a saved
    draft changes nothing, and publishing it makes a new, discoverable pack
    with its gated workflow intact. The old direct override write is closed."""
    _isolate(monkeypatch, tmp_path)
    from maverick.domain import available_domains

    client = _client()
    entered = {
        "description": "AP clerk", "persona": "You are a careful AP clerk.",
        "allow_tools": ["ocr", "global_payments"], "deny_tools": ["shell"],
        "max_risk": "high",
        "workflow": [
            {"name": "Read", "instruction": "ocr", "tools": ["ocr"], "gate": None},
            {"name": "Pay", "instruction": "pay", "tools": ["global_payments"], "gate": "approval"},
        ],
    }
    direct = client.post("/api/v1/agents/ap-bot/override", json=entered)
    assert direct.status_code == 409 and "ap-bot" not in available_domains()
    # Saving accepts only actions this installation can run.
    saved = _specialist_decision(client, "ap-bot", "save", entered=entered)
    assert saved.status_code == 200, saved.text
    assert saved.json()["confirmed"] is True and "ap-bot" not in available_domains()
    # A new agent has no active definition yet; the editor then names the
    # draft by its original operation, exactly as Workflow Builder does.
    draft = saved.json().get("draft") or "SPD-" + saved.json()["operation"]
    published = _specialist_decision(client, "ap-bot", "publish", selected=draft,
                                     reason="New agent from the workflow builder")
    assert published.status_code == 200, published.text
    assert published.json()["confirmed"] is True
    prof = available_domains()["ap-bot"]
    assert [(s.name, s.gate) for s in prof.workflow] == [("Read", None), ("Pay", "approval")]
    assert prof.allow_tools == ["ocr", "global_payments"]
    # The draft is linted first, so the risk ceiling admits the action and the
    # refusal is about availability alone.
    unknown = _specialist_decision(client, "ap-bot-2", "save", entered={
        "description": "AP clerk", "allow_tools": ["send_payment"], "max_risk": "high"})
    assert unknown.status_code == 422 and "not available in this installation" in unknown.text


def test_save_playbook_rejects_lint_failure(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    # An empty allowlist grants ALL tools -> lint error -> draft refused (422).
    r = _specialist_decision(_client(), "loose-bot", "save", entered={
        "description": "x", "allow_tools": [], "max_risk": "low",
        "workflow": [{"name": "go"}],
    })
    assert r.status_code == 422, r.text
    assert "allow_tools" in r.json()["detail"]


def test_refine_endpoint_routes_by_form(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    from maverick_dashboard import workflow_ai
    monkeypatch.setattr(workflow_ai, "refine_workflow",
                        lambda cur, instr: {"name": "t", "title": "T", "params": [],
                                            "steps": ["s"], "body": "b", "budget_dollars": 5.0})
    monkeypatch.setattr(
        workflow_ai, "refine_playbook", lambda cur, instr, **k: _PB_DRAFT)
    rt = _client().post("/api/v1/workflows/refine",
                        json={"form": "template", "instruction": "make it weekly", "current": {}})
    assert rt.status_code == 200 and rt.json()["name"] == "t"
    rp = _client().post("/api/v1/workflows/refine",
                        json={"form": "playbook", "instruction": "require approval", "current": {}})
    assert rp.status_code == 200 and rp.json()["form"] == "playbook"


def test_operators_can_draft_playbooks_but_only_admins_can_validate_or_save(
    monkeypatch, tmp_path
):
    """Generating an unsaved first pass cannot cross the pack mutation gate."""
    _isolate(monkeypatch, tmp_path)
    _enable_proxy_auth(monkeypatch)
    _provider(monkeypatch, True)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:admin")

    from maverick_dashboard import app as app_mod
    from maverick_dashboard import rbac, workflow_ai

    rbac.set_role("user:operator", "operator")
    monkeypatch.setattr(app_mod, "check_goal_rate_limit", lambda *a, **k: None)
    template = {
        "name": "safe-template", "title": "Safe template", "params": [],
        "steps": ["do work"], "body": "## Steps\n1. do work", "budget_dollars": 5.0,
    }
    monkeypatch.setattr(workflow_ai, "draft_workflow", lambda *a, **k: template)
    monkeypatch.setattr(workflow_ai, "refine_workflow", lambda *a, **k: template)
    monkeypatch.setattr(workflow_ai, "draft_playbook", lambda *a, **k: _PB_DRAFT)
    monkeypatch.setattr(workflow_ai, "refine_playbook", lambda *a, **k: _PB_DRAFT)

    paths = (
        "/api/v1/workflows/draft",
        "/api/v1/workflows/draft-from-file",
        "/api/v1/workflows/refine",
    )
    client = _client()
    for path in paths:
        operator_draft = _post_builder_form(client, path, "playbook", "operator")
        assert operator_draft.status_code == 200, (path, operator_draft.text)
        assert operator_draft.json()["form"] == "playbook"

        template_ok = _post_builder_form(client, path, "template", "operator")
        assert template_ok.status_code == 200, (path, template_ok.text)

        admin_ok = _post_builder_form(client, path, "playbook", "admin")
        assert admin_ok.status_code == 200, (path, admin_ok.text)

    pack = {
        key: value for key, value in _PB_DRAFT.items()
        if key not in {"form", "name", "notes"}
    }
    denied_validate = client.post(
        "/api/v1/agents/ap-bot/validate",
        headers={"X-Forwarded-User": "operator"},
        json=pack,
    )
    denied_save = client.post(
        "/api/v1/agents/ap-bot/override",
        headers={"X-Forwarded-User": "operator"},
        json=pack,
    )
    assert denied_validate.status_code == 403
    assert denied_save.status_code == 403


def test_playbook_draft_tool_grounding_is_tenant_scoped_through_api(monkeypatch, tmp_path):
    """One tenant's tool catalog must never ground another tenant's playbook."""
    _isolate(monkeypatch, tmp_path)
    _enable_proxy_auth(monkeypatch)
    _provider(monkeypatch, True)
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:alice,user:bob")

    from maverick.paths import current_tenant_id
    from maverick_dashboard import api, workflow_ai
    from maverick_dashboard import app as app_mod

    monkeypatch.setattr(app_mod, "check_goal_rate_limit", lambda *a, **k: None)
    catalog_calls = []

    def tenant_tools(**_kwargs):
        tenant = current_tenant_id()
        catalog_calls.append(tenant)
        return [{
            "name": f"{tenant.replace(':', '_')}_private_tool",
            "description": "tenant-private",
            "params": [],
            "category": "Other",
        }]

    model_reply = (
        '{"name":"tenant-agent","description":"tenant work",'
        '"allow_tools":["api_user_alice_private_tool","api_user_bob_private_tool"],'
        '"max_risk":"low","steps":[{"name":"Act","instruction":"act",'
        '"tools":["api_user_alice_private_tool","api_user_bob_private_tool"],'
        '"gate":null}]}'
    )
    monkeypatch.setattr(api, "_live_tool_index", tenant_tools)
    monkeypatch.setattr(workflow_ai, "_run_completion", lambda *a, **k: model_reply)

    client = _client()
    alice = _post_builder_form(
        client, "/api/v1/workflows/draft", "playbook", "alice"
    )
    bob = _post_builder_form(client, "/api/v1/workflows/draft", "playbook", "bob")

    assert alice.status_code == 200, alice.text
    assert bob.status_code == 200, bob.text
    assert alice.json()["allow_tools"] == ["api_user_alice_private_tool"]
    assert bob.json()["allow_tools"] == ["api_user_bob_private_tool"]
    assert alice.json()["workflow"][0]["tools"] == ["api_user_alice_private_tool"]
    assert bob.json()["workflow"][0]["tools"] == ["api_user_bob_private_tool"]
    assert catalog_calls == ["api:user:alice", "api:user:bob"]


def test_refine_endpoint_requires_an_instruction(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, True)
    r = _client().post("/api/v1/workflows/refine", json={"instruction": "   ", "current": {}})
    assert r.status_code == 400


def test_refine_endpoint_needs_complete_model_route(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _provider(monkeypatch, False)
    r = _client().post("/api/v1/workflows/refine", json={"instruction": "x", "current": {}})
    assert r.status_code == 400
    assert "model route" in r.json()["detail"].lower()


def test_tools_endpoint_includes_risk(monkeypatch, tmp_path):
    """The connector picker reads /api/v1/tools; each entry carries a risk level."""
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/api/v1/tools")
    assert r.status_code == 200, r.text
    tools = r.json()["tools"]
    assert tools and all("name" in t and "risk" in t for t in tools)
    assert {t["risk"] for t in tools} <= {"low", "medium", "high"}
    by_name = {t["name"]: t for t in tools}
    if "shell" in by_name:                 # a known-high tool is classified high
        assert by_name["shell"]["risk"] == "high"


def test_workflow_builder_page_renders(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/workflow-builder")
    assert r.status_code == 200
    assert "<title>Workflow builder · Lightwork</title>" in r.text
    assert '<h1 class="page-title"><span lang="en" dir="ltr" data-product-copy>Workflow builder</span></h1>' in r.text
    assert 'id="wf-draft-btn"' in r.text
    assert "/api/v1/workflows/draft" in r.text
    # Both forms are offered, and the playbook saves via the agent-override path.
    assert 'id="wf-form-playbook"' in r.text and 'id="pb-preview"' in r.text
    assert "/api/v1/agents/" in r.text
    # Level-100 affordances: refine loop, live governance check, starter examples.
    assert "/api/v1/workflows/refine" in r.text
    assert 'id="pb-refine"' in r.text and 'id="wf-refine"' in r.text
    assert 'id="pb-govern"' in r.text and "/api/v1/agents/" in r.text
    assert 'id="wf-examples"' in r.text
    # Connector picker: browse real tools (with risk) instead of typing names.
    assert 'id="tool-picker"' in r.text and "/api/v1/tools" in r.text
    assert 'data-browse="allow"' in r.text and 'data-browse="deny"' in r.text
    # Visual flow canvas: start/end nodes bracket the connected, gated steps.
    assert "pb-flow__start" in r.text and 'id="pb-flow-end"' in r.text
    # Schedule panel: arm a saved template on a cron (feature defaults on).
    assert 'id="wf-sched"' in r.text and "/api/v1/schedules" in r.text
    # Times are chosen in the viewer's own time zone and stored as UTC.
    assert "At (your time)" in r.text and "function toUtc(" in r.text
    # Webhook-trigger panel: bind a saved template to an inbound webhook.
    assert 'id="wf-trig"' in r.text and "/api/v1/triggers" in r.text
    # Decluttered: the automate panels are collapsible <details>, not always-open.
    assert '<details class="wf__sched" id="wf-sched"' in r.text
    assert '<summary class="wf__sched-title">' in r.text
    # Reachable from the primary nav (Operate group): the redesigned Flows
    # builder is the sidebar entry; the workflow builder is linked in-page from it.
    assert_navigation_link(r.text, "/workflows", "Workflows")
    # A Chat handoff is verified before filling the ordinary brief for review.
    assert "lightwork.authoring-handoff" in r.text
    assert "/api/v1/templates/draft-context" in r.text
    assert 'id="wf-brief"' in r.text and 'id="wf-draft-btn"' in r.text


def test_builder_schedule_words_copyable_address_and_governance_badge(monkeypatch, tmp_path):
    # Schedules, trigger addresses and the governance gate colour on the builder.
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/workflow-builder").text
    # No raw timetable box or shell snippet: days, a day of the month and a
    # copyable address are offered instead.
    assert 'value="hourly"' in t and 'value="days"' in t and 'value="monthly"' in t
    assert 'id="sched-cron"' not in t and "Cron expression" not in t
    assert 'id="trig-curl"' not in t and "openssl" not in t and "Copy address" in t
    assert ".pb-gatebadge.gov" in t and "'gov'" in t   # approval = brand, not amber
    assert "mvCopy(" in t                                # shared copy primitive


def test_builder_summary_heading_cron_words_and_label_association(monkeypatch, tmp_path):
    # Accessibility and readability details on the builder page.
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/workflow-builder").text
    assert 'role="heading" aria-level="3"' in t      # <summary> regained heading semantics
    assert "function cronWords(" in t                  # stored timetables read in local words
    assert "label.htmlFor" in t                        # param inputs associate their label


def test_builder_edit_agent_rehydrates_playbook(monkeypatch, tmp_path):
    # ?edit_agent=<name> rehydrates the playbook editor and round-trips the
    # override fields the builder can't show (so a save can't silently drop them).
    _isolate(monkeypatch, tmp_path)
    import maverick.domain_edit as de
    monkeypatch.setattr(de, "resolved_view", lambda name: ({
        "name": name, "description": "d", "persona": "p",
        "allow_tools": ["a"], "deny_tools": [], "max_risk": "medium",
        "workflow": [{"name": "s1", "instruction": "do", "tools": [], "gate": "approval"}],
    } if name == "invoice-clerk" else None))
    monkeypatch.setattr(de, "read_override",
                        lambda name: {"persona": "p", "knowledge_sources": ["kb1"], "compartment": "finance"})
    t = _client().get("/workflow-builder?edit_agent=invoice-clerk").text
    assert "PB_EDIT = null" not in t and "invoice-clerk" in t
    assert "renderPlaybook(PB_EDIT)" in t and "Editing agent" in t
    assert "knowledge_sources" in t and "finance" in t   # preserved on the round-trip
    # an unknown agent yields no prefill
    monkeypatch.setattr(de, "resolved_view", lambda name: None)
    assert "PB_EDIT = null" in _client().get("/workflow-builder?edit_agent=nope").text


def test_non_admin_edit_agent_deeplink_withholds_existing_pack(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _enable_proxy_auth(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:admin")
    from maverick_dashboard import rbac

    rbac.set_role("user:operator", "operator")
    import maverick.domain_edit as de

    def must_not_read(_name):
        raise AssertionError("non-admin route read an existing pack")

    monkeypatch.setattr(de, "resolved_view", must_not_read)
    html = _client().get(
        "/workflow-builder?edit_agent=invoice-clerk",
        headers={"X-Forwarded-User": "operator"},
    ).text
    assert "PB_EDIT = null" in html
    assert 'PB_EDIT_DENIED = "invoice-clerk"' in html
    assert "You can still draft an unsaved first pass." in html


def test_builder_edit_deeplink_rehydrates_editor(monkeypatch, tmp_path):
    # ?edit=<name> rehydrates the full editor so Save overwrites (the create-only
    # gap Maya flagged); takes precedence over the automate ?template= jump.
    _isolate(monkeypatch, tmp_path)
    tdir = tmp_path / ".maverick" / "templates"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "weekly-report.md").write_text(
        "---\nowner: local\ntitle: Weekly report\nparams:\n  - topic\n---\nResearch {{topic}}.\n", encoding="utf-8")
    t = _client().get("/workflow-builder?edit=weekly-report").text
    assert "WF_EDIT = null" not in t and "weekly-report" in t
    assert "renderDraft(WF_EDIT)" in t and "Editing" in t
    # unknown / absent -> no edit prefill, page still renders
    assert "WF_EDIT = null" in _client().get("/workflow-builder?edit=nope").text
    assert "WF_EDIT = null" in _client().get("/workflow-builder").text


def test_builder_prefill_deeplink_jumps_to_automate(monkeypatch, tmp_path):
    # ?template=<name> injects a prefill so the JS jumps straight to automating
    # an existing template (reusing the schedule/trigger panels), not the draft flow.
    _isolate(monkeypatch, tmp_path)
    tdir = tmp_path / ".maverick" / "templates"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "weekly-report.md").write_text(
        "---\nowner: local\ntitle: Weekly report\nparams:\n  - topic\n---\nbody\n", encoding="utf-8")
    r = _client().get("/workflow-builder?template=weekly-report")
    assert r.status_code == 200
    assert "weekly-report" in r.text and "WF_PREFILL = null" not in r.text
    # an unknown template (and no query) yields no prefill; the page still renders
    assert "WF_PREFILL = null" in _client().get("/workflow-builder?template=nope").text
    assert "WF_PREFILL = null" in _client().get("/workflow-builder").text


def test_workflow_builder_reads_plainly(monkeypatch, tmp_path):
    from test_support.plain_language import developer_terms

    _isolate(monkeypatch, tmp_path)
    t = _client().get("/workflow-builder").text
    assert developer_terms(t) == []
    for phrase in ("a name (id)", "no gate", "Trigger from a webhook", "POSTing", "Failed: '", "Save failed: '"):
        assert phrase not in t
    assert "Someone must approve" in t and "Start it from another app" in t


def test_extract_document_requires_review_and_never_calls_drafter(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr("maverick_dashboard.api._extract_binary_doc_text", lambda raw, name: "Procedure text")
    monkeypatch.setattr("maverick_dashboard.api._drafter_for", lambda form: pytest.fail("Extraction must not call a paid drafter"))
    response = _client().post("/api/v1/workflows/extract-source", files={"file": ("procedure.pdf", b"%PDF synthetic", "application/pdf")})
    assert response.status_code == 200
    assert response.json() == {"text": "Procedure text", "truncated": False, "review_required": True, "started": False}


def test_extract_document_refuses_unsupported_empty_and_oversize(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    for name, body in [("procedure.exe", b"data"), ("empty.txt", b""), ("large.txt", b"x" * 512001)]:
        response = _client().post("/api/v1/workflows/extract-source", files={"file": (name, body)})
        assert response.status_code == 422


def test_the_two_delete_buttons_say_what_they_delete_in_every_language():
    from pathlib import Path

    from maverick_dashboard import i18n_journeys
    page = (Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / "workflow_builder.html").read_text(encoding="utf-8")
    assert "productText(rm,'Delete');" not in page and "okText: 'Delete'," not in page
    assert page.count("productText(rm,'Delete schedule');") == 1
    assert page.count("productText(rm,'Delete start');") == 1
    # A schedule due within a minute is confirmed and deleted at once; otherwise
    # both deletes leave the list with an Undo toast.
    assert "okText: 'Delete schedule'" in page
    assert page.count("mvUndo(") == 2 and "Other apps can no longer start this workflow." in page
    for label in ("Delete schedule", "Delete start"):
        for lang in i18n_journeys.TRANSLATION_LANGS:
            assert i18n_journeys.entry(label, lang)[1] == lang, (label, lang)
