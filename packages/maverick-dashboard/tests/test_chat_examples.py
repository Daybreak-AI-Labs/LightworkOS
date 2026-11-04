"""The empty chat says what Lightwork can do, with examples for the person's department, and one true limit."""
from __future__ import annotations

import html
import inspect
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import chat_examples
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _request():
    return SimpleNamespace(query_params={}, headers={}, cookies={}, state=SimpleNamespace())


def _scoped(monkeypatch, suites, recorded=None):
    monkeypatch.setattr("maverick_dashboard.auth.caller_suites", lambda request: suites)
    monkeypatch.setattr("maverick.config.get_first_outcome",
                        lambda: {"department": recorded, "sample_workspace_created": False})


def test_a_finance_person_sees_finance_examples_first(monkeypatch):
    _scoped(monkeypatch, frozenset({"finance"}))
    found = chat_examples.examples_for(_request())
    assert found["department"] == "Finance"
    assert 4 <= len(found["examples"]) <= 6
    assert found["examples"][:3] == list(chat_examples.EXAMPLES["finance"])


def test_a_procurement_person_sees_procurement_before_the_finance_sample(monkeypatch):
    _scoped(monkeypatch, frozenset({"procurement"}))
    found = chat_examples.examples_for(_request())
    assert found["department"] == "Procurement"
    assert found["examples"][0] == chat_examples.EXAMPLES["procurement"][0]


def test_an_unscoped_administrator_gets_the_department_picked_at_setup(monkeypatch):
    _scoped(monkeypatch, None, recorded="legal")
    found = chat_examples.examples_for(_request())
    assert found["department"] == "Legal"
    assert found["examples"][0] == chat_examples.EXAMPLES["legal"][0]


def test_with_no_department_known_the_examples_are_general(monkeypatch):
    _scoped(monkeypatch, None, recorded=None)
    found = chat_examples.examples_for(_request())
    assert found["department"] is None
    assert found["examples"] == list(chat_examples.GENERAL)
    assert 4 <= len(found["examples"]) <= 6


def test_every_department_in_the_sample_catalogue_has_examples():
    from maverick import sample_outcomes

    assert set(chat_examples.EXAMPLES) == set(sample_outcomes.FIRST_OUTCOMES)
    for texts in chat_examples.EXAMPLES.values():
        assert len(texts) == 3 and all(text.endswith((".", "?")) for text in texts)


def test_the_limit_line_is_true_in_code():
    """The empty state promises a command never runs without a person's approval;
    the shell tool must keep refusing silent and standing approvals for that to hold."""
    from maverick.tools import shell

    source = inspect.getsource(shell)
    call = source.split("permit = require_operation_consent(", 1)[1].split("except ConsentDenied", 1)[0]
    assert "allow_auto_approve=False" in call and "consult_ledger=False" in call
    assert "never runs a command without a person's approval" in chat_examples.LIMITS
    assert "can make mistakes" in chat_examples.LIMITS


@pytest.fixture
def ready(tmp_path, monkeypatch):
    from maverick import world_model
    from maverick_dashboard import onboarding_state

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(onboarding_state, "workspace_readiness",
                        lambda: {"verdict": "ready", "reason": "", "next_action": None})


def test_the_empty_chat_offers_examples_and_states_the_limit(ready, monkeypatch):
    _scoped(monkeypatch, frozenset({"hr"}))
    body = html.unescape(client.get("/chat").text)
    section = body.split('id="chat-examples"', 1)[1].split("</section>", 1)[0]
    assert section.count('class="cs-example"') >= 4
    assert chat_examples.EXAMPLES["hr"][0] in section
    assert "picked for" in section and ">HR<" in section
    assert 'id="chat-limits"' in body and "never runs a command without a person" in body


def test_people_who_cannot_start_work_see_no_examples(ready, monkeypatch):
    from maverick_dashboard import app as app_module

    _scoped(monkeypatch, frozenset({"hr"}))
    monkeypatch.setattr(app_module, "has_permission", lambda request, permission: permission == "view")
    body = client.get("/chat").text
    assert 'id="chat-examples"' not in body
    assert 'id="chat-limits"' in body


def test_every_ai_entry_point_says_it_is_ai_what_it_does_and_two_limits(ready, monkeypatch):
    """The empty chat and Copilot each carry an AI disclosure, a capability
    statement, a reliability statement and at least two limitations."""
    assert chat_examples.CAPABILITY.startswith("Lightwork is an AI assistant.")
    assert "never runs a command without a person's approval" in chat_examples.LIMITS
    assert "only reaches the tools and connected systems your administrator allows" in chat_examples.LIMITS
    body = html.unescape(client.get("/chat").text)
    assert 'id="chat-capability"' in body and "Lightwork is an AI assistant." in body
    assert "can make mistakes" in body and "connected systems your administrator allows" in body
    about = " ".join(body.split("id=\"mv-copilot-about\"", 1)[1].split("</p>", 1)[0].split())
    assert "Copilot is an AI guide" in about and "can make mistakes" in about
    assert "never changes a setting or starts work by itself" in about
