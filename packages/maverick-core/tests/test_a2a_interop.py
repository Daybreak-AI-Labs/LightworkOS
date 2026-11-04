"""A2A interop tests against the A2A Agent Card, in both directions: the card
Lightwork SERVES conforms, and cards OTHER agents serve are consumable.
"""
from __future__ import annotations

import pytest
from maverick import a2a

# Hand-authored third-party fixtures shaped per the A2A spec: a rich card
# (LangGraph-style optional fields) and a minimal-conformant one.
_THIRD_PARTY_RICH = {
    "protocolVersion": "0.3.0",
    "name": "ResearchMate",
    "description": "A LangGraph research agent.",
    "url": "https://agents.example.com/a2a/v1",
    "version": "2.3.1",
    "provider": {"organization": "Example Corp"},
    "capabilities": {"streaming": True, "pushNotifications": False},
    "defaultInputModes": ["text/plain", "application/json"],
    "defaultOutputModes": ["text/plain"],
    "skills": [
        {"id": "search", "name": "Web search",
         "description": "Search and summarize.", "tags": ["research"]},
        {"id": "cite", "name": "Citation check",
         "description": "Verify quotes.", "tags": []},
    ],
    "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
}

_THIRD_PARTY_MINIMAL = {
    "protocolVersion": "0.3.0",
    "name": "TinyAgent",
    "url": "https://tiny.example/a2a",
    "version": "0.1",
    "capabilities": {},
    "skills": [{"id": "echo", "name": "Echo", "description": "Echoes."}],
}


def test_third_party_cards_validate():
    assert a2a.validate_agent_card(_THIRD_PARTY_RICH) == []
    assert a2a.validate_agent_card(_THIRD_PARTY_MINIMAL) == []


def test_own_card_passes_own_validator():
    """Self-interop: the card Lightwork serves is consumable by its own
    consuming half (and therefore by any conformant peer)."""
    card = a2a.build_agent_card(base_url="https://mvk.example")
    assert a2a.validate_agent_card(card) == []
    parsed = a2a.parse_remote_card(card)
    assert parsed["name"] == "Lightwork" and parsed["streaming"] is True


def test_parse_remote_card_normalizes():
    parsed = a2a.parse_remote_card(_THIRD_PARTY_RICH)
    assert parsed["name"] == "ResearchMate"
    assert parsed["url"].startswith("https://")
    assert parsed["streaming"] is True
    assert [s["id"] for s in parsed["skills"]] == ["search", "cite"]
    assert parsed["skills"][1]["tags"] == []  # absent tags normalized


def test_parse_minimal_card_defaults():
    parsed = a2a.parse_remote_card(_THIRD_PARTY_MINIMAL)
    assert parsed["streaming"] is False
    assert parsed["version"] == "0.1"


@pytest.mark.parametrize("mutate,expect", [
    (lambda c: c.pop("name"), "missing required field: name"),
    (lambda c: c.pop("skills"), "missing required field: skills"),
    (lambda c: c.__setitem__("skills", "nope"), "skills must be a list"),
    (lambda c: c["skills"][0].pop("description"), "skills[0] missing description"),
    (lambda c: c.__setitem__("url", "ftp://x"), "url must be an http(s) URL"),
    (lambda c: c.__setitem__("capabilities", []), "capabilities must be an object"),
])
def test_validator_pinpoints_problems(mutate, expect):
    import copy
    card = copy.deepcopy(_THIRD_PARTY_RICH)
    mutate(card)
    assert any(expect in p for p in a2a.validate_agent_card(card))


def test_parse_refuses_nonconformant():
    with pytest.raises(ValueError, match="non-conformant agent card"):
        a2a.parse_remote_card({"name": "x"})


def test_validator_rejects_non_object():
    assert a2a.validate_agent_card(["not", "a", "card"]) == [
        "card must be a JSON object"]
