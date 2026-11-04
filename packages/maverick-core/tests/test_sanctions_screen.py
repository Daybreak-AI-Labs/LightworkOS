"""Sanctions screening (finance-agent-suite §2.6)."""
from __future__ import annotations

import maverick.tools.sanctions_screen as sanctions_mod
import pytest
from maverick.tools.sanctions_screen import load_list, normalize, sanctions_screen, screen

_SDN = ["Evil Corp LLC", "Bad Actor", "Sanctioned Holdings Ltd", "John Q Public"]


def test_normalize():
    assert normalize("  Evil Corp, LLC. ") == "evil corp llc"


def test_exact_match():
    r = screen("evil corp llc", _SDN)
    assert r["match"] is True
    assert r["hits"][0]["score"] == 1.0
    assert r["hits"][0]["name"] == "Evil Corp LLC"


def test_clear_when_no_match():
    r = screen("Totally Legit Inc", _SDN)
    assert r["match"] is False
    assert r["hits"] == []


def test_token_overlap_below_threshold_clears():
    # shares one token with "John Q Public" but not enough at 0.85
    assert screen("John Smith", _SDN, threshold=0.85)["match"] is False


def test_token_overlap_match_at_lower_threshold():
    r = screen("Sanctioned Holdings", _SDN, threshold=0.6)
    assert r["match"] is True
    assert any("Sanctioned Holdings" in h["name"] for h in r["hits"])


def test_screen_rejects_unsafe_thresholds():
    for threshold in (-1, 0, 1.1):
        with pytest.raises(ValueError):
            screen("Totally Legit Inc", _SDN, threshold=threshold)


def test_tool_rejects_negative_threshold_without_leaking_list(tmp_path, monkeypatch):
    p = tmp_path / "sdn.txt"
    p.write_text("Secret Watchlist One\nSecret Watchlist Two\n", encoding="utf-8")
    monkeypatch.setattr(sanctions_mod, "_list_path", lambda: p)

    out = sanctions_screen().fn({"name": "Totally Legit Inc", "threshold": -1})

    assert out.startswith("ERROR: threshold")
    assert "Secret Watchlist" not in out


def test_load_list_newline(tmp_path):
    p = tmp_path / "sdn.txt"
    p.write_text("Evil Corp LLC\nBad Actor\n\n", encoding="utf-8")
    assert load_list(p) == ["Evil Corp LLC", "Bad Actor"]


def test_load_list_json(tmp_path):
    p = tmp_path / "sdn.json"
    p.write_text('{"names": ["A Co", "B Co"]}', encoding="utf-8")
    assert load_list(p) == ["A Co", "B Co"]


def test_load_list_missing(tmp_path):
    assert load_list(tmp_path / "nope.txt") == []


def test_tool_requires_name():
    assert sanctions_screen().fn({"name": ""}).startswith("ERROR")


def test_tool_errors_without_list(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    out = sanctions_screen().fn({"name": "Anyone"})
    assert out.startswith("ERROR") and "sanctions list" in out


def test_tool_uses_governed_screening_and_case_when_enabled(monkeypatch):
    from maverick.finance import aml_screening

    calls = []
    monkeypatch.setattr(aml_screening, "enabled", lambda: True)
    monkeypatch.setattr(
        aml_screening,
        "screen_subject",
        lambda name, **kwargs: calls.append((name, kwargs)) or {
            "match": True,
            "screened_lists": [{"list_id": "FSL-test"}],
            "case": {"id": "FSC-test"},
            "hits": [{
                "entry_name": "Acme Shipping",
                "score": 0.94,
                "match_method": "character_similarity",
                "citation": {
                    "source_name": "OFAC fixture",
                    "list_version": "2026-07-22",
                },
            }],
        },
    )

    out = sanctions_screen().fn({"name": "Acme Shiping", "subject_ref": "vendor-42"})

    assert "POSSIBLE SANCTIONS HIT" in out
    assert "FSC-test" in out
    assert "character_similarity" in out
    assert calls[0][0] == "Acme Shiping"
    assert calls[0][1]["subject_ref"] == "vendor-42"


def test_governed_screening_never_falls_back_or_accepts_threshold_override(monkeypatch):
    from maverick.finance import aml_screening

    monkeypatch.setattr(aml_screening, "enabled", lambda: True)
    monkeypatch.setattr(
        sanctions_mod,
        "load_list",
        lambda _path: (_ for _ in ()).throw(AssertionError("legacy fallback used")),
    )
    monkeypatch.setattr(
        aml_screening,
        "screen_subject",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            aml_screening.ScreeningIncompleteError("no complete list scope")
        ),
    )

    incomplete = sanctions_screen().fn({"name": "Anyone"})
    override = sanctions_screen().fn({"name": "Anyone", "threshold": 0.9})

    assert incomplete.startswith("ERROR: governed sanctions screening is incomplete")
    assert "no complete list scope" in incomplete
    assert override.startswith("ERROR: threshold overrides")
