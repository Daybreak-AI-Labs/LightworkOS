"""marketplace_moderation: pure APPROVE/REVIEW/REJECT heuristics.

NO network: pure heuristics; every test runs the scanner directly.
"""
from __future__ import annotations

from maverick.tools.marketplace_moderation import _scan, marketplace_moderation


def _run(listing):
    return marketplace_moderation().fn({"op": "scan", "listing": listing})


def test_clean_listing_approves():
    res = _scan({
        "title": "Vintage oak desk",
        "description": "A solid oak writing desk in good condition.",
        "tags": ["furniture", "desk"],
    })
    assert res["decision"] == "APPROVE"


def test_banned_term_rejects():
    res = _scan({
        "title": "Replica handbag",
        "description": "Looks just like the real thing.",
        "tags": ["bags"],
    })
    assert res["decision"] == "REJECT"
    assert any("banned" in r for r in res["reasons"])
    # banned wins even with other issues
    assert _scan({"title": "gun", "description": "", "tags": []})["decision"] == "REJECT"


def test_missing_fields_reviews():
    res = _scan({"title": "Lamp", "description": "", "tags": ["home"]})
    assert res["decision"] == "REVIEW"
    assert any("missing fields" in r and "description" in r for r in res["reasons"])
    # no tags also flags
    res2 = _scan({"title": "Lamp", "description": "A nice lamp.", "tags": []})
    assert res2["decision"] == "REVIEW"


def test_spam_signals_review():
    # excessive caps + repeated chars + promo phrase
    res = _scan({
        "title": "HUGE SAAAALE!!!! ACT NOW",
        "description": "BUY THIS RIGHT NOW LIMITED TIME ONLY OFFER",
        "tags": ["deal"],
    })
    assert res["decision"] == "REVIEW"
    joined = " ".join(res["reasons"])
    assert "repeated characters" in joined
    assert "excessive caps" in joined
    assert "promo phrases" in joined


def test_run_string_and_errors():
    out = _run({"title": "Oak chair", "description": "Sturdy oak chair.",
                "tags": ["furniture"]})
    assert out.startswith("APPROVE")
    assert marketplace_moderation().fn({"op": "scan"}).startswith("ERROR")
    assert marketplace_moderation().fn({"op": "nope", "listing": {}}).startswith("ERROR")


def test_factory_tool():
    t = marketplace_moderation()
    assert t.name == "marketplace_moderation"
    assert t.parallel_safe is True
    assert t.input_schema["required"] == ["listing"]
