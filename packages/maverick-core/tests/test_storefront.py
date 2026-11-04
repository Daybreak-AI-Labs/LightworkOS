"""Marketplace catalogs: browsable packs (by department) and connectors."""
from __future__ import annotations

from maverick.domain import suite_for
from maverick.marketplace import storefront as marketplace


def test_pack_marketplace_groups_packs_under_departments():
    cat = marketplace.pack_marketplace()
    assert cat, "expected populated marketplace"
    titles = [d["title"] for d in cat]
    assert titles == sorted(titles)
    finance = next(d for d in cat if d["key"] == "finance")
    assert finance["headcount"] == len(finance["packs"]) > 0
    assert finance["charter"]
    names = [p["name"] for p in finance["packs"]]
    assert all(suite_for(n) == "finance" for n in names)
    # Each pack card carries the fields a buyer browses on.
    assert set(finance["packs"][0]) >= {"name", "description", "max_risk"}


def test_search_packs_matches_name_or_description():
    hits = marketplace.search_packs("finance")
    assert hits
    assert all("department" in h and "suite" in h for h in hits)
    assert marketplace.search_packs("") == []
    assert marketplace.search_packs("zzz_no_such_pack_xyz") == []


def test_disabled_suite_excluded_from_marketplace():
    cfg = {"suites": {"finance": False}}
    keys = {d["key"] for d in marketplace.pack_marketplace(cfg)}
    assert "finance" not in keys
    # Disabling the suite removes its packs from search (other packs may still
    # match the word "finance" in their description — those are fine).
    assert all(h["suite"] != "finance"
               for h in marketplace.search_packs("finance", cfg))


def test_connector_marketplace_counts_and_searches():
    full = marketplace.connector_marketplace()
    assert full["total"] > 50
    assert len(full["connectors"]) == full["total"]
    assert all({"name", "label", "env_count"} <= set(c) for c in full["connectors"])
    # Search narrows the list but total stays the full catalog size (honest count).
    filtered = marketplace.connector_marketplace("zendesk")
    assert filtered["total"] == full["total"]
    assert len(filtered["connectors"]) < full["total"]
    assert any(c["name"] == "zendesk" for c in filtered["connectors"])
