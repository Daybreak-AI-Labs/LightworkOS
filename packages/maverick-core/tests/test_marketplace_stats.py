"""Marketplace stats aggregation over the ratings ledger."""
from __future__ import annotations

from maverick.marketplace.ratings import RatingsLedger
from maverick.marketplace.stats import summarize


def _ledger(tmp_path, ratings):
    led = RatingsLedger(tmp_path / "ratings.json")
    for kind, name, stars in ratings:
        led.rate(kind, name, stars)
    return led


def test_empty_ledger(tmp_path):
    s = summarize(RatingsLedger(tmp_path / "r.json"))
    assert s["total"] == 0 and s["average"] == 0.0
    assert s["distribution"] == {"1": 0, "2": 0, "3": 0, "4": 0, "5": 0}
    assert s["by_kind"] == {} and s["top_rated"] == []


def test_aggregates_total_average_distribution(tmp_path):
    led = _ledger(tmp_path, [
        ("skills", "a", 5), ("skills", "b", 3), ("templates", "c", 4),
    ])
    s = summarize(led)
    assert s["total"] == 3
    assert s["average"] == round((5 + 3 + 4) / 3, 2)
    assert s["distribution"]["5"] == 1 and s["distribution"]["3"] == 1
    assert s["distribution"]["1"] == 0


def test_by_kind_breakdown(tmp_path):
    led = _ledger(tmp_path, [
        ("skills", "a", 5), ("skills", "b", 1), ("templates", "c", 4),
    ])
    s = summarize(led)
    assert s["by_kind"]["skills"] == {"count": 2, "average": 3.0}
    assert s["by_kind"]["templates"] == {"count": 1, "average": 4.0}


def test_top_rated_sorted(tmp_path):
    led = _ledger(tmp_path, [
        ("skills", "low", 2), ("skills", "high", 5), ("templates", "mid", 4),
    ])
    s = summarize(led, top_n=2)
    assert [r["name"] for r in s["top_rated"]] == ["high", "mid"]
    assert s["top_rated"][0]["stars"] == 5


def test_summarize_ignores_malformed(tmp_path):
    led = RatingsLedger(tmp_path / "r.json")
    led.rate("skills", "ok", 4)
    # inject a malformed entry directly
    import json
    raw = json.loads((tmp_path / "r.json").read_text())
    raw["skills"]["bad"] = {"stars": "oops"}
    raw["skills"]["alsobad"] = {"stars": 99}
    (tmp_path / "r.json").write_text(json.dumps(raw))
    s = summarize(led)
    assert s["total"] == 1  # only the valid 4-star counted


def test_rate_is_concurrency_safe(tmp_path):
    """Separate ledgers at one path (≈ separate processes) rating different
    names must not clobber each other's entry."""
    import threading

    p = tmp_path / "ratings.json"
    n = 24

    def worker(i: int):
        RatingsLedger(p).rate("skills", f"pack{i:03d}", (i % 5) + 1)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    all_skills = RatingsLedger(p).all_ratings("skills")
    assert len(all_skills) == n
    assert list(tmp_path.glob("*.tmp")) == []
