"""Outbound webhooks honor the enterprise egress lock."""
from __future__ import annotations

import maverick.enterprise as ent
from maverick import webhooks


def _capture_submits(monkeypatch):
    submitted: list[str] = []
    monkeypatch.setattr(webhooks, "_get_executor", lambda: object())
    monkeypatch.setattr(
        webhooks, "_submit",
        lambda executor, fn, url, *a: submitted.append(url) or True,
    )
    return submitted


def test_fire_blocks_non_allowlisted_under_egress_lock(monkeypatch):
    submitted = _capture_submits(monkeypatch)
    # Egress lock on: only the allowlisted host is permitted.
    monkeypatch.setattr(ent, "egress_permitted", lambda url: "good.example.com" in url)

    sent = webhooks.fire(
        "evt", {"a": 1},
        urls=["https://good.example.com/hook", "https://evil.test/hook"],
        secret=None,
    )
    assert sent == 1
    assert submitted == ["https://good.example.com/hook"]  # the off-boundary URL dropped


def test_fire_allows_all_when_egress_open(monkeypatch):
    submitted = _capture_submits(monkeypatch)
    # Enterprise mode off (or all hosts permitted) -> unchanged behavior.
    monkeypatch.setattr(ent, "egress_permitted", lambda url: True)

    sent = webhooks.fire(
        "evt", {"a": 1},
        urls=["https://a.test/h", "https://b.test/h"],
        secret=None,
    )
    assert sent == 2
    assert submitted == ["https://a.test/h", "https://b.test/h"]
