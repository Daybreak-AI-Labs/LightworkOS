"""Deliverable hand-off: an approved deliverable is POSTed to the configured
system-of-record endpoint, reusing the signed webhook delivery."""
from __future__ import annotations

import maverick.webhooks as webhooks


def _set_config(monkeypatch, cfg):
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: cfg)


def test_no_endpoint_is_a_silent_noop(monkeypatch):
    _set_config(monkeypatch, {})  # no [deliverables] handoff_webhook
    fired = []
    monkeypatch.setattr(webhooks, "fire", lambda *a, **k: fired.append((a, k)) or 1)
    assert webhooks.fire_deliverable_handoff({"goal_id": 1}) == 0
    assert fired == []  # fire() never even called


def test_configured_endpoint_fires_signed_event(monkeypatch):
    _set_config(monkeypatch, {
        "deliverables": {"handoff_webhook": "https://sor.example/ingest"},
        "webhooks": {"secret": "s3cr3t"},  # pragma: allowlist secret
    })
    captured = {}

    def fake_fire(event, payload, *, urls=None, secret=None, timeout=5.0):
        captured.update(event=event, payload=payload, urls=urls, secret=secret)
        return len(urls or [])

    monkeypatch.setattr(webhooks, "fire", fake_fire)
    n = webhooks.fire_deliverable_handoff({"goal_id": 7, "domain": "finance_cash13w"})
    assert n == 1
    assert captured["event"] == "deliverable.approved"
    assert captured["urls"] == ["https://sor.example/ingest"]
    assert captured["secret"] == "s3cr3t"  # pragma: allowlist secret
    assert captured["payload"]["goal_id"] == 7


def test_env_referenced_url_is_not_expanded(monkeypatch):
    monkeypatch.setenv("MY_SOR_URL", "https://treasury.internal/deliverables")
    _set_config(monkeypatch, {
        "deliverables": {"handoff_webhook": "${MY_SOR_URL}"},
    })
    url, _ = webhooks._load_handoff_target()
    assert url is None


def test_unset_env_reference_yields_no_target(monkeypatch):
    monkeypatch.delenv("MISSING_SOR_URL", raising=False)
    _set_config(monkeypatch, {"deliverables": {"handoff_webhook": "${MISSING_SOR_URL}"}})
    url, _ = webhooks._load_handoff_target()
    assert url is None
