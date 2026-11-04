"""doctor warns about US-default regions only when a data-residency requirement
is declared — zero noise otherwise."""
from __future__ import annotations


def _rows(monkeypatch):
    import maverick.health as health
    captured = []
    monkeypatch.setattr(health, "_row",
                        lambda m, label, detail="", fix="": captured.append((label, detail)))
    return health, captured


def test_no_warning_without_declared_residency(monkeypatch):
    health, captured = _rows(monkeypatch)
    monkeypatch.delenv("MAVERICK_RESIDENCY_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    health._check_data_residency({})
    assert captured == []


def test_warns_on_us_defaults_when_residency_declared(monkeypatch):
    health, captured = _rows(monkeypatch)
    monkeypatch.setenv("MAVERICK_RESIDENCY_REGION", "eu")
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("VERTEX_LOCATION", raising=False)
    health._check_data_residency({})
    labels = [d for (_l, d) in captured]
    assert any("AWS_REGION" in d for d in labels)
    assert any("VERTEX_LOCATION" in d for d in labels)


def test_no_warning_when_regions_set(monkeypatch):
    health, captured = _rows(monkeypatch)
    monkeypatch.setenv("MAVERICK_RESIDENCY_REGION", "eu")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.setenv("VERTEX_LOCATION", "europe-west1")
    health._check_data_residency({})
    assert captured == []
