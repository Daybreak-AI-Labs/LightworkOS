"""Supply-chain pinning: snapshot/pin/verify ledger.

Offline + deterministic: ``importlib.metadata.distributions`` is faked so the
"installed environment" is a scripted list of fake dists.
"""
from __future__ import annotations

import importlib.metadata
import json
import logging
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from maverick import supply_chain as sc
from maverick.file_lock import private_path_is_restricted


def _dist(name: str, version: str):
    return SimpleNamespace(metadata={"Name": name}, version=version)


def _fake_env(monkeypatch, dists):
    monkeypatch.setattr(importlib.metadata, "distributions", lambda: list(dists))


@pytest.fixture(autouse=True)
def _feature_off(monkeypatch):
    monkeypatch.delenv("MAVERICK_SUPPLY_CHAIN_PINNING", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)


def test_snapshot_normalizes_names_pep503(monkeypatch):
    _fake_env(monkeypatch, [_dist("My_Package.Foo", "1.0"), _dist("HTTPX", "0.27.0")])
    snap = sc.snapshot()
    assert snap == {"my-package-foo": "1.0", "httpx": "0.27.0"}


def test_snapshot_skips_broken_dist_and_keeps_first_duplicate(monkeypatch):
    class _Broken:
        @property
        def metadata(self):
            raise OSError("corrupt dist-info")

    _fake_env(monkeypatch, [
        _dist("pkg", "1.0"),
        _Broken(),
        _dist("PKG", "2.0"),                      # duplicate on sys.path: first wins
        SimpleNamespace(metadata={"Name": None}, version="9"),  # nameless: skipped
    ])
    assert sc.snapshot() == {"pkg": "1.0"}


def test_write_pins_roundtrip_verify_ok(monkeypatch, tmp_path):
    _fake_env(monkeypatch, [_dist("alpha", "1.0"), _dist("beta", "2.1")])
    path = tmp_path / "pins.json"
    ts = datetime(2026, 6, 10, tzinfo=timezone.utc)
    assert sc.write_pins(path, now=ts) == path

    data = json.loads(path.read_text())
    assert data["generated_at"] == ts.isoformat()
    assert data["pins"] == {"alpha": "1.0", "beta": "2.1"}

    report = sc.verify(path)
    assert report.ok is True
    assert report.missing == [] and report.drifted == [] and report.unpinned == []
    assert report.generated_at == ts.isoformat()
    assert "PASS" in sc.render(report)


def test_verify_detects_drift(monkeypatch, tmp_path):
    _fake_env(monkeypatch, [_dist("alpha", "1.0"), _dist("beta", "2.1")])
    path = sc.write_pins(tmp_path / "pins.json")
    _fake_env(monkeypatch, [_dist("alpha", "1.0"), _dist("beta", "9.9")])

    report = sc.verify(path)
    assert report.ok is False
    assert report.drifted == [("beta", "2.1", "9.9")]
    rendered = sc.render(report)
    assert "FAIL" in rendered and "beta" in rendered and "2.1 -> installed 9.9" in rendered


def test_verify_missing_and_unpinned(monkeypatch, tmp_path):
    _fake_env(monkeypatch, [_dist("alpha", "1.0"), _dist("gone", "0.1")])
    path = sc.write_pins(tmp_path / "pins.json")
    _fake_env(monkeypatch, [_dist("alpha", "1.0"), _dist("newcomer", "3.0")])

    report = sc.verify(path)
    assert report.missing == ["gone"]
    assert report.unpinned == ["newcomer"]
    assert report.ok is False  # missing fails; unpinned alone would not


def test_unpinned_alone_is_warning_not_failure(monkeypatch, tmp_path):
    _fake_env(monkeypatch, [_dist("alpha", "1.0")])
    path = sc.write_pins(tmp_path / "pins.json")
    _fake_env(monkeypatch, [_dist("alpha", "1.0"), _dist("extra", "0.1")])

    report = sc.verify(path)
    assert report.ok is True
    assert report.unpinned == ["extra"]
    assert "PASS" in sc.render(report) and "extra" in sc.render(report)


def test_verify_renormalizes_hand_edited_pins(monkeypatch, tmp_path):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"generated_at": "x", "pins": {"My_Pkg": "1.0"}}))
    _fake_env(monkeypatch, [_dist("my-pkg", "1.0")])
    assert sc.verify(path).ok is True


def test_write_pins_atomic_and_0600(monkeypatch, tmp_path):
    _fake_env(monkeypatch, [_dist("alpha", "1.0")])
    path = sc.write_pins(tmp_path / "pins.json")
    assert private_path_is_restricted(path, 0o600)
    assert not list(tmp_path.glob(".pins.json-*.tmp"))


def test_default_path_under_data_dir(monkeypatch, tmp_path):
    # conftest pins HOME to tmp_path, so data_dir() == tmp_path/.maverick.
    _fake_env(monkeypatch, [_dist("alpha", "1.0")])
    path = sc.write_pins()
    assert path == tmp_path / ".maverick" / "supply_chain_pins.json"
    assert path.exists()


def test_check_or_warn_off_by_default(monkeypatch, tmp_path):
    _fake_env(monkeypatch, [_dist("alpha", "1.0")])
    pins = sc.write_pins(tmp_path / "pins.json")
    assert sc.enabled() is False
    assert sc.check_or_warn(pins) is None  # default OFF: inert even with pins


def test_check_or_warn_env_enables_and_warns_on_fail(monkeypatch, tmp_path, caplog):
    _fake_env(monkeypatch, [_dist("alpha", "1.0")])
    pins = sc.write_pins(tmp_path / "pins.json")
    _fake_env(monkeypatch, [_dist("alpha", "6.6.6")])
    monkeypatch.setenv("MAVERICK_SUPPLY_CHAIN_PINNING", "1")

    with caplog.at_level(logging.WARNING, logger="maverick.supply_chain"):
        report = sc.check_or_warn(pins)
    assert report is not None and report.ok is False
    assert any("FAILED" in r.message for r in caplog.records)


def test_check_or_warn_pass_returns_report_without_warning(monkeypatch, tmp_path, caplog):
    _fake_env(monkeypatch, [_dist("alpha", "1.0")])
    pins = sc.write_pins(tmp_path / "pins.json")
    monkeypatch.setenv("MAVERICK_SUPPLY_CHAIN_PINNING", "true")

    with caplog.at_level(logging.WARNING, logger="maverick.supply_chain"):
        report = sc.check_or_warn(pins)
    assert report is not None and report.ok is True
    assert not any("FAILED" in r.message for r in caplog.records)


def test_check_or_warn_missing_pins_file_is_none(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_SUPPLY_CHAIN_PINNING", "1")
    assert sc.check_or_warn(tmp_path / "nope.json") is None


def test_check_or_warn_never_raises_on_corrupt_pins(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("MAVERICK_SUPPLY_CHAIN_PINNING", "1")
    bad = tmp_path / "pins.json"
    bad.write_text("{ not json")
    with caplog.at_level(logging.WARNING, logger="maverick.supply_chain"):
        assert sc.check_or_warn(bad) is None  # fail-open, logged
    assert any("skipped" in r.message for r in caplog.records)


def test_env_zero_wins_over_enabled_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[safety]\nsupply_chain_pinning = true\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert sc.enabled() is True               # config turns it on
    monkeypatch.setenv("MAVERICK_SUPPLY_CHAIN_PINNING", "0")
    assert sc.enabled() is False              # env wins over [safety]
