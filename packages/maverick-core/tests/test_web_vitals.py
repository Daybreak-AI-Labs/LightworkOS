"""Field Core Web Vitals: off by default, aggregate only, p75 per page and device."""
from __future__ import annotations

import calendar
import json
import os

import pytest
from maverick import web_vitals as vitals
from maverick.file_lock import private_path_is_restricted

DAY = 86_400
NOW = calendar.timegm((2026, 10, 6, 12, 0, 0))


@pytest.fixture
def home(monkeypatch, tmp_path):
    from maverick import config

    def configure(text: str) -> None:
        path = tmp_path / "config.toml"
        path.write_text(text, encoding="utf-8")
        monkeypatch.setenv("MAVERICK_CONFIG", str(path))
        config.reset_config_cache()

    for name in tuple(os.environ):
        if name.startswith("MAVERICK_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    configure("[analytics]\nweb_vitals = true\n")
    yield configure
    config.reset_config_cache()


def test_off_by_default(home):
    home("")
    assert vitals.enabled() is False
    with pytest.raises(vitals.VitalsError):
        vitals.record("/goals", "desktop", {"lcp": 900}, now=NOW)
    home("[analytics]\nweb_vitals = false\n")
    assert vitals.enabled() is False
    home('[analytics]\nweb_vitals = "yes"\n')
    assert vitals.enabled() is False


def test_p75_per_page_and_device_against_the_thresholds(home):
    for value in (1000, 1200, 1400, 1600, 1800, 2000, 2200, 2400, 2600, 2800, 3000, 3200, 3400, 3600, 3800, 4000,
                  4200, 4400, 4600, 4800):
        vitals.record("/goals", "phone", {"lcp": value, "inp": 120, "cls": 0.02}, now=NOW)
    for _ in range(vitals.MIN_SAMPLES):
        vitals.record("/goals", "desktop", {"lcp": 700, "inp": 40, "cls": 0.0}, now=NOW)
    rows = {(row["route"], row["device"]): row for row in vitals.report(now=NOW)["rows"]}
    phone = rows[("/goals", "phone")]
    assert phone["lcp"]["n"] == 20 and phone["enough"] is True
    # The 15th of 20 sorted values is 3800 ms; the report gives the upper edge
    # of the histogram bucket holding it, so it never understates.
    assert 3800 <= phone["lcp"]["p75"] <= 3900
    assert phone["lcp"]["good"] is False
    assert phone["inp"]["good"] is True and phone["cls"]["good"] is True
    assert phone["passes"] is False
    desktop = rows[("/goals", "desktop")]
    assert desktop["passes"] is True
    assert desktop["lcp"]["p75"] <= 800


def test_too_few_samples_report_only_a_count(home):
    vitals.record("/approvals", "desktop", {"lcp": 900}, now=NOW)
    (row,) = vitals.report(now=NOW)["rows"]
    assert row["enough"] is False and row["passes"] is None
    assert row["lcp"] == {"n": 1}


def test_only_the_last_28_days_count(home):
    for _ in range(vitals.MIN_SAMPLES):
        vitals.record("/goals", "desktop", {"lcp": 9000}, now=NOW - 30 * DAY)
        vitals.record("/goals", "desktop", {"lcp": 800}, now=NOW)
    (row,) = vitals.report(now=NOW)["rows"]
    assert row["lcp"]["n"] == vitals.MIN_SAMPLES and row["lcp"]["p75"] <= 900
    # Days older than the window are dropped from the file when it is written.
    vitals.record("/goals", "desktop", {"lcp": 800}, now=NOW)
    stored = json.loads(vitals.store_path().read_text())
    assert all(int(day) >= int((NOW - 28 * DAY) // DAY) for day in stored["days"])


def test_stores_no_person_no_raw_address_and_no_raw_values(home):
    vitals.record("/chat/goal/{goal_id}", "phone", {"lcp": 1234, "inp": 88, "cls": 0.05}, now=NOW)
    text = vitals.store_path().read_text()
    assert "1234" not in text and "88," not in text
    if os.name == "nt":
        # Windows has no mode bits; the store is created with a protected owner-only DACL.
        assert private_path_is_restricted(vitals.store_path(), 0o600)
    else:
        assert oct(vitals.store_path().stat().st_mode & 0o777) == "0o600"
    stored = json.loads(text)
    assert set(stored) == {"version", "days"}


@pytest.mark.parametrize("route,device,metrics", [
    ("goals", "desktop", {"lcp": 1}),                 # not a path
    ("/goals?x=1", "desktop", {"lcp": 1}),            # query strings never stored
    ("/x" * 200, "desktop", {"lcp": 1}),              # too long
    ("/goals", "tablet", {"lcp": 1}),                 # unknown device class
    ("/goals", "desktop", {}),                        # nothing measured
    ("/goals", "desktop", {"lcp": -1}),               # out of range
    ("/goals", "desktop", {"lcp": 600_001}),
    ("/goals", "desktop", {"cls": 101}),
    ("/goals", "desktop", {"inp": True}),
    ("/goals", "desktop", {"ttfb": 10}),              # unknown metric
])
def test_rejects_what_it_will_not_store(home, route, device, metrics):
    with pytest.raises(vitals.VitalsError):
        vitals.record(route, device, metrics, now=NOW)


def test_sampling_rate_is_a_fraction():
    assert 0 < vitals.SAMPLE_RATE <= 1


@pytest.mark.parametrize("text,expected", [
    ("", vitals.SAMPLE_RATE),
    ("web_vitals_sample_rate = 0.1\n", 0.1),
    ("web_vitals_sample_rate = 1\n", 1.0),
    ("web_vitals_sample_rate = 0\n", 0.0),
    ("web_vitals_sample_rate = 1.5\n", vitals.SAMPLE_RATE),     # out of range keeps the default
    ("web_vitals_sample_rate = -0.2\n", vitals.SAMPLE_RATE),
    ('web_vitals_sample_rate = "half"\n', vitals.SAMPLE_RATE),
    ("web_vitals_sample_rate = true\n", vitals.SAMPLE_RATE),
])
def test_the_share_of_visits_measured_is_a_setting(home, text, expected):
    home("[analytics]\nweb_vitals = true\n" + text)
    assert vitals.sample_rate() == expected
    assert vitals.report()["sample_rate"] == expected


def test_config_lint_knows_the_sample_rate_key():
    from maverick import config_lint

    assert "web_vitals_sample_rate" in config_lint.KNOWN_SCHEMA["analytics"]
    assert "web_vitals_sample_rate" in config_lint._NUMERIC_KEYS["analytics"]
    assert "web_vitals_sample_rate" not in config_lint._BOOL_KEYS["analytics"]
