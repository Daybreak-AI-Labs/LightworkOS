from __future__ import annotations

from maverick import compliance_catalog as catalog

_EXPECTED_KEYS = {
    "ai_governance",
    "privacy_automation",
    "consent_preferences",
    "tech_risk_compliance",
    "third_party_management",
    "data_use_governance",
}
_STATUSES = {catalog.STATUS_SHIPPED, catalog.STATUS_PREVIEW, catalog.STATUS_EXTERNAL}


def test_six_suites_cover_the_product() -> None:
    suites = catalog.suites()
    assert len(suites) == 6
    assert {suite.key for suite in suites} == _EXPECTED_KEYS
    # Every suite carries a label, a description, and at least one module.
    for suite in suites:
        assert suite.label and suite.description
        assert suite.modules


def test_every_module_path_is_a_string_route() -> None:
    for suite in catalog.suites():
        for module in suite.modules:
            assert isinstance(module.path, str)
            assert module.path.startswith("/")
            assert isinstance(module.label, str) and module.label


def test_every_status_is_one_of_the_three() -> None:
    for suite in catalog.suites():
        for module in suite.modules:
            assert module.status in _STATUSES


def test_module_status_round_trips() -> None:
    for suite in catalog.suites():
        for module in suite.modules:
            assert catalog.module_status(module.path) == module.status
    assert catalog.module_status("/not-a-real-module") is None


def test_status_metadata_is_complete_and_consistent() -> None:
    assert set(catalog.STATUS_ORDER) == _STATUSES
    assert len(catalog.STATUS_ORDER) == 3
    for status in _STATUSES:
        assert status in catalog.STATUS_LABELS
        assert status in catalog.STATUS_MEANINGS
        assert status in catalog.STATUS_BADGE_CLASS
        # badge_class() must agree with the table it derives from.
        assert catalog.badge_class(status) == catalog.STATUS_BADGE_CLASS[status]
    assert catalog.badge_class("nonsense") == ""


def test_module_paths_are_unique() -> None:
    paths = [m.path for s in catalog.suites() for m in s.modules]
    assert len(paths) == len(set(paths))
