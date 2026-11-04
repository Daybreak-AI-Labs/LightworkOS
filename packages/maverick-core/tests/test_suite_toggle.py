"""Per-suite enable/disable: ``[suites]`` config -> ``enabled_domains`` filter.

The installer wizard writes ``[suites]`` (suite -> bool); the factory/orchestrator
spawn from ``enabled_domains()`` so a switched-off suite's packs become
unavailable. Opt-out semantics: absent/true = enabled, so the default behaviour
(no ``[suites]``) is unchanged.
"""
from __future__ import annotations

from maverick.domain import available_domains, enabled_domains, suite_for, suites_for_domain


def test_suite_for_prefix_mapping():
    assert suite_for("ops_purchasing") == "operations"
    assert suite_for("legal_research") == "legal"
    assert suite_for("finance_gl_close") == "finance"
    # Legacy/generic packs have no suite prefix and are never toggled off.
    assert suite_for("legal") is None
    assert suite_for("finance") is None
    assert suite_for("generic") is None


def test_no_config_returns_everything():
    assert enabled_domains(cfg={}) == available_domains()
    assert enabled_domains(cfg={"suites": {}}) == available_domains()


def test_disabling_a_suite_drops_only_its_packs():
    alld = available_domains()
    if not any(n.startswith("ops_") for n in alld):  # ops packs not in this build
        return
    out = enabled_domains(cfg={"suites": {"operations": False}})
    assert not any(n.startswith("ops_") for n in out), "operations packs should be gone"
    # legacy/generic packs and other suites survive
    assert "generic" in out
    if "finance" in alld:
        assert "finance" in out


def test_enabled_true_is_a_noop_and_toggles_are_independent():
    alld = available_domains()
    out = enabled_domains(cfg={"suites": {"operations": True, "legal": False}})
    if any(n.startswith("ops_") for n in alld):
        assert any(n.startswith("ops_") for n in out)
    if any(n.startswith("legal_") for n in alld):
        assert not any(n.startswith("legal_") for n in out)
    # the legacy 'legal' pack (no legal_ prefix) is unaffected by the suite toggle
    if "legal" in alld:
        assert "legal" in out


def test_fork_cannot_bypass_disabled_inherited_suite(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    (tmp_path / "client_fork.toml").write_text(
        'name = "client_fork"\nextends = "aero_avionics"\n', encoding="utf-8",
    )
    assert "client_fork" in available_domains()
    assert suites_for_domain("client_fork") == frozenset({"aerospace_defense"})
    assert "client_fork" not in enabled_domains(
        cfg={"suites": {"aerospace_defense": False}}
    )
