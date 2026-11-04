"""Kernel-level department (suite) grant enforcement.

The grant store lives in the kernel so the deploy/dispatch chokepoints gate
EVERY caller (dashboard, CLI, any other surface). Safety invariants under test:
  * empty acting principal (host operator / auth off) -> unrestricted;
  * configured dashboard admins -> unrestricted;
  * ``deploy_department`` raises DepartmentAccessError outside the grant;
  * ``fleet.ensure_dispatch_allowed`` gates domain-bound agents only;
  * resolution chain: explicit grant -> registered resolver -> config default.
"""
from __future__ import annotations

import pytest
from maverick import suite_grants as sg


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")


def test_unrestricted_paths():
    # No acting principal (CLI / auth off) and suite-less (generic) packs are
    # never scoped, even when a grant store exists for other principals.
    sg.set_suites("user:fin", ["finance"])
    assert sg.suite_allowed_for(None, "legal")
    assert sg.suite_allowed_for("", "legal")
    assert sg.suite_allowed_for("user:fin", None)
    # And an ungranted principal is unrestricted by default (opt-in scoping).
    assert sg.suite_allowed_for("user:other", "legal")


def test_admin_principals_never_scoped(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:boss")
    sg.set_suites("user:boss", ["finance"])  # a stale grant must not bite
    assert sg.is_admin_principal("user:boss")
    assert sg.suite_allowed_for("user:boss", "legal")


def test_ensure_raises_department_access_error():
    sg.set_suites("user:fin", ["finance"])
    sg.ensure_suite_allowed("user:fin", "finance")
    with pytest.raises(sg.DepartmentAccessError) as exc:
        sg.ensure_suite_allowed("user:fin", "legal")
    assert "legal" in str(exc.value) and "user:fin" in str(exc.value)


def test_resolution_chain_explicit_then_resolver_then_default(monkeypatch):
    import maverick.config as config
    monkeypatch.setattr(config, "load_config",
                        lambda: {"dashboard": {"default_suites": ["tax"]}})
    calls = []

    def resolver(principal):
        calls.append(principal)
        if principal == "user:grouped":
            return ["finance", "bogus_suite"]  # unknown keys are dropped
        return None

    monkeypatch.setattr(sg, "_EXTRA_RESOLVERS", [resolver])
    # Explicit grant wins without consulting the resolver.
    sg.set_suites("user:explicit", ["legal"])
    assert sg.granted_suites("user:explicit") == frozenset({"legal"})
    assert calls == []
    # Resolver answer wins over the config default, validated to known suites.
    assert sg.granted_suites("user:grouped") == frozenset({"finance"})
    # No explicit, resolver has no opinion -> config default.
    assert sg.granted_suites("user:plain") == frozenset({"tax"})


def test_resolver_error_fails_closed(monkeypatch):
    import maverick.config as config
    monkeypatch.setattr(config, "load_config",
                        lambda: {"dashboard": {"default_suites": ["finance"]}})

    def broken(principal):
        raise RuntimeError("group store unavailable")

    monkeypatch.setattr(sg, "_EXTRA_RESOLVERS", [broken])
    with pytest.raises(sg.SuiteGrantStoreError):
        sg.granted_suites("user:x")


def test_resolver_error_cannot_become_unrestricted_without_default(monkeypatch):
    import maverick.config as config
    monkeypatch.setattr(config, "load_config", dict)

    def broken(principal):
        raise RuntimeError("group store unavailable")

    monkeypatch.setattr(sg, "_EXTRA_RESOLVERS", [broken])
    with pytest.raises(sg.SuiteGrantStoreError):
        sg.ensure_suite_allowed("user:x", "legal")


def test_register_grant_resolver_is_idempotent(monkeypatch):
    monkeypatch.setattr(sg, "_EXTRA_RESOLVERS", [])

    def fn(principal):
        return None

    sg.register_grant_resolver(fn)
    sg.register_grant_resolver(fn)
    assert [fn] == sg._EXTRA_RESOLVERS


def test_deploy_department_gates_on_owner_grant():
    from maverick.departments import deploy_department
    sg.set_suites("user:fin", ["finance"])
    # Outside the grant: the KERNEL refuses, whatever the calling surface.
    with pytest.raises(sg.DepartmentAccessError):
        deploy_department("legal", "user:fin", save=False)
    # Inside the grant: deploys.
    fleet = deploy_department("finance", "user:fin", save=False)
    assert fleet is not None and fleet.agents
    # Host operator (empty owner) stays unrestricted — kernel rule 1.
    assert deploy_department("legal", "", save=False) is not None


def test_ensure_dispatch_allowed_gates_domain_bound_agents():
    from maverick.fleet import FleetAgent, ensure_dispatch_allowed
    sg.set_suites("user:fin", ["finance"])
    legal = FleetAgent(name="legal_contracts", role="legal",
                       domain="legal_contracts")
    generic = FleetAgent(name="helper", role="ops")
    with pytest.raises(sg.DepartmentAccessError):
        ensure_dispatch_allowed("user:fin", legal)
    ensure_dispatch_allowed("user:fin", FleetAgent(
        name="finance_ap", role="finance", domain="finance_ap"))
    ensure_dispatch_allowed("user:fin", generic)   # no domain -> never scoped
    ensure_dispatch_allowed(None, legal)           # host operator -> never scoped


def test_ensure_dispatch_allowed_respects_inherited_suite(monkeypatch, tmp_path):
    from maverick.fleet import FleetAgent, ensure_dispatch_allowed

    (tmp_path / "client_fork.toml").write_text(
        'name = "client_fork"\nextends = "aero_avionics"\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    sg.set_suites("user:fin", ["finance"])
    fork = FleetAgent(name="client_fork", role="custom", domain="client_fork")
    with pytest.raises(sg.DepartmentAccessError):
        ensure_dispatch_allowed("user:fin", fork)
    ensure_dispatch_allowed(None, fork)
