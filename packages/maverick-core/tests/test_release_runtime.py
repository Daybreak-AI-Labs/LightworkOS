"""Release checks must catch absent/broken extras inside a frozen application."""
from __future__ import annotations

import socket

import pytest
from click.testing import CliRunner
from maverick import release_runtime
from maverick.cli import main


@pytest.fixture
def release_dependencies():
    for module in ("sqlalchemy", "psycopg.pq", "psycopg_pool", "latex2mathml.converter",
                   "prometheus_client"):
        pytest.importorskip(module)


def test_offline_checks_use_actual_dependencies_without_customer_connections(
    release_dependencies, monkeypatch,
):
    def refuse_connection(*args, **kwargs):
        pytest.fail("offline release check attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse_connection)
    monkeypatch.setattr(socket, "create_connection", refuse_connection)
    monkeypatch.setenv("DATABASE_URL", "postgresql://customer.invalid/private")
    monkeypatch.setenv("PGHOST", "customer.invalid")
    from prometheus_client import REGISTRY

    before = set(REGISTRY._collector_to_names)
    for _ in range(2):
        release_runtime.verify_release_database_runtime()
        release_runtime.verify_release_mathml_runtime()
        release_runtime.verify_release_metrics_runtime()
    assert set(REGISTRY._collector_to_names) == before


@pytest.mark.parametrize("missing,probe", [
    ("sqlalchemy", release_runtime.verify_release_database_runtime),
    ("psycopg.pq", release_runtime.verify_release_database_runtime),
    ("psycopg_pool", release_runtime.verify_release_database_runtime),
    ("prometheus_client", release_runtime.verify_release_metrics_runtime),
])
def test_missing_release_dependency_is_not_reported_ready(
    release_dependencies, monkeypatch, missing, probe,
):
    original = release_runtime.importlib.import_module

    def absent(name, *args, **kwargs):
        if name == missing:
            raise ImportError(f"missing release dependency: {missing}")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(release_runtime.importlib, "import_module", absent)
    with pytest.raises(ImportError, match="missing release dependency"):
        probe()


@pytest.mark.parametrize("implementation,version", [
    ("python", 180004), ("binary", 0), ("binary", -1),
])
def test_release_cannot_rely_on_system_libpq(
    release_dependencies, monkeypatch, implementation, version,
):
    from psycopg import pq

    monkeypatch.setattr(pq, "__impl__", implementation)
    monkeypatch.setattr(pq, "version", lambda: version)
    with pytest.raises(RuntimeError, match="bundled binary libpq"):
        release_runtime.verify_release_database_runtime()


@pytest.mark.parametrize("version,accepted", [
    (130999, False),
    (140022, False), (140023, True),
    (150017, False), (150018, True),
    (160013, False), (160014, True),
    (170009, False), (170010, True),
    (180003, False), (180004, True), (190000, True),
])
def test_release_checks_the_loaded_libpq_security_boundary(
    release_dependencies, monkeypatch, version, accepted,
):
    from psycopg import pq

    monkeypatch.setattr(pq, "version", lambda: version)
    if accepted:
        assert release_runtime.verify_release_database_runtime() == version
    else:
        with pytest.raises(RuntimeError, match=f"bundled libpq {version} predates"):
            release_runtime.verify_release_database_runtime()


def test_release_checks_the_actual_closed_pool(release_dependencies, monkeypatch):
    import psycopg_pool

    def unavailable_pool(*args, **kwargs):
        raise RuntimeError("packaged PostgreSQL pool unavailable")

    monkeypatch.setattr(psycopg_pool, "ConnectionPool", unavailable_pool)
    with pytest.raises(RuntimeError, match="packaged PostgreSQL pool unavailable"):
        release_runtime.verify_release_database_runtime()


def test_packaged_mathml_check_detects_missing_symbol_data(release_dependencies, monkeypatch):
    from latex2mathml import converter

    def missing_symbols(*args, **kwargs):
        raise FileNotFoundError("packaged symbol data missing")

    monkeypatch.setattr(converter, "convert", missing_symbols)
    with pytest.raises(RuntimeError, match="packaged symbol data missing"):
        release_runtime.verify_release_mathml_runtime()


def test_metrics_dependency_cannot_hide_missing_platform_collector(
    release_dependencies, monkeypatch,
):
    from maverick import observability

    monkeypatch.setattr(observability, "_register_computed_collector", lambda **kwargs: None)
    with pytest.raises(RuntimeError, match="did not export"):
        release_runtime.verify_release_metrics_runtime()


def test_release_metrics_remain_scrapable_when_a_profile_is_broken(
    release_dependencies, monkeypatch,
):
    from maverick import tool_latency

    def broken_profile():
        raise OSError("profile unavailable")

    monkeypatch.setattr(tool_latency, "report", broken_profile)
    release_runtime.verify_release_metrics_runtime()


@pytest.mark.parametrize("broken", [
    "verify_release_database_runtime", "verify_release_mathml_runtime",
    "verify_release_metrics_runtime",
])
def test_release_command_fails_when_a_packaged_feature_check_fails(monkeypatch, broken):
    from maverick import providers
    from maverick.tools import document_processing

    monkeypatch.setattr(providers, "verify_release_runtime", lambda: None)
    monkeypatch.setattr(document_processing, "verify_release_document_runtime", lambda: None)
    for name in ("verify_release_database_runtime", "verify_release_mathml_runtime",
                 "verify_release_metrics_runtime"):
        monkeypatch.setattr(release_runtime, name, lambda: None)

    def unavailable():
        raise RuntimeError("packaged feature unavailable")

    monkeypatch.setattr(release_runtime, broken, unavailable)
    result = CliRunner().invoke(main, ["release-runtime-check"])
    assert result.exit_code != 0
    assert "packaged feature unavailable" in result.output
    assert "release runtime ready:" not in result.output
