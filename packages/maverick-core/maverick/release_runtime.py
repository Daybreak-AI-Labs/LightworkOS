"""Offline checks for dependencies included in distributable release artifacts.

These run in the frozen executable during staging and installed acceptance.
They use an in-memory database and a private metrics registry, never customer
credentials or a remote database. Live account acceptance remains separate.
"""
from __future__ import annotations

import importlib
import sys
import xml.etree.ElementTree as ET

_LIBPQ_SECURITY_FLOORS = {
    14: 140023, 15: 150018, 16: 160014, 17: 170010, 18: 180004,
}


def verify_release_database_runtime() -> int:
    """Exercise SQL execution, the selected PostgreSQL dialect and bundled libpq."""
    sqlalchemy = importlib.import_module("sqlalchemy")
    pq = importlib.import_module("psycopg.pq")
    pool_module = importlib.import_module("psycopg_pool")
    version = pq.version()
    if pq.__impl__ != "binary" or type(version) is not int or version <= 0:
        raise RuntimeError(
            f"release PostgreSQL driver requires bundled binary libpq (observed {version!r})"
        )
    # Check the actual loaded library, not the Python wheel's version. These
    # are the vendor's fixed branches for CVE-2026-6477; subsequent major
    # releases include prior fixes. Unsupported older branches are refused.
    minimum = _LIBPQ_SECURITY_FLOORS.get(version // 10000, 190000)
    if version < minimum:
        raise RuntimeError(
            f"bundled libpq {version} predates required client security fixes; "
            "rebuild with the reviewed release dependencies (CVE-2026-6477)"
        )

    engine = sqlalchemy.create_engine("sqlite:///:memory:")
    try:
        with engine.begin() as connection:
            connection.execute(sqlalchemy.text("CREATE TABLE probe (value INTEGER)"))
            connection.execute(sqlalchemy.text("INSERT INTO probe VALUES (:value)"),
                               {"value": 42})
        with engine.connect() as connection:
            if connection.execute(sqlalchemy.text("SELECT value FROM probe")).scalar() != 42:
                raise RuntimeError("release SQL query returned an unexpected result")
    finally:
        engine.dispose()

    # Engine construction loads the actual URL-selected DBAPI without opening
    # a socket. The closed pool also checks the platform storage dependency.
    engine = sqlalchemy.create_engine("postgresql+psycopg://127.0.0.1:9/release_check")
    try:
        if engine.dialect.driver != "psycopg":
            raise RuntimeError("release PostgreSQL dialect is unavailable")
        pool = pool_module.ConnectionPool(
            "host=127.0.0.1 port=9 dbname=release_check", min_size=0, max_size=1,
            open=False,
        )
        pool.close()
    finally:
        engine.dispose()
    return version


def verify_release_mathml_runtime() -> None:
    """Exercise the real converter, packaged symbol data and malformed input."""
    from .tools.latex_tool import to_mathml

    root = ET.fromstring(to_mathml(r"\frac{\alpha}{2}"))
    fraction = root.find(".//{http://www.w3.org/1998/Math/MathML}mfrac")
    if fraction is None or len(fraction) != 2 or "α" not in "".join(root.itertext()):
        raise RuntimeError("release MathML conversion returned incomplete output")
    try:
        to_mathml(r"\frac{1}")
    except RuntimeError:
        return
    raise RuntimeError("release MathML converter accepted an incomplete fraction")


def verify_release_metrics_runtime() -> None:
    """Render the platform's real collectors without opening a metrics listener."""
    from .observability import _register_computed_collector

    prometheus = importlib.import_module("prometheus_client")
    registry = prometheus.CollectorRegistry()
    _register_computed_collector(registry=registry)
    rendered = prometheus.generate_latest(registry).decode("utf-8")
    for name in ("maverick_tool_latency_ms", "maverick_provider_error_rate",
                 "maverick_tool_latency_budget_breaches"):
        if f"# HELP {name} " not in rendered:
            raise RuntimeError(f"release metrics collector did not export {name}")


def verify_full_release_runtime() -> int:
    """Run every packaged-feature check ``maverick release-runtime-check`` runs.

    Providers, document parsers and worker source, offline SQL with the bundled
    PostgreSQL driver, MathML, metrics and offline token estimates. Returns the bundled libpq version
    number; raises the first failing check's exception unchanged.
    """
    from . import providers
    from .tools import document_processing

    providers.verify_release_runtime()
    document_processing.verify_release_document_runtime()
    libpq_version = verify_release_database_runtime()
    verify_release_mathml_runtime()
    verify_release_metrics_runtime()
    verify_release_plugin_runtime()
    verify_release_token_counter_runtime()
    verify_release_checkpoint_storage_runtime()
    verify_release_desktop_recording_runtime()
    return libpq_version


def verify_release_desktop_recording_runtime() -> None:
    """Require installed platform bindings without opening or reading a desktop."""
    if sys.platform == "darwin":
        importlib.import_module("AppKit")
        importlib.import_module("objc")
    elif sys.platform.startswith("linux"):
        importlib.import_module("Xlib.display")
        importlib.import_module("Xlib.Xatom")


def verify_release_checkpoint_storage_runtime() -> None:
    """Load packaged S3 request models with explicit fictional keys; no request."""
    import json

    from .audit.checkpoint_custody import _client

    client = _client({"token": json.dumps({"access_key_id": "AKIA" + "0" * 16,
        "secret_access_key": "fictional-release-key" * 2, "region": "us-east-1"})}, "us-east-1")  # pragma: allowlist secret -- fictional key; no request is sent
    try:
        models = client.meta.service_model
        required = {"PutObject": {"IfNoneMatch", "ObjectLockMode", "ObjectLockRetainUntilDate"},
                    "ListObjectVersions": {"KeyMarker", "VersionIdMarker", "MaxKeys"},
                    "GetObjectRetention": {"Key", "VersionId"}, "GetObject": {"Key", "VersionId"}}
        for name, members in required.items():
            if not members <= models.operation_model(name).input_shape.members.keys():
                raise RuntimeError("Release checkpoint storage request data is incomplete.")
        if client.meta.config.retries.get("total_max_attempts") != 1:
            raise RuntimeError("Release checkpoint storage must not replay an uncertain request.")
    finally:
        client.close()


def verify_release_plugin_runtime() -> None:
    """Check the guided form validator and retained offline worker sources."""
    from pathlib import Path

    from jsonschema import ValidationError

    from .sandbox.plugin_contracts import validate

    schema = {"type": "object", "properties": {"count": {"type": "integer", "minimum": 1}},
              "required": ["count"], "additionalProperties": False}
    validate(schema, {"count": 2})
    try:
        validate(schema, {"count": "two"})
    except ValidationError:
        pass
    else:
        raise RuntimeError("Packaged plugin questions accepted an invalid answer")
    for name in ("plugin_probe.py", "plugin_contracts.py"):
        source = Path(__file__).parent / "sandbox" / name
        compile(source.read_bytes(), str(source), "exec")


def verify_release_token_counter_runtime() -> None:
    """Exercise the bundled vocabulary and native tokenizer without networking."""
    from .local_token_counter import counter

    count = counter()
    if count("") != 0 or count("hello world") != 2:
        raise RuntimeError("Packaged token estimates returned an unexpected result")
    # Reserved-looking customer content remains ordinary text. Include real
    # Unicode so this exercises the native wheel, not a character approximation.
    if count("<|endoftext|>") <= 1 or count("你好 👋") <= 0:
        raise RuntimeError("Packaged token estimates could not count ordinary text")


def libpq_label(libpq_version: int) -> str:
    """``major.minor`` of a libpq version number (e.g. 160004 -> "16.4")."""
    return f"{libpq_version // 10000}.{libpq_version % 10000}"
