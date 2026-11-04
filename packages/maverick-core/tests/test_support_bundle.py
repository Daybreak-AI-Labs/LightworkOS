"""maverick support — a redacted diagnostics bundle. Secrets must never appear
in it; the core sections must always be present."""
from __future__ import annotations

import json

from maverick import support_bundle
from maverick.file_lock import private_path_is_restricted


def test_diagnostic_inventory_matches_release_cohort_even_when_a_package_is_missing(monkeypatch):
    import importlib.metadata as metadata
    from pathlib import Path
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib
    manifest = Path(__file__).resolve().parents[3] / "release-cohort.toml"
    cohort = tomllib.loads(manifest.read_text(encoding="utf-8"))
    expected = {package["distribution"] for package in cohort["packages"]}
    def installed_version(name):
        if name == "maverick-knowledge":
            raise metadata.PackageNotFoundError(name)
        return "test-version"
    monkeypatch.setattr(metadata, "version", installed_version)
    actual = support_bundle._versions()
    assert set(actual) == expected
    assert actual["maverick-knowledge"] == "not installed"
    assert actual["maverick-evolve"] == "test-version"


def test_redacts_secret_named_keys():
    src = {
        "providers": {"anthropic": {"api_key": "sk-ant-SECRETVALUE"}},  # pragma: allowlist secret
        "federation": {"peers": [{"name": "vega", "token": "TOPSECRETTOKEN"}]},  # pragma: allowlist secret
        "models": {"orchestrator": "anthropic:claude-opus-4-8"},  # kept
    }
    out = support_bundle._redact(src)
    assert out["providers"]["anthropic"]["api_key"] == "[REDACTED]"
    assert out["federation"]["peers"][0]["token"] == "[REDACTED]"
    assert out["models"]["orchestrator"] == "anthropic:claude-opus-4-8"
    assert "SECRETVALUE" not in json.dumps(out)
    assert "TOPSECRETTOKEN" not in json.dumps(out)


def test_collect_has_core_sections_and_is_json():
    bundle = support_bundle.collect()
    for key in ("versions", "runtime", "paths", "readiness", "providers",
                "recent_failures", "config_redacted", "generated_at"):
        assert key in bundle
    # The whole bundle must serialize (no stray non-JSON objects).
    json.dumps(bundle, default=str)


def test_collect_config_is_redacted(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"providers": {"openai": {"api_key": "sk-LEAKME"}}})  # pragma: allowlist secret
    bundle = support_bundle.collect()
    assert "sk-LEAKME" not in json.dumps(bundle["config_redacted"], default=str)


def test_collect_never_exports_customer_authored_config_text(monkeypatch):
    marker = "SYNTHETIC_UNAUTHORIZED_DOCUMENT_EXCERPT_91D4"
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {
            "workflow": {
                "prompt": marker,
                "source_urls": ["https://private.example/document/customer-plan"],
                "enabled": True,
                "limit": 4,
            }
        },
    )

    config = support_bundle.collect()["config_redacted"]
    serialized = json.dumps(config)

    assert marker not in serialized
    assert "private.example" not in serialized
    assert "workflow" not in serialized
    assert "prompt" not in serialized
    assert "source_urls" not in serialized
    assert config["type"] == "object"
    assert config["configured_items"] == 1
    assert '"configured_items": 4' in serialized
    assert '"configured_items": 1' in serialized
    assert "true" in serialized
    assert "4" in serialized


def test_config_topology_never_exports_customer_authored_dictionary_keys():
    needles = [
        "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "Customer private document sentence 8137",
        "https://example.invalid/private-document/CASE-991",
    ]
    topology = support_bundle._config_topology(
        {
            needles[0]: True,
            needles[1]: {"enabled": True},
            needles[2]: 1,
        }
    )
    serialized = json.dumps(topology)

    assert all(needle not in serialized for needle in needles)
    assert topology["configured_items"] == 3
    assert all(len(row["key_sha256"]) == 64 for row in topology["entries"])


def test_cli_support_writes_redacted_file(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"providers": {"openai": {"api_key": "sk-LEAKME"}}})  # pragma: allowlist secret
    out = tmp_path / "bundle.json"
    r = CliRunner().invoke(main, ["support", "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert out.exists()
    text = out.read_text()
    assert "sk-LEAKME" not in text
    assert json.loads(text)["versions"]  # parseable + populated


def test_collect_categorizes_failed_job_errors_without_exporting_raw_text(tmp_path, monkeypatch):
    from maverick import job_queue

    monkeypatch.setattr(job_queue, "DEFAULT_DB", tmp_path / "jobs.db")
    q = job_queue.JobQueue()
    job_id = q.enqueue("demo", {})
    claimed = q.claim()
    assert claimed and claimed.id == job_id
    q.fail(
        job_id,
        "RuntimeError: Authorization: Bearer sk-live-POCSECRET1234567890 "
        "and https://user:SuperSecretPass@example.test/cb?api_key=AKIAABCDEFGHIJKLMNOP",
        retry_after=None,
    )

    bundle = support_bundle.collect()
    text = json.dumps(bundle, default=str)
    assert "sk-live-POCSECRET1234567890" not in text
    assert "SuperSecretPass" not in text
    assert "AKIAABCDEFGHIJKLMNOP" not in text
    failed = bundle["recent_failures"]["failed_jobs"]
    assert failed == {
        "count": 1,
        "errors_recorded": 1,
        "categories": {"permission_denied": 1},
    }


def test_collect_never_exports_customer_controlled_job_identifiers(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from maverick import job_queue

    customer_id = "customer-zephyr-case-72819"
    customer_kind = "Customer-Zephyr-private-workflow"
    monkeypatch.setattr(job_queue, "DEFAULT_DB", tmp_path / "jobs.db")
    monkeypatch.setattr(
        job_queue.JobQueue,
        "list",
        lambda *_args, **_kwargs: [
            SimpleNamespace(
                id=customer_id,
                kind=customer_kind,
                last_error="request timed out",
            )
        ],
    )

    serialized = json.dumps(support_bundle.collect(), default=str)

    assert customer_kind not in serialized
    assert customer_id not in serialized
    assert '"categories": {"timeout": 1}' in serialized


def test_collect_never_exports_customer_document_excerpt_from_job_error(tmp_path, monkeypatch):
    from maverick import job_queue

    marker = "SYNTHETIC_UNAUTHORIZED_DOCUMENT_EXCERPT_7F3A"
    monkeypatch.setattr(job_queue, "DEFAULT_DB", tmp_path / "jobs.db")
    q = job_queue.JobQueue()
    job_id = q.enqueue("document_parser", {})
    claimed = q.claim()
    assert claimed and claimed.id == job_id
    q.fail(job_id, f"Parser error near customer document: {marker}", retry_after=None)

    bundle = support_bundle.collect()
    serialized = json.dumps(bundle, default=str)
    assert marker not in serialized
    assert "Parser error" not in serialized
    assert "last_error" not in serialized


def test_cli_support_tightens_existing_output_file_permissions(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main

    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"providers": {"openai": {"api_key": "sk-LEAKME"}}})  # pragma: allowlist secret
    out = tmp_path / "bundle.json"
    out.write_text("old")
    out.chmod(0o644)

    r = CliRunner().invoke(main, ["support", "-o", str(out)])

    assert r.exit_code == 0, r.output
    assert private_path_is_restricted(out, 0o600)
    assert "sk-LEAKME" not in out.read_text()


def test_cli_support_stdout():
    from click.testing import CliRunner
    from maverick.cli import main
    r = CliRunner().invoke(main, ["support"])
    assert r.exit_code == 0
    assert json.loads(r.output)["runtime"]["python"]


def test_support_export_writes_redacted_bundle(tmp_path):
    out, bundle = support_bundle.export(tmp_path / "support.json")
    assert out.exists()
    on_disk = json.loads(out.read_text())
    assert on_disk["correlation_id"].startswith("sup_")
    assert on_disk["correlation_id"] == bundle["correlation_id"]


def test_support_export_emits_a_redacted_audit_event(monkeypatch, tmp_path):
    import maverick.cli as C
    from click.testing import CliRunner
    calls = []
    monkeypatch.setattr("maverick.audit.record",
                        lambda kind, **kw: calls.append((kind, kw)) or True)
    out = tmp_path / "bundle.json"
    res = CliRunner().invoke(C.main, ["support", "-o", str(out)])
    assert res.exit_code == 0, res.output
    assert out.exists()
    ev = [kw for kind, kw in calls if kind == "support_bundle_exported"]
    assert len(ev) == 1                                    # exactly one export event
    assert ev[0].get("correlation_id", "").startswith("sup_")
    assert ev[0].get("filename") == "bundle.json"          # basename only, no path


def test_ticket_summary_is_redacted_and_routable():
    bundle = {
        "correlation_id": "sup_abc123", "generated_at": "2026-07-02T00:00:00Z",
        "versions": {"maverick-agent": "0.1.7"},
        "readiness": {"client_binding": "ok", "shield": "fail: required but unavailable"},
        "recent_failures": {"failure_modes": {"timeout": 3},
                            "failed_jobs": [{"id": 1}, {"id": 2}]},
    }
    s = support_bundle.ticket_summary(bundle)
    assert s["correlation_id"] == "sup_abc123"
    assert s["readiness_failing"] == ["shield"] and s["healthy"] is False
    assert s["agent_version"] == "0.1.7" and s["failed_job_count"] == 2
