"""Command groups refuse invalid input and protect caller-supplied files."""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))


def _export_command(kind, monkeypatch, tmp_path, output):
    from maverick import (
        ai_bom,
        assessment_exports,
        attestation,
        config,
        consent_registry,
        content_provenance,
        domain_audit,
        underwriting_pack,
    )
    from maverick.immune import title

    monkeypatch.setattr(config, "get_tax", lambda: {"auto_update": False})
    monkeypatch.setattr(content_provenance, "create_manifest", lambda *a, **kw: {
        "manifest_sha256": "a" * 64, "attestation": {"key_id": "fixture"},
    })
    monkeypatch.setattr(underwriting_pack, "export_underwriting_pack", lambda **kw: {
        "summary": {"inventory_count": 0, "assurance_pack_sha256": "a" * 64},
    })
    monkeypatch.setattr(consent_registry, "export_receipts", lambda **kw: [])
    monkeypatch.setattr(assessment_exports, "render_oscal_assessment_results", lambda *a: {
        "assessment-results": {"results": [{"observations": [], "findings": []}]},
    })
    monkeypatch.setattr(assessment_exports, "render_statement_of_applicability", lambda *a: {
        "counts": {"implemented": 0, "not_implemented": 0, "excluded": 0},
    })
    monkeypatch.setattr(assessment_exports, "soa_markdown", lambda *a: "reviewed controls")
    monkeypatch.setattr(ai_bom, "export_ai_bom", lambda **kw: {"components": [], "dependencies": []})
    monkeypatch.setattr(title, "seal", lambda *a: {"sealed": True})
    monkeypatch.setattr(title, "add_research_runs", lambda *a: {"gates": []})
    monkeypatch.setattr(domain_audit, "audit_roster", list)
    monkeypatch.setattr(attestation, "verifier_source", lambda: ("print('verify')\n", "a" * 64))
    source = tmp_path / "source.json"
    source.write_text("{}")
    docs = tmp_path / "docs"
    docs.mkdir(exist_ok=True)
    commands = {
        "tax_prepare": ["tax", "prepare", str(docs), "--out", output],
        "tax_backtest": ["tax", "backtest", str(docs), "--out", output],
        "provenance": ["content-provenance", "sign", "--file", str(source), "--asset", "fixture",
                       "--modality", "text", "--by", "reviewer", "--out", output],
        "underwriting": ["underwriting-pack", "export", "--by", "reviewer", "--out", output],
        "consent": ["consent", "export", "--out", output],
        "oscal": ["exports", "oscal", "--assessment", "fixture", "--out", output],
        "soa_json": ["exports", "soa", "--assessment", "fixture", "--json", "--out", output],
        "soa_text": ["exports", "soa", "--assessment", "fixture", "--out", output],
        "ai_bom": ["exports", "ai-bom", "--out", output],
        "title_seal": ["immune", "title", "seal", str(source), "--out", output],
        "title_research": ["immune", "title", "research", str(source), str(source), "--out", output],
        "domains": ["domains-audit", "--json", output],
        "verifier": ["attest", "export-verifier", output],
    }
    return commands[kind]


@pytest.mark.parametrize("kind", [
    "tax_prepare", "tax_backtest", "provenance", "underwriting", "consent",
    "oscal", "soa_json", "soa_text", "ai_bom", "title_seal", "title_research", "domains", "verifier",
])
def test_text_exports_are_private_and_refuse_aliases(kind, tmp_path, monkeypatch):
    from maverick.file_lock import private_path_is_restricted

    output = tmp_path / "export.txt"
    previous = os.umask(0o022)
    try:
        result = CliRunner().invoke(main, _export_command(kind, monkeypatch, tmp_path, str(output)))
    finally:
        os.umask(previous)
    assert result.exit_code == 0, result.output
    assert private_path_is_restricted(output)
    streamed = CliRunner().invoke(main, _export_command(kind, monkeypatch, tmp_path, "-"))
    assert streamed.exit_code == 0, streamed.output
    assert streamed.stdout == output.read_text()
    if os.name != "nt":
        alias = tmp_path / "alias.txt"
        alias.symlink_to(output)
        before = output.read_bytes()
        refused = CliRunner().invoke(main, _export_command(kind, monkeypatch, tmp_path, str(alias)))
        assert refused.exit_code == 1
        assert "Error:" in refused.output
        assert output.read_bytes() == before
    directory = tmp_path / "directory"
    directory.mkdir()
    refused = CliRunner().invoke(main, _export_command(kind, monkeypatch, tmp_path, str(directory)))
    assert refused.exit_code != 0
    assert "Error:" in refused.output


def test_finance_lint_requires_at_least_one_pack(monkeypatch):
    from maverick.finance import sod_linter

    monkeypatch.setattr(sod_linter, "lint_finance_roster", lambda: ([], []))
    result = CliRunner().invoke(main, ["finance", "lint-sod"])
    assert result.exit_code != 0
    assert "no finance" in result.output.lower()
    monkeypatch.setattr(sod_linter, "lint_finance_roster", lambda: (["finance_test"], []))
    assert CliRunner().invoke(main, ["finance", "lint-sod"]).exit_code == 0


def test_learning_confidence_is_validated_and_reported(tmp_path):
    from maverick.learning_proof import paired_lift

    scores = tmp_path / "scores.json"
    scores.write_text(json.dumps({"baseline": [0, 0], "treatment": [1, 1]}))
    for invalid in ("0", "1", "nan", "inf", "-0.5"):
        result = CliRunner().invoke(main, ["prove-learning", "--scores", str(scores), "--confidence", invalid])
        assert result.exit_code == 2, (invalid, result.output)
        with pytest.raises(ValueError, match="confidence"):
            paired_lift([0, 0], [1, 1], confidence=float(invalid))
    result = CliRunner().invoke(main, ["prove-learning", "--scores", str(scores), "--confidence", "0.8"])
    assert result.exit_code == 0, result.output
    assert "80% CI" in result.output


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission-mode controls")
@pytest.mark.parametrize("parent_mode,key_mode", [
    (0o775, 0o600), (0o757, 0o600), (0o700, 0o644), (0o700, 0o640),
])
def test_result_key_refuses_unsafe_modes_without_claiming_files(tmp_path, parent_mode, key_mode):
    from maverick.cli.run_result import read_result_key

    parent = tmp_path / "caller"
    parent.mkdir(mode=parent_mode)
    parent.chmod(parent_mode)
    key = parent / "key"
    key.write_bytes(b"k" * 32)
    key.chmod(key_mode)
    with pytest.raises(PermissionError):
        read_result_key(key)
    assert parent.stat().st_mode & 0o777 == parent_mode
    assert key.stat().st_mode & 0o777 == key_mode
    parent.chmod(0o700)
    key.chmod(0o600)
    assert read_result_key(key) == b"k" * 32
    key.chmod(0o400)
    assert read_result_key(key) == b"k" * 32
    assert key.stat().st_mode & 0o777 == 0o400
    alias = parent / "alias"
    alias.symlink_to(key)
    with pytest.raises((PermissionError, OSError)):
        read_result_key(alias)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission-mode controls")
def test_result_key_accepts_private_key_in_ordinary_project_folder(tmp_path, monkeypatch):
    from maverick.cli.run_result import read_result_key

    project = tmp_path / "project"
    project.mkdir()
    project.chmod(0o755)
    key = project / "key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    assert read_result_key(key) == b"k" * 32
    monkeypatch.chdir(project)
    assert read_result_key("key") == b"k" * 32
    assert project.stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize("option", ["--estimated-payments", "--prior-year-overpayment"])
def test_tax_payments_must_be_finite_and_nonnegative(tmp_path, option):
    docs = tmp_path / "tax-docs"
    docs.mkdir()
    for value in ("-5", "nan", "inf"):
        result = CliRunner().invoke(main, ["tax", "prepare", str(docs), option, value])
        assert result.exit_code == 2, (value, result.output)


def test_graph_as_of_requires_date_or_explicit_finite_epoch(monkeypatch):
    from maverick import entity_graph

    seen = []
    monkeypatch.setattr(entity_graph, "dossier", lambda *a, **kw: seen.append(kw["as_of"]) or {})
    for value in ("20240101", "01/02/2024", "epoch:nan", "epoch:inf", "2024-02-30"):
        result = CliRunner().invoke(main, ["graph", "dossier", "vendor", "--as-of", value])
        assert result.exit_code == 2, (value, result.output)
        assert seen == []
    for value, expected in (("2024-01-01", 1704153600), ("epoch:1704067200", 1704067200)):
        result = CliRunner().invoke(main, ["graph", "dossier", "vendor", "--as-of", value])
        assert result.exit_code == 0, result.output
        assert seen[-1] == expected


def test_knowledge_seed_unknown_collection_is_refused_before_open(monkeypatch):
    from maverick import knowledge_admin, knowledge_seed

    opened = []
    monkeypatch.setattr(knowledge_seed, "available_corpora", lambda: [{"collection": "known"}])
    monkeypatch.setattr(knowledge_admin, "open_knowledge_base", lambda **kw: opened.append(True) or SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(knowledge_seed, "seed_corpora", lambda *a, **kw: {})
    result = CliRunner().invoke(main, ["knowledge", "seed", "--collection", "typo"])
    assert result.exit_code == 2, result.output
    assert not opened
    result = CliRunner().invoke(main, ["knowledge", "seed", "--collection", "known"])
    assert result.exit_code == 0, result.output
    assert opened == [True]


def test_grc_blocked_records_fail_the_command(monkeypatch):
    from maverick import grc_sync

    result = {"delivered_count": 0, "unchanged_count": 0, "blocked_count": 1,
              "failure_count": 0, "connector": "fixture", "failures": [],
              "blocked": [{"source_id": "item", "reason": "review required"}]}
    monkeypatch.setattr(grc_sync, "run_sync", lambda **kw: result)
    blocked = CliRunner().invoke(main, ["grc-sync", "run", "--by", "reviewer"])
    assert blocked.exit_code == 1, blocked.output
    assert "BLOCKED" in blocked.output
    result.update(blocked_count=0, blocked=[])
    assert CliRunner().invoke(main, ["grc-sync", "run", "--by", "reviewer"]).exit_code == 0


def test_dream_rollback_needs_confirmation_and_reports_failures(monkeypatch):
    from maverick import dreaming

    calls = []
    monkeypatch.setattr(dreaming, "rollback_learning_state", lambda name: calls.append(name) or ["skills"])
    declined = CliRunner().invoke(main, ["dream", "--rollback", "latest"], input="n\n")
    assert declined.exit_code != 0
    assert not calls
    accepted = CliRunner().invoke(main, ["dream", "--rollback", "latest", "--yes"])
    assert accepted.exit_code == 0, accepted.output
    assert calls == ["latest"]

    def fail(name):
        raise OSError("snapshot unavailable")

    monkeypatch.setattr(dreaming, "rollback_learning_state", fail)
    failed = CliRunner().invoke(main, ["dream", "--rollback", "latest", "--yes"])
    assert failed.exit_code == 1
    assert "Error:" in failed.output and "snapshot unavailable" in failed.output
