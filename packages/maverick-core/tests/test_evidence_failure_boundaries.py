"""Unavailable evidence must never become a verified empty result."""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import governed_actions, knowledge_admin


@pytest.mark.parametrize("body", ["{broken\n", "[]\n", "null\n", "123\n"])
def test_lineage_corruption_is_not_valid_empty(tmp_path, body):
    (tmp_path / "1.ndjson").write_text(body, encoding="utf-8")
    assert governed_actions.verify_lineage_file(1, tmp_path).startswith("BROKEN")


def test_missing_lineage_differs_from_existing_empty_chain(tmp_path):
    assert governed_actions.verify_lineage_file(1, tmp_path).startswith("MISSING")
    (tmp_path / "1.ndjson").write_text("", encoding="utf-8")
    assert governed_actions.verify_lineage_file(1, tmp_path) == "VALID: 0 link(s) (empty)"


def test_unreadable_lineage_is_not_valid_empty(tmp_path, monkeypatch):
    (tmp_path / "1.ndjson").write_text("", encoding="utf-8")

    def unavailable(*args, **kwargs):
        raise PermissionError("store unavailable")

    monkeypatch.setattr(Path, "read_text", unavailable)
    assert governed_actions.verify_lineage_file(1, tmp_path).startswith("UNAVAILABLE")


def _knowledge_config(monkeypatch, tmp_path):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(config, "get_knowledge", lambda: {
        "enable": True, "embedder": "deterministic", "store": "sqlite", "path": "",
    })


def test_explicit_tenant_overrides_ambient_knowledge_tenant(monkeypatch, tmp_path):
    _knowledge_config(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_TENANT", "customer-a")
    a = knowledge_admin.open_knowledge_base(tenant="customer-a")
    b = knowledge_admin.open_knowledge_base(tenant="customer-b")
    try:
        a.ingest_text("contracts", "Customer A contract", subject="slack:U1")
        b.ingest_text("contracts", "Customer B contract", subject="slack:U1")
        knowledge_admin.erase_subject("slack", "U1", tenant="customer-b")
        assert a.count_subject("slack:U1") == 1
        assert b.count_subject("slack:U1") == 0
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("operation", ["count_subject", "erase_subject"])
def test_knowledge_query_failure_is_not_success(monkeypatch, operation):
    class BrokenKnowledge:
        def count_subject(self, subject):
            raise OSError("unavailable")

        erase_subject = count_subject

        def close(self):
            pass

    monkeypatch.setattr(knowledge_admin, "open_knowledge_base", lambda **kwargs: BrokenKnowledge())
    with pytest.raises(RuntimeError, match="knowledge"):
        getattr(knowledge_admin, operation)("slack", "U1")


def test_missing_knowledge_is_not_recreated_for_verification(monkeypatch, tmp_path):
    _knowledge_config(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="missing"):
        knowledge_admin.count_subject("slack", "U1", tenant="customer-a")
    from maverick.workspace import Workspace
    assert not Workspace("customer-a").knowledge_path.exists()


def test_tenant_admin_rejects_shared_custom_storage(monkeypatch, tmp_path):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(config, "get_knowledge", lambda: {
        "enable": True, "path": str(tmp_path / "shared.db"), "store": "sqlite",
    })
    with pytest.raises(RuntimeError, match="outside the selected tenant"):
        knowledge_admin.open_knowledge_base(tenant="customer-a")
    assert not (tmp_path / "shared.db").exists()


def test_knowledge_corruption_cannot_produce_clean_cli_report(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main

    _knowledge_config(monkeypatch, tmp_path)
    (tmp_path / "knowledge.db").write_bytes(b"not a sqlite database")
    result = CliRunner().invoke(main, ["knowledge", "residual", "--channel", "slack",
                                      "--user", "U1", "--json"])
    assert result.exit_code == 2
    import json
    report = json.loads(result.output)
    assert report["clean"] is False and report["knowledge_chunks"] is None
    assert report["checked"] is False


def test_unavailable_collection_enumeration_cannot_certify_zero():
    from maverick_knowledge import KnowledgeBase

    base = KnowledgeBase(store=object())
    with pytest.raises(RuntimeError, match="collections"):
        base.count_subject("slack:U1")
