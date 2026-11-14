"""Governed knowledge admin: subject_key convention, fail-open when knowledge
is off, and the seed corpus. Plus the erase-verify integration that folds the
knowledge residual into the right-to-erasure verdict."""
from __future__ import annotations

import json

from maverick import knowledge_admin
from maverick.knowledge_seed import available_corpora, seed_corpora


def test_reindex_cli_reports_only_committed_migration(monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main
    from maverick_knowledge import KnowledgeBase
    from maverick_knowledge.embed import DeterministicEmbedder

    kb = KnowledgeBase()
    kb.ingest_text("ops", "some policy", source="policy.txt")
    kb.embedder = DeterministicEmbedder(32)
    calls = []

    def opened(**kwargs):
        calls.append(kwargs)
        return kb

    monkeypatch.setattr(knowledge_admin, "open_knowledge_base", opened)
    monkeypatch.setattr(kb, "close", lambda: None)
    result = CliRunner().invoke(main, ["knowledge", "reindex", "ops", "--tenant", "tenant-a"])
    assert result.exit_code == 0, result.output
    assert "reindexed 1 chunk(s) in ops" in result.output
    assert calls == [{"tenant": "tenant-a", "require_existing": True}]
    assert kb.search("ops", "policy")

    def failed(_collection):
        raise RuntimeError("source changed during reindex")

    monkeypatch.setattr(kb, "reindex", failed)
    failed_result = CliRunner().invoke(main, ["knowledge", "reindex", "ops"])
    assert failed_result.exit_code != 0
    assert "reindexed" not in failed_result.output
    kb.store.close()


def test_subject_key_matches_dsar_convention():
    # Must equal maverick.dsar._fact_subject_token so knowledge erasure and
    # world-model erasure agree on subject identity.
    from maverick.dsar import _fact_subject_token
    assert knowledge_admin.subject_key("slack", "U/1") == _fact_subject_token("slack", "U/1")
    assert knowledge_admin.subject_key("a b", "c:d") == _fact_subject_token("a b", "c:d")


def test_admin_fail_open_when_knowledge_disabled(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[knowledge]\nenable = false\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert knowledge_admin.open_knowledge_base() is None
    assert knowledge_admin.erase_subject("slack", "U1") == {}
    assert knowledge_admin.count_subject("slack", "U1") == 0


def test_admin_erase_and_count_when_enabled(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[knowledge]\nenable = true\nembedder = \"deterministic\"\nstore = \"sqlite\"\n"
        f'path = {json.dumps(str(tmp_path / "knowledge.db"))}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    kb = knowledge_admin.open_knowledge_base()
    assert kb is not None
    kb.ingest_text("itgrc", "Dana's private document.", source="dana.txt",
                   subject=knowledge_admin.subject_key("slack", "UDANA"))
    kb.close()
    assert knowledge_admin.count_subject("slack", "UDANA") == 1
    removed = knowledge_admin.erase_subject("slack", "UDANA")
    assert removed == {"itgrc": 1}
    assert knowledge_admin.count_subject("slack", "UDANA") == 0


# ---- seed corpus -------------------------------------------------------------

def test_admin_erases_a_store_left_after_knowledge_was_disabled(tmp_path, monkeypatch):
    # Turning knowledge off leaves the populated store on disk; erasure and the
    # residual count must still look at it instead of reporting zero.
    cfg = tmp_path / "config.toml"
    body = ("embedder = \"deterministic\"\nstore = \"sqlite\"\n"
            f'path = {json.dumps(str(tmp_path / "knowledge.db"))}\n')
    cfg.write_text("[knowledge]\nenable = true\n" + body, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    kb = knowledge_admin.open_knowledge_base()
    kb.ingest_text("itgrc", "Dana's private document.", source="dana.txt",
                   subject=knowledge_admin.subject_key("slack", "UDANA"))
    kb.close()
    cfg.write_text("[knowledge]\nenable = false\n" + body, encoding="utf-8")
    assert knowledge_admin.open_knowledge_base() is None
    assert knowledge_admin.count_subject("slack", "UDANA") == 1
    assert knowledge_admin.erase_subject("slack", "UDANA") == {"itgrc": 1}
    assert knowledge_admin.count_subject("slack", "UDANA") == 0


def test_disabled_admin_neither_raises_nor_runs_ddl_when_no_store_exists(tmp_path, monkeypatch):
    import sys
    import types

    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    # Tenant install, knowledge off, explicit path outside the workspace and
    # no file: nothing to look at, so no confinement error.
    monkeypatch.setattr(config, "get_knowledge", lambda: {
        "enable": False, "store": "sqlite", "path": str(tmp_path / "shared.db")})
    assert knowledge_admin.count_subject("slack", "U1", tenant="customer-a") == 0
    assert knowledge_admin.erase_subject("slack", "U1", tenant="customer-a") == {}

    # pgvector off on a Postgres install (MAVERICK_PG_DSN is the world-model
    # database) where knowledge was never used: read-only probe, no DDL.
    sqls = []

    class _Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def execute(self, sql, params=None):
            sqls.append(sql)
            return self

        def fetchone(self):
            return (None,)  # to_regclass: the knowledge table does not exist

    class _Conn:
        def execute(self, sql, params=None):
            sqls.append(sql)

        def cursor(self):
            return _Cursor()

        def close(self):
            sqls.append("close")

    monkeypatch.setitem(sys.modules, "psycopg",
                        types.SimpleNamespace(connect=lambda *a, **k: _Conn()))
    monkeypatch.setenv("MAVERICK_PG_DSN", "postgresql://world-model")
    monkeypatch.setattr(config, "get_knowledge", lambda: {
        "enable": False, "store": "pgvector", "path": "", "dim": 4})
    assert knowledge_admin.count_subject("slack", "U1") == 0
    assert knowledge_admin.erase_subject("slack", "U1") == {}
    assert sqls and all(sql.startswith("SELECT") or sql == "close" for sql in sqls)
    assert not any("CREATE" in sql or "ALTER" in sql for sql in sqls)


def test_available_corpora_shape():
    corpora = available_corpora()
    assert corpora, "starter corpora must ship"
    cols = {c["collection"] for c in corpora}
    assert "itgrc" in cols
    assert all(c["documents"] > 0 for c in corpora)


def test_seed_is_idempotent(tmp_path):
    from maverick_knowledge import KnowledgeBase
    from maverick_knowledge.store import SqliteVectorStore
    kb = KnowledgeBase(store=SqliteVectorStore(":memory:"))
    r1 = seed_corpora(kb)
    n1 = kb.store.count("itgrc")
    r2 = seed_corpora(kb)          # re-seed same content
    n2 = kb.store.count("itgrc")
    assert r1 == r2
    assert n1 == n2, "re-seeding identical content must not duplicate chunks"
    # seeded material is public reference (no subject) -> untouched by erasure
    assert kb.count_subject("anything") == 0


def test_seed_only_one_collection(tmp_path):
    from maverick_knowledge import KnowledgeBase
    from maverick_knowledge.store import SqliteVectorStore
    kb = KnowledgeBase(store=SqliteVectorStore(":memory:"))
    report = seed_corpora(kb, only="itgrc")
    assert set(report) == {"itgrc"}


# ---- erase-verify integration ------------------------------------------------

def test_erase_verify_includes_knowledge_residual(tmp_path, monkeypatch):
    """verify_erasure must count a subject's residual knowledge chunks so a
    right-to-erasure verdict covers the vector store, not just the world model."""
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[knowledge]\nenable = true\nembedder = \"deterministic\"\nstore = \"sqlite\"\n"
        f'path = {json.dumps(str(tmp_path / "knowledge.db"))}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")

    # A subject with a residual knowledge chunk but no world-model rows: the
    # verdict must be NOT clean because knowledge still holds their document.
    kb = knowledge_admin.open_knowledge_base()
    kb.ingest_text("itgrc", "Erin's uploaded contract.", source="erin.txt",
                   subject=knowledge_admin.subject_key("slack", "UERIN"))
    kb.close()

    from maverick.erasure_verify import verify_erasure
    report = verify_erasure("UERIN", channel="slack")
    assert report["counts"].get("knowledge_chunks") == 1
    assert not report["clean"]

    knowledge_admin.erase_subject("slack", "UERIN")
    report2 = verify_erasure("UERIN", channel="slack")
    assert report2["counts"].get("knowledge_chunks") == 0
    # The knowledge store is now clean, but a bare post-hoc subject scan cannot
    # reconstruct the deleted goal closure. Only a durable pre-delete receipt
    # can turn the complete erasure report into a clean certificate.
    assert not report2["clean"]
    assert report2["indeterminate"]
    assert "erasure_receipt" in report2["errors"]
