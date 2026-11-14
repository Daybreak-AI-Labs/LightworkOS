"""World-DB learning store (fleet-shared state) -- the store seam,
routing rule, lifecycle round-trips, and the migrate-store CLI."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick import learning_store as ls
from maverick import self_harness as sh
from maverick import self_improvement as si


@pytest.fixture()
def world_home(tmp_path, monkeypatch):
    """Isolated MAVERICK_HOME with [self_harness] store = "world" configured
    (SQLite world DB inside the temp home)."""
    home = tmp_path / "home"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "store": "world"}})
    return home


def _ctrl(monkeypatch, ledger_path):
    monkeypatch.setattr(si, "enabled", lambda: True)
    return si.SelfImprovementController(frozen_fn=lambda: False,
                                        ledger=si.PromotionLedger(path=ledger_path))


def _promote(model, line, ctrl, path=None):
    return sh.run_self_harness(
        [{"owner": "", "goal_id": 0, "model_id": model, "failure_class": "timeout",
          "goal_text": f"task {i}", "failure_msg": "x"} for i in range(3)],
        model_id=model, controller=ctrl, min_support=3, path=path,
        held_in=["a", "b"], held_out=["c", "d", "e", "f", "g"],
        propose_fn=lambda s, _l=line: _l,
        score_with=lambda a, c: 0.95, score_without=lambda a, c: 0.4)


def test_store_knob_defaults_to_files(monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {})
    assert config.get_self_harness()["store"] == "files"
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"store": "WORLD "}})
    assert config.get_self_harness()["store"] == "world"
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"store": "s3"}})
    assert config.get_self_harness()["store"] == "files"   # unknown -> files


def test_explicit_path_always_means_the_file_store(world_home, tmp_path,
                                                   monkeypatch):
    # The seam's contract: tests/tenant redirection pass explicit paths and
    # stay on files even when the world store is configured.
    ctrl = _ctrl(monkeypatch, tmp_path / "promotion-ledger.json")
    store = tmp_path / "explicit.json"
    rep = _promote("M", "file line", ctrl, path=store)
    assert rep.promoted == 1
    assert "file line" in store.read_text()
    assert ls.load_addenda_db() == {}          # world store untouched


def test_full_lifecycle_through_the_world_store(world_home, monkeypatch):
    # Promote -> recall -> outcome -> canary review -> forget, all with
    # path=None routed to the world DB; no JSON store file is ever written.
    ctrl = _ctrl(monkeypatch, world_home / "promotion-ledger.json")
    rep = _promote("M", "verify the export first", ctrl)
    assert rep.promoted == 1
    assert not sh._store_path().exists()       # nothing on disk at the default path
    assert "verify the export first" in sh.recall_addendum("M")
    assert ls.load_addenda_db()                # ...because it lives in the DB
    assert sh.line_provenance("M")             # sidecar records too
    sh.mark_canary("M", "verify the export first")
    for _ in range(2):
        sh.note_outcome("M", False, line="verify the export first")
    res = sh.review_canaries("M", demote_after=2)
    assert res["demoted"] == ["verify the export first"]
    assert sh.recall_addendum("M") == ""
    # The demotion recorded the transfer tried-memory in the DB (rollback
    # durability spans stores).
    assert ls.load_transfer_tried_db()


def test_transfer_one_shot_via_world_store(world_home, monkeypatch):
    ctrl = _ctrl(monkeypatch, world_home / "promotion-ledger.json")
    _promote("SRC", "solid line", ctrl)
    quad = (["a", "b"], ["c", "d", "e", "f", "g"],
            lambda a, c: 0.95, lambda a, c: 0.4)
    rep = sh.run_transfer("SRC", ["TGT"], eval_for_target=lambda m: quad,
                          controller=ctrl)
    assert rep["TGT"]["promoted"] == ["solid line"]
    assert sh.list_canaries("TGT") == ["solid line"]
    rep2 = sh.run_transfer("SRC", ["TGT"], eval_for_target=lambda m: quad,
                           controller=ctrl)
    assert rep2["TGT"]["attempted"] == []
    assert any("already present" in s for s in rep2["TGT"]["skipped"])


def test_world_store_concurrency_keeps_every_promotion(world_home, monkeypatch):
    # The battery's concurrency drill, against the DB store: 8 threads each
    # promote a distinct line; none may be lost to a read-modify-write race.
    import threading
    ctrl = _ctrl(monkeypatch, world_home / "promotion-ledger.json")
    errs: list[Exception] = []

    def work(i):
        try:
            _promote("M", f"guidance line {i}", ctrl)
        except Exception as e:  # pragma: no cover
            errs.append(e)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    bullets = [ln for ln in sh.recall_addendum("M").splitlines()
               if ln.startswith("- ")]
    assert len(bullets) == 8


def test_migrate_store_imports_and_backs_up(world_home, monkeypatch):
    from maverick.cli import main
    # Seed FILE stores at the default path (write raw -- routing is world).
    src = sh._store_path()
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(json.dumps(
        {"M": "Operating guidance learned for this model:\n- from the file era"}))
    sh._meta_path(src).write_text(json.dumps(
        {sh._line_id("M", "from the file era"): {
            "model_id": "M", "text": "from the file era"}}))
    sh._transfer_tried_path(src).write_text(json.dumps({"abc123": 1700000000.0}))
    r = CliRunner().invoke(main, ["self-harness", "migrate-store"])
    assert r.exit_code == 0, r.output
    assert "imported 1 addenda key(s)" in r.output
    assert "from the file era" not in sh.recall_addendum("M")
    assert "from the file era" in sh.load_addenda()["M"]  # retained without invented lineage
    assert ls.load_transfer_tried_db() == {"abc123": 1700000000.0}
    assert not src.exists()                     # renamed to backups
    assert src.with_name(src.name + ".migrated").exists()
    # Idempotent: a second run finds nothing to migrate.
    r = CliRunner().invoke(main, ["self-harness", "migrate-store"])
    assert r.exit_code == 0 and "nothing to migrate" in r.output


def test_migrate_store_reports_a_refused_corpus_migration(world_home, monkeypatch):
    from maverick import learning_store_migration as mig
    from maverick.cli import main

    def _refuse():
        raise mig.MigrationRefused("corpus file is unreadable")
    monkeypatch.setattr(mig, "migrate_corpus", _refuse)
    r = CliRunner().invoke(main, ["self-harness", "migrate-store"])
    assert r.exit_code == 1 and "corpus file is unreadable" in r.output
    assert isinstance(r.exception, SystemExit)


def test_migrate_store_refuses_when_the_world_read_fails(world_home, monkeypatch):
    ls.write_addenda_db({"model-a": "- keep a", "model-b": "- keep b"})
    sh._store_path().parent.mkdir(parents=True, exist_ok=True)
    sh._store_path().write_text(json.dumps({"model-c": "- from file"}))
    real_rows = ls._rows

    def _locked(conn, sql, params=()):
        if sql.startswith("SELECT key, block FROM harness_addenda"):
            raise RuntimeError("database is locked")
        return real_rows(conn, sql, params)

    monkeypatch.setattr(ls, "_rows", _locked)
    from maverick import learning_store_migration as mig
    with pytest.raises(RuntimeError):
        mig.migrate_learning_files()
    monkeypatch.setattr(ls, "_rows", real_rows)
    assert ls.load_addenda_db() == {"model-a": "- keep a", "model-b": "- keep b"}


def test_migrate_store_refuses_a_corrupt_file_instead_of_renaming_it(world_home):
    from maverick import learning_store_migration as mig
    sh._store_path().parent.mkdir(parents=True, exist_ok=True)
    sh._store_path().write_text("{not json")
    sh._meta_path(sh._store_path()).write_text(json.dumps({"l1": {"a": 1}}))
    with pytest.raises(mig.LearningFileUnreadable, match="could not be read"):
        mig.migrate_learning_files()
    assert sh._store_path().read_text() == "{not json"
    assert mig.preview()["unreadable"] == str(sh._store_path())


def test_migrate_store_merges_conflicting_blocks(world_home, monkeypatch):
    from maverick.cli import main
    ctrl = _ctrl(monkeypatch, world_home / "promotion-ledger.json")
    _promote("M", "db-era line", ctrl)          # already in the world store
    src = sh._store_path()
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(json.dumps(
        {"M": "Operating guidance learned for this model:\n- file-era line"}))
    r = CliRunner().invoke(main, ["self-harness", "migrate-store"])
    assert r.exit_code == 0, r.output
    block = sh.recall_addendum("M")
    assert "db-era line" in block and "file-era line" not in block
    assert "file-era line" in sh.load_addenda()["M"]  # unknown legacy content retained, never silently published


@pytest.fixture()
def world_corpus(tmp_path, monkeypatch):
    """world_home plus a configured eval_corpus path (world-routed)."""
    home = tmp_path / "home"
    cpath = tmp_path / "corpus.json"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "store": "world",
                         "eval_corpus": str(cpath)}})
    return cpath


def test_corpus_lifecycle_through_the_world_store(world_corpus):
    # stage -> review (reject remembered, accept merges) entirely as world
    # rows; no corpus/pending/rejected file ever appears on disk.
    from maverick import self_harness_eval as ev
    cpath = world_corpus
    assert ev.stage_candidates(cpath, "M", [
        {"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "g1", "expected": "e1"}, {"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "g2", "expected": "e2"}]) == 2
    assert not cpath.exists()
    assert not ev.pending_corpus_path(cpath).exists()
    assert [c["goal"] for c in ev.load_pending(cpath)["M"]] == ["g1", "g2"]
    res = ev.resolve_pending(cpath, "M", accept=[1], reject=[2])
    assert (res["merged"], res["rejected"]) == (1, 1)
    assert [c["goal"] for c in ev.load_eval_corpus(cpath)["M"]] == ["g1"]
    assert ev.load_rejected(cpath) == {"M": ["g2"]}
    # rejection stays durable through the DB path
    assert ev.stage_candidates(cpath, "M", [{"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "g2", "expected": "x"}]) == 0
    assert ls.load_corpus_db("live")            # rows really live in the DB


def test_explicit_other_corpus_path_stays_on_files(world_corpus, tmp_path):
    # Only the CONFIGURED corpus path routes; any other path is a plain file.
    from maverick import self_harness_eval as ev
    other = tmp_path / "other.json"
    other.write_text("{}")
    assert ev.stage_candidates(other, "M", [{"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "g", "expected": "e"}]) == 1
    assert ev.pending_corpus_path(other).exists()      # file sidecar written
    assert ev.load_pending(world_corpus) == {}         # world store untouched


def test_corpus_export_import_round_trip(world_corpus, tmp_path):
    # The hand-editing story: export the world-stored corpus to JSON, edit,
    # import back -- operator fields and non-list keys survive both ways.
    from click.testing import CliRunner as _CR
    from maverick import self_harness_eval as ev
    from maverick.cli import main
    cpath = world_corpus
    ev.import_corpus(cpath, {
        "M": [{"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "live", "expected": "x", "notes": "keep me"}],
        "_meta": {"owner": "ops"},
    })
    out = tmp_path / "export.json"
    r = _CR().invoke(main, ["self-harness", "corpus", "export",
                            "--out", str(out)])
    assert r.exit_code == 0, r.output
    data = json.loads(out.read_text())
    assert data["M"][0]["notes"] == "keep me" and data["_meta"] == {"owner": "ops"}
    # edit: add a case, then import (merge)
    data["M"].append({"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "new", "expected": "y", "reviewed": True})
    out.write_text(json.dumps(data))
    r = _CR().invoke(main, ["self-harness", "corpus", "import", str(out)])
    assert r.exit_code == 0, r.output
    raw = ev._load_raw(cpath)
    assert [c["goal"] for c in raw["M"]] == ["live", "new"]
    assert raw["M"][1]["reviewed"] is True and raw["_meta"] == {"owner": "ops"}
    # --replace overwrites wholesale
    out.write_text(json.dumps({"M": [{"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "only", "expected": "z"}]}))
    r = _CR().invoke(main, ["self-harness", "corpus", "import", str(out),
                            "--replace"])
    assert r.exit_code == 0, r.output
    assert [c["goal"] for c in ev._load_raw(cpath)["M"]] == ["only"]


def test_migrate_store_carries_the_corpus_family(world_corpus, monkeypatch):
    from maverick import self_harness_eval as ev
    from maverick.cli import main
    cpath = world_corpus
    cpath.write_text(json.dumps(
        {"M": [{"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "old live", "expected": "x", "notes": "n"}]}))
    ev.pending_corpus_path(cpath).write_text(json.dumps(
        {"M": [{"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "old pending", "expected": "y"}]}))
    ev.rejected_corpus_path(cpath).write_text(json.dumps({"M": ["old reject"]}))
    r = CliRunner().invoke(main, ["self-harness", "migrate-store"])
    assert r.exit_code == 0, r.output
    assert "corpus: merged 1 live case(s), 1 pending, 1 rejected" in r.output
    assert not cpath.exists()                          # renamed to backup
    assert cpath.with_name(cpath.name + ".migrated").exists()
    assert ev._load_raw(cpath)["M"][0]["notes"] == "n"  # via the world store
    assert [c["goal"] for c in ev.load_pending(cpath)["M"]] == ["old pending"]
    assert ev.load_rejected(cpath) == {"M": ["old reject"]}


def test_world_corpus_seals_machine_owned_rows(world_corpus, monkeypatch):
    import base64
    import sqlite3

    pytest.importorskip("cryptography")

    from maverick import self_harness_eval as ev
    from maverick.crypto_at_rest import is_sealed_str
    from maverick.paths import data_dir

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", base64.b64encode(b"k" * 32).decode("ascii"))
    cpath = world_corpus

    assert ev.stage_candidates(cpath, "M", [
        {"privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0], "goal": "SECRET_CORPUS_GOAL", "expected": "SECRET_EXPECTED_HINT"},
    ]) == 1
    assert ev.load_pending(cpath)["M"][0]["goal"] == "SECRET_CORPUS_GOAL"

    conn = sqlite3.connect(data_dir("world.db"))
    try:
        row = conn.execute(
            "SELECT row FROM harness_corpus WHERE kind = 'pending'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert "SECRET_CORPUS_GOAL" not in row
    assert "SECRET_EXPECTED_HINT" not in row
    assert is_sealed_str(row)

    res = ev.resolve_pending(cpath, "M", accept=[], reject=[1])
    assert res["rejected"] == 1
    assert ev.load_rejected(cpath) == {"M": ["SECRET_CORPUS_GOAL"]}
    conn = sqlite3.connect(data_dir("world.db"))
    try:
        rejected = conn.execute(
            "SELECT row FROM harness_corpus WHERE kind = 'rejected'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert "SECRET_CORPUS_GOAL" not in rejected
    assert is_sealed_str(rejected)


def test_migrate_store_requires_world_config(tmp_path, monkeypatch):
    from maverick.cli import main
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {
        "self_harness": {"enable": True}})       # store = files
    r = CliRunner().invoke(main, ["self-harness", "migrate-store"])
    assert r.exit_code != 0 and 'store = "world"' in r.output


def test_migrate_store_refuses_an_unreadable_corpus_file(world_corpus):
    # An unreadable file read as {} was renamed to *.migrated and the run
    # reported success with zero counts.
    from maverick.cli import main
    cpath = world_corpus
    cpath.write_text('{"M": [,]}')
    r = CliRunner().invoke(main, ["self-harness", "migrate-store"])
    assert r.exit_code != 0
    assert cpath.read_text() == '{"M": [,]}'
    assert not cpath.with_name(cpath.name + ".migrated").exists()
    # The callers report MigrationRefused, and can check before moving anything.
    from maverick import self_harness_eval as ev
    from maverick.learning_store_migration import MigrationRefused
    with pytest.raises(MigrationRefused):
        ev.check_corpus_files_migratable(cpath)
    with pytest.raises(MigrationRefused):
        ev.migrate_corpus_files(cpath)
