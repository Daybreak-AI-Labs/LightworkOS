"""maverick encryption migrate: seal pre-existing plaintext."""
from __future__ import annotations

import importlib.util
import sqlite3

import pytest
from maverick import crypto_at_rest as car

requires_crypto = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra is not installed",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    # The migration scenario STARTS from a legacy plaintext estate: say so
    # explicitly ("0"), because under the secure posture an UNSET flag
    # means encryption on and the plaintext fixtures would never exist.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")


def test_migrate_requires_encryption_enabled(tmp_path):
    from maverick.crypto_at_rest import EncryptionUnavailable
    from maverick.encryption_migrate import migrate_world_db

    with pytest.raises(EncryptionUnavailable):
        migrate_world_db(tmp_path / "world.db")  # at_rest off -> refuse, never plaintext


@requires_crypto
def test_migrate_seals_existing_plaintext(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    # Write everything as plaintext (encryption off).
    wm = WorldModel(db)
    conv = wm.get_or_create_conversation("slack", "u")
    wm.append_turn(conv.id, "user", "turn SSN 123-45-6789")
    wm.upsert_fact("k", "fact 4111111111111111")
    gid = wm.create_goal("g", "d")
    wm.append_message(gid, "user", "message secret")
    qid = wm.ask("question secret", goal_id=gid)
    wm.answer(qid, "answer secret")

    # Enable encryption and seal the existing rows.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    assert migrate_world_db(db) == {
        "turns.content": 1, "facts.value": 1, "messages.content": 1,
        "questions.question": 1, "questions.answer": 1,
        "goals.title": 1, "goals.description": 1, "goals.result": 0,
        "goals.connection_selection": 1,
        "goal_events.content": 0,
        "episodes.summary": 0, "episodes.outcome": 0,
        "approvals.action": 0, "approvals.scope": 0, "approvals.detail": 0,
        "signoffs.note": 0, "artifacts.content": 0,
        "projects.name": 0, "projects.description": 0,
        "fact_history.value": 0,
        "harness_corpus.row": 0,
    }

    # On disk the columns are now sealed (ciphertext, no plaintext).
    c = sqlite3.connect(str(db))
    turn = c.execute("SELECT content FROM turns").fetchone()[0]
    assert turn.startswith("MVKBND1:") and "123-45-6789" not in turn
    assert c.execute("SELECT value FROM facts").fetchone()[0].startswith("MVKBND1:")
    assert c.execute("SELECT title FROM goals").fetchone()[0].startswith("MVKBND1:")

    # Reads still return plaintext.
    wm2 = WorldModel(db)
    assert wm2.recent_turns(conv.id)[-1].content == "turn SSN 123-45-6789"
    assert wm2.get_fact("k") == "fact 4111111111111111"
    assert wm2.get_goal(gid).title == "g"          # goal content round-trips

    # Idempotent: a second run seals nothing.
    assert migrate_world_db(db) == {
        "turns.content": 0, "facts.value": 0, "messages.content": 0,
        "questions.question": 0, "questions.answer": 0,
        "goals.title": 0, "goals.description": 0, "goals.result": 0,
        "goals.connection_selection": 0,
        "goal_events.content": 0,
        "episodes.summary": 0, "episodes.outcome": 0,
        "approvals.action": 0, "approvals.scope": 0, "approvals.detail": 0,
        "signoffs.note": 0, "artifacts.content": 0,
        "projects.name": 0, "projects.description": 0,
        "fact_history.value": 0,
        "harness_corpus.row": 0,
    }


@requires_crypto
def test_migrate_seals_artifacts_projects_signoffs_and_fact_history(monkeypatch, tmp_path):
    """Regression: _SEALED_COLUMNS omitted artifacts.content, projects.name/
    description, signoffs.note and fact_history.value, so legacy plaintext in
    them survived `maverick encryption migrate` (and strict mode then withheld
    it forever)."""
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")   # populate fact_history
    # Write everything as plaintext (encryption off).
    wm = WorldModel(db)
    gid = wm.create_goal("g", "d")
    wm.add_artifact(gid, "text", "t", "artifact body secret")
    pid = wm.create_project("project name secret", description="project desc secret")
    wm.set_goal_status(gid, "done", result="draft")
    wm.record_signoff(gid, "approved", note="signoff note secret")
    wm.upsert_fact("k", "fact history secret")
    wm.conn.close()

    # Enable encryption and seal the existing rows.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    report = migrate_world_db(db)
    assert report["artifacts.content"] == 1
    assert report["projects.name"] == 1
    assert report["projects.description"] == 1
    assert report["signoffs.note"] == 1
    assert report["fact_history.value"] == 1

    # On disk the columns are now sealed ciphertext (no plaintext residue).
    c = sqlite3.connect(str(db))
    content = c.execute("SELECT content FROM artifacts").fetchone()[0]
    assert car.is_sealed_str(content) and "secret" not in content
    name, desc = c.execute("SELECT name, description FROM projects").fetchone()
    assert car.is_sealed_str(name) and car.is_sealed_str(desc)
    assert car.is_sealed_str(c.execute("SELECT note FROM signoffs").fetchone()[0])
    assert car.is_sealed_str(c.execute("SELECT value FROM fact_history").fetchone()[0])
    c.close()

    # Reads still return plaintext.
    wm2 = WorldModel(db)
    assert wm2.artifacts_for_goal(gid)[0]["content"] == "artifact body secret"
    p = wm2.get_project(pid)
    assert p["name"] == "project name secret"
    assert p["description"] == "project desc secret"
    assert wm2.signoff_for(gid)["note"] == "signoff note secret"
    assert wm2.fact_history("k")[0].value == "fact history secret"


@requires_crypto
def test_migrate_seals_malformed_prefixed_plaintext(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    gid = wm.create_goal("MVKAR1:legacy prefixed title", "d")
    wm.append_event(gid, "agent-1", "note", "MVKAR1:legacy prefixed event")

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    report = migrate_world_db(db)
    assert report["goals.title"] == 1
    assert report["goal_events.content"] == 1

    c = sqlite3.connect(str(db))
    raw_title = c.execute("SELECT title FROM goals WHERE id=?", (gid,)).fetchone()[0]
    raw_event = c.execute("SELECT content FROM goal_events WHERE goal_id=?", (gid,)).fetchone()[0]
    assert car.is_sealed_str(raw_title)
    assert car.is_sealed_str(raw_event)
    assert raw_title != "MVKAR1:legacy prefixed title"
    assert raw_event != "MVKAR1:legacy prefixed event"

    wm2 = WorldModel(db)
    assert wm2.get_goal(gid).title == "MVKAR1:legacy prefixed title"
    assert wm2.goal_events(gid)[0].content == "MVKAR1:legacy prefixed event"


@requires_crypto
def test_migrate_dry_run_writes_nothing(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    conv = wm.get_or_create_conversation("slack", "u")
    wm.append_turn(conv.id, "user", "still plaintext")

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    assert migrate_world_db(db, dry_run=True)["turns.content"] == 1
    # Unchanged on disk.
    raw = sqlite3.connect(str(db)).execute("SELECT content FROM turns").fetchone()[0]
    assert raw == "still plaintext"


@requires_crypto
def test_migrate_preserves_a_concurrent_edit(monkeypatch, tmp_path):
    from maverick import encryption_migrate as migration

    db = tmp_path / "world.db"
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE turns (content TEXT)")
        connection.execute("INSERT INTO turns VALUES ('original customer text')")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    original_seal = migration.seal_bound_to_str

    def seal_after_customer_edit(value, context, **kwargs):
        with sqlite3.connect(db) as connection:
            connection.execute("UPDATE turns SET content='new customer text'")
        return original_seal(value, context, **kwargs)

    monkeypatch.setattr(migration, "seal_bound_to_str", seal_after_customer_edit)
    assert migration.migrate_world_db(db)["turns.content"] == 0
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT content FROM turns").fetchone()[0] == "new customer text"
    monkeypatch.setattr(migration, "seal_bound_to_str", original_seal)
    assert migration.migrate_world_db(db)["turns.content"] == 1
    with sqlite3.connect(db) as connection:
        assert car.unseal_from_str(connection.execute("SELECT content FROM turns").fetchone()[0]) == "new customer text"


def _all_db_bytes(db):
    """The DB main file + its WAL/SHM sidecars, concatenated."""
    blob = db.read_bytes() if db.exists() else b""
    for suf in ("-wal", "-shm"):
        p = db.with_name(db.name + suf)
        if p.exists():
            blob += p.read_bytes()
    return blob


@requires_crypto
def test_migrate_backup_true_writes_backup_before_resealing(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.file_lock import private_path_is_restricted
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    wm.create_goal("backup me 4111111111111111", "d")
    wm.conn.close()

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    migrate_world_db(db, backup=True)

    backups = list(tmp_path.glob("world.db.pre-encrypt-*.bak"))
    assert len(backups) == 1
    bak = backups[0]
    # Backup is a private (0600) PLAINTEXT snapshot the migration can recover from.
    assert private_path_is_restricted(bak, 0o600)
    assert b"4111111111111111" in bak.read_bytes()
    # ...and it is a usable SQLite DB holding the pre-migration plaintext.
    c = sqlite3.connect(str(bak))
    assert c.execute("SELECT title FROM goals").fetchone()[0] == "backup me 4111111111111111"
    c.close()
    # The live DB is sealed.
    live = sqlite3.connect(str(db)).execute("SELECT title FROM goals").fetchone()[0]
    assert car.is_sealed_str(live)


@requires_crypto
def test_migrate_default_writes_no_backup(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    wm.create_goal("g", "d")
    wm.conn.close()

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    migrate_world_db(db)
    assert list(tmp_path.glob("world.db.pre-encrypt-*.bak")) == []
    live = sqlite3.connect(str(db)).execute("SELECT title FROM goals").fetchone()[0]
    assert car.is_sealed_str(live)


@requires_crypto
def test_migrate_backup_true_when_nothing_to_seal_skips_backup(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    wm.create_goal("g 4111111111111111", "d")
    wm.conn.close()

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    migrate_world_db(db)
    migrate_world_db(db, backup=True)
    assert list(tmp_path.glob("world.db.pre-encrypt-*.bak")) == []


@requires_crypto
def test_migrate_dry_run_makes_no_backup(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    wm.create_goal("g 4111111111111111", "d")
    wm.conn.close()

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    migrate_world_db(db, dry_run=True)
    assert list(tmp_path.glob("world.db.pre-encrypt-*.bak")) == []


@requires_crypto
def test_migrate_leaves_no_plaintext_residue_in_the_db_file(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    marker = "RESIDUE-MARKER-4111111111111111"
    wm.create_goal(marker, "desc")
    wm.conn.close()                                   # release the DB (offline migrate)
    assert marker.encode() in _all_db_bytes(db)       # plaintext present before

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    migrate_world_db(db)

    # secure_delete zeroed the freed cells + VACUUM/checkpoint rebuilt the file:
    # the pre-encryption plaintext is gone from the DB file and the WAL sidecar.
    assert marker.encode() not in _all_db_bytes(db)


def test_migrate_leaves_no_plaintext_terms_in_a_pre_v49_message_index(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import SCHEMA, WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    gid = wm.create_goal("g", "d")
    wm.conn.close()
    # A database not yet opened since v49 still carries the message index.
    start = SCHEMA.index("CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts")
    end = SCHEMA.index("END;", SCHEMA.index("messages_au")) + len("END;")
    c = sqlite3.connect(str(db))
    c.executescript(SCHEMA[start:end])
    for n in range(6):
        c.execute("INSERT INTO messages(goal_id, role, content, ts) VALUES(?, 'user', ?, 0)",
                  (gid, f"zebraterm{n}quokka"))
    c.commit()
    c.close()
    assert b"zebraterm3quokka" in _all_db_bytes(db)

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    assert migrate_world_db(db)["messages.content"] == 6
    assert b"zebraterm" not in _all_db_bytes(db)


@requires_crypto
def test_migrate_rebinds_legacy_sealed_rows_and_marks_the_store(monkeypatch, tmp_path):
    from maverick.encryption_migrate import migrate_world_db
    from maverick.world_model import WorldModel, migrated_marker_path

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    wm.upsert_fact("k", "plain fact")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    # One row sealed by an older build (unbound MVKAR1 token).
    c = sqlite3.connect(str(db))
    c.execute("UPDATE facts SET value=? WHERE key='k'", (car.seal_to_str("plain fact"),))
    c.commit()
    assert not migrated_marker_path(db).exists()
    report = migrate_world_db(db)
    assert report["facts.value"] == 1               # re-sealed with its binding
    value = c.execute("SELECT value FROM facts WHERE key='k'").fetchone()[0]
    c.close()
    assert value.startswith("MVKBND1:facts.value:")
    assert migrated_marker_path(db).exists()
    assert wm.get_fact("k") == "plain fact"
    # Idempotent: a second run finds nothing to do and keeps the marker.
    assert sum(migrate_world_db(db).values()) == 0
    assert migrated_marker_path(db).exists()
